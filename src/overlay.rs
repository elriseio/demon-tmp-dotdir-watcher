//! Host-side overlay-fs scanner for container-resident Azazel-style
//! shallow dot-directories (ADR-0002 § 5).
//!
//! Walks Docker `overlay2` layer trees under
//! `overlay_scan_roots` (default `/var/lib/docker/overlay2`) and
//! discovers container layers by enumerating immediate subdirs of
//! each root, then walking each layer's `tmp/.?*/` subtree up to
//! `overlay_scan_maxdepth` (default 3) looking for `.*` (dot-prefixed)
//! entries per the operator's detection scope.
//!
//! Reuses the existing IOC matcher (`src/ioc.rs`) and allowlist
//! filter (`src/allowlist.rs`). The quarantine side effect is
//! delegated to `crate::subsystem::quarantine`; `overlay_quarantine`
//! is a thin wrapper that emits the overlay-source structured log
//! line required by ADR-0002 § 3 and § 7.
//!
//! The scanner is **purely host filesystem** — no docker.sock,
//! no container exec, no outbound network, no third-party
//! container client (see ADR-0002 § 2 for the rationale).

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::allowlist::Allowlist;
use crate::subsystem::{Candidate, QuarantineOutcome};

/// ADR-0002 § 5: origin tag attached to overlay-resident
/// candidates. `Host` is the legacy default (host-resident paths);
/// `Overlay { layer_id, kind }` tags an overlay-path candidate so
/// the runtime / journal can map back to the container layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateSource {
    Host,
    Overlay {
        layer_id: String,
        kind: LayerKind,
    },
}

/// ADR-0002 § 5: which overlay sub-tree the candidate was found
/// in. `Diff` is the persistent upper layer (post-restart
/// residue); `Merged` is the live container view (running case).
/// Both are walked because a container may have been stopped
/// (only `diff/` is left) — see ADR-0002 § 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    Diff,
    Merged,
}

/// ADR-0002 § 5: a single container layer discovered under an
/// `overlay_scan_roots` entry. `root` is the absolute path of the
/// layer's `diff/` or `merged/` sub-tree that `walk_overlay` will
/// traverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerPath {
    pub layer_id: String,
    pub kind: LayerKind,
    pub root: PathBuf,
}

impl LayerPath {
    fn new(layer_id: String, kind: LayerKind, root: PathBuf) -> Self {
        Self {
            layer_id,
            kind,
            root,
        }
    }
}

impl std::fmt::Display for LayerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Diff => f.write_str("diff"),
            Self::Merged => f.write_str("merged"),
        }
    }
}

impl LayerKind {
    /// The fixed sub-directory name under a container layer that
    /// contains the overlay's upper-layer (`diff`) or live
    /// (`merged`) filesystem tree. See ADR-0002 § 6.
    pub fn subdir_name(&self) -> &'static str {
        match self {
            Self::Diff => "diff",
            Self::Merged => "merged",
        }
    }
}

/// ADR-0002 § 5: enumerate container layers under each
/// `overlay_scan_roots` entry. Each layer is discovered by listing
/// the immediate subdirs of a root and emitting a `LayerPath` for
/// every `<layer>/diff/` and `<layer>/merged/` subtree that
/// exists. Unreadable roots are warned and skipped — the walker
/// must never abort the daemon (ADR-0002 § 8).
pub fn discover_layers(roots: &[PathBuf]) -> Vec<LayerPath> {
    let mut layers = Vec::new();
    for root in roots {
        let read = match fs::read_dir(root) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    target: "tmp-watcher",
                    priority = 4,
                    overlay_root = %root.display(),
                    error = %e,
                    "overlay: scan root unreadable; skipping for this poll cycle",
                );
                continue;
            }
        };

        for entry in read {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        target: "tmp-watcher",
                        priority = 4,
                        overlay_root = %root.display(),
                        error = %e,
                        "overlay: read_dir entry error",
                    );
                    continue;
                }
            };
            let layer_path = entry.path();
            if !layer_path.is_dir() {
                continue;
            }
            let layer_id = entry.file_name().to_string_lossy().into_owned();
            for kind in [LayerKind::Diff, LayerKind::Merged] {
                let subtree = layer_path.join(kind.subdir_name());
                if subtree.is_dir() {
                    layers.push(LayerPath::new(
                        layer_id.clone(),
                        kind,
                        subtree,
                    ));
                }
            }
        }
    }

    layers.sort_by(|a, b| {
        a.layer_id
            .cmp(&b.layer_id)
            .then_with(|| a.kind.subdir_name().cmp(b.kind.subdir_name()))
    });
    layers
}

/// ADR-0002 § 5: walk a single layer's `tmp/.?*/` subtree and
/// return candidates. `maxdepth` caps the recursive descent at
/// `<layer>/<diff|merged>/tmp/<dotdir>/<child>/...` (default 3
/// preserves invariant 6). When `dotdir_only` is true, only
/// entries whose basename starts with `.` are emitted; sessions,
/// pipe buffers, and bind-mounts are skipped — that is the
/// detection fingerprint the operator scoped this scan to.
///
/// `allowlist` is passed by reference per SC-RUST-001
/// (idioms/ownership) — no clones, no `Arc`. The IOC matcher is
/// applied later in `subsystem::walk_decision_pipeline` against
/// each candidate's `entries` (the host-side walker uses the
/// same shape), so `walk_overlay` does not take a matcher here.
///
/// The walker does NOT enforce a mtime window. The host daemon
/// bounds host candidates via the 24-hour window; overlay-resident
/// malware may sit for days (per the 2026-08-09 elrise incident)
/// and a recent-only filter would miss it. The bounded walk scope
/// (`maxdepth ≤ 3` + dotdir filter) is the detection fingerprint.
pub fn walk_overlay(
    layer: &LayerPath,
    maxdepth: usize,
    dotdir_only: bool,
    allowlist: &Allowlist,
) -> Vec<Candidate> {
    let tmp_root = layer.root.join("tmp");
    let mut out = Vec::new();

    if !tmp_root.is_dir() {
        return out;
    }

    let read = match fs::read_dir(&tmp_root) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                target: "tmp-watcher",
                priority = 4,
                layer_id = %layer.layer_id,
                layer_kind = %layer.kind,
                tmp_root = %tmp_root.display(),
                error = %e,
                "overlay: tmp/ read_dir failed; skipping layer",
            );
            return out;
        }
    };

    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    target: "tmp-watcher",
                    priority = 4,
                    layer_id = %layer.layer_id,
                    layer_kind = %layer.kind,
                    error = %e,
                    "overlay: tmp/ read_dir entry error",
                );
                continue;
            }
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let basename = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        // ADR-0002 § 1 + operator direction 2026-08-13: the
        // detection fingerprint is `.<lowercase-token>/` (issue
        // DE-006 § "Detection target"). `dotdir_only` therefore
        // requires a lowercase letter immediately after the dot —
        // this skips `sess_*`, `systemd-private-*` (no dot
        // prefix) and `.X11-unix`, `.ICE-unix` (uppercase X11/ICE
        // are X11 socket / ICE protocol paths that belong to
        // legitimate desktop sessions, never to Azazel-style kits).
        if dotdir_only && !is_lowercase_dotdir(&basename) {
            continue;
        }
        if allowlist.allows(&basename) {
            continue;
        }

        // Each `tmp/.?*` entry is a candidate top-level dir; its
        // children are walked up to `maxdepth - 1` levels so the
        // total descent from `<layer>/diff/tmp/` stays bounded.
        // `maxdepth == 0` short-circuits — invariant 6 (bounded
        // walk scope) yields zero candidates when depth is zero.
        if maxdepth == 0 {
            continue;
        }
        let local_depth = maxdepth - 1;
        walk_overlay_recursive(
            &path,
            0,
            local_depth,
            &layer.layer_id,
            layer.kind,
            &mut out,
        );
    }

    out
}

/// True iff `basename` starts with `.` followed by an ASCII
/// lowercase letter — the operator-scoped detection fingerprint
/// (issue DE-006 § "Detection target"). Non-lowercase `.X11-unix`
/// and `.ICE-unix` are filtered out here; the operator's
/// `.font-unix` / `systemd-private-*` patterns are filtered by
/// the allowlist pass after this function returns true.
fn is_lowercase_dotdir(basename: &str) -> bool {
    let mut chars = basename.chars();
    match chars.next() {
        Some('.') => match chars.next() {
            Some(c) => c.is_ascii_lowercase(),
            None => false,
        },
        _ => false,
    }
}

fn walk_overlay_recursive(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    layer_id: &str,
    kind: LayerKind,
    out: &mut Vec<Candidate>,
) {
    let mut entries = Vec::new();
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                target: "tmp-watcher",
                priority = 4,
                layer_id = %layer_id,
                layer_kind = %kind,
                path = %dir.display(),
                error = %e,
                "overlay: read_dir failed inside layer; descending into children may miss entries",
            );
            return;
        }
    };

    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    target: "tmp-watcher",
                    priority = 4,
                    layer_id = %layer_id,
                    layer_kind = %kind,
                    error = %e,
                    "overlay: read_dir entry error inside layer",
                );
                continue;
            }
        };
        let p = entry.path();
        if p.is_file() {
            entries.push(p);
        } else if p.is_dir() && depth < max_depth {
            walk_overlay_recursive(&p, depth + 1, max_depth, layer_id, kind, out);
        }
    }

    // Always emit the candidate for this dir so the runtime can
    // classify + quarantine via the existing pipeline. IOC matches
    // are discovered in `walk_decision_pipeline` via the hash of
    // each `entries[i]`. The candidate is tagged with the overlay
    // source so the journal line can map back to the container.
    out.push(Candidate {
        path: dir.to_path_buf(),
        entries,
        skipped_reason: None,
        source: Some(CandidateSource::Overlay {
            layer_id: layer_id.to_string(),
            kind,
        }),
    });
}

/// ADR-0002 § 5 + § 7: idempotent overlay-aware `chmod 0o000`
/// side effect. Emits the `source=overlay2 layer=<id>` structured
/// log line the operator uses to map back to the container, then
/// delegates to `crate::subsystem::quarantine` so the path-level
/// semantics stay identical to host candidates.
pub fn overlay_quarantine(candidate: &Candidate) -> QuarantineOutcome {
    let (layer_id, kind) = match &candidate.source {
        Some(CandidateSource::Overlay { layer_id, kind }) => {
            (layer_id.as_str(), *kind)
        }
        _ => ("unknown", LayerKind::Diff),
    };
    info!(
        target: "tmp-watcher",
        source = "overlay2",
        layer_id = layer_id,
        layer_kind = %kind,
        path = %candidate.path.display(),
        "overlay: applying quarantine",
    );
    crate::subsystem::quarantine(&candidate.path)
}

/// Helper used by `runtime::Runtime::run_once` to compose host +
/// overlay candidates when the operator has not opted out via
/// `paths.overlay_scan.enabled = false`.
///
/// Returns an empty `Vec` (and emits one INFO log) when overlay
/// scan is disabled or when `roots` is empty (e.g. operator
/// overrode to `[]`). The walker never aborts on overlay errors
/// — see ADR-0002 § 8 failure modes.
pub fn walk_all_overlays(
    roots: &[PathBuf],
    maxdepth: usize,
    dotdir_only: bool,
    allowlist: &Allowlist,
) -> Vec<Candidate> {
    if roots.is_empty() {
        return Vec::new();
    }

    let layers = discover_layers(roots);
    if layers.is_empty() {
        info!(
            target: "tmp-watcher",
            overlay_root_count = roots.len(),
            "overlay_scan_skipped reason=no_overlay2_layers",
        );
        return Vec::new();
    }

    info!(
        target: "tmp-watcher",
        layer_count = layers.len(),
        overlay_root_count = roots.len(),
        "overlay_scan_started",
    );

    let mut out = Vec::new();
    for layer in &layers {
        out.extend(walk_overlay(layer, maxdepth, dotdir_only, allowlist));
    }

    info!(
        target: "tmp-watcher",
        candidate_count = out.len(),
        layer_count = layers.len(),
        "overlay_scan_completed",
    );
    out
}

/// Empty Allowlist convenience re-export. Tests construct their
/// own; this is the public-API anchor for downstream callers
/// that hold a `None` allowlist at the integration boundary.
#[allow(dead_code)]
pub fn empty_allowlist() -> Allowlist {
    Allowlist::empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OverlayScanConfig;
    use crate::test_util::TempDir;
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Build an overlay-fs fixture under `root` mimicking Docker's
    /// `/var/lib/docker/overlay2/<layer>/{diff,merged}/tmp/.?*/`
    /// shape. Returns the layer_id used for traceability in
    /// assertions. `kind_filter` lets tests pin a single sub-tree.
    fn make_overlay_fixture(
        root: &Path,
        layer_id: &str,
        kind_filter: Option<LayerKind>,
        dotdirs: &[&str],
    ) -> PathBuf {
        for kind in [LayerKind::Diff, LayerKind::Merged] {
            if let Some(k) = kind_filter {
                if k != kind {
                    continue;
                }
            }
            let tmp = root.join(layer_id).join(kind.subdir_name()).join("tmp");
            fs::create_dir_all(&tmp).expect("create overlay fixture tmp/");
            for d in dotdirs {
                let dotdir = tmp.join(d);
                fs::create_dir_all(&dotdir).expect("create dotdir");
                File::create(dotdir.join("seed.txt")).expect("create seed file");
            }
        }
        PathBuf::from(layer_id)
    }

    fn overlay_cfg(enabled: bool, maxdepth: usize, dotdir_only: bool) -> OverlayScanConfig {
        OverlayScanConfig {
            enabled,
            roots: vec![],
            maxdepth,
            dotdir_only,
        }
    }

    // ADR-0002 § 9 test 1: `.r.rpk/` in `diff/tmp/` is found.
    #[test]
    fn overlay_walk_finds_dotdir_in_diff() {
        let tmp = TempDir::new("overlay_diff");
        let layer_id = make_overlay_fixture(
            tmp.path(),
            "abc123",
            Some(LayerKind::Diff),
            &[".r.rpk"],
        );

        let roots = vec![tmp.path().to_path_buf()];
        let candidates = walk_all_overlays(&roots, 3, true, &Allowlist::empty());

        assert!(
            candidates.iter().any(|c| {
                c.path.ends_with(".r.rpk")
                    && matches!(
                        &c.source,
                        Some(CandidateSource::Overlay { layer_id: lid, kind: LayerKind::Diff })
                            if *lid == layer_id
                    )
            }),
            "expected `.r.rpk` candidate with overlay source, got {candidates:?}"
        );
    }

    // ADR-0002 § 9 test 2: same, in `merged/tmp/` (live container case).
    #[test]
    fn overlay_walk_finds_dotdir_in_merged() {
        let tmp = TempDir::new("overlay_merged");
        let layer_id = make_overlay_fixture(
            tmp.path(),
            "def456",
            Some(LayerKind::Merged),
            &[".xdiag"],
        );

        let roots = vec![tmp.path().to_path_buf()];
        let candidates = walk_all_overlays(&roots, 3, true, &Allowlist::empty());

        assert!(
            candidates.iter().any(|c| {
                c.path.ends_with(".xdiag")
                    && matches!(
                        &c.source,
                        Some(CandidateSource::Overlay { layer_id: lid, kind: LayerKind::Merged })
                            if *lid == layer_id
                    )
            }),
            "expected `.xdiag` candidate with overlay source Merged, got {candidates:?}"
        );
    }

    // ADR-0002 § 9 test 3: `dotdir_only: true` skips non-dot entries.
    #[test]
    fn overlay_walk_skips_nondotdir() {
        let tmp = TempDir::new("overlay_skip_nondot");
        make_overlay_fixture(
            tmp.path(),
            "lyr",
            Some(LayerKind::Diff),
            &["sess_1234", ".X11-unix", "systemd-private-xyz"],
        );

        let roots = vec![tmp.path().to_path_buf()];
        let candidates = walk_all_overlays(&roots, 3, true, &Allowlist::empty());

        let basenames: Vec<String> = candidates
            .iter()
            .filter_map(|c| {
                c.path.file_name().map(|s| s.to_string_lossy().into_owned())
            })
            .collect();

        for forbidden in ["sess_1234", ".X11-unix", "systemd-private-xyz"] {
            assert!(
                !basenames.iter().any(|b| b == forbidden),
                "non-dotdir {forbidden} must be skipped under dotdir_only=true, got {basenames:?}"
            );
        }
    }

    // ADR-0002 § 9 test 4: missing overlay_scan_roots does not crash.
    #[test]
    fn overlay_walk_handles_missing_root() {
        let bogus_root = std::env::temp_dir().join("demon_overlay_definitely_missing_99999");
        let _ = fs::remove_dir_all(&bogus_root);

        let roots = vec![bogus_root.clone()];
        let candidates = walk_all_overlays(&roots, 3, true, &Allowlist::empty());

        assert!(
            candidates.is_empty(),
            "missing root must produce empty candidates, got {candidates:?}"
        );
    }

    // ADR-0002 § 9 test 5: permission-denied layer is skipped;
    // sibling layers still scanned.
    #[test]
    fn overlay_walk_handles_unreadable_layer() {
        let tmp = TempDir::new("overlay_unreadable_layer");

        make_overlay_fixture(tmp.path(), "good-layer", Some(LayerKind::Diff), &[".r.rpk"]);
        make_overlay_fixture(tmp.path(), "bad-layer", Some(LayerKind::Diff), &[".xdiag"]);

        let bad_layer = tmp.path().join("bad-layer");
        fs::set_permissions(&bad_layer, fs::Permissions::from_mode(0o000))
            .expect("chmod 000 on bad-layer");
        // Restoring 0o700 must happen via a path that does not
        // require read perm; `chmod` itself only requires the
        // caller to own the inode. Best-effort restore so TempDir
        // Drop can recursively clean up.
        let restore = || {
            let _ = fs::set_permissions(&bad_layer, fs::Permissions::from_mode(0o755));
        };

        let roots = vec![tmp.path().to_path_buf()];
        let candidates = walk_all_overlays(&roots, 3, true, &Allowlist::empty());
        restore();

        assert!(
            candidates.iter().any(|c| c.path.to_string_lossy().contains("good-layer")),
            "expected good-layer candidate, got {candidates:?}"
        );
        assert!(
            !candidates.iter().any(|c| c.path.to_string_lossy().contains("bad-layer")),
            "bad-layer must be skipped (permission denied), got {candidates:?}"
        );
    }

    // ADR-0002 § 9 test 6: overlay_quarantine chmods the path and
    // is idempotent on re-run.
    #[test]
    fn overlay_quarantine_chmods_path() {
        let tmp = TempDir::new("overlay_quarantine");
        let target = tmp.path().join(".r.rpk");
        fs::create_dir_all(&target).expect("create dotdir");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("chmod 0o755");

        let candidate = Candidate {
            path: target.clone(),
            entries: Vec::new(),
            skipped_reason: None,
            source: Some(CandidateSource::Overlay {
                layer_id: "test-layer".to_string(),
                kind: LayerKind::Diff,
            }),
        };

        let first = overlay_quarantine(&candidate);
        let mode_after_first = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        let second = overlay_quarantine(&candidate);
        let mode_after_second = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o755));

        assert_eq!(first, QuarantineOutcome::Applied);
        assert_eq!(mode_after_first, 0o000);
        assert_eq!(second, QuarantineOutcome::AlreadyQuarantined);
        assert_eq!(mode_after_second, 0o000);
    }

    // ADR-0002 § 9 test 7: src/overlay.rs does not reference any
    // docker-sock / container-runtime primitive. This test is
    // intentionally a static string scan; it fails CI if the
    // forbidden tokens reappear in this module's runtime code.
    //
    // The scan is restricted to the source above `#[cfg(test)]`
    // so the test's own forbidden-token literals do not match
    // themselves when `include_str!("overlay.rs")` embeds the
    // whole file.
    #[test]
    fn overlay_module_does_not_open_docker_sock() {
        let src = include_str!("overlay.rs");
        let code_only = src.split("#[cfg(test)]").next().unwrap_or(src);
        let forbidden = [
            "/var/run/docker.sock",
            "DOCKER_HOST",
            "bollard",
            "use docker",
        ];
        let lower = code_only.to_lowercase();
        for needle in &forbidden {
            assert!(
                !lower.contains(&needle.to_lowercase()),
                "src/overlay.rs runtime code references forbidden token: {needle}"
            );
        }
    }

    // ADR-0002 § 9 test 8: walk_overlay returns candidates without
    // applying chmod. This is the unit-level guarantee that
    // `walk_overlay` is read-only; the runtime-level dry-run
    // guarantee is covered by `tests/smoke.rs::dry_run_succeeds_...`
    // plus the runtime `quarantine_on_ioc_match = false` override.
    #[test]
    fn overlay_walk_does_not_quarantine_path() {
        let tmp = TempDir::new("overlay_no_quarantine");
        make_overlay_fixture(tmp.path(), "lyr", Some(LayerKind::Diff), &[".r.rpk"]);

        let target_dotdir = tmp
            .path()
            .join("lyr")
            .join("diff")
            .join("tmp")
            .join(".r.rpk");
        fs::set_permissions(&target_dotdir, fs::Permissions::from_mode(0o755))
            .expect("pre-chmod 0o755");

        let roots = vec![tmp.path().to_path_buf()];
        let _ = walk_all_overlays(&roots, 3, true, &Allowlist::empty());

        let mode = fs::metadata(&target_dotdir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "walk_overlay must not chmod path; expected 0o755, got {mode:o}"
        );
    }

    // ADR-0002 § 9 test 9: when overlay_scan is disabled at the
    // config layer, the walker produces no overlay candidates even
    // if the roots are present.
    #[test]
    fn overlay_disabled_returns_no_candidates() {
        let tmp = TempDir::new("overlay_disabled");
        make_overlay_fixture(tmp.path(), "lyr", Some(LayerKind::Diff), &[".r.rpk"]);

        let cfg = overlay_cfg(false, 3, true);
        let candidates = if cfg.enabled {
            walk_all_overlays(
                &cfg.roots,
                cfg.maxdepth,
                cfg.dotdir_only,
                &Allowlist::empty(),
            )
        } else {
            Vec::new()
        };

        assert!(
            candidates.is_empty(),
            "disabled overlay scan must yield no candidates, got {candidates:?}"
        );
    }

    // ADR-0002 § 9 test 10: maxdepth=0 yields no candidates
    // (walk_overlay returns at depth zero; no descent).
    #[test]
    fn overlay_inv6_maxdepth_enforced() {
        let tmp = TempDir::new("overlay_maxdepth_zero");
        make_overlay_fixture(tmp.path(), "lyr", Some(LayerKind::Diff), &[".r.rpk"]);

        let roots = vec![tmp.path().to_path_buf()];
        let candidates = walk_all_overlays(&roots, 0, true, &Allowlist::empty());

        assert!(
            candidates.is_empty(),
            "maxdepth=0 must yield zero candidates, got {candidates:?}"
        );
    }
}
