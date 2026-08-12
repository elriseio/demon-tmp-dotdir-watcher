#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tracing::warn;

use crate::allowlist::Allowlist;
use crate::config::Config;
use crate::ioc::{hash_file, Matcher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub entries: Vec<PathBuf>,
    pub skipped_reason: Option<SkipReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    TooManyFiles(usize),
    IoError(String),
    Timeout,
}

/// AR-005: outcome of the idempotent `chmod 000` quarantine side
/// effect (ARCHITECTURE.md invariant 7 — quarantine is reversible).
///
/// Privacy: the `Failed(String)` payload is the io::Error's own
/// formatted message and does not include the path; the path is
/// logged via `tracing::warn!` separately so the return value is
/// safe to surface in operator-facing contexts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    Applied,
    AlreadyQuarantined,
    Failed(String),
}

/// AR-005: apply `chmod 000` to `path` as the IOC-match side effect.
///
/// Idempotent: re-invocation against a path that is already mode
/// `0o000` returns `AlreadyQuarantined` without a syscall beyond
/// the pre-check `metadata()`. Failure paths return
/// `Failed(io::Error.to_string())` and emit a `warn!` log line;
/// no panic, per ARCHITECTURE.md invariant 5 (failures are loud,
/// not crash-inducing).
pub fn quarantine(path: &Path) -> QuarantineOutcome {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if meta.permissions().mode() & 0o777 == 0o000 {
                return QuarantineOutcome::AlreadyQuarantined;
            }
        }
        Err(e) => {
            warn!(
                "subsystem: quarantine pre-check failed for {}: {e}",
                path.display()
            );
            return QuarantineOutcome::Failed(e.to_string());
        }
    }

    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)) {
        Ok(()) => QuarantineOutcome::Applied,
        Err(e) => {
            warn!(
                "subsystem: quarantine set_permissions failed for {}: {e}",
                path.display()
            );
            QuarantineOutcome::Failed(e.to_string())
        }
    }
}

/// AR-005: per-candidate decision emitted by the walk pipeline so
/// AR-006 (journal + NTFY) and AR-008 (runtime wiring) can act on
/// each candidate without re-classifying.
///
/// Precedence (highest first):
///   1. `Skipped(reason)` — the walk itself marked the candidate
///      as over-budget or unreadable; downstream consumers log the
///      reason and continue.
///   2. `Allowlisted` — basename matches a glob in the loaded
///      `Allowlist`.
///   3. `IocMatch` — at least one entry file's SHA-256 is in the
///      `Matcher` set (the side-effect trigger for `quarantine`).
///   4. `Unknown` — none of the above; AR-006 decides whether to
///      alert based on `cfg.actions.alert_on_unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowlisted,
    IocMatch { sha256: String },
    Unknown,
    Skipped(SkipReason),
}

/// AR-005: classify every candidate produced by `walk` so
/// downstream consumers (AR-006 journal, AR-008 runtime) get a
/// ready-to-act tuple without re-walking or re-hashing.
///
/// This is the data shape AR-006 consumes. Quarantine side
/// effects are NOT triggered here; the integration wiring that
/// turns `Decision::IocMatch` into `quarantine()` calls lives in
/// AR-008.
pub fn walk_decision_pipeline(
    candidates: Vec<Candidate>,
    matcher: &Matcher,
    allowlist: &Allowlist,
) -> Vec<(Candidate, Decision)> {
    candidates
        .into_iter()
        .map(|c| {
            let decision = classify(&c, matcher, allowlist);
            (c, decision)
        })
        .collect()
}

fn classify(c: &Candidate, matcher: &Matcher, allowlist: &Allowlist) -> Decision {
    if let Some(reason) = &c.skipped_reason {
        return Decision::Skipped(reason.clone());
    }

    if let Some(basename) = c.path.file_name().and_then(|s| s.to_str()) {
        if allowlist.allows(basename) {
            return Decision::Allowlisted;
        }
    }

    for entry in &c.entries {
        match hash_file(entry) {
            Ok(h) => {
                if matcher.contains(&h) {
                    return Decision::IocMatch { sha256: h };
                }
            }
            Err(e) => warn!("subsystem: hash_file failed for {}: {e}", entry.display()),
        }
    }

    Decision::Unknown
}

pub fn walk(cfg: &Config) -> Vec<Candidate> {
    let mut out = Vec::with_capacity(cfg.paths.scan_roots.len());
    let window = Duration::from_secs(cfg.paths.scan_window_minutes as u64 * 60);
    let now = SystemTime::now();
    let max_depth = cfg.paths.scan_maxdepth;
    let max_files = cfg.allowlist.max_files_per_dir;

    for root in &cfg.paths.scan_roots {
        walk_recursive(root, 0, max_depth, &window, now, max_files, &mut out);
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn walk_recursive(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    window: &Duration,
    now: SystemTime,
    max_files: usize,
    out: &mut Vec<Candidate>,
) {
    let basename = match dir.file_name().and_then(|s| s.to_str()) {
        Some(b) => b.to_string(),
        None => return,
    };

    let is_dotdir = basename.starts_with('.');
    let mtime_result = if is_dotdir {
        Some(dir.metadata().and_then(|m| m.modified()))
    } else {
        None
    };

    if let Some(result) = mtime_result {
        match result {
            Ok(t) => {
                let within = now.duration_since(t).map(|d| d <= *window).unwrap_or(false);
                if within {
                    let (entries, skipped) = collect_entries(dir, max_files);
                    out.push(Candidate {
                        path: dir.to_path_buf(),
                        entries,
                        skipped_reason: skipped,
                    });
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "subsystem: stat failed for candidate {}: {e}",
                    dir.display()
                );
                out.push(Candidate {
                    path: dir.to_path_buf(),
                    entries: Vec::new(),
                    skipped_reason: Some(SkipReason::IoError(e.to_string())),
                });
                return;
            }
        }
    }

    if depth >= max_depth {
        return;
    }

    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warn!("subsystem: read_dir failed for {}: {e}", dir.display());
            return;
        }
    };

    for entry in read {
        match entry {
            Ok(e) => {
                let p = e.path();
                if p.is_dir() {
                    walk_recursive(&p, depth + 1, max_depth, window, now, max_files, out);
                }
            }
            Err(e) => warn!("subsystem: read_dir entry error at {}: {e}", dir.display()),
        }
    }
}

fn collect_entries(dir: &Path, max_files: usize) -> (Vec<PathBuf>, Option<SkipReason>) {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                "subsystem: collect_entries read_dir failed for {}: {e}",
                dir.display()
            );
            return (
                Vec::new(),
                Some(SkipReason::IoError(format!("entries readdir: {e}"))),
            );
        }
    };

    let mut all: Vec<PathBuf> = Vec::new();
    for entry in read {
        match entry {
            Ok(e) => {
                let p = e.path();
                if p.is_file() {
                    all.push(p);
                }
            }
            Err(e) => warn!(
                "subsystem: collect_entries entry error at {}: {e}",
                dir.display()
            ),
        }
    }

    let total = all.len();
    all.sort();
    all.truncate(max_files);

    let skipped = if total > max_files {
        Some(SkipReason::TooManyFiles(total))
    } else {
        None
    };

    (all, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::Allowlist;
    use crate::config::{
        ActionsConfig, AllowlistConfig, Config, IocConfig, LogConfig, PathsConfig, RuntimeConfig,
    };
    use crate::ioc::{hash_file, Matcher};
    use crate::test_util::{TempDir, TempFile};
    use std::fs::{self, File};
    use std::path::PathBuf;

    fn set_mtime(path: &Path, t: SystemTime) {
        let f =
            File::open(path).unwrap_or_else(|e| panic!("open {} for mtime: {e}", path.display()));
        f.set_modified(t)
            .unwrap_or_else(|e| panic!("set_modified {}: {e}", path.display()));
    }

    fn make_config(
        roots: Vec<PathBuf>,
        max_depth: usize,
        window_min: u32,
        max_files: usize,
    ) -> Config {
        Config {
            log: LogConfig {
                level: "info".to_string(),
            },
            runtime: RuntimeConfig {
                shutdown_timeout_sec: 30,
            },
            paths: PathsConfig {
                scan_roots: roots,
                scan_maxdepth: max_depth,
                scan_window_minutes: window_min,
            },
            ioc: IocConfig {
                ioc_list: PathBuf::from("/dev/null"),
                ioc_archive_ref: None,
                proposed_iocs: None,
            },
            allowlist: AllowlistConfig {
                allowlist: PathBuf::from("/dev/null"),
                max_files_per_dir: max_files,
            },
            actions: ActionsConfig {
                quarantine_on_ioc_match: false,
                alert_on_unknown: false,
            },
        }
    }

    #[test]
    fn walk_returns_only_dotdirs_within_window() {
        let tmp = TempDir::new("window");
        let root = tmp.path();

        for name in [".alpha", ".beta", ".gamma"] {
            fs::create_dir_all(root.join(name)).unwrap();
        }
        set_mtime(&root.join(".beta"), SystemTime::UNIX_EPOCH);

        let cfg = make_config(vec![root.to_path_buf()], 3, 60, 10);
        let result = walk(&cfg);

        let basenames: Vec<String> = result
            .iter()
            .map(|c| {
                c.path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(basenames, vec![".alpha".to_string(), ".gamma".to_string()]);
        for c in &result {
            assert!(c.skipped_reason.is_none());
            assert!(c.entries.is_empty());
        }
    }

    #[test]
    fn walk_marks_too_many_files() {
        let tmp = TempDir::new("toomany");
        let root = tmp.path();
        let target = root.join(".target");
        fs::create_dir_all(&target).unwrap();
        for i in 0..5 {
            File::create(target.join(format!("f{i}"))).unwrap();
        }

        let cfg = make_config(vec![root.to_path_buf()], 3, 60, 2);
        let result = walk(&cfg);

        assert_eq!(result.len(), 1);
        let c = &result[0];
        assert_eq!(
            c.path.file_name().map(|s| s.to_string_lossy().into_owned()),
            Some(".target".to_string())
        );
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.skipped_reason, Some(SkipReason::TooManyFiles(5)));
        let names: Vec<String> = c
            .entries
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn walk_respects_scan_maxdepth_one() {
        let tmp = TempDir::new("depth");
        let root = tmp.path();
        let top = root.join(".top");
        fs::create_dir_all(&top).unwrap();
        let nested = top.join(".nested");
        fs::create_dir_all(&nested).unwrap();
        File::create(root.join("regular")).unwrap();
        File::create(nested.join("inside")).unwrap();

        let cfg = make_config(vec![root.to_path_buf()], 1, 60, 10);
        let result = walk(&cfg);

        let basenames: Vec<String> = result
            .iter()
            .map(|c| {
                c.path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(basenames, vec![".top".to_string()]);
    }

    #[test]
    fn walk_sorts_candidates_by_path() {
        let tmp = TempDir::new("sort");
        let root = tmp.path();
        fs::create_dir_all(root.join(".zeta")).unwrap();
        fs::create_dir_all(root.join(".alpha")).unwrap();
        fs::create_dir_all(root.join(".mu")).unwrap();

        let cfg = make_config(vec![root.to_path_buf()], 3, 60, 10);
        let result = walk(&cfg);

        let basenames: Vec<String> = result
            .iter()
            .map(|c| {
                c.path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(
            basenames,
            vec![".alpha".to_string(), ".mu".to_string(), ".zeta".to_string(),]
        );
    }

    #[test]
    fn walk_handles_unreadable_scan_root() {
        let cfg = make_config(
            vec![PathBuf::from("/this/path/does/not/exist/subsystem_ar_002")],
            3,
            60,
            10,
        );
        let result = walk(&cfg);
        assert!(result.is_empty());
    }

    #[test]
    fn walk_survives_broken_symlink_in_scan_root() {
        // Walker must not panic on broken symlinks inside the scan
        // root. chmod-000 is unreliable in CI containers (the process
        // usually runs as root), so broken symlinks serve as a stable
        // stand-in for "per-entry iterator weirdness": they survive
        // read_dir (the entry itself is Ok) but cause downstream
        // metadata operations to fail, exercising the same warn-on-err
        // path that the flatten() → match refactor opened up.
        let tmp = TempDir::new("broken_symlink");
        let root = tmp.path();
        let dotdir = root.join(".target");
        fs::create_dir_all(&dotdir).unwrap();
        std::os::unix::fs::symlink("/this/path/does/not/exist/broken_link", dotdir.join("link"))
            .unwrap();

        let cfg = make_config(vec![root.to_path_buf()], 3, 60, 10);
        let result = walk(&cfg);

        assert!(result.iter().any(|c| {
            c.path.file_name().map(|s| s.to_string_lossy().into_owned())
                == Some(".target".to_string())
        }));
        for c in &result {
            assert!(c.skipped_reason.is_none());
        }
    }

    fn restore_mode_for_cleanup(path: &Path) {
        // Best-effort restore so the TempDir Drop can remove the
        // tree even if the test asserts after chmod-000.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    }

    #[test]
    fn quarantine_applies_to_directory() {
        let tmp = TempDir::new("quarantine_applies");
        let target = tmp.path().join(".target");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();

        let outcome = quarantine(&target);
        // Read the mode BEFORE restoring — once restored to 0o755
        // the assertion would be meaningless.
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        restore_mode_for_cleanup(&target);

        assert_eq!(outcome, QuarantineOutcome::Applied);
        // metadata() does not require traversal; the mode read on
        // a 0o000 directory succeeds even without read perms on
        // the directory itself (Linux semantics: metadata read
        // needs read perm on the parent directory, not the
        // directory being inspected).
        assert_eq!(mode, 0o000);
    }

    #[test]
    fn quarantine_idempotent() {
        let tmp = TempDir::new("quarantine_idempotent");
        let target = tmp.path().join(".target");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();

        let first = quarantine(&target);
        let second = quarantine(&target);
        restore_mode_for_cleanup(&target);

        assert_eq!(first, QuarantineOutcome::Applied);
        assert_eq!(second, QuarantineOutcome::AlreadyQuarantined);
    }

    #[test]
    fn quarantine_handles_missing_path() {
        // Path that does not exist and never did for this test
        // run. metadata() returns NotFound → Failed, no panic.
        let bogus = std::env::temp_dir().join(format!(
            "demon_quarantine_missing_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_file(&bogus);

        let outcome = quarantine(&bogus);
        match outcome {
            QuarantineOutcome::Failed(msg) => {
                assert!(
                    !msg.is_empty(),
                    "Failed payload must carry a non-empty error string"
                );
            }
            other => panic!("expected Failed for missing path, got {other:?}"),
        }
    }

    #[test]
    fn walk_decision_pipeline_classifies_three_candidates() {
        // Three subdirs in one tempdir, each engineered to land
        // in a different Decision branch:
        //   .allowed  — basename matches the allowlist glob
        //   .ioc      — one entry whose SHA-256 is in the Matcher
        //   .unknown  — entries whose SHA-256 is NOT in the Matcher
        let tmp = TempDir::new("decision_pipeline");
        let root = tmp.path();

        fs::create_dir_all(root.join(".allowed")).unwrap();

        let ioc_dir = root.join(".ioc");
        fs::create_dir_all(&ioc_dir).unwrap();
        let ioc_payload: &[u8] = b"azazel-trunk-content-for-ar-005-decision-test\n";
        fs::write(ioc_dir.join("trunk.bin"), ioc_payload).unwrap();
        let ioc_hash = hash_file(&ioc_dir.join("trunk.bin")).expect("hash ioc payload");

        let unknown_dir = root.join(".unknown");
        fs::create_dir_all(&unknown_dir).unwrap();
        let unknown_payload: &[u8] = b"plain hello, no malware here\n";
        fs::write(unknown_dir.join("a.txt"), unknown_payload).unwrap();
        let unknown_hash = hash_file(&unknown_dir.join("a.txt")).expect("hash unknown");
        assert_ne!(ioc_hash, unknown_hash, "fixture hashes must differ");

        // Matcher with exactly the IOC hash.
        let ioc_list = TempFile::with_content("decision_ioc_list", ioc_hash.as_bytes());
        let matcher = Matcher::load(ioc_list.path()).expect("load matcher");
        assert!(matcher.contains(&ioc_hash));
        assert!(!matcher.contains(&unknown_hash));

        // Allowlist that lets ".allowed" through and nothing else.
        let allowlist_file = TempFile::with_content("decision_allowlist", b".allowed\n");
        let allowlist = Allowlist::load(allowlist_file.path()).expect("load allowlist");
        assert!(allowlist.allows(".allowed"));
        assert!(!allowlist.allows(".ioc"));
        assert!(!allowlist.allows(".unknown"));

        let candidates = vec![
            Candidate {
                path: root.join(".allowed"),
                entries: Vec::new(),
                skipped_reason: None,
            },
            Candidate {
                path: ioc_dir.clone(),
                entries: vec![ioc_dir.join("trunk.bin")],
                skipped_reason: None,
            },
            Candidate {
                path: unknown_dir.clone(),
                entries: vec![unknown_dir.join("a.txt")],
                skipped_reason: None,
            },
            // Skipped candidate: precedence check — Skipped wins
            // over Allowlisted.
            Candidate {
                path: root.join(".allowed"),
                entries: Vec::new(),
                skipped_reason: Some(SkipReason::TooManyFiles(99)),
            },
        ];

        let decisions = walk_decision_pipeline(candidates, &matcher, &allowlist);
        assert_eq!(decisions.len(), 4);

        let (c0, d0) = &decisions[0];
        assert_eq!(
            c0.path.file_name().and_then(|s| s.to_str()),
            Some(".allowed")
        );
        assert_eq!(*d0, Decision::Allowlisted);

        let (c1, d1) = &decisions[1];
        assert_eq!(c1.path.file_name().and_then(|s| s.to_str()), Some(".ioc"));
        assert!(
            matches!(d1, Decision::IocMatch { sha256 } if *sha256 == ioc_hash),
            "expected IocMatch variant carrying ioc_hash, got {d1:?}",
        );

        let (c2, d2) = &decisions[2];
        assert_eq!(
            c2.path.file_name().and_then(|s| s.to_str()),
            Some(".unknown")
        );
        assert_eq!(*d2, Decision::Unknown);

        let (c3, d3) = &decisions[3];
        assert_eq!(
            c3.path.file_name().and_then(|s| s.to_str()),
            Some(".allowed")
        );
        assert_eq!(*d3, Decision::Skipped(SkipReason::TooManyFiles(99)));
    }
}
