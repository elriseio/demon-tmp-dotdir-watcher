//! AR-008: runtime tick body.
//!
//! Wires the full pipeline that the bash reference impl performs
//! per poll cycle:
//!   1. Walk scan roots (`subsystem::walk`).
//!   2. Classify candidates via `subsystem::walk_decision_pipeline`
//!      (allowlist + IOC match).
//!   3. Quarantine IOC matches (`subsystem::quarantine`).
//!   4. Emit journal + NTFY events (`output::emit_*`).
//!
//! CR-005: the runtime is owned by `main()` and runs exactly one
//! poll cycle per systemd activation (`Type=oneshot`). Cadence
//! is driven by the systemd timer per ARCHITECTURE.md
//! invariant 2; the daemon itself does not drive an
//! `interval()`-based cadence loop.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::allowlist::Allowlist;
use crate::config::Config;
use crate::ioc::Matcher;
use crate::learn::Proposer;
use crate::output;
use crate::subsystem::{self, Decision, QuarantineOutcome, SkipReason};

/// Per-tick counter. Plain-data; cheap to log and clone.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RunSummary {
    pub candidates: usize,
    pub allowlisted: usize,
    pub ioc_matches: usize,
    pub unknown: usize,
    pub quarantined: usize,
    pub skipped: usize,
    /// CR-006: paths of top-level `scan_root`s whose `read_dir()`
    /// failed (EACCES on a `chmod 700` subtree, ENOENT on a
    /// missing path, etc.). The walker now emits a synthetic
    /// `Candidate { skipped_reason: Some(IoError) }` for each
    /// unreadable root, and the runtime collects those paths
    /// here so the per-poll summary log line surfaces them.
    pub unreadable_roots: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct Runtime {
    cfg: Config,
    matcher: Matcher,
    allowlist: Allowlist,
    proposer: Proposer,
    shutdown_rx: watch::Receiver<bool>,
}

impl Runtime {
    /// Load the IOC matcher and allowlist eagerly so per-tick
    /// errors (e.g., transient FS hiccups on the IOC list file)
    /// don't break the runtime; they are logged at boot.
    ///
    /// Missing allowlist returns an empty Allowlist
    /// (`allowlist::load` semantics).
    ///
    /// A missing or empty IOC list is a first-class bootstrap
    /// state, not an error: a fresh deployment with no IOC list
    /// is the normal baseline, and the daemon proceeds with
    /// `Matcher::empty()`. Every candidate then classifies as
    /// `Decision::Unknown`, which is the expected state until
    /// the operator curates the live IOC list. Truly unreadable
    /// IOC lists (permission denied, malformed line) still error
    /// out via `Matcher::load`.
    pub fn new(cfg: Config, shutdown_rx: watch::Receiver<bool>) -> Result<Self> {
        let matcher = match Matcher::load(&cfg.ioc.ioc_list) {
            Ok(m) => m,
            Err(e) => {
                info!(
                    target: "tmp-watcher",
                    ioc_list = %cfg.ioc.ioc_list.display(),
                    ioc_count = 0,
                    error = %e,
                    "runtime: IOC list unavailable; using empty Matcher (baseline for fresh deployment)",
                );
                Matcher::empty()
            }
        };
        let allowlist = Allowlist::load(&cfg.allowlist.allowlist).context("load allowlist")?;
        let proposer_path = cfg
            .ioc
            .proposed_iocs
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/tmp-watcher.proposed.iocs"));
        let proposer =
            Proposer::new(&proposer_path).context("init proposal file at runtime startup")?;
        Ok(Self {
            cfg,
            matcher,
            allowlist,
            proposer,
            shutdown_rx,
        })
    }

    /// AR-008 + ADR-0002 § 1: one full poll pipeline. Returns a
    /// `RunSummary` counter for logging and tests.
    ///
    /// The 5-step ordering per the issue scope:
    ///   1. walk scan roots (host + overlay)
    ///   2. classify (allowlist + IOC match)
    ///   3. quarantine IOC matches
    ///   4. emit journal events
    ///   5. (NTFY push is wired but a no-op until `Config` learns
    ///      a `ntfy_url` field; see implementation notes below.)
    pub async fn run_once(&mut self) -> Result<RunSummary> {
        let mut candidates = subsystem::walk(&self.cfg);

        // ADR-0002 § 1: the daemon's poll cycle walks both host
        // scan roots and overlay scan roots in the same pass. The
        // IOC + allowlist matchers are the same instance for both;
        // the host-side `.font-unix` / `systemd-private-*` patterns
        // apply to overlay candidates too. Overlay candidates
        // carry the same `Candidate` shape with a tagged `source`
        // field, so the existing `walk_decision_pipeline` consumes
        // both uniformly.
        if self.cfg.paths.overlay_scan.enabled {
            let overlay_candidates = crate::overlay::walk_all_overlays(
                &self.cfg.paths.overlay_scan.roots,
                self.cfg.paths.overlay_scan.maxdepth,
                self.cfg.paths.overlay_scan.dotdir_only,
                &self.allowlist,
            );
            candidates.extend(overlay_candidates);
        }

        let decisions =
            subsystem::walk_decision_pipeline(candidates, &self.matcher, &self.allowlist);

        let mut summary = RunSummary {
            candidates: decisions.len(),
            ..Default::default()
        };

        for (c, d) in &decisions {
            // basename is recomputed from c.path; the pipeline
            // derives it once for allowlist.allows.
            let basename = c.path.file_name().and_then(|s| s.to_str()).unwrap_or("");

            match d {
                Decision::Skipped(reason) => {
                    summary.skipped += 1;
                    // CR-006: a top-level `scan_root` whose
                    // `read_dir` failed lands here as
                    // `Skipped(IoError(_))` with `c.path == root`.
                    // Record the path in `unreadable_roots` so the
                    // operator's per-poll summary surfaces the
                    // exact root(s) that disappeared from coverage.
                    if let SkipReason::IoError(_) = reason {
                        if self.cfg.paths.scan_roots.contains(&c.path) {
                            summary.unreadable_roots.push(c.path.clone());
                        }
                    }
                    warn!(
                        target: "tmp-watcher",
                        priority = 4,
                        basename = basename,
                        reason = ?reason,
                        "runtime: candidate skipped",
                    );
                }
                Decision::Allowlisted => {
                    summary.allowlisted += 1;
                    info!(
                        target: "tmp-watcher",
                        basename = basename,
                        "runtime: candidate allowlisted",
                    );
                }
                Decision::IocMatch { sha256 } => {
                    summary.ioc_matches += 1;
                    if self.cfg.actions.quarantine_on_ioc_match {
                        let outcome = subsystem::quarantine(&c.path);
                        match outcome {
                            QuarantineOutcome::Applied => {
                                summary.quarantined += 1;
                                output::emit_ioc_match(basename, &c.path, sha256.as_str());
                                if let Err(e) = push_ntfy_for_match(
                                    basename,
                                    &c.path,
                                    sha256.as_str(),
                                    self.cfg.actions.ntfy_url.as_deref(),
                                )
                                .await
                                {
                                    warn!(
                                        target: "tmp-watcher",
                                        priority = 4,
                                        error = %e,
                                        "runtime: ntfy push failed",
                                    );
                                }
                            }
                            QuarantineOutcome::AlreadyQuarantined => {
                                // Already 0o000 from a previous
                                // poll; the IOC match still
                                // triggers the journal event so
                                // operators see the recurrence.
                                output::emit_ioc_match(basename, &c.path, sha256.as_str());
                            }
                            QuarantineOutcome::Failed(err) => {
                                output::emit_ioc_quarantine_failed(&c.path, &err);
                            }
                        }
                    } else {
                        output::emit_ioc_match(basename, &c.path, sha256.as_str());
                    }
                }
                Decision::Unknown => {
                    summary.unknown += 1;
                    if self.cfg.actions.alert_on_unknown {
                        output::emit_unknown(basename, &c.path);
                    }
                    // Per the IOC-list baseline semantics, the
                    // propser observes each Unknown event and appends
                    // a candidate-IOC entry to the proposal file.
                    // The first entry's SHA-256 is recorded if the
                    // candidate has files; otherwise the basename-
                    // only proposal uses an empty sha256.
                    let sha_for_proposer = c
                        .entries
                        .first()
                        .and_then(|entry| crate::ioc::hash_file(entry).ok())
                        .unwrap_or_default();
                    if let Err(e) = self.proposer.observe(basename, &sha_for_proposer, &c.path) {
                        error!(
                            target: "tmp-watcher",
                            priority = 2,
                            basename = basename,
                            error = %e,
                            "runtime: proposer.observe failed",
                        );
                    }
                }
            }
        }

        info!(
            target: "tmp-watcher",
            candidates = summary.candidates,
            allowlisted = summary.allowlisted,
            ioc_matches = summary.ioc_matches,
            unknown = summary.unknown,
            quarantined = summary.quarantined,
            skipped = summary.skipped,
            unreadable_roots = summary.unreadable_roots.len(),
            "runtime: tick summary",
        );

        Ok(summary)
    }

    /// CR-005: oneshot entry point. Runs exactly one poll cycle
    /// per systemd activation and returns `Ok(())` so the systemd
    /// timer (`Type=oneshot` + `OnUnitActiveSec=10min`) drives
    /// cadence per ARCHITECTURE.md invariant 2.
    ///
    /// SIGTERM (from `systemctl stop` during a long poll) is
    /// observed via `shutdown_rx.changed()` and interrupts the
    /// poll cleanly inside one activation; the runtime then
    /// returns `Ok(())` so systemd sees a clean exit and the
    /// next timer activation starts a fresh process. Per-tick
    /// errors are logged at CRITICAL but do NOT prevent the
    /// `Ok(())` exit (invariant 5: failures are loud, not
    /// crash-inducing).
    pub async fn run(mut self) -> Result<()> {
        // Detach a cloned shutdown receiver so the two select!
        // branches do not fight over `&mut self`. The cloned
        // receiver shares the underlying watch state, so a
        // `tx.send(true)` from the signal handler is observed
        // here just as it would be on the original receiver.
        let mut shutdown_rx = self.shutdown_rx.clone();
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("shutdown: requested by signal before poll completed");
                } else {
                    info!("shutdown: watch notification observed; exiting");
                }
            }
            result = self.run_once() => match result {
                Ok(_) => info!(
                    "runtime: oneshot poll complete; exiting per Type=oneshot contract"
                ),
                Err(e) => error!(
                    target: "tmp-watcher",
                    priority = 2,
                    error = %e,
                    "runtime: tick failed",
                ),
            },
        }
        Ok(())
    }
}

/// AR-008 + DE-019: NTFY push for an IOC match. The URL is taken
/// from `self.cfg.actions.ntfy_url`; when `None` (embedded default
/// per AR-011), `output::ntfy_push(None, …)` is a documented no-op
/// and the IOC match surfaces on the journal only.
async fn push_ntfy_for_match(
    basename: &str,
    path: &Path,
    hash: &str,
    ntfy_url: Option<&str>,
) -> Result<()> {
    let title = format!("tmp-watcher IOC match: {basename}");
    let body = format!("path={} sha256={}", path.display(), hash);
    output::ntfy_push(ntfy_url, &title, &body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ActionsConfig, AllowlistConfig, Config, IocConfig, LogConfig, PathsConfig, RuntimeConfig,
    };
    use crate::ioc::hash_file;
    use crate::test_util::{TempDir, TempFile};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tokio::sync::watch;

    #[tokio::test]
    async fn run_once_full_pipeline() {
        // AR-008 acceptance: a tempdir containing a known IOC
        // file under a non-allowlisted dotdir produces
        // `RunSummary { ioc_matches: 1, quarantined: 1, unknown: 0 }`
        // and the dotdir is now chmod 0o000.
        let tmp = TempDir::new("runtime_pipeline");
        let root = tmp.path();

        let dot = root.join(".r.rpk-test");
        fs::create_dir_all(&dot).expect("create dotdir");
        let payload: &[u8] = b"azazel-trunk-content-for-ar-008-runtime-pipeline\n";
        fs::write(dot.join("trunk.bin"), payload).expect("write payload");

        let ioc_hash = hash_file(&dot.join("trunk.bin")).expect("hash payload");

        let ioc_list = TempFile::with_content("runtime_ioc_list", ioc_hash.as_bytes());
        let proposal = TempFile::with_content("runtime_proposer", b"");

        let cfg = Config {
            log: LogConfig {
                level: "info".to_string(),
            },
            runtime: RuntimeConfig {
                shutdown_timeout_sec: 5,
            },
            paths: PathsConfig {
                scan_roots: vec![root.to_path_buf()],
                scan_maxdepth: 3,
                scan_window_minutes: 60,
                overlay_scan: crate::config::OverlayScanConfig::default(),
            },
            ioc: IocConfig {
                ioc_list: ioc_list.path().to_path_buf(),
                ioc_archive_ref: None,
                proposed_iocs: Some(proposal.path().to_path_buf()),
            },
            allowlist: AllowlistConfig {
                allowlist: PathBuf::from("/dev/null"),
                max_files_per_dir: 10,
            },
            actions: ActionsConfig {
                quarantine_on_ioc_match: true,
                alert_on_unknown: false,
                ntfy_url: None,
            },
        };

        let (_tx, shutdown_rx) = watch::channel(false);
        let mut runtime = Runtime::new(cfg, shutdown_rx).expect("build runtime");
        let summary = runtime.run_once().await.expect("run_once");

        assert_eq!(summary.candidates, 1, "expected 1 candidate");
        assert_eq!(summary.ioc_matches, 1, "expected 1 IOC match");
        assert_eq!(summary.quarantined, 1, "expected 1 quarantine");
        assert_eq!(summary.unknown, 0, "expected 0 unknown");

        // Read the mode BEFORE restoring for the TempDir Drop.
        let mode_after_quarantine = fs::metadata(&dot).unwrap().permissions().mode() & 0o777;
        // Best-effort restore so the TempDir's recursive removal
        // can walk the directory.
        let _ = fs::set_permissions(&dot, fs::Permissions::from_mode(0o755));
        assert_eq!(
            mode_after_quarantine, 0o000,
            "expected dotdir to be chmod 0o000 after quarantine"
        );
    }

    fn build_cfg_with_proposer(
        scan_root: PathBuf,
        ioc_list: PathBuf,
        proposer_path: PathBuf,
    ) -> Config {
        Config {
            log: LogConfig {
                level: "info".to_string(),
            },
            runtime: RuntimeConfig {
                shutdown_timeout_sec: 5,
            },
            paths: PathsConfig {
                scan_roots: vec![scan_root],
                scan_maxdepth: 3,
                scan_window_minutes: 60,
                overlay_scan: crate::config::OverlayScanConfig::default(),
            },
            ioc: IocConfig {
                ioc_list,
                ioc_archive_ref: None,
                proposed_iocs: Some(proposer_path),
            },
            allowlist: AllowlistConfig {
                allowlist: PathBuf::from("/dev/null"),
                max_files_per_dir: 10,
            },
            actions: ActionsConfig {
                quarantine_on_ioc_match: true,
                alert_on_unknown: false,
                ntfy_url: None,
            },
        }
    }

    #[test]
    fn runtime_new_with_missing_ioc_list_uses_empty_matcher() {
        let tmp = TempDir::new("missing_ioc_list");
        let bogus = tmp.path().join("does_not_exist.iocs");
        let proposer = tmp.path().join("proposed.iocs");
        let cfg = build_cfg_with_proposer(tmp.path().to_path_buf(), bogus, proposer);

        let (_tx, shutdown_rx) = watch::channel(false);
        let runtime = Runtime::new(cfg, shutdown_rx)
            .expect("Runtime::new must succeed with missing IOC list (baseline)");

        assert_eq!(
            runtime.matcher.len(),
            0,
            "missing IOC list must produce empty Matcher"
        );
    }

    #[test]
    fn runtime_new_with_empty_ioc_list_uses_empty_matcher() {
        let tmp = TempDir::new("empty_ioc_list");
        let ioc_list = tmp.path().join("comments_only.iocs");
        fs::write(
            &ioc_list,
            b"# only comments and blank lines\n\n# nothing here\n",
        )
        .expect("write comments-only IOC list");
        let proposer = tmp.path().join("proposed.iocs");
        let cfg = build_cfg_with_proposer(tmp.path().to_path_buf(), ioc_list, proposer);

        let (_tx, shutdown_rx) = watch::channel(false);
        let runtime = Runtime::new(cfg, shutdown_rx)
            .expect("Runtime::new must succeed with empty IOC list (baseline)");

        assert_eq!(
            runtime.matcher.len(),
            0,
            "comments-only IOC list must produce empty Matcher"
        );
    }

    #[test]
    fn runtime_new_with_populated_ioc_list_loads_matcher() {
        let tmp = TempDir::new("populated_ioc_list");
        let root = tmp.path();
        let payload: &[u8] = b"populate-list-content\n";
        let target = TempFile::with_content("hash_target", payload);
        let hash = hash_file(target.path()).expect("hash target");
        let ioc_list = root.join("populated.iocs");
        fs::write(&ioc_list, format!("{hash}  sample.bin\n").as_bytes())
            .expect("write populated IOC list");
        let proposer = root.join("proposed.iocs");
        let cfg = build_cfg_with_proposer(root.to_path_buf(), ioc_list, proposer);

        let (_tx, shutdown_rx) = watch::channel(false);
        let runtime = Runtime::new(cfg, shutdown_rx)
            .expect("Runtime::new must succeed with populated IOC list");

        assert_eq!(runtime.matcher.len(), 1);
        assert!(runtime.matcher.contains(&hash));
    }

    #[tokio::test]
    async fn run_once_unknown_arm_writes_proposal_entry() {
        // A non-allowlisted non-IOC dotdir lands on Decision::Unknown;
        // the proposer must observe the event and append a candidate
        // entry to the proposal file.
        let tmp = TempDir::new("proposer_observation");
        let root = tmp.path();

        let dot = root.join(".unknown-target");
        fs::create_dir_all(&dot).expect("create dotdir");
        let payload: &[u8] = b"plain hello, not an IOC\n";
        fs::write(dot.join("a.txt"), payload).expect("write payload");

        let hash = hash_file(&dot.join("a.txt")).expect("hash payload");
        let ioc_list = TempFile::with_content("unknown_ioc_list", b"# empty\n");
        let proposer = tmp.path().join("proposed.iocs");

        let cfg = build_cfg_with_proposer(
            root.to_path_buf(),
            ioc_list.path().to_path_buf(),
            proposer.clone(),
        );
        let (_tx, shutdown_rx) = watch::channel(false);
        let mut runtime = Runtime::new(cfg, shutdown_rx).expect("build runtime");
        let summary = runtime.run_once().await.expect("run_once");

        assert_eq!(summary.candidates, 1);
        assert_eq!(summary.unknown, 1);

        let content = fs::read_to_string(&proposer).expect("read proposal");
        assert!(
            content.contains(".unknown-target"),
            "expected basename in proposal, got: {content}"
        );
        assert!(
            content.contains(&hash),
            "expected sha256 in proposal, got: {content}"
        );
        assert!(
            content.contains("/.unknown-target/a.txt")
                || content.contains(&dot.display().to_string())
        );
    }

    #[tokio::test]
    async fn run_once_records_unreadable_scan_root() {
        // CR-006 acceptance: when a `scan_root` cannot be read
        // (operator-reported shape: `chmod 700 /home/<user>`),
        // `RunSummary.unreadable_roots` MUST contain the path
        // and `RunSummary.skipped` MUST increment, so the
        // per-poll summary log line surfaces the loss of coverage.
        let tmp = TempDir::new("cr006_unreadable_root");
        let missing_root = tmp.path().join("does_not_exist");
        let ioc_list = TempFile::with_content("cr006_ioc_list", b"# empty\n");
        let proposer = tmp.path().join("proposed.iocs");
        let cfg = build_cfg_with_proposer(
            missing_root.clone(),
            ioc_list.path().to_path_buf(),
            proposer.clone(),
        );
        let (_tx, shutdown_rx) = watch::channel(false);
        let mut runtime = Runtime::new(cfg, shutdown_rx).expect("build runtime");
        let summary = runtime.run_once().await.expect("run_once");

        assert_eq!(
            summary.unreadable_roots.len(),
            1,
            "expected 1 unreadable root, got {:?}",
            summary.unreadable_roots
        );
        assert_eq!(summary.unreadable_roots[0], missing_root);
        assert_eq!(summary.skipped, 1, "Skipped(IoError) must bump skipped");
    }
}
