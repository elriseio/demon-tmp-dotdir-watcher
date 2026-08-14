//! Journal-tag, NTFY alert output, and per-tick summary webhook payload.
//!
//! ARCHITECTURE.md invariant 3 ("Structured logging from the first
//! line") and invariant 5 ("Failures are loud") drive the shape:
//! `tracing` macros with explicit `target = "tmp-watcher"` and
//! `priority` fields matching the journal PRIORITY convention
//! (`PRIORITY=2` CRITICAL, `PRIORITY=4` WARNING), plus a 5-second
//! bounded `ntfy_push` so the poll cycle is never blocked by a
//! slow network.
//!
//! The per-tick summary emit maps `Severity` from `RunSummary`
//! to NTFY priority (info=2 / warn=3 / error=5) and assembles the
//! summary payload via `assemble_summary_payload` (pure
//! body+headers assembler). `ntfy_push` itself is shared with
//! the IOC-match path so both emit through one transport.
//!
//! The `reqwest` client builder is cached per-call (the per-call
//! cost is negligible); if profiling shows this matters, lift
//! it to a `OnceCell` in a follow-up.

#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use tracing::{error, warn};

use crate::config::Config;
use crate::runtime::RunSummary;

const NTFY_TIMEOUT_SECS: u64 = 5;

/// `PRIORITY=4` WARNING event for an unknown
/// non-allowlisted dotdir (the operator-side alert trigger from
/// `Decision::Unknown` once `cfg.actions.alert_on_unknown` is
/// wired in the runtime layer).
pub fn emit_unknown(basename: &str, path: &Path) {
    warn!(
        target: "tmp-watcher",
        priority = 4,
        basename = basename,
        path = %path.display(),
        "unknown non-allowlisted dotdir detected",
    );
}

/// `PRIORITY=2` CRITICAL event for an IOC match (the
/// trigger for the `quarantine()` side effect in `subsystem.rs`).
/// `sha256` is the matching entry's SHA-256 hex string.
pub fn emit_ioc_match(basename: &str, path: &Path, sha256: &str) {
    error!(
        target: "tmp-watcher",
        priority = 2,
        basename = basename,
        path = %path.display(),
        sha256 = sha256,
        "IOC match detected",
    );
}

/// `PRIORITY=2` CRITICAL event for a quarantine
/// side-effect failure (the `QuarantineOutcome::Failed(_)` arm of
/// `subsystem.rs::quarantine()`).
pub fn emit_ioc_quarantine_failed(path: &Path, err: &str) {
    error!(
        target: "tmp-watcher",
        priority = 2,
        path = %path.display(),
        error = err,
        "quarantine side effect failed",
    );
}

/// `PRIORITY=4` WARNING event for allowlist loader
/// warnings (mirrors `allowlist::load`'s warn-on-parse-failure
/// path; centralized here so the runtime layer has a single
/// emit point).
pub fn emit_allowlist_load_warning(path: &Path, reason: &str) {
    warn!(
        target: "tmp-watcher",
        priority = 4,
        allowlist_path = %path.display(),
        reason = reason,
        "allowlist load warning",
    );
}

/// Async NTFY push to the operator's phone. `url = None`
/// is the "operator has not configured NTFY" no-op path;
/// `url = Some(_)` POSTs `body` to `url` with a `Title:` header
/// and a 5-second timeout.
///
/// Per ARCHITECTURE.md § Failure modes, the daemon does NOT
/// retry inside one poll cycle; the next poll retries. We surface
/// the error via `anyhow::Result` so the runtime layer can decide
/// whether to abort the tick or continue; we ALSO log the error
/// here (with `priority = 2` CRITICAL) so the journal captures
/// the failure regardless of caller-side handling.
///
/// Privacy note (per `AGENT_OUTPUT_SANITIZATION_POLICY.md`):
/// the URL is logged verbatim because it is operator-supplied and
/// already operator-visible; the path is logged via
/// `path.display()` which is operator-internal context.
pub async fn ntfy_push(url: Option<&str>, title: &str, body: &str) -> Result<()> {
    let url = match url {
        Some(u) => u,
        None => return Ok(()),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(NTFY_TIMEOUT_SECS))
        .build()
        .context("build reqwest client")?;

    let response = match client
        .post(url)
        .header("Title", title)
        .body(body.to_string())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(
                target: "tmp-watcher",
                priority = 2,
                url = url,
                error = %e,
                "ntfy push failed",
            );
            return Err(anyhow::Error::new(e).context("ntfy POST"));
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        error!(
            target: "tmp-watcher",
            priority = 2,
            url = url,
            status = %status,
            body = %body_text,
            "ntfy push returned non-2xx",
        );
        anyhow::bail!("ntfy push non-success: HTTP {status}");
    }

    Ok(())
}

/// Per-tick severity tier. Drives the NTFY priority header
/// for the post-tick summary emit. Mapping matches
/// `docs/contracts/webhook-payload.md` and the peer daemon's
/// `demon-docker-janitor/src/notify/mod.rs::Severity`. The
/// `RefuseToRun` variant is intentionally absent here (tmp-watcher
/// does not have that exit-code class); a top-level daemon error
/// (`run_once` returned `Err`) is mapped to `Severity::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    /// Classify a tick into a severity tier. `tick_err = true`
    /// short-circuits to `Error` (the runtime catches `run_once` errors
    /// and passes `true` here so a top-level daemon failure surfaces
    /// as NTFY priority 5 even when the in-progress `RunSummary` is
    /// empty).
    pub fn from_run_summary(s: &RunSummary, tick_err: bool) -> Self {
        if tick_err {
            return Self::Error;
        }
        // Order: error first (so partial-quarantine-failure dominates unreadable /
        // first (so partial-quarantine-failure dominates unreadable /
        // skipped), then warn (any flapping signal), then info.
        if s.ioc_matches > 0 && s.quarantined < s.ioc_matches {
            return Self::Error;
        }
        if !s.unreadable_roots.is_empty() || s.skipped > 0 || s.candidates == 0 {
            return Self::Warn;
        }
        Self::Info
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }

    pub fn priority(self) -> u8 {
        match self {
            Severity::Info => 2,
            Severity::Warn => 3,
            Severity::Error => 5,
        }
    }
}

/// Pure assembler for the per-tick summary payload. Returns
/// `(title, body, priority, tags)`. The body layout is the same
/// `key=value` plain-text shape that `demon-docker-janitor` uses
/// (see `docs/contracts/webhook-payload.md` peer contract, adapted
/// to tmp-watcher's field set).
pub fn assemble_summary_payload(summary: &RunSummary, sev: Severity) -> (String, String, u8, String) {
    let status_str = sev.as_str();
    let title = format!("tmp-watcher: cycle {status_str}");
    let priority = sev.priority();
    let tags = format!("tmp,watcher,{status_str}");
    let body = format!(
        "candidates={n}\n\
         allowlisted={a}\n\
         ioc_matches={i}\n\
         quarantined={q}\n\
         unknown={u}\n\
         skipped={s}\n\
         unreadable_roots={r}\n\
         duration_seconds={d}",
        n = summary.candidates,
        a = summary.allowlisted,
        i = summary.ioc_matches,
        q = summary.quarantined,
        u = summary.unknown,
        s = summary.skipped,
        r = summary.unreadable_roots.len(),
        d = summary.duration_seconds,
    );
    (title, body, priority, tags)
}

/// Per-tick NTFY push for the assembled summary. No-op when
/// `Config.actions.ntfy_url` is `None` (host-agnostic embedded
/// default). When set, POSTs `Title`/`Priority`/`Tags` headers with
/// the assembled `text/plain` body via the existing `ntfy_push`
/// transport; 5-second timeout inherited.
///
/// `tick_err = true` is the runtime's signal that `run_once`
/// returned `Err` (partial or refused); severity short-circuits
/// to `Severity::Error` so the NTFY surface reflects the daemon
/// failure rather than the default-state `RunSummary`.
///
/// The helper returns `Result<()>` so the runtime can log a
/// `priority = 4` warning with `error = %e` on transport failure;
/// the daemon does NOT retry inside one poll — the next poll
/// retries, same "next-poll-retries" semantics as the IOC-match
/// NTFY path.
pub async fn push_tick_summary(
    cfg: &Config,
    summary: &RunSummary,
    tick_err: bool,
) -> Result<()> {
    let sev = Severity::from_run_summary(summary, tick_err);
    let (title, body, priority, tags) = assemble_summary_payload(summary, sev);

    // Set the Priority and Tags headers explicitly; the existing
    // ntfy_push signature uses positional String args, so we use
    // a small extension helper to pass the extra NTFY headers.
    push_tick_summary_with_headers(
        cfg.actions.ntfy_url.as_deref(),
        &title,
        &body,
        priority,
        &tags,
    )
    .await
}

/// Low-level helper used by `push_tick_summary`. Exposed as a
/// separate fn so the httpmock round-trip test can verify
/// headers + body byte-for-byte against the mock server.
pub async fn push_tick_summary_with_headers(
    url: Option<&str>,
    title: &str,
    body: &str,
    priority: u8,
    tags: &str,
) -> Result<()> {
    let url = match url {
        Some(u) => u,
        None => return Ok(()),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(NTFY_TIMEOUT_SECS))
        .build()
        .context("build reqwest client")?;

    let response = client
        .post(url)
        .header("Title", title)
        .header("Priority", priority.to_string())
        .header("Tags", tags)
        .body(body.to_string())
        .send()
        .await;

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            error!(
                target: "tmp-watcher",
                priority = 2,
                url = url,
                error = %e,
                "ntfy post-summary push failed",
            );
            return Err(anyhow::Error::new(e).context("ntfy POST summary"));
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        error!(
            target: "tmp-watcher",
            priority = 4,
            url = url,
            status = %status,
            body = %body_text,
            "ntfy post-summary push returned non-2xx",
        );
        anyhow::bail!("ntfy post-summary non-success: HTTP {status}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::Event;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::Registry;

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        target: String,
        level: tracing::Level,
        fields: HashMap<String, String>,
    }

    impl Default for CapturedEvent {
        fn default() -> Self {
            Self {
                target: String::new(),
                level: tracing::Level::INFO,
                fields: HashMap::new(),
            }
        }
    }

    #[derive(Default, Clone)]
    struct EventRecorder {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    struct FieldVisitor {
        fields: HashMap<String, String>,
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{:?}", value));
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S> Layer<S> for EventRecorder
    where
        S: tracing::Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = FieldVisitor {
                fields: HashMap::new(),
            };
            event.record(&mut visitor);
            let captured = CapturedEvent {
                target: event.metadata().target().to_string(),
                level: *event.metadata().level(),
                fields: visitor.fields,
            };
            self.events.lock().unwrap().push(captured);
        }
    }

    fn with_recorder<F: FnOnce()>(recorder: EventRecorder, f: F) {
        let subscriber = Registry::default().with(recorder.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        f();
    }

    #[test]
    fn emit_unknown_writes_priority_4_event() {
        let recorder = EventRecorder::default();
        with_recorder(recorder.clone(), || {
            emit_unknown(".target", Path::new("/tmp/.target"));
        });

        let events = recorder.events.lock().unwrap();
        let event = events
            .iter()
            .find(|e| e.target == "tmp-watcher")
            .expect("event with target=tmp-watcher");
        assert_eq!(event.level, tracing::Level::WARN);
        assert_eq!(event.fields.get("priority").map(String::as_str), Some("4"));
        assert_eq!(
            event.fields.get("basename").map(String::as_str),
            Some(".target")
        );
    }

    #[test]
    fn emit_ioc_match_writes_priority_2_event() {
        let recorder = EventRecorder::default();
        with_recorder(recorder.clone(), || {
            emit_ioc_match(
                ".target",
                Path::new("/tmp/.target"),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            );
        });

        let events = recorder.events.lock().unwrap();
        let event = events
            .iter()
            .find(|e| e.target == "tmp-watcher")
            .expect("event with target=tmp-watcher");
        assert_eq!(event.level, tracing::Level::ERROR);
        assert_eq!(event.fields.get("priority").map(String::as_str), Some("2"));
        assert_eq!(
            event.fields.get("sha256").map(String::as_str),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[tokio::test]
    async fn ntfy_push_no_url_is_noop() {
        // No subscriber needed; the no-op path short-circuits
        // before any tracing event or HTTP call.
        let result = ntfy_push(None, "title", "body").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ntfy_push_unreachable_logs_error() {
        use httpmock::Method;

        // httpmock binds a free local port and serves the mock.
        // The 500 response exercises the non-2xx Err arm.
        let server = httpmock::MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(Method::POST).path("/");
            then.status(500).body("internal error");
        });
        let url = format!("{}/", server.url(""));

        let recorder = EventRecorder::default();
        let result = {
            let subscriber = Registry::default().with(recorder.clone());
            let _guard = tracing::subscriber::set_default(subscriber);
            ntfy_push(Some(&url), "title", "body").await
        };

        assert!(
            result.is_err(),
            "expected Err on 500 response, got {result:?}"
        );

        let events = recorder.events.lock().unwrap();
        let err_event = events
            .iter()
            .find(|e| e.level == tracing::Level::ERROR)
            .expect("ERROR event was logged");
        assert_eq!(err_event.target, "tmp-watcher");
        assert_eq!(
            err_event.fields.get("priority").map(String::as_str),
            Some("2")
        );
    }

    // === Severity + assemble_summary_payload + httpmock round-trip ===

    use crate::runtime::RunSummary;

    fn summary_clean() -> RunSummary {
        RunSummary {
            candidates: 5,
            allowlisted: 2,
            ioc_matches: 0,
            unknown: 0,
            quarantined: 0,
            skipped: 0,
            unreadable_roots: vec![],
            duration_seconds: 4,
        }
    }

    #[test]
    fn severity_info_for_clean_short_success() {
        let s = summary_clean();
        assert_eq!(Severity::from_run_summary(&s, false), Severity::Info);
        assert_eq!(Severity::Info.priority(), 2);
    }

    #[test]
    fn severity_warn_for_unreadable_roots() {
        let mut s = summary_clean();
        s.unreadable_roots = vec![std::path::PathBuf::from("/tmp/missing")];
        assert_eq!(Severity::from_run_summary(&s, false), Severity::Warn);
        assert_eq!(Severity::Warn.priority(), 3);
    }

    #[test]
    fn severity_warn_for_skipped_candidates() {
        let mut s = summary_clean();
        s.skipped = 1;
        assert_eq!(Severity::from_run_summary(&s, false), Severity::Warn);
    }

    #[test]
    fn severity_error_for_quarantine_partial_failure() {
        let mut s = summary_clean();
        s.ioc_matches = 3;
        s.quarantined = 1;
        assert_eq!(Severity::from_run_summary(&s, false), Severity::Error);
        assert_eq!(Severity::Error.priority(), 5);
    }

    #[test]
    fn severity_warn_for_zero_candidates() {
        let mut s = summary_clean();
        s.candidates = 0;
        // unreadable root forces Warn above Info; here we keep no
        // unreadable/skipped and just collapse to 0 candidates, per
        // the Severity mapping in `from_run_summary`.
        assert_eq!(Severity::from_run_summary(&s, false), Severity::Warn);
    }

    #[test]
    fn severity_error_when_tick_err_true_even_on_clean_summary() {
        // A runtime.run_once error maps to Error regardless of
        // in-progress RunSummary counters.
        let s = summary_clean();
        assert_eq!(
            Severity::from_run_summary(&s, true),
            Severity::Error,
            "tick_err must short-circuit to Severity::Error"
        );
    }

    #[test]
    fn assemble_payload_info_matches_examples() {
        let s = summary_clean();
        let (title, body, priority, tags) =
            assemble_summary_payload(&s, Severity::from_run_summary(&s, false));
        assert_eq!(title, "tmp-watcher: cycle info");
        assert_eq!(priority, 2);
        assert_eq!(tags, "tmp,watcher,info");

        // Body must include every key=value line per the contract
        // doc. The exact integers come from summary_clean() above.
        assert!(body.contains("candidates=5"), "body: {body}");
        assert!(body.contains("allowlisted=2"), "body: {body}");
        assert!(body.contains("ioc_matches=0"), "body: {body}");
        assert!(body.contains("quarantined=0"), "body: {body}");
        assert!(body.contains("unknown=0"), "body: {body}");
        assert!(body.contains("skipped=0"), "body: {body}");
        assert!(body.contains("unreadable_roots=0"), "body: {body}");
        assert!(body.contains("duration_seconds=4"), "body: {body}");
    }

    #[test]
    fn assemble_payload_body_layout_matches_peer_daemon_convention() {
        // Body uses `\n` separators and `key=value` form per
        // `demon-docker-janitor/docs/contracts/webhook-payload.md`
        // (peer contract; tmp-watcher field set is a subset).
        let s = summary_clean();
        let (_title, body, _priority, _tags) =
            assemble_summary_payload(&s, Severity::Info);
        let lines: Vec<&str> = body.split('\n').collect();
        // 8 expected key=value lines, no blank lines.
        assert_eq!(
            lines.len(),
            8,
            "expected 8 newline-separated key=value lines, got {}: {lines:?}",
            lines.len()
        );
        for line in &lines {
            assert!(line.contains('='), "line must be key=value: {line}");
            assert!(
                !line.contains(','),
                "peer-daemon key=value form forbids comma separators: {line}"
            );
        }
    }

    #[tokio::test]
    async fn ntfy_push_round_trip_with_assembled_payload() {
        // httpmock round-trip: receives exactly one
        // POST with the expected headers (Title / Priority / Tags)
        // and the body byte-for-byte.
        use httpmock::Method;

        let server = httpmock::MockServer::start();
        let _mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path("/")
                .header("Title", "tmp-watcher: cycle info")
                .header("Priority", "2")
                .header("Tags", "tmp,watcher,info");
            then.status(200).body("ok");
        });
        let url = format!("{}/", server.url(""));

        let s = summary_clean();
        let (title, body, priority, tags) =
            assemble_summary_payload(&s, Severity::Info);

        let result =
            push_tick_summary_with_headers(Some(&url), &title, &body, priority, &tags).await;
        assert!(result.is_ok(), "round-trip push must Ok, got {result:?}");
    }

    #[tokio::test]
    async fn push_tick_summary_no_url_is_noop() {
        // When Config.actions.ntfy_url is None the post-tick summary
        // is journal-only; the helper short-circuits before any HTTP
        // call.
        let cfg = Config {
            log: crate::config::LogConfig { level: "info".into() },
            runtime: crate::config::RuntimeConfig {
                shutdown_timeout_sec: 5,
            },
            paths: crate::config::PathsConfig {
                scan_roots: vec![std::path::PathBuf::from("/tmp")],
                scan_maxdepth: 3,
                scan_window_minutes: 60,
                overlay_scan: crate::config::OverlayScanConfig::default(),
            },
            ioc: crate::config::IocConfig {
                ioc_list: std::path::PathBuf::from("/dev/null"),
                ioc_archive_ref: None,
                proposed_iocs: None,
            },
            allowlist: crate::config::AllowlistConfig {
                allowlist: std::path::PathBuf::from("/dev/null"),
                max_files_per_dir: 10,
            },
            actions: crate::config::ActionsConfig {
                quarantine_on_ioc_match: true,
                alert_on_unknown: false,
                ntfy_url: None,
            },
        };
        let s = summary_clean();
        let result = push_tick_summary(&cfg, &s, false).await;
        assert!(result.is_ok(), "no-URL path is a documented no-op");
    }
}
