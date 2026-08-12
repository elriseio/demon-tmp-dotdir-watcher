//! AR-006: journal-tag and NTFY alert output.
//!
//! ARCHITECTURE.md invariant 3 ("Structured logging from the first
//! line") and invariant 5 ("Failures are loud") drive the shape:
//! `tracing` macros with explicit `target = "tmp-watcher"` and
//! `priority` fields matching the journal PRIORITY convention
//! (`PRIORITY=2` CRITICAL, `PRIORITY=4` WARNING), plus a 5-second
//! bounded `ntfy_push` so the poll cycle is never blocked by a
//! slow network.
//!
//! The `reqwest` client builder is cached per-call (the issue scope
//! does not require a process-wide singleton); if profiling shows
//! this matters, lift it to a `OnceCell` in a follow-up.

#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use tracing::{error, warn};

const NTFY_TIMEOUT_SECS: u64 = 5;

/// AR-006: `PRIORITY=4` WARNING event for an unknown
/// non-allowlisted dotdir (the operator-side alert trigger from
/// `Decision::Unknown` once `cfg.actions.alert_on_unknown` is
/// wired in AR-008).
pub fn emit_unknown(basename: &str, path: &Path) {
    warn!(
        target: "tmp-watcher",
        priority = 4,
        basename = basename,
        path = %path.display(),
        "unknown non-allowlisted dotdir detected",
    );
}

/// AR-006: `PRIORITY=2` CRITICAL event for an IOC match (the
/// trigger for the AR-005 `quarantine()` side effect). `sha256`
/// is the matching entry's SHA-256 hex string.
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

/// AR-006: `PRIORITY=2` CRITICAL event for a quarantine
/// side-effect failure (the `QuarantineOutcome::Failed(_)` arm of
/// AR-005's `quarantine()`).
pub fn emit_ioc_quarantine_failed(path: &Path, err: &str) {
    error!(
        target: "tmp-watcher",
        priority = 2,
        path = %path.display(),
        error = err,
        "quarantine side effect failed",
    );
}

/// AR-006: `PRIORITY=4` WARNING event for allowlist loader
/// warnings (mirrors `allowlist::load`'s warn-on-parse-failure
/// path; centralized here so AR-008 has a single emit point).
pub fn emit_allowlist_load_warning(path: &Path, reason: &str) {
    warn!(
        target: "tmp-watcher",
        priority = 4,
        allowlist_path = %path.display(),
        reason = reason,
        "allowlist load warning",
    );
}

/// AR-006: async NTFY push to the operator's phone. `url = None`
/// is the "operator has not configured NTFY" no-op path;
/// `url = Some(_)` POSTs `body` to `url` with a `Title:` header
/// and a 5-second timeout.
///
/// Per ARCHITECTURE.md § Failure modes, the daemon does NOT
/// retry inside one poll cycle; the next poll retries. We surface
/// the error via `anyhow::Result` so AR-008 can decide whether
/// to abort the tick or continue; we ALSO log the error here
/// (with `priority = 2` CRITICAL) so the journal captures the
/// failure regardless of caller-side handling.
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
}
