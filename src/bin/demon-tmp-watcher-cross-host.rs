//! Cross-host IOC correlation sidecar binary.
//!
//! Reads per-host observation streams from a `Sink` (abstracted
//! transport), aggregates them across hosts, and writes candidate-IOC
//! proposal entries to `/etc/tmp-watcher.proposed.iocs` (the same
//! file the detection daemon writes per AR-013) with a
//! `cross_host_count=N` suffix.
//!
//! Cadence is driven by the systemd timer (one activation per
//! hour; the sidecar is `Type=oneshot` and exits after one
//! `poll_once`). See `packaging/tmp-watcher-cross-host.timer`.
//!
//! Install: shipped disabled by default. The operator enables
//! the unit after picking a concrete `Sink` transport (HTTP POST
//! to a shared endpoint, file drop on a shared filesystem, syslog
//! relay, or Unix-domain socket).

#[path = "../cross_host.rs"]
mod cross_host;

#[cfg(test)]
#[path = "../test_util.rs"]
mod test_util;

use std::path::PathBuf;

use anyhow::{Context, Result};
use cross_host::{Aggregator, NullSink};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging()?;

    let proposal_path = std::env::var("DEMON_CROSS_HOST_PROPOSED_IOCS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/tmp-watcher.proposed.iocs"));

    info!(
        target: "tmp-watcher-cross-host",
        proposal_path = %proposal_path.display(),
        "boot: cross-host sidecar starting (NullSink placeholder)"
    );

    let mut aggregator = Aggregator::new(NullSink, proposal_path.clone());
    let summary = aggregator
        .poll_once()
        .await
        .context("cross-host poll_once")?;

    info!(
        target: "tmp-watcher-cross-host",
        observed = summary.observed,
        deduped = summary.deduped,
        proposals_written = summary.proposals_written,
        "shutdown: poll_once complete"
    );

    if summary.proposals_written == 0 && summary.observed == 0 {
        // The NullSink returns zero observations; surface this in
        // the journal so the operator notices the sidecar is not
        // actually aggregating anything yet (the placeholder Sink
        // is the only public Sink impl until the transport is
        // chosen).
        error!(
            target: "tmp-watcher-cross-host",
            priority = 4,
            "shutdown: sidecar is wired with NullSink; install a concrete Sink impl to enable cross-host aggregation"
        );
    }

    Ok(())
}

fn init_logging() -> Result<()> {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("init tracing subscriber: {e}"))?;
    Ok(())
}
