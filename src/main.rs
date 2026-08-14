#![warn(clippy::correctness)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::{load_config, LogConfig};

mod allowlist;
mod config;
mod ioc;
mod learn;
mod output;
mod overlay;
mod runtime;
mod subsystem;

#[cfg(test)]
mod test_util;

fn init_logging(cfg: &LogConfig) -> Result<()> {
    let filter = EnvFilter::try_new(&cfg.level).context("parse log level")?;
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_span_list(false);
    subscriber
        .try_init()
        .map_err(|e| anyhow::anyhow!("init tracing subscriber: {e}"))?;
    Ok(())
}

/// stderr-bound variant of `init_logging` for the
/// `--dry-run` CLI handler. The runtime path uses
/// `init_logging` (stdout-bound) per the daemon's existing
/// operator runbook (`journalctl -t tmp-watcher` captures stdout
/// from the systemd unit). `--dry-run` writes to stderr so the
/// smoke-test predicate
/// `predicate::str::contains("dry-run")` (which inspects stderr)
/// sees the structured JSON event fields.
fn init_logging_stderr(cfg: &LogConfig) -> Result<()> {
    let filter = EnvFilter::try_new(&cfg.level).context("parse log level")?;
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_writer(std::io::stderr)
        .with_current_span(false)
        .with_span_list(false);
    subscriber
        .try_init()
        .map_err(|e| anyhow::anyhow!("init tracing subscriber (stderr): {e}"))?;
    Ok(())
}

fn print_usage() {
    println!(
        "demon-tmp-dotdir-watcher\n\
         \n\
         Usage: demon-tmp-dotdir-watcher [OPTIONS] [CONFIG_PATH]\n\
         \n\
         Options:\n\
           --validate-config [CONFIG_PATH]  Load + validate config; exit 0 on success, non-zero on failure.\n\
           --dry-run                        Load config and walk the candidate tree without quarantining.\n\
           --help, -h                       Show this help.\n\
         \n\
         When CONFIG_PATH is omitted, the embedded default config is used.\n\
         \n\
         Env overrides:\n\
           DEMON_LOG_LEVEL\n\
           DEMON_SHUTDOWN_TIMEOUT_SEC\n\
           DEMON_PATHS_SCAN_MAXDEPTH\n\
           DEMON_PATHS_SCAN_WINDOW_MINUTES\n\
           DEMON_PATHS_SCAN_ROOTS (colon-separated)\n\
           DEMON_PATHS_OVERLAY_SCAN_ENABLED\n\
           DEMON_PATHS_OVERLAY_SCAN_ROOTS (colon-separated)\n\
           DEMON_PATHS_OVERLAY_SCAN_MAXDEPTH\n\
           DEMON_PATHS_OVERLAY_SCAN_DOTDIR_ONLY\n\
           DEMON_IOC_IOC_LIST\n\
           DEMON_IOC_IOC_ARCHIVE_REF\n\
           DEMON_ALLOWLIST_ALLOWLIST\n\
           DEMON_ALLOWLIST_MAX_FILES_PER_DIR\n\
           DEMON_ACTIONS_QUARANTINE_ON_IOC_MATCH\n\
           DEMON_ACTIONS_ALERT_ON_UNKNOWN\n\
           DEMON_ACTIONS_NTFY_URL"
    );
}

fn parse_args() -> CliArgs {
    let mut args = std::env::args().skip(1);
    let mut cli = CliArgs::default();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => cli.help = true,
            "--validate-config" => {
                cli.validate_config = true;
                cli.config_path = args.next().map(PathBuf::from);
            }
            "--dry-run" => {
                cli.dry_run = true;
                cli.config_path = args.next().map(PathBuf::from);
            }
            other if !other.starts_with("--") && !other.starts_with('-') => {
                cli.config_path = Some(PathBuf::from(other));
            }
            unknown => {
                eprintln!("unknown flag: {unknown}");
                std::process::exit(2);
            }
        }
    }
    cli
}

#[derive(Default)]
struct CliArgs {
    help: bool,
    validate_config: bool,
    dry_run: bool,
    config_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args();

    if cli.help {
        print_usage();
        return Ok(());
    }

    if cli.validate_config {
        let cfg = load_config(cli.config_path.as_deref())?;
        match cfg.validate() {
            Ok(()) => {
                println!("OK");
                return Ok(());
            }
            Err(e) => {
                eprintln!("validation failed: {e:#}");
                std::process::exit(1);
            }
        }
    }

    let cfg = load_config(cli.config_path.as_deref())?;
    cfg.validate().context("config validation")?;

    if cli.dry_run {
        // `--dry-run` runs the full `Runtime::run_once`
        // pipeline once and emits structured JSON logs to stderr
        // so operators can verify config + scan coverage + IOC
        // matching before booting the daemon. Exits after one
        // tick because the `--dry-run` flag exits after run_once.
        //
        // SAFETY: `--dry-run` MUST NOT mutate the host. Override
        // `actions.quarantine_on_ioc_match` to false for this
        // single activation so the daemon is safe-by-default
        // regardless of the operator's config — see README
        // § "Run" table entry for `--dry-run` which documents
        // this contract.
        let mut cfg =
            load_config(cli.config_path.as_deref()).context("load config for --dry-run")?;
        cfg.actions.quarantine_on_ioc_match = false;
        init_logging_stderr(&cfg.log)?;
        info!(target: "tmp-watcher", "dry-run: starting one poll tick (quarantine force-off)");
        let (_tx, shutdown_rx) = watch::channel(false);
        let mut runtime =
            runtime::Runtime::new(cfg, shutdown_rx).context("build runtime for --dry-run")?;
        let summary = runtime
            .run_once()
            .await
            .context("dry-run run_once failed")?;
        info!(
            target: "tmp-watcher",
            candidates = summary.candidates,
            allowlisted = summary.allowlisted,
            ioc_matches = summary.ioc_matches,
            unknown = summary.unknown,
            quarantined = summary.quarantined,
            skipped = summary.skipped,
            unreadable_roots = summary.unreadable_roots.len(),
            "dry-run: tick summary",
        );
        return Ok(());
    }

    init_logging(&cfg.log)?;
    info!(version = env!("CARGO_PKG_VERSION"), "boot: daemon started");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_handlers(shutdown_tx)?;

    let runtime = runtime::Runtime::new(cfg, shutdown_rx)?;
    runtime.run().await?;

    info!("exit: clean shutdown");
    // tracing-subscriber's stdout writer is block-buffered when
    // the daemon is run under `cargo test`'s pipe capture (the
    // integration test in `tests/runtime.rs`). Explicit flush
    // ensures the final `exit: clean shutdown` line reaches the
    // pipe before the process exits.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    Ok(())
}

fn spawn_signal_handlers(tx: watch::Sender<bool>) -> Result<()> {
    let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => info!("signal: SIGTERM received"),
            _ = int.recv()  => info!("signal: SIGINT received"),
        }
        let _ = tx.send(true);
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_embedded_default_config_via_main_module() {
        let cfg = load_config(None).expect("default config must parse");
        assert!(cfg.runtime.shutdown_timeout_sec > 0);
    }
}
