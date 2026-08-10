#![warn(clippy::correctness)]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::{load_config, LogConfig};

mod config;
mod ioc;
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
           DEMON_PATHS__SCAN_MAXDEPTH\n\
           DEMON_PATHS__SCAN_WINDOW_MINUTES\n\
           DEMON_PATHS__SCAN_ROOTS (colon-separated)\n\
           DEMON_IOC__IOC_LIST\n\
           DEMON_IOC__IOC_ARCHIVE_REF\n\
           DEMON_ALLOWLIST__ALLOWLIST\n\
           DEMON_ALLOWLIST__MAX_FILES_PER_DIR\n\
           DEMON_ACTIONS__QUARANTINE_ON_IOC_MATCH\n\
           DEMON_ACTIONS__ALERT_ON_UNKNOWN"
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
            _ => {}
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
    init_logging(&cfg.log)?;

    if cli.dry_run {
        info!("dry-run: skipping boot loop (subsystem wiring lands in AR-008)");
        return Ok(());
    }

    info!(version = env!("CARGO_PKG_VERSION"), "boot: daemon started");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_handlers(shutdown_tx)?;

    let timeout = Duration::from_secs(cfg.runtime.shutdown_timeout_sec);
    run(shutdown_rx, timeout).await?;

    info!("exit: clean shutdown");
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

async fn run(mut shutdown: watch::Receiver<bool>, _shutdown_timeout: Duration) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("shutdown: requested by signal");
                    return Ok(());
                }
            }
            _ = tick.tick() => {
                // TODO: replace this placeholder with the actual subsystem side effect.
                info!("tick: placeholder heartbeat");
            }
        }
    }
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
