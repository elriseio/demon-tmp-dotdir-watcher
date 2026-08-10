use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Deserialize)]
struct Config {
    log: LogConfig,
    runtime: RuntimeConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct LogConfig {
    level: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RuntimeConfig {
    shutdown_timeout_sec: u64,
}

fn load_config(path: Option<&PathBuf>) -> Result<Config> {
    let raw = match path {
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("read config file {}", p.display()))?,
        None => String::new(),
    };
    let cfg: Config = if raw.trim().is_empty() {
        serde_yaml::from_str(include_str!("../config/default.yaml"))
            .context("parse embedded default config")?
    } else {
        serde_yaml::from_str(&raw).context("parse config file")?
    };

    Ok(apply_env_overrides(cfg))
}

fn apply_env_overrides(mut cfg: Config) -> Config {
    if let Ok(level) = std::env::var("DEMON_LOG_LEVEL") {
        cfg.log.level = level;
    }
    if let Ok(t) = std::env::var("DEMON_SHUTDOWN_TIMEOUT_SEC") {
        if let Ok(parsed) = t.parse() {
            cfg.runtime.shutdown_timeout_sec = parsed;
        }
    }
    cfg
}

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

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = std::env::args()
        .nth(1)
        .filter(|a| a != "--help" && a != "-h")
        .map(PathBuf::from);

    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!(
            "rust_demon_template\n\
             \n\
             Usage: rust_demon_template [CONFIG_PATH]\n\
             \n\
             Env overrides:\n  DEMON_LOG_LEVEL\n  DEMON_SHUTDOWN_TIMEOUT_SEC"
        );
        return Ok(());
    }

    let cfg = load_config(cfg_path.as_ref())?;
    init_logging(&cfg.log)?;

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
    fn load_embedded_default_config() {
        let cfg = load_config(None).expect("default config must parse");
        assert!(cfg.runtime.shutdown_timeout_sec > 0);
    }
}
