use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

macro_rules! set_from_env {
    ($cfg:expr, $env:expr, $field:expr, $ty:ty) => {{
        if let Ok(v) = std::env::var($env) {
            match v.parse::<$ty>() {
                Ok(parsed) => $field = parsed,
                Err(e) => tracing::warn!(
                    "config: env {} rejected value {:?}: {e}; keeping default",
                    $env,
                    v
                ),
            }
        }
    }};
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub log: LogConfig,
    pub runtime: RuntimeConfig,
    pub paths: PathsConfig,
    pub ioc: IocConfig,
    pub allowlist: AllowlistConfig,
    pub actions: ActionsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    pub shutdown_timeout_sec: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathsConfig {
    pub scan_roots: Vec<PathBuf>,
    pub scan_maxdepth: usize,
    pub scan_window_minutes: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IocConfig {
    pub ioc_list: PathBuf,
    pub ioc_archive_ref: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistConfig {
    pub allowlist: PathBuf,
    pub max_files_per_dir: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionsConfig {
    pub quarantine_on_ioc_match: bool,
    pub alert_on_unknown: bool,
}

const SCAN_MAXDEPTH_LIMIT: usize = 3;
const MAX_FILES_PER_DIR_LIMIT: usize = 10;

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.paths.scan_roots.is_empty() {
            return Err(anyhow!("paths.scan_roots must be non-empty"));
        }
        if self.paths.scan_maxdepth > SCAN_MAXDEPTH_LIMIT {
            return Err(anyhow!(
                "paths.scan_maxdepth must be <= {SCAN_MAXDEPTH_LIMIT} (ARCHITECTURE invariant 6), got {}",
                self.paths.scan_maxdepth
            ));
        }
        if self.paths.scan_window_minutes == 0 {
            return Err(anyhow!("paths.scan_window_minutes must be > 0"));
        }
        if self.allowlist.max_files_per_dir > MAX_FILES_PER_DIR_LIMIT {
            return Err(anyhow!(
                "allowlist.max_files_per_dir must be <= {MAX_FILES_PER_DIR_LIMIT} (ARCHITECTURE invariant 6), got {}",
                self.allowlist.max_files_per_dir
            ));
        }
        Ok(())
    }
}

pub fn load_config(path: Option<&Path>) -> Result<Config> {
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

pub fn apply_env_overrides(mut cfg: Config) -> Config {
    if let Ok(level) = std::env::var("DEMON_LOG_LEVEL") {
        cfg.log.level = level;
    }
    set_from_env!(
        cfg,
        "DEMON_SHUTDOWN_TIMEOUT_SEC",
        cfg.runtime.shutdown_timeout_sec,
        u64
    );

    set_from_env!(
        cfg,
        "DEMON_PATHS__SCAN_MAXDEPTH",
        cfg.paths.scan_maxdepth,
        usize
    );
    set_from_env!(
        cfg,
        "DEMON_PATHS__SCAN_WINDOW_MINUTES",
        cfg.paths.scan_window_minutes,
        u32
    );
    if let Ok(v) = std::env::var("DEMON_PATHS__SCAN_ROOTS") {
        cfg.paths.scan_roots = v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    if let Ok(v) = std::env::var("DEMON_IOC__IOC_LIST") {
        cfg.ioc.ioc_list = PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("DEMON_IOC__IOC_ARCHIVE_REF") {
        cfg.ioc.ioc_archive_ref = Some(PathBuf::from(v));
    }
    if let Ok(v) = std::env::var("DEMON_ALLOWLIST__ALLOWLIST") {
        cfg.allowlist.allowlist = PathBuf::from(v);
    }
    set_from_env!(
        cfg,
        "DEMON_ALLOWLIST__MAX_FILES_PER_DIR",
        cfg.allowlist.max_files_per_dir,
        usize
    );
    set_from_env!(
        cfg,
        "DEMON_ACTIONS__QUARANTINE_ON_IOC_MATCH",
        cfg.actions.quarantine_on_ioc_match,
        bool
    );
    set_from_env!(
        cfg,
        "DEMON_ACTIONS__ALERT_ON_UNKNOWN",
        cfg.actions.alert_on_unknown,
        bool
    );

    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_from_yaml(yaml: &str) -> Config {
        let cfg: Config = serde_yaml::from_str(yaml).expect("test yaml must parse");
        apply_env_overrides(cfg)
    }

    const VALID_YAML: &str = r#"
log:
  level: info
runtime:
  shutdown_timeout_sec: 30
paths:
  scan_roots: ["/tmp"]
  scan_maxdepth: 3
  scan_window_minutes: 60
ioc:
  ioc_list: "/etc/tmp-watcher.iocs"
allowlist:
  allowlist: "/etc/tmp-watcher.allowlist"
  max_files_per_dir: 10
actions:
  quarantine_on_ioc_match: true
  alert_on_unknown: true
"#;

    #[test]
    fn load_embedded_default_config() {
        let cfg = load_config(None).expect("default config must parse");
        assert!(cfg.runtime.shutdown_timeout_sec > 0);
        assert!(cfg.paths.scan_maxdepth <= SCAN_MAXDEPTH_LIMIT);
        assert!(!cfg.paths.scan_roots.is_empty());
    }

    #[test]
    fn validate_passes_default() {
        let cfg = load_config(None).expect("default config must parse");
        cfg.validate().expect("embedded default config must validate");
    }

    #[test]
    fn validate_passes_explicit_valid_yaml() {
        let cfg = load_from_yaml(VALID_YAML);
        cfg.validate().expect("explicit valid yaml must validate");
    }

    #[test]
    fn validate_rejects_scan_maxdepth_above_limit() {
        let yaml = r#"
log:
  level: info
runtime:
  shutdown_timeout_sec: 30
paths:
  scan_roots: ["/tmp"]
  scan_maxdepth: 10
  scan_window_minutes: 60
ioc:
  ioc_list: "/etc/tmp-watcher.iocs"
allowlist:
  allowlist: "/etc/tmp-watcher.allowlist"
  max_files_per_dir: 10
actions:
  quarantine_on_ioc_match: true
  alert_on_unknown: true
"#;
        let cfg = load_from_yaml(yaml);
        let err = cfg.validate().expect_err("scan_maxdepth > 3 must fail");
        assert!(err.to_string().contains("scan_maxdepth"));
    }

    #[test]
    fn validate_rejects_zero_scan_window_minutes() {
        let yaml = r#"
log:
  level: info
runtime:
  shutdown_timeout_sec: 30
paths:
  scan_roots: ["/tmp"]
  scan_maxdepth: 1
  scan_window_minutes: 0
ioc:
  ioc_list: "/etc/tmp-watcher.iocs"
allowlist:
  allowlist: "/etc/tmp-watcher.allowlist"
  max_files_per_dir: 10
actions:
  quarantine_on_ioc_match: true
  alert_on_unknown: true
"#;
        let cfg = load_from_yaml(yaml);
        let err = cfg.validate().expect_err("scan_window_minutes == 0 must fail");
        assert!(err.to_string().contains("scan_window_minutes"));
    }

    #[test]
    fn validate_rejects_empty_scan_roots() {
        let yaml = r#"
log:
  level: info
runtime:
  shutdown_timeout_sec: 30
paths:
  scan_roots: []
  scan_maxdepth: 1
  scan_window_minutes: 60
ioc:
  ioc_list: "/etc/tmp-watcher.iocs"
allowlist:
  allowlist: "/etc/tmp-watcher.allowlist"
  max_files_per_dir: 10
actions:
  quarantine_on_ioc_match: true
  alert_on_unknown: true
"#;
        let cfg = load_from_yaml(yaml);
        let err = cfg.validate().expect_err("empty scan_roots must fail");
        assert!(err.to_string().contains("scan_roots"));
    }

    #[test]
    fn validate_rejects_max_files_per_dir_above_limit() {
        let yaml = r#"
log:
  level: info
runtime:
  shutdown_timeout_sec: 30
paths:
  scan_roots: ["/tmp"]
  scan_maxdepth: 3
  scan_window_minutes: 60
ioc:
  ioc_list: "/etc/tmp-watcher.iocs"
allowlist:
  allowlist: "/etc/tmp-watcher.allowlist"
  max_files_per_dir: 20
actions:
  quarantine_on_ioc_match: true
  alert_on_unknown: true
"#;
        let cfg = load_from_yaml(yaml);
        let err = cfg.validate().expect_err("max_files_per_dir > 10 must fail");
        assert!(err.to_string().contains("max_files_per_dir"));
    }

    #[test]
    fn env_overrides_paths_scan_maxdepth() {
        std::env::set_var("DEMON_PATHS__SCAN_MAXDEPTH", "2");
        let cfg = load_config(None).expect("default config must parse");
        assert_eq!(cfg.paths.scan_maxdepth, 2);
        std::env::remove_var("DEMON_PATHS__SCAN_MAXDEPTH");
    }

    #[test]
    fn env_override_keeps_default_on_unparseable_value() {
        // A parse-failed env var must not silently fall through to
        // the default; the default must be kept AND a warn! line
        // must be emitted. The default assertion is deterministic;
        // the warn! line is verified by inspection (tracing-subscriber
        // test layer is not wired here, but the macro form is
        // exercised on every call).
        std::env::set_var("DEMON_SHUTDOWN_TIMEOUT_SEC", "not-a-number");
        let cfg = load_config(None).expect("default config must parse");
        assert_eq!(cfg.runtime.shutdown_timeout_sec, 30);
        std::env::remove_var("DEMON_SHUTDOWN_TIMEOUT_SEC");
    }
}
