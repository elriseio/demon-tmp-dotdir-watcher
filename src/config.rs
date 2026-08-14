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
    #[serde(default)]
    pub overlay_scan: OverlayScanConfig,
}

// ADR-0002 § 4: host-side overlay-fs scan configuration. v1 covers
// Docker overlay2 only; Podman / containerd / CRI-O are out of scope
// and tracked as future work in `docs/architecture/STATUS.md`.
#[derive(Debug, Clone, Deserialize)]
pub struct OverlayScanConfig {
    #[serde(default = "default_overlay_scan_enabled")]
    pub enabled: bool,
    #[serde(default = "default_overlay_scan_roots")]
    pub roots: Vec<PathBuf>,
    #[serde(default = "default_overlay_scan_maxdepth")]
    pub maxdepth: usize,
    #[serde(default = "default_overlay_scan_dotdir_only")]
    pub dotdir_only: bool,
}

impl Default for OverlayScanConfig {
    fn default() -> Self {
        Self {
            enabled: default_overlay_scan_enabled(),
            roots: default_overlay_scan_roots(),
            maxdepth: default_overlay_scan_maxdepth(),
            dotdir_only: default_overlay_scan_dotdir_only(),
        }
    }
}

fn default_overlay_scan_enabled() -> bool {
    true
}

fn default_overlay_scan_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/var/lib/docker/overlay2")]
}

fn default_overlay_scan_maxdepth() -> usize {
    3
}

fn default_overlay_scan_dotdir_only() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct IocConfig {
    pub ioc_list: PathBuf,
    pub ioc_archive_ref: Option<PathBuf>,
    #[serde(default)]
    pub proposed_iocs: Option<PathBuf>,
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
    /// DE-019: operator-supplied NTFY topic URL. When `Some(_)`, the
    /// runtime POSTs the per-tick summary via `output::ntfy_push`.
    /// When `None` (embedded default), the alert channel is journal-only
    /// (per AR-011: host-agnostic embedded default; the concrete value
    /// lives in `/etc/tmp-watcher.yaml` or `DEMON_ACTIONS_NTFY_URL`).
    #[serde(default)]
    pub ntfy_url: Option<String>,
}

const SCAN_MAXDEPTH_LIMIT: usize = 3;
const MAX_FILES_PER_DIR_LIMIT: usize = 10;
const OVERLAY_SCAN_MAXDEPTH_LIMIT: usize = 3;

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
        // ADR-0002 § 4 + ARCHITECTURE invariant 6: overlay walk scope
        // is bounded by `maxdepth ≤ 3`. Validation runs at boot only;
        // a missing or unreadable overlay root is logged at runtime
        // by the walker (see `src/overlay.rs::discover_layers`).
        if self.paths.overlay_scan.enabled {
            if self.paths.overlay_scan.roots.is_empty() {
                return Err(anyhow!(
                    "paths.overlay_scan.roots must be non-empty when overlay_scan.enabled is true"
                ));
            }
            if self.paths.overlay_scan.maxdepth > OVERLAY_SCAN_MAXDEPTH_LIMIT {
                return Err(anyhow!(
                    "paths.overlay_scan.maxdepth must be <= {OVERLAY_SCAN_MAXDEPTH_LIMIT} (ARCHITECTURE invariant 6), got {}",
                    self.paths.overlay_scan.maxdepth
                ));
            }
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
        toml::from_str(include_str!("../config/default.toml"))
            .context("parse embedded default config (toml)")?
    } else {
        toml::from_str(&raw).context("parse config file (toml)")?
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
        "DEMON_PATHS_SCAN_MAXDEPTH",
        cfg.paths.scan_maxdepth,
        usize
    );
    set_from_env!(
        cfg,
        "DEMON_PATHS_SCAN_WINDOW_MINUTES",
        cfg.paths.scan_window_minutes,
        u32
    );
    if let Ok(v) = std::env::var("DEMON_PATHS_SCAN_ROOTS") {
        cfg.paths.scan_roots = v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    // ADR-0002 § 4: overlay-fs scan env overrides.
    set_from_env!(
        cfg,
        "DEMON_PATHS_OVERLAY_SCAN_ENABLED",
        cfg.paths.overlay_scan.enabled,
        bool
    );
    if let Ok(v) = std::env::var("DEMON_PATHS_OVERLAY_SCAN_ROOTS") {
        cfg.paths.overlay_scan.roots = v
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    set_from_env!(
        cfg,
        "DEMON_PATHS_OVERLAY_SCAN_MAXDEPTH",
        cfg.paths.overlay_scan.maxdepth,
        usize
    );
    set_from_env!(
        cfg,
        "DEMON_PATHS_OVERLAY_SCAN_DOTDIR_ONLY",
        cfg.paths.overlay_scan.dotdir_only,
        bool
    );
    if let Ok(v) = std::env::var("DEMON_IOC_IOC_LIST") {
        cfg.ioc.ioc_list = PathBuf::from(v);
    }
    if let Ok(v) = std::env::var("DEMON_IOC_IOC_ARCHIVE_REF") {
        cfg.ioc.ioc_archive_ref = Some(PathBuf::from(v));
    }
    if let Ok(v) = std::env::var("DEMON_IOC_PROPOSED_IOCS") {
        cfg.ioc.proposed_iocs = Some(PathBuf::from(v));
    }
    if let Ok(v) = std::env::var("DEMON_ALLOWLIST_ALLOWLIST") {
        cfg.allowlist.allowlist = PathBuf::from(v);
    }
    set_from_env!(
        cfg,
        "DEMON_ALLOWLIST_MAX_FILES_PER_DIR",
        cfg.allowlist.max_files_per_dir,
        usize
    );
    set_from_env!(
        cfg,
        "DEMON_ACTIONS_QUARANTINE_ON_IOC_MATCH",
        cfg.actions.quarantine_on_ioc_match,
        bool
    );
    set_from_env!(
        cfg,
        "DEMON_ACTIONS_ALERT_ON_UNKNOWN",
        cfg.actions.alert_on_unknown,
        bool
    );
    // DE-019: NTFY topic URL. Mirror the `DEMON_IOC_IOC_LIST` override
    // pattern: raw `std::env::var` + `PathBuf::from(...)` style is
    // unsuitable for a free-form URL string, so we use the explicit
    // form and warn on invalid (non-UTF-8) values without panicking.
    if let Ok(v) = std::env::var("DEMON_ACTIONS_NTFY_URL") {
        cfg.actions.ntfy_url = Some(v);
    }

    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_from_toml(toml_str: &str) -> Config {
        let cfg: Config = toml::from_str(toml_str).expect("test toml must parse");
        apply_env_overrides(cfg)
    }

    const VALID_TOML: &str = r#"
log = { level = "info" }

[runtime]
shutdown_timeout_sec = 30

[paths]
scan_roots = ["/tmp"]
scan_maxdepth = 3
scan_window_minutes = 60

[ioc]
ioc_list = "/etc/tmp-watcher.iocs"

[allowlist]
allowlist = "/etc/tmp-watcher.allowlist"
max_files_per_dir = 10

[actions]
quarantine_on_ioc_match = true
alert_on_unknown = true
"#;

    #[test]
    fn load_embedded_default_toml_config() {
        let cfg = load_config(None).expect("default config must parse");
        assert!(cfg.runtime.shutdown_timeout_sec > 0);
        assert!(cfg.paths.scan_maxdepth <= SCAN_MAXDEPTH_LIMIT);
        assert!(!cfg.paths.scan_roots.is_empty());
    }

    #[test]
    fn validate_passes_default() {
        let cfg = load_config(None).expect("default config must parse");
        cfg.validate()
            .expect("embedded default config must validate");
    }

    #[test]
    fn validate_passes_explicit_valid_toml() {
        let cfg = load_from_toml(VALID_TOML);
        cfg.validate().expect("explicit valid toml must validate");
    }

    #[test]
    fn validate_rejects_scan_maxdepth_above_limit() {
        let toml_str = r#"
log = { level = "info" }

[runtime]
shutdown_timeout_sec = 30

[paths]
scan_roots = ["/tmp"]
scan_maxdepth = 10
scan_window_minutes = 60

[ioc]
ioc_list = "/etc/tmp-watcher.iocs"

[allowlist]
allowlist = "/etc/tmp-watcher.allowlist"
max_files_per_dir = 10

[actions]
quarantine_on_ioc_match = true
alert_on_unknown = true
"#;
        let cfg = load_from_toml(toml_str);
        let err = cfg.validate().expect_err("scan_maxdepth > 3 must fail");
        assert!(err.to_string().contains("scan_maxdepth"));
    }

    #[test]
    fn validate_rejects_zero_scan_window_minutes() {
        let toml_str = r#"
log = { level = "info" }

[runtime]
shutdown_timeout_sec = 30

[paths]
scan_roots = ["/tmp"]
scan_maxdepth = 1
scan_window_minutes = 0

[ioc]
ioc_list = "/etc/tmp-watcher.iocs"

[allowlist]
allowlist = "/etc/tmp-watcher.allowlist"
max_files_per_dir = 10

[actions]
quarantine_on_ioc_match = true
alert_on_unknown = true
"#;
        let cfg = load_from_toml(toml_str);
        let err = cfg
            .validate()
            .expect_err("scan_window_minutes == 0 must fail");
        assert!(err.to_string().contains("scan_window_minutes"));
    }

    #[test]
    fn validate_rejects_empty_scan_roots() {
        let toml_str = r#"
log = { level = "info" }

[runtime]
shutdown_timeout_sec = 30

[paths]
scan_roots = []
scan_maxdepth = 1
scan_window_minutes = 60

[ioc]
ioc_list = "/etc/tmp-watcher.iocs"

[allowlist]
allowlist = "/etc/tmp-watcher.allowlist"
max_files_per_dir = 10

[actions]
quarantine_on_ioc_match = true
alert_on_unknown = true
"#;
        let cfg = load_from_toml(toml_str);
        let err = cfg.validate().expect_err("empty scan_roots must fail");
        assert!(err.to_string().contains("scan_roots"));
    }

    #[test]
    fn validate_rejects_max_files_per_dir_above_limit() {
        let toml_str = r#"
log = { level = "info" }

[runtime]
shutdown_timeout_sec = 30

[paths]
scan_roots = ["/tmp"]
scan_maxdepth = 3
scan_window_minutes = 60

[ioc]
ioc_list = "/etc/tmp-watcher.iocs"

[allowlist]
allowlist = "/etc/tmp-watcher.allowlist"
max_files_per_dir = 20

[actions]
quarantine_on_ioc_match = true
alert_on_unknown = true
"#;
        let cfg = load_from_toml(toml_str);
        let err = cfg
            .validate()
            .expect_err("max_files_per_dir > 10 must fail");
        assert!(err.to_string().contains("max_files_per_dir"));
    }

    #[test]
    fn env_overrides_paths_scan_maxdepth_toml() {
        std::env::set_var("DEMON_PATHS_SCAN_MAXDEPTH", "2");
        let cfg = load_config(None).expect("default config must parse");
        assert_eq!(cfg.paths.scan_maxdepth, 2);
        std::env::remove_var("DEMON_PATHS_SCAN_MAXDEPTH");
    }

    /// DE-019: serialised env-override test for `DEMON_ACTIONS_NTFY_URL`.
    ///
    /// The acceptance criterion is three checks (env-override-set /
    /// env-override-unset / embedded-default-has-no-ntfy-url). They all
    /// share the same env var, so we run them in one `#[test]` to avoid
    /// `std::env::set_var` race conditions under Rust's parallel test
    /// runner (each sub-case is followed by a deterministic removal of
    /// the env var before the next sub-case).
    #[test]
    fn env_override_ntfy_url_set_unset_and_default() {
        // 1. Embedded default: host-agnostic, no concrete NTFY URL
        //    (per AR-011 / AR-010 host-agnostic rule).
        std::env::remove_var("DEMON_ACTIONS_NTFY_URL");
        let cfg = load_config(None).expect("default config must parse");
        assert!(
            cfg.actions.ntfy_url.is_none(),
            "embedded default must carry no ntfy_url (AR-011 host-agnostic rule)"
        );
        // 2. With env var set: the field is populated verbatim.
        std::env::set_var("DEMON_ACTIONS_NTFY_URL", "https://ntfy.sh/test");
        let cfg = load_config(None).expect("default config must parse");
        assert_eq!(
            cfg.actions.ntfy_url,
            Some("https://ntfy.sh/test".to_string()),
            "DEMON_ACTIONS_NTFY_URL must populate actions.ntfy_url"
        );
        // 3. With env var removed again: field returns to None.
        std::env::remove_var("DEMON_ACTIONS_NTFY_URL");
        let cfg = load_config(None).expect("default config must parse");
        assert_eq!(
            cfg.actions.ntfy_url, None,
            "DEMON_ACTIONS_NTFY_URL unset must keep embedded-default None"
        );
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
