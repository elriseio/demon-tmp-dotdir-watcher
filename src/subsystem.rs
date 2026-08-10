#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tracing::warn;

use crate::config::Config;

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
                let within = now
                    .duration_since(t)
                    .map(|d| d <= *window)
                    .unwrap_or(false);
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
            Err(e) => warn!(
                "subsystem: read_dir entry error at {}: {e}",
                dir.display()
            ),
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
    use crate::config::{
        ActionsConfig, AllowlistConfig, Config, IocConfig, LogConfig, PathsConfig,
        RuntimeConfig,
    };
    use crate::test_util::TempDir;
    use std::fs::{self, File};
    use std::path::PathBuf;

    fn set_mtime(path: &Path, t: SystemTime) {
        let f = File::open(path)
            .unwrap_or_else(|e| panic!("open {} for mtime: {e}", path.display()));
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
            vec![
                ".alpha".to_string(),
                ".mu".to_string(),
                ".zeta".to_string(),
            ]
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
        // DE-001 regression: walker must not panic on broken symlinks
        // inside the scan root. chmod-000 is unreliable in CI containers
        // (the process usually runs as root), so broken symlinks serve
        // as a stable stand-in for "per-entry iterator weirdness": they
        // survive read_dir (the entry itself is Ok) but cause downstream
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
            c.path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                == Some(".target".to_string())
        }));
        for c in &result {
            assert!(c.skipped_reason.is_none());
        }
    }
}
