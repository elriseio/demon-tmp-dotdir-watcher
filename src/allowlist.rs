#![allow(dead_code)]

// AR-004: glob-based allowlist filter for known-good dot-directories.
// Loader contract: docs/contracts/tmp-watcher-allowlist-ioc.md § File:
// `/etc/tmp-watcher.allowlist`. Wired into the runtime by AR-008.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Result;
use globset::{Glob, GlobMatcher};

pub struct Allowlist {
    patterns: Vec<String>,
    matchers: Vec<GlobMatcher>,
}

impl std::fmt::Debug for Allowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allowlist")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

impl Allowlist {
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
            matchers: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Allowlist> {
        let reader = match File::open(path) {
            Ok(file) => BufReader::new(file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    allowlist = %path.display(),
                    "allowlist file missing; using empty in-memory allowlist"
                );
                return Ok(Self::empty());
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                tracing::warn!(
                    allowlist = %path.display(),
                    "allowlist file unreadable (permission denied); using empty in-memory allowlist"
                );
                return Ok(Self::empty());
            }
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context(format!("open allowlist {}", path.display()))
                );
            }
        };

        let mut patterns = Vec::new();
        let mut matchers = Vec::new();
        for (lineno, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "read allowlist line {} of {}",
                        lineno + 1,
                        path.display()
                    )));
                }
            };
            let trimmed = line.trim_end();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match Glob::new(trimmed) {
                Ok(g) => {
                    patterns.push(trimmed.to_string());
                    matchers.push(g.compile_matcher());
                }
                Err(e) => {
                    tracing::warn!(
                        allowlist = %path.display(),
                        line = lineno + 1,
                        pattern = %trimmed,
                        error = %e,
                        "allowlist: malformed pattern; skipping"
                    );
                }
            }
        }
        Ok(Allowlist { patterns, matchers })
    }

    pub fn allows(&self, basename: &str) -> bool {
        self.matchers.iter().any(|m| m.is_match(basename))
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempFile;
    use std::fs;

    #[test]
    fn allows_matches_anchored_glob() {
        let content = b"systemd-private-*\n";
        let f = TempFile::with_content("anchored_glob", content);
        let a = Allowlist::load(f.path()).expect("load must succeed");
        assert!(a.allows("systemd-private-abc1234"));
        assert!(!a.allows("not-systemd-private"));
    }

    #[test]
    fn load_skips_blank_and_comment_lines() {
        let content = b"# leading comment\n\n.valid-pattern\n";
        let f = TempFile::with_content("skips_blank_comment", content);
        let a = Allowlist::load(f.path()).expect("load must succeed");
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn load_returns_empty_on_missing_file() {
        let bogus = std::env::temp_dir().join("demon_allowlist_definitely_missing_67890");
        let _ = fs::remove_file(&bogus);
        let a =
            Allowlist::load(&bogus).expect("missing file must yield Ok(empty), not Err");
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn load_skips_malformed_pattern() {
        let content = b"[unclosed\n.valid-pattern\n";
        let f = TempFile::with_content("malformed_pattern", content);
        let a = Allowlist::load(f.path()).expect("malformed pattern must not fail load");
        assert_eq!(a.len(), 1, "only the valid pattern should load");
    }

    #[test]
    fn short_circuits_on_first_match() {
        let content = b".first\n.second\n";
        let f = TempFile::with_content("short_circuit", content);
        let a = Allowlist::load(f.path()).expect("load");
        assert!(a.allows(".first"));
        assert!(a.allows(".second"));
        assert!(!a.allows(".third"));
    }
}