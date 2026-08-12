//! Auto-promote `Decision::Unknown` events to a candidate-IOC
//! proposal file. The live IOC list is never mutated by this
//! module; `tmp-watcher-promote` (separate CLI tool, future scope)
//! is the only writer of `/etc/tmp-watcher.iocs`.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

const ROTATION_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const ROTATION_AGE_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_ROTATION_DIR: &str = "/var/log/tmp-watcher";

#[derive(Debug, PartialEq, Eq)]
pub enum ProposalAction {
    Appended,
    Duplicate,
    FileRotated,
}

#[derive(Debug)]
pub struct Proposer {
    path: PathBuf,
    dedupe: HashSet<(String, String)>,
    file_mtime: SystemTime,
    max_size_bytes: u64,
    max_age_secs: u64,
    rotation_dir: PathBuf,
}

impl Proposer {
    pub fn new(path: &Path) -> Result<Self> {
        Self::with_thresholds(
            path,
            ROTATION_SIZE_BYTES,
            ROTATION_AGE_SECS,
            Path::new(DEFAULT_ROTATION_DIR),
        )
    }

    fn with_thresholds(
        path: &Path,
        max_size_bytes: u64,
        max_age_secs: u64,
        rotation_dir: &Path,
    ) -> Result<Self> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open proposal file {}", path.display()))?;

        let mut dedupe = HashSet::new();
        if let Ok(f) = File::open(path) {
            let reader = BufReader::new(f);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(key) = parse_entry(&line) {
                    dedupe.insert(key);
                }
            }
        }

        let file_mtime = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| SystemTime::now());

        Ok(Self {
            path: path.to_path_buf(),
            dedupe,
            file_mtime,
            max_size_bytes,
            max_age_secs,
            rotation_dir: rotation_dir.to_path_buf(),
        })
    }

    pub fn observe(
        &mut self,
        basename: &str,
        sha256: &str,
        first_seen_path: &Path,
    ) -> Result<ProposalAction> {
        let key = (basename.to_string(), sha256.to_string());
        if self.dedupe.contains(&key) {
            return Ok(ProposalAction::Duplicate);
        }

        let rotated = self.should_rotate()?;
        if rotated {
            self.rotate()?;
            self.dedupe.clear();
            self.file_mtime = SystemTime::now();
        }

        self.append_entry(basename, sha256, first_seen_path)?;
        self.dedupe.insert(key);
        Ok(if rotated {
            ProposalAction::FileRotated
        } else {
            ProposalAction::Appended
        })
    }

    #[allow(dead_code)]
    pub fn flush(&mut self) -> Result<()> {
        let f = File::open(&self.path)
            .with_context(|| format!("open proposal file for flush {}", self.path.display()))?;
        f.sync_all()
            .with_context(|| format!("sync_all proposal file {}", self.path.display()))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(dead_code)]
    pub fn dedupe_len(&self) -> usize {
        self.dedupe.len()
    }

    fn should_rotate(&self) -> Result<bool> {
        let meta = std::fs::metadata(&self.path)
            .with_context(|| format!("stat proposal file {}", self.path.display()))?;
        if meta.len() >= self.max_size_bytes {
            return Ok(true);
        }
        let age = SystemTime::now()
            .duration_since(self.file_mtime)
            .unwrap_or(Duration::ZERO);
        if age.as_secs() >= self.max_age_secs {
            return Ok(true);
        }
        Ok(false)
    }

    fn rotate(&self) -> Result<()> {
        let dest = self.rotation_path();
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create rotation dir {}", parent.display()))?;
        }
        std::fs::rename(&self.path, &dest)
            .with_context(|| format!("rotate {} -> {}", self.path.display(), dest.display()))?;
        File::create(&self.path)
            .with_context(|| format!("create empty proposal file {}", self.path.display()))?;
        Ok(())
    }

    fn rotation_path(&self) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.rotation_dir
            .join(format!("proposed-rotate-{ts}.iocs"))
    }

    fn append_entry(
        &self,
        basename: &str,
        sha256: &str,
        first_seen_path: &Path,
    ) -> Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let utc_iso = format_iso8601_utc(ts);
        let sha_or_dash = if sha256.is_empty() { "-" } else { sha256 };
        let line = format!(
            "{utc_iso}  {sha_or_dash}  {basename}  {}\n",
            first_seen_path.display(),
        );
        let f = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open proposal file for append {}", self.path.display()))?;
        let mut writer = BufWriter::new(f);
        writer
            .write_all(line.as_bytes())
            .with_context(|| format!("write to proposal file {}", self.path.display()))?;
        writer
            .flush()
            .with_context(|| format!("flush proposal file {}", self.path.display()))?;
        Ok(())
    }
}

fn parse_entry(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let _ts = parts.next()?;
    let sha = parts.next()?;
    let basename = parts.next()?;
    let sha_real = if sha == "-" {
        String::new()
    } else {
        sha.to_string()
    };
    Some((basename.to_string(), sha_real))
}

fn format_iso8601_utc(unix_secs: u64) -> String {
    let secs_in_day = 86_400u64;
    let days = (unix_secs / secs_in_day) as i64;
    let secs_today = unix_secs % secs_in_day;
    let hour = (secs_today / 3600) as u32;
    let min = ((secs_today % 3600) / 60) as u32;
    let sec = (secs_today % 60) as u32;

    let (year, month, day) = epoch_days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

fn epoch_days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Howard Hinnant's date algorithm (civil_from_days).
    // http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y_final = if m <= 2 { y + 1 } else { y } as i32;
    (y_final, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;
    use std::fs;

    fn make_proposer_with_thresholds(
        path: &Path,
        max_size: u64,
        max_age: u64,
        rotation_dir: &Path,
    ) -> Proposer {
        Proposer::with_thresholds(path, max_size, max_age, rotation_dir)
            .expect("proposer construction")
    }

    #[test]
    fn observe_first_call_appends_entry() {
        let tmp = TempDir::new("proposer_first");
        let path = tmp.path().join("proposed.iocs");
        let rotation_dir = tmp.path().join("rotate");
        let mut p = make_proposer_with_thresholds(
            &path,
            10 * 1024 * 1024,
            30 * 86400,
            &rotation_dir,
        );

        let action = p
            .observe(
                ".r.rpk",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Path::new("/tmp/.r.rpk"),
            )
            .expect("observe");

        assert_eq!(action, ProposalAction::Appended);
        let content = fs::read_to_string(&path).expect("read proposal");
        assert!(
            content.contains(".r.rpk"),
            "expected basename in proposal, got: {content}"
        );
        assert!(content.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(content.contains("/tmp/.r.rpk"));
        assert_eq!(p.dedupe_len(), 1);
    }

    #[test]
    fn observe_duplicate_does_not_reappend() {
        let tmp = TempDir::new("proposer_dedupe");
        let path = tmp.path().join("proposed.iocs");
        let rotation_dir = tmp.path().join("rotate");
        let mut p = make_proposer_with_thresholds(
            &path,
            10 * 1024 * 1024,
            30 * 86400,
            &rotation_dir,
        );

        let first = p
            .observe(".r.rpk", "abc", Path::new("/tmp/.r.rpk"))
            .expect("first observe");
        let second = p
            .observe(".r.rpk", "abc", Path::new("/tmp/.r.rpk"))
            .expect("second observe");

        assert_eq!(first, ProposalAction::Appended);
        assert_eq!(second, ProposalAction::Duplicate);

        let content = fs::read_to_string(&path).expect("read proposal");
        // The basename ".r.rpk" appears once in the proposal line
        // plus once in the path "/tmp/.r.rpk"; count lines instead
        // of substring matches.
        assert_eq!(
            content.lines().count(),
            1,
            "proposal must contain exactly one line, got: {content}"
        );
    }

    #[test]
    fn observe_basename_only_uses_dash_sha() {
        let tmp = TempDir::new("proposer_basename_only");
        let path = tmp.path().join("proposed.iocs");
        let rotation_dir = tmp.path().join("rotate");
        let mut p = make_proposer_with_thresholds(
            &path,
            10 * 1024 * 1024,
            30 * 86400,
            &rotation_dir,
        );

        let action = p
            .observe(".weird-xdg", "", Path::new("/tmp/.weird-xdg"))
            .expect("observe");
        assert_eq!(action, ProposalAction::Appended);

        let content = fs::read_to_string(&path).expect("read proposal");
        assert!(content.contains("  -  .weird-xdg  "), "expected dash sha in: {content}");
    }

    #[test]
    fn observe_dedupes_across_proposer_restart() {
        let tmp = TempDir::new("proposer_restart");
        let path = tmp.path().join("proposed.iocs");
        let rotation_dir = tmp.path().join("rotate");

        let mut p1 = make_proposer_with_thresholds(
            &path,
            10 * 1024 * 1024,
            30 * 86400,
            &rotation_dir,
        );
        p1.observe(".r.rpk", "abc", Path::new("/tmp/.r.rpk"))
            .expect("first observe");

        let mut p2 = Proposer::new(&path).expect("restart proposer");
        let action = p2
            .observe(".r.rpk", "abc", Path::new("/tmp/.r.rpk"))
            .expect("second observe after restart");
        assert_eq!(
            action,
            ProposalAction::Duplicate,
            "post-restart observe must dedupe against on-disk entries"
        );
    }

    #[test]
    fn observe_triggers_rotation_after_size_limit() {
        let tmp = TempDir::new("proposer_rot_size");
        let live = tmp.path().join("proposed.iocs");
        let rotation_dir = tmp.path().join("rotate");
        // Tight threshold so a single observation triggers rotation.
        let mut p = make_proposer_with_thresholds(&live, 0, 30 * 86400, &rotation_dir);

        let first = p
            .observe(".first", "abc", Path::new("/tmp/.first"))
            .expect("first observe triggers rotation");
        assert_eq!(first, ProposalAction::FileRotated);
        // After rotation the live file is rebuilt empty and the
        // new entry is appended; total size is the size of one
        // proposal line.
        let live_content = fs::read_to_string(&live).expect("read live");
        assert_eq!(
            live_content.lines().count(),
            1,
            "live file must have exactly one line after a rotation-then-append cycle, got: {live_content}"
        );

        let second = p
            .observe(".second", "def", Path::new("/tmp/.second"))
            .expect("second observe after rotation");
        assert_eq!(second, ProposalAction::FileRotated);
    }

    #[test]
    fn observe_does_not_touch_live_ioc_list() {
        let tmp = TempDir::new("proposer_no_live");
        let proposal = tmp.path().join("proposed.iocs");
        let live = tmp.path().join("ioc.iocs");
        let original_live = b"# canonical live IOC list\nabc123\n";
        fs::write(&live, original_live).expect("write live IOC list");

        let mut p = Proposer::new(&proposal).expect("proposer");
        for _ in 0..100 {
            p.observe(".x", "", Path::new("/tmp/.x"))
                .expect("observe");
        }

        let post = fs::read(&live).expect("read live IOC list");
        assert_eq!(post, original_live, "live IOC list must remain byte-equal");
    }

    #[test]
    fn flush_persists_pending_writes() {
        let tmp = TempDir::new("proposer_flush");
        let path = tmp.path().join("proposed.iocs");
        let mut p = Proposer::new(&path).expect("proposer");

        p.observe(".a", "abc", Path::new("/tmp/.a"))
            .expect("observe");
        p.flush().expect("flush");

        let content = fs::read_to_string(&path).expect("read");
        assert!(content.contains(".a"));
    }

    #[test]
    fn format_iso8601_utc_known_values() {
        // 2026-08-12T15:00:00Z = 1786546800 (verified by
        // `datetime.datetime(2026, 8, 12, 15, 0, 0, tzinfo=timezone.utc).timestamp()`).
        let txt = format_iso8601_utc(1_786_546_800);
        assert_eq!(txt, "2026-08-12T15:00:00Z");
    }

    #[test]
    fn epoch_days_to_ymd_known_epoch() {
        assert_eq!(epoch_days_to_ymd(0), (1970, 1, 1));
        assert_eq!(epoch_days_to_ymd(365), (1971, 1, 1));
        // 2024 is a leap year; 2024-01-01 is days 19723 from epoch.
        assert_eq!(epoch_days_to_ymd(19_723), (2024, 1, 1));
    }

    #[test]
    fn parse_entry_round_trip() {
        let line = "2026-08-12T18:30:00Z  abc123  .r.rpk  /tmp/.r.rpk";
        let parsed = parse_entry(line).expect("parse");
        assert_eq!(parsed, (".r.rpk".to_string(), "abc123".to_string()));

        let line2 = "2026-08-12T18:30:00Z  -  .weird-xdg  /tmp/.weird-xdg";
        let parsed2 = parse_entry(line2).expect("parse");
        assert_eq!(parsed2, (".weird-xdg".to_string(), String::new()));
    }
}
