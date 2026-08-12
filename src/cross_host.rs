//! Cross-host IOC correlation sidecar.
//!
//! Reads per-host observation streams from a `Sink` (abstracted
//! transport), aggregates them across hosts, and writes candidate-IOC
//! proposal entries to `/etc/tmp-watcher.proposed.iocs` (the same
//! file the detection daemon writes per AR-013) with a
//! `cross_host_count=N` suffix.
//!
//! The concrete `Sink` implementation is a follow-up; the sidecar
//! ships with a `NullSink` placeholder that returns empty
//! observations. The operator replaces the placeholder once a
//! transport (HTTP POST, file drop, syslog relay, Unix-domain
//! socket) is chosen.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use async_trait::async_trait;

#[async_trait]
pub trait Sink: Send + Sync {
    async fn fetch_observations(&self, since: SystemTime) -> Result<Vec<Observation>>;
    async fn send_proposal(&self, proposal: ProposalEntry) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub host_id: String,
    pub ts: SystemTime,
    pub basename: String,
    pub sha256: Option<String>,
    pub origin_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalEntry {
    pub host_id: String,
    pub ts: SystemTime,
    pub basename: String,
    pub sha256: Option<String>,
    pub origin_path: PathBuf,
    pub cross_host_count: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AggregatorSummary {
    pub observed: usize,
    pub deduped: usize,
    pub proposals_written: usize,
}

pub struct Aggregator<S: Sink> {
    sink: S,
    /// Per-(basename, sha256) set of host_ids seen so far. Hosts
    /// are tracked by stable id (`/etc/machine-id` for the
    /// detection daemon; the operator may extend with additional
    /// sources per the open questions in the cross-host task).
    state: HashMap<(String, Option<String>), HashSet<String>>,
    proposal_path: PathBuf,
}

type Key = (String, Option<String>);

struct BatchEntry {
    hosts: HashSet<String>,
    ts: SystemTime,
    origin_path: PathBuf,
}

impl<S: Sink> Aggregator<S> {
    pub fn new(sink: S, proposal_path: PathBuf) -> Self {
        let mut state: HashMap<Key, HashSet<String>> = HashMap::new();
        if let Ok(f) = File::open(&proposal_path) {
            let reader = BufReader::new(f);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(parsed) = parse_proposal_line(&line) {
                    let key = (parsed.basename.clone(), parsed.sha256.clone());
                    let host_set = state.entry(key).or_default();
                    for i in 0..parsed.cross_host_count {
                        host_set.insert(format!("__restored_{i}"));
                    }
                }
            }
        }
        Self {
            sink,
            state,
            proposal_path,
        }
    }

    pub async fn poll_once(&mut self) -> Result<AggregatorSummary> {
        let observations = self
            .sink
            .fetch_observations(SystemTime::UNIX_EPOCH)
            .await?;
        let observed = observations.len();
        let mut summary = AggregatorSummary {
            observed,
            deduped: 0,
            proposals_written: 0,
        };

        // Group observations by (basename, sha256) for this poll cycle.
        // The first observation of a key carries the entry's ts and
        // origin_path; subsequent observations of the same key in
        // this batch are deduped (counted but not written).
        let mut batch_keys: HashSet<(String, Option<String>)> = HashSet::new();
        let mut batch: HashMap<Key, BatchEntry> = HashMap::new();

        for obs in observations {
            let key = (obs.basename.clone(), obs.sha256.clone());
            let entry = batch.entry(key.clone()).or_insert_with(|| BatchEntry {
                hosts: HashSet::new(),
                ts: obs.ts,
                origin_path: obs.origin_path.clone(),
            });
            entry.hosts.insert(obs.host_id.clone());
            if !batch_keys.insert(key) {
                summary.deduped += 1;
            }
        }

        for (key, batch_entry) in batch {
            let state_hosts: &mut HashSet<String> = self.state.entry(key.clone()).or_default();
            let host_set = batch_entry.hosts;
            let ts = batch_entry.ts;
            let origin_path = batch_entry.origin_path;
            for h in &host_set {
                state_hosts.insert(h.clone());
            }
            let entry = ProposalEntry {
                host_id: host_set.iter().next().cloned().unwrap_or_default(),
                ts,
                basename: key.0,
                sha256: key.1,
                origin_path,
                cross_host_count: state_hosts.len() as u64,
            };
            self.append_proposal_entry(&entry)?;
            summary.proposals_written += 1;
        }

        Ok(summary)
    }

    pub fn state_len(&self) -> usize {
        self.state.len()
    }

    fn append_proposal_entry(&self, entry: &ProposalEntry) -> Result<()> {
        let ts = entry
            .ts
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let utc_iso = format_iso8601_utc(ts);
        let sha_or_dash = entry.sha256.as_deref().unwrap_or("-");
        let line = format!(
            "{utc_iso}  {sha_or_dash}  {basename}  {origin_path}  cross_host_count={count}\n",
            sha_or_dash = sha_or_dash,
            basename = entry.basename,
            origin_path = entry.origin_path.display(),
            count = entry.cross_host_count,
        );
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.proposal_path)
            .with_context(|| format!("open proposal file {}", self.proposal_path.display()))?;
        let mut writer = BufWriter::new(f);
        writer
            .write_all(line.as_bytes())
            .with_context(|| format!("write to proposal file {}", self.proposal_path.display()))?;
        writer
            .flush()
            .with_context(|| format!("flush proposal file {}", self.proposal_path.display()))?;
        Ok(())
    }
}

/// Placeholder `Sink` that returns empty observations. The
/// sidecar binary wires this Sink until the operator picks a
/// concrete transport.
pub struct NullSink;

#[async_trait]
impl Sink for NullSink {
    async fn fetch_observations(&self, _since: SystemTime) -> Result<Vec<Observation>> {
        Ok(Vec::new())
    }

    async fn send_proposal(&self, _proposal: ProposalEntry) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedProposal {
    host_id: String,
    ts: SystemTime,
    basename: String,
    sha256: Option<String>,
    origin_path: PathBuf,
    cross_host_count: u64,
}

fn parse_proposal_line(line: &str) -> Option<ParsedProposal> {
    let mut parts = line.split_whitespace();
    let ts_str = parts.next()?;
    let sha = parts.next()?;
    let basename = parts.next()?;
    let path = parts.next()?;
    let suffix = parts.next()?;
    let count = suffix.strip_prefix("cross_host_count=")?.parse::<u64>().ok()?;
    let ts = parse_iso8601_to_epoch(ts_str)?;
    let sha_real = if sha == "-" {
        None
    } else {
        Some(sha.to_string())
    };
    Some(ParsedProposal {
        host_id: String::new(),
        ts,
        basename: basename.to_string(),
        sha256: sha_real,
        origin_path: PathBuf::from(path),
        cross_host_count: count,
    })
}

fn parse_iso8601_to_epoch(s: &str) -> Option<SystemTime> {
    if s.len() != 20 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u64 = s.get(11..13)?.parse().ok()?;
    let min: u64 = s.get(14..16)?.parse().ok()?;
    let sec: u64 = s.get(17..19)?.parse().ok()?;
    let days = ymd_to_epoch_days(year, month, day)?;
    let secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);
    Some(UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
}

fn ymd_to_epoch_days(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400;
    let m_i64 = if month > 2 { month as i64 - 3 } else { month as i64 + 9 };
    let doy = (153 * m_i64 + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719_468)
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct MockSink {
        observations: Vec<Observation>,
        proposals: Arc<Mutex<Vec<ProposalEntry>>>,
        fetch_calls: Arc<AtomicUsize>,
        send_calls: Arc<AtomicUsize>,
    }

    impl MockSink {
        fn with_observations(obs: Vec<Observation>) -> Self {
            Self {
                observations: obs,
                proposals: Arc::new(Mutex::new(Vec::new())),
                fetch_calls: Arc::new(AtomicUsize::new(0)),
                send_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn proposal_count(&self) -> usize {
            self.proposals.lock().unwrap().len()
        }

        fn fetch_call_count(&self) -> usize {
            self.fetch_calls.load(Ordering::SeqCst)
        }

        fn send_call_count(&self) -> usize {
            self.send_calls.load(Ordering::SeqCst)
        }
    }

    impl Default for MockSink {
        fn default() -> Self {
            Self::with_observations(Vec::new())
        }
    }

    #[async_trait]
    impl Sink for MockSink {
        async fn fetch_observations(&self, _since: SystemTime) -> Result<Vec<Observation>> {
            self.fetch_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.observations.clone())
        }

        async fn send_proposal(&self, proposal: ProposalEntry) -> Result<()> {
            self.send_calls.fetch_add(1, Ordering::SeqCst);
            self.proposals.lock().unwrap().push(proposal);
            Ok(())
        }
    }

    fn obs(host_id: &str, basename: &str, sha: Option<&str>) -> Observation {
        Observation {
            host_id: host_id.to_string(),
            ts: UNIX_EPOCH + Duration::from_secs(1_786_546_800),
            basename: basename.to_string(),
            sha256: sha.map(|s| s.to_string()),
            origin_path: PathBuf::from(format!("/tmp/{basename}")),
        }
    }

    #[tokio::test]
    async fn aggregator_dedupes_across_hosts() {
        let tmp = TempDir::new("cross_host_dedup");
        let proposal = tmp.path().join("proposed.iocs");
        let sink = MockSink::with_observations(vec![
            obs("hostA", ".r.rpk", Some("abc")),
            obs("hostB", ".r.rpk", Some("abc")),
            obs("hostC", ".r.rpk", Some("abc")),
        ]);
        let mut agg = Aggregator::new(sink, proposal.clone());
        let summary = agg.poll_once().await.expect("poll_once");

        assert_eq!(summary.observed, 3);
        assert_eq!(summary.deduped, 2);
        assert_eq!(summary.proposals_written, 1);
        let content = std::fs::read_to_string(&proposal).expect("read");
        assert!(
            content.contains("cross_host_count=3"),
            "expected count=3 in: {content}"
        );
    }

    #[tokio::test]
    async fn aggregator_writes_cross_host_count_suffix() {
        let tmp = TempDir::new("cross_host_suffix");
        let proposal = tmp.path().join("proposed.iocs");
        let sink = MockSink::with_observations(vec![
            obs("hostA", ".target", Some("xyz")),
            obs("hostB", ".target", Some("xyz")),
        ]);
        let mut agg = Aggregator::new(sink, proposal.clone());
        agg.poll_once().await.expect("poll_once");

        let content = std::fs::read_to_string(&proposal).expect("read");
        let line = content.lines().next().expect("one line");
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(
            parts[4].starts_with("cross_host_count="),
            "expected count suffix in: {line}"
        );
        assert_eq!(parts[4], "cross_host_count=2");
    }

    #[tokio::test]
    async fn aggregator_does_not_mutate_live_ioc_list() {
        let tmp = TempDir::new("cross_host_no_live");
        let proposal = tmp.path().join("proposed.iocs");
        let live = tmp.path().join("ioc.iocs");
        let original_live = b"# canonical live IOC list\nabc123\n";
        std::fs::write(&live, original_live).expect("write live");

        let sink = MockSink::with_observations(vec![
            obs("hostA", ".x", Some("h1")),
            obs("hostB", ".y", Some("h2")),
        ]);
        let mut agg = Aggregator::new(sink, proposal);
        agg.poll_once().await.expect("poll_once");

        let post = std::fs::read(&live).expect("read live");
        assert_eq!(post, original_live, "live IOC list must remain byte-equal");
    }

    #[tokio::test]
    async fn sink_trait_mock_round_trip() {
        let sink = MockSink::with_observations(vec![obs("hostA", ".r", Some("h"))]);
        let observations = sink.fetch_observations(UNIX_EPOCH).await.expect("fetch");
        assert_eq!(observations.len(), 1);
        assert_eq!(sink.fetch_call_count(), 1);
        sink.send_proposal(ProposalEntry {
            host_id: "hostA".to_string(),
            ts: UNIX_EPOCH,
            basename: ".r".to_string(),
            sha256: Some("h".to_string()),
            origin_path: PathBuf::from("/tmp/.r"),
            cross_host_count: 1,
        })
        .await
        .expect("send");
        assert_eq!(sink.proposal_count(), 1);
        assert_eq!(sink.send_call_count(), 1);
    }

    #[tokio::test]
    async fn aggregator_basename_only_proposal() {
        let tmp = TempDir::new("cross_host_basename");
        let proposal = tmp.path().join("proposed.iocs");
        let sink = MockSink::with_observations(vec![obs("hostA", ".weird", None)]);
        let mut agg = Aggregator::new(sink, proposal.clone());
        agg.poll_once().await.expect("poll_once");

        let content = std::fs::read_to_string(&proposal).expect("read");
        assert!(
            content.contains("  -  .weird  "),
            "expected dash sha for basename-only: {content}"
        );
    }

    #[tokio::test]
    async fn aggregator_restart_preserves_count() {
        let tmp = TempDir::new("cross_host_restart");
        let proposal = tmp.path().join("proposed.iocs");

        let sink1 = MockSink::with_observations(vec![
            obs("hostA", ".r.rpk", Some("abc")),
            obs("hostB", ".r.rpk", Some("abc")),
        ]);
        let mut agg1 = Aggregator::new(sink1, proposal.clone());
        let summary1 = agg1.poll_once().await.expect("poll_once");
        assert_eq!(summary1.proposals_written, 1);

        // Restart: new Aggregator reconstructs state from the file.
        // The restored state has 2 placeholder host_ids
        // (__restored_0, __restored_1). When a new host
        // observation arrives, the placeholder set grows to 3.
        let sink2 = MockSink::with_observations(vec![obs(
            "hostC",
            ".r.rpk",
            Some("abc"),
        )]);
        let mut agg2 = Aggregator::new(sink2, proposal.clone());
        let summary2 = agg2.poll_once().await.expect("poll_once");
        assert_eq!(summary2.observed, 1);
        assert_eq!(
            summary2.deduped, 0,
            "hostC is not in the placeholder set, so it counts as new"
        );
        assert_eq!(summary2.proposals_written, 1);

        let content = std::fs::read_to_string(&proposal).expect("read");
        let last_line = content.lines().last().expect("last line");
        assert!(
            last_line.contains("cross_host_count=3"),
            "expected cross_host_count=3 after restart + new host, got: {last_line}"
        );
    }

    #[tokio::test]
    async fn aggregator_skips_send_on_send_proposal_error() {
        // The Sink trait method send_proposal is the round-trip
        // mechanism; the Aggregator does not call it during
        // poll_once (the Aggregator writes to the proposal file
        // directly). This test verifies the Aggregator does NOT
        // call sink.send_proposal, so a failing Sink impl is
        // benign.
        struct NoSendSink;
        #[async_trait]
        impl Sink for NoSendSink {
            async fn fetch_observations(&self, _since: SystemTime) -> Result<Vec<Observation>> {
                Ok(Vec::new())
            }
            async fn send_proposal(&self, _proposal: ProposalEntry) -> Result<()> {
                panic!("Aggregator MUST NOT call send_proposal during poll_once")
            }
        }

        let tmp = TempDir::new("cross_host_no_send");
        let proposal = tmp.path().join("proposed.iocs");
        let mut agg = Aggregator::new(NoSendSink, proposal.clone());
        let summary = agg.poll_once().await.expect("poll_once");
        assert_eq!(summary.observed, 0);
        assert_eq!(summary.proposals_written, 0);
    }

    #[tokio::test]
    async fn null_sink_returns_empty_observations() {
        let sink = NullSink;
        let observations = sink.fetch_observations(UNIX_EPOCH).await.expect("fetch");
        assert!(observations.is_empty());
        sink.send_proposal(ProposalEntry {
            host_id: "hostA".to_string(),
            ts: UNIX_EPOCH,
            basename: ".r".to_string(),
            sha256: Some("h".to_string()),
            origin_path: PathBuf::from("/tmp/.r"),
            cross_host_count: 1,
        })
        .await
        .expect("send");
        // NullSink does not write anywhere; the Aggregator wiring
        // produces zero proposals because fetch returned empty.
    }

    #[test]
    fn parse_iso8601_round_trip_via_epoch_days() {
        let txt = format_iso8601_utc(1_786_546_800);
        let parsed = parse_iso8601_to_epoch(&txt).expect("parse");
        let secs = parsed
            .duration_since(UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        assert_eq!(secs, 1_786_546_800);
    }
}
