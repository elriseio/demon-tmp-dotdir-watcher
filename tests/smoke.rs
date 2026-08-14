use std::time::{Duration, SystemTime};

use assert_cmd::Command;
use predicates::prelude::*;

// AR-007 § scope 2: bind to `env!("CARGO_PKG_NAME")` instead of a
// hardcoded literal so a future rename of the binary name in
// `Cargo.toml` does not silently regress this integration test.
const BIN: &str = env!("CARGO_PKG_NAME");

#[test]
fn help_flag_prints_usage() {
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn help_flag_lists_validate_config_and_dry_run() {
    // AR-007 acceptance: `--help` lists both new flags so the
    // operator runbook references survive the Rust port.
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--validate-config"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn exits_clean_when_config_is_invalid() {
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("/nonexistent/config.yaml")
        .timeout(Duration::from_secs(5))
        .assert()
        .failure();
}

#[test]
fn validate_config_succeeds_against_embedded_default() {
    // AR-007 acceptance: `--validate-config` with no positional
    // arg must load the embedded default config, validate it, and
    // exit 0.
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--validate-config")
        .assert()
        .success();
}

#[test]
fn validate_config_nonexistent_path_exits_nonzero() {
    // AR-007 acceptance: `--validate-config /nonexistent/...` must
    // exit non-zero (the file load fails before validation runs).
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--validate-config")
        .arg("/nonexistent/config.yaml")
        .timeout(Duration::from_secs(5))
        .assert()
        .failure();
}

#[test]
fn dry_run_succeeds_and_prints_dry_run_to_stderr() {
    // AR-007 acceptance: `--dry-run` (no arg) must exit 0 AND emit
    // at least one log line tagged `dry-run` to stderr. AR-008
    // wires the full Decision pipeline + output::emit_* calls;
    // here we only need the operator-visible walk summary to
    // confirm config + scan_roots coverage.
    //
    // AR-013: The Proposer opens `/etc/tmp-watcher.proposed.iocs`
    // at startup; CI containers lack write access to /etc, so the
    // test rewrites the env override to a writable tempdir.
    let nanos = std::time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("demon_smoke_dryrun_{nanos}"));
    std::fs::create_dir_all(&tmp).expect("create tempdir");
    let proposal_path = tmp.join("proposed.iocs").display().to_string();
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--dry-run")
        .env("DEMON_IOC_PROPOSED_IOCS", &proposal_path)
        .timeout(Duration::from_secs(10))
        .assert()
        .success()
        .stderr(predicate::str::contains("dry-run"));
    let _ = std::fs::remove_dir_all(&tmp);
}

// ADR-0002 § 9 test 8 (runtime-side): `--dry-run` against an
// overlay fixture must complete without `chmod 0o000` on the
// overlay path. `--dry-run` already forces
// `actions.quarantine_on_ioc_match = false` in `main.rs`; this
// test verifies the runtime path walks the overlay candidates
// without mutating them. We also assert that `--dry-run` exits 0
// and emits the dry-run tag so the operator sees coverage.
#[test]
fn dry_run_against_overlay_fixture_does_not_quarantine() {
    let nanos = std::time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let overlay_root = std::env::temp_dir().join(format!("demon_overlay_smoke_{nanos}"));
    let layer_dir = overlay_root.join("smoke-layer");
    let tmp_dot = layer_dir.join("diff").join("tmp").join(".r.rpk");
    std::fs::create_dir_all(&tmp_dot).expect("create overlay fixture tmp/.r.rpk");
    std::fs::write(tmp_dot.join("seed.txt"), b"smoke-fixture\n").expect("write seed");

    let proposal_path = overlay_root.join("proposed.iocs");
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--dry-run")
        .env("DEMON_PATHS_SCAN_ROOTS", "/nope")
        .env("DEMON_PATHS_OVERLAY_SCAN_ROOTS", overlay_root.display().to_string())
        .env("DEMON_IOC_PROPOSED_IOCS", proposal_path.display().to_string())
        .timeout(Duration::from_secs(10))
        .assert()
        .success()
        .stderr(predicate::str::contains("dry-run"));

    // Verify the overlay fixture path is still readable; if
    // dry-run had called chmod 0o000, this metadata() would still
    // succeed on Linux (per subsystem::quarantine tests) but the
    // directory listing would not. We assert the seed file is
    // still present as a stronger end-to-end check.
    let seed_still_present = tmp_dot.join("seed.txt").exists();
    let _ = std::fs::remove_dir_all(&overlay_root);
    assert!(
        seed_still_present,
        "dry-run must not delete or otherwise remove the overlay fixture",
    );
}
