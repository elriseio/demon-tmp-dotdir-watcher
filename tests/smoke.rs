use std::time::Duration;

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
    Command::cargo_bin(BIN)
        .unwrap()
        .arg("--dry-run")
        .timeout(Duration::from_secs(10))
        .assert()
        .success()
        .stderr(predicate::str::contains("dry-run"));
}
