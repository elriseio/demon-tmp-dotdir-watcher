use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_flag_prints_usage() {
    Command::cargo_bin("demon-tmp-dotdir-watcher")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn exits_clean_when_config_is_invalid() {
    Command::cargo_bin("demon-tmp-dotdir-watcher")
        .unwrap()
        .arg("/nonexistent/config.yaml")
        .timeout(Duration::from_secs(5))
        .assert()
        .failure();
}
