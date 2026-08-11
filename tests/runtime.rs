//! AR-008 integration test: SIGTERM yields a clean shutdown.
//!
//! Boots the daemon with a tempdir scan_root (via a generated
//! YAML config), sends SIGTERM after 2 seconds, asserts the
//! process exited 0 and the final log line `exit: clean shutdown`
//! appeared on stdout (where `init_logging` writes by default).

use std::io::Write;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;

const BIN: &str = env!("CARGO_PKG_NAME");

#[test]
fn sigterm_yields_clean_shutdown() {
    // Build a self-contained tempdir containing a generated
    // config that points its only scan_root at the tempdir.
    // This avoids touching /tmp, /home, /var/tmp in CI
    // containers where one or more may be missing.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("demon_runtime_sigterm_{nanos}"));
    std::fs::create_dir_all(&tmp).expect("create tempdir");

    let cfg_path = tmp.join("config.yaml");
    {
        let mut f = std::fs::File::create(&cfg_path).expect("create config.yaml");
        // Write the YAML as discrete lines so the inner double
        // quotes don't have to be escape-mangled through a raw
        // string literal.
        let scan_root = tmp.display().to_string();
        let yaml_lines = [
            "log:",
            "  level: info",
            "runtime:",
            "  shutdown_timeout_sec: 5",
            "paths:",
            &format!("  scan_roots: [\"{scan_root}\"]"),
            "  scan_maxdepth: 1",
            "  scan_window_minutes: 1440",
            "ioc:",
            "  ioc_list: \"/dev/null\"",
            "  ioc_archive_ref: null",
            "allowlist:",
            "  allowlist: \"/dev/null\"",
            "  max_files_per_dir: 10",
            "actions:",
            "  quarantine_on_ioc_match: false",
            "  alert_on_unknown: false",
        ];
        for line in &yaml_lines {
            writeln!(f, "{line}").expect("write config line");
        }
    }

    // AR-008 acceptance: SIGTERM (NOT SIGKILL) yields exit_code 0.
    // assert_cmd::Command::spawn() is private in assert_cmd 2.2.2,
    // so we resolve the binary path via `cargo_bin` and use
    // `std::process::Command` directly.
    let bin_path = cargo_bin(BIN);
    let child = std::process::Command::new(&bin_path)
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    // Give the daemon a moment to boot + enter the runtime loop.
    std::thread::sleep(Duration::from_secs(2));

    // AR-008 acceptance: send SIGTERM and verify clean shutdown.
    // SIGKILL would also kill the process but with exit code
    // 128+9=137 (not 0), defeating the test's `exit_code == 0`
    // assertion. SIGTERM lets the daemon's `tokio::select!` arm
    // observe the watch notification and exit 0.
    //
    // SAFETY: `child.id()` returns a valid OS pid until we
    // `wait()` on it; `libc::kill` is a libc wrapper that does
    // not dereference user pointers, so an `unsafe` block is
    // the standard Rust idiom here.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }

    let output = child.wait_with_output().expect("wait daemon");

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit code 0 on SIGTERM; got {:?}, stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("exit: clean shutdown"),
        "expected 'exit: clean shutdown' in stdout; got {stdout:?}"
    );

    // Best-effort cleanup of the tempdir.
    let _ = std::fs::remove_dir_all(&tmp);
}
