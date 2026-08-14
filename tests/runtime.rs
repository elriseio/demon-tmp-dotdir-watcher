//! CR-005 regression tests: oneshot runtime contract.
//!
//! Boots the daemon with a tempdir scan_root (via a generated
//! TOML config), asserts:
//!   1. `daemon_exits_cleanly_after_one_poll` — exit 0 within
//!      the boot+poll budget, with no SIGTERM sent. This is the
//!      primary regression test for the CR-005 fix (Runtime::run
//!      must exit after exactly one poll, not loop forever).
//!   2. `sigterm_yields_clean_shutdown` — backwards-compat test:
//!      SIGTERM still yields exit 0 (CR-005 must not regress
//!      signal handling).

use std::io::Write;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;

const BIN: &str = env!("CARGO_PKG_NAME");

/// Write a self-contained TOML config that points the daemon's
/// only `scan_root` at `tmp` and `quarantine_on_ioc_match: false`
/// so the test cannot mutate the host regardless of what the
/// fixture contains.
fn write_minimal_config(tmp: &std::path::Path) -> std::path::PathBuf {
    let cfg_path = tmp.join("config.toml");
    let mut f = std::fs::File::create(&cfg_path).expect("create config.toml");
    let scan_root = tmp.display().to_string();
    let proposal_path = tmp.join("proposed.iocs").display().to_string();
    let toml_lines = [
        "log = { level = \"info\" }",
        "",
        "[runtime]",
        "shutdown_timeout_sec = 5",
        "",
        "[paths]",
        &format!("scan_roots = [\"{scan_root}\"]"),
        "scan_maxdepth = 1",
        "scan_window_minutes = 1440",
        "",
        "[ioc]",
        "ioc_list = \"/dev/null\"",
        &format!("proposed_iocs = \"{proposal_path}\""),
        "",
        "[allowlist]",
        "allowlist = \"/dev/null\"",
        "max_files_per_dir = 10",
        "",
        "[actions]",
        "quarantine_on_ioc_match = false",
        "alert_on_unknown = false",
    ];
    for line in &toml_lines {
        writeln!(f, "{line}").expect("write config line");
    }
    cfg_path
}

/// CR-005 acceptance: production daemon exits 0 after exactly
/// one `run_once()` invocation, with no SIGTERM required.
/// Without the fix, `Runtime::run` drove an infinite 1-second
/// loop and `wait_with_output` would block until the test's
/// timeout, never seeing `exit_code == 0`. With the fix, the
/// daemon boots, runs one poll on an empty tempdir, emits
/// `runtime: oneshot poll complete`, then `exit: clean shutdown`,
/// and exits 0 within a bounded budget.
#[test]
fn daemon_exits_cleanly_after_one_poll() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("demon_runtime_oneshot_{nanos}"));
    std::fs::create_dir_all(&tmp).expect("create tempdir");
    let cfg_path = write_minimal_config(&tmp);

    let bin_path = cargo_bin(BIN);
    let mut child = std::process::Command::new(&bin_path)
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    // Bounded wait: the oneshot daemon exits on its own within
    // boot + one poll + journal flush. Poll `try_wait` at 100 ms
    // intervals up to a 10 s budget. The legacy infinite-loop
    // bug would exceed this budget and the test would time out
    // (fail), which is exactly the regression signal we want.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None => {
                if std::time::Instant::now() >= deadline {
                    panic!("daemon did not exit within 10s; CR-005 oneshot contract violated");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let output = child.wait_with_output().expect("wait_with_output");

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit code 0 from oneshot poll; got {:?}, stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("runtime: oneshot poll complete"),
        "expected oneshot completion log; got {stdout:?}"
    );
    assert!(
        stdout.contains("exit: clean shutdown"),
        "expected 'exit: clean shutdown' in stdout; got {stdout:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn sigterm_yields_clean_shutdown() {
    // AR-008 + CR-005 acceptance: SIGTERM (NOT SIGKILL) yields
    // exit_code 0 regardless of whether the daemon is still
    // mid-poll or has already exited on its own. CR-005 makes
    // the production path a `Type=oneshot` runtime that exits
    // after one poll, so on a fast empty-tree poll the daemon
    // may have already exited by the time the 2-second sleep
    // completes — the SIGTERM is then sent to a reaped pid
    // (no-op). The test still asserts exit_code == 0 and
    // `exit: clean shutdown` in stdout, which holds under both
    // regimes.
    //
    // assert_cmd::Command::spawn() is private in assert_cmd 2.2.2,
    // so we resolve the binary path via `cargo_bin` and use
    // `std::process::Command` directly.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("demon_runtime_sigterm_{nanos}"));
    std::fs::create_dir_all(&tmp).expect("create tempdir");
    let cfg_path = write_minimal_config(&tmp);

    let bin_path = cargo_bin(BIN);
    let child = std::process::Command::new(&bin_path)
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    // Give the daemon a moment to boot + run its oneshot poll
    // (which now exits on its own) OR enter the runtime loop
    // (legacy AR-008 only — kept here for backwards compat).
    std::thread::sleep(Duration::from_secs(2));

    // SIGTERM lets the daemon's `tokio::select!` arm observe
    // the watch notification and exit 0 if it is still alive.
    // If the daemon already exited (CR-005 oneshot contract),
    // `libc::kill` is a no-op against the reaped pid.
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
