# tmp-dotdir-watcher

```
Demon:           tmp-dotdir-watcher
Crate:           demon-tmp-dotdir-watcher (v0.1.0)
Edition / MSRV:  Rust 2021 / 1.74
Host target:     single Linux host running systemd
Cadence:         every 10 minutes (systemd timer)
Severity:        high — would have detected an Azazel-family
                 compromise on an affected host 71 hours earlier than
                 operator-flagged 502 detection
```

## What it is

A host-resident Rust daemon that scans shallow dot-directories
on a Linux box (`/tmp`, `/home`, `/var/tmp`) every ten minutes,
matches their contents against a SHA-256 IOC list, and
auto-quarantines any hit by stripping permissions (`chmod 000`)
on the directory. Anything that escapes the allowlist but does
not match an IOC is logged at WARNING for operator triage.

Hidden Azazel-style malware drops everything it needs under
directories whose names start with a dot and live close to the
filesystem root: `.r.rpk/`, `.xdiag/`, `.perf.c/`, `.apid/`,
or `.atmp/`. systemd-tmpfiles cleanup does not touch them, and
they sit well inside the noise floor of a busy `/tmp/`. This
daemon is a bounded, idempotent detector that surfaces them on
the same day they appear.

The canonical operator-facing description (problem statement,
algorithm, configuration, failure modes) lives in `ORIGIN.md`.
This README is the on-ramp: build, install, run, monitor.

## When it fires

| Event | Severity | Side effect |
|---|---|---|
| Dotdir candidate in scan window matches a SHA-256 in `/etc/tmp-watcher.iocs` | CRITICAL (`PRIORITY=2`) | `chmod 000 <path>` (idempotent), journal line, log line, NTFY push (when configured in code) |
| Dotdir candidate in scan window is not on the allowlist and not an IOC | WARNING (`PRIORITY=4`) | journal line, log line |
| Dotdir candidate matches the allowlist | silent | counters only |
| Anything else | silent | counters only |

The NTFY push side effect is wired through
`runtime::push_ntfy_for_match`. In the current release that
function calls `output::ntfy_push(None, …)`; the URL is not
yet read from config, so the alert goes to the journal and the
log file only. Wiring NTFY through `Config` is tracked
separately; until that lands, plan operator paging off the
journal tag `tmp-watcher`.

The quarantine is reversible: `chmod 700 <path>` re-enables the
directory. The daemon never deletes files. See `ARCHITECTURE.md`
(invariant 7) and `RUNBOOK.md` §4 for the rollback flow.

## Build

The daemon is a single Rust binary. The crate name is
`demon-tmp-dotdir-watcher` and the installed binary name is the
same.

```bash
# toolchain check
cargo --version        # 1.74+ required (Cargo.toml `rust-version`)

# release build
cargo build --release

# the binary lands at target/release/demon-tmp-dotdir-watcher
ls -l target/release/demon-tmp-dotdir-watcher
```

Build-only checks (no host installation needed):

```bash
cargo check --all-targets   # compile-only, fastest signal
cargo clippy --all-targets -- -D warnings
cargo test                  # runs unit + integration tests
cargo test --test smoke     # CLI smoke test (`--help`, dry-run)
cargo test --test runtime   # walk + classify + quarantine e2e
```

## Run

The binary supports three operating modes selected by CLI
flags. The positional `[CONFIG_PATH]` argument is optional; when
omitted, the embedded default config is used.

```bash
# 1. Help
demon-tmp-dotdir-watcher --help

# 2. Validate a config file (no scanning, no side effects)
demon-tmp-dotdir-watcher --validate-config /etc/tmp-watcher.yaml

# 3. One polling tick, no quarantine side effect (operators use
#    this to sanity-check config + scan coverage + IOC matching
#    before activating the daemon)
demon-tmp-dotdir-watcher --dry-run /etc/tmp-watcher.yaml

# 4. Production run driven by systemd timer
demon-tmp-dotdir-watcher /etc/tmp-watcher.yaml
```

Flags:

| Flag | Effect |
|---|---|
| `--help`, `-h` | Print CLI help and exit 0 |
| `--validate-config [PATH]` | Load + validate the config; exit 0 on success, non-zero on validation failure |
| `--dry-run [PATH]` | Load config and run one full polling tick; log JSON events to stderr; never quarantine |
| `[CONFIG_PATH]` (positional) | Path to YAML config. Falls back to the embedded default |

CLI arguments and the embedded default config cover most
deployments. Environment variables override individual fields
without editing the config file (see [Configuration](#configuration)).

## Configuration

The daemon reads a single YAML file at the path given on the
command line. When no path is given, the embedded default
(`config/default.yaml`, baked into the binary at build time)
is used. Any missing section falls back to the embedded
default; only the keys you actually set override.

Fields the daemon validates on load:

- `paths.scan_roots` must be non-empty.
- `paths.scan_maxdepth` must be `<= 3`.
- `paths.scan_window_minutes` must be `> 0`.
- `allowlist.max_files_per_dir` must be `<= 10`.

A reference config matching the embedded default:

```yaml
# /etc/tmp-watcher.yaml

log:
  level: info

runtime:
  shutdown_timeout_sec: 30

paths:
  scan_roots: ["/tmp", "/home", "/var/tmp"]
  scan_maxdepth: 3
  scan_window_minutes: 1440

ioc:
  ioc_list: "/etc/tmp-watcher.iocs"
  # ioc_archive_ref: "<path>"   # optional; set per-host in /etc/tmp-watcher.yaml when forensic auto-refresh is enabled

allowlist:
  allowlist: "/etc/tmp-watcher.allowlist"
  max_files_per_dir: 10

actions:
  quarantine_on_ioc_match: true
  alert_on_unknown: true
```

The journal tag (`tmp-watcher`), the log file destination
(`/var/log/tmp-watcher.log`), and the alerts channel
(`PRIORITY=2` journal + planned NTFY push) are baked into the
binary and are not configurable from the YAML. Operators tune
behaviour by editing the keys above; tuning the alert
transport requires a code change.

Environment overrides take precedence over the YAML file and
use double-underscore (`__`) as the section separator:

| Variable | YAML field |
|---|---|
| `DEMON_LOG_LEVEL` | `log.level` (string) |
| `DEMON_SHUTDOWN_TIMEOUT_SEC` | `runtime.shutdown_timeout_sec` (integer) |
| `DEMON_PATHS__SCAN_MAXDEPTH` | `paths.scan_maxdepth` (integer) |
| `DEMON_PATHS__SCAN_WINDOW_MINUTES` | `paths.scan_window_minutes` (integer) |
| `DEMON_PATHS__SCAN_ROOTS` | `paths.scan_roots` (colon-separated list) |
| `DEMON_IOC__IOC_LIST` | `ioc.ioc_list` (path) |
| `DEMON_IOC__IOC_ARCHIVE_REF` | `ioc.ioc_archive_ref` (path) |
| `DEMON_ALLOWLIST__ALLOWLIST` | `allowlist.allowlist` (path) |
| `DEMON_ALLOWLIST__MAX_FILES_PER_DIR` | `allowlist.max_files_per_dir` (integer) |
| `DEMON_ACTIONS__QUARANTINE_ON_IOC_MATCH` | `actions.quarantine_on_ioc_match` (bool) |
| `DEMON_ACTIONS__ALERT_ON_UNKNOWN` | `actions.alert_on_unknown` (bool) |

An env override that fails to parse is logged at WARN and
ignored; the YAML value (or the embedded default) is kept.

Validate after any edit:

```bash
demon-tmp-dotdir-watcher --validate-config /etc/tmp-watcher.yaml
```

## IOC list

`/etc/tmp-watcher.iocs` — one SHA-256 per line. The matcher
hashes the first `max_files_per_dir` files inside each
candidate dotdir and looks up the hash string. Lines that are
blank or start with `#` are ignored.

```text
# Example IOC entry (synthetic hash for documentation; not a real sample)
b02ad43cfa407a01c376c7a904104b03  trunk.md5
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  trunk.sha256
```

A missing IOC list is treated as an empty list — the daemon
boots, logs a warning, and continues scanning. This is the
documented behaviour for dev boxes; production deploys must
keep the file populated and review it against the canonical
forensic archive (operator-supplied path via per-host config).

## Allowlist

`/etc/tmp-watcher.allowlist` — one glob per line (the `globset`
syntax). Anything matching a glob is skipped silently. Comment
lines (`# ...`) and blank lines are allowed.

```text
# FastPanel2 X11 / systemd-private entries — legitimate, keep
.font-unix
.ICE-unix
.X11-unix
.XIM-unix
.Test-unix
systemd-private-*
```

A missing or unreadable allowlist becomes an empty in-memory
allowlist; a WARNING is logged and scanning proceeds. Operators
expand this file as new false-positive patterns are observed;
the daemon picks up changes on the next poll cycle (within ten
minutes), no restart needed.

## Memory footprint

| Metric | Value | Notes |
|---|---|---|
| Binary (main) | 6.7 MB | `demon-tmp-dotdir-watcher`, stripped release |
| Binary (sidecar) | 2.3 MB | `demon-tmp-watcher-cross-host`, one-shot |
| RSS idle | 7.0 MB | boot complete, between ticks |
| RSS peak (500 candidates) | 7.3 MB | +264 KB ≈ 540 B per candidate |
| Tick duration (500 dotdirs) | ~5 ms | measured on a typical tmpfs/ext4 |
| Virtual size | ~764 MB | unmapped mmap; not a RAM concern |

The daemon holds no state between ticks: the `IOC` HashSet, allowlist
GlobMatcher set, and per-tick `Vec<Candidate>` are released at the
end of every poll cycle. Steady-state RSS stays at 7.0 MB across
thousands of cycles (no leak). Memory growth is linear in candidate
count and bounded by `scan_maxdepth` × `max_files_per_dir` per
scan_root.

Run the daemon under `Type=oneshot` systemd activation so the process
is reclaimed between activations — the daemon does not need to hold
memory when no timer is firing.

## Deployment (systemd)

The daemon is timer-driven. The unit and timer are not shipped
in this folder (they belong to the host's systemd catalog at
`/etc/systemd/system/`). Drop in the following two files and
enable the timer:

`/etc/systemd/system/tmp-watcher.service`

```ini
[Unit]
Description=demon-tmp-dotdir-watcher (shallow dot-directory IOC scanner)
After=local-fs.target
Documentation=file:<repo>/README.md

[Service]
Type=oneshot
ExecStart=/usr/local/bin/demon-tmp-dotdir-watcher /etc/tmp-watcher.yaml
WorkingDirectory=/var/lib/tmp-watcher
StateDirectory=tmp-watcher
LogsDirectory=tmp-watcher
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=false           # the daemon must read /tmp; private /tmp would hide signals
ReadWritePaths=/run /var/log /var/tmp /tmp /home
CapabilityBoundingSet=
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tmp-watcher

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/tmp-watcher.timer`

```ini
[Unit]
Description=demon-tmp-dotdir-watcher poll timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
AccuracySec=30s
Persistent=true
Unit=tmp-watcher.service

[Install]
WantedBy=timers.target
```

One-time install on the target host (assumes you have
`tmp-watcher.yaml`, `tmp-watcher.allowlist`, and
`tmp-watcher.iocs` already authored somewhere on the build
host — copy them in via your normal config-management path):

```bash
sudo install -m 0755 target/release/demon-tmp-dotdir-watcher \
                    /usr/local/bin/demon-tmp-dotdir-watcher
sudo install -m 0644 tmp-watcher.yaml      /etc/tmp-watcher.yaml
sudo install -m 0644 tmp-watcher.allowlist /etc/tmp-watcher.allowlist
sudo install -m 0644 tmp-watcher.iocs      /etc/tmp-watcher.iocs

# sanity-check that the config the daemon will see parses + validates
demon-tmp-dotdir-watcher --validate-config /etc/tmp-watcher.yaml

# activate the poll timer
sudo systemctl daemon-reload
sudo systemctl enable --now tmp-watcher.timer
```

`Restart=on-failure` (never `always`) is intentional: the
daemon is timer-driven and a hard restart loop on a persistent
failure would burn CPU.

## Logs and alerts

| Where | What | Filter |
|---|---|---|
| `journalctl -t tmp-watcher -n 50` | last 50 structured events | service journal |
| `journalctl -t tmp-watcher PRIORITY=2 -S -24h` | CRITICAL (IOC match) | last 24h |
| `journalctl -t tmp-watcher PRIORITY=4 -S -24h` | WARNING (unknown dotdir) | last 24h |
| `tail -F /var/log/tmp-watcher.log` | full event log with timestamps | host log |
| NTFY push | wired through `runtime::push_ntfy_for_match`; currently noop until `Config.ntfy_url` lands — see *When it fires* above | operator phone (when wired) |

The daemon uses `tracing-subscriber` with JSON output; each
event carries `candidates`, `allowlisted`, `ioc_matches`,
`quarantined`, and `skipped` counters when emitted by
`--dry-run` or at end of poll.

## Health check and triage

The minimum-viable health check for a deployment:

```bash
# timer scheduled?
systemctl list-timers --all | grep tmp-watcher

# last run status?
systemctl status tmp-watcher.service

# recent activity?
journalctl -t tmp-watcher -n 50 --since "1 hour ago"

# CRITICAL events in the last 24h?
journalctl -t tmp-watcher PRIORITY=2 -S -24h

# WARNING events in the last 24h?
journalctl -t tmp-watcher PRIORITY=4 -S -24h
```

Full operator triage — what to do on CRITICAL, how to roll
back a false-positive quarantine, what to capture before
escalating — lives in `RUNBOOK.md`. It is built around the
exact paths, journal tags, and quarantine side effect described
above, so the two documents stay in sync.

## Repository layout

```
demon-tmp-dotdir-watcher/
├── Cargo.toml            # crate manifest, deps, MSRV 1.74
├── config/
│   └── default.yaml      # embedded default config (bake-in via include_str!)
├── src/
│   ├── main.rs           # CLI parser, boot, signal handling
│   ├── config.rs         # YAML loader + validation + env overlay
│   ├── runtime.rs        # main poll loop, RunSummary, quarantine wiring
│   ├── subsystem.rs      # walk() + walk_decision_pipeline() + quarantine()
│   ├── allowlist.rs      # glob-based allowlist filter
│   ├── ioc.rs            # IOC loader + SHA-256 matcher + hash_file()
│   ├── output.rs         # structured event emitters (PRIORITY=2, =4)
│   └── test_util.rs      # shared TempDir/TempFile for unit tests
├── tests/
│   ├── smoke.rs          # `--help` + `--validate-config` smoke
│   └── runtime.rs        # walk + classify + quarantine e2e
├── docs/
│   ├── components/tmp-watcher.md
│   ├── contracts/tmp-watcher-allowlist-ioc.md
│   ├── architecture/ROADMAP.md
│   └── architecture/STATUS.md
├── ORIGIN.md             # canonical operator-facing description
├── DAEMON.md             # on-ramp summary for an architect
├── ARCHITECTURE.md       # component breakdown + invariants + failure modes
├── RUNBOOK.md            # operator triage flow
└── README.md             # this file
```

## Where to look next

- `ORIGIN.md` — full problem statement and algorithm. The
  authoritative source for what the daemon does and when.
- `DAEMON.md` — on-ramp summary covering the six things every
  architect should know before touching this daemon
  (forensic origin, host-side state paths, journal tags,
  restart policy, quarantine side effect).
- `ARCHITECTURE.md` — components, invariants (`Idempotent
  restart`, `No silent background timers`, `Quarantine is
  reversible`, etc.), failure modes, Rust-port migration
  checklist.
- `RUNBOOK.md` — operator triage for CRITICAL, WARNING,
  not-running, and quarantine rollback; restart and reload
  policy.
- `docs/architecture/STATUS.md` — current build / wave state.
- `docs/components/tmp-watcher.md` — component-level view
  (purpose, inputs/outputs, invariants, failure modes).
- `docs/contracts/tmp-watcher-allowlist-ioc.md` — file shape
  contract for the allowlist and IOC list (required by the
  loader; do not change without updating this contract).
- ORIGIN.md § "Problem it solves" — the originating incident that
  informed the original spec (Azazel-family malware in shallow
  dot-directories). Reference for the threat model.

## Source of truth

`ORIGIN.md` is the canonical operator-facing description. Any
disagreement between this folder and `ORIGIN.md` is a bug;
reconcile by updating this folder to match.
