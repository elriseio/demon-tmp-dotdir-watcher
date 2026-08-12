---
demon: tmp-dotdir-watcher
kind: proposed
---

# Architecture

## Purpose

Detect and quarantine hidden Azazel-style malware footprints
under `/tmp/.dotdir/`, `/home/<user>/.atmp/...`, and similar
shallow dot-directories, by polling every 10 minutes and matching
newly-created entries against a known-bad SHA-256 list. Origin of
the spec: the 2026-08-09 Azazel compromise on `elrise-backend`
(see `notes/2026-08-09-elrise-compromise-malware-analysis.md`).

## Current state

Open ORIGIN.md and read the "## What it does" section. List
each step as a sequenced observation: input signal, observation
or transformation, side effect.

## Subsystem

| Concern | Owned by this daemon | Owned elsewhere |
|---|---|---|
| Cron / cadence | systemd timer (`OnUnitActiveSec=10min`) | external |
| Persistent state | none (state is volatile only) | external |
| Volatile state | /run/tmp-watcher/ (last-seen paths, cooldowns) | n/a |
| Configuration | /etc/tmp-watcher.yaml (YAML; embedded default at `config/default.yaml`) | external |
| Source-of-truth IOCs | /etc/tmp-watcher.iocs (one SHA-256 per line) | forensic archive |
| Allowlist | /etc/tmp-watcher.allowlist (one glob per line) | external |
| Logging | journald (`-t tmp-watcher`) + /var/log/tmp-watcher.log | external |
| Notifications | NTFY push — **planned, not wired** (runtime path through `output::ntfy_push` exists but always receives `None`; see `docs/architecture/STATUS.md`) | external |
| Secrets | env vars only; no reads from disk | operator secret manager |

## Components (target Rust port)

| Component | Responsibility | Source of truth |
|---|---|---|
| `src/main.rs` | Boot, signal handling, top-level wiring | this folder |
| `src/config.rs` | Load + validate YAML config; env overlay | ORIGIN.md "Configuration" |
| `src/runtime.rs` | Main loop; shutdown coordination | ORIGIN.md "What it does" |
| `src/subsystem.rs` | Walk + hash + match + quarantine | ORIGIN.md "What it does" |
| `src/ioc.rs` | IOC list loader + SHA-256 matcher | ORIGIN.md "IOC list" |
| `src/allowlist.rs` | Glob-based allowlist filter | ORIGIN.md "allowlist" |
| `tests/smoke.rs` | `--help` + invalid-config fast-fail | `_template/tests` |

## Boundaries

| Concern | MUST | MUST NOT |
|---|---|---|
| Subsystem count | 1 (one observable side effect) | multi-purpose |
| Network | loopback only | accept inbound connections |
| State retention | one poll window only | keep path history across reboots |
| Output | journal + /var/log/tmp-watcher.log (NTFY path wired but always noop; see `docs/architecture/STATUS.md`) | `println!` past boot |
| Secrets | env vars only | read from disk |
| Side effect on IOC match | `chmod 000 <path>` (idempotent) | `rm -rf` (destructive) |
| Side effect on unknown dotdir | log WARNING (NTFY push planned, see `docs/architecture/STATUS.md`) | auto-quarantine |

## Invariants

1. **Idempotent restart.** Re-running the daemon must not
   produce a different observable state than the previous run
   after a graceful shutdown.
2. **No silent background timers.** All cadence is driven by the
   systemd timer; the daemon itself does not run `interval()`
   for cadence. (It may use intervals for state sampling inside
   a single activation, but the activation interval is the
   timer's job.)
3. **Structured logging from the first line.** No `println!`
   past the bootstrap `info!` line. Journal tags
   (`PRIORITY=2` for CRITICAL, `PRIORITY=4` for WARNING) are
   preserved.
4. **One subsystem per daemon.** Detection only. Auto-recovery
   beyond the `chmod 000` quarantine is out of scope.
5. **Failures are loud.** Any non-zero exit must have a
   corresponding journal `error!` event with `priority = 2`
   (CRITICAL). NTFY notification is **not** part of the
   failure-loudness contract today because the NTFY push is
   unwired (see `docs/architecture/STATUS.md`); when the
   `Config.ntfy_url` field lands, the invariant re-tightens to
   "non-zero exit + NTFY push, subject to per-config suppression".
6. **Walking scope is bounded.** `scan_maxdepth` ≤ 3,
   `max_files_per_dir` ≤ 10 caps the find/sha256sum cost per
   candidate; larger candidates log a WARNING and are skipped.
7. **Quarantine is reversible.** `chmod 000` (not `rm -rf`,
   not `chattr +i`). The operator can re-enable with `chmod 700`
   if the match is a false positive.

## Failure modes

| Failure | Detection | Response |
|---|---|---|
| Boots but config invalid | systemd `PreStart` or first `info!` | exit non-zero; systemd `Restart=on-failure` retries |
| IOC list missing | subsystem startup probe | log to journal (NTFY push planned, see `docs/architecture/STATUS.md`); skip scan; exit 0 |
| Allowlist missing | subsystem startup probe | log to journal; use empty in-memory allowlist; proceed |
| `/run/tmp-watcher/` not writable | mkdir probe | exit non-zero; systemd retries |
| `/var/log/tmp-watcher.log` not writable | open() probe | log to journal only; continue |
| sha256sum on a 10+ file dotdir | file count > limit | abort that candidate; WARNING; continue |
| find crossing a slow filesystem | timeout in `find` | log WARNING; skip that subtree |
| NTFY endpoint unreachable | (not yet wired; runtime call site `output::ntfy_push(None, …)` is a no-op) | log error; do not retry inside daemon (next poll) — applies once `Config.ntfy_url` lands |

## Migration to Rust

The daemon does not yet have a live production binary. When the
Rust port lands:

1. Preserve CLI surface (--validate-config, --dry-run, --help).
2. Preserve journal field names: `journal_tag = "tmp-watcher"`,
   `PRIORITY=2` for CRITICAL, `PRIORITY=4` for WARNING.
3. Preserve `/run/tmp-watcher/`, `/var/log/tmp-watcher.log`,
   `/etc/tmp-watcher.{allowlist,iocs}` paths. Config lives at
   `/etc/tmp-watcher.yaml` (or the embedded default at
   `config/default.yaml`); no other config file path is
   read by the Rust port.
4. Preserve the `chmod 000` quarantine side effect (no `rm -rf`).
5. Run a shadow week: bash script remains active, Rust binary
   runs in dry-run / log-only mode for one cycle.
6. Cut over: disable timer for bash, enable timer for Rust.
7. Keep the bash script in tree for one release as fallback.

## Cross-references

- ORIGIN.md — operator-facing description
- RUNBOOK.md — operator triage flow
- DAEMON.md — on-ramp summary
- notes/2026-08-09-elrise-compromise-malware-analysis.md —
  the incident that produced this spec
