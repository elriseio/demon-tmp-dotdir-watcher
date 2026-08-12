---
project_slug: demon-tmp-dotdir-watcher
doc_slug: components_tmp_watcher
doc_type: component
applicable_roles: [all]
version: 1
summary: "Component description for the tmp-watcher daemon: purpose, I/O contracts across the 7 internal modules, invariants, failure modes, and observability surface. The canonical cross-reference between ORIGIN.md (operator spec), ARCHITECTURE.md (architectural invariants), and the Rust module split."
source_artifacts:
  - ORIGIN.md
  - ARCHITECTURE.md
  - DAEMON.md
  - RUNBOOK.md
  - config/default.yaml
  - src/main.rs
  - Cargo.toml
  - docs/contracts/tmp-watcher-allowlist-ioc.md
tags: [component, tmp_watcher, rust_port, modules, invariants]
---

# Component: `tmp-watcher`

> **Component name:** `demon-tmp-dotdir-watcher` (crate name) /
> `tmp-watcher` (display name / journal tag).
> **Folder:** `<project_root>/` (the daemon's own repo folder).
> **Language:** Rust (edition 2021, MSRV 1.74).
> **Owner role:** `architect` for invariants and docs;
> `developer` for implementation; `sysadmin` for deployment.

## Purpose

Detect and quarantine hidden Azazel-style malware footprints under
`/tmp/.dotdir/` (e.g. `.r.rpk/`, `.xdiag/`, `.perf.c/`, `.apid/`,
`.atmp/`) and `/home/<user>/.atmp/...` patterns by polling every
10 minutes (systemd timer) and matching newly-created entries
against a known-bad SHA-256 list. On match, the matched directory
is `chmod 000`-quarantined (forensic preservation + reversibility);
on unknown non-allowlisted dotdir, a WARNING is logged.

## Inputs

| Input | Source | Format | Path |
|---|---|---|---|
| Configuration | daemon args + env overlay | YAML | `config/default.yaml` (default) or arg `<CONFIG_PATH>` |
| IOC list | operator-curated file | one SHA-256 per line | `/etc/tmp-watcher.iocs` |
| Allowlist | operator-curated file | one glob per line | `/etc/tmp-watcher.allowlist` |
| Scan roots | config | list of paths | `/tmp`, `/home`, `/var/tmp` (defaults) |
| Forensic archive (optional) | operator-mounted read-only | tar.gz | `/opt/forensics/2026-08-09-elrise-compromise.tar.gz` |
| NTFY URL (optional) | env | URL string | `${NTFY_URL}` |

## Outputs

| Output | Destination | Format | Trigger |
|---|---|---|---|
| Boot / heartbeat / shutdown | journald (`-t tmp-watcher`) + `/var/log/tmp-watcher.log` | structured JSON via `tracing-subscriber` json | every poll cycle |
| Unknown dotdir | journald (`PRIORITY=4`) + optional NTFY | structured event | per non-allowlisted dotdir |
| IOC match + quarantine | journald (`PRIORITY=2`) + NTFY | structured event + chmod side effect | per SHA-256 match |
| Audit note | `/home/alex/Er/Computer/reports/<date>-tmp-watcher.md` | markdown one-liner | clean shutdown / long-outage recovery |
| Incident file | `/home/alex/Er/Computer/reports/<date>-tmp-watcher-ioc-<hash>.md` | markdown incident | per IOC match |

## Module map (target Rust split)

| Module | File | Responsibility | Source of truth |
|---|---|---|---|
| `main` | `src/main.rs` | Boot, signal handling, top-level wiring | `ORIGIN.md` + `DAEMON.md` |
| `config` | `src/config.rs` | Load + validate YAML config; env overlay | `config/default.yaml` |
| `runtime` | `src/runtime.rs` | Main loop, shutdown coordination | `ARCHITECTURE.md` § "Subsystem" |
| `subsystem` | `src/subsystem.rs` | Walk + hash + match + quarantine | `ORIGIN.md` § "What it does" |
| `ioc` | `src/ioc.rs` | IOC list loader + SHA-256 matcher | `ORIGIN.md` § "IOC list" |
| `allowlist` | `src/allowlist.rs` | Glob-based allowlist filter | `ORIGIN.md` § "Allowlist" |
| `output` | `src/output.rs` | Journal tags + NTFY push + audit reports | `RUNBOOK.md` § "Audit notes" |
| (test) | `tests/smoke.rs` | `--help` + `--validate-config` + invalid-config fast-fail | `README.md` |

## Internal contracts

- `config::Config` ↔ `subsystem::walk` — the walker reads `paths`,
  `ioc.ioc_list`, `allowlist.allowlist`, `allowlist.max_files_per_dir`,
  `actions.quarantine_on_ioc_match`, `actions.alert_on_unknown` from
  `Config`. Field names are the canonical YAML keys.
- `subsystem::walk` ↔ `allowlist::Allowlist` — each candidate dotdir
  is checked against the allowlist before any SHA-256 work.
- `subsystem::walk` ↔ `ioc::Matcher` — non-allowlisted candidates
  get hashed and looked up. `Matcher::contains(sha256) -> bool`.
- `subsystem::walk` ↔ `output::emit_*` — outcomes are routed to
  journal + NTFY through `output`; subsystem does not call
  `journal::*` directly.
- `runtime::run` ↔ `subsystem::run_once` — runtime owns the loop
  and shutdown signal; subsystem is a single-pass function per
  poll cycle.

## Cross-boundary contract

The shared contract for the IOC list + allowlist semantics (file
format, parsing rules, glob syntax, semantic edge cases) is documented
in `docs/contracts/tmp-watcher-allowlist-ioc.md`. That contract is
the source of truth for both the bash reference impl and the Rust
port; if they drift, the contract is right and the impl is wrong.

## Invariants (from `ARCHITECTURE.md` § Invariants)

1. **Idempotent restart.** Re-running the daemon must not
   produce a different observable state than the previous run
   after a graceful shutdown.
2. **No silent background timers.** All cadence is driven by the
   systemd timer; the daemon itself does not run `interval()` for
   cadence. It MAY use intervals inside one activation only.
3. **Structured logging from the first line.** No `println!`
   past the bootstrap `info!` line. Journal tags preserved:
   `PRIORITY=2` CRITICAL, `PRIORITY=4` WARNING.
4. **One subsystem per daemon.** Detection only. Auto-recovery
   beyond the `chmod 000` quarantine is out of scope.
5. **Failures are loud.** Any non-zero exit must have a
   corresponding NTFY notification (subject to per-config
   suppression).
6. **Walking scope is bounded.** `scan_maxdepth` ≤ 3,
   `max_files_per_dir` ≤ 10.
7. **Quarantine is reversible.** `chmod 000` (not `rm -rf`,
   not `chattr +i`).

## Failure modes (from `ARCHITECTURE.md` § Failure modes)

| Failure | Detection | Response |
|---|---|---|
| Boots but config invalid | systemd `PreStart` or first `info!` | exit non-zero; systemd `Restart=on-failure` retries |
| IOC list missing | subsystem startup probe | log to journal + NTFY; skip scan; exit 0 |
| Allowlist missing | subsystem startup probe | log to journal; use empty in-memory allowlist; proceed |
| `/run/tmp-watcher/` not writable | mkdir probe | exit non-zero; systemd retries |
| `/var/log/tmp-watcher.log` not writable | open() probe | log to journal only; continue |
| sha256sum on a 10+ file dotdir | file count > limit | abort that candidate; WARNING; continue |
| find crossing a slow filesystem | timeout in walker | log WARNING; skip that subtree |
| NTFY endpoint unreachable | curl error | log error; do not retry inside daemon (next poll) |

## Observability surface

| Signal | Tool / query |
|---|---|
| Timer scheduled? | `systemctl list-timers --all \| grep tmp-watcher` |
| Last run status | `systemctl status tmp-watcher.service` |
| Recent logs | `journalctl -t tmp-watcher -n 50 --since "1 hour ago"` |
| CRITICAL alerts (24 h) | `journalctl -t tmp-watcher PRIORITY=2 -S -24h` |
| WARNING (24 h) | `journalctl -t tmp-watcher PRIORITY=4 -S -24h` |
| File log tail | `tail -100 /var/log/tmp-watcher.log` |
| Audit one-liners | `ls -1 /home/alex/Er/Computer/reports/*tmp-watcher*.md` |
| Incident files | `ls -1 /home/alex/Er/Computer/reports/*tmp-watcher-ioc-*.md` |

## Cross-references

- `ORIGIN.md` — operator-facing description (canonical spec)
- `ARCHITECTURE.md` — invariants, failure modes, migration plan
- `DAEMON.md` — on-ramp summary
- `RUNBOOK.md` — operator triage flow + audit notes + restart policy
- `docs/contracts/tmp-watcher-allowlist-ioc.md` — IOC + allowlist contract
- `docs/architecture/STATUS.md` — current state, captured trade-offs
- `docs/architecture/ROADMAP.md` — active wave + planned waves
- `Cargo.toml` — manifest, deps, MSRV
