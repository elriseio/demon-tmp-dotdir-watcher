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
| IOC list | operator-curated file (optional at first start) | one SHA-256 per line; baseline empty matcher when missing or comments-only | `/etc/tmp-watcher.iocs` |
| Proposed IOC list | detection daemon writes; operator reads | `<UTC-ISO>  <sha256-or-dash>  <basename>  <first-seen-path>` (one per line; append-only; rotation 10 MB / 30 days) | `/etc/tmp-watcher.proposed.iocs` (rotated to `/var/log/tmp-watcher/proposed-rotate-<UTC>.iocs`) |
| Allowlist | operator-curated file | one glob per line | `/etc/tmp-watcher.allowlist` |
| Scan roots | config | list of paths | `/tmp`, `/home`, `/var/tmp` (defaults) |
| Overlay scan roots | config | list of paths | `/var/lib/docker/overlay2` (default; v1: Docker `overlay2` only) |
| Overlay scan flag | config | boolean | `paths.overlay_scanEnabled: true` (default); `false` disables overlay scan |
| Overlay scan depth | config | integer | `paths.overlay_scan_maxdepth: 3` (default; per invariant 6) |
| Overlay scan scope | config | boolean | `paths.overlay_scan_dotdir_only: true` (default; per operator direction 2026-08-13) |
| Forensic archive (optional) | operator-mounted read-only | tar.gz | operator-supplied path (per-host) |
| NTFY URL (optional) | env | URL string | `${NTFY_URL}` |

## Outputs

| Output | Destination | Format | Trigger |
|---|---|---|---|
| Boot / heartbeat / shutdown | journald (`-t tmp-watcher`) + `/var/log/tmp-watcher.log` | structured JSON via `tracing-subscriber` json | every poll cycle |
| Unknown dotdir | journald (`PRIORITY=4`) + optional NTFY | structured event | per non-allowlisted dotdir |
| IOC match + quarantine | journald (`PRIORITY=2`) + NTFY | structured event + chmod side effect | per SHA-256 match |
| Audit note | `${REPORT_DIR}/<date>-tmp-watcher.md` | markdown one-liner | clean shutdown / long-outage recovery |
| Incident file | `${REPORT_DIR}/<date>-tmp-watcher-ioc-<hash>.md` | markdown incident | per IOC match |

## Module map (target Rust split)

| Module | File | Responsibility | Source of truth |
|---|---|---|---|
| `main` | `src/main.rs` | Boot, signal handling, top-level wiring | `ORIGIN.md` + `DAEMON.md` |
| `config` | `src/config.rs` | Load + validate YAML config; env overlay (host + overlay scan keys) | `config/default.yaml` |
| `runtime` | `src/runtime.rs` | Main loop, shutdown coordination | `ARCHITECTURE.md` § "Subsystem" |
| `subsystem` | `src/subsystem.rs` | Walk + hash + match + quarantine (host scan + overlay scan via `overlay` module) | `ORIGIN.md` § "What it does" + `docs/adr/0002-container-overlay-scan.md` |
| `overlay` | `src/overlay.rs` | Host-side overlay-fs walker for Docker `overlay2` layers; discovers layers, walks `tmp/.?*/` at depth ≤ 3, reuses IOC + allowlist matchers, applies `chmod 0o000` quarantine on overlay paths | `docs/adr/0002-container-overlay-scan.md` § "Decision" item 5 |
| `ioc` | `src/ioc.rs` | IOC list loader + SHA-256 matcher | `ORIGIN.md` § "IOC list" |
| `allowlist` | `src/allowlist.rs` | Glob-based allowlist filter | `ORIGIN.md` § "Allowlist" |
| `learn` | `src/learn.rs` | `Decision::Unknown` observer; writes candidate IOCs to `/etc/tmp-watcher.proposed.iocs` (rotation 10 MB / 30 days) | `docs/contracts/tmp-watcher-allowlist-ioc.md` § "File: `/etc/tmp-watcher.proposed.iocs`" |
| `cross_host` | `src/cross_host.rs` | Cross-host IOC correlation: `Sink` trait + `Aggregator` aggregating per-host observations into the proposal file with `cross_host_count=N` suffix | `docs/contracts/tmp-watcher-allowlist-ioc.md` § "Cross-host sink contract" |
| `output` | `src/output.rs` | Journal tags + NTFY push + audit reports | `RUNBOOK.md` § "Audit notes" |
| (test) | `tests/smoke.rs` | `--help` + `--validate-config` + invalid-config fast-fail + overlay fixtures (10 tests) | `README.md` + `docs/adr/0002-container-overlay-scan.md` |

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

## Webhook channel (DE-018..DE-022)

DE-018..DE-022 introduce the operator-supplied NTFY post-tick-summary
emit. The producer is `output`; the canonical contract doc is
`docs/contracts/webhook-payload.md`.

### Inputs (per cycle)

| Input | Source | Format |
|---|---|---|
| Per-tick `RunSummary` | `runtime::run_once` | struct with `candidates`, `allowlisted`, `ioc_matches`, `quarantined`, `unknown`, `skipped`, `unreadable_roots`, `duration_seconds` |
| `Config.actions.ntfy_url` | `Config` | `Option<String>`; `None` ⇒ journal-only emit |
| `tick_err` flag | `runtime::run` Err-arm | `bool`; `true` ⇒ short-circuit to `Severity::Error` |

### Webhook payload

The HTTP POST format, headers, body layout, and severity mapping
are the canonical contract; see `docs/contracts/webhook-payload.md`
for the authoritative spec. Short form:

- `POST <actions.ntfy_url>` with `Title` / `Priority` / `Tags` headers
  and `text/plain` body (`key=value` lines).
- Severity mapping: `info` → `Priority=2`, `warn` → `3`, `error` →
  `5`. Mapping logic is in
  `src/output.rs::Severity::from_run_summary`.
- Body is `candidates`, `allowlisted`, `ioc_matches`, `quarantined`,
  `unknown`, `skipped`, `unreadable_roots` (count), `duration_seconds`.

### Invariants (webhook channel-specific)

1. **One POST per tick.** The runtime emits one summary per
   `run_once` cycle; failure modes that co-occur roll up into one
   severity (worst observed).
2. **Webhook failure never blocks cycle completion.** A non-2xx
   or transport timeout is logged at priority-4 WARNING and
   propagates as `Err` to the runtime, which logs and continues;
   the next tick retries.
3. **`actions.ntfy_url = None` suppresses the webhook silently.**
   The journal `info!` summary line is the only emit in that case.

### Failure modes (webhook channel-specific)

| Failure | Detection | Response |
|---|---|---|
| NTFY URL invalid / unreachable | `reqwest` connect / timeout | log `priority = 2` ERROR; runtime logs priority-4 WARNING; tick completes |
| NTFY endpoint returns non-2xx | `reqwest::Response.status()` | log `priority = 4` ERROR; runtime logs priority-4 WARNING; tick completes |
| `actions.ntfy_url = None` | `output::push_tick_summary` short-circuit | journal-only tick summary, no HTTP traffic |
| `runtime.run_once` returned `Err` | `runtime.rs::run` Err-arm | severity short-circuits to `Error` (priority 5); `RunSummary::default()` used as the body source |

### Observability surface (webhook channel-specific)

| Signal | Tool / query |
|---|---|
| Last NTFY post (URL+title) | `journalctl -t tmp-watcher \| grep "ntfy post-summary"` |
| NTFY transport failure | `journalctl -t tmp-watcher PRIORITY=4 -S -24h \| grep ntfy` |
| NTFY non-2xx | `journalctl -t tmp-watcher -S -24h \| grep "ntfy post-summary push returned non-2xx"` |
| Tick severity (info / warn / error) | `journalctl -t tmp-watcher -n 50 \| grep "runtime: tick summary"` (the `candidates`, `allowlisted`, ... counter line per tick) |

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
| IOC list missing | subsystem startup probe | log to journal (INFO); use empty Matcher baseline; proceed with scan (every candidate classifies as Unknown) |
| Allowlist missing | subsystem startup probe | log to journal; use empty in-memory allowlist; proceed |
| `/run/tmp-watcher/` not writable | mkdir probe | exit non-zero; systemd retries |
| `/var/log/tmp-watcher.log` not writable | open() probe | log to journal only; continue |
| sha256sum on a 10+ file dotdir | file count > limit | abort that candidate; WARNING; continue |
| find crossing a slow filesystem | timeout in walker | log WARNING; skip that subtree |
| NTFY endpoint unreachable | curl error | log error; do not retry inside daemon (next poll) |
| Overlay root absent (no Docker on host) | `metadata()` probe at startup | log INFO `overlay_scan_skipped reason=overlay_root_absent`; continue with host scan |
| Overlay root unreadable | `read_dir()` Err | log WARNING; skip overlay scan for this poll cycle; continue with host scan |
| Docker uses non-overlay2 driver (btrfs, zfs, vfs) | overlay root has no `<layer>/diff` subdirs | log INFO `overlay_scan_skipped reason=no_overlay2_layers`; continue |
| `chmod 0o000` on overlay path fails | `Err(e)` from `std::fs::Permissions` | log CRITICAL; continue; `RUNBOOK.md` "Quarantine rollback (false positive)" instructions apply |

## Observability surface

| Signal | Tool / query |
|---|---|
| Timer scheduled? | `systemctl list-timers --all \| grep tmp-watcher` |
| Last run status | `systemctl status tmp-watcher.service` |
| Recent logs | `journalctl -t tmp-watcher -n 50 --since "1 hour ago"` |
| CRITICAL alerts (24 h) | `journalctl -t tmp-watcher PRIORITY=2 -S -24h` |
| WARNING (24 h) | `journalctl -t tmp-watcher PRIORITY=4 -S -24h` |
| File log tail | `tail -100 /var/log/tmp-watcher.log` |
| Audit one-liners | `ls -1 "${REPORT_DIR}"/*tmp-watcher*.md` |
| Incident files | `ls -1 "${REPORT_DIR}"/*tmp-watcher-ioc-*.md` |

## Cross-references

- `ORIGIN.md` — operator-facing description (canonical spec)
- `ARCHITECTURE.md` — invariants, failure modes, migration plan
- `DAEMON.md` — on-ramp summary
- `RUNBOOK.md` — operator triage flow + audit notes + restart policy
- `docs/contracts/tmp-watcher-allowlist-ioc.md` — IOC + allowlist contract
- `docs/architecture/STATUS.md` — current state, captured trade-offs
- `docs/architecture/ROADMAP.md` — active wave + planned waves
- `Cargo.toml` — manifest, deps, MSRV
