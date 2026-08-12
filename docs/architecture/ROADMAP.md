---
project_slug: demon-tmp-dotdir-watcher
doc_slug: architecture_roadmap
doc_type: architecture_roadmap
applicable_roles: [all]
version: 1
summary: "Roadmap for the tmp-watcher daemon. Active wave = Rust port from bash spec; planned waves = shadow-week cutover, forensic archive auto-refresh; closed = spec doc pass."
source_artifacts:
  - docs/architecture/STATUS.md
  - ORIGIN.md
  - ARCHITECTURE.md
  - DAEMON.md
  - RUNBOOK.md
tags: [roadmap, daemon, tmp_watcher, rust_port, waves]
---

# tmp-watcher — Roadmap

## Active wave — `wave-rust-port-001`

Replace the placeholder Rust scaffold with a runtime-backed
implementation that preserves the bash-spec invariants.

Scope: 8 bounded developer tasks (`Issues/open/developer/AR-001..AR-008`),
each ≤ 1 commit, ≤ 5 files, single primary layer.

| Task | Title | Layer | Commit count | Depends on |
|---|---|---|---|---|
| AR-001 | Config: full schema + validation + env-overlay | `src/config.rs` (new) | 1 | — |
| AR-002 | Subsystem: walk scanner with bounded depth + mtime filter | `src/subsystem.rs` (new) | 1 | AR-001 |
| AR-003 | IOC loader + SHA-256 matcher | `src/ioc.rs` (new) | 1 | AR-001 |
| AR-004 | Allowlist glob filter | `src/allowlist.rs` (new) | 1 | AR-001 |
| AR-005 | Quarantine action: idempotent `chmod 000` | `src/subsystem.rs` (extend) | 1 | AR-002 |
| AR-006 | Alert output: journal tags + NTFY push | `src/output.rs` (new) | 1 | AR-005 |
| AR-007 | CLI: `--validate-config` + `--dry-run` + fix smoke-test binary name | `src/main.rs`, `tests/smoke.rs` | 1 | AR-001 |
| AR-008 | Runtime integration: replace placeholder loop, shutdown coordination | `src/runtime.rs` (new), `src/main.rs` (slim) | 1 | AR-002, AR-003, AR-004, AR-005, AR-006 |

Acceptance for the wave as a whole:

- `cargo build --release` succeeds with zero warnings.
- `cargo test` passes (smoke + per-component unit tests).
- `demon-tmp-dotdir-watcher --help` prints usage.
- `demon-tmp-dotdir-watcher --validate-config` returns 0 on
  `config/default.yaml`.
- `demon-tmp-dotdir-watcher --dry-run` scans scan_roots and
  emits the same journal lines as a live run but performs
  **no** `chmod 000` action.
- Re-running against an already-chmod-000 path is a no-op
  (invariant 7 from `ARCHITECTURE.md`).

## Planned waves

### `wave-learning-baseline-005` (active after wave-001 + AR-009 close)

Codify the empty/missing IOC list as a first-class bootstrap
state and ship the first three learning tasks from the AR-012
decomposition. Driver: operator directive 2026-08-12 — "при
первом старте /etc/tmp-watcher.iocs пустой или может вообще
отсутствовать". Foundation task AR-015 first (no deps), then
AR-013, then AR-014.

| Task | Title | Layer | Commit count | Depends on |
|---|---|---|---|---|
| AR-015 | Empty/missing IOC list as bootstrap baseline + contract update | `src/runtime.rs` + `docs/contracts/tmp-watcher-allowlist-ioc.md` | 1 | — |
| AR-013 | Auto-promote `Decision::Unknown` → `/etc/tmp-watcher.proposed.iocs` | new `src/learn.rs` + contract extension | 1 | AR-015 |
| AR-014 | Cross-host IOC correlation via separate sidecar | new `src/cross_host.rs` + new `demon-tmp-watcher-cross-host` binary + systemd unit | 1 | AR-013, AR-015 |

Exit criteria for the wave as a whole:

- `cargo build --release --bin demon-tmp-dotdir-watcher` succeeds
  with zero warnings.
- `cargo build --release --bin demon-tmp-watcher-cross-host`
  succeeds with zero warnings (added by AR-014).
- `cargo test` passes (smoke + per-component unit tests).
- A fresh deployment with no `/etc/tmp-watcher.iocs` boots
  without error and proceeds with `Matcher::empty()` baseline.
- `Decision::Unknown` events accumulate in
  `/etc/tmp-watcher.proposed.iocs` with deduplication and
  rotation.
- The cross-host sidecar (when enabled) writes aggregated
  entries annotated with `cross_host_count=N`.
- `tmp-watcher-promote` (separate CLI, future scope) is the
  ONLY path that mutates `/etc/tmp-watcher.iocs`.

### `wave-shadow-cutover-002` (after wave-001 lands)

Two-track safe cutover: keep the bash script active for one poll
cycle while the Rust binary runs in `--dry-run`. Compare journal
lines for parity. Then swap systemd timer to Rust; keep bash as
fallback for one release.

Exit criteria: bash cron disabled, Rust timer enabled, both
present in tree.

### `wave-forensic-archive-auto-refresh-003`

Per `ORIGIN.md` "IOC-list refresh (optional, daily)": add the
sidecar that re-reads `/etc/tmp-watcher.iocs` from an
operator-mounted read-only IOC source (tar.gz) and updates the
host-local IOC list.

Exit criteria: a new IOC hash added to the forensic archive
appears in `/etc/tmp-watcher.iocs` within 24 h without
operator action.

### `wave-cross-host-ioc-sync-004` (future enhancement)

Per `ORIGIN.md` "Outstanding issues → Cross-host IOC sync":
shared IOC list on `iton-nest` synced via cron, consumed by
each `tmp-watcher` host. Out of scope for the current priority
(high) — the daemon already catches the footprint on each
host independently.

## Recently-closed waves

(none yet — first wave is the active one above.)

## Cross-cutting track anchors

| Track | Anchor doc | Owner | Status |
|---|---|---|---|
| Observability | `RUNBOOK.md` (journal queries, NTFY) | architect + sysadmin | live (bash spec); Rust port will preserve |
| Logging | `RUNBOOK.md` § "Quick health check" + `ARCHITECTURE.md` invariant 3 | architect | preserved by AR-006 |
| Config | `config/default.yaml` + `Cargo.toml` deps | architect | extending via AR-001 |
| Security | `chmod 000` quarantine + allowlist + IOC list | architect + sysadmin | preserved by AR-005 + AR-004 + AR-003 |
| Documentation | `ORIGIN.md` / `ARCHITECTURE.md` / `DAEMON.md` / `RUNBOOK.md` / `docs/components/tmp-watcher.md` / `docs/contracts/tmp-watcher-allowlist-ioc.md` / `docs/architecture/{STATUS,ROADMAP}.md` | architect (direct write) | live; spec-vs-code reconciliation on every implementation commit |

## Coordination notes

- The active wave (`wave-learning-baseline-005`) is
  **single-role**: only `developer` consumes
  `Issues/open/developer/AR-013`, `AR-014`, `AR-015`. Architect
  monitors via `memory.get_task_lineage_chain(project_slug,
  task_ref='<file>.md')` after each closure. Foundation-first
  ordering: claim AR-015 → AR-013 → AR-014.
- The wave-001 wave (already closed) was **single-role**: only
  `developer` consumed `Issues/open/developer/AR-*`. Architect
  monitored via `memory.get_task_lineage_chain(project_slug,
  task_ref='<file>.md')` after each closure.
- Tests (cross-role handoff to `tester`) are out of scope for
  this wave — each task carries its own unit tests and the
  smoke test (AR-007). A separate `wave-test-coverage-006` may
  be added if live-host test gaps surface.
- Operator approval required at the end of `wave-shadow-cutover-002`
  (cutover is the operator's call; not the daemon's).
- Operator must answer the three open questions in AR-014 §
  "Open questions for operator" before AR-014 lands:
  per-host observation sink transport, host identity source,
  whether the sidecar is enabled on day 1.
