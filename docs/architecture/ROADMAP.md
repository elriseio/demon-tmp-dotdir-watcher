---
project_slug: demon-tmp-dotdir-watcher
doc_slug: architecture_roadmap
doc_type: architecture_roadmap
applicable_roles: [all]
version: 2
summary: "Roadmap for the tmp-watcher daemon. Active wave = hardening follow-up after the overlay-scan production deployment. Recently-closed waves = container overlay scan, learning baseline, Rust port. Planned waves = shadow cutover, forensic archive auto-refresh, cross-host IOC sync."
source_artifacts:
  - docs/architecture/STATUS.md
  - ORIGIN.md
  - ARCHITECTURE.md
  - DAEMON.md
  - RUNBOOK.md
  - the overlay-scan and SA-003 production deployment commits
    (per git log)
tags: [roadmap, daemon, tmp_watcher, rust_port, waves, prod_deployment, overlay_scan]
---

# tmp-watcher — Roadmap

## Active wave — `wave-hardening-followup-007` (post-overlay-scan production reality)

After the overlay-scan closure and the production deployment
(2026-08-13 sysadmin follow-up), one operational follow-up surfaces:

| Task | Title | Layer | Owner | Depends on |
|---|---|---|---|---|
| SA-019-followup-1 | `/home/artgs-deploy/.ssh` EACCES — supplementary group OR `chmod o+x` on `/home/artgs-deploy` only (NOT on `.ssh`) | runtime / deployment | sysadmin | operator decision |

Per SA-003 follow-up: the operator deferred the decision. The
daemon does NOT need to read this directory; the on-call operator
may address it operationally or via a separate group-membership
config. If a structural fix is needed (e.g., a per-host
`/home/<user>/allowlist` exemption), the change is a separate ADR
+ a daemon feature flag, not a silent extension.

The wave carries the **cross-cutting capability constraint** added
to ADR-0002 § "Constraints preserved" on 2026-08-13: "no new capability
requirements." Any future feature that needs more caps requires a
separate ADR + a separate systemd unit diff.

## Recently-closed waves

### `wave-container-overlay-006` (closed 2026-08-13)

Container overlay scan shipped. Designer: operator directive 2026-08-13
("у этого демона есть одна проблема.. он сканирует систему, но не
сканирует контейнеры docker" + "ответаы: сканировать только .*").
Backed by the 2026-08-09 `elrise-backend` container compromise (5 days
of `.r.rpk`, `.xdiag`, `.apid`, `.perf.c` persistence inside an overlay
layer while the host daemon reported clean). Design record:
`docs/adr/0002-container-overlay-scan.md`.

| Task | Title | Layer | Commit count | Depends on |
|---|---|---|---|---|
| DE-006 | Overlay scan: host-side overlay-fs walker for Docker `overlay2` | new `src/overlay.rs` + thin extensions to `src/subsystem.rs`, `src/config.rs`, `config/default.yaml`, `tests/smoke.rs` | 1 | AR-016 approved |

Architect's doc propagation (separate commits, direct-written by
architect):

1. `docs/components/tmp-watcher.md` — extend § "Module map" + § "Inputs" + § "Failure modes" with overlay entries.
2. `docs/contracts/tmp-watcher-allowlist-ioc.md` — extend § "Scope" + new § "Overlay scan filter semantics" (overlay is scope-narrowed to `.*` only).
3. `RUNBOOK.md` — extend § "Common failure modes" with overlay rows (overlay root absent / unreadable / wrong driver).
4. `docs/architecture/STATUS.md` — bump `Last Updated` + extend "Risks" item 2.
5. `docs/architecture/ROADMAP.md` — this wave plan added.

Acceptance for the wave as a whole:

- `cargo build --release --bin demon-tmp-dotdir-watcher` succeeds
  with zero warnings.
- `cargo test` passes (smoke + 10 new overlay tests).
- On a host with `/var/lib/docker/overlay2/<layer>/diff/tmp/.r.rpk/`,
  the daemon's next poll cycle emits a CRITICAL journal line and
  `chmod 0o000` the overlay path.
- On a host without Docker, the overlay scan logs INFO once and
  skips overlay paths without error.
- Host scan behaviour is unchanged (no regression on pure-host hosts).
- The static-analysis gate
  `scripts/check_overlay_no_docker_sock.sh` (added in this wave)
  passes: `src/overlay.rs` does not reference `/var/run/docker.sock`,
  `bollard`, `DOCKER_HOST`, or `docker` (case-insensitive
  text-grep).
- All 10 tests from ADR-0002 § "Decision" item 9 pass.

Verification per the overlay-scan closure DoD report:
82 tests pass; `cargo clippy --all-targets` clean; runtime
integration verified via `--dry-run` against an overlay fixture.
Production deployment context recorded in the sysadmin
2026-08-13 follow-up commit (capability set updated, 2 candidates
per tick in production).

### `wave-learning-baseline-005` (closed 2026-08-12)

Codify the empty/missing IOC list as a first-class bootstrap state
and ship the first three learning tasks from the learning-model
decomposition (per `docs/adr/0001-tmp-watcher-learning-model.md`).
Driver: operator directive 2026-08-12 — "при первом старте
/etc/tmp-watcher.iocs пустой или может вообще отсутствовать".
Foundation task (empty-list baseline) first (no deps), then the
auto-promotion task, then the cross-host correlation task (table
below lists them by role-code).

| Task | Title | Layer | Commit count | Depends on |
|---|---|---|---|---|
| AR-015 | Empty/missing IOC list as bootstrap baseline + contract update | `src/runtime.rs` + `docs/contracts/tmp-watcher-allowlist-ioc.md` | 1 | — |
| AR-013 | Auto-promote `Decision::Unknown` → `/etc/tmp-watcher.proposed.iocs` | new `src/learn.rs` + contract extension | 1 | AR-015 |
| AR-014 | Cross-host IOC correlation via separate sidecar | new `src/cross_host.rs` + new `demon-tmp-watcher-cross-host` binary + systemd unit | 1 | AR-013, AR-015 |

### `wave-rust-port-001` (closed 2026-08-12)

Replace the placeholder Rust scaffold with a runtime-backed
implementation that preserves the bash-spec invariants.

Scope: 8 bounded developer tasks (see the wave-table below for
per-task role-codes; the local queue for this wave has been
archived and the closure lineage lives in git history), each ≤ 1
commit, ≤ 5 files, single primary layer.

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
each `tmp-watcher` host. The `cross_host` module shipped in
`wave-learning-baseline-005` (see the wave-table for the
per-task role-code) is the local-side; the shared-list sync is
the next layer.

## Cross-cutting track anchors

| Track | Anchor doc | Owner | Status |
|---|---|---|---|
| Observability | `RUNBOOK.md` (journal queries, NTFY) | architect + sysadmin | live; Rust port preserves |
| Logging | `RUNBOOK.md` § "Quick health check" + `ARCHITECTURE.md` invariant 3 | architect | preserved by the alert-output module |
| Config | `config/default.toml` + `Cargo.toml` deps | architect | extended via the config-schema and overlay-scan waves |
| Security | `chmod 0o000` quarantine + allowlist + IOC list + production capability set | architect + sysadmin | preserved across the rust-port + overlay-scan waves; production capability baseline recorded in the sysadmin 2026-08-13 follow-up |
| Container overlay | `src/overlay.rs` + ADR-0002 | architect + developer | shipped 2026-08-13 |
| Capability contract | `packaging/tmp-watcher-cross-host.service` minimal `CapabilityBoundingSet=` | sysadmin | live (2026-08-13, per the sysadmin production-capability follow-up) |
| Documentation | `ORIGIN.md` / `ARCHITECTURE.md` / `DAEMON.md` / `RUNBOOK.md` / `docs/components/tmp-watcher.md` / `docs/contracts/tmp-watcher-allowlist-ioc.md` / `docs/architecture/{STATUS,ROADMAP}.md` | architect (direct write) | live; spec-vs-code reconciliation on every implementation commit |

## Coordination notes

- The active wave (`wave-hardening-followup-007`) is **single-actor**:
  Sysadmin may address the `/home/artgs-deploy/.ssh` follow-up
  operationally (per-host group membership or operator-supervised
  `chmod o+x /home/artgs-deploy`). No daemon code change is required.
  Cross-cutting constraint: ADR-0002 § "Constraints preserved" →
  "no new capability requirements." Future features that need more
  caps require a separate ADR.
- The `wave-container-overlay-006` (closed 2026-08-13) was
  **single-role**: only `developer` consumed the overlay-scan
  task (the closure lineage is in git log; the local queue
  entry has been archived). Architect monitored via
  `memory.get_task_lineage_chain` after closure. Verification:
  82 tests pass; production deployment confirmed via the
  sysadmin follow-up.
- The `wave-learning-baseline-005` (closed 2026-08-12) was
  **single-role**: only `developer` consumed the three
  learning-model tasks (see the wave-table for per-task
  role-codes; foundation-first ordering).
- The `wave-rust-port-001` (closed 2026-08-12) was **single-role**:
  only `developer` consumed the 8-task rust-port decomposition
  (see the wave-table for per-task role-codes).
- Tests (cross-role handoff to `tester`) are out of scope — each
  task carries its own unit tests and the smoke test (the CLI
  wave + the overlay-scan wave). A separate `wave-test-coverage-008`
  may be added if live-host test gaps surface.
- Operator approval required at the end of `wave-shadow-cutover-002`
  (cutover is the operator's call; not the daemon's).
- Operator must answer the three open questions in the
  cross-host sidecar's "Open questions for operator" section (per
  the ADR-0001 decomposition; see `docs/adr/0001-tmp-watcher-learning-model.md`)
  before the cross-host task ships in production:
  per-host observation sink transport, host identity source,
  whether the sidecar is enabled on day 1.
