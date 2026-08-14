---
project_slug: demon-tmp-dotdir-watcher
doc_slug: architecture_status
doc_type: architecture_status
applicable_roles: [architect]
version: 1
summary: "Architect status document for the tmp-watcher daemon. Goals, key properties, architect cycles, captured trade-offs, and the current Rust-port wave plan."
source_artifacts:
  - ORIGIN.md
  - ARCHITECTURE.md
  - DAEMON.md
  - RUNBOOK.md
  - config/default.yaml
  - src/main.rs
tags: [architecture, status, daemon, tmp_watcher, rust_port]
---

# tmp-watcher — Architect Status

## Goals

`demon-tmp-dotdir-watcher` (short: `tmp-watcher`) is a host-local
Rust daemon that detects and quarantines hidden Azazel-style
malware footprints under `/tmp/.dotdir/`, `/home/<user>/.atmp/...`,
and similar shallow dot-directories. The daemon was specified the
same day as an Azazel-family compromise on an affected host
(see the post-incident write-up in the operator's notes tree).

Business goal:

- **Detection latency reduction.** The originating incident lived
  undetected for 72 hours despite Prometheus + Uptime Kuma + Loki
  monitoring. `tmp-watcher` polls every 10 minutes, so a new
  Azazel-style footprint is detected within the first poll cycle
  (~10 min) instead of after the operator-flagged 502. Effective
  detection-lag reduction: ~71 hours on the original incident.

Architectural goal (current wave):

- **Replace the placeholder Rust scaffold** with a runtime-backed
  implementation that preserves the bash-spec invariants
  (idempotent restart, journal-tagged logging, `chmod 000`
  quarantine, bounded walk scope, env-overlay config).

## Key Properties

| Field | Value |
|---|---|
| Crate | `demon-tmp-dotdir-watcher` (`Cargo.toml`) |
| Edition / MSRV | Rust 2021 / 1.74 |
| Language target | Rust (port from bash spec in `ORIGIN.md`) |
| Host target | single Linux host running systemd |
| Cadence | systemd timer (`OnUnitActiveSec=10min`) |
| State retention | one poll window only (volatile `/run/tmp-watcher/`) |
| Network | loopback only (NTFY push to operator-configured URL) |
| Side effect on IOC match | `chmod 000 <path>` (idempotent; never `rm -rf`) |
| Side effect on unknown dotdir | journal WARNING + optional NTFY |
| Config schema | YAML at `config/default.yaml`, env-overlay via `DEMON_*` |
| Severity tag | `journal_tag = "tmp-watcher"`, `PRIORITY=2` CRITICAL, `PRIORITY=4` WARNING |

## Current state

| Layer | State | Evidence |
|---|---|---|
| Spec | **complete** | `ORIGIN.md` (verbatim from operator catalogue) |
| Components doc | **complete** | `ARCHITECTURE.md` § "Components (target Rust port)" |
| Contracts doc | **drafted** | `docs/contracts/tmp-watcher-allowlist-ioc.md` (this wave) |
| Cargo manifest | **present** | `Cargo.toml` deps: anyhow, serde, serde_yaml, tokio, tracing, tracing-subscriber |
| `src/main.rs` | **scaffold only** | placeholder heartbeat loop; needs subsystem wiring |
| `tests/smoke.rs` | **broken** | asserts binary name `rust_demon_template` (template leftover); must be renamed to `demon-tmp-dotdir-watcher` |
| `config/default.yaml` | **present** | already carries paths/ioc/allowlist/actions keys; not yet consumed by code |
| Status doc | **drafted** | this file |
| Roadmap doc | **drafted** | `docs/architecture/ROADMAP.md` |
| Component description | **drafted** | `docs/components/tmp-watcher.md` |
| Task decomposition | **8 tasks** queued for `developer` | see the active `Issues/open/developer/` queue + git log for the per-wave AR-### history |
| Production deploy | **not deployed** | daemon is "proposed" in `README.md` "Current state" |

## Architect Cycles

| Cycle | Cadence | Output |
|---|---|---|
| Spec-vs-code reconciliation | per implementation commit | updates to `ARCHITECTURE.md` / `docs/components/tmp-watcher.md` if invariants drift |
| Runbook sync | per new failure-mode observed | append to `RUNBOOK.md` "Common failure modes" |
| ADR seeding | per cross-cutting decision | `docs/adr/NNNN-<slug>.md` |
| Task decomposition | per wave plan | `Issues/open/<role>/<ROLE_CODE>-<NNN>_<slug>.md` + `memory.record_handoff` |
| Queue hygiene | once per session | verify `Issues/open/<role>/` matches the per-issue routing field per `AGENT_ISSUE_ROUTING_AND_LOCATION.md` |

## Captured Trade-offs

| Trade-off | Choice | Why | Reference |
|---|---|---|---|
| `chmod 000` vs `rm -rf` on IOC match | `chmod 000` | forensic preservation + reversible + safe under malware symlink-race | `ORIGIN.md` § "Auto-fix actions"; `ARCHITECTURE.md` invariant 7 |
| Bash spec vs Rust port | Rust port, preserve CLI surface and journal field names | single binary, no `bash`/`find`/`sha256sum` shellout; systemd oneshot stays the same | `ARCHITECTURE.md` § "Migration to Rust" |
| Per-config timeout vs hard-coded | per-config (`DEMON_SHUTDOWN_TIMEOUT_SEC`) | operator tuning without rebuild | `Cargo.toml` deps include `tokio` `time` feature |
| Allowlist pattern language | glob (one pattern per line) | matches `find -name` semantics the bash spec already uses | `ORIGIN.md` § "Allowlist" |
| IOC list format | one SHA-256 per line (no comments after hash) | keeps matcher a single `HashSet<String>` load | `ORIGIN.md` § "IOC list" |
| Single binary vs module split | split into `src/{config,runtime,subsystem,ioc,allowlist,output}.rs` | bounded single-commit tasks per `TASK_PLANNING_GUIDE.md` heuristic | `ARCHITECTURE.md` § "Components (target Rust port)" |

## Risks (carry-forward into the implementation wave)

1. **`scan_roots = ["/home", ...]` on a host with 50 GB `/home`** —
   `find -maxdepth 3` + bounded `max_files_per_dir = 10` cap the
   worst case, but the daemon still enumerates inode metadata across
   `/home/<user>/`. Mitigation: per-tree timeout in the scan walker
   (logged WARNING; skip subtree). See `RUNBOOK.md` failure-mode
   "find crossing a slow filesystem".
2. **Encrypted droppers + container-resident kits** — SHA-256 matcher
   only catches known hashes; a new Azazel variant would not match.
   The daemon catches the **footprint** (dot-dir pattern), not the
   binary. The unknown-dotdir WARNING path is the backstop; it depends
   on the allowlist staying curated. Two sub-bullets:
   - **2a. Encrypted droppers** — closed by AR-013/014/015 (cross-host
     learning: WARNING → proposed.iocs → curator review).
   - **2b. Container-resident kits** — closed by **DE-006**
     (`wave-container-overlay-006`): the daemon's host scan currently
     walks `/tmp`, `/home`, `/var/tmp`. Docker overlay layers under
     `/var/lib/docker/overlay2/<layer>/{diff,merged}/tmp/` are NOT seen
     by `find /tmp` on the host. The 2026-08-09 `elrise-backend`
     incident proves the gap (5-day persistence). DE-006 adds an
     overlay-fs walker that reuses the existing IOC + allowlist
     matchers and `chmod 0o000` quarantine. No `docker.sock`, no
     privilege escalation. Scope is `.*` dot-directories only at depth
     ≤ 3 (per operator direction 2026-08-13). Detection strategy is
     **Strategy A** (comprehensive `.*` + three-stage filter:
     IOC matcher → allowlist → unknown WARNING + proposed.iocs)
     locked in `docs/adr/0002-container-overlay-scan.md` § "Decision"
     item 0. Strategies B (name-snapshot denylist only) and C
     (Strategy A + name-pattern classifier) are explicitly rejected
     on 2026-08-13.
3. **Cross-host IOC sync** — each host owns its own
   `/etc/tmp-watcher.iocs`. New IOCs from another host's incident
   must be propagated manually (see `ORIGIN.md` "Outstanding issues").
4. **Smoke test binary-name drift** — `tests/smoke.rs` asserts
   `rust_demon_template` (a leftover from the daemon template);
   `cargo test` will fail on this daemon until renamed. Must be
   fixed as part of `AR-007`.

5. **NTFY push is unwired** — **resolved: 2026-08-13 (DE-018..DE-022
   wave close).** `Config.actions.ntfy_url` (DE-019),
   `output::push_tick_summary` (DE-020), `docs/contracts/webhook-payload.md`
   + invariant-5 re-tightening (DE-021), `httpmock` round-trip
   test + README / RUNBOOK cross-reference (DE-022). See the
   "Last Updated" entry for `wave-build-config-and-webhook-008`
   above and the git history of the closing commits for the
   per-task lineage.

## Last Updated

## Last Updated

- 2026-08-13 — **Build-time config + NTFY webhook post-summary wave
  shipped (DE-018..DE-022).** Operator directive 2026-08-13 ("у этого
  демона 1. есть конфиг, котрый учитывается при билде ... Так это
  надо внедрить и тут") drove the wave. `demon-docker-janitor`'s
  three install targets (`install-config` / `install-bin` /
  `install-units`) are backported to tmp-watcher's `Makefile`;
  the operator-facing example config lands at
  `contrib/config/tmp-watcher.conf.example`; stub systemd unit
  files (`Type=oneshot`, `OnUnitActiveSec=10min`) ship in
  `contrib/systemd/`. DE-019 adds `Config.actions.ntfy_url` +
  `DEMON_ACTIONS__NTFY_URL` env override. DE-020 lights the
  per-tick NTFY post-summary emit via the assembled payload
  (`Severity { Info, Warn, Error }` mapping per AR-017 §2.2;
  priority 2 / 3 / 5). DE-021 publishes
  `docs/contracts/webhook-payload.md` (request shape, headers,
  body layout, severity mapping, examples) and re-tightens
  `ARCHITECTURE.md` invariant 5 ("Failures are loud") to include
  the NTFY POST. DE-022 closes the wave with a `httpmock`
  round-trip test + `README.md` / `RUNBOOK.md` updates.
  ARCHITECTURE.md invariant 5 ("Failures are loud") is now a
  single, closed contract: the runtime's failure path emits both
  a journal ERROR event and (when `actions.ntfy_url` is set) a
  NTFY priority-5 alert. Functional systemd activation (`make
  enable`) is intentionally NOT shipped — the daemon's README
  § "Current state" still calls it "proposed", and operator-side
  enablement keeps the wave wave-build-config-and-webhook-008
  scoped to the runtime contract.

  Risks: item 4 ("Smoke test binary-name drift") and item
  "NTFY push is unwired" both cleared by this wave; see § "Risks"
  for the resolved entries.

- 2026-08-13 — **Container overlay scan completed (DE-006) + production deployment context (SA-003).**
  Operator directive 2026-08-13 ("у этого демона есть одна проблема..
  он сканирует систему, но не сканирует контейнеры docker" + "ответаы:
  сканировать только .*") drove the architectural decision. The
  2026-08-09 `elrise-backend` container compromise (Azazel-style kit
  persisting 5 days inside `elrise-backend` while the host daemon
  reported clean) is the in-scope incident. The fix is a host-side
  overlay-fs walker against
  `/var/lib/docker/overlay2/<layer>/{diff,merged}/tmp/.?*/` that
  reuses the existing IOC + allowlist matchers and the `chmod 0o000`
  quarantine. No `docker.sock`, no privilege escalation, no
  destructive side effect. Scope is `.*` dot-directories only at
  depth ≤ 3 (per operator direction). Implementation is the single
  bounded developer task DE-006 (one commit, ≤ 5 files; new module
  `src/overlay.rs` + thin extensions to subsystem/config).

  **DE-006 closed** (per the closing commit on 2026-08-13):
  82 tests pass (10 ADR-0002 § 9 tests + 9 cross-host + 7 smoke +
  65 unit + 1 runtime); `cargo clippy --all-targets` clean; runtime
  integration verified via `--dry-run` against an overlay fixture.

  Detection strategy is **Strategy A** (comprehensive `.*` + three-stage
  filter: IOC matcher → allowlist → unknown WARNING + proposed.iocs)
  locked in `docs/adr/0002-container-overlay-scan.md` § "Decision"
  item 0. Strategies B (name-snapshot denylist only) and C (Strategy A
  + name-pattern classifier) are explicitly rejected on 2026-08-13.

  **Production deployment context (2026-08-13):**
  the daemon runs in production with a minimal hardening-friendly
  `CapabilityBoundingSet=` (`CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
  CAP_CHOWN CAP_FOWNER CAP_SETFCAP`). The upstream
  `CapabilityBoundingSet=` (empty) recipe was identified as breaking
  root readability of mode-0700 directories on 2026-08-13 and replaced.
  Verification: `CapEff` = `000001ffffffffff` (post-fix); 2 candidates
  per tick on the install user's `.docker` and `.ssh` directories
  in their home.

  **Cross-cutting constraint** added to ADR-0002 § "Constraints preserved":
  "no new capability requirements." DE-006's overlay walker must work
  with the existing `CAP_DAC_READ_SEARCH` capability (`std::fs::read_dir`
  is sufficient). Any future feature requiring more is a separate ADR +
  separate systemd unit diff.

  Podman / containerd / CRI-O runtime support is explicitly out of scope
  for v1 (Docker overlay2 only); config-driven extension is a
  config-only change.

  Risks item 2 is extended to split the "encrypted droppers / footprint
  backbone" risk into two sub-bullets: (a) encrypted droppers (existing,
  AR-013/014/015 cross-host path), (b) container overlay exposure (this
  wave, DE-006). Compliance matrix adds overlay-scan invariants.

- 2026-08-13 — **Container overlay scan accepted (AR-016 + ADR-0002 + DE-006).**
  Operator directive 2026-08-13 ("у этого демона есть одна проблема..
  он сканирует систему, но не сканирует контейнеры docker" + "ответаы:
  сканировать только .*") drove the architectural decision. The
  2026-08-09 `elrise-backend` container compromise (Azazel-style kit
  persisting 5 days inside `elrise-backend` while the host daemon
  reported clean) is the in-scope incident. The fix is a host-side
  overlay-fs walker against
  `/var/lib/docker/overlay2/<layer>/{diff,merged}/tmp/.?*/` that
  reuses the existing IOC + allowlist matchers and the `chmod 0o000`
  quarantine. No `docker.sock`, no privilege escalation, no
  destructive side effect. Scope is `.*` dot-directories only at
  depth ≤ 3 (per operator direction). Implementation is the single
  bounded developer task DE-006 (one commit, ≤ 5 files; new module
  `src/overlay.rs` + thin extensions to subsystem/config). New wave
  `wave-container-overlay-006` recorded in `docs/architecture/ROADMAP.md`.

  Risks item 2 is extended to split the "encrypted droppers / footprint
  backbone" risk into two sub-bullets: (a) encrypted droppers (existing,
  AR-013/014/015 cross-host path), (b) container overlay exposure (this
  wave, DE-006). Compliance matrix adds overlay-scan invariants.

  Podman / containerd / CRI-O runtime support is explicitly out of scope
  for v1 (Docker overlay2 only); config-driven extension is a
  config-only change.

- 2026-08-12 — **Learning model decomposition accepted (AR-012 + ADR-0001 + AR-013/014/015).**
  Operator approved the 3-task split for closing the three gaps
  the operator flagged on "как именно демон учится":

  1. **AR-015 (foundation, no deps)** — codify the
     empty/missing `/etc/tmp-watcher.iocs` as a first-class
     bootstrap state. Closes the docs↔code drift between
     `docs/contracts/tmp-watcher-allowlist-ioc.md` (mandates
     CRITICAL on missing) and `src/runtime.rs::Runtime::new`
     (already degrades to `Matcher::empty` with WARN).
  2. **AR-013 (depends on AR-015)** — auto-promote
     `Decision::Unknown` events to
     `/etc/tmp-watcher.proposed.iocs` (deduplicated, retention
     10 MB or 30 days). Operator-side `tmp-watcher-promote`
     is the only writer of the live IOC list.
  3. **AR-014 (depends on AR-013 + AR-015)** — separate sidecar
     binary `demon-tmp-watcher-cross-host` aggregates
     observations across hosts (loopback-only per
     ARCHITECTURE.md § "Boundaries") and writes to the same
     proposal file annotated with `cross_host_count=N`.

  Design record: `docs/adr/0001-tmp-watcher-learning-model.md`.
  Umbrella proposal has been archived (routing moved from
  `architect` → `developer` per operator approval). New wave:
  `wave-learning-baseline-005` recorded in
  `docs/architecture/ROADMAP.md`.

  All three tasks MUST consult Rust best-practice briefs
  before writing code; all three tasks MUST NOT embed task keys
  (AR-013, AR-014, AR-015) inside `//` or `/* */` comments inside
  `.rs` files.

- 2026-08-12 — **AR-009 closed (Option A: docs-only reconciliation).**
  Resolved the docs-vs-code drift on two points:

  1. **Config format** — `ORIGIN.md`, `ARCHITECTURE.md`,
     `RUNBOOK.md` previously described a TOML file at
     `/etc/tmp-watcher.conf`. The Rust port (v0.1.0) loads a
     YAML file via `serde_yaml::from_str` from
     `config/default.yaml` (embedded default) with operator
     override via `--config`; no TOML parser, no
     `tmp-watcher.conf` loader. The four ship-docs
     (`README.md`, `ORIGIN.md`, `ARCHITECTURE.md`, `RUNBOOK.md`)
     now consistently describe the YAML schema and the
     `config/default.yaml` / `/etc/tmp-watcher.yaml` paths.

  2. **NTFY alert channel** — `ORIGIN.md`,
     `ARCHITECTURE.md`, `RUNBOOK.md` previously described
     NTFY push as a working alert driven by
`ntfy_url = "${NTFY_URL}"`. The code path
      (`output::ntfy_push(None, …)` in `src/runtime.rs::push_ntfy_for_match`)
      was a placeholder pass-through at the time of AR-009
      closure (2026-08-12); the `Config` struct did not yet have
      a `ntfy_url` field and the runtime received an inert
      argument value. The runtime NTFY path is now FULLY WIRED
      as of the `wave-build-config-and-webhook-008` close
      (2026-08-13, DE-018..DE-022): `Config.actions.ntfy_url` +
      `DEMON_ACTIONS__NTFY_URL` env override (DE-019), the
      per-tick summary emit via `output::push_tick_summary` and
      `Severity::from_run_summary` (DE-020), the contract doc
      `docs/contracts/webhook-payload.md` (DE-021), and the
      `httpmock` round-trip test + README/RUNBOOK cross-references
      (DE-022). All four ship-docs now describe the wired NTFY
      channel per `docs/contracts/webhook-payload.md`.
     as a follow-up. ARCHITECTURE.md invariant 5
     ("Failures are loud") was re-tightened to journal-only
     today; the invariant re-expands to include NTFY push
     when `Config.ntfy_url` lands.

  Resolution rationale: Option A (docs-only) is the smaller,
  safer change; the operator-level decision on whether NTFY
  paging will be a real production reliability requirement
  before first deployment is out of scope for this task. The
  wiring work (add `ntfy_url: Option<String>` to `Config`,
  env override `DEMON_OUTPUT__NTFY_URL`, pass through
  `push_ntfy_for_match`) remains a one-line follow-up; it
  is **not** done by AR-009.

  See the AR-009 closure commit (per git log) for the DoD report.

- 2026-08-10 — Initial architect onboarding for
  `demon-tmp-dotdir-watcher`. Specs read; placeholder scaffold
  inventoried; 8 bounded developer tasks queued
  (see git log for the initial wave of AR-### commits);
  STATUS + ROADMAP + component + contract docs drafted.
  Source-of-truth relations recorded via
  `memory.record_architecture_relation`.
