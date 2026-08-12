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
| Task decomposition | **8 tasks** queued for `developer` | `Issues/open/developer/AR-001..AR-008` |
| Production deploy | **not deployed** | daemon is "proposed" in `README.md` "Current state" |

## Architect Cycles

| Cycle | Cadence | Output |
|---|---|---|
| Spec-vs-code reconciliation | per implementation commit | updates to `ARCHITECTURE.md` / `docs/components/tmp-watcher.md` if invariants drift |
| Runbook sync | per new failure-mode observed | append to `RUNBOOK.md` "Common failure modes" |
| ADR seeding | per cross-cutting decision | `docs/adr/NNNN-<slug>.md` |
| Task decomposition | per wave plan | `Issues/open/developer/AR-<NNN>_<slug>.md` + `memory.record_handoff` |
| Queue hygiene | once per session | verify `Issues/open/<role>/` matches routing field per `AGENT_ISSUE_ROUTING_AND_LOCATION.md` |

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
2. **Encrypted droppers** — SHA-256 matcher only catches known
   hashes; a new Azazel variant would not match. The daemon catches
   the **footprint** (dot-dir pattern), not the binary. The
   unknown-dotdir WARNING path is the backstop; it depends on the
   allowlist staying curated.
3. **Cross-host IOC sync** — each host owns its own
   `/etc/tmp-watcher.iocs`. New IOCs from another host's incident
   must be propagated manually (see `ORIGIN.md` "Outstanding issues").
4. **Smoke test binary-name drift** — `tests/smoke.rs` asserts
   `rust_demon_template` (a leftover from the daemon template);
   `cargo test` will fail on this daemon until renamed. Must be
   fixed as part of `AR-007`.

## Last Updated

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
  Umbrella: `Issues/open/developer/AR-012_define_learning_model.md`
  (routing moved from `architect` → `developer` per operator
  approval). New wave: `wave-learning-baseline-005` recorded in
  `docs/architecture/ROADMAP.md`.

  All three tasks MUST consult
  `Issues/open/scout/briefs/SC-RUST-001..011` before writing
  code; all three tasks MUST NOT embed task keys (AR-013,
  AR-014, AR-015) inside `//` or `/* */` comments inside `.rs`
  files.

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
     is wired but always receives `None`; the `Config` struct
     has no `ntfy_url` field. All four ship-docs now mark NTFY
     as **planned, not wired**, with the wiring work tracked
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

  See `Issues/done/developer/AR-009_reconcile_docs_yaml_config_and_ntfy.md`
  for the DoD report.

- 2026-08-10 — Initial architect onboarding for
  `demon-tmp-dotdir-watcher`. Specs read; placeholder scaffold
  inventoried; 8 bounded developer tasks queued
  (`Issues/open/developer/AR-001..AR-008`); STATUS + ROADMAP +
  component + contract docs drafted. Source-of-truth relations
  recorded via `memory.record_architecture_relation`.
