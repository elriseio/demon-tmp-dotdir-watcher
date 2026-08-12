---
project_slug: demon-tmp-dotdir-watcher
doc_slug: adr_tmp_watcher_learning_model
doc_type: adr
applicable_roles: [all]
version: 1
summary: "ADR for the tmp-watcher learning model. Decomposes the operator-approved AR-012 proposal into three implementation tasks (AR-013 auto-promotion, AR-014 cross-host correlation, AR-015 empty-IOC-list baseline) and codifies the empty/missing IOC list as a first-class bootstrap state rather than a CRITICAL failure. Inherited constraints from ARCHITECTURE.md invariants 1-7 and ORIGIN.md 'Auto-fix actions' are preserved."
source_artifacts:
  - docs/architecture/STATUS.md § "Last Updated" (AR-012 closed by operator decision)
  - docs/architecture/STATUS.md § "Risks (carry-forward into the implementation wave)" item 2
  - ORIGIN.md § "What it does" step 5
  - ORIGIN.md § "Outstanding issues" → "Cross-host IOC sync"
  - ORIGIN.md § "Auto-fix actions" (no auto-add to allowlist)
  - ARCHITECTURE.md § "Invariants" (1-7)
  - ARCHITECTURE.md § "Failure modes" (IOC list missing row)
  - docs/contracts/tmp-watcher-allowlist-ioc.md § "Loader semantics" (docs↔code drift on missing IOC list)
  - src/runtime.rs::Runtime::new (lines 62-74 — current graceful-degrade path)
  - src/ioc.rs::Matcher::empty (line 33 — the baseline empty Matcher)
  - config/default.yaml (no `ioc.ioc_list` requirement at boot)
  - Issues/open/scout/briefs/SC-RUST-001..011 (Rust best-practice briefs to consult during implementation)
tags: [adr, tmp_watcher, learning, ioc, empty_list, first_start, cross_host, auto_promotion, scout_briefs]
---

# ADR 0001 — tmp-watcher learning model

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-08-12 |
| Authors | architect (operator-approved) |
| Supersedes | AR-012 proposal-stage variant choice |
| Implements | `docs/architecture/STATUS.md` "Risks" item 2 |
| Decomposes into | AR-013, AR-014, AR-015 (developer tasks) |

## Context

The current `tmp-watcher` daemon emits three concrete gaps that the
operator flagged as "учится" (learning) requirements:

1. **G1 — no auto-promotion unknown → IOC.** WARNING events from
   `Decision::Unknown` (see `src/output.rs::emit_unknown` and
   `src/subsystem.rs::classify`) accumulate in journald but no
   mechanism exists to convert them into IOC entries. The operator
   is the only path from WARNING → IOC list.
2. **G2 — no cross-host IOC correlation.** Each host owns its own
   `/etc/tmp-watcher.iocs`. ORIGIN.md "Outstanding issues" names
   this explicitly; `wave-cross-host-ioc-sync-004` is marked
   future.
3. **G3 — no learning pattern on IOC-list refresh.** The
   `wave-forensic-archive-auto-refresh-003` sidecar downloads a
   human-curated archive. Distribution is not learning.

A fourth, latent gap surfaced during analysis: the contract
`docs/contracts/tmp-watcher-allowlist-ioc.md` § "Loader semantics"
declares "If the file is missing: log CRITICAL + NTFY, skip the
scan, exit 0", but `src/runtime.rs::Runtime::new` (lines 62-74)
**already** degrades to `Matcher::empty()` with a WARN log and
proceeds. This is a docs↔code drift the operator explicitly
called out: "при первом старте /etc/tmp-watcher.iocs пустой или
может вообще отсутствовать" must be a **first-class bootstrap
state**, not a CRITICAL failure.

ARCHITECTURE.md invariants constrain the design space:

- Invariant 4: detection-only; auto-recovery beyond `chmod 000` is
  out of scope.
- Invariant 5: failures are loud.
- Invariant 7: quarantine is reversible (`chmod 000`, never `rm -rf`).
- ORIGIN.md "Auto-fix actions": "The daemon does NOT auto-add new
  directories to the allowlist. Unknown dotdirs are flagged as
  WARNING so the operator can decide."

Together these forbid auto-quarantine of unknown dotdirs and
auto-add to the allowlist, but they do **not** forbid (a) the
detection daemon observing its own WARNING stream and emitting
candidate-IOC proposals to a separate file, or (b) a separate
sidecar daemon reading those proposals.

## Decision

Adopt a **3-task split** (decomposed into bounded developer tasks
per `docs/agent_context/TASK_PLANNING_GUIDE.md` Heuristic #2 — each
≤ 1 commit, ≤ 5 files, single primary layer):

| Task | Gap | Primary layer | Depends on |
|---|---|---|---|
| AR-013 | G1 — auto-promotion unknown → IOC | new `src/learn.rs` module + `/etc/tmp-watcher.proposed.iocs` writer | AR-015 |
| AR-014 | G2 — cross-host IOC correlation | new `src/cross_host.rs` module + per-host observation sink | AR-013, AR-015 |
| AR-015 | G3 — empty/missing IOC list as baseline + observation-stream first-class | `src/runtime.rs` + contract update | — |

Foundation-first ordering: AR-015 establishes the empty-List
baseline so AR-013's promotion logic has a defined "what was the
IOC set before this WARNING?" comparison. AR-014 builds on AR-013
by aggregating observations across hosts.

Cross-cutting decisions:

1. **Empty IOC list is a baseline, not an error.**
   - Update `docs/contracts/tmp-watcher-allowlist-ioc.md` §
     "Loader semantics" so the missing-file case reads
     "**Baseline** (not an error): use `Matcher::empty()`; log
     INFO with `ioc_count=0`; proceed with scan; emit
     `Decision::Unknown` for every candidate. This is the
     expected state for a fresh deployment."
   - The current `src/runtime.rs::Runtime::new` (lines 62-74)
     graceful-degrade path is **codified as the only correct
     behavior**, not a workaround.
   - The contract's CRITICAL-on-missing arm is removed.

2. **Detection daemon stays detection-only.** Promotion logic
   (AR-013) lives in a new `learn.rs` module that consumes the
   `Decision::Unknown` events *inside the daemon process* but
   writes only to `/etc/tmp-watcher.proposed.iocs` — a separate
   file that does not feed the live `Matcher`. The promotion
   path is **observation-only, write-only** to the proposal
   file; the live IOC list is mutated only by operator action.

3. **Cross-host aggregation is a separate sidecar process**
   (AR-014). The sidecar consumes per-host observation logs
   shipped to a shared sink (path TBD by operator; this ADR
   does not commit a specific sink protocol). The sidecar
   proposes candidate IOC entries via the same
   `/etc/tmp-watcher.proposed.iocs` mechanism so the operator
   gets a unified review surface.

4. **No auto-promotion without operator review.** The proposal
   file is the *only* artifact a learning mechanism may write.
   `tmp-watcher-promote` (a small CLI tool) is the *only* writer
   of `/etc/tmp-watcher.iocs`. This keeps invariant 7 ("quarantine
   is reversible") and the "operator decides" posture intact.

5. **Every task must consult `Issues/open/scout/briefs/SC-RUST-001..011`.**
   The 11 briefs cover idioms/ownership, error handling, async,
   API design/clippy, performance/unsafe, testing, concurrency,
   macros, async deep-dive, cargo workspaces, and unsafe/FFI.
   Tasks pick the briefs that apply to their layer.

6. **Task keys MUST NOT appear in code comments.** Developer
   writes `git commit -m "AR-013: ..."` style references in
   commit messages (canonical cross-reference per
   `AGENT_ISSUE_NAMING_CONVENTIONS.md` Step 6) but **NOT** in
   `//` or `/* */` comments inside `.rs` files. The reason:
   code comments are read in isolation and survive rename /
   delete of the issue; they rot. Commits survive deletion of
   the issue tracker row.

## Consequences

Positive:

- Operator has a unified review surface (`/etc/tmp-watcher.proposed.iocs`)
  for new IOC candidates, regardless of whether the trigger is a
  WARNING repeat (G1), a cross-host pattern (G2), or a forensic
  archive download (G3, future `wave-003`).
- The empty-IOC-list drift between contract and code is closed.
- Three bounded, committable, separately-deployable units per
  TASK_PLANNING_GUIDE.md.

Negative:

- New filesystem artifact (`/etc/tmp-watcher.proposed.iocs`) is
  not in the existing contract; AR-013 must extend the contract.
- The cross-host sink (AR-014) is currently undefined; the
  operator must commit to a transport (file drop on iton-nest,
  HTTPS POST, syslog relay, etc.) before AR-014 lands.
- `/etc/tmp-watcher.proposed.iocs` adds operator review overhead;
  if the operator does not run `tmp-watcher-promote` periodically,
  the proposal file grows unbounded. AR-013 must include a
  retention policy (suggested: rotate at 10 MB or 30 days, whichever
  comes first; log rotation to `/var/log/tmp-watcher/rotate/`).

## Alternatives considered

- **Single monolithic "learning" subsystem** — rejected. Violates
  TASK_PLANNING_GUIDE.md Heuristic #2 (≤ 4 hours single-pass, ≤ 5
  files) and forces the cross-host path into the detection daemon,
  violating invariant 2 ("No silent background timers" — a
  monolithic learner would need internal scheduling).
- **Auto-promotion without operator review** — rejected. Violates
  ORIGIN.md "Auto-fix actions" and ARCHITECTURE.md invariant 7.
- **Network calls inside the detection daemon** — rejected.
  ARCHITECTURE.md § "Boundaries" declares "loopback only".

## Compliance matrix

| Requirement | Satisfied by |
|---|---|
| ARCHITECTURE.md invariant 1 (idempotent restart) | AR-015 baseline Matcher::empty() |
| ARCHITECTURE.md invariant 2 (no silent background timers) | All learning paths are sidecar or poll-driven; detection daemon uses no `interval()` |
| ARCHITECTURE.md invariant 3 (structured logging) | AR-013, AR-014 inherit `output::emit_*` contract |
| ARCHITECTURE.md invariant 4 (one subsystem per daemon) | Detection stays detection; learning is a separate sidecar |
| ARCHITECTURE.md invariant 5 (failures are loud) | Proposal file write failures log CRITICAL |
| ARCHITECTURE.md invariant 6 (bounded walk scope) | No change to walk scope |
| ARCHITECTURE.md invariant 7 (reversible quarantine) | No change to `chmod 0o000` |
| ORIGIN.md "Auto-fix actions" (no auto-add to allowlist) | AR-013 writes only to `.proposed.iocs`, not to allowlist |
| AGENT_ISSUE_NAMING_CONVENTIONS.md (cross-reference by `<ROLE_CODE>-<NNN>`) | All cross-references in this ADR use `AR-013`, `AR-014`, `AR-015` |
| TASK_PLANNING_GUIDE.md Heuristic #2 (small-task shape) | Three bounded tasks, each ≤ 1 commit, ≤ 5 files |
| AGENT_OUTPUT_SANITIZATION_POLICY.md (no absolute paths in artifacts) | No absolute paths in this ADR; references use `<repo_root>` semantics |

## Open questions for operator (carried into AR-014)

1. Transport for the per-host observation sink (HTTP POST, file
   drop on iton-nest, syslog relay, ...).
2. Retention policy for `/etc/tmp-watcher.proposed.iocs` (default
   proposed: 10 MB or 30 days, whichever comes first).
3. Whether `tmp-watcher-promote` should run interactively or be
   daemonized under systemd (suggested: systemd oneshot daily,
   operator invokes manually to confirm).

## Cross-references

- ARCHITECTURE.md § "Invariants" — the 7 hard constraints
- ORIGIN.md § "What it does" — detection pipeline (no learning)
- ORIGIN.md § "Outstanding issues" — cross-host + encrypted droppers
- docs/components/tmp-watcher.md — current module map
- docs/contracts/tmp-watcher-allowlist-ioc.md — to be updated by AR-015
- docs/architecture/STATUS.md § "Risks" — items 2 and 3
- docs/architecture/ROADMAP.md — to be updated with the new wave
- Issues/open/architect/AR-012_define_learning_model.md — superseded by this ADR
- Issues/open/scout/briefs/SC-RUST-001..011 — Rust best-practice briefs
- docs/agent_context/AGENT_ISSUE_NAMING_CONVENTIONS.md — filename shape
- docs/agent_context/TASK_PLANNING_GUIDE.md — small-task heuristic
