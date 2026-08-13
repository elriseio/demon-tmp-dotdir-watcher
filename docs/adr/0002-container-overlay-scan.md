---
project_slug: demon-tmp-dotdir-watcher
doc_slug: adr_overlay_scan_for_container_dotdirs
doc_type: adr
applicable_roles: [all]
version: 1
summary: "ADR for scanning container overlay-fs layers for Azazel-style shallow dot-directories. Closes the gap demonstrated by the 2026-08-09 elrise-backend container compromise (`.r.rpk`, `.xdiag`, `.apid`, `.perf.c` survived 5 days inside an overlay layer without the host daemon noticing). Implements an overlay-diff scan at `/var/lib/docker/overlay2/<layer>/{diff,merged}/tmp/.?*/` in addition to the host `/tmp`, `/home`, `/var/tmp` scan. Scope is **`.*` dot-directories only** (per operator direction 2026-08-13) — preserves bounded walk scope, no docker.sock, no privilege escalation, no destructive side effect."
source_artifacts:
  - elrise-backend container compromise report (2026-08-09; `Computer/reports/2026-08-09-elrise-backend-container-compromise.md`)
  - ARCHITECTURE.md § "Invariants" (1-7)
  - ARCHITECTURE.md § "Subsystem" (scan roots column)
  - ARCHITECTURE.md § "Boundaries" (loopback only, no destructive)
  - ORIGIN.md § "What it does" (detection pipeline)
  - ORIGIN.md § "Auto-fix actions" (operator decides)
  - config/default.yaml (current scan_roots)
  - docs/architecture/STATUS.md § "Risks" item 2 (encrypted droppers + footprint backbone)
  - docs/components/tmp-watcher.md (module map)
  - docs/contracts/tmp-watcher-allowlist-ioc.md (existing IOC + allowlist contract; extended)
  - docs/adr/0001-tmp-watcher-learning-model.md (precedent: 3-task decomposition, bounded scope)
  - Issues/open/architect/AR-016_container_scan_overlay.md (origin proposal)
  - Issues/done/developer/DE-006_implement_overlay_scan.md (implementation task; closed 2026-08-13)
tags: [adr, tmp_watcher, container, overlay, docker, dotdir, threat_model, elrise_incident]
---

# ADR 0002 — Container overlay scan for Azazel-style shallow dot-directories

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-08-13 |
| Authors | architect (operator-approved) |
| Supersedes | (none) |
| Implements | `docs/architecture/STATUS.md` "Risks" item 2 (expanded) |
| Decomposes into | DE-006 (developer task; single bounded commit) |

## Context

The `tmp-watcher` daemon's current scan scope is **host filesystem only**:

```
paths:
  scan_roots: ["/tmp", "/home", "/var/tmp"]
```

This scope is no longer sufficient. The 2026-08-09 `elrise-backend`
container compromise (see
`Computer/reports/2026-08-09-elrise-backend-container-compromise.md`)
demonstrated that an Azazel-style kit can persist inside a Docker
container's overlay filesystem layer for days while the host daemon
reports clean. Forensic timeline from the incident:

| Time (UTC) | Event |
|---|---|
| 2026-08-06 18:59 | `/tmp/.r.rpk/` first created inside `elrise-backend` (20 entries) — earliest evidence |
| 2026-08-09 17:43 | Host rebooted (load avg 47); `elrise-backend` restarted |
| 2026-08-09 17:56 | `elrise-backend` started again post-reboot — same container, still compromised |
| 2026-08-09 18:30 | Operator triggered 502 investigation; sysadmin found the kit |
| **5 days, 11 hours** | **Visibility gap**: host daemon polled every 10 min, never reported |

The malware location is the same shallow dot-directory pattern the
daemon already targets on the host (`/tmp/.r.rpk/`, `/tmp/.xdiag/`,
`/tmp/.apid/`, `/tmp/.perf.c/`). The only difference is that the
filesystem tree is the container's overlay layer, not the host's
`/tmp`. The host daemon's `walk()` function enumerates the host
`/tmp` directory via `std::fs::read_dir("/tmp")` — that call returns
the host's `/tmp` contents, with no awareness of overlay layers.

### Why the host scan cannot see this

Docker's `overlay2` storage driver lays down each container's
mutable filesystem under
`/var/lib/docker/overlay2/<layer-id>/{diff,merged}/`. The host's
`/tmp` is a separate tree. `find /tmp -maxdepth 3` on the host
returns only host-resident files; container-resident files exist
only inside the overlay directory tree.

The overlay write path is: a container's process writes to
`/tmp/.r.rpk/foo`; the kernel copies up the parent layer from the
image's read-only layer into the container's writable layer
(`/var/lib/docker/overlay2/<container-diff>/tmp/.r.rpk/foo`); the
host filesystem sees the file at the overlay path, not at `/tmp`
on the host.

### Why a tcp/socket-based scan is rejected

Two alternatives were considered and rejected:

1. **`docker exec` per running container** — requires `docker.sock`
   access (group `docker` membership or the unix socket's owner).
   This is a privilege escalation risk: a daemon with `docker.sock`
   access can start/stop containers, mount host filesystems, read
   any container's secrets. ARCHITECTURE.md § "Boundaries" only
   forbids inbound network and disk-secret reads; it does not
   explicitly forbid `docker.sock`, but the precedent is clear
   (loopback only, no external service dependencies). The
   `src/output.rs::ntfy_push` call site is the only networking
   primitive today, and it is opt-in.

2. **Walking the containerd CRI socket** — same privilege concern
   multiplied by `containerd.sock` + `cri-sock` per runtime.

Both alternatives also expand the daemon's threat surface (the
container runtime becomes a dependency) and add a new roundtrip
cost per poll cycle. Given that the target pattern (shallow
dot-directories) is reliable and predictable, host-side filesystem
inspection is sufficient.

### Why scanning only the host `/tmp` is not enough

`/tmp` inside most containers is `tmpfs` (in-memory). Files in
tmpfs do **not** persist across container restarts; the Azazel kit
persisted 5 days only because the daemon's `subset_of_state` was
on the overlay. So the question is: when tmpfs is used, is the
malware in tmpfs or in the overlay?

The 2026-08-09 incident answers: it is in the overlay. The
attacker chose overlay-resident paths because tmpfs would lose
state on container restart, and the attacker needed persistence
across the 2026-08-09 reboot. The `sleep 300; rm -rf /tmp/.install.pid*`
pattern (incident timeline §) is the staging pattern: write to
overlay, sleep, clean up install markers. tmpfs is a transient
substrate; the attacker prefers overlay.

We do not propose to scan tmpfs. The current contract is
"detect and quarantine the persistent footprint." Tmpfs-only
malware is a transient intrusion that disappears on container
restart — it is out of scope for this ADR.

### Why scan only `.*` (operator direction 2026-08-13)

The operator verified that the detection target is the Azazel
shallow-dot-directory pattern, not arbitrary content in `/tmp`.
The pattern is precise: `.<lowercase-token>/` at depth ≤ 3
inside the scan root. Scanning every entry under `/tmp` would
explode the I/O cost (sessions, pipe buffers, kernel tmpfiles,
all legitimate). The bounded walk is the **detection fingerprint**,
not a generic integrity scan.

This matches the host-side scan behaviour: it walks every entry
under `scan_roots` but matches on the **dot-prefixed** pattern
(see `src/subsystem.rs::walk` and the `candidate.dotdir_name`
test). The overlay scan inherits the same shape — only `.*`
entries at depth ≤ 3 are examined.

## Decision

### 0. Pattern detection strategy

The operator confirmed **Strategy A** (comprehensive `.*` + three-stage
filter) on 2026-08-13. Locked in this ADR so the developer does not
have to re-derive it.

**Strategy A — comprehensive `.*` + three-stage filter**

- **Discovery**: walk all `.*` entries at depth ≤ 3 inside the scan
  root (host `/tmp`/overlay `/tmp`).
- **Filter 1 — IOC matcher**: SHA-256 of files inside each candidate
  vs `/etc/tmp-watcher.iocs`. Match → CRITICAL + `chmod 0o000`.
- **Filter 2 — allowlist**: glob against `/etc/tmp-watcher.allowlist`.
  Match → skip (legitimate).
- **Filter 3 — unknown WARNING**: candidate passed Filters 1 and 2
  without a match. Emits `Decision::Unknown` → journal WARNING +
  `/etc/tmp-watcher.proposed.iocs` (per AR-013 learning pipeline).
  Operator review via `tmp-watcher-promote` is the only path to
  promote a candidate into the live IOC list.

**Strategies rejected on 2026-08-13**

- **Strategy B** (name-snapshot denylist only — `.r.rpk`, `.xdiag`,
  `.apid`, `.perf.c`, `.atmp`, `.dotdir`): minimal I/O, but new Azazel
  variants with different names slip through. The IOC list is the
  hash-based denylist; we do not duplicate the denylist as a name
  list.
- **Strategy C** (Strategy A + name-pattern classifier as a fourth
  filter): adds detection-by-name heuristically above hash matching.
  Deferred to follow-up; AR-013's learning pipeline gradually
  produces a name-pattern signal as `proposed.iocs` accumulates.

The three-stage filter is the same pattern the host-side scan uses
(per `src/subsystem.rs::classify`). The overlay scan inherits the
pattern unchanged; the only difference is the scan root.

### 1. Add an overlay-fs scan at the daemon's host side

The daemon's subsystem (`src/subsystem.rs::walk`) gains an
additional scan pass that walks the Docker overlay2 storage
directory. The walk discovers container layers, then walks the
`tmp/` subdirectory of each layer's `diff/` and `merged/` trees
looking for `.*` (dot-prefixed) entries at depth ≤ 3.

```
overlay_scan_roots: ["/var/lib/docker/overlay2"]
overlay_scan_maxdepth: 3
overlay_scan_dotdir_only: true   # scope-narrow: only .* entries
overlay_scan_enabled: true        # default ON; OFF for non-Docker hosts
```

The existing scanner (`subsystem::walk`) is reused against the
overlay paths. The walker composes the scan roots at runtime:
the host scan roots and the overlay scan roots are walked by the
same function, with the overlay sources added to the candidate
set. The IOC + allowlist matchers are unchanged. The quarantine
side effect (`chmod 0o000`) is unchanged in semantics; the path
that gets quarantined is the overlay path (where the host-owned
file actually lives).

### 2. No docker.sock dependency

The overlay scan is **purely host filesystem**. It does not call
`docker`, does not open `/var/run/docker.sock`, does not execute
in-container. The daemon's privilege requirements are unchanged:
read access to `/var/lib/docker/overlay2` (which is world-readable
on stock Ubuntu / Debian Docker installs; root-owned on RHEL-derived
distros and runs unprivileged — see failure modes below).

### 3. Podman / containerd / CRI-O — out of scope for v1

Overlay paths differ between runtimes:

| Runtime | Overlay path |
|---|---|
| Docker (overlay2 driver) | `/var/lib/docker/overlay2/<layer>/{diff,merged}/` |
| Podman (vfs storage) | `/var/lib/containers/storage/vfs/dir/` |
| Podman (overlay storage) | `/var/lib/containers/storage/overlay/<id>/diff/` |
| containerd (overlayfs snapshotter) | `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<n>/fs/` |
| CRI-O | `/var/lib/containers/storage/overlay/<id>/diff/` |

v1 implements Docker overlay2 only. Podman / containerd / CRI-O
are future work (see "Open questions" below). The
`overlay_scan_roots` config key is a list, so adding a Podman
host is a config-only change; the walker already iterates the
list.

### 4. New config keys

```yaml
paths:
  # existing
  scan_roots: ["/tmp", "/home", "/var/tmp"]
  scan_maxdepth: 3
  scan_window_minutes: 1440

  # new (overlay scan)
  overlay_scan_enabled: true
  overlay_scan_roots: ["/var/lib/docker/overlay2"]
  overlay_scan_maxdepth: 3
  overlay_scan_dotdir_only: true   # per operator direction 2026-08-13
```

Env overrides (per the existing `DEMON_*` convention):
`DEMON_PATHS__OVERLAY_SCAN_ENABLED`,
`DEMON_PATHS__OVERLAY_SCAN_ROOTS`,
`DEMON_PATHS__OVERLAY_SCAN_MAXDEPTH`,
`DEMON_PATHS__OVERLAY_SCAN_DOTDIR_ONLY`.

### 5. New module: `src/overlay.rs`

Scope of the new module:
- `discover_layers(roots: &[PathBuf]) -> Vec<LayerPath>` — enumerate
  overlay layers under each root.
- `walk_overlay(layer: &LayerPath, maxdepth: usize, dotdir_only: bool,
  dotdir_filter: &DotDirFilter) -> Vec<Candidate>` — walk a single
  layer's `tmp/` subtree, returning candidates distinct from
  `subsystem::Candidate` by an extra `source: CandidateSource` field
  (`Host | Overlay(DockerLayerId)`).
- `overlay_quarantine(candidate: &OverlayCandidate) -> QuarantineOutcome`
  — same `chmod 0o000` semantics, log entry includes the source
  layer id so the operator can map back to the container.

The overlay module reuses the existing IOC matcher and allowlist
filter from `src/ioc.rs` and `src/allowlist.rs`. No new match logic.

Implementation is bounded per `TASK_PLANNING_GUIDE.md` Heuristic #2:
1 commit, ≤ 5 files
(`src/overlay.rs` new, `src/subsystem.rs` extend to call overlay,
`src/config.rs` extend for new keys, `config/default.yaml` extend,
`tests/smoke.rs` new fixture).

### 6. Concrete scan paths

The walker traverses `/var/lib/docker/overlay2/<layer>/{diff,merged}/tmp/`
for each layer. For each `tmp/.?*` entry at depth ≤ 3, it runs the
existing walker's classify → hash → match → quarantine pipeline.

The `merged/` path is the live container's view (when the container
is running). The `diff/` path is the persistent upper layer (the
copy-up write target). Both are walked because a container may have
been stopped (the `diff/` is the only thing left) — the diff
persists after the container is removed (until `docker image prune`
or `docker system prune` reclaims it).

For the **elrise incident** specifically: the host's overlay2 path
would have been `/var/lib/docker/overlay2/<container-diff>/tmp/.r.rpk/`,
`tmp/.xdiag/`, `tmp/.apid/`, `tmp/.perf.c/`. The host daemon walking
those paths would have detected the kit at the 2026-08-06 poll cycle.

### 7. Quarantine on overlay paths

`chmod 0o000` on
`/var/lib/docker/overlay2/<layer>/diff/tmp/.r.rpk/` works: the
host owns the overlay directory, the chmod man-page is filesystem-
level, and the container's view of `/tmp/.r.rpk/` reflects the
underlying inode's mode.

The container's process can still attempt to read the file
(`/tmp/.r.rpk/foo`); the read will fail with EACCES. The malware
cannot exfiltrate the data, but the directory itself is preserved
on disk for forensic examination per invariant 7 (reversible
quarantine).

The active miner process inside the container is **not** stopped by
the daemon. The daemon's contract is detection + forensic
preservation; container stop is the operator's job per `RUNBOOK.md`
§ "CRITICAL flow" step 5 (`docker compose stop`). This is unchanged.

### 8. Failure modes

| Failure | Detection | Response |
|---|---|---|
| `/var/lib/docker/overlay2` does not exist | `metadata()` probe at startup | log INFO `overlay_scan_skipped reason=overlay_root_absent`; continue with host scan |
| `/var/lib/docker/overlay2` exists but is not readable | `read_dir()` Err | log WARNING; skip overlay scan for this poll cycle; continue with host scan |
| Docker uses storage driver other than overlay2 (btrfs, zfs, vfs) | `dirs` of overlay root is empty (no `<layer>/diff` subdirs) | log INFO `overlay_scan_skipped reason=no_overlay2_layers`; continue |
| Container layer has tmp/ on a separate mount (bind mount) | walker's `metadata()` returns the bind-mount path | quarantine the bind-mount path; behaviour matches host scan |
| `chmod 0o000` on overlay path fails | `Err(e)` from `std::fs::Permissions` | log CRITICAL; continue; `RUNBOOK.md` "Quarantine rollback (false positive)" instructions apply |
| `overlay_scan_enabled: false` (operator opt-out) | config flag | skip overlay scan entirely; INFO log at boot |

The overlay scan never aborts the daemon; it is best-effort with
host scan as the always-on backbone.

### 9. Tests

Required (per `TASK_PLANNING_GUIDE.md`):

| Test | What it verifies |
|---|---|
| `overlay_walk_finds_dotdir_in_diff` | Fixture overlay layout with `.r.rpk/` in `diff/tmp/`; assert candidate emitted |
| `overlay_walk_finds_dotdir_in_merged` | Same, in `merged/tmp/` (live container case) |
| `overlay_walk_skips_nondotdir` | Verify `overlay_scan_dotdir_only: true` skips `tmp/sess_*`, `tmp/.X11-unix/`, `tmp/systemd-private-*/` |
| `overlay_walk_handles_missing_root` | `overlay_scan_roots: ["/nope"]` does not crash |
| `overlay_walk_handles_unreadable_layer` | Permission-denied layer is skipped, sibling layers still scanned |
| `overlay_quarantine_chmods_path` | `chmod 0o000` applies to overlay path; idempotent on re-run |
| `overlay_module_does_not_open_docker_sock` | Static test: `src/overlay.rs` does not reference `/var/run/docker.sock`, `bollard`, `docker`, or `DOCKER_HOST`; fails CI if present |
| `overlay_dry_run_does_not_quarantine` | `--dry-run` reports candidates but does not chmod |
| `overlay_disabled_returns_no_candidates` | `overlay_scan_enabled: false` returns empty list |
| `overlay_inv6_maxdepth_enforced` | `overlay_scan_maxdepth: 0` returns no candidates |

### 10. Documentation updates

- `docs/components/tmp-watcher.md` — add overlay scan section to
  module map; extend Inputs table with `overlay_scan_roots`;
  extend Failure modes table with new rows.
- `docs/contracts/tmp-watcher-allowlist-ioc.md` — extend § "Scope"
  with overlay path; add § "Overlay scan: filter semantics" with
  the `overlay_scan_dotdir_only` behaviour.
- `RUNBOOK.md` — extend § "Common failure modes" with overlay
  non-WARNING/CRITICAL rows (overlap with this ADR's failure modes
  table).
- `docs/architecture/STATUS.md` — bump `Last Updated`; extend
  "Risks" item 2 with the overlay-scan sub-bullet.
- `docs/architecture/ROADMAP.md` — add new wave
  `wave-container-overlay-006` (this is the implementation wave).

## Constraints preserved (from ADR-0001 + ARCHITECTURE.md)

| Constraint | How preserved |
|---|---|
| Invariant 1 (idempotent restart) | `chmod 0o000` on overlay path is idempotent; overlay scan is read-only on first run |
| Invariant 2 (no silent background timers) | Overlay scan is a single pass inside one poll cycle; no internal scheduling |
| Invariant 3 (structured logging) | Overlay scan emits `overlay_scan_started`, `overlay_candidate_found`, `overlay_scan_completed` events with `source=overlay2 layer=<id>` fields |
| Invariant 4 (one subsystem per daemon) | Overlay scan is a new module consumed by `subsystem::run_once`; no new daemon process |
| Invariant 5 (failures are loud) | Overlay scan failures log WARNING/CRITICAL with structured fields; never silently skip |
| Invariant 6 (bounded walk scope) | `overlay_scan_maxdepth` ≤ 3; `overlay_scan_dotdir_only` bounds the candidate set per layer; per-layer timeout inherited from existing walker |
| Invariant 7 (reversible quarantine) | `chmod 0o000`; never `rm -rf`; `chmod 0o700` reverses |
| ORIGIN.md "Auto-fix actions" | Overlay scan does not auto-add to IOC list; relies on existing `Decision::Unknown` → proposed.iocs pipeline (AR-013) |
| `loopback only` boundary | Overlay scan is host filesystem read; no network call |
| `no inbound connections` | Same — scanner does not listen |
| `no disk-secret reads` | Overlay scan reads public filesystem paths only |
| `existing IOC + allowlist contract` | Override adds config keys; existing matcher behaviour is unchanged |
| **Production capability set (new constraint)** | The daemon runs on tmp-vps with a minimal hardening-friendly `CapabilityBoundingSet=` (`CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETFCAP`). DE-006 MUST NOT introduce new capability requirements — the overlay scan must work with the existing `CAP_DAC_READ_SEARCH` capability (sufficient for `std::fs::read_dir` on `/var/lib/docker/overlay2` on stock Docker installs). If a future feature requires more, the change is a separate ADR + a separate `systemd` unit diff, not a silent extension. Per `Issues/done/sysadmin/SA-003_install_demon-tmp-dotdir-watcher_on_tmp_vps.md` (2026-08-13 follow-up): the upstream `CapabilityBoundingSet=` (empty) recipe clears `CAP_DAC_READ_SEARCH` and breaks root readability of mode-0700 directories; the minimal-cap set is the production baseline. |

## Compliance matrix

| Requirement | Satisfied by |
|---|---|
| Scan inside containers | DE-006 overlay walker |
| No docker.sock | Static test in DE-006 |
| No privilege escalation | Host fs read only |
| `.*` only scope | `overlay_scan_dotdir_only: true` config + walker filter |
| Reversible quarantine | `chmod 0o000` (unchanged) |
| Bounded walk scope | `overlay_scan_maxdepth` ≤ 3 + dotdir filter |
| Detection latency target (10 min) | Overlay scan runs in same poll cycle as host scan |
| Decomposition into ≤ 1 commit developer task | DE-006 |
| AGENT_ISSUE_NAMING_CONVENTIONS.md | All cross-references use `AR-016`, `DE-006` |
| AGENT_OUTPUT_SANITIZATION_POLICY.md | No absolute paths in this ADR; references use `<repo_root>` semantics |
| Domain invariant (Azazel footprint pattern) | Target pattern is identical to host scan; overlay is just a different mount |

## Alternatives considered

1. **docker exec per container** — rejected. Requires `docker.sock`;
   expands threat surface; new outbound dependency per container per
   cycle. Detection pattern (shallow dot-dir) is reliable on overlay
   alone.
2. **containerd CRI socket** — rejected. Same privilege concern.
3. **Scan all overlay paths including root (`/`) inside container** —
   rejected. I/O bound explodes; pattern is `.?*` at depth ≤ 3 in
   `/tmp`; broadening scope adds noise without detection power.
4. **Single panic-everything scan** — rejected. Must compose with
   host scan and degrade gracefully when Docker is not installed.
5. **Defer to manual operator workflow** — rejected. The 71-hour
   detection-lag reduction is the daemon's business goal;
   5-day persistence is unacceptable.
6. **Replace host scan with overlay scan** — rejected. Non-container
   hosts (no Docker) would lose detection entirely. Host scan is
   the always-on backbone; overlay scan is additive.

## Open questions for operator (carried into DE-006 implementation)

1. **`overlay_scan_enabled` default**. This ADR proposes default
   `true` because containers are now standard; an operator on a
   non-Docker host can set it `false`. Confirm or override.
2. **Overlay path coverage**. v1 implements Docker `overlay2` only.
   Podman / containerd / CRI-O are listed as future work. If
   `iton-nest` runs only Docker, this is fine; if Podman is in use
   on any host, an additional developer task is required.
3. **Read-only rootfs containers**. Containers with
   `read_only: true` in compose cannot write to `/tmp` regardless,
   so the Azazel pattern collapses there. No action needed; the
   dotdir walker simply finds nothing.
4. **`overlay_scan_dotdir_only` discoverability**. The key is
   `true` by default but a verbose operator might want to set
   `false` for incident-time deep-scan. The CLI flag
   `--overlay-force-full` is a candidate follow-up; not in v1.

## Out of scope (explicit)

- `docker exec` / `docker.sock` integration. v1 is host-fs only.
- Podman / containerd / CRI-O runtime support. v1 is Docker overlay2.
- Tmpfs-resident malware scan. Tmpfs is out of scope per "Why
  scanning only the host `/tmp` is not enough" above.
- Active container stoppage. The daemon detects; the operator
  stops per `RUNBOOK.md` "CRITICAL flow" step 5.
- Forensic archive for overlay-resident files. The same
  `tar -cz /tmp/.r.rpk` recipe in `RUNBOOK.md` works on overlay
  paths with the operator substituting the absolute overlay path.
- Network-namespaced container inspection. v1 only inspects the
  host filesystem tree.

## Sources / Authority

- Operator directive 2026-08-13 (this session): "у этого демона
  есть одна проблема.. он сканирует систему, но не сканирует
  контейнеры docker" + "ответаы: сканировать только .*".
- `Computer/reports/2026-08-09-elrise-backend-container-compromise.md`
  — incident timeline, evidence, and root-cause analysis.
- `Issues/open/architect/AR-016_container_scan_overlay.md` —
  origin proposal; this ADR codifies the decision. The proposal
  remains in `Issues/open/architect/` per
  `AGENT_ISSUE_ROUTING_AND_LOCATION.md` Rule 4 (proposal-stage
  exception); it is the umbrella for the now-closed
  `DE-006_implement_overlay_scan.md`.
- `Issues/done/developer/DE-006_implement_overlay_scan.md` —
  implementation task (closed 2026-08-13; bounded single commit;
  DoD-Report `Status: CLOSED (full closure)`).
- `docs/adr/0001-tmp-watcher-learning-model.md` — precedent for
  3-task decomposition and bounded-scope policy.
- `ARCHITECTURE.md` § "Invariants" (1-7) — preserved.
- `ORIGIN.md` § "Auto-fix actions" — preserved.
- `docs/architecture/STATUS.md` § "Risks" item 2 — extended.
- `Issues/done/sysadmin/SA-003_install_demon-tmp-dotdir-watcher_on_tmp_vps.md`
  (2026-08-13 follow-up) — production deployment context: the
  daemon runs with a minimal hardening-friendly
  `CapabilityBoundingSet=` (replaced upstream empty set after EACCES
  on `/home/deploy/.docker` and `/home/deploy/.ssh`). Production
  expects 2 candidates per tick. The overlay scan must work with
  the existing capability set (no new caps required).
