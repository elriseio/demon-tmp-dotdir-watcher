---
demon: tmp-dotdir-watcher
kind: proposed
status: scaffold
language_target: rust
priority: high
---

# tmp-dotdir-watcher

> Brief for an architect picking up this daemon cold. The full
> operator-facing description (problem, algorithm, config, failure
> modes) lives in ORIGIN.md. This file is the on-ramp.

## One-line purpose

```
Hidden Azazel-style malware footprints under `/tmp/.dotdir/`
(`.r.rpk/`, `.xdiag/`, `.perf.c/`, `.apid/`, `.atmp/`)
```

Open ORIGIN.md and read the full problem statement and algorithm.

## Where it lives

| Field | Value |
|---|---|
| Folder | `demon-tmp-dotdir-watcher/` |
| Crate | `demon-tmp-dotdir-watcher` (Cargo.toml) |
| Source of truth | ORIGIN.md (verbatim copy from existing catalogue) |
| Reference index | computer:/demons/proposed/tmp-dotdir-watcher.md |

## Status

**Proposed** daemon: spec exists (see ORIGIN.md); no production
deployment yet. Effort estimate is in ORIGIN.md under "Effort
estimate" — ~3 hours total. Build order among the proposed set
is set by the priority listed in the catalogue index. This one
is **high** because it would have turned the 71-hour Azazel
detection lag into a same-day find.

The Cargo.toml / src/ main.rs available here are a scaffold only.

## What an architect should know before touching this daemon

1. **Read ORIGIN.md first.** It is the canonical source for "what
   this daemon does, when it fires, and what it should never do".
   Anything in this folder that contradicts ORIGIN.md is a bug.
2. **Forensics origin.** This daemon was specified the same day
   as an Azazel-family compromise analysis. The problem statement,
   IOC list, and allowlist are derived directly from that
   incident. When changing the IOC list, cite the originating
   threat family in the commit message.
3. **State directory and config live on the host** under
   `/run/tmp-watcher/`, `/var/log/tmp-watcher.log`, and
   `/etc/tmp-watcher.{conf,allowlist,iocs}` (see ORIGIN.md
   "Configuration" + "State"). The Rust port must keep the same
   paths so existing operator runbooks and incident-response
   scripts do not break.
4. **Logging is `journalctl -t tmp-watcher`** with structured
   journal tags (`PRIORITY=2` for CRITICAL, `PRIORITY=4` for
   WARNING). The Rust port MUST emit equivalent fields so log
   filters keep working.
5. **Restart policy is on-failure, never always.** The daemon is
   timer-driven (every 10 min); auto-restart loops on a
   persistent failure would burn CPU.
6. **Side effect is destructive on detection.** On an IOC match
   the daemon auto-quarantines via `chmod 000 <path>`. The Rust
   port MUST preserve this exact side effect — never `rm -rf` —
   and MUST make the auto-quarantine idempotent (re-running
   against an already-chmod-000 path must not error).

## Open questions (carry into the first implementation commit)

- [ ] Confirm the host list in ORIGIN.md "Target host" is current
      (single Linux host running systemd).
- [ ] Confirm the IOC list is current and matches the canonical
      forensic archive reference.
- [ ] Confirm the allowlist is current (X11 + systemd-private
      entries live and stable).
- [ ] Replace the placeholder loop in `src/main.rs` with the
      subsystem described in ORIGIN.md.
- [ ] Decide whether the Rust port preserves the bash script's
      CLI surface (`--validate-config`, `--dry-run`) or replaces
      it.

## Cross-references

- ORIGIN.md — full operator description
- ARCHITECTURE.md — component breakdown, invariants, failure modes
- RUNBOOK.md — operator triage flow
- README.md — build / run / test commands
- ../README.md — folder convention for all daemons
- ../_template/README.md — starting-point conventions
