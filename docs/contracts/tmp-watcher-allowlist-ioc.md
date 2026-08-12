---
project_slug: demon-tmp-dotdir-watcher
doc_slug: contracts_tmp_watcher_allowlist_ioc
doc_type: contract
applicable_roles: [all]
version: 1
summary: "Boundary contract for the tmp-watcher IOC list + allowlist semantics. Defines file format, parsing rules, glob syntax, and matching semantics for both `/etc/tmp-watcher.iocs` and `/etc/tmp-watcher.allowlist`. Authoritative for the bash reference impl, the Rust port, and any future reimplementation; if they drift, this contract is the source of truth."
source_artifacts:
  - ORIGIN.md
  - ARCHITECTURE.md
  - config/default.yaml
  - docs/components/tmp-watcher.md
tags: [contract, tmp_watcher, ioc_list, allowlist, glob, sha256]
---

# Contract: `tmp-watcher` IOC list + Allowlist

> **Boundary:** between the tmp-watcher daemon's filesystem
> configuration files and its matchers (`ioc::Matcher`,
> `allowlist::Allowlist`).
> **Scope:** file format, parsing rules, glob syntax, and
> matching semantics. NOT in scope: scan-roots configuration,
> cadence, journal output schema (those live in
> `docs/components/tmp-watcher.md` and `ARCHITECTURE.md`).

## File: `/etc/tmp-watcher.iocs` — IOC list

### Format

- One SHA-256 hex string per line.
- Lowercase hex only (64 chars, `[0-9a-f]{64}`).
- No `sha256sum`-style `<hash>  ` dual-column format —
  filename tokens are ignored if present (current bash impl uses
  just the first column).
- Empty lines are allowed and ignored.
- Lines starting with `#` are comments and ignored (until end of
  line).
- Trailing whitespace is trimmed.
- Whitespace inside the hash string is an error: loader MUST
  reject the file and log CRITICAL + NTFY (systemd retries).

### Loader semantics

- On startup, the IOC list is read once.
- **Baseline (not an error)**: if the file is missing or
  contains only comments and blank lines, use `Matcher::empty()`,
  log INFO with `ioc_count=0`, proceed with the scan, and emit
  `Decision::Unknown` for every candidate. This is the expected
  state for a fresh deployment: the operator has not yet curated
  the IOC list, and the daemon must still operate against the
  current files on disk. systemd `Restart=on-failure` does NOT
  trigger because the missing-file case is not a failure.
- If the file is unreadable (e.g., permission denied): the same
  baseline behavior fires (graceful-degrade to `Matcher::empty()`).
  The current detection daemon path treats this uniformly with the
  missing-file case; a strict-fail-closed variant is out of scope
  for this contract revision.
- If the file exists with content but contains a malformed line
  (e.g., invalid SHA-256 hex, wrong line length): the daemon path
  currently also degrades to `Matcher::empty()` (the runtime's
  `Err(e)` arm is shared across all `Matcher::load` failures). A
  strict-fail-closed variant for malformed-only is a candidate
  follow-up; today the contract reflects the runtime behavior.

### Matcher semantics

- Lookup is by **SHA-256 hash of a single file** inside the
  candidate dotdir.
- Recursion depth: walk the candidate dotdir, hash each regular
  file up to `max_files_per_dir` (default 10).
- Match: candidate is quarantined if **any** of the hashed files
  is present in the IOC set.
- Quarantine applies to the **parent** dotdir (the one matching
  `/tmp/.dotdir/`, `/home/<user>/.atmp/`, etc.), not to the
  individual file. Idempotent: re-running against an
  already-chmod-000 directory is a no-op.
- The hashing step uses SHA-256, hex-lowercase, no prefix. If
  `sha256sum` is used in the bash reference impl, the loader
  MUST strip the `  filename` suffix before lookup.

### Example

```
# Example IOC entry (synthetic hash for documentation; not a real sample)
b02ad43cfa407a01c376c7a904104b03  trunk.md5
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  trunk.sha256
```

The first non-comment line is a 32-char hex MD5 hash (legacy)
that the loader MUST ignore (length != 64). The second line is
a valid 64-char SHA-256 hash; the trailing `trunk.sha256` token
is the filename (ignored).

## File: `/etc/tmp-watcher.allowlist` — Allowlist

### Format

- One glob pattern per line.
- Patterns are matched against the **dotdir basename** (the
  last path component of the candidate dotdir), NOT the full
  path. Example: candidate `/tmp/.font-unix` matches the
  pattern `.font-unix`.
- Patterns follow `find -name` glob semantics: `*` matches any
  number of characters, `?` matches any single character,
  `[abc]` matches any one of the listed characters.
- Anchoring: patterns are anchored at the start of the basename
  (implicit `^`) but NOT at the end (implicit `.*`). Pattern
  `systemd-private-*` matches `systemd-private-abc1234`.
- Empty lines are allowed and ignored.
- Lines starting with `#` are comments and ignored (until end of
  line).
- Trailing whitespace is trimmed.

### Loader semantics

- On startup, the allowlist is read once.
- If the file is missing: log WARNING (`PRIORITY=4`), proceed
  with an empty in-memory allowlist (every dotdir will be
  hashed and matched).
- If the file is unreadable: same as missing.
- If the file has any malformed pattern (e.g. unmatched `[`):
  log WARNING + NTFY, skip that single pattern (the rest of
  the allowlist still loads).

### Matcher semantics

- For each candidate dotdir, check its basename against every
  loaded pattern.
- **Short-circuit on first match** — the candidate is allowlisted
  as soon as one pattern matches.
- An allowlisted candidate is **skipped entirely**: no SHA-256
  work, no journal line, no NTFY.

### Default contents (deployed)

```
# FastPanel2 X11 / systemd-private entries (legitimate)
.font-unix
.ICE-unix
.X11-unix
.XIM-unix
.Test-unix
systemd-private-*
```

## Cross-references

- `ORIGIN.md` § "Allowlist" — operator-facing description
- `ORIGIN.md` § "IOC list" — operator-facing description
- `config/default.yaml` — paths to the live config files (this
  daemon does NOT deploy them; the systemd unit places them at
  the canonical paths on install)
- `docs/components/tmp-watcher.md` — module map (`ioc` /
  `allowlist` / `learn`)
- `ARCHITECTURE.md` § Failure modes — "IOC list missing",
  "Allowlist missing"

## File: `/etc/tmp-watcher.proposed.iocs` — Candidate IOC list

The detection daemon auto-observes `Decision::Unknown` events
and writes candidate-IOC entries to a **separate** file. The
live `/etc/tmp-watcher.iocs` is never mutated by the detection
daemon; the operator reviews the proposal file and runs the
forthcoming `tmp-watcher-promote` CLI to move selected entries
to the live IOC list. Per `ARCHITECTURE.md` invariant 7
(reversible quarantine) and `ORIGIN.md` "Auto-fix actions"
(no auto-add to allowlist), this is the only auto-write surface
the detection daemon has.

### Format

One entry per line, four whitespace-separated fields:

```
<UTC-ISO>  <sha256-or-dash>  <basename>  <first-seen-path>
```

- `<UTC-ISO>` — RFC3339 / ISO8601 in UTC, e.g.
  `2026-08-12T18:30:00Z`.
- `<sha256-or-dash>` — lowercase 64-char hex SHA-256 of the
  first entry file under the candidate dotdir; the literal
  `-` (single hyphen) when the candidate has no entry files
  (basename-only proposal).
- `<basename>` — the dotdir basename (the candidate path's
  last component).
- `<first-seen-path>` — the directory path where the
  candidate dotdir was observed (operator-facing context).

Example:

```
2026-08-12T18:30:00Z  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  .r.rpk  /tmp/.r.rpk
2026-08-12T18:30:00Z  -  .weird-xdg  /tmp/.weird-xdg
```

### Loader semantics (proposer writer)

- The detection daemon is the **only writer** of this file.
  The live IOC list is mutated only by the operator-side
  `tmp-watcher-promote` CLI tool (separate scope, future
  follow-up).
- The file is **append-only** within one rotation cycle. The
  writer does NOT rewrite existing lines; it only appends new
  candidate entries.
- The writer is **lock-free single-writer** (the detection
  daemon). If a second writer ever appears, the writer MUST
  add an `flock(LOCK_EX)` per `Issues/open/scout/briefs/SC-RUST-007`.

### Dedup semantics

- The proposer maintains a `HashSet<(basename, sha256)>`
  cache for the lifetime of the writer.
- The same `(basename, sha256)` pair observed twice within
  the writer's lifetime does NOT produce a second entry — the
  second call returns `ProposalAction::Duplicate` and is a
  no-op on the file.
- Across writer restarts, the cache is reconstructed from the
  file content at writer startup: a `(basename, sha256)` pair
  that is already on disk is treated as a duplicate.
- After a rotation, the cache is cleared: the rotated file
  remains in `/var/log/tmp-watcher/`, and the new empty file
  is the new dedupe scope.

### Retention policy

- The file is rotated at **10 MB or 30 days**, whichever
  comes first.
- On rotation, the live file is moved to
  `/var/log/tmp-watcher/proposed-rotate-<UTC>.iocs` (where
  `<UTC>` is the Unix epoch seconds at rotation time).
- The live file is recreated empty after rotation.
- The `/var/log/tmp-watcher/` directory MUST exist and be
  writable by the daemon; the systemd unit is responsible
  for creating it at install time. Rotation failures are
  logged at CRITICAL (`priority = 2`) and the live file is
  kept as-is (the append proceeds against the existing file).

### Failure handling

- A writer error during `proposer.observe` is logged at
  CRITICAL (`priority = 2`) via `tracing::error!` with the
  basename and the error message. The detection daemon does
  NOT abort the poll cycle on a proposer error; the next
  poll cycle retries.
- The detection daemon does NOT touch
  `/etc/tmp-watcher.iocs` (the live IOC list) in any branch
  of `Proposer::*`.
