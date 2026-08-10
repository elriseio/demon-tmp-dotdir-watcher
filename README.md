Demon: tmp-dotdir-watcher

## Build / Run / Test

```bash
cargo build --release
cargo run --release     # placeholder loop; replace src/main.rs
cargo test
```

## Current state

| Field | Value |
|---|---|
| Kind | proposed |
| Production deploy | not yet deployed |
| Rust port | scaffold only |
| Owner | sysadmin (see computer:/demons README) |

## Source of truth

`ORIGIN.md` is the canonical operator-facing description. Any
disagreement between this folder and ORIGIN.md is a bug;
reconcile by updating this folder to match.

## Host scope

Single host: `tmp-vps (46.36.219.176)`. The daemon is the
direct response to the 2026-08-09 Azazel compromise on
`elrise-backend`; see `notes/2026-08-09-elrise-compromise-malware-analysis.md`.

## Priority

High — would have detected the 2026-08-09 incident 71 hours
earlier than the operator-flagged 502 detection.

## Related

- computer:/demons/proposed/tmp-dotdir-watcher.md — original catalogue entry
- ../README.md — folder-level convention
- ../_template/README.md — scaffold conventions
