---
contract: webhook-payload
producer: output
consumer: operator notification handlers
boundary: HTTP POST to operator-supplied NTFY URL
version: 1
last_updated: 2026-08-13
---

# Contract: `webhook-payload` — NTFY message shape

## Boundary

The daemon POSTs a per-tick summary to `actions.ntfy_url` after every
tick when `Config.actions.ntfy_url` is `Some(_)`. The contract
specifies the HTTP request shape (URL, method, headers, body) and
the priority / tags conventions. The contract is intentionally
aligned with `demon-docker-janitor`'s `docs/contracts/webhook-payload.md`
for cross-daemon parity.

The daemon does NOT construct the URL. `actions.ntfy_url` is
operator-supplied via `/etc/tmp-watcher.yaml` or
`DEMON_ACTIONS__NTFY_URL` (per DE-019).

## Request shape

### Method + URL

```
POST <actions.ntfy_url>
```

`<actions.ntfy_url>` is operator-supplied. The daemon does NOT
construct, validate, or normalize the URL.

### Headers

| Header | Required | Value |
|---|---|---|
| `Title` | yes | `tmp-watcher: cycle <status>` |
| `Priority` | yes | `1` (min) .. `5` (max), per severity mapping |
| `Tags` | yes | Comma-separated: `tmp,watcher,<status>` |
| `Content-Type` | no | `text/plain` (default; the body is `key=value` lines) |

### Body (text)

The body uses the peer daemon's `key=value` plain-text shape with
newline separators (no commas). Every key is one line:

```
candidates={n}
allowlisted={n}
ioc_matches={n}
quarantined={n}
unknown={n}
skipped={n}
unreadable_roots={n}
duration_seconds={n}
```

Field semantics (all values are integers; `unreadable_roots` is
the count of unreadable scan roots, NOT the list of paths):

| Key | Source |
|---|---|
| `candidates` | total candidates classified in this tick |
| `allowlisted` | candidates that matched the allowlist (silently skipped) |
| `ioc_matches` | candidates that matched an IOC SHA-256 |
| `quarantined` | IOC matches for which `chmod 000` succeeded |
| `unknown` | candidates that were neither allowlisted nor IOCs |
| `skipped` | candidates that errored mid-classification (count) |
| `unreadable_roots` | top-level scan roots whose `read_dir` returned `Err` (CR-006) |
| `duration_seconds` | wall-clock duration of the tick in seconds |

### Severity → priority mapping

| Severity | Webhook priority | When |
|---|---|---|
| `info` | 2 (default) | tick completed clean (`ioc_matches == quarantined`, no unreadable roots, no skipped, candidates > 0) |
| `warn` | 3 (high) | `unreadable_roots > 0` OR `skipped > 0` OR `candidates == 0` (no scan output — possible runtime regression) |
| `error` | 5 (urgent) | quarantine partial failure (`ioc_matches > 0` AND `quarantined < ioc_matches`) OR tick returned `Err` |

The `<status>` token in `Title` / `Tags` is one of `info`, `warn`,
`error` and matches the severity that produced the priority. The
mapping is implemented in `src/output.rs::Severity::from_run_summary`
and covered by unit tests.

## Examples

### Success tick

```
POST <actions.ntfy_url>
Title: tmp-watcher: cycle info
Priority: 2
Tags: tmp,watcher,info

candidates=12
allowlisted=8
ioc_matches=1
quarantined=1
unknown=2
skipped=0
unreadable_roots=0
duration_seconds=4
```

### Unreadable-root warning

```
POST <actions.ntfy_url>
Title: tmp-watcher: cycle warn
Priority: 3
Tags: tmp,watcher,warn

candidates=12
allowlisted=8
ioc_matches=0
quarantined=0
unknown=2
skipped=1
unreadable_roots=1
duration_seconds=4
```

### Quarantine partial failure

```
POST <actions.ntfy_url>
Title: tmp-watcher: cycle error
Priority: 5
Tags: tmp,watcher,error

candidates=5
allowlisted=0
ioc_matches=3
quarantined=1
unknown=0
skipped=0
unreadable_roots=0
duration_seconds=2
```

## Behavioural guarantees

1. **One POST per tick.** Even if multiple failure modes co-occur
   (e.g. unreadable root + skipped candidate), the daemon sends
   one summary POST that classifies the worst observed severity.
2. **Webhook failure never blocks tick completion.** A non-2xx
   response or transport timeout is logged at `priority = 4`
   WARNING but does NOT change the tick exit code. The next tick
   retries (per `docs/architecture/STATUS.md` "next-poll retries"
   semantics for the IOC-match path; reused verbatim for the
   post-tick summary).
3. **No body in the IOC-match path.** The per-tick summary emit
   is a separate function (`push_tick_summary` /
   `push_tick_summary_with_headers`); the IOC-match path uses
   `output::ntfy_push` directly with a `path=...sha256=...` body.
   The contract above is for the per-tick summary only.
4. **`actions.ntfy_url` is the topic URL.** The daemon POSTs to
   it directly; the operator-side handler forwards to whatever
   notification system is in use. No URL construction, no
   path suffix, no auth header added by the daemon.
5. **Severity defaults when `actions.ntfy_url` is unset.** With
   `actions.ntfy_url = None` (the embedded default per AR-011),
   the post-tick summary path short-circuits and no HTTP traffic
   is generated; the per-tick `info!(... 'runtime: tick summary')`
   journal line is the only emit.

## Versioning

Semver. Major bump on header rename or removal. Minor bump on
optional header addition. The body is a positional `key=value`
shape (not JSON) by design — the peer daemon uses the same shape
for cross-daemon parity, and a positional shape lets operators
forward the body verbatim to NTFY / Telegram / Slack without
parsing JSON.

## Cross-references

- `ARCHITECTURE.md` § "Invariant 5 — Failures are loud" — the
  daemon's failure-loudness contract is re-tightened by
  `actions.ntfy_url` + this contract.
- `docs/components/tmp-watcher.md` § "Webhook channel" — the
  producer side (producer = `output`).
- `src/output.rs::Severity::from_run_summary` — implementation
  of the severity mapping.
- `src/output.rs::assemble_summary_payload` — pure assembler.
- `src/output.rs::push_tick_summary_with_headers` — wire
  format.
- `demon-docker-janitor/docs/contracts/webhook-payload.md` —
  template (peer contract; the body field set differs but the
  shape convention is shared).
