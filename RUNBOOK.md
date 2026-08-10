---
demon: tmp-dotdir-watcher
kind: proposed
audience: operator
---

# Runbook

## Quick health check

```bash
# is the timer scheduled?
systemctl list-timers --all | grep tmp-watcher

# when did it last run?
systemctl status tmp-watcher.service

# latest log lines
journalctl -t tmp-watcher -n 50 --since "1 hour ago"

# any CRITICAL alerts in the last 24h?
journalctl -t tmp-watcher PRIORITY=2 -S -24h

# any WARNING (unknown dotdir) in the last 24h?
journalctl -t tmp-watcher PRIORITY=4 -S -24h

# full event log
tail -100 /var/log/tmp-watcher.log
```

## Common failure modes

(Fill in from ORIGIN.md "Failure modes" section. Each entry must
include: symptom, triage steps, escalation path.)

### 1. CRITICAL: IOC match (host may be compromised)

**Symptom:** `PRIORITY=2` journal line + NTFY alert with
"daemon: tmp-watcher | event: ioc_match | path: /tmp/.dotdir/...".
The daemon has already `chmod 000` the matched directory.

**Triage:**

1. **Do NOT delete the matched directory.** It is the forensic
   evidence. `chmod 000` makes it inaccessible but preserves
   the disk state.
2. Inspect the directory contents:
   ```bash
   sudo chmod 700 /tmp/.dotdir/.r.rpk  # temporary re-enable for read
   sudo find /tmp/.dotdir -maxdepth 3 -type f -print0 | \
     xargs -0 sha256sum | tee /tmp/ioc-matched.sha256
   sudo chmod 000 /tmp/.dotdir/.r.rpk  # re-quarantine
   ```
3. Compare the file hashes against the canonical IOCs at
   `/etc/tmp-watcher.iocs` and the forensic archive at
   `/opt/forensics/2026-08-09-elrise-compromise.tar.gz`.
4. Capture:
   ```bash
   sudo tar -cz /tmp/.dotdir > /tmp/ioc-matched-dirs.tgz 2>/dev/null
   sudo journalctl -t tmp-watcher -o json > /tmp/tmp-watcher.json
   ```
5. Take the host offline (`docker compose stop` for affected
   services, then `iptables -I INPUT -s <host> -j DROP` for
   upstream containment).
6. Begin incident-response per the playbook in
   `notes/2026-08-09-elrise-compromise-malware-analysis.md`.

**Escalation:** open an incident; the original Azazel analysis
chain is the canonical reference.

### 2. WARNING: unknown dotdir (likely false positive)

**Symptom:** `PRIORITY=4` journal line with a path that does
not match the IOC list and is not in the allowlist.

**Triage:**

1. Inspect the directory:
   ```bash
   ls -la /tmp/<unknown-dotdir>
   sudo find /tmp/<unknown-dotdir> -maxdepth 3 -type f
   ```
2. If the contents are legitimate (X11 socket, systemd-private,
   build artefact, etc.): add the directory name to
   `/etc/tmp-watcher.allowlist`. Restart the daemon or wait
   for the next poll cycle.
3. If the contents are unknown binaries: treat as a potential
   IOC, follow CRITICAL flow above.

**Escalation:** if the path matches a 2026-08-09 Azazel pattern
(`.r.rpk`, `.xdiag`, `.perf.c`, `.apid`, `.atmp`) at all,
escalate immediately.

### 3. Daemon not running

**Symptom:** `systemctl status tmp-watcher.service` shows
`inactive (dead)`. No recent journal lines.

**Triage:**

1. Check the timer:
   ```bash
   systemctl list-timers --all | grep tmp-watcher
   ```
2. Check the last run logs:
   ```bash
   journalctl -t tmp-watcher -n 50
   ```
3. Try a manual run:
   ```bash
   demon-tmp-dotdir-watcher --dry-run
   ```
4. If manual run fails with a config error, fix
   `/etc/tmp-watcher.conf` and retry.

**Escalation:** if the daemon refuses to start after a config
fix, capture the full journal output and the contents of
`/etc/tmp-watcher.*` and escalate.

### 4. Quarantine rollback (false positive)

**Symptom:** operator identified a CRITICAL alert as a false
positive; the daemon has `chmod 000` the directory.

**Triage:**

1. Re-enable access:
   ```bash
   sudo chmod 700 /tmp/<the-directory>
   ```
2. Confirm the contents are legitimate with the operator.
3. Add the directory name to `/etc/tmp-watcher.allowlist`.
4. Restart the daemon or wait for the next poll cycle.
5. The directory remains at mode `700` until the operator
   cleans it up; the daemon will not re-quarantine it once
   it is in the allowlist.

## Restart policy

```ini
Restart=on-failure
RestartSec=5s
```

The daemon is restart-safe only if the scan is idempotent.
The Rust port MUST verify that re-running against an already
chmod-000 path does not error (it must be a no-op).

## Configuration reload

The daemon does not support SIGHUP. To pick up a config change:

```bash
$EDITOR /etc/tmp-watcher.conf
demon-tmp-dotdir-watcher --validate-config
systemctl start tmp-watcher.service
```

For allowlist changes (common false-positive mitigation):

```bash
$EDITOR /etc/tmp-watcher.allowlist
# next poll cycle (within 10 min) picks it up automatically
```

## Escalation

If the symptom is not listed above:

1. Capture the last 200 structured journal lines:
   `journalctl -t tmp-watcher -n 200 -o json > /tmp/tmp-watcher.json`
2. Capture the daemon's state directory:
   `tar -cz /run/tmp-watcher/ > /tmp/tmp-watcher-state.tgz`
3. Capture the host fingerprint:
   `uname -a; cat /etc/os-release; df -h /tmp /home /var/tmp`
4. Capture the systemd unit status:
   `systemctl status tmp-watcher.service tmp-watcher.timer --no-pager`
5. Escalate to the daemon owner (see DAEMON.md and ORIGIN.md).

## Audit notes

When the daemon does a clean shutdown or recovers from a long
outage, it should append a one-liner to:

```
/home/alex/Er/Computer/reports/<date>-tmp-watcher.md
```

For IOC matches, the daemon writes a separate incident file
under `/home/alex/Er/Computer/reports/<date>-tmp-watcher-ioc-<hash>.md`
with the matched path, hash, and quarantine action.

## Cross-references

- ORIGIN.md — full description
- ARCHITECTURE.md — invariants
- DAEMON.md — on-ramp
- notes/2026-08-09-elrise-compromise-malware-analysis.md —
  the incident that produced this spec
