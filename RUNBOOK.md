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

**Symptom:** `PRIORITY=2` journal line with
"daemon: tmp-watcher | event: ioc_match | path: /tmp/.dotdir/...".
The daemon has already `chmod 000` the matched directory. The NTFY
push for operator phone alert is **planned, not wired** today
(see `docs/architecture/STATUS.md`); if the journal is silent and
the operator phone is silent, the IOC match may have been missed
by the systemd-journal shipping path. Verify with
`journalctl -t tmp-watcher PRIORITY=2 -S -1h`.

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
   `/etc/tmp-watcher.iocs` and against any operator-supplied
   forensic archive referenced from the per-host IOC source.
4. Capture:
   ```bash
   sudo tar -cz /tmp/.dotdir > /tmp/ioc-matched-dirs.tgz 2>/dev/null
   sudo journalctl -t tmp-watcher -o json > /tmp/tmp-watcher.json
   ```
5. Take the host offline (`docker compose stop` for affected
   services, then `iptables -I INPUT -s <host> -j DROP` for
   upstream containment).
6. Begin incident-response per the playbook in
   the post-incident write-up in the operator's notes tree.

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

**Escalation:** if the path matches an Azazel-style pattern
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
4. If manual run fails with a config error, fix the YAML
   config (default at `config/default.yaml`; operator override
   at `/etc/tmp-watcher.yaml` if present) and retry. No
   other config file path is read by the Rust port.

**Escalation:** if the daemon refuses to start after a config
fix, capture the full journal output, the resolved config (run
`demon-tmp-dotdir-watcher --print-config` if available, else
copy `/etc/tmp-watcher.yaml` plus the embedded default), and
the contents of `/etc/tmp-watcher.{allowlist,iocs}` and
escalate.

### 4. Quarantine rollback (false positive)

**Symptom:** operator identified a CRITICAL alert as a false
positive; the daemon has `chmod 000` the directory.

**Triage:**

1. Re-enable access:
   ```bash
   sudo chmod 700 /tmp/<the-directory>
   ```
   For overlay-resident matches (the container's overlay path), use
   the path the daemon's CRITICAL journal line reports:
   ```bash
   sudo chmod 700 /var/lib/docker/overlay2/<layer-id>/diff/tmp/<the-directory>
   ```
2. Confirm the contents are legitimate with the operator.
3. Add the directory name to `/etc/tmp-watcher.allowlist`.
4. Restart the daemon or wait for the next poll cycle.
5. The directory remains at mode `700` until the operator
   cleans it up; the daemon will not re-quarantine it once
   it is in the allowlist.

### 5. WARNING: overlay scan skipped (no Docker on host)

**Symptom:** journal line at INFO priority
`overlay_scan_skipped reason=overlay_root_absent` at boot.

**Triage:** expected on non-Docker hosts. The overlay scan is
opt-in via `paths.overlay_scan_enabled`; set to `false` in
`/etc/tmp-watcher.yaml` to silence the INFO log.

**Escalation:** none — the host scan continues normally.

### 6. WARNING: overlay root unreadable

**Symptom:** journal line at WARNING priority
`overlay_scan_skipped reason=overlay_root_unreadable` once per poll
cycle. The host scan still runs; only the overlay scan is skipped.

**Triage:**

1. Verify the daemon has read access to the overlay root:
   ```bash
   ls -la /var/lib/docker/overlay2
   sudo -u <daemon-user> ls /var/lib/docker/overlay2
   ```
2. On RHEL-derived Docker installs, the overlay root is root-owned
   with mode 0o700 by default. Add the daemon's user to the
   `docker` group, or run the daemon as root per the existing
   systemd unit.
3. If the daemon SHOULD run unprivileged, set:
   ```yaml
   paths:
     overlay_scan_enabled: false
   ```
   in `/etc/tmp-watcher.yaml`. Host scan still catches the host-side
   pattern; container-resident kits are missed (documented in
   STATUS.md § "Risks" item 5).

**Escalation:** if the overlay scan is required for compliance
(no host without overlay coverage), add the daemon to the `docker`
group on the affected host.

### 7. INFO: overlay2 driver not detected

**Symptom:** journal line at INFO priority
`overlay_scan_skipped reason=no_overlay2_layers` at boot, then
silence thereafter.

**Triage:** Docker is using a storage driver other than `overlay2`
(btrfs, zfs, vfs). The overlay scan gracefully skips. Future work
will add support for the other drivers; v1 is Docker `overlay2` only.

**Escalation:** none — host scan continues normally. If the host
has a high-value container workload relying on overlay coverage,
open a follow-up issue for the non-overlay2 driver.

### 8. CRITICAL: overlay quarantine failed

**Symptom:** journal line at CRITICAL priority
`overlay_quarantine_failed path=<overlay-path> reason=<error>`.

**Triage:** the daemon found an IOC match on an overlay path but
could not apply `chmod 0o000`. The matched file is still active.

1. Inspect the path manually:
   ```bash
   ls -la /var/lib/docker/overlay2/<layer>/diff/tmp/<matched-dir>
   ```
2. Apply the quarantine manually:
   ```bash
   sudo chmod 0 /var/lib/docker/overlay2/<layer>/diff/tmp/<matched-dir>
   ```
3. Stop the affected container per the operator playbook:
   ```bash
   docker stop <container-id>
   ```
4. Capture the journal lines for the incident (see § 1
   "CRITICAL: IOC match" step 4) and follow the IOC-match incident
   flow from step 5.

**Escalation:** follow the CRITICAL IOC-match flow downstream.

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
$EDITOR /etc/tmp-watcher.yaml      # or the embedded config/default.yaml
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
${REPORT_DIR}/<date>-tmp-watcher.md
```

For IOC matches, the daemon writes a separate incident file
under `${REPORT_DIR}/<date>-tmp-watcher-ioc-<hash>.md`
with the matched path, hash, and quarantine action.

`${REPORT_DIR}` is the operator-configured report directory; see
`config/default.yaml` § `report_dir` for the canonical default and
override it per host via `/etc/tmp-watcher.yaml` or the
`DEMON_TMP_DOTDIR_WATCHER_REPORT_DIR` environment variable. The
daemon itself does not write these files automatically; the
audit / incident artifacts are produced by the operator following
this runbook.

## Cross-references

- ORIGIN.md — full description
- ARCHITECTURE.md — invariants
- DAEMON.md — on-ramp
- ORIGIN.md § "Problem it solves" — the Azazel-family compromise
  that informed the original spec.
