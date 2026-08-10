# tmp-dotdir-watcher (proposed daemon)

**Priority:** 🔴 high (would have detected the 2026-08-09 Azazel compromise 71 hours earlier than operator-flagged 502 detection)
**Target host:** tmp-vps (46.36.219.176)
**Period:** every 10 minutes (timer)
**Would prevent:** Hidden Azazel-style malware footprints under `/tmp/.dotdir/` (`.r.rpk/`, `.xdiag/`, `.perf.c/`, `.apid/`, `.atmp/`)

## Problem it solves

The 2026-08-09 Azazel compromise on `elrise-backend` lived for 72 hours undetected despite extensive monitoring (Prometheus, Uptime Kuma, journald shipping to Loki). The malware's 5 components (per `notes/2026-08-09-elrise-compromise-malware-analysis.md` §3) all lived under `/tmp/.dotdir/` paths:

- `/tmp/.r.rpk/` — chroot jail skeleton (88 KB, 20 entries)
- `/tmp/.xdiag/` — Azazel control directory (37 MB with Tor data)
- `/tmp/.perf.c/` — the 3 rogue binaries (17 MB)
- `/tmp/.apid` — runtime marker (4 bytes)
- `/home/www-data/.atmp/tmp/.applocal.xdiag/` — the actual payload (12 KB)

`tmp-prune` cron doesn't run on tmp-vps (alpine image — wait, Debian 12 here; the host's `systemd-tmpfiles-clean.timer` runs but doesn't delete dot-directories). `du /tmp` wasn't monitored. `/tmp/.r.rpk/` is 88 KB total — well within the noise of a 600 MB `/tmp/`.

The malware analysis §8 lesson-learned explicitly states: *"A simple `find /tmp -maxdepth 1 -name '.*' -type d -newer ...` cron would have caught `.r.rpk/`, `.xdiag/`, `.perf.c/` on day 1"*.

This daemon implements exactly that cron, plus SHA-256 IOC matching against the known-bad hashes from the forensic archive.

## What it does

Every 10 min:

1. **Scan host `/tmp`, `/home`, `/var/tmp`** for dot-directories created in the last 24 hours:
   ```bash
   find /tmp /home /var/tmp -maxdepth 3 -type d -name '.*' -mmin -1440 2>/dev/null
   ```
   The `/home` arm catches `/home/<user>/.atmp/...` patterns (Azazel's secondary footprint). The `/var/tmp` arm catches similar attacks that bypass `/tmp` cleanup.

2. **SHA-256 match against IOC list** at `/etc/tmp-watcher.iocs`. Each candidate dotdir is hashed recursively (max 10 files, abort with `WARNING: too-many-files` if larger) and matched. Any match → CRITICAL alert + auto-quarantine (`chmod 000 <path>` to make it inaccessible without removing evidence).

3. **Allowlist filter** at `/etc/tmp-watcher.allowlist` — directories matching these globs are skipped (FastPanel2's `.font-unix`, `.ICE-unix`, `.X11-unix`, systemd-private-*, etc.). Without the allowlist, every poll would generate noise from legitimate X11/systemd-private entries.

4. **Unknown dotdir → WARNING alert**: any dotdir not in the allowlist and not in the IOC list fires a WARNING (still logged for forensics). The operator can later add new patterns to the allowlist as false-positive noise is identified.

5. **IOC-list refresh** (optional, daily): re-reads `/etc/tmp-watcher.iocs` from the canonical forensic archive path (if mounted read-only at `/opt/forensics/2026-08-09-elrise-compromise.tar.gz`); updates the local `/etc/tmp-watcher.iocs` so new IOCs from operator research auto-propagate.

## Configuration

```toml
# /etc/tmp-watcher.conf
[paths]
scan_roots = ["/tmp", "/home", "/var/tmp"]
scan_maxdepth = 3
scan_window_minutes = 1440        # last 24h

[ioc]
ioc_list = "/etc/tmp-watcher.iocs"
ioc_archive_ref = "/opt/forensics/2026-08-09-elrise-compromise.tar.gz"

[allowlist]
allowlist = "/etc/tmp-watcher.allowlist"
max_files_per_dir = 10

[actions]
quarantine_on_ioc_match = true    # chmod 000 the matched directory
alert_on_unknown = true           # WARNING for non-allowlist dotdirs

[output]
journal_tag = "tmp-watcher"
ntfy_url = "${NTFY_URL}"          # https://ntfy.sh/<topic> or empty
log_file = "/var/log/tmp-watcher.log"
```

### Default `/etc/tmp-watcher.allowlist` contents

```
# FastPanel2 X11 / systemd-private entries (legitimate)
.font-unix
.ICE-unix
.X11-unix
.XIM-unix
.Test-unix
systemd-private-*
```

### Default `/etc/tmp-watcher.iocs` contents

```
# Azazel trunk binary (from notes/2026-08-09-elrise-compromise-malware-analysis.md §3)
b02ad43cfa407a01c376c7a904104b03  trunk.md5
db338d19241c95d42c4da2888ade4d8bc6286e3b5689e3746771918c6c3b1b8c  trunk.sha256
```

## Outputs

- `journalctl -t tmp-watcher` — structured events
- `journalctl -t tmp-watcher PRIORITY=4` — WARNING-level (unknown dotdir)
- `journalctl -t tmp-watcher PRIORITY=2` — CRITICAL-level (IOC match + quarantine)
- NTFY push (if configured) — operator phone alert on CRITICAL
- `/var/log/tmp-watcher.log` — full event log with timestamps
- `/run/tmp-watcher/` — state directory (cooldowns, last-seen paths, last-known-good manifest)

## Auto-fix actions

The daemon auto-quarantines IOC-matched directories (`chmod 000 <path>` — makes them inaccessible without removing them). Why not auto-`rm -rf`:
- Forensic value: future investigation may need the originals
- Reversibility: chmod is trivially reversible (`chmod 700` to re-enable)
- Safety: `rm -rf` on a path that the malware controls is risky (Azazel could symlink-races the rm)

The daemon does NOT auto-add new directories to the allowlist. Unknown dotdirs are flagged as WARNING so the operator can decide.

## Implementation

- Single bash script (~80 lines) at `/usr/local/bin/tmp-watcher`
- 2 config files (`/etc/tmp-watcher.conf`, `/etc/tmp-watcher.allowlist`, `/etc/tmp-watcher.iocs`)
- systemd service + timer (oneshot, 10-minute polling)
- `/run/tmp-watcher/` runtime state directory
- `/var/log/tmp-watcher.log` log file
- No Python dependency (uses `find`, `sha256sum`, `curl`, `systemd-cat`)

## Effort estimate

- Build: 1-2 hours (bash + systemd)
- Test: 30 minutes (drop a fake `.test-azazel-pattern/trunk.b02ad43cfa407a01c376c7a904104b03` file, verify quarantine + alert)
- Deploy: 5 minutes (drop in `/usr/local/bin/`, enable timer)
- Total: ~3 hours

## Outstanding issues

- **Performance on large `/home`**: if the operator's `/home/<user>/` is large (e.g., user has 50 GB of files), the find/sha256sum cycle could be slow. Mitigation: `find -maxdepth 3` limits the scope; `max_files_per_dir=10` caps the sha256sum cost per candidate.
- **Cross-host IOC sync**: each host gets its own `/etc/tmp-watcher.iocs`. If the operator finds new IOCs after investigating another host, they need to manually distribute. Future enhancement: shared IOC list on iton-nest synced via cron.
- **Encrypted droppers**: SHA-256 matching only catches known hashes. A new Azazel variant would not match. Mitigation: this daemon catches the FOOTPRINT, not the BINARY itself — even a new variant creates the same `.r.rpk/`/`.xdiag/`/`/home/<user>/.atmp/` patterns that an allowlist-mismatch would flag as WARNING.
