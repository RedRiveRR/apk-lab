# win-lab

A reproducible Windows VM on Ubuntu Server, built on `dockur/windows`: one
compose service running QEMU+KVM with a noVNC web viewer and RDP, backed by a
persistent disk in `storage/`.

See [[win-lab]], the service in [[win-lab/docker-compose.yml]] and the runbook
[[win-lab/README.md]].

## Service and endpoints

The `windows` service (container `win-lab`) serves the web viewer on `WEB_PORT`
(8006) and RDP on `RDP_PORT` (3389, tcp+udp).

It requires `/dev/kvm` and `/dev/net/tun` and `NET_ADMIN`. Host paths `storage/`,
`shared/` (guest drive Z:) and `oem/` (C:\OEM automation) are bind-mounted.
Configuration is environment-driven via [[win-lab/.env.example]].

## Lifecycle and readiness

`make boot` starts the VM and waits for the web viewer; `make wait-install`
blocks on the `storage/windows.boot` marker that signals the install finished.

Targets are in [[win-lab/Makefile]], readiness logic in
[[win-lab/scripts/wait-ready.sh]], host checks in [[win-lab/scripts/preflight.sh]].
The three readiness stages are container `Up`, web viewer HTTP 200 (visible
during install too), and the `windows.boot` marker (install complete).

## State, backup and reset

All guest state is in `storage/`; configuration is `.env` plus compose.

[[win-lab/scripts/backup.sh]] takes a cold, crash-consistent archive (unless
`--live`); [[win-lab/scripts/restore.sh]] moves the current `storage/` aside
before extracting, so restores are reversible. `make reset CONFIRM=yes` destroys
the disk and reinstalls on next boot.

## Windows Apps Lab

On a real Windows host, the dashboard can open the separate `winapps` lab. It
serves a read-only desktop mirror through [[console/winapps.py]] with ctypes
window enumeration and a `PrintWindow` capture; no process control is offered.
This is separate from the Windows VM lifecycle and public Pages never mounts it.

A window is listed only when it is actually on screen: visible, captioned,
not minimized, not a tool or shell window and not DWM-cloaked (suspended UWP
frames stay "visible" to Win32 but cannot be seen). Each entry carries
`elevated` (true, false, or null when Windows will not say) so an elevated
window a standard-user console cannot capture is marked rather than hidden.
`GET /api/labs/winapps/doctor` and `python console/winapps.py --doctor` report
the desktop session, this console's own elevation and one live capture probe.

### Agent safety gate

Everything the web endpoints and the MCP server show of this lab passes through
[[console/winapps_guard.py]], which reads the policy file `win-lab/winapps-policy.json`
(or `OSLAB_WINAPPS_POLICY`). An agent sees only windows of apps on `allowedApps`; an
empty, missing or broken policy means it sees nothing and reports `policyError`.
Windows that look sensitive (built-in password managers, private or incognito
browsing, online-banking title hints, plus anything the policy adds) are never
captured for anyone and are marked restricted in the panel. Restricted beats the
allowlist, and the built-in restrictions cannot be removed. A capture is checked
before and after the pixels are taken, because a title can change meanwhile.

Every agent call and every refusal is audited without titles or images, in memory
and in a daily JSONL file; identical rows within a minute are counted, not repeated.
The MCP server adds read-only `winapps_*` tools on Windows and no arm or input tool.

Honest limits: the filter reads process names and titles only, so it is a
heuristic. The allowlist binds the MCP path; the local HTTP address serves the
human panel, so an agent that can run commands on this machine can still request
unrestricted windows there. It guards against agent mistakes, not a hostile local
user; a secret the agent does not hold on that address is a later phase.

## Research

Windows-lab research and the command reference.

They live in [[win-lab/knowledge]] and [[win-lab/dockur-windows-cheat-sheet.md]].
Cross-lab operation is via [[labctl]] (`./labctl win ...`).
