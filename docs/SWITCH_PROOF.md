# Switch integration proof

**Status: BLOCKED — live integration not demonstrated.** The Switch source is present as a shallow submodule at `vendor/switch`, revision `4e0711a5928340580c3a66e085ecfa550cdcc2eb` (`switch-agent-controller-v0.31.1-dev.272.g4e0711a`); no Switch Console, messaging platform, or coding agent has been configured or exercised in this setup milestone.

This record is required before IncidentPilot implementation can claim a working Switch integration. It must be updated with observed versions, timestamps, sanitized evidence, and limitations. Do not replace any evidence below with a mock.

## Reproducible setup

From the IncidentPilot project root in Windows PowerShell:

```powershell
git submodule update --init --depth 1 vendor/switch
```

The checked-out Switch README currently directs Windows users to install Switch Console from the latest release installer:

```powershell
$installer = Join-Path $env:TEMP 'switch-console-x64.exe'
Invoke-WebRequest 'https://github.com/sandbox-quantum/switch/releases/latest/download/switch-console-x64.exe' -OutFile $installer
Start-Process -FilePath $installer -Wait
```

Then open Switch Console and follow its setup checklist. Check that Node.js 20+ and the chosen coding-agent CLI are available. Sign the provider in if needed (for Codex, `codex login`), add a local or team Switch server, connect a supported chat platform, register a real coding agent, and create a room. The current published [Switch quickstart](https://docs.switchagents.ai/switch-rooms/getting-started) says a local server runs in Docker and its first start downloads a few GB; it bundles Mattermost. This supersedes the checked-out source guide's claim that Docker is only needed for optional bundled Mattermost.

Use the [Switch getting-started guide](https://docs.switchagents.ai/switch-rooms/getting-started) and the matching local guide in `vendor/switch/docs/official/deploy/messaging-apps/` (for example, `discord.md`). Release URLs and Console steps can change; record the tested Console/server versions below.

## Host preflight (2026-11-03)

This is a preflight record, not a Switch proof run. Docker Desktop and Switch Console were not installed or started.

| Check | Observed result | Requirement / interpretation |
|---|---|---|
| Windows | Windows 10 Pro, version 22H2, build 19045 | Matches Docker's listed Windows 10 edition/build, but standard Windows 10 support ended on 2025-10-14. ESU enrollment was not checked, so current supported-OS status is unverified. |
| Windows 11 upgrade compatibility | Intel Core i3-2120 CPU; 3.9 GB RAM reported | The CPU is absent from Microsoft's supported Windows 11 Intel processor list; Windows 11 also requires 4 GB RAM. This PC is not shown to meet Windows 11 requirements. TPM and Secure Boot status were not checked. |
| CPU virtualization | SLAT reported true; firmware virtualization reported false | Docker's WSL 2 requirements require hardware virtualization enabled in BIOS/UEFI. This prerequisite currently fails. |
| Memory | 3.9 GB reported | Docker Desktop's current Windows requirements specify 8 GB system RAM. This prerequisite currently fails. |
| WSL | `wsl --version` returned inbox-version usage/help instead of version details | Docker documents WSL 2.1.5+ for its WSL 2 backend. Installed WSL version and WSL 2 feature state are not verified. Switch's quickstart says its local server itself does not require WSL, but Docker Desktop's WSL backend does. |
| Disk | C: had 30.9 GB free at the latest read-only check | Docker's Windows requirements page does not specify one fixed free-space minimum. Switch says the first local-server start downloads a few GB. Available space was observed, but future image growth is unknown. |
| Docker | `docker` command not found; no Docker Desktop detected in the checked install paths | Not installed/detected during this preflight. |
| Switch Console installer | A download to `%TEMP%\switch-console-x64.exe` was interrupted; latest read-only check found a 166,576,128-byte file | It was not installed or signature-verified. The incomplete file is not evidence of a working Console. It was left in place. |

Official references checked on this date: [Docker Desktop Windows requirements](https://docs.docker.com/desktop/setup/install/windows-install/), [Microsoft Windows 10 lifecycle](https://learn.microsoft.com/en-us/windows/release-health/release-information), [Microsoft Windows 11 supported Intel processors](https://learn.microsoft.com/en-us/windows-hardware/design/minimum/supported/windows-11-supported-intel-processors), and the [Switch quickstart](https://docs.switchagents.ai/switch-rooms/getting-started).

**Preflight outcome:** Local setup was not attempted. The observed RAM and firmware-virtualization prerequisites fail; the Windows 11 CPU requirement fails; Windows 10 servicing eligibility and WSL state are unverified. No Windows features, BIOS settings, or IncidentPilot application files were changed.

## Remote server availability check (2026-11-03)

Read-only checks on this PC/session found:

- No Switch Console application in the app inventory or installed-app registry entries, and no Switch-named process was running.
- No top-level Switch-named directory under the current user's Roaming or Local application-data directories.
- No environment variable names matching Switch, Gateway, or Agent; no project-root `.env*` file was present.
- No Switch connector/tool is available in this Codex session.
- No Gateway URL, API URL, or remote-server account is recorded in this proof document.

**Result:** No authorized remote Switch server is discoverable from this PC/session, so the existing-server connection workflow was not started. This does not establish whether an organization-managed server exists elsewhere. No network connection to a candidate server was attempted, and no credentials were requested or exposed.

## External requirements to unblock

All of the following must be available before the live Switch acceptance criteria can be attempted:

1. **Authorized Switch server URL and access:** Gateway URL, API URL, and a provisioned account. Authentication must happen through the approved Switch Console sign-in flow; do not place credentials in this document.
2. **Supported team-chat connection:** A supported chat service connected to that Switch server, with the human tester's account linked and access to a real room.
3. **Real coding-agent provider authentication:** A supported coding-agent CLI/provider authenticated on the host that will run Switch Console, with permission to perform the agreed repository task.
4. **Switch Console on a suitable host:** Console installed and able to connect to the authorized existing server. Local Docker setup on the currently checked PC remains blocked by the recorded host prerequisites.

## Required proof run

| Check | Evidence to capture | Result |
|---|---|---|
| Switch Console starts | Console version and sanitized startup screenshot/log | BLOCKED — Console/server access unavailable; not run |
| Supported team chat is connected | Platform name and sanitized connection view | BLOCKED — no authorized server/chat connection discoverable; not run |
| Human sends a real room message | Timestamped room screenshot | BLOCKED — no room available; not run |
| Real coding agent receives it and replies through Switch | Agent identity, correlation/message IDs, room screenshot | BLOCKED — provider is not connected through Switch; not run |
| Agent performs a repository task | Repository commit, requested task, resulting diff, and tool transcript | BLOCKED — live Switch path unavailable; not run |
| Human sees the full conversation | Room screenshot showing both sides | BLOCKED — no real conversation to capture; not run |

## Evidence record

- IncidentPilot commit: pending
- Switch submodule revision: pending capture during proof run
- Switch Console version: not installed
- Server version: not started
- Team chat: not connected
- Agent provider and identity: not connected
- Run timestamp: not run
- Evidence directory: `docs/evidence/switch/` (create when the proof run begins)

## Current limitations

- Only the Switch source checkout has been verified. Runtime startup and end-to-end collaboration have not been demonstrated.
- Local Switch setup is blocked on this host pending a machine that meets Docker's current requirements (or an authorized, supported team-server setup). The preflight above does not establish a live Switch integration.
- No local Switch Console configuration with a server, team-chat identity, or agent provider was discoverable. A separate Codex CLI login does not establish a Switch connection. Do not record a pass until a human can observe the real conversation and repository task.
- Do not publish screenshots containing credentials, private room content, or personal data.
