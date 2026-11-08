# MDE Isolation and Live Response Lab

KQL queries and PowerShell scripts that go with the cloud-secure.ai blog series on simulating Microsoft Defender for Endpoint machine isolation and remediation.

The lab uses an Azure-hosted Windows 11 VM onboarded to Defender for Endpoint. It covers:

1. Lab setup - onboarding, Optional features (Live Response, tamper protection, isolation exclusion rules) and RBAC
2. Simulating a credential theft attack (Mimikatz) and investigating the incident
3. Isolating the device and remediating it through Live Response
4. Recovering a device locked out of RDP by firewall rules and registry changes, using Live Response

> **Lab use only.** The simulation script deliberately locks a device out of Remote Desktop. Never run it on a production device.

## Requirements

- Microsoft Defender for Endpoint Plan 2 (or Microsoft 365 E5)
- Windows 11 (or Windows 10 1709+) onboarded to Defender for Endpoint
- **Live Response** turned on in Settings > Endpoints > Optional features
- An RBAC role with advanced Live Response permissions to use `run`, `putfile` and `remediate`
- Signed scripts, or **Live Response unsigned script execution** turned on (signing is recommended)

## Scripts

Upload these to the Live Response library (Settings > Endpoints > Library management, or `library` in a session) and run them with `run`.

| Script | Purpose | Changes the device? |
|---|---|---|
| [`Get-RdpLockoutState.ps1`](scripts/Get-RdpLockoutState.ps1) | Reports registry, service, firewall and listener state that blocks RDP | No |
| [`Restore-RdpAccess.ps1`](scripts/Restore-RdpAccess.ps1) | Restores RDP: fDenyTSConnections, TermService, firewall rules. Supports `-WhatIf` | Yes |
| [`Get-DefenderDetectionSummary.ps1`](scripts/Get-DefenderDetectionSummary.ps1) | Defender status (incl. tamper protection) and recent detections | No |
| [`Invoke-RdpLockoutSimulation.ps1`](scripts/Invoke-RdpLockoutSimulation.ps1) | **Lab only.** Locks the device out of RDP. Run locally, not through Live Response | Yes |

Examples in a Live Response session:

```
run Get-RdpLockoutState.ps1
run Restore-RdpAccess.ps1 -parameters "-WhatIf"
run Restore-RdpAccess.ps1 -parameters "-BlockRuleNamePattern 'LAB-Block-RDP*' -RemoveBlockRules"
run Get-DefenderDetectionSummary.ps1 -parameters "-Days 2"
```

Live Response runs scripts as SYSTEM in Windows PowerShell 5.1, with a 30-minute timeout on `run`. The scripts don't prompt for input.

## KQL

Run these in Advanced hunting. Each query has a `DeviceNameFilter` variable at the top. Set it to your test device, or leave it empty to search all devices.

| Query | What it shows |
|---|---|
| [`01-Mimikatz-Alerts-And-Evidence.kql`](kql/01-Mimikatz-Alerts-And-Evidence.kql) | Alerts and evidence raised by the simulation |
| [`02-Antivirus-Detections.kql`](kql/02-Antivirus-Detections.kql) | Defender Antivirus detections and whether they were remediated |
| [`03-Credential-Theft-Commands.kql`](kql/03-Credential-Theft-Commands.kql) | Mimikatz-style command lines and LSASS access or ASR events |
| [`04-RDP-Lockout-Changes.kql`](kql/04-RDP-Lockout-Changes.kql) | fDenyTSConnections, firewall rule and firewall profile changes |
| [`05-RDP-Connections-And-Blocks.kql`](kql/05-RDP-Connections-And-Blocks.kql) | RDP connections accepted, blocked and logged on |
| [`06-Live-Response-Activity.kql`](kql/06-Live-Response-Activity.kql) | Processes started by the Defender response components (Live Response scripts) |

## Author

Seán O'Farrell - [cloud-secure.ai](https://cloud-secure.ai/)

Provided as-is, without warranty. Test in a lab before using in production.
