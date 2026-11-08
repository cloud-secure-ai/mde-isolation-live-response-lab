<#
.SYNOPSIS
    Reports why Remote Desktop might be unreachable on a Windows device. Read-only.

.DESCRIPTION
    Designed to be uploaded to the Microsoft Defender for Endpoint Live Response library
    and run with the 'run' command against a device you can't reach over RDP.

    The script changes nothing. It reports:
      - The fDenyTSConnections value (Terminal Server and policy keys)
      - Remote Desktop Services (TermService) status and start type
      - Windows Firewall profile state and default inbound action
      - Enabled inbound firewall rules that block the RDP port
      - The state of the built-in Remote Desktop firewall rule group
      - Whether anything is listening on the RDP port

.PARAMETER RdpPort
    The RDP port to check. Defaults to the value in the RDP-Tcp registry key, or 3389.

.EXAMPLE
    Live Response:
    run Get-RdpLockoutState.ps1

.EXAMPLE
    Live Response, custom port:
    run Get-RdpLockoutState.ps1 -parameters "-RdpPort 3390"

.NOTES
    Author:  Seán O'Farrell
    Website: https://cloud-secure.ai/
    Series:  Simulating Defender for Endpoint machine isolation and remediation
    Runs as SYSTEM under Live Response (Windows PowerShell 5.1). No interactive prompts.
#>
[CmdletBinding()]
param(
    [int]$RdpPort
)

$ErrorActionPreference = 'Stop'
$findings = 0

function Write-Section([string]$Title) {
    Write-Output ''
    Write-Output ("=== {0} ===" -f $Title)
}

# Resolve the RDP port if not supplied
if (-not $RdpPort) {
    try {
        $RdpPort = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
    }
    catch {
        $RdpPort = 3389
    }
}

Write-Output ("🔎 RDP lockout check on {0} (port {1}) at {2:u}" -f $env:COMPUTERNAME, $RdpPort, (Get-Date).ToUniversalTime())

# 1. fDenyTSConnections
Write-Section 'Remote Desktop registry settings'
$denyKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
)
foreach ($key in $denyKeys) {
    try {
        $value = (Get-ItemProperty -Path $key -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
        if ($value -eq 1) {
            Write-Output ("❌ {0}\fDenyTSConnections = 1 (RDP denied)" -f $key)
            $findings++
        }
        else {
            Write-Output ("✅ {0}\fDenyTSConnections = {1}" -f $key, $value)
        }
    }
    catch {
        Write-Output ("ℹ️ {0}\fDenyTSConnections not set" -f $key)
    }
}

# 2. TermService
Write-Section 'Remote Desktop Services'
try {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService'"
    $icon = if ($svc.State -eq 'Running') { '✅' } else { $findings++; '❌' }
    Write-Output ("{0} TermService state: {1}, start mode: {2}" -f $icon, $svc.State, $svc.StartMode)
}
catch {
    Write-Output ("⚠️ Could not query TermService: {0}" -f $_.Exception.Message)
}

# 3. Firewall profiles
Write-Section 'Windows Firewall profiles'
try {
    Get-NetFirewallProfile | ForEach-Object {
        Write-Output ("ℹ️ {0}: Enabled={1}, DefaultInboundAction={2}, AllowLocalFirewallRules={3}" -f $_.Name, $_.Enabled, $_.DefaultInboundAction, $_.AllowLocalFirewallRules)
    }
}
catch {
    Write-Output ("⚠️ Could not query firewall profiles: {0}" -f $_.Exception.Message)
}

# 4. Inbound block rules covering the RDP port
Write-Section 'Inbound block rules affecting the RDP port'
try {
    $blockRules = Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue
    $hits = foreach ($rule in $blockRules) {
        $pf = $rule | Get-NetFirewallPortFilter
        $ports = @($pf.LocalPort)
        if ($ports -contains 'Any' -or $ports -contains [string]$RdpPort -or ($ports | Where-Object { $_ -match '-' -and ([int]($_.Split('-')[0]) -le $RdpPort) -and ([int]($_.Split('-')[1]) -ge $RdpPort) })) {
            if ($pf.Protocol -in @('TCP', 'Any', '6')) {
                [pscustomobject]@{
                    Name        = $rule.Name
                    DisplayName = $rule.DisplayName
                    Profile     = $rule.Profile
                    LocalPort   = ($ports -join ',')
                    Store       = $rule.PolicyStoreSourceType
                }
            }
        }
    }
    if ($hits) {
        foreach ($h in $hits) {
            Write-Output ("❌ Block rule: '{0}' (Name: {1}, Profile: {2}, Ports: {3}, Source: {4})" -f $h.DisplayName, $h.Name, $h.Profile, $h.LocalPort, $h.Store)
            $findings++
        }
    }
    else {
        Write-Output '✅ No enabled inbound block rules cover the RDP port'
    }
}
catch {
    Write-Output ("⚠️ Could not enumerate firewall rules: {0}" -f $_.Exception.Message)
}

# 5. Built-in Remote Desktop allow rules
Write-Section 'Built-in Remote Desktop allow rules'
try {
    $rdRules = Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue
    if ($rdRules) {
        foreach ($r in $rdRules) {
            $icon = if ($r.Enabled -eq 'True') { '✅' } else { '⚠️' }
            Write-Output ("{0} {1} Enabled={2} Action={3}" -f $icon, $r.DisplayName, $r.Enabled, $r.Action)
        }
    }
    else {
        Write-Output '⚠️ Remote Desktop rule group not found'
    }
}
catch {
    Write-Output ("⚠️ Could not query the Remote Desktop rule group: {0}" -f $_.Exception.Message)
}

# 6. Listener
Write-Section 'Listener'
try {
    $listener = Get-NetTCPConnection -LocalPort $RdpPort -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
        Write-Output ("✅ Listening on TCP {0}" -f $RdpPort)
    }
    else {
        Write-Output ("❌ Nothing listening on TCP {0}" -f $RdpPort)
        $findings++
    }
}
catch {
    Write-Output ("⚠️ Could not query listeners: {0}" -f $_.Exception.Message)
}

Write-Section 'Summary'
if ($findings -eq 0) {
    Write-Output '✅ No local RDP blockers found. Check network isolation, NSG rules and the client side.'
}
else {
    Write-Output ("❌ {0} local RDP blocker(s) found. Run Restore-RdpAccess.ps1 to remediate." -f $findings)
}
