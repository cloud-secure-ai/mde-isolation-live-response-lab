<#
.SYNOPSIS
    LAB ONLY - locks a Windows device out of Remote Desktop to simulate a misconfiguration
    or attacker action, so it can be recovered through Defender for Endpoint Live Response.

.DESCRIPTION
    Makes three local changes:
      1. Turns on Windows Firewall for all profiles
      2. Adds an inbound block rule for the RDP port (DisplayName 'LAB-Block-RDP-Inbound')
      3. Sets fDenyTSConnections to 1 (Remote Desktop disabled)

    Running this from an RDP session will disconnect you, and you won't be able to reconnect.
    Make sure the device is onboarded to Defender for Endpoint, shows as Active in the
    Defender portal, and Live Response is enabled BEFORE running it.

    Recover with Restore-RdpAccess.ps1 via Live Response.

.PARAMETER RdpPort
    The RDP port. Defaults to the value in the RDP-Tcp registry key, or 3389.

.PARAMETER IUnderstandThisLocksMeOut
    Required. The script does nothing without it.

.EXAMPLE
    .\Invoke-RdpLockoutSimulation.ps1 -IUnderstandThisLocksMeOut -WhatIf

.EXAMPLE
    .\Invoke-RdpLockoutSimulation.ps1 -IUnderstandThisLocksMeOut

.NOTES
    Author:  Seán O'Farrell
    Website: https://cloud-secure.ai/
    Series:  Simulating Defender for Endpoint machine isolation and remediation
    Never run this on a production device.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [int]$RdpPort,
    [switch]$IUnderstandThisLocksMeOut
)

$ErrorActionPreference = 'Stop'
$ruleName = 'LAB-Block-RDP-Inbound'
$changed = 0

if (-not $IUnderstandThisLocksMeOut) {
    Write-Output '⛔ Refusing to run. Add -IUnderstandThisLocksMeOut to confirm this is a lab device.'
    return
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output '⛔ Run this from an elevated PowerShell session.'
    return
}

if (-not $RdpPort) {
    try {
        $RdpPort = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
    }
    catch {
        $RdpPort = 3389
    }
}

Write-Output ("🧪 RDP lockout simulation on {0} (port {1})" -f $env:COMPUTERNAME, $RdpPort)

try {
    # 1. Firewall on for all profiles
    $off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
    if ($off -and $PSCmdlet.ShouldProcess('All firewall profiles', 'Enable')) {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
        Write-Output '🔥 Windows Firewall enabled on all profiles'
        $changed++
    }

    # 2. Block rule
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Write-Output ("✅ '{0}' already exists" -f $ruleName)
    }
    elseif ($PSCmdlet.ShouldProcess($ruleName, "Create inbound block rule for TCP $RdpPort")) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $RdpPort -Action Block -Profile Any -Description 'cloud-secure.ai lab - RDP lockout simulation' | Out-Null
        Write-Output ("🚫 Created '{0}' blocking TCP {1}" -f $ruleName, $RdpPort)
        $changed++
    }

    # 3. Disable Remote Desktop (last, because it can end the current session)
    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-ItemProperty -Path $tsKey -Name fDenyTSConnections).fDenyTSConnections -eq 1) {
        Write-Output '✅ fDenyTSConnections already 1'
    }
    elseif ($PSCmdlet.ShouldProcess("$tsKey\fDenyTSConnections", 'Set to 1')) {
        $changed++
        Write-Output ("📊 {0} change(s) made. Setting fDenyTSConnections = 1 - your RDP session may drop now." -f $changed)
        Set-ItemProperty -Path $tsKey -Name fDenyTSConnections -Value 1 -Type DWord
    }
}
catch {
    Write-Output ("❌ {0}" -f $_.Exception.Message)
}
