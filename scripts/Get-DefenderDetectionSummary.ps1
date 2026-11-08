<#
.SYNOPSIS
    Summarises recent Microsoft Defender Antivirus detections on a device. Read-only.

.DESCRIPTION
    Designed to be uploaded to the Microsoft Defender for Endpoint Live Response library
    and run with the 'run' command during triage, including on an isolated device.

    Reports:
      - Defender service and engine state, including tamper protection
      - Detections from the last N days (threat, resource path, action, user, process)

.PARAMETER Days
    How many days of detections to show. Default 7.

.EXAMPLE
    Live Response:
    run Get-DefenderDetectionSummary.ps1

.EXAMPLE
    Live Response, last 2 days:
    run Get-DefenderDetectionSummary.ps1 -parameters "-Days 2"

.NOTES
    Author:  Seán O'Farrell
    Website: https://cloud-secure.ai/
    Series:  Simulating Defender for Endpoint machine isolation and remediation
    Runs as SYSTEM under Live Response (Windows PowerShell 5.1). No interactive prompts.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$Days = 7
)

$ErrorActionPreference = 'Stop'

Write-Output ("🔎 Defender detection summary for {0}, last {1} day(s)" -f $env:COMPUTERNAME, $Days)

try {
    $status = Get-MpComputerStatus
    Write-Output ''
    Write-Output '=== Defender status ==='
    Write-Output ("ℹ️ AM running mode:        {0}" -f $status.AMRunningMode)
    Write-Output ("ℹ️ Real-time protection:   {0}" -f $status.RealTimeProtectionEnabled)
    Write-Output ("ℹ️ Behaviour monitoring:   {0}" -f $status.BehaviorMonitorEnabled)
    Write-Output ("ℹ️ Tamper protection:      {0} ({1})" -f $status.IsTamperProtected, $status.TamperProtectionSource)
    Write-Output ("ℹ️ Signature version:      {0} ({1:u})" -f $status.AntivirusSignatureVersion, $status.AntivirusSignatureLastUpdated)
}
catch {
    Write-Output ("⚠️ Could not read Defender status: {0}" -f $_.Exception.Message)
}

try {
    $since = (Get-Date).AddDays(-$Days)
    $threats = @{}
    Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $threats[$_.ThreatID] = $_.ThreatName }

    $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { $_.InitialDetectionTime -ge $since } |
        Sort-Object InitialDetectionTime -Descending)

    Write-Output ''
    Write-Output '=== Detections ==='
    if ($detections.Count -eq 0) {
        Write-Output '✅ No detections in the selected period'
    }
    foreach ($d in $detections) {
        $name = if ($threats.ContainsKey($d.ThreatID)) { $threats[$d.ThreatID] } else { "ThreatID $($d.ThreatID)" }
        Write-Output ("🦠 {0:u}  {1}" -f $d.InitialDetectionTime.ToUniversalTime(), $name)
        Write-Output ("    Action success: {0}  User: {1}  Process: {2}" -f $d.ActionSuccess, $d.DomainUser, $d.ProcessName)
        foreach ($r in @($d.Resources)) { Write-Output ("    Resource: {0}" -f $r) }
    }
    Write-Output ''
    Write-Output ("📊 {0} detection(s)" -f $detections.Count)
}
catch {
    Write-Output ("❌ Could not read detections: {0}" -f $_.Exception.Message)
}
