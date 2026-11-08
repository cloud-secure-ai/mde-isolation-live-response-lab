<#
.SYNOPSIS
    LAB ONLY - generates benign Microsoft Defender for Endpoint detections to
    drive the machine isolation and Live Response walkthrough.

.DESCRIPTION
    This runs no real attack tooling and steals no credentials. It produces two
    safe, well-known test detections that Defender for Endpoint reports as an
    alert and incident:

      1. The EICAR anti-malware test file - the standard string every AV engine
         recognises as a test. Writing it triggers a Defender Antivirus detection.
      2. Microsoft's documented endpoint detection test - a benign PowerShell
         command that simulates a download-and-execute pattern and raises an EDR
         alert on the device (appears in the portal in about 10 minutes).

    Run from an elevated PowerShell session on the lab VM.

.NOTES
    Author:  Seán O'Farrell
    Website: https://cloud-secure.ai/
    Series:  Simulating Defender for Endpoint machine isolation and remediation
    Lab use only. Never run on a production device.
#>
[CmdletBinding()]
param(
    [string]$SimPath = 'C:\sim'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $SimPath)) { New-Item -Path $SimPath -ItemType Directory | Out-Null }

Write-Output "🧪 Lab detection test starting on $env:COMPUTERNAME"

# 1. EICAR test file - assembled at runtime so the script itself is not quarantined
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!' + '$H+H*'
$eicarFile = Join-Path $SimPath 'eicar-test.com'
try {
    Set-Content -Path $eicarFile -Value $eicar -Encoding Ascii
    Write-Output "📝 Wrote EICAR test file to $eicarFile - Defender should quarantine it"
}
catch {
    Write-Output "🛡️ Defender blocked the EICAR write (this is the expected result): $($_.Exception.Message)"
}

# 2. Microsoft documented endpoint detection test (benign, from learn.microsoft.com)
Write-Output '🧪 Running the Microsoft endpoint detection test'
$inner = "`$ErrorActionPreference='SilentlyContinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe','C:\test-MDATP-test\invoice.exe');Start-Process 'C:\test-MDATP-test\invoice.exe'"
Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-Command', $inner

Write-Output '✅ Triggers sent. Watch the Defender portal for the device alert and incident (EDR alert can take ~10 minutes).'
