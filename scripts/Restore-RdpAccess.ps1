<#
.SYNOPSIS
    Restores Remote Desktop access on a Windows device that has been locked out locally.

.DESCRIPTION
    Designed to be uploaded to the Microsoft Defender for Endpoint Live Response library
    and run with the 'run' command against a device you can't reach over RDP.

    The script:
      1. Sets fDenyTSConnections to 0 in the Terminal Server key
      2. Optionally removes fDenyTSConnections from the policy key (-IncludePolicyKey)
      3. Sets TermService to Manual (if Disabled) and starts it
      4. Enables the built-in Remote Desktop firewall rule group
      5. Disables enabled inbound block rules that cover the RDP port
         (or deletes them with -RemoveBlockRules)

    Rules delivered by Group Policy or MDM can't be changed locally and are reported instead.
    The script is idempotent and supports -WhatIf.

    Network isolation still blocks RDP. Release the device from isolation in the
    Defender portal before testing the connection.

.PARAMETER RdpPort
    The RDP port. Defaults to the value in the RDP-Tcp registry key, or 3389.

.PARAMETER BlockRuleNamePattern
    Only act on block rules whose DisplayName matches this wildcard pattern. Default '*'.

.PARAMETER RemoveBlockRules
    Delete matching block rules instead of disabling them.

.PARAMETER IncludePolicyKey
    Also remove fDenyTSConnections from HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services.
    If Group Policy or Intune sets this value it will be reapplied at the next refresh.

.EXAMPLE
    Live Response, preview only:
    run Restore-RdpAccess.ps1 -parameters "-WhatIf"

.EXAMPLE
    Live Response, remediate:
    run Restore-RdpAccess.ps1

.EXAMPLE
    Live Response, delete only the simulation rule:
    run Restore-RdpAccess.ps1 -parameters "-BlockRuleNamePattern 'LAB-Block-RDP*' -RemoveBlockRules"

.NOTES
    Author:  Seán O'Farrell
    Website: https://cloud-secure.ai/
    Series:  Simulating Defender for Endpoint machine isolation and remediation
    Runs as SYSTEM under Live Response (Windows PowerShell 5.1). No interactive prompts.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [int]$RdpPort,
    [string]$BlockRuleNamePattern = '*',
    [switch]$RemoveBlockRules,
    [switch]$IncludePolicyKey
)

$ErrorActionPreference = 'Stop'
$changed = 0
$skipped = 0
$failed  = 0

if (-not $RdpPort) {
    try {
        $RdpPort = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
    }
    catch {
        $RdpPort = 3389
    }
}

Write-Output ("🛠️ Restoring RDP on {0} (port {1}) at {2:u}" -f $env:COMPUTERNAME, $RdpPort, (Get-Date).ToUniversalTime())
if ($WhatIfPreference) { Write-Output 'ℹ️ WhatIf mode - no changes will be made' }

# 1. fDenyTSConnections (local key)
$tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
try {
    $current = (Get-ItemProperty -Path $tsKey -Name fDenyTSConnections).fDenyTSConnections
    if ($current -eq 0) {
        Write-Output '✅ fDenyTSConnections already 0'
        $skipped++
    }
    elseif ($PSCmdlet.ShouldProcess("$tsKey\fDenyTSConnections", 'Set to 0')) {
        Set-ItemProperty -Path $tsKey -Name fDenyTSConnections -Value 0 -Type DWord
        Write-Output '🔧 fDenyTSConnections set to 0'
        $changed++
    }
}
catch {
    Write-Output ("❌ Failed to set fDenyTSConnections: {0}" -f $_.Exception.Message)
    $failed++
}

# 2. fDenyTSConnections (policy key)
$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
try {
    $policyValue = (Get-ItemProperty -Path $policyKey -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    if ($policyValue -eq 1 -and $IncludePolicyKey) {
        if ($PSCmdlet.ShouldProcess("$policyKey\fDenyTSConnections", 'Remove value')) {
            Remove-ItemProperty -Path $policyKey -Name fDenyTSConnections
            Write-Output '🔧 Policy fDenyTSConnections removed (will return if GPO/MDM still sets it)'
            $changed++
        }
    }
    elseif ($policyValue -eq 1) {
        Write-Output '⚠️ Policy key sets fDenyTSConnections = 1. Rerun with -IncludePolicyKey, and fix the GPO/MDM source.'
        $skipped++
    }
}
catch {
    # Value not present - nothing to do
}

# 3. TermService
try {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='TermService'"
    if ($svc.StartMode -eq 'Disabled' -and $PSCmdlet.ShouldProcess('TermService', 'Set start type to Manual')) {
        Set-Service -Name TermService -StartupType Manual
        Write-Output '🔧 TermService start type set to Manual'
        $changed++
    }
    if ($svc.State -ne 'Running') {
        if ($PSCmdlet.ShouldProcess('TermService', 'Start')) {
            Start-Service -Name TermService
            Write-Output '🔧 TermService started'
            $changed++
        }
    }
    else {
        Write-Output '✅ TermService already running'
        $skipped++
    }
}
catch {
    Write-Output ("❌ TermService: {0}" -f $_.Exception.Message)
    $failed++
}

# 4. Built-in Remote Desktop allow rules
try {
    $rdRules = Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction Stop
    $disabled = $rdRules | Where-Object { $_.Enabled -ne 'True' }
    if ($disabled) {
        if ($PSCmdlet.ShouldProcess('Remote Desktop firewall rule group', 'Enable')) {
            $disabled | Enable-NetFirewallRule
            Write-Output ("🔧 Enabled {0} Remote Desktop allow rule(s)" -f @($disabled).Count)
            $changed++
        }
    }
    else {
        Write-Output '✅ Remote Desktop allow rules already enabled'
        $skipped++
    }
}
catch {
    Write-Output ("❌ Remote Desktop rule group: {0}" -f $_.Exception.Message)
    $failed++
}

# 5. Inbound block rules covering the RDP port
try {
    $blockRules = Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like $BlockRuleNamePattern }

    foreach ($rule in $blockRules) {
        $pf = $rule | Get-NetFirewallPortFilter
        $ports = @($pf.LocalPort)
        $coversPort = $ports -contains 'Any' -or $ports -contains [string]$RdpPort -or
            ($ports | Where-Object { $_ -match '-' -and ([int]($_.Split('-')[0]) -le $RdpPort) -and ([int]($_.Split('-')[1]) -ge $RdpPort) })
        if (-not $coversPort -or $pf.Protocol -notin @('TCP', 'Any', '6')) { continue }

        if ($rule.PolicyStoreSourceType -ne 'Local') {
            Write-Output ("⚠️ '{0}' comes from {1} and can't be changed locally - fix it at the source" -f $rule.DisplayName, $rule.PolicyStoreSourceType)
            $skipped++
            continue
        }

        try {
            if ($RemoveBlockRules) {
                if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Remove inbound block rule')) {
                    $rule | Remove-NetFirewallRule
                    Write-Output ("🗑️ Removed block rule '{0}'" -f $rule.DisplayName)
                    $changed++
                }
            }
            elseif ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Disable inbound block rule')) {
                $rule | Disable-NetFirewallRule
                Write-Output ("🔧 Disabled block rule '{0}'" -f $rule.DisplayName)
                $changed++
            }
        }
        catch {
            Write-Output ("❌ '{0}': {1}" -f $rule.DisplayName, $_.Exception.Message)
            $failed++
        }
    }
}
catch {
    Write-Output ("❌ Could not enumerate firewall rules: {0}" -f $_.Exception.Message)
    $failed++
}

Write-Output ''
Write-Output ("📊 Summary: {0} changed, {1} already OK or skipped, {2} failed" -f $changed, $skipped, $failed)
if (-not $WhatIfPreference) {
    Write-Output 'ℹ️ If the device is isolated, release it in the Defender portal before testing RDP.'
}
