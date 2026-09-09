
######################## SYSTEM & PATCH POSTURE ########################

# Detect elevation once, up front. Several checks below (audit policy, secedit
# baseline, bcdedit boot config, Security event log, BitLocker, WMI
# subscriptions, NetworkList history, IIS config) require administrator. This
# makes that explicit rather than silently reporting a false "OK".
$script:IsElevated = $false
try {
  $script:IsElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
$script:ElevGated = 'audit policy, secedit password/lockout baseline, bcdedit test-signing/code-integrity, Security event-log size, BitLocker status, WMI permanent-subscription enumeration, NetworkList connectivity history, IIS applicationHost deep config, and other users'' RDP/process history'
Write-Host ''
if ($script:IsElevated) {
  Write-Host '[+] Running ELEVATED - full check coverage.' -ForegroundColor Green
}
else {
  Write-Host '[!] Running NON-ELEVATED - some checks are limited or skipped.' -ForegroundColor Yellow
  Write-Host ('    Elevation-gated: ' + $script:ElevGated) -ForegroundColor DarkYellow
  Write-Host '    Re-run from an elevated prompt for a complete audit.' -ForegroundColor DarkYellow
}
Add-Finding -Severity $(if ($script:IsElevated) { 'Info' } else { 'Low' }) -Category 'Scan' `
  -Title $(if ($script:IsElevated) { 'Scan ran elevated (full coverage)' } else { 'Scan ran NON-elevated (partial coverage)' }) `
  -Detail $(if ($script:IsElevated) { 'Administrator context - all checks attempted.' } else { 'Standard-user context. These checks were limited or skipped: ' + $script:ElevGated + '.' }) `
  -Remediation $(if ($script:IsElevated) { 'None.' } else { 'Re-run from an elevated PowerShell prompt for complete, trustworthy results.' })

Start-Section 'SYSTEM INFORMATION'
$os = Get-CimInstance Win32_OperatingSystem
Add-Finding -Severity Info -Category 'System' -Title 'OS baseline' `
  -Detail ("{0} (build {1}) | installed {2:yyyy-MM-dd} | last boot {3:yyyy-MM-dd HH:mm} | {4} GB RAM" -f `
    $os.Caption, $os.BuildNumber, $os.InstallDate, $os.LastBootUpTime, [math]::Round($os.TotalVisibleMemorySize/1MB,1))

# Patch recency (defenders care about exposure window, not KB-by-KB exploit mapping)
$latestHF = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
if ($latestHF -and $latestHF.InstalledOn) {
  $age = (Get-Date) - $latestHF.InstalledOn
  if ($age.Days -gt 60) {
    Add-Finding -Severity High -Category 'Patching' -Title 'No patches installed in over 60 days' `
      -Detail ("Most recent hotfix {0} installed {1:yyyy-MM-dd} ({2} days ago)." -f $latestHF.HotFixID, $latestHF.InstalledOn, $age.Days) `
      -Remediation 'Patch cadence is stale; inventory missing CVEs and expedite critical/security updates.'
  }
  else {
    Add-Finding -Severity Info -Category 'Patching' -Title 'Patch cadence OK' `
      -Detail ("Most recent hotfix {0} {1} days ago." -f $latestHF.HotFixID, $age.Days)
  }
}

# Reboot-pending (patch effectiveness)
try {
  $pendingReboot = $false
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReboot = $true }
  $fro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
  if ($fro.PendingFileRenameOperations) { $pendingReboot = $true }
  if ($pendingReboot) {
    Add-Finding -Severity Medium -Category 'Patching' -Title 'Reboot pending' `
      -Detail 'Updates staged but not finalized until reboot - host may still be vulnerable to patched CVEs.' `
      -Remediation 'Schedule reboot maintenance window.'
  }
} catch { }

######################## DEFENDER / AV POSTURE (NEW) ########################

Start-Section 'DEFENDER / AV POSTURE'
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  if ($mp.AMServiceEnabled) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender realtime protection ON' -Detail ("Engine {0}, signatures {1:yyyy-MM-dd HH:mm}" -f $mp.AMEngineVersion, $mp.AntivirusSignatureLastUpdated)
  }
  else {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender realtime protection OFF' `
      -Remediation 'Re-enable realtime protection; investigate why it was disabled (often attacker first action).'
  }
  if ($mp.AntivirusSignatureLastUpdated -and ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days -gt 3) {
    Add-Finding -Severity High -Category 'AV' -Title 'AV signatures stale' `
      -Detail ("Last updated {0:yyyy-MM-dd}" -f $mp.AntivirusSignatureLastUpdated) `
      -Remediation 'Force signature update; check connectivity to definition sources.'
  }
  if ($mp.QuickScanEndTime) {
    $scanAge = (Get-Date) - $mp.QuickScanEndTime
    if ($scanAge.Days -gt 14) {
      Add-Finding -Severity Medium -Category 'AV' -Title 'Quick scan not run in 14+ days' `
        -Detail ("Last quick scan {0:yyyy-MM-dd}" -f $mp.QuickScanEndTime) -Remediation 'Schedule regular quick scans.'
    }
  }
  else {
    Add-Finding -Severity Medium -Category 'AV' -Title 'No record of a Defender quick scan' -Remediation 'Run a baseline scan and enable scheduled scanning.'
  }
  # Exclusions = classic defense-evasion foothold
  $prefs = Get-MpPreference -ErrorAction SilentlyContinue
  $excl = @()
  if ($prefs) {
    $excl += $prefs.ExclusionPath
    $excl += $prefs.ExclusionProcess
    $excl += $prefs.ExclusionExtension
  }
  # Get-MpPreference returns only the exclusions visible to the caller. A standard
  # user sees a subset (measured: 3 of 28 on a test host), so the count must never
  # be presented as complete unless the scan is elevated.
  $exclPartial = -not $script:IsElevated
  if ($excl.Count -gt 0) {
    $suffix = if ($exclPartial) { ' - PARTIAL, needs elevation' } else { '' }
    $warn = if ($exclPartial) { ' || WARNING: this list is incomplete - a non-elevated caller sees only a subset. Re-run elevated for the true count.' } else { '' }
    Add-Finding -Severity High -Category 'AV' -Title ('Defender exclusions configured ({0}{1})' -f $excl.Count, $suffix) `
      -Detail ('Exclusions: ' + (($excl | Where-Object { $_ }) -join ' | ') + $warn) `
      -Remediation 'Review every exclusion for necessity; attackers commonly add their tool paths here. Remove any that are not documented.'
  }
  elseif ($exclPartial) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender exclusions not assessed (needs elevation)' `
      -Detail 'Get-MpPreference returned no exclusions, but a non-elevated caller cannot see the full list. Absence here is not evidence that none are configured.' `
      -Remediation 'Re-run elevated to enumerate Defender exclusions.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'AV' -Title 'Defender status unavailable' -Detail 'Get-MpComputerStatus failed (non-Defender AV or older OS). Verify AV presence manually.'
}

######################## AUDITING & LOGGING POSTURE (NEW) ########################

Start-Section 'AUDITING & LOGGING POSTURE'
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed (needs elevation)' `
    -Detail 'auditpol /get requires administrator; run elevated to verify Logon/Logoff, Privilege Use and Object Access auditing.'
}
else {
  try {
    $auditPolicy = (auditpol.exe /get /category:* 2>$null | Where-Object { $_ -match '^\s' })
    if (-not $auditPolicy) {
      Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy unreadable' -Detail 'auditpol returned no data even when elevated.'
    }
    else {
      $lapse = $auditPolicy | Where-Object { $_ -match 'Logon/Logoff|Privilege Use|Object Access' -and $_ -match 'No Auditing' }
      if ($lapse) {
        Add-Finding -Severity Medium -Category 'Logging' -Title 'Critical audit subcategories set to No Auditing' `
          -Detail (($lapse | ForEach-Object { $_.Trim() }) -join ' ; ') `
          -Remediation 'Enable auditing for Logon/Logoff and Privilege Use (advanced audit policy: AuditLogon, AuditPrivilegeUse).'
      }
      else {
        Add-Finding -Severity Info -Category 'Logging' -Title 'Core audit categories enabled'
      }
    }
  } catch { }
}

# Security log size + retention
try {
  $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
  $mb = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
  if ($mb -lt 128) {
    Add-Finding -Severity Medium -Category 'Logging' -Title "Security event log small ($mb MB)" `
      -Remediation 'Increase Security log size (>= 256 MB) or forward to SIEM (WEF) to avoid losing intrusion evidence.'
  }
  else {
    Add-Finding -Severity Info -Category 'Logging' -Title "Security event log size ${mb} MB"
  }
}
catch {
  if (-not $script:IsElevated) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Security event log not assessed (needs elevation)' `
      -Detail 'Reading the Security log configuration requires administrator; run elevated to check its size/retention.'
  }
}

# WEF
if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager') {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Windows Event Forwarding configured'
}
else {
  Add-Finding -Severity Low -Category 'Logging' -Title 'No Windows Event Forwarding' `
    -Detail 'Local logs die with the host; attackers clear logs post-incident.' `
    -Remediation 'Deploy WEF or a log agent so security events reach a central SIEM.'
}

# PowerShell operational logging (blue-team staple)
$psLogPaths = @(
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'Script Block Logging' },
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';     Name = 'Module Logging' },
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';     Name = 'Transcription' }
)
foreach ($lp in $psLogPaths) {
  $key = Get-ItemProperty -Path $lp.Path -ErrorAction SilentlyContinue
  $on = $key -and (($key.EnableModuleLogging -eq 1) -or ($key.EnableTranscripting -eq 1) -or ($key.EnableScriptBlockLogging -eq 1) -or ($key.PSObject.Properties.Name -contains 'EnableScriptBlockLogging' -and $key.EnableScriptBlockLogging -ne 0))
  if ($on) {
    Add-Finding -Severity Info -Category 'Logging' -Title ('PowerShell {0} enabled' -f $lp.Name)
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell {0} NOT enabled' -f $lp.Name) `
      -Detail 'Attacker tooling (and abusive admins) rely on PowerShell flying under the radar.' `
      -Remediation ('Enable {0} via GPO for command-line visibility.' -f $lp.Name)
  }
}
