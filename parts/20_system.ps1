
######################## SYSTEM & PATCH POSTURE ########################

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
  if ($excl.Count -gt 0) {
    Add-Finding -Severity High -Category 'AV' -Title ('Defender exclusions configured ({0})' -f $excl.Count) `
      -Detail ('Exclusions: ' + (($excl | Where-Object { $_ }) -join ' | ')) `
      -Remediation 'Review every exclusion for necessity; attackers commonly add their tool paths here. Remove any that are not documented.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'AV' -Title 'Defender status unavailable' -Detail 'Get-MpComputerStatus failed (non-Defender AV or older OS). Verify AV presence manually.'
}

######################## AUDITING & LOGGING POSTURE (NEW) ########################

Start-Section 'AUDITING & LOGGING POSTURE'
try {
  $auditPolicy = (auditpol.exe /get /category:* 2>$null | Where-Object { $_ -match '^\s' })
  $lapse = $auditPolicy | Where-Object { $_ -match 'Logon/Logoff|Privilege Use|Object Access' -and $_ -match 'No Auditing' }
  if ($lapse) {
    Add-Finding -Severity Medium -Category 'Logging' -Title 'Critical audit subcategories set to No Auditing' `
      -Detail (($lapse | ForEach-Object { $_.Trim() }) -join ' ; ') `
      -Remediation 'Enable auditing for Logon/Logoff and Privilege Use (advanced audit policy: AuditLogon, AuditPrivilegeUse).'
  }
  else {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Core audit categories enabled'
  }
} catch { }

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
} catch { }

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
