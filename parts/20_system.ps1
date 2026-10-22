
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
else {
  Add-Finding -Severity Info -Category 'Patching' -Title 'Patch history not assessed' `
    -Detail 'Get-HotFix returned no entries with an install date (common on fresh images and in-place upgrades). Patch recency is unknown, not current.' `
    -Remediation 'Check Settings > Windows Update > Update history, or query the Windows Update agent, to confirm the host is current.'
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
  # AMServiceEnabled is only the service state. RealTimeProtectionEnabled is the realtime
  # engine, and AMRunningMode says whether Defender is even the primary product: in
  # "Passive Mode" / "EDR Block Mode" a third-party AV is expected to own prevention.
  $amMode = "$($mp.AMRunningMode)"
  $rtp = [bool]$mp.RealTimeProtectionEnabled
  if (-not $mp.AMServiceEnabled -or $amMode -match 'Not running') {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender antimalware service not running' `
      -Detail ("AMServiceEnabled={0}; AMRunningMode={1}." -f $mp.AMServiceEnabled, $amMode) `
      -Remediation 'Start WinDefend and investigate why it stopped; if a third-party product replaced it, confirm that product is active.'
  }
  elseif ($amMode -match 'Passive|EDR Block|SxS') {
    Add-Finding -Severity Medium -Category 'AV' -Title ("Defender in {0}: another AV product must be primary" -f $amMode) `
      -Detail ("AMRunningMode={0}; RealTimeProtectionEnabled={1}. In this mode Defender does not block in realtime (EDR Block Mode only remediates what MDE flags). If no third-party AV is installed and enabled, the host has no realtime prevention." -f $amMode, $rtp) `
      -Remediation 'Confirm a third-party AV/EDR is installed, licensed and running (Windows Security > Virus and threat protection). If none, clear ForceDefenderPassiveMode and return Defender to Normal mode.'
  }
  elseif ($rtp) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender realtime protection ON' `
      -Detail ("Mode {0}; engine {1}; signatures {2:yyyy-MM-dd HH:mm}" -f $amMode, $mp.AMEngineVersion, $mp.AntivirusSignatureLastUpdated)
  }
  else {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender realtime protection OFF' `
      -Detail ("RealTimeProtectionEnabled=False while AMRunningMode={0} (service running, engine not scanning)." -f $amMode) `
      -Remediation 'Re-enable realtime protection; investigate why it was disabled (often attacker first action).'
  }
  # Tamper Protection: the first control malware tries to disable (T1562.001).
  $tpProp = $mp.PSObject.Properties['IsTamperProtected']
  $tpReg = $null
  try { $tpReg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection } catch { }
  $tpState = if ($tpProp -and $null -ne $tpProp.Value) { [bool]$tpProp.Value } elseif ($tpReg -eq 5) { $true } elseif ($tpReg -eq 4) { $false } else { $null }
  if ($tpState -eq $true) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender Tamper Protection ON' -Detail ("IsTamperProtected={0}; Features\TamperProtection={1}" -f $(if ($tpProp) { $tpProp.Value } else { 'n/a' }), $tpReg)
  }
  elseif ($tpState -eq $false) {
    Add-Finding -Severity High -Category 'AV' -Title 'Defender Tamper Protection OFF' `
      -Detail ("IsTamperProtected={0}; Features\TamperProtection={1}. Without it, any admin process (or malware running as admin) can turn Defender off with one registry write." -f $(if ($tpProp) { $tpProp.Value } else { 'n/a' }), $tpReg) `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features::TamperProtection' `
      -Remediation 'Enable Tamper Protection (Windows Security UI, Intune, or MDE tenant-wide). It cannot be set by GPO or script by design.'
  }
  else {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender Tamper Protection not assessed' -Detail 'Neither Get-MpComputerStatus.IsTamperProtected nor Features\TamperProtection was readable.'
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
# Advanced audit policy, keyed by subcategory GUID so the check is language-neutral.
# auditpol /get /category:* /r emits CSV with a "Subcategory GUID" column; the
# "Inclusion Setting" column IS localized, so only the four English strings are
# evaluated and anything else is reported as not assessed rather than as a pass.
# Want: S = Success at least, SF = Success and Failure, F = Failure at least (MS baseline / CIS 17.x).
$auditWanted = @(
  @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                     Want = 'SF' }
  @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                    Want = 'S'  }
  @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';           Want = 'F'  }
  @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon';             Want = 'S'  }
  @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation';          Want = 'S'  }
  @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';       Want = 'S'  }
  @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Security State Change';     Want = 'S'  }
  @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension'; Want = 'S'  }
  @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Name = 'System Integrity';          Want = 'SF' }
  @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';   Want = 'SF' }
  @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';   Want = 'SF' }
  @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management'; Want = 'S'  }
  @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';     Want = 'SF' }
  @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Other Object Access Events'; Want = 'SF' }
  @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Name = 'File Share';                Want = 'SF' }
  @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Name = 'Removable Storage';         Want = 'SF' }
)
$wantLabel = @{ S = 'Success'; SF = 'Success and Failure'; F = 'Failure' }
$procCreationAudited = $null   # $true / $false / $null (not assessed)
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed (needs elevation)' `
    -Detail ('auditpol /get requires administrator. Not assessed: ' + (($auditWanted | ForEach-Object { $_.Name }) -join ', ') + '.') `
    -Remediation 'Re-run elevated to verify the advanced audit policy against the Microsoft baseline.'
}
else {
  try {
    $auditRaw = @(auditpol.exe /get /category:* /r 2>$null | Where-Object { "$_".Trim() })
    $auditRows = @()
    if ($auditRaw.Count -gt 1) { $auditRows = @($auditRaw | ConvertFrom-Csv -ErrorAction Stop) }
    if ($auditRows.Count -eq 0 -or -not ($auditRows[0].PSObject.Properties.Name -contains 'Subcategory GUID')) {
      Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed (auditpol output unreadable)' `
        -Detail 'auditpol /get /category:* /r returned no CSV with a Subcategory GUID column even when elevated.'
    }
    else {
      $auditOk = @(); $auditMissing = @(); $auditForeign = @()
      foreach ($w in $auditWanted) {
        $row = $auditRows | Where-Object { "$($_.'Subcategory GUID')".Trim().ToUpper() -eq $w.Guid } | Select-Object -First 1
        if (-not $row) { $auditMissing += ('{0} (not reported, want {1})' -f $w.Name, $wantLabel[$w.Want]); continue }
        $inc = "$($row.'Inclusion Setting')".Trim()
        $have = switch -Regex ($inc) {
          '^Success and Failure$' { 'SF'; break }
          '^Success$'             { 'S';  break }
          '^Failure$'             { 'F';  break }
          '^No Auditing$'         { 'N';  break }
          default                 { $null }
        }
        if ($null -eq $have) { $auditForeign += ('{0}="{1}"' -f $w.Name, $inc); continue }
        $meets = switch ($w.Want) {
          'SF' { $have -eq 'SF' }
          'S'  { $have -eq 'S' -or $have -eq 'SF' }
          'F'  { $have -eq 'F' -or $have -eq 'SF' }
        }
        if ($w.Guid -eq '{0CCE922B-69AE-11D9-BED3-505054503030}') { $procCreationAudited = [bool]$meets }
        if ($meets) { $auditOk += ('{0}={1}' -f $w.Name, $inc) } else { $auditMissing += ('{0}={1} (want {2})' -f $w.Name, $inc, $wantLabel[$w.Want]) }
      }
      if ($auditForeign.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Logging' -Title ('{0} audit subcategories not assessed (non-English auditpol output)' -f $auditForeign.Count) `
          -Detail ($auditForeign -join '; ') `
          -Remediation 'Compare the Inclusion Setting values against the Microsoft baseline manually; this tool only evaluates the English strings.'
      }
      if ($auditMissing.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Logging' -Title ('{0} of {1} critical audit subcategories below baseline' -f $auditMissing.Count, $auditWanted.Count) `
          -Detail ($auditMissing -join '; ') `
          -Remediation 'Set the advanced audit policy (Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration) to the Microsoft security baseline for these subcategories; without them logon, process and account-change events are never written.'
      }
      if ($auditOk.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Logging' -Title ('{0} of {1} critical audit subcategories at baseline' -f $auditOk.Count, $auditWanted.Count) `
          -Detail ($auditOk -join '; ')
      }
    }
  } catch {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed' -Detail ('auditpol failed: ' + $_.Exception.Message)
  }
}

# Process creation command line (4688 without the command line is near useless; CIS 18.9.3.1)
try {
  $cmdLineInc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
  $cmdLineOn = ($cmdLineInc -eq 1)
  if ($cmdLineOn -and $procCreationAudited -eq $true) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Process creation auditing with command line ON' `
      -Detail 'Process Creation subcategory audits Success and ProcessCreationIncludeCmdLine_Enabled=1, so event 4688 carries the full command line.'
  }
  elseif ($cmdLineOn -and $null -eq $procCreationAudited) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Command line in 4688 enabled; Process Creation subcategory not assessed (needs elevation)' `
      -Detail 'ProcessCreationIncludeCmdLine_Enabled=1, but whether the Process Creation subcategory is audited could not be read without elevation.'
  }
  else {
    $why = @()
    if (-not $cmdLineOn) { $why += ('ProcessCreationIncludeCmdLine_Enabled=' + $(if ($null -eq $cmdLineInc) { 'absent (off)' } else { "$cmdLineInc" })) }
    if ($procCreationAudited -eq $false) { $why += 'Process Creation subcategory is not auditing Success' }
    Add-Finding -Severity Medium -Category 'Logging' -Title 'Process creation command-line auditing incomplete' `
      -Detail (($why -join '; ') + '. Without both, 4688 events either do not exist or omit the command line that distinguishes malicious from benign execution (T1059 visibility).') `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit::ProcessCreationIncludeCmdLine_Enabled' `
      -Remediation 'Enable "Include command line in process creation events" (Administrative Templates > System > Audit Process Creation) and audit Process Creation Success (CIS 17.3.2).'
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
}
catch {
  if (-not $script:IsElevated) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Security event log not assessed (needs elevation)' `
      -Detail 'Reading the Security log configuration requires administrator; run elevated to check its size/retention.'
  }
}

# WEF, gated on log-shipping agents: a host that ships logs through an agent is not "local only".
$logAgentNames = @('SplunkForwarder', 'nxlog', 'winlogbeat', 'filebeat', 'elastic-agent', 'HealthService', 'AzureMonitorAgent', 'DatadogAgent', 'WinCollect', 'QRadar', 'fluentdwinsvc')
$logAgentsRunning = @()
try {
  $logAgentsRunning = @(Get-Service -Name $logAgentNames -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
} catch { }
$wefConfigured = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
if ($wefConfigured) {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Windows Event Forwarding configured'
}
# (Agent and Sysmon inventory is reported by the Security Features section; here the agent
#  list only gates this finding.)
if (-not $wefConfigured -and $logAgentsRunning.Count -eq 0) {
  Add-Finding -Severity Low -Category 'Logging' -Title 'No Windows Event Forwarding or log-shipping agent' `
    -Detail ('Local logs die with the host; attackers clear logs post-incident. No WEF SubscriptionManager policy and none of these services running: ' + ($logAgentNames -join ', ') + '.') `
    -Remediation 'Deploy WEF or a log agent so security events reach a central SIEM.'
}

# PowerShell operational logging (blue-team staple). Each setting is evaluated for what it
# actually produces: module logging logs nothing without ModuleNames, transcription needs a
# directory to be useful, and an explicit 0 is reported as "disabled by policy", not "not configured".
try {
  $sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
  $sblVal = if ($sbl) { $sbl.EnableScriptBlockLogging } else { $null }
  if ($sblVal -eq 1) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'PowerShell Script Block Logging enabled' `
      -Detail ("EnableScriptBlockInvocationLogging={0}" -f $(if ($null -ne $sbl.EnableScriptBlockInvocationLogging) { $sbl.EnableScriptBlockInvocationLogging } else { 'not set' }))
  }
  else {
    $state = if ($null -eq $sblVal) { 'not configured (OS default logs only blocks Defender/AMSI flags as suspicious)' } else { "explicitly disabled by policy (EnableScriptBlockLogging=$sblVal)" }
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell Script Block Logging NOT enabled: ' + $(if ($null -eq $sblVal) { 'not configured' } else { 'disabled by policy' })) `
      -Detail ($state + '. Attacker tooling (and abusive admins) rely on PowerShell flying under the radar; event 4104 is the record of what actually ran.') `
      -Remediation 'Enable Script Block Logging via GPO (Administrative Templates > Windows Components > Windows PowerShell).'
  }
  $ml = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
  $mlVal = if ($ml) { $ml.EnableModuleLogging } else { $null }
  $mlNames = @()
  try { $mn = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction SilentlyContinue; if ($mn) { $mlNames = @($mn.Property) } } catch { }
  if ($mlVal -eq 1 -and $mlNames.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'PowerShell Module Logging enabled' -Detail ('ModuleNames: ' + ($mlNames -join ', '))
  }
  elseif ($mlVal -eq 1) {
    Add-Finding -Severity Medium -Category 'Logging' -Title 'PowerShell Module Logging enabled but ModuleNames is empty (nothing is logged)' `
      -Detail 'EnableModuleLogging=1 without entries under ModuleLogging\ModuleNames logs no module activity at all.' `
      -Remediation 'Add "*" (or the modules of interest) under ModuleNames so event 4103 is produced.'
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell Module Logging NOT enabled: ' + $(if ($null -eq $mlVal) { 'not configured' } else { 'disabled by policy' })) `
      -Detail 'Module logging (event 4103) records pipeline execution details per module.' `
      -Remediation 'Enable Module Logging via GPO with ModuleNames = *.'
  }
  $tr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
  $trVal = if ($tr) { $tr.EnableTranscripting } else { $null }
  if ($trVal -eq 1) {
    $outDir = "$($tr.OutputDirectory)"
    if ($outDir) {
      Add-Finding -Severity Info -Category 'Logging' -Title 'PowerShell Transcription enabled' -Detail ("OutputDirectory: {0}; EnableInvocationHeader={1}" -f $outDir, $tr.EnableInvocationHeader)
    }
    else {
      Add-Finding -Severity Low -Category 'Logging' -Title 'PowerShell Transcription enabled without a central OutputDirectory' `
        -Detail 'Transcripts land in each user''s Documents folder, where the user (or malware running as the user) can delete them.' `
        -Remediation 'Set OutputDirectory to a write-only share or protected folder collected by the SIEM.'
    }
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell Transcription NOT enabled: ' + $(if ($null -eq $trVal) { 'not configured' } else { 'disabled by policy' })) `
      -Detail 'Transcription captures full session input and output, including interactive attacker sessions.' `
      -Remediation 'Enable Transcription via GPO with a protected OutputDirectory.'
  }
} catch { }
