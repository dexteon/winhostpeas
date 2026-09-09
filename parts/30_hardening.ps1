
######################## PERSISTENCE DEEP-DIVE ########################
# High-signal persistence locations beyond Run/RunOnce/startup/tasks:
# Winlogon hijacks, WMI permanent subscriptions, COM hijack-prone HKCU CLSIDs,
# IFEO debuggers, AppInit_DLLs, LSA security packages, Active Setup,
# netsh helpers, screensaver hijacks, service failure actions.

Start-Section 'PERSISTENCE DEEP-DIVE'

# --- Winlogon hijack points ---
$wlg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wlg) {
  foreach ($val in @('Shell', 'Userinit', 'Taskman', 'System', 'VmApplet', 'AppSetup')) {
    $v = $wlg.$val
    if ($null -eq $v) { continue }
    $expected = @{ Shell = 'explorer.exe'; Userinit = 'C:\Windows\system32\userinit.exe,' }
    if ($expected.ContainsKey($val)) {
      if ($v -notlike "*$($expected[$val])*") {
        Add-Finding -Severity Critical -Category 'Persistence' -Title ("Winlogon {0} hijacked: {1}" -f $val, $v) `
          -Detail 'Executed at every logon as SYSTEM - classic Kovter-class persistence.' `
          -Remediation "Restore ${val} to its Windows default immediately; trace what installed it."
      }
    }
    elseif ($v) {
      Add-Finding -Severity Medium -Category 'Persistence' -Title ("Winlogon '{0}' configured: {1}" -f $val, $v) `
        -Remediation 'Verify this value against a clean image; non-default Winlogon values execute at logon.'
    }
  }
}

# --- WMI permanent event subscriptions (fileless persistence) ---
try {
  $subs = @()
  foreach ($nsName in @('root\subscription', "root\cimv2")) {
    $filter = Get-CimInstance -Namespace $nsName -ClassName __EventFilter -ErrorAction SilentlyContinue
    $binding = Get-CimInstance -Namespace $nsName -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    $consumer = @()
    $consumer += Get-CimInstance -Namespace $nsName -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    $consumer += Get-CimInstance -Namespace $nsName -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $consumer += Get-CimInstance -Namespace $nsName -ClassName CommandLineTemplateConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumer) {
      $linkedFilter = $binding | Where-Object { $_.Consumer -like "*$($c.Name)*" }
      $subs += [pscustomobject]@{
        Namespace = $nsName; Consumer = $c.__CLASS; Name = $c.Name
        Cmd = $c.CommandLineTemplate; Script = $c.ScriptText
        Filter = ($linkedFilter | Select-Object -First 1).Filter
      }
    }
  }
  if ($subs.Count -gt 0) {
    foreach ($s in ($subs | Select-Object -First 15)) {
      $detail = ("{0}\{1} ({2})" -f $s.Namespace, $s.Name, $s.Consumer)
      if ($s.Cmd) { $detail += " | Cmd: " + $s.Cmd }
      if ($s.Script) { $detail += " | Script present" }
      Add-Finding -Severity High -Category 'Persistence' -Title ("WMI event consumer: {0}" -f $s.Name) `
        -Detail $detail `
        -Remediation 'Permanent WMI subscriptions survive reboots and run as SYSTEM. Baseline a clean image; anything not from your build = remove + investigate.'
    }
  }
  elseif ($script:IsElevated) {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No WMI permanent event consumers'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'WMI event subscriptions not assessed (needs elevation)' `
      -Detail 'Enumerating root\subscription requires administrator; run elevated to detect WMI-based fileless persistence.'
  }
} catch { }

# --- COM hijack-prone: HKCU CLSID (per-user COM overrides) ---
try {
  $hkcuClsid = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
  $count = @($hkcuClsid).Count
  if ($count -gt 0) {
    Add-Finding -Severity Medium -Category 'Persistence' -Title ("{0} per-user CLSID overrides in HKCU (COM hijack surface)" -f $count) `
      -Detail 'HKCU\Software\Classes\CLSID overrides HKLM COM registrations - a silent code-exec persistence slot invisible to per-machine audits.' `
      -Remediation 'Compare against a clean profile; watch InprocServer32/LocalServer32 default values pointing outside Windows/Program Files.'
    $suspicious = 0
    foreach ($k in ($hkcuClsid | Select-Object -First 300)) {
      $ips = Get-ItemProperty "$($k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
      if ($ips -and $ips.'(default)' -and "$($ips.'(default)')" -notmatch '^C:\\(Windows|Program Files)' -and $suspicious -lt 5) {
        Add-Finding -Severity High -Category 'Persistence' -Title ("HKCU COM server outside standard paths: {0}" -f $k.PSChildName) `
          -Detail ("DLL: {0}" -f $ips.'(default)') `
          -Remediation 'Verify; per-user COM DLLs loading from user-writable paths are hijack/persistence primitives.'
        $suspicious++
      }
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No per-user CLSID overrides (clean COM surface)'
  }
} catch { }

# --- IFEO debuggers (arbitrary code exec launcher) ---
try {
  $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
  $debuggers = Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
    if ($d -and $d.Debugger) { [pscustomobject]@{ Exe = $_.PSChildName; Debugger = $d.Debugger } }
  }
  if (@($debuggers).Count -gt 0) {
    foreach ($d in $debuggers) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("IFEO Debugger on {0}" -f $d.Exe) `
        -Detail ("Debugger: {0} - runs INSTEAD of the target executable, as the caller." -f $d.Debugger) `
        -Remediation 'Legit uses are rare (some AV, legacy tools). Anything else = remove and investigate.'
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No IFEO debugger keys'
  }
  # IFEO GlobalFlag + SilentProcessExit (subtler variant)
  $spe = Get-ChildItem "$ifeoRoot" -ErrorAction SilentlyContinue | ForEach-Object {
    $g = Get-ItemProperty $_.PSPath -Name GlobalFlag -ErrorAction SilentlyContinue
    if ($g -and ($g.GlobalFlag -band 0x200)) {
      $s = Get-ItemProperty "$($_.PSPath)\SilentProcessExit" -Name MonitorProcess -ErrorAction SilentlyContinue
      if ($s -and $s.MonitorProcess) { [pscustomobject]@{ Exe = $_.PSChildName; Monitor = $s.MonitorProcess } }
    }
  }
  foreach ($s in @($spe)) {
    if ($s) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("SilentProcessExit monitor on {0}" -f $s.Exe) `
        -Detail ("MonitorProcess: {0}" -f $s.Monitor) `
        -Remediation 'Flag+SilentProcessExit persistence: remove GlobalFlag 0x200 and the MonitorProcess value unless documented.'
    }
  }
} catch { }

# --- AppInit_DLLs (global DLL injection) ---
$appInit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
if ($appInit -and $appInit.AppInit_DLLs) {
  Add-Finding -Severity High -Category 'Persistence' -Title ("AppInit_DLLs set: {0}" -f $appInit.AppInit_DLLs) `
    -Detail 'Injects into every GUI process that loads user32.dll.' `
    -Remediation 'Clear AppInit_DLLs (disabled on modern Windows anyway); identify the DLL and treat as malicious until proven otherwise.'
}
else {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'AppInit_DLLs empty'
}

# --- LSA security packages / notification packages (DLL load at boot) ---
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
foreach ($pkgName in @('Security Packages', 'Notification Packages')) {
  $pkgs = $lsa.$pkgName
  if ($pkgs) {
    $expected = @{ 'Security Packages' = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','ntlm'); 'Notification Packages' = @('scecli','rassfm','wdigest') }
    $extra = @($pkgs | ForEach-Object { "$_" } | Where-Object { ($_.Trim('"', ' ', "`t") -ne '') } |
      Where-Object { $expected[$pkgName] -notcontains $_.Trim().ToLower() })
    if ($extra.Count -gt 0) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Non-standard LSA {0}: {1}" -f $pkgName, ($extra -join ', ')) `
        -Detail 'LSA packages load into LSASS at boot as SYSTEM - credential-capture territory (mimikatz uses this).' `
        -Remediation 'Remove non-standard entries; verify the DLLs against the build baseline.'
    }
  }
}

# --- Active Setup (per-user exec at first logon) ---
try {
  foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
      $stub = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).StubPath
      if ($stub) {
        $known = ($_.PSChildName -match '^\{?[0-9A-Fa-f-]{36}\}?$') -and ($stub -match 'system32|Program Files')
        $sev = if ($stub -match 'user-writable|AppData|Temp|Public|Downloads') { 'High' } else { 'Low' }
        if ($stub -match 'AppData|\\Temp\\|\\Public\\|Downloads') {
          Add-Finding -Severity $sev -Category 'Persistence' -Title ("Active Setup StubPath in user-writable path: {0}" -f $_.PSChildName) `
            -Detail ("Command: {0}" -f $stub) `
            -Remediation 'StubPath runs at first logon of every user; user-writable stub = persistence + privilege escalation.'
        }
      }
    }
  }
} catch { }

# --- netsh helpers ---
try {
  $helpers = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Netsh' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'
    if ($p) { [pscustomobject]@{ Helper = $_.PSChildName; Dll = $p } }
  }
  foreach ($h in @($helpers)) {
    if ($h -and $h.Dll -notmatch '^C:\\(Windows|Program Files)') {
      Add-Finding -Severity High -Category 'Persistence' -Title ("netsh helper DLL outside standard path: {0}" -f $h.Helper) `
        -Detail ("DLL: {0} - netsh.exe loads it at every invocation." -f $h.Dll) `
        -Remediation 'Remove via the helper key; netsh helper persistence runs as the calling user (often admin).'
    }
  }
  if (@($helpers).Count -eq 0) { Add-Finding -Severity Info -Category 'Persistence' -Title 'No netsh helper DLLs registered' }
} catch { }

# --- Screensaver hijack (per-user, logon-session exec) ---
foreach ($sidKey in @('HKCU:\Control Panel\Desktop')) {
  $ss = Get-ItemProperty $sidKey -ErrorAction SilentlyContinue
  if ($ss -and $ss.SCRNSAVE.EXE -and "$($ss.SCRNSAVE.EXE)" -notmatch '^C:\\Windows\\System32') {
    Add-Finding -Severity Medium -Category 'Persistence' -Title ("Screensaver outside System32: {0}" -f $ss.'SCRNSAVE.EXE') `
      -Remediation 'Screensaver path executes at idle timeout; user-writable .scr = persistence.'
  }
}

######################## IMAGE HARDENING BASELINE ########################
# The switch-to-flip list: what the golden image should enforce. Each check
# reports the current state + the exact hardening action.

Start-Section 'IMAGE HARDENING BASELINE'

# --- Defender ASR rules ---
try {
  $prefs = Get-MpPreference -ErrorAction Stop
  # Canonical Microsoft ASR rule GUIDs (learn.microsoft.com ASR rules reference).
  $asrIds = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office apps from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables not meeting prevalence/age/trust'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBScript launching downloaded executables'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps injecting into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office comms app creating child processes'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block PSExec/WMI process creation'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied/impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block webshell creation for servers'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced ransomware protection'
  }
  # Pair each configured rule with its action (1=Block, 2=Audit, 6=Warn, 0/absent=Disabled).
  # A rule present but in Audit/Warn does NOT block the technique, so it is not counted as enabled.
  $ruleIds = @($prefs.AttackSurfaceReductionRules_Ids)
  $ruleActions = @($prefs.AttackSurfaceReductionRules_Actions)
  $blocking = New-Object System.Collections.Generic.List[string]
  $auditing = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $ruleIds.Count; $i++) {
    $id = "$($ruleIds[$i])".ToLower()
    if (-not $id) { continue }
    $act = if ($i -lt $ruleActions.Count) { [int]$ruleActions[$i] } else { 0 }
    $label = if ($asrIds[$id]) { $asrIds[$id] } else { $id }
    if ($act -eq 1) { $blocking.Add($label) }
    elseif ($act -eq 2 -or $act -eq 6) { $auditing.Add($label) }
  }
  if ($blocking.Count -eq 0) {
    Add-Finding -Severity High -Category 'Hardening' -Title ('Defender ASR rules: none in Block mode ({0} audit/warn)' -f $auditing.Count) `
      -Detail 'ASR blocks the exact techniques this tool detects (WMI persistence, LSASS abuse, Office child-process, USB payloads). Audit/warn rules only log - they do not stop the technique.' `
      -Remediation 'Enable the ASR rule set in Block mode via GPO/Intune (set AttackSurfaceReductionRules_Actions to 1, not 2/6).'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title ("Defender ASR rules: {0} in Block mode" -f $blocking.Count) `
      -Detail (($blocking -join ' | ') + $(if ($auditing.Count) { ' || audit/warn only: ' + ($auditing -join ', ') } else { '' }))
  }
  if ($blocking.Count -gt 0 -and $auditing.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} ASR rules are audit/warn only (not blocking)" -f $auditing.Count) `
      -Detail ($auditing -join ', ') `
      -Remediation 'Promote audited rules to Block once validated; audit mode logs the technique but allows it.'
  }
  # Controlled Folder Access
  $cfa = $prefs.EnableControlledFolderAccess
  if ($cfa -eq 1) { Add-Finding -Severity Info -Category 'Hardening' -Title 'Controlled Folder Access (ransomware guard) ON' }
  else {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Controlled Folder Access OFF' `
      -Remediation 'Enable in audit mode first, then block: Set-MpPreference -EnableControlledFolderAccess 1.'
  }
  # Network protection
  if ($prefs.EnableNetworkProtection -eq 1) { Add-Finding -Severity Info -Category 'Hardening' -Title 'Defender network protection ON' }
  else {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Defender network protection OFF' `
      -Remediation 'EnableNetworkProtection=1 blocks malicious domains at the filter driver (C2 callback kill).'
  }
  # Cloud protection + sample submit
  if ($prefs.MAPSReporting -eq 0) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Defender cloud-delivered protection OFF' `
      -Remediation 'MAPSReporting=2 (advanced maps) - without cloud signals, zero-day behavior detection is blind.'
  }
} catch { }

# --- Exploit Protection (system-wide mitigations) ---
try {
  $procMit = Get-ProcessMitigation -System -ErrorAction Stop
  $dep = "$($procMit.Dep.Policy)"
  if ($dep -match 'ON|Permanent') {
    Add-Finding -Severity Info -Category 'Hardening' -Title "DEP: $dep"
  }
  elseif ($dep -match 'OFF') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title "DEP not fully ON ($dep)" `
      -Remediation 'Enable DEP AlwaysOn plus ATL thunk emulation off.'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title ("DEP policy: {0} (default/opt-in state)" -f $(if ($dep) { $dep } else { 'not set - OS default' }))
  }
  $aslr = $procMit.ASLR
  if ($aslr.ForceRelocateImages -eq 'ON') {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'Mandatory ASLR ON (force relocation)'
  }
  else {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Mandatory ASLR not forced' `
      -Remediation 'Set ForceRelocateImages ON (bottom-up + high-entropy too) - closes no-rebase bypass.'
  }
  $cfg = $procMit.CFG
  if ("$($cfg.Enable)" -match 'ON') {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'Control Flow Guard enabled'
  }
  else {
    Add-Finding -Severity Low -Category 'Hardening' -Title 'Control Flow Guard not system-enabled' `
      -Remediation 'Enable CFG system-wide (mostly default on modern builds/apps).'
  }
} catch { }

# --- AppLocker / WDAC policy presence ---
$appLockerSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
$alRules = 0
try {
  foreach ($coll in @('Exe','Dll','Script','Msi','Packaged app')) {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$coll"
    if (Test-Path $path) { $alRules += @(Get-ChildItem $path).Count }
  }
} catch { }
$wdac = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
if ($alRules -gt 0) {
  Add-Finding -Severity Info -Category 'Hardening' -Title ("AppLocker: {0} rules configured" -f $alRules)
  if ($appLockerSvc -and $appLockerSvc.Status -ne 'Running') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'AppLocker rules exist but AppIDSvc not running' `
      -Remediation 'Set AppIDSvc to auto-start; rules without the service are inert.'
  }
}
elseif ($wdac) {
  Add-Finding -Severity Info -Category 'Hardening' -Title 'WDAC policy present (code integrity)'
}
else {
  Add-Finding -Severity High -Category 'Hardening' -Title 'No AppLocker or WDAC application-control policy' `
    -Detail 'Everything this report lists as persistence/privexec runs because nothing blocks unsigned execution.' `
    -Remediation 'Golden-image item: deploy WDAC (audit -> enforce) or AppLocker baseline rules (EXE/DLL/Script/MSI). Single highest-value hardening control.'
}

# --- SmartScreen ---
try {
  $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
  $ssVal = "$($ss.SmartScreenEnabled)"
  if ($ssVal -eq 'Off') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen OFF (machine)' `
      -Remediation 'Set SmartScreenEnabled=Warn/Block.'
  }
  elseif ($ssVal) {
    Add-Finding -Severity Info -Category 'Hardening' -Title "SmartScreen: $ssVal"
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'SmartScreen key not set (modern builds use per-app policies - verify via Windows Security UI)'
  }
} catch { }

# --- UAC notification level (image default) ---
$uacLevel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$uacMap = @{ 0 = 'Elevate without prompting (no consent)'; 1 = 'Prompt for creds on secure desktop'; 2 = 'Prompt for consent on secure desktop'; 5 = 'Prompt for consent for non-Windows binaries (default)' }
if ($null -ne $uacLevel) {
  $desc = $uacMap[[int]$uacLevel]; if (-not $desc) { $desc = "level $uacLevel" }
  if ([int]$uacLevel -eq 0) {
    Add-Finding -Severity High -Category 'Hardening' -Title "UAC silent-elevate mode ($desc)" `
      -Remediation 'Set ConsentPromptBehaviorAdmin=5 (default).'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title "UAC admin prompt level: $desc"
  }
}

# --- Guest account / local policies the image should lock ---
try {
  $guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
  if ($guest -and $guest.Enabled) {
    Add-Finding -Severity High -Category 'Hardening' -Title 'Guest account enabled' `
      -Remediation 'Disable Guest in the golden image.'
  }
  else { Add-Finding -Severity Info -Category 'Hardening' -Title 'Guest account disabled' }
} catch { }

# --- Remote desktop helpers image should remove ---
foreach ($feature in @('TelnetClient', 'TFTPClient', 'MicrosoftWindowsPowerShellV2', 'SMB1Protocol')) {
  try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
      Add-Finding -Severity High -Category 'Hardening' -Title ("Remove from image: feature {0} enabled" -f $feature) `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName $feature"
    }
  } catch { }
}

# --- Local admin RDP membership recap (image hygiene) ---
try {
  $adm = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
  if ($adm.Count -gt 3) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} local Administrators - trim the image baseline" -f $adm.Count)
  }
} catch { }

# --- Null sessions / registry remote access ---
foreach ($rk in @(
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Want = 1 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Want = 1 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks'; Want = 0 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Want = 0 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry'; Name = 'Start'; Want = 4 }
)) {
  $v = (Get-ItemProperty $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue).($rk.Name)
  if ($null -ne $v -and [int]$v -ne [int]$rk.Want) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title ("{0} = {1} (hardening wants {2})" -f $rk.Name, $v, $rk.Want) `
      -Remediation ("Set {0}={1} in the image (null-session / remote-registry hardening)." -f $rk.Name, $rk.Want)
  }
  elseif ($null -eq $v -and $rk.Name -match 'AutoShare') {
    # defaults: Wks=1 on client SKUs
    if ($rk.Name -eq 'AutoShareWks') {
      Add-Finding -Severity Low -Category 'Hardening' -Title 'AutoShareWks not set (default shares C$/ADMIN$ enabled)' `
        -Remediation 'Set AutoShareWks=0 in hardened images to kill default admin shares.'
    }
  }
}
