
######################## PERSISTENCE DEEP-DIVE ########################
# High-signal persistence locations beyond Run/RunOnce/startup/tasks:
# Winlogon hijacks, WMI permanent subscriptions, COM hijack-prone HKCU CLSIDs,
# IFEO debuggers, AppInit_DLLs, LSA security packages, Active Setup,
# netsh helpers, screensaver hijacks, service failure actions.

Start-Section 'PERSISTENCE DEEP-DIVE'

# --- Winlogon hijack points ---
# Shell and Userinit are compared token by token after trimming and expanding %SystemRoot%:
# a substring match let "explorer.exe,evil.exe" and "userinit.exe,C:\evil.exe" pass, which is
# exactly how the technique is used. Every extra token is hashed when it points at a file.
$wlg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wlg) {
  try {
    $sysRoot = "$env:SystemRoot"
    $expectedTokens = @{
      Shell    = @('explorer.exe')
      Userinit = @((Join-Path $sysRoot 'system32\userinit.exe'))
    }
    # Values that are absent on a clean build, or have one known default (VmApplet is set by
    # Windows itself; reporting it was a false positive on every host).
    $knownDefaults = @{ VmApplet = @('SystemPropertiesPerformance.exe /pagefile', 'rundll32 shell32,Control_RunDLL "sysdm.cpl"') }
    foreach ($val in @('Shell', 'Userinit', 'Taskman', 'System', 'VmApplet', 'AppSetup')) {
      $v = $wlg.$val
      if ($null -eq $v) { continue }
      $raw = "$v"
      if ($knownDefaults.ContainsKey($val) -and ($knownDefaults[$val] | Where-Object { $raw.Trim() -ieq $_ })) { continue }
      if ($expectedTokens.ContainsKey($val)) {
        $tokens = @($raw -split ',' | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } | Where-Object { $_ })
        $extra = @()
        foreach ($t in $tokens) {
          $match = $false
          foreach ($e in $expectedTokens[$val]) { if ($t -ieq $e) { $match = $true } }
          # Shell may legitimately be "explorer.exe" only; Userinit must be the single System32 path.
          if (-not $match) { $extra += $t }
        }
        if ($extra.Count -gt 0 -or $tokens.Count -eq 0) {
          $hashes = @()
          foreach ($x in $extra) {
            $exe = ($x -split '\s+')[0]
            try { if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { $hashes += ('{0} SHA256={1}' -f $exe, (Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash) } } catch { }
          }
          Add-Finding -Severity Critical -Category 'Persistence' -Title ("Winlogon {0} hijacked: {1}" -f $val, $raw) `
            -Detail ('Expected exactly "{0}"; extra token(s): {1}. Executed at every logon - classic Kovter-class persistence.{2}' -f ($expectedTokens[$val] -join ','), ($extra -join ' | '), $(if ($hashes) { ' ' + ($hashes -join '; ') } else { '' })) `
            -Evidence ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon::{0} = {1}" -f $val, $raw) `
            -Remediation "Restore ${val} to its Windows default immediately; trace what installed it."
        }
      }
      elseif ($raw.Trim()) {
        Add-Finding -Severity Medium -Category 'Persistence' -Title ("Winlogon '{0}' configured: {1}" -f $val, $raw) `
          -Remediation 'Verify this value against a clean image; non-default Winlogon values execute at logon.'
      }
    }
  } catch { }
}

# --- WMI permanent event subscriptions (fileless persistence) ---
# root\subscription is readable by standard users, so the result is reported either way;
# "not assessed" is only emitted when the enumeration itself failed.
try {
  $subs = @()
  $wmiErr = $null
  foreach ($nsName in @('root\subscription', "root\cimv2")) {
    $filter = $null
    try { $filter = Get-CimInstance -Namespace $nsName -ClassName __EventFilter -ErrorAction Stop } catch { if ($nsName -eq 'root\subscription') { $wmiErr = $_.Exception.Message } }
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
  elseif ($wmiErr) {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'WMI event subscriptions not assessed' `
      -Detail ('Enumerating root\subscription failed: ' + $wmiErr + '. Run elevated if this was access denied.')
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No WMI permanent event consumers'
  }
} catch { }

# --- COM hijack-prone: HKCU CLSID (per-user COM overrides) ---
try {
  # Per-user CLSIDs are normal on a desktop (PowerToys, Teams, OneDrive, browsers register under
  # %LOCALAPPDATA%), so the count is Info. High only for a DLL that is unsigned, not validly
  # signed, missing, or sitting in Temp, Public, Downloads or ProgramData; Low for a validly
  # signed vendor DLL under LocalAppData.
  $hkcuClsid = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
  $count = @($hkcuClsid).Count
  if ($count -gt 0) {
    $highHits = @(); $lowCount = 0; $lowSample = @(); $sysCount = 0
    foreach ($k in ($hkcuClsid | Select-Object -First 500)) {
      $ips = Get-ItemProperty "$($k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
      if (-not $ips -or -not $ips.'(default)') { continue }
      $dll = [Environment]::ExpandEnvironmentVariables(("$($ips.'(default)')").Trim().Trim('"'))
      if ($dll -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\))\\') { $sysCount++; continue }
      $sig = $null; $hash = ''; $exists = $false
      try {
        if ($dll -and (Test-Path -LiteralPath $dll -PathType Leaf)) {
          $exists = $true
          $sig = (Get-AuthenticodeSignature -LiteralPath $dll -ErrorAction Stop).Status
          $hash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256 -ErrorAction Stop).Hash
        }
      } catch { }
      $badPath = $dll -match '(?i)\\(Temp|Public|Downloads|ProgramData)\\'
      $desc = ('{0} -> {1} [exists={2}; signature={3}{4}]' -f $k.PSChildName, $dll, $exists, $(if ($null -eq $sig) { 'n/a' } else { $sig }), $(if ($hash) { '; SHA256=' + $hash } else { '' }))
      if ($badPath -or -not $exists -or "$sig" -ne 'Valid') {
        $highHits += $desc
      }
      else {
        $lowCount++
        if ($lowSample.Count -lt 5) { $lowSample += $desc }
      }
    }
    Add-Finding -Severity Info -Category 'Persistence' -Title ("{0} per-user CLSID overrides in HKCU (COM hijack surface)" -f $count) `
      -Detail ("InprocServer32 targets: {0} under Windows/Program Files, {1} validly signed elsewhere, {2} suspect. HKCU\Software\Classes\CLSID overrides HKLM COM registrations, a persistence slot invisible to per-machine audits." -f $sysCount, $lowCount, $highHits.Count) `
      -Remediation 'Compare against a clean profile; watch InprocServer32/LocalServer32 default values pointing outside Windows/Program Files.'
    foreach ($h in ($highHits | Select-Object -First 8)) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("HKCU COM server unsigned, missing or in a user-writable drop path") `
        -Detail $h `
        -Evidence ('HKCU:\Software\Classes\CLSID\' + ($h -split ' -> ')[0] + '\InprocServer32') `
        -Remediation 'Verify the DLL; per-user COM DLLs that are unsigned or load from Temp/Public/Downloads/ProgramData are hijack and persistence primitives.'
    }
    if ($lowCount -gt 0) {
      Add-Finding -Severity Low -Category 'Persistence' -Title ("{0} HKCU COM servers are validly signed DLLs outside Windows/Program Files" -f $lowCount) `
        -Detail (($lowSample -join ' | ') + $(if ($lowCount -gt 5) { " | ... ($lowCount total)" } else { '' })) `
        -Remediation 'Vendor DLLs under LocalAppData are normal (PowerToys, Teams, OneDrive, browsers); confirm the publisher matches an installed product.'
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
try {
  $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  $lsaOs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -ErrorAction SilentlyContinue
  $expected = @{
    'Security Packages'       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'ntlm', 'negoexts', 'negotiate')
    'Notification Packages'   = @('scecli', 'rassfm', 'wdigest')
    'Authentication Packages' = @('msv1_0')   # T1547.002: the default is exactly msv1_0
  }
  $lsaSets = @(
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'Security Packages';       Obj = $lsa }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'Notification Packages';   Obj = $lsa }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'Authentication Packages'; Obj = $lsa }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'; Name = 'Security Packages'; Obj = $lsaOs }
  )
  foreach ($ls in $lsaSets) {
    if (-not $ls.Obj) { continue }
    $pkgs = $ls.Obj.($ls.Name)
    if ($null -eq $pkgs) { continue }
    $entries = @($pkgs | ForEach-Object { "$_".Trim('"', ' ', "`t") } | Where-Object { $_ -ne '' })
    $extra = @($entries | Where-Object { $expected[$ls.Name] -notcontains $_.ToLower() })
    if ($extra.Count -gt 0) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Non-standard LSA {0}: {1}" -f $ls.Name, ($extra -join ', ')) `
        -Detail ("Full list: {0}. LSA packages load into LSASS at boot as SYSTEM - credential-capture territory (mimikatz misc::memssp, T1547.002)." -f ($entries -join ', ')) `
        -Evidence ("{0}::{1}" -f $ls.Key, $ls.Name) `
        -Remediation 'Remove non-standard entries; verify the DLLs against the build baseline.'
    }
    elseif ($ls.Name -eq 'Authentication Packages') {
      Add-Finding -Severity Info -Category 'Persistence' -Title 'LSA Authentication Packages at default (msv1_0)'
    }
  }
} catch { }

# --- Active Setup (per-user exec at first logon) ---
try {
  foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
      $stub = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).StubPath
      if ($stub) {
        if ($stub -match 'AppData|\\Temp\\|\\Public\\|Downloads') {
          Add-Finding -Severity High -Category 'Persistence' -Title ("Active Setup StubPath in user-writable path: {0}" -f $_.PSChildName) `
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
# The value name contains a dot, so it must be quoted: $ss.SCRNSAVE.EXE parses as
# ($ss.SCRNSAVE).EXE, which is always null and made this check unable to fire.
try {
  foreach ($sidKey in @('HKCU:\Control Panel\Desktop')) {
    $ss = Get-ItemProperty $sidKey -ErrorAction SilentlyContinue
    $scr = if ($ss) { "$($ss.'SCRNSAVE.EXE')".Trim() } else { '' }
    if ($scr) {
      $scrPath = [Environment]::ExpandEnvironmentVariables($scr.Trim('"'))
      $sysDir = Join-Path "$env:SystemRoot" 'System32'
      if ($scrPath -notmatch '^[A-Za-z]:\\' ) { $scrPath = Join-Path $sysDir $scrPath }   # bare name resolves from System32
      if ($scrPath -notlike "$sysDir\*") {
        $h = ''
        try { if (Test-Path -LiteralPath $scrPath -PathType Leaf) { $h = ' SHA256=' + (Get-FileHash -LiteralPath $scrPath -Algorithm SHA256 -ErrorAction Stop).Hash } } catch { }
        Add-Finding -Severity Medium -Category 'Persistence' -Title ("Screensaver outside System32: {0}" -f $scr) `
          -Detail ("Resolved path: {0}{1}" -f $scrPath, $h) `
          -Evidence "$sidKey::SCRNSAVE.EXE" `
          -Remediation 'Screensaver path executes at idle timeout; user-writable .scr = persistence (T1546.002).'
      }
    }
  }
} catch { }

# --- AppCertDlls (loaded into every process that calls CreateProcess, T1546.009) ---
try {
  $appCert = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
  if ($appCert -and @($appCert.Property).Count -gt 0) {
    $vals = @($appCert.Property | ForEach-Object { '{0} = {1}' -f $_, (Get-ItemProperty $appCert.PSPath -Name $_ -ErrorAction SilentlyContinue).$_ })
    Add-Finding -Severity High -Category 'Persistence' -Title ("AppCertDlls configured ({0} value(s))" -f $vals.Count) `
      -Detail (($vals -join ' | ') + '. Each DLL is loaded by every process that calls CreateProcess, CreateProcessAsUser, WinExec and friends.') `
      -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' `
      -Remediation 'The key is empty on a clean build. Identify the DLL, treat it as malicious until proven otherwise, and remove the value.'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'AppCertDlls key absent or empty (clean)'
  }
} catch { }

# --- Hidden logon accounts (SpecialAccounts\UserList, T1564.002) ---
try {
  $ul = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -ErrorAction SilentlyContinue
  $hidden = @()
  if ($ul) {
    foreach ($n in @($ul.Property)) {
      $v = (Get-ItemProperty $ul.PSPath -Name $n -ErrorAction SilentlyContinue).$n
      if ($v -eq 0) { $hidden += $n }
    }
  }
  if ($hidden.Count -gt 0) {
    foreach ($hname in $hidden) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("Account hidden from the logon screen: {0}" -f $hname) `
        -Detail 'A UserList value of 0 hides the account from the Welcome screen and user switching; classic backdoor-account concealment.' `
        -Evidence ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList::{0} = 0" -f $hname) `
        -Remediation 'Confirm the account is authorized; remove the UserList value and investigate who created the account.'
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No accounts hidden via SpecialAccounts\UserList'
  }
} catch { }

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

# --- Application control: WDAC (user-mode code integrity), Smart App Control, AppLocker ---
# Real state, not key counts: Win32_DeviceGuard reports UMCI enforcement (0 off, 1 audit,
# 2 enforced) and kernel CI; CI\Policy VerifiedAndReputablePolicyState is Smart App Control
# (0 off, 1 on, 2 evaluation); Get-AppLockerPolicy -Effective is the merged AppLocker policy.
# High only when all three are off. Kernel-mode CI enforced (the HVCI default policy) is NOT
# application control, so it is reported as detail only.
try {
  $umci = $null; $kmci = $null
  try {
    $dgAc = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1
    if ($dgAc) { $umci = [int]$dgAc.UsermodeCodeIntegrityPolicyEnforcementStatus; $kmci = [int]$dgAc.CodeIntegrityPolicyEnforcementStatus }
  } catch { }
  $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
  $ciLabel = @{ 0 = 'off'; 1 = 'audit'; 2 = 'enforced' }
  $sacLabel = @{ 0 = 'off'; 1 = 'on'; 2 = 'evaluation' }
  $alRules = 0; $alCollections = @(); $alEffectiveRead = $false
  try {
    $alp = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $alEffectiveRead = $true
    foreach ($rc in @($alp.RuleCollections)) {
      $n = @($rc).Count
      if ($n -gt 0) { $alRules += $n; $alCollections += ('{0}:{1} rules ({2})' -f $rc.RuleCollectionType, $n, $rc.EnforcementMode) }
    }
  } catch { }
  if (-not $alEffectiveRead) {
    # Fallback: policy registry key counts (the previous method).
    foreach ($coll in @('Exe', 'Dll', 'Script', 'Msi', 'Appx')) {
      $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$coll"
      if (Test-Path $path) { $c = @(Get-ChildItem $path -ErrorAction SilentlyContinue).Count; if ($c -gt 0) { $alRules += $c; $alCollections += "${coll}:$c rules (registry)" } }
    }
  }
  $appLockerSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
  $umciOn = ($null -ne $umci -and $umci -ge 1)
  $sacOn = ($sac -eq 1 -or $sac -eq 2)
  $alOn = ($alRules -gt 0)
  $stateDetail = ("WDAC user-mode CI: {0}; kernel-mode CI: {1}; Smart App Control: {2}; AppLocker: {3}" -f `
    $(if ($null -eq $umci) { 'not readable' } elseif ($ciLabel.ContainsKey($umci)) { $ciLabel[$umci] } else { $umci }), `
    $(if ($null -eq $kmci) { 'not readable' } elseif ($ciLabel.ContainsKey($kmci)) { $ciLabel[$kmci] } else { $kmci }), `
    $(if ($null -eq $sac) { 'absent (off)' } elseif ($sacLabel.ContainsKey([int]$sac)) { $sacLabel[[int]$sac] } else { $sac }), `
    $(if ($alOn) { $alCollections -join ', ' } elseif ($alEffectiveRead) { 'no effective rules' } else { 'not readable' }))
  if ($umciOn -or $sacOn -or $alOn) {
    $sev = 'Info'; $mode = @()
    if ($umciOn) { $mode += ('WDAC ' + $ciLabel[$umci]) ; if ($umci -eq 1) { $sev = 'Low' } }
    if ($sacOn)  { $mode += ('Smart App Control ' + $sacLabel[[int]$sac]); if ($sac -eq 2) { $sev = 'Low' } }
    if ($alOn)   { $mode += 'AppLocker' }
    Add-Finding -Severity $sev -Category 'Hardening' -Title ("Application control present: {0}" -f ($mode -join ' + ')) `
      -Detail ($stateDetail + $(if ($sev -eq 'Low') { '. Audit/evaluation mode logs but does not block.' } else { '' })) `
      -Remediation $(if ($sev -eq 'Low') { 'Promote audit/evaluation to enforced once the allow list is validated.' } else { '' })
    if ($alOn -and $appLockerSvc -and $appLockerSvc.Status -ne 'Running') {
      Add-Finding -Severity Medium -Category 'Hardening' -Title 'AppLocker rules exist but AppIDSvc not running' `
        -Detail ($alCollections -join ', ') `
        -Remediation 'Set AppIDSvc to auto-start; rules without the service are inert.'
    }
  }
  else {
    Add-Finding -Severity High -Category 'Hardening' -Title 'No application control (WDAC user-mode, Smart App Control and AppLocker all off)' `
      -Detail ($stateDetail + '. Everything this report lists as persistence/privexec runs because nothing blocks unsigned execution.') `
      -Remediation 'Golden-image item: deploy WDAC (audit -> enforce) or AppLocker baseline rules (EXE/DLL/Script/MSI); on unmanaged Win11, Smart App Control. Single highest-value hardening control.'
  }
} catch {
  Add-Finding -Severity Info -Category 'Hardening' -Title 'Application control state not assessed' -Detail ('Read failed: ' + $_.Exception.Message)
}

# --- SmartScreen (policy first, Explorer value as fallback) ---
try {
  $ssPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
  $polEnable = if ($ssPol) { $ssPol.EnableSmartScreen } else { $null }
  $polLevel = if ($ssPol) { "$($ssPol.ShellSmartScreenLevel)" } else { '' }
  $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
  $ssVal = "$($ss.SmartScreenEnabled)"
  if ($polEnable -eq 0) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen disabled by policy (EnableSmartScreen=0)' `
      -Evidence 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System::EnableSmartScreen' `
      -Remediation 'Set "Configure Windows Defender SmartScreen" to Enabled with "Warn and prevent bypass" (CIS 18.10.76.2.1).'
  }
  elseif ($polEnable -eq 1) {
    $sev = if ($polLevel -eq 'Block') { 'Info' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'Hardening' -Title ("SmartScreen enforced by policy (level: {0})" -f $(if ($polLevel) { $polLevel } else { 'not set = Warn' })) `
      -Remediation $(if ($sev -eq 'Low') { 'Set ShellSmartScreenLevel=Block ("Warn and prevent bypass") so users cannot click through.' } else { '' })
  }
  elseif ($ssVal -eq 'Off') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen OFF (machine Explorer setting, no policy)' `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer::SmartScreenEnabled' `
      -Remediation 'Set SmartScreenEnabled=Warn/Block, or enforce it by policy (EnableSmartScreen=1, ShellSmartScreenLevel=Block).'
  }
  elseif ($ssVal) {
    Add-Finding -Severity Info -Category 'Hardening' -Title "SmartScreen: $ssVal (Explorer setting, not enforced by policy)"
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'SmartScreen not configured by policy or Explorer value (OS default Warn; user-changeable)' `
      -Remediation 'Enforce by policy so users cannot turn it off (EnableSmartScreen=1, ShellSmartScreenLevel=Block).'
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

# (Legacy optional features - Telnet, TFTP, PowerShell v2, SMB1 - are reported once, in the
#  OS Vulnerability section, which also says "not assessed" when not elevated.)

# --- Local admin RDP membership recap (image hygiene) ---
try {
  $adm = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
  if ($adm.Count -gt 3) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} local Administrators - trim the image baseline" -f $adm.Count)
  }
} catch { }

# --- Null sessions / registry remote access ---
# An absent value means the OS default, and the default is evaluated: RestrictAnonymous
# defaults to 0 (fails CIS 2.3.10.2), RestrictAnonymousSAM to 1, EveryoneIncludesAnonymous
# to 0, AutoShare* to 1. RemoteRegistry Start defaults to 3 (Manual, trigger-started) on
# client SKUs, which is Low; 2 (Automatic) is Medium; absent means the service is not installed.
try {
  $isClientSku = $true
  try { $isClientSku = ([int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 1) } catch { }
  $nullChecks = @(
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous';         Want = 1; Default = 0; Sev = 'Medium'; Ref = 'CIS 2.3.10.2: anonymous enumeration of SAM accounts and shares' }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM';      Want = 1; Default = 1; Sev = 'Medium'; Ref = 'CIS 2.3.10.1: anonymous enumeration of SAM accounts' }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Want = 0; Default = 0; Sev = 'Medium'; Ref = 'CIS 2.3.10.4: Everyone permissions apply to anonymous users' }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks';    Want = 0; Default = 1; Sev = 'Low'; Ref = 'default admin shares C$/ADMIN$ (client SKU)'; OnlyClient = $true }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Want = 0; Default = 1; Sev = 'Low'; Ref = 'default admin shares C$/ADMIN$ (server SKU)'; OnlyServer = $true }
  )
  foreach ($rk in $nullChecks) {
    if ($rk.OnlyClient -and -not $isClientSku) { continue }
    if ($rk.OnlyServer -and $isClientSku) { continue }
    $v = (Get-ItemProperty $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue).($rk.Name)
    $eff = if ($null -eq $v) { [int]$rk.Default } else { [int]$v }
    $src = if ($null -eq $v) { 'absent = OS default ' + $rk.Default } else { "$v" }
    if ($eff -ne [int]$rk.Want) {
      Add-Finding -Severity $rk.Sev -Category 'Hardening' -Title ("{0} = {1} (hardening wants {2})" -f $rk.Name, $src, $rk.Want) `
        -Detail $rk.Ref `
        -Evidence ("{0}::{1}" -f $rk.Key, $rk.Name) `
        -Remediation ("Set {0}={1} in the image (null-session / default-share hardening)." -f $rk.Name, $rk.Want)
    }
  }
  $rrStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' -Name Start -ErrorAction SilentlyContinue).Start
  if ($null -ne $rrStart -and [int]$rrStart -ne 4) {
    $rrSev = if ([int]$rrStart -eq 2) { 'Medium' } else { 'Low' }
    Add-Finding -Severity $rrSev -Category 'Hardening' -Title ("RemoteRegistry service Start = {0} (hardening wants 4 = Disabled)" -f $rrStart) `
      -Detail $(if ([int]$rrStart -eq 2) { 'Automatic start: remote registry reads/writes are available to any authenticated admin, and to attackers with a stolen admin credential.' } else { 'Manual (trigger-started) is the client default; it still starts on demand for remote registry access.' }) `
      -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry::Start' `
      -Remediation 'Set the Remote Registry service to Disabled (CIS 5.x) unless a management tool needs it.'
  }
} catch { }
