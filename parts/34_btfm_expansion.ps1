
######################## EXTENDED PERSISTENCE & HARDENING ########################
# Persistence slots and hardening values drawn from the Blue Team Field Manual.
# Local reads only: registry, local files, local firewall/event-log config.
# Nothing is sent to any host. Elevation-gated checks say so rather than
# reporting a clean result they could not actually verify.

Start-Section 'EXTENDED PERSISTENCE & HARDENING BASELINE'

# Shared helper: SHA-256 a suspect binary so a finding carries an IOC that can be
# matched against threat intel later. Bounded and failure-tolerant by design.
function Get-SuspectHash {
  param([string]$Path)
  try {
    if (-not $Path) { return $null }
    $p = $Path.Trim('"')
    # Strip trailing arguments from a command string to reach the binary itself.
    if ($p -match '^(.*?\.(exe|dll|bat|cmd|scr|com))\b') { $p = $Matches[1] }
    $p = [System.Environment]::ExpandEnvironmentVariables($p)
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $p).Length -gt 100MB) { return 'skipped (>100MB)' }
    return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
  } catch { return $null }
}

# --- Legacy and policy Run keys -------------------------------------------------
# The Run/RunOnce pair is already covered in 22_privesc. These are the sibling
# keys that still execute on modern Windows but are rarely inspected.
$extraRunKeys = @(
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'; Note = 'RunOnceEx executes via a DLL/entry list and is commonly missed by autoruns review' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'; Note = 'RunOnceEx executes via a DLL/entry list and is commonly missed by autoruns review' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Note = 'Policy-based Run key, separate from the standard Run key and often unaudited' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Note = 'Policy-based Run key, separate from the standard Run key and often unaudited' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'; Note = 'Shell service objects load into explorer.exe at logon' }
)
# WebCheck ships with Windows and is present on every install, so flagging it
# would put a High finding on every clean host.
$shellObjDefaults = @('webcheck')
foreach ($k in $extraRunKeys) {
  if (-not (Test-Path $k.Path)) { continue }
  $props = Get-ItemProperty $k.Path -ErrorAction SilentlyContinue
  if (-not $props) { continue }
  foreach ($v in $props.PSObject.Properties) {
    if ($v.Name -like 'PS*' -or -not $v.Value) { continue }
    if ($k.Path -match 'ShellServiceObjectDelayLoad' -and $shellObjDefaults -contains $v.Name.ToLower()) {
      Add-Finding -Severity Info -Category 'Persistence' -Title ('ShellServiceObjectDelayLoad at expected default ({0})' -f $v.Name)
      continue
    }
    $hash = Get-SuspectHash ([string]$v.Value)
    Add-Finding -Severity High -Category 'Persistence' -Title ('Autostart entry in {0}' -f ($k.Path -replace '^HK(LM|CU):\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\', '')) `
      -Detail ('{0} = {1} || {2}' -f $v.Name, $v.Value, $k.Note) `
      -Evidence ('{0} :: {1}{2}' -f $k.Path, $v.Name, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
      -Remediation 'Validate against the golden image. These legacy and policy autostart keys are rarely used legitimately, so any entry deserves attribution.'
  }
}

# --- HKCU\Environment: logon script and PATH hijack -----------------------------
# UserInitMprLogonScript runs at every logon of this user (MITRE T1037.001) and
# is a per-user key, so it never appears in a machine-wide autoruns audit.
$envKey = 'HKCU:\Environment'
$envProps = Get-ItemProperty $envKey -ErrorAction SilentlyContinue
if ($envProps) {
  $logonScript = $envProps.UserInitMprLogonScript
  if ($logonScript) {
    $hash = Get-SuspectHash ([string]$logonScript)
    Add-Finding -Severity Critical -Category 'Persistence' -Title 'Logon script set in HKCU\Environment (UserInitMprLogonScript)' `
      -Detail ('Command: {0} || Runs at every logon of this user. This value has no default and no common legitimate use.' -f $logonScript) `
      -Evidence ('{0} :: UserInitMprLogonScript{1}' -f $envKey, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
      -Remediation 'Delete the value and investigate the referenced command. MITRE T1037.001.'
  }
  # A user-writable directory placed early in the user PATH lets an attacker
  # shadow a system binary invoked without a full path.
  $userPath = $envProps.Path
  if ($userPath) {
    $risky = @($userPath -split ';' | Where-Object { $_ -and ($_ -match '(?i)(AppData|\\Temp\\|\\Public\\|Downloads|ProgramData)') })
    if ($risky.Count -gt 0) {
      Add-Finding -Severity Medium -Category 'Persistence' -Title ('User PATH contains {0} user-writable director(ies)' -f $risky.Count) `
        -Detail ('Entries: ' + ($risky -join ' | ') + ' || A writable directory on PATH can shadow a system binary called without a full path.') `
        -Evidence "$envKey :: Path" `
        -Remediation 'Remove user-writable directories from PATH, or confirm each is intentional and access-controlled.'
    }
  }
}

# --- HKCU Windows: Load / Run legacy values -------------------------------------
$winKey = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$winProps = Get-ItemProperty $winKey -ErrorAction SilentlyContinue
if ($winProps) {
  foreach ($n in @('Load', 'Run', 'Scripts')) {
    $val = $winProps.$n
    if ($val) {
      $hash = Get-SuspectHash ([string]$val)
      Add-Finding -Severity High -Category 'Persistence' -Title ('Legacy {0} value set in HKCU Windows NT key' -f $n) `
        -Detail ('{0} = {1} || A 16-bit-era autostart slot that modern Windows still honours and modern tooling rarely inspects.' -f $n, $val) `
        -Evidence ('{0} :: {1}{2}' -f $winKey, $n, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
        -Remediation 'Clear the value unless a documented legacy application requires it.'
    }
  }
}

# --- Group Policy logon/startup scripts -----------------------------------------
foreach ($sp in @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts',
    'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts')) {
  if (-not (Test-Path $sp)) { continue }
  $scriptCount = @(Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue).Count
  if ($scriptCount -gt 0) {
    Add-Finding -Severity Info -Category 'Persistence' -Title ('{0} policy script entr(ies) registered' -f $scriptCount) `
      -Detail ('Under {0}. Policy-delivered logon/logoff/startup scripts run automatically; confirm each maps to a known GPO.' -f $sp) `
      -Evidence $sp `
      -Remediation 'Cross-check against the GPOs that should apply to this host. An entry with no matching GPO is persistence.'
  }
}

# --- Session Manager: BootExecute and KnownDLLs ---------------------------------
$smKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$sm = Get-ItemProperty $smKey -ErrorAction SilentlyContinue
if ($sm) {
  # BootExecute runs before any security product initialises.
  $boot = @($sm.BootExecute | Where-Object { $_ })
  $bootExtra = @($boot | Where-Object { $_ -notmatch '^autocheck\s+autochk\s+\*?$' })
  if ($bootExtra.Count -gt 0) {
    Add-Finding -Severity High -Category 'Persistence' -Title 'Non-default BootExecute entry' `
      -Detail ('BootExecute: ' + ($boot -join ' | ') + ' || Expected only "autocheck autochk *". These run during boot before security controls load.') `
      -Evidence "$smKey :: BootExecute" `
      -Remediation 'Remove unrecognised entries. Legitimate additions are rare and usually come from disk or encryption tooling.'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'BootExecute at expected default'
  }
}

# KnownDLLs is the trusted preload set; an added entry is loaded by every process
# that resolves that name. A NAME baseline is unreliable here because the set
# varies by Windows version and architecture (the xtajit* x86-on-ARM64 emulation
# DLLs, for example), so validate what each entry RESOLVES TO instead: the target
# must exist in System32 and carry a valid Microsoft signature.
$kdKey = "$smKey\KnownDLLs"
if (Test-Path $kdKey) {
  $kd = Get-ItemProperty $kdKey -ErrorAction SilentlyContinue
  $entries = @($kd.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -notmatch '^DllDirectory(32)?$' })
  $bad = New-Object System.Collections.Generic.List[string]
  foreach ($e in $entries) {
    $dllName = "$($e.Value)"
    if (-not $dllName) { continue }
    if ($dllName -notmatch '\.dll$') { $dllName += '.dll' }
    $target = Join-Path $env:SystemRoot "System32\$dllName"
    if (-not (Test-Path -LiteralPath $target)) {
      # Architecture-specific entries legitimately absent on this build are not
      # a finding; only a resolvable-but-untrusted target is.
      continue
    }
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
      if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
        $bad.Add("$($e.Name) -> $dllName (signature: $($sig.Status))")
      }
    } catch { }
  }
  if ($bad.Count -gt 0) {
    Add-Finding -Severity High -Category 'Persistence' -Title ('{0} KnownDLLs entr(ies) resolve to a non-Microsoft-signed DLL' -f $bad.Count) `
      -Detail (($bad -join ' | ') + ' || Every process resolving these names loads the target.') `
      -Evidence $kdKey `
      -Remediation 'Investigate the target DLL immediately and compare the KnownDLLs list against a clean build of the same Windows version and architecture.'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title ('KnownDLLs entries all resolve to Microsoft-signed DLLs ({0} entries)' -f $entries.Count) `
      -Detail 'Validated by signature rather than by name, since the expected name set varies across Windows versions and architectures.'
  }
}

# --- Browser Helper Objects ------------------------------------------------------
# A 32/64-bit BHO is legitimately registered under both the native and
# Wow6432Node paths, so collect by CLSID and report each one once.
$bhoSeen = @{}
foreach ($bhoPath in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')) {
  if (-not (Test-Path $bhoPath)) { continue }
  foreach ($bho in (Get-ChildItem $bhoPath -ErrorAction SilentlyContinue)) {
    $clsid = $bho.PSChildName
    if (-not $bhoSeen.ContainsKey($clsid)) { $bhoSeen[$clsid] = @{ Hives = @(); Dll = $null } }
    $bhoSeen[$clsid].Hives += $(if ($bhoPath -match 'Wow6432Node') { 'Wow6432Node' } else { 'native' })
  }
}
foreach ($clsid in $bhoSeen.Keys) {
  $dll = $null
  foreach ($c in @("HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32", "HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID\$clsid\InprocServer32")) {
    if (Test-Path $c) { $dll = (Get-ItemProperty $c -ErrorAction SilentlyContinue).'(default)'; if ($dll) { break } }
  }
  $outside = $dll -and ($dll -notmatch '(?i)^"?(C:\\Windows|C:\\Program Files)')
  $hash = if ($dll) { Get-SuspectHash ([string]$dll) } else { $null }
  Add-Finding -Severity $(if ($outside) { 'High' } else { 'Low' }) -Category 'Persistence' -Title ("Browser Helper Object registered: {0}" -f $clsid) `
    -Detail ('DLL: {0} | Registered: {1}{2}' -f $(if ($dll) { $dll } else { 'unresolved' }), (($bhoSeen[$clsid].Hives | Sort-Object -Unique) -join ' + '), $(if ($outside) { ' || Loads from outside Windows/Program Files.' } else { '' })) `
    -Evidence ('{0}{1}' -f $clsid, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
    -Remediation 'BHOs load into Internet Explorer and some shell hosts. Remove any that do not map to installed, expected software.'
}

# --- Accessibility binary hijack -------------------------------------------------
# sethc.exe / utilman.exe are reachable from the logon screen before authentication,
# which is what makes replacing them a full pre-auth SYSTEM backdoor.
foreach ($acc in @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'DisplaySwitch.exe', 'AtBroker.exe', 'Narrator.exe')) {
  $accPath = Join-Path $env:SystemRoot "System32\$acc"
  if (-not (Test-Path $accPath)) { continue }
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $accPath -ErrorAction Stop
    $ok = $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft'
    if (-not $ok) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Accessibility binary is not validly Microsoft-signed: {0}" -f $acc) `
        -Detail ('Path: {0} | Signature status: {1} | Signer: {2} || These binaries are launchable from the logon screen, so a replaced one is a pre-authentication SYSTEM backdoor.' -f $accPath, $sig.Status, $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'none' })) `
        -Evidence ('{0} :: SHA256 {1}' -f $accPath, (Get-SuspectHash $accPath)) `
        -Remediation 'Restore the original binary from a trusted source (sfc /scannow or the install media) and investigate how it was replaced. MITRE T1546.008.'
    }
  } catch { }
}

# --- Legacy startup files --------------------------------------------------------
$legacyFiles = @(
  @{ Path = "$env:SystemRoot\winstart.bat"; Note = 'Legacy batch autostart' }
  @{ Path = "$env:SystemRoot\wininit.ini"; Note = 'Legacy init file, historically used for file replacement at boot' }
  @{ Path = "$env:SystemDrive\Autoexec.bat"; Note = 'Legacy DOS autostart' }
  @{ Path = "$env:SystemRoot\System32\autoexec.nt"; Note = 'NTVDM autostart' }
)
foreach ($lf in $legacyFiles) {
  if (-not (Test-Path $lf.Path)) { continue }
  $len = (Get-Item $lf.Path -ErrorAction SilentlyContinue).Length
  Add-Finding -Severity $(if ($len -gt 0) { 'Medium' } else { 'Low' }) -Category 'Persistence' -Title ("Legacy startup file present: {0}" -f (Split-Path $lf.Path -Leaf)) `
    -Detail ('Path: {0} | Size: {1} bytes || {2}. Modern Windows does not create these.' -f $lf.Path, $len, $lf.Note) `
    -Evidence $lf.Path `
    -Remediation 'Inspect the contents. On a modern build these files are either vendor cruft or attacker-placed.'
}
# win.ini still honours run= and load= in its [windows] section.
$winIni = "$env:SystemRoot\win.ini"
if (Test-Path $winIni) {
  $iniHits = @(Get-Content $winIni -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(run|load)\s*=\s*\S' })
  if ($iniHits.Count -gt 0) {
    Add-Finding -Severity High -Category 'Persistence' -Title 'win.ini contains a run= or load= directive' `
      -Detail (($iniHits | ForEach-Object { $_.Trim() }) -join ' | ') `
      -Evidence $winIni `
      -Remediation 'Blank the value. These directives still execute at logon and are almost never used legitimately.'
  }
}

# --- Firewall logging ------------------------------------------------------------
# Read via the local firewall provider, not netsh output parsing.
try {
  $profiles = Get-NetFirewallProfile -ErrorAction Stop
  foreach ($p in $profiles) {
    $gaps = @()
    if ($p.LogBlocked -ne 'True' -and $p.LogBlocked -ne $true) { $gaps += 'dropped packets not logged' }
    if ($p.LogAllowed -ne 'True' -and $p.LogAllowed -ne $true) { $gaps += 'allowed connections not logged' }
    if ($gaps.Count -gt 0) {
      Add-Finding -Severity $(if ($p.Enabled -eq 'True' -or $p.Enabled -eq $true) { 'Medium' } else { 'Low' }) -Category 'Logging' -Title ("Firewall logging incomplete on {0} profile" -f $p.Name) `
        -Detail (($gaps -join '; ') + (' || Profile enabled: {0}; log file: {1}; max size: {2} KB' -f $p.Enabled, $p.LogFileName, $p.LogMaxSizeKilobytes)) `
        -Remediation ('Set-NetFirewallProfile -Profile {0} -LogBlocked True -LogAllowed True, and raise LogMaxSizeKilobytes. Without this there is no local record of blocked traffic.' -f $p.Name)
    }
    else {
      Add-Finding -Severity Info -Category 'Logging' -Title ("Firewall logging enabled on {0} profile" -f $p.Name) `
        -Detail ('Log file: {0} ({1} KB max)' -f $p.LogFileName, $p.LogMaxSizeKilobytes)
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Firewall logging configuration not assessed' `
    -Detail ('Get-NetFirewallProfile failed: ' + $_.Exception.Message)
}

# --- Application and System event log sizing ------------------------------------
# The Security log is covered in 20_system; these two are the other halves of a
# usable local forensic record.
foreach ($logName in @('Application', 'System')) {
  try {
    $lg = Get-WinEvent -ListLog $logName -ErrorAction Stop
    $mb = [math]::Round($lg.MaximumSizeInBytes / 1MB, 0)
    if ($mb -lt 64) {
      Add-Finding -Severity Medium -Category 'Logging' -Title ("{0} event log undersized ({1} MB)" -f $logName, $mb) `
        -Detail ('Retention: {0}. A small log rotates away the evidence window during an incident.' -f $lg.LogMode) `
        -Remediation ('Raise the {0} log to at least 64 MB, or forward events to a SIEM.' -f $logName)
    }
    else {
      Add-Finding -Severity Info -Category 'Logging' -Title ("{0} event log size {1} MB" -f $logName, $mb)
    }
  } catch {
    Add-Finding -Severity Info -Category 'Logging' -Title ("{0} event log configuration not assessed" -f $logName) `
      -Detail 'Reading the log configuration failed; size and retention are unknown, not confirmed adequate.'
  }
}

# --- IPv6 configuration ----------------------------------------------------------
$tcpip6 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -ErrorAction SilentlyContinue
$disabledComponents = if ($tcpip6 -and ($tcpip6.PSObject.Properties.Name -contains 'DisabledComponents')) { $tcpip6.DisabledComponents } else { $null }
Add-Finding -Severity Info -Category 'Hardening' -Title ('IPv6 DisabledComponents = {0}' -f $(if ($null -ne $disabledComponents) { '0x{0:X}' -f [int]$disabledComponents } else { 'not set (IPv6 fully enabled)' })) `
  -Detail 'Recorded for baseline comparison. IPv6 being enabled is not itself a finding, but an IPv6 stack nobody monitors is a blind spot for local discovery and rogue router advertisements.' `
  -Remediation 'If IPv6 is unused on this network, 0xFF disables it. If it is used, ensure RA guard and IPv6 monitoring exist. Decide deliberately rather than by default.'

# --- Scheduled task registry cache ----------------------------------------------
# TaskCache is the authoritative registry-side task list. A task present here but
# absent from Get-ScheduledTask is deliberately hidden.
if ($script:IsElevated) {
  try {
    $tcPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
    $cacheCount = @(Get-ChildItem $tcPath -ErrorAction SilentlyContinue).Count
    $apiCount = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
    if ($cacheCount -gt 0 -and $apiCount -gt 0 -and ($cacheCount - $apiCount) -gt 5) {
      Add-Finding -Severity High -Category 'Persistence' -Title 'Scheduled task registry cache exceeds the enumerable task list' `
        -Detail ('TaskCache registry entries: {0}; tasks returned by the scheduler API: {1}. A large gap can indicate tasks hidden by removing their security descriptor.' -f $cacheCount, $apiCount) `
        -Evidence $tcPath `
        -Remediation 'Compare the TaskCache GUIDs against the task list and investigate any that do not appear. Hidden tasks are a known persistence technique.'
    }
    else {
      Add-Finding -Severity Info -Category 'Persistence' -Title ('Scheduled task registry cache consistent ({0} cached / {1} enumerable)' -f $cacheCount, $apiCount)
    }
  } catch { }
}
else {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Scheduled task registry cache not assessed (needs elevation)' `
    -Detail 'TaskCache is not readable without administrator, so hidden-task detection could not run.'
}
