
######################## ADVANCED PERSISTENCE + OBFUSCATION ########################
# Local reads only (registry, WMI, local files). No packets are sent to any host.
# Checks that duplicate 22_privesc (service binary ACLs) and 30_hardening
# (IFEO Debugger / SilentProcessExit) are deliberately NOT repeated here.

Start-Section 'ADVANCED PERSISTENCE + OBFUSCATION DETECTION'

# Shared indicator pattern: interpreter + encoded/download/reflective-load tradecraft.
$script:ObfPattern = '(?i)(?:\B-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,})|IEX\s*\(|Invoke-Expression|FromBase64String|DownloadString|DownloadFile|Net\.WebClient|Reflection\.Assembly\]::Load|scrobj\.dll|RunHTMLApplication|(?:certutil|bitsadmin).*(?:-decode|-urlcache)'

# --- UAC bypass registry residue -------------------------------------------------
# fodhelper/computerdefaults/sdclt auto-elevate and read these HKCU class keys.
# Presence on a fleet image means the bypass was run here.
$uacBypassKeys = @(
  @{ Key = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'; Name = 'fodhelper / computerdefaults (ms-settings)' }
  @{ Key = 'HKCU:\Software\Classes\mscfile\Shell\Open\command'; Name = 'eventvwr / mmc (mscfile)' }
  @{ Key = 'HKCU:\Software\Classes\exefile\Shell\Open\command'; Name = 'exefile association hijack' }
  @{ Key = 'HKCU:\Software\Classes\Applications\powershell.exe\shell\open\command'; Name = 'PowerShell application hijack' }
  @{ Key = 'HKCU:\Software\Classes\Folder\shell\Open\command'; Name = 'Folder class hijack' }
  @{ Key = 'HKCU:\Software\Classes\Drive\shell\Open\command'; Name = 'Drive class hijack (sdclt)' }
  @{ Key = 'HKCU:\Software\Classes\Launcher.SystemSettings\shell\open\command'; Name = 'SystemSettings launcher hijack' }
)
foreach ($u in $uacBypassKeys) {
  if (-not (Test-Path $u.Key)) { continue }
  $props = Get-ItemProperty $u.Key -ErrorAction SilentlyContinue
  $val = $props.'(default)'
  $hasDelegate = $props -and ($props.PSObject.Properties.Name -contains 'DelegateExecute')
  # DelegateExecute set to an EMPTY string is the actual bypass trigger, so its
  # mere presence matters even when the default value is blank.
  if ($val -or $hasDelegate) {
    Add-Finding -Severity Critical -Category 'Persistence' -Title ("UAC bypass registry residue: {0}" -f $u.Name) `
      -Detail ("Key: {0} | Command: {1} | DelegateExecute present: {2} - auto-elevates via a trusted signed binary (MITRE T1548.002)." -f $u.Key, $val, $hasDelegate) `
      -Evidence $u.Key `
      -Remediation 'Delete the key. These HKCU class overrides have no legitimate use; presence on a golden image indicates prior compromise.'
  }
}

# --- File-association / ProgID hijack --------------------------------------------
# Targeted ProgID list rather than enumerating HKLM:\Software\Classes (~7,000
# subkeys). The old sweep took the first 500 alphabetically, which is all
# dot-extensions - it never actually reached exefile/htafile/piffile.
$progIdDefaults = @{
  'exefile'  = '"%1" %*'
  'comfile'  = '"%1" %*'
  'batfile'  = '"%1" %*'
  'cmdfile'  = '"%1" %*'
  'piffile'  = '"%1" %*'
  'scrfile'  = '"%1" /S'
}
$progIdWatch = @('exefile', 'comfile', 'batfile', 'cmdfile', 'piffile', 'scrfile', 'htafile', 'txtfile', 'regfile', 'Folder', 'Directory', 'Drive')
foreach ($hive in @('HKLM:\Software\Classes', 'HKCU:\Software\Classes')) {
  foreach ($progId in $progIdWatch) {
    $cmdKey = Join-Path $hive "$progId\shell\open\command"
    if (-not (Test-Path $cmdKey)) { continue }
    $val = "$((Get-ItemProperty $cmdKey -ErrorAction SilentlyContinue).'(default)')"
    if (-not $val) { continue }
    if ($val -match $script:ObfPattern) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("File-association hijacked with obfuscated command: {0}" -f $progId) `
        -Detail ("Key: {0} | Command: {1} - every launch of this file type runs attacker code." -f $cmdKey, $val) `
        -Evidence $cmdKey `
        -Remediation ('Restore the default handler for {0} and hunt for the dropper that set it.' -f $progId)
    }
    elseif ($progIdDefaults.ContainsKey($progId) -and $val -ne $progIdDefaults[$progId]) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("Non-default handler for {0}" -f $progId) `
        -Detail ("Key: {0} | Command: {1} | Expected: {2}" -f $cmdKey, $val, $progIdDefaults[$progId]) `
        -Evidence $cmdKey `
        -Remediation ('Executable-class handlers should be exactly {0}. Anything else intercepts every execution of that type.' -f $progIdDefaults[$progId])
    }
  }
}

# --- Service recovery command ----------------------------------------------------
# NOTE: service BINARY ACLs are already covered in 22_privesc with per-path
# dedup; re-checking them here would re-ACL System32 hundreds of times.
try {
  foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
    $fc = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -Name FailureCommand -ErrorAction SilentlyContinue).FailureCommand
    if (-not $fc) { continue }
    # Only flag genuine tradecraft or binaries outside protected dirs. The old
    # logic flagged anything not starting with %SystemRoot%, which fired on
    # every legitimate vendor recovery script.
    $isObf = $fc -match $script:ObfPattern
    $isOutside = $fc -notmatch '(?i)^"?(%SystemRoot%|C:\\Windows|C:\\Program Files)'
    if ($isObf -or $isOutside) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("Service recovery command is non-standard: {0}" -f $s.Name) `
        -Detail ("FailureCommand: {0} - runs as SYSTEM when the service crashes, so an attacker can trigger it on demand." -f $fc) `
        -Evidence ("HKLM\SYSTEM\CurrentControlSet\Services\{0}" -f $s.Name) `
        -Remediation 'A legitimate recovery action should be a signed binary under Windows or Program Files, never an inline interpreter command.'
    }
  }
} catch { }

# --- AMSI provider state ---------------------------------------------------------
# Providers are SUBKEYS (CLSIDs) under ...\AMSI\Providers - not values on the
# AMSI key itself. Reading values of the parent key never matched anything.
try {
  $amsiProviders = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue)
  if ($amsiProviders.Count -eq 0) {
    Add-Finding -Severity High -Category 'Obfuscation' -Title 'No AMSI providers registered' `
      -Detail 'AMSI feeds PowerShell/VBS/JS content to the AV engine at runtime. With no provider registered, script content is never scanned.' `
      -Remediation 'Expect at least the Defender provider {2781761E-28E0-4109-99FE-B9D127C57AFE}. Investigate why it was removed.'
  }
  else {
    $resolved = foreach ($p in $amsiProviders) {
      $clsid = $p.PSChildName
      $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
      # Defender's own provider (MpOav.dll) ships from the versioned platform
      # directory under ProgramData, which is ACL-protected - treat it as trusted.
      if ($dll -and $dll -notmatch '(?i)^"?(C:\\Windows|C:\\Program Files|%ProgramFiles%|C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\)') {
        Add-Finding -Severity Critical -Category 'Obfuscation' -Title ("AMSI provider DLL outside protected path: {0}" -f $clsid) `
          -Detail ("DLL: {0} - a rogue AMSI provider can silently pass all content as clean." -f $dll) `
          -Evidence $clsid `
          -Remediation 'Remove the provider registration and investigate the DLL.'
      }
      ("{0}{1}" -f $clsid, $(if ($dll) { " -> $dll" } else { '' }))
    }
    Add-Finding -Severity Info -Category 'Obfuscation' -Title ("{0} AMSI provider(s) registered" -f $amsiProviders.Count) `
      -Detail (($resolved | Select-Object -First 5) -join ' | ')
  }
  if (Test-Path 'HKCU:\SOFTWARE\Microsoft\AMSI\Providers') {
    Add-Finding -Severity High -Category 'Obfuscation' -Title 'AMSI provider override present in HKCU' `
      -Detail 'Per-user AMSI provider registration is not a supported configuration and can redirect scanning for the current user.' `
      -Remediation 'Delete HKCU\SOFTWARE\Microsoft\AMSI and investigate.'
  }
} catch { }

# --- Encoded / obfuscated PowerShell in console history --------------------------
# Current user's history only; other users' history needs elevation and is
# covered by the history module.
try {
  $histPath = $null
  try { $histPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath } catch { }
  if (-not $histPath) {
    # PSReadLine is not loaded in non-interactive hosts, so fall back to the
    # documented default location rather than skipping the check entirely.
    $histPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
  }
  if (Test-Path $histPath) {
    $hits = New-Object System.Collections.Generic.List[string]
    $ln = 0
    foreach ($line in (Get-Content $histPath -ErrorAction SilentlyContinue)) {
      $ln++
      if ($line -match $script:ObfPattern) { $hits.Add("line ${ln}: $(Get-Redacted $line)") }
      if ($hits.Count -ge 8) { break }
    }
    if ($hits.Count -gt 0) {
      Add-Finding -Severity High -Category 'Obfuscation' -Title ("Obfuscated/encoded PowerShell in console history ({0} hits)" -f $hits.Count) `
        -Detail ($hits -join ' | ') `
        -Evidence $histPath `
        -Remediation 'Investigate each hit. Encoded commands plus IEX/DownloadString is the signature of fileless tooling; rotate any credentials that were in scope.'
    }
  }
} catch { }

# --- Scheduled task tradecraft ---------------------------------------------------
try {
  $allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
  foreach ($t in $allTasks) {
    foreach ($a in @($t.Actions)) {
      if (-not $a.Execute) { continue }
      $cmd = ("{0} {1}" -f $a.Execute, $a.Arguments).Trim()
      # Scan EVERY task, including \Microsoft\* - masquerading into the Microsoft
      # task tree is exactly where fileless persistence hides, so excluding it
      # would blind the check at its most important target.
      if ($cmd -match $script:ObfPattern) {
        Add-Finding -Severity High -Category 'Obfuscation' -Title ("Scheduled task with obfuscated command: {0}" -f $t.TaskName) `
          -Detail ("Path: {0} | Command: {1} | State: {2}" -f $t.TaskPath, (Get-Redacted $cmd), $t.State) `
          -Evidence ("{0}{1}" -f $t.TaskPath, $t.TaskName) `
          -Remediation 'Investigate. Encoded PowerShell or regsvr32+scrobj.dll in a task is classic fileless persistence (T1053.005 / T1218).'
      }
      # User-writable binary path only matters for non-Microsoft tasks; the
      # in-box tasks all live under System32 by definition.
      if ($t.TaskPath -notlike '\Microsoft*') {
        $exe = ($a.Execute -replace '"', '')
        if ($exe -match '(?i)^[A-Z]:\\(ProgramData|Users\\[^\\]+\\AppData|Temp|Public)') {
          Add-Finding -Severity High -Category 'Masquerading' -Title ("Task binary in user-writable path: {0}" -f $t.TaskName) `
            -Detail ("Path: {0} - an executable in a user-writable directory can be swapped without touching the task definition." -f $exe) `
            -Evidence $exe `
            -Remediation 'Relocate the binary under Program Files, or validate it against the authorized task baseline.'
        }
      }
    }
  }
} catch { }

# --- Process masquerading --------------------------------------------------------
try {
  $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
  # explorer.exe legitimately lives in C:\Windows, NOT System32 - checking it
  # against the System32 rule flags every healthy desktop as compromised.
  $coreRe = '^(svchost|lsass|csrss|winlogon|smss|services|spoolsv)\.exe$'
  foreach ($p in @($procs | Where-Object {
        $_.ExecutablePath -and (
          ($_.Name -match $coreRe -and $_.ExecutablePath -notmatch '(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)\\') -or
          ($_.Name -match '^explorer\.exe$' -and $_.ExecutablePath -notmatch '(?i)^C:\\Windows\\(explorer\.exe|SysWOW64\\|WinSxS\\)')
        )
      } | Select-Object -First 10)) {
    Add-Finding -Severity Critical -Category 'Masquerading' -Title ("{0} running from non-standard path" -f $p.Name) `
      -Detail ("Path: {0} | PID: {1} - a core Windows binary outside System32/SysWOW64 is T1036 masquerading." -f $p.ExecutablePath, $p.ProcessId) `
      -Evidence $p.ExecutablePath `
      -Remediation 'Isolate the host and investigate. Genuine svchost/lsass/csrss always run from System32.'
  }
  foreach ($c in @($procs | Where-Object {
        $_.Name -match '^(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32)\.exe$' -and
        $_.CommandLine -match $script:ObfPattern
      } | Select-Object -First 5)) {
    $parent = $procs | Where-Object { $_.ProcessId -eq $c.ParentProcessId } | Select-Object -First 1
    Add-Finding -Severity High -Category 'Obfuscation' -Title ("Obfuscated command line running now: {0} (PID {1})" -f $c.Name, $c.ProcessId) `
      -Detail ("Parent: {0} (PID {1}) | Command redacted: {2}" -f $(if ($parent) { $parent.Name } else { 'unknown' }), $c.ParentProcessId, (Get-Redacted $c.CommandLine)) `
      -Remediation 'Investigate the parent. Encoded PowerShell spawned by Office or a browser is a live fileless attack.'
  }
  if (-not $script:IsElevated) {
    Add-Finding -Severity Low -Category 'Masquerading' -Title 'Process command lines only partly visible (needs elevation)' `
      -Detail 'Without administrator rights, ExecutablePath and CommandLine are hidden for processes owned by other users, so masquerading in those processes is not assessed.' `
      -Remediation 'Re-run elevated for full process-level coverage.'
  }
} catch { }

# --- Scheduled task file baseline ------------------------------------------------
# Reading System32\Tasks needs elevation; a non-elevated run returns 0 files,
# which must not be reported as "0 tasks present".
if ($script:IsElevated) {
  try {
    $taskCount = @(Get-ChildItem 'C:\Windows\System32\Tasks' -Recurse -File -ErrorAction SilentlyContinue).Count
    Add-Finding -Severity Info -Category 'Persistence' -Title ("{0} scheduled task definition files on disk" -f $taskCount) `
      -Detail 'Counted recursively under C:\Windows\System32\Tasks.' `
      -Remediation 'Baseline this count on the golden image; an unexplained increase means new tasks were registered.'
  } catch { }
}
else {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Scheduled task file baseline not assessed (needs elevation)' `
    -Detail 'C:\Windows\System32\Tasks is not readable without administrator rights.'
}
