
######################## PRIVILEGE-ESCALATION SURFACE ########################

Start-Section 'PRIVILEGE-ESCALATION SURFACE'

# --- Local helpers for this section -------------------------------------------------
# Every helper here is read-only: it parses strings, reads ACLs and hashes files.

# Folder variant of Get-LowPrivWriteAce: an ACE that only allows creating
# subfolders (AppendData alone, "CreateSubfolders only") cannot plant a file in
# the folder, so it is not a hijack path and is skipped to keep noise down.
function Get-LowPrivFolderWriteAce {
  param($ACLObject)
  if (-not $ACLObject) { return $null }
  foreach ($ace in $ACLObject.Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    if ("$($ace.PropagationFlags)" -match 'InheritOnly') { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
    if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
    $rights = "$($ace.FileSystemRights)"
    if ($rights -notmatch 'FullControl|Modify|Write|CreateFiles|ChangePermissions|TakeOwnership') { continue }
    $level = if ($rights -match 'FullControl') { 'FullControl' } elseif ($rights -match 'Modify') { 'Modify' }
             elseif ($rights -match 'ChangePermissions|TakeOwnership') { 'ChangePermissions/TakeOwnership' } else { 'Write' }
    return [pscustomobject]@{ Name = $script:LowPrivSids[$sid]; Sid = $sid; Level = $level; Rights = $rights }
  }
  return $null
}

# SHA-256 of a binary referenced by a command string, for IOC matching. Bounded.
function Get-PrivEscFileHash {
  param([string]$Path)
  try {
    if (-not $Path) { return $null }
    $p = $Path.Trim().Trim('"')
    if ($p -match '^(.*?\.(exe|dll|bat|cmd|scr|com|ps1|vbs|js))\b') { $p = $Matches[1] }
    $p = [System.Environment]::ExpandEnvironmentVariables($p)
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $p).Length -gt 100MB) { return 'skipped (>100MB)' }
    return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
  } catch { return $null }
}

# Resolve the executable path out of a Win32_Service.PathName command string.
function Get-ServiceExePath {
  param([string]$PathName)
  if (-not $PathName) { return $null }
  $p = $PathName.Trim()
  if ($p.StartsWith('"')) {
    $end = $p.IndexOf('"', 1)
    $p = if ($end -gt 1) { $p.Substring(1, $end - 1) } else { $p.Trim('"') }
  }
  elseif ($p -match '^(.*?\.exe)(\s|$)') { $p = $Matches[1] }
  else { $p = ($p -split '\s+')[0] }
  $p = $p -replace '^\\\?\?\\', ''
  $p = $p -replace '^(?i)\\SystemRoot', $env:SystemRoot
  $p = [System.Environment]::ExpandEnvironmentVariables($p)
  if ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
  return $p
}

# SDDL service-right letters (two characters each). Hex masks are mapped to the same names.
$script:SvcSddlRightBits = [ordered]@{
  CC = [int64]1; DC = [int64]2; LC = [int64]4; SW = [int64]8
  RP = [int64]16; WP = [int64]32; DT = [int64]64; LO = [int64]128
  CR = [int64]256; SD = [int64]65536; RC = [int64]131072; WD = [int64]262144
  WO = [int64]524288; GA = [int64]268435456; GX = [int64]536870912; GW = [int64]1073741824; GR = [int64]2147483648
}
# Rights that let the trustee change what the service runs or who controls it.
$script:SvcSddlEscalationRights = @('DC', 'WD', 'WO', 'GA', 'GW')
# Two-letter SDDL trustees that are low-privilege principals.
$script:SvcSddlLowPrivTrustees = @{
  WD = 'S-1-1-0'; BU = 'S-1-5-32-545'; AU = 'S-1-5-11'; IU = 'S-1-5-4'
  AN = 'S-1-5-7'; BG = 'S-1-5-32-546'; NU = 'S-1-5-2'
}

# Parse the D: (DACL) part of a service SDDL string into one object per ACE.
# Pure string parsing, independent of OS language.
function ConvertFrom-ServiceSddlDacl {
  param([string]$Sddl)
  $result = New-Object System.Collections.Generic.List[object]
  if (-not $Sddl) { return $result }
  $s = ($Sddl -replace '\s', '')
  $dIdx = $s.IndexOf('D:')
  if ($dIdx -lt 0) { return $result }
  $dacl = $s.Substring($dIdx + 2)
  $sIdx = $dacl.IndexOf('S:')
  if ($sIdx -ge 0) { $dacl = $dacl.Substring(0, $sIdx) }
  foreach ($m in [regex]::Matches($dacl, '\(([^)]*)\)')) {
    $parts = $m.Groups[1].Value -split ';'
    if ($parts.Count -lt 6) { continue }
    $aceType = $parts[0]
    $rightsRaw = $parts[2]
    $trustee = $parts[5]
    $rightsList = New-Object System.Collections.Generic.List[string]
    if ($rightsRaw -match '^0x[0-9A-Fa-f]+$') {
      $mask = [Convert]::ToInt64($rightsRaw.Substring(2), 16)
      foreach ($k in $script:SvcSddlRightBits.Keys) {
        if (($mask -band $script:SvcSddlRightBits[$k]) -ne 0) { $rightsList.Add($k) }
      }
    }
    else {
      for ($i = 0; $i + 1 -lt $rightsRaw.Length; $i += 2) { $rightsList.Add($rightsRaw.Substring($i, 2).ToUpper()) }
    }
    $trusteeSid = $null
    if ($trustee -match '^S-1-') { $trusteeSid = $trustee }
    elseif ($script:SvcSddlLowPrivTrustees.ContainsKey($trustee)) { $trusteeSid = $script:SvcSddlLowPrivTrustees[$trustee] }
    $isLow = $false
    if ($script:SvcSddlLowPrivTrustees.ContainsKey($trustee)) { $isLow = $true }
    elseif ($trusteeSid -and $script:LowPrivSids -and $script:LowPrivSids.ContainsKey($trusteeSid)) { $isLow = $true }
    $esc = @($rightsList | Where-Object { $script:SvcSddlEscalationRights -contains $_ })
    $startStop = @($rightsList | Where-Object { $_ -in @('RP', 'WP', 'DT') })
    $result.Add([pscustomobject]@{
      AceType          = $aceType
      Trustee          = $trustee
      TrusteeSid       = $trusteeSid
      Rights           = ($rightsList -join '')
      RightsList       = @($rightsList)
      IsLowPriv        = $isLow
      EscalationRights = $esc
      IsEscalation     = ($aceType -eq 'A' -and $isLow -and $esc.Count -gt 0)
      IsStartStopOnly  = ($aceType -eq 'A' -and $isLow -and $esc.Count -eq 0 -and $startStop.Count -gt 0)
    })
  }
  return $result
}

# Service inventory, read once for every check in this section.
$script:PeasServices = @()
try { $script:PeasServices = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service inventory not assessed' `
    -Detail ('Get-CimInstance Win32_Service failed: ' + $_.Exception.Message)
}

# AlwaysInstallElevated
foreach ($hive in 'HKLM', 'HKCU') {
  $aie = (Get-ItemProperty "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($aie -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title "AlwaysInstallElevated=1 ($hive)" `
      -Detail 'Any MSI (including malicious) installs with SYSTEM privileges.' `
      -Remediation 'Set AlwaysInstallElevated=0 in both hives (or leave the policy undefined).'
  }
}

# Unquoted service paths. Only the part BEFORE the executable name matters: a
# path with no space followed by arguments (C:\tools\agent.exe --service) is fine.
$unquoted = @()
try {
  $unquoted = @($script:PeasServices | Where-Object {
    $_.PathName -and $_.PathName -notmatch '"' -and $_.PathName -inotmatch ':\\Windows\\' -and $_.State -in @('Running', 'Stopped')
  } | Where-Object {
    $head = if ($_.PathName -match '^(?i)(.*?\.exe)') { $Matches[1] } else { $_.PathName }
    $head -match '\s'
  })
} catch { }
if ($unquoted.Count -gt 0) {
  foreach ($s in ($unquoted | Select-Object -First 10)) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("Unquoted service path: {0}" -f $s.Name) `
      -Detail ("Path: {0} | StartMode: {1} | State: {2}" -f $s.PathName, $s.StartMode, $s.State) `
      -Remediation 'Wrap the service ImagePath in quotes; ensure parent directories are not user-writable.'
  }
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'No unquoted service paths outside Windows dirs'
}

# Weak ACLs on service binaries (attacker-writable = instant SYSTEM)
Write-Host '  Scanning service binary ACLs (this takes a moment)...' -ForegroundColor DarkGray
$UniqueServices = @{}
foreach ($svc in ($script:PeasServices | Where-Object { $_.PathName -like '*.exe*' })) {
  try {
    $Path = ($svc.PathName -split '(?<=\.exe\b)')[0].Trim('"')
    if ($Path -and -not $UniqueServices.ContainsKey($Path)) { $UniqueServices[$Path] = $svc.Name }
  } catch { }
}
foreach ($h in $UniqueServices.GetEnumerator()) {
  Start-ACLCheck -Target $h.Name -ServiceName $h.Value
}

# Service registry key write access, by SID (works on any OS language). No cap:
# hosts carry 600 to 800 service keys and a registry ACL read is cheap.
$svcKeyHits = 0
foreach ($svcKey in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\services' -ErrorAction SilentlyContinue)) {
  try {
    $target = $svcKey.Name.Replace('HKEY_LOCAL_MACHINE', 'hklm:')
    $acl = Get-Acl $target -ErrorAction SilentlyContinue
    if (-not $acl) { continue }
    $weak = Get-LowPrivWriteAce -ACLObject $acl
    if ($weak) {
      $svcKeyHits++
      if ($svcKeyHits -le 25) {
        Add-Finding -Severity High -Category 'PrivEsc' -Title ("Service registry key modifiable by low-privilege principal: {0}" -f $svcKey.PSChildName) `
          -Detail ("{0} grants {1} to {2} ({3}) - an editable ImagePath yields SYSTEM." -f $target, $weak.Rights, $weak.Name, $weak.Sid) `
          -Evidence $target `
          -Remediation 'Restrict the key to Administrators/SYSTEM.'
      }
    }
  } catch { continue }
}
if ($svcKeyHits -gt 25) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title ("{0} service registry keys are modifiable by low-privilege principals (first 25 listed)" -f $svcKeyHits)
}

# --- Service object DACL (sc.exe sdshow) -------------------------------------------
# The binary and registry ACLs above do not cover the SERVICE OBJECT itself. A
# low-privilege principal with SERVICE_CHANGE_CONFIG (DC), WRITE_DAC (WD),
# WRITE_OWNER (WO) or generic all/write can repoint the service binary and
# restart it as the service account. SDDL is not localized. Start/stop alone
# (RP/WP/DT) is not an escalation and is only counted. T1543.003, T1574.011.
Write-Host '  Reading service object DACLs via sc.exe sdshow (this takes a moment)...' -ForegroundColor DarkGray
try {
  $sdChecked = 0; $sdFailed = 0; $sdFlagged = 0; $sdStartStop = New-Object System.Collections.Generic.List[string]
  $sdExe = Join-Path $env:SystemRoot 'System32\sc.exe'
  if (-not (Test-Path $sdExe)) { $sdExe = 'sc.exe' }
  foreach ($svc in $script:PeasServices) {
    if (-not $svc.Name) { continue }
    $sddl = $null
    try {
      $out = & $sdExe sdshow "$($svc.Name)" 2>$null
      $sddl = (@($out) | Where-Object { $_ -match 'D:' } | Select-Object -First 1)
    } catch { $sddl = $null }
    if (-not $sddl) { $sdFailed++; continue }
    $sdChecked++
    $aces = ConvertFrom-ServiceSddlDacl -Sddl "$sddl"
    $bad = @($aces | Where-Object { $_.IsEscalation })
    $ss = @($aces | Where-Object { $_.IsStartStopOnly })
    if ($ss.Count -gt 0 -and $sdStartStop.Count -lt 50) { $sdStartStop.Add($svc.Name) }
    if ($bad.Count -eq 0) { continue }
    $sdFlagged++
    if ($sdFlagged -gt 25) { continue }
    $asSystem = ("$($svc.StartName)" -match '(?i)^(\.\\)?LocalSystem$|S-1-5-18$|NT AUTHORITY\\SYSTEM$')
    $sev = if ($asSystem) { 'Critical' } else { 'High' }
    $who = ($bad | ForEach-Object {
      $label = if ($script:SvcSddlLowPrivTrustees.ContainsKey($_.Trustee)) { '{0} ({1})' -f $_.Trustee, $_.TrusteeSid }
               elseif ($script:LowPrivSids.ContainsKey("$($_.TrusteeSid)")) { '{0} ({1})' -f $script:LowPrivSids[$_.TrusteeSid], $_.TrusteeSid }
               else { $_.Trustee }
      '{0}: {1} [{2}]' -f $label, $_.Rights, ($_.EscalationRights -join ',')
    }) -join ' | '
    Add-Finding -Severity $sev -Category 'PrivEsc' -Title ("Service DACL lets a low-privilege principal reconfigure service: {0}" -f $svc.Name) `
      -Detail ("Runs as: {0} | State: {1} | Binary: {2} | Weak ACEs: {3}. DC = change config (repoint the binary), WD = rewrite the DACL, WO = take ownership, GA/GW = generic all/write." -f $svc.StartName, $svc.State, $svc.PathName, $who) `
      -Evidence ("sc.exe sdshow {0} :: {1}" -f $svc.Name, $sddl) `
      -Remediation 'Reset the service security descriptor so only Administrators and SYSTEM hold DC/WD/WO (sc.exe sdset with the vendor default, or reinstall the service). MITRE T1543.003 / T1574.011.'
  }
  if ($sdFlagged -gt 25) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("{0} services have a low-privilege reconfigure right in their DACL (first 25 listed)" -f $sdFlagged)
  }
  if ($sdChecked -eq 0) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service object DACLs not assessed' `
      -Detail ('sc.exe sdshow returned no SDDL for any service ({0} services attempted).' -f $sdFailed)
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title ("Service object DACLs read for {0} services ({1} weak, {2} unreadable)" -f $sdChecked, $sdFlagged, $sdFailed) `
      -Detail $(if ($sdStartStop.Count -gt 0) { ('Low-privilege start/stop/pause rights (not an escalation on their own) on: ' + (($sdStartStop | Select-Object -First 15) -join ', ') + $(if ($sdStartStop.Count -gt 15) { ' ...' } else { '' })) } else { 'No low-privilege principal holds start/stop rights on any service.' })
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service object DACLs not assessed' `
    -Detail ('sc.exe sdshow sweep failed: ' + $_.Exception.Message)
}

# --- Service binary location, signature and svchost ServiceDll --------------------
# A service executable in a user-writable folder, or an unsigned third-party
# service binary, is the common shape of a malware service. Microsoft-signed
# binaries under the Windows directory are skipped. T1543.003.
try {
  $userDirRx = '(?i)^[A-Z]:\\(ProgramData|Users\\[^\\]+\\(AppData|Downloads)|Windows\\Temp|Temp|Users\\Public)'
  $binSeen = @{}
  $binFlagged = 0; $binChecked = 0; $binUnsigned = 0
  foreach ($svc in $script:PeasServices) {
    if (-not $svc.PathName) { continue }
    $exe = Get-ServiceExePath -PathName $svc.PathName
    if (-not $exe -or $binSeen.ContainsKey($exe.ToLower())) { continue }
    $binSeen[$exe.ToLower()] = $true
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
    $binChecked++
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop } catch { }
    $sigStatus = if ($sig) { "$($sig.Status)" } else { 'unknown' }
    $signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    $isMsSigned = ($sigStatus -eq 'Valid' -and $signer -match 'Microsoft')
    $inWindows = $exe -like "$env:SystemRoot\*"
    if ($isMsSigned -and $inWindows) { continue }
    $folder = Split-Path $exe -Parent
    $folderHit = $null
    try {
      $facl = Get-Acl -LiteralPath $folder -ErrorAction SilentlyContinue
      if ($facl) { $folderHit = Get-LowPrivFolderWriteAce -ACLObject $facl }
    } catch { }
    if ($folderHit -and $folder -like "$env:USERPROFILE*" -and $folderHit.Sid -eq $script:AclCurrent.User.Value) { $folderHit = $null }
    $inUserDir = ($exe -match $userDirRx)
    $unsigned = ($sigStatus -ne 'Valid')
    if ($unsigned) { $binUnsigned++ }
    # The ACL is the ground truth. A binary in a typically user-writable tree
    # (ProgramData, AppData, Temp, Public) whose folder ACL does NOT grant a
    # low-privilege write is only unusual placement: skipped when Microsoft-signed
    # (Defender Platform lives there), Low when validly signed by someone else.
    if ($inUserDir -and -not $folderHit -and $isMsSigned) { continue }
    if (-not $folderHit -and -not $inUserDir -and -not $unsigned) { continue }
    $sev = if ($folderHit) { 'High' } elseif ($unsigned) { $(if ($inUserDir) { 'Medium' } else { 'Low' }) } else { 'Low' }
    $why = @()
    if ($folderHit) { $why += ('folder writable by {0} ({1}: {2})' -f $folderHit.Name, $folderHit.Sid, $folderHit.Level) }
    if ($inUserDir) { $why += $(if ($folderHit) { 'lives in a user-writable location' } else { 'lives in a typically user-writable tree (folder ACL restricts writes)' }) }
    if ($unsigned) { $why += ('signature {0}' -f $sigStatus) } elseif ($signer) { $why += ('signed by {0}' -f (($signer -split ',')[0] -replace '^CN=', '')) }
    $binFlagged++
    if ($binFlagged -gt 25) { continue }
    Add-Finding -Severity $sev -Category 'PrivEsc' -Title ("Service binary {0}: {1}" -f $(if ($folderHit) { 'in user-writable folder' } elseif ($inUserDir) { 'in user-writable location' } else { 'unsigned' }), $svc.Name) `
      -Detail ("Binary: {0} | Runs as: {1} | StartMode: {2} | State: {3} | {4}" -f $exe, $svc.StartName, $svc.StartMode, $svc.State, ($why -join '; ')) `
      -Evidence ("{0} :: SHA256 {1}" -f $exe, (Get-PrivEscFileHash $exe)) `
      -Remediation $(if ($folderHit) { 'Move the service binary to a folder writable only by Administrators and SYSTEM, or fix the folder ACL. A writable folder lets any user replace the binary or plant a DLL beside it.' } else { 'Confirm the binary is the expected vendor build (hash against the vendor release) and move services out of ProgramData, AppData, Temp and Public. Unsigned service binaries cannot be validated by signature. MITRE T1543.003.' })
  }
  if ($binFlagged -gt 25) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("{0} service binaries flagged for location or signature (first 25 listed)" -f $binFlagged)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ("Service binaries checked: {0} unique ({1} flagged, {2} without a valid signature)" -f $binChecked, $binFlagged, $binUnsigned) `
    -Detail 'Microsoft-signed binaries under the Windows directory are not reported.'
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service binary location and signature not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

# svchost-hosted services load a ServiceDll instead of a binary. One outside
# System32/SysWOW64, or not Microsoft-signed, is the quiet form of a malware service.
try {
  $dllChecked = 0; $dllFlagged = 0
  $sys32 = (Join-Path $env:SystemRoot 'System32').ToLower()
  $wow64 = (Join-Path $env:SystemRoot 'SysWOW64').ToLower()
  foreach ($svc in ($script:PeasServices | Where-Object { $_.PathName -match '(?i)svchost\.exe' })) {
    $dll = $null
    foreach ($k in @("HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters", "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)")) {
      try { $dll = (Get-ItemProperty $k -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll } catch { }
      if ($dll) { break }
    }
    if (-not $dll) { continue }
    $dllPath = "$dll".Trim().Trim('"')
    $dllPath = $dllPath -replace '^\\\?\?\\', ''
    $dllPath = $dllPath -replace '^(?i)\\SystemRoot', $env:SystemRoot
    $dllPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
    $dllChecked++
    $lower = $dllPath.ToLower()
    $outside = -not ($lower.StartsWith($sys32 + '\') -or $lower.StartsWith($wow64 + '\'))
    $sigStatus = 'not checked'; $signer = ''
    if (Test-Path -LiteralPath $dllPath -PathType Leaf) {
      try {
        $sig = Get-AuthenticodeSignature -LiteralPath $dllPath -ErrorAction Stop
        $sigStatus = "$($sig.Status)"
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
      } catch { $sigStatus = 'unknown' }
    }
    else { $sigStatus = 'file missing' }
    $notMs = -not ($sigStatus -eq 'Valid' -and $signer -match 'Microsoft')
    if (-not $outside -and -not $notMs) { continue }
    $dllFlagged++
    if ($dllFlagged -gt 25) { continue }
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("svchost ServiceDll {0}: {1}" -f $(if ($outside) { 'outside System32' } else { 'not Microsoft-signed' }), $svc.Name) `
      -Detail ("ServiceDll: {0} | Signature: {1}{2} | Runs as: {3} | State: {4}" -f $dllPath, $sigStatus, $(if ($signer) { ' (' + (($signer -split ',')[0] -replace '^CN=', '') + ')' } else { '' }), $svc.StartName, $svc.State) `
      -Evidence ("HKLM:\SYSTEM\CurrentControlSet\Services\{0} :: ServiceDll{1}" -f $svc.Name, $(if ($sigStatus -ne 'file missing') { ' :: SHA256 ' + (Get-PrivEscFileHash $dllPath) } else { '' })) `
      -Remediation 'Every svchost-hosted service ships from Microsoft and loads from System32 or SysWOW64. Attribute the DLL immediately; a third-party or relocated ServiceDll runs inside a trusted host process. MITRE T1543.003.'
  }
  if ($dllFlagged -gt 25) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("{0} svchost ServiceDll entries flagged (first 25 listed)" -f $dllFlagged)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ("svchost ServiceDll entries checked: {0} ({1} flagged)" -f $dllChecked, $dllFlagged)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'svchost ServiceDll check not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- Writable Program Files subfolders and unquoted-path parent directories ------
# Binary replacement and DLL planting (T1574.005 / T1574.010). Only ACEs that
# allow creating FILES count; "create subfolders only" is skipped.
try {
  $pfDirs = New-Object System.Collections.Generic.List[string]
  foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) }) {
    foreach ($d in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) { $pfDirs.Add($d.FullName) }
  }
  foreach ($s in $unquoted) {
    $head = if ($s.PathName -match '^(?i)(.*?\.exe)') { $Matches[1] } else { $s.PathName }
    $dir = Split-Path $head -Parent
    while ($dir -and $dir.Length -gt 3) {
      if (-not $pfDirs.Contains($dir)) { $pfDirs.Add($dir) }
      $dir = Split-Path $dir -Parent
    }
  }
  $svcDirs = @{}
  foreach ($p in $UniqueServices.Keys) { $parent = Split-Path $p -Parent; if ($parent) { $svcDirs[$parent.ToLower()] = $UniqueServices[$p] } }
  $pfHits = 0; $pfChecked = 0
  foreach ($d in $pfDirs) {
    try {
      if (-not (Test-Path -LiteralPath $d)) { continue }
      $acl = Get-Acl -LiteralPath $d -ErrorAction SilentlyContinue
      if (-not $acl) { continue }
      $pfChecked++
      $hit = Get-LowPrivFolderWriteAce -ACLObject $acl
      if (-not $hit) { continue }
      $svcHere = @($svcDirs.Keys | Where-Object { $_ -eq $d.ToLower() -or $_.StartsWith($d.ToLower() + '\') } | ForEach-Object { $svcDirs[$_] } | Select-Object -Unique)
      $pfHits++
      if ($pfHits -gt 25) { continue }
      Add-Finding -Severity $(if ($svcHere.Count -gt 0) { 'High' } else { 'Medium' }) -Category 'PrivEsc' -Title ("Low-privilege '{0}' can write into program folder: {1}" -f $hit.Name, $d) `
        -Detail ("{0} ({1}) has {2} ({3}){4}. Files planted here are loaded by whatever runs from this folder." -f $hit.Name, $hit.Sid, $hit.Level, $hit.Rights, $(if ($svcHere.Count -gt 0) { ' | service binaries under this folder: ' + ($svcHere -join ', ') } else { '' })) `
        -Evidence $d `
        -Remediation 'Reset the folder ACL so only Administrators, SYSTEM and TrustedInstaller can create or modify files. MITRE T1574.005 / T1574.010.'
    } catch { continue }
  }
  if ($pfHits -gt 25) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("{0} program folders are writable by low-privilege principals (first 25 listed)" -f $pfHits)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ("Program folders checked for low-privilege write access: {0} ({1} writable)" -f $pfChecked, $pfHits)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Program folder ACLs not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- Running-process binaries -----------------------------------------------------
# A writable executable of a long-lived process is replaced at the next restart.
# High when the process runs as a DIFFERENT principal than the writer (a real
# boundary is crossed), Medium when it is this user's own process (another
# low-privilege principal could hijack this user's session). A file writable
# only by the user whose process it is crosses no boundary and is not reported.
try {
  $meName = "$($script:AclCurrent.Name)"
  $meSidP = "$($script:AclCurrent.User.Value)"
  # One Get-Process call gives every owner we are allowed to see (own processes
  # when non-elevated, all when elevated); per-process GetOwner costs ~1 s each.
  $ownerMap = @{}
  try { foreach ($gp in (Get-Process -IncludeUserName -ErrorAction Stop)) { if ($gp.UserName) { $ownerMap[[int]$gp.Id] = $gp.UserName } } } catch { }
  $procSeen = @{}
  $procHits = 0; $procChecked = 0
  foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ExecutablePath })) {
    $k = $proc.ExecutablePath.ToLower()
    if ($procSeen.ContainsKey($k) -or $UniqueServices.ContainsKey($proc.ExecutablePath)) { continue }
    $procSeen[$k] = $true
    if ($procSeen.Count -gt 300) { break }
    try {
      $acl = Get-Acl -LiteralPath $proc.ExecutablePath -ErrorAction SilentlyContinue
      if (-not $acl) { continue }
      $procChecked++
      $hit = Get-LowPrivWriteAce -ACLObject $acl
      if (-not $hit) { continue }
      $owner = ''
      if ($ownerMap.ContainsKey([int]$proc.ProcessId)) { $owner = $ownerMap[[int]$proc.ProcessId] }
      elseif ($procHits -lt 25) {
        # Windows PowerShell 5.1 refuses -IncludeUserName without elevation; fall
        # back to GetOwner for the few processes that actually have a weak ACL.
        try {
          $o = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
          if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { }
      }
      $isMine = ($owner -and $owner -ieq $meName)
      if ($isMine -and $hit.Sid -eq $meSidP) { continue }
      $procHits++
      if ($procHits -gt 25) { continue }
      Add-Finding -Severity $(if ($isMine) { 'Medium' } else { 'High' }) -Category 'Filesystem ACL' -Title ("Low-privilege '{0}' has {1} on running process binary: {2}" -f $hit.Name, $hit.Level, $proc.Name) `
        -Detail ("{0} | runs as: {1} | {2} ({3}) can {4} this file. {5}" -f $proc.ExecutablePath, $(if ($owner) { $owner } else { 'unknown' }), $hit.Name, $hit.Sid, $hit.Level.ToLower(), $(if ($isMine) { 'The process is this user''s own, so the exposure is to other low-privilege principals on this host.' } else { 'The process runs as a different principal, so replacing the file crosses a privilege boundary at the next start.' })) `
        -Evidence $proc.ExecutablePath `
        -Remediation 'Keep executables in folders writable only by Administrators, SYSTEM and TrustedInstaller; install tools per-machine instead of in shared or world-writable trees.'
    } catch { continue }
  }
  if ($procHits -gt 25) {
    Add-Finding -Severity Medium -Category 'Filesystem ACL' -Title ("{0} running-process binaries are writable by low-privilege principals (first 25 listed)" -f $procHits)
  }
  Add-Finding -Severity Info -Category 'Filesystem ACL' -Title ("Running-process binaries checked: {0} unique ({1} writable by a low-privilege principal)" -f $procChecked, $procHits)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Running-process binary ACLs not assessed' `
    -Detail ('Win32_Process read failed: ' + $_.Exception.Message)
}

# Startup folders: flag items a low-privilege principal (other than the owner of
# that profile) can modify. SID-based so it works on any OS language.
foreach ($startup in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                       "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
  if (Test-Path $startup) {
    $items = @(Get-ChildItem $startup -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
      if ($i.PSIsContainer) { continue }
      try {
        $acl = Get-Acl -LiteralPath $i.FullName -ErrorAction SilentlyContinue
        if (-not $acl) { continue }
        $w = Get-LowPrivWriteAce -ACLObject $acl
        if ($w -and $i.FullName -like "$env:USERPROFILE*" -and $w.Sid -eq $script:AclCurrent.User.Value) { $w = $null }
        if ($w) {
          Add-Finding -Severity High -Category 'PrivEsc' -Title ("User-writable startup item: {0}" -f $i.Name) `
            -Detail ("{0} | {1} ({2}) has {3}" -f $i.FullName, $w.Name, $w.Sid, $w.Level) -Evidence $i.FullName `
            -Remediation 'Persistence point: any user can plant malware executed at admin logon. Restrict ACLs, remove stale entries.'
        }
      } catch { continue }
    }
  }
}

# Run/RunOnce entries (persistence inventory), including the 32-bit view.
$runSeen = @{}
foreach ($rk in @('registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                  'registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $item = Get-Item $rk -ErrorAction SilentlyContinue
  if ($item -and $item.Property) {
    foreach ($p in $item.Property) {
      $val = (Get-ItemProperty $rk).$p
      $runSeen[("{0}|{1}" -f $p, $val).ToLower()] = $true
      $hash = Get-PrivEscFileHash ([string]$val)
      Add-Finding -Severity Low -Category 'Persistence' -Title ("Autorun entry: {0}" -f $p) `
        -Detail ("{0} = {1}" -f $rk.Replace('registry::', ''), $val) `
        -Evidence $(if ($hash) { "SHA256 $hash" } else { '' }) `
        -Remediation 'Validate each entry against a known-good baseline; autoruns are the #1 malware persistence slot.'
    }
  }
}
# Other users' hives and the startup folders, via Win32_StartupCommand. Entries
# already listed from the Run keys above are skipped.
try {
  $meSid = "$($script:AclCurrent.User.Value)"
  $extra = 0
  foreach ($sc in @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)) {
    $loc = "$($sc.Location)"
    if ($loc -match '^(?i)HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?$') { continue }
    if ($meSid -and $loc -match ('^(?i)HKU\\' + [regex]::Escape($meSid) + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?$')) { continue }
    if ($runSeen.ContainsKey(("{0}|{1}" -f $sc.Name, $sc.Command).ToLower())) { continue }
    $extra++
    if ($extra -gt 40) { continue }
    $hash = Get-PrivEscFileHash ([string]$sc.Command)
    Add-Finding -Severity Low -Category 'Persistence' -Title ("Autorun entry ({0}): {1}" -f $loc, $sc.Name) `
      -Detail ("Command: {0} | User: {1}" -f $sc.Command, $sc.User) `
      -Evidence $(if ($hash) { "SHA256 $hash" } else { '' }) `
      -Remediation 'Validate each entry against a known-good baseline; autoruns are the #1 malware persistence slot.'
  }
  if ($extra -gt 40) {
    Add-Finding -Severity Low -Category 'Persistence' -Title ("{0} additional startup commands found (first 40 listed)" -f $extra)
  }
} catch {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Win32_StartupCommand inventory not assessed' `
    -Detail ('Read failed: ' + $_.Exception.Message)
}

# Scheduled tasks (non-Microsoft) - writable actions
try {
  Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | ForEach-Object {
    $task = $_
    foreach ($a in @($task.Actions)) {
      if (-not $a.Execute) { continue }
      $exe = $a.Execute.Replace('"', '')
      foreach ($envPair in @(@('%windir%', $env:windir), @('%SystemRoot%', $env:windir),
                             @('%localappdata%', "$env:UserProfile\AppData\local"), @('%appdata%', $env:AppData))) {
        $exe = $exe -replace [regex]::Escape($envPair[0]), $envPair[1]
      }
      $exe = ($exe -split '(?<=\.exe\b)')[0].Trim('"')
      if (Test-Path $exe) { Start-ACLCheck -Target $exe -ServiceName ("task: " + $task.TaskName) }
    }
  }
} catch { }

# Dangerous token privileges held by the CURRENT user (what an attacker here could abuse).
# whoami /priv /fo csv keeps privilege NAMES in English on every locale, but the
# State column is localized. SeChangeNotifyPrivilege is enabled on every token,
# so its State string is the local word for "Enabled".
try {
  $privRows = @()
  $csvLines = @(whoami.exe /priv /fo csv /nh 2>$null | Where-Object { $_ -and $_.Trim() })
  if ($csvLines.Count -gt 0) { $privRows = @($csvLines | ConvertFrom-Csv -Header 'Name', 'Description', 'State') }
  if ($privRows.Count -eq 0) { throw 'whoami /priv returned no rows' }
  $anchor = $privRows | Where-Object { $_.Name -eq 'SeChangeNotifyPrivilege' } | Select-Object -First 1
  $enabledWord = if ($anchor) { "$($anchor.State)".Trim() } else { $null }
  $dangerHeld = 0
  foreach ($dangerPriv in @('SeImpersonatePrivilege', 'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                            'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege', 'SeCreateTokenPrivilege', 'SeTcbPrivilege',
                            'SeAssignPrimaryTokenPrivilege')) {
    $row = $privRows | Where-Object { $_.Name -eq $dangerPriv } | Select-Object -First 1
    if (-not $row) { continue }
    $dangerHeld++
    $state = "$($row.State)".Trim()
    $isEnabled = if ($enabledWord) { $state -eq $enabledWord } else { $state -match '^Enabled$' }
    if ($isEnabled) {
      Add-Finding -Severity High -Category 'PrivEsc' -Title ("Current user holds {0} (enabled)" -f $dangerPriv) `
        -Detail 'Dangerous privilege - standard tooling can turn this into SYSTEM or credential access.' `
        -Remediation 'Remove the account from the granting group/local policy (e.g. Administrators, Backup Operators) unless operationally required.'
    }
    else {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("Current user holds {0} (present, not enabled)" -f $dangerPriv) `
        -Detail ('The privilege is in the token in a disabled state. Any process of this user can enable it with AdjustTokenPrivileges, so it is held, not absent. Token state: ' + $state) `
        -Remediation 'Remove the account from the granting group/local policy unless operationally required.'
    }
  }
  if ($dangerHeld -eq 0) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Current token holds none of the 9 dangerous privileges ({0} privileges listed by whoami /priv)' -f $privRows.Count)
  }
  if (-not $anchor) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Token privilege state compared against the English word only' `
      -Detail 'SeChangeNotifyPrivilege was not in the whoami output, so the localized "Enabled" string could not be learned.'
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Current-user token privileges not assessed' `
    -Detail ('whoami /priv failed: ' + $_.Exception.Message)
}

# UAC. A MISSING EnableLUA is not the same as EnableLUA=0 - the value is present
# on a stock install, so its absence points at tampering or a stripped image, and
# the remediation differs. Report the two cases distinctly.
$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacProps = Get-ItemProperty $uacKey -ErrorAction SilentlyContinue
$hasLUA = $uacProps -and ($uacProps.PSObject.Properties.Name -contains 'EnableLUA')
$enableLUA = $uacProps.EnableLUA
if (-not $hasLUA) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'UAC EnableLUA value is absent from the registry' `
    -Detail ('{0} has no EnableLUA value. Windows ships with it set to 1, so its absence means it was removed. Confirm behaviourally: if an elevation request succeeds with no consent prompt, UAC is not protecting this host.' -f $uacKey) `
    -Evidence $uacKey `
    -Remediation 'Recreate EnableLUA (DWORD) = 1 and reboot, then investigate what removed it.'
}
elseif ($enableLUA -ne 1) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title ('UAC disabled (EnableLUA = {0})' -f $enableLUA) `
    -Detail 'Every process launched by an administrator runs fully elevated with no consent prompt.' `
    -Remediation 'Set EnableLUA=1 and reboot.'
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'UAC enabled (EnableLUA = 1)'
}

# Consent behaviour: 0 = elevate silently, which defeats UAC even when EnableLUA=1.
if ($uacProps -and ($uacProps.PSObject.Properties.Name -contains 'ConsentPromptBehaviorAdmin') -and $uacProps.ConsentPromptBehaviorAdmin -eq 0) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'UAC set to elevate silently (ConsentPromptBehaviorAdmin = 0)' `
    -Detail 'Administrators are elevated with no prompt, so a compromised user-context process can take full admin unattended.' `
    -Remediation 'Set ConsentPromptBehaviorAdmin=5 (prompt for consent for non-Windows binaries) or higher.'
}

# Secondary UAC values (CIS 2.3.17.x). One Low finding listing every value that
# misses the benchmark; absent values are evaluated at their OS default.
try {
  $uacSecondary = @(
    @{ Name = 'FilterAdministratorToken'; Want = 1; DefaultAbsent = 0; Note = 'built-in Administrator (RID 500) runs with a full token (CIS 2.3.17.1)' }
    @{ Name = 'ConsentPromptBehaviorUser'; Want = 0; DefaultAbsent = 3; Note = 'standard users are prompted for admin credentials instead of being denied (CIS 2.3.17.3)' }
    @{ Name = 'PromptOnSecureDesktop'; Want = 1; DefaultAbsent = 1; Note = 'elevation prompts are not on the secure desktop and can be spoofed (CIS 2.3.17.6)' }
    @{ Name = 'EnableSecureUIAPaths'; Want = 1; DefaultAbsent = 1; Note = 'UIAccess applications may run from any location (CIS 2.3.17.5)' }
    @{ Name = 'EnableInstallerDetection'; Want = 1; DefaultAbsent = 1; Note = 'installer elevation detection is off (CIS 2.3.17.4)' }
    @{ Name = 'EnableVirtualization'; Want = 1; DefaultAbsent = 1; Note = 'file and registry write failures are not virtualized to per-user locations (CIS 2.3.17.7)' }
  )
  $uacMiss = @()
  foreach ($u in $uacSecondary) {
    $present = $uacProps -and ($uacProps.PSObject.Properties.Name -contains $u.Name)
    $val = if ($present) { [int]$uacProps.($u.Name) } else { $u.DefaultAbsent }
    if ($val -ne $u.Want) { $uacMiss += ('{0} = {1}{2}: {3}' -f $u.Name, $val, $(if ($present) { '' } else { ' (absent, OS default)' }), $u.Note) }
  }
  if ($uacMiss.Count -gt 0) {
    Add-Finding -Severity Low -Category 'PrivEsc' -Title ("{0} secondary UAC value(s) below the CIS benchmark" -f $uacMiss.Count) `
      -Detail ($uacMiss -join ' | ') `
      -Evidence $uacKey `
      -Remediation 'Set the listed values under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System per CIS 2.3.17.x (FilterAdministratorToken=1, ConsentPromptBehaviorUser=0, PromptOnSecureDesktop=1, EnableSecureUIAPaths=1, EnableInstallerDetection=1, EnableVirtualization=1).'
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Secondary UAC values meet the CIS benchmark'
  }
} catch { }

# Remote UAC restrictions. =1 gives LOCAL admin accounts an unfiltered token over
# the network, which is what makes pass-the-hash against admin shares work here.
if ($uacProps -and $uacProps.LocalAccountTokenFilterPolicy -eq 1) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'Remote UAC restrictions disabled (LocalAccountTokenFilterPolicy = 1)' `
    -Detail 'Local administrator accounts receive a full token over the network, enabling pass-the-hash and remote admin-share access with local credentials.' `
    -Evidence $uacKey `
    -Remediation 'Delete LocalAccountTokenFilterPolicy unless a remote-management tool documents needing it; prefer domain accounts for remote admin.'
}

# PrintNightmare-relevant PointAndPrint policy. RestrictDriverInstallationToAdministrators=0
# on its own reopens CVE-2021-34527 after KB5005652; paired with
# NoWarningNoElevationOnInstall=1 it is the full silent non-admin driver install path.
$pnKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$pn = Get-ItemProperty $pnKey -ErrorAction SilentlyContinue
if ($pn) {
  $rdita = if ($pn.PSObject.Properties.Name -contains 'RestrictDriverInstallationToAdministrators') { [int]$pn.RestrictDriverInstallationToAdministrators } else { $null }
  $nwne = if ($pn.PSObject.Properties.Name -contains 'NoWarningNoElevationOnInstall') { [int]$pn.NoWarningNoElevationOnInstall } else { $null }
  $ups = if ($pn.PSObject.Properties.Name -contains 'UpdatePromptSettings') { [int]$pn.UpdatePromptSettings } else { $null }
  if ($rdita -eq 0 -and $nwne -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title 'PointAndPrint policy allows silent non-admin printer driver installs' `
      -Detail ('RestrictDriverInstallationToAdministrators = 0 and NoWarningNoElevationOnInstall = 1{0}. Known PrintNightmare-style driver install path to SYSTEM (CVE-2021-34527).' -f $(if ($null -ne $ups) { ', UpdatePromptSettings = ' + $ups } else { '' })) `
      -Evidence $pnKey `
      -Remediation 'Set RestrictDriverInstallationToAdministrators=1; remove NoWarningNoElevationOnInstall and UpdatePromptSettings.'
  }
  elseif ($rdita -eq 0) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title 'PointAndPrint allows non-admin printer driver installs (RestrictDriverInstallationToAdministrators = 0)' `
      -Detail ('This value alone re-enables the non-admin driver install path that KB5005652 closed{0}.' -f $(if ($null -ne $nwne) { '; NoWarningNoElevationOnInstall = ' + $nwne } else { '' })) `
      -Evidence $pnKey `
      -Remediation 'Set RestrictDriverInstallationToAdministrators=1 (or delete the value; the default is 1).'
  }
  elseif ($nwne -eq 1 -or $ups -eq 2) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title 'PointAndPrint suppresses driver install or update warnings' `
      -Detail ('NoWarningNoElevationOnInstall = {0}, UpdatePromptSettings = {1}. Driver installs remain admin-only (RestrictDriverInstallationToAdministrators is not 0), but prompts are suppressed for admins.' -f $nwne, $ups) `
      -Evidence $pnKey `
      -Remediation 'Remove NoWarningNoElevationOnInstall and UpdatePromptSettings unless a documented print-server trust relationship requires them.'
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'PointAndPrint policy present with admin-only driver installation' `
      -Detail ('RestrictDriverInstallationToAdministrators = {0}; NoWarningNoElevationOnInstall = {1}; UpdatePromptSettings = {2}' -f $rdita, $nwne, $ups)
  }
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'No PointAndPrint policy override (OS default: admin-only driver installation)'
}

# Print Spooler exposure (PrintNightmare class, T1068 / T1547.012). CIS wants the
# Spooler off on domain controllers and servers that do not print.
try {
  $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
  if ($spooler) {
    $productType = 1
    try { $productType = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType } catch { }
    $rpcEp = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -ErrorAction SilentlyContinue).RegisterSpoolerRemoteRpcEndPoint
    $rpcOff = ($rpcEp -eq 2)
    $running = ($spooler.Status -eq 'Running')
    $role = switch ($productType) { 2 { 'domain controller' } 3 { 'server' } default { 'workstation' } }
    if ($running -and $productType -eq 2) {
      Add-Finding -Severity High -Category 'PrivEsc' -Title 'Print Spooler running on a domain controller' `
        -Detail ('Spooler: {0} ({1}); remote RPC endpoint policy: {2}. The spooler on a DC is the PrintNightmare and printer-bug coercion target.' -f $spooler.Status, $spooler.StartType, $(if ($null -ne $rpcEp) { $rpcEp } else { 'not set' })) `
        -Remediation 'Disable the Print Spooler service on domain controllers (CIS 5.x / Microsoft guidance), or at minimum set RegisterSpoolerRemoteRpcEndPoint = 2.'
    }
    elseif ($running -and $productType -eq 3 -and -not $rpcOff) {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title 'Print Spooler running on a server without the remote RPC endpoint disabled' `
        -Detail ('Spooler: {0} ({1}); RegisterSpoolerRemoteRpcEndPoint: {2}. Remote clients can reach the spooler RPC interface.' -f $spooler.Status, $spooler.StartType, $(if ($null -ne $rpcEp) { $rpcEp } else { 'not set' })) `
        -Remediation 'Disable the Spooler on servers that do not print; otherwise set RegisterSpoolerRemoteRpcEndPoint = 2 under HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers.'
    }
    elseif ($running -and $null -eq $rpcEp) {
      Add-Finding -Severity Low -Category 'PrivEsc' -Title ('Print Spooler running on a {0} with no remote RPC policy' -f $role) `
        -Detail ('Spooler: {0} ({1}). No RegisterSpoolerRemoteRpcEndPoint policy is set, so the spooler accepts remote RPC connections.' -f $spooler.Status, $spooler.StartType) `
        -Remediation 'On hosts that only print locally, set RegisterSpoolerRemoteRpcEndPoint = 2 (Allow Print Spooler to accept client connections: Disabled).'
    }
    else {
      Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Print Spooler: {0} ({1}) on a {2}; remote RPC endpoint policy: {3}' -f $spooler.Status, $spooler.StartType, $role, $(if ($null -ne $rpcEp) { $rpcEp } else { 'not set' }))
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Print Spooler exposure not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

# WSUS over HTTP
$wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
$wuServer = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue).WUServer
if ($wu.UseWUServer -eq 1 -and $wuServer -match '^http://') {
  Add-Finding -Severity Critical -Category 'PrivEsc' -Title 'WSUS configured over unencrypted HTTP' `
    -Detail ("Server: {0} - update content can be intercepted/tampered (fake-update -> SYSTEM)." -f $wuServer) `
    -Remediation 'Move WSUS to HTTPS with certificate pinning or enforce TLS.'
}

# SAM/SYSTEM backup copies lying around
foreach ($samPath in @("$env:windir\repair\SAM", "$env:windir\System32\config\RegBack\SAM",
                       "$env:windir\repair\system", "$env:windir\System32\config\RegBack\system")) {
  if (Test-Path $samPath -ErrorAction SilentlyContinue) {
    Add-Finding -Severity High -Category 'Credentials' -Title "SAM/SYSTEM hive copy exposed: $samPath" `
      -Detail 'Offline hash extraction -> pass-the-hash against every local account.' `
      -Remediation 'Delete stale hive backups; restrict NTFS ACLs on config dirs.'
  }
}
