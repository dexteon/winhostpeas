
######################## PRIVILEGE-ESCALATION SURFACE ########################

Start-Section 'PRIVILEGE-ESCALATION SURFACE'

# AlwaysInstallElevated
foreach ($hive in 'HKLM', 'HKCU') {
  $aie = (Get-ItemProperty "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($aie -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title "AlwaysInstallElevated=1 ($hive)" `
      -Detail 'Any MSI (including malicious) installs with SYSTEM privileges.' `
      -Remediation 'Set AlwaysInstallElevated=0 in both hives (or leave the policy undefined).'
  }
}

# Unquoted service paths
$services = Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -inotmatch '"' -and $_.PathName -inotmatch ':\\Windows\\' -and $_.State -in @('Running', 'Stopped')
}
$unquoted = @($services | Where-Object { $_.PathName -match '^\S*\s' })
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
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -like '*.exe*' } | ForEach-Object {
  try {
    $Path = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
    if ($Path -and -not $UniqueServices.ContainsKey($Path)) { $UniqueServices[$Path] = $_.Name }
  } catch { }
}
foreach ($h in $UniqueServices.GetEnumerator()) {
  Start-ACLCheck -Target $h.Name -ServiceName $h.Value
}

# Service registry key write access
foreach ($svcKey in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\services' -ErrorAction SilentlyContinue | Select-Object -First 400)) {
  $target = $svcKey.Name.Replace('HKEY_LOCAL_MACHINE', 'hklm:')
  $acl = $null
  try { $acl = Get-Acl $target -ErrorAction SilentlyContinue } catch { continue }
  if (-not $acl) { continue }
  $weak = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and
    ("$($_.RegistryRights)" -match 'FullControl|ChangePermissions|TakeOwnership')
  }
  if ($weak) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("Service registry key world-modifiable: {0}" -f $svcKey.PSChildName) `
      -Detail ("{0} grants {1} to {2} - editable ImagePath yields SYSTEM." -f $target, $weak[0].RegistryRights, $weak[0].IdentityReference) `
      -Remediation 'Restrict the key to Administrators/SYSTEM.'
  }
}

# Startup folders
foreach ($startup in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                       "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
  if (Test-Path $startup) {
    $items = @(Get-ChildItem $startup -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
      if ($i.PSIsContainer) { continue }
      $acl = Get-Acl $i.FullName -ErrorAction SilentlyContinue
      $w = $acl | ForEach-Object { $_.Access | Where-Object { $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and "$($_.FileSystemRights)" -match 'FullControl|Modify|Write' } }
      if ($w) {
        Add-Finding -Severity High -Category 'PrivEsc' -Title ("User-writable startup item: {0}" -f $i.Name) `
          -Detail $i.FullName -Evidence $i.FullName `
          -Remediation 'Persistence point: any user can plant malware executed at admin logon. Restrict ACLs, remove stale entries.'
      }
    }
  }
}

# Run/RunOnce entries (persistence inventory)
foreach ($rk in @('registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $item = Get-Item $rk -ErrorAction SilentlyContinue
  if ($item -and $item.Property) {
    foreach ($p in $item.Property) {
      $val = (Get-ItemProperty $rk).$p
      Add-Finding -Severity Low -Category 'Persistence' -Title ("Autorun entry: {0}" -f $p) `
        -Detail ("{0} = {1}" -f $rk.Replace('registry::', ''), $val) `
        -Remediation 'Validate each entry against a known-good baseline; autoruns are the #1 malware persistence slot.'
    }
  }
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

# Dangerous token privileges held by the CURRENT user (what an attacker here could abuse)
$privs = whoami.exe /all
foreach ($dangerPriv in @('SeImpersonatePrivilege', 'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                          'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege', 'SeCreateTokenPrivilege', 'SeTcbPrivilege',
                          'SeAssignPrimaryTokenPrivilege')) {
  if ($privs | Select-String $dangerPriv | Where-Object { $_ -match 'Enabled' }) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("Current user holds {0}" -f $dangerPriv) `
      -Detail 'Dangerous privilege - standard tooling can turn this into SYSTEM or credential access.' `
      -Remediation 'Remove the account from the granting group/local policy (e.g. Administrators, Backup Operators) unless operationally required.'
  }
}

# UAC
$enableLUA = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
if ($enableLUA -ne 1) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'UAC disabled (EnableLUA != 1)' `
    -Remediation 'Set EnableLUA=1; UAC off means every process runs unprompted at full elevation rights.'
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'UAC enabled'
}

# PrintNightmare-relevant PointAndPrint policy
$pn = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -ErrorAction SilentlyContinue
if ($pn) {
  if ($pn.RestrictDriverInstallationToAdministrators -eq 0 -and $pn.NoWarningNoElevationOnInstall -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title 'PointAndPrint policy allows non-admin printer drivers' `
      -Detail 'Known PrintNightmare-style driver install path to SYSTEM.' `
      -Remediation 'Set RestrictDriverInstallationToAdministrators=1; remove NoWarningNoElevationOnInstall.'
  }
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'No PointAndPrint policy override (server default applies)'
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
