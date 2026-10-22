######################## INVENTORY ########################
# Plain asset inventory: every service, every installed program, and every
# program folder under Program Files, ProgramData and user AppData. Read-only.
# Full lists go to the inventory CSVs and the HTML report; findings carry
# counts and the items worth a second look.

Start-Section 'INVENTORY (services, installed programs, program folders)'

$script:Inventory = [ordered]@{ Services = @(); Software = @(); Folders = @() }
$invMax = 40   # longest list printed inside a single finding

function Format-InvList {
  param([string[]]$Items, [int]$Max = 40)
  $Items = @($Items | Where-Object { $_ })
  if ($Items.Count -le $Max) { return ($Items -join ', ') }
  return (($Items | Select-Object -First $Max) -join ', ') + (' ... and {0} more (full list in the inventory report)' -f ($Items.Count - $Max))
}

function Get-InvLocation {
  # Bucket a path by where it lives on disk.
  param([string]$Path)
  if (-not $Path) { return 'Unknown' }
  $p = $Path.ToLower()
  $win = $env:SystemRoot.ToLower()
  $pf = $env:ProgramFiles.ToLower()
  $pf86 = if (${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)}.ToLower() } else { '<none>' }
  $pd = $env:ProgramData.ToLower()
  $users = (Split-Path $env:PUBLIC -Parent).ToLower()
  if ($p.StartsWith($win + '\')) { return 'Windows' }
  if ($p.StartsWith($pf86 + '\')) { return 'Program Files (x86)' }
  if ($p.StartsWith($pf + '\')) { return 'Program Files' }
  if ($p.StartsWith($pd + '\')) { return 'ProgramData' }
  if ($p.StartsWith($users + '\')) { return 'User profile' }
  return 'Other'
}

function Get-InvFileVersion {
  param([string]$Path)
  try {
    if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
      $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
      return [pscustomobject]@{ Company = $vi.CompanyName; Product = $vi.ProductName; Version = $vi.FileVersion }
    }
  } catch { }
  return [pscustomobject]@{ Company = ''; Product = ''; Version = '' }
}

# Walk a folder a few levels deep and count executables. Bounded so a huge
# tree (SDKs, node caches) cannot stall the scan.
function Get-InvFolderExes {
  param([string]$Root, [int]$MaxDepth = 3, [int]$MaxDirs = 400)
  $exes = New-Object System.Collections.Generic.List[string]
  $queue = New-Object System.Collections.Generic.Queue[object]
  $queue.Enqueue(@($Root, 0))
  $visited = 0; $truncated = $false
  while ($queue.Count -gt 0) {
    $item = $queue.Dequeue(); $dir = $item[0]; $depth = $item[1]
    $visited++
    if ($visited -gt $MaxDirs) { $truncated = $true; break }
    try {
      foreach ($f in [System.IO.Directory]::EnumerateFiles($dir, '*.exe')) { $exes.Add($f) }
    } catch { }
    if ($depth -lt $MaxDepth) {
      try {
        foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
          # Skip junctions and symlinks so a reparse loop cannot recurse.
          try {
            if (([System.IO.File]::GetAttributes($d) -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $queue.Enqueue(@($d, ($depth + 1))) }
          } catch { }
        }
      } catch { }
    }
  }
  return [pscustomobject]@{ Exes = $exes; Truncated = $truncated }
}

# ---------- Services ----------
$invSvcSource = $script:PeasServices
if (-not $invSvcSource -or @($invSvcSource).Count -eq 0) {
  try { $invSvcSource = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch { $invSvcSource = @() }
}
$fvCache = @{}
$script:Inventory.Services = @(foreach ($s in $invSvcSource) {
  $exe = Get-ServiceExePath $s.PathName
  if ($exe -and -not $fvCache.ContainsKey($exe)) { $fvCache[$exe] = Get-InvFileVersion $exe }
  $fv = if ($exe) { $fvCache[$exe] } else { $null }
  [pscustomobject]@{
    Name        = $s.Name
    DisplayName = $s.DisplayName
    State       = $s.State
    StartMode   = $s.StartMode
    RunsAs      = $s.StartName
    Location    = Get-InvLocation $exe
    Company     = if ($fv) { $fv.Company } else { '' }
    Version     = if ($fv) { $fv.Version } else { '' }
    Binary      = $exe
    CommandLine = $s.PathName
  }
}) | Sort-Object Name

$svcAll = @($script:Inventory.Services)
if ($svcAll.Count -eq 0) {
  Add-Finding -Severity Info -Category 'Inventory' -Title 'Service inventory not assessed' `
    -Detail 'The service list could not be read (Win32_Service query failed).' `
    -Remediation 'Rerun from an account that can query WMI.'
}
else {
  $svcRun = @($svcAll | Where-Object { $_.State -eq 'Running' }).Count
  $svcAuto = @($svcAll | Where-Object { $_.StartMode -eq 'Auto' }).Count
  # Third party = the binary is not signed off as Microsoft by its version info
  # and does not live under the Windows folder.
  $svc3p = @($svcAll | Where-Object { $_.Location -ne 'Windows' -and $_.Company -notmatch 'Microsoft' })
  Add-Finding -Severity Info -Category 'Inventory' -Title ('{0} services installed ({1} running, {2} start automatically, {3} third-party)' -f $svcAll.Count, $svcRun, $svcAuto, $svc3p.Count) `
    -Detail ('Third-party services: ' + (Format-InvList -Max $invMax -Items ($svc3p | ForEach-Object {
          '{0} [{1}, {2}{3}]' -f $_.Name, $_.State, $_.RunsAs, $(if ($_.Company) { ', ' + $_.Company } else { '' })
        }))) `
    -Remediation 'Compare the third-party services against the approved software list for this host role; remove or disable anything nobody can account for.'

  $svcUser = @($svc3p | Where-Object { $_.Location -in 'User profile', 'ProgramData' })
  if ($svcUser.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Inventory' -Title ('{0} services run programs from ProgramData or a user profile' -f $svcUser.Count) `
      -Detail (Format-InvList -Max $invMax -Items ($svcUser | ForEach-Object { '{0} ({1}) -> {2}' -f $_.Name, $_.RunsAs, $_.Binary })) `
      -Remediation 'Services normally run from Program Files, where ordinary users cannot write. Check the folder permissions (see the Privilege Escalation findings) and move these installs to Program Files where the vendor allows it.'
  }
}

# ---------- Installed programs ----------
$swAll = @(Get-InstalledApplications | Where-Object { -not $_.Hidden })
$script:Inventory.Software = @($swAll | ForEach-Object {
    [pscustomobject]@{
      Name            = $_.Software
      Version         = $_.Version
      Publisher       = $_.Publisher
      InstallDate     = $_.InstallDate
      Scope           = $_.Scope
      User            = $_.User
      Architecture    = $_.Architecture
      InstallLocation = $_.InstallLocation
      Location        = Get-InvLocation $_.InstallLocation
    }
  })
$swMachine = @($swAll | Where-Object { $_.Scope -eq 'Machine' }).Count
$swUser = @($swAll | Where-Object { $_.Scope -eq 'User' })
Add-Finding -Severity Info -Category 'Inventory' -Title ('{0} installed programs ({1} for all users, {2} per-user)' -f $swAll.Count, $swMachine, $swUser.Count) `
  -Detail 'Read from the Uninstall registry keys (64-bit, 32-bit and every loaded user hive). The full list with versions and publishers is in the inventory report.' `
  -Remediation 'Feed this list to the asset or vulnerability management system and remove programs the host role does not need.'
if ($swUser.Count -gt 0) {
  Add-Finding -Severity Low -Category 'Inventory' -Title ('{0} programs installed per-user, without admin rights' -f $swUser.Count) `
    -Detail (Format-InvList -Max $invMax -Items ($swUser | ForEach-Object {
          # Many DisplayNames already end with the version; do not print it twice.
          $n = $_.Software; $v = [string]$_.Version
          if ($v -and $n.EndsWith($v)) { $v = '' }
          ('{0} {1}{2}' -f $n, $v, $(if ($_.User) { ' (' + ($_.User -replace '^.*\\', '') + ')' } else { '' })) -replace '\s{2,}', ' '
        })) `
    -Remediation 'Per-user installs skip admin approval and are often missed by software inventory and patching tools. Confirm each is approved and patched; application control (WDAC or AppLocker) can block programs from running out of user profiles.'
}

# ---------- Program folders ----------
$invRoots = New-Object System.Collections.Generic.List[object]
foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Select-Object -Unique) {
  if ($r -and (Test-Path -LiteralPath $r)) { $invRoots.Add([pscustomobject]@{ Root = $r; Area = (Get-InvLocation ($r + '\x')); User = ''; ExeOnly = $false }) }
}
if ($env:ProgramData -and (Test-Path -LiteralPath $env:ProgramData)) {
  $invRoots.Add([pscustomobject]@{ Root = $env:ProgramData; Area = 'ProgramData'; User = ''; ExeOnly = $true })
}
$profRoot = Split-Path $env:PUBLIC -Parent
$profUnread = New-Object System.Collections.Generic.List[string]
foreach ($prof in @(Get-ChildItem -LiteralPath $profRoot -Directory -Force -ErrorAction SilentlyContinue)) {
  if ($prof.Name -in 'Public', 'Default', 'Default User', 'All Users' -or ($prof.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { continue }
  $sub = @('AppData\Local\Programs', 'AppData\Local', 'AppData\Roaming')
  $readable = $false
  foreach ($s in $sub) {
    $p = Join-Path $prof.FullName $s
    try { [void][System.IO.Directory]::EnumerateDirectories($p).GetEnumerator().MoveNext(); $readable = $true } catch { continue }
    $invRoots.Add([pscustomobject]@{ Root = $p; Area = ('AppData (' + ($s -replace '^AppData\\', '') + ')'); User = $prof.Name; ExeOnly = $true })
  }
  if (-not $readable) { $profUnread.Add($prof.Name) }
}

$folders = New-Object System.Collections.Generic.List[object]
$seen = @{}
foreach ($root in $invRoots) {
  $children = @()
  try { $children = @([System.IO.Directory]::EnumerateDirectories($root.Root)) } catch { continue }
  foreach ($d in $children) {
    $key = $d.ToLower()
    if ($seen.ContainsKey($key)) { continue }   # Local\Programs is also under Local
    $seen[$key] = $true
    $leaf = Split-Path $d -Leaf
    # Local\Programs is listed as its own root; do not count it twice as one folder.
    if ($root.Root -match '\\AppData\\Local$' -and $leaf -eq 'Programs') { continue }
    try { if (([System.IO.File]::GetAttributes($d) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue } } catch { continue }
    $walk = Get-InvFolderExes -Root $d
    $exeCount = $walk.Exes.Count
    # Installer and updater stubs (electron-builder caches, Package Cache) are
    # not programs; a ProgramData or AppData folder holding only those is skipped.
    $progExes = @($walk.Exes | Where-Object { (Split-Path $_ -Leaf) -notmatch '^(installer|setup.*|unins.*|uninstall.*|update|updater|squirrel|.*_installer|.*-setup.*)\.exe$' })
    if ($root.ExeOnly -and $progExes.Count -eq 0) { continue }
    # Name the folder by its biggest executable (usually the main program).
    $main = $null; $mainSize = -1
    foreach ($e in $progExes) {
      try { $len = ([System.IO.FileInfo]$e).Length; if ($len -gt $mainSize) { $mainSize = $len; $main = $e } } catch { }
    }
    $fv = if ($main) { Get-InvFileVersion $main } else { $null }
    $lastWrite = ''
    try { $lastWrite = [System.IO.Directory]::GetLastWriteTime($d).ToString('yyyy-MM-dd') } catch { }
    $folders.Add([pscustomobject]@{
        Area       = $root.Area
        User       = $root.User
        Folder     = $leaf
        Executables = $(if ($walk.Truncated) { "$exeCount+" } else { "$exeCount" })
        MainProgram = $(if ($main) { Split-Path $main -Leaf } else { '' })
        Company    = $(if ($fv) { $fv.Company } else { '' })
        Version    = $(if ($fv) { $fv.Version } else { '' })
        LastWrite  = $lastWrite
        Path       = $d
      })
  }
}
$script:Inventory.Folders = @($folders | Sort-Object Area, User, Folder)

$byArea = $script:Inventory.Folders | Group-Object Area | Sort-Object Name
Add-Finding -Severity Info -Category 'Inventory' -Title ('{0} program folders found' -f $script:Inventory.Folders.Count) `
  -Detail ((($byArea | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) -join ' | ') + '. Program Files lists every top-level folder; ProgramData and AppData list only folders that contain executables (searched 3 levels deep).') `
  -Remediation 'Use the folder list to find software that never registered an uninstall entry (portable apps, copied tools, leftovers).'

$appDataProgs = @($script:Inventory.Folders | Where-Object { $_.Area -like 'AppData*' })
if ($appDataProgs.Count -gt 0) {
  Add-Finding -Severity Low -Category 'Inventory' -Title ('{0} programs live in user AppData folders' -f $appDataProgs.Count) `
    -Detail (Format-InvList -Max $invMax -Items ($appDataProgs | ForEach-Object {
          '{0}\{1}{2}' -f $_.User, $_.Folder, $(if ($_.MainProgram) { ' (' + $_.MainProgram + ')' } else { '' })
        })) `
    -Remediation 'Programs in AppData are writable by the user who runs them, so malware can replace them, and they often miss patching. Confirm each is expected; block execution from AppData with WDAC or AppLocker where the business allows it.'
}

# Folders with executables that no uninstall entry points at: portable or copied programs.
$knownLocs = @($swAll | Where-Object { $_.InstallLocation } | ForEach-Object { $_.InstallLocation.TrimEnd('\').ToLower() })
$unregistered = @(foreach ($fo in $script:Inventory.Folders) {
    if ($fo.Executables -eq '0' -or $fo.Area -like 'Program Files*' -or $fo.Company -match 'Microsoft') { continue }
    $fp = $fo.Path.ToLower()
    $hit = $false
    foreach ($k in $knownLocs) { if ($k -eq $fp -or $k.StartsWith($fp + '\') -or $fp.StartsWith($k + '\')) { $hit = $true; break } }
    if (-not $hit) { $fo }
  })
if ($unregistered.Count -gt 0) {
  Add-Finding -Severity Info -Category 'Inventory' -Title ('{0} folders in ProgramData or AppData hold programs that are not in the installed-programs list' -f $unregistered.Count) `
    -Detail (Format-InvList -Max $invMax -Items ($unregistered | ForEach-Object {
          '{0}{1}{2}' -f $(if ($_.User) { $_.User + '\' } else { 'ProgramData\' }), $_.Folder, $(if ($_.MainProgram) { ' (' + $_.MainProgram + ')' } else { '' })
        })) `
    -Remediation 'These are portable tools, auto-updaters, or leftovers from removed software. Patch tooling does not see them; confirm each is wanted.'
}

if ($profUnread.Count -gt 0) {
  Add-Finding -Severity Info -Category 'Inventory' -Title ('AppData not assessed for {0} user profiles (access denied)' -f $profUnread.Count) `
    -Detail ('Profiles: ' + ($profUnread -join ', ')) `
    -Remediation 'Run elevated to inventory programs in every user profile.'
}
