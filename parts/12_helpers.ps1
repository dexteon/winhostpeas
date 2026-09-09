
######################## RETAINED HELPERS (defensive refit) ########################
# Local-only helpers: weak-ACL detection and installed-software inventory.
# Nothing here contacts a domain controller. (Convert-SidToName / Get-DomainContext
# were removed with the DC-querying AD checks.)

# ACL check refit: record weak service/path ACLs as findings instead of console hints.
function Start-ACLCheck {
  param($Target, $ServiceName)
  if ($null -eq $Target) { return }
  try { $ACLObject = Get-Acl $Target -ErrorAction SilentlyContinue } catch { return }
  if (-not $ACLObject) { return }
  $Identity = @("$env:COMPUTERNAME\$env:USERNAME")
  try {
    whoami.exe /groups /fo csv 2>$null | Select-Object -skip 2 | ConvertFrom-Csv -Header 'group name' |
      Select-Object -ExpandProperty 'group name' | ForEach-Object { $Identity += $_ }
  } catch { }
  $everyoneLike = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Authenticated Users')
  foreach ($i in $Identity) {
    $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }
    # FileSystemRights stringifies as a combined flag list (e.g. "Modify, Synchronize"),
    # so match substrings rather than requiring an exact single value.
    $fsr = "$($permission.FileSystemRights)"
    $rr = "$($permission.RegistryRights)"
    $userPermission = ''
    if ($fsr -match 'FullControl') { $userPermission = 'FullControl' }
    elseif ($fsr -match 'Modify') { $userPermission = 'Modify' }
    elseif ($fsr -match 'Write') { $userPermission = 'Write' }
    if ($rr -match 'FullControl') { $userPermission = 'FullControl' }
    if ($userPermission) {
      # filter benign: Users write on their own profile paths is by-design
      if ($Target -like "*$env:USERNAME*") { continue }
      Add-Finding -Severity High -Category 'Filesystem ACL' `
        -Title ("Non-admin identity has '{0}' on: {1}" -f $userPermission, $Target) `
        -Detail ("Identity: {0}{1} - an attacker landing as this user could tamper with this object." -f $permission.IdentityReference, $(if ($ServiceName) { ' (service: ' + $ServiceName + ')' } else { '' })) `
        -Evidence $Target `
        -Remediation 'Tighten the ACL: remove broad write/modify for non-admin principals on executable paths and service binaries.'
      return
    }
  }
  # world-writable check
  foreach ($ev in $everyoneLike) {
    $perm = $ACLObject.Access | Where-Object { $_.IdentityReference -like "*$ev*" -and $_.AccessControlType -eq 'Allow' }
    foreach ($p in $perm) {
      if ("$($p.FileSystemRights)" -match 'FullControl|Modify|Write') {
        Add-Finding -Severity High -Category 'Filesystem ACL' `
          -Title ("'{0}' granted {1} to: {2}" -f $ev, $p.FileSystemRights, $Target) `
          -Evidence $Target `
          -Remediation 'Restrict this permission to the service account / administrators that need it.'
        return
      }
    }
  }
}

# Installed-software inventory via a direct LOCAL registry read of the 64-bit,
# 32-bit (Wow6432Node) and per-user uninstall hives. Does not use the
# remote-registry API and does not depend on the RemoteRegistry service.
function Get-InstalledApplications {
  $roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    $arch = if ($root -match 'Wow6432Node') { 'x86' } else { 'x64' }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      if ($props -and $props.DisplayName) {
        [pscustomobject]@{
          Computername = $env:COMPUTERNAME
          Software     = $props.DisplayName
          Version      = $props.DisplayVersion
          Publisher    = $props.Publisher
          InstallDate  = $props.InstallDate
          Architecture = $arch
        }
      }
    }
  }
}
