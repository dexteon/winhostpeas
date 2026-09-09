
######################## RETAINED HELPERS (defensive refit) ########################
# ACL / SID / AD helper functions carried over from winPEAS.ps1 - unchanged logic.

function Convert-SidToName {
  param($SidInput)
  if ($null -eq $SidInput) { return $null }
  try {
    if ($SidInput -is [System.Security.Principal.SecurityIdentifier]) { $sidObject = $SidInput }
    else { $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SidInput) }
    return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
  }
  catch {
    try { return $sidObject.Value } catch { return [string]$SidInput }
  }
}

function Get-DomainContext {
  try { return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() }
  catch { return $null }
}

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
  $currentUser = "$env:COMPUTERNAME\$env:USERNAME"
  $everyoneLike = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Authenticated Users')
  foreach ($i in $Identity) {
    $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }
    $userPermission = ''
    switch -WildCard ("$($Permission.FileSystemRights)") {
      'FullControl' { $userPermission = 'FullControl' }
      'Write*'      { $userPermission = 'Write' }
      'Modify'      { $userPermission = 'Modify' }
    }
    if ("$($Permission.RegistryRights)" -eq 'FullControl') { $userPermission = 'FullControl' }
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

function Get-InstalledApplications {
  [cmdletbinding()]
  param([Parameter(DontShow)]$keys = @('', '\Wow6432Node'))
  foreach ($key in $keys) {
    try {
      $apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
    }
    catch { continue }
    foreach ($app in $apps) {
      $program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
      $name = $program.GetValue('DisplayName')
      if ($name) {
        [pscustomobject]@{
          Computername = $env:COMPUTERNAME
          Software     = $name
          Version      = $program.GetValue('DisplayVersion')
          Publisher    = $program.GetValue('Publisher')
          InstallDate  = $program.GetValue('InstallDate')
          Architecture = $(if ($key -eq '\wow6432node') { 'x86' } else { 'x64' })
        }
      }
    }
  }
}
