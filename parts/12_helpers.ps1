
######################## RETAINED HELPERS (defensive refit) ########################
# Local-only helpers: weak-ACL detection and installed-software inventory.
# Nothing here contacts a domain controller. (Convert-SidToName / Get-DomainContext
# were removed with the DC-querying AD checks.)

# Low-privilege principals whose write access on an executable path or service binary is a real
# privilege-escalation risk, by SID so the check works on any OS language and no matter who runs
# the audit. Earlier versions used the RUNNING user's whoami groups, so an elevated run flagged
# BUILTIN\Administrators (and every admin-writable folder) as "non-admin".
$script:LowPrivSids = @{
  'S-1-1-0'      = 'Everyone'
  'S-1-5-32-545' = 'BUILTIN\Users'
  'S-1-5-11'     = 'Authenticated Users'
  'S-1-5-4'      = 'INTERACTIVE'
  'S-1-5-2'      = 'NETWORK'
  'S-1-5-7'      = 'ANONYMOUS LOGON'
  'S-1-5-32-546' = 'BUILTIN\Guests'
  'S-1-5-13'     = 'Terminal Server Users'
}
# When the audit runs NON-elevated, the running user is itself a low-privilege principal.
try {
  $script:AclCurrent = [Security.Principal.WindowsIdentity]::GetCurrent()
  $isElevated = ([Security.Principal.WindowsPrincipal]$script:AclCurrent).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isElevated) { $script:LowPrivSids[$script:AclCurrent.User.Value] = $script:AclCurrent.Name }
} catch { }
# Rights that let a principal replace or alter the object (file or registry).
$script:WriteRightsRx = 'FullControl|Modify|Write|CreateFiles|AppendData|ChangePermissions|TakeOwnership|SetValue|CreateSubKey'

function Get-LowPrivWriteAce {
  param($ACLObject)
  foreach ($ace in $ACLObject.Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    # An inherit-only ACE does not apply to this object itself.
    if ("$($ace.PropagationFlags)" -match 'InheritOnly') { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
    if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
    $rights = "$($ace.FileSystemRights)$($ace.RegistryRights)"
    if ($rights -notmatch $script:WriteRightsRx) { continue }
    $level = if ($rights -match 'FullControl') { 'FullControl' } elseif ($rights -match 'Modify') { 'Modify' }
             elseif ($rights -match 'ChangePermissions|TakeOwnership') { 'ChangePermissions/TakeOwnership' } else { 'Write' }
    return [pscustomobject]@{ Name = $script:LowPrivSids[$sid]; Sid = $sid; Level = $level; Rights = $rights }
  }
  return $null
}

# ACL check refit: record weak service/path ACLs as findings instead of console hints.
function Start-ACLCheck {
  param($Target, $ServiceName)
  if ($null -eq $Target) { return }
  try { $ACLObject = Get-Acl $Target -ErrorAction SilentlyContinue } catch { return }
  if (-not $ACLObject) { return }
  $hit = Get-LowPrivWriteAce -ACLObject $ACLObject
  if (-not $hit) { return }
  # A user's own profile is writable by that user by design.
  if ($Target -like "$env:USERPROFILE*" -and $hit.Sid -eq $script:AclCurrent.User.Value) { return }
  Add-Finding -Severity High -Category 'Filesystem ACL' `
    -Title ("Low-privilege '{0}' has {1} on: {2}" -f $hit.Name, $hit.Level, $Target) `
    -Detail ("{0} ({1}) can {2} this object{3}. Any process running as that principal could replace or alter it and gain the privileges of whatever runs it." -f $hit.Name, $hit.Sid, $hit.Level.ToLower(), $(if ($ServiceName) { ' (service: ' + $ServiceName + ')' } else { '' })) `
    -Evidence $Target `
    -Remediation 'Remove write, modify and full control for non-admin principals on executable paths, service binaries and their folders; keep them to Administrators, SYSTEM and TrustedInstaller.'
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
