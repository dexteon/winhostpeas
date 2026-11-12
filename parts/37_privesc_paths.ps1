
######################## PRIVILEGE-ESCALATION PATHS (EXTENDED) ########################
# The escalation paths seen most in real intrusions and red-team work that the
# PRIVILEGE-ESCALATION SURFACE section does not already cover: privileged local
# group membership, user-rights assignment, Potato-family exposure, phantom DLL
# hijacks, scheduled tasks that run privileged with writable actions, machine
# autoruns with writable targets, stored credential counts, GPP cpassword,
# HiveNightmare, relay preconditions, named-pipe names, WSL and a short
# known-LPE software watchlist.
#
# Every check is a local read: registry, ACLs, file names, WMI, whoami. No
# credential value is printed (counts and names only; any secret goes through
# Get-Redacted). Named pipes are listed by name only: reading a pipe's security
# descriptor means opening it, which is a client connection to its server.

Start-Section 'PRIVILEGE-ESCALATION PATHS (GROUPS, RIGHTS, HIJACK SLOTS)'

# Principals whose membership in a privileged group means "everyone": Everyone,
# Authenticated Users, INTERACTIVE, Users, Anonymous, NETWORK, Guests, and the
# domain-wide Domain Users / Domain Guests / Domain Computers groups.
$script:PeBroadSidRx = '^(S-1-1-0|S-1-5-11|S-1-5-4|S-1-5-32-545|S-1-5-7|S-1-5-2|S-1-5-32-546|S-1-5-21-[\d-]+-(513|514|515))$'

# Group members by group SID. Get-LocalGroupMember throws on the first member SID
# it cannot resolve (a deleted domain account, for example), so the WinNT
# provider on the local machine is the fallback. Returns $null when the group
# does not exist on this host.
function Get-PeGroupMembers {
  param([string]$GroupSid, [string]$GroupName)
  $grp = $null
  try {
    if ($GroupSid) { $grp = Get-LocalGroup -SID $GroupSid -ErrorAction Stop }
    else { $grp = Get-LocalGroup -Name $GroupName -ErrorAction Stop }
  } catch { return $null }
  $members = New-Object System.Collections.Generic.List[object]
  $ok = $false
  try {
    foreach ($m in @(Get-LocalGroupMember -SID $grp.SID -ErrorAction Stop)) {
      $members.Add([pscustomobject]@{ Name = "$($m.Name)"; Sid = "$($m.SID)"; Class = "$($m.ObjectClass)"; Source = "$($m.PrincipalSource)" })
    }
    $ok = $true
  } catch { }
  if (-not $ok) {
    try {
      $adsi = [ADSI]("WinNT://./{0},group" -f $grp.Name)
      foreach ($m in @($adsi.psbase.Invoke('Members'))) {
        $t = $m.GetType()
        $path = "$($t.InvokeMember('ADsPath', 'GetProperty', $null, $m, $null))"
        $cls = "$($t.InvokeMember('Class', 'GetProperty', $null, $m, $null))"
        $sid = ''
        try { $sid = (New-Object Security.Principal.SecurityIdentifier($t.InvokeMember('objectSid', 'GetProperty', $null, $m, $null), 0)).Value } catch { }
        $name = ($path -replace '^WinNT://', '') -replace '/', '\'
        $src = if ($path -like ("WinNT://{0}/*" -f $env:COMPUTERNAME)) { 'Local' } else { 'Other' }
        $members.Add([pscustomobject]@{ Name = $name; Sid = $sid; Class = $cls; Source = $src })
      }
      $ok = $true
    } catch { }
  }
  if (-not $ok) { return [pscustomobject]@{ Name = $grp.Name; Sid = "$($grp.SID)"; Members = $null } }
  # A plain object[] (not the List): @() over a generic List property throws
  # "Argument types do not match" in PowerShell 7.
  return [pscustomobject]@{ Name = $grp.Name; Sid = "$($grp.SID)"; Members = [object[]]$members.ToArray() }
}

# Cached Get-Acl, since several checks below look at the same folders.
$script:PeAclCache = @{}
function Get-PeAcl {
  param([string]$Path)
  if (-not $Path) { return $null }
  $k = $Path.ToLower()
  if ($script:PeAclCache.ContainsKey($k)) { return $script:PeAclCache[$k] }
  $a = $null
  try { $a = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { $a = $null }
  $script:PeAclCache[$k] = $a
  return $a
}

# Write access on a file or, failing that, on the folder that holds it (replace
# the file, or plant a DLL or a missing file beside it). Returns a short reason.
function Get-PeWritableReason {
  param([string]$Path)
  if (-not $Path) { return $null }
  $p = [System.Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
  if (-not [System.IO.Path]::IsPathRooted($p)) { return $null }
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $acl = Get-PeAcl $p
    if ($acl) {
      $hit = Get-LowPrivWriteAce -ACLObject $acl
      if ($hit) { return ('file writable by {0} ({1}: {2})' -f $hit.Name, $hit.Sid, $hit.Level) }
    }
  }
  $dir = Split-Path $p -Parent
  if ($dir -and (Test-Path -LiteralPath $dir -PathType Container)) {
    $dacl = Get-PeAcl $dir
    if ($dacl) {
      $hit = Get-LowPrivFolderWriteAce -ACLObject $dacl
      if ($hit) {
        $state = if (Test-Path -LiteralPath $p -PathType Leaf) { 'folder' } else { 'file is missing and its folder' }
        return ('{0} {1} is writable by {2} ({3}: {4})' -f $state, $dir, $hit.Name, $hit.Sid, $hit.Level)
      }
    }
  }
  return $null
}

# --- 1. Local Administrators: direct, nested, domain and broad members ----------------
# T1078.003 / T1069.001. Domain groups are listed, not expanded: expanding them
# means querying a domain controller.
try {
  $adm = Get-PeGroupMembers -GroupSid 'S-1-5-32-544'
  if (-not $adm -or $null -eq $adm.Members) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Local Administrators membership not assessed' `
      -Detail 'Neither Get-LocalGroupMember nor the local WinNT provider returned the group members.'
  }
  else {
    $m = @($adm.Members)
    $broad = @($m | Where-Object { $_.Sid -match $script:PeBroadSidRx })
    $orphan = @($m | Where-Object { -not $_.Name -or $_.Name -match '^S-1-' -or $_.Source -eq 'Unknown' })
    $localUsers = @($m | Where-Object { $_.Source -eq 'Local' -and $_.Class -eq 'User' })
    $localGroups = @($m | Where-Object { $_.Source -eq 'Local' -and $_.Class -eq 'Group' })
    $dirGroups = @($m | Where-Object { $_.Source -ne 'Local' -and $_.Class -eq 'Group' -and $_.Sid -notmatch $script:PeBroadSidRx })
    # Domain Admins (-512) and Entra built-in roles (S-1-12-1-*) are the expected directory members.
    $dirGroupsOdd = @($dirGroups | Where-Object { $_.Sid -notmatch '^S-1-5-21-[\d-]+-512$' -and $_.Sid -notlike 'S-1-12-1-*' })
    $dirUsers = @($m | Where-Object { $_.Source -ne 'Local' -and $_.Class -eq 'User' })

    if ($broad.Count -gt 0) {
      Add-Finding -Severity Critical -Category 'PrivEsc' -Title ('Local Administrators contains a broad principal: {0}' -f (($broad | ForEach-Object { $_.Name }) -join ', ')) `
        -Detail ('Every member of {0} is a local administrator of this host.' -f (($broad | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Sid }) -join ', ')) `
        -Evidence 'S-1-5-32-544 membership' `
        -Remediation 'Remove the broad principal from Administrators now and find the GPO, Intune policy or script that added it (Restricted Groups, Group Policy Preferences local users and groups). MITRE T1098.'
    }
    # Nested local groups: expand one level locally.
    foreach ($lg in $localGroups) {
      $inner = Get-PeGroupMembers -GroupSid $lg.Sid
      $innerNames = if ($inner -and $inner.Members) { (@($inner.Members) | ForEach-Object { $_.Name }) -join ', ' } else { '(none or unreadable)' }
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title ('Local group nested in Administrators: {0}' -f $lg.Name) `
        -Detail ('Members of {0} are local administrators through nesting, which most admin-membership reviews miss. Its members: {1}' -f $lg.Name, $innerNames) `
        -Evidence ('{0} ({1})' -f $lg.Name, $lg.Sid) `
        -Remediation 'Add accounts to Administrators directly, or not at all; remove the nested group.'
    }
    if ($dirGroupsOdd.Count -gt 0) {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title ('{0} directory group(s) in local Administrators beyond Domain Admins' -f $dirGroupsOdd.Count) `
        -Detail ('{0}. Their membership is managed in the directory and is not expanded here (that needs a domain controller query). Each member of each group is a local admin of this host.' -f (($dirGroupsOdd | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Sid }) -join ', ')) `
        -Remediation 'Confirm each group is a tiered, host-scoped admin group with a small, reviewed membership. Broad helpdesk or all-servers groups are the usual lateral movement path.'
    }
    if ($dirUsers.Count -gt 0) {
      Add-Finding -Severity Low -Category 'PrivEsc' -Title ('{0} directory user account(s) directly in local Administrators' -f $dirUsers.Count) `
        -Detail (($dirUsers | ForEach-Object { $_.Name }) -join ', ') `
        -Remediation 'Grant admin rights through a managed group or just-in-time elevation instead of individual accounts.'
    }
    if ($orphan.Count -gt 0) {
      Add-Finding -Severity Low -Category 'PrivEsc' -Title ('{0} unresolvable SID(s) in local Administrators' -f $orphan.Count) `
        -Detail ('{0}. An orphaned SID is usually a deleted account; if the SID is ever reused or restored through SID history, it is admin again.' -f (($orphan | ForEach-Object { if ($_.Sid) { $_.Sid } else { $_.Name } }) -join ', ')) `
        -Remediation 'Remove orphaned SIDs from Administrators.'
    }
    $rid500Here = @($localUsers | Where-Object { $_.Sid -like '*-500' }).Count
    Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Local Administrators: {0} member(s): {1} local user(s), {2} local group(s), {3} directory group(s), {4} directory user(s)' -f $m.Count, $localUsers.Count, $localGroups.Count, $dirGroups.Count, $dirUsers.Count) `
      -Detail ('Members: {0}. Built-in Administrator (RID 500) is {1} a member; its enabled state is reported in LOCAL ACCOUNT HYGIENE.' -f (($m | ForEach-Object { $_.Name }) -join ', '), $(if ($rid500Here) { '' } else { 'not' })) `
      -Remediation 'Keep local admin membership minimal; prefer LAPS plus just-in-time elevation.'
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Local Administrators membership not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 2. Other privileged local groups ---------------------------------------------
# Admin-equivalent or abuse-prone built-in groups, by well-known SID so the check
# works in any language. DnsAdmins and docker-users have no well-known SID and
# are looked up by name.
try {
  $peGroups = @(
    @{ Sid = 'S-1-5-32-551'; Sev = 'High';   Why = 'SeBackupPrivilege and SeRestorePrivilege: read the SAM and SYSTEM hives and write any file, which is administrator in all but name.' }
    @{ Sid = 'S-1-5-32-549'; Sev = 'High';   Why = 'can reconfigure and start services, so any member can run code as SYSTEM.' }
    @{ Sid = 'S-1-5-32-550'; Sev = 'High';   Why = 'holds SeLoadDriverPrivilege on domain controllers and manages printer drivers: a kernel code-execution path.' }
    @{ Sid = 'S-1-5-32-548'; Sev = 'High';   Why = 'can create and modify most accounts and groups.' }
    @{ Sid = 'S-1-5-32-578'; Sev = 'High';   Why = 'full control of Hyper-V, including mounting virtual disks; Microsoft treats it as administrator-equivalent.' }
    @{ Sid = 'S-1-5-32-582'; Sev = 'High';   Why = 'Storage Replica administration, including raw access to replicated volumes.' }
    @{ Sid = 'S-1-5-32-556'; Sev = 'Medium'; Why = 'can change network configuration and holds write access on some network service registry keys, which has been abused for escalation to SYSTEM.' }
    @{ Sid = 'S-1-5-32-555'; Sev = 'Low';    Why = 'interactive logon over RDP: every member gets a desktop session to escalate from.' }
    @{ Sid = 'S-1-5-32-580'; Sev = 'Low';    Why = 'WinRM and PowerShell remoting access to this host.' }
    @{ Sid = 'S-1-5-32-573'; Sev = 'Low';    Why = 'reads every event log, including process command lines that often carry credentials.' }
    @{ Sid = 'S-1-5-32-562'; Sev = 'Low';    Why = 'can launch and activate DCOM objects remotely, a lateral-movement path.' }
    @{ Sid = 'S-1-5-32-559'; Sev = 'Low';    Why = 'can schedule performance logging, which has been abused for code execution through DCOM.' }
    @{ Sid = 'S-1-5-32-569'; Sev = 'Low';    Why = 'can perform cryptographic operations, including some certificate and key configuration.' }
    @{ Name = 'DnsAdmins';   Sev = 'High';   Why = 'can make the DNS Server service, which runs as SYSTEM, load an arbitrary DLL (ServerLevelPluginDll).' }
    @{ Name = 'docker-users'; Sev = 'High';  Why = 'can drive the Docker engine, which runs as SYSTEM: mounting the host file system from a container is host takeover.' }
  )
  $grpSeen = 0; $grpFlagged = 0
  foreach ($g in $peGroups) {
    $r = if ($g.Sid) { Get-PeGroupMembers -GroupSid $g.Sid } else { Get-PeGroupMembers -GroupName $g.Name }
    if (-not $r) { continue }
    $grpSeen++
    if ($null -eq $r.Members) {
      Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Privileged group membership not readable: {0}' -f $r.Name) -Evidence ('{0} ({1})' -f $r.Name, $r.Sid)
      continue
    }
    $mem = @($r.Members)
    if ($mem.Count -eq 0) { continue }
    $grpFlagged++
    $broadHere = @($mem | Where-Object { $_.Sid -match $script:PeBroadSidRx })
    # A broad principal makes an admin-equivalent group Critical; in a lower-impact
    # group it raises the finding to Medium (Performance Log Users holds INTERACTIVE
    # on some builds by default).
    $sev = if ($broadHere.Count -gt 0) { $(if ($g.Sev -eq 'High') { 'Critical' } else { 'Medium' }) } else { $g.Sev }
    Add-Finding -Severity $sev -Category 'PrivEsc' -Title ('Privileged local group {0} has {1} member(s)' -f $r.Name, $mem.Count) `
      -Detail ('Members: {0}. This group {1}{2}' -f (($mem | ForEach-Object { $_.Name }) -join ', '), $g.Why, $(if ($broadHere.Count -gt 0) { ' A broad principal is a member, so every user on this host holds these rights.' } else { '' })) `
      -Evidence ('{0} ({1})' -f $r.Name, $r.Sid) `
      -Remediation ('Keep {0} empty unless a documented role needs it, and review it like Administrators. MITRE T1069.001 / T1078.003.' -f $r.Name)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Privileged local groups checked: {0} present, {1} with members' -f $grpSeen, $grpFlagged) `
    -Detail 'Backup, Server, Print and Account Operators, Hyper-V and Storage Replica Administrators, Network Configuration Operators, Remote Desktop Users, Remote Management Users, Event Log Readers, Distributed COM Users, Performance Log Users, Cryptographic Operators, DnsAdmins, docker-users.'
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Privileged local groups not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 3. The audit account's own group memberships ---------------------------------
# whoami /groups keeps SIDs language-neutral. A non-elevated token that carries
# Administrators (as a deny-only SID) is a split-token admin: the only thing
# between it and full admin is a UAC prompt, which Microsoft does not treat as
# a security boundary.
try {
  $grpRows = @()
  $gl = @(whoami.exe /groups /fo csv /nh 2>$null | Where-Object { $_ -and $_.Trim() })
  if ($gl.Count -gt 0) { $grpRows = @($gl | ConvertFrom-Csv -Header 'Name', 'Type', 'Sid', 'Attributes') }
  if ($grpRows.Count -eq 0) { throw 'whoami /groups returned no rows' }
  $privSidNames = @{
    'S-1-5-32-551' = 'Backup Operators'; 'S-1-5-32-549' = 'Server Operators'; 'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-578' = 'Hyper-V Administrators'; 'S-1-5-32-582' = 'Storage Replica Administrators'
  }
  $tokSids = @($grpRows | ForEach-Object { "$($_.Sid)".Trim() })
  $inAdmins = $tokSids -contains 'S-1-5-32-544'
  $privHeld = @($tokSids | Where-Object { $privSidNames.ContainsKey($_) } | ForEach-Object { $privSidNames[$_] })
  $domPriv = @($tokSids | Where-Object { $_ -match '^S-1-5-21-[\d-]+-(512|518|519)$' })
  if ($inAdmins -and -not $script:IsElevated) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title 'Audit account is a split-token administrator (non-elevated run)' `
      -Detail 'The token carries BUILTIN\Administrators as a deny-only SID. Any code this account runs is one consent prompt (or one UAC bypass) away from full administrator, and Microsoft does not treat UAC as a security boundary.' `
      -Remediation 'Use a standard account for daily work and a separate admin account (or just-in-time elevation) for administration. Set ConsentPromptBehaviorAdmin=2 to require the secure desktop for every elevation.'
  }
  if ($privHeld.Count -gt 0) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ('Audit account is in privileged group(s): {0}' -f ($privHeld -join ', ')) `
      -Detail 'These groups are admin-equivalent on this host; any code running as this account can use their rights.' `
      -Remediation 'Remove the everyday account from these groups and use a dedicated, separately protected account for the role.'
  }
  if ($domPriv.Count -gt 0) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ('Audit account holds {0} domain-privileged group SID(s) (Domain, Schema or Enterprise Admins)' -f $domPriv.Count) `
      -Detail 'A tier-0 account is logged on to this host, so its credentials and tokens are exposed to anything that compromises the host.' `
      -Remediation 'Log on to member hosts with tier-0 accounts only from privileged access workstations; use tiered admin accounts.'
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Audit token: {0} group SIDs; Administrators member: {1}; elevated: {2}' -f $tokSids.Count, $inAdmins, [bool]$script:IsElevated)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Audit token group membership not assessed' -Detail ('whoami /groups failed: ' + $_.Exception.Message)
}

# --- 4. User-rights assignment: who holds the escalation privileges ---------------
# Read from the secedit export taken in the OS section (elevated only). Default
# holders are allowed; anyone else holding one of these is an escalation path.
if ($null -eq $script:SeceditPrivRights) {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title $(if ($script:IsElevated) { 'User-rights assignment not assessed (secedit export failed)' } else { 'User-rights assignment not assessed (needs elevation)' }) `
    -Detail 'Which accounts hold SeImpersonate, SeDebug, SeBackup, SeLoadDriver and similar rights comes from secedit /export, which needs administrator. The token-privilege check above still covers the running account.'
}
else {
  try {
    $expected = @{
      SeImpersonatePrivilege          = @('S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-6', 'S-1-5-32-568')
      SeAssignPrimaryTokenPrivilege   = @('S-1-5-19', 'S-1-5-20')
      SeBackupPrivilege               = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549')
      SeRestorePrivilege              = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549')
      SeDebugPrivilege                = @('S-1-5-32-544')
      SeTakeOwnershipPrivilege        = @('S-1-5-32-544')
      SeLoadDriverPrivilege           = @('S-1-5-32-544', 'S-1-5-32-550')
      SeManageVolumePrivilege         = @('S-1-5-32-544')
      SeTcbPrivilege                  = @()
      SeCreateTokenPrivilege          = @()
      SeRelabelPrivilege              = @()
      SeTrustedCredManAccessPrivilege = @()
      SeEnableDelegationPrivilege     = @('S-1-5-32-544')
    }
    $odd = 0
    foreach ($priv in $expected.Keys) {
      if (-not $script:SeceditPrivRights.ContainsKey($priv)) { continue }
      foreach ($holder in @($script:SeceditPrivRights[$priv])) {
        # SYSTEM, per-service SIDs (NT SERVICE\*) and IIS application pool identities are expected.
        if ($holder -eq 'S-1-5-18' -or $holder -like 'S-1-5-80-*' -or $holder -like 'S-1-5-82-*') { continue }
        if ($expected[$priv] -contains $holder) { continue }
        $name = $holder
        if ($holder -match '^S-1-(1-0|5-\d+|5-32-\d+)$') {
          try { $name = ([Security.Principal.SecurityIdentifier]$holder).Translate([Security.Principal.NTAccount]).Value + " ($holder)" } catch { }
        }
        $odd++
        if ($odd -gt 25) { continue }
        $sev = if ($holder -match $script:PeBroadSidRx) { 'Critical' } else { 'High' }
        Add-Finding -Severity $sev -Category 'PrivEsc' -Title ('{0} assigned to a non-default holder: {1}' -f $priv, $name) `
          -Detail ('Local policy grants {0} to {1}. Any process running as that principal holds the privilege, which public tooling turns into SYSTEM or credential access.' -f $priv, $name) `
          -Evidence ('secedit [Privilege Rights] {0}' -f $priv) `
          -Remediation 'Remove the assignment in the GPO or local security policy (User Rights Assignment) unless a documented service needs it; prefer a per-service SID over a user or group. MITRE T1134.'
      }
    }
    if ($odd -gt 25) { Add-Finding -Severity High -Category 'PrivEsc' -Title ('{0} non-default holders of escalation privileges (first 25 listed)' -f $odd) }
    Add-Finding -Severity Info -Category 'PrivEsc' -Title ('User-rights assignment checked for {0} escalation privileges ({1} non-default holder(s))' -f $expected.Count, $odd)
  } catch {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'User-rights assignment not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
  }
}

# --- 5. Potato-family exposure through service accounts ---------------------------
# LocalService, NetworkService, per-service virtual accounts and IIS application
# pools all hold SeImpersonate. Code execution inside any of them (a web shell,
# SQL xp_cmdshell) is one Potato-family tool away from SYSTEM.
try {
  $potatoRx = '(?i)^(NT AUTHORITY\\(LocalService|NetworkService|Local Service|Network Service)|NT SERVICE\\.+)$'
  $exposedRx = '(?i)MSSQL|SQLAgent|Tomcat|Apache|httpd|nginx|php|Jenkins|Exchange|ReportServer|MySQL|Postgres|MariaDB|w3svc|WAS$'
  $svcAcct = @($script:PeasServices | Where-Object { "$($_.StartName)" -match $potatoRx })
  $exposed = @($svcAcct | Where-Object { $_.State -eq 'Running' -and ($_.Name -match $exposedRx -or $_.DisplayName -match $exposedRx) })
  $iis = @($script:PeasServices | Where-Object { $_.Name -eq 'W3SVC' -and $_.State -eq 'Running' })
  if ($exposed.Count -gt 0 -or $iis.Count -gt 0) {
    $list = @($exposed | ForEach-Object { '{0} ({1})' -f $_.Name, $_.StartName })
    if ($iis.Count -gt 0) { $list += 'W3SVC worker processes (IIS application pool identities)' }
    Add-Finding -Severity Low -Category 'PrivEsc' -Title ('{0} network-facing service(s) run under accounts that hold SeImpersonate' -f $list.Count) `
      -Detail ('{0}. Code execution in any of these (web shell, SQL xp_cmdshell, deserialization bug) becomes SYSTEM through the Potato family (PrintSpoofer, GodPotato, JuicyPotatoNG, EfsPotato). The privilege cannot be removed from these accounts, so the boundary is the application itself.' -f ($list -join ', ')) `
      -Remediation 'Patch these services first, keep xp_cmdshell and similar features off, stop the Print Spooler where it is not needed, and alert on child processes of w3wp.exe and sqlservr.exe. MITRE T1134.001 / T1068.'
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('{0} service(s) run as LocalService, NetworkService or a virtual service account' -f $svcAcct.Count) `
    -Detail 'These accounts hold SeImpersonate by design.'
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service-account impersonation exposure not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 6. Phantom DLL hijacks: SYSTEM services that load a DLL Windows does not ship ----
# These services look up a DLL that is absent on a stock install, so the search
# order reaches the machine PATH. A writable PATH folder (or a DLL planted in
# one) is SYSTEM code execution at the next service start. T1574.001 / T1574.007.
try {
  $phantoms = @(
    @{ Dll = 'wlbsctrl.dll';       Svc = 'IKEEXT';     Desc = 'IKE and AuthIP IPsec Keying Modules' }
    @{ Dll = 'WptsExtensions.dll'; Svc = 'Schedule';   Desc = 'Task Scheduler' }
    @{ Dll = 'cdpsgshims.dll';     Svc = 'CDPSvc';     Desc = 'Connected Devices Platform Service' }
    @{ Dll = 'TSMSISrv.dll';       Svc = 'SessionEnv'; Desc = 'Remote Desktop Configuration' }
    @{ Dll = 'TSVIPSrv.dll';       Svc = 'SessionEnv'; Desc = 'Remote Desktop Configuration' }
  )
  $machPathRaw = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path -ErrorAction Stop).Path
  $pathDirs = @($machPathRaw -split ';' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { [System.Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')).TrimEnd('\') } | Select-Object -Unique)
  $sys32 = (Join-Path $env:SystemRoot 'System32').ToLower()
  $wPathDirs = @()
  foreach ($d in $pathDirs) {
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { continue }
    $acl = Get-PeAcl $d
    if (-not $acl) { continue }
    $hit = Get-LowPrivFolderWriteAce -ACLObject $acl
    if ($hit) { $wPathDirs += ('{0} ({1}: {2})' -f $d, $hit.Name, $hit.Level) }
  }
  $phFound = 0; $phOpen = 0
  foreach ($ph in $phantoms) {
    $svc = $script:PeasServices | Where-Object { $_.Name -eq $ph.Svc } | Select-Object -First 1
    # Where the DLL exists today. Present in a PATH folder outside System32 = planted.
    $locs = @()
    foreach ($d in (@($pathDirs) + @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'), $env:SystemRoot) | Select-Object -Unique)) {
      $f = Join-Path $d $ph.Dll
      if (Test-Path -LiteralPath $f -PathType Leaf) { $locs += $f }
    }
    foreach ($f in ($locs | Select-Object -Unique)) {
      $sigStatus = 'unknown'; $signer = ''
      try { $sig = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction Stop; $sigStatus = "$($sig.Status)"; if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject } } catch { }
      $msOk = ($sigStatus -eq 'Valid' -and $signer -match 'Microsoft')
      $inSys32 = $f.ToLower().StartsWith($sys32 + '\')
      if ($msOk -and $inSys32) { continue }
      $phFound++
      Add-Finding -Severity High -Category 'PrivEsc' -Title ('Phantom DLL present: {0} (loaded by {1})' -f $ph.Dll, $ph.Svc) `
        -Detail ('{0} exists at {1} (signature {2}{3}). Windows does not ship this DLL; the {4} service ({5}) loads it as SYSTEM if found. Service state: {6}.' -f $ph.Dll, $f, $sigStatus, $(if ($signer) { ', ' + (($signer -split ',')[0] -replace '^CN=', '') } else { '' }), $ph.Svc, $ph.Desc, $(if ($svc) { "$($svc.State), $($svc.StartMode)" } else { 'not installed' })) `
        -Evidence ('{0} :: SHA256 {1}' -f $f, (Get-PrivEscFileHash $f)) `
        -Remediation 'Treat as a likely implant: attribute and hash the file, then remove it and investigate how it was written. MITRE T1574.001.'
    }
    if ($svc -and $wPathDirs.Count -gt 0 -and $svc.StartMode -ne 'Disabled') {
      $phOpen++
      Add-Finding -Severity High -Category 'PrivEsc' -Title ('Phantom DLL hijack path open: {0} loads missing {1}' -f $ph.Svc, $ph.Dll) `
        -Detail ('The {0} service ({1}, {2}, {3}) runs as {4} and searches for {5}, which Windows does not ship. Writable machine PATH folder(s): {6}. A DLL dropped there runs as SYSTEM at the next service start.' -f $ph.Svc, $ph.Desc, $svc.State, $svc.StartMode, $svc.StartName, $ph.Dll, ($wPathDirs -join '; ')) `
        -Evidence ('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment :: Path') `
        -Remediation 'Remove the writable folders from the machine PATH or restrict their ACLs to Administrators and SYSTEM. MITRE T1574.007.'
    }
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Phantom DLL hijack slots checked: {0} DLLs, {1} writable machine PATH folder(s), {2} planted, {3} open' -f $phantoms.Count, $wPathDirs.Count, $phFound, $phOpen) `
    -Detail (($phantoms | ForEach-Object { '{0} ({1})' -f $_.Dll, $_.Svc }) -join ', ')
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Phantom DLL hijack slots not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 7. Scheduled tasks that run privileged with a writable action -----------------
# The earlier section ACL-checks the executable of non-Microsoft tasks. This one
# looks at WHO the task runs as and adds the action's folder, a missing action
# binary, and script files passed as arguments (powershell -File x.ps1).
# T1053.005. A standard user cannot enumerate every task, so a non-elevated run
# sees part of the list.
try {
  $tasks = @(Get-ScheduledTask -ErrorAction Stop)
  $privSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
  $tChecked = 0; $tFlagged = 0
  $argFileRx = '(?i)([A-Z]:\\[^"<>|*?\r\n]+?\.(ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|exe|dll|py|hta))'
  foreach ($t in $tasks) {
    $uid = "$($t.Principal.UserId)"
    $uidSid = ''
    if ($uid -match '^S-1-') { $uidSid = $uid }
    elseif ($uid) { try { $uidSid = ([Security.Principal.NTAccount]$uid).Translate([Security.Principal.SecurityIdentifier]).Value } catch { } }
    $gidSid = ''
    if ("$($t.Principal.GroupId)") { try { $gidSid = ([Security.Principal.NTAccount]"$($t.Principal.GroupId)").Translate([Security.Principal.SecurityIdentifier]).Value } catch { } }
    $highest = ("$($t.Principal.RunLevel)" -eq 'Highest')
    $priv = ($privSids -contains $uidSid) -or ($gidSid -eq 'S-1-5-32-544') -or $highest
    if (-not $priv) { continue }
    $runAs = if ($uid) { $uid } elseif ($t.Principal.GroupId) { "group $($t.Principal.GroupId)" } else { 'unknown' }
    foreach ($a in @($t.Actions)) {
      if (-not $a.Execute) { continue }
      $tChecked++
      $targets = New-Object System.Collections.Generic.List[string]
      $exe = [System.Environment]::ExpandEnvironmentVariables(($a.Execute -replace '"', '').Trim())
      if ([System.IO.Path]::IsPathRooted($exe)) { $targets.Add($exe) }
      foreach ($mm in [regex]::Matches([System.Environment]::ExpandEnvironmentVariables("$($a.Arguments)"), $argFileRx)) { $targets.Add($mm.Groups[1].Value) }
      foreach ($tg in ($targets | Select-Object -Unique)) {
        # The executable file of a non-Microsoft task is already ACL-checked in PRIVILEGE-ESCALATION SURFACE.
        $why = Get-PeWritableReason -Path $tg
        if (-not $why) { continue }
        if ($t.TaskPath -notlike '\Microsoft*' -and $tg -eq $exe -and $why -like 'file writable*') { continue }
        $tFlagged++
        if ($tFlagged -gt 25) { continue }
        $sev = if (($privSids -contains $uidSid) -or $gidSid -eq 'S-1-5-32-544') { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category 'PrivEsc' -Title ('Privileged scheduled task with writable action: {0}{1}' -f $t.TaskPath, $t.TaskName) `
          -Detail ('Runs as {0}{1} | Action: {2} {3} | {4}: {5}. Whoever can write it runs code as the task principal at the next trigger.' -f $runAs, $(if ($highest) { ' (highest privileges)' } else { '' }), $a.Execute, $a.Arguments, $tg, $why) `
          -Evidence $tg `
          -Remediation 'Move the task''s binaries and scripts to a folder writable only by Administrators and SYSTEM, or fix the ACL. MITRE T1053.005.'
      }
    }
  }
  if ($tFlagged -gt 25) { Add-Finding -Severity High -Category 'PrivEsc' -Title ('{0} privileged scheduled task actions are writable (first 25 listed)' -f $tFlagged) }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Privileged scheduled task actions checked: {0} ({1} writable) out of {2} visible tasks' -f $tChecked, $tFlagged, $tasks.Count) `
    -Detail $(if ($script:IsElevated) { 'Tasks running as SYSTEM, LocalService, NetworkService, the Administrators group, or with highest privileges.' } else { 'Non-elevated: tasks owned by other principals may not be visible to this account, so the list can be incomplete.' })
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Privileged scheduled tasks not assessed' -Detail ('Get-ScheduledTask failed: ' + $_.Exception.Message)
}

# --- 8. Machine-wide autoruns with writable targets or keys -------------------------
# HKLM Run entries start in every user's session, administrators included, so a
# writable target or a writable Run key is code execution as the next admin to
# log on. T1547.001.
try {
  $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
  $arChecked = 0; $arFlagged = 0
  foreach ($rk in $runKeys) {
    if (-not (Test-Path $rk)) { continue }
    $kacl = Get-PeAcl $rk
    if ($kacl) {
      $khit = Get-LowPrivWriteAce -ACLObject $kacl
      if ($khit) {
        $arFlagged++
        Add-Finding -Severity High -Category 'PrivEsc' -Title ('Machine autorun key writable by low-privilege principal: {0}' -f $rk) `
          -Detail ('{0} ({1}) has {2} on the key. A new value here runs at every user''s logon, administrators included.' -f $khit.Name, $khit.Sid, $khit.Level) `
          -Evidence $rk -Remediation 'Reset the key ACL to Administrators and SYSTEM (inherited from HKLM\SOFTWARE). MITRE T1547.001.'
      }
    }
    $item = Get-Item $rk -ErrorAction SilentlyContinue
    foreach ($p in @($item.Property)) {
      $val = "$((Get-ItemProperty $rk -Name $p -ErrorAction SilentlyContinue).$p)"
      if (-not $val) { continue }
      $exe = Get-ServiceExePath -PathName $val
      if (-not $exe) { continue }
      $arChecked++
      $why = Get-PeWritableReason -Path $exe
      if (-not $why) { continue }
      $arFlagged++
      if ($arFlagged -gt 25) { continue }
      Add-Finding -Severity High -Category 'PrivEsc' -Title ('Machine autorun target writable: {0}' -f $p) `
        -Detail ('{0} :: {1} = {2} | {3}. The target runs in every user''s session at logon, administrators included.' -f $rk, $p, $val, $why) `
        -Evidence $exe `
        -Remediation 'Restrict the target binary and its folder to Administrators, SYSTEM and TrustedInstaller, or remove the entry. MITRE T1547.001.'
    }
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Machine autorun targets checked by ACL: {0} ({1} writable target(s) or key(s))' -f $arChecked, $arFlagged)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Machine autorun target ACLs not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 9. Stored credentials: Credential Manager, runas /savecred, saved RDP -----------
# Counts only. cmdkey /list prints target names; only the language-neutral
# ':target=' / ':interactive=' / 'TERMSRV/' tokens are counted and no target is
# reported. T1555.004.
try {
  $blobDirs = @("$env:LOCALAPPDATA\Microsoft\Credentials", "$env:APPDATA\Microsoft\Credentials")
  $blobCount = 0
  foreach ($d in $blobDirs) { if ($d -and (Test-Path -LiteralPath $d)) { $blobCount += @(Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue).Count } }
  $vaultCount = 0
  foreach ($d in @("$env:LOCALAPPDATA\Microsoft\Vault", "$env:APPDATA\Microsoft\Vault")) {
    if ($d -and (Test-Path -LiteralPath $d)) { $vaultCount += @(Get-ChildItem -LiteralPath $d -Recurse -File -Filter '*.vcrd' -Force -ErrorAction SilentlyContinue).Count }
  }
  $ck = @(cmdkey.exe /list 2>$null)
  $ckTotal = @($ck | Where-Object { $_ -match ':(target|interactive)=' }).Count
  $ckInteractive = @($ck | Where-Object { $_ -match '(?i)Domain:interactive=' }).Count
  $ckRdp = @($ck | Where-Object { $_ -match '(?i)TERMSRV/' }).Count
  if ($ckInteractive -gt 0) {
    Add-Finding -Severity High -Category 'Credentials' -Title ('{0} saved runas /savecred credential(s) for this user' -f $ckInteractive) `
      -Detail 'A Domain:interactive credential lets any process of this user run "runas /savecred" as the saved account without knowing its password. When that account is an administrator, this is a direct escalation. Target names are not reported.' `
      -Remediation 'Delete the saved credential (cmdkey /delete) and stop using runas /savecred; use a separate admin logon or just-in-time elevation. MITRE T1555.004.'
  }
  if ($ckRdp -gt 0) {
    Add-Finding -Severity Medium -Category 'Credentials' -Title ('{0} saved RDP credential(s) in Credential Manager' -f $ckRdp) `
      -Detail 'TERMSRV credentials are DPAPI-protected with this user''s key, so any code running as this user can recover and replay them to the saved hosts. Target names are not reported.' `
      -Remediation 'Remove saved RDP passwords and set the policy "Do not allow passwords to be saved" (CIS 18.10.57.2.2). MITRE T1555.004.'
  }
  Add-Finding -Severity Info -Category 'Credentials' -Title ('Credential Manager for this user: {0} cmdkey entr(ies), {1} credential blob file(s), {2} vault item(s)' -f $ckTotal, $blobCount, $vaultCount) `
    -Detail 'Counts only; no target names or values are read. Other users'' stores are not visible from this account.'
} catch {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Manager counts not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 10. Group Policy Preferences cpassword ------------------------------------------
# GPP stored passwords AES-encrypted with a key Microsoft published (MS14-025), so
# any cpassword value is plaintext to anyone who can read it. Checked in the local
# GP history cache and, on a domain controller, the local SYSVOL copy. T1552.006.
try {
  $gppRoots = @("$env:ProgramData\Microsoft\Group Policy\History", "$env:SystemRoot\SYSVOL\sysvol", "$env:SystemRoot\SYSVOL\domain") | Where-Object { Test-Path -LiteralPath $_ }
  $gppNames = @('Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml')
  $gppFiles = 0; $gppHits = 0
  foreach ($root in $gppRoots) {
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Include $gppNames -ErrorAction SilentlyContinue | Select-Object -First 500)) {
      $gppFiles++
      $txt = $null
      try { $txt = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
      $vals = @([regex]::Matches("$txt", 'cpassword="([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
      if ($vals.Count -eq 0) { continue }
      $gppHits++
      Add-Finding -Severity Critical -Category 'Credentials' -Title ('Group Policy Preferences password (cpassword) in {0}' -f $f.Name) `
        -Detail ('{0} holds {1} cpassword value(s), first {2}. The GPP encryption key is public (MS14-025), so this is a plaintext password for whoever can read the file, and every domain user can read SYSVOL.' -f $f.FullName, $vals.Count, (Get-Redacted $vals[0])) `
        -Evidence $f.FullName `
        -Remediation 'Delete the preference item from the GPO (not just this cached copy), rotate the password on every host it was pushed to, and use Windows LAPS for local admin passwords. MITRE T1552.006.'
    }
  }
  Add-Finding -Severity Info -Category 'Credentials' -Title ('Group Policy Preferences files checked: {0} ({1} with cpassword)' -f $gppFiles, $gppHits) `
    -Detail ('Locations: {0}' -f $(if ($gppRoots) { ($gppRoots -join ', ') } else { 'none present' }))
} catch {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'Group Policy Preferences cpassword not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 11. HiveNightmare / SeriousSAM (CVE-2021-36934) --------------------------------
# A readable SAM file ACL lets any user copy the hives out of a volume shadow
# copy and extract local password hashes. Reading the ACL does not open the hive.
try {
  $samFile = Join-Path $env:SystemRoot 'System32\config\SAM'
  $samAcl = Get-PeAcl $samFile
  if ($samAcl) {
    $readers = @()
    foreach ($ace in $samAcl.Access) {
      if ($ace.AccessControlType -ne 'Allow') { continue }
      $sid = $null
      try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
      if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
      if ("$($ace.FileSystemRights)" -match 'Read|FullControl|Modify') { $readers += ('{0} ({1}: {2})' -f $script:LowPrivSids[$sid], $sid, $ace.FileSystemRights) }
    }
    if ($readers.Count -gt 0) {
      Add-Finding -Severity High -Category 'Credentials' -Title 'SAM hive ACL readable by low-privilege principals (HiveNightmare, CVE-2021-36934)' `
        -Detail ('{0} grants read to {1}. With any volume shadow copy present, a standard user can copy SAM, SYSTEM and SECURITY and extract local hashes.' -f $samFile, ($readers -join ', ')) `
        -Evidence $samFile `
        -Remediation 'Run icacls %windir%\system32\config\*.* /inheritance:e, then delete shadow copies created before the fix and create a new restore point (Microsoft KB5005357). MITRE T1003.002.'
    }
    else {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'SAM hive ACL does not grant read to low-privilege principals (HiveNightmare not present)'
    }
  }
  elseif (-not $script:IsElevated) {
    # Reading a DACL needs READ_CONTROL, which every Read grant includes. A standard
    # user who is refused the DACL therefore holds no Read grant on the file.
    Add-Finding -Severity Info -Category 'Credentials' -Title 'SAM hive ACL refuses this standard user (HiveNightmare not present)' `
      -Detail ('Get-Acl on {0} was denied. Any Read grant to Users would include READ_CONTROL, so the vulnerable ACL is not in place.' -f $samFile)
  }
  else {
    Add-Finding -Severity Info -Category 'Credentials' -Title 'SAM hive ACL not assessed' -Detail ('Get-Acl on {0} failed.' -f $samFile)
  }
} catch {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'SAM hive ACL not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 12. NTLM relay preconditions readable on this host (KrbRelayUp and kin) ----------
# KrbRelayUp needs LDAP signing not enforced on the DCs and a MachineAccountQuota
# above zero; both live on the DC and are not queried. What this host can show:
# its own LDAP client signing, its LDAP server settings if it IS a DC, and the
# WebClient service that turns this host into an HTTP coercion target.
try {
  $csR = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  $joinedR = [bool]($csR -and $csR.PartOfDomain)
  $isDc = ($csR -and $csR.DomainRole -ge 4)
  if ($isDc) {
    $ntds = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
    $lsi = if ($ntds -and ($ntds.PSObject.Properties.Name -contains 'LDAPServerIntegrity')) { [int]$ntds.LDAPServerIntegrity } else { $null }
    $cb = if ($ntds -and ($ntds.PSObject.Properties.Name -contains 'LdapEnforceChannelBinding')) { [int]$ntds.LdapEnforceChannelBinding } else { $null }
    if ($lsi -ne 2) {
      Add-Finding -Severity High -Category 'PrivEsc' -Title ('Domain controller does not require LDAP signing (LDAPServerIntegrity = {0})' -f $(if ($null -eq $lsi) { 'absent' } else { $lsi })) `
        -Detail 'Unsigned LDAP binds can be relayed, which is the core of KrbRelayUp, RBCD and shadow-credential escalation paths from any domain-joined host.' `
        -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters::LDAPServerIntegrity' `
        -Remediation 'Set "Domain controller: LDAP server signing requirements" to Require signing (LDAPServerIntegrity=2) after auditing event 2889 for unsigned binds.'
    }
    if ($cb -ne 2) {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title ('Domain controller LDAPS channel binding not enforced (LdapEnforceChannelBinding = {0})' -f $(if ($null -eq $cb) { 'absent' } else { $cb })) `
        -Detail 'Without channel binding, NTLM authentication can be relayed to LDAPS.' `
        -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters::LdapEnforceChannelBinding' `
        -Remediation 'Set LdapEnforceChannelBinding=2 (Always) after auditing event 3039.'
    }
  }
  if ($joinedR) {
    $lci = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name LDAPClientIntegrity -ErrorAction SilentlyContinue).LDAPClientIntegrity
    if ($null -ne $lci -and [int]$lci -eq 0) {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title 'LDAP client signing disabled (LDAPClientIntegrity = 0)' `
        -Detail 'This host sends unsigned LDAP, so its own directory traffic can be tampered with or relayed.' `
        -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP::LDAPClientIntegrity' `
        -Remediation 'Set "Network security: LDAP client signing requirements" to at least Negotiate signing (1), ideally Require (2) (CIS 2.3.11.8).'
    }
  }
  $wc = $script:PeasServices | Where-Object { $_.Name -eq 'WebClient' } | Select-Object -First 1
  if ($wc -and $wc.StartMode -ne 'Disabled' -and $joinedR) {
    Add-Finding -Severity Low -Category 'PrivEsc' -Title ('WebClient (WebDAV) service installed and not disabled ({0}, {1})' -f $wc.State, $wc.StartMode) `
      -Detail 'With WebClient running, authentication coercion (PetitPotam, PrinterBug) can make this host authenticate over HTTP, which is relayable to LDAP even where SMB signing is enforced. That is the start of RBCD and shadow-credential takeovers of this host.' `
      -Remediation 'Disable the WebClient service where WebDAV is not needed, and require LDAP signing and channel binding on the domain controllers.'
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Relay preconditions read locally; DC-side settings not assessed' `
    -Detail ('Domain-joined: {0}; domain controller: {1}. LDAP signing on the domain controllers and ms-DS-MachineAccountQuota, the other KrbRelayUp preconditions, need a DC query and are out of scope.' -f $joinedR, [bool]$isDc)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Relay preconditions not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 13. Named pipes: names only -----------------------------------------------------
# Listing the pipe namespace is a directory read. Default pipe names of common
# post-exploitation and remote-execution tools are flagged; DACLs are not read.
try {
  $pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_ -replace '^\\\\\.\\pipe\\', '' })
  $pipeRx = '(?i)^(msagent_[0-9a-f]+|postex_[0-9a-f]+|postex_ssh_[0-9a-f]+|status_[0-9a-f]+|MSSE-\d+-server|PSEXESVC.*|RemCom_communicat.*|PAExec.*|csexecsvc.*)$'
  $odd = @($pipes | Where-Object { $_ -match $pipeRx })
  if ($odd.Count -gt 0) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ('{0} named pipe(s) match post-exploitation or remote-execution tool defaults' -f $odd.Count) `
      -Detail ('Pipes: {0}. These names are the defaults of Cobalt Strike, PsExec, RemCom and PAExec. A legitimate admin PsExec session also creates PSEXESVC.' -f (($odd | Select-Object -First 15) -join ', ')) `
      -Remediation 'Identify the owning process (handle or Sysinternals pipelist as an administrator) and confirm it is authorized. MITRE T1570 / T1021.002.'
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('{0} named pipes listed (names only)' -f $pipes.Count) `
    -Detail 'Pipe DACLs are not read: opening a pipe to read its security descriptor is a client connection to the service behind it.'
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Named pipes not assessed' -Detail ('Listing \\.\pipe\ failed: ' + $_.Exception.Message)
}

# --- 14. Windows Subsystem for Linux -------------------------------------------------
# A WSL distro gives its user root inside Linux without Windows admin, and work
# done there is invisible to most Windows EDR telemetry (T1202).
try {
  $lxSvc = $script:PeasServices | Where-Object { $_.Name -in 'LxssManager', 'WSLService' } | Select-Object -First 1
  $wslExe = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\wsl.exe')
  $distros = @()
  $hives = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })
  foreach ($h in $hives) {
    $lx = "Registry::HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Lxss"
    foreach ($d in @(Get-ChildItem $lx -ErrorAction SilentlyContinue)) {
      $dn = (Get-ItemProperty $d.PSPath -Name DistributionName -ErrorAction SilentlyContinue).DistributionName
      if ($dn) { $distros += $dn }
    }
  }
  if ($distros.Count -gt 0) {
    Add-Finding -Severity Low -Category 'PrivEsc' -Title ('WSL installed with {0} registered distribution(s)' -f $distros.Count) `
      -Detail ('Distributions (loaded user hives only): {0}. Root inside a distro needs no Windows admin, the Windows drives are mounted under /mnt, and Linux-side activity is mostly invisible to Windows EDR.' -f (($distros | Select-Object -Unique) -join ', ')) `
      -Remediation 'Remove WSL where it is not needed; where it is, use an EDR with WSL coverage and manage it through the WSL policy settings. MITRE T1202.'
  }
  elseif ($lxSvc -or $wslExe) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'WSL components present, no registered distribution in loaded user hives' `
      -Detail ('Service: {0}; wsl.exe present: {1}.' -f $(if ($lxSvc) { "$($lxSvc.Name) ($($lxSvc.StartMode))" } else { 'none' }), $wslExe)
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'WSL not installed'
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'WSL presence not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

# --- 15. Installed software with a known local privilege escalation ----------------
# A short watchlist, not a vulnerability scanner: products that commonly sit on
# managed hosts as SYSTEM services and had a public LPE fixed in a known version.
try {
  $lpeWatch = @(
    @{ Label = 'OpenVPN 2.x';  Rx = '^OpenVPN 2\.';   Fixed = '2.6.10';  Ref = 'CVE-2024-27459 / CVE-2024-24974: local escalation through the openvpnserv interactive service' }
    @{ Label = 'TeamViewer';   Rx = '^TeamViewer';    Fixed = '15.58.4'; Ref = 'CVE-2024-7479 / CVE-2024-7481: a standard user can make the TeamViewer service install a driver' }
    @{ Label = 'VMware Tools'; Rx = '^VMware Tools';  Fixed = '12.5.1';  Ref = 'CVE-2025-22230: authentication bypass that lets a non-admin guest user perform high-privilege operations' }
  )
  $apps = @(Get-InstalledApplications)
  $watchHits = 0; $watchSeen = 0
  foreach ($w in $lpeWatch) {
    foreach ($app in @($apps | Where-Object { "$($_.Software)" -match $w.Rx })) {
      $watchSeen++
      $vs = $null
      if ("$($app.Software)" -match '(\d+\.\d+\.\d+)') { $vs = $Matches[1] }
      elseif ("$($app.Version)" -match '^(\d+\.\d+(\.\d+)?)') { $vs = $Matches[1] }
      if (-not $vs) { continue }
      $have = $null; try { $have = [version]$vs } catch { continue }
      if ($have -lt [version]$w.Fixed) {
        $watchHits++
        Add-Finding -Severity Medium -Category 'PrivEsc' -Title ('{0} {1} predates the fix for a known local privilege escalation' -f $w.Label, $vs) `
          -Detail ('{0} (reported version {1}). {2}. Fixed in {3}.' -f $app.Software, $app.Version, $w.Ref, $w.Fixed) `
          -Evidence ('{0} {1}' -f $app.Software, $app.Version) `
          -Remediation ('Update to {0} or later, or remove the product if it is not needed. MITRE T1068.' -f $w.Fixed)
      }
    }
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Known-LPE software watchlist: {0} product(s) checked, {1} installed, {2} outdated' -f $lpeWatch.Count, $watchSeen, $watchHits) `
    -Detail ('Watchlist: {0}. This is not a vulnerability scan; feed the software inventory to your scanner for full coverage.' -f (($lpeWatch | ForEach-Object { '{0} < {1}' -f $_.Label, $_.Fixed }) -join ', '))
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Known-LPE software watchlist not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}
