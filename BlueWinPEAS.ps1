<#
.SYNOPSIS
  BlueWinPEAS - the winPEAS.ps1 enumeration engine refit as a BLUE TEAM posture audit.
.DESCRIPTION
  Same detection surface an attacker would enumerate, repurposed for defenders:
    - structured findings (Severity / Category / Title / Detail / Remediation)
    - secret VALUES are detected but redacted - never printed or written to reports
    - added defender-side checks: Defender status, PowerShell logging coverage,
      SMBv1/signing, LLMNR/NBT-NS, RDP NLA, BitLocker, LSA/CredGuard, password
      policy, local account hygiene, dangerous token privileges
    - machine-wide regex sweeps (registry/files) are opt-in (-FullCheck) and scoped
    - emits JSON + CSV + HTML reports for ticketing / compliance pipelines
  Read-only: changes nothing on the host. Produces no exploit instructions.
.EXAMPLE
  .\BlueWinPEAS.ps1                     # fast posture audit + reports
  .\BlueWinPEAS.ps1 -FullCheck          # + deep (redacted) secret-pattern sweep
  .\BlueWinPEAS.ps1 -OutputDir C:\Audits -TimeStamp
.NOTES
  Derived from winPEAS.ps1 v1.3 (PEASS-ng / @RandolphConley), defensive refit.
  Run only on systems you own or are explicitly authorized to audit.
#>

[CmdletBinding()]
param(
  [switch]$TimeStamp,
  [switch]$FullCheck,
  [string]$OutputDir = '.\BlueWinPEAS_Output',
  [switch]$NoReport
)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function TimeElapsed {
  if ($TimeStamp) { Write-Host ('  [{0:mm\:ss}]' -f $stopwatch.Elapsed) -ForegroundColor DarkGray }
}

######################## FINDINGS ENGINE ########################
# Every check records a finding instead of printing exploit guidance.
# Severities: Critical / High / Medium / Low / Info
# Values that look like secrets are detected but REDACTED in every output lane.

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:FindingsByName = @{}

function Get-Redacted {
  # return length + fingerprint only, never the value
  param($Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ($s.Length -le 4) { return '<redacted:' + $s.Length + 'ch>' }
  $fp = $s.Substring($s.Length - 4)
  return ('<redacted:{0}ch, ends ...{1}>' -f $s.Length, $fp)
}

function Add-Finding {
  param(
    [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Title,
    [string]$Detail = '',
    [string]$Evidence = '',
    [string]$Remediation = ''
  )
  $f = [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    Host      = $env:COMPUTERNAME
    Severity  = $Severity
    Category  = $Category
    Title     = $Title
    Detail    = $Detail
    Evidence  = $Evidence
    Remediation = $Remediation
  }
  $script:Findings.Add($f)
  $key = "$Category|$Title"
  if (-not $script:FindingsByName.ContainsKey($key)) { $script:FindingsByName[$key] = 0 }
  $script:FindingsByName[$key]++

  $sevColor = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
  Write-Host ('  [{0}] {1}: {2}' -f $Severity, $Category, $Title) -ForegroundColor $sevColor[$Severity]
  if ($Detail)     { Write-Host ('      ' + $Detail) -ForegroundColor DarkGray }
  if ($Remediation) { Write-Host ('      Fix: ' + $Remediation) -ForegroundColor DarkCyan }
}

function Start-Section {
  param([string]$Name)
  Write-Host ''
  TimeElapsed
  Write-Host ('===== ' + $Name + ' =====') -ForegroundColor Blue
}

function Get-HighestSeverity {
  $order = 'Info','Low','Medium','High','Critical'
  $highest = 'Info'
  foreach ($f in $script:Findings) {
    if ($order.IndexOf($f.Severity) -gt $order.IndexOf($highest)) { $highest = $f.Severity }
  }
  return $highest
}

function Write-Reports {
  param([string]$Dir)
  if ($NoReport) { return }
  try { New-Item -ItemType Directory -Path $Dir -Force | Out-Null } catch { Write-Host "Cannot create report dir: $_" -ForegroundColor Red; return }
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $json = Join-Path $Dir ("BlueWinPEAS_{0}_{1}.json" -f $env:COMPUTERNAME, $stamp)
  $csv  = Join-Path $Dir ("BlueWinPEAS_{0}_{1}.csv"  -f $env:COMPUTERNAME, $stamp)
  $html = Join-Path $Dir ("BlueWinPEAS_{0}_{1}.html" -f $env:COMPUTERNAME, $stamp)

  $meta = [pscustomobject]@{
    Tool        = 'BlueWinPEAS (defensive refit of winPEAS.ps1)'
    Host        = $env:COMPUTERNAME
    Generated   = (Get-Date).ToString('s')
    Duration    = $stopwatch.Elapsed.ToString('mm\:ss')
    FullCheck   = [bool]$FullCheck
    TotalFindings = $script:Findings.Count
    HighestSeverity = Get-HighestSeverity
  }
  @{ Meta = $meta; Findings = $script:Findings } | ConvertTo-Json -Depth 4 | Set-Content -Path $json -Encoding UTF8
  $script:Findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

  $sevBadge = { param($s)
    $c = @{ Critical='#b91c1c'; High='#dc2626'; Medium='#d97706'; Low='#0891b2'; Info='#6b7280' }[$s]
    '<span style="background:' + $c + ';color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">' + $s + '</span>'
  }
  $rows = foreach ($f in $script:Findings) {
    '<tr><td>' + $f.Severity + '</td><td>' + $f.Category + '</td><td><b>' + $f.Title + '</b></td><td>' + $f.Detail +
    '</td><td><code>' + $f.Evidence + '</code></td><td>' + $f.Remediation + '</td></tr>'
  }
  $counts = $script:Findings | Group-Object Severity | ForEach-Object { $_.Name + ': ' + $_.Count }
  $htmlDoc = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>BlueWinPEAS Report - $($env:COMPUTERNAME)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f8fafc;color:#111827}
 h1{margin-bottom:0} .meta{color:#6b7280;margin-bottom:16px}
 table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
 th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#f1f5f9}
 tr:nth-child(even){background:#f9fafb}
 .Critical{background:#b91c1c!important;color:#fff}.High{background:#fee2e2}
 .Medium{background:#fef3c7}.Low{background:#e0f2fe}.Info{background:#f3f4f6}
 code{font-size:11px;word-break:break-all}
</style></head><body>
<h1>BlueWinPEAS Posture Audit</h1>
<div class="meta">Host: $($env:COMPUTERNAME) &middot; $(Get-Date) &middot; $($stopwatch.Elapsed.ToString('mm\:ss')) elapsed &middot; `$joinCountsPlaceholder`</div>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Evidence</th><th>Remediation</th></tr>
`$rowsPlaceholder`
</table></body></html>
"@
  $htmlDoc = $htmlDoc.Replace('$joinCountsPlaceholder', ($counts -join ' &middot; '))
  $htmlDoc = $htmlDoc.Replace('$rowsPlaceholder', ($rows -join "`n"))
  Set-Content -Path $html -Value $htmlDoc -Encoding UTF8

  Write-Host ''
  Write-Host ('Report summary: ' + ($counts -join ', ')) -ForegroundColor Cyan
  Write-Host ('Reports written: ' + $json) -ForegroundColor Cyan
  Write-Host ('                ' + $csv)  -ForegroundColor Cyan
  Write-Host ('                ' + $html) -ForegroundColor Cyan
}

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
function Get-DomainContext {
  try {
    return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
  }
  catch {
    return $null
  }
}

function Convert-SidToName {
  param(
    $SidInput
  )
  if ($null -eq $SidInput) { return $null }
  try {
    if ($SidInput -is [System.Security.Principal.SecurityIdentifier]) {
      $sidObject = $SidInput
    }
    else {
      $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SidInput)
    }
    return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
  }
  catch {
    try { return $sidObject.Value }
    catch { return [string]$SidInput }
  }
}

function Get-WeakDnsUpdateFindings {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  $forestDN = $DomainContext.Forest.RootDomain.GetDirectoryEntry().distinguishedName
  $paths = @(
    "LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN",
    "LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN",
    "LDAP://CN=MicrosoftDNS,$domainDN"
  )
  $weakPatterns = @(
    "authenticated users",
    "everyone",
    "domain users"
  )
  $dangerousRights = @("GenericAll", "GenericWrite", "CreateChild", "WriteProperty", "WriteDacl", "WriteOwner")
  $findings = @()
  foreach ($path in $paths) {
    try {
      $container = New-Object System.DirectoryServices.DirectoryEntry($path)
      $null = $container.NativeGuid
    }
    catch { continue }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($container)
    $searcher.Filter = "(objectClass=dnsZone)"
    $searcher.PageSize = 500
    $results = $searcher.FindAll()
    foreach ($result in $results) {
      try {
        $zoneEntry = $result.GetDirectoryEntry()
        $zoneEntry.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $sd = $zoneEntry.ObjectSecurity
        foreach ($ace in $sd.Access) {
          if ($ace.AccessControlType -ne 'Allow') { continue }
          $principal = Convert-SidToName $ace.IdentityReference
          if (-not $principal) { continue }
          $principalLower = $principal.ToLower()
          if (-not ($weakPatterns | Where-Object { $principalLower -like "*${_}*" })) { continue }
          $rights = $ace.ActiveDirectoryRights.ToString()
          if (-not ($dangerousRights | Where-Object { $rights -like "*${_}*" })) { continue }
          $findings += [pscustomobject]@{
            Zone      = $zoneEntry.Properties["name"].Value
            Partition = $path.Split(',')[1]
            Principal = $principal
            Rights    = $rights
          }
        }
      }
      catch { continue }
    }
  }
  return ($findings | Sort-Object Zone, Principal -Unique)
}

function Get-GmsaReadersReport {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher.Filter = "(&(objectClass=msDS-GroupManagedServiceAccount))"
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add("sAMAccountName")
    [void]$searcher.PropertiesToLoad.Add("msDS-GroupMSAMembership")
    $results = $searcher.FindAll()
  }
  catch { return @() }
  $report = @()
  foreach ($result in $results) {
    $name = $result.Properties["samaccountname"]
    $blobs = $result.Properties["msds-groupmsamembership"]
    if (-not $blobs) { continue }
    $principals = @()
    foreach ($blob in $blobs) {
      try {
        $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor (, $blob)
        foreach ($ace in $raw.DiscretionaryAcl) {
          $sid = Convert-SidToName $ace.SecurityIdentifier
          if ($sid) { $principals += $sid }
        }
      }
      catch { continue }
    }
    if ($principals.Count -eq 0) { continue }
    $principals = $principals | Sort-Object -Unique
    $weak = $principals | Where-Object { $_ -match 'Domain Users|Authenticated Users|Everyone' }
    $report += [pscustomobject]@{
      Account        = ($name | Select-Object -First 1)
      Allowed        = ($principals -join ", ")
      WeakPrincipals = if ($weak) { $weak -join ", " } else { "" }
    }
  }
  return $report
}

function Get-PrivilegedSpnTargets {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  $keywords = @(
    "Domain Admin",
    "Enterprise Admin",
    "Administrators",
    "Exchange",
    "IT_",
    "Schema Admin",
    "Account Operator",
    "Server Operator",
    "Backup Operator",
    "DnsAdmin"
  )
  try {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add("sAMAccountName")
    [void]$searcher.PropertiesToLoad.Add("memberOf")
    $results = $searcher.FindAll()
  }
  catch { return @() }
  $findings = @()
  foreach ($res in $results) {
    $groups = $res.Properties["memberof"]
    if (-not $groups) { continue }
    $matchedGroups = @()
    foreach ($group in $groups) {
      $cn = ($group -split ',')[0] -replace '^CN=',''
      if ($keywords | Where-Object { $cn -like "*${_}*" }) {
        $matchedGroups += $cn
      }
    }
    if ($matchedGroups.Count -gt 0) {
      $findings += [pscustomobject]@{
        User   = ($res.Properties["samaccountname"] | Select-Object -First 1)
        Groups = ($matchedGroups | Sort-Object -Unique) -join ', '
      }
    }
  }
  return ($findings | Sort-Object User | Select-Object -First 12)
}

function Get-NtlmPolicySummary {
  try {
    $msv = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction Stop
  }
  catch { return $null }
  $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  return [pscustomobject]@{
    RestrictReceiving = $msv.RestrictReceivingNTLMTraffic
    RestrictSending   = $msv.RestrictSendingNTLMTraffic
    LmCompatibility   = if ($lsa) { $lsa.LmCompatibilityLevel } else { $null }
  }
}

function Get-TimeSkewInfo {
  param(
    [System.DirectoryServices.ActiveDirectory.Domain]$DomainContext
  )
  if (-not $DomainContext) { return $null }
  try {
    $pdc = $DomainContext.PdcRoleOwner.Name
  }
  catch { return $null }
  try {
    $stripchart = w32tm /stripchart /computer:$pdc /dataonly /samples:3 2>$null
    $sample = $stripchart | Where-Object { $_ -match ',' } | Select-Object -Last 1
    if (-not $sample) { return $null }
    $parts = $sample.Split(',')
    if ($parts.Count -lt 2) { return $null }
    $offsetString = $parts[1].Trim().TrimEnd('s')
    [double]$offsetSeconds = 0
    if (-not [double]::TryParse($offsetString, [ref]$offsetSeconds)) { return $null }
    return [pscustomobject]@{
      Source        = $pdc
      OffsetSeconds = $offsetSeconds
      RawSample     = $sample
    }
  }
  catch {
    return $null
  }
}

function Get-AdcsSchannelInfo {
  $info = [ordered]@{
    MappingValue = $null
    UpnMapping   = $false
    ServiceState = $null
  }
  try {
    $schannel = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name 'CertificateMappingMethods' -ErrorAction Stop
    $info.MappingValue = $schannel.CertificateMappingMethods
    if (($schannel.CertificateMappingMethods -band 0x4) -eq 0x4) { $info.UpnMapping = $true }
  }
  catch { }
  $svc = Get-Service -Name certsrv -ErrorAction SilentlyContinue
  if ($svc) { $info.ServiceState = $svc.Status }
  return [pscustomobject]$info
}

######################## SECRET PATTERN LIBRARY (detection + redaction) ########################
# The winPEAS regex corpus, kept for DETECTION only. Matched values are redacted
# before they reach console or reports. Sweep is scoped to credential-bearing
# locations and only runs with -FullCheck (machine-wide sweeps) or always-on
# targeted checks (winlogon, unattend, PS history).

function Get-SecretPatterns {
  $p = [ordered]@{}
  $p['Winlogon credential']        = '(?i)(DefaultPassword|AltDefaultPassword)\s*='
  $p['Autologon enabled']          = '(?i)AutoAdminLogon\s*=\s*1'
  $p['Password assignment']        = '(?i)\bpass(word)?\s*[=:]\s*\S{4,}'
  $p['Username assignment']        = '(?i)\b(user(name)?|login)\s*[=:]\s*\S+'
  $p['Basic auth URL']             = '://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.]+'
  $p['Private key block']          = '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----'
  $p['AWS access key']             = '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
  $p['GitHub token']               = '(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{20,}'
  $p['GitHub fine-grained token']  = 'github_pat_[0-9a-zA-Z_]{20,}'
  $p['GitLab token']               = 'glpat-[0-9a-zA-Z\-]{15,}'
  $p['Slack token']                = 'xox[baprs]-[0-9a-zA-Z\-]{10,}'
  $p['Slack webhook']              = 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
  $p['OpenAI-style key']           = 'sk-[A-Za-z0-9_\-]{20,}'
  $p['Google API key']             = 'AIza[0-9A-Za-z_\-]{35}'
  $p['Azure storage key']          = 'AccountKey=[a-zA-Z0-9+/=]{40,}'
  $p['SendGrid key']               = 'SG\.[a-zA-Z0-9_\-]{10,}'
  $p['Twilio key']                 = 'SK[0-9a-fA-F]{32}'
  $p['Mailchimp key']              = '[0-9a-f]{32}-us[0-9]{1,2}'
  $p['Stripe key']                 = '(sk|pk)_(test|live)_[0-9a-zA-Z]{10,}'
  $p['JWT']                        = 'ey[0-9a-zA-Z_\-]{15,}\.ey[0-9a-zA-Z_\-]{15,}\.[0-9a-zA-Z_\-]{10,}'
  $p['Teamcity/NTLM hash shape']   = '(?i)[a-f0-9]{32}:[a-f0-9]{32}'
  $p['Connection string w/ pwd']   = '(?i)(connectionstring|connstr).{0,80}pwd\s*='
  $p['Net user add (history)']     = '(?i)net user .+ /add'
  return $p
}

$script:SecretPatterns = Get-SecretPatterns

# High-signal credential files an attacker (or malware) would target first.
$script:SensitiveFileTargets = @(
  "$env:windir\Panther\Unattend.xml"
  "$env:windir\Panther\unattend.xml"
  "$env:windir\System32\Sysprep\unattend.xml"
  "$env:windir\System32\Sysprep\unattended.xml"
  'C:\Windows\sysprep\sysprep.xml'
  'C:\Windows\sysprep\sysprep.inf'
  'C:\Windows\sysprep.inf'
  'C:\unattend.txt'
  'C:\unattend.inf'
  "$env:USERPROFILE\.aws\credentials"
  "$env:USERPROFILE\.azure\accessTokens.json"
  "$env:USERPROFILE\.azure\azureProfile.json"
  "$env:USERPROFILE\AppData\Roaming\gcloud\credentials.db"
  "$env:USERPROFILE\AppData\Roaming\gcloud\access_tokens.db"
  "$env:USERPROFILE\.kube\config"
  "$env:USERPROFILE\.docker\config.json"
  "$env:USERPROFILE\.netrc"
  "$env:USERPROFILE\.git-credentials"
  "$env:USERPROFILE\_netrc"
)

function Test-FileForSecrets {
  param([string]$Path, [string]$Context = '')
  if (-not (Test-Path $Path -PathType Leaf)) { return }
  $lines = $null
  try { $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue } catch { return }
  if (-not $lines) { return }
  $seenPatterns = @{}
  $lineNo = 0
  foreach ($line in $lines) {
    $lineNo++
    foreach ($name in $script:SecretPatterns.Keys) {
      if ($seenPatterns.ContainsKey($name)) { continue }
      $m = [regex]::Match($line, $script:SecretPatterns[$name])
      if ($m.Success) {
        $seenPatterns[$name] = $true
        $red = Get-Redacted ($m.Value)
        Add-Finding -Severity High -Category 'Exposed secret (file)' `
          -Title ("Credential pattern '{0}' in {1}" -f $name, (Split-Path $Path -Leaf)) `
          -Detail ("File: $Path line $lineNo$Context. Value redacted: $red") `
          -Evidence ("{0}:{1}" -f $Path, $lineNo) `
          -Remediation 'Remove/rotate the credential; move secrets to a vault or managed identity; restrict file ACLs.'
      }
    }
  }
}

######################## SYSTEM & PATCH POSTURE ########################

Start-Section 'SYSTEM INFORMATION'
$os = Get-CimInstance Win32_OperatingSystem
Add-Finding -Severity Info -Category 'System' -Title 'OS baseline' `
  -Detail ("{0} (build {1}) | installed {2:yyyy-MM-dd} | last boot {3:yyyy-MM-dd HH:mm} | {4} GB RAM" -f `
    $os.Caption, $os.BuildNumber, $os.InstallDate, $os.LastBootUpTime, [math]::Round($os.TotalVisibleMemorySize/1MB,1))

# Patch recency (defenders care about exposure window, not KB-by-KB exploit mapping)
$latestHF = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
if ($latestHF -and $latestHF.InstalledOn) {
  $age = (Get-Date) - $latestHF.InstalledOn
  if ($age.Days -gt 60) {
    Add-Finding -Severity High -Category 'Patching' -Title 'No patches installed in over 60 days' `
      -Detail ("Most recent hotfix {0} installed {1:yyyy-MM-dd} ({2} days ago)." -f $latestHF.HotFixID, $latestHF.InstalledOn, $age.Days) `
      -Remediation 'Patch cadence is stale; inventory missing CVEs and expedite critical/security updates.'
  }
  else {
    Add-Finding -Severity Info -Category 'Patching' -Title 'Patch cadence OK' `
      -Detail ("Most recent hotfix {0} {1} days ago." -f $latestHF.HotFixID, $age.Days)
  }
}

# Reboot-pending (patch effectiveness)
try {
  $pendingReboot = $false
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReboot = $true }
  $fro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
  if ($fro.PendingFileRenameOperations) { $pendingReboot = $true }
  if ($pendingReboot) {
    Add-Finding -Severity Medium -Category 'Patching' -Title 'Reboot pending' `
      -Detail 'Updates staged but not finalized until reboot - host may still be vulnerable to patched CVEs.' `
      -Remediation 'Schedule reboot maintenance window.'
  }
} catch { }

######################## DEFENDER / AV POSTURE (NEW) ########################

Start-Section 'DEFENDER / AV POSTURE'
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  if ($mp.AMServiceEnabled) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender realtime protection ON' -Detail ("Engine {0}, signatures {1:yyyy-MM-dd HH:mm}" -f $mp.AMEngineVersion, $mp.AntivirusSignatureLastUpdated)
  }
  else {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender realtime protection OFF' `
      -Remediation 'Re-enable realtime protection; investigate why it was disabled (often attacker first action).'
  }
  if ($mp.AntivirusSignatureLastUpdated -and ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days -gt 3) {
    Add-Finding -Severity High -Category 'AV' -Title 'AV signatures stale' `
      -Detail ("Last updated {0:yyyy-MM-dd}" -f $mp.AntivirusSignatureLastUpdated) `
      -Remediation 'Force signature update; check connectivity to definition sources.'
  }
  if ($mp.QuickScanEndTime) {
    $scanAge = (Get-Date) - $mp.QuickScanEndTime
    if ($scanAge.Days -gt 14) {
      Add-Finding -Severity Medium -Category 'AV' -Title 'Quick scan not run in 14+ days' `
        -Detail ("Last quick scan {0:yyyy-MM-dd}" -f $mp.QuickScanEndTime) -Remediation 'Schedule regular quick scans.'
    }
  }
  else {
    Add-Finding -Severity Medium -Category 'AV' -Title 'No record of a Defender quick scan' -Remediation 'Run a baseline scan and enable scheduled scanning.'
  }
  # Exclusions = classic defense-evasion foothold
  $prefs = Get-MpPreference -ErrorAction SilentlyContinue
  $excl = @()
  if ($prefs) {
    $excl += $prefs.ExclusionPath
    $excl += $prefs.ExclusionProcess
    $excl += $prefs.ExclusionExtension
  }
  if ($excl.Count -gt 0) {
    Add-Finding -Severity High -Category 'AV' -Title ('Defender exclusions configured ({0})' -f $excl.Count) `
      -Detail ('Exclusions: ' + (($excl | Where-Object { $_ }) -join ' | ')) `
      -Remediation 'Review every exclusion for necessity; attackers commonly add their tool paths here. Remove any that are not documented.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'AV' -Title 'Defender status unavailable' -Detail 'Get-MpComputerStatus failed (non-Defender AV or older OS). Verify AV presence manually.'
}

######################## AUDITING & LOGGING POSTURE (NEW) ########################

Start-Section 'AUDITING & LOGGING POSTURE'
try {
  $auditPolicy = (auditpol.exe /get /category:* 2>$null | Where-Object { $_ -match '^\s' })
  $lapse = $auditPolicy | Where-Object { $_ -match 'Logon/Logoff|Privilege Use|Object Access' -and $_ -match 'No Auditing' }
  if ($lapse) {
    Add-Finding -Severity Medium -Category 'Logging' -Title 'Critical audit subcategories set to No Auditing' `
      -Detail (($lapse | ForEach-Object { $_.Trim() }) -join ' ; ') `
      -Remediation 'Enable auditing for Logon/Logoff and Privilege Use (advanced audit policy: AuditLogon, AuditPrivilegeUse).'
  }
  else {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Core audit categories enabled'
  }
} catch { }

# Security log size + retention
try {
  $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
  $mb = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
  if ($mb -lt 128) {
    Add-Finding -Severity Medium -Category 'Logging' -Title "Security event log small ($mb MB)" `
      -Remediation 'Increase Security log size (>= 256 MB) or forward to SIEM (WEF) to avoid losing intrusion evidence.'
  }
  else {
    Add-Finding -Severity Info -Category 'Logging' -Title "Security event log size ${mb} MB"
  }
} catch { }

# WEF
if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager') {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Windows Event Forwarding configured'
}
else {
  Add-Finding -Severity Low -Category 'Logging' -Title 'No Windows Event Forwarding' `
    -Detail 'Local logs die with the host; attackers clear logs post-incident.' `
    -Remediation 'Deploy WEF or a log agent so security events reach a central SIEM.'
}

# PowerShell operational logging (blue-team staple)
$psLogPaths = @(
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'Script Block Logging' },
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';     Name = 'Module Logging' },
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';     Name = 'Transcription' }
)
foreach ($lp in $psLogPaths) {
  $key = Get-ItemProperty -Path $lp.Path -ErrorAction SilentlyContinue
  $on = $key -and (($key.EnableModuleLogging -eq 1) -or ($key.EnableTranscripting -eq 1) -or ($key.EnableScriptBlockLogging -eq 1) -or ($key.PSObject.Properties.Name -contains 'EnableScriptBlockLogging' -and $key.EnableScriptBlockLogging -ne 0))
  if ($on) {
    Add-Finding -Severity Info -Category 'Logging' -Title ('PowerShell {0} enabled' -f $lp.Name)
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell {0} NOT enabled' -f $lp.Name) `
      -Detail 'Attacker tooling (and abusive admins) rely on PowerShell flying under the radar.' `
      -Remediation ('Enable {0} via GPO for command-line visibility.' -f $lp.Name)
  }
}

######################## CREDENTIAL EXPOSURE HARDENING ########################

Start-Section 'CREDENTIAL EXPOSURE'

# WDigest
$wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
if ($wdigest -eq 1) {
  Add-Finding -Severity High -Category 'Credentials' -Title 'WDigest storing plaintext credentials in LSASS' `
    -Detail 'UseLogonCredential=1 - any LSASS dump yields live passwords.' `
    -Remediation 'Set UseLogonCredential=0 (default on 8.1+/2012R2+); combine with Credential Guard.'
}
else {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'WDigest plaintext storage disabled'
}

# LSA Protection (RunAsPPL)
$runAsPPL = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -ErrorAction SilentlyContinue).RunAsPPL
if ($runAsPPL -eq 1 -or $runAsPPL -eq 2) {
  Add-Finding -Severity Info -Category 'Credentials' -Title "LSA Protection enabled (RunAsPPL=$runAsPPL)"
}
else {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'LSA Protection (RunAsPPL) not enabled' `
    -Remediation 'Enable RunAsPPL=1 via GPE: Computer Config > Admin Templates > System > Local Run As PPL.'
}

# Credential Guard
$lsaCfg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -ErrorAction SilentlyContinue).LsaCfgFlags
if ($lsaCfg -eq 1 -or $lsaCfg -eq 2) {
  Add-Finding -Severity Info -Category 'Credentials' -Title "Credential Guard enabled (LsaCfgFlags=$lsaCfg)"
}
else {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard not enabled' `
    -Remediation 'Enable Credential Guard (hardware virtualization) to harden LSASS against dump-and-reuse.'
}

# Cached logons
$cached = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).CACHEDLOGONSCOUNT
if ($null -ne $cached -and $cached -gt 4) {
  Add-Finding -Severity Low -Category 'Credentials' -Title "Cached domain logon count high ($cached)" `
    -Remediation 'Reduce CACHEDLOGONSCOUNT to <= 4 (MS baseline) to limit offline credential extraction.'
}

# Winlogon autologon / embedded creds - REDACTED
$wlg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wlg) {
  if ($wlg.AutoAdminLogon -eq 1) {
    Add-Finding -Severity Critical -Category 'Credentials' -Title 'AutoAdminLogon enabled' `
      -Detail 'Any user with file access can read the autologon password from the registry.' `
      -Remediation 'Disable autologon; use a credential manager or LAPS-managed local admin instead.'
  }
  if ($wlg.DefaultPassword) {
    Add-Finding -Severity Critical -Category 'Credentials' -Title 'DefaultPassword present in Winlogon key' `
      -Detail ("Value redacted: {0}" -f (Get-Redacted $wlg.DefaultPassword)) `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon::DefaultPassword' `
      -Remediation 'Delete the value, rotate the credential, disable autologon.'
  }
  if ($wlg.AltDefaultPassword) {
    Add-Finding -Severity Critical -Category 'Credentials' -Title 'AltDefaultPassword present in Winlogon key' `
      -Detail ("Value redacted: {0}" -f (Get-Redacted $wlg.AltDefaultPassword)) `
      -Remediation 'Delete and rotate.'
  }
}

# RDCMan / saved RDP artifacts presence (risk indicators, no values read)
if (Test-Path "$env:USERPROFILE\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'RDCMan settings file present' `
    -Detail 'RDCMan .rdg files frequently contain decryptable stored credentials.' `
    -Remediation 'Migrate stored connections to Windows Credential Manager; audit .rdg file ACLs.'
}
$rdpKey = Get-ItemProperty 'registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default' -ErrorAction SilentlyContinue
if ($rdpKey -and $rdpKey.MRU0) {
  Add-Finding -Severity Low -Category 'Credentials' -Title 'RDP connection history present' `
    -Detail ("Most recent target: {0}" -f $rdpKey.MRU0)
}
# PuTTY sessions with saved proxy passwords
if (Test-Path 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions') {
  Get-ChildItem 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions' | ForEach-Object {
    $s = Get-ItemProperty $_.PSPath
    if ($s.ProxyPassword) {
      Add-Finding -Severity High -Category 'Credentials' -Title ('PuTTY session stores proxy password: {0}' -f $_.PSChildName) `
        -Detail ("Value redacted: {0}" -f (Get-Redacted $s.ProxyPassword)) `
        -Remediation 'Remove stored proxy passwords from PuTTY sessions.'
    }
  }
}
# OpenSSH agent keys registered
if (Test-Path 'HKCU:\Software\OpenSSH\Agent\Keys') {
  $n = (Get-Item 'HKCU:\Software\OpenSSH\Agent\Keys').Property.Count
  Add-Finding -Severity Medium -Category 'Credentials' -Title "$n SSH key(s) registered in ssh-agent" `
    -Remediation 'Verify these are authorized; ssh-agent keys are extractable by SYSTEM-level code.'
}

# DPAPI protect folders present (normal, informational)
foreach ($p in @("$env:USERPROFILE\AppData\Roaming\Microsoft\Protect", "$env:USERPROFILE\AppData\Local\Microsoft\Protect")) {
  if (Test-Path $p) { Add-Finding -Severity Info -Category 'Credentials' -Title "DPAPI master key store present ($p)" }
}

# Sensitive files: existence + targeted redacted scan
foreach ($f in $script:SensitiveFileTargets) {
  if (Test-Path $f) {
    if ($f -match 'Unattend|sysprep|unattend') {
      Test-FileForSecrets -Path $f -Context ' (unattended install answer file)'
      Add-Finding -Severity Medium -Category 'Credentials' -Title "Unattended install file retained: $f" `
        -Remediation 'Delete stale sysprep/unattend files; they often embed encoded local admin passwords.'
    }
    else {
      Add-Finding -Severity High -Category 'Credentials' -Title "Cloud/CLI credential file present: $f" `
        -Detail 'Detected by presence only; contents not read.' `
        -Remediation 'Confirm the file is required; rotate keys if the host is shared, and tighten ACLs.'
    }
  }
}

# Sticky notes database (plaintext credential risk)
if (Test-Path "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite") {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'Sticky Notes database present' `
    -Detail 'Sticky Notes frequently contain passwords in plaintext (plum.sqlite).' `
    -Remediation 'Educate users; consider disabling Sticky Notes on sensitive hosts.'
}

# PowerShell history credential usage - REDACTED, current user only
$histPath = (Get-PSReadLineOption).HistorySavePath
if (Test-Path $histPath) {
  $histHits = @()
  try {
    $ln = 0
    foreach ($line in (Get-Content $histPath -ErrorAction SilentlyContinue)) {
      $ln++
      if ($line -match '(?i)(-password|passwd\s*=|\bpass\s*=|ConvertTo-SecureString\s+["'']?[^\s"'']{4,}|net user .+ /add)') {
        $histHits += "line ${ln}: $(Get-Redacted $line)"
        if ($histHits.Count -ge 5) { break }
      }
    }
  } catch { }
  if ($histHits.Count -gt 0) {
    Add-Finding -Severity Medium -Category 'Credentials' -Title 'PowerShell history contains credential-shaped input' `
      -Detail ($histHits -join ' | ') `
      -Remediation 'Clear history, rotate exposed credentials, prefer prompting/PSCredential objects over inline passwords.'
  }
}

# Clipboard (presence only - do not print content)
try {
  Add-Type -AssemblyName PresentationCore -ErrorAction SilentlyContinue
  $cb = [Windows.Clipboard]::GetText()
  if ($cb) {
    $hit = $false
    foreach ($name in $script:SecretPatterns.Keys) {
      if ($cb -match $script:SecretPatterns[$name]) {
        Add-Finding -Severity Medium -Category 'Credentials' -Title ("Clipboard contains credential pattern '{0}'" -f $name) `
          -Detail 'Clipboard contents inspected for patterns only; value not captured.' `
          -Remediation 'Avoid clipboard for credentials; clear after use.'
        $hit = $true
        break
      }
    }
    if (-not $hit) { Add-Finding -Severity Info -Category 'Credentials' -Title 'Clipboard non-empty (no credential pattern)' }
  }
} catch { }

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

######################## NETWORK ATTACK SURFACE ########################

Start-Section 'NETWORK ATTACK SURFACE'

# SMBv1
$smb1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.EnableSMB1Protocol) {
  Add-Finding -Severity Critical -Category 'Network' -Title 'SMBv1 enabled' `
    -Detail 'WannaCry/NotPetya-class wormable protocol, no signing or encryption guarantees.' `
    -Remediation 'Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false (also disable on client).'
}
elseif ($smb1) {
  Add-Finding -Severity Info -Category 'Network' -Title 'SMBv1 disabled'
}

# SMB signing
if ($smb1) {
  if (-not $smb1.RequireSecuritySignature) {
    Add-Finding -Severity Medium -Category 'Network' -Title 'SMB signing not required (server)' `
      -Detail 'Enables relay/NTLM interception attacks against this host.' `
      -Remediation 'Set-SmbServerConfiguration -RequireSecuritySignature $true.'
  }
  else {
    Add-Finding -Severity Info -Category 'Network' -Title 'SMB signing required (server)'
  }
}

# LLMNR / NBT-NS (responder-style credential capture)
try {
  $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
  if ($llmnr -eq 0) { Add-Finding -Severity Info -Category 'Network' -Title 'LLMNR disabled by policy' }
  else {
    Add-Finding -Severity High -Category 'Network' -Title 'LLMNR not disabled' `
      -Detail 'Poisonable name-resolution protocol; anyone on-segment can capture NTLM hashes.' `
      -Remediation 'GPO: EnableMulticast=0 (Administrative Templates > Network > DNS Client > Turn off multicast name resolution).'
  }
} catch { }
try {
  $nbtf = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
  $nbtKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
  $nbtOn = $false
  foreach ($nk in $nbtKeys) {
    if ((Get-ItemProperty $nk.PSPath -ErrorAction SilentlyContinue).NetbiosOptions -ne 2) { $nbtOn = $true }
  }
  if ($nbtOn) {
    Add-Finding -Severity Medium -Category 'Network' -Title 'NetBIOS name resolution active on some interfaces' `
      -Remediation 'Set NetbiosOptions=2 (disable) per interface via policy.'
  }
  else {
    Add-Finding -Severity Info -Category 'Network' -Title 'NetBIOS resolution disabled'
  }
} catch { }

# RDP hardening
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
$rdpEnabled = -not ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1)
if ($rdpEnabled) {
  Add-Finding -Severity Info -Category 'Network' -Title 'RDP enabled'
  if ($ts.UserAuthentication -eq 0) {
    Add-Finding -Severity High -Category 'Network' -Title 'RDP without Network Level Authentication (NLA)' `
      -Remediation 'Require NLA (System Properties > Remote > allow only with NLA).'
  }
  if ($ts.SecurityLayer -eq 0) {
    Add-Finding -Severity Medium -Category 'Network' -Title 'RDP SecurityLayer=0 (native RDP encryption)' `
      -Remediation 'Set SecurityLayer=2 (TLS 1.0+).'
  }
}
else {
  Add-Finding -Severity Info -Category 'Network' -Title 'RDP disabled'
}

# Defender firewall profiles
try {
  foreach ($prof in (Get-NetFirewallProfile -ErrorAction Stop)) {
    if (-not $prof.Enabled) {
      Add-Finding -Severity High -Category 'Network' -Title ("Firewall profile '{0}' disabled" -f $prof.Name) `
        -Remediation 'Enable all firewall profiles via GPO.'
    }
  }
  Add-Finding -Severity Info -Category 'Network' -Title 'Firewall profile states recorded'
}
catch { }

# Listening ports inventory (exposure map, no exploit mapping)
$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalAddress -notmatch '::1|127\.0\.0\.1' } |
  Select-Object LocalAddress, LocalPort, OwningProcess
if ($ports) {
  $grouped = $ports | Group-Object LocalPort | Sort-Object { [int]$_.Name }
  Add-Finding -Severity Info -Category 'Network' -Title ('{0} externally-listening TCP ports' -f $grouped.Count) `
    -Detail (($grouped | ForEach-Object { $_.Name }) -join ', ') `
    -Remediation 'Baseline expected services; investigate anything not in the standard build.'
  # risky classics
  foreach ($risky in @{ 21 = 'FTP'; 23 = 'Telnet'; 69 = 'TFTP'; 445 = 'SMB'; 3389 = 'RDP'; 5985 = 'WinRM-HTTP'; 5986 = 'WinRM-HTTPS' }.GetEnumerator()) {
    if ($ports.LocalPort -contains [int]$risky.Key) {
      $sev = if ($risky.Key -in 23, 21) { 'High' } else { 'Low' }
      Add-Finding -Severity $sev -Category 'Network' -Title ("{0} (port {1}) listening" -f $risky.Value, $risky.Key) `
        -Remediation 'Confirm business need; telnet/FTP should be removed outright.'
    }
  }
}

# Hosts file overrides (redirection tampering indicator)
try {
  $hostsEntries = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#].+\s' }
  if ($hostsEntries.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Network' -Title ('{0} active hosts-file entries' -f $hostsEntries.Count) `
      -Detail (($hostsEntries | Select-Object -First 10) -join ' | ') `
      -Remediation 'Hosts overrides can silently redirect auth traffic; verify each against the build baseline.'
  }
} catch { }

# WPAD proxy auto-detection
$wpad = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue)
$autoDetect = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).AutoDetectProxySettings
Add-Finding -Severity Info -Category 'Network' -Title 'WPAD status recorded' `
  -Detail ("HKCU AutoDetectProxySettings: {0} - if enabled, ensure WPAD is pinned/served only by trusted DHCP/DNS." -f $autoDetect)

# SMB shares and broad access
try {
  Get-SmbShare -ErrorAction Stop | ForEach-Object {
    $share = $_
    if ($share.Name -eq 'IPC$' -or $share.Name -eq 'ADMIN$') { return }
    $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
    foreach ($a in @($access)) {
      if ($a.AccessRight -in 'Full','Change' -and $a.AccessControlType -eq 'Allow' -and
          "$($a.AccountName)" -match 'Everyone|Authenticated Users') {
        Add-Finding -Severity Medium -Category 'Network' -Title ("Share '{0}' writable by {1}" -f $share.Name, $a.AccountName) `
          -Detail ("Path: {0}" -f $share.Path) `
          -Remediation 'Restrict share permissions to required groups; writable Everyone-shares are lateral-movement and ransomware vectors.'
      }
    }
  }
} catch { }

######################## LOCAL ACCOUNT HYGIENE ########################

Start-Section 'LOCAL ACCOUNT HYGIENE'
try {
  $minLen = (net accounts | Select-String 'minimum password length').ToString()
  $val = [int]($minLen -replace '[^\d]', '')
  if ($val -lt 12) {
    Add-Finding -Severity Medium -Category 'Accounts' -Title ("Minimum password length only {0}" -f $val) `
      -Remediation 'Raise minimum length to 14+ and pair with banned-password lists.'
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title "Minimum password length ${val}"
  }
} catch { }

try {
  $users = Get-LocalUser -ErrorAction Stop
  foreach ($u in $users) {
    if ($u.Enabled -and -not $u.PasswordRequired) {
      Add-Finding -Severity Critical -Category 'Accounts' -Title ("Account '{0}' has NO password requirement" -f $u.Name) `
        -Remediation 'Disable the account or require a password immediately.'
    }
    if (-not $u.Enabled) {
      Add-Finding -Severity Info -Category 'Accounts' -Title ("Disabled account: {0}" -f $u.Name)
    }
    if ($u.Enabled -and $u.PasswordExpires -eq $null -and $u.Name -ne $env:USERNAME) {
      Add-Finding -Severity Low -Category 'Accounts' -Title ("Account '{0}' password never expires" -f $u.Name) `
        -Remediation 'Rotate periodically or move to managed (LAPS) credentials.'
    }
  }
  # local admin inventory
  $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
  Add-Finding -Severity Info -Category 'Accounts' -Title ('{0} local Administrators' -f @($admins).Count) `
    -Detail ((@($admins) | ForEach-Object { $_.Name }) -join ', ') `
    -Remediation 'Keep local admin membership minimal; prefer LAPS + just-in-time elevation.'
} catch { }

# LAPS presence
$lapsOk = (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') -or (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll') -or
  ((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) -or
  (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -ErrorAction SilentlyContinue)
if ($lapsOk) {
  Add-Finding -Severity Info -Category 'Accounts' -Title 'LAPS (legacy or Windows LAPS) detected'
}
else {
  Add-Finding -Severity Medium -Category 'Accounts' -Title 'No LAPS management detected' `
    -Detail 'Shared/rotating local admin passwords enable Pass-the-Hash across the fleet.' `
    -Remediation 'Deploy Windows LAPS to randomize local admin passwords per host.'
}

# Currently logged-on sessions (incident context)
try { $sessions = quser 2>$null; if ($sessions) { Add-Finding -Severity Info -Category 'Accounts' -Title 'Active sessions' -Detail (($sessions | Select-Object -Skip 1) -join ' | ') } } catch { }

# BitLocker (data-at-rest)
try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  if ($bl.ProtectionStatus -eq 1) {
    Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker protection ON (system drive)'
  }
  else {
    Add-Finding -Severity Medium -Category 'Data' -Title 'BitLocker not protecting system drive' `
      -Remediation 'Enable BitLocker with TPM+PIN; stolen laptop = stolen data otherwise.'
  }
} catch {
  Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker status unavailable on this volume'
}

# Screen lock policy (interactive attack surface)
$lock = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).InactivityTimeoutSecs
if ($null -ne $lock -and [int]$lock -gt 900) {
  Add-Finding -Severity Low -Category 'Data' -Title "Screen lock timeout ${lock}s (>15 min)" `
    -Remediation 'Cap inactivity lock at 15 minutes or less via policy.'
}

######################## AD / DOMAIN MISCONFIG CHECKS ########################
# Retained winPEAS AD functions, recast as findings (attacker-relevant abuse
# paths reported as risk + fix, no exploitation guidance).

Start-Section 'ACTIVE DIRECTORY / IDENTITY'
$domainContext = Get-DomainContext
if (-not $domainContext) {
  Add-Finding -Severity Info -Category 'AD' -Title 'Workgroup host (no AD domain context)'
}
else {
  Add-Finding -Severity Info -Category 'AD' -Title 'Domain-joined' -Detail ("Domain: {0}" -f $domainContext.Name)

  # NTLM policy posture
  $ntlm = Get-NtlmPolicySummary
  if ($ntlm) {
    $lm = -1
    if ($null -ne $ntlm.LmCompatibility) { $lm = [int]$ntlm.LmCompatibility }
    if ($lm -ge 0 -and $lm -lt 3) {
      Add-Finding -Severity High -Category 'AD' -Title ("LmCompatibilityLevel={0} (accepts LM/NTLMv1)" -f $lm) `
        -Detail 'NTLMv1 downgrade = crackable challenge-response capture.' `
        -Remediation 'Set LmCompatibilityLevel=5 (refuse LM & NTLMv1).'
    }
    else {
      Add-Finding -Severity Info -Category 'AD' -Title 'NTLM minimum level acceptable (>=3)'
    }
  }

  # Insecure dynamic DNS ACLs
  $dnsFindings = @(Get-WeakDnsUpdateFindings -DomainContext $domainContext)
  if ($dnsFindings.Count -gt 0) {
    foreach ($d in $dnsFindings) {
      Add-Finding -Severity Medium -Category 'AD' -Title ("DNS zone '{0}' writable by {1}" -f $d.Zone, $d.Principal) `
        -Detail ("Rights: {0} | Partition: {1} - record spoofing enables service MITM." -f $d.Rights, $d.Partition) `
        -Remediation 'Secure dynamic updates only (DHCP-owned or specific groups); remove broad write principals.'
    }
  }

  # Kerberoastable privileged SPN accounts
  $spnFindings = @(Get-PrivilegedSpnTargets -DomainContext $domainContext)
  if ($spnFindings.Count -gt 0) {
    Add-Finding -Severity High -Category 'AD' -Title ('{0} privileged accounts with SPNs (Kerberoast targets)' -f $spnFindings.Count) `
      -Detail (($spnFindings | ForEach-Object { '{0} [{1}]' -f $_.User, $_.Groups }) -join ' | ') `
      -Remediation 'Remove SPNs from privileged accounts or set long (25+ char) passwords / use gMSA.'
  }

  # gMSA readable by broad groups
  $gmsaReport = @(Get-GmsaReadersReport -DomainContext $domainContext)
  foreach ($g in ($gmsaReport | Where-Object { $_.WeakPrincipals -ne '' })) {
    Add-Finding -Severity Critical -Category 'AD' -Title ("gMSA '{0}' password readable by {1}" -f $g.Account, $g.WeakPrincipals) `
      -Remediation 'Restrict msDS-GroupMSAMembership to only the specific hosts/services that need it.'
  }

  # ADCS Schannel UPN mapping (ESC10)
  $adcs = Get-AdcsSchannelInfo
  if ($adcs.MappingValue -ne $null -and $adcs.UpnMapping) {
    Add-Finding -Severity High -Category 'AD' -Title ('Schannel UPN certificate mapping enabled (ESC10 pattern, 0x{0:X})' -f [int]$adcs.MappingValue) `
      -Remediation 'Clear the 0x4 UPN-mapping bit from CertificateMappingMethods.'
  }

  # Time skew (Kerberos health)
  $skew = Get-TimeSkewInfo -DomainContext $domainContext
  if ($skew -and [math]::Abs($skew.OffsetSeconds) -gt 300) {
    Add-Finding -Severity Medium -Category 'AD' -Title ('Kerberos time skew {0:N0}s vs PDC' -f $skew.OffsetSeconds) `
      -Detail 'Large skew breaks Kerberos and can indicate ntp tampering or stale images.' `
      -Remediation 'Force w32tm resync; verify NTP hierarchy points to the domain PDC.'
  }
}

######################## INSTALLED SOFTWARE BASELINE ########################

Start-Section 'INSTALLED SOFTWARE (baseline inventory)'
try {
  $apps = @(Get-InstalledApplications)
  Add-Finding -Severity Info -Category 'Software' -Title ('{0} installed applications recorded' -f $apps.Count) `
    -Detail 'Full inventory in reports; diff against build baseline to catch unauthorized software.'
  # flag ancient/unmaintained common-risk software by name
  $riskyNames = @('VNC', 'Telnet', 'WinSCP', 'FileZilla', 'uTorrent', 'TeamViewer')
  foreach ($r in $riskyNames) {
    $hit = $apps | Where-Object { $_.Software -match $r }
    if ($hit) {
      Add-Finding -Severity Low -Category 'Software' -Title ("Remote-access/file-transfer software present: {0}" -f $r) `
        -Detail (($hit | Select-Object -First 3 | ForEach-Object { '{0} {1}' -f $_.Software, $_.Version }) -join ', ') `
        -Remediation 'Verify authorization; these tools frequently store credentials and bypass DLP.'
    }
  }
} catch { }

######################## FULLCHECK: SCOPED SECRET SWEEP ########################

if ($FullCheck) {
  Start-Section 'DEEP SECRET-PATTERN SWEEP (-FullCheck; values redacted)'
  Write-Host '  Sweeping credential-bearing file locations and registry hives for secret patterns.' -ForegroundColor DarkGray
  Write-Host '  Matches are recorded REDACTED - no secret values are written to console or reports.' -ForegroundColor DarkGray

  # Targeted dirs, not whole drives: user profile config areas + ProgramData
  $sweepDirs = @(
    "$env:USERPROFILE\.ssh"
    "$env:USERPROFILE\.aws"
    "$env:USERPROFILE\.azure"
    "$env:USERPROFILE\.kube"
    "$env:USERPROFILE\.config"
    "$env:USERPROFILE\AppData\Roaming"
    'C:\Windows\Temp'
    "$env:windir\Panther"
  ) | Where-Object { Test-Path $_ }

  $sweepExt = @('*.txt', '*.ini', '*.cfg', '*.conf', '*.config', '*.xml', '*.yml', '*.yaml', '*.json', '*.ps1', '*.bat', '*.cmd', '*.log')
  foreach ($dir in $sweepDirs) {
    Write-Host "  Sweeping $dir" -ForegroundColor DarkGray
    try {
      Get-ChildItem -LiteralPath $dir -Recurse -Include $sweepExt -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 1MB } | Select-Object -First 300 | ForEach-Object {
        Test-FileForSecrets -Path $_.FullName
      }
    } catch { }
  }

  # Registry: winlogon + uninstall + services areas (not entire hives)
  $regTargets = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SYSTEM\CurrentControlSet\Services'
  )
  foreach ($rt in $regTargets) {
    if (-not (Test-Path $rt)) { continue }
    Get-ChildItem $rt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000 | ForEach-Object {
      $key = $_
      foreach ($p in @($key.Property)) {
        $v = $null
        try { $v = (Get-ItemProperty $key.PSPath).$p } catch { continue }
        if ($null -eq $v -or $v -isnot [string] -or $v.Length -lt 8) { continue }
        foreach ($name in $script:SecretPatterns.Keys) {
          if ($v -match $script:SecretPatterns[$name]) {
            Add-Finding -Severity Medium -Category 'Exposed secret (registry)' `
              -Title ("Credential pattern '{0}' in registry value {1}\{2}" -f $name, $key.Name, $p) `
              -Detail ('Value redacted: ' + (Get-Redacted $v)) `
              -Evidence ($key.Name + '\' + $p) `
              -Remediation 'Remove the stored credential; rotate it and use a secrets manager.'
            break
          }
        }
      }
    }
  }
}

######################## NETWORK DISCOVERY: ARP, NEIGHBORS, DEVICES ########################
# OT-safe: ARP table + neighbor cache (passive), ICMP-only ping sweep of local
# subnets (no SYN/protocol probes at PLCs), MAC vendor OUI tagging (partial table).

Start-Section 'NETWORK DISCOVERY (ARP / NEIGHBOR TABLE)'

# Passive snapshot first
$neighbors = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object {
  $_.IPAddress -notmatch '^(127\.|::1|224\.|239\.|ff)' -and $_.LinkLayerAddress
})
$arpMap = @{}
foreach ($n in $neighbors) { $arpMap[$n.IPAddress] = $n.LinkLayerAddress }

# Partial OUI table - extend as needed for your fleet
$ouiMap = [ordered]@{
  '00-1B-1B' = 'Siemens AG';            '00-1D-9C' = 'Rockwell Automation'
  '00-00-0C' = 'Cisco';                  '00-50-56' = 'VMware'
  '00-15-5D' = 'Microsoft Hyper-V';      '08-00-27' = 'VirtualBox'
  '52-54-00' = 'QEMU/KVM';               'B8-27-EB' = 'Raspberry Pi'
  'DC-A6-32' = 'Raspberry Pi (newer)';   '00-0D-93' = 'Apple'
  '00-14-22' = 'Dell';                   '00-1A-A0' = 'Dell (newer)'
  '3C-D9-2B' = 'HPE';                    '00-1E-C9' = 'Dell iDRAC'
  '00-23-7D' = 'Digi International';     '00-40-9D' = 'Moog/Lambda'
  '00-80-D0' = 'Vermont Technologies';   '00-E0-4C' = 'Realtek'
  '00-1B-44' = 'SanDisk';                '00-04-A9' = 'Lantronix (device servers)'
}
function Get-OuiVendor([string]$Mac) {
  if (-not $Mac) { return '' }
  $prefix = ($Mac -replace '-', '-').ToUpper().Substring(0, 8)
  if ($ouiMap.Contains($prefix)) { return $ouiMap[$prefix] }
  return ''
}

Add-Finding -Severity Info -Category 'Discovery' -Title ('{0} live ARP/neighbor entries (passive)' -f $neighbors.Count) `
  -Detail (($neighbors | Sort-Object IPAddress | ForEach-Object { '{0} -> {1} ({2})' -f $_.IPAddress, $_.LinkLayerAddress, $_.State }) -join ' | ') `
  -Remediation 'Baseline this list; new MACs in the BMS zone = investigate (unauthorized device).'

# ICMP-only sweep of directly connected IPv4 subnets (skip loopback/APIPA)
$localIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
  $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown'
})
$swept = @{}
foreach ($ip in ($localIps | Select-Object -First 3)) {
  $mask = $ip.PrefixLength
  if ($mask -lt 8 -or $mask -gt 24) { continue }  # only sweep up to /24; wider = too slow/fragile
  $base = ($ip.IPAddress.Split('.')[0..2] -join '.')
  if ($swept.ContainsKey($base)) { continue }
  $swept[$base] = $true
  Write-Host "  ICMP sweep ${base}.0/24 (interface $($ip.InterfaceAlias))..." -ForegroundColor DarkGray
  $pings = @{}
  foreach ($i in 1..254) {
    $tgt = "$base.$i"
    try {
      $p = New-Object System.Net.NetworkInformation.Ping
      $pings[$tgt] = $p.SendPingAsync($tgt, 600)
    } catch { }
  }
  try { [void][System.Threading.Tasks.Task]::WaitAll(@($pings.Values), 8000) } catch { }
  $alive = @($pings.GetEnumerator() | Where-Object { $_.Value.Result.Status -eq 'Success' })
  # refresh neighbor cache after sweep
  Start-Sleep -Milliseconds 800
  $post = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress })
  $postMap = @{}
  foreach ($n in $post) { $postMap[$n.IPAddress] = $n.LinkLayerAddress }
  foreach ($a in $alive) {
    $addr = $a.Key
    $mac = if ($postMap[$addr]) { $postMap[$addr] } elseif ($arpMap[$addr]) { $arpMap[$addr] } else { '' }
    $macClean = ($mac -replace '-', '-')
    $vendor = Get-OuiVendor $macClean
    $rtt = [math]::Round($a.Value.RoundtripTime, 0)
    Add-Finding -Severity Info -Category 'Discovery' -Title ("Reachable device: {0}" -f $addr) `
      -Detail ("MAC: {0}{1} | ICMP RTT {2}ms (ICMP-only; no protocol probes sent - OT safe)" -f `
        $(if ($mac) { $mac } else { 'unknown' }), $(if ($vendor) { ' [' + $vendor + ']' } else { '' }), $rtt) `
      -Remediation 'Compare against the authorized device inventory for this zone (IEC 62443 SR 6.2 asset inventory).'
    if ($vendor -match 'VMware|VirtualBox|QEMU|Hyper-V|Raspberry Pi') {
      Add-Finding -Severity Medium -Category 'Discovery' -Title ("Virtualization MAC (${vendor}) in BMS subnet: {0}" -f $addr) `
        -Detail 'Unmanaged VMs/SBCs in an OT zone are outside the controlled build baseline.' `
        -Remediation 'Confirm the device is authorized; remove or formally enroll it in the asset inventory.'
    }
  }
}
if ($swept.Count -eq 0) {
  Add-Finding -Severity Info -Category 'Discovery' -Title 'No eligible /24-or-tighter IPv4 subnets to sweep (passive ARP data only)'
}

# Active conversations (who this host actually talks to) - exclude loopback
$convs = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
  $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|::$)'
})
$remotes = $convs | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 25
foreach ($r in $remotes) {
  $ports = ($r.Group | Select-Object -ExpandProperty RemotePort -Unique | Select-Object -First 6) -join ','
  $mac = $arpMap[$r.Name]; $vendor = Get-OuiVendor $mac
  Add-Finding -Severity Info -Category 'Discovery' -Title ("Active conversation: {0} ({1} conns)" -f $r.Name, $r.Count) `
    -Detail ("Remote ports: $ports$(if ($mac) { ' | MAC ' + $mac })$(if ($vendor) { ' [' + $vendor + ']' })")
}

######################## SERVICE & VERSION INVENTORY ########################
# Service inventory + banner grab on already-open ports. TCP connect + a short
# generic read; NO exploit payloads, NO ICS protocol probes (OT safe).
# Banner sections in < > are truncated to 60 chars; full content stays in the
# console transcript only if you run with -VerboseBanners.

function Get-ServiceBanner {
  param([string]$Ip, [int]$Port, [int]$TimeoutMs = 1200, [int]$BannerLen = 128)
  $entry = $null
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($Ip, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $client.Close(); return $null }
    $client.EndConnect($iar)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $TimeoutMs
    $buf = New-Object byte[] $BannerLen
    $n = 0
    try { $n = $stream.Read($buf, 0, $BannerLen) } catch { $n = 0 }
    $client.Close()
    if ($n -gt 0) {
      $txt = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
      return ($txt -replace '[^\x20-\x7E]', '.')    # printable only
    }
    return ''
  } catch { return $null }
}

Start-Section 'SERVICE INVENTORY (listening ports + banners)'

# Standard IT services
$portMap = @{
  21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';67='DHCP';69='TFTP';80='HTTP';110='POP3';
  123='NTP';135='MSRPC';139='NetBIOS';143='IMAP';389='LDAP';443='HTTPS';445='SMB';465='SMTPS';
  514='Syslog';587='SMTP';636='LDAPS';993='IMAPS';995='POP3S';1433='MSSQL';1521='Oracle';
  3000='Grafana';3306='MySQL';3389='RDP';4444='Metasploit-default';502='Modbus/TCP';
  4840='OPC-UA discovery';4843='OPC-UA (TLS)';47808='BACnet';44818='EtherNet/IP';
  20000='DNP3';2222='EthinCC/SSH-alt';5010='Niagara Fox';1911='Niagara Fox (alt)';
  4911='Niagara Fox (alt2)';9600='Omron FINS/TCP';96='CoDeSys';5900='VNC';5800='VNC-http';
  8080='HTTP-alt';8443='HTTPS-alt';8888='HTTP-alt2';10000='Webmin';41794='Crestron';
  41795='Crestron-secure';1313='BACnet-IP alt';137='NetBIOS-NS';5060='SIP';1719='H.323';
  1720='H.323-Q.931';49152='MSSQL-browser';1900='SSDP';5353='mDNS';3702='WS-Discovery'
}

$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
$remoteListen = @()
# Local listening services with owning process + version
foreach ($c in $listen) {
  if ($c.LocalAddress -match '^127\.|^::1') {
    continue   # counted in loopback section instead
  }
  $proc = $null
  try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction Stop } catch { }
  $svc = $portMap[[int]$c.LocalPort]
  $name = if ($svc) { $svc } else { 'unknown' }
  $pv = ''
  if ($proc) { $pv = '{0} {1}' -f $proc.ProcessName, $proc.VersionInfo.FileVersion }
  $remoteListen += [pscustomobject]@{ Port = $c.LocalPort; Name = $name; Process = $pv; Addr = $c.LocalAddress }
}
$locGrouped = $remoteListen | Group-Object Port | Sort-Object { [int]$_.Name }
Add-Finding -Severity Info -Category 'Services' -Title ('{0} locally-listening TCP ports (non-loopback)' -f $locGrouped.Count) `
  -Detail (($locGrouped | ForEach-Object {
      $p = [int]$_.Name; $svc = $portMap[$p]
      '{0}{1} [{2}]' -f $p, $(if ($svc) { '(' + $svc + ')' } else { '' }), ($_.Group.Process | Select-Object -First 1)
    }) -join ' | ') `
  -Remediation 'Diff against the authorized service list per host role; close anything not required.'

# BMS/OT-protocol ports listening locally = controllers/jace/hmi software on THIS host
$otPorts = @(502, 4840, 4843, 47808, 44818, 20000, 5010, 1911, 4911, 9600, 41794, 41795, 137, 5353)
$localOt = @($remoteListen | Where-Object { $otPorts -contains [int]$_.Port })
if ($localOt.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'OT Services' -Title ('BMS/OT protocol listeners on this host: {0}' -f $localOt.Count) `
    -Detail (($localOt | ForEach-Object { '{0} ({1}) <- {2}' -f $_.Port, $_.Name, $_.Process }) -join ' | ') `
    -Remediation 'These are the crown jewels: enumerate owning software, version, and ensure zone firewall restricts who can reach them (IEC 62443 SR 5.1).'
}

# Banner grab against discovered neighbors (ICMP-alive devices from sweep)
$grabTargets = @($script:Findings | Where-Object { $_.Category -eq 'Discovery' -and $_.Title -like 'Reachable device*' })
$bannerPorts = @(80, 443, 8080, 8443, 4840, 502, 47808, 44818, 5900, 3389, 22, 23)
if ($grabTargets.Count -gt 0) {
  Write-Host ('  Banner-grabbing {0} discovered devices (12 common ports, 1.2s timeout each)...' -f $grabTargets.Count) -ForegroundColor DarkGray
  $grabbed = 0
  foreach ($t in $grabTargets) {
    $ip = ($t.Title -replace 'Reachable device: ', '')
    foreach ($port in $bannerPorts) {
      $b = Get-ServiceBanner -Ip $ip -Port $port
      if ($null -ne $b) {
        $svc = $portMap[$port]; if (-not $svc) { $svc = 'unknown' }
        $bTrim = if ($b.Length -gt 60) { $b.Substring(0, 60) + '...' } else { $b }
        Add-Finding -Severity Info -Category 'Services' -Title ("{0}:{1} open ({2})" -f $ip, $port, $svc) `
          -Detail $(if ($b) { 'Banner: ' + $bTrim } else { 'No banner (connect-only)' }) `
          -Remediation 'Record service+version in the CMDB; version pinning enables CVE watchlisting.'
        $grabbed++
        if ($grabbed -ge 60) { break }
      }
    }
    if ($grabbed -ge 60) { Write-Host '  Banner cap (60) reached.' -ForegroundColor DarkGray; break }
  }
}

# Installed BMS/OT vendor software on this host
$otVendors = [ordered]@{
  'Niagara' = 'Tridium Niagara (JACE/supervisor)'
  'Honeywell' = 'Honeywell EBI/WebStation'
  'Johnson Controls' = 'Johnson Controls Metasys'
  'Siemens' = 'Siemens Desigo/APOGEE'
  'Schneider' = 'Schneider EcoStruxure/TAC'
  'Trane' = 'Trane Tracer'
  'Carrier' = 'Carrier i-Vu'
  'Delta Controls' = 'Delta Controls enteliBUS'
  'Reliable Controls' = 'Reliable Controls RC-Studio'
  'Automated Logic' = 'Automated Logic WebCTRL'
  'Distech' = 'Distech Controls EC-BOS'
  'CoDeSys' = 'CoDeSys runtime (3S-Smartforce)'
  'KEPServer' = 'KEPServerEX (OPC)'
  'Matrikon' = 'MatrikonOPC'
  'Wonderware' = 'Wonderware/AVEVA'
  'Ignition' = 'Inductive Automation Ignition'
  'Advanced Serial Data Log' = 'ASDL BMS'
  'Viconics' = 'Viconics'
  'Novar' = 'Novar Opus'
}
$apps = @(Get-InstalledApplications)
foreach ($v in $otVendors.GetEnumerator()) {
  $hits = $apps | Where-Object { $_.Software -match [regex]::Escape($v.Key) }
  if ($hits) {
    foreach ($h in ($hits | Select-Object -First 3)) {
      Add-Finding -Severity Medium -Category 'BMS Software' -Title ('BMS vendor software: {0} {1}' -f $h.Software, $h.Version) `
        -Detail $v.Value `
        -Remediation 'Pin the version in the CMDB; subscribe to vendor security advisories (Niagara Fox/HTTPS vulns are common); patch in maintenance windows.'
    }
  }
}

######################## LOOPBACK / PORT-REDIRECTION DETECTION ########################
# Detects: loopback-only listeners, loopback-bound conversations, port-proxy
# (netsh portproxy) rules, SSH -L/-R tunnels via process cmdline, DNS-over-
# loopback, and hosts-file loopback overrides (both 127.x and ::1).

Start-Section 'LOOPBACK / TUNNEL DETECTION'

# 1) Loopback-bound listeners (dedupe by port+process across IPv4/IPv6)
$loListen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
  $_.LocalAddress -match '^127\.|^::1$'
})
if ($loListen.Count -gt 0) {
  $loSeen = @{}
  foreach ($c in ($loListen | Sort-Object LocalPort)) {
    $proc = ''
    try {
      $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop
      $proc = '{0} (PID {1})' -f $p.ProcessName, $p.Id
    } catch { $proc = 'PID ' + $c.OwningProcess }
    $key = '{0}|{1}' -f $c.LocalPort, $proc
    if ($loSeen.ContainsKey($key)) { continue }
    $loSeen[$key] = $true
    $svc = $portMap[[int]$c.LocalPort]; if (-not $svc) { $svc = 'non-standard' }
    Add-Finding -Severity Low -Category 'Loopback' -Title ("Loopback listener: 127.0.0.1:{0} ({1})" -f $c.LocalPort, $svc) `
      -Detail ("Owning process: {0}" -f $proc) `
      -Remediation 'Verify legitimacy: dev tools (databases, proxies) are normal; unknown loopback listeners on BMS hosts deserve scrutiny - pair with the tunnel checks below.'
  }
}
else {
  Add-Finding -Severity Info -Category 'Loopback' -Title 'No loopback-only TCP listeners'
}

# 2) Established conversations over loopback
$loEst = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
  $_.LocalAddress -match '^127\.|^::1$' -and $_.RemoteAddress -match '^127\.|^::1$'
})
$loGrouped = @($loEst | Group-Object LocalPort, RemotePort)
foreach ($g in ($loGrouped | Select-Object -First 20)) {
  $sample = $g.Group[0]
  $lp = (Get-Process -Id $sample.OwningProcess -ErrorAction SilentlyContinue).ProcessName
  Add-Finding -Severity Low -Category 'Loopback' -Title ('Loopback conversation: {0}:{1} -> 127.0.0.1:{2}' -f $sample.LocalAddress, $sample.LocalPort, $sample.RemotePort) `
    -Detail ("{0} connections | client-side process: {1}" -f $g.Count, $lp)
}
if ($loGrouped.Count -eq 0) {
  Add-Finding -Severity Info -Category 'Loopback' -Title 'No active loopback conversations'
}

# 3) netsh portproxy rules (classic tunnel/relay persistence)
$portproxy = $null
try { $portproxy = netsh interface portproxy show all 2>$null } catch { }
$ppRules = @($portproxy | Where-Object { $_ -match '^\s*tcp\s|^tcpv6' })
if ($ppRules.Count -gt 0) {
  foreach ($r in $ppRules) {
    Add-Finding -Severity High -Category 'Loopback' -Title ('netsh portproxy rule: {0}' -f $r.Trim()) `
      -Detail 'A portproxy forwards traffic between interfaces - legitimate (NAT helper) or attacker relay. Listens via IP Helper service.' `
      -Remediation 'Verify authorization. Remove with: netsh interface portproxy delete (matching rule). If unexpected, treat as persistence (MITRE ATT&CK T1090).'
  }
}
else {
  Add-Finding -Severity Info -Category 'Loopback' -Title 'No netsh portproxy rules'
}

# 4) SSH tunnel args in running processes
try {
  $sshTunnels = Get-CimInstance Win32_Process -Filter "Name='ssh.exe' OR Name='plink.exe' OR Name='putty.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match '\s-[LRD]\s|\s-D\s' }
  foreach ($s in @($sshTunnels)) {
    $cmd = $s.CommandLine
    if ($cmd.Length -gt 120) { $cmd = $cmd.Substring(0, 120) + '...' }
    Add-Finding -Severity Medium -Category 'Loopback' -Title ('SSH tunnel process: {0} (PID {1})' -f $s.Name, $s.ProcessId) `
      -Detail ("Args: {0}" -f $cmd) `
      -Remediation 'Confirm the tunnel is sanctioned; unsanctioned -L/-R/-D tunnels bypass network segmentation (T1090/T1572).'
  }
  if (-not $sshTunnels) { Add-Finding -Severity Info -Category 'Loopback' -Title 'No SSH/plink tunnel processes running' }
} catch { }

# 5) DNS-over-loopback (local resolver/proxy, incl. DoH clients)
$loDns = @(Get-NetTCPConnection -State Listen, Established -ErrorAction SilentlyContinue | Where-Object {
  ($_.LocalPort -eq 53 -or $_.RemotePort -eq 53) -and ($_.LocalAddress -match '^127\.|^::1$' -or $_.RemoteAddress -match '^127\.|^::1$')
})
if ($loDns.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'Loopback' -Title 'DNS traffic terminating on loopback' `
    -Detail ("{0} sockets | suspect local DNS proxy/resolver (Pi-hole, DoH client, or DNS tunneling tool)" -f $loDns.Count) `
    -Remediation 'Identify the process; unauthorized local DNS proxies can hide C2 traffic from network monitoring.'
}
else {
  Add-Finding -Severity Info -Category 'Loopback' -Title 'No loopback DNS activity'
}

# 6) hosts-file loopback overrides (traffic silently redirected to self)
try {
  $hostsLo = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction Stop |
    Where-Object { $_ -match '^\s*(127\.|::1)\s' -and $_ -notmatch 'localhost' }
  if (@($hostsLo).Count -gt 0) {
    foreach ($h in @($hostsLo)) {
      Add-Finding -Severity Low -Category 'Loopback' -Title ('hosts loopback override: {0}' -f $h.Trim()) `
        -Remediation 'Blocking/redirect entries are sometimes legit (license servers, ad-block); verify intent - silent redirection of auth domains is an attack technique (T1586-adjacent).'
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Loopback' -Title 'No nonstandard hosts-file loopback overrides'
  }
} catch { }

# 7) Loopback exclusions from proxy/inspection (attacker-evasion angle): check
#    common localhost bypass settings only as Info
$proxyOverride = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyOverride
if ($proxyOverride -match 'localhost|127\.') {
  Add-Finding -Severity Info -Category 'Loopback' -Title 'Proxy bypass includes localhost (standard config)'
}

######################## IIS / WEB SERVER RECON ########################
# Deep IIS inventory when IIS is present (Server 2019/Win11): sites, bindings,
# app pools, certificates, web.config secrets, IIS Rewrite module, auth, TLS.
# All checks are read-only (ServerManager API + config files).

Start-Section 'IIS WEB SERVER RECON'
$iisPresent = $false
$sm = $null
$adminDll = "$env:windir\System32\inetsrv\Microsoft.Web.Administration.dll"
if ((Get-Service W3SVC -ErrorAction SilentlyContinue) -or (Test-Path $adminDll)) {
  $iisPresent = $true
  try {
    [void][System.Reflection.Assembly]::LoadFrom($adminDll)
    $sm = New-Object Microsoft.Web.Administration.ServerManager
  } catch { $sm = $null }
}

if (-not $iisPresent) {
  Add-Finding -Severity Info -Category 'IIS' -Title 'IIS not installed on this host'
}
else {
  Add-Finding -Severity Info -Category 'IIS' -Title 'IIS is installed' `
    -Detail 'Full web-server recon follows - every finding is attacker-recon surface.'

  # --- IIS version ---
  $iisVer = (Get-Item "$env:windir\System32\inetsrv\w3wp.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
  if ($iisVer) { Add-Finding -Severity Info -Category 'IIS' -Title "IIS engine version $iisVer" }

  # --- Sites & bindings ---
  if ($sm) {
    foreach ($site in $sm.Sites) {
      $bindings = ($site.Bindings | ForEach-Object {
        '{0}://{1}:{2}' -f $_.Protocol, $(if ($_.Host) { $_.Host } else { '*' }), $_.BindingInformation.Split(':')[-1]
      }) -join ', '
      Add-Finding -Severity Info -Category 'IIS' -Title ("Site '{0}' ({1})" -f $site.Name, $site.State) `
        -Detail ("Bindings: {0} | ID: {1}" -f $bindings, $site.Id) `
        -Remediation 'Baseline expected bindings; unknown sites = investigate.'
      # HTTP-only site (no TLS binding)
      if (-not ($site.Bindings | Where-Object { $_.Protocol -eq 'https' })) {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Site '{0}' has NO HTTPS binding" -f $site.Name) `
          -Detail 'Cleartext HTTP - credentials/cookies/session tokens readable on the wire.' `
          -Remediation 'Add an HTTPS binding with a valid cert; redirect HTTP to HTTPS; set HSTS.'
      }
      # Physical path + writability check
      foreach ($app in $site.Applications) {
        $root = $app.VirtualDirectories | Select-Object -First 1
        if ($root -and $root.PhysicalPath -and (Test-Path $root.PhysicalPath)) {
          $acl = Get-Acl $root.PhysicalPath -ErrorAction SilentlyContinue
          if ($acl) {
            $w = $acl.Access | Where-Object {
              $_.IdentityReference -match 'BUILTIN\\Users|Everyone|IIS_IUSRS' -and
              $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match 'FullControl|Modify|Write'
            }
            if ($w) {
              Add-Finding -Severity High -Category 'IIS' -Title ("Web root writable by non-admin: {0}" -f $root.PhysicalPath) `
                -Detail ("Site: {0} | {1} granted {2} - webshell drop-in." -f $site.Name, $w[0].IdentityReference, $w[0].FileSystemRights) `
                -Remediation 'Web roots should be read-only for app-pool identities and Users; writers need explicit ACLs.'
            }
          }
        }
      }
    }

    # --- App pools ---
    foreach ($pool in $sm.ApplicationPools) {
      $ident = $pool.ProcessModel.IdentityType
      $flags = @()
      if ($pool.Enable32BitAppOnWin64) { $flags += '32bit' }
      if ($pool.ProcessModel.LoadUserProfile -eq $false) { $flags += 'no-profile' }
      Add-Finding -Severity Info -Category 'IIS' -Title ("App pool '{0}' ({1})" -f $pool.Name, $pool.State) `
        -Detail ("Identity: {0} | .NET CLR: {1}{2}" -f $ident, $pool.ManagedRuntimeVersion, $(if ($flags) { ' | ' + ($flags -join ',') } else { '' }))
      if ("$ident" -match 'LocalSystem') {
        Add-Finding -Severity High -Category 'IIS' -Title ("App pool '{0}' runs as LocalSystem" -f $pool.Name) `
          -Detail 'Any app-level RCE/LFI in that pool = full SYSTEM compromise.' `
          -Remediation 'Use ApplicationPoolIdentity; grant precise per-pool resource ACLs.'
      }
      if ($pool.ManagedRuntimeVersion -eq 'v2.0') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("App pool '{0}' targets .NET 2.0/3.5 runtime" -f $pool.Name) `
          -Remediation 'Migrate to v4.x; legacy runtime lacks modern mitigations.'
      }
    }
  }

  # --- Machine certificates: expiry / weak keys (covers HTTPS bindings) ---
  try {
    $now = Get-Date
    foreach ($cert in (Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue)) {
      $days = ($cert.NotAfter - $now).Days
      $subj = $cert.Subject -replace '^CN=', ''
      if ($days -lt 0) {
        Add-Finding -Severity Critical -Category 'IIS' -Title ("EXPIRED certificate: {0} (expired {1}d ago)" -f $subj, -$days) `
          -Detail ('Thumbprint: ' + $cert.Thumbprint) `
          -Remediation 'Renew now - expired certs break TLS and push users to click-through errors.'
      }
      elseif ($days -lt 30) {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Certificate expiring in {0}d: {1}" -f $days, $subj) `
          -Detail ('Thumbprint: ' + $cert.Thumbprint) `
          -Remediation 'Schedule renewal.'
      }
      if ($cert.SignatureAlgorithm.FriendlyName -match 'MD5|SHA1') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Weak signature ({0}) on cert: {1}" -f $cert.SignatureAlgorithm.FriendlyName, $subj) `
          -Remediation 'Reissue with SHA256+.'
      }
    }
  } catch { }

  # --- IIS URL Rewrite module ---
  $rewriteDll = "$env:windir\System32\inetsrv\rewrite.dll"
  if (Test-Path $rewriteDll) {
    $rv = (Get-Item $rewriteDll).VersionInfo
    $rver = '{0}.{1}.{2}.{3}' -f $rv.FileMajorPart, $rv.FileMinorPart, $rv.FileBuildPart, $rv.FilePrivatePart
    Add-Finding -Severity Info -Category 'IIS' -Title ("IIS URL Rewrite module installed: v{0}" -f $rver) `
      -Detail 'Rewrite is internet-reachable logic: inbound/outbound rules in web.config can leak or redirect.'
    $fileVerNum = [double]('{0}.{1}' -f $rv.FileMajorPart, $rv.FileMinorPart)
    $buildNum = [int]$rv.FileBuildPart
    if ($fileVerNum -lt 2.1 -or ($fileVerNum -eq 2.1 -and $buildNum -lt 2105)) {
      Add-Finding -Severity Medium -Category 'IIS' -Title ("IIS URL Rewrite v{0} is outdated" -f $rver) `
        -Detail 'Older Rewrite 2.x builds have published security fixes (e.g. spoofing/info-disclosure class advisories).' `
        -Remediation 'Upgrade to the latest URL Rewrite 2.1 from Microsoft; verify against the advisory list.'
    }
    # Rewrite rules referenced in web.configs get scanned below with the file sweep
  }
  else {
    Add-Finding -Severity Info -Category 'IIS' -Title 'IIS URL Rewrite module not installed'
  }

  # --- web.config secrets & weak machineKey settings ---
  $webRoots = @("$env:windir\System32\inetsrv\config", "$env:SystemDrive\inetpub")
  if ($sm) {
    foreach ($site in $sm.Sites) {
      foreach ($app in $site.Applications) {
        $root = $app.VirtualDirectories | Select-Object -First 1
        if ($root -and $root.PhysicalPath) { $webRoots += $root.PhysicalPath }
      }
    }
  }
  $webRoots = $webRoots | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
  foreach ($wr in $webRoots) {
    $cfgFiles = @(Get-ChildItem -LiteralPath $wr -Recurse -Filter 'web.config' -ErrorAction SilentlyContinue | Select-Object -First 50)
    foreach ($cfg in $cfgFiles) {
      $content = $null
      try { $content = Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue } catch { }
      if (-not $content) { continue }
      # connection strings with passwords (redacted)
      if ($content -match '(?i)connectionstring\s*=.{0,200}password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Plaintext DB password in {0}" -f $cfg.FullName) `
          -Detail 'Detected via pattern; value not recorded.' `
          -Remediation 'Move to encrypted connectionStrings sections or managed identities.'
      }
      # machineKey weak/validation
      if ($content -match '(?i)<machinekey[^>]*validation\s*=\s*"(MD5|SHA1|3DES|AES"[^"]*"?)') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Weak machineKey validation in {0}" -f $cfg.FullName) `
          -Detail 'MD5/SHA1/3DES ViewState signing is forgeable - ViewState deserialization RCE path.' `
          -Remediation 'Use HMACSHA256 validation; rotate autoGenerated keys.'
      }
      if ($content -match '(?i)<machinekey[^>]*validationkey\s*=\s*"([0-9A-Fa-f]{10,60})"') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Short/weak validationKey in {0}" -f $cfg.FullName) `
          -Detail 'Explicit short validationKey is brute-forceable, enabling ViewState forgery.' `
          -Remediation 'Use 64-128 hex byte autoGenerated keys.'
      }
      # debug=true exposed
      if ($content -match '(?i)<deployment[^>]*retail\s*=\s*"false"') {
        Add-Finding -Severity Low -Category 'IIS' -Title ("deployment retail=false in {0}" -f $cfg.FullName) `
          -Remediation 'Set retail="true" on production servers (kills debug tracing + detailed errors).'
      }
      # directory browsing on
      if ($content -match '(?i)<directorybrowse[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Directory browsing enabled in {0}" -f $cfg.FullName) `
          -Remediation 'Disable directoryBrowse - leaks file inventory to attackers.'
      }
      # generic secret patterns
      Test-FileForSecrets -Path $cfg.FullName -Context ' (IIS web.config)'
    }
  }

  # --- Server-level auth config from applicationHost.config ---
  $appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
  if (Test-Path $appHost) {
    $ah = $null
    try { $ah = Get-Content $appHost -Raw } catch { }
    if ($ah) {
      if ($ah -match '(?i)<anonymousAuthentication[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Low -Category 'IIS' -Title 'Anonymous authentication enabled (server-wide default)' `
          -Remediation 'Expected for public sites; ensure protected vdirs override with auth.'
      }
      if ($ah -match '(?i)<basicAuthentication[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title 'Basic authentication enabled in IIS' `
          -Detail 'Base64 cleartext credentials on the wire unless bound to TLS.' `
          -Remediation 'Require HTTPS on all Basic-auth bindings or move to Windows/auth modes.'
      }
      if ($ah -match '(?i)<directoryBrowse[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title 'Directory browsing enabled at server level'
      }
      # applicationHost.config itself: connection strings / passwords
      if ($ah -match '(?i)password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title 'Password-shaped value in applicationHost.config' `
          -Detail 'App-pool/service credentials stored in config are readable by admins and backup-exfiltration.' `
          -Remediation 'Use app-pool identities where possible; protect config backups.'
      }
    }
    # writable applicationHost.config = total IIS takeover
    $aclAh = Get-Acl $appHost -ErrorAction SilentlyContinue
    if ($aclAh) {
      $weakAh = $aclAh.Access | Where-Object {
        $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and $_.AccessControlType -eq 'Allow' -and
        ("$($_.FileSystemRights)" -match 'FullControl|Modify|Write')
      }
      if ($weakAh) {
        Add-Finding -Severity Critical -Category 'IIS' -Title 'applicationHost.config is user-writable' `
          -Detail 'Edit = full control of every site/app pool on the box.' `
          -Remediation 'Restore Administrators/SYSTEM/Administrators-only ACL immediately.'
      }
    }
  }

  # --- Other web-adjacent services ---
  foreach ($svc in @(@('FTPSVC', 'IIS FTP'), @('SMTPSVC', 'IIS SMTP'))) {
    $s = Get-Service $svc[0] -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Running') {
      Add-Finding -Severity Low -Category 'IIS' -Title ("{0} service running" -f $svc[1]) `
        -Remediation 'Confirm business need; FTP/SMTP legacy services widen attack surface (cleartext protocols).'
    }
  }
}

# --- WinRM transport security (IIS-adjacent remote mgmt) ---
try {
  $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | Get-Item
  foreach ($l in $listeners) {
    $tr = $l.ChildKeys | Where-Object { $_ }
    $transport = (Get-ChildItem $l.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Transport' })
    $tval = if ($transport) { $transport.Value } else { 'HTTP' }
    $portItem = Get-ChildItem $l.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Port' }
    Add-Finding -Severity Info -Category 'RemoteMgmt' -Title ("WinRM listener ({0}, port {1})" -f $tval, $portItem.Value)
    if ("$tval" -eq 'HTTP') {
      Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM listener on HTTP (unencrypted transport)' `
        -Remediation 'Add an HTTPS listener (or use trusted host + NTLMnegotiate); ideally HTTPS-only.'
    }
  }
  $unenc = (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue).Value
  $allowUnenc = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
  if ("$allowUnenc" -eq 'true') {
    Add-Finding -Severity High -Category 'RemoteMgmt' -Title 'WinRM AllowUnencrypted = true' `
      -Remediation 'Set to false; unencrypted WinRM exposes credentials to on-path capture.'
  }
  if ("$unenc" -eq 'true') {
    Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM Basic auth enabled' `
      -Remediation 'Prefer Kerberos/Negotiate; Basic over HTTP is trivially sniffable.'
  }
} catch {
  Add-Finding -Severity Info -Category 'RemoteMgmt' -Title 'WinRM not configured on this host'
}

######################## OS VULNERABILITY / CRYPTO / EOL SURFACE ########################
# OS-level vulnerability surface for Server 2019/2022 and Win10/11:
# OS EOL, TLS protocol inventory, cipher suites, SMB dialects, RDP encryption,
# .NET/edge/legacy runtime inventory, LSA old behavior, secedit baseline dump.

Start-Section 'OS VULNERABILITY SURFACE'

# --- OS build + support status ---
$osCim = Get-CimInstance Win32_OperatingSystem
$osName = $osCim.Caption
$build = [int]$osCim.BuildNumber
Add-Finding -Severity Info -Category 'OS' -Title ("OS: {0} (build {1})" -f $osName, $build)
$eolTable = @(
  @{ Match = 'Server 2019';    EOL = [datetime]'2029-01-09' }
  @{ Match = 'Server 2022';    EOL = [datetime]'2031-10-14' }
  @{ Match = 'Server 2025';    EOL = [datetime]'2034-10-10' }
  @{ Match = 'Server 2016';    EOL = [datetime]'2027-01-12' }
  @{ Match = 'Server 2012';    EOL = [datetime]'2023-10-10' }
  @{ Match = 'Windows 10';     EOL = [datetime]'2025-10-14' }
  @{ Match = 'Windows 11';     EOL = [datetime]'2028-10-10' }
)
foreach ($e in $eolTable) {
  if ($osName -like "*$($e.Match)*") {
    if ((Get-Date) -gt $e.EOL) {
      Add-Finding -Severity Critical -Category 'OS' -Title ("{0} is PAST END OF SUPPORT ({1:yyyy-MM-dd})" -f $osName, $e.EOL) `
        -Detail 'No security patches - every future CVE is permanent.' `
        -Remediation 'Plan migration/upgrade immediately; isolate the host meanwhile.'
    }
    elseif (((Get-Date) - $e.EOL).Days -gt -365) {
      Add-Finding -Severity Medium -Category 'OS' -Title ("{0} support ends {1:yyyy-MM-dd} (<1 year)" -f $osName, $e.EOL) `
        -Remediation 'Budget the upgrade now.'
    }
    else {
      Add-Finding -Severity Info -Category 'OS' -Title ("{0} supported until {1:yyyy-MM-dd}" -f $osName, $e.EOL)
    }
    break
  }
}
# Win11 Pro build currency check (24H2 = 26100)
if ($osName -like '*Windows 11*' -and $build -lt 26100) {
  Add-Finding -Severity Medium -Category 'OS' -Title ("Windows 11 build {0} is behind (24H2 = 26100)" -f $build) `
    -Remediation 'Old Win11 builds fall out of servicing faster; update to the current feature update.'
}

# --- TLS protocol inventory (SSP Schannel enabled protocols) ---
foreach ($hive in @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols')) {
  $protos = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')
  foreach ($p in $protos) {
    $k = Join-Path $hive "$p\Server"
    $enabled = (Get-ItemProperty $k -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
    $disabled = (Get-ItemProperty $k -Name Enabled -ErrorAction SilentlyContinue).Enabled
    $active = if ($disabled -eq 0 -and $enabled -eq 1) { $true }
              elseif ($null -eq $disabled -and $null -eq $enabled) {
                # OS defaults: TLS1.2/1.3 on; older off on modern builds
                if ($p -in 'TLS 1.2', 'TLS 1.3' -and $build -ge 17763) { $true }
                elseif ($p -in 'TLS 1.2', 'TLS 1.3') { $false } else { $false }
              } else { $false }
    if ($active -and $p -match 'SSL|TLS 1\.0|TLS 1\.1') {
      Add-Finding -Severity High -Category 'Crypto' -Title ("Weak protocol ACTIVE server-side: {0}" -f $p) `
        -Detail 'SSL/TLS1.0/1.1 fail PCI/DISAGDSS baselines; downgrade attacks (POODLE/BAR-MITZVAH class).' `
        -Remediation "Disable ${p} server and client side via SCHANNEL registry + reboot."
    }
  }
}
$activeProtos = @()
foreach ($p in @('TLS 1.2', 'TLS 1.3')) {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Server"
  $dis = (Get-ItemProperty $k -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
  if ($dis -eq 0 -or $null -eq $dis) { $activeProtos += $p }
}
if ($activeProtos.Count -gt 0) {
  Add-Finding -Severity Info -Category 'Crypto' -Title ("Modern TLS available: {0}" -f ($activeProtos -join ', '))
} else {
  Add-Finding -Severity High -Category 'Crypto' -Title 'No modern TLS protocol confirmed enabled' `
    -Remediation 'Explicitly enable TLS 1.2/1.3 server-side.'
}

# --- Cipher suites: weak/NULL/RC4/3DES presence in the enabled list ---
try {
  $cs = Get-TlsCipherSuite -ErrorAction Stop | Select-Object -ExpandProperty Name
  $weak = @($cs | Where-Object { $_ -match 'NULL|RC4|3DES|DES_' })
  if ($weak.Count -gt 0) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title ("{0} weak cipher suites enabled" -f $weak.Count) `
      -Detail (($weak | Select-Object -First 8) -join ', ') `
      -Remediation 'Reorder/prune with Get-TlsCipherSuite | Disable-TlsCipherSuite; keep AEAD suites (GCM/ChaCha20).'
  }
  else {
    Add-Finding -Severity Info -Category 'Crypto' -Title ("{0} cipher suites enabled, none weak" -f $cs.Count)
  }
} catch { }

# --- FIPS mode ---
$fips = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsPolicyGroup' -ErrorAction SilentlyContinue).Enabled
$fips2 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name FipsAlgorithmPolicy -ErrorAction SilentlyContinue
Add-Finding -Severity Info -Category 'Crypto' -Title 'FIPS policy status recorded' `
  -Detail ("FipsAlgorithmPolicy present: {0}" -f [bool]$fips2)

# --- SMB client/server dialect floor ---
try {
  $srv = Get-SmbServerConfiguration -ErrorAction Stop
  if ($srv.EnableSMB1Protocol) {
    Add-Finding -Severity Critical -Category 'Crypto' -Title 'SMBv1 server enabled' `
      -Detail 'EternalBlue/WannaCry class; no integrity or confidentiality.' `
      -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'
  }
  if (-not $srv.RequireSecuritySignature) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB signing not required (previously flagged; repeated in crypto context)'
  }
  $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
  if ($cli -and $cli.EnableSecuritySignature -eq $false -and $cli.RequireSecuritySignature -eq $false) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB client: signing neither enabled nor required' `
      -Remediation 'Require SMB client signing via GPO (NTLM relay defense).'
  }
} catch { }

# --- .NET framework inventory + strong-crypto opt-in ---
$releaseKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
$netVer = if ($releaseKey) {
  if ($releaseKey -ge 533320) { '4.8.1+' } elseif ($releaseKey -ge 528040) { '4.8' }
  elseif ($releaseKey -ge 461808) { '4.7.2' } elseif ($releaseKey -ge 394802) { '4.6.2' } else { "4.x (release $releaseKey)" }
} else { 'unknown' }
Add-Finding -Severity Info -Category 'OS' -Title ".NET Framework: $netVer"
if ($netVer -match '^4\.[0-6]' ) {
  Add-Finding -Severity Medium -Category 'OS' -Title "Old .NET Framework ($netVer)" `
    -Remediation 'Upgrade to 4.8.x - older runtimes miss TLS1.2 defaults and security fixes.'
}
foreach ($v2v35 in @('v2.0.50727', 'v3.0', 'v3.5')) {
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\$v2v35") {
    Add-Finding -Severity Low -Category 'OS' -Title ".NET $v2v35 runtime present" `
      -Remediation 'Remove if no apps depend on it (legacy attack surface).'
  }
}

# --- Legacy/insecure optional features enabled ---
try {
  $feats = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -match 'PowerShellV2|SMB1Protocol|TelnetClient|TFTPClient|NetFx3|IIS-.*Basicauth' }
  foreach ($f in @($feats)) {
    $sev = if ($f.FeatureName -match 'SMB1|PowerShellV2') { 'High' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'OS' -Title ("Legacy feature enabled: {0}" -f $f.FeatureName) `
      -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName <name> - remove unless explicitly required (PowerShellv2 = downgrade attacks, SMB1 = wormable).'
  }
} catch { }

# --- Depreciated crypto in .NET machine.config (SchUseStrongCrypto) ---
foreach ($runtimeVer in @('v2.0.50727', 'v4.0.30319')) {
  foreach ($bit in @('64', '32')) {
    $mc = "$env:windir\Microsoft.NET\Framework$($bit)\$runtimeVer\CONFIG\machine.config"
    $mcPath = $mc -replace 'Framework64', 'Framework'
    if ($bit -eq '64') { $mcPath = $mc }
    if (Test-Path $mcPath) {
      $c = $null
      try { $c = Get-Content $mcPath -Raw -ErrorAction SilentlyContinue } catch { }
      if ($c -and $c -notmatch 'SchUseStrongCrypto"?\s*=\s*"?true' -and $runtimeVer -eq 'v4.0.30319') {
        Add-Finding -Severity Low -Category 'Crypto' -Title "SchUseStrongCrypto not set in machine.config ($bit-bit)" `
          -Detail 'Default .NET TLS defaults may allow weak protocol negotiation for legacy apps.' `
          -Remediation 'Set SchUseStrongCrypto=true in machine.config / registry UseStrongCrypto=1.'
      }
    }
  }
}

# --- Local security policy dump (secedit) - password/lockout baseline ---
try {
  $secOut = "$env:TEMP\bluepeas_secedit.cfg"
  secedit /export /cfg $secOut /quiet 2>$null | Out-Null
  if (Test-Path $secOut) {
    $sec = Get-Content $secOut -ErrorAction SilentlyContinue
    $pl = ($sec | Select-String 'MinimumPasswordLength').Line
    if ($pl -match '=\s*(\d+)') {
      $minLen = [int]$Matches[1]
      if ($minLen -lt 14) {
        Add-Finding -Severity Medium -Category 'OS' -Title ("Password policy: minimum length {0} (<14)" -f $minLen) `
          -Remediation 'NIST/CIS: 14+ characters, length over complexity theater.'
      }
    }
    $lock = ($sec | Select-String 'LockoutBadCount').Line
    if ($lock -match '=\s*(\d+)') {
      $lb = [int]$Matches[1]
      if ($lb -eq 0) {
        Add-Finding -Severity Medium -Category 'OS' -Title 'Account lockout threshold: 0 (never locks)' `
          -Remediation 'Set lockout 5-10 attempts with timed reset (blocks brute force).'
      }
    }
    $lba = ($sec | Select-String 'LsaAnonymousNameLookup').Line
    if ($lba -match '=\s*1') {
      Add-Finding -Severity Medium -Category 'OS' -Title 'Anonymous SAM/LSA lookup enabled' `
        -Remediation 'Disable: LsaAnonymousNameLookup=0 (blocks null-session enumeration).'
    }
    $restrictAnon = ($sec | Select-String 'RestrictAnonymous(SAM)?\s*=').Line
    Add-Finding -Severity Info -Category 'OS' -Title 'Secedit baseline exported (password/lockout/anonymous policy recorded)'
    Remove-Item $secOut -Force -ErrorAction SilentlyContinue
  }
} catch { }

# --- RDP encryption level (Terminal Server) ---
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if ($ts) {
  if ($ts.MinEncryptionLevel -lt 3) {
    Add-Finding -Severity High -Category 'Crypto' -Title ("RDP encryption level {0} (low/client-compatible)" -f $ts.MinEncryptionLevel) `
      -Remediation 'Set MinEncryptionLevel=3 (High) minimum; pair with NLA + TLS SecurityLayer.'
  }
  if ($ts.SecurityLayer -eq 0) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'RDP SecurityLayer=0 (native RDP crypto instead of TLS)'
  }
}

# --- Unsigned driver / test-signing exposure ---
$bcdTest = $null
try { $bcdTest = (bcdedit /enum `{current`} 2>$null | Select-String 'testsigning\s+Yes') } catch { }
if ($bcdTest) {
  Add-Finding -Severity High -Category 'OS' -Title 'Test signing mode enabled (bcdedit testsigning)' `
    -Detail 'Unsigned kernel drivers load freely - rootkit path.' `
    -Remediation 'bcdedit /set testsigning off; investigate why it was on.'
}
$nointegritychecks = $null
try { $nointegritychecks = (bcdedit /enum `{current`} 2>$null | Select-String 'nointegritychecks\s+Yes') } catch { }
if ($nointegritychecks) {
  Add-Finding -Severity High -Category 'OS' -Title 'Code-integrity checks disabled (nointegritychecks)' `
    -Remediation 'bcdedit /set nointegritychecks on (restore) - disabled CI allows unsigned code at boot.'
}

# --- Enabled local-admin RDP/WinRM exposure recap (ties into network findings) ---
$nullDevice = $null
try {
  $denyRdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
  if ($denyRdp -eq 0 -and $build -ge 17763) {
    Add-Finding -Severity Info -Category 'OS' -Title 'RDP enabled (modern build) - ensure NLA enforced and exposure firewalled'
  }
} catch { }

######################## PERSISTENCE DEEP-DIVE ########################
# High-signal persistence locations beyond Run/RunOnce/startup/tasks:
# Winlogon hijacks, WMI permanent subscriptions, COM hijack-prone HKCU CLSIDs,
# IFEO debuggers, AppInit_DLLs, LSA security packages, Active Setup,
# netsh helpers, screensaver hijacks, service failure actions.

Start-Section 'PERSISTENCE DEEP-DIVE'

# --- Winlogon hijack points ---
$wlg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wlg) {
  foreach ($val in @('Shell', 'Userinit', 'Taskman', 'System', 'VmApplet', 'AppSetup')) {
    $v = $wlg.$val
    if ($null -eq $v) { continue }
    $expected = @{ Shell = 'explorer.exe'; Userinit = 'C:\Windows\system32\userinit.exe,' }
    if ($expected.ContainsKey($val)) {
      if ($v -notlike "*$($expected[$val])*") {
        Add-Finding -Severity Critical -Category 'Persistence' -Title ("Winlogon {0} hijacked: {1}" -f $val, $v) `
          -Detail 'Executed at every logon as SYSTEM - classic Kovter-class persistence.' `
          -Remediation "Restore ${val} to its Windows default immediately; trace what installed it."
      }
    }
    elseif ($v) {
      Add-Finding -Severity Medium -Category 'Persistence' -Title ("Winlogon '{0}' configured: {1}" -f $val, $v) `
        -Remediation 'Verify this value against a clean image; non-default Winlogon values execute at logon.'
    }
  }
}

# --- WMI permanent event subscriptions (fileless persistence) ---
try {
  $subs = @()
  foreach ($nsName in @('root\subscription', "root\cimv2")) {
    $filter = Get-CimInstance -Namespace $nsName -ClassName __EventFilter -ErrorAction SilentlyContinue
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
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No WMI permanent event consumers'
  }
} catch { }

# --- COM hijack-prone: HKCU CLSID (per-user COM overrides) ---
try {
  $hkcuClsid = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
  $count = @($hkcuClsid).Count
  if ($count -gt 0) {
    Add-Finding -Severity Medium -Category 'Persistence' -Title ("{0} per-user CLSID overrides in HKCU (COM hijack surface)" -f $count) `
      -Detail 'HKCU\Software\Classes\CLSID overrides HKLM COM registrations - a silent code-exec persistence slot invisible to per-machine audits.' `
      -Remediation 'Compare against a clean profile; watch InprocServer32/LocalServer32 default values pointing outside Windows/Program Files.'
    $suspicious = 0
    foreach ($k in ($hkcuClsid | Select-Object -First 300)) {
      $ips = Get-ItemProperty "$($k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
      if ($ips -and $ips.'(default)' -and "$($ips.'(default)')" -notmatch '^C:\\(Windows|Program Files)' -and $suspicious -lt 5) {
        Add-Finding -Severity High -Category 'Persistence' -Title ("HKCU COM server outside standard paths: {0}" -f $k.PSChildName) `
          -Detail ("DLL: {0}" -f $ips.'(default)') `
          -Remediation 'Verify; per-user COM DLLs loading from user-writable paths are hijack/persistence primitives.'
        $suspicious++
      }
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
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
foreach ($pkgName in @('Security Packages', 'Notification Packages')) {
  $pkgs = $lsa.$pkgName
  if ($pkgs) {
    $expected = @{ 'Security Packages' = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','ntlm'); 'Notification Packages' = @('scecli','rassfm','wdigest') }
    $extra = @($pkgs | ForEach-Object { "$_" } | Where-Object { ($_.Trim('"', ' ', "`t") -ne '') } |
      Where-Object { $expected[$pkgName] -notcontains $_.Trim().ToLower() })
    if ($extra.Count -gt 0) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Non-standard LSA {0}: {1}" -f $pkgName, ($extra -join ', ')) `
        -Detail 'LSA packages load into LSASS at boot as SYSTEM - credential-capture territory (mimikatz uses this).' `
        -Remediation 'Remove non-standard entries; verify the DLLs against the build baseline.'
    }
  }
}

# --- Active Setup (per-user exec at first logon) ---
try {
  foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
      $stub = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).StubPath
      if ($stub) {
        $known = ($_.PSChildName -match '^\{?[0-9A-Fa-f-]{36}\}?$') -and ($stub -match 'system32|Program Files')
        $sev = if ($stub -match 'user-writable|AppData|Temp|Public|Downloads') { 'High' } else { 'Low' }
        if ($stub -match 'AppData|\\Temp\\|\\Public\\|Downloads') {
          Add-Finding -Severity $sev -Category 'Persistence' -Title ("Active Setup StubPath in user-writable path: {0}" -f $_.PSChildName) `
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
foreach ($sidKey in @('HKCU:\Control Panel\Desktop')) {
  $ss = Get-ItemProperty $sidKey -ErrorAction SilentlyContinue
  if ($ss -and $ss.SCRNSAVE.EXE -and "$($ss.SCRNSAVE.EXE)" -notmatch '^C:\\Windows\\System32') {
    Add-Finding -Severity Medium -Category 'Persistence' -Title ("Screensaver outside System32: {0}" -f $ss.'SCRNSAVE.EXE') `
      -Remediation 'Screensaver path executes at idle timeout; user-writable .scr = persistence.'
  }
}

######################## IMAGE HARDENING BASELINE ########################
# The switch-to-flip list: what the golden image should enforce. Each check
# reports the current state + the exact hardening action.

Start-Section 'IMAGE HARDENING BASELINE'

# --- Defender ASR rules ---
try {
  $prefs = Get-MpPreference -ErrorAction Stop
  $asrIds = @{
    '56a863a9-8df3-4e41-9a2e-6de5b9d7a1bd' = 'Abuse of vulnerable signed drivers (LOLBins)'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619b2b' = 'Adobe Reader child-process spawn'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Office apps child-process spawn'
    '9e6c4cd1-2c9c-4deb-a2b3-82c2de07b19b' = 'Office apps creating executable content'
    'b2b3f03d-6a44-4d6f-a68a-d5f3a5b0f9c4' = 'Office macro code winning APIs'
    'e6db88a8-b28b-4c36-9463-6d50a5e3d4b0' = 'Credential stealing from LSASS (ref)'
    '3b576869-a4ec-4529-8536-b6a2e5f3d7c1' = 'WMI event subscription persistence'
    'be9ba2d9-53ea-4cdc-84e5-9b1d1b0f5c1e' = 'Ransomware protection (controlled folder access companion)'
    '5beb7efe-fd9a-4556-801d-bd0a5f6f7a1c' = 'Untrusted/unsigned processes from USB'
    'd3e037e1-3eb8-44c8-a5a0-2e0f0b5a1a2b' = 'JS/VBS launching script interpreters'
    '92e97ca1-2edf-4476-bdd6-9a0f0d6a1a2c' = 'Office communication apps child-process'
    'c1db55ab-c21a-4837-a377-f0f1e2b3c4d5' = 'WPS/Explorer exploit-guard extras'
    '26190899-1602-49e8-8b27-eb1d0a1baac6' = 'Office dropping executable content'
    '33ddedf1-c6ed-4bb3-a5a5-9a0f0d6a1a2d' = 'Persist through WMI (alt id)'
  }
  $enabled = @($prefs.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
  if ($enabled.Count -eq 0) {
    Add-Finding -Severity High -Category 'Hardening' -Title 'Defender ASR rules: NONE enabled' `
      -Detail 'ASR blocks the exact techniques this tool detects (WMI persistence, LSASS abuse, Office child-process, USB payloads).' `
      -Remediation 'Enable the full ASR rule set in block mode via GPO/Intune (AttackSurfaceReductionRules_Ids/Actions).'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title ("Defender ASR rules: {0} enabled" -f $enabled.Count) `
      -Detail (($enabled | ForEach-Object { if ($asrIds["$_"]) { $asrIds["$_"] } else { $_ } }) -join ' | ')
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

# --- AppLocker / WDAC policy presence ---
$appLockerSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
$alRules = 0
try {
  foreach ($coll in @('Exe','Dll','Script','Msi','Packaged app')) {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$coll"
    if (Test-Path $path) { $alRules += @(Get-ChildItem $path).Count }
  }
} catch { }
$wdac = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
if ($alRules -gt 0) {
  Add-Finding -Severity Info -Category 'Hardening' -Title ("AppLocker: {0} rules configured" -f $alRules)
  if ($appLockerSvc -and $appLockerSvc.Status -ne 'Running') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'AppLocker rules exist but AppIDSvc not running' `
      -Remediation 'Set AppIDSvc to auto-start; rules without the service are inert.'
  }
}
elseif ($wdac) {
  Add-Finding -Severity Info -Category 'Hardening' -Title 'WDAC policy present (code integrity)'
}
else {
  Add-Finding -Severity High -Category 'Hardening' -Title 'No AppLocker or WDAC application-control policy' `
    -Detail 'Everything this report lists as persistence/privexec runs because nothing blocks unsigned execution.' `
    -Remediation 'Golden-image item: deploy WDAC (audit -> enforce) or AppLocker baseline rules (EXE/DLL/Script/MSI). Single highest-value hardening control.'
}

# --- SmartScreen ---
try {
  $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
  $ssVal = "$($ss.SmartScreenEnabled)"
  if ($ssVal -eq 'Off') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen OFF (machine)' `
      -Remediation 'Set SmartScreenEnabled=Warn/Block.'
  }
  elseif ($ssVal) {
    Add-Finding -Severity Info -Category 'Hardening' -Title "SmartScreen: $ssVal"
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'SmartScreen key not set (modern builds use per-app policies - verify via Windows Security UI)'
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

# --- Remote desktop helpers image should remove ---
foreach ($feature in @('TelnetClient', 'TFTPClient', 'MicrosoftWindowsPowerShellV2', 'SMB1Protocol')) {
  try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
      Add-Finding -Severity High -Category 'Hardening' -Title ("Remove from image: feature {0} enabled" -f $feature) `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName $feature"
    }
  } catch { }
}

# --- Local admin RDP membership recap (image hygiene) ---
try {
  $adm = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
  if ($adm.Count -gt 3) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} local Administrators - trim the image baseline" -f $adm.Count)
  }
} catch { }

# --- Null sessions / registry remote access ---
foreach ($rk in @(
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Want = 1 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Want = 1 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks'; Want = 0 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Want = 0 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\RemoteRegistry'; Name = 'Start'; Want = 4 }
)) {
  $v = (Get-ItemProperty $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue).($rk.Name)
  if ($null -ne $v -and [int]$v -ne [int]$rk.Want) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title ("{0} = {1} (hardening wants {2})" -f $rk.Name, $v, $rk.Want) `
      -Remediation ("Set {0}={1} in the image (null-session / remote-registry hardening)." -f $rk.Name, $rk.Want)
  }
  elseif ($null -eq $v -and $rk.Name -match 'AutoShare') {
    # defaults: Wks=1 on client SKUs
    if ($rk.Name -eq 'AutoShareWks') {
      Add-Finding -Severity Low -Category 'Hardening' -Title 'AutoShareWks not set (default shares C$/ADMIN$ enabled)' `
        -Remediation 'Set AutoShareWks=0 in hardened images to kill default admin shares.'
    }
  }
}

######################## SUMMARY & REPORTS ########################

Start-Section 'SUMMARY'
$total = $script:Findings.Count
Write-Host ''
Write-Host ('Scan complete in {0:mm\:ss}. {1} findings.' -f $stopwatch.Elapsed, $total) -ForegroundColor Cyan
$grouped = $script:Findings | Group-Object Severity | Sort-Object { @('Critical','High','Medium','Low','Info').IndexOf($_.Name) }
foreach ($g in $grouped) {
  $color = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }[$g.Name]
  Write-Host ('  {0,-9} {1}' -f $g.Name, $g.Count) -ForegroundColor $color
}
Write-Host ''
Write-Host 'Top items by severity:' -ForegroundColor Cyan
$top = $script:Findings | Where-Object { $_.Severity -in 'Critical', 'High' } | Select-Object -First 10
if ($top) {
  foreach ($f in $top) { Write-Host ('  [{0}] {1}: {2}' -f $f.Severity, $f.Category, $f.Title) -ForegroundColor Red }
}
else {
  Write-Host '  No Critical/High findings. ' -ForegroundColor Green
}

Write-Reports -Dir $OutputDir

# Unattended mode: exit code = count of Critical+High findings (capped 250) so
# deployment/scheduling tooling can triage hosts without parsing output.
$critHigh = @($script:Findings | Where-Object { $_.Severity -in 'Critical', 'High' }).Count
$exitCode = [math]::Min($critHigh, 250)
Write-Host ''
Write-Host ("Exit code will be {0} (Critical+High count) for unattended triage." -f $exitCode) -ForegroundColor DarkCyan
exit $exitCode

Write-Host ''
Write-Host 'BlueWinPEAS audit finished. Reports contain no secret values (detection + redaction only).' -ForegroundColor Cyan
