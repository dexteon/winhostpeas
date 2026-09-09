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
