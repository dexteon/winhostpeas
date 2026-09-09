
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
