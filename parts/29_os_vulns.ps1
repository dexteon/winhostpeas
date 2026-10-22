
######################## OS VULNERABILITY / CRYPTO / EOL SURFACE ########################
# OS-level vulnerability surface for Server 2019/2022 and Win10/11:
# OS EOL, TLS protocol inventory, cipher suites, SMB dialects, RDP encryption,
# .NET/edge/legacy runtime inventory, LSA old behavior, secedit baseline dump.

Start-Section 'OS VULNERABILITY SURFACE'

# --- OS build + support status ---
$osCim = Get-CimInstance Win32_OperatingSystem
$osName = $osCim.Caption
$build = [int]$osCim.BuildNumber
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$displayVer = "$($cv.DisplayVersion)"; if (-not $displayVer) { $displayVer = "$($cv.ReleaseId)" }
$editionId = "$($cv.EditionID)"
$isServerSku = ($null -ne $osCim.ProductType -and [int]$osCim.ProductType -ne 1)
Add-Finding -Severity Info -Category 'OS' -Title ("OS: {0} {1} {2} (build {3})" -f $osName, $displayVer, $editionId, $build)

# Support end is per version AND edition. Client dates below were read from the Microsoft
# Lifecycle pages on 2026-10-22 (end date = last supported day, Pacific time):
#   Windows 11 Home/Pro (incl. Pro Education, Pro for Workstations) vs Enterprise/Education.
#   Windows 10: every GAC edition ended 2025-10-14 (ESU is not detectable from the registry).
# LTSC and Server rows are the published lifecycle dates (LTSC 2021 / Server rows from memory
# of the lifecycle site; re-check if a host reports one of those).
$eol = $null
$eolKind = ''
try {
  $w11 = @{   # version = @(HomePro, EnterpriseEducation)
    '21H2' = @('2023-10-10', '2024-10-08'); '22H2' = @('2024-10-08', '2025-10-14')
    '23H2' = @('2025-11-11', '2026-11-10'); '24H2' = @('2026-10-13', '2027-10-12')
    '25H2' = @('2027-10-12', '2028-10-10'); '26H1' = @('2028-03-14', '2029-03-13')
    '26H2' = @('2028-10-09', '2029-10-09')
  }
  $w10 = @{
    '22H2' = @('2025-10-14', '2025-10-14'); '21H2' = @('2023-06-13', '2024-06-11')
    '21H1' = @('2022-12-13', '2022-12-13'); '20H2' = @('2022-05-10', '2023-05-09')
    '2004' = @('2021-12-14', '2021-12-14'); '1909' = @('2021-05-11', '2022-05-10')
    '1809' = @('2020-11-10', '2021-05-11'); '1803' = @('2019-11-12', '2021-05-11')
  }
  $isEE = $editionId -match '^(Enterprise|Education|IoTEnterprise)' -and $editionId -notmatch 'EnterpriseS'
  if ($isServerSku) {
    $serverTable = @(
      @{ Match = 'Server 2025'; EOL = '2034-10-10' }, @{ Match = 'Server 2022'; EOL = '2031-10-14' },
      @{ Match = 'Server 2019'; EOL = '2029-01-09' }, @{ Match = 'Server 2016'; EOL = '2027-01-12' },
      @{ Match = 'Server 2012'; EOL = '2023-10-10' }, @{ Match = 'Server 2008'; EOL = '2020-01-14' }
    )
    foreach ($e in $serverTable) { if ($osName -like "*$($e.Match)*") { $eol = [datetime]$e.EOL; $eolKind = $e.Match; break } }
  }
  elseif ($editionId -match 'EnterpriseS') {
    $iot = $editionId -match '^IoT'
    $ltsc = @{ 10240 = '2025-10-14'; 14393 = '2026-10-13'; 17763 = '2029-01-09'
               19044 = $(if ($iot) { '2032-01-13' } else { '2027-01-12' })
               26100 = $(if ($iot) { '2034-10-10' } else { '2029-10-09' }) }
    if ($ltsc.ContainsKey($build)) { $eol = [datetime]$ltsc[$build]; $eolKind = "LTSC build $build" }
  }
  elseif ($build -ge 22000) {
    if ($w11.ContainsKey($displayVer)) { $eol = [datetime]$w11[$displayVer][$(if ($isEE) { 1 } else { 0 })]; $eolKind = "Windows 11 $displayVer " + $(if ($isEE) { 'Enterprise/Education' } else { 'Home/Pro' }) }
  }
  elseif ($build -ge 10240) {
    if ($w10.ContainsKey($displayVer)) { $eol = [datetime]$w10[$displayVer][$(if ($isEE) { 1 } else { 0 })] } else { $eol = [datetime]'2025-10-14' }
    $eolKind = "Windows 10 $displayVer"
  }
} catch { $eol = $null }
# Warning window: 365 days for Server and LTSC (multi-year lifecycles); 180 days for client
# feature updates, whose Home/Pro lifetime is only 24 months, so a 1-year window would flag
# the current release a few weeks after it ships. Newer feature updates are named in the detail
# instead of raising their own finding.
$isClientGac = (-not $isServerSku -and $editionId -notmatch 'EnterpriseS')
$warnDays = if ($isClientGac) { 180 } else { 365 }
$newerVer = ''
try {
  if ($isClientGac -and $build -ge 22000 -and $w11.ContainsKey($displayVer)) {
    $newerList = @($w11.Keys | Where-Object { [datetime]$w11[$_][0] -gt [datetime]$w11[$displayVer][0] } | Sort-Object)
    if ($newerList.Count -gt 0) { $newerVer = ' Newer feature update(s) available: ' + ($newerList -join ', ') + '.' }
  }
} catch { }
if ($null -eq $eol) {
  Add-Finding -Severity Info -Category 'OS' -Title ("OS support date not assessed for {0} {1} {2}" -f $osName, $displayVer, $editionId) `
    -Detail 'This version/edition is not in the built-in lifecycle table; check the Microsoft Lifecycle site.'
}
elseif ((Get-Date) -gt $eol) {
  Add-Finding -Severity Critical -Category 'OS' -Title ("{0} is PAST END OF SUPPORT ({1:yyyy-MM-dd})" -f $eolKind, $eol) `
    -Detail ('No security patches (unless enrolled in Extended Security Updates, which this scan cannot see) - every future CVE is permanent.' + $newerVer) `
    -Remediation 'Move to a supported feature update or OS; isolate the host meanwhile.'
}
elseif (((Get-Date) - $eol).Days -gt (-1 * $warnDays)) {
  Add-Finding -Severity Medium -Category 'OS' -Title ("{0} support ends {1:yyyy-MM-dd} (within {2} days)" -f $eolKind, $eol, $warnDays) `
    -Detail ('Feature updates past end of servicing receive no security fixes.' + $newerVer) `
    -Remediation 'Schedule the feature update or OS upgrade now.'
}
else {
  Add-Finding -Severity Info -Category 'OS' -Title ("{0} supported until {1:yyyy-MM-dd}" -f $eolKind, $eol) -Detail ($newerVer.Trim())
}

# --- TLS protocol inventory (SSP Schannel enabled protocols) ---
# A protocol is active when Enabled is not 0 AND DisabledByDefault is not 1. An absent value
# takes the OS default for this build: TLS 1.0/1.1 are on by default below build 26100
# (Win10, Server 2019/2022) and off from 26100 (Win11 24H2+, Server 2025); SSL 2.0/3.0 are
# off on every supported build; TLS 1.2 is on from 17763; TLS 1.3 from 20348.
# (The previous version had the two values swapped, so a hardened host that set
# Enabled=0/DisabledByDefault=1 was reported as ACTIVE and an explicitly enabled one as clean.)
function Test-SchannelProtocolActive {
  param([string]$Protocol, [string]$Side, [int]$OsBuild)
  $defaultOn = switch ($Protocol) {
    'TLS 1.3' { $OsBuild -ge 20348 }
    'TLS 1.2' { $OsBuild -ge 17763 }
    'TLS 1.1' { $OsBuild -lt 26100 }
    'TLS 1.0' { $OsBuild -lt 26100 }
    default   { $false }
  }
  $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Side"
  $en  = (Get-ItemProperty $k -Name Enabled -ErrorAction SilentlyContinue).Enabled
  $dbd = (Get-ItemProperty $k -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
  $enEff  = if ($null -eq $en)  { 1 } else { [int]$en }
  $dbdEff = if ($null -eq $dbd) { $(if ($defaultOn) { 0 } else { 1 }) } else { [int]$dbd }
  $src = if ($null -eq $en -and $null -eq $dbd) { 'OS default' } else { "Enabled=$en DisabledByDefault=$dbd" }
  return [pscustomobject]@{ Active = (($enEff -ne 0) -and ($dbdEff -ne 1)); Source = $src }
}
try {
  foreach ($p in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
    foreach ($side in @('Server', 'Client')) {
      $st = Test-SchannelProtocolActive -Protocol $p -Side $side -OsBuild $build
      if ($st.Active) {
        $sev = if ($side -eq 'Server') { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category 'Crypto' -Title ("Weak protocol ACTIVE {0}-side: {1}" -f $side.ToLower(), $p) `
          -Detail ("Resolved from: {0}. SSL and TLS 1.0/1.1 fail PCI DSS and DISA STIG baselines; downgrade attacks (POODLE/BEAST class)." -f $st.Source) `
          -Evidence ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\{1}" -f $p, $side) `
          -Remediation ("Set Enabled=0 and DisabledByDefault=1 under SCHANNEL\Protocols\{0}\{1} and reboot." -f $p, $side)
      }
    }
  }
  $activeProtos = @()
  foreach ($p in @('TLS 1.2', 'TLS 1.3')) {
    $st = Test-SchannelProtocolActive -Protocol $p -Side 'Server' -OsBuild $build
    if ($st.Active) { $activeProtos += $p }
  }
  if ($activeProtos.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Crypto' -Title ("Modern TLS available server-side: {0}" -f ($activeProtos -join ', '))
  } else {
    Add-Finding -Severity High -Category 'Crypto' -Title 'No modern TLS protocol enabled server-side' `
      -Detail 'TLS 1.2 and 1.3 are both disabled (Enabled=0 or DisabledByDefault=1), so only weak protocols can be negotiated.' `
      -Remediation 'Explicitly enable TLS 1.2/1.3 server-side (Enabled=1, DisabledByDefault=0).'
  }
} catch {
  Add-Finding -Severity Info -Category 'Crypto' -Title 'SCHANNEL protocol state not assessed' -Detail ('Registry read failed: ' + $_.Exception.Message)
}

# --- Cipher suites: weak/NULL/RC4/3DES presence in the enabled list ---
try {
  # Get-TlsCipherSuite must be collected into a variable BEFORE property access.
  # Piping it straight into Select-Object -ExpandProperty Name fails with
  # 'Property "Name" cannot be found' on the binary TLS module (both PS 5.1 and
  # 7.x), yielding an empty list that was then reported as the false-clean
  # "0 cipher suites enabled, none weak" while weak NULL suites were live.
  $suites = @(Get-TlsCipherSuite -ErrorAction Stop)
  $cs = @($suites | ForEach-Object { $_.Name } | Where-Object { $_ })
  if ($cs.Count -eq 0) {
    Add-Finding -Severity Info -Category 'Crypto' -Title 'Cipher suite list not assessed' `
      -Detail 'Get-TlsCipherSuite returned no readable suite names; weak-cipher status is unknown, not clean.'
  }
  else {
    $weak = @($cs | Where-Object { $_ -match 'NULL|RC4|3DES|DES_' })
    if ($weak.Count -gt 0) {
      Add-Finding -Severity Medium -Category 'Crypto' -Title ("{0} of {1} enabled cipher suites are weak" -f $weak.Count, $cs.Count) `
        -Detail (($weak | Select-Object -First 8) -join ', ') `
        -Remediation 'Prune with Disable-TlsCipherSuite -Name <suite>; keep AEAD suites (GCM/ChaCha20) only.'
    }
    else {
      Add-Finding -Severity Info -Category 'Crypto' -Title ("{0} cipher suites enabled, none weak" -f $cs.Count)
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Crypto' -Title 'Cipher suite enumeration failed' `
    -Detail ('Get-TlsCipherSuite error: ' + $_.Exception.Message + '. Weak-cipher status not assessed.')
}

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
  # Server-side signing is reported once, in the Network section (23_network), not repeated here.
  $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
  if ($cli -and $cli.EnableSecuritySignature -eq $false -and $cli.RequireSecuritySignature -eq $false) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB client: signing neither enabled nor required' `
      -Remediation 'Require SMB client signing via GPO (NTLM relay defense).'
  }
  # Insecure guest logons (CIS 18.5.8.1): a guest SMB session has no signing or encryption, so it defeats both.
  $guestPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name AllowInsecureGuestAuth -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
  if (($cli -and $cli.EnableInsecureGuestLogons) -or $guestPolicy -eq 1) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB client allows insecure guest logons' `
      -Detail ("EnableInsecureGuestLogons={0}; policy AllowInsecureGuestAuth={1}. Guest sessions carry no signing or encryption, so a rogue server can serve tampered files." -f $(if ($cli) { $cli.EnableInsecureGuestLogons } else { 'n/a' }), $guestPolicy) `
      -Remediation 'Set-SmbClientConfiguration -EnableInsecureGuestLogons $false, or policy LanmanWorkstation AllowInsecureGuestAuth=0.'
  }
  elseif ($cli) {
    Add-Finding -Severity Info -Category 'Crypto' -Title 'SMB client blocks insecure guest logons'
  }
  Add-Finding -Severity Info -Category 'Crypto' -Title 'SMB server encryption state recorded' `
    -Detail ("EncryptData={0}; RejectUnencryptedAccess={1}. EncryptData=True forces SMB 3 encryption for every share." -f $srv.EncryptData, $srv.RejectUnencryptedAccess)
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
# Get-WindowsOptionalFeature -Online needs elevation ("The requested operation requires
# elevation"); a silent catch here used to look like a clean host. This is the only block
# that reports optional features (the Hardening section no longer repeats it).
if (-not $script:IsElevated) {
  $smb1Start = $null
  try { $smb1Start = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -ErrorAction SilentlyContinue).Start } catch { }
  $smb1Hint = if ($null -eq $smb1Start) { 'Partial signal: the SMB1 client driver (mrxsmb10) is not installed, so the SMB1 client feature is off.' }
              elseif ([int]$smb1Start -eq 4) { 'Partial signal: the SMB1 client driver (mrxsmb10) is installed but disabled (Start=4).' }
              else { "Partial signal: the SMB1 client driver (mrxsmb10) is installed with Start=$smb1Start, so the SMB1 client feature is likely enabled." }
  $smb1Sev = if ($null -ne $smb1Start -and [int]$smb1Start -ne 4) { 'High' } else { 'Info' }
  Add-Finding -Severity $smb1Sev -Category 'OS' -Title 'Legacy optional features not assessed (needs elevation)' `
    -Detail ('Get-WindowsOptionalFeature requires administrator, so PowerShell v2, SMB1, Telnet and TFTP client state is unknown, not clean. ' + $smb1Hint) `
    -Remediation 'Re-run elevated to enumerate legacy optional features.'
}
else {
  try {
    $feats = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -match 'PowerShellV2|SMB1Protocol|TelnetClient|TFTPClient|NetFx3|IIS-.*Basicauth' }
    $featCount = 0
    foreach ($f in @($feats)) {
      $featCount++
      $sev = if ($f.FeatureName -match 'SMB1|PowerShellV2') { 'High' } else { 'Low' }
      Add-Finding -Severity $sev -Category 'OS' -Title ("Legacy feature enabled: {0}" -f $f.FeatureName) `
        -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName <name> - remove unless explicitly required (PowerShellv2 = downgrade attacks, SMB1 = wormable).'
    }
    if ($featCount -eq 0) {
      Add-Finding -Severity Info -Category 'OS' -Title 'No legacy optional features enabled (PowerShell v2, SMB1, Telnet, TFTP, NetFx3, IIS Basic auth)'
    }
  } catch {
    Add-Finding -Severity Info -Category 'OS' -Title 'Legacy optional features not assessed' -Detail ('Get-WindowsOptionalFeature failed: ' + $_.Exception.Message)
  }
}

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
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'OS' -Title 'Local security policy (secedit) not assessed (needs elevation)' `
    -Detail 'secedit /export requires administrator; run elevated to verify minimum password length, account-lockout threshold and anonymous-lookup policy.'
}
elseif ($true) {
try {
  $secOut = "$env:TEMP\winhostpeas_secedit.cfg"
  secedit /export /cfg $secOut /quiet 2>$null | Out-Null
  if (Test-Path $secOut) {
    $sec = Get-Content $secOut -ErrorAction SilentlyContinue
    # Minimum password length and lockout threshold are reported once, from net accounts in the
    # Accounts section (works non-elevated). Here they are recorded as supporting detail only.
    $secVal = @{}
    foreach ($n in @('MinimumPasswordLength', 'LockoutBadCount', 'PasswordComplexity', 'MaximumPasswordAge', 'MinimumPasswordAge',
                     'PasswordHistorySize', 'ClearTextPassword', 'LockoutDuration', 'ResetLockoutCount', 'EnableGuestAccount', 'LsaAnonymousNameLookup')) {
      $line = ($sec | Select-String ("^\s*{0}\s*=" -f $n) | Select-Object -First 1).Line
      if ($line -match '=\s*(-?\d+)') { $secVal[$n] = [int]$Matches[1] }
    }
    if ($secVal['LsaAnonymousNameLookup'] -eq 1) {
      Add-Finding -Severity Medium -Category 'OS' -Title 'Anonymous SAM/LSA lookup enabled' `
        -Remediation 'Disable: LsaAnonymousNameLookup=0 (blocks null-session enumeration).'
    }
    if ($secVal['ClearTextPassword'] -eq 1) {
      Add-Finding -Severity Medium -Category 'OS' -Title 'Passwords stored with reversible encryption (ClearTextPassword=1)' `
        -Detail 'Reversible encryption is equivalent to plaintext for anyone who can read the SAM or AD database.' `
        -Remediation 'Set "Store passwords using reversible encryption" to Disabled (CIS 1.1.7).'
    }
    if ($secVal.ContainsKey('PasswordComplexity') -and $secVal['PasswordComplexity'] -eq 0) {
      Add-Finding -Severity Low -Category 'OS' -Title 'Password complexity not required (PasswordComplexity=0)' `
        -Remediation 'Enable complexity (CIS 1.1.6) or enforce a banned-password list with a 14+ length minimum.'
    }
    if ($secVal.ContainsKey('MaximumPasswordAge') -and ($secVal['MaximumPasswordAge'] -le 0 -or $secVal['MaximumPasswordAge'] -gt 365)) {
      Add-Finding -Severity Low -Category 'OS' -Title ("Maximum password age {0} (never expires or over 365 days)" -f $secVal['MaximumPasswordAge']) `
        -Remediation 'CIS 1.1.3: 365 days or fewer, but not 0. Rotation matters most for shared and service accounts.'
    }
    if ($secVal.ContainsKey('PasswordHistorySize') -and $secVal['PasswordHistorySize'] -lt 24) {
      Add-Finding -Severity Low -Category 'OS' -Title ("Password history {0} (CIS wants 24)" -f $secVal['PasswordHistorySize']) `
        -Remediation 'Set "Enforce password history" to 24 or more (CIS 1.1.1).'
    }
    if ($secVal.ContainsKey('LockoutBadCount') -and $secVal['LockoutBadCount'] -gt 0) {
      if ($secVal.ContainsKey('LockoutDuration') -and $secVal['LockoutDuration'] -ge 0 -and $secVal['LockoutDuration'] -lt 15) {
        Add-Finding -Severity Low -Category 'OS' -Title ("Account lockout duration {0} minutes (CIS wants 15 or more)" -f $secVal['LockoutDuration']) `
          -Remediation 'Set lockout duration to 15 minutes or more (CIS 1.2.1); -1 (until admin unlocks) also passes.'
      }
      if ($secVal.ContainsKey('ResetLockoutCount') -and $secVal['ResetLockoutCount'] -lt 15) {
        Add-Finding -Severity Low -Category 'OS' -Title ("Lockout counter reset after {0} minutes (CIS wants 15 or more)" -f $secVal['ResetLockoutCount']) `
          -Remediation 'Set "Reset account lockout counter after" to 15 minutes or more (CIS 1.2.3).'
      }
    }
    Add-Finding -Severity Info -Category 'OS' -Title 'Secedit baseline exported (password/lockout/anonymous policy recorded)' `
      -Detail (($secVal.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ')
    Remove-Item $secOut -Force -ErrorAction SilentlyContinue
  }
} catch { }
}

# --- RDP encryption level (Terminal Server) ---
# MinEncryptionLevel defaults to 2 (Client Compatible) on every host, and it only governs the
# legacy RDP security layer. With SecurityLayer 1 (negotiate) or 2 (TLS) the legacy level is
# moot, so a low level is only High when SecurityLayer=0 forces native RDP encryption.
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if ($ts) {
  $encLevel = if ($null -eq $ts.MinEncryptionLevel) { 2 } else { [int]$ts.MinEncryptionLevel }
  $secLayer = if ($null -eq $ts.SecurityLayer) { 1 } else { [int]$ts.SecurityLayer }
  $encSrc = if ($null -eq $ts.MinEncryptionLevel) { ' (value absent, OS default)' } else { '' }
  if ($encLevel -lt 3 -and $secLayer -eq 0) {
    Add-Finding -Severity High -Category 'Crypto' -Title ("RDP encryption level {0}{1} with SecurityLayer=0 (legacy RDP crypto)" -f $encLevel, $encSrc) `
      -Detail 'Native RDP security with a low encryption level is subject to downgrade and MITM; TLS is not in use.' `
      -Remediation 'Set SecurityLayer=2 (TLS) and MinEncryptionLevel=3 (High); pair with NLA.'
  }
  elseif ($encLevel -lt 3) {
    Add-Finding -Severity Low -Category 'Crypto' -Title ("RDP legacy encryption level {0}{1}; TLS security layer {2} makes it moot" -f $encLevel, $encSrc, $secLayer) `
      -Remediation 'Optional hardening: MinEncryptionLevel=3 (CIS 18.9.65.3.9.5). Keep SecurityLayer at 2 (TLS).'
  }
  # SecurityLayer=0 itself is reported in the Network section (23_network).
}

# --- Unsigned driver / test-signing exposure ---
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'OS' -Title 'Boot config (bcdedit) not assessed (needs elevation)' `
    -Detail 'bcdedit /enum requires administrator; run elevated to detect test-signing mode and disabled code-integrity (nointegritychecks).'
}
else {
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
      -Remediation 'bcdedit /set nointegritychecks off (restores integrity enforcement); disabled CI allows unsigned code at boot.'
  }
}

# --- Enabled local-admin RDP/WinRM exposure recap (ties into network findings) ---
$nullDevice = $null
try {
  $denyRdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
  if ($denyRdp -eq 0 -and $build -ge 17763) {
    Add-Finding -Severity Info -Category 'OS' -Title 'RDP enabled (modern build) - ensure NLA enforced and exposure firewalled'
  }
} catch { }
