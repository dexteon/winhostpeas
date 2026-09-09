
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
