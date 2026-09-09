
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
