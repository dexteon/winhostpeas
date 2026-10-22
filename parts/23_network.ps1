
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

# Defender firewall profiles (state, default inbound action, local rule merge: CIS 9.x)
try {
  $profSummary = @()
  foreach ($prof in (Get-NetFirewallProfile -ErrorAction Stop)) {
    if (-not $prof.Enabled) {
      Add-Finding -Severity High -Category 'Network' -Title ("Firewall profile '{0}' disabled" -f $prof.Name) `
        -Remediation 'Enable all firewall profiles via GPO.'
    }
    # NotConfigured means the OS default (Block), so only an explicit Allow is a finding.
    if ("$($prof.DefaultInboundAction)" -eq 'Allow') {
      Add-Finding -Severity High -Category 'Network' -Title ("Firewall profile '{0}' default inbound action is Allow" -f $prof.Name) `
        -Detail 'Every inbound connection not matched by a block rule is accepted; the firewall is effectively open on this profile.' `
        -Remediation ("Set-NetFirewallProfile -Name {0} -DefaultInboundAction Block (CIS 9.x.2)." -f $prof.Name)
    }
    if ("$($prof.Name)" -eq 'Domain' -and $prof.Enabled -and ("$($prof.AllowLocalFirewallRules)" -eq 'True' -or "$($prof.AllowLocalIPsecRules)" -eq 'True')) {
      Add-Finding -Severity Low -Category 'Network' -Title 'Domain firewall profile merges locally defined rules' `
        -Detail ("AllowLocalFirewallRules={0}; AllowLocalIPsecRules={1}. A local admin (or malware running as one) can add allow rules that GPO does not override." -f $prof.AllowLocalFirewallRules, $prof.AllowLocalIPsecRules) `
        -Remediation 'Set "Apply local firewall rules" and "Apply local connection security rules" to No on the Domain profile (CIS 9.1.5, 9.1.6).'
    }
    $profSummary += ('{0}: enabled={1}, inbound={2}, outbound={3}' -f $prof.Name, $prof.Enabled, $prof.DefaultInboundAction, $prof.DefaultOutboundAction)
  }
  Add-Finding -Severity Info -Category 'Network' -Title 'Firewall profile states recorded' -Detail ($profSummary -join ' | ')
}
catch {
  Add-Finding -Severity Info -Category 'Network' -Title 'Firewall profiles not assessed' -Detail ('Get-NetFirewallProfile failed: ' + $_.Exception.Message)
}

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

# WPAD is evaluated in the Security Features section (service state, DisableWpad, WpadOverride).

# SMB shares and broad access, by SID (language-neutral) and confirmed against NTFS.
# The share security descriptor is read as SDDL from the share object itself, so no name
# lookup (and no LSA/DC traffic) is needed. Default admin shares (C$, ADMIN$, IPC$: Special=True)
# are skipped: they require Administrators regardless of the ACE list.
$script:ShareWriteMask = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000   # WRITE_DATA, APPEND, DELETE, WRITE_DAC, WRITE_OWNER
try {
  $shareCount = 0
  foreach ($share in @(Get-SmbShare -ErrorAction Stop)) {
    if ($share.Special) { continue }
    if ($share.Name -eq 'IPC$' -or $share.Name -eq 'ADMIN$' -or $share.Name -match '^[A-Za-z]\$$') { continue }
    $shareCount++
    $broad = @()
    try {
      if ($share.SecurityDescriptor) {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($share.SecurityDescriptor)
        foreach ($ace in $sd.DiscretionaryAcl) {
          if ("$($ace.AceType)" -ne 'AccessAllowed') { continue }
          $sid = "$($ace.SecurityIdentifier.Value)"
          if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
          if (($ace.AccessMask -band $script:ShareWriteMask) -eq 0) { continue }
          $broad += [pscustomobject]@{ Name = $script:LowPrivSids[$sid]; Sid = $sid; Mask = ('0x{0:X}' -f $ace.AccessMask) }
        }
      }
    } catch { }
    if ($broad.Count -eq 0) { continue }
    $who = ($broad | ForEach-Object { '{0} ({1}, mask {2})' -f $_.Name, $_.Sid, $_.Mask }) -join ', '
    # The effective permission is the intersection of share and NTFS ACLs.
    $ntfsHit = $null; $ntfsReadable = $false
    try {
      if ($share.Path -and (Test-Path -LiteralPath $share.Path)) {
        $acl = Get-Acl -LiteralPath $share.Path -ErrorAction Stop
        $ntfsReadable = $true
        $ntfsHit = Get-LowPrivWriteAce -ACLObject $acl
      }
    } catch { $ntfsReadable = $false }
    if ($ntfsHit) {
      Add-Finding -Severity Medium -Category 'Network' -Title ("Share '{0}' writable by low-privilege principals (share and NTFS agree)" -f $share.Name) `
        -Detail ("Path: {0}. Share ACL grants write to {1}; NTFS grants {2} to {3} ({4})." -f $share.Path, $who, $ntfsHit.Level, $ntfsHit.Name, $ntfsHit.Sid) `
        -Evidence ("\\{0}\{1} -> {2}" -f $env:COMPUTERNAME, $share.Name, $share.Path) `
        -Remediation 'Restrict share and NTFS permissions to the groups that need write; writable broad shares are lateral-movement and ransomware vectors.'
    }
    elseif ($ntfsReadable) {
      Add-Finding -Severity Low -Category 'Network' -Title ("Share '{0}' ACL is broad but NTFS restricts write" -f $share.Name) `
        -Detail ("Path: {0}. Share ACL grants write to {1}, but no low-privilege principal has write on the folder's NTFS ACL, so the effective access is read-only. Tightening the share ACL removes the dependency on NTFS." -f $share.Path, $who) `
        -Evidence ("\\{0}\{1} -> {2}" -f $env:COMPUTERNAME, $share.Name, $share.Path) `
        -Remediation 'Reduce the share permission to Read for broad groups so NTFS is not the only control.'
    }
    else {
      Add-Finding -Severity Low -Category 'Network' -Title ("Share '{0}' ACL is broad; NTFS not assessed" -f $share.Name) `
        -Detail ("Path: {0}. Share ACL grants write to {1}; the folder ACL could not be read, so effective write access is unknown." -f $share.Path, $who) `
        -Evidence ("\\{0}\{1} -> {2}" -f $env:COMPUTERNAME, $share.Name, $share.Path) `
        -Remediation 'Check the NTFS ACL of the share path; restrict the share permission to Read for broad groups.'
    }
  }
  Add-Finding -Severity Info -Category 'Network' -Title ("{0} non-default SMB shares assessed" -f $shareCount)
} catch {
  Add-Finding -Severity Info -Category 'Network' -Title 'SMB shares not assessed' -Detail ('Get-SmbShare failed: ' + $_.Exception.Message)
}

######################## LOCAL ACCOUNT HYGIENE ########################

Start-Section 'LOCAL ACCOUNT HYGIENE'
try {
  # net accounts labels are translated, but the line order is fixed in every language:
  # minimum password length is always the 4th "label: value" line. Try the English label,
  # then fall back to that position, so non-English Windows still gets a real value.
  $na = @(net accounts 2>$null)
  $minLen = $na | Where-Object { $_ -match 'minimum password length' } | Select-Object -First 1
  if (-not $minLen) {
    $kv = @($na | Where-Object { $_ -match ':\s*\S' })
    if ($kv.Count -ge 4) { $minLen = $kv[3] }
  }
  if (-not $minLen) { throw 'net accounts returned no password policy' }
  $digits = ($minLen -split ':', 2)[1] -replace '[^\d]', ''
  $val = if ($digits) { [int]$digits } else { 0 }
  # One threshold (CIS 1.1.4: 14). The secedit block in the OS section no longer repeats this.
  if ($val -lt 14) {
    Add-Finding -Severity Medium -Category 'Accounts' -Title ("Minimum password length {0} (<14)" -f $val) `
      -Evidence ($minLen.Trim()) `
      -Remediation 'Raise minimum length to 14+ (CIS 1.1.4) and pair with banned-password lists.'
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title "Minimum password length ${val}"
  }
  # Lockout threshold is the 6th "label: value" line in every language. "Never" (or any
  # localized word with no digits) means 0, which is no lockout at all.
  $lockLine = $na | Where-Object { $_ -match 'lockout threshold' } | Select-Object -First 1
  if (-not $lockLine) {
    $kv = @($na | Where-Object { $_ -match ':\s*\S' })
    if ($kv.Count -ge 6) { $lockLine = $kv[5] }
  }
  if ($lockLine) {
    $lockDigits = ($lockLine -split ':', 2)[1] -replace '[^\d]', ''
    $lockVal = if ($lockDigits) { [int]$lockDigits } else { 0 }
    if ($lockVal -eq 0) {
      Add-Finding -Severity Medium -Category 'Accounts' -Title 'Account lockout threshold: 0 (never locks)' `
        -Detail 'Unlimited password guesses against every local account, over the network and at the console.' `
        -Evidence ($lockLine.Trim()) `
        -Remediation 'Set lockout threshold to 5 or fewer invalid attempts (CIS 1.2.2) with a 15-minute duration and reset window.'
    }
    elseif ($lockVal -gt 10) {
      Add-Finding -Severity Low -Category 'Accounts' -Title ("Account lockout threshold {0} (CIS wants 5 or fewer)" -f $lockVal) `
        -Evidence ($lockLine.Trim()) -Remediation 'Lower the threshold to 5 or fewer invalid attempts (CIS 1.2.2).'
    }
    else {
      Add-Finding -Severity Info -Category 'Accounts' -Title ("Account lockout threshold {0}" -f $lockVal) -Evidence ($lockLine.Trim())
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title 'Account lockout threshold not assessed' -Detail 'net accounts output had fewer than six policy lines.'
  }
} catch {
  Add-Finding -Severity Info -Category 'Accounts' -Title 'Password and lockout policy not assessed' -Detail ('net accounts failed: ' + $_.Exception.Message)
}

try {
  # PasswordRequired = False is the PASSWD_NOTREQD flag. It means a blank password
  # is PERMITTED on the account, NOT that the account has one - the flag is a
  # routine artifact of programmatic account creation, so reporting it as
  # "no password" raises a false alarm on ordinary service accounts.
  #
  # Confirming whether a blank password actually authenticates would require an
  # authentication attempt, which writes failed-logon events and can trip lockout
  # policy. This tool stays passive, so it reports the flag accurately and scales
  # severity by whether blank-password network logon is possible at all.
  $limitBlank = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse
  # Absent defaults to 1 (blocked) on all supported Windows versions.
  $blankOverNetworkAllowed = ($limitBlank -eq 0)

  $users = Get-LocalUser -ErrorAction Stop
  foreach ($u in $users) {
    if ($u.Enabled -and -not $u.PasswordRequired) {
      $hasPwdEvidence = $null -ne $u.PasswordLastSet
      $sev = if ($blankOverNetworkAllowed) { 'High' } elseif ($hasPwdEvidence) { 'Low' } else { 'Medium' }
      $detail = "The PASSWD_NOTREQD flag is set, so this account is allowed to have a blank password. That is not proof it has one, and this scan does not attempt authentication to find out."
      $detail += if ($hasPwdEvidence) { (" A password was last set {0:yyyy-MM-dd}, which indicates one exists." -f $u.PasswordLastSet) } else { ' No password-set timestamp is recorded, so a blank password is plausible.' }
      $detail += if ($blankOverNetworkAllowed) {
        ' LimitBlankPasswordUse = 0, so a blank password WOULD be usable for network logon. This is the combination that matters.'
      }
      else {
        ' LimitBlankPasswordUse = 1, so even a blank password could not be used for network logon, only at the console.'
      }
      Add-Finding -Severity $sev -Category 'Accounts' -Title ("Account '{0}' permits a blank password (PASSWD_NOTREQD)" -f $u.Name) `
        -Detail $detail `
        -Evidence ("{0} | PasswordLastSet: {1}" -f $u.Name, $(if ($hasPwdEvidence) { '{0:yyyy-MM-dd HH:mm}' -f $u.PasswordLastSet } else { 'never' })) `
        -Remediation 'Clear the flag with: net user <user> /passwordreq:yes. Confirm the account holds a strong password, and keep LimitBlankPasswordUse = 1 so a blank password can never be used over the network.'
    }
    if (-not $u.Enabled) {
      Add-Finding -Severity Info -Category 'Accounts' -Title ("Disabled account: {0}" -f $u.Name)
    }
  }
  # local admin inventory
  $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
  Add-Finding -Severity Info -Category 'Accounts' -Title ('{0} local Administrators' -f @($admins).Count) `
    -Detail ((@($admins) | ForEach-Object { $_.Name }) -join ', ') `
    -Remediation 'Keep local admin membership minimal; prefer LAPS + just-in-time elevation.'
} catch { }

# Password-never-expires and built-in Administrator state, from Win32_UserAccount.
# Get-LocalUser.PasswordExpires is also null when the policy maximum age is unlimited, and the
# old check excluded the running user, so the auditor's own never-expiring admin was never
# reported. Win32_UserAccount.PasswordExpires is the DONT_EXPIRE_PASSWD flag itself.
try {
  $wmiUsers = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=TRUE" -ErrorAction Stop)
  $neverExp = @($wmiUsers | Where-Object { -not $_.Disabled -and $_.PasswordExpires -eq $false } | ForEach-Object { $_.Name })
  if ($neverExp.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Accounts' -Title ("{0} enabled local account(s) with password set to never expire" -f $neverExp.Count) `
      -Detail ($neverExp -join ', ') `
      -Remediation 'Rotate periodically or move local admin credentials to LAPS; service accounts should use managed credentials.'
  }
  $rid500 = $wmiUsers | Where-Object { "$($_.SID)" -like '*-500' } | Select-Object -First 1
  if ($rid500) {
    if (-not $rid500.Disabled) {
      Add-Finding -Severity Medium -Category 'Accounts' -Title ("Built-in Administrator (RID 500) is enabled: {0}" -f $rid500.Name) `
        -Detail 'RID 500 cannot be locked out and is the first target of password spraying and Pass-the-Hash.' `
        -Remediation 'Disable the built-in Administrator (CIS 2.3.1.1) and use LAPS-managed or named admin accounts.'
    }
    if ("$($rid500.Name)" -ieq 'Administrator') {
      Add-Finding -Severity Low -Category 'Accounts' -Title 'Built-in Administrator account not renamed' `
        -Detail 'The RID 500 account still carries the well-known name, which removes one guess from every attacker script.' `
        -Remediation 'Rename the built-in Administrator account (CIS 2.3.1.5); renaming is cosmetic against RID-based tools but stops name-based spraying.'
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Accounts' -Title 'Password-expiry and built-in Administrator state not assessed' -Detail ('Win32_UserAccount failed: ' + $_.Exception.Message)
}

# LAPS presence, gated on join state: LAPS cannot be deployed on a workgroup host, and the
# Windows LAPS keys exist (empty) on every unmanaged host, so key presence is not proof.
try {
  $joined = $false; $joinKind = 'workgroup'
  try { if ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain) { $joined = $true; $joinKind = 'domain-joined' } } catch { }
  if (-not $joined) {
    try {
      if ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0) { $joined = $true; $joinKind = 'Entra-joined' }
    } catch { }
  }
  $lapsEvidence = @()
  if ((Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') -or (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')) { $lapsEvidence += 'legacy LAPS CSE installed' }
  if ((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { $lapsEvidence += 'legacy LAPS policy AdmPwdEnabled=1' }
  foreach ($pk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS')) {
    $pv = Get-ItemProperty $pk -ErrorAction SilentlyContinue
    if ($pv -and $null -ne $pv.BackupDirectory) { $lapsEvidence += ("Windows LAPS policy BackupDirectory={0} ({1})" -f $pv.BackupDirectory, $pk) }
  }
  try {
    $stateKey = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State' -ErrorAction SilentlyContinue
    if ($stateKey -and @($stateKey.Property).Count -gt 0) { $lapsEvidence += ("Windows LAPS State has {0} value(s)" -f @($stateKey.Property).Count) }
  } catch { }
  if ($lapsEvidence.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Accounts' -Title 'LAPS (legacy or Windows LAPS) detected' -Detail ($lapsEvidence -join '; ')
  }
  elseif ($joined) {
    Add-Finding -Severity Medium -Category 'Accounts' -Title ("No LAPS management detected on a {0} host" -f $joinKind) `
      -Detail 'No LAPS policy BackupDirectory, no LAPS state and no legacy CSE. Shared or static local admin passwords enable Pass-the-Hash across the fleet.' `
      -Remediation 'Deploy Windows LAPS (Intune or GPO) to randomize the local admin password per host.'
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title 'LAPS not applicable (workgroup host)' `
      -Detail 'LAPS needs a directory (AD or Entra) to store the password; keep the local admin password unique to this host.'
  }
} catch { }

# Currently logged-on sessions (incident context)
try { $sessions = quser 2>$null; if ($sessions) { Add-Finding -Severity Info -Category 'Accounts' -Title 'Active sessions' -Detail (($sessions | Select-Object -Skip 1) -join ' | ') } } catch { }

# BitLocker (data-at-rest). Get-BitLockerVolume needs elevation; say so instead of
# "unavailable on this volume", which reads like a hardware limitation.
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker not assessed (needs elevation)' `
    -Detail 'Get-BitLockerVolume returns Access denied for a standard user; run elevated to check the system drive, fixed data volumes and protector types.'
}
else {
  try {
    $isLaptop = $false
    try { $isLaptop = @((Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop).ChassisTypes) | Where-Object { $_ -in 8, 9, 10, 14, 30, 31, 32 } | Select-Object -First 1 } catch { }
    $isLaptop = [bool]$isLaptop
    $vols = @(Get-BitLockerVolume -ErrorAction Stop)
    foreach ($bl in $vols) {
      if ("$($bl.VolumeType)" -notmatch 'OperatingSystem|Data') { continue }
      $isOs = ("$($bl.VolumeType)" -eq 'OperatingSystem')
      $protectors = @($bl.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
      $label = if ($isOs) { 'system drive' } else { 'fixed data volume' }
      if ($bl.ProtectionStatus -eq 'On' -or $bl.ProtectionStatus -eq 1) {
        $tpmOnly = ($protectors -contains 'Tpm') -and -not ($protectors | Where-Object { $_ -match 'TpmPin|TpmAndPin|TpmPinAndStartupKey|TpmAndPinAndStartupKey|Password' })
        if ($isOs -and $tpmOnly -and $isLaptop) {
          Add-Finding -Severity Low -Category 'Data' -Title ("BitLocker ON for {0} {1} with TPM-only protector on a portable device" -f $bl.MountPoint, $label) `
            -Detail ("Protectors: {0}; method {1}. TPM-only unlocks automatically at boot, so DMA and cold-boot attacks on a stolen laptop can recover the key." -f ($protectors -join ', '), $bl.EncryptionMethod) `
            -Remediation 'Add a PIN (TPM+PIN) for portable devices (CIS 18.10.9.1.x); keep the recovery key escrowed.'
        }
        else {
          Add-Finding -Severity Info -Category 'Data' -Title ("BitLocker protection ON for {0} ({1})" -f $bl.MountPoint, $label) `
            -Detail ("Protectors: {0}; method {1}" -f ($protectors -join ', '), $bl.EncryptionMethod)
        }
      }
      else {
        Add-Finding -Severity Medium -Category 'Data' -Title ("BitLocker not protecting {0} ({1})" -f $bl.MountPoint, $label) `
          -Detail ("ProtectionStatus={0}; VolumeStatus={1}" -f $bl.ProtectionStatus, $bl.VolumeStatus) `
          -Remediation 'Enable BitLocker (TPM+PIN for the OS drive, auto-unlock for data volumes); stolen disk = stolen data otherwise.'
      }
    }
    if ($vols.Count -eq 0) { Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker not assessed (no volumes returned)' }
  } catch {
    Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker not assessed' -Detail ('Get-BitLockerVolume failed: ' + $_.Exception.Message)
  }
}

# Screen lock policy (interactive attack surface). The machine inactivity limit is the HKLM
# policy value InactivityTimeoutSecs (CIS 2.3.7.3); the old check read it from HKCU
# Control Panel\Desktop, where it never exists. Per-user screensaver values are secondary.
try {
  $inact = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
  $desk = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
  $ssSecure = if ($desk) { $desk.ScreenSaverIsSecure } else { $null }
  $ssTimeout = if ($desk -and $desk.ScreenSaveTimeOut) { [int]$desk.ScreenSaveTimeOut } else { $null }
  $ssActive = if ($desk) { $desk.ScreenSaveActive } else { $null }
  $userLock = ($ssActive -eq 1 -and $ssSecure -eq 1 -and $null -ne $ssTimeout -and $ssTimeout -gt 0 -and $ssTimeout -le 900)
  if ($null -ne $inact -and [int]$inact -gt 0 -and [int]$inact -le 900) {
    Add-Finding -Severity Info -Category 'Data' -Title ("Machine inactivity lock enforced: {0}s" -f $inact) -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System::InactivityTimeoutSecs'
  }
  elseif ($userLock) {
    Add-Finding -Severity Low -Category 'Data' -Title 'No machine-wide inactivity lock; current user has a secure screensaver' `
      -Detail ("Policy InactivityTimeoutSecs={0}. HKCU ScreenSaverIsSecure=1, ScreenSaveTimeOut={1}s applies to this user only and can be changed by the user." -f $(if ($null -eq $inact) { 'absent' } else { $inact }), $ssTimeout) `
      -Remediation 'Set "Interactive logon: Machine inactivity limit" to 900 seconds or less (CIS 2.3.7.3).'
  }
  else {
    Add-Finding -Severity Low -Category 'Data' -Title ('No enforced inactivity lock (policy InactivityTimeoutSecs ' + $(if ($null -eq $inact) { 'absent' } elseif ([int]$inact -eq 0) { '0 = disabled' } else { "$inact s > 900" }) + ')') `
      -Detail ("Current user: ScreenSaveActive={0}, ScreenSaverIsSecure={1}, ScreenSaveTimeOut={2}. An unlocked, unattended console is a walk-up compromise." -f $ssActive, $ssSecure, $ssTimeout) `
      -Remediation 'Set "Interactive logon: Machine inactivity limit" to 900 seconds or less (CIS 2.3.7.3), and enforce a password-protected screensaver by policy.'
  }
} catch { }
