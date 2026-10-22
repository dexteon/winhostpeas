
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

# Credential Guard: running state from Win32_DeviceGuard (SecurityServicesRunning contains 1).
# LsaCfgFlags alone gives false negatives: CG is on by default on Win11 22H2+ Enterprise/
# Education with no registry value, the policy value lives under Policies\...\DeviceGuard,
# and "configured" is not "running".
try {
  $lsaCfg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
  $lsaCfgPol = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
  $cgDetail = ("Registry: Control\LSA LsaCfgFlags={0}; policy DeviceGuard LsaCfgFlags={1}" -f $(if ($null -eq $lsaCfg) { 'absent' } else { $lsaCfg }), $(if ($null -eq $lsaCfgPol) { 'absent' } else { $lsaCfgPol }))
  $dg = $null
  try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1 } catch { $dg = $null }
  if ($dg) {
    $cgRunning    = (@($dg.SecurityServicesRunning)    -contains 1)
    $cgConfigured = (@($dg.SecurityServicesConfigured) -contains 1)
    $vbsRunning   = ([int]$dg.VirtualizationBasedSecurityStatus -eq 2)
    $vbsCapable   = (@($dg.AvailableSecurityProperties) -contains 2)
    $osBuild = 0; try { $osBuild = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { }
    $cgDetail += ("; Win32_DeviceGuard: VBS status={0}, SecurityServicesConfigured={1}, SecurityServicesRunning={2}" -f $dg.VirtualizationBasedSecurityStatus, (@($dg.SecurityServicesConfigured) -join ','), (@($dg.SecurityServicesRunning) -join ','))
    if ($cgRunning) {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Guard RUNNING' -Detail $cgDetail
    }
    elseif ($cgConfigured) {
      Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard configured but NOT running' `
        -Detail ($cgDetail + '. Configured without running usually means a pending reboot, a missing VBS prerequisite (UEFI, Secure Boot, hypervisor), or the UEFI lock blocking a change.') `
        -Remediation 'Reboot and re-check; verify VBS prerequisites with msinfo32 (Virtualization-based security: Running).'
    }
    elseif ($vbsCapable -and $osBuild -ge 22000) {
      Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard not running (hardware capable)' `
        -Detail ($cgDetail + ("; VBS running={0}. LSASS secrets (NTLM hashes, Kerberos TGTs) are dumpable by any admin-level code." -f $vbsRunning)) `
        -Remediation 'Enable Credential Guard (GPO: Turn On Virtualization Based Security > Credential Guard configuration = Enabled with UEFI lock, or Intune/MDM). Requires VBS; on Pro it needs explicit enablement.'
    }
    else {
      Add-Finding -Severity Low -Category 'Credentials' -Title 'Credential Guard not running (platform not capable or pre-Win11 build)' `
        -Detail ($cgDetail + ("; VBS capable={0}, build={1}." -f $vbsCapable, $osBuild)) `
        -Remediation 'Credential Guard needs UEFI, Secure Boot, a hypervisor-capable CPU and a supported SKU; plan it into the next hardware/OS refresh.'
    }
  }
  else {
    if ($lsaCfg -eq 1 -or $lsaCfg -eq 2 -or $lsaCfgPol -eq 1 -or $lsaCfgPol -eq 2) {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Guard configured (running state not assessed: Win32_DeviceGuard unavailable)' -Detail $cgDetail
    }
    else {
      Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard not configured (running state not assessed: Win32_DeviceGuard unavailable)' `
        -Detail ($cgDetail + '. The DeviceGuard CIM namespace was not readable, so only the registry configuration is known.') `
        -Remediation 'Enable Credential Guard (hardware virtualization) to harden LSASS against dump-and-reuse.'
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Guard not assessed' -Detail ('Read failed: ' + $_.Exception.Message)
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
# OpenSSH agent keys registered. The key is ACLed to SYSTEM on current builds, so a read
# failure is reported as "not assessed", never as 0 keys.
if (Test-Path 'HKCU:\Software\OpenSSH\Agent\Keys') {
  try {
    $n = @((Get-Item 'HKCU:\Software\OpenSSH\Agent\Keys' -ErrorAction Stop).Property).Count
    if ($n -gt 0) {
      Add-Finding -Severity Medium -Category 'Credentials' -Title "$n SSH key(s) registered in ssh-agent" `
        -Remediation 'Verify these are authorized; ssh-agent keys are extractable by SYSTEM-level code.'
    }
    else {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'No SSH keys registered in ssh-agent'
    }
  } catch {
    Add-Finding -Severity Info -Category 'Credentials' -Title 'ssh-agent key store present but not readable (not assessed)' `
      -Detail ('HKCU:\Software\OpenSSH\Agent\Keys exists; read failed: ' + $_.Exception.Message + '. The key is SYSTEM-only by design; inspect with ssh-add -l as the user.')
  }
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
if ($env:LOCALAPPDATA -and (Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite")) {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'Sticky Notes database present' `
    -Detail 'Sticky Notes frequently contain passwords in plaintext (plum.sqlite).' `
    -Remediation 'Educate users; consider disabling Sticky Notes on sensitive hosts.'
}

# PowerShell history credential usage - REDACTED, current user only
# Get-PSReadLineOption throws when PSReadLine is not loaded (scheduled / -File runs), so fall
# back to the documented default history path instead of skipping the check.
$histPath = $null
try { $histPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath } catch { $histPath = $null }
if (-not $histPath) { $histPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' }
if ($histPath -and (Test-Path $histPath)) {
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
