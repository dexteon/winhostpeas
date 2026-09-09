
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
