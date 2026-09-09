
######################## PREVIOUSLY-CONNECTED DEVICE HISTORY ########################
# Fully passive - reads local artifacts only. Shows every network the machine
# has EVER joined, every WiFi profile, cached DNS answers, RDP/SSH history,
# and static routes. This is the "previously talked to" record.

function ConvertFrom-NetworkListSystemTime($val) {
  # NetworkList DateCreated / DateLastConnected are REG_BINARY SYSTEMTIME (16 bytes,
  # little-endian WORDs: year, month, dayOfWeek, day, hour, minute, second, ms).
  if (-not $val) { return $null }
  try {
    $b = [byte[]]$val
    if ($b.Count -ne 16) { return $null }
    $yr = [BitConverter]::ToUInt16($b, 0)
    if ($yr -lt 1980 -or $yr -gt 2400) { return $null }
    return (Get-Date -Year $yr -Month ([BitConverter]::ToUInt16($b, 2)) -Day ([BitConverter]::ToUInt16($b, 6)) `
        -Hour ([BitConverter]::ToUInt16($b, 8)) -Minute ([BitConverter]::ToUInt16($b, 10)) -Second ([BitConverter]::ToUInt16($b, 12)) -ErrorAction Stop)
  } catch { return $null }
}

Start-Section 'CONNECTIVITY HISTORY (PREVIOUSLY CONNECTED / TALKED TO)'

# 1) Windows NetworkList: every network ever connected (wired + WiFi)
try {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed'
  )
  $nets = @()
  foreach ($p in ($paths | Where-Object { Test-Path $_ })) {
    Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      if (-not $props) { return }
      $name = $props.ProfileName
      if (-not $name) { $name = $props.Description }
      if (-not $name) { return }
      $first = ConvertFrom-NetworkListSystemTime $props.DateCreated
      $last = ConvertFrom-NetworkListSystemTime $props.DateLastConnected
      $nets += [pscustomobject]@{
        Name = $name; Type = $(if ($props.Category -eq 1) { 'Private' } elseif ($props.Category -eq 0) { 'Public' } else { 'Domain/Other' })
        FirstSeen = $first; LastConnected = $last; Path = $_.PSChildName
      }
    }
  }
  $dedup = $nets | Sort-Object Name -Unique
  $netListReadable = $true
  try {
    $null = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64').OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles')
  } catch { $netListReadable = $false }
  if (@($dedup).Count -eq 0 -and -not $netListReadable) {
    Add-Finding -Severity Info -Category 'History' -Title 'NetworkList history unreadable without elevation' `
      -Detail 'The NetworkList registry key requires admin. Run elevated to capture previously-connected network history.' `
      -Remediation 'Schedule WinHostPEAS elevated for full connectivity history.'
  }
  else {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} distinct networks previously connected (NetworkList)' -f @($dedup).Count) `
      -Detail (($dedup | Sort-Object LastConnected -Descending | Select-Object -First 25 | ForEach-Object {
          '{0} [{1}] last: {2:yyyy-MM-dd}' -f $_.Name, $_.Type, $_.LastConnected
        }) -join ' | ') `
      -Remediation 'Every network this image has EVER joined is recorded here - golden-image builds should be clean; a long history on a fleet image reveals where the machine has physically been.'
  }
  $public = @($dedup | Where-Object { $_.Type -eq 'Public' })
  if ($public.Count -gt 3) {
    Add-Finding -Severity Low -Category 'History' -Title ("{0} previously-joined networks marked Public" -f $public.Count) `
      -Detail 'Frequent public/hotspot joins on a BMS host indicate non-operational use.' `
      -Remediation 'Restrict which networks fleet hosts may join via GPO (Network List Manager + WLAN policy).'
  }
} catch { }

# 2) Saved WiFi profiles (SSIDs remembered, incl. hidden corporate SSIDs)
try {
  $wlanOutput = netsh wlan show profiles 2>$null
  $ssids = @($wlanOutput | Where-Object { $_ -match 'All User Profile\s*:\s*(.+)$' } | ForEach-Object { $Matches[1].Trim() })
  if ($ssids.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} saved WiFi profiles' -f $ssids.Count) `
      -Detail ($ssids -join ' | ') `
      -Remediation 'Saved profiles travel with the image; remove non-operational SSIDs before deployment (each is a location/oracle hint).'
  } else {
    Add-Finding -Severity Info -Category 'History' -Title 'No saved WiFi profiles (or no WLAN service)'
  }
} catch { }

# 3) DNS resolver cache - hosts recently resolved (who it has been talking to)
try {
  $dnsCache = @(Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Entry -notmatch '\.$' -or $_.Data })
  $entries = @($dnsCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 5 -or $_.Type -eq 28 } |
    Select-Object -ExpandProperty Entry -Unique)
  if ($entries.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} recently-resolved DNS names (resolver cache)' -f $entries.Count) `
      -Detail (($entries | Select-Object -First 40) -join ' | ') `
      -Remediation 'The resolver cache shows what this host has been communicating with in the last minutes-to-hours (A/CNAME/AAAA entries only).'
  } else {
    Add-Finding -Severity Info -Category 'History' -Title 'DNS resolver cache empty'
  }
} catch { }

# 4) RDP connection history (HKCU + all loaded HKU hives)
$rdpTargets = @()
New-PSDrive -PSProvider Registry -Name HKU2 -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
foreach ($hive in @('registry::HKEY_CURRENT_USER', 'registry::HKEY_USERS')) {
  if ($hive -eq 'registry::HKEY_USERS') {
    $sids = Get-ChildItem 'registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
    foreach ($s in $sids) {
      $serversKey = Get-Item "registry::$($s.Name)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
      if ($serversKey) {
        foreach ($sub in ($serversKey.GetSubKeyNames())) { $rdpTargets += "$sub (user $($s.PSChildName))" }
      }
    }
  } else {
    $serversKey = Get-Item "$hive\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
    if ($serversKey) {
      foreach ($sub in ($serversKey.GetSubKeyNames())) { $rdpTargets += "$sub (current user)" }
    }
  }
}
$rdpTargets = $rdpTargets | Sort-Object -Unique
if ($rdpTargets.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'History' -Title ('{0} RDP servers previously connected to' -f $rdpTargets.Count) `
    -Detail ($rdpTargets -join ' | ') `
    -Remediation 'RDP history is lateral-movement recon gold and reveals infrastructure targets; clear on fleet images and monitor on live hosts.'
} else {
  Add-Finding -Severity Info -Category 'History' -Title 'No RDP connection history'
}

# 5) PuTTY saved sessions / SSH known hosts
$puttySessions = @(Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions' -ErrorAction SilentlyContinue | ForEach-Object {
  $h = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).HostName
  if ($h) { $_.PSChildName + ' -> ' + $h }
})
$sshKnown = @()
foreach ($kh in @("$env:USERPROFILE\.ssh\known_hosts", "$env:USERPROFILE\.ssh\known_hosts.old")) {
  if (Test-Path $kh) {
    $lines = Get-Content $kh -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\S+' }
    foreach ($l in ($lines | Select-Object -First 50)) { $sshKnown += ($l -split '\s+')[0] }
  }
}
if ($puttySessions.Count -gt 0 -or $sshKnown.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'History' -Title 'SSH connection history present' `
    -Detail ("PuTTY sessions: {0} | known_hosts entries: {1}{2}" -f $puttySessions.Count, @($sshKnown | Sort-Object -Unique).Count,
      $(if ($sshKnown) { ' | ' + (($sshKnown | Sort-Object -Unique | Select-Object -First 20) -join ', ') })) `
    -Remediation 'SSH history maps management access paths; audit against authorized target lists.'
} else {
  Add-Finding -Severity Info -Category 'History' -Title 'No PuTTY sessions or SSH known_hosts'
}

# 6) Static/persistent routes (hardcoded paths to specific subnets)
try {
  $pers = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.Protocol -eq 'NetMgmt' -and $_.DestinationPrefix -notmatch '^(127\.|169\.254|224\.|255\.|0\.0\.0\.0/0|::/0|fe80)' })
  if ($pers.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} statically managed routes' -f $pers.Count) `
      -Detail (($pers | ForEach-Object { '{0} -> {1} (metric {2})' -f $_.DestinationPrefix, $_.NextHop, $_.RouteMetric } | Select-Object -First 15) -join ' | ') `
      -Remediation 'Persistent routes reveal hardcoded OT/management network paths; verify each against the network design.'
  }
} catch { }

# 7) Mapped network drives + recent UNC paths
$mapped = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.DisplayRoot -match '^\\\\' } | ForEach-Object { $_.Name + ' -> ' + $_.DisplayRoot })
$recentUnic = @()
foreach ($rk in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU')) {
  if (Test-Path $rk) {
    (Get-Item $rk -ErrorAction SilentlyContinue).Property | ForEach-Object {
      $v = (Get-ItemProperty $rk -Name $_ -ErrorAction SilentlyContinue).$_
      if ($v -match '^\\\\') { $recentUnic += $v }
    }
  }
}
if ($mapped.Count -gt 0 -or $recentUnic.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'History' -Title 'Network share connections (mapped/recent UNC)' `
    -Detail ("Mapped: {0} | Recent UNC: {1}" -f (($mapped | Select-Object -First 10) -join ', '), (($recentUnic | Sort-Object -Unique | Select-Object -First 10) -join ', ')) `
    -Remediation 'Share history shows file-transfer paths between hosts - include in the authorized-target baseline.'
} else {
  Add-Finding -Severity Info -Category 'History' -Title 'No mapped drives or recent UNC paths'
}

# 8) Firewall "allowed app" pairs that imply past comms config (subset, most recent)
try {
  $fwRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Group -eq '' } | Select-Object -First 15)
  if ($fwRules.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} custom inbound allow rules (ungrouped)' -f $fwRules.Count) `
      -Detail (($fwRules | ForEach-Object { $_.DisplayName } | Select-Object -First 15) -join ' | ') `
      -Remediation 'Custom firewall holes are configuration debt - each is an exposure someone requested; verify business need.'
  }
} catch { }
