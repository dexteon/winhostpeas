
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
