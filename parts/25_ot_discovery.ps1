
######################## NETWORK DISCOVERY: ARP, NEIGHBORS, DEVICES ########################
# OT-safe: ARP table + neighbor cache (passive), ICMP-only ping sweep of local
# subnets (no SYN/protocol probes at PLCs), MAC vendor OUI tagging (partial table).

Start-Section 'NETWORK DISCOVERY (ARP / NEIGHBOR TABLE)'

# Passive snapshot first
$neighbors = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object {
  $_.IPAddress -notmatch '^(127\.|::1|224\.|239\.|ff)' -and $_.LinkLayerAddress
})
$arpMap = @{}
foreach ($n in $neighbors) { $arpMap[$n.IPAddress] = $n.LinkLayerAddress }

# Partial OUI table - extend as needed for your fleet
$ouiMap = [ordered]@{
  '00-1B-1B' = 'Siemens AG';            '00-1D-9C' = 'Rockwell Automation'
  '00-00-0C' = 'Cisco';                  '00-50-56' = 'VMware'
  '00-15-5D' = 'Microsoft Hyper-V';      '08-00-27' = 'VirtualBox'
  '52-54-00' = 'QEMU/KVM';               'B8-27-EB' = 'Raspberry Pi'
  'DC-A6-32' = 'Raspberry Pi (newer)';   '00-0D-93' = 'Apple'
  '00-14-22' = 'Dell';                   '00-1A-A0' = 'Dell (newer)'
  '3C-D9-2B' = 'HPE';                    '00-1E-C9' = 'Dell iDRAC'
  '00-23-7D' = 'Digi International';     '00-40-9D' = 'Moog/Lambda'
  '00-80-D0' = 'Vermont Technologies';   '00-E0-4C' = 'Realtek'
  '00-1B-44' = 'SanDisk';                '00-04-A9' = 'Lantronix (device servers)'
}
function Get-OuiVendor([string]$Mac) {
  if (-not $Mac) { return '' }
  $prefix = ($Mac -replace '-', '-').ToUpper().Substring(0, 8)
  if ($ouiMap.Contains($prefix)) { return $ouiMap[$prefix] }
  return ''
}

Add-Finding -Severity Info -Category 'Discovery' -Title ('{0} live ARP/neighbor entries (passive)' -f $neighbors.Count) `
  -Detail (($neighbors | Sort-Object IPAddress | ForEach-Object { '{0} -> {1} ({2})' -f $_.IPAddress, $_.LinkLayerAddress, $_.State }) -join ' | ') `
  -Remediation 'Baseline this list; new MACs in the BMS zone = investigate (unauthorized device).'

# ICMP-only sweep of directly connected IPv4 subnets (skip loopback/APIPA)
$localIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
  $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown'
})
$swept = @{}
foreach ($ip in ($localIps | Select-Object -First 3)) {
  $mask = $ip.PrefixLength
  if ($mask -lt 8 -or $mask -gt 24) { continue }  # only sweep up to /24; wider = too slow/fragile
  $base = ($ip.IPAddress.Split('.')[0..2] -join '.')
  if ($swept.ContainsKey($base)) { continue }
  $swept[$base] = $true
  Write-Host "  ICMP sweep ${base}.0/24 (interface $($ip.InterfaceAlias))..." -ForegroundColor DarkGray
  $pings = @{}
  foreach ($i in 1..254) {
    $tgt = "$base.$i"
    try {
      $p = New-Object System.Net.NetworkInformation.Ping
      $pings[$tgt] = $p.SendPingAsync($tgt, 600)
    } catch { }
  }
  try { [void][System.Threading.Tasks.Task]::WaitAll(@($pings.Values), 8000) } catch { }
  $alive = @($pings.GetEnumerator() | Where-Object { $_.Value.Result.Status -eq 'Success' })
  # refresh neighbor cache after sweep
  Start-Sleep -Milliseconds 800
  $post = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress })
  $postMap = @{}
  foreach ($n in $post) { $postMap[$n.IPAddress] = $n.LinkLayerAddress }
  foreach ($a in $alive) {
    $addr = $a.Key
    $mac = if ($postMap[$addr]) { $postMap[$addr] } elseif ($arpMap[$addr]) { $arpMap[$addr] } else { '' }
    $macClean = ($mac -replace '-', '-')
    $vendor = Get-OuiVendor $macClean
    $rtt = [math]::Round($a.Value.RoundtripTime, 0)
    Add-Finding -Severity Info -Category 'Discovery' -Title ("Reachable device: {0}" -f $addr) `
      -Detail ("MAC: {0}{1} | ICMP RTT {2}ms (ICMP-only; no protocol probes sent - OT safe)" -f `
        $(if ($mac) { $mac } else { 'unknown' }), $(if ($vendor) { ' [' + $vendor + ']' } else { '' }), $rtt) `
      -Remediation 'Compare against the authorized device inventory for this zone (IEC 62443 SR 6.2 asset inventory).'
    if ($vendor -match 'VMware|VirtualBox|QEMU|Hyper-V|Raspberry Pi') {
      Add-Finding -Severity Medium -Category 'Discovery' -Title ("Virtualization MAC (${vendor}) in BMS subnet: {0}" -f $addr) `
        -Detail 'Unmanaged VMs/SBCs in an OT zone are outside the controlled build baseline.' `
        -Remediation 'Confirm the device is authorized; remove or formally enroll it in the asset inventory.'
    }
  }
}
if ($swept.Count -eq 0) {
  Add-Finding -Severity Info -Category 'Discovery' -Title 'No eligible /24-or-tighter IPv4 subnets to sweep (passive ARP data only)'
}

# Active conversations (who this host actually talks to) - exclude loopback
$convs = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
  $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|::$)'
})
$remotes = $convs | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 25
foreach ($r in $remotes) {
  $ports = ($r.Group | Select-Object -ExpandProperty RemotePort -Unique | Select-Object -First 6) -join ','
  $mac = $arpMap[$r.Name]; $vendor = Get-OuiVendor $mac
  Add-Finding -Severity Info -Category 'Discovery' -Title ("Active conversation: {0} ({1} conns)" -f $r.Name, $r.Count) `
    -Detail ("Remote ports: $ports$(if ($mac) { ' | MAC ' + $mac })$(if ($vendor) { ' [' + $vendor + ']' })")
}
