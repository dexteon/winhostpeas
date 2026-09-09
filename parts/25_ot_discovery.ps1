
######################## NETWORK: PASSIVE-ONLY DEVICE VISIBILITY ########################
# No packets are sent to other hosts. Reads local state only:
# ARP/neighbor cache on PHYSICAL adapters, and established connections.

Start-Section 'NETWORK VISIBILITY (PASSIVE ONLY - NO PACKETS SENT)'

$virtualIf = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
  $_.InterfaceDescription -match 'Virtual|Hyper-V|VMware|VirtualBox|WSL|Loopback|TAP|Tunnel|WireGuard|Bluestacks|Removable|Microsoft KM-TEST'
} | Select-Object -ExpandProperty ifIndex -ErrorAction SilentlyContinue

$neighbors = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object {
  $_.IPAddress -notmatch '^(127\.|::1|224\.|239\.|ff|169\.254|255\.)' -and
  $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
  ($virtualIf -notcontains $_.ifIndex)
})
$arpMap = @{}
foreach ($n in $neighbors) { $arpMap[$n.IPAddress] = $n.LinkLayerAddress }

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

Add-Finding -Severity Info -Category 'Discovery' -Title ('{0} devices in ARP/neighbor cache (passive read, physical adapters only)' -f $neighbors.Count) `
  -Detail (($neighbors | Sort-Object IPAddress | ForEach-Object {
      $v = Get-OuiVendor $_.LinkLayerAddress
      '{0} -> {1} ({2}){3}' -f $_.IPAddress, $_.LinkLayerAddress, $_.State, $(if ($v) { ' [' + $v + ']' })
    }) -join ' | ') `
  -Remediation 'Baseline this list; new MACs in the BMS zone = investigate (unauthorized device). Virtual adapters (WSL/VMware/Hyper-V) and APIPA/broadcast entries are excluded.'

foreach ($n in ($neighbors | Where-Object { $_.State -eq 'Reachable' -or $_.State -eq 'Stale' })) {
  $vendor = Get-OuiVendor $n.LinkLayerAddress
  if ($vendor -match 'VMware|VirtualBox|QEMU|Hyper-V|Raspberry Pi') {
    Add-Finding -Severity Medium -Category 'Discovery' -Title ("Virtualization MAC (${vendor}) seen nearby: {0}" -f $n.IPAddress) `
      -Detail ('MAC {0} - unmanaged VMs/SBCs in an OT zone sit outside the controlled build baseline.' -f $n.LinkLayerAddress) `
      -Remediation 'Confirm the device is authorized; remove or formally enroll it in the asset inventory.'
  }
}

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
