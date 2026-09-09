
######################## SERVICE & VERSION INVENTORY ########################

Start-Section 'SERVICE INVENTORY (listening ports + banners)'

# Standard IT services
$portMap = @{
  21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';67='DHCP';69='TFTP';80='HTTP';110='POP3';
  123='NTP';135='MSRPC';139='NetBIOS';143='IMAP';389='LDAP';443='HTTPS';445='SMB';465='SMTPS';
  514='Syslog';587='SMTP';636='LDAPS';993='IMAPS';995='POP3S';1433='MSSQL';1521='Oracle';
  3000='Grafana';3306='MySQL';3389='RDP';4444='Metasploit-default';502='Modbus/TCP';
  4840='OPC-UA discovery';4843='OPC-UA (TLS)';47808='BACnet';44818='EtherNet/IP';
  20000='DNP3';2222='EthinCC/SSH-alt';5010='Niagara Fox';1911='Niagara Fox (alt)';
  4911='Niagara Fox (alt2)';9600='Omron FINS/TCP';96='CoDeSys';5900='VNC';5800='VNC-http';
  8080='HTTP-alt';8443='HTTPS-alt';8888='HTTP-alt2';10000='Webmin';41794='Crestron';
  41795='Crestron-secure';1313='BACnet-IP alt';137='NetBIOS-NS';5060='SIP';1719='H.323';
  1720='H.323-Q.931';49152='MSSQL-browser';1900='SSDP';5353='mDNS';3702='WS-Discovery'
}

$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
$remoteListen = @()
# Local listening services with owning process + version
foreach ($c in $listen) {
  if ($c.LocalAddress -match '^127\.|^::1') {
    continue   # counted in loopback section instead
  }
  $proc = $null
  try { $proc = Get-Process -Id $c.OwningProcess -ErrorAction Stop } catch { }
  $svc = $portMap[[int]$c.LocalPort]
  $name = if ($svc) { $svc } else { 'unknown' }
  $pv = ''
  if ($proc) { $pv = '{0} {1}' -f $proc.ProcessName, $proc.VersionInfo.FileVersion }
  $remoteListen += [pscustomobject]@{ Port = $c.LocalPort; Name = $name; Process = $pv; Addr = $c.LocalAddress }
}
$locGrouped = $remoteListen | Group-Object Port | Sort-Object { [int]$_.Name }
Add-Finding -Severity Info -Category 'Services' -Title ('{0} locally-listening TCP ports (non-loopback)' -f $locGrouped.Count) `
  -Detail (($locGrouped | ForEach-Object {
      $p = [int]$_.Name; $svc = $portMap[$p]
      '{0}{1} [{2}]' -f $p, $(if ($svc) { '(' + $svc + ')' } else { '' }), ($_.Group.Process | Select-Object -First 1)
    }) -join ' | ') `
  -Remediation 'Diff against the authorized service list per host role; close anything not required.'

# BMS/OT-protocol ports listening locally = controllers/jace/hmi software on THIS host
$otPorts = @(502, 4840, 4843, 47808, 44818, 20000, 5010, 1911, 4911, 9600, 41794, 41795, 137, 5353)
$localOt = @($remoteListen | Where-Object { $otPorts -contains [int]$_.Port })
if ($localOt.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'OT Services' -Title ('BMS/OT protocol listeners on this host: {0}' -f $localOt.Count) `
    -Detail (($localOt | ForEach-Object { '{0} ({1}) <- {2}' -f $_.Port, $_.Name, $_.Process }) -join ' | ') `
    -Remediation 'These are the crown jewels: enumerate owning software, version, and ensure zone firewall restricts who can reach them (IEC 62443 SR 5.1).'
}

# Installed BMS/OT vendor software on this host
$otVendors = [ordered]@{
  'Niagara' = 'Tridium Niagara (JACE/supervisor)'
  'Honeywell' = 'Honeywell EBI/WebStation'
  'Johnson Controls' = 'Johnson Controls Metasys'
  'Siemens' = 'Siemens Desigo/APOGEE'
  'Schneider' = 'Schneider EcoStruxure/TAC'
  'Trane' = 'Trane Tracer'
  'Carrier' = 'Carrier i-Vu'
  'Delta Controls' = 'Delta Controls enteliBUS'
  'Reliable Controls' = 'Reliable Controls RC-Studio'
  'Automated Logic' = 'Automated Logic WebCTRL'
  'Distech' = 'Distech Controls EC-BOS'
  'CoDeSys' = 'CoDeSys runtime (3S-Smartforce)'
  'KEPServer' = 'KEPServerEX (OPC)'
  'Matrikon' = 'MatrikonOPC'
  'Wonderware' = 'Wonderware/AVEVA'
  'Ignition' = 'Inductive Automation Ignition'
  'Advanced Serial Data Log' = 'ASDL BMS'
  'Viconics' = 'Viconics'
  'Novar' = 'Novar Opus'
}
$apps = @(Get-InstalledApplications)
foreach ($v in $otVendors.GetEnumerator()) {
  $hits = $apps | Where-Object { $_.Software -match [regex]::Escape($v.Key) }
  if ($hits) {
    foreach ($h in ($hits | Select-Object -First 3)) {
      Add-Finding -Severity Medium -Category 'BMS Software' -Title ('BMS vendor software: {0} {1}' -f $h.Software, $h.Version) `
        -Detail $v.Value `
        -Remediation 'Pin the version in the CMDB; subscribe to vendor security advisories (Niagara Fox/HTTPS vulns are common); patch in maintenance windows.'
    }
  }
}
