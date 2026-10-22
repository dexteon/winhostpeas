
######################## SECURITY FEATURES & DETECTION COVERAGE ########################
# Platform protections (VBS/HVCI, Secure Boot, driver blocklist), NTLM session
# security, the name-resolution poisoning trio (mDNS, WPAD; LLMNR and NBT-NS are
# in 23_network) and detection coverage (AV/EDR, MDE onboarding, Sysmon, log
# forwarding agents). Every read is local and passive: registry, CIM, the service
# table and event-log metadata. Nothing is written and nothing leaves the host.
# Credential Guard is deliberately NOT read here (21_creds owns it).

Start-Section 'SECURITY FEATURES & DETECTION COVERAGE'

# --- shared context for this section (each read guarded; a failure leaves the default) ---
$sfOs = $null
try { $sfOs = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$sfBuild = 0
if ($sfOs) { [void][int]::TryParse("$($sfOs.BuildNumber)", [ref]$sfBuild) }
# ProductType: 1 = workstation, 2 = domain controller, 3 = member server
$sfIsServer = [bool]($sfOs -and ($sfOs.ProductType -ne 1))
$sfDomainJoined = $false
try { $sfDomainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }

# One snapshot of the service table, keyed by lower-case service name.
$sfServices = @{}
$sfServiceNames = @()
try {
  foreach ($svc in @(Get-Service -ErrorAction Stop)) {
    $sfServices[$svc.Name.ToLowerInvariant()] = $svc
  }
  $sfServiceNames = @($sfServices.Keys)
} catch { }

function Get-SfService {
  # Exact (case-insensitive) match, or wildcard match when the pattern contains '*'.
  param([string]$Pattern)
  if ($Pattern -like '*[*]*') {
    foreach ($n in $sfServiceNames) { if ($n -like $Pattern.ToLowerInvariant()) { return $sfServices[$n] } }
    return $null
  }
  $k = $Pattern.ToLowerInvariant()
  if ($sfServices.ContainsKey($k)) { return $sfServices[$k] }
  return $null
}

# Shared flags consumed by the telemetry-gap roll-up at the end of the section.
$sfEdrRunning     = @()   # product names of EDR/AV agents whose service is Running
$sfEdrStopped     = @()   # installed but not running
$sfMdeOnboarded   = $false
$sfSysmonPresent  = $false
$sfAgentsRunning  = @()
$sfAgentsStopped  = @()
$sfWefConfigured  = $false
try { $sfWefConfigured = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' } catch { }

######## 1. Third-party AV / EDR presence (root\SecurityCenter2 + service table) ########
# Service names are the stable identifier across product versions; display names
# are localized and marketing-renamed. Wildcards cover version-suffixed names.
$sfEdrTable = @(
  @{ Name = 'Sense';                    Product = 'Microsoft Defender for Endpoint (Sense)'; Kind = 'EDR' },
  @{ Name = 'CSFalconService';          Product = 'CrowdStrike Falcon';                    Kind = 'EDR' },
  @{ Name = 'SentinelAgent';            Product = 'SentinelOne';                           Kind = 'EDR' },
  @{ Name = 'CbDefense';                Product = 'VMware Carbon Black Cloud';             Kind = 'EDR' },
  @{ Name = 'CarbonBlack';              Product = 'Carbon Black EDR (Response)';           Kind = 'EDR' },
  @{ Name = 'cyserver';                 Product = 'Palo Alto Cortex XDR';                  Kind = 'EDR' },
  @{ Name = 'CylanceSvc';               Product = 'BlackBerry Cylance';                    Kind = 'EDR' },
  @{ Name = 'ElasticEndpoint';          Product = 'Elastic Defend';                        Kind = 'EDR' },
  @{ Name = 'xagt';                     Product = 'Trellix (FireEye) Endpoint Security HX';Kind = 'EDR' },
  @{ Name = 'TaniumClient';             Product = 'Tanium';                                Kind = 'EDR' },
  @{ Name = 'CybereasonActiveProbe';    Product = 'Cybereason';                            Kind = 'EDR' },
  @{ Name = 'FortiEDR';                 Product = 'Fortinet FortiEDR';                     Kind = 'EDR' },
  @{ Name = 'HuntressAgent';            Product = 'Huntress';                              Kind = 'EDR' },
  @{ Name = 'ir_agent';                 Product = 'Rapid7 Insight Agent';                  Kind = 'EDR' },
  @{ Name = 'CiscoAMP*';                Product = 'Cisco Secure Endpoint (AMP)';           Kind = 'EDR' },
  @{ Name = 'SEDService';               Product = 'Sophos Endpoint Defense';               Kind = 'EDR' },
  @{ Name = 'Sophos MCS Agent';         Product = 'Sophos Central agent';                  Kind = 'EDR' },
  @{ Name = 'SepMasterService';         Product = 'Symantec Endpoint Protection';          Kind = 'AV' },
  @{ Name = 'masvc';                    Product = 'McAfee / Trellix Agent';                Kind = 'AV' },
  @{ Name = 'mfemms';                   Product = 'McAfee / Trellix ENS';                  Kind = 'AV' },
  @{ Name = 'ekrn';                     Product = 'ESET';                                  Kind = 'AV' },
  @{ Name = 'AVP*';                     Product = 'Kaspersky';                             Kind = 'AV' },
  @{ Name = 'klnagent';                 Product = 'Kaspersky Network Agent';               Kind = 'AV' },
  @{ Name = 'EPSecurityService';        Product = 'Bitdefender Endpoint Security';         Kind = 'AV' },
  @{ Name = 'ntrtscan';                 Product = 'Trend Micro Apex One / OfficeScan';     Kind = 'AV' },
  @{ Name = 'Amsp';                     Product = 'Trend Micro Anti-Malware Solution Platform'; Kind = 'AV' },
  @{ Name = 'MBAMService';              Product = 'Malwarebytes';                          Kind = 'AV' },
  @{ Name = 'WazuhSvc';                 Product = 'Wazuh agent';                           Kind = 'EDR' },
  @{ Name = 'OssecSvc';                 Product = 'OSSEC agent';                           Kind = 'EDR' }
)

try {
  $edrLines = @()
  foreach ($e in $sfEdrTable) {
    $svc = Get-SfService -Pattern $e.Name
    if (-not $svc) { continue }
    $line = ('{0} [{1}] service {2}: {3}' -f $e.Product, $e.Kind, $svc.Name, $svc.Status)
    $edrLines += $line
    if ("$($svc.Status)" -eq 'Running') {
      if ($e.Kind -eq 'EDR') { $sfEdrRunning += $e.Product }
    }
    else {
      if ($e.Kind -eq 'EDR') { $sfEdrStopped += $e.Product }
    }
  }

  # Defender's own running mode tells whether a third-party product is primary.
  $amMode = 'unknown'
  try {
    $mpStat = Get-MpComputerStatus -ErrorAction Stop
    if ($mpStat -and $mpStat.AMRunningMode) { $amMode = "$($mpStat.AMRunningMode)" }
  } catch { }

  if ($sfIsServer) {
    # root\SecurityCenter2 exists only on client SKUs (the Security Center service is
    # not part of Server), so AV presence is judged from Defender and the service table.
    $scDetail = 'root\SecurityCenter2 AntiVirusProduct is not available on Server SKUs. AV presence judged from Defender running mode and the EDR/AV service table.'
    $avSev = 'Info'
    if ($amMode -match 'Passive' -and $sfEdrRunning.Count -eq 0 -and $edrLines.Count -eq 0) { $avSev = 'High' }
    Add-Finding -Severity $avSev -Category 'Detection' `
      -Title $(if ($avSev -eq 'High') { 'Defender in passive mode with no other AV/EDR agent running (Server)' } else { 'AV / EDR presence (Server)' }) `
      -Detail ($scDetail + ' Defender AMRunningMode: ' + $amMode + '. T1562.001 (impair defenses).') `
      -Evidence $(if ($edrLines.Count) { $edrLines -join ' | ' } else { 'No third-party AV/EDR service from the known table is installed.' }) `
      -Remediation $(if ($avSev -eq 'High') { 'A passive-mode Defender with no primary product means no real-time prevention. Install and onboard an EDR, or return Defender to active mode.' } else { 'Confirm the listed product is the intended primary AV/EDR and that it is running.' })
  }
  else {
    $avProducts = @()
    $scReadable = $true
    try {
      $avProducts = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    }
    catch { $scReadable = $false }
    if (-not $scReadable) {
      Add-Finding -Severity Info -Category 'Detection' -Title 'Registered AV products not assessed' `
        -Detail 'root\SecurityCenter2 AntiVirusProduct could not be read on this workstation (Security Center service stopped or WMI namespace missing). Absence of data is not evidence of protection.' `
        -Evidence $(if ($edrLines.Count) { $edrLines -join ' | ' } else { 'No known AV/EDR service found in the service table.' }) `
        -Remediation 'Verify AV/EDR presence through the Windows Security app or the management console.'
    }
    else {
      # productState: bit 0x1000 = product enabled (real-time on); bit 0x10 = signatures out of date.
      $enabledCount = 0
      $avLines = @()
      foreach ($p in $avProducts) {
        $state = 0
        [void][int]::TryParse("$($p.productState)", [ref]$state)
        $isOn = (($state -band 0x1000) -ne 0)
        $stale = (($state -band 0x10) -ne 0)
        if ($isOn) { $enabledCount++ }
        $avLines += ('{0} (productState 0x{1:X}: {2}{3})' -f $p.displayName, $state, $(if ($isOn) { 'enabled' } else { 'DISABLED' }), $(if ($stale) { ', signatures out of date' } else { '' }))
      }
      $evid = (@($avLines) + @($edrLines)) -join ' | '
      if ($avProducts.Count -eq 0 -or $enabledCount -eq 0) {
        if ($sfEdrRunning.Count -gt 0) {
          Add-Finding -Severity Low -Category 'Detection' -Title 'No enabled AV product registered with Security Center, but an EDR agent is running' `
            -Detail ('Security Center lists {0} product(s), none enabled. Running EDR: {1}. Defender AMRunningMode: {2}. Confirm the EDR provides real-time prevention and not only telemetry.' -f $avProducts.Count, ($sfEdrRunning -join ', '), $amMode) `
            -Evidence $evid -Remediation 'Register or enable a real-time AV engine; EDR sensors that only record do not stop commodity malware.'
        }
        else {
          Add-Finding -Severity High -Category 'Detection' -Title 'No enabled antivirus product registered (no real-time protection)' `
            -Detail ('Security Center lists {0} product(s), none with the enabled bit (0x1000) set, and no known EDR service is running. Defender AMRunningMode: {1}. T1562.001.' -f $avProducts.Count, $amMode) `
            -Evidence $(if ($evid) { $evid } else { 'AntiVirusProduct returned no rows' }) `
            -Remediation 'Enable Microsoft Defender real-time protection or install the organisation standard AV/EDR and confirm it registers as enabled.'
        }
      }
      else {
        $title = ('{0} enabled AV product(s) registered' -f $enabledCount)
        if ($sfEdrRunning.Count -gt 0) { $title += (' plus EDR: ' + ($sfEdrRunning -join ', ')) }
        Add-Finding -Severity Info -Category 'Detection' -Title $title `
          -Detail ('Defender AMRunningMode: {0}. A third-party product in Security Center with Defender in Passive Mode means the third-party product is primary.' -f $amMode) `
          -Evidence $evid
      }
    }
  }

  if ($sfEdrStopped.Count -gt 0 -and $sfEdrRunning.Count -eq 0) {
    # Sense (MDE) ships on every Win10/11 image, stopped until onboarded; report that under MDE below.
    $stoppedNonSense = @($sfEdrStopped | Where-Object { $_ -notmatch 'Sense' })
    if ($stoppedNonSense.Count -gt 0) {
      Add-Finding -Severity Medium -Category 'Detection' -Title ('EDR agent installed but not running: ' + ($stoppedNonSense -join ', ')) `
        -Detail 'An installed sensor that is stopped records nothing and protects nothing. Stopped EDR services are a common sign of tampering (T1562.001) or a failed deployment.' `
        -Evidence ($edrLines -join ' | ') `
        -Remediation 'Start the service and confirm it stays running; investigate who stopped it and when.'
    }
  }
}
catch {
  Add-Finding -Severity Info -Category 'Detection' -Title 'AV / EDR presence not assessed' `
    -Detail ('Reading Security Center or the service table failed: ' + $_.Exception.Message)
}

######## 2. Microsoft Defender for Endpoint onboarding state ########
try {
  $mdeState = $null
  $mdeKey = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
  if (Test-Path $mdeKey) {
    $mdeProps = Get-ItemProperty $mdeKey -ErrorAction SilentlyContinue
    if ($mdeProps -and ($mdeProps.PSObject.Properties.Name -contains 'OnboardingState')) { $mdeState = $mdeProps.OnboardingState }
  }
  $senseSvc = Get-SfService -Pattern 'Sense'
  $senseText = if ($senseSvc) { ('Sense service: {0} ({1})' -f $senseSvc.Status, $senseSvc.StartType) } else { 'Sense service: not installed' }
  $mdeText = if ($null -eq $mdeState) { 'OnboardingState: absent' } else { ('OnboardingState: {0}' -f $mdeState) }

  if ($mdeState -eq 1) {
    $sfMdeOnboarded = $true
    if ($senseSvc -and "$($senseSvc.Status)" -eq 'Running') { $sfEdrRunning += 'Microsoft Defender for Endpoint (onboarded)' }
    Add-Finding -Severity $(if ($senseSvc -and "$($senseSvc.Status)" -eq 'Running') { 'Info' } else { 'Medium' }) -Category 'Detection' `
      -Title $(if ($senseSvc -and "$($senseSvc.Status)" -eq 'Running') { 'Microsoft Defender for Endpoint onboarded and running' } else { 'Microsoft Defender for Endpoint onboarded but the Sense service is not running' }) `
      -Detail ($mdeText + '; ' + $senseText) `
      -Evidence $mdeKey `
      -Remediation $(if ($senseSvc -and "$($senseSvc.Status)" -eq 'Running') { 'None.' } else { 'Start the Sense service and check the MDE portal for sensor health; a stopped sensor on an onboarded host is a tamper indicator (T1562.001).' })
  }
  else {
    $otherEdr = @($sfEdrRunning | Where-Object { $_ -notmatch 'Defender for Endpoint' })
    if ($otherEdr.Count -gt 0) {
      Add-Finding -Severity Info -Category 'Detection' -Title 'Microsoft Defender for Endpoint not onboarded (another EDR is running)' `
        -Detail ($mdeText + '; ' + $senseText + '. Running EDR: ' + ($otherEdr -join ', ') + '.') -Evidence $mdeKey
    }
    elseif ($senseSvc) {
      Add-Finding -Severity Low -Category 'Detection' -Title 'Microsoft Defender for Endpoint sensor present but not onboarded' `
        -Detail ($mdeText + '; ' + $senseText + '. The Sense sensor ships with Windows but records nothing until onboarded. No other EDR agent was found running, so this host has no endpoint detection and response coverage. T1562.001 visibility gap.') `
        -Evidence $mdeKey `
        -Remediation 'Onboard the host to Defender for Endpoint (or deploy the organisation EDR); OnboardingState becomes 1 and Sense starts automatically.'
    }
    else {
      Add-Finding -Severity Info -Category 'Detection' -Title 'Microsoft Defender for Endpoint not present' `
        -Detail ($mdeText + '; ' + $senseText) -Evidence $mdeKey
    }
  }
}
catch {
  Add-Finding -Severity Info -Category 'Detection' -Title 'Defender for Endpoint onboarding not assessed' `
    -Detail ('Reading the ATP Status key or the Sense service failed: ' + $_.Exception.Message)
}

######## 3. VBS and HVCI (Memory Integrity) running state ########
# Win32_DeviceGuard: VirtualizationBasedSecurityStatus 0 = off, 1 = enabled not
# running, 2 = running. SecurityServicesRunning 1 = Credential Guard (owned by
# 21_creds, not repeated here), 2 = HVCI. AvailableSecurityProperties contains 1
# when the hardware offers base virtualization support (VBS-capable).
try {
  $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
  if (-not $dg) { throw 'Win32_DeviceGuard returned no instance' }
  $vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
  $running   = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
  $configured = @($dg.SecurityServicesConfigured | ForEach-Object { [int]$_ })
  $avail     = @($dg.AvailableSecurityProperties | ForEach-Object { [int]$_ })
  $hvciRunning = ($running -contains 2)
  $hvciConfigured = ($configured -contains 2)
  $vbsCapable = ($avail -contains 1)
  $hvciReg = $null
  try {
    $hvciKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
    if ($hvciKey -and ($hvciKey.PSObject.Properties.Name -contains 'Enabled')) { $hvciReg = $hvciKey.Enabled }
  } catch { }
  $vbsWord = @{ 0 = 'not enabled'; 1 = 'enabled but not running'; 2 = 'running' }[$vbsStatus]
  if (-not $vbsWord) { $vbsWord = ('status ' + $vbsStatus) }
  $dgEvidence = ('VirtualizationBasedSecurityStatus={0}; SecurityServicesRunning={1}; SecurityServicesConfigured={2}; AvailableSecurityProperties={3}; HVCI registry Enabled={4}' -f `
    $vbsStatus, $(if ($running.Count) { $running -join ',' } else { 'none' }), $(if ($configured.Count) { $configured -join ',' } else { 'none' }), $(if ($avail.Count) { $avail -join ',' } else { 'none' }), $(if ($null -eq $hvciReg) { 'absent' } else { $hvciReg }))

  if ($vbsStatus -eq 2 -and $hvciRunning) {
    Add-Finding -Severity Info -Category 'Platform Security' -Title 'VBS running with HVCI (Memory Integrity) enforced' `
      -Detail 'Kernel code integrity is enforced from the hypervisor, which blocks unsigned kernel code and most BYOVD exploit chains (T1068, T1014). Microsoft security baseline item.' `
      -Evidence $dgEvidence
  }
  elseif (-not $vbsCapable) {
    Add-Finding -Severity Info -Category 'Platform Security' -Title ('VBS ' + $vbsWord + '; hardware not VBS-capable') `
      -Detail 'AvailableSecurityProperties lacks base virtualization support (1), so VBS and HVCI cannot be enabled on this hardware or VM configuration. Not a configuration fault, but the host has no hypervisor-enforced kernel protection (T1068, T1014).' `
      -Evidence $dgEvidence `
      -Remediation 'For VMs, enable nested virtualization / vTPM and Secure Boot in the hypervisor; for physical hosts, enable VT-x/AMD-V and IOMMU in firmware.'
  }
  else {
    $sev = if ($sfBuild -ge 22000) { 'Medium' } else { 'Low' }
    $why = if ($vbsStatus -ne 2) { 'VBS is ' + $vbsWord } else { 'VBS is running but HVCI is ' + $(if ($hvciConfigured -or $hvciReg -eq 1) { 'configured and not running (reboot pending, or blocked by an incompatible driver)' } else { 'not configured' }) }
    Add-Finding -Severity $sev -Category 'Platform Security' -Title ('HVCI (Memory Integrity) not running: ' + $why) `
      -Detail ('The hardware is VBS-capable but kernel code integrity is not hypervisor-enforced, so a vulnerable or unsigned driver can be loaded to disable security tooling (BYOVD, T1068, T1014, T1562.001). Microsoft baseline and Windows 11 default expect it on. Build {0}.' -f $sfBuild) `
      -Evidence $dgEvidence `
      -Remediation 'Windows Security > Device security > Core isolation > Memory integrity ON (policy: DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity Enabled=1, or the Enable virtualization based security GPO). Resolve any driver the UI reports as incompatible first.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'Platform Security' -Title 'VBS / HVCI state not assessed' `
    -Detail ('Win32_DeviceGuard (root\Microsoft\Windows\DeviceGuard) could not be read: ' + $_.Exception.Message + '. Older OS builds lack the class; absence of data is not confirmation of protection.')
}

######## 4. Secure Boot ########
# UEFISecureBootEnabled under SecureBoot\State is readable without elevation
# (Confirm-SecureBootUEFI needs admin). Firmware type: $env:firmware_type is set by
# the OS to UEFI or Legacy; PEFirmwareType (1 = BIOS, 2 = UEFI) is the registry
# mirror where it exists; the SecureBoot\State key itself exists only under UEFI.
try {
  $fwType = 'unknown'
  if ($env:firmware_type) { $fwType = "$($env:firmware_type)" }
  else {
    $ctl = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction SilentlyContinue
    if ($ctl -and ($ctl.PSObject.Properties.Name -contains 'PEFirmwareType')) {
      $fwType = @{ 1 = 'Legacy'; 2 = 'UEFI' }[[int]$ctl.PEFirmwareType]
      if (-not $fwType) { $fwType = 'unknown' }
    }
    elseif (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') { $fwType = 'UEFI' }
  }
  $sbVal = $null
  $sbKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
  if (Test-Path $sbKey) {
    $sb = Get-ItemProperty $sbKey -ErrorAction SilentlyContinue
    if ($sb -and ($sb.PSObject.Properties.Name -contains 'UEFISecureBootEnabled')) { $sbVal = [int]$sb.UEFISecureBootEnabled }
  }
  $sbEvidence = ('firmware type: {0}; UEFISecureBootEnabled: {1}' -f $fwType, $(if ($null -eq $sbVal) { 'absent' } else { $sbVal }))
  if ($sbVal -eq 1) {
    Add-Finding -Severity Info -Category 'Platform Security' -Title 'Secure Boot enabled' `
      -Detail 'Boot chain is signature-verified; bootkits and unsigned boot drivers are blocked (T1542.001, T1553.006). CIS / Microsoft baseline item.' -Evidence $sbEvidence
  }
  elseif ($fwType -match 'Legacy|BIOS') {
    Add-Finding -Severity Medium -Category 'Platform Security' -Title 'Legacy BIOS boot: Secure Boot impossible' `
      -Detail 'The host boots in legacy BIOS/CSM mode, so Secure Boot, and with it VBS, HVCI and Credential Guard, cannot be used. Bootkit persistence (T1542.001) is unchecked.' `
      -Evidence $sbEvidence `
      -Remediation 'Convert the disk to GPT (mbr2gpt) and switch firmware to UEFI with Secure Boot on; this is a golden-image decision.'
  }
  elseif ($sbVal -eq 0) {
    Add-Finding -Severity High -Category 'Platform Security' -Title 'Secure Boot disabled on a UEFI host' `
      -Detail 'UEFI firmware with Secure Boot off accepts unsigned boot loaders and drivers, the entry point for bootkits and for disabling security tooling before the OS starts (T1542.001, T1553.006). Fails CIS and the Microsoft security baseline.' `
      -Evidence $sbEvidence `
      -Remediation 'Enable Secure Boot in firmware setup (Microsoft UEFI CA mode). Check whether it was turned off deliberately for an unsigned driver or a dual-boot setup.'
  }
  else {
    Add-Finding -Severity Info -Category 'Platform Security' -Title 'Secure Boot state not assessed' `
      -Detail 'UEFISecureBootEnabled is absent and the firmware type could not be determined (common inside some VMs). Not confirmed on.' -Evidence $sbEvidence `
      -Remediation 'Run Confirm-SecureBootUEFI from an elevated prompt.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'Platform Security' -Title 'Secure Boot state not assessed' `
    -Detail ('Reading SecureBoot\State failed: ' + $_.Exception.Message)
}

######## 5. Microsoft vulnerable driver blocklist ########
# HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config VulnerableDriverBlocklistEnable.
# On Windows 11 22H2 (build 22621) and later the blocklist is on by default when
# the value is absent; on earlier builds absence means off unless HVCI or Smart
# App Control enforces it.
try {
  $ciVal = $null
  $ciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
  if (Test-Path $ciKey) {
    $ci = Get-ItemProperty $ciKey -ErrorAction SilentlyContinue
    if ($ci -and ($ci.PSObject.Properties.Name -contains 'VulnerableDriverBlocklistEnable')) { $ciVal = [int]$ci.VulnerableDriverBlocklistEnable }
  }
  $ciEvidence = ('{0} VulnerableDriverBlocklistEnable={1}; build {2}' -f $ciKey, $(if ($null -eq $ciVal) { 'absent' } else { $ciVal }), $sfBuild)
  $blockRem = 'Windows Security > Device security > Core isolation > Microsoft Vulnerable Driver Blocklist ON (VulnerableDriverBlocklistEnable=1), or enable HVCI which enforces the blocklist.'
  if ($ciVal -eq 1) {
    Add-Finding -Severity Info -Category 'Platform Security' -Title 'Microsoft vulnerable driver blocklist enabled' `
      -Detail 'Known-vulnerable signed drivers (the BYOVD set used to kill EDR, T1068, T1562.001) are refused at load.' -Evidence $ciEvidence
  }
  elseif ($ciVal -eq 0) {
    Add-Finding -Severity Medium -Category 'Platform Security' -Title 'Microsoft vulnerable driver blocklist explicitly disabled' `
      -Detail 'VulnerableDriverBlocklistEnable=0 lets signed-but-vulnerable drivers load. Bring-your-own-vulnerable-driver is the standard way ransomware operators disable EDR (T1068, T1562.001).' `
      -Evidence $ciEvidence -Remediation $blockRem
  }
  elseif ($sfBuild -ge 22621) {
    Add-Finding -Severity Info -Category 'Platform Security' -Title 'Microsoft vulnerable driver blocklist on by default (value absent)' `
      -Detail 'Windows 11 22H2 and later enable the blocklist when VulnerableDriverBlocklistEnable is absent.' -Evidence $ciEvidence
  }
  else {
    Add-Finding -Severity Medium -Category 'Platform Security' -Title 'Microsoft vulnerable driver blocklist not enabled' `
      -Detail ('On builds before 22621 the blocklist is off unless the value is set to 1 or HVCI enforces it. BYOVD EDR-kill drivers load freely (T1068, T1562.001).') `
      -Evidence $ciEvidence -Remediation $blockRem
  }
}
catch {
  Add-Finding -Severity Info -Category 'Platform Security' -Title 'Vulnerable driver blocklist not assessed' `
    -Detail ('Reading CI\Config failed: ' + $_.Exception.Message)
}

######## 6. NTLM session security minimums (CIS 2.3.11.9 / 2.3.11.10) ########
# NTLMMinClientSec / NTLMMinServerSec must contain 0x20000000 (NTLMv2 session
# security) and 0x00080000 (128-bit encryption): 0x20080000 = 537395200.
try {
  $msv = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction Stop
  $minClient = $null; $minServer = $null
  if ($msv.PSObject.Properties.Name -contains 'NtlmMinClientSec') { $minClient = [int64]$msv.NtlmMinClientSec }
  if ($msv.PSObject.Properties.Name -contains 'NtlmMinServerSec') { $minServer = [int64]$msv.NtlmMinServerSec }
  $need = [int64]0x20080000
  $fmt = { param($v) if ($null -eq $v) { 'absent' } else { '0x{0:X8}' -f $v } }
  $clientOk = ($null -ne $minClient) -and (($minClient -band $need) -eq $need)
  $serverOk = ($null -ne $minServer) -and (($minServer -band $need) -eq $need)
  $ntlmEvidence = ('NTLMMinClientSec={0}; NTLMMinServerSec={1}; required 0x20080000 (NTLMv2 session security + 128-bit)' -f (& $fmt $minClient), (& $fmt $minServer))
  if ($clientOk -and $serverOk) {
    Add-Finding -Severity Info -Category 'NTLM' -Title 'NTLM session security requires NTLMv2 and 128-bit encryption (client and server)' `
      -Detail 'CIS 2.3.11.9 and 2.3.11.10 satisfied.' -Evidence $ntlmEvidence
  }
  else {
    $missing = @()
    foreach ($pair in @(@('client', $minClient), @('server', $minServer))) {
      $v = $pair[1]
      $m = @()
      if ($null -eq $v -or (($v -band 0x20000000) -eq 0)) { $m += 'NTLMv2 session security' }
      if ($null -eq $v -or (($v -band 0x00080000) -eq 0)) { $m += '128-bit encryption' }
      if ($m.Count) { $missing += ('{0} lacks {1}' -f $pair[0], ($m -join ' and ')) }
    }
    Add-Finding -Severity Medium -Category 'NTLM' -Title 'NTLM session security below CIS minimum' `
      -Detail ('{0}. Without both bits, NTLM sessions can be negotiated down to weaker session security, which eases relay and offline cracking (T1557.001, T1550.002). CIS 2.3.11.9 / 2.3.11.10 want 0x20080000 on both.' -f ($missing -join '; ')) `
      -Evidence $ntlmEvidence `
      -Remediation 'GPO: Network security: Minimum session security for NTLM SSP based clients and servers = Require NTLMv2 session security + Require 128-bit encryption (NTLMMinClientSec and NTLMMinServerSec = 537395200).'
  }
}
catch {
  Add-Finding -Severity Info -Category 'NTLM' -Title 'NTLM session security minimums not assessed' `
    -Detail ('Reading Lsa\MSV1_0 failed: ' + $_.Exception.Message)
}

######## 7. NTLM traffic restrictions and auditing ########
# RestrictSendingNTLMTraffic: 0 allow all, 1 audit, 2 deny all.
# RestrictReceivingNTLMTraffic: 0 allow all, 1 deny domain accounts, 2 deny all.
# AuditReceivingNTLMTraffic: 0 off, 1 domain accounts, 2 all accounts.
# LmCompatibilityLevel is evaluated in 24_ad_software; shown here as context only.
try {
  $msv2 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction Stop
  $lsa2 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  $getv = { param($o, $n) if ($o -and ($o.PSObject.Properties.Name -contains $n)) { [int]$o.$n } else { $null } }
  $rSend = & $getv $msv2 'RestrictSendingNTLMTraffic'
  $rRecv = & $getv $msv2 'RestrictReceivingNTLMTraffic'
  $aRecv = & $getv $msv2 'AuditReceivingNTLMTraffic'
  $lmLvl = & $getv $lsa2 'LmCompatibilityLevel'
  $sendWord = @{ 0 = 'allow all'; 1 = 'audit all'; 2 = 'deny all' }
  $recvWord = @{ 0 = 'allow all'; 1 = 'deny domain accounts'; 2 = 'deny all accounts' }
  $audWord  = @{ 0 = 'disabled'; 1 = 'audit domain accounts'; 2 = 'audit all accounts' }
  $w = { param($tbl, $v) if ($null -eq $v) { 'absent (default: allow, no audit)' } elseif ($tbl.ContainsKey($v)) { ('{0} ({1})' -f $v, $tbl[$v]) } else { "$v" } }
  $restrictEvidence = ('RestrictSendingNTLMTraffic={0}; RestrictReceivingNTLMTraffic={1}; AuditReceivingNTLMTraffic={2}; LmCompatibilityLevel={3}' -f `
    (& $w $sendWord $rSend), (& $w $recvWord $rRecv), (& $w $audWord $aRecv), $(if ($null -eq $lmLvl) { 'absent (OS default 3: send NTLMv2 only)' } else { $lmLvl }))
  $anySet = ($rSend -gt 0) -or ($rRecv -gt 0) -or ($aRecv -gt 0)
  if ($anySet) {
    Add-Finding -Severity Info -Category 'NTLM' -Title 'NTLM traffic restriction or auditing configured' `
      -Detail 'Restrict/Audit NTLM policies are set (CIS 2.3.11.x L2). Audit mode produces event IDs 8001 to 8004 in Microsoft-Windows-NTLM/Operational.' -Evidence $restrictEvidence
  }
  else {
    $sev = if ($sfDomainJoined) { 'Low' } else { 'Info' }
    Add-Finding -Severity $sev -Category 'NTLM' -Title 'NTLM use neither restricted nor audited' `
      -Detail ('Outgoing and incoming NTLM are allowed to any host with no audit trail, so NTLM relay and pass-the-hash (T1557.001, T1550.002) leave no NTLM-specific record and a move to Kerberos-only cannot be planned.{0}' -f $(if ($sfDomainJoined) { '' } else { ' Expected on a workgroup host; recorded for baseline.' })) `
      -Evidence $restrictEvidence `
      -Remediation 'Start with audit: Network security: Restrict NTLM: Audit incoming NTLM traffic = Enable auditing for all accounts, and Outgoing NTLM traffic to remote servers = Audit all; then restrict once the 8004 events show no legitimate NTLM use.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'NTLM' -Title 'NTLM restriction policy not assessed' `
    -Detail ('Reading Lsa\MSV1_0 failed: ' + $_.Exception.Message)
}

######## 8. mDNS (multicast DNS) ########
# Responder poisons mDNS exactly like LLMNR. Dnscache\Parameters EnableMDNS=0 or
# the policy DNSClient EnableMDNS=0 turns it off; absent means on.
try {
  $mdnsSvc = $null; $mdnsPol = $null
  $dnsp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue
  if ($dnsp -and ($dnsp.PSObject.Properties.Name -contains 'EnableMDNS')) { $mdnsSvc = [int]$dnsp.EnableMDNS }
  $dnspol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
  if ($dnspol -and ($dnspol.PSObject.Properties.Name -contains 'EnableMDNS')) { $mdnsPol = [int]$dnspol.EnableMDNS }
  $mdnsEvidence = ('Dnscache\Parameters EnableMDNS={0}; Policies DNSClient EnableMDNS={1}' -f $(if ($null -eq $mdnsSvc) { 'absent' } else { $mdnsSvc }), $(if ($null -eq $mdnsPol) { 'absent' } else { $mdnsPol }))
  if ($mdnsSvc -eq 0 -or $mdnsPol -eq 0) {
    Add-Finding -Severity Info -Category 'Network' -Title 'mDNS disabled' -Detail 'Multicast DNS is off; one of the three poisonable name-resolution protocols is closed.' -Evidence $mdnsEvidence
  }
  else {
    Add-Finding -Severity Medium -Category 'Network' -Title 'mDNS enabled (poisonable name resolution)' `
      -Detail 'Windows answers and issues multicast DNS queries on UDP 5353. Anyone on the segment can answer a failed lookup and capture NTLM hashes or relay them (T1557.001), the same chain as LLMNR and NBT-NS, which 23_network reports separately.' `
      -Evidence $mdnsEvidence `
      -Remediation 'Set HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters EnableMDNS=0 (DWORD), or the DNS Client policy Turn off multicast DNS on supported builds; disable LLMNR and NBT-NS at the same time.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'Network' -Title 'mDNS state not assessed' -Detail ('Reading Dnscache parameters failed: ' + $_.Exception.Message)
}

######## 9. WPAD proxy auto-discovery ########
# Exploitable default: WinHttpAutoProxySvc running and neither DisableWpad=1
# (Internet Settings\WinHttp) nor WpadOverride=1 (WinHttpAutoProxySvc\Parameters).
# The full Responder chain needs a poisonable resolver too, so severity rises when
# LLMNR or NBT-NS is also on (both read again here, cheaply; 23_network reports them).
try {
  $wpadSvc = Get-SfService -Pattern 'WinHttpAutoProxySvc'
  $wpadRunning = [bool]($wpadSvc -and "$($wpadSvc.Status)" -eq 'Running')
  $disableWpad = $null; $wpadOverride = $null
  $wh = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue
  if ($wh -and ($wh.PSObject.Properties.Name -contains 'DisableWpad')) { $disableWpad = [int]$wh.DisableWpad }
  $wp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc\Parameters' -ErrorAction SilentlyContinue
  if ($wp -and ($wp.PSObject.Properties.Name -contains 'WpadOverride')) { $wpadOverride = [int]$wp.WpadOverride }
  $wpadOff = ($disableWpad -eq 1) -or ($wpadOverride -eq 1)

  $llmnrOn = $true
  try {
    $mc = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
    if ($mc -and ($mc.PSObject.Properties.Name -contains 'EnableMulticast') -and ([int]$mc.EnableMulticast -eq 0)) { $llmnrOn = $false }
  } catch { }
  $nbtOn = $false
  try {
    foreach ($nk in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
      $no = (Get-ItemProperty $nk.PSPath -ErrorAction SilentlyContinue).NetbiosOptions
      if ($no -ne 2) { $nbtOn = $true }
    }
  } catch { }
  $wpadEvidence = ('WinHttpAutoProxySvc: {0}; DisableWpad={1}; WpadOverride={2}; LLMNR {3}; NBT-NS {4}' -f `
    $(if ($wpadSvc) { "$($wpadSvc.Status)" } else { 'not installed' }), $(if ($null -eq $disableWpad) { 'absent' } else { $disableWpad }), $(if ($null -eq $wpadOverride) { 'absent' } else { $wpadOverride }), $(if ($llmnrOn) { 'on' } else { 'off' }), $(if ($nbtOn) { 'on' } else { 'off' }))

  if ($wpadOff -or -not $wpadRunning) {
    Add-Finding -Severity Info -Category 'Network' -Title 'WPAD proxy auto-discovery disabled' `
      -Detail $(if ($wpadOff) { 'WPAD is turned off by registry policy.' } else { 'The WinHTTP Web Proxy Auto-Discovery service is not running.' }) -Evidence $wpadEvidence
  }
  else {
    $sev = if ($llmnrOn -or $nbtOn) { 'Medium' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'Network' -Title $(if ($sev -eq 'Medium') { 'WPAD active with a poisonable resolver (Responder WPAD chain open)' } else { 'WPAD proxy auto-discovery active (default)' }) `
      -Detail ('Windows looks for a proxy script at http://wpad/wpad.dat at logon and on each network change. {0} T1557.001; also abused for credential prompts through a rogue proxy (T1557).' -f $(if ($sev -eq 'Medium') { 'With LLMNR or NBT-NS still on, an attacker on the segment answers the "wpad" lookup, serves a PAC file and proxies or captures authentication.' } else { 'LLMNR and NBT-NS are off, so the remaining risk is a rogue DHCP option 252 or DNS entry named wpad.' })) `
      -Evidence $wpadEvidence `
      -Remediation 'Set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp DisableWpad=1 (and WpadOverride=1 under Services\WinHttpAutoProxySvc\Parameters, which also lets the service be stopped), or register a static "wpad" DNS record you control. Keep LLMNR and NBT-NS off.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'Network' -Title 'WPAD state not assessed' -Detail ('Reading the WinHttp proxy settings failed: ' + $_.Exception.Message)
}

######## 10. Sysmon presence ########
# The Sysmon service and driver names are user-chosen at install, so the stable
# signal is the minifilter altitude 385201 under Services\*\Instances\*. The
# altitude must match exactly (385200 is Process Monitor). Rules are reported by
# byte length only.
try {
  $sysmonDrv = $null; $sysmonAlt = $null
  foreach ($s in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue)) {
    $instPath = Join-Path $s.PSPath 'Instances'
    if (-not (Test-Path $instPath)) { continue }
    foreach ($inst in @(Get-ChildItem $instPath -ErrorAction SilentlyContinue)) {
      $alt = (Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue).Altitude
      if ("$alt".Trim() -eq '385201') { $sysmonDrv = $s.PSChildName; $sysmonAlt = "$alt"; break }
    }
    if ($sysmonDrv) { break }
  }
  if (-not $sysmonDrv) {
    foreach ($cand in @('SysmonDrv', 'Sysmon', 'Sysmon64')) {
      if (Get-SfService -Pattern $cand) { $sysmonDrv = $cand; break }
    }
  }
  $sysmonLog = $null
  try { $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop } catch { }

  if ($sysmonDrv) {
    $sfSysmonPresent = $true
    $rulesLen = 'not readable'
    try {
      $prm = Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $sysmonDrv + '\Parameters') -ErrorAction SilentlyContinue
      if ($prm -and ($prm.PSObject.Properties.Name -contains 'Rules')) { $rulesLen = ('{0} bytes' -f @($prm.Rules).Count) } else { $rulesLen = 'absent (default config)' }
    } catch { }
    $logText = if ($sysmonLog) { ('log enabled={0}, {1} records, max {2} MB' -f $sysmonLog.IsEnabled, $sysmonLog.RecordCount, [math]::Round($sysmonLog.MaximumSizeInBytes / 1MB, 0)) } else { 'Sysmon/Operational log not found' }
    $sev = if ($sysmonLog -and $sysmonLog.IsEnabled) { 'Info' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'Detection' -Title $(if ($sev -eq 'Info') { 'Sysmon installed' } else { 'Sysmon installed but its event log is missing or disabled' }) `
      -Detail ('Driver {0} (altitude {1}); rules blob {2}; {3}.' -f $sysmonDrv, $(if ($sysmonAlt) { $sysmonAlt } else { 'matched by service name' }), $rulesLen, $logText) `
      -Evidence ('HKLM\SYSTEM\CurrentControlSet\Services\' + $sysmonDrv) `
      -Remediation $(if ($sev -eq 'Info') { 'Confirm the rules blob matches the deployed configuration and that the Sysmon log is forwarded.' } else { 'Re-enable Microsoft-Windows-Sysmon/Operational; a disabled Sysmon log is a tamper indicator (T1562.002).' })
  }
  else {
    Add-Finding -Severity Info -Category 'Detection' -Title 'Sysmon not installed' `
      -Detail ('No minifilter with altitude 385201 and no Sysmon service. {0}' -f $(if ($sfEdrRunning.Count) { 'Running EDR (' + ($sfEdrRunning -join ', ') + ') supplies process telemetry instead.' } else { 'Without Sysmon or an EDR, process, network-connection and image-load telemetry is limited to event 4688.' })) `
      -Evidence $(if ($sysmonLog) { 'Sysmon/Operational log channel exists (leftover from a previous install)' } else { 'no Sysmon log channel' })
  }
}
catch {
  Add-Finding -Severity Info -Category 'Detection' -Title 'Sysmon presence not assessed' -Detail ('Enumerating minifilter instances failed: ' + $_.Exception.Message)
}

######## 11. Log forwarding agent presence ########
$sfAgentTable = @(
  @{ Name = 'SplunkForwarder';     Product = 'Splunk Universal Forwarder' },
  @{ Name = 'nxlog';               Product = 'NXLog' },
  @{ Name = 'winlogbeat';          Product = 'Elastic Winlogbeat' },
  @{ Name = 'filebeat';            Product = 'Elastic Filebeat' },
  @{ Name = 'Elastic Agent';       Product = 'Elastic Agent' },
  @{ Name = 'elastic-agent';       Product = 'Elastic Agent' },
  @{ Name = 'HealthService';       Product = 'Microsoft Monitoring Agent (MMA / SCOM)' },
  @{ Name = 'AzureMonitorAgent';   Product = 'Azure Monitor Agent' },
  @{ Name = 'DatadogAgent';        Product = 'Datadog Agent' },
  @{ Name = 'WinCollect';          Product = 'IBM QRadar WinCollect' },
  @{ Name = 'fluentdwinsvc';       Product = 'Fluentd' },
  @{ Name = 'td-agent';            Product = 'Fluentd (td-agent)' },
  @{ Name = 'WazuhSvc';            Product = 'Wazuh agent' },
  @{ Name = 'OssecSvc';            Product = 'OSSEC agent' },
  @{ Name = 'sumo-collector';      Product = 'Sumo Logic Collector' },
  @{ Name = 'graylog-sidecar';     Product = 'Graylog Sidecar' },
  @{ Name = 'CriblEdge';           Product = 'Cribl Edge' },
  @{ Name = 'vector';              Product = 'Vector' },
  @{ Name = 'promtail';            Product = 'Grafana Promtail' },
  @{ Name = 'Alloy';               Product = 'Grafana Alloy' },
  @{ Name = 'otelcol*';            Product = 'OpenTelemetry Collector' },
  @{ Name = 'LogRhythm System Monitor Service'; Product = 'LogRhythm SysMon' },
  @{ Name = 'Rapid7 Endpoint Agent'; Product = 'Rapid7 Insight Agent' }
)
try {
  $agentLines = @()
  foreach ($a in $sfAgentTable) {
    $svc = Get-SfService -Pattern $a.Name
    if (-not $svc) { continue }
    $agentLines += ('{0} (service {1}: {2})' -f $a.Product, $svc.Name, $svc.Status)
    if ("$($svc.Status)" -eq 'Running') { $sfAgentsRunning += $a.Product } else { $sfAgentsStopped += $a.Product }
  }
  $sfAgentsRunning = @($sfAgentsRunning | Select-Object -Unique)
  $wefText = if ($sfWefConfigured) { 'WEF SubscriptionManager policy present' } else { 'no WEF SubscriptionManager policy' }
  if ($sfAgentsRunning.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Detection' -Title ('Log forwarding agent running: ' + ($sfAgentsRunning -join ', ')) `
      -Detail ('Local event logs are shipped off-host, so log clearing (T1070.001) does not erase the record. ' + $wefText + '.') -Evidence ($agentLines -join ' | ')
  }
  elseif ($sfAgentsStopped.Count -gt 0) {
    Add-Finding -Severity Medium -Category 'Detection' -Title ('Log forwarding agent installed but not running: ' + (($sfAgentsStopped | Select-Object -Unique) -join ', ')) `
      -Detail ('The agent is present but stopped, so nothing is being shipped. A stopped collector is either a failed deployment or a tamper indicator (T1562.001). ' + $wefText + '.') `
      -Evidence ($agentLines -join ' | ') -Remediation 'Start the service, set it to Automatic and confirm the SIEM is receiving events from this host.'
  }
  else {
    Add-Finding -Severity Info -Category 'Detection' -Title 'No log forwarding agent found' `
      -Detail ('None of the known collector services is installed; ' + $wefText + '. Severity is assigned in the telemetry roll-up below (an EDR may ship its own telemetry).') `
      -Evidence 'service table checked for: Splunk UF, NXLog, Winlogbeat, Filebeat, Elastic Agent, MMA, Azure Monitor Agent, Datadog, WinCollect, Fluentd, Wazuh, OSSEC, Sumo, Graylog, Cribl, Vector, Promtail, Alloy, OTel Collector, LogRhythm, Rapid7'
  }
}
catch {
  Add-Finding -Severity Info -Category 'Detection' -Title 'Log forwarding agent presence not assessed' -Detail ('Service table read failed: ' + $_.Exception.Message)
}

######## 12. Host telemetry roll-up ########
# Sysmon or an EDR supplies rich process telemetry; an agent, WEF or an EDR ships
# it off-host. Missing both halves is the gap that lets an intrusion go unseen.
try {
  $hasRich  = $sfSysmonPresent -or ($sfEdrRunning.Count -gt 0)
  $hasShip  = ($sfAgentsRunning.Count -gt 0) -or $sfWefConfigured -or ($sfEdrRunning.Count -gt 0)
  $rollEvidence = ('Sysmon: {0}; EDR running: {1}; forwarding agent running: {2}; WEF policy: {3}; MDE onboarded: {4}' -f `
    $(if ($sfSysmonPresent) { 'yes' } else { 'no' }), $(if ($sfEdrRunning.Count) { $sfEdrRunning -join ', ' } else { 'none' }), $(if ($sfAgentsRunning.Count) { $sfAgentsRunning -join ', ' } else { 'none' }), $(if ($sfWefConfigured) { 'yes' } else { 'no' }), $(if ($sfMdeOnboarded) { 'yes' } else { 'no' }))
  if (-not $hasRich -and -not $hasShip) {
    Add-Finding -Severity Medium -Category 'Detection' -Title 'Host telemetry gap: no Sysmon, no EDR, no log forwarding' `
      -Detail 'Process creation is recorded only as event 4688 in a local Security log that the attacker can clear (T1070.001). No network-connection, image-load or driver-load telemetry exists, and nothing leaves the host, so an intrusion here is detectable only by a manual forensic visit.' `
      -Evidence $rollEvidence `
      -Remediation 'Deploy an EDR (Defender for Endpoint onboarding is the lowest-friction option on Windows), or Sysmon with a maintained config plus a forwarding agent or WEF subscription to the SIEM.'
  }
  elseif (-not $hasRich) {
    Add-Finding -Severity Low -Category 'Detection' -Title 'Logs are forwarded but process telemetry is limited to event 4688' `
      -Detail 'A collector ships the Windows logs, but without Sysmon or an EDR there is no network-connection, image-load, named-pipe or driver-load visibility and 4688 depends on command-line auditing being on.' `
      -Evidence $rollEvidence `
      -Remediation 'Add Sysmon (SwiftOnSecurity or Olaf Hartong modular config) to the forwarded channels, or onboard an EDR.'
  }
  elseif (-not $hasShip) {
    Add-Finding -Severity Low -Category 'Detection' -Title 'Sysmon telemetry stays on the host (no forwarding agent or WEF)' `
      -Detail 'Sysmon records rich telemetry, but nothing ships it, so it is cleared with the local logs after an intrusion (T1070.001).' `
      -Evidence $rollEvidence `
      -Remediation 'Forward Microsoft-Windows-Sysmon/Operational with a collector agent or a WEF subscription.'
  }
  else {
    Add-Finding -Severity Info -Category 'Detection' -Title 'Host telemetry coverage present' -Detail 'Rich process telemetry exists and a shipping path is in place.' -Evidence $rollEvidence
  }
}
catch {
  Add-Finding -Severity Info -Category 'Detection' -Title 'Host telemetry roll-up not assessed' -Detail ('Roll-up failed: ' + $_.Exception.Message)
}
