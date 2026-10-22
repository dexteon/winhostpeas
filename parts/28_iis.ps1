
######################## IIS / WEB SERVER RECON ########################
# Deep IIS inventory when IIS is present (Server 2019/Win11): sites, bindings,
# app pools, certificates, web.config secrets, IIS Rewrite module, auth, TLS.
# All checks are read-only (ServerManager API + config files).

Start-Section 'IIS WEB SERVER RECON'

# Web-root write check by SID, so it works on any OS language. Beyond the shared
# low-privilege set, the IIS worker identities count here: IIS_IUSRS
# (S-1-5-32-568), IUSR (S-1-5-17) and application pool identities (S-1-5-82-*).
# A web root those can write to is a webshell drop point.
function Get-IisWriteAce {
  param($ACLObject)
  if (-not $ACLObject) { return $null }
  $hit = Get-LowPrivWriteAce -ACLObject $ACLObject
  if ($hit) { return $hit }
  foreach ($ace in $ACLObject.Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    if ("$($ace.PropagationFlags)" -match 'InheritOnly') { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
    if (-not ($sid -eq 'S-1-5-32-568' -or $sid -eq 'S-1-5-17' -or $sid -like 'S-1-5-82-*')) { continue }
    $rights = "$($ace.FileSystemRights)"
    if ($rights -notmatch $script:WriteRightsRx) { continue }
    $name = switch -Wildcard ($sid) { 'S-1-5-32-568' { 'IIS_IUSRS' } 'S-1-5-17' { 'IUSR' } default { 'IIS AppPool identity' } }
    $level = if ($rights -match 'FullControl') { 'FullControl' } elseif ($rights -match 'Modify') { 'Modify' } else { 'Write' }
    return [pscustomobject]@{ Name = $name; Sid = $sid; Level = $level; Rights = $rights }
  }
  return $null
}

$iisPresent = $false
$sm = $null
$adminDll = "$env:windir\System32\inetsrv\Microsoft.Web.Administration.dll"
if ((Get-Service W3SVC -ErrorAction SilentlyContinue) -or (Test-Path $adminDll)) {
  $iisPresent = $true
  try {
    [void][System.Reflection.Assembly]::LoadFrom($adminDll)
    $sm = New-Object Microsoft.Web.Administration.ServerManager
  } catch { $sm = $null }
}

if (-not $iisPresent) {
  Add-Finding -Severity Info -Category 'IIS' -Title 'IIS not installed on this host'
}
else {
  Add-Finding -Severity Info -Category 'IIS' -Title 'IIS is installed' `
    -Detail 'Full web-server recon follows - every finding is attacker-recon surface.'

  # --- IIS version ---
  $iisVer = (Get-Item "$env:windir\System32\inetsrv\w3wp.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
  if ($iisVer) { Add-Finding -Severity Info -Category 'IIS' -Title "IIS engine version $iisVer" }

  # --- Sites & bindings ---
  if ($sm) {
    foreach ($site in $sm.Sites) {
      $bindings = ($site.Bindings | ForEach-Object {
        '{0}://{1}:{2}' -f $_.Protocol, $(if ($_.Host) { $_.Host } else { '*' }), $_.BindingInformation.Split(':')[-1]
      }) -join ', '
      Add-Finding -Severity Info -Category 'IIS' -Title ("Site '{0}' ({1})" -f $site.Name, $site.State) `
        -Detail ("Bindings: {0} | ID: {1}" -f $bindings, $site.Id) `
        -Remediation 'Baseline expected bindings; unknown sites = investigate.'
      # HTTP-only site (no TLS binding)
      if (-not ($site.Bindings | Where-Object { $_.Protocol -eq 'https' })) {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Site '{0}' has NO HTTPS binding" -f $site.Name) `
          -Detail 'Cleartext HTTP - credentials/cookies/session tokens readable on the wire.' `
          -Remediation 'Add an HTTPS binding with a valid cert; redirect HTTP to HTTPS; set HSTS.'
      }
      # Physical path + writability check
      foreach ($app in $site.Applications) {
        $root = $app.VirtualDirectories | Select-Object -First 1
        if ($root -and $root.PhysicalPath -and (Test-Path $root.PhysicalPath)) {
          $acl = $null
          try { $acl = Get-Acl -LiteralPath $root.PhysicalPath -ErrorAction SilentlyContinue } catch { }
          if ($acl) {
            $w = Get-IisWriteAce -ACLObject $acl
            if ($w) {
              Add-Finding -Severity High -Category 'IIS' -Title ("Web root writable by non-admin: {0}" -f $root.PhysicalPath) `
                -Detail ("Site: {0} | {1} ({2}) granted {3} - webshell drop-in." -f $site.Name, $w.Name, $w.Sid, $w.Rights) `
                -Evidence $root.PhysicalPath `
                -Remediation 'Web roots should be read-only for app-pool identities and Users; writers need explicit ACLs.'
            }
          }
        }
      }
    }

    # --- App pools ---
    foreach ($pool in $sm.ApplicationPools) {
      $ident = $pool.ProcessModel.IdentityType
      $flags = @()
      if ($pool.Enable32BitAppOnWin64) { $flags += '32bit' }
      if ($pool.ProcessModel.LoadUserProfile -eq $false) { $flags += 'no-profile' }
      Add-Finding -Severity Info -Category 'IIS' -Title ("App pool '{0}' ({1})" -f $pool.Name, $pool.State) `
        -Detail ("Identity: {0} | .NET CLR: {1}{2}" -f $ident, $pool.ManagedRuntimeVersion, $(if ($flags) { ' | ' + ($flags -join ',') } else { '' }))
      if ("$ident" -match 'LocalSystem') {
        Add-Finding -Severity High -Category 'IIS' -Title ("App pool '{0}' runs as LocalSystem" -f $pool.Name) `
          -Detail 'Any app-level RCE/LFI in that pool = full SYSTEM compromise.' `
          -Remediation 'Use ApplicationPoolIdentity; grant precise per-pool resource ACLs.'
      }
      if ($pool.ManagedRuntimeVersion -eq 'v2.0') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("App pool '{0}' targets .NET 2.0/3.5 runtime" -f $pool.Name) `
          -Remediation 'Migrate to v4.x; legacy runtime lacks modern mitigations.'
      }
    }
  }

  # --- Machine certificates: expiry / weak keys (covers HTTPS bindings) ---
  try {
    $now = Get-Date
    foreach ($cert in (Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue)) {
      $days = ($cert.NotAfter - $now).Days
      $subj = $cert.Subject -replace '^CN=', ''
      if ($days -lt 0) {
        Add-Finding -Severity Critical -Category 'IIS' -Title ("EXPIRED certificate: {0} (expired {1}d ago)" -f $subj, -$days) `
          -Detail ('Thumbprint: ' + $cert.Thumbprint) `
          -Remediation 'Renew now - expired certs break TLS and push users to click-through errors.'
      }
      elseif ($days -lt 30) {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Certificate expiring in {0}d: {1}" -f $days, $subj) `
          -Detail ('Thumbprint: ' + $cert.Thumbprint) `
          -Remediation 'Schedule renewal.'
      }
      if ($cert.SignatureAlgorithm.FriendlyName -match 'MD5|SHA1') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Weak signature ({0}) on cert: {1}" -f $cert.SignatureAlgorithm.FriendlyName, $subj) `
          -Remediation 'Reissue with SHA256+.'
      }
    }
  } catch { }

  # --- IIS URL Rewrite module ---
  $rewriteDll = "$env:windir\System32\inetsrv\rewrite.dll"
  if (Test-Path $rewriteDll) {
    $rv = (Get-Item $rewriteDll).VersionInfo
    $rver = '{0}.{1}.{2}.{3}' -f $rv.FileMajorPart, $rv.FileMinorPart, $rv.FileBuildPart, $rv.FilePrivatePart
    Add-Finding -Severity Info -Category 'IIS' -Title ("IIS URL Rewrite module installed: v{0}" -f $rver) `
      -Detail 'Rewrite is internet-reachable logic: inbound/outbound rules in web.config can leak or redirect.'
    $fileVerNum = [double]('{0}.{1}' -f $rv.FileMajorPart, $rv.FileMinorPart)
    $buildNum = [int]$rv.FileBuildPart
    if ($fileVerNum -lt 2.1 -or ($fileVerNum -eq 2.1 -and $buildNum -lt 2105)) {
      Add-Finding -Severity Medium -Category 'IIS' -Title ("IIS URL Rewrite v{0} is outdated" -f $rver) `
        -Detail 'Older Rewrite 2.x builds have published security fixes (e.g. spoofing/info-disclosure class advisories).' `
        -Remediation 'Upgrade to the latest URL Rewrite 2.1 from Microsoft; verify against the advisory list.'
    }
    # Rewrite rules referenced in web.configs get scanned below with the file sweep
  }
  else {
    Add-Finding -Severity Info -Category 'IIS' -Title 'IIS URL Rewrite module not installed'
  }

  # --- web.config secrets & weak machineKey settings ---
  $webRoots = @("$env:windir\System32\inetsrv\config", "$env:SystemDrive\inetpub")
  if ($sm) {
    foreach ($site in $sm.Sites) {
      foreach ($app in $site.Applications) {
        $root = $app.VirtualDirectories | Select-Object -First 1
        if ($root -and $root.PhysicalPath) { $webRoots += $root.PhysicalPath }
      }
    }
  }
  $webRoots = $webRoots | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
  foreach ($wr in $webRoots) {
    $cfgFiles = @(Get-ChildItem -LiteralPath $wr -Recurse -Filter 'web.config' -ErrorAction SilentlyContinue | Select-Object -First 50)
    foreach ($cfg in $cfgFiles) {
      $content = $null
      try { $content = Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue } catch { }
      if (-not $content) { continue }
      # connection strings with passwords (redacted)
      if ($content -match '(?i)connectionstring\s*=.{0,200}password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Plaintext DB password in {0}" -f $cfg.FullName) `
          -Detail 'Detected via pattern; value not recorded.' `
          -Remediation 'Move to encrypted connectionStrings sections or managed identities.'
      }
      # machineKey weak/validation
      if ($content -match '(?i)<machinekey[^>]*\bvalidation\s*=\s*"(MD5|SHA1|3DES)"') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Weak machineKey validation in {0}" -f $cfg.FullName) `
          -Detail 'MD5/SHA1/3DES ViewState signing is forgeable - ViewState deserialization RCE path.' `
          -Remediation 'Use HMACSHA256 validation; rotate autoGenerated keys.'
      }
      if ($content -match '(?i)<machinekey[^>]*validationkey\s*=\s*"([0-9A-Fa-f]{10,60})"') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Short/weak validationKey in {0}" -f $cfg.FullName) `
          -Detail 'Explicit short validationKey is brute-forceable, enabling ViewState forgery.' `
          -Remediation 'Use 64-128 hex byte autoGenerated keys.'
      }
      # debug=true exposed
      if ($content -match '(?i)<deployment[^>]*retail\s*=\s*"false"') {
        Add-Finding -Severity Low -Category 'IIS' -Title ("deployment retail=false in {0}" -f $cfg.FullName) `
          -Remediation 'Set retail="true" on production servers (kills debug tracing + detailed errors).'
      }
      # directory browsing on
      if ($content -match '(?i)<directorybrowse[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Directory browsing enabled in {0}" -f $cfg.FullName) `
          -Remediation 'Disable directoryBrowse - leaks file inventory to attackers.'
      }
      # generic secret patterns
      Test-FileForSecrets -Path $cfg.FullName -Context ' (IIS web.config)'
    }
  }

  # --- Server-level auth config from applicationHost.config ---
  $appHost = "$env:windir\System32\inetsrv\config\applicationHost.config"
  if (Test-Path $appHost -ErrorAction SilentlyContinue) {
    $ah = $null
    try { $ah = Get-Content $appHost -Raw } catch { }
    if ($ah) {
      if ($ah -match '(?i)<anonymousAuthentication[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Low -Category 'IIS' -Title 'Anonymous authentication enabled (server-wide default)' `
          -Remediation 'Expected for public sites; ensure protected vdirs override with auth.'
      }
      if ($ah -match '(?i)<basicAuthentication[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title 'Basic authentication enabled in IIS' `
          -Detail 'Base64 cleartext credentials on the wire unless bound to TLS.' `
          -Remediation 'Require HTTPS on all Basic-auth bindings or move to Windows/auth modes.'
      }
      if ($ah -match '(?i)<directoryBrowse[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title 'Directory browsing enabled at server level'
      }
      # applicationHost.config itself: connection strings / passwords
      if ($ah -match '(?i)password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title 'Password-shaped value in applicationHost.config' `
          -Detail 'App-pool/service credentials stored in config are readable by admins and backup-exfiltration.' `
          -Remediation 'Use app-pool identities where possible; protect config backups.'
      }
    }
    # writable applicationHost.config = total IIS takeover
    $aclAh = $null
    try { $aclAh = Get-Acl -LiteralPath $appHost -ErrorAction SilentlyContinue } catch { }
    if ($aclAh) {
      $weakAh = Get-IisWriteAce -ACLObject $aclAh
      if ($weakAh) {
        Add-Finding -Severity Critical -Category 'IIS' -Title 'applicationHost.config is user-writable' `
          -Detail ('{0} ({1}) has {2}. Edit = full control of every site/app pool on the box.' -f $weakAh.Name, $weakAh.Sid, $weakAh.Rights) `
          -Evidence $appHost `
          -Remediation 'Restore the Administrators/SYSTEM-only ACL immediately.'
      }
    }
  }

  # --- Other web-adjacent services ---
  foreach ($svc in @(@('FTPSVC', 'IIS FTP'), @('SMTPSVC', 'IIS SMTP'))) {
    $s = Get-Service $svc[0] -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Running') {
      Add-Finding -Severity Low -Category 'IIS' -Title ("{0} service running" -f $svc[1]) `
        -Remediation 'Confirm business need; FTP/SMTP legacy services widen attack surface (cleartext protocols).'
    }
  }
}

# --- WinRM transport security (IIS-adjacent remote mgmt) ---
try {
  $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | Get-Item
  foreach ($l in $listeners) {
    $tr = $l.ChildKeys | Where-Object { $_ }
    $transport = (Get-ChildItem $l.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Transport' })
    $tval = if ($transport) { $transport.Value } else { 'HTTP' }
    $portItem = Get-ChildItem $l.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Port' }
    Add-Finding -Severity Info -Category 'RemoteMgmt' -Title ("WinRM listener ({0}, port {1})" -f $tval, $portItem.Value)
    if ("$tval" -eq 'HTTP') {
      Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM listener on HTTP (unencrypted transport)' `
        -Remediation 'Add an HTTPS listener (or use trusted host + NTLMnegotiate); ideally HTTPS-only.'
    }
  }
  $unenc = (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue).Value
  $allowUnenc = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
  if ("$allowUnenc" -eq 'true') {
    Add-Finding -Severity High -Category 'RemoteMgmt' -Title 'WinRM AllowUnencrypted = true' `
      -Remediation 'Set to false; unencrypted WinRM exposes credentials to on-path capture.'
  }
  if ("$unenc" -eq 'true') {
    Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM Basic auth enabled' `
      -Remediation 'Prefer Kerberos/Negotiate; Basic over HTTP is trivially sniffable.'
  }
} catch {
  # Enumerating WSMan:\localhost\Listener needs administrator. Without it the
  # provider throws Access Denied, and reporting that as "not configured" states
  # a false negative as fact - a host with an unencrypted HTTP listener would be
  # reported clean. Fall back to evidence that IS readable unprivileged: the
  # service state and the listening ports.
  $svc = Get-Service WinRM -ErrorAction SilentlyContinue
  $winrmPorts = @()
  try {
    $winrmPorts = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in 5985, 5986 } | Select-Object -ExpandProperty LocalPort -Unique)
  } catch { }
  if ($svc -and $svc.Status -eq 'Running') {
    $portTxt = if ($winrmPorts.Count) { ($winrmPorts -join ', ') } else { 'none detected' }
    Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM is running but its listener config was not assessed' `
      -Detail ("WinRM service state: {0} (StartType {1}); listening ports: {2}. Listener transport/auth settings require administrator to read, so HTTP-vs-HTTPS and Basic-auth status are UNKNOWN, not clean." -f $svc.Status, $svc.StartType, $portTxt) `
      -Remediation 'Re-run elevated to confirm the transport and auth configuration. Port 5985 indicates an HTTP listener.'
  }
  elseif ($svc) {
    Add-Finding -Severity Info -Category 'RemoteMgmt' -Title ('WinRM service present but not running (state: {0})' -f $svc.Status) `
      -Detail 'Listener configuration not read; the service is not currently accepting connections.'
  }
  else {
    Add-Finding -Severity Info -Category 'RemoteMgmt' -Title 'WinRM service not present on this host'
  }
}

# --- WinRM CLIENT settings (readable without elevation) ---
# TrustedHosts = * lets this host send its credentials to any name it is told to
# connect to; AllowUnencrypted or Basic on the client side leaks them in clear.
try {
  $cliBase = 'WSMan:\localhost\Client'
  if (Test-Path $cliBase) {
    $trusted = "$((Get-Item (Join-Path $cliBase 'TrustedHosts') -ErrorAction Stop).Value)".Trim()
    $cliUnenc = "$((Get-Item (Join-Path $cliBase 'AllowUnencrypted') -ErrorAction SilentlyContinue).Value)"
    $cliBasic = "$((Get-Item (Join-Path $cliBase 'Auth\Basic') -ErrorAction SilentlyContinue).Value)"
    $cliDigest = "$((Get-Item (Join-Path $cliBase 'Auth\Digest') -ErrorAction SilentlyContinue).Value)"
    if ($trusted -eq '*' -or $trusted -match '(^|,)\s*\*\s*(,|$)') {
      Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM client TrustedHosts is * (any host)' `
        -Detail ('TrustedHosts: {0}. NTLM credentials from this host are sent to any target name, so a spoofed or poisoned name (LLMNR, WPAD, DNS) collects admin credentials.' -f $trusted) `
        -Evidence "$cliBase\TrustedHosts" `
        -Remediation 'Clear TrustedHosts or list only the specific management targets; use Kerberos or HTTPS listeners instead of host trust.'
    }
    elseif ($trusted) {
      Add-Finding -Severity Low -Category 'RemoteMgmt' -Title 'WinRM client TrustedHosts list is set' `
        -Detail ('TrustedHosts: {0}. Each listed name receives this host''s NTLM credentials without mutual authentication.' -f $trusted) `
        -Evidence "$cliBase\TrustedHosts" `
        -Remediation 'Keep the list minimal and prefer Kerberos or HTTPS with certificate validation.'
    }
    if ($cliUnenc -eq 'true') {
      Add-Finding -Severity Medium -Category 'RemoteMgmt' -Title 'WinRM client AllowUnencrypted = true' `
        -Evidence "$cliBase\AllowUnencrypted" `
        -Remediation 'Set the client AllowUnencrypted to false so outbound WinRM sessions always negotiate message encryption.'
    }
    if ($cliBasic -eq 'true' -or $cliDigest -eq 'true') {
      Add-Finding -Severity Low -Category 'RemoteMgmt' -Title ('WinRM client allows {0} authentication' -f (@($(if ($cliBasic -eq 'true') { 'Basic' }), $(if ($cliDigest -eq 'true') { 'Digest' })) | Where-Object { $_ }) -join ' and ') `
        -Evidence "$cliBase\Auth" `
        -Remediation 'Disable Basic and Digest on the WinRM client (CIS 18.10.89.1.x); keep Kerberos and Negotiate.'
    }
    if (-not $trusted -and $cliUnenc -ne 'true' -and $cliBasic -ne 'true' -and $cliDigest -ne 'true') {
      Add-Finding -Severity Info -Category 'RemoteMgmt' -Title 'WinRM client settings at secure defaults (no TrustedHosts, encrypted, no Basic/Digest)'
    }
  }
  else {
    Add-Finding -Severity Info -Category 'RemoteMgmt' -Title 'WinRM client settings not assessed' -Detail 'The WSMan client provider path is not available on this host.'
  }
} catch {
  Add-Finding -Severity Info -Category 'RemoteMgmt' -Title 'WinRM client settings not assessed' `
    -Detail ('Reading WSMan:\localhost\Client failed: ' + $_.Exception.Message)
}
