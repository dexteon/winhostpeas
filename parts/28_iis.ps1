
######################## IIS / WEB SERVER RECON ########################
# Deep IIS inventory when IIS is present (Server 2019/Win11): sites, bindings,
# app pools, certificates, web.config secrets, IIS Rewrite module, auth, TLS.
# All checks are read-only (ServerManager API + config files).

Start-Section 'IIS WEB SERVER RECON'
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
          $acl = Get-Acl $root.PhysicalPath -ErrorAction SilentlyContinue
          if ($acl) {
            $w = $acl.Access | Where-Object {
              $_.IdentityReference -match 'BUILTIN\\Users|Everyone|IIS_IUSRS' -and
              $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match 'FullControl|Modify|Write'
            }
            if ($w) {
              Add-Finding -Severity High -Category 'IIS' -Title ("Web root writable by non-admin: {0}" -f $root.PhysicalPath) `
                -Detail ("Site: {0} | {1} granted {2} - webshell drop-in." -f $site.Name, $w[0].IdentityReference, $w[0].FileSystemRights) `
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
  if (Test-Path $appHost) {
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
    $aclAh = Get-Acl $appHost -ErrorAction SilentlyContinue
    if ($aclAh) {
      $weakAh = $aclAh.Access | Where-Object {
        $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and $_.AccessControlType -eq 'Allow' -and
        ("$($_.FileSystemRights)" -match 'FullControl|Modify|Write')
      }
      if ($weakAh) {
        Add-Finding -Severity Critical -Category 'IIS' -Title 'applicationHost.config is user-writable' `
          -Detail 'Edit = full control of every site/app pool on the box.' `
          -Remediation 'Restore Administrators/SYSTEM/Administrators-only ACL immediately.'
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
