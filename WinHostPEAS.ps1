

[CmdletBinding()]
param(
  [switch]$TimeStamp,
  [switch]$FullCheck,
  [string]$OutputDir = '.\WinHostPEAS_Output',
  [switch]$NoReport,
  [switch]$NoLaunch,
  [switch]$Obfuscate
)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function TimeElapsed {
  if ($TimeStamp) { Write-Host ('  [{0:mm\:ss}]' -f $stopwatch.Elapsed) -ForegroundColor DarkGray }
}

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:FindingsByName = @{}

function Get-Redacted {
  param($Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ($s.Length -le 4) { return '<redacted:' + $s.Length + 'ch>' }
  $fp = $s.Substring($s.Length - 4)
  return ('<redacted:{0}ch, ends ...{1}>' -f $s.Length, $fp)
}

function Add-Finding {
  param(
    [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Title,
    [string]$Detail = '',
    [string]$Evidence = '',
    [string]$Remediation = ''
  )
  $f = [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    Host      = $env:COMPUTERNAME
    Severity  = $Severity
    Category  = $Category
    Title     = $Title
    Detail    = $Detail
    Evidence  = $Evidence
    Remediation = $Remediation
  }
  $script:Findings.Add($f)
  $key = "$Category|$Title"
  if (-not $script:FindingsByName.ContainsKey($key)) { $script:FindingsByName[$key] = 0 }
  $script:FindingsByName[$key]++

  $sevColor = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
  Write-Host ('  [{0}] {1}: {2}' -f $Severity, $Category, $Title) -ForegroundColor $sevColor[$Severity]
  if ($Detail)       { Write-Host ('      ' + $Detail) -ForegroundColor DarkGray }
  if ($Remediation)  { Write-Host ('      Fix: ' + $Remediation) -ForegroundColor DarkCyan }
}

function Start-Section {
  param([string]$Name)
  Write-Host ''
  TimeElapsed
  Write-Host ('===== ' + $Name + ' =====') -ForegroundColor Blue
}

function Get-HighestSeverity {
  $order = 'Info','Low','Medium','High','Critical'
  $highest = 'Info'
  foreach ($f in $script:Findings) {
    if ($order.IndexOf($f.Severity) -gt $order.IndexOf($highest)) { $highest = $f.Severity }
  }
  return $highest
}

function Write-Reports {
  param([string]$Dir, [switch]$LaunchHtml)
  if ($NoReport) { return }
  try { New-Item -ItemType Directory -Path $Dir -Force | Out-Null } catch { Write-Host "Cannot create report dir: $_" -ForegroundColor Red; return }
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  if ($Obfuscate) {
    $rid = -join ((1..12) | ForEach-Object { [char](Get-Random -Min 97 -Max 122) })
    $baseName = "rpt_{0}_{1}" -f $rid, $stamp
  } else {
    $baseName = "WinHostPEAS_{0}_{1}" -f $env:COMPUTERNAME, $stamp
  }
  $json = Join-Path $Dir ("{0}.json" -f $baseName)
  $csv  = Join-Path $Dir ("{0}.csv"  -f $baseName)
  $html = Join-Path $Dir ("{0}.html" -f $baseName)

  $toolLabel = if ($Obfuscate) { 'Posture Audit' } else { 'WinHostPEAS (defensive refit of winPEAS.ps1)' }
  $meta = [pscustomobject]@{
    Tool        = $toolLabel
    Host        = $env:COMPUTERNAME
    Generated   = (Get-Date).ToString('s')
    Duration    = $stopwatch.Elapsed.ToString('mm\:ss')
    FullCheck   = [bool]$FullCheck
    TotalFindings = $script:Findings.Count
    HighestSeverity = Get-HighestSeverity
  }
  @{ Meta = $meta; Findings = $script:Findings } | ConvertTo-Json -Depth 4 | Set-Content -Path $json -Encoding UTF8
  $script:Findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

  $sevOrder = 'Critical','High','Medium','Low','Info'
  $counts = @{}
  foreach ($s in $sevOrder) { $counts[$s] = @($script:Findings | Where-Object { $_.Severity -eq $s }).Count }
  $cats = $script:Findings | Group-Object Category | Sort-Object Name

  $tiles = foreach ($s in $sevOrder) {
    $c = @{ Critical='#b91c1c'; High='#dc2626'; Medium='#d97706'; Low='#0891b2'; Info='#64748b' }[$s]
    @"

    <div class="tile" style="border-top:4px solid $c" data-sev="$s" onclick="filterSev('$s')">
      <div class="tile-num" style="color:$c">$($counts[$s])</div>
      <div class="tile-label">$s</div>
    </div>
"@
  }
  $catOpts = foreach ($c in $cats) { '<option value="' + $c.Name + '">' + $c.Name + ' (' + $c.Count + ')</option>' }

  $rowsJs = foreach ($f in $script:Findings) {
    $esc = { param($t) if ($null -eq $t) { '' } else { $t.ToString().Replace('\', '\\').Replace('"', '\"').Replace('<', ([char]0x5c + 'u003c')).Replace('>', ([char]0x5c + 'u003e')).Replace("`r", '').Replace("`n", ' ') } }
    '  { sev: "' + $f.Severity + '", cat: "' + (& $esc $f.Category) + '", title: "' + (& $esc $f.Title) + '", detail: "' + (& $esc $f.Detail) + '", evid: "' + (& $esc $f.Evidence) + '", rem: "' + (& $esc $f.Remediation) + '" },'
  }

  $adminList = if ($script:Exec.Admins) { (($script:Exec.Admins | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) }) -join ', ') } else { '(none resolved)' }
  $userRows = foreach ($u in $script:Exec.Users) {
    $ll = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '<span class="never">never</span>' }
    $adm = if ($u.IsAdmin) { '<b class="adm">ADMIN</b>' } else { '' }
    $en = if ($u.Enabled) { 'enabled' } else { '<span class="dis">disabled</span>' }
    '<tr><td>' + [System.Net.WebUtility]::HtmlEncode([string]$u.Name) + '</td><td>' + $en + '</td><td>' + $adm + '</td><td>' + $ll + '</td></tr>'
  }
  $userRows = @('<tr><th>User</th><th>Status</th><th>Role</th><th>Last logon</th></tr>') + @($userRows)

  $htmlDoc = @"
<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WinHostPEAS Report - $($env:COMPUTERNAME)</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;margin:0;background:#f1f5f9;color:#111827}
 header{background:#0f172a;color:#fff;padding:18px 28px}
 header h1{margin:0;font-size:22px} header .meta{color:#94a3b8;font-size:13px;margin-top:4px}
 .bar{display:flex;gap:14px;align-items:center;background:#fff;padding:14px 28px;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}
 .tiles{display:flex;gap:12px;margin:0}
 .tile{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 18px;min-width:86px;text-align:center;cursor:pointer;user-select:none}
 .tile:hover{box-shadow:0 1px 4px rgba(0,0,0,.12)}
 .tile.active{outline:2px solid #0f172a}
 .tile-num{font-size:26px;font-weight:700;line-height:1.1}
 .tile-label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#64748b}
 .controls{display:flex;gap:8px;align-items:center;margin-left:auto;flex-wrap:wrap}
 input[type=text],select{padding:7px 10px;border:1px solid #cbd5e1;border-radius:6px;font-size:13px;background:#fff}
 input[type=text]{width:240px}
 button{padding:7px 12px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;cursor:pointer;font-size:13px}
 button:hover{background:#f8fafc}
 main{padding:20px 28px}
 table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
 th,td{border:1px solid #e5e7eb;padding:7px 9px;text-align:left;vertical-align:top}
 th{background:#f1f5f9;position:sticky;top:0}
 tr:nth-child(even){background:#f9fafb}
 code{font-size:11px;word-break:break-all}
 .sev{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}
 .sev.Critical{background:#b91c1c}.sev.High{background:#dc2626}.sev.Medium{background:#d97706}
 .sev.Low{background:#0891b2}.sev.Info{background:#64748b}
 .rem{color:#0f766e}
 .count{color:#64748b;font-size:12px;margin:0 0 10px 2px}
 .exec{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:18px}
 .exec-card{flex:1 1 380px;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:14px 18px}
 .exec-card h3{margin:0 0 8px;font-size:14px;color:#0f172a;text-transform:uppercase;letter-spacing:.5px}
 table.kv{width:100%;border-collapse:collapse;font-size:13px}
 table.kv td,table.kv th{border:1px solid #e5e7eb;padding:5px 8px;text-align:left}
 table.kv tr td:first-child{color:#64748b;width:40%}
 table.kv th{background:#f1f5f9}
 .never{color:#b91c1c;font-weight:600}
 .adm{color:#b91c1c}
 .dis{color:#94a3b8}
</style></head><body>
<header>
 <h1>$(if ($Obfuscate) { "Posture Audit" } else { "WinHostPEAS Posture Audit" }) &mdash; $($env:COMPUTERNAME)</h1>
 <div class="meta">Generated $(Get-Date) &middot; $($stopwatch.Elapsed.ToString('mm\:ss')) elapsed &middot; $($meta.TotalFindings) findings &middot; highest severity: $($meta.HighestSeverity) &middot; FullCheck: $($meta.FullCheck)</div>
</header>
<div class="bar">
<div class="tiles">`$tilesPlaceholder</div>
 <div class="controls">
   <input type="text" id="q" placeholder="Search findings..." oninput="render()">
   <select id="catSel" onchange="render()"><option value="">All categories</option>`$catOptsPlaceholder</select>
   <button onclick="clearFilters()">Clear filters</button>
 </div>
</div>
<main>
 <div class="exec">
  <div class="exec-card">
   <h3>Executive summary</h3>
   <table class="kv">
    <tr><td>Local admins</td><td><b>$($script:Exec.AdminCount)</b> &mdash; `$adminListPlaceholder</td></tr>
    <tr><td>Local users</td><td><b>$($script:Exec.UserCount)</b> ($($script:Exec.EnabledCount) enabled, $($script:Exec.DisabledCount) disabled, $($script:Exec.NeverLoggedIn) enabled-but-never-logged-on)</td></tr>
    <tr><td>Persistence findings (Crit/High)</td><td><b>$($script:Exec.PersistCritHigh)</b></td></tr>
    <tr><td>Priv-esc findings (Crit/High)</td><td><b>$($script:Exec.PrivEscCritHigh)</b></td></tr>
    <tr><td>Hardening gaps (Crit/High/Med)</td><td><b>$($script:Exec.HardeningGaps)</b></td></tr>
    <tr><td>Exposed secrets (Crit/High)</td><td><b>$($script:Exec.SecretsExposed)</b></td></tr>
    <tr><td>Devices seen on network</td><td><b>$($script:Exec.DevicesSeen)</b> (passive ARP/neighbor cache - no packets sent)</td></tr>
    <tr><td>Scan mode</td><td>Fully passive host recon - every check reads local state only (registry, WMI, local socket tables, local files). No network packets are sent to any host, including domain controllers.</td></tr>
   </table>
  </div>
  <div class="exec-card">
   <h3>Local accounts &mdash; last logon</h3>
   <table class="kv" id="usersTable">`$userRowsPlaceholder</table>
  </div>
 </div>
 <p class="count" id="count"></p>
 <table id="tbl"><thead><tr><th style="width:70px">Severity</th><th style="width:130px">Category</th><th>Finding</th><th>Detail / Evidence</th><th style="width:28%">Remediation</th></tr></thead><tbody id="tbody"></tbody></table>
</main>
<script>
const F = [
`$rowsJsPlaceholder
];
let sevFilter = '';
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML;}
function filterSev(s){ sevFilter = (sevFilter===s)?'':s;
  document.querySelectorAll('.tile').forEach(t=>t.classList.toggle('active', t.dataset.sev===sevFilter)); render(); }
function clearFilters(){ sevFilter=''; document.getElementById('q').value=''; document.getElementById('catSel').value='';
  document.querySelectorAll('.tile').forEach(t=>t.classList.remove('active')); render(); }
function render(){
  const q = document.getElementById('q').value.toLowerCase();
  const cat = document.getElementById('catSel').value;
  const rows = F.filter(f =>
    (!sevFilter || f.sev===sevFilter) &&
    (!cat || f.cat===cat) &&
    (!q || (f.title+' '+f.detail+' '+f.evid+' '+f.rem+' '+f.cat).toLowerCase().includes(q)));
  const tb = document.getElementById('tbody');
  tb.innerHTML = rows.map(f =>
    '<tr><td><span class="sev '+f.sev+'">'+f.sev+'</span></td><td>'+esc(f.cat)+'</td>'+
    '<td><b>'+esc(f.title)+'</b>'+(f.evid?'<br><code>'+esc(f.evid)+'</code>':'')+'</td>'+
    '<td>'+esc(f.detail)+'</td>'+
    '<td class="rem">'+esc(f.rem)+'</td></tr>').join('');
  document.getElementById('count').textContent = rows.length + ' of ' + F.length + ' findings shown';
}
render();
</script>
</body></html>
"@
  $htmlDoc = $htmlDoc.Replace('$adminListPlaceholder', $adminList)
  $htmlDoc = $htmlDoc.Replace('$userRowsPlaceholder', ($userRows -join "`n"))
  $htmlDoc = $htmlDoc.Replace('$tilesPlaceholder', ($tiles -join ''))
  $htmlDoc = $htmlDoc.Replace('$catOptsPlaceholder', ($catOpts -join ''))
  $htmlDoc = $htmlDoc.Replace('$rowsJsPlaceholder', ($rowsJs -join "`n"))
  Set-Content -Path $html -Value $htmlDoc -Encoding UTF8

  Write-Host ''
  Write-Host ('Report summary: ' + (($sevOrder | Where-Object { $counts[$_] -gt 0 } | ForEach-Object { $_ + ': ' + $counts[$_] }) -join ', ')) -ForegroundColor Cyan
  Write-Host ('Reports written: ' + $json) -ForegroundColor Cyan
  Write-Host ('                ' + $csv)  -ForegroundColor Cyan
  Write-Host ('                ' + $html) -ForegroundColor Cyan

  if ($LaunchHtml -and -not $NoLaunch) {
    try {
      $resolved = (Resolve-Path $html).Path
      Start-Process $resolved
      Write-Host ('Report opened in browser: ' + $resolved) -ForegroundColor Cyan
    }
    catch {
      Write-Host ('Could not launch browser automatically - open manually: ' + $html) -ForegroundColor Yellow
    }
  }
}

function Start-ACLCheck {
  param($Target, $ServiceName)
  if ($null -eq $Target) { return }
  try { $ACLObject = Get-Acl $Target -ErrorAction SilentlyContinue } catch { return }
  if (-not $ACLObject) { return }
  $Identity = @("$env:COMPUTERNAME\$env:USERNAME")
  try {
    whoami.exe /groups /fo csv 2>$null | Select-Object -skip 2 | ConvertFrom-Csv -Header 'group name' |
      Select-Object -ExpandProperty 'group name' | ForEach-Object { $Identity += $_ }
  } catch { }
  $everyoneLike = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Authenticated Users')
  foreach ($i in $Identity) {
    $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }

    $fsr = "$($permission.FileSystemRights)"
    $rr = "$($permission.RegistryRights)"
    $userPermission = ''
    if ($fsr -match 'FullControl') { $userPermission = 'FullControl' }
    elseif ($fsr -match 'Modify') { $userPermission = 'Modify' }
    elseif ($fsr -match 'Write') { $userPermission = 'Write' }
    if ($rr -match 'FullControl') { $userPermission = 'FullControl' }
    if ($userPermission) {
      if ($Target -like "*$env:USERNAME*") { continue }
      Add-Finding -Severity High -Category 'Filesystem ACL' `
        -Title ("Non-admin identity has '{0}' on: {1}" -f $userPermission, $Target) `
        -Detail ("Identity: {0}{1} - an attacker landing as this user could tamper with this object." -f $permission.IdentityReference, $(if ($ServiceName) { ' (service: ' + $ServiceName + ')' } else { '' })) `
        -Evidence $Target `
        -Remediation 'Tighten the ACL: remove broad write/modify for non-admin principals on executable paths and service binaries.'
      return
    }
  }
  foreach ($ev in $everyoneLike) {
    $perm = $ACLObject.Access | Where-Object { $_.IdentityReference -like "*$ev*" -and $_.AccessControlType -eq 'Allow' }
    foreach ($p in $perm) {
      if ("$($p.FileSystemRights)" -match 'FullControl|Modify|Write') {
        Add-Finding -Severity High -Category 'Filesystem ACL' `
          -Title ("'{0}' granted {1} to: {2}" -f $ev, $p.FileSystemRights, $Target) `
          -Evidence $Target `
          -Remediation 'Restrict this permission to the service account / administrators that need it.'
        return
      }
    }
  }
}

function Get-InstalledApplications {
  $roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    $arch = if ($root -match 'Wow6432Node') { 'x86' } else { 'x64' }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      if ($props -and $props.DisplayName) {
        [pscustomobject]@{
          Computername = $env:COMPUTERNAME
          Software     = $props.DisplayName
          Version      = $props.DisplayVersion
          Publisher    = $props.Publisher
          InstallDate  = $props.InstallDate
          Architecture = $arch
        }
      }
    }
  }
}

function Get-NtlmPolicySummary {
  try {
    $msv = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction Stop
  }
  catch { return $null }
  $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  return [pscustomobject]@{
    RestrictReceiving = $msv.RestrictReceivingNTLMTraffic
    RestrictSending   = $msv.RestrictSendingNTLMTraffic
    LmCompatibility   = if ($lsa) { $lsa.LmCompatibilityLevel } else { $null }
  }
}

function Get-AdcsSchannelInfo {
  $info = [ordered]@{
    MappingValue = $null
    UpnMapping   = $false
    ServiceState = $null
  }
  try {
    $schannel = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name 'CertificateMappingMethods' -ErrorAction Stop
    $info.MappingValue = $schannel.CertificateMappingMethods
    if (($schannel.CertificateMappingMethods -band 0x4) -eq 0x4) { $info.UpnMapping = $true }
  }
  catch { }
  $svc = Get-Service -Name certsrv -ErrorAction SilentlyContinue
  if ($svc) { $info.ServiceState = $svc.Status }
  return [pscustomobject]$info
}

function Get-SecretPatterns {
  $p = [ordered]@{}
  $p['Winlogon credential']        = '(?i)(DefaultPassword|AltDefaultPassword)\s*='
  $p['Autologon enabled']          = '(?i)AutoAdminLogon\s*=\s*1'
  $p['Password assignment']        = '(?i)\bpass(word)?\s*[=:]\s*\S{4,}'
  $p['Username assignment']        = '(?i)\b(user(name)?|login)\s*[=:]\s*\S+'
  $p['Basic auth URL']             = '://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.]+'
  $p['Private key block']          = '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----'
  $p['AWS access key']             = '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
  $p['GitHub token']               = '(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{20,}'
  $p['GitHub fine-grained token']  = 'github_pat_[0-9a-zA-Z_]{20,}'
  $p['GitLab token']               = 'glpat-[0-9a-zA-Z\-]{15,}'
  $p['Slack token']                = 'xox[baprs]-[0-9a-zA-Z\-]{10,}'
  $p['Slack webhook']              = 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
  $p['OpenAI-style key']           = 'sk-[A-Za-z0-9_\-]{20,}'
  $p['Google API key']             = 'AIza[0-9A-Za-z_\-]{35}'
  $p['Azure storage key']          = 'AccountKey=[a-zA-Z0-9+/=]{40,}'
  $p['SendGrid key']               = 'SG\.[a-zA-Z0-9_\-]{10,}'
  $p['Twilio key']                 = 'SK[0-9a-fA-F]{32}'
  $p['Mailchimp key']              = '[0-9a-f]{32}-us[0-9]{1,2}'
  $p['Stripe key']                 = '(sk|pk)_(test|live)_[0-9a-zA-Z]{10,}'
  $p['JWT']                        = 'ey[0-9a-zA-Z_\-]{15,}\.ey[0-9a-zA-Z_\-]{15,}\.[0-9a-zA-Z_\-]{10,}'
  $p['Teamcity/NTLM hash shape']   = '(?i)[a-f0-9]{32}:[a-f0-9]{32}'
  $p['Connection string w/ pwd']   = '(?i)(connectionstring|connstr).{0,80}pwd\s*='
  $p['Net user add (history)']     = '(?i)net user .+ /add'
  return $p
}

$script:SecretPatterns = Get-SecretPatterns

$script:SensitiveFileTargets = @(
  "$env:windir\Panther\Unattend.xml"
  "$env:windir\Panther\unattend.xml"
  "$env:windir\System32\Sysprep\unattend.xml"
  "$env:windir\System32\Sysprep\unattended.xml"
  'C:\Windows\sysprep\sysprep.xml'
  'C:\Windows\sysprep\sysprep.inf'
  'C:\Windows\sysprep.inf'
  'C:\unattend.txt'
  'C:\unattend.inf'
  "$env:USERPROFILE\.aws\credentials"
  "$env:USERPROFILE\.azure\accessTokens.json"
  "$env:USERPROFILE\.azure\azureProfile.json"
  "$env:USERPROFILE\AppData\Roaming\gcloud\credentials.db"
  "$env:USERPROFILE\AppData\Roaming\gcloud\access_tokens.db"
  "$env:USERPROFILE\.kube\config"
  "$env:USERPROFILE\.docker\config.json"
  "$env:USERPROFILE\.netrc"
  "$env:USERPROFILE\.git-credentials"
  "$env:USERPROFILE\_netrc"
)

function Test-FileForSecrets {
  param([string]$Path, [string]$Context = '')
  if (-not (Test-Path $Path -PathType Leaf)) { return }
  $lines = $null
  try { $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue } catch { return }
  if (-not $lines) { return }
  $seenPatterns = @{}
  $lineNo = 0
  foreach ($line in $lines) {
    $lineNo++
    foreach ($name in $script:SecretPatterns.Keys) {
      if ($seenPatterns.ContainsKey($name)) { continue }
      $m = [regex]::Match($line, $script:SecretPatterns[$name])
      if ($m.Success) {
        $seenPatterns[$name] = $true
        $red = Get-Redacted ($m.Value)
        Add-Finding -Severity High -Category 'Exposed secret (file)' `
          -Title ("Credential pattern '{0}' in {1}" -f $name, (Split-Path $Path -Leaf)) `
          -Detail ("File: $Path line $lineNo$Context. Value redacted: $red") `
          -Evidence ("{0}:{1}" -f $Path, $lineNo) `
          -Remediation 'Remove/rotate the credential; move secrets to a vault or managed identity; restrict file ACLs.'
      }
    }
  }
}

$script:IsElevated = $false
try {
  $script:IsElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
$script:ElevGated = 'audit policy, secedit password/lockout baseline, bcdedit test-signing/code-integrity, Security event-log size, BitLocker status, WMI permanent-subscription enumeration, NetworkList connectivity history, IIS applicationHost deep config, and other users'' RDP/process history'
Write-Host ''
if ($script:IsElevated) {
  Write-Host '[+] Running ELEVATED - full check coverage.' -ForegroundColor Green
}
else {
  Write-Host '[!] Running NON-ELEVATED - some checks are limited or skipped.' -ForegroundColor Yellow
  Write-Host ('    Elevation-gated: ' + $script:ElevGated) -ForegroundColor DarkYellow
  Write-Host '    Re-run from an elevated prompt for a complete audit.' -ForegroundColor DarkYellow
}
Add-Finding -Severity $(if ($script:IsElevated) { 'Info' } else { 'Low' }) -Category 'Scan' `
  -Title $(if ($script:IsElevated) { 'Scan ran elevated (full coverage)' } else { 'Scan ran NON-elevated (partial coverage)' }) `
  -Detail $(if ($script:IsElevated) { 'Administrator context - all checks attempted.' } else { 'Standard-user context. These checks were limited or skipped: ' + $script:ElevGated + '.' }) `
  -Remediation $(if ($script:IsElevated) { 'None.' } else { 'Re-run from an elevated PowerShell prompt for complete, trustworthy results.' })

Start-Section 'SYSTEM INFORMATION'
$os = Get-CimInstance Win32_OperatingSystem
Add-Finding -Severity Info -Category 'System' -Title 'OS baseline' `
  -Detail ("{0} (build {1}) | installed {2:yyyy-MM-dd} | last boot {3:yyyy-MM-dd HH:mm} | {4} GB RAM" -f `
    $os.Caption, $os.BuildNumber, $os.InstallDate, $os.LastBootUpTime, [math]::Round($os.TotalVisibleMemorySize/1MB,1))

$latestHF = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1
if ($latestHF -and $latestHF.InstalledOn) {
  $age = (Get-Date) - $latestHF.InstalledOn
  if ($age.Days -gt 60) {
    Add-Finding -Severity High -Category 'Patching' -Title 'No patches installed in over 60 days' `
      -Detail ("Most recent hotfix {0} installed {1:yyyy-MM-dd} ({2} days ago)." -f $latestHF.HotFixID, $latestHF.InstalledOn, $age.Days) `
      -Remediation 'Patch cadence is stale; inventory missing CVEs and expedite critical/security updates.'
  }
  else {
    Add-Finding -Severity Info -Category 'Patching' -Title 'Patch cadence OK' `
      -Detail ("Most recent hotfix {0} {1} days ago." -f $latestHF.HotFixID, $age.Days)
  }
}

try {
  $pendingReboot = $false
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingReboot = $true }
  $fro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
  if ($fro.PendingFileRenameOperations) { $pendingReboot = $true }
  if ($pendingReboot) {
    Add-Finding -Severity Medium -Category 'Patching' -Title 'Reboot pending' `
      -Detail 'Updates staged but not finalized until reboot - host may still be vulnerable to patched CVEs.' `
      -Remediation 'Schedule reboot maintenance window.'
  }
} catch { }

Start-Section 'DEFENDER / AV POSTURE'
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  if ($mp.AMServiceEnabled) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender realtime protection ON' -Detail ("Engine {0}, signatures {1:yyyy-MM-dd HH:mm}" -f $mp.AMEngineVersion, $mp.AntivirusSignatureLastUpdated)
  }
  else {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender realtime protection OFF' `
      -Remediation 'Re-enable realtime protection; investigate why it was disabled (often attacker first action).'
  }
  if ($mp.AntivirusSignatureLastUpdated -and ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days -gt 3) {
    Add-Finding -Severity High -Category 'AV' -Title 'AV signatures stale' `
      -Detail ("Last updated {0:yyyy-MM-dd}" -f $mp.AntivirusSignatureLastUpdated) `
      -Remediation 'Force signature update; check connectivity to definition sources.'
  }
  if ($mp.QuickScanEndTime) {
    $scanAge = (Get-Date) - $mp.QuickScanEndTime
    if ($scanAge.Days -gt 14) {
      Add-Finding -Severity Medium -Category 'AV' -Title 'Quick scan not run in 14+ days' `
        -Detail ("Last quick scan {0:yyyy-MM-dd}" -f $mp.QuickScanEndTime) -Remediation 'Schedule regular quick scans.'
    }
  }
  else {
    Add-Finding -Severity Medium -Category 'AV' -Title 'No record of a Defender quick scan' -Remediation 'Run a baseline scan and enable scheduled scanning.'
  }
  $prefs = Get-MpPreference -ErrorAction SilentlyContinue
  $excl = @()
  if ($prefs) {
    $excl += $prefs.ExclusionPath
    $excl += $prefs.ExclusionProcess
    $excl += $prefs.ExclusionExtension
  }

  $exclPartial = -not $script:IsElevated
  if ($excl.Count -gt 0) {
    $suffix = if ($exclPartial) { ' - PARTIAL, needs elevation' } else { '' }
    $warn = if ($exclPartial) { ' || WARNING: this list is incomplete - a non-elevated caller sees only a subset. Re-run elevated for the true count.' } else { '' }
    Add-Finding -Severity High -Category 'AV' -Title ('Defender exclusions configured ({0}{1})' -f $excl.Count, $suffix) `
      -Detail ('Exclusions: ' + (($excl | Where-Object { $_ }) -join ' | ') + $warn) `
      -Remediation 'Review every exclusion for necessity; attackers commonly add their tool paths here. Remove any that are not documented.'
  }
  elseif ($exclPartial) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender exclusions not assessed (needs elevation)' `
      -Detail 'Get-MpPreference returned no exclusions, but a non-elevated caller cannot see the full list. Absence here is not evidence that none are configured.' `
      -Remediation 'Re-run elevated to enumerate Defender exclusions.'
  }
}
catch {
  Add-Finding -Severity Info -Category 'AV' -Title 'Defender status unavailable' -Detail 'Get-MpComputerStatus failed (non-Defender AV or older OS). Verify AV presence manually.'
}

Start-Section 'AUDITING & LOGGING POSTURE'
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed (needs elevation)' `
    -Detail 'auditpol /get requires administrator; run elevated to verify Logon/Logoff, Privilege Use and Object Access auditing.'
}
else {
  try {
    $auditPolicy = (auditpol.exe /get /category:* 2>$null | Where-Object { $_ -match '^\s' })
    if (-not $auditPolicy) {
      Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy unreadable' -Detail 'auditpol returned no data even when elevated.'
    }
    else {
      $lapse = $auditPolicy | Where-Object { $_ -match 'Logon/Logoff|Privilege Use|Object Access' -and $_ -match 'No Auditing' }
      if ($lapse) {
        Add-Finding -Severity Medium -Category 'Logging' -Title 'Critical audit subcategories set to No Auditing' `
          -Detail (($lapse | ForEach-Object { $_.Trim() }) -join ' ; ') `
          -Remediation 'Enable auditing for Logon/Logoff and Privilege Use (advanced audit policy: AuditLogon, AuditPrivilegeUse).'
      }
      else {
        Add-Finding -Severity Info -Category 'Logging' -Title 'Core audit categories enabled'
      }
    }
  } catch { }
}

try {
  $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
  $mb = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
  if ($mb -lt 128) {
    Add-Finding -Severity Medium -Category 'Logging' -Title "Security event log small ($mb MB)" `
      -Remediation 'Increase Security log size (>= 256 MB) or forward to SIEM (WEF) to avoid losing intrusion evidence.'
  }
  else {
    Add-Finding -Severity Info -Category 'Logging' -Title "Security event log size ${mb} MB"
  }
}
catch {
  if (-not $script:IsElevated) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Security event log not assessed (needs elevation)' `
      -Detail 'Reading the Security log configuration requires administrator; run elevated to check its size/retention.'
  }
}

if (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager') {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Windows Event Forwarding configured'
}
else {
  Add-Finding -Severity Low -Category 'Logging' -Title 'No Windows Event Forwarding' `
    -Detail 'Local logs die with the host; attackers clear logs post-incident.' `
    -Remediation 'Deploy WEF or a log agent so security events reach a central SIEM.'
}

$psLogPaths = @(
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'Script Block Logging' },
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';     Name = 'Module Logging' },
  @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';     Name = 'Transcription' }
)
foreach ($lp in $psLogPaths) {
  $key = Get-ItemProperty -Path $lp.Path -ErrorAction SilentlyContinue
  $on = $key -and (($key.EnableModuleLogging -eq 1) -or ($key.EnableTranscripting -eq 1) -or ($key.EnableScriptBlockLogging -eq 1) -or ($key.PSObject.Properties.Name -contains 'EnableScriptBlockLogging' -and $key.EnableScriptBlockLogging -ne 0))
  if ($on) {
    Add-Finding -Severity Info -Category 'Logging' -Title ('PowerShell {0} enabled' -f $lp.Name)
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell {0} NOT enabled' -f $lp.Name) `
      -Detail 'Attacker tooling (and abusive admins) rely on PowerShell flying under the radar.' `
      -Remediation ('Enable {0} via GPO for command-line visibility.' -f $lp.Name)
  }
}

Start-Section 'CREDENTIAL EXPOSURE'

$wdigest = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
if ($wdigest -eq 1) {
  Add-Finding -Severity High -Category 'Credentials' -Title 'WDigest storing plaintext credentials in LSASS' `
    -Detail 'UseLogonCredential=1 - any LSASS dump yields live passwords.' `
    -Remediation 'Set UseLogonCredential=0 (default on 8.1+/2012R2+); combine with Credential Guard.'
}
else {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'WDigest plaintext storage disabled'
}

$runAsPPL = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -ErrorAction SilentlyContinue).RunAsPPL
if ($runAsPPL -eq 1 -or $runAsPPL -eq 2) {
  Add-Finding -Severity Info -Category 'Credentials' -Title "LSA Protection enabled (RunAsPPL=$runAsPPL)"
}
else {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'LSA Protection (RunAsPPL) not enabled' `
    -Remediation 'Enable RunAsPPL=1 via GPE: Computer Config > Admin Templates > System > Local Run As PPL.'
}

$lsaCfg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -ErrorAction SilentlyContinue).LsaCfgFlags
if ($lsaCfg -eq 1 -or $lsaCfg -eq 2) {
  Add-Finding -Severity Info -Category 'Credentials' -Title "Credential Guard enabled (LsaCfgFlags=$lsaCfg)"
}
else {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard not enabled' `
    -Remediation 'Enable Credential Guard (hardware virtualization) to harden LSASS against dump-and-reuse.'
}

$cached = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).CACHEDLOGONSCOUNT
if ($null -ne $cached -and $cached -gt 4) {
  Add-Finding -Severity Low -Category 'Credentials' -Title "Cached domain logon count high ($cached)" `
    -Remediation 'Reduce CACHEDLOGONSCOUNT to <= 4 (MS baseline) to limit offline credential extraction.'
}

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

if (Test-Path 'HKCU:\Software\OpenSSH\Agent\Keys') {
  $n = (Get-Item 'HKCU:\Software\OpenSSH\Agent\Keys').Property.Count
  Add-Finding -Severity Medium -Category 'Credentials' -Title "$n SSH key(s) registered in ssh-agent" `
    -Remediation 'Verify these are authorized; ssh-agent keys are extractable by SYSTEM-level code.'
}

foreach ($p in @("$env:USERPROFILE\AppData\Roaming\Microsoft\Protect", "$env:USERPROFILE\AppData\Local\Microsoft\Protect")) {
  if (Test-Path $p) { Add-Finding -Severity Info -Category 'Credentials' -Title "DPAPI master key store present ($p)" }
}

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

if (Test-Path "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite") {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'Sticky Notes database present' `
    -Detail 'Sticky Notes frequently contain passwords in plaintext (plum.sqlite).' `
    -Remediation 'Educate users; consider disabling Sticky Notes on sensitive hosts.'
}

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

Start-Section 'PRIVILEGE-ESCALATION SURFACE'

foreach ($hive in 'HKLM', 'HKCU') {
  $aie = (Get-ItemProperty "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($aie -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title "AlwaysInstallElevated=1 ($hive)" `
      -Detail 'Any MSI (including malicious) installs with SYSTEM privileges.' `
      -Remediation 'Set AlwaysInstallElevated=0 in both hives (or leave the policy undefined).'
  }
}

$services = Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -inotmatch '"' -and $_.PathName -inotmatch ':\\Windows\\' -and $_.State -in @('Running', 'Stopped')
}
$unquoted = @($services | Where-Object { $_.PathName -match '^\S*\s' })
if ($unquoted.Count -gt 0) {
  foreach ($s in ($unquoted | Select-Object -First 10)) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("Unquoted service path: {0}" -f $s.Name) `
      -Detail ("Path: {0} | StartMode: {1} | State: {2}" -f $s.PathName, $s.StartMode, $s.State) `
      -Remediation 'Wrap the service ImagePath in quotes; ensure parent directories are not user-writable.'
  }
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'No unquoted service paths outside Windows dirs'
}

Write-Host '  Scanning service binary ACLs (this takes a moment)...' -ForegroundColor DarkGray
$UniqueServices = @{}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -like '*.exe*' } | ForEach-Object {
  try {
    $Path = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
    if ($Path -and -not $UniqueServices.ContainsKey($Path)) { $UniqueServices[$Path] = $_.Name }
  } catch { }
}
foreach ($h in $UniqueServices.GetEnumerator()) {
  Start-ACLCheck -Target $h.Name -ServiceName $h.Value
}

foreach ($svcKey in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\services' -ErrorAction SilentlyContinue | Select-Object -First 400)) {
  $target = $svcKey.Name.Replace('HKEY_LOCAL_MACHINE', 'hklm:')
  $acl = $null
  try { $acl = Get-Acl $target -ErrorAction SilentlyContinue } catch { continue }
  if (-not $acl) { continue }
  $weak = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and
    ("$($_.RegistryRights)" -match 'FullControl|ChangePermissions|TakeOwnership')
  }
  if ($weak) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("Service registry key world-modifiable: {0}" -f $svcKey.PSChildName) `
      -Detail ("{0} grants {1} to {2} - editable ImagePath yields SYSTEM." -f $target, $weak[0].RegistryRights, $weak[0].IdentityReference) `
      -Remediation 'Restrict the key to Administrators/SYSTEM.'
  }
}

foreach ($startup in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                       "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
  if (Test-Path $startup) {
    $items = @(Get-ChildItem $startup -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
      if ($i.PSIsContainer) { continue }
      $acl = Get-Acl $i.FullName -ErrorAction SilentlyContinue
      $w = $acl | ForEach-Object { $_.Access | Where-Object { $_.IdentityReference -match 'BUILTIN\\Users|Everyone' -and "$($_.FileSystemRights)" -match 'FullControl|Modify|Write' } }
      if ($w) {
        Add-Finding -Severity High -Category 'PrivEsc' -Title ("User-writable startup item: {0}" -f $i.Name) `
          -Detail $i.FullName -Evidence $i.FullName `
          -Remediation 'Persistence point: any user can plant malware executed at admin logon. Restrict ACLs, remove stale entries.'
      }
    }
  }
}

foreach ($rk in @('registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $item = Get-Item $rk -ErrorAction SilentlyContinue
  if ($item -and $item.Property) {
    foreach ($p in $item.Property) {
      $val = (Get-ItemProperty $rk).$p
      Add-Finding -Severity Low -Category 'Persistence' -Title ("Autorun entry: {0}" -f $p) `
        -Detail ("{0} = {1}" -f $rk.Replace('registry::', ''), $val) `
        -Remediation 'Validate each entry against a known-good baseline; autoruns are the #1 malware persistence slot.'
    }
  }
}

try {
  Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | ForEach-Object {
    $task = $_
    foreach ($a in @($task.Actions)) {
      if (-not $a.Execute) { continue }
      $exe = $a.Execute.Replace('"', '')
      foreach ($envPair in @(@('%windir%', $env:windir), @('%SystemRoot%', $env:windir),
                             @('%localappdata%', "$env:UserProfile\AppData\local"), @('%appdata%', $env:AppData))) {
        $exe = $exe -replace [regex]::Escape($envPair[0]), $envPair[1]
      }
      $exe = ($exe -split '(?<=\.exe\b)')[0].Trim('"')
      if (Test-Path $exe) { Start-ACLCheck -Target $exe -ServiceName ("task: " + $task.TaskName) }
    }
  }
} catch { }

$privs = whoami.exe /all
foreach ($dangerPriv in @('SeImpersonatePrivilege', 'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                          'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege', 'SeCreateTokenPrivilege', 'SeTcbPrivilege',
                          'SeAssignPrimaryTokenPrivilege')) {
  if ($privs | Select-String $dangerPriv | Where-Object { $_ -match 'Enabled' }) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("Current user holds {0}" -f $dangerPriv) `
      -Detail 'Dangerous privilege - standard tooling can turn this into SYSTEM or credential access.' `
      -Remediation 'Remove the account from the granting group/local policy (e.g. Administrators, Backup Operators) unless operationally required.'
  }
}

$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacProps = Get-ItemProperty $uacKey -ErrorAction SilentlyContinue
$hasLUA = $uacProps -and ($uacProps.PSObject.Properties.Name -contains 'EnableLUA')
$enableLUA = $uacProps.EnableLUA
if (-not $hasLUA) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'UAC EnableLUA value is absent from the registry' `
    -Detail ('{0} has no EnableLUA value. Windows ships with it set to 1, so its absence means it was removed. Confirm behaviourally: if an elevation request succeeds with no consent prompt, UAC is not protecting this host.' -f $uacKey) `
    -Evidence $uacKey `
    -Remediation 'Recreate EnableLUA (DWORD) = 1 and reboot, then investigate what removed it.'
}
elseif ($enableLUA -ne 1) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title ('UAC disabled (EnableLUA = {0})' -f $enableLUA) `
    -Detail 'Every process launched by an administrator runs fully elevated with no consent prompt.' `
    -Remediation 'Set EnableLUA=1 and reboot.'
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'UAC enabled (EnableLUA = 1)'
}

if ($uacProps -and ($uacProps.PSObject.Properties.Name -contains 'ConsentPromptBehaviorAdmin') -and $uacProps.ConsentPromptBehaviorAdmin -eq 0) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'UAC set to elevate silently (ConsentPromptBehaviorAdmin = 0)' `
    -Detail 'Administrators are elevated with no prompt, so a compromised user-context process can take full admin unattended.' `
    -Remediation 'Set ConsentPromptBehaviorAdmin=5 (prompt for consent for non-Windows binaries) or higher.'
}

if ($uacProps -and $uacProps.LocalAccountTokenFilterPolicy -eq 1) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'Remote UAC restrictions disabled (LocalAccountTokenFilterPolicy = 1)' `
    -Detail 'Local administrator accounts receive a full token over the network, enabling pass-the-hash and remote admin-share access with local credentials.' `
    -Evidence $uacKey `
    -Remediation 'Delete LocalAccountTokenFilterPolicy unless a remote-management tool documents needing it; prefer domain accounts for remote admin.'
}

$pn = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -ErrorAction SilentlyContinue
if ($pn) {
  if ($pn.RestrictDriverInstallationToAdministrators -eq 0 -and $pn.NoWarningNoElevationOnInstall -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title 'PointAndPrint policy allows non-admin printer drivers' `
      -Detail 'Known PrintNightmare-style driver install path to SYSTEM.' `
      -Remediation 'Set RestrictDriverInstallationToAdministrators=1; remove NoWarningNoElevationOnInstall.'
  }
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'No PointAndPrint policy override (server default applies)'
}

$wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
$wuServer = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue).WUServer
if ($wu.UseWUServer -eq 1 -and $wuServer -match '^http://') {
  Add-Finding -Severity Critical -Category 'PrivEsc' -Title 'WSUS configured over unencrypted HTTP' `
    -Detail ("Server: {0} - update content can be intercepted/tampered (fake-update -> SYSTEM)." -f $wuServer) `
    -Remediation 'Move WSUS to HTTPS with certificate pinning or enforce TLS.'
}

foreach ($samPath in @("$env:windir\repair\SAM", "$env:windir\System32\config\RegBack\SAM",
                       "$env:windir\repair\system", "$env:windir\System32\config\RegBack\system")) {
  if (Test-Path $samPath -ErrorAction SilentlyContinue) {
    Add-Finding -Severity High -Category 'Credentials' -Title "SAM/SYSTEM hive copy exposed: $samPath" `
      -Detail 'Offline hash extraction -> pass-the-hash against every local account.' `
      -Remediation 'Delete stale hive backups; restrict NTFS ACLs on config dirs.'
  }
}

Start-Section 'NETWORK ATTACK SURFACE'

$smb1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.EnableSMB1Protocol) {
  Add-Finding -Severity Critical -Category 'Network' -Title 'SMBv1 enabled' `
    -Detail 'WannaCry/NotPetya-class wormable protocol, no signing or encryption guarantees.' `
    -Remediation 'Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false (also disable on client).'
}
elseif ($smb1) {
  Add-Finding -Severity Info -Category 'Network' -Title 'SMBv1 disabled'
}

if ($smb1) {
  if (-not $smb1.RequireSecuritySignature) {
    Add-Finding -Severity Medium -Category 'Network' -Title 'SMB signing not required (server)' `
      -Detail 'Enables relay/NTLM interception attacks against this host.' `
      -Remediation 'Set-SmbServerConfiguration -RequireSecuritySignature $true.'
  }
  else {
    Add-Finding -Severity Info -Category 'Network' -Title 'SMB signing required (server)'
  }
}

try {
  $llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
  if ($llmnr -eq 0) { Add-Finding -Severity Info -Category 'Network' -Title 'LLMNR disabled by policy' }
  else {
    Add-Finding -Severity High -Category 'Network' -Title 'LLMNR not disabled' `
      -Detail 'Poisonable name-resolution protocol; anyone on-segment can capture NTLM hashes.' `
      -Remediation 'GPO: EnableMulticast=0 (Administrative Templates > Network > DNS Client > Turn off multicast name resolution).'
  }
} catch { }
try {
  $nbtf = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
  $nbtKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
  $nbtOn = $false
  foreach ($nk in $nbtKeys) {
    if ((Get-ItemProperty $nk.PSPath -ErrorAction SilentlyContinue).NetbiosOptions -ne 2) { $nbtOn = $true }
  }
  if ($nbtOn) {
    Add-Finding -Severity Medium -Category 'Network' -Title 'NetBIOS name resolution active on some interfaces' `
      -Remediation 'Set NetbiosOptions=2 (disable) per interface via policy.'
  }
  else {
    Add-Finding -Severity Info -Category 'Network' -Title 'NetBIOS resolution disabled'
  }
} catch { }

$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
$rdpEnabled = -not ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1)
if ($rdpEnabled) {
  Add-Finding -Severity Info -Category 'Network' -Title 'RDP enabled'
  if ($ts.UserAuthentication -eq 0) {
    Add-Finding -Severity High -Category 'Network' -Title 'RDP without Network Level Authentication (NLA)' `
      -Remediation 'Require NLA (System Properties > Remote > allow only with NLA).'
  }
  if ($ts.SecurityLayer -eq 0) {
    Add-Finding -Severity Medium -Category 'Network' -Title 'RDP SecurityLayer=0 (native RDP encryption)' `
      -Remediation 'Set SecurityLayer=2 (TLS 1.0+).'
  }
}
else {
  Add-Finding -Severity Info -Category 'Network' -Title 'RDP disabled'
}

try {
  foreach ($prof in (Get-NetFirewallProfile -ErrorAction Stop)) {
    if (-not $prof.Enabled) {
      Add-Finding -Severity High -Category 'Network' -Title ("Firewall profile '{0}' disabled" -f $prof.Name) `
        -Remediation 'Enable all firewall profiles via GPO.'
    }
  }
  Add-Finding -Severity Info -Category 'Network' -Title 'Firewall profile states recorded'
}
catch { }

$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalAddress -notmatch '::1|127\.0\.0\.1' } |
  Select-Object LocalAddress, LocalPort, OwningProcess
if ($ports) {
  $grouped = $ports | Group-Object LocalPort | Sort-Object { [int]$_.Name }
  Add-Finding -Severity Info -Category 'Network' -Title ('{0} externally-listening TCP ports' -f $grouped.Count) `
    -Detail (($grouped | ForEach-Object { $_.Name }) -join ', ') `
    -Remediation 'Baseline expected services; investigate anything not in the standard build.'
  foreach ($risky in @{ 21 = 'FTP'; 23 = 'Telnet'; 69 = 'TFTP'; 445 = 'SMB'; 3389 = 'RDP'; 5985 = 'WinRM-HTTP'; 5986 = 'WinRM-HTTPS' }.GetEnumerator()) {
    if ($ports.LocalPort -contains [int]$risky.Key) {
      $sev = if ($risky.Key -in 23, 21) { 'High' } else { 'Low' }
      Add-Finding -Severity $sev -Category 'Network' -Title ("{0} (port {1}) listening" -f $risky.Value, $risky.Key) `
        -Remediation 'Confirm business need; telnet/FTP should be removed outright.'
    }
  }
}

try {
  $hostsEntries = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#].+\s' }
  if ($hostsEntries.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Network' -Title ('{0} active hosts-file entries' -f $hostsEntries.Count) `
      -Detail (($hostsEntries | Select-Object -First 10) -join ' | ') `
      -Remediation 'Hosts overrides can silently redirect auth traffic; verify each against the build baseline.'
  }
} catch { }

$wpad = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -ErrorAction SilentlyContinue)
$autoDetect = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).AutoDetectProxySettings
Add-Finding -Severity Info -Category 'Network' -Title 'WPAD status recorded' `
  -Detail ("HKCU AutoDetectProxySettings: {0} - if enabled, ensure WPAD is pinned/served only by trusted DHCP/DNS." -f $autoDetect)

try {
  Get-SmbShare -ErrorAction Stop | ForEach-Object {
    $share = $_
    if ($share.Name -eq 'IPC$' -or $share.Name -eq 'ADMIN$') { return }
    $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
    foreach ($a in @($access)) {
      if ($a.AccessRight -in 'Full','Change' -and $a.AccessControlType -eq 'Allow' -and
          "$($a.AccountName)" -match 'Everyone|Authenticated Users') {
        Add-Finding -Severity Medium -Category 'Network' -Title ("Share '{0}' writable by {1}" -f $share.Name, $a.AccountName) `
          -Detail ("Path: {0}" -f $share.Path) `
          -Remediation 'Restrict share permissions to required groups; writable Everyone-shares are lateral-movement and ransomware vectors.'
      }
    }
  }
} catch { }

Start-Section 'LOCAL ACCOUNT HYGIENE'
try {
  $minLen = (net accounts | Select-String 'minimum password length').ToString()
  $val = [int]($minLen -replace '[^\d]', '')
  if ($val -lt 12) {
    Add-Finding -Severity Medium -Category 'Accounts' -Title ("Minimum password length only {0}" -f $val) `
      -Remediation 'Raise minimum length to 14+ and pair with banned-password lists.'
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title "Minimum password length ${val}"
  }
} catch { }

try {
  $users = Get-LocalUser -ErrorAction Stop
  foreach ($u in $users) {
    if ($u.Enabled -and -not $u.PasswordRequired) {
      Add-Finding -Severity Critical -Category 'Accounts' -Title ("Account '{0}' has NO password requirement" -f $u.Name) `
        -Remediation 'Disable the account or require a password immediately.'
    }
    if (-not $u.Enabled) {
      Add-Finding -Severity Info -Category 'Accounts' -Title ("Disabled account: {0}" -f $u.Name)
    }
    if ($u.Enabled -and $u.PasswordExpires -eq $null -and $u.Name -ne $env:USERNAME) {
      Add-Finding -Severity Low -Category 'Accounts' -Title ("Account '{0}' password never expires" -f $u.Name) `
        -Remediation 'Rotate periodically or move to managed (LAPS) credentials.'
    }
  }
  $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
  Add-Finding -Severity Info -Category 'Accounts' -Title ('{0} local Administrators' -f @($admins).Count) `
    -Detail ((@($admins) | ForEach-Object { $_.Name }) -join ', ') `
    -Remediation 'Keep local admin membership minimal; prefer LAPS + just-in-time elevation.'
} catch { }

$lapsOk = (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') -or (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll') -or
  ((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) -or
  (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' -ErrorAction SilentlyContinue)
if ($lapsOk) {
  Add-Finding -Severity Info -Category 'Accounts' -Title 'LAPS (legacy or Windows LAPS) detected'
}
else {
  Add-Finding -Severity Medium -Category 'Accounts' -Title 'No LAPS management detected' `
    -Detail 'Shared/rotating local admin passwords enable Pass-the-Hash across the fleet.' `
    -Remediation 'Deploy Windows LAPS to randomize local admin passwords per host.'
}

try { $sessions = quser 2>$null; if ($sessions) { Add-Finding -Severity Info -Category 'Accounts' -Title 'Active sessions' -Detail (($sessions | Select-Object -Skip 1) -join ' | ') } } catch { }

try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  if ($bl.ProtectionStatus -eq 1) {
    Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker protection ON (system drive)'
  }
  else {
    Add-Finding -Severity Medium -Category 'Data' -Title 'BitLocker not protecting system drive' `
      -Remediation 'Enable BitLocker with TPM+PIN; stolen laptop = stolen data otherwise.'
  }
} catch {
  Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker status unavailable on this volume'
}

$lock = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).InactivityTimeoutSecs
if ($null -ne $lock -and [int]$lock -gt 900) {
  Add-Finding -Severity Low -Category 'Data' -Title "Screen lock timeout ${lock}s (>15 min)" `
    -Remediation 'Cap inactivity lock at 15 minutes or less via policy.'
}

Start-Section 'IDENTITY / DOMAIN POSTURE (LOCAL READ ONLY)'
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if ($cs -and $cs.PartOfDomain) {
  Add-Finding -Severity Info -Category 'AD' -Title 'Domain-joined' `
    -Detail ("Domain: {0} (read locally from Win32_ComputerSystem; no DC queried)" -f $cs.Domain)
  Add-Finding -Severity Info -Category 'AD' -Title 'Domain-side AD hygiene not assessed (by design)' `
    -Detail 'Kerberoastable SPNs, gMSA read permissions, DNS-zone ACLs and Kerberos time-skew require querying a domain controller and are intentionally out of scope for this passive host recon.' `
    -Remediation 'Run a dedicated AD audit from a management host for domain-side abuse paths.'
}
else {
  Add-Finding -Severity Info -Category 'AD' -Title 'Workgroup host (not domain-joined)' `
    -Detail ("Workgroup: {0}" -f $(if ($cs) { $cs.Workgroup } else { 'unknown' }))
}

$ntlm = Get-NtlmPolicySummary
if ($ntlm) {
  $lm = -1
  if ($null -ne $ntlm.LmCompatibility) { $lm = [int]$ntlm.LmCompatibility }
  if ($lm -ge 0 -and $lm -lt 3) {
    Add-Finding -Severity High -Category 'AD' -Title ("LmCompatibilityLevel={0} (accepts LM/NTLMv1)" -f $lm) `
      -Detail 'NTLMv1 downgrade = crackable challenge-response capture.' `
      -Remediation 'Set LmCompatibilityLevel=5 (refuse LM & NTLMv1).'
  }
  else {
    Add-Finding -Severity Info -Category 'AD' -Title 'NTLM minimum level acceptable (>=3)'
  }
}

$adcs = Get-AdcsSchannelInfo
if ($null -ne $adcs.MappingValue -and $adcs.UpnMapping) {
  Add-Finding -Severity High -Category 'AD' -Title ('Schannel UPN certificate mapping enabled (ESC10 pattern, 0x{0:X})' -f [int]$adcs.MappingValue) `
    -Remediation 'Clear the 0x4 UPN-mapping bit from CertificateMappingMethods.'
}

Start-Section 'INSTALLED SOFTWARE (baseline inventory)'
try {
  $apps = @(Get-InstalledApplications)
  Add-Finding -Severity Info -Category 'Software' -Title ('{0} installed applications recorded' -f $apps.Count) `
    -Detail 'Full inventory in reports; diff against build baseline to catch unauthorized software.'
  $riskyNames = @('VNC', 'Telnet', 'WinSCP', 'FileZilla', 'uTorrent', 'TeamViewer')
  foreach ($r in $riskyNames) {
    $hit = $apps | Where-Object { $_.Software -match $r }
    if ($hit) {
      Add-Finding -Severity Low -Category 'Software' -Title ("Remote-access/file-transfer software present: {0}" -f $r) `
        -Detail (($hit | Select-Object -First 3 | ForEach-Object { '{0} {1}' -f $_.Software, $_.Version }) -join ', ') `
        -Remediation 'Verify authorization; these tools frequently store credentials and bypass DLP.'
    }
  }
} catch { }

if ($FullCheck) {
  Start-Section 'DEEP SECRET-PATTERN SWEEP (-FullCheck; values redacted)'
  Write-Host '  Sweeping credential-bearing file locations and registry hives for secret patterns.' -ForegroundColor DarkGray
  Write-Host '  Matches are recorded REDACTED - no secret values are written to console or reports.' -ForegroundColor DarkGray

  $sweepDirs = @(
    "$env:USERPROFILE\.ssh"
    "$env:USERPROFILE\.aws"
    "$env:USERPROFILE\.azure"
    "$env:USERPROFILE\.kube"
    "$env:USERPROFILE\.config"
    "$env:USERPROFILE\AppData\Roaming"
    'C:\Windows\Temp'
    "$env:windir\Panther"
  ) | Where-Object { Test-Path $_ }

  $sweepExt = @('*.txt', '*.ini', '*.cfg', '*.conf', '*.config', '*.xml', '*.yml', '*.yaml', '*.json', '*.ps1', '*.bat', '*.cmd', '*.log')
  foreach ($dir in $sweepDirs) {
    Write-Host "  Sweeping $dir" -ForegroundColor DarkGray
    try {
      Get-ChildItem -LiteralPath $dir -Recurse -Include $sweepExt -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 1MB } | Select-Object -First 300 | ForEach-Object {
        Test-FileForSecrets -Path $_.FullName
      }
    } catch { }
  }

  $regTargets = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SYSTEM\CurrentControlSet\Services'
  )
  foreach ($rt in $regTargets) {
    if (-not (Test-Path $rt)) { continue }
    Get-ChildItem $rt -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000 | ForEach-Object {
      $key = $_
      foreach ($p in @($key.Property)) {
        $v = $null
        try { $v = (Get-ItemProperty $key.PSPath).$p } catch { continue }
        if ($null -eq $v -or $v -isnot [string] -or $v.Length -lt 8) { continue }
        foreach ($name in $script:SecretPatterns.Keys) {
          if ($v -match $script:SecretPatterns[$name]) {
            Add-Finding -Severity Medium -Category 'Exposed secret (registry)' `
              -Title ("Credential pattern '{0}' in registry value {1}\{2}" -f $name, $key.Name, $p) `
              -Detail ('Value redacted: ' + (Get-Redacted $v)) `
              -Evidence ($key.Name + '\' + $p) `
              -Remediation 'Remove the stored credential; rotate it and use a secrets manager.'
            break
          }
        }
      }
    }
  }
}

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

Start-Section 'SERVICE INVENTORY (listening ports + banners)'

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

foreach ($c in $listen) {
  if ($c.LocalAddress -match '^127\.|^::1') {
    continue   
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

$otPorts = @(502, 4840, 4843, 47808, 44818, 20000, 5010, 1911, 4911, 9600, 41794, 41795, 137, 5353)
$localOt = @($remoteListen | Where-Object { $otPorts -contains [int]$_.Port })
if ($localOt.Count -gt 0) {
  Add-Finding -Severity Medium -Category 'OT Services' -Title ('BMS/OT protocol listeners on this host: {0}' -f $localOt.Count) `
    -Detail (($localOt | ForEach-Object { '{0} ({1}) <- {2}' -f $_.Port, $_.Name, $_.Process }) -join ' | ') `
    -Remediation 'These are the crown jewels: enumerate owning software, version, and ensure zone firewall restricts who can reach them (IEC 62443 SR 5.1).'
}

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

Start-Section 'LOOPBACK / TUNNEL DETECTION'

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

$proxyOverride = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyOverride
if ($proxyOverride -match 'localhost|127\.') {
  Add-Finding -Severity Info -Category 'Loopback' -Title 'Proxy bypass includes localhost (standard config)'
}

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

  $iisVer = (Get-Item "$env:windir\System32\inetsrv\w3wp.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
  if ($iisVer) { Add-Finding -Severity Info -Category 'IIS' -Title "IIS engine version $iisVer" }

  if ($sm) {
    foreach ($site in $sm.Sites) {
      $bindings = ($site.Bindings | ForEach-Object {
        '{0}://{1}:{2}' -f $_.Protocol, $(if ($_.Host) { $_.Host } else { '*' }), $_.BindingInformation.Split(':')[-1]
      }) -join ', '
      Add-Finding -Severity Info -Category 'IIS' -Title ("Site '{0}' ({1})" -f $site.Name, $site.State) `
        -Detail ("Bindings: {0} | ID: {1}" -f $bindings, $site.Id) `
        -Remediation 'Baseline expected bindings; unknown sites = investigate.'
      if (-not ($site.Bindings | Where-Object { $_.Protocol -eq 'https' })) {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Site '{0}' has NO HTTPS binding" -f $site.Name) `
          -Detail 'Cleartext HTTP - credentials/cookies/session tokens readable on the wire.' `
          -Remediation 'Add an HTTPS binding with a valid cert; redirect HTTP to HTTPS; set HSTS.'
      }
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
  }
  else {
    Add-Finding -Severity Info -Category 'IIS' -Title 'IIS URL Rewrite module not installed'
  }

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
      if ($content -match '(?i)connectionstring\s*=.{0,200}password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title ("Plaintext DB password in {0}" -f $cfg.FullName) `
          -Detail 'Detected via pattern; value not recorded.' `
          -Remediation 'Move to encrypted connectionStrings sections or managed identities.'
      }
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
      if ($content -match '(?i)<deployment[^>]*retail\s*=\s*"false"') {
        Add-Finding -Severity Low -Category 'IIS' -Title ("deployment retail=false in {0}" -f $cfg.FullName) `
          -Remediation 'Set retail="true" on production servers (kills debug tracing + detailed errors).'
      }
      if ($content -match '(?i)<directorybrowse[^>]*enabled\s*=\s*"true"') {
        Add-Finding -Severity Medium -Category 'IIS' -Title ("Directory browsing enabled in {0}" -f $cfg.FullName) `
          -Remediation 'Disable directoryBrowse - leaks file inventory to attackers.'
      }
      Test-FileForSecrets -Path $cfg.FullName -Context ' (IIS web.config)'
    }
  }

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
      if ($ah -match '(?i)password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title 'Password-shaped value in applicationHost.config' `
          -Detail 'App-pool/service credentials stored in config are readable by admins and backup-exfiltration.' `
          -Remediation 'Use app-pool identities where possible; protect config backups.'
      }
    }
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

  foreach ($svc in @(@('FTPSVC', 'IIS FTP'), @('SMTPSVC', 'IIS SMTP'))) {
    $s = Get-Service $svc[0] -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Running') {
      Add-Finding -Severity Low -Category 'IIS' -Title ("{0} service running" -f $svc[1]) `
        -Remediation 'Confirm business need; FTP/SMTP legacy services widen attack surface (cleartext protocols).'
    }
  }
}

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

Start-Section 'OS VULNERABILITY SURFACE'

$osCim = Get-CimInstance Win32_OperatingSystem
$osName = $osCim.Caption
$build = [int]$osCim.BuildNumber
Add-Finding -Severity Info -Category 'OS' -Title ("OS: {0} (build {1})" -f $osName, $build)
$eolTable = @(
  @{ Match = 'Server 2019';    EOL = [datetime]'2029-01-09' }
  @{ Match = 'Server 2022';    EOL = [datetime]'2031-10-14' }
  @{ Match = 'Server 2025';    EOL = [datetime]'2034-10-10' }
  @{ Match = 'Server 2016';    EOL = [datetime]'2027-01-12' }
  @{ Match = 'Server 2012';    EOL = [datetime]'2023-10-10' }
  @{ Match = 'Windows 10';     EOL = [datetime]'2025-10-14' }
  @{ Match = 'Windows 11';     EOL = [datetime]'2028-10-10' }
)
foreach ($e in $eolTable) {
  if ($osName -like "*$($e.Match)*") {
    if ((Get-Date) -gt $e.EOL) {
      Add-Finding -Severity Critical -Category 'OS' -Title ("{0} is PAST END OF SUPPORT ({1:yyyy-MM-dd})" -f $osName, $e.EOL) `
        -Detail 'No security patches - every future CVE is permanent.' `
        -Remediation 'Plan migration/upgrade immediately; isolate the host meanwhile.'
    }
    elseif (((Get-Date) - $e.EOL).Days -gt -365) {
      Add-Finding -Severity Medium -Category 'OS' -Title ("{0} support ends {1:yyyy-MM-dd} (<1 year)" -f $osName, $e.EOL) `
        -Remediation 'Budget the upgrade now.'
    }
    else {
      Add-Finding -Severity Info -Category 'OS' -Title ("{0} supported until {1:yyyy-MM-dd}" -f $osName, $e.EOL)
    }
    break
  }
}

if ($osName -like '*Windows 11*' -and $build -lt 26100) {
  Add-Finding -Severity Medium -Category 'OS' -Title ("Windows 11 build {0} is behind (24H2 = 26100)" -f $build) `
    -Remediation 'Old Win11 builds fall out of servicing faster; update to the current feature update.'
}

foreach ($hive in @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols')) {
  $protos = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')
  foreach ($p in $protos) {
    $k = Join-Path $hive "$p\Server"
    $enabled = (Get-ItemProperty $k -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
    $disabled = (Get-ItemProperty $k -Name Enabled -ErrorAction SilentlyContinue).Enabled
    $active = if ($disabled -eq 0 -and $enabled -eq 1) { $true }
              elseif ($null -eq $disabled -and $null -eq $enabled) {
                if ($p -in 'TLS 1.2', 'TLS 1.3' -and $build -ge 17763) { $true }
                elseif ($p -in 'TLS 1.2', 'TLS 1.3') { $false } else { $false }
              } else { $false }
    if ($active -and $p -match 'SSL|TLS 1\.0|TLS 1\.1') {
      Add-Finding -Severity High -Category 'Crypto' -Title ("Weak protocol ACTIVE server-side: {0}" -f $p) `
        -Detail 'SSL/TLS1.0/1.1 fail PCI/DISAGDSS baselines; downgrade attacks (POODLE/BAR-MITZVAH class).' `
        -Remediation "Disable ${p} server and client side via SCHANNEL registry + reboot."
    }
  }
}
$activeProtos = @()
foreach ($p in @('TLS 1.2', 'TLS 1.3')) {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Server"
  $dis = (Get-ItemProperty $k -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
  if ($dis -eq 0 -or $null -eq $dis) { $activeProtos += $p }
}
if ($activeProtos.Count -gt 0) {
  Add-Finding -Severity Info -Category 'Crypto' -Title ("Modern TLS available: {0}" -f ($activeProtos -join ', '))
} else {
  Add-Finding -Severity High -Category 'Crypto' -Title 'No modern TLS protocol confirmed enabled' `
    -Remediation 'Explicitly enable TLS 1.2/1.3 server-side.'
}

try {

  $suites = @(Get-TlsCipherSuite -ErrorAction Stop)
  $cs = @($suites | ForEach-Object { $_.Name } | Where-Object { $_ })
  if ($cs.Count -eq 0) {
    Add-Finding -Severity Info -Category 'Crypto' -Title 'Cipher suite list not assessed' `
      -Detail 'Get-TlsCipherSuite returned no readable suite names; weak-cipher status is unknown, not clean.'
  }
  else {
    $weak = @($cs | Where-Object { $_ -match 'NULL|RC4|3DES|DES_' })
    if ($weak.Count -gt 0) {
      Add-Finding -Severity Medium -Category 'Crypto' -Title ("{0} of {1} enabled cipher suites are weak" -f $weak.Count, $cs.Count) `
        -Detail (($weak | Select-Object -First 8) -join ', ') `
        -Remediation 'Prune with Disable-TlsCipherSuite -Name <suite>; keep AEAD suites (GCM/ChaCha20) only.'
    }
    else {
      Add-Finding -Severity Info -Category 'Crypto' -Title ("{0} cipher suites enabled, none weak" -f $cs.Count)
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Crypto' -Title 'Cipher suite enumeration failed' `
    -Detail ('Get-TlsCipherSuite error: ' + $_.Exception.Message + '. Weak-cipher status not assessed.')
}

$fips = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsPolicyGroup' -ErrorAction SilentlyContinue).Enabled
$fips2 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name FipsAlgorithmPolicy -ErrorAction SilentlyContinue
Add-Finding -Severity Info -Category 'Crypto' -Title 'FIPS policy status recorded' `
  -Detail ("FipsAlgorithmPolicy present: {0}" -f [bool]$fips2)

try {
  $srv = Get-SmbServerConfiguration -ErrorAction Stop
  if ($srv.EnableSMB1Protocol) {
    Add-Finding -Severity Critical -Category 'Crypto' -Title 'SMBv1 server enabled' `
      -Detail 'EternalBlue/WannaCry class; no integrity or confidentiality.' `
      -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'
  }
  if (-not $srv.RequireSecuritySignature) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB signing not required (previously flagged; repeated in crypto context)'
  }
  $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
  if ($cli -and $cli.EnableSecuritySignature -eq $false -and $cli.RequireSecuritySignature -eq $false) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB client: signing neither enabled nor required' `
      -Remediation 'Require SMB client signing via GPO (NTLM relay defense).'
  }
} catch { }

$releaseKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
$netVer = if ($releaseKey) {
  if ($releaseKey -ge 533320) { '4.8.1+' } elseif ($releaseKey -ge 528040) { '4.8' }
  elseif ($releaseKey -ge 461808) { '4.7.2' } elseif ($releaseKey -ge 394802) { '4.6.2' } else { "4.x (release $releaseKey)" }
} else { 'unknown' }
Add-Finding -Severity Info -Category 'OS' -Title ".NET Framework: $netVer"
if ($netVer -match '^4\.[0-6]' ) {
  Add-Finding -Severity Medium -Category 'OS' -Title "Old .NET Framework ($netVer)" `
    -Remediation 'Upgrade to 4.8.x - older runtimes miss TLS1.2 defaults and security fixes.'
}
foreach ($v2v35 in @('v2.0.50727', 'v3.0', 'v3.5')) {
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\$v2v35") {
    Add-Finding -Severity Low -Category 'OS' -Title ".NET $v2v35 runtime present" `
      -Remediation 'Remove if no apps depend on it (legacy attack surface).'
  }
}

try {
  $feats = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -match 'PowerShellV2|SMB1Protocol|TelnetClient|TFTPClient|NetFx3|IIS-.*Basicauth' }
  foreach ($f in @($feats)) {
    $sev = if ($f.FeatureName -match 'SMB1|PowerShellV2') { 'High' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'OS' -Title ("Legacy feature enabled: {0}" -f $f.FeatureName) `
      -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName <name> - remove unless explicitly required (PowerShellv2 = downgrade attacks, SMB1 = wormable).'
  }
} catch { }

foreach ($runtimeVer in @('v2.0.50727', 'v4.0.30319')) {
  foreach ($bit in @('64', '32')) {
    $mc = "$env:windir\Microsoft.NET\Framework$($bit)\$runtimeVer\CONFIG\machine.config"
    $mcPath = $mc -replace 'Framework64', 'Framework'
    if ($bit -eq '64') { $mcPath = $mc }
    if (Test-Path $mcPath) {
      $c = $null
      try { $c = Get-Content $mcPath -Raw -ErrorAction SilentlyContinue } catch { }
      if ($c -and $c -notmatch 'SchUseStrongCrypto"?\s*=\s*"?true' -and $runtimeVer -eq 'v4.0.30319') {
        Add-Finding -Severity Low -Category 'Crypto' -Title "SchUseStrongCrypto not set in machine.config ($bit-bit)" `
          -Detail 'Default .NET TLS defaults may allow weak protocol negotiation for legacy apps.' `
          -Remediation 'Set SchUseStrongCrypto=true in machine.config / registry UseStrongCrypto=1.'
      }
    }
  }
}

if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'OS' -Title 'Local security policy (secedit) not assessed (needs elevation)' `
    -Detail 'secedit /export requires administrator; run elevated to verify minimum password length, account-lockout threshold and anonymous-lookup policy.'
}
elseif ($true) {
try {
  $secOut = "$env:TEMP\winhostpeas_secedit.cfg"
  secedit /export /cfg $secOut /quiet 2>$null | Out-Null
  if (Test-Path $secOut) {
    $sec = Get-Content $secOut -ErrorAction SilentlyContinue
    $pl = ($sec | Select-String 'MinimumPasswordLength').Line
    if ($pl -match '=\s*(\d+)') {
      $minLen = [int]$Matches[1]
      if ($minLen -lt 14) {
        Add-Finding -Severity Medium -Category 'OS' -Title ("Password policy: minimum length {0} (<14)" -f $minLen) `
          -Remediation 'NIST/CIS: 14+ characters, length over complexity theater.'
      }
    }
    $lock = ($sec | Select-String 'LockoutBadCount').Line
    if ($lock -match '=\s*(\d+)') {
      $lb = [int]$Matches[1]
      if ($lb -eq 0) {
        Add-Finding -Severity Medium -Category 'OS' -Title 'Account lockout threshold: 0 (never locks)' `
          -Remediation 'Set lockout 5-10 attempts with timed reset (blocks brute force).'
      }
    }
    $lba = ($sec | Select-String 'LsaAnonymousNameLookup').Line
    if ($lba -match '=\s*1') {
      Add-Finding -Severity Medium -Category 'OS' -Title 'Anonymous SAM/LSA lookup enabled' `
        -Remediation 'Disable: LsaAnonymousNameLookup=0 (blocks null-session enumeration).'
    }
    $restrictAnon = ($sec | Select-String 'RestrictAnonymous(SAM)?\s*=').Line
    Add-Finding -Severity Info -Category 'OS' -Title 'Secedit baseline exported (password/lockout/anonymous policy recorded)'
    Remove-Item $secOut -Force -ErrorAction SilentlyContinue
  }
} catch { }
}

$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if ($ts) {
  if ($ts.MinEncryptionLevel -lt 3) {
    Add-Finding -Severity High -Category 'Crypto' -Title ("RDP encryption level {0} (low/client-compatible)" -f $ts.MinEncryptionLevel) `
      -Remediation 'Set MinEncryptionLevel=3 (High) minimum; pair with NLA + TLS SecurityLayer.'
  }
  if ($ts.SecurityLayer -eq 0) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'RDP SecurityLayer=0 (native RDP crypto instead of TLS)'
  }
}

if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'OS' -Title 'Boot config (bcdedit) not assessed (needs elevation)' `
    -Detail 'bcdedit /enum requires administrator; run elevated to detect test-signing mode and disabled code-integrity (nointegritychecks).'
}
else {
  $bcdTest = $null
  try { $bcdTest = (bcdedit /enum `{current`} 2>$null | Select-String 'testsigning\s+Yes') } catch { }
  if ($bcdTest) {
    Add-Finding -Severity High -Category 'OS' -Title 'Test signing mode enabled (bcdedit testsigning)' `
      -Detail 'Unsigned kernel drivers load freely - rootkit path.' `
      -Remediation 'bcdedit /set testsigning off; investigate why it was on.'
  }
  $nointegritychecks = $null
  try { $nointegritychecks = (bcdedit /enum `{current`} 2>$null | Select-String 'nointegritychecks\s+Yes') } catch { }
  if ($nointegritychecks) {
    Add-Finding -Severity High -Category 'OS' -Title 'Code-integrity checks disabled (nointegritychecks)' `
      -Remediation 'bcdedit /set nointegritychecks off (restores integrity enforcement); disabled CI allows unsigned code at boot.'
  }
}

$nullDevice = $null
try {
  $denyRdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
  if ($denyRdp -eq 0 -and $build -ge 17763) {
    Add-Finding -Severity Info -Category 'OS' -Title 'RDP enabled (modern build) - ensure NLA enforced and exposure firewalled'
  }
} catch { }

Start-Section 'PERSISTENCE DEEP-DIVE'

$wlg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wlg) {
  foreach ($val in @('Shell', 'Userinit', 'Taskman', 'System', 'VmApplet', 'AppSetup')) {
    $v = $wlg.$val
    if ($null -eq $v) { continue }
    $expected = @{ Shell = 'explorer.exe'; Userinit = 'C:\Windows\system32\userinit.exe,' }
    if ($expected.ContainsKey($val)) {
      if ($v -notlike "*$($expected[$val])*") {
        Add-Finding -Severity Critical -Category 'Persistence' -Title ("Winlogon {0} hijacked: {1}" -f $val, $v) `
          -Detail 'Executed at every logon as SYSTEM - classic Kovter-class persistence.' `
          -Remediation "Restore ${val} to its Windows default immediately; trace what installed it."
      }
    }
    elseif ($v) {
      Add-Finding -Severity Medium -Category 'Persistence' -Title ("Winlogon '{0}' configured: {1}" -f $val, $v) `
        -Remediation 'Verify this value against a clean image; non-default Winlogon values execute at logon.'
    }
  }
}

try {
  $subs = @()
  foreach ($nsName in @('root\subscription', "root\cimv2")) {
    $filter = Get-CimInstance -Namespace $nsName -ClassName __EventFilter -ErrorAction SilentlyContinue
    $binding = Get-CimInstance -Namespace $nsName -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    $consumer = @()
    $consumer += Get-CimInstance -Namespace $nsName -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    $consumer += Get-CimInstance -Namespace $nsName -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $consumer += Get-CimInstance -Namespace $nsName -ClassName CommandLineTemplateConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumer) {
      $linkedFilter = $binding | Where-Object { $_.Consumer -like "*$($c.Name)*" }
      $subs += [pscustomobject]@{
        Namespace = $nsName; Consumer = $c.__CLASS; Name = $c.Name
        Cmd = $c.CommandLineTemplate; Script = $c.ScriptText
        Filter = ($linkedFilter | Select-Object -First 1).Filter
      }
    }
  }
  if ($subs.Count -gt 0) {
    foreach ($s in ($subs | Select-Object -First 15)) {
      $detail = ("{0}\{1} ({2})" -f $s.Namespace, $s.Name, $s.Consumer)
      if ($s.Cmd) { $detail += " | Cmd: " + $s.Cmd }
      if ($s.Script) { $detail += " | Script present" }
      Add-Finding -Severity High -Category 'Persistence' -Title ("WMI event consumer: {0}" -f $s.Name) `
        -Detail $detail `
        -Remediation 'Permanent WMI subscriptions survive reboots and run as SYSTEM. Baseline a clean image; anything not from your build = remove + investigate.'
    }
  }
  elseif ($script:IsElevated) {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No WMI permanent event consumers'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'WMI event subscriptions not assessed (needs elevation)' `
      -Detail 'Enumerating root\subscription requires administrator; run elevated to detect WMI-based fileless persistence.'
  }
} catch { }

try {
  $hkcuClsid = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
  $count = @($hkcuClsid).Count
  if ($count -gt 0) {
    Add-Finding -Severity Medium -Category 'Persistence' -Title ("{0} per-user CLSID overrides in HKCU (COM hijack surface)" -f $count) `
      -Detail 'HKCU\Software\Classes\CLSID overrides HKLM COM registrations - a silent code-exec persistence slot invisible to per-machine audits.' `
      -Remediation 'Compare against a clean profile; watch InprocServer32/LocalServer32 default values pointing outside Windows/Program Files.'
    $suspicious = 0
    foreach ($k in ($hkcuClsid | Select-Object -First 300)) {
      $ips = Get-ItemProperty "$($k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
      if ($ips -and $ips.'(default)' -and "$($ips.'(default)')" -notmatch '^C:\\(Windows|Program Files)' -and $suspicious -lt 5) {
        Add-Finding -Severity High -Category 'Persistence' -Title ("HKCU COM server outside standard paths: {0}" -f $k.PSChildName) `
          -Detail ("DLL: {0}" -f $ips.'(default)') `
          -Remediation 'Verify; per-user COM DLLs loading from user-writable paths are hijack/persistence primitives.'
        $suspicious++
      }
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No per-user CLSID overrides (clean COM surface)'
  }
} catch { }

try {
  $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
  $debuggers = Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
    if ($d -and $d.Debugger) { [pscustomobject]@{ Exe = $_.PSChildName; Debugger = $d.Debugger } }
  }
  if (@($debuggers).Count -gt 0) {
    foreach ($d in $debuggers) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("IFEO Debugger on {0}" -f $d.Exe) `
        -Detail ("Debugger: {0} - runs INSTEAD of the target executable, as the caller." -f $d.Debugger) `
        -Remediation 'Legit uses are rare (some AV, legacy tools). Anything else = remove and investigate.'
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No IFEO debugger keys'
  }
  $spe = Get-ChildItem "$ifeoRoot" -ErrorAction SilentlyContinue | ForEach-Object {
    $g = Get-ItemProperty $_.PSPath -Name GlobalFlag -ErrorAction SilentlyContinue
    if ($g -and ($g.GlobalFlag -band 0x200)) {
      $s = Get-ItemProperty "$($_.PSPath)\SilentProcessExit" -Name MonitorProcess -ErrorAction SilentlyContinue
      if ($s -and $s.MonitorProcess) { [pscustomobject]@{ Exe = $_.PSChildName; Monitor = $s.MonitorProcess } }
    }
  }
  foreach ($s in @($spe)) {
    if ($s) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("SilentProcessExit monitor on {0}" -f $s.Exe) `
        -Detail ("MonitorProcess: {0}" -f $s.Monitor) `
        -Remediation 'Flag+SilentProcessExit persistence: remove GlobalFlag 0x200 and the MonitorProcess value unless documented.'
    }
  }
} catch { }

$appInit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
if ($appInit -and $appInit.AppInit_DLLs) {
  Add-Finding -Severity High -Category 'Persistence' -Title ("AppInit_DLLs set: {0}" -f $appInit.AppInit_DLLs) `
    -Detail 'Injects into every GUI process that loads user32.dll.' `
    -Remediation 'Clear AppInit_DLLs (disabled on modern Windows anyway); identify the DLL and treat as malicious until proven otherwise.'
}
else {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'AppInit_DLLs empty'
}

$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
foreach ($pkgName in @('Security Packages', 'Notification Packages')) {
  $pkgs = $lsa.$pkgName
  if ($pkgs) {
    $expected = @{ 'Security Packages' = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','ntlm'); 'Notification Packages' = @('scecli','rassfm','wdigest') }
    $extra = @($pkgs | ForEach-Object { "$_" } | Where-Object { ($_.Trim('"', ' ', "`t") -ne '') } |
      Where-Object { $expected[$pkgName] -notcontains $_.Trim().ToLower() })
    if ($extra.Count -gt 0) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Non-standard LSA {0}: {1}" -f $pkgName, ($extra -join ', ')) `
        -Detail 'LSA packages load into LSASS at boot as SYSTEM - credential-capture territory (mimikatz uses this).' `
        -Remediation 'Remove non-standard entries; verify the DLLs against the build baseline.'
    }
  }
}

try {
  foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
      $stub = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).StubPath
      if ($stub) {
        $known = ($_.PSChildName -match '^\{?[0-9A-Fa-f-]{36}\}?$') -and ($stub -match 'system32|Program Files')
        $sev = if ($stub -match 'user-writable|AppData|Temp|Public|Downloads') { 'High' } else { 'Low' }
        if ($stub -match 'AppData|\\Temp\\|\\Public\\|Downloads') {
          Add-Finding -Severity $sev -Category 'Persistence' -Title ("Active Setup StubPath in user-writable path: {0}" -f $_.PSChildName) `
            -Detail ("Command: {0}" -f $stub) `
            -Remediation 'StubPath runs at first logon of every user; user-writable stub = persistence + privilege escalation.'
        }
      }
    }
  }
} catch { }

try {
  $helpers = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Netsh' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'
    if ($p) { [pscustomobject]@{ Helper = $_.PSChildName; Dll = $p } }
  }
  foreach ($h in @($helpers)) {
    if ($h -and $h.Dll -notmatch '^C:\\(Windows|Program Files)') {
      Add-Finding -Severity High -Category 'Persistence' -Title ("netsh helper DLL outside standard path: {0}" -f $h.Helper) `
        -Detail ("DLL: {0} - netsh.exe loads it at every invocation." -f $h.Dll) `
        -Remediation 'Remove via the helper key; netsh helper persistence runs as the calling user (often admin).'
    }
  }
  if (@($helpers).Count -eq 0) { Add-Finding -Severity Info -Category 'Persistence' -Title 'No netsh helper DLLs registered' }
} catch { }

foreach ($sidKey in @('HKCU:\Control Panel\Desktop')) {
  $ss = Get-ItemProperty $sidKey -ErrorAction SilentlyContinue
  if ($ss -and $ss.SCRNSAVE.EXE -and "$($ss.SCRNSAVE.EXE)" -notmatch '^C:\\Windows\\System32') {
    Add-Finding -Severity Medium -Category 'Persistence' -Title ("Screensaver outside System32: {0}" -f $ss.'SCRNSAVE.EXE') `
      -Remediation 'Screensaver path executes at idle timeout; user-writable .scr = persistence.'
  }
}

Start-Section 'IMAGE HARDENING BASELINE'

try {
  $prefs = Get-MpPreference -ErrorAction Stop
  $asrIds = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office apps from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables not meeting prevalence/age/trust'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBScript launching downloaded executables'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps injecting into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office comms app creating child processes'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block PSExec/WMI process creation'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied/impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block webshell creation for servers'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced ransomware protection'
  }

  $ruleIds = @($prefs.AttackSurfaceReductionRules_Ids)
  $ruleActions = @($prefs.AttackSurfaceReductionRules_Actions)
  $blocking = New-Object System.Collections.Generic.List[string]
  $auditing = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $ruleIds.Count; $i++) {
    $id = "$($ruleIds[$i])".ToLower()
    if (-not $id) { continue }
    $act = if ($i -lt $ruleActions.Count) { [int]$ruleActions[$i] } else { 0 }
    $label = if ($asrIds[$id]) { $asrIds[$id] } else { $id }
    if ($act -eq 1) { $blocking.Add($label) }
    elseif ($act -eq 2 -or $act -eq 6) { $auditing.Add($label) }
  }
  if ($blocking.Count -eq 0) {
    Add-Finding -Severity High -Category 'Hardening' -Title ('Defender ASR rules: none in Block mode ({0} audit/warn)' -f $auditing.Count) `
      -Detail 'ASR blocks the exact techniques this tool detects (WMI persistence, LSASS abuse, Office child-process, USB payloads). Audit/warn rules only log - they do not stop the technique.' `
      -Remediation 'Enable the ASR rule set in Block mode via GPO/Intune (set AttackSurfaceReductionRules_Actions to 1, not 2/6).'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title ("Defender ASR rules: {0} in Block mode" -f $blocking.Count) `
      -Detail (($blocking -join ' | ') + $(if ($auditing.Count) { ' || audit/warn only: ' + ($auditing -join ', ') } else { '' }))
  }
  if ($blocking.Count -gt 0 -and $auditing.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} ASR rules are audit/warn only (not blocking)" -f $auditing.Count) `
      -Detail ($auditing -join ', ') `
      -Remediation 'Promote audited rules to Block once validated; audit mode logs the technique but allows it.'
  }
  $cfa = $prefs.EnableControlledFolderAccess
  if ($cfa -eq 1) { Add-Finding -Severity Info -Category 'Hardening' -Title 'Controlled Folder Access (ransomware guard) ON' }
  else {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Controlled Folder Access OFF' `
      -Remediation 'Enable in audit mode first, then block: Set-MpPreference -EnableControlledFolderAccess 1.'
  }
  if ($prefs.EnableNetworkProtection -eq 1) { Add-Finding -Severity Info -Category 'Hardening' -Title 'Defender network protection ON' }
  else {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Defender network protection OFF' `
      -Remediation 'EnableNetworkProtection=1 blocks malicious domains at the filter driver (C2 callback kill).'
  }
  if ($prefs.MAPSReporting -eq 0) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Defender cloud-delivered protection OFF' `
      -Remediation 'MAPSReporting=2 (advanced maps) - without cloud signals, zero-day behavior detection is blind.'
  }
} catch { }

try {
  $procMit = Get-ProcessMitigation -System -ErrorAction Stop
  $dep = "$($procMit.Dep.Policy)"
  if ($dep -match 'ON|Permanent') {
    Add-Finding -Severity Info -Category 'Hardening' -Title "DEP: $dep"
  }
  elseif ($dep -match 'OFF') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title "DEP not fully ON ($dep)" `
      -Remediation 'Enable DEP AlwaysOn plus ATL thunk emulation off.'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title ("DEP policy: {0} (default/opt-in state)" -f $(if ($dep) { $dep } else { 'not set - OS default' }))
  }
  $aslr = $procMit.ASLR
  if ($aslr.ForceRelocateImages -eq 'ON') {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'Mandatory ASLR ON (force relocation)'
  }
  else {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'Mandatory ASLR not forced' `
      -Remediation 'Set ForceRelocateImages ON (bottom-up + high-entropy too) - closes no-rebase bypass.'
  }
  $cfg = $procMit.CFG
  if ("$($cfg.Enable)" -match 'ON') {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'Control Flow Guard enabled'
  }
  else {
    Add-Finding -Severity Low -Category 'Hardening' -Title 'Control Flow Guard not system-enabled' `
      -Remediation 'Enable CFG system-wide (mostly default on modern builds/apps).'
  }
} catch { }

$appLockerSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
$alRules = 0
try {
  foreach ($coll in @('Exe','Dll','Script','Msi','Packaged app')) {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$coll"
    if (Test-Path $path) { $alRules += @(Get-ChildItem $path).Count }
  }
} catch { }
$wdac = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
if ($alRules -gt 0) {
  Add-Finding -Severity Info -Category 'Hardening' -Title ("AppLocker: {0} rules configured" -f $alRules)
  if ($appLockerSvc -and $appLockerSvc.Status -ne 'Running') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'AppLocker rules exist but AppIDSvc not running' `
      -Remediation 'Set AppIDSvc to auto-start; rules without the service are inert.'
  }
}
elseif ($wdac) {
  Add-Finding -Severity Info -Category 'Hardening' -Title 'WDAC policy present (code integrity)'
}
else {
  Add-Finding -Severity High -Category 'Hardening' -Title 'No AppLocker or WDAC application-control policy' `
    -Detail 'Everything this report lists as persistence/privexec runs because nothing blocks unsigned execution.' `
    -Remediation 'Golden-image item: deploy WDAC (audit -> enforce) or AppLocker baseline rules (EXE/DLL/Script/MSI). Single highest-value hardening control.'
}

try {
  $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
  $ssVal = "$($ss.SmartScreenEnabled)"
  if ($ssVal -eq 'Off') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen OFF (machine)' `
      -Remediation 'Set SmartScreenEnabled=Warn/Block.'
  }
  elseif ($ssVal) {
    Add-Finding -Severity Info -Category 'Hardening' -Title "SmartScreen: $ssVal"
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'SmartScreen key not set (modern builds use per-app policies - verify via Windows Security UI)'
  }
} catch { }

$uacLevel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$uacMap = @{ 0 = 'Elevate without prompting (no consent)'; 1 = 'Prompt for creds on secure desktop'; 2 = 'Prompt for consent on secure desktop'; 5 = 'Prompt for consent for non-Windows binaries (default)' }
if ($null -ne $uacLevel) {
  $desc = $uacMap[[int]$uacLevel]; if (-not $desc) { $desc = "level $uacLevel" }
  if ([int]$uacLevel -eq 0) {
    Add-Finding -Severity High -Category 'Hardening' -Title "UAC silent-elevate mode ($desc)" `
      -Remediation 'Set ConsentPromptBehaviorAdmin=5 (default).'
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title "UAC admin prompt level: $desc"
  }
}

try {
  $guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
  if ($guest -and $guest.Enabled) {
    Add-Finding -Severity High -Category 'Hardening' -Title 'Guest account enabled' `
      -Remediation 'Disable Guest in the golden image.'
  }
  else { Add-Finding -Severity Info -Category 'Hardening' -Title 'Guest account disabled' }
} catch { }

foreach ($feature in @('TelnetClient', 'TFTPClient', 'MicrosoftWindowsPowerShellV2', 'SMB1Protocol')) {
  try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
      Add-Finding -Severity High -Category 'Hardening' -Title ("Remove from image: feature {0} enabled" -f $feature) `
        -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName $feature"
    }
  } catch { }
}

try {
  $adm = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
  if ($adm.Count -gt 3) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} local Administrators - trim the image baseline" -f $adm.Count)
  }
} catch { }

foreach ($rk in @(
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Want = 1 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; Want = 1 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks'; Want = 0 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Want = 0 },
  @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry'; Name = 'Start'; Want = 4 }
)) {
  $v = (Get-ItemProperty $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue).($rk.Name)
  if ($null -ne $v -and [int]$v -ne [int]$rk.Want) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title ("{0} = {1} (hardening wants {2})" -f $rk.Name, $v, $rk.Want) `
      -Remediation ("Set {0}={1} in the image (null-session / remote-registry hardening)." -f $rk.Name, $rk.Want)
  }
  elseif ($null -eq $v -and $rk.Name -match 'AutoShare') {
    if ($rk.Name -eq 'AutoShareWks') {
      Add-Finding -Severity Low -Category 'Hardening' -Title 'AutoShareWks not set (default shares C$/ADMIN$ enabled)' `
        -Remediation 'Set AutoShareWks=0 in hardened images to kill default admin shares.'
    }
  }
}

$script:Exec = @{
  Admins            = @()
  AdminCount        = 0
  Users             = @()   
  UserCount         = 0
  EnabledCount      = 0
  DisabledCount     = 0
  NeverLoggedIn     = 0
  PersistCritHigh   = 0
  PrivEscCritHigh   = 0
  HardeningGaps     = 0
  SecretsExposed    = 0
  OpenPorts         = 0
  DevicesSeen       = 0
}

try {
  $adminNames = @()
  foreach ($m in @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)) {
    if ($m.Name -match '\\([^\\]+)$') { $adminNames += $Matches[1] } else { $adminNames += $m.Name }
  }
  $script:Exec.Admins = $adminNames
  $script:Exec.AdminCount = $adminNames.Count

  $logonMap = @{}
  foreach ($lp in @(Get-CimInstance Win32_NetworkLoginProfile -ErrorAction SilentlyContinue)) {
    if (-not $lp.Name) { continue }
    $acct = $lp.Name; if ($acct -match '\\([^\\]+)$') { $acct = $Matches[1] }
    if ($lp.LastLogon -and $lp.LastLogon -ne '***********') {
      $dt = $lp.LastLogon
      if ($dt -is [string]) { $null = [datetime]::TryParse($dt, [ref]$dt) }
      if ($dt -is [datetime] -and (-not $logonMap.ContainsKey($acct) -or $dt -gt $logonMap[$acct])) {
        $logonMap[$acct] = $dt
      }
    }
  }

  $userRows = @()
  foreach ($u in @(Get-LocalUser -ErrorAction SilentlyContinue | Sort-Object Name)) {
    $last = $null
    foreach ($k in $logonMap.Keys) { if ($k -ieq $u.Name) { $last = $logonMap[$k]; break } }
    $userRows += [pscustomobject]@{
      Name     = $u.Name
      IsAdmin  = ($adminNames -icontains $u.Name)
      Enabled  = [bool]$u.Enabled
      LastLogon = $last
    }
  }
  $script:Exec.Users = $userRows
  $script:Exec.UserCount = $userRows.Count
  $script:Exec.EnabledCount = @($userRows | Where-Object Enabled).Count
  $script:Exec.DisabledCount = @($userRows | Where-Object { -not $_.Enabled }).Count
  $script:Exec.NeverLoggedIn = @($userRows | Where-Object { -not $_.LastLogon -and $_.Enabled }).Count
}
catch { }

$script:Exec.PersistCritHigh = @($script:Findings | Where-Object { $_.Category -eq 'Persistence' -and $_.Severity -in 'Critical', 'High' }).Count
$script:Exec.PrivEscCritHigh = @($script:Findings | Where-Object { $_.Category -eq 'PrivEsc' -and $_.Severity -in 'Critical', 'High' }).Count
$script:Exec.HardeningGaps = @($script:Findings | Where-Object { $_.Category -eq 'Hardening' -and $_.Severity -in 'Critical', 'High', 'Medium' }).Count
$script:Exec.SecretsExposed = @($script:Findings | Where-Object { $_.Category -match 'Exposed secret|Credentials' -and $_.Severity -in 'Critical', 'High' }).Count
$arpFinding = $script:Findings | Where-Object { $_.Title -like '*devices in ARP/neighbor cache*' } | Select-Object -First 1
if ($arpFinding -and $arpFinding.Title -match '^(\d+) ') { $script:Exec.DevicesSeen = [int]$Matches[1] }
else {
  $arp = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|::1|224\.|239\.|ff)' -and $_.LinkLayerAddress })
  $script:Exec.DevicesSeen = $arp.Count
}

function ConvertFrom-NetworkListSystemTime($val) {

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

try {
  $pers = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.Protocol -eq 'NetMgmt' -and $_.DestinationPrefix -notmatch '^(127\.|169\.254|224\.|255\.|0\.0\.0\.0/0|::/0|fe80)' })
  if ($pers.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} statically managed routes' -f $pers.Count) `
      -Detail (($pers | ForEach-Object { '{0} -> {1} (metric {2})' -f $_.DestinationPrefix, $_.NextHop, $_.RouteMetric } | Select-Object -First 15) -join ' | ') `
      -Remediation 'Persistent routes reveal hardcoded OT/management network paths; verify each against the network design.'
  }
} catch { }

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

try {
  $fwRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Group -eq '' } | Select-Object -First 15)
  if ($fwRules.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} custom inbound allow rules (ungrouped)' -f $fwRules.Count) `
      -Detail (($fwRules | ForEach-Object { $_.DisplayName } | Select-Object -First 15) -join ' | ') `
      -Remediation 'Custom firewall holes are configuration debt - each is an exposure someone requested; verify business need.'
  }
} catch { }

Start-Section 'ADVANCED PERSISTENCE + OBFUSCATION DETECTION'

$script:ObfPattern = '(?i)(?:\B-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,})|IEX\s*\(|Invoke-Expression|FromBase64String|DownloadString|DownloadFile|Net\.WebClient|Reflection\.Assembly\]::Load|scrobj\.dll|RunHTMLApplication|(?:certutil|bitsadmin).*(?:-decode|-urlcache)'

$uacBypassKeys = @(
  @{ Key = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'; Name = 'fodhelper / computerdefaults (ms-settings)' }
  @{ Key = 'HKCU:\Software\Classes\mscfile\Shell\Open\command'; Name = 'eventvwr / mmc (mscfile)' }
  @{ Key = 'HKCU:\Software\Classes\exefile\Shell\Open\command'; Name = 'exefile association hijack' }
  @{ Key = 'HKCU:\Software\Classes\Applications\powershell.exe\shell\open\command'; Name = 'PowerShell application hijack' }
  @{ Key = 'HKCU:\Software\Classes\Folder\shell\Open\command'; Name = 'Folder class hijack' }
  @{ Key = 'HKCU:\Software\Classes\Drive\shell\Open\command'; Name = 'Drive class hijack (sdclt)' }
  @{ Key = 'HKCU:\Software\Classes\Launcher.SystemSettings\shell\open\command'; Name = 'SystemSettings launcher hijack' }
)
foreach ($u in $uacBypassKeys) {
  if (-not (Test-Path $u.Key)) { continue }
  $props = Get-ItemProperty $u.Key -ErrorAction SilentlyContinue
  $val = $props.'(default)'
  $hasDelegate = $props -and ($props.PSObject.Properties.Name -contains 'DelegateExecute')

  if ($val -or $hasDelegate) {
    Add-Finding -Severity Critical -Category 'Persistence' -Title ("UAC bypass registry residue: {0}" -f $u.Name) `
      -Detail ("Key: {0} | Command: {1} | DelegateExecute present: {2} - auto-elevates via a trusted signed binary (MITRE T1548.002)." -f $u.Key, $val, $hasDelegate) `
      -Evidence $u.Key `
      -Remediation 'Delete the key. These HKCU class overrides have no legitimate use; presence on a golden image indicates prior compromise.'
  }
}

$progIdDefaults = @{
  'exefile'  = '"%1" %*'
  'comfile'  = '"%1" %*'
  'batfile'  = '"%1" %*'
  'cmdfile'  = '"%1" %*'
  'piffile'  = '"%1" %*'
  'scrfile'  = '"%1" /S'
}
$progIdWatch = @('exefile', 'comfile', 'batfile', 'cmdfile', 'piffile', 'scrfile', 'htafile', 'txtfile', 'regfile', 'Folder', 'Directory', 'Drive')
foreach ($hive in @('HKLM:\Software\Classes', 'HKCU:\Software\Classes')) {
  foreach ($progId in $progIdWatch) {
    $cmdKey = Join-Path $hive "$progId\shell\open\command"
    if (-not (Test-Path $cmdKey)) { continue }
    $val = "$((Get-ItemProperty $cmdKey -ErrorAction SilentlyContinue).'(default)')"
    if (-not $val) { continue }
    if ($val -match $script:ObfPattern) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("File-association hijacked with obfuscated command: {0}" -f $progId) `
        -Detail ("Key: {0} | Command: {1} - every launch of this file type runs attacker code." -f $cmdKey, $val) `
        -Evidence $cmdKey `
        -Remediation ('Restore the default handler for {0} and hunt for the dropper that set it.' -f $progId)
    }
    elseif ($progIdDefaults.ContainsKey($progId) -and $val -ne $progIdDefaults[$progId]) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("Non-default handler for {0}" -f $progId) `
        -Detail ("Key: {0} | Command: {1} | Expected: {2}" -f $cmdKey, $val, $progIdDefaults[$progId]) `
        -Evidence $cmdKey `
        -Remediation ('Executable-class handlers should be exactly {0}. Anything else intercepts every execution of that type.' -f $progIdDefaults[$progId])
    }
  }
}

try {
  foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
    $fc = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -Name FailureCommand -ErrorAction SilentlyContinue).FailureCommand
    if (-not $fc) { continue }

    $isObf = $fc -match $script:ObfPattern
    $isOutside = $fc -notmatch '(?i)^"?(%SystemRoot%|C:\\Windows|C:\\Program Files)'
    if ($isObf -or $isOutside) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("Service recovery command is non-standard: {0}" -f $s.Name) `
        -Detail ("FailureCommand: {0} - runs as SYSTEM when the service crashes, so an attacker can trigger it on demand." -f $fc) `
        -Evidence ("HKLM\SYSTEM\CurrentControlSet\Services\{0}" -f $s.Name) `
        -Remediation 'A legitimate recovery action should be a signed binary under Windows or Program Files, never an inline interpreter command.'
    }
  }
} catch { }

try {
  $amsiProviders = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue)
  if ($amsiProviders.Count -eq 0) {
    Add-Finding -Severity High -Category 'Obfuscation' -Title 'No AMSI providers registered' `
      -Detail 'AMSI feeds PowerShell/VBS/JS content to the AV engine at runtime. With no provider registered, script content is never scanned.' `
      -Remediation 'Expect at least the Defender provider {2781761E-28E0-4109-99FE-B9D127C57AFE}. Investigate why it was removed.'
  }
  else {
    $resolved = foreach ($p in $amsiProviders) {
      $clsid = $p.PSChildName
      $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'

      if ($dll -and $dll -notmatch '(?i)^"?(C:\\Windows|C:\\Program Files|%ProgramFiles%|C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\)') {
        Add-Finding -Severity Critical -Category 'Obfuscation' -Title ("AMSI provider DLL outside protected path: {0}" -f $clsid) `
          -Detail ("DLL: {0} - a rogue AMSI provider can silently pass all content as clean." -f $dll) `
          -Evidence $clsid `
          -Remediation 'Remove the provider registration and investigate the DLL.'
      }
      ("{0}{1}" -f $clsid, $(if ($dll) { " -> $dll" } else { '' }))
    }
    Add-Finding -Severity Info -Category 'Obfuscation' -Title ("{0} AMSI provider(s) registered" -f $amsiProviders.Count) `
      -Detail (($resolved | Select-Object -First 5) -join ' | ')
  }
  if (Test-Path 'HKCU:\SOFTWARE\Microsoft\AMSI\Providers') {
    Add-Finding -Severity High -Category 'Obfuscation' -Title 'AMSI provider override present in HKCU' `
      -Detail 'Per-user AMSI provider registration is not a supported configuration and can redirect scanning for the current user.' `
      -Remediation 'Delete HKCU\SOFTWARE\Microsoft\AMSI and investigate.'
  }
} catch { }

try {
  $histPath = $null
  try { $histPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath } catch { }
  if (-not $histPath) {

    $histPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
  }
  if (Test-Path $histPath) {
    $hits = New-Object System.Collections.Generic.List[string]
    $ln = 0
    foreach ($line in (Get-Content $histPath -ErrorAction SilentlyContinue)) {
      $ln++
      if ($line -match $script:ObfPattern) { $hits.Add("line ${ln}: $(Get-Redacted $line)") }
      if ($hits.Count -ge 8) { break }
    }
    if ($hits.Count -gt 0) {
      Add-Finding -Severity High -Category 'Obfuscation' -Title ("Obfuscated/encoded PowerShell in console history ({0} hits)" -f $hits.Count) `
        -Detail ($hits -join ' | ') `
        -Evidence $histPath `
        -Remediation 'Investigate each hit. Encoded commands plus IEX/DownloadString is the signature of fileless tooling; rotate any credentials that were in scope.'
    }
  }
} catch { }

try {
  $allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
  foreach ($t in $allTasks) {
    foreach ($a in @($t.Actions)) {
      if (-not $a.Execute) { continue }
      $cmd = ("{0} {1}" -f $a.Execute, $a.Arguments).Trim()

      if ($cmd -match $script:ObfPattern) {
        Add-Finding -Severity High -Category 'Obfuscation' -Title ("Scheduled task with obfuscated command: {0}" -f $t.TaskName) `
          -Detail ("Path: {0} | Command: {1} | State: {2}" -f $t.TaskPath, (Get-Redacted $cmd), $t.State) `
          -Evidence ("{0}{1}" -f $t.TaskPath, $t.TaskName) `
          -Remediation 'Investigate. Encoded PowerShell or regsvr32+scrobj.dll in a task is classic fileless persistence (T1053.005 / T1218).'
      }

      if ($t.TaskPath -notlike '\Microsoft*') {
        $exe = ($a.Execute -replace '"', '')
        if ($exe -match '(?i)^[A-Z]:\\(ProgramData|Users\\[^\\]+\\AppData|Temp|Public)') {
          Add-Finding -Severity High -Category 'Masquerading' -Title ("Task binary in user-writable path: {0}" -f $t.TaskName) `
            -Detail ("Path: {0} - an executable in a user-writable directory can be swapped without touching the task definition." -f $exe) `
            -Evidence $exe `
            -Remediation 'Relocate the binary under Program Files, or validate it against the authorized task baseline.'
        }
      }
    }
  }
} catch { }

try {
  $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)

  $coreRe = '^(svchost|lsass|csrss|winlogon|smss|services|spoolsv)\.exe$'
  foreach ($p in @($procs | Where-Object {
        $_.ExecutablePath -and (
          ($_.Name -match $coreRe -and $_.ExecutablePath -notmatch '(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)\\') -or
          ($_.Name -match '^explorer\.exe$' -and $_.ExecutablePath -notmatch '(?i)^C:\\Windows\\(explorer\.exe|SysWOW64\\|WinSxS\\)')
        )
      } | Select-Object -First 10)) {
    Add-Finding -Severity Critical -Category 'Masquerading' -Title ("{0} running from non-standard path" -f $p.Name) `
      -Detail ("Path: {0} | PID: {1} - a core Windows binary outside System32/SysWOW64 is T1036 masquerading." -f $p.ExecutablePath, $p.ProcessId) `
      -Evidence $p.ExecutablePath `
      -Remediation 'Isolate the host and investigate. Genuine svchost/lsass/csrss always run from System32.'
  }
  foreach ($c in @($procs | Where-Object {
        $_.Name -match '^(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32)\.exe$' -and
        $_.CommandLine -match $script:ObfPattern
      } | Select-Object -First 5)) {
    $parent = $procs | Where-Object { $_.ProcessId -eq $c.ParentProcessId } | Select-Object -First 1
    Add-Finding -Severity High -Category 'Obfuscation' -Title ("Obfuscated command line running now: {0} (PID {1})" -f $c.Name, $c.ProcessId) `
      -Detail ("Parent: {0} (PID {1}) | Command redacted: {2}" -f $(if ($parent) { $parent.Name } else { 'unknown' }), $c.ParentProcessId, (Get-Redacted $c.CommandLine)) `
      -Remediation 'Investigate the parent. Encoded PowerShell spawned by Office or a browser is a live fileless attack.'
  }
  if (-not $script:IsElevated) {
    Add-Finding -Severity Low -Category 'Masquerading' -Title 'Process command lines only partly visible (needs elevation)' `
      -Detail 'Without administrator rights, ExecutablePath and CommandLine are hidden for processes owned by other users, so masquerading in those processes is not assessed.' `
      -Remediation 'Re-run elevated for full process-level coverage.'
  }
} catch { }

if ($script:IsElevated) {
  try {
    $taskCount = @(Get-ChildItem 'C:\Windows\System32\Tasks' -Recurse -File -ErrorAction SilentlyContinue).Count
    Add-Finding -Severity Info -Category 'Persistence' -Title ("{0} scheduled task definition files on disk" -f $taskCount) `
      -Detail 'Counted recursively under C:\Windows\System32\Tasks.' `
      -Remediation 'Baseline this count on the golden image; an unexplained increase means new tasks were registered.'
  } catch { }
}
else {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Scheduled task file baseline not assessed (needs elevation)' `
    -Detail 'C:\Windows\System32\Tasks is not readable without administrator rights.'
}

Start-Section 'SUMMARY'
$total = $script:Findings.Count
Write-Host ''
Write-Host ('Scan complete in {0:mm\:ss}. {1} findings.' -f $stopwatch.Elapsed, $total) -ForegroundColor Cyan
$grouped = $script:Findings | Group-Object Severity | Sort-Object { @('Critical','High','Medium','Low','Info').IndexOf($_.Name) }
foreach ($g in $grouped) {
  $color = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }[$g.Name]
  Write-Host ('  {0,-9} {1}' -f $g.Name, $g.Count) -ForegroundColor $color
}
Write-Host ''
Write-Host 'Top items by severity:' -ForegroundColor Cyan
$top = $script:Findings | Where-Object { $_.Severity -in 'Critical', 'High' } | Select-Object -First 10
if ($top) {
  foreach ($f in $top) { Write-Host ('  [{0}] {1}: {2}' -f $f.Severity, $f.Category, $f.Title) -ForegroundColor Red }
}
else {
  Write-Host '  No Critical/High findings. ' -ForegroundColor Green
}

Write-Reports -Dir $OutputDir -LaunchHtml

$critHigh = @($script:Findings | Where-Object { $_.Severity -in 'Critical', 'High' }).Count
$exitCode = [math]::Min($critHigh, 250)
Write-Host ''
Write-Host ("Exit code will be {0} (Critical+High count) for unattended triage." -f $exitCode) -ForegroundColor DarkCyan
exit $exitCode

Write-Host ''
Write-Host 'WinHostPEAS audit finished. Reports contain no secret values (detection + redaction only).' -ForegroundColor Cyan


