

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

$script:LowPrivSids = @{
  'S-1-1-0'      = 'Everyone'
  'S-1-5-32-545' = 'BUILTIN\Users'
  'S-1-5-11'     = 'Authenticated Users'
  'S-1-5-4'      = 'INTERACTIVE'
  'S-1-5-2'      = 'NETWORK'
  'S-1-5-7'      = 'ANONYMOUS LOGON'
  'S-1-5-32-546' = 'BUILTIN\Guests'
  'S-1-5-13'     = 'Terminal Server Users'
}

try {
  $script:AclCurrent = [Security.Principal.WindowsIdentity]::GetCurrent()
  $isElevated = ([Security.Principal.WindowsPrincipal]$script:AclCurrent).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isElevated) { $script:LowPrivSids[$script:AclCurrent.User.Value] = $script:AclCurrent.Name }
} catch { }

$script:WriteRightsRx = 'FullControl|Modify|Write|CreateFiles|AppendData|ChangePermissions|TakeOwnership|SetValue|CreateSubKey'

function Get-LowPrivWriteAce {
  param($ACLObject)
  foreach ($ace in $ACLObject.Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    if ("$($ace.PropagationFlags)" -match 'InheritOnly') { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
    if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
    $rights = "$($ace.FileSystemRights)$($ace.RegistryRights)"
    if ($rights -notmatch $script:WriteRightsRx) { continue }
    $level = if ($rights -match 'FullControl') { 'FullControl' } elseif ($rights -match 'Modify') { 'Modify' }
             elseif ($rights -match 'ChangePermissions|TakeOwnership') { 'ChangePermissions/TakeOwnership' } else { 'Write' }
    return [pscustomobject]@{ Name = $script:LowPrivSids[$sid]; Sid = $sid; Level = $level; Rights = $rights }
  }
  return $null
}

function Start-ACLCheck {
  param($Target, $ServiceName)
  if ($null -eq $Target) { return }
  try { $ACLObject = Get-Acl $Target -ErrorAction SilentlyContinue } catch { return }
  if (-not $ACLObject) { return }
  $hit = Get-LowPrivWriteAce -ACLObject $ACLObject
  if (-not $hit) { return }
  if ($Target -like "$env:USERPROFILE*" -and $hit.Sid -eq $script:AclCurrent.User.Value) { return }
  Add-Finding -Severity High -Category 'Filesystem ACL' `
    -Title ("Low-privilege '{0}' has {1} on: {2}" -f $hit.Name, $hit.Level, $Target) `
    -Detail ("{0} ({1}) can {2} this object{3}. Any process running as that principal could replace or alter it and gain the privileges of whatever runs it." -f $hit.Name, $hit.Sid, $hit.Level.ToLower(), $(if ($ServiceName) { ' (service: ' + $ServiceName + ')' } else { '' })) `
    -Evidence $Target `
    -Remediation 'Remove write, modify and full control for non-admin principals on executable paths, service binaries and their folders; keep them to Administrators, SYSTEM and TrustedInstaller.'
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
else {
  Add-Finding -Severity Info -Category 'Patching' -Title 'Patch history not assessed' `
    -Detail 'Get-HotFix returned no entries with an install date (common on fresh images and in-place upgrades). Patch recency is unknown, not current.' `
    -Remediation 'Check Settings > Windows Update > Update history, or query the Windows Update agent, to confirm the host is current.'
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

  $amMode = "$($mp.AMRunningMode)"
  $rtp = [bool]$mp.RealTimeProtectionEnabled
  if (-not $mp.AMServiceEnabled -or $amMode -match 'Not running') {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender antimalware service not running' `
      -Detail ("AMServiceEnabled={0}; AMRunningMode={1}." -f $mp.AMServiceEnabled, $amMode) `
      -Remediation 'Start WinDefend and investigate why it stopped; if a third-party product replaced it, confirm that product is active.'
  }
  elseif ($amMode -match 'Passive|EDR Block|SxS') {
    Add-Finding -Severity Medium -Category 'AV' -Title ("Defender in {0}: another AV product must be primary" -f $amMode) `
      -Detail ("AMRunningMode={0}; RealTimeProtectionEnabled={1}. In this mode Defender does not block in realtime (EDR Block Mode only remediates what MDE flags). If no third-party AV is installed and enabled, the host has no realtime prevention." -f $amMode, $rtp) `
      -Remediation 'Confirm a third-party AV/EDR is installed, licensed and running (Windows Security > Virus and threat protection). If none, clear ForceDefenderPassiveMode and return Defender to Normal mode.'
  }
  elseif ($rtp) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender realtime protection ON' `
      -Detail ("Mode {0}; engine {1}; signatures {2:yyyy-MM-dd HH:mm}" -f $amMode, $mp.AMEngineVersion, $mp.AntivirusSignatureLastUpdated)
  }
  else {
    Add-Finding -Severity Critical -Category 'AV' -Title 'Defender realtime protection OFF' `
      -Detail ("RealTimeProtectionEnabled=False while AMRunningMode={0} (service running, engine not scanning)." -f $amMode) `
      -Remediation 'Re-enable realtime protection; investigate why it was disabled (often attacker first action).'
  }
  $tpProp = $mp.PSObject.Properties['IsTamperProtected']
  $tpReg = $null
  try { $tpReg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection } catch { }
  $tpState = if ($tpProp -and $null -ne $tpProp.Value) { [bool]$tpProp.Value } elseif ($tpReg -eq 5) { $true } elseif ($tpReg -eq 4) { $false } else { $null }
  if ($tpState -eq $true) {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender Tamper Protection ON' -Detail ("IsTamperProtected={0}; Features\TamperProtection={1}" -f $(if ($tpProp) { $tpProp.Value } else { 'n/a' }), $tpReg)
  }
  elseif ($tpState -eq $false) {
    Add-Finding -Severity High -Category 'AV' -Title 'Defender Tamper Protection OFF' `
      -Detail ("IsTamperProtected={0}; Features\TamperProtection={1}. Without it, any admin process (or malware running as admin) can turn Defender off with one registry write." -f $(if ($tpProp) { $tpProp.Value } else { 'n/a' }), $tpReg) `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features::TamperProtection' `
      -Remediation 'Enable Tamper Protection (Windows Security UI, Intune, or MDE tenant-wide). It cannot be set by GPO or script by design.'
  }
  else {
    Add-Finding -Severity Info -Category 'AV' -Title 'Defender Tamper Protection not assessed' -Detail 'Neither Get-MpComputerStatus.IsTamperProtected nor Features\TamperProtection was readable.'
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

$auditWanted = @(
  @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                     Want = 'SF' }
  @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                    Want = 'S'  }
  @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';           Want = 'F'  }
  @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon';             Want = 'S'  }
  @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation';          Want = 'S'  }
  @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';       Want = 'S'  }
  @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Security State Change';     Want = 'S'  }
  @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension'; Want = 'S'  }
  @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Name = 'System Integrity';          Want = 'SF' }
  @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';   Want = 'SF' }
  @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';   Want = 'SF' }
  @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management'; Want = 'S'  }
  @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';     Want = 'SF' }
  @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Other Object Access Events'; Want = 'SF' }
  @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Name = 'File Share';                Want = 'SF' }
  @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Name = 'Removable Storage';         Want = 'SF' }
)
$wantLabel = @{ S = 'Success'; SF = 'Success and Failure'; F = 'Failure' }
$procCreationAudited = $null   
if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed (needs elevation)' `
    -Detail ('auditpol /get requires administrator. Not assessed: ' + (($auditWanted | ForEach-Object { $_.Name }) -join ', ') + '.') `
    -Remediation 'Re-run elevated to verify the advanced audit policy against the Microsoft baseline.'
}
else {
  try {
    $auditRaw = @(auditpol.exe /get /category:* /r 2>$null | Where-Object { "$_".Trim() })
    $auditRows = @()
    if ($auditRaw.Count -gt 1) { $auditRows = @($auditRaw | ConvertFrom-Csv -ErrorAction Stop) }
    if ($auditRows.Count -eq 0 -or -not ($auditRows[0].PSObject.Properties.Name -contains 'Subcategory GUID')) {
      Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed (auditpol output unreadable)' `
        -Detail 'auditpol /get /category:* /r returned no CSV with a Subcategory GUID column even when elevated.'
    }
    else {
      $auditOk = @(); $auditMissing = @(); $auditForeign = @()
      foreach ($w in $auditWanted) {
        $row = $auditRows | Where-Object { "$($_.'Subcategory GUID')".Trim().ToUpper() -eq $w.Guid } | Select-Object -First 1
        if (-not $row) { $auditMissing += ('{0} (not reported, want {1})' -f $w.Name, $wantLabel[$w.Want]); continue }
        $inc = "$($row.'Inclusion Setting')".Trim()
        $have = switch -Regex ($inc) {
          '^Success and Failure$' { 'SF'; break }
          '^Success$'             { 'S';  break }
          '^Failure$'             { 'F';  break }
          '^No Auditing$'         { 'N';  break }
          default                 { $null }
        }
        if ($null -eq $have) { $auditForeign += ('{0}="{1}"' -f $w.Name, $inc); continue }
        $meets = switch ($w.Want) {
          'SF' { $have -eq 'SF' }
          'S'  { $have -eq 'S' -or $have -eq 'SF' }
          'F'  { $have -eq 'F' -or $have -eq 'SF' }
        }
        if ($w.Guid -eq '{0CCE922B-69AE-11D9-BED3-505054503030}') { $procCreationAudited = [bool]$meets }
        if ($meets) { $auditOk += ('{0}={1}' -f $w.Name, $inc) } else { $auditMissing += ('{0}={1} (want {2})' -f $w.Name, $inc, $wantLabel[$w.Want]) }
      }
      if ($auditForeign.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Logging' -Title ('{0} audit subcategories not assessed (non-English auditpol output)' -f $auditForeign.Count) `
          -Detail ($auditForeign -join '; ') `
          -Remediation 'Compare the Inclusion Setting values against the Microsoft baseline manually; this tool only evaluates the English strings.'
      }
      if ($auditMissing.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Logging' -Title ('{0} of {1} critical audit subcategories below baseline' -f $auditMissing.Count, $auditWanted.Count) `
          -Detail ($auditMissing -join '; ') `
          -Remediation 'Set the advanced audit policy (Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration) to the Microsoft security baseline for these subcategories; without them logon, process and account-change events are never written.'
      }
      if ($auditOk.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Logging' -Title ('{0} of {1} critical audit subcategories at baseline' -f $auditOk.Count, $auditWanted.Count) `
          -Detail ($auditOk -join '; ')
      }
    }
  } catch {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Audit policy not assessed' -Detail ('auditpol failed: ' + $_.Exception.Message)
  }
}

try {
  $cmdLineInc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
  $cmdLineOn = ($cmdLineInc -eq 1)
  if ($cmdLineOn -and $procCreationAudited -eq $true) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Process creation auditing with command line ON' `
      -Detail 'Process Creation subcategory audits Success and ProcessCreationIncludeCmdLine_Enabled=1, so event 4688 carries the full command line.'
  }
  elseif ($cmdLineOn -and $null -eq $procCreationAudited) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'Command line in 4688 enabled; Process Creation subcategory not assessed (needs elevation)' `
      -Detail 'ProcessCreationIncludeCmdLine_Enabled=1, but whether the Process Creation subcategory is audited could not be read without elevation.'
  }
  else {
    $why = @()
    if (-not $cmdLineOn) { $why += ('ProcessCreationIncludeCmdLine_Enabled=' + $(if ($null -eq $cmdLineInc) { 'absent (off)' } else { "$cmdLineInc" })) }
    if ($procCreationAudited -eq $false) { $why += 'Process Creation subcategory is not auditing Success' }
    Add-Finding -Severity Medium -Category 'Logging' -Title 'Process creation command-line auditing incomplete' `
      -Detail (($why -join '; ') + '. Without both, 4688 events either do not exist or omit the command line that distinguishes malicious from benign execution (T1059 visibility).') `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit::ProcessCreationIncludeCmdLine_Enabled' `
      -Remediation 'Enable "Include command line in process creation events" (Administrative Templates > System > Audit Process Creation) and audit Process Creation Success (CIS 17.3.2).'
  }
} catch { }

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

$logAgentNames = @('SplunkForwarder', 'nxlog', 'winlogbeat', 'filebeat', 'elastic-agent', 'HealthService', 'AzureMonitorAgent', 'DatadogAgent', 'WinCollect', 'QRadar', 'fluentdwinsvc')
$logAgentsRunning = @()
try {
  $logAgentsRunning = @(Get-Service -Name $logAgentNames -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
} catch { }
$wefConfigured = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
if ($wefConfigured) {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Windows Event Forwarding configured'
}

if (-not $wefConfigured -and $logAgentsRunning.Count -eq 0) {
  Add-Finding -Severity Low -Category 'Logging' -Title 'No Windows Event Forwarding or log-shipping agent' `
    -Detail ('Local logs die with the host; attackers clear logs post-incident. No WEF SubscriptionManager policy and none of these services running: ' + ($logAgentNames -join ', ') + '.') `
    -Remediation 'Deploy WEF or a log agent so security events reach a central SIEM.'
}

try {
  $sbl = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
  $sblVal = if ($sbl) { $sbl.EnableScriptBlockLogging } else { $null }
  if ($sblVal -eq 1) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'PowerShell Script Block Logging enabled' `
      -Detail ("EnableScriptBlockInvocationLogging={0}" -f $(if ($null -ne $sbl.EnableScriptBlockInvocationLogging) { $sbl.EnableScriptBlockInvocationLogging } else { 'not set' }))
  }
  else {
    $state = if ($null -eq $sblVal) { 'not configured (OS default logs only blocks Defender/AMSI flags as suspicious)' } else { "explicitly disabled by policy (EnableScriptBlockLogging=$sblVal)" }
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell Script Block Logging NOT enabled: ' + $(if ($null -eq $sblVal) { 'not configured' } else { 'disabled by policy' })) `
      -Detail ($state + '. Attacker tooling (and abusive admins) rely on PowerShell flying under the radar; event 4104 is the record of what actually ran.') `
      -Remediation 'Enable Script Block Logging via GPO (Administrative Templates > Windows Components > Windows PowerShell).'
  }
  $ml = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
  $mlVal = if ($ml) { $ml.EnableModuleLogging } else { $null }
  $mlNames = @()
  try { $mn = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction SilentlyContinue; if ($mn) { $mlNames = @($mn.Property) } } catch { }
  if ($mlVal -eq 1 -and $mlNames.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Logging' -Title 'PowerShell Module Logging enabled' -Detail ('ModuleNames: ' + ($mlNames -join ', '))
  }
  elseif ($mlVal -eq 1) {
    Add-Finding -Severity Medium -Category 'Logging' -Title 'PowerShell Module Logging enabled but ModuleNames is empty (nothing is logged)' `
      -Detail 'EnableModuleLogging=1 without entries under ModuleLogging\ModuleNames logs no module activity at all.' `
      -Remediation 'Add "*" (or the modules of interest) under ModuleNames so event 4103 is produced.'
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell Module Logging NOT enabled: ' + $(if ($null -eq $mlVal) { 'not configured' } else { 'disabled by policy' })) `
      -Detail 'Module logging (event 4103) records pipeline execution details per module.' `
      -Remediation 'Enable Module Logging via GPO with ModuleNames = *.'
  }
  $tr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
  $trVal = if ($tr) { $tr.EnableTranscripting } else { $null }
  if ($trVal -eq 1) {
    $outDir = "$($tr.OutputDirectory)"
    if ($outDir) {
      Add-Finding -Severity Info -Category 'Logging' -Title 'PowerShell Transcription enabled' -Detail ("OutputDirectory: {0}; EnableInvocationHeader={1}" -f $outDir, $tr.EnableInvocationHeader)
    }
    else {
      Add-Finding -Severity Low -Category 'Logging' -Title 'PowerShell Transcription enabled without a central OutputDirectory' `
        -Detail 'Transcripts land in each user''s Documents folder, where the user (or malware running as the user) can delete them.' `
        -Remediation 'Set OutputDirectory to a write-only share or protected folder collected by the SIEM.'
    }
  }
  else {
    Add-Finding -Severity Medium -Category 'Logging' -Title ('PowerShell Transcription NOT enabled: ' + $(if ($null -eq $trVal) { 'not configured' } else { 'disabled by policy' })) `
      -Detail 'Transcription captures full session input and output, including interactive attacker sessions.' `
      -Remediation 'Enable Transcription via GPO with a protected OutputDirectory.'
  }
} catch { }

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

try {
  $lsaCfg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
  $lsaCfgPol = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
  $cgDetail = ("Registry: Control\LSA LsaCfgFlags={0}; policy DeviceGuard LsaCfgFlags={1}" -f $(if ($null -eq $lsaCfg) { 'absent' } else { $lsaCfg }), $(if ($null -eq $lsaCfgPol) { 'absent' } else { $lsaCfgPol }))
  $dg = $null
  try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1 } catch { $dg = $null }
  if ($dg) {
    $cgRunning    = (@($dg.SecurityServicesRunning)    -contains 1)
    $cgConfigured = (@($dg.SecurityServicesConfigured) -contains 1)
    $vbsRunning   = ([int]$dg.VirtualizationBasedSecurityStatus -eq 2)
    $vbsCapable   = (@($dg.AvailableSecurityProperties) -contains 2)
    $osBuild = 0; try { $osBuild = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber } catch { }
    $cgDetail += ("; Win32_DeviceGuard: VBS status={0}, SecurityServicesConfigured={1}, SecurityServicesRunning={2}" -f $dg.VirtualizationBasedSecurityStatus, (@($dg.SecurityServicesConfigured) -join ','), (@($dg.SecurityServicesRunning) -join ','))
    if ($cgRunning) {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Guard RUNNING' -Detail $cgDetail
    }
    elseif ($cgConfigured) {
      Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard configured but NOT running' `
        -Detail ($cgDetail + '. Configured without running usually means a pending reboot, a missing VBS prerequisite (UEFI, Secure Boot, hypervisor), or the UEFI lock blocking a change.') `
        -Remediation 'Reboot and re-check; verify VBS prerequisites with msinfo32 (Virtualization-based security: Running).'
    }
    elseif ($vbsCapable -and $osBuild -ge 22000) {
      Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard not running (hardware capable)' `
        -Detail ($cgDetail + ("; VBS running={0}. LSASS secrets (NTLM hashes, Kerberos TGTs) are dumpable by any admin-level code." -f $vbsRunning)) `
        -Remediation 'Enable Credential Guard (GPO: Turn On Virtualization Based Security > Credential Guard configuration = Enabled with UEFI lock, or Intune/MDM). Requires VBS; on Pro it needs explicit enablement.'
    }
    else {
      Add-Finding -Severity Low -Category 'Credentials' -Title 'Credential Guard not running (platform not capable or pre-Win11 build)' `
        -Detail ($cgDetail + ("; VBS capable={0}, build={1}." -f $vbsCapable, $osBuild)) `
        -Remediation 'Credential Guard needs UEFI, Secure Boot, a hypervisor-capable CPU and a supported SKU; plan it into the next hardware/OS refresh.'
    }
  }
  else {
    if ($lsaCfg -eq 1 -or $lsaCfg -eq 2 -or $lsaCfgPol -eq 1 -or $lsaCfgPol -eq 2) {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Guard configured (running state not assessed: Win32_DeviceGuard unavailable)' -Detail $cgDetail
    }
    else {
      Add-Finding -Severity Medium -Category 'Credentials' -Title 'Credential Guard not configured (running state not assessed: Win32_DeviceGuard unavailable)' `
        -Detail ($cgDetail + '. The DeviceGuard CIM namespace was not readable, so only the registry configuration is known.') `
        -Remediation 'Enable Credential Guard (hardware virtualization) to harden LSASS against dump-and-reuse.'
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Credentials' -Title 'Credential Guard not assessed' -Detail ('Read failed: ' + $_.Exception.Message)
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
  try {
    $n = @((Get-Item 'HKCU:\Software\OpenSSH\Agent\Keys' -ErrorAction Stop).Property).Count
    if ($n -gt 0) {
      Add-Finding -Severity Medium -Category 'Credentials' -Title "$n SSH key(s) registered in ssh-agent" `
        -Remediation 'Verify these are authorized; ssh-agent keys are extractable by SYSTEM-level code.'
    }
    else {
      Add-Finding -Severity Info -Category 'Credentials' -Title 'No SSH keys registered in ssh-agent'
    }
  } catch {
    Add-Finding -Severity Info -Category 'Credentials' -Title 'ssh-agent key store present but not readable (not assessed)' `
      -Detail ('HKCU:\Software\OpenSSH\Agent\Keys exists; read failed: ' + $_.Exception.Message + '. The key is SYSTEM-only by design; inspect with ssh-add -l as the user.')
  }
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

if ($env:LOCALAPPDATA -and (Test-Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite")) {
  Add-Finding -Severity Medium -Category 'Credentials' -Title 'Sticky Notes database present' `
    -Detail 'Sticky Notes frequently contain passwords in plaintext (plum.sqlite).' `
    -Remediation 'Educate users; consider disabling Sticky Notes on sensitive hosts.'
}

$histPath = $null
try { $histPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath } catch { $histPath = $null }
if (-not $histPath) { $histPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' }
if ($histPath -and (Test-Path $histPath)) {
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

function Get-LowPrivFolderWriteAce {
  param($ACLObject)
  if (-not $ACLObject) { return $null }
  foreach ($ace in $ACLObject.Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    if ("$($ace.PropagationFlags)" -match 'InheritOnly') { continue }
    $sid = $null
    try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
    if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
    $rights = "$($ace.FileSystemRights)"
    if ($rights -notmatch 'FullControl|Modify|Write|CreateFiles|ChangePermissions|TakeOwnership') { continue }
    $level = if ($rights -match 'FullControl') { 'FullControl' } elseif ($rights -match 'Modify') { 'Modify' }
             elseif ($rights -match 'ChangePermissions|TakeOwnership') { 'ChangePermissions/TakeOwnership' } else { 'Write' }
    return [pscustomobject]@{ Name = $script:LowPrivSids[$sid]; Sid = $sid; Level = $level; Rights = $rights }
  }
  return $null
}

function Get-PrivEscFileHash {
  param([string]$Path)
  try {
    if (-not $Path) { return $null }
    $p = $Path.Trim().Trim('"')
    if ($p -match '^(.*?\.(exe|dll|bat|cmd|scr|com|ps1|vbs|js))\b') { $p = $Matches[1] }
    $p = [System.Environment]::ExpandEnvironmentVariables($p)
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $p).Length -gt 100MB) { return 'skipped (>100MB)' }
    return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
  } catch { return $null }
}

function Get-ServiceExePath {
  param([string]$PathName)
  if (-not $PathName) { return $null }
  $p = $PathName.Trim()
  if ($p.StartsWith('"')) {
    $end = $p.IndexOf('"', 1)
    $p = if ($end -gt 1) { $p.Substring(1, $end - 1) } else { $p.Trim('"') }
  }
  elseif ($p -match '^(.*?\.exe)(\s|$)') { $p = $Matches[1] }
  else { $p = ($p -split '\s+')[0] }
  $p = $p -replace '^\\\?\?\\', ''
  $p = $p -replace '^(?i)\\SystemRoot', $env:SystemRoot
  $p = [System.Environment]::ExpandEnvironmentVariables($p)
  if ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
  return $p
}

$script:SvcSddlRightBits = [ordered]@{
  CC = [int64]1; DC = [int64]2; LC = [int64]4; SW = [int64]8
  RP = [int64]16; WP = [int64]32; DT = [int64]64; LO = [int64]128
  CR = [int64]256; SD = [int64]65536; RC = [int64]131072; WD = [int64]262144
  WO = [int64]524288; GA = [int64]268435456; GX = [int64]536870912; GW = [int64]1073741824; GR = [int64]2147483648
}

$script:SvcSddlEscalationRights = @('DC', 'WD', 'WO', 'GA', 'GW')

$script:SvcSddlLowPrivTrustees = @{
  WD = 'S-1-1-0'; BU = 'S-1-5-32-545'; AU = 'S-1-5-11'; IU = 'S-1-5-4'
  AN = 'S-1-5-7'; BG = 'S-1-5-32-546'; NU = 'S-1-5-2'
}

function ConvertFrom-ServiceSddlDacl {
  param([string]$Sddl)
  $result = New-Object System.Collections.Generic.List[object]
  if (-not $Sddl) { return $result }
  $s = ($Sddl -replace '\s', '')
  $dIdx = $s.IndexOf('D:')
  if ($dIdx -lt 0) { return $result }
  $dacl = $s.Substring($dIdx + 2)
  $sIdx = $dacl.IndexOf('S:')
  if ($sIdx -ge 0) { $dacl = $dacl.Substring(0, $sIdx) }
  foreach ($m in [regex]::Matches($dacl, '\(([^)]*)\)')) {
    $parts = $m.Groups[1].Value -split ';'
    if ($parts.Count -lt 6) { continue }
    $aceType = $parts[0]
    $rightsRaw = $parts[2]
    $trustee = $parts[5]
    $rightsList = New-Object System.Collections.Generic.List[string]
    if ($rightsRaw -match '^0x[0-9A-Fa-f]+$') {
      $mask = [Convert]::ToInt64($rightsRaw.Substring(2), 16)
      foreach ($k in $script:SvcSddlRightBits.Keys) {
        if (($mask -band $script:SvcSddlRightBits[$k]) -ne 0) { $rightsList.Add($k) }
      }
    }
    else {
      for ($i = 0; $i + 1 -lt $rightsRaw.Length; $i += 2) { $rightsList.Add($rightsRaw.Substring($i, 2).ToUpper()) }
    }
    $trusteeSid = $null
    if ($trustee -match '^S-1-') { $trusteeSid = $trustee }
    elseif ($script:SvcSddlLowPrivTrustees.ContainsKey($trustee)) { $trusteeSid = $script:SvcSddlLowPrivTrustees[$trustee] }
    $isLow = $false
    if ($script:SvcSddlLowPrivTrustees.ContainsKey($trustee)) { $isLow = $true }
    elseif ($trusteeSid -and $script:LowPrivSids -and $script:LowPrivSids.ContainsKey($trusteeSid)) { $isLow = $true }
    $esc = @($rightsList | Where-Object { $script:SvcSddlEscalationRights -contains $_ })
    $startStop = @($rightsList | Where-Object { $_ -in @('RP', 'WP', 'DT') })
    $result.Add([pscustomobject]@{
      AceType          = $aceType
      Trustee          = $trustee
      TrusteeSid       = $trusteeSid
      Rights           = ($rightsList -join '')
      RightsList       = @($rightsList)
      IsLowPriv        = $isLow
      EscalationRights = $esc
      IsEscalation     = ($aceType -eq 'A' -and $isLow -and $esc.Count -gt 0)
      IsStartStopOnly  = ($aceType -eq 'A' -and $isLow -and $esc.Count -eq 0 -and $startStop.Count -gt 0)
    })
  }
  return $result
}

$script:PeasServices = @()
try { $script:PeasServices = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service inventory not assessed' `
    -Detail ('Get-CimInstance Win32_Service failed: ' + $_.Exception.Message)
}

foreach ($hive in 'HKLM', 'HKCU') {
  $aie = (Get-ItemProperty "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($aie -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title "AlwaysInstallElevated=1 ($hive)" `
      -Detail 'Any MSI (including malicious) installs with SYSTEM privileges.' `
      -Remediation 'Set AlwaysInstallElevated=0 in both hives (or leave the policy undefined).'
  }
}

$unquoted = @()
try {
  $unquoted = @($script:PeasServices | Where-Object {
    $_.PathName -and $_.PathName -notmatch '"' -and $_.PathName -inotmatch ':\\Windows\\' -and $_.State -in @('Running', 'Stopped')
  } | Where-Object {
    $head = if ($_.PathName -match '^(?i)(.*?\.exe)') { $Matches[1] } else { $_.PathName }
    $head -match '\s'
  })
} catch { }
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
foreach ($svc in ($script:PeasServices | Where-Object { $_.PathName -like '*.exe*' })) {
  try {
    $Path = ($svc.PathName -split '(?<=\.exe\b)')[0].Trim('"')
    if ($Path -and -not $UniqueServices.ContainsKey($Path)) { $UniqueServices[$Path] = $svc.Name }
  } catch { }
}
foreach ($h in $UniqueServices.GetEnumerator()) {
  Start-ACLCheck -Target $h.Name -ServiceName $h.Value
}

$svcKeyHits = 0
foreach ($svcKey in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\services' -ErrorAction SilentlyContinue)) {
  try {
    $target = $svcKey.Name.Replace('HKEY_LOCAL_MACHINE', 'hklm:')
    $acl = Get-Acl $target -ErrorAction SilentlyContinue
    if (-not $acl) { continue }
    $weak = Get-LowPrivWriteAce -ACLObject $acl
    if ($weak) {
      $svcKeyHits++
      if ($svcKeyHits -le 25) {
        Add-Finding -Severity High -Category 'PrivEsc' -Title ("Service registry key modifiable by low-privilege principal: {0}" -f $svcKey.PSChildName) `
          -Detail ("{0} grants {1} to {2} ({3}) - an editable ImagePath yields SYSTEM." -f $target, $weak.Rights, $weak.Name, $weak.Sid) `
          -Evidence $target `
          -Remediation 'Restrict the key to Administrators/SYSTEM.'
      }
    }
  } catch { continue }
}
if ($svcKeyHits -gt 25) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title ("{0} service registry keys are modifiable by low-privilege principals (first 25 listed)" -f $svcKeyHits)
}

Write-Host '  Reading service object DACLs via sc.exe sdshow (this takes a moment)...' -ForegroundColor DarkGray
try {
  $sdChecked = 0; $sdFailed = 0; $sdFlagged = 0; $sdStartStop = New-Object System.Collections.Generic.List[string]
  $sdExe = Join-Path $env:SystemRoot 'System32\sc.exe'
  if (-not (Test-Path $sdExe)) { $sdExe = 'sc.exe' }
  foreach ($svc in $script:PeasServices) {
    if (-not $svc.Name) { continue }
    $sddl = $null
    try {
      $out = & $sdExe sdshow "$($svc.Name)" 2>$null
      $sddl = (@($out) | Where-Object { $_ -match 'D:' } | Select-Object -First 1)
    } catch { $sddl = $null }
    if (-not $sddl) { $sdFailed++; continue }
    $sdChecked++
    $aces = ConvertFrom-ServiceSddlDacl -Sddl "$sddl"
    $bad = @($aces | Where-Object { $_.IsEscalation })
    $ss = @($aces | Where-Object { $_.IsStartStopOnly })
    if ($ss.Count -gt 0 -and $sdStartStop.Count -lt 50) { $sdStartStop.Add($svc.Name) }
    if ($bad.Count -eq 0) { continue }
    $sdFlagged++
    if ($sdFlagged -gt 25) { continue }
    $asSystem = ("$($svc.StartName)" -match '(?i)^(\.\\)?LocalSystem$|S-1-5-18$|NT AUTHORITY\\SYSTEM$')
    $sev = if ($asSystem) { 'Critical' } else { 'High' }
    $who = ($bad | ForEach-Object {
      $label = if ($script:SvcSddlLowPrivTrustees.ContainsKey($_.Trustee)) { '{0} ({1})' -f $_.Trustee, $_.TrusteeSid }
               elseif ($script:LowPrivSids.ContainsKey("$($_.TrusteeSid)")) { '{0} ({1})' -f $script:LowPrivSids[$_.TrusteeSid], $_.TrusteeSid }
               else { $_.Trustee }
      '{0}: {1} [{2}]' -f $label, $_.Rights, ($_.EscalationRights -join ',')
    }) -join ' | '
    Add-Finding -Severity $sev -Category 'PrivEsc' -Title ("Service DACL lets a low-privilege principal reconfigure service: {0}" -f $svc.Name) `
      -Detail ("Runs as: {0} | State: {1} | Binary: {2} | Weak ACEs: {3}. DC = change config (repoint the binary), WD = rewrite the DACL, WO = take ownership, GA/GW = generic all/write." -f $svc.StartName, $svc.State, $svc.PathName, $who) `
      -Evidence ("sc.exe sdshow {0} :: {1}" -f $svc.Name, $sddl) `
      -Remediation 'Reset the service security descriptor so only Administrators and SYSTEM hold DC/WD/WO (sc.exe sdset with the vendor default, or reinstall the service). MITRE T1543.003 / T1574.011.'
  }
  if ($sdFlagged -gt 25) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("{0} services have a low-privilege reconfigure right in their DACL (first 25 listed)" -f $sdFlagged)
  }
  if ($sdChecked -eq 0) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service object DACLs not assessed' `
      -Detail ('sc.exe sdshow returned no SDDL for any service ({0} services attempted).' -f $sdFailed)
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title ("Service object DACLs read for {0} services ({1} weak, {2} unreadable)" -f $sdChecked, $sdFlagged, $sdFailed) `
      -Detail $(if ($sdStartStop.Count -gt 0) { ('Low-privilege start/stop/pause rights (not an escalation on their own) on: ' + (($sdStartStop | Select-Object -First 15) -join ', ') + $(if ($sdStartStop.Count -gt 15) { ' ...' } else { '' })) } else { 'No low-privilege principal holds start/stop rights on any service.' })
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service object DACLs not assessed' `
    -Detail ('sc.exe sdshow sweep failed: ' + $_.Exception.Message)
}

try {
  $userDirRx = '(?i)^[A-Z]:\\(ProgramData|Users\\[^\\]+\\(AppData|Downloads)|Windows\\Temp|Temp|Users\\Public)'
  $binSeen = @{}
  $binFlagged = 0; $binChecked = 0; $binUnsigned = 0
  foreach ($svc in $script:PeasServices) {
    if (-not $svc.PathName) { continue }
    $exe = Get-ServiceExePath -PathName $svc.PathName
    if (-not $exe -or $binSeen.ContainsKey($exe.ToLower())) { continue }
    $binSeen[$exe.ToLower()] = $true
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
    $binChecked++
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop } catch { }
    $sigStatus = if ($sig) { "$($sig.Status)" } else { 'unknown' }
    $signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    $isMsSigned = ($sigStatus -eq 'Valid' -and $signer -match 'Microsoft')
    $inWindows = $exe -like "$env:SystemRoot\*"
    if ($isMsSigned -and $inWindows) { continue }
    $folder = Split-Path $exe -Parent
    $folderHit = $null
    try {
      $facl = Get-Acl -LiteralPath $folder -ErrorAction SilentlyContinue
      if ($facl) { $folderHit = Get-LowPrivFolderWriteAce -ACLObject $facl }
    } catch { }
    if ($folderHit -and $folder -like "$env:USERPROFILE*" -and $folderHit.Sid -eq $script:AclCurrent.User.Value) { $folderHit = $null }
    $inUserDir = ($exe -match $userDirRx)
    $unsigned = ($sigStatus -ne 'Valid')
    if ($unsigned) { $binUnsigned++ }

    if ($inUserDir -and -not $folderHit -and $isMsSigned) { continue }
    if (-not $folderHit -and -not $inUserDir -and -not $unsigned) { continue }
    $sev = if ($folderHit) { 'High' } elseif ($unsigned) { $(if ($inUserDir) { 'Medium' } else { 'Low' }) } else { 'Low' }
    $why = @()
    if ($folderHit) { $why += ('folder writable by {0} ({1}: {2})' -f $folderHit.Name, $folderHit.Sid, $folderHit.Level) }
    if ($inUserDir) { $why += $(if ($folderHit) { 'lives in a user-writable location' } else { 'lives in a typically user-writable tree (folder ACL restricts writes)' }) }
    if ($unsigned) { $why += ('signature {0}' -f $sigStatus) } elseif ($signer) { $why += ('signed by {0}' -f (($signer -split ',')[0] -replace '^CN=', '')) }
    $binFlagged++
    if ($binFlagged -gt 25) { continue }
    Add-Finding -Severity $sev -Category 'PrivEsc' -Title ("Service binary {0}: {1}" -f $(if ($folderHit) { 'in user-writable folder' } elseif ($inUserDir) { 'in user-writable location' } else { 'unsigned' }), $svc.Name) `
      -Detail ("Binary: {0} | Runs as: {1} | StartMode: {2} | State: {3} | {4}" -f $exe, $svc.StartName, $svc.StartMode, $svc.State, ($why -join '; ')) `
      -Evidence ("{0} :: SHA256 {1}" -f $exe, (Get-PrivEscFileHash $exe)) `
      -Remediation $(if ($folderHit) { 'Move the service binary to a folder writable only by Administrators and SYSTEM, or fix the folder ACL. A writable folder lets any user replace the binary or plant a DLL beside it.' } else { 'Confirm the binary is the expected vendor build (hash against the vendor release) and move services out of ProgramData, AppData, Temp and Public. Unsigned service binaries cannot be validated by signature. MITRE T1543.003.' })
  }
  if ($binFlagged -gt 25) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("{0} service binaries flagged for location or signature (first 25 listed)" -f $binFlagged)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ("Service binaries checked: {0} unique ({1} flagged, {2} without a valid signature)" -f $binChecked, $binFlagged, $binUnsigned) `
    -Detail 'Microsoft-signed binaries under the Windows directory are not reported.'
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Service binary location and signature not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

try {
  $dllChecked = 0; $dllFlagged = 0
  $sys32 = (Join-Path $env:SystemRoot 'System32').ToLower()
  $wow64 = (Join-Path $env:SystemRoot 'SysWOW64').ToLower()
  foreach ($svc in ($script:PeasServices | Where-Object { $_.PathName -match '(?i)svchost\.exe' })) {
    $dll = $null
    foreach ($k in @("HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters", "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)")) {
      try { $dll = (Get-ItemProperty $k -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll } catch { }
      if ($dll) { break }
    }
    if (-not $dll) { continue }
    $dllPath = "$dll".Trim().Trim('"')
    $dllPath = $dllPath -replace '^\\\?\?\\', ''
    $dllPath = $dllPath -replace '^(?i)\\SystemRoot', $env:SystemRoot
    $dllPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
    $dllChecked++
    $lower = $dllPath.ToLower()
    $outside = -not ($lower.StartsWith($sys32 + '\') -or $lower.StartsWith($wow64 + '\'))
    $sigStatus = 'not checked'; $signer = ''
    if (Test-Path -LiteralPath $dllPath -PathType Leaf) {
      try {
        $sig = Get-AuthenticodeSignature -LiteralPath $dllPath -ErrorAction Stop
        $sigStatus = "$($sig.Status)"
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
      } catch { $sigStatus = 'unknown' }
    }
    else { $sigStatus = 'file missing' }
    $notMs = -not ($sigStatus -eq 'Valid' -and $signer -match 'Microsoft')
    if (-not $outside -and -not $notMs) { continue }
    $dllFlagged++
    if ($dllFlagged -gt 25) { continue }
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("svchost ServiceDll {0}: {1}" -f $(if ($outside) { 'outside System32' } else { 'not Microsoft-signed' }), $svc.Name) `
      -Detail ("ServiceDll: {0} | Signature: {1}{2} | Runs as: {3} | State: {4}" -f $dllPath, $sigStatus, $(if ($signer) { ' (' + (($signer -split ',')[0] -replace '^CN=', '') + ')' } else { '' }), $svc.StartName, $svc.State) `
      -Evidence ("HKLM:\SYSTEM\CurrentControlSet\Services\{0} :: ServiceDll{1}" -f $svc.Name, $(if ($sigStatus -ne 'file missing') { ' :: SHA256 ' + (Get-PrivEscFileHash $dllPath) } else { '' })) `
      -Remediation 'Every svchost-hosted service ships from Microsoft and loads from System32 or SysWOW64. Attribute the DLL immediately; a third-party or relocated ServiceDll runs inside a trusted host process. MITRE T1543.003.'
  }
  if ($dllFlagged -gt 25) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title ("{0} svchost ServiceDll entries flagged (first 25 listed)" -f $dllFlagged)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ("svchost ServiceDll entries checked: {0} ({1} flagged)" -f $dllChecked, $dllFlagged)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'svchost ServiceDll check not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

try {
  $pfDirs = New-Object System.Collections.Generic.List[string]
  foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) }) {
    foreach ($d in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) { $pfDirs.Add($d.FullName) }
  }
  foreach ($s in $unquoted) {
    $head = if ($s.PathName -match '^(?i)(.*?\.exe)') { $Matches[1] } else { $s.PathName }
    $dir = Split-Path $head -Parent
    while ($dir -and $dir.Length -gt 3) {
      if (-not $pfDirs.Contains($dir)) { $pfDirs.Add($dir) }
      $dir = Split-Path $dir -Parent
    }
  }
  $svcDirs = @{}
  foreach ($p in $UniqueServices.Keys) { $parent = Split-Path $p -Parent; if ($parent) { $svcDirs[$parent.ToLower()] = $UniqueServices[$p] } }
  $pfHits = 0; $pfChecked = 0
  foreach ($d in $pfDirs) {
    try {
      if (-not (Test-Path -LiteralPath $d)) { continue }
      $acl = Get-Acl -LiteralPath $d -ErrorAction SilentlyContinue
      if (-not $acl) { continue }
      $pfChecked++
      $hit = Get-LowPrivFolderWriteAce -ACLObject $acl
      if (-not $hit) { continue }
      $svcHere = @($svcDirs.Keys | Where-Object { $_ -eq $d.ToLower() -or $_.StartsWith($d.ToLower() + '\') } | ForEach-Object { $svcDirs[$_] } | Select-Object -Unique)
      $pfHits++
      if ($pfHits -gt 25) { continue }
      Add-Finding -Severity $(if ($svcHere.Count -gt 0) { 'High' } else { 'Medium' }) -Category 'PrivEsc' -Title ("Low-privilege '{0}' can write into program folder: {1}" -f $hit.Name, $d) `
        -Detail ("{0} ({1}) has {2} ({3}){4}. Files planted here are loaded by whatever runs from this folder." -f $hit.Name, $hit.Sid, $hit.Level, $hit.Rights, $(if ($svcHere.Count -gt 0) { ' | service binaries under this folder: ' + ($svcHere -join ', ') } else { '' })) `
        -Evidence $d `
        -Remediation 'Reset the folder ACL so only Administrators, SYSTEM and TrustedInstaller can create or modify files. MITRE T1574.005 / T1574.010.'
    } catch { continue }
  }
  if ($pfHits -gt 25) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("{0} program folders are writable by low-privilege principals (first 25 listed)" -f $pfHits)
  }
  Add-Finding -Severity Info -Category 'PrivEsc' -Title ("Program folders checked for low-privilege write access: {0} ({1} writable)" -f $pfChecked, $pfHits)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Program folder ACLs not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
}

try {
  $meName = "$($script:AclCurrent.Name)"
  $meSidP = "$($script:AclCurrent.User.Value)"

  $ownerMap = @{}
  try { foreach ($gp in (Get-Process -IncludeUserName -ErrorAction Stop)) { if ($gp.UserName) { $ownerMap[[int]$gp.Id] = $gp.UserName } } } catch { }
  $procSeen = @{}
  $procHits = 0; $procChecked = 0
  foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.ExecutablePath })) {
    $k = $proc.ExecutablePath.ToLower()
    if ($procSeen.ContainsKey($k) -or $UniqueServices.ContainsKey($proc.ExecutablePath)) { continue }
    $procSeen[$k] = $true
    if ($procSeen.Count -gt 300) { break }
    try {
      $acl = Get-Acl -LiteralPath $proc.ExecutablePath -ErrorAction SilentlyContinue
      if (-not $acl) { continue }
      $procChecked++
      $hit = Get-LowPrivWriteAce -ACLObject $acl
      if (-not $hit) { continue }
      $owner = ''
      if ($ownerMap.ContainsKey([int]$proc.ProcessId)) { $owner = $ownerMap[[int]$proc.ProcessId] }
      elseif ($procHits -lt 25) {

        try {
          $o = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction Stop
          if ($o -and $o.User) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { }
      }
      $isMine = ($owner -and $owner -ieq $meName)
      if ($isMine -and $hit.Sid -eq $meSidP) { continue }
      $procHits++
      if ($procHits -gt 25) { continue }
      Add-Finding -Severity $(if ($isMine) { 'Medium' } else { 'High' }) -Category 'Filesystem ACL' -Title ("Low-privilege '{0}' has {1} on running process binary: {2}" -f $hit.Name, $hit.Level, $proc.Name) `
        -Detail ("{0} | runs as: {1} | {2} ({3}) can {4} this file. {5}" -f $proc.ExecutablePath, $(if ($owner) { $owner } else { 'unknown' }), $hit.Name, $hit.Sid, $hit.Level.ToLower(), $(if ($isMine) { 'The process is this user''s own, so the exposure is to other low-privilege principals on this host.' } else { 'The process runs as a different principal, so replacing the file crosses a privilege boundary at the next start.' })) `
        -Evidence $proc.ExecutablePath `
        -Remediation 'Keep executables in folders writable only by Administrators, SYSTEM and TrustedInstaller; install tools per-machine instead of in shared or world-writable trees.'
    } catch { continue }
  }
  if ($procHits -gt 25) {
    Add-Finding -Severity Medium -Category 'Filesystem ACL' -Title ("{0} running-process binaries are writable by low-privilege principals (first 25 listed)" -f $procHits)
  }
  Add-Finding -Severity Info -Category 'Filesystem ACL' -Title ("Running-process binaries checked: {0} unique ({1} writable by a low-privilege principal)" -f $procChecked, $procHits)
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Running-process binary ACLs not assessed' `
    -Detail ('Win32_Process read failed: ' + $_.Exception.Message)
}

foreach ($startup in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                       "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
  if (Test-Path $startup) {
    $items = @(Get-ChildItem $startup -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
      if ($i.PSIsContainer) { continue }
      try {
        $acl = Get-Acl -LiteralPath $i.FullName -ErrorAction SilentlyContinue
        if (-not $acl) { continue }
        $w = Get-LowPrivWriteAce -ACLObject $acl
        if ($w -and $i.FullName -like "$env:USERPROFILE*" -and $w.Sid -eq $script:AclCurrent.User.Value) { $w = $null }
        if ($w) {
          Add-Finding -Severity High -Category 'PrivEsc' -Title ("User-writable startup item: {0}" -f $i.Name) `
            -Detail ("{0} | {1} ({2}) has {3}" -f $i.FullName, $w.Name, $w.Sid, $w.Level) -Evidence $i.FullName `
            -Remediation 'Persistence point: any user can plant malware executed at admin logon. Restrict ACLs, remove stale entries.'
        }
      } catch { continue }
    }
  }
}

$runSeen = @{}
foreach ($rk in @('registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                  'registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
                  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $item = Get-Item $rk -ErrorAction SilentlyContinue
  if ($item -and $item.Property) {
    foreach ($p in $item.Property) {
      $val = (Get-ItemProperty $rk).$p
      $runSeen[("{0}|{1}" -f $p, $val).ToLower()] = $true
      $hash = Get-PrivEscFileHash ([string]$val)
      Add-Finding -Severity Low -Category 'Persistence' -Title ("Autorun entry: {0}" -f $p) `
        -Detail ("{0} = {1}" -f $rk.Replace('registry::', ''), $val) `
        -Evidence $(if ($hash) { "SHA256 $hash" } else { '' }) `
        -Remediation 'Validate each entry against a known-good baseline; autoruns are the #1 malware persistence slot.'
    }
  }
}

try {
  $meSid = "$($script:AclCurrent.User.Value)"
  $extra = 0
  foreach ($sc in @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)) {
    $loc = "$($sc.Location)"
    if ($loc -match '^(?i)HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?$') { continue }
    if ($meSid -and $loc -match ('^(?i)HKU\\' + [regex]::Escape($meSid) + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?$')) { continue }
    if ($runSeen.ContainsKey(("{0}|{1}" -f $sc.Name, $sc.Command).ToLower())) { continue }
    $extra++
    if ($extra -gt 40) { continue }
    $hash = Get-PrivEscFileHash ([string]$sc.Command)
    Add-Finding -Severity Low -Category 'Persistence' -Title ("Autorun entry ({0}): {1}" -f $loc, $sc.Name) `
      -Detail ("Command: {0} | User: {1}" -f $sc.Command, $sc.User) `
      -Evidence $(if ($hash) { "SHA256 $hash" } else { '' }) `
      -Remediation 'Validate each entry against a known-good baseline; autoruns are the #1 malware persistence slot.'
  }
  if ($extra -gt 40) {
    Add-Finding -Severity Low -Category 'Persistence' -Title ("{0} additional startup commands found (first 40 listed)" -f $extra)
  }
} catch {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Win32_StartupCommand inventory not assessed' `
    -Detail ('Read failed: ' + $_.Exception.Message)
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

try {
  $privRows = @()
  $csvLines = @(whoami.exe /priv /fo csv /nh 2>$null | Where-Object { $_ -and $_.Trim() })
  if ($csvLines.Count -gt 0) { $privRows = @($csvLines | ConvertFrom-Csv -Header 'Name', 'Description', 'State') }
  if ($privRows.Count -eq 0) { throw 'whoami /priv returned no rows' }
  $anchor = $privRows | Where-Object { $_.Name -eq 'SeChangeNotifyPrivilege' } | Select-Object -First 1
  $enabledWord = if ($anchor) { "$($anchor.State)".Trim() } else { $null }
  $dangerHeld = 0
  foreach ($dangerPriv in @('SeImpersonatePrivilege', 'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                            'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege', 'SeCreateTokenPrivilege', 'SeTcbPrivilege',
                            'SeAssignPrimaryTokenPrivilege')) {
    $row = $privRows | Where-Object { $_.Name -eq $dangerPriv } | Select-Object -First 1
    if (-not $row) { continue }
    $dangerHeld++
    $state = "$($row.State)".Trim()
    $isEnabled = if ($enabledWord) { $state -eq $enabledWord } else { $state -match '^Enabled$' }
    if ($isEnabled) {
      Add-Finding -Severity High -Category 'PrivEsc' -Title ("Current user holds {0} (enabled)" -f $dangerPriv) `
        -Detail 'Dangerous privilege - standard tooling can turn this into SYSTEM or credential access.' `
        -Remediation 'Remove the account from the granting group/local policy (e.g. Administrators, Backup Operators) unless operationally required.'
    }
    else {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title ("Current user holds {0} (present, not enabled)" -f $dangerPriv) `
        -Detail ('The privilege is in the token in a disabled state. Any process of this user can enable it with AdjustTokenPrivileges, so it is held, not absent. Token state: ' + $state) `
        -Remediation 'Remove the account from the granting group/local policy unless operationally required.'
    }
  }
  if ($dangerHeld -eq 0) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Current token holds none of the 9 dangerous privileges ({0} privileges listed by whoami /priv)' -f $privRows.Count)
  }
  if (-not $anchor) {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Token privilege state compared against the English word only' `
      -Detail 'SeChangeNotifyPrivilege was not in the whoami output, so the localized "Enabled" string could not be learned.'
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Current-user token privileges not assessed' `
    -Detail ('whoami /priv failed: ' + $_.Exception.Message)
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

try {
  $uacSecondary = @(
    @{ Name = 'FilterAdministratorToken'; Want = 1; DefaultAbsent = 0; Note = 'built-in Administrator (RID 500) runs with a full token (CIS 2.3.17.1)' }
    @{ Name = 'ConsentPromptBehaviorUser'; Want = 0; DefaultAbsent = 3; Note = 'standard users are prompted for admin credentials instead of being denied (CIS 2.3.17.3)' }
    @{ Name = 'PromptOnSecureDesktop'; Want = 1; DefaultAbsent = 1; Note = 'elevation prompts are not on the secure desktop and can be spoofed (CIS 2.3.17.6)' }
    @{ Name = 'EnableSecureUIAPaths'; Want = 1; DefaultAbsent = 1; Note = 'UIAccess applications may run from any location (CIS 2.3.17.5)' }
    @{ Name = 'EnableInstallerDetection'; Want = 1; DefaultAbsent = 1; Note = 'installer elevation detection is off (CIS 2.3.17.4)' }
    @{ Name = 'EnableVirtualization'; Want = 1; DefaultAbsent = 1; Note = 'file and registry write failures are not virtualized to per-user locations (CIS 2.3.17.7)' }
  )
  $uacMiss = @()
  foreach ($u in $uacSecondary) {
    $present = $uacProps -and ($uacProps.PSObject.Properties.Name -contains $u.Name)
    $val = if ($present) { [int]$uacProps.($u.Name) } else { $u.DefaultAbsent }
    if ($val -ne $u.Want) { $uacMiss += ('{0} = {1}{2}: {3}' -f $u.Name, $val, $(if ($present) { '' } else { ' (absent, OS default)' }), $u.Note) }
  }
  if ($uacMiss.Count -gt 0) {
    Add-Finding -Severity Low -Category 'PrivEsc' -Title ("{0} secondary UAC value(s) below the CIS benchmark" -f $uacMiss.Count) `
      -Detail ($uacMiss -join ' | ') `
      -Evidence $uacKey `
      -Remediation 'Set the listed values under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System per CIS 2.3.17.x (FilterAdministratorToken=1, ConsentPromptBehaviorUser=0, PromptOnSecureDesktop=1, EnableSecureUIAPaths=1, EnableInstallerDetection=1, EnableVirtualization=1).'
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Secondary UAC values meet the CIS benchmark'
  }
} catch { }

if ($uacProps -and $uacProps.LocalAccountTokenFilterPolicy -eq 1) {
  Add-Finding -Severity High -Category 'PrivEsc' -Title 'Remote UAC restrictions disabled (LocalAccountTokenFilterPolicy = 1)' `
    -Detail 'Local administrator accounts receive a full token over the network, enabling pass-the-hash and remote admin-share access with local credentials.' `
    -Evidence $uacKey `
    -Remediation 'Delete LocalAccountTokenFilterPolicy unless a remote-management tool documents needing it; prefer domain accounts for remote admin.'
}

$pnKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$pn = Get-ItemProperty $pnKey -ErrorAction SilentlyContinue
if ($pn) {
  $rdita = if ($pn.PSObject.Properties.Name -contains 'RestrictDriverInstallationToAdministrators') { [int]$pn.RestrictDriverInstallationToAdministrators } else { $null }
  $nwne = if ($pn.PSObject.Properties.Name -contains 'NoWarningNoElevationOnInstall') { [int]$pn.NoWarningNoElevationOnInstall } else { $null }
  $ups = if ($pn.PSObject.Properties.Name -contains 'UpdatePromptSettings') { [int]$pn.UpdatePromptSettings } else { $null }
  if ($rdita -eq 0 -and $nwne -eq 1) {
    Add-Finding -Severity Critical -Category 'PrivEsc' -Title 'PointAndPrint policy allows silent non-admin printer driver installs' `
      -Detail ('RestrictDriverInstallationToAdministrators = 0 and NoWarningNoElevationOnInstall = 1{0}. Known PrintNightmare-style driver install path to SYSTEM (CVE-2021-34527).' -f $(if ($null -ne $ups) { ', UpdatePromptSettings = ' + $ups } else { '' })) `
      -Evidence $pnKey `
      -Remediation 'Set RestrictDriverInstallationToAdministrators=1; remove NoWarningNoElevationOnInstall and UpdatePromptSettings.'
  }
  elseif ($rdita -eq 0) {
    Add-Finding -Severity High -Category 'PrivEsc' -Title 'PointAndPrint allows non-admin printer driver installs (RestrictDriverInstallationToAdministrators = 0)' `
      -Detail ('This value alone re-enables the non-admin driver install path that KB5005652 closed{0}.' -f $(if ($null -ne $nwne) { '; NoWarningNoElevationOnInstall = ' + $nwne } else { '' })) `
      -Evidence $pnKey `
      -Remediation 'Set RestrictDriverInstallationToAdministrators=1 (or delete the value; the default is 1).'
  }
  elseif ($nwne -eq 1 -or $ups -eq 2) {
    Add-Finding -Severity Medium -Category 'PrivEsc' -Title 'PointAndPrint suppresses driver install or update warnings' `
      -Detail ('NoWarningNoElevationOnInstall = {0}, UpdatePromptSettings = {1}. Driver installs remain admin-only (RestrictDriverInstallationToAdministrators is not 0), but prompts are suppressed for admins.' -f $nwne, $ups) `
      -Evidence $pnKey `
      -Remediation 'Remove NoWarningNoElevationOnInstall and UpdatePromptSettings unless a documented print-server trust relationship requires them.'
  }
  else {
    Add-Finding -Severity Info -Category 'PrivEsc' -Title 'PointAndPrint policy present with admin-only driver installation' `
      -Detail ('RestrictDriverInstallationToAdministrators = {0}; NoWarningNoElevationOnInstall = {1}; UpdatePromptSettings = {2}' -f $rdita, $nwne, $ups)
  }
}
else {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'No PointAndPrint policy override (OS default: admin-only driver installation)'
}

try {
  $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
  if ($spooler) {
    $productType = 1
    try { $productType = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType } catch { }
    $rpcEp = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -ErrorAction SilentlyContinue).RegisterSpoolerRemoteRpcEndPoint
    $rpcOff = ($rpcEp -eq 2)
    $running = ($spooler.Status -eq 'Running')
    $role = switch ($productType) { 2 { 'domain controller' } 3 { 'server' } default { 'workstation' } }
    if ($running -and $productType -eq 2) {
      Add-Finding -Severity High -Category 'PrivEsc' -Title 'Print Spooler running on a domain controller' `
        -Detail ('Spooler: {0} ({1}); remote RPC endpoint policy: {2}. The spooler on a DC is the PrintNightmare and printer-bug coercion target.' -f $spooler.Status, $spooler.StartType, $(if ($null -ne $rpcEp) { $rpcEp } else { 'not set' })) `
        -Remediation 'Disable the Print Spooler service on domain controllers (CIS 5.x / Microsoft guidance), or at minimum set RegisterSpoolerRemoteRpcEndPoint = 2.'
    }
    elseif ($running -and $productType -eq 3 -and -not $rpcOff) {
      Add-Finding -Severity Medium -Category 'PrivEsc' -Title 'Print Spooler running on a server without the remote RPC endpoint disabled' `
        -Detail ('Spooler: {0} ({1}); RegisterSpoolerRemoteRpcEndPoint: {2}. Remote clients can reach the spooler RPC interface.' -f $spooler.Status, $spooler.StartType, $(if ($null -ne $rpcEp) { $rpcEp } else { 'not set' })) `
        -Remediation 'Disable the Spooler on servers that do not print; otherwise set RegisterSpoolerRemoteRpcEndPoint = 2 under HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers.'
    }
    elseif ($running -and $null -eq $rpcEp) {
      Add-Finding -Severity Low -Category 'PrivEsc' -Title ('Print Spooler running on a {0} with no remote RPC policy' -f $role) `
        -Detail ('Spooler: {0} ({1}). No RegisterSpoolerRemoteRpcEndPoint policy is set, so the spooler accepts remote RPC connections.' -f $spooler.Status, $spooler.StartType) `
        -Remediation 'On hosts that only print locally, set RegisterSpoolerRemoteRpcEndPoint = 2 (Allow Print Spooler to accept client connections: Disabled).'
    }
    else {
      Add-Finding -Severity Info -Category 'PrivEsc' -Title ('Print Spooler: {0} ({1}) on a {2}; remote RPC endpoint policy: {3}' -f $spooler.Status, $spooler.StartType, $role, $(if ($null -ne $rpcEp) { $rpcEp } else { 'not set' }))
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'PrivEsc' -Title 'Print Spooler exposure not assessed' `
    -Detail ('Check failed: ' + $_.Exception.Message)
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
  $profSummary = @()
  foreach ($prof in (Get-NetFirewallProfile -ErrorAction Stop)) {
    if (-not $prof.Enabled) {
      Add-Finding -Severity High -Category 'Network' -Title ("Firewall profile '{0}' disabled" -f $prof.Name) `
        -Remediation 'Enable all firewall profiles via GPO.'
    }
    if ("$($prof.DefaultInboundAction)" -eq 'Allow') {
      Add-Finding -Severity High -Category 'Network' -Title ("Firewall profile '{0}' default inbound action is Allow" -f $prof.Name) `
        -Detail 'Every inbound connection not matched by a block rule is accepted; the firewall is effectively open on this profile.' `
        -Remediation ("Set-NetFirewallProfile -Name {0} -DefaultInboundAction Block (CIS 9.x.2)." -f $prof.Name)
    }
    if ("$($prof.Name)" -eq 'Domain' -and $prof.Enabled -and ("$($prof.AllowLocalFirewallRules)" -eq 'True' -or "$($prof.AllowLocalIPsecRules)" -eq 'True')) {
      Add-Finding -Severity Low -Category 'Network' -Title 'Domain firewall profile merges locally defined rules' `
        -Detail ("AllowLocalFirewallRules={0}; AllowLocalIPsecRules={1}. A local admin (or malware running as one) can add allow rules that GPO does not override." -f $prof.AllowLocalFirewallRules, $prof.AllowLocalIPsecRules) `
        -Remediation 'Set "Apply local firewall rules" and "Apply local connection security rules" to No on the Domain profile (CIS 9.1.5, 9.1.6).'
    }
    $profSummary += ('{0}: enabled={1}, inbound={2}, outbound={3}' -f $prof.Name, $prof.Enabled, $prof.DefaultInboundAction, $prof.DefaultOutboundAction)
  }
  Add-Finding -Severity Info -Category 'Network' -Title 'Firewall profile states recorded' -Detail ($profSummary -join ' | ')
}
catch {
  Add-Finding -Severity Info -Category 'Network' -Title 'Firewall profiles not assessed' -Detail ('Get-NetFirewallProfile failed: ' + $_.Exception.Message)
}

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

$script:ShareWriteMask = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000   
try {
  $shareCount = 0
  foreach ($share in @(Get-SmbShare -ErrorAction Stop)) {
    if ($share.Special) { continue }
    if ($share.Name -eq 'IPC$' -or $share.Name -eq 'ADMIN$' -or $share.Name -match '^[A-Za-z]\$$') { continue }
    $shareCount++
    $broad = @()
    try {
      if ($share.SecurityDescriptor) {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($share.SecurityDescriptor)
        foreach ($ace in $sd.DiscretionaryAcl) {
          if ("$($ace.AceType)" -ne 'AccessAllowed') { continue }
          $sid = "$($ace.SecurityIdentifier.Value)"
          if (-not $script:LowPrivSids.ContainsKey($sid)) { continue }
          if (($ace.AccessMask -band $script:ShareWriteMask) -eq 0) { continue }
          $broad += [pscustomobject]@{ Name = $script:LowPrivSids[$sid]; Sid = $sid; Mask = ('0x{0:X}' -f $ace.AccessMask) }
        }
      }
    } catch { }
    if ($broad.Count -eq 0) { continue }
    $who = ($broad | ForEach-Object { '{0} ({1}, mask {2})' -f $_.Name, $_.Sid, $_.Mask }) -join ', '
    $ntfsHit = $null; $ntfsReadable = $false
    try {
      if ($share.Path -and (Test-Path -LiteralPath $share.Path)) {
        $acl = Get-Acl -LiteralPath $share.Path -ErrorAction Stop
        $ntfsReadable = $true
        $ntfsHit = Get-LowPrivWriteAce -ACLObject $acl
      }
    } catch { $ntfsReadable = $false }
    if ($ntfsHit) {
      Add-Finding -Severity Medium -Category 'Network' -Title ("Share '{0}' writable by low-privilege principals (share and NTFS agree)" -f $share.Name) `
        -Detail ("Path: {0}. Share ACL grants write to {1}; NTFS grants {2} to {3} ({4})." -f $share.Path, $who, $ntfsHit.Level, $ntfsHit.Name, $ntfsHit.Sid) `
        -Evidence ("\\{0}\{1} -> {2}" -f $env:COMPUTERNAME, $share.Name, $share.Path) `
        -Remediation 'Restrict share and NTFS permissions to the groups that need write; writable broad shares are lateral-movement and ransomware vectors.'
    }
    elseif ($ntfsReadable) {
      Add-Finding -Severity Low -Category 'Network' -Title ("Share '{0}' ACL is broad but NTFS restricts write" -f $share.Name) `
        -Detail ("Path: {0}. Share ACL grants write to {1}, but no low-privilege principal has write on the folder's NTFS ACL, so the effective access is read-only. Tightening the share ACL removes the dependency on NTFS." -f $share.Path, $who) `
        -Evidence ("\\{0}\{1} -> {2}" -f $env:COMPUTERNAME, $share.Name, $share.Path) `
        -Remediation 'Reduce the share permission to Read for broad groups so NTFS is not the only control.'
    }
    else {
      Add-Finding -Severity Low -Category 'Network' -Title ("Share '{0}' ACL is broad; NTFS not assessed" -f $share.Name) `
        -Detail ("Path: {0}. Share ACL grants write to {1}; the folder ACL could not be read, so effective write access is unknown." -f $share.Path, $who) `
        -Evidence ("\\{0}\{1} -> {2}" -f $env:COMPUTERNAME, $share.Name, $share.Path) `
        -Remediation 'Check the NTFS ACL of the share path; restrict the share permission to Read for broad groups.'
    }
  }
  Add-Finding -Severity Info -Category 'Network' -Title ("{0} non-default SMB shares assessed" -f $shareCount)
} catch {
  Add-Finding -Severity Info -Category 'Network' -Title 'SMB shares not assessed' -Detail ('Get-SmbShare failed: ' + $_.Exception.Message)
}

Start-Section 'LOCAL ACCOUNT HYGIENE'
try {

  $na = @(net accounts 2>$null)
  $minLen = $na | Where-Object { $_ -match 'minimum password length' } | Select-Object -First 1
  if (-not $minLen) {
    $kv = @($na | Where-Object { $_ -match ':\s*\S' })
    if ($kv.Count -ge 4) { $minLen = $kv[3] }
  }
  if (-not $minLen) { throw 'net accounts returned no password policy' }
  $digits = ($minLen -split ':', 2)[1] -replace '[^\d]', ''
  $val = if ($digits) { [int]$digits } else { 0 }
  if ($val -lt 14) {
    Add-Finding -Severity Medium -Category 'Accounts' -Title ("Minimum password length {0} (<14)" -f $val) `
      -Evidence ($minLen.Trim()) `
      -Remediation 'Raise minimum length to 14+ (CIS 1.1.4) and pair with banned-password lists.'
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title "Minimum password length ${val}"
  }

  $lockLine = $na | Where-Object { $_ -match 'lockout threshold' } | Select-Object -First 1
  if (-not $lockLine) {
    $kv = @($na | Where-Object { $_ -match ':\s*\S' })
    if ($kv.Count -ge 6) { $lockLine = $kv[5] }
  }
  if ($lockLine) {
    $lockDigits = ($lockLine -split ':', 2)[1] -replace '[^\d]', ''
    $lockVal = if ($lockDigits) { [int]$lockDigits } else { 0 }
    if ($lockVal -eq 0) {
      Add-Finding -Severity Medium -Category 'Accounts' -Title 'Account lockout threshold: 0 (never locks)' `
        -Detail 'Unlimited password guesses against every local account, over the network and at the console.' `
        -Evidence ($lockLine.Trim()) `
        -Remediation 'Set lockout threshold to 5 or fewer invalid attempts (CIS 1.2.2) with a 15-minute duration and reset window.'
    }
    elseif ($lockVal -gt 10) {
      Add-Finding -Severity Low -Category 'Accounts' -Title ("Account lockout threshold {0} (CIS wants 5 or fewer)" -f $lockVal) `
        -Evidence ($lockLine.Trim()) -Remediation 'Lower the threshold to 5 or fewer invalid attempts (CIS 1.2.2).'
    }
    else {
      Add-Finding -Severity Info -Category 'Accounts' -Title ("Account lockout threshold {0}" -f $lockVal) -Evidence ($lockLine.Trim())
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title 'Account lockout threshold not assessed' -Detail 'net accounts output had fewer than six policy lines.'
  }
} catch {
  Add-Finding -Severity Info -Category 'Accounts' -Title 'Password and lockout policy not assessed' -Detail ('net accounts failed: ' + $_.Exception.Message)
}

try {

  $limitBlank = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse
  $blankOverNetworkAllowed = ($limitBlank -eq 0)

  $users = Get-LocalUser -ErrorAction Stop
  foreach ($u in $users) {
    if ($u.Enabled -and -not $u.PasswordRequired) {
      $hasPwdEvidence = $null -ne $u.PasswordLastSet
      $sev = if ($blankOverNetworkAllowed) { 'High' } elseif ($hasPwdEvidence) { 'Low' } else { 'Medium' }
      $detail = "The PASSWD_NOTREQD flag is set, so this account is allowed to have a blank password. That is not proof it has one, and this scan does not attempt authentication to find out."
      $detail += if ($hasPwdEvidence) { (" A password was last set {0:yyyy-MM-dd}, which indicates one exists." -f $u.PasswordLastSet) } else { ' No password-set timestamp is recorded, so a blank password is plausible.' }
      $detail += if ($blankOverNetworkAllowed) {
        ' LimitBlankPasswordUse = 0, so a blank password WOULD be usable for network logon. This is the combination that matters.'
      }
      else {
        ' LimitBlankPasswordUse = 1, so even a blank password could not be used for network logon, only at the console.'
      }
      Add-Finding -Severity $sev -Category 'Accounts' -Title ("Account '{0}' permits a blank password (PASSWD_NOTREQD)" -f $u.Name) `
        -Detail $detail `
        -Evidence ("{0} | PasswordLastSet: {1}" -f $u.Name, $(if ($hasPwdEvidence) { '{0:yyyy-MM-dd HH:mm}' -f $u.PasswordLastSet } else { 'never' })) `
        -Remediation 'Clear the flag with: net user <user> /passwordreq:yes. Confirm the account holds a strong password, and keep LimitBlankPasswordUse = 1 so a blank password can never be used over the network.'
    }
    if (-not $u.Enabled) {
      Add-Finding -Severity Info -Category 'Accounts' -Title ("Disabled account: {0}" -f $u.Name)
    }
  }
  $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
  Add-Finding -Severity Info -Category 'Accounts' -Title ('{0} local Administrators' -f @($admins).Count) `
    -Detail ((@($admins) | ForEach-Object { $_.Name }) -join ', ') `
    -Remediation 'Keep local admin membership minimal; prefer LAPS + just-in-time elevation.'
} catch { }

try {
  $wmiUsers = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=TRUE" -ErrorAction Stop)
  $neverExp = @($wmiUsers | Where-Object { -not $_.Disabled -and $_.PasswordExpires -eq $false } | ForEach-Object { $_.Name })
  if ($neverExp.Count -gt 0) {
    Add-Finding -Severity Low -Category 'Accounts' -Title ("{0} enabled local account(s) with password set to never expire" -f $neverExp.Count) `
      -Detail ($neverExp -join ', ') `
      -Remediation 'Rotate periodically or move local admin credentials to LAPS; service accounts should use managed credentials.'
  }
  $rid500 = $wmiUsers | Where-Object { "$($_.SID)" -like '*-500' } | Select-Object -First 1
  if ($rid500) {
    if (-not $rid500.Disabled) {
      Add-Finding -Severity Medium -Category 'Accounts' -Title ("Built-in Administrator (RID 500) is enabled: {0}" -f $rid500.Name) `
        -Detail 'RID 500 cannot be locked out and is the first target of password spraying and Pass-the-Hash.' `
        -Remediation 'Disable the built-in Administrator (CIS 2.3.1.1) and use LAPS-managed or named admin accounts.'
    }
    if ("$($rid500.Name)" -ieq 'Administrator') {
      Add-Finding -Severity Low -Category 'Accounts' -Title 'Built-in Administrator account not renamed' `
        -Detail 'The RID 500 account still carries the well-known name, which removes one guess from every attacker script.' `
        -Remediation 'Rename the built-in Administrator account (CIS 2.3.1.5); renaming is cosmetic against RID-based tools but stops name-based spraying.'
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Accounts' -Title 'Password-expiry and built-in Administrator state not assessed' -Detail ('Win32_UserAccount failed: ' + $_.Exception.Message)
}

try {
  $joined = $false; $joinKind = 'workgroup'
  try { if ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain) { $joined = $true; $joinKind = 'domain-joined' } } catch { }
  if (-not $joined) {
    try {
      if ((Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0) { $joined = $true; $joinKind = 'Entra-joined' }
    } catch { }
  }
  $lapsEvidence = @()
  if ((Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') -or (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')) { $lapsEvidence += 'legacy LAPS CSE installed' }
  if ((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { $lapsEvidence += 'legacy LAPS policy AdmPwdEnabled=1' }
  foreach ($pk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS')) {
    $pv = Get-ItemProperty $pk -ErrorAction SilentlyContinue
    if ($pv -and $null -ne $pv.BackupDirectory) { $lapsEvidence += ("Windows LAPS policy BackupDirectory={0} ({1})" -f $pv.BackupDirectory, $pk) }
  }
  try {
    $stateKey = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State' -ErrorAction SilentlyContinue
    if ($stateKey -and @($stateKey.Property).Count -gt 0) { $lapsEvidence += ("Windows LAPS State has {0} value(s)" -f @($stateKey.Property).Count) }
  } catch { }
  if ($lapsEvidence.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Accounts' -Title 'LAPS (legacy or Windows LAPS) detected' -Detail ($lapsEvidence -join '; ')
  }
  elseif ($joined) {
    Add-Finding -Severity Medium -Category 'Accounts' -Title ("No LAPS management detected on a {0} host" -f $joinKind) `
      -Detail 'No LAPS policy BackupDirectory, no LAPS state and no legacy CSE. Shared or static local admin passwords enable Pass-the-Hash across the fleet.' `
      -Remediation 'Deploy Windows LAPS (Intune or GPO) to randomize the local admin password per host.'
  }
  else {
    Add-Finding -Severity Info -Category 'Accounts' -Title 'LAPS not applicable (workgroup host)' `
      -Detail 'LAPS needs a directory (AD or Entra) to store the password; keep the local admin password unique to this host.'
  }
} catch { }

try { $sessions = quser 2>$null; if ($sessions) { Add-Finding -Severity Info -Category 'Accounts' -Title 'Active sessions' -Detail (($sessions | Select-Object -Skip 1) -join ' | ') } } catch { }

if (-not $script:IsElevated) {
  Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker not assessed (needs elevation)' `
    -Detail 'Get-BitLockerVolume returns Access denied for a standard user; run elevated to check the system drive, fixed data volumes and protector types.'
}
else {
  try {
    $isLaptop = $false
    try { $isLaptop = @((Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop).ChassisTypes) | Where-Object { $_ -in 8, 9, 10, 14, 30, 31, 32 } | Select-Object -First 1 } catch { }
    $isLaptop = [bool]$isLaptop
    $vols = @(Get-BitLockerVolume -ErrorAction Stop)
    foreach ($bl in $vols) {
      if ("$($bl.VolumeType)" -notmatch 'OperatingSystem|Data') { continue }
      $isOs = ("$($bl.VolumeType)" -eq 'OperatingSystem')
      $protectors = @($bl.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" })
      $label = if ($isOs) { 'system drive' } else { 'fixed data volume' }
      if ($bl.ProtectionStatus -eq 'On' -or $bl.ProtectionStatus -eq 1) {
        $tpmOnly = ($protectors -contains 'Tpm') -and -not ($protectors | Where-Object { $_ -match 'TpmPin|TpmAndPin|TpmPinAndStartupKey|TpmAndPinAndStartupKey|Password' })
        if ($isOs -and $tpmOnly -and $isLaptop) {
          Add-Finding -Severity Low -Category 'Data' -Title ("BitLocker ON for {0} {1} with TPM-only protector on a portable device" -f $bl.MountPoint, $label) `
            -Detail ("Protectors: {0}; method {1}. TPM-only unlocks automatically at boot, so DMA and cold-boot attacks on a stolen laptop can recover the key." -f ($protectors -join ', '), $bl.EncryptionMethod) `
            -Remediation 'Add a PIN (TPM+PIN) for portable devices (CIS 18.10.9.1.x); keep the recovery key escrowed.'
        }
        else {
          Add-Finding -Severity Info -Category 'Data' -Title ("BitLocker protection ON for {0} ({1})" -f $bl.MountPoint, $label) `
            -Detail ("Protectors: {0}; method {1}" -f ($protectors -join ', '), $bl.EncryptionMethod)
        }
      }
      else {
        Add-Finding -Severity Medium -Category 'Data' -Title ("BitLocker not protecting {0} ({1})" -f $bl.MountPoint, $label) `
          -Detail ("ProtectionStatus={0}; VolumeStatus={1}" -f $bl.ProtectionStatus, $bl.VolumeStatus) `
          -Remediation 'Enable BitLocker (TPM+PIN for the OS drive, auto-unlock for data volumes); stolen disk = stolen data otherwise.'
      }
    }
    if ($vols.Count -eq 0) { Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker not assessed (no volumes returned)' }
  } catch {
    Add-Finding -Severity Info -Category 'Data' -Title 'BitLocker not assessed' -Detail ('Get-BitLockerVolume failed: ' + $_.Exception.Message)
  }
}

try {
  $inact = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
  $desk = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
  $ssSecure = if ($desk) { $desk.ScreenSaverIsSecure } else { $null }
  $ssTimeout = if ($desk -and $desk.ScreenSaveTimeOut) { [int]$desk.ScreenSaveTimeOut } else { $null }
  $ssActive = if ($desk) { $desk.ScreenSaveActive } else { $null }
  $userLock = ($ssActive -eq 1 -and $ssSecure -eq 1 -and $null -ne $ssTimeout -and $ssTimeout -gt 0 -and $ssTimeout -le 900)
  if ($null -ne $inact -and [int]$inact -gt 0 -and [int]$inact -le 900) {
    Add-Finding -Severity Info -Category 'Data' -Title ("Machine inactivity lock enforced: {0}s" -f $inact) -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System::InactivityTimeoutSecs'
  }
  elseif ($userLock) {
    Add-Finding -Severity Low -Category 'Data' -Title 'No machine-wide inactivity lock; current user has a secure screensaver' `
      -Detail ("Policy InactivityTimeoutSecs={0}. HKCU ScreenSaverIsSecure=1, ScreenSaveTimeOut={1}s applies to this user only and can be changed by the user." -f $(if ($null -eq $inact) { 'absent' } else { $inact }), $ssTimeout) `
      -Remediation 'Set "Interactive logon: Machine inactivity limit" to 900 seconds or less (CIS 2.3.7.3).'
  }
  else {
    Add-Finding -Severity Low -Category 'Data' -Title ('No enforced inactivity lock (policy InactivityTimeoutSecs ' + $(if ($null -eq $inact) { 'absent' } elseif ([int]$inact -eq 0) { '0 = disabled' } else { "$inact s > 900" }) + ')') `
      -Detail ("Current user: ScreenSaveActive={0}, ScreenSaverIsSecure={1}, ScreenSaveTimeOut={2}. An unlocked, unattended console is a walk-up compromise." -f $ssActive, $ssSecure, $ssTimeout) `
      -Remediation 'Set "Interactive logon: Machine inactivity limit" to 900 seconds or less (CIS 2.3.7.3), and enforce a password-protected screensaver by policy.'
  }
} catch { }

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
      if ($ah -match '(?i)password\s*=') {
        Add-Finding -Severity High -Category 'IIS' -Title 'Password-shaped value in applicationHost.config' `
          -Detail 'App-pool/service credentials stored in config are readable by admins and backup-exfiltration.' `
          -Remediation 'Use app-pool identities where possible; protect config backups.'
      }
    }
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

Start-Section 'OS VULNERABILITY SURFACE'

$osCim = Get-CimInstance Win32_OperatingSystem
$osName = $osCim.Caption
$build = [int]$osCim.BuildNumber
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$displayVer = "$($cv.DisplayVersion)"; if (-not $displayVer) { $displayVer = "$($cv.ReleaseId)" }
$editionId = "$($cv.EditionID)"
$isServerSku = ($null -ne $osCim.ProductType -and [int]$osCim.ProductType -ne 1)
Add-Finding -Severity Info -Category 'OS' -Title ("OS: {0} {1} {2} (build {3})" -f $osName, $displayVer, $editionId, $build)

$eol = $null
$eolKind = ''
try {
  $w11 = @{   
    '21H2' = @('2023-10-10', '2024-10-08'); '22H2' = @('2024-10-08', '2025-10-14')
    '23H2' = @('2025-11-11', '2026-11-10'); '24H2' = @('2026-10-13', '2027-10-12')
    '25H2' = @('2027-10-12', '2028-10-10'); '26H1' = @('2028-03-14', '2029-03-13')
    '26H2' = @('2028-10-09', '2029-10-09')
  }
  $w10 = @{
    '22H2' = @('2025-10-14', '2025-10-14'); '21H2' = @('2023-06-13', '2024-06-11')
    '21H1' = @('2022-12-13', '2022-12-13'); '20H2' = @('2022-05-10', '2023-05-09')
    '2004' = @('2021-12-14', '2021-12-14'); '1909' = @('2021-05-11', '2022-05-10')
    '1809' = @('2020-11-10', '2021-05-11'); '1803' = @('2019-11-12', '2021-05-11')
  }
  $isEE = $editionId -match '^(Enterprise|Education|IoTEnterprise)' -and $editionId -notmatch 'EnterpriseS'
  if ($isServerSku) {
    $serverTable = @(
      @{ Match = 'Server 2025'; EOL = '2034-10-10' }, @{ Match = 'Server 2022'; EOL = '2031-10-14' },
      @{ Match = 'Server 2019'; EOL = '2029-01-09' }, @{ Match = 'Server 2016'; EOL = '2027-01-12' },
      @{ Match = 'Server 2012'; EOL = '2023-10-10' }, @{ Match = 'Server 2008'; EOL = '2020-01-14' }
    )
    foreach ($e in $serverTable) { if ($osName -like "*$($e.Match)*") { $eol = [datetime]$e.EOL; $eolKind = $e.Match; break } }
  }
  elseif ($editionId -match 'EnterpriseS') {
    $iot = $editionId -match '^IoT'
    $ltsc = @{ 10240 = '2025-10-14'; 14393 = '2026-10-13'; 17763 = '2029-01-09'
               19044 = $(if ($iot) { '2032-01-13' } else { '2027-01-12' })
               26100 = $(if ($iot) { '2034-10-10' } else { '2029-10-09' }) }
    if ($ltsc.ContainsKey($build)) { $eol = [datetime]$ltsc[$build]; $eolKind = "LTSC build $build" }
  }
  elseif ($build -ge 22000) {
    if ($w11.ContainsKey($displayVer)) { $eol = [datetime]$w11[$displayVer][$(if ($isEE) { 1 } else { 0 })]; $eolKind = "Windows 11 $displayVer " + $(if ($isEE) { 'Enterprise/Education' } else { 'Home/Pro' }) }
  }
  elseif ($build -ge 10240) {
    if ($w10.ContainsKey($displayVer)) { $eol = [datetime]$w10[$displayVer][$(if ($isEE) { 1 } else { 0 })] } else { $eol = [datetime]'2025-10-14' }
    $eolKind = "Windows 10 $displayVer"
  }
} catch { $eol = $null }

$isClientGac = (-not $isServerSku -and $editionId -notmatch 'EnterpriseS')
$warnDays = if ($isClientGac) { 180 } else { 365 }
$newerVer = ''
try {
  if ($isClientGac -and $build -ge 22000 -and $w11.ContainsKey($displayVer)) {
    $newerList = @($w11.Keys | Where-Object { [datetime]$w11[$_][0] -gt [datetime]$w11[$displayVer][0] } | Sort-Object)
    if ($newerList.Count -gt 0) { $newerVer = ' Newer feature update(s) available: ' + ($newerList -join ', ') + '.' }
  }
} catch { }
if ($null -eq $eol) {
  Add-Finding -Severity Info -Category 'OS' -Title ("OS support date not assessed for {0} {1} {2}" -f $osName, $displayVer, $editionId) `
    -Detail 'This version/edition is not in the built-in lifecycle table; check the Microsoft Lifecycle site.'
}
elseif ((Get-Date) -gt $eol) {
  Add-Finding -Severity Critical -Category 'OS' -Title ("{0} is PAST END OF SUPPORT ({1:yyyy-MM-dd})" -f $eolKind, $eol) `
    -Detail ('No security patches (unless enrolled in Extended Security Updates, which this scan cannot see) - every future CVE is permanent.' + $newerVer) `
    -Remediation 'Move to a supported feature update or OS; isolate the host meanwhile.'
}
elseif (((Get-Date) - $eol).Days -gt (-1 * $warnDays)) {
  Add-Finding -Severity Medium -Category 'OS' -Title ("{0} support ends {1:yyyy-MM-dd} (within {2} days)" -f $eolKind, $eol, $warnDays) `
    -Detail ('Feature updates past end of servicing receive no security fixes.' + $newerVer) `
    -Remediation 'Schedule the feature update or OS upgrade now.'
}
else {
  Add-Finding -Severity Info -Category 'OS' -Title ("{0} supported until {1:yyyy-MM-dd}" -f $eolKind, $eol) -Detail ($newerVer.Trim())
}

function Test-SchannelProtocolActive {
  param([string]$Protocol, [string]$Side, [int]$OsBuild)
  $defaultOn = switch ($Protocol) {
    'TLS 1.3' { $OsBuild -ge 20348 }
    'TLS 1.2' { $OsBuild -ge 17763 }
    'TLS 1.1' { $OsBuild -lt 26100 }
    'TLS 1.0' { $OsBuild -lt 26100 }
    default   { $false }
  }
  $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Side"
  $en  = (Get-ItemProperty $k -Name Enabled -ErrorAction SilentlyContinue).Enabled
  $dbd = (Get-ItemProperty $k -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
  $enEff  = if ($null -eq $en)  { 1 } else { [int]$en }
  $dbdEff = if ($null -eq $dbd) { $(if ($defaultOn) { 0 } else { 1 }) } else { [int]$dbd }
  $src = if ($null -eq $en -and $null -eq $dbd) { 'OS default' } else { "Enabled=$en DisabledByDefault=$dbd" }
  return [pscustomobject]@{ Active = (($enEff -ne 0) -and ($dbdEff -ne 1)); Source = $src }
}
try {
  foreach ($p in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')) {
    foreach ($side in @('Server', 'Client')) {
      $st = Test-SchannelProtocolActive -Protocol $p -Side $side -OsBuild $build
      if ($st.Active) {
        $sev = if ($side -eq 'Server') { 'High' } else { 'Medium' }
        Add-Finding -Severity $sev -Category 'Crypto' -Title ("Weak protocol ACTIVE {0}-side: {1}" -f $side.ToLower(), $p) `
          -Detail ("Resolved from: {0}. SSL and TLS 1.0/1.1 fail PCI DSS and DISA STIG baselines; downgrade attacks (POODLE/BEAST class)." -f $st.Source) `
          -Evidence ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\{1}" -f $p, $side) `
          -Remediation ("Set Enabled=0 and DisabledByDefault=1 under SCHANNEL\Protocols\{0}\{1} and reboot." -f $p, $side)
      }
    }
  }
  $activeProtos = @()
  foreach ($p in @('TLS 1.2', 'TLS 1.3')) {
    $st = Test-SchannelProtocolActive -Protocol $p -Side 'Server' -OsBuild $build
    if ($st.Active) { $activeProtos += $p }
  }
  if ($activeProtos.Count -gt 0) {
    Add-Finding -Severity Info -Category 'Crypto' -Title ("Modern TLS available server-side: {0}" -f ($activeProtos -join ', '))
  } else {
    Add-Finding -Severity High -Category 'Crypto' -Title 'No modern TLS protocol enabled server-side' `
      -Detail 'TLS 1.2 and 1.3 are both disabled (Enabled=0 or DisabledByDefault=1), so only weak protocols can be negotiated.' `
      -Remediation 'Explicitly enable TLS 1.2/1.3 server-side (Enabled=1, DisabledByDefault=0).'
  }
} catch {
  Add-Finding -Severity Info -Category 'Crypto' -Title 'SCHANNEL protocol state not assessed' -Detail ('Registry read failed: ' + $_.Exception.Message)
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
  $cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
  if ($cli -and $cli.EnableSecuritySignature -eq $false -and $cli.RequireSecuritySignature -eq $false) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB client: signing neither enabled nor required' `
      -Remediation 'Require SMB client signing via GPO (NTLM relay defense).'
  }
  $guestPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name AllowInsecureGuestAuth -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
  if (($cli -and $cli.EnableInsecureGuestLogons) -or $guestPolicy -eq 1) {
    Add-Finding -Severity Medium -Category 'Crypto' -Title 'SMB client allows insecure guest logons' `
      -Detail ("EnableInsecureGuestLogons={0}; policy AllowInsecureGuestAuth={1}. Guest sessions carry no signing or encryption, so a rogue server can serve tampered files." -f $(if ($cli) { $cli.EnableInsecureGuestLogons } else { 'n/a' }), $guestPolicy) `
      -Remediation 'Set-SmbClientConfiguration -EnableInsecureGuestLogons $false, or policy LanmanWorkstation AllowInsecureGuestAuth=0.'
  }
  elseif ($cli) {
    Add-Finding -Severity Info -Category 'Crypto' -Title 'SMB client blocks insecure guest logons'
  }
  Add-Finding -Severity Info -Category 'Crypto' -Title 'SMB server encryption state recorded' `
    -Detail ("EncryptData={0}; RejectUnencryptedAccess={1}. EncryptData=True forces SMB 3 encryption for every share." -f $srv.EncryptData, $srv.RejectUnencryptedAccess)
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

if (-not $script:IsElevated) {
  $smb1Start = $null
  try { $smb1Start = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -ErrorAction SilentlyContinue).Start } catch { }
  $smb1Hint = if ($null -eq $smb1Start) { 'Partial signal: the SMB1 client driver (mrxsmb10) is not installed, so the SMB1 client feature is off.' }
              elseif ([int]$smb1Start -eq 4) { 'Partial signal: the SMB1 client driver (mrxsmb10) is installed but disabled (Start=4).' }
              else { "Partial signal: the SMB1 client driver (mrxsmb10) is installed with Start=$smb1Start, so the SMB1 client feature is likely enabled." }
  $smb1Sev = if ($null -ne $smb1Start -and [int]$smb1Start -ne 4) { 'High' } else { 'Info' }
  Add-Finding -Severity $smb1Sev -Category 'OS' -Title 'Legacy optional features not assessed (needs elevation)' `
    -Detail ('Get-WindowsOptionalFeature requires administrator, so PowerShell v2, SMB1, Telnet and TFTP client state is unknown, not clean. ' + $smb1Hint) `
    -Remediation 'Re-run elevated to enumerate legacy optional features.'
}
else {
  try {
    $feats = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.FeatureName -match 'PowerShellV2|SMB1Protocol|TelnetClient|TFTPClient|NetFx3|IIS-.*Basicauth' }
    $featCount = 0
    foreach ($f in @($feats)) {
      $featCount++
      $sev = if ($f.FeatureName -match 'SMB1|PowerShellV2') { 'High' } else { 'Low' }
      Add-Finding -Severity $sev -Category 'OS' -Title ("Legacy feature enabled: {0}" -f $f.FeatureName) `
        -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName <name> - remove unless explicitly required (PowerShellv2 = downgrade attacks, SMB1 = wormable).'
    }
    if ($featCount -eq 0) {
      Add-Finding -Severity Info -Category 'OS' -Title 'No legacy optional features enabled (PowerShell v2, SMB1, Telnet, TFTP, NetFx3, IIS Basic auth)'
    }
  } catch {
    Add-Finding -Severity Info -Category 'OS' -Title 'Legacy optional features not assessed' -Detail ('Get-WindowsOptionalFeature failed: ' + $_.Exception.Message)
  }
}

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

    $secVal = @{}
    foreach ($n in @('MinimumPasswordLength', 'LockoutBadCount', 'PasswordComplexity', 'MaximumPasswordAge', 'MinimumPasswordAge',
                     'PasswordHistorySize', 'ClearTextPassword', 'LockoutDuration', 'ResetLockoutCount', 'EnableGuestAccount', 'LsaAnonymousNameLookup')) {
      $line = ($sec | Select-String ("^\s*{0}\s*=" -f $n) | Select-Object -First 1).Line
      if ($line -match '=\s*(-?\d+)') { $secVal[$n] = [int]$Matches[1] }
    }
    if ($secVal['LsaAnonymousNameLookup'] -eq 1) {
      Add-Finding -Severity Medium -Category 'OS' -Title 'Anonymous SAM/LSA lookup enabled' `
        -Remediation 'Disable: LsaAnonymousNameLookup=0 (blocks null-session enumeration).'
    }
    if ($secVal['ClearTextPassword'] -eq 1) {
      Add-Finding -Severity Medium -Category 'OS' -Title 'Passwords stored with reversible encryption (ClearTextPassword=1)' `
        -Detail 'Reversible encryption is equivalent to plaintext for anyone who can read the SAM or AD database.' `
        -Remediation 'Set "Store passwords using reversible encryption" to Disabled (CIS 1.1.7).'
    }
    if ($secVal.ContainsKey('PasswordComplexity') -and $secVal['PasswordComplexity'] -eq 0) {
      Add-Finding -Severity Low -Category 'OS' -Title 'Password complexity not required (PasswordComplexity=0)' `
        -Remediation 'Enable complexity (CIS 1.1.6) or enforce a banned-password list with a 14+ length minimum.'
    }
    if ($secVal.ContainsKey('MaximumPasswordAge') -and ($secVal['MaximumPasswordAge'] -le 0 -or $secVal['MaximumPasswordAge'] -gt 365)) {
      Add-Finding -Severity Low -Category 'OS' -Title ("Maximum password age {0} (never expires or over 365 days)" -f $secVal['MaximumPasswordAge']) `
        -Remediation 'CIS 1.1.3: 365 days or fewer, but not 0. Rotation matters most for shared and service accounts.'
    }
    if ($secVal.ContainsKey('PasswordHistorySize') -and $secVal['PasswordHistorySize'] -lt 24) {
      Add-Finding -Severity Low -Category 'OS' -Title ("Password history {0} (CIS wants 24)" -f $secVal['PasswordHistorySize']) `
        -Remediation 'Set "Enforce password history" to 24 or more (CIS 1.1.1).'
    }
    if ($secVal.ContainsKey('LockoutBadCount') -and $secVal['LockoutBadCount'] -gt 0) {
      if ($secVal.ContainsKey('LockoutDuration') -and $secVal['LockoutDuration'] -ge 0 -and $secVal['LockoutDuration'] -lt 15) {
        Add-Finding -Severity Low -Category 'OS' -Title ("Account lockout duration {0} minutes (CIS wants 15 or more)" -f $secVal['LockoutDuration']) `
          -Remediation 'Set lockout duration to 15 minutes or more (CIS 1.2.1); -1 (until admin unlocks) also passes.'
      }
      if ($secVal.ContainsKey('ResetLockoutCount') -and $secVal['ResetLockoutCount'] -lt 15) {
        Add-Finding -Severity Low -Category 'OS' -Title ("Lockout counter reset after {0} minutes (CIS wants 15 or more)" -f $secVal['ResetLockoutCount']) `
          -Remediation 'Set "Reset account lockout counter after" to 15 minutes or more (CIS 1.2.3).'
      }
    }
    Add-Finding -Severity Info -Category 'OS' -Title 'Secedit baseline exported (password/lockout/anonymous policy recorded)' `
      -Detail (($secVal.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ')
    Remove-Item $secOut -Force -ErrorAction SilentlyContinue
  }
} catch { }
}

$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
if ($ts) {
  $encLevel = if ($null -eq $ts.MinEncryptionLevel) { 2 } else { [int]$ts.MinEncryptionLevel }
  $secLayer = if ($null -eq $ts.SecurityLayer) { 1 } else { [int]$ts.SecurityLayer }
  $encSrc = if ($null -eq $ts.MinEncryptionLevel) { ' (value absent, OS default)' } else { '' }
  if ($encLevel -lt 3 -and $secLayer -eq 0) {
    Add-Finding -Severity High -Category 'Crypto' -Title ("RDP encryption level {0}{1} with SecurityLayer=0 (legacy RDP crypto)" -f $encLevel, $encSrc) `
      -Detail 'Native RDP security with a low encryption level is subject to downgrade and MITM; TLS is not in use.' `
      -Remediation 'Set SecurityLayer=2 (TLS) and MinEncryptionLevel=3 (High); pair with NLA.'
  }
  elseif ($encLevel -lt 3) {
    Add-Finding -Severity Low -Category 'Crypto' -Title ("RDP legacy encryption level {0}{1}; TLS security layer {2} makes it moot" -f $encLevel, $encSrc, $secLayer) `
      -Remediation 'Optional hardening: MinEncryptionLevel=3 (CIS 18.9.65.3.9.5). Keep SecurityLayer at 2 (TLS).'
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
  try {
    $sysRoot = "$env:SystemRoot"
    $expectedTokens = @{
      Shell    = @('explorer.exe')
      Userinit = @((Join-Path $sysRoot 'system32\userinit.exe'))
    }

    $knownDefaults = @{ VmApplet = @('SystemPropertiesPerformance.exe /pagefile', 'rundll32 shell32,Control_RunDLL "sysdm.cpl"') }
    foreach ($val in @('Shell', 'Userinit', 'Taskman', 'System', 'VmApplet', 'AppSetup')) {
      $v = $wlg.$val
      if ($null -eq $v) { continue }
      $raw = "$v"
      if ($knownDefaults.ContainsKey($val) -and ($knownDefaults[$val] | Where-Object { $raw.Trim() -ieq $_ })) { continue }
      if ($expectedTokens.ContainsKey($val)) {
        $tokens = @($raw -split ',' | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } | Where-Object { $_ })
        $extra = @()
        foreach ($t in $tokens) {
          $match = $false
          foreach ($e in $expectedTokens[$val]) { if ($t -ieq $e) { $match = $true } }
          if (-not $match) { $extra += $t }
        }
        if ($extra.Count -gt 0 -or $tokens.Count -eq 0) {
          $hashes = @()
          foreach ($x in $extra) {
            $exe = ($x -split '\s+')[0]
            try { if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { $hashes += ('{0} SHA256={1}' -f $exe, (Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash) } } catch { }
          }
          Add-Finding -Severity Critical -Category 'Persistence' -Title ("Winlogon {0} hijacked: {1}" -f $val, $raw) `
            -Detail ('Expected exactly "{0}"; extra token(s): {1}. Executed at every logon - classic Kovter-class persistence.{2}' -f ($expectedTokens[$val] -join ','), ($extra -join ' | '), $(if ($hashes) { ' ' + ($hashes -join '; ') } else { '' })) `
            -Evidence ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon::{0} = {1}" -f $val, $raw) `
            -Remediation "Restore ${val} to its Windows default immediately; trace what installed it."
        }
      }
      elseif ($raw.Trim()) {
        Add-Finding -Severity Medium -Category 'Persistence' -Title ("Winlogon '{0}' configured: {1}" -f $val, $raw) `
          -Remediation 'Verify this value against a clean image; non-default Winlogon values execute at logon.'
      }
    }
  } catch { }
}

try {
  $subs = @()
  $wmiErr = $null
  foreach ($nsName in @('root\subscription', "root\cimv2")) {
    $filter = $null
    try { $filter = Get-CimInstance -Namespace $nsName -ClassName __EventFilter -ErrorAction Stop } catch { if ($nsName -eq 'root\subscription') { $wmiErr = $_.Exception.Message } }
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
  elseif ($wmiErr) {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'WMI event subscriptions not assessed' `
      -Detail ('Enumerating root\subscription failed: ' + $wmiErr + '. Run elevated if this was access denied.')
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No WMI permanent event consumers'
  }
} catch { }

try {

  $hkcuClsid = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
  $count = @($hkcuClsid).Count
  if ($count -gt 0) {
    $highHits = @(); $lowCount = 0; $lowSample = @(); $sysCount = 0
    foreach ($k in ($hkcuClsid | Select-Object -First 500)) {
      $ips = Get-ItemProperty "$($k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
      if (-not $ips -or -not $ips.'(default)') { continue }
      $dll = [Environment]::ExpandEnvironmentVariables(("$($ips.'(default)')").Trim().Trim('"'))
      if ($dll -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\))\\') { $sysCount++; continue }
      $sig = $null; $hash = ''; $exists = $false
      try {
        if ($dll -and (Test-Path -LiteralPath $dll -PathType Leaf)) {
          $exists = $true
          $sig = (Get-AuthenticodeSignature -LiteralPath $dll -ErrorAction Stop).Status
          $hash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256 -ErrorAction Stop).Hash
        }
      } catch { }
      $badPath = $dll -match '(?i)\\(Temp|Public|Downloads|ProgramData)\\'
      $desc = ('{0} -> {1} [exists={2}; signature={3}{4}]' -f $k.PSChildName, $dll, $exists, $(if ($null -eq $sig) { 'n/a' } else { $sig }), $(if ($hash) { '; SHA256=' + $hash } else { '' }))
      if ($badPath -or -not $exists -or "$sig" -ne 'Valid') {
        $highHits += $desc
      }
      else {
        $lowCount++
        if ($lowSample.Count -lt 5) { $lowSample += $desc }
      }
    }
    Add-Finding -Severity Info -Category 'Persistence' -Title ("{0} per-user CLSID overrides in HKCU (COM hijack surface)" -f $count) `
      -Detail ("InprocServer32 targets: {0} under Windows/Program Files, {1} validly signed elsewhere, {2} suspect. HKCU\Software\Classes\CLSID overrides HKLM COM registrations, a persistence slot invisible to per-machine audits." -f $sysCount, $lowCount, $highHits.Count) `
      -Remediation 'Compare against a clean profile; watch InprocServer32/LocalServer32 default values pointing outside Windows/Program Files.'
    foreach ($h in ($highHits | Select-Object -First 8)) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("HKCU COM server unsigned, missing or in a user-writable drop path") `
        -Detail $h `
        -Evidence ('HKCU:\Software\Classes\CLSID\' + ($h -split ' -> ')[0] + '\InprocServer32') `
        -Remediation 'Verify the DLL; per-user COM DLLs that are unsigned or load from Temp/Public/Downloads/ProgramData are hijack and persistence primitives.'
    }
    if ($lowCount -gt 0) {
      Add-Finding -Severity Low -Category 'Persistence' -Title ("{0} HKCU COM servers are validly signed DLLs outside Windows/Program Files" -f $lowCount) `
        -Detail (($lowSample -join ' | ') + $(if ($lowCount -gt 5) { " | ... ($lowCount total)" } else { '' })) `
        -Remediation 'Vendor DLLs under LocalAppData are normal (PowerToys, Teams, OneDrive, browsers); confirm the publisher matches an installed product.'
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

try {
  $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  $lsaOs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -ErrorAction SilentlyContinue
  $expected = @{
    'Security Packages'       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'ntlm', 'negoexts', 'negotiate')
    'Notification Packages'   = @('scecli', 'rassfm', 'wdigest')
    'Authentication Packages' = @('msv1_0')   
  }
  $lsaSets = @(
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'Security Packages';       Obj = $lsa }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'Notification Packages';   Obj = $lsa }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'Authentication Packages'; Obj = $lsa }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'; Name = 'Security Packages'; Obj = $lsaOs }
  )
  foreach ($ls in $lsaSets) {
    if (-not $ls.Obj) { continue }
    $pkgs = $ls.Obj.($ls.Name)
    if ($null -eq $pkgs) { continue }
    $entries = @($pkgs | ForEach-Object { "$_".Trim('"', ' ', "`t") } | Where-Object { $_ -ne '' })
    $extra = @($entries | Where-Object { $expected[$ls.Name] -notcontains $_.ToLower() })
    if ($extra.Count -gt 0) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Non-standard LSA {0}: {1}" -f $ls.Name, ($extra -join ', ')) `
        -Detail ("Full list: {0}. LSA packages load into LSASS at boot as SYSTEM - credential-capture territory (mimikatz misc::memssp, T1547.002)." -f ($entries -join ', ')) `
        -Evidence ("{0}::{1}" -f $ls.Key, $ls.Name) `
        -Remediation 'Remove non-standard entries; verify the DLLs against the build baseline.'
    }
    elseif ($ls.Name -eq 'Authentication Packages') {
      Add-Finding -Severity Info -Category 'Persistence' -Title 'LSA Authentication Packages at default (msv1_0)'
    }
  }
} catch { }

try {
  foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
      $stub = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).StubPath
      if ($stub) {
        if ($stub -match 'AppData|\\Temp\\|\\Public\\|Downloads') {
          Add-Finding -Severity High -Category 'Persistence' -Title ("Active Setup StubPath in user-writable path: {0}" -f $_.PSChildName) `
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

try {
  foreach ($sidKey in @('HKCU:\Control Panel\Desktop')) {
    $ss = Get-ItemProperty $sidKey -ErrorAction SilentlyContinue
    $scr = if ($ss) { "$($ss.'SCRNSAVE.EXE')".Trim() } else { '' }
    if ($scr) {
      $scrPath = [Environment]::ExpandEnvironmentVariables($scr.Trim('"'))
      $sysDir = Join-Path "$env:SystemRoot" 'System32'
      if ($scrPath -notmatch '^[A-Za-z]:\\' ) { $scrPath = Join-Path $sysDir $scrPath }   
      if ($scrPath -notlike "$sysDir\*") {
        $h = ''
        try { if (Test-Path -LiteralPath $scrPath -PathType Leaf) { $h = ' SHA256=' + (Get-FileHash -LiteralPath $scrPath -Algorithm SHA256 -ErrorAction Stop).Hash } } catch { }
        Add-Finding -Severity Medium -Category 'Persistence' -Title ("Screensaver outside System32: {0}" -f $scr) `
          -Detail ("Resolved path: {0}{1}" -f $scrPath, $h) `
          -Evidence "$sidKey::SCRNSAVE.EXE" `
          -Remediation 'Screensaver path executes at idle timeout; user-writable .scr = persistence (T1546.002).'
      }
    }
  }
} catch { }

try {
  $appCert = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
  if ($appCert -and @($appCert.Property).Count -gt 0) {
    $vals = @($appCert.Property | ForEach-Object { '{0} = {1}' -f $_, (Get-ItemProperty $appCert.PSPath -Name $_ -ErrorAction SilentlyContinue).$_ })
    Add-Finding -Severity High -Category 'Persistence' -Title ("AppCertDlls configured ({0} value(s))" -f $vals.Count) `
      -Detail (($vals -join ' | ') + '. Each DLL is loaded by every process that calls CreateProcess, CreateProcessAsUser, WinExec and friends.') `
      -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' `
      -Remediation 'The key is empty on a clean build. Identify the DLL, treat it as malicious until proven otherwise, and remove the value.'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'AppCertDlls key absent or empty (clean)'
  }
} catch { }

try {
  $ul = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -ErrorAction SilentlyContinue
  $hidden = @()
  if ($ul) {
    foreach ($n in @($ul.Property)) {
      $v = (Get-ItemProperty $ul.PSPath -Name $n -ErrorAction SilentlyContinue).$n
      if ($v -eq 0) { $hidden += $n }
    }
  }
  if ($hidden.Count -gt 0) {
    foreach ($hname in $hidden) {
      Add-Finding -Severity High -Category 'Persistence' -Title ("Account hidden from the logon screen: {0}" -f $hname) `
        -Detail 'A UserList value of 0 hides the account from the Welcome screen and user switching; classic backdoor-account concealment.' `
        -Evidence ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList::{0} = 0" -f $hname) `
        -Remediation 'Confirm the account is authorized; remove the UserList value and investigate who created the account.'
    }
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No accounts hidden via SpecialAccounts\UserList'
  }
} catch { }

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

try {
  $umci = $null; $kmci = $null
  try {
    $dgAc = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object -First 1
    if ($dgAc) { $umci = [int]$dgAc.UsermodeCodeIntegrityPolicyEnforcementStatus; $kmci = [int]$dgAc.CodeIntegrityPolicyEnforcementStatus }
  } catch { }
  $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
  $ciLabel = @{ 0 = 'off'; 1 = 'audit'; 2 = 'enforced' }
  $sacLabel = @{ 0 = 'off'; 1 = 'on'; 2 = 'evaluation' }
  $alRules = 0; $alCollections = @(); $alEffectiveRead = $false
  try {
    $alp = Get-AppLockerPolicy -Effective -ErrorAction Stop
    $alEffectiveRead = $true
    foreach ($rc in @($alp.RuleCollections)) {
      $n = @($rc).Count
      if ($n -gt 0) { $alRules += $n; $alCollections += ('{0}:{1} rules ({2})' -f $rc.RuleCollectionType, $n, $rc.EnforcementMode) }
    }
  } catch { }
  if (-not $alEffectiveRead) {
    foreach ($coll in @('Exe', 'Dll', 'Script', 'Msi', 'Appx')) {
      $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$coll"
      if (Test-Path $path) { $c = @(Get-ChildItem $path -ErrorAction SilentlyContinue).Count; if ($c -gt 0) { $alRules += $c; $alCollections += "${coll}:$c rules (registry)" } }
    }
  }
  $appLockerSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
  $umciOn = ($null -ne $umci -and $umci -ge 1)
  $sacOn = ($sac -eq 1 -or $sac -eq 2)
  $alOn = ($alRules -gt 0)
  $stateDetail = ("WDAC user-mode CI: {0}; kernel-mode CI: {1}; Smart App Control: {2}; AppLocker: {3}" -f `
    $(if ($null -eq $umci) { 'not readable' } elseif ($ciLabel.ContainsKey($umci)) { $ciLabel[$umci] } else { $umci }), `
    $(if ($null -eq $kmci) { 'not readable' } elseif ($ciLabel.ContainsKey($kmci)) { $ciLabel[$kmci] } else { $kmci }), `
    $(if ($null -eq $sac) { 'absent (off)' } elseif ($sacLabel.ContainsKey([int]$sac)) { $sacLabel[[int]$sac] } else { $sac }), `
    $(if ($alOn) { $alCollections -join ', ' } elseif ($alEffectiveRead) { 'no effective rules' } else { 'not readable' }))
  if ($umciOn -or $sacOn -or $alOn) {
    $sev = 'Info'; $mode = @()
    if ($umciOn) { $mode += ('WDAC ' + $ciLabel[$umci]) ; if ($umci -eq 1) { $sev = 'Low' } }
    if ($sacOn)  { $mode += ('Smart App Control ' + $sacLabel[[int]$sac]); if ($sac -eq 2) { $sev = 'Low' } }
    if ($alOn)   { $mode += 'AppLocker' }
    Add-Finding -Severity $sev -Category 'Hardening' -Title ("Application control present: {0}" -f ($mode -join ' + ')) `
      -Detail ($stateDetail + $(if ($sev -eq 'Low') { '. Audit/evaluation mode logs but does not block.' } else { '' })) `
      -Remediation $(if ($sev -eq 'Low') { 'Promote audit/evaluation to enforced once the allow list is validated.' } else { '' })
    if ($alOn -and $appLockerSvc -and $appLockerSvc.Status -ne 'Running') {
      Add-Finding -Severity Medium -Category 'Hardening' -Title 'AppLocker rules exist but AppIDSvc not running' `
        -Detail ($alCollections -join ', ') `
        -Remediation 'Set AppIDSvc to auto-start; rules without the service are inert.'
    }
  }
  else {
    Add-Finding -Severity High -Category 'Hardening' -Title 'No application control (WDAC user-mode, Smart App Control and AppLocker all off)' `
      -Detail ($stateDetail + '. Everything this report lists as persistence/privexec runs because nothing blocks unsigned execution.') `
      -Remediation 'Golden-image item: deploy WDAC (audit -> enforce) or AppLocker baseline rules (EXE/DLL/Script/MSI); on unmanaged Win11, Smart App Control. Single highest-value hardening control.'
  }
} catch {
  Add-Finding -Severity Info -Category 'Hardening' -Title 'Application control state not assessed' -Detail ('Read failed: ' + $_.Exception.Message)
}

try {
  $ssPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
  $polEnable = if ($ssPol) { $ssPol.EnableSmartScreen } else { $null }
  $polLevel = if ($ssPol) { "$($ssPol.ShellSmartScreenLevel)" } else { '' }
  $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
  $ssVal = "$($ss.SmartScreenEnabled)"
  if ($polEnable -eq 0) {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen disabled by policy (EnableSmartScreen=0)' `
      -Evidence 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System::EnableSmartScreen' `
      -Remediation 'Set "Configure Windows Defender SmartScreen" to Enabled with "Warn and prevent bypass" (CIS 18.10.76.2.1).'
  }
  elseif ($polEnable -eq 1) {
    $sev = if ($polLevel -eq 'Block') { 'Info' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'Hardening' -Title ("SmartScreen enforced by policy (level: {0})" -f $(if ($polLevel) { $polLevel } else { 'not set = Warn' })) `
      -Remediation $(if ($sev -eq 'Low') { 'Set ShellSmartScreenLevel=Block ("Warn and prevent bypass") so users cannot click through.' } else { '' })
  }
  elseif ($ssVal -eq 'Off') {
    Add-Finding -Severity Medium -Category 'Hardening' -Title 'SmartScreen OFF (machine Explorer setting, no policy)' `
      -Evidence 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer::SmartScreenEnabled' `
      -Remediation 'Set SmartScreenEnabled=Warn/Block, or enforce it by policy (EnableSmartScreen=1, ShellSmartScreenLevel=Block).'
  }
  elseif ($ssVal) {
    Add-Finding -Severity Info -Category 'Hardening' -Title "SmartScreen: $ssVal (Explorer setting, not enforced by policy)"
  }
  else {
    Add-Finding -Severity Info -Category 'Hardening' -Title 'SmartScreen not configured by policy or Explorer value (OS default Warn; user-changeable)' `
      -Remediation 'Enforce by policy so users cannot turn it off (EnableSmartScreen=1, ShellSmartScreenLevel=Block).'
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

try {
  $adm = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
  if ($adm.Count -gt 3) {
    Add-Finding -Severity Low -Category 'Hardening' -Title ("{0} local Administrators - trim the image baseline" -f $adm.Count)
  }
} catch { }

try {
  $isClientSku = $true
  try { $isClientSku = ([int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 1) } catch { }
  $nullChecks = @(
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous';         Want = 1; Default = 0; Sev = 'Medium'; Ref = 'CIS 2.3.10.2: anonymous enumeration of SAM accounts and shares' }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM';      Want = 1; Default = 1; Sev = 'Medium'; Ref = 'CIS 2.3.10.1: anonymous enumeration of SAM accounts' }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; Want = 0; Default = 0; Sev = 'Medium'; Ref = 'CIS 2.3.10.4: Everyone permissions apply to anonymous users' }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareWks';    Want = 0; Default = 1; Sev = 'Low'; Ref = 'default admin shares C$/ADMIN$ (client SKU)'; OnlyClient = $true }
    @{ Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'AutoShareServer'; Want = 0; Default = 1; Sev = 'Low'; Ref = 'default admin shares C$/ADMIN$ (server SKU)'; OnlyServer = $true }
  )
  foreach ($rk in $nullChecks) {
    if ($rk.OnlyClient -and -not $isClientSku) { continue }
    if ($rk.OnlyServer -and $isClientSku) { continue }
    $v = (Get-ItemProperty $rk.Key -Name $rk.Name -ErrorAction SilentlyContinue).($rk.Name)
    $eff = if ($null -eq $v) { [int]$rk.Default } else { [int]$v }
    $src = if ($null -eq $v) { 'absent = OS default ' + $rk.Default } else { "$v" }
    if ($eff -ne [int]$rk.Want) {
      Add-Finding -Severity $rk.Sev -Category 'Hardening' -Title ("{0} = {1} (hardening wants {2})" -f $rk.Name, $src, $rk.Want) `
        -Detail $rk.Ref `
        -Evidence ("{0}::{1}" -f $rk.Key, $rk.Name) `
        -Remediation ("Set {0}={1} in the image (null-session / default-share hardening)." -f $rk.Name, $rk.Want)
    }
  }
  $rrStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' -Name Start -ErrorAction SilentlyContinue).Start
  if ($null -ne $rrStart -and [int]$rrStart -ne 4) {
    $rrSev = if ([int]$rrStart -eq 2) { 'Medium' } else { 'Low' }
    Add-Finding -Severity $rrSev -Category 'Hardening' -Title ("RemoteRegistry service Start = {0} (hardening wants 4 = Disabled)" -f $rrStart) `
      -Detail $(if ([int]$rrStart -eq 2) { 'Automatic start: remote registry reads/writes are available to any authenticated admin, and to attackers with a stolen admin credential.' } else { 'Manual (trigger-started) is the client default; it still starts on demand for remote registry access.' }) `
      -Evidence 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry::Start' `
      -Remediation 'Set the Remote Registry service to Disabled (CIS 5.x) unless a management tool needs it.'
  }
} catch { }

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
  $ssids = @()
  $wlanOutput = @(netsh wlan show profiles 2>$null)
  $separators = 0
  foreach ($line in $wlanOutput) {
    if ($line -match '^-{5,}\s*$') { $separators++; continue }
    if ($separators -ge 2 -and $line -match '^\s{4}\S.*?\s:\s(.+)$') {
      $name = $Matches[1].Trim()
      if ($name) { $ssids += $name }
    }
  }
  if ($ssids.Count -eq 0) {
    try {
      $xmls = @(Get-ChildItem "$env:ProgramData\Microsoft\Wlansvc\Profiles\Interfaces" -Filter '*.xml' -Recurse -ErrorAction SilentlyContinue)
      foreach ($x in $xmls) {
        try {
          [xml]$doc = Get-Content -LiteralPath $x.FullName -Raw -ErrorAction Stop
          $n = $doc.WLANProfile.name
          if ($n) { $ssids += "$n".Trim() }
        } catch { }
      }
    } catch { }
  }
  $ssids = @($ssids | Sort-Object -Unique)
  if ($ssids.Count -gt 0) {
    Add-Finding -Severity Info -Category 'History' -Title ('{0} saved WiFi profiles' -f $ssids.Count) `
      -Detail ($ssids -join ' | ') `
      -Remediation 'Saved profiles travel with the image; remove non-operational SSIDs before deployment (each is a location/oracle hint).'
  }
  elseif ($separators -lt 2) {
    Add-Finding -Severity Info -Category 'History' -Title 'WiFi profiles not assessed (no wireless interface or WLAN service)' `
      -Detail 'netsh wlan show profiles produced no profile table on this host.'
  }
  else {
    Add-Finding -Severity Info -Category 'History' -Title 'No saved WiFi profiles'
  }
} catch {
  Add-Finding -Severity Info -Category 'History' -Title 'WiFi profiles not assessed' -Detail ('netsh wlan failed: ' + $_.Exception.Message)
}

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

  $selfChain = @{}
  $walk = $PID
  for ($i = 0; $i -lt 8 -and $walk -and -not $selfChain.ContainsKey($walk); $i++) {
    $selfChain[$walk] = $true
    $walk = ($procs | Where-Object { $_.ProcessId -eq $walk } | Select-Object -First 1).ParentProcessId
  }
  foreach ($c in @($procs | Where-Object {
        -not $selfChain.ContainsKey($_.ProcessId) -and
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

Start-Section 'EXTENDED PERSISTENCE & HARDENING BASELINE'

function Get-SuspectHash {
  param([string]$Path)
  try {
    if (-not $Path) { return $null }
    $p = $Path.Trim('"')
    if ($p -match '^(.*?\.(exe|dll|bat|cmd|scr|com))\b') { $p = $Matches[1] }
    $p = [System.Environment]::ExpandEnvironmentVariables($p)
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $p).Length -gt 100MB) { return 'skipped (>100MB)' }
    return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
  } catch { return $null }
}

$extraRunKeys = @(
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'; Note = 'RunOnceEx executes via a DLL/entry list and is commonly missed by autoruns review' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'; Note = 'RunOnceEx executes via a DLL/entry list and is commonly missed by autoruns review' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'; Note = 'Legacy service-style autostart; no legitimate use on modern Windows' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Note = 'Policy-based Run key, separate from the standard Run key and often unaudited' }
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Note = 'Policy-based Run key, separate from the standard Run key and often unaudited' }
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'; Note = 'Shell service objects load into explorer.exe at logon' }
)

$shellObjDefaults = @('webcheck')
foreach ($k in $extraRunKeys) {
  if (-not (Test-Path $k.Path)) { continue }
  $props = Get-ItemProperty $k.Path -ErrorAction SilentlyContinue
  if (-not $props) { continue }
  foreach ($v in $props.PSObject.Properties) {
    if ($v.Name -like 'PS*' -or -not $v.Value) { continue }
    if ($k.Path -match 'ShellServiceObjectDelayLoad' -and $shellObjDefaults -contains $v.Name.ToLower()) {
      Add-Finding -Severity Info -Category 'Persistence' -Title ('ShellServiceObjectDelayLoad at expected default ({0})' -f $v.Name)
      continue
    }
    $hash = Get-SuspectHash ([string]$v.Value)
    Add-Finding -Severity High -Category 'Persistence' -Title ('Autostart entry in {0}' -f ($k.Path -replace '^HK(LM|CU):\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\', '')) `
      -Detail ('{0} = {1} || {2}' -f $v.Name, $v.Value, $k.Note) `
      -Evidence ('{0} :: {1}{2}' -f $k.Path, $v.Name, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
      -Remediation 'Validate against the golden image. These legacy and policy autostart keys are rarely used legitimately, so any entry deserves attribution.'
  }
}

$envKey = 'HKCU:\Environment'
$envProps = Get-ItemProperty $envKey -ErrorAction SilentlyContinue
if ($envProps) {
  $logonScript = $envProps.UserInitMprLogonScript
  if ($logonScript) {
    $hash = Get-SuspectHash ([string]$logonScript)
    Add-Finding -Severity Critical -Category 'Persistence' -Title 'Logon script set in HKCU\Environment (UserInitMprLogonScript)' `
      -Detail ('Command: {0} || Runs at every logon of this user. This value has no default and no common legitimate use.' -f $logonScript) `
      -Evidence ('{0} :: UserInitMprLogonScript{1}' -f $envKey, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
      -Remediation 'Delete the value and investigate the referenced command. MITRE T1037.001.'
  }
}

function Test-PathEntryWritable {
  param([string]$Entry)
  $dir = [System.Environment]::ExpandEnvironmentVariables($Entry.Trim().Trim('"'))
  if (-not $dir) { return $null }
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return [pscustomobject]@{ Dir = $dir; Missing = $true; Hit = $null } }
  $acl = $null
  try { $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop } catch { return [pscustomobject]@{ Dir = $dir; Missing = $false; Hit = $null; Unreadable = $true } }
  $hit = $null
  if (Get-Command Get-LowPrivFolderWriteAce -ErrorAction SilentlyContinue) { $hit = Get-LowPrivFolderWriteAce -ACLObject $acl }
  else { $hit = Get-LowPrivWriteAce -ACLObject $acl }
  if ($hit -and $dir -like "$env:USERPROFILE*" -and $hit.Sid -eq $script:AclCurrent.User.Value) { $hit = $null }
  return [pscustomobject]@{ Dir = $dir; Missing = $false; Hit = $hit; Unreadable = $false }
}

try {
  $machEnvKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  $machPath = (Get-ItemProperty $machEnvKey -Name Path -ErrorAction Stop).Path
  $entries = @($machPath -split ';' | Where-Object { $_ -and $_.Trim() })
  $sys32 = (Join-Path $env:SystemRoot 'System32').TrimEnd('\').ToLower()
  $sys32Index = -1
  for ($i = 0; $i -lt $entries.Count; $i++) {
    $e = [System.Environment]::ExpandEnvironmentVariables($entries[$i].Trim().Trim('"')).TrimEnd('\').ToLower()
    if ($e -eq $sys32) { $sys32Index = $i; break }
  }
  $writable = @(); $missing = @(); $unreadable = 0
  for ($i = 0; $i -lt $entries.Count; $i++) {
    $r = Test-PathEntryWritable -Entry $entries[$i]
    if (-not $r) { continue }
    if ($r.Missing) { $missing += $r.Dir; continue }
    if ($r.Unreadable) { $unreadable++; continue }
    if ($r.Hit) {
      $ahead = ($sys32Index -lt 0 -or $i -lt $sys32Index)
      $writable += $r.Dir
      Add-Finding -Severity $(if ($ahead) { 'High' } else { 'Medium' }) -Category 'Persistence' -Title ('Machine PATH directory writable by low-privilege principal: {0}' -f $r.Dir) `
        -Detail ('Position {0} of {1}{2} | {3} ({4}) has {5} ({6}). Any program or service that launches a binary by bare name, or loads a DLL through the search order, can be hijacked from this folder.' -f ($i + 1), $entries.Count, $(if ($ahead) { ' (ahead of System32)' } else { ' (after System32)' }), $r.Hit.Name, $r.Hit.Sid, $r.Hit.Level, $r.Hit.Rights) `
        -Evidence ('{0} :: Path [{1}]' -f $machEnvKey, $entries[$i]) `
        -Remediation 'Remove the directory from the machine PATH or restrict its ACL to Administrators and SYSTEM. MITRE T1574.007.'
    }
  }
  Add-Finding -Severity $(if ($missing.Count -gt 0) { 'Low' } else { 'Info' }) -Category 'Persistence' -Title ('Machine PATH: {0} entries checked by ACL, {1} writable, {2} missing' -f $entries.Count, $writable.Count, $missing.Count) `
    -Detail $(if ($missing.Count -gt 0) { 'Missing directories (a low-privilege user who can create them inherits the PATH slot): ' + (($missing | Select-Object -First 10) -join ' | ') + $(if ($unreadable -gt 0) { " | $unreadable ACL(s) unreadable" } else { '' }) } else { 'All machine PATH directories exist and none grants write access to a low-privilege principal.' + $(if ($unreadable -gt 0) { " $unreadable ACL(s) unreadable." } else { '' }) }) `
    -Evidence "$machEnvKey :: Path" `
    -Remediation $(if ($missing.Count -gt 0) { 'Remove stale PATH entries; check whether the parent directory lets a standard user create the missing folder.' } else { '' })
} catch {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Machine PATH directories not assessed' `
    -Detail ('Reading the machine PATH failed: ' + $_.Exception.Message)
}

if ($envProps) {
  $userPath = $envProps.Path
  if ($userPath) {
    try {
      $uEntries = @($userPath -split ';' | Where-Object { $_ -and $_.Trim() })
      $uHits = @()
      foreach ($ue in $uEntries) {
        $r = Test-PathEntryWritable -Entry $ue
        if ($r -and $r.Hit) { $uHits += ('{0} [{1} ({2}): {3}]' -f $r.Dir, $r.Hit.Name, $r.Hit.Sid, $r.Hit.Level) }
      }
      if ($uHits.Count -gt 0) {
        Add-Finding -Severity Medium -Category 'Persistence' -Title ('User PATH contains {0} director(ies) writable by another low-privilege principal' -f $uHits.Count) `
          -Detail ('Entries: ' + ($uHits -join ' | ') + ' || A writable directory on PATH can shadow a system binary called without a full path. Directories writable only by this user are not reported.') `
          -Evidence "$envKey :: Path" `
          -Remediation 'Remove the directories from the user PATH or restrict their ACLs. MITRE T1574.007.'
      }
      else {
        Add-Finding -Severity Info -Category 'Persistence' -Title ('User PATH: {0} entries checked by ACL, none writable by another low-privilege principal' -f $uEntries.Count)
      }
    } catch {
      Add-Finding -Severity Info -Category 'Persistence' -Title 'User PATH directories not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
    }
  }
}

$winKey = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$winProps = Get-ItemProperty $winKey -ErrorAction SilentlyContinue
if ($winProps) {
  foreach ($n in @('Load', 'Run', 'Scripts')) {
    $val = $winProps.$n
    if ($val) {
      $hash = Get-SuspectHash ([string]$val)
      Add-Finding -Severity High -Category 'Persistence' -Title ('Legacy {0} value set in HKCU Windows NT key' -f $n) `
        -Detail ('{0} = {1} || A 16-bit-era autostart slot that modern Windows still honours and modern tooling rarely inspects.' -f $n, $val) `
        -Evidence ('{0} :: {1}{2}' -f $winKey, $n, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
        -Remediation 'Clear the value unless a documented legacy application requires it.'
    }
  }
}

foreach ($sp in @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts',
    'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts')) {
  if (-not (Test-Path $sp)) { continue }
  $scriptCount = @(Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue).Count
  if ($scriptCount -gt 0) {
    Add-Finding -Severity Info -Category 'Persistence' -Title ('{0} policy script entr(ies) registered' -f $scriptCount) `
      -Detail ('Under {0}. Policy-delivered logon/logoff/startup scripts run automatically; confirm each maps to a known GPO.' -f $sp) `
      -Evidence $sp `
      -Remediation 'Cross-check against the GPOs that should apply to this host. An entry with no matching GPO is persistence.'
  }
}

$smKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$sm = Get-ItemProperty $smKey -ErrorAction SilentlyContinue
if ($sm) {
  $boot = @($sm.BootExecute | Where-Object { $_ })
  $bootExtra = @($boot | Where-Object { $_ -notmatch '^autocheck\s+autochk\s+\*?$' })
  if ($bootExtra.Count -gt 0) {
    Add-Finding -Severity High -Category 'Persistence' -Title 'Non-default BootExecute entry' `
      -Detail ('BootExecute: ' + ($boot -join ' | ') + ' || Expected only "autocheck autochk *". These run during boot before security controls load.') `
      -Evidence "$smKey :: BootExecute" `
      -Remediation 'Remove unrecognised entries. Legitimate additions are rare and usually come from disk or encryption tooling.'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'BootExecute at expected default'
  }

  try {
    $sdsm = if ($sm.PSObject.Properties.Name -contains 'SafeDllSearchMode') { [int]$sm.SafeDllSearchMode } else { $null }
    if ($sdsm -eq 0) {
      Add-Finding -Severity High -Category 'Hardening' -Title 'SafeDllSearchMode disabled (SafeDllSearchMode = 0)' `
        -Detail 'The current working directory is searched before System32 for every DLL load, so a planted DLL beside any document or in any writable launch directory is loaded by the process that opens it.' `
        -Evidence "$smKey :: SafeDllSearchMode" `
        -Remediation 'Delete the value or set it to 1. MITRE T1574.001.'
    }
    else {
      Add-Finding -Severity Info -Category 'Hardening' -Title ('SafeDllSearchMode {0}' -f $(if ($null -eq $sdsm) { 'at default (not set = enabled)' } else { "= $sdsm (enabled)" }))
    }
  } catch { }
}

$kdKey = "$smKey\KnownDLLs"
if (Test-Path $kdKey) {
  $kd = Get-ItemProperty $kdKey -ErrorAction SilentlyContinue
  $entries = @($kd.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and $_.Name -notmatch '^DllDirectory(32)?$' })
  $bad = New-Object System.Collections.Generic.List[string]
  foreach ($e in $entries) {
    $dllName = "$($e.Value)"
    if (-not $dllName) { continue }
    if ($dllName -notmatch '\.dll$') { $dllName += '.dll' }
    $target = Join-Path $env:SystemRoot "System32\$dllName"
    if (-not (Test-Path -LiteralPath $target)) {

      continue
    }
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
      if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
        $bad.Add("$($e.Name) -> $dllName (signature: $($sig.Status))")
      }
    } catch { }
  }
  if ($bad.Count -gt 0) {
    Add-Finding -Severity High -Category 'Persistence' -Title ('{0} KnownDLLs entr(ies) resolve to a non-Microsoft-signed DLL' -f $bad.Count) `
      -Detail (($bad -join ' | ') + ' || Every process resolving these names loads the target.') `
      -Evidence $kdKey `
      -Remediation 'Investigate the target DLL immediately and compare the KnownDLLs list against a clean build of the same Windows version and architecture.'
  }
  else {
    Add-Finding -Severity Info -Category 'Persistence' -Title ('KnownDLLs entries all resolve to Microsoft-signed DLLs ({0} entries)' -f $entries.Count) `
      -Detail 'Validated by signature rather than by name, since the expected name set varies across Windows versions and architectures.'
  }
}

$bhoSeen = @{}
foreach ($bhoPath in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')) {
  if (-not (Test-Path $bhoPath)) { continue }
  foreach ($bho in (Get-ChildItem $bhoPath -ErrorAction SilentlyContinue)) {
    $clsid = $bho.PSChildName
    if (-not $bhoSeen.ContainsKey($clsid)) { $bhoSeen[$clsid] = @{ Hives = @(); Dll = $null } }
    $bhoSeen[$clsid].Hives += $(if ($bhoPath -match 'Wow6432Node') { 'Wow6432Node' } else { 'native' })
  }
}
foreach ($clsid in $bhoSeen.Keys) {
  $dll = $null
  foreach ($c in @("HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32", "HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID\$clsid\InprocServer32")) {
    if (Test-Path $c) { $dll = (Get-ItemProperty $c -ErrorAction SilentlyContinue).'(default)'; if ($dll) { break } }
  }
  $outside = $dll -and ($dll -notmatch '(?i)^"?(C:\\Windows|C:\\Program Files)')
  $hash = if ($dll) { Get-SuspectHash ([string]$dll) } else { $null }
  Add-Finding -Severity $(if ($outside) { 'High' } else { 'Low' }) -Category 'Persistence' -Title ("Browser Helper Object registered: {0}" -f $clsid) `
    -Detail ('DLL: {0} | Registered: {1}{2}' -f $(if ($dll) { $dll } else { 'unresolved' }), (($bhoSeen[$clsid].Hives | Sort-Object -Unique) -join ' + '), $(if ($outside) { ' || Loads from outside Windows/Program Files.' } else { '' })) `
    -Evidence ('{0}{1}' -f $clsid, $(if ($hash) { " :: SHA256 $hash" } else { '' })) `
    -Remediation 'BHOs load into Internet Explorer and some shell hosts. Remove any that do not map to installed, expected software.'
}

foreach ($acc in @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'DisplaySwitch.exe', 'AtBroker.exe', 'Narrator.exe')) {
  $accPath = Join-Path $env:SystemRoot "System32\$acc"
  if (-not (Test-Path $accPath)) { continue }
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $accPath -ErrorAction Stop
    $ok = $sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft'
    if (-not $ok) {
      Add-Finding -Severity Critical -Category 'Persistence' -Title ("Accessibility binary is not validly Microsoft-signed: {0}" -f $acc) `
        -Detail ('Path: {0} | Signature status: {1} | Signer: {2} || These binaries are launchable from the logon screen, so a replaced one is a pre-authentication SYSTEM backdoor.' -f $accPath, $sig.Status, $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'none' })) `
        -Evidence ('{0} :: SHA256 {1}' -f $accPath, (Get-SuspectHash $accPath)) `
        -Remediation 'Restore the original binary from a trusted source (sfc /scannow or the install media) and investigate how it was replaced. MITRE T1546.008.'
    }
  } catch { }
}

$legacyFiles = @(
  @{ Path = "$env:SystemRoot\winstart.bat"; Note = 'Legacy batch autostart' }
  @{ Path = "$env:SystemRoot\wininit.ini"; Note = 'Legacy init file, historically used for file replacement at boot' }
  @{ Path = "$env:SystemDrive\Autoexec.bat"; Note = 'Legacy DOS autostart' }
  @{ Path = "$env:SystemRoot\System32\autoexec.nt"; Note = 'NTVDM autostart' }
)
foreach ($lf in $legacyFiles) {
  if (-not (Test-Path $lf.Path)) { continue }
  $len = (Get-Item $lf.Path -ErrorAction SilentlyContinue).Length
  Add-Finding -Severity $(if ($len -gt 0) { 'Medium' } else { 'Low' }) -Category 'Persistence' -Title ("Legacy startup file present: {0}" -f (Split-Path $lf.Path -Leaf)) `
    -Detail ('Path: {0} | Size: {1} bytes || {2}. Modern Windows does not create these.' -f $lf.Path, $len, $lf.Note) `
    -Evidence $lf.Path `
    -Remediation 'Inspect the contents. On a modern build these files are either vendor cruft or attacker-placed.'
}

$winIni = "$env:SystemRoot\win.ini"
if (Test-Path $winIni) {
  $iniHits = @(Get-Content $winIni -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(run|load)\s*=\s*\S' })
  if ($iniHits.Count -gt 0) {
    Add-Finding -Severity High -Category 'Persistence' -Title 'win.ini contains a run= or load= directive' `
      -Detail (($iniHits | ForEach-Object { $_.Trim() }) -join ' | ') `
      -Evidence $winIni `
      -Remediation 'Blank the value. These directives still execute at logon and are almost never used legitimately.'
  }
}

try {
  $obfRx = if ($script:ObfPattern) { $script:ObfPattern } else { '(?i)IEX\s*\(|Invoke-Expression|FromBase64String|DownloadString|DownloadFile|Net\.WebClient|Reflection\.Assembly\]::Load' }
  $isServerSku = $false
  try { $isServerSku = ([int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 1) } catch { }
  $psDocs = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ''
  $profileSet = @(
    @{ Scope = 'AllUsers'; Path = "$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1" }
    @{ Scope = 'AllUsers'; Path = "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1" }
    @{ Scope = 'AllUsers'; Path = "$env:ProgramFiles\PowerShell\7\profile.ps1" }
    @{ Scope = 'AllUsers'; Path = "$env:ProgramFiles\PowerShell\7\Microsoft.PowerShell_profile.ps1" }
    @{ Scope = 'CurrentUser'; Path = (Join-Path $psDocs 'WindowsPowerShell\profile.ps1') }
    @{ Scope = 'CurrentUser'; Path = (Join-Path $psDocs 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1') }
    @{ Scope = 'CurrentUser'; Path = (Join-Path $psDocs 'PowerShell\profile.ps1') }
    @{ Scope = 'CurrentUser'; Path = (Join-Path $psDocs 'PowerShell\Microsoft.PowerShell_profile.ps1') }
  )
  $profFound = 0
  foreach ($pf in $profileSet) {
    if (-not (Test-Path -LiteralPath $pf.Path -PathType Leaf)) { continue }
    $profFound++
    $content = ''
    try { $content = [string](Get-Content -LiteralPath $pf.Path -Raw -ErrorAction Stop) } catch { }
    $obf = ($content -and ($content -match $obfRx))

    $dlEnc = ($content -and ($content -match '(?i)DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Start-BitsTransfer|FromBase64String|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|Reflection\.Assembly\]::Load'))
    $condaRx = '(?im)^.*conda(\.exe)?["'']?\s+["'']?shell\.powershell["'']?\s+["'']?hook.*Invoke-Expression.*$'
    $knownHook = ($content -and ($content -match $condaRx))
    if ($knownHook) { $obf = (($content -replace $condaRx, '') -match $obfRx) }
    $len = (Get-Item -LiteralPath $pf.Path).Length
    $sev = if ($dlEnc) { 'High' } elseif ($obf) { 'Medium' } elseif ($pf.Scope -eq 'AllUsers' -and $isServerSku) { 'High' } elseif ($pf.Scope -eq 'AllUsers') { 'Medium' } else { 'Low' }
    Add-Finding -Severity $sev -Category 'Persistence' -Title ('PowerShell {0} profile script present: {1}' -f $pf.Scope, (Split-Path $pf.Path -Leaf)) `
      -Detail ('Path: {0} | Size: {1} bytes{2}. Runs at the start of every {3} PowerShell session.' -f $pf.Path, $len, $(if ($dlEnc) { ' | content downloads or decodes a payload' } elseif ($obf) { ' | content uses Invoke-Expression outside a recognized tool hook' } elseif ($knownHook) { ' | recognized conda init hook only' } else { '' }),$(if ($pf.Scope -eq 'AllUsers') { 'user''s' } else { 'session of this user''s' })) `
      -Evidence ('{0} :: SHA256 {1}' -f $pf.Path, (Get-SuspectHash $pf.Path)) `
      -Remediation $(if ($obf) { 'Read the profile now. Download, base64 or Invoke-Expression constructs in a profile are the classic T1546.013 persistence.' } else { 'Confirm the profile content is expected; AllUsers profiles should be rare and change-controlled. MITRE T1546.013.' })
  }
  if ($profFound -eq 0) {
    Add-Finding -Severity Info -Category 'Persistence' -Title 'No PowerShell profile scripts present (AllUsers or CurrentUser)'
  }
} catch {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'PowerShell profile scripts not assessed' -Detail ('Check failed: ' + $_.Exception.Message)
}

try {
  $lolDrivers = @('RTCore64.sys', 'DBUtil_2_3.sys', 'gdrv.sys', 'AsIO.sys', 'ene.sys', 'iqvw64e.sys', 'mhyprot2.sys', 'PROCEXP152.sys',
                  'aswArPot.sys', 'WinRing0x64.sys', 'WinRing0.sys', 'kprocesshacker.sys', 'HW.sys', 'atillk64.sys', 'AsrDrv106.sys', 'AsrDrv103.sys',
                  'dbk64.sys', 'dbk32.sys', 'zam64.sys', 'TrueSight.sys', 'viragt64.sys', 'AsUpIO.sys', 'NalDrv.sys', 'EneIo64.sys', 'EneTechIo64.sys')
  $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' -and $_.PathName })
  $drvChecked = 0; $drvFlagged = 0; $drvMissing = 0
  foreach ($drv in $drivers) {
    $dp = "$($drv.PathName)".Trim().Trim('"')
    $dp = $dp -replace '^\\\?\?\\', ''
    $dp = $dp -replace '^(?i)\\SystemRoot', $env:SystemRoot
    $dp = [System.Environment]::ExpandEnvironmentVariables($dp)
    if ($dp -match '^(?i)system32\\') { $dp = Join-Path $env:SystemRoot $dp }
    if (-not (Test-Path -LiteralPath $dp -PathType Leaf)) { $drvMissing++; continue }
    $drvChecked++
    $leaf = Split-Path $dp -Leaf
    $known = ($lolDrivers | Where-Object { $_ -ieq $leaf } | Select-Object -First 1)
    $sigStatus = 'unknown'; $signer = ''
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath $dp -ErrorAction Stop
      $sigStatus = "$($sig.Status)"
      if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
    } catch { }
    if (-not $known -and $sigStatus -eq 'Valid') { continue }
    $drvFlagged++
    if ($drvFlagged -gt 25) { continue }
    Add-Finding -Severity High -Category 'Hardening' -Title $(if ($known) { 'Known-vulnerable driver loaded: {0}' -f $leaf } else { 'Running driver without a valid signature: {0} ({1})' -f $leaf, $sigStatus }) `
      -Detail ('Service: {0} | Path: {1} | Signature: {2}{3}{4}' -f $drv.Name, $dp, $sigStatus, $(if ($signer) { ' (' + (($signer -split ',')[0] -replace '^CN=', '') + ')' } else { '' }), $(if ($known) { ' | On the LOLDrivers vulnerable-driver list: a signed driver with a known kernel read/write primitive.' } else { '' })) `
      -Evidence ('{0} :: SHA256 {1}' -f $dp, (Get-SuspectHash $dp)) `
      -Remediation $(if ($known) { 'Unload and remove the driver unless the owning product is required; enable the Microsoft vulnerable driver blocklist and HVCI. MITRE T1068 / T1562.001.' } else { 'A running driver that fails signature validation means test-signing, a tampered file or a BYOVD loader. Verify bcdedit testsigning and investigate the file. MITRE T1014.' })
  }
  if ($drvFlagged -gt 25) {
    Add-Finding -Severity High -Category 'Hardening' -Title ('{0} running drivers flagged for signature or vulnerable-driver list (first 25 listed)' -f $drvFlagged)
  }
  Add-Finding -Severity Info -Category 'Hardening' -Title ('Running kernel drivers checked: {0} ({1} flagged, {2} file not found)' -f $drvChecked, $drvFlagged, $drvMissing) `
    -Detail 'Each running driver file was signature-checked and compared against the LOLDrivers name list.'
} catch {
  Add-Finding -Severity Info -Category 'Hardening' -Title 'Running driver signatures not assessed' -Detail ('Win32_SystemDriver read failed: ' + $_.Exception.Message)
}

try {
  $profiles = Get-NetFirewallProfile -ErrorAction Stop
  foreach ($p in $profiles) {
    $gaps = @()
    if ($p.LogBlocked -ne 'True' -and $p.LogBlocked -ne $true) { $gaps += 'dropped packets not logged' }
    if ($p.LogAllowed -ne 'True' -and $p.LogAllowed -ne $true) { $gaps += 'allowed connections not logged' }
    if ($gaps.Count -gt 0) {
      Add-Finding -Severity $(if ($p.Enabled -eq 'True' -or $p.Enabled -eq $true) { 'Medium' } else { 'Low' }) -Category 'Logging' -Title ("Firewall logging incomplete on {0} profile" -f $p.Name) `
        -Detail (($gaps -join '; ') + (' || Profile enabled: {0}; log file: {1}; max size: {2} KB' -f $p.Enabled, $p.LogFileName, $p.LogMaxSizeKilobytes)) `
        -Remediation ('Set-NetFirewallProfile -Profile {0} -LogBlocked True -LogAllowed True, and raise LogMaxSizeKilobytes. Without this there is no local record of blocked traffic.' -f $p.Name)
    }
    else {
      Add-Finding -Severity Info -Category 'Logging' -Title ("Firewall logging enabled on {0} profile" -f $p.Name) `
        -Detail ('Log file: {0} ({1} KB max)' -f $p.LogFileName, $p.LogMaxSizeKilobytes)
    }
  }
} catch {
  Add-Finding -Severity Info -Category 'Logging' -Title 'Firewall logging configuration not assessed' `
    -Detail ('Get-NetFirewallProfile failed: ' + $_.Exception.Message)
}

foreach ($logName in @('Application', 'System')) {
  try {
    $lg = Get-WinEvent -ListLog $logName -ErrorAction Stop
    $mb = [math]::Round($lg.MaximumSizeInBytes / 1MB, 0)
    if ($mb -lt 64) {
      Add-Finding -Severity Medium -Category 'Logging' -Title ("{0} event log undersized ({1} MB)" -f $logName, $mb) `
        -Detail ('Retention: {0}. A small log rotates away the evidence window during an incident.' -f $lg.LogMode) `
        -Remediation ('Raise the {0} log to at least 64 MB, or forward events to a SIEM.' -f $logName)
    }
    else {
      Add-Finding -Severity Info -Category 'Logging' -Title ("{0} event log size {1} MB" -f $logName, $mb)
    }
  } catch {
    Add-Finding -Severity Info -Category 'Logging' -Title ("{0} event log configuration not assessed" -f $logName) `
      -Detail 'Reading the log configuration failed; size and retention are unknown, not confirmed adequate.'
  }
}

$tcpip6 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -ErrorAction SilentlyContinue
$disabledComponents = if ($tcpip6 -and ($tcpip6.PSObject.Properties.Name -contains 'DisabledComponents')) { $tcpip6.DisabledComponents } else { $null }
Add-Finding -Severity Info -Category 'Hardening' -Title ('IPv6 DisabledComponents = {0}' -f $(if ($null -ne $disabledComponents) { '0x{0:X}' -f [int]$disabledComponents } else { 'not set (IPv6 fully enabled)' })) `
  -Detail 'Recorded for baseline comparison. IPv6 being enabled is not itself a finding, but an IPv6 stack nobody monitors is a blind spot for local discovery and rogue router advertisements.' `
  -Remediation 'If IPv6 is unused on this network, 0xFF disables it. If it is used, ensure RA guard and IPv6 monitoring exist. Decide deliberately rather than by default.'

if ($script:IsElevated) {
  try {
    $tcPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
    $cacheCount = @(Get-ChildItem $tcPath -ErrorAction SilentlyContinue).Count
    $apiCount = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
    if ($cacheCount -gt 0 -and $apiCount -gt 0 -and ($cacheCount - $apiCount) -gt 5) {
      Add-Finding -Severity High -Category 'Persistence' -Title 'Scheduled task registry cache exceeds the enumerable task list' `
        -Detail ('TaskCache registry entries: {0}; tasks returned by the scheduler API: {1}. A large gap can indicate tasks hidden by removing their security descriptor.' -f $cacheCount, $apiCount) `
        -Evidence $tcPath `
        -Remediation 'Compare the TaskCache GUIDs against the task list and investigate any that do not appear. Hidden tasks are a known persistence technique.'
    }
    else {
      Add-Finding -Severity Info -Category 'Persistence' -Title ('Scheduled task registry cache consistent ({0} cached / {1} enumerable)' -f $cacheCount, $apiCount)
    }
  } catch { }
}
else {
  Add-Finding -Severity Info -Category 'Persistence' -Title 'Scheduled task registry cache not assessed (needs elevation)' `
    -Detail 'TaskCache is not readable without administrator, so hidden-task detection could not run.'
}

Start-Section 'SECURITY FEATURES & DETECTION COVERAGE'

$sfOs = $null
try { $sfOs = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$sfBuild = 0
if ($sfOs) { [void][int]::TryParse("$($sfOs.BuildNumber)", [ref]$sfBuild) }

$sfIsServer = [bool]($sfOs -and ($sfOs.ProductType -ne 1))
$sfDomainJoined = $false
try { $sfDomainJoined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }

$sfServices = @{}
$sfServiceNames = @()
try {
  foreach ($svc in @(Get-Service -ErrorAction Stop)) {
    $sfServices[$svc.Name.ToLowerInvariant()] = $svc
  }
  $sfServiceNames = @($sfServices.Keys)
} catch { }

function Get-SfService {
  param([string]$Pattern)
  if ($Pattern -like '*[*]*') {
    foreach ($n in $sfServiceNames) { if ($n -like $Pattern.ToLowerInvariant()) { return $sfServices[$n] } }
    return $null
  }
  $k = $Pattern.ToLowerInvariant()
  if ($sfServices.ContainsKey($k)) { return $sfServices[$k] }
  return $null
}

$sfEdrRunning     = @()   
$sfEdrStopped     = @()   
$sfMdeOnboarded   = $false
$sfSysmonPresent  = $false
$sfAgentsRunning  = @()
$sfAgentsStopped  = @()
$sfWefConfigured  = $false
try { $sfWefConfigured = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' } catch { }

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

  $amMode = 'unknown'
  try {
    $mpStat = Get-MpComputerStatus -ErrorAction Stop
    if ($mpStat -and $mpStat.AMRunningMode) { $amMode = "$($mpStat.AMRunningMode)" }
  } catch { }

  if ($sfIsServer) {

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


