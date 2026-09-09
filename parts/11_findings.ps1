
######################## FINDINGS ENGINE ########################
# Every check records a finding instead of printing exploit guidance.
# Severities: Critical / High / Medium / Low / Info
# Values that look like secrets are detected but REDACTED in every output lane.

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:FindingsByName = @{}

function Get-Redacted {
  # return length + fingerprint only, never the value
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
  $json = Join-Path $Dir ("BlueWinPEAS_{0}_{1}.json" -f $env:COMPUTERNAME, $stamp)
  $csv  = Join-Path $Dir ("BlueWinPEAS_{0}_{1}.csv"  -f $env:COMPUTERNAME, $stamp)
  $html = Join-Path $Dir ("BlueWinPEAS_{0}_{1}.html" -f $env:COMPUTERNAME, $stamp)

  $meta = [pscustomobject]@{
    Tool        = 'BlueWinPEAS (defensive refit of winPEAS.ps1)'
    Host        = $env:COMPUTERNAME
    Generated   = (Get-Date).ToString('s')
    Duration    = $stopwatch.Elapsed.ToString('mm\:ss')
    FullCheck   = [bool]$FullCheck
    TotalFindings = $script:Findings.Count
    HighestSeverity = Get-HighestSeverity
  }
  @{ Meta = $meta; Findings = $script:Findings } | ConvertTo-Json -Depth 4 | Set-Content -Path $json -Encoding UTF8
  $script:Findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

  # ---------- HTML dashboard ----------
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
    $esc = { param($t) if ($null -eq $t) { '' } else { $t.ToString().Replace('\', '\\').Replace('"', '\"').Replace("`r", '').Replace("`n", ' ') } }
    '  { sev: "' + $f.Severity + '", cat: "' + (& $esc $f.Category) + '", title: "' + (& $esc $f.Title) + '", detail: "' + (& $esc $f.Detail) + '", evid: "' + (& $esc $f.Evidence) + '", rem: "' + (& $esc $f.Remediation) + '" },'
  }

  # Executive-summary placeholder values
  $adminList = if ($script:Exec.Admins) { $script:Exec.Admins -join ', ' } else { '(none resolved)' }
  $userRows = foreach ($u in $script:Exec.Users) {
    $ll = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { '<span class="never">never</span>' }
    $adm = if ($u.IsAdmin) { '<b class="adm">ADMIN</b>' } else { '' }
    $en = if ($u.Enabled) { 'enabled' } else { '<span class="dis">disabled</span>' }
    '<tr><td>' + $u.Name + '</td><td>' + $en + '</td><td>' + $adm + '</td><td>' + $ll + '</td></tr>'
  }
  $userRows = @('<tr><th>User</th><th>Status</th><th>Role</th><th>Last logon</th></tr>') + @($userRows)

  $htmlDoc = @"
<!DOCTYPE html><html><head><meta charset="utf-8">
<title>BlueWinPEAS Report - $($env:COMPUTERNAME)</title>
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
 <h1>BlueWinPEAS Posture Audit &mdash; $($env:COMPUTERNAME)</h1>
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
    <tr><td>Devices seen on network</td><td><b>$($script:Exec.DevicesSeen)</b> (active ICMP sweep + TCP banner grab)</td></tr>
    <tr><td>Scan mode</td><td>Local host checks <b>passive</b>; network discovery <b>active</b> (ICMP + TCP connect only)</td></tr>
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

  # Auto-launch the HTML report in the default browser (interactive runs).
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
