
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
  if ($Detail)     { Write-Host ('      ' + $Detail) -ForegroundColor DarkGray }
  if ($Remediation) { Write-Host ('      Fix: ' + $Remediation) -ForegroundColor DarkCyan }
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
  param([string]$Dir)
  if ($NoReport) { return }
  try { New-Item -ItemType Directory -Path $Dir -Force | Out-Null } catch { Write-Host "Cannot create report dir: $_" -ForegroundColor Red; return }
  $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
  $json = Join-Path $Dir ("BluePEAS_{0}_{1}.json" -f $env:COMPUTERNAME, $stamp)
  $csv  = Join-Path $Dir ("BluePEAS_{0}_{1}.csv"  -f $env:COMPUTERNAME, $stamp)
  $html = Join-Path $Dir ("BluePEAS_{0}_{1}.html" -f $env:COMPUTERNAME, $stamp)

  $meta = [pscustomobject]@{
    Tool        = 'BluePEAS (defensive refit of winPEAS.ps1)'
    Host        = $env:COMPUTERNAME
    Generated   = (Get-Date).ToString('s')
    Duration    = $stopwatch.Elapsed.ToString('mm\:ss')
    FullCheck   = [bool]$FullCheck
    TotalFindings = $script:Findings.Count
    HighestSeverity = Get-HighestSeverity
  }
  @{ Meta = $meta; Findings = $script:Findings } | ConvertTo-Json -Depth 4 | Set-Content -Path $json -Encoding UTF8
  $script:Findings | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

  $sevBadge = { param($s)
    $c = @{ Critical='#b91c1c'; High='#dc2626'; Medium='#d97706'; Low='#0891b2'; Info='#6b7280' }[$s]
    '<span style="background:' + $c + ';color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">' + $s + '</span>'
  }
  $rows = foreach ($f in $script:Findings) {
    '<tr><td>' + $f.Severity + '</td><td>' + $f.Category + '</td><td><b>' + $f.Title + '</b></td><td>' + $f.Detail +
    '</td><td><code>' + $f.Evidence + '</code></td><td>' + $f.Remediation + '</td></tr>'
  }
  $counts = $script:Findings | Group-Object Severity | ForEach-Object { $_.Name + ': ' + $_.Count }
  $htmlDoc = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>BluePEAS Report - $($env:COMPUTERNAME)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f8fafc;color:#111827}
 h1{margin-bottom:0} .meta{color:#6b7280;margin-bottom:16px}
 table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
 th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#f1f5f9}
 tr:nth-child(even){background:#f9fafb}
 .Critical{background:#b91c1c!important;color:#fff}.High{background:#fee2e2}
 .Medium{background:#fef3c7}.Low{background:#e0f2fe}.Info{background:#f3f4f6}
 code{font-size:11px;word-break:break-all}
</style></head><body>
<h1>BluePEAS Posture Audit</h1>
<div class="meta">Host: $($env:COMPUTERNAME) &middot; $(Get-Date) &middot; $($stopwatch.Elapsed.ToString('mm\:ss')) elapsed &middot; `$joinCountsPlaceholder`</div>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Evidence</th><th>Remediation</th></tr>
`$rowsPlaceholder`
</table></body></html>
"@
  $htmlDoc = $htmlDoc.Replace('$joinCountsPlaceholder', ($counts -join ' &middot; '))
  $htmlDoc = $htmlDoc.Replace('$rowsPlaceholder', ($rows -join "`n"))
  Set-Content -Path $html -Value $htmlDoc -Encoding UTF8

  Write-Host ''
  Write-Host ('Report summary: ' + ($counts -join ', ')) -ForegroundColor Cyan
  Write-Host ('Reports written: ' + $json) -ForegroundColor Cyan
  Write-Host ('                ' + $csv)  -ForegroundColor Cyan
  Write-Host ('                ' + $html) -ForegroundColor Cyan
}
