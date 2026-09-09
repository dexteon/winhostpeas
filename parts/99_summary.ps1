
######################## SUMMARY & REPORTS ########################

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

# Unattended mode: exit code = count of Critical+High findings (capped 250) so
# deployment/scheduling tooling can triage hosts without parsing output.
$critHigh = @($script:Findings | Where-Object { $_.Severity -in 'Critical', 'High' }).Count
$exitCode = [math]::Min($critHigh, 250)
Write-Host ''
Write-Host ("Exit code will be {0} (Critical+High count) for unattended triage." -f $exitCode) -ForegroundColor DarkCyan
exit $exitCode

Write-Host ''
Write-Host 'WinHostPEAS audit finished. Reports contain no secret values (detection + redaction only).' -ForegroundColor Cyan
