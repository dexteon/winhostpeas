$ErrorActionPreference = 'Stop'
# Resolve from the script's own location, never a hardcoded path. A pinned path
# is how the G:\Scratch copy and the D: repo silently drifted apart.
$base = $PSScriptRoot
if (-not $base) { $base = Split-Path -Parent $MyInvocation.MyCommand.Path }

# Explicit assembly order (reproduces the shipped layout). 04_installedapps and
# 05_regex are intentionally excluded (dead/orphaned).
$order = @(
  '10_header', '11_findings', '12_helpers', '03_adfuncs', '13_secrets',
  '20_system', '21_creds', '22_privesc', '23_network', '24_ad_software',
  '25_ot_discovery', '26_service_inventory', '27_loopback', '28_iis', '29_os_vulns',
  '30_hardening', '31_exec_summary', '32_history', '33_advanced', '34_btfm_expansion', '99_summary'
)

$sb = New-Object System.Text.StringBuilder
foreach ($name in $order) {
  $f = Join-Path $base "parts\$name.ps1"
  if (-not (Test-Path $f)) { throw "missing part: $f" }
  [void]$sb.AppendLine((Get-Content -Raw $f))
}
$src = $sb.ToString()

# Parse the assembled source; abort on any syntax error.
$t = $null; $e = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$t, [ref]$e)
if ($e.Count) {
  $e | ForEach-Object { Write-Host ("ASSEMBLED PARSE ERR line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red }
  exit 1
}

# Strip comment tokens (tokenizer-based, so '#' inside regex/strings survives).
$comments = @($t | Where-Object { $_.Kind.ToString() -eq 'Comment' } | Sort-Object { $_.Extent.StartOffset })
$out = New-Object System.Text.StringBuilder
$prevEnd = 0
foreach ($tok in $comments) {
  [void]$out.Append($src.Substring($prevEnd, $tok.Extent.StartOffset - $prevEnd))
  $prevEnd = $tok.Extent.EndOffset
}
[void]$out.Append($src.Substring($prevEnd))
$text = $out.ToString()
$text = $text -replace "(`r?`n[ \t]*){2,}(`r?`n)", "`r`n`r`n"
$text = $text -replace "(?m)^[ \t]+`r?`n", ''

$clean = Join-Path $base 'WinHostPEAS.ps1'
Set-Content -Path $clean -Value $text -Encoding UTF8

# Verify the stripped file still parses cleanly and has no comments left.
$t2 = $null; $e2 = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput((Get-Content -Raw $clean), [ref]$t2, [ref]$e2)
if ($e2.Count) {
  $e2 | ForEach-Object { Write-Host ("CLEAN PARSE ERR line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red }
  exit 1
}
$commentsLeft = @($t2 | Where-Object { $_.Kind.ToString() -eq 'Comment' }).Count

Copy-Item $clean 'G:\Documents\WinHostPEAS.ps1' -Force
$lines = (Get-Content $clean).Count
Write-Host ("BUILD OK: {0} lines, {1} comments remaining. Shipped to G:\Documents\WinHostPEAS.ps1" -f $lines, $commentsLeft) -ForegroundColor Green
