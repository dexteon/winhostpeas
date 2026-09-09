
######################## EXECUTIVE SUMMARY DATA ########################
# Collected before reports are written; rendered as the tables at the top
# of the HTML dashboard.

$script:Exec = @{
  Admins            = @()
  AdminCount        = 0
  Users             = @()   # Name, IsAdmin, Enabled, LastLogon
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

  # Last-logon map from Win32_NetworkLoginProfile (local logon history)
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

# Aggregates straight from the findings list
$script:Exec.PersistCritHigh = @($script:Findings | Where-Object { $_.Category -eq 'Persistence' -and $_.Severity -in 'Critical', 'High' }).Count
$script:Exec.PrivEscCritHigh = @($script:Findings | Where-Object { $_.Category -eq 'PrivEsc' -and $_.Severity -in 'Critical', 'High' }).Count
$script:Exec.HardeningGaps = @($script:Findings | Where-Object { $_.Category -eq 'Hardening' -and $_.Severity -in 'Critical', 'High', 'Medium' }).Count
$script:Exec.SecretsExposed = @($script:Findings | Where-Object { $_.Category -match 'Exposed secret|Credentials' -and $_.Severity -in 'Critical', 'High' }).Count
$script:Exec.DevicesSeen = @($script:Findings | Where-Object { $_.Title -like 'Reachable device*' }).Count
