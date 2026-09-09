<#
.SYNOPSIS
  BlueWinPEAS - the winPEAS.ps1 enumeration engine refit as a BLUE TEAM posture audit.
.DESCRIPTION
  Same detection surface an attacker would enumerate, repurposed for defenders:
    - structured findings (Severity / Category / Title / Detail / Remediation)
    - secret VALUES are detected but redacted - never printed or written to reports
    - added defender-side checks: Defender status, PowerShell logging coverage,
      SMBv1/signing, LLMNR/NBT-NS, RDP NLA, BitLocker, LSA/CredGuard, password
      policy, local account hygiene, dangerous token privileges
    - machine-wide regex sweeps (registry/files) are opt-in (-FullCheck) and scoped
    - emits JSON + CSV + HTML reports for ticketing / compliance pipelines
  Read-only: changes nothing on the host. Produces no exploit instructions.
.EXAMPLE
  .\BlueWinPEAS.ps1                     # fast posture audit + reports
  .\BlueWinPEAS.ps1 -FullCheck          # + deep (redacted) secret-pattern sweep
  .\BlueWinPEAS.ps1 -OutputDir C:\Audits -TimeStamp
.NOTES
  Derived from winPEAS.ps1 v1.3 (PEASS-ng / @RandolphConley), defensive refit.
  Run only on systems you own or are explicitly authorized to audit.
#>

[CmdletBinding()]
param(
  [switch]$TimeStamp,
  [switch]$FullCheck,
  [string]$OutputDir = '.\BlueWinPEAS_Output',
  [switch]$NoReport,
  [switch]$NoLaunch
)

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function TimeElapsed {
  if ($TimeStamp) { Write-Host ('  [{0:mm\:ss}]' -f $stopwatch.Elapsed) -ForegroundColor DarkGray }
}
