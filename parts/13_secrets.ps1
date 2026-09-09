
######################## SECRET PATTERN LIBRARY (detection + redaction) ########################
# The winPEAS regex corpus, kept for DETECTION only. Matched values are redacted
# before they reach console or reports. Sweep is scoped to credential-bearing
# locations and only runs with -FullCheck (machine-wide sweeps) or always-on
# targeted checks (winlogon, unattend, PS history).

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

# High-signal credential files an attacker (or malware) would target first.
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
