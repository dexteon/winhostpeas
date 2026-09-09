# Splunk Detection Ideas for WinHostPEAS Fleet

Sourced from cyberdefense-book corpus: BTFM (auditpol subcategories, event log commands), Practical Network Scanning ch6 (SIEM correlation/alerting/dashboards), hunting-ghosts-fileless-attacks (WMI + scheduled task IOCs), Hexacorn persistence series, fodhelper UAC bypass PoC, PowerShell obfuscation corpus.

These are starting-point SPL queries for a Splunk agent to validate, tune, and productionize against your actual Splunk instance. None are tested against a live indexer — they need field-name verification against your Windows TA / Splunk Add-on for Microsoft Windows.

---

## 1. Persistence Detection Alerts

### 1a. UAC bypass registry creation (fodhelper/computerdefaults/sdclt)
```
index=windows EventCode=4657 OR EventCode=4663
ObjectName="*ms-settings*shell*open*command*" OR
ObjectName="*mscfile*shell*open*command*" OR
ObjectName="*Classes*shell*open*command*"
| stats count by host, ObjectName, ProcessName
| rename ObjectName as registry_path
```
Alert: any hit = likely UAC bypass (fodhelper residue). Severity: High.

### 1b. WMI permanent subscription creation
```
index=windows source="*Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| table _time, host, User, Namespace, AccessMask
```
Alert: Event 5861 = permanent event consumer binding created. Severity: High unless from a known deployment tool.

### 1c. New scheduled task with encoded command
```
index=windows EventCode=4698
TaskContent="*powershell*-*enc*" OR TaskContent="*IEX*" OR TaskContent="*DownloadString*" OR TaskContent="*FromBase64String*" OR TaskContent="*scrobj.dll*" OR TaskContent="*regsvr32*"
| table _time, host, TaskName, SubjectUserName, TaskContent
```
Alert: any hit = fileless persistence. Severity: Critical.

### 1d. Service FailureCommand set to non-standard
```
index=windows EventCode=4657
ObjectName="*services*FailureCommand*"
| where NewValue != "" AND NewValue NOT LIKE "%SystemRoot%"
| table _time, host, ObjectName, NewValue, ProcessName
```
Alert: service crash-handler pointing at PowerShell or non-standard binary. Severity: High.

### 1e. Run/RunOnce registry modification by non-standard process
```
index=windows EventCode=4657
ObjectName="*CurrentVersion*Run*" OR ObjectName="*CurrentVersion*RunOnce*"
| where ProcessName NOT IN ("msiexec.exe","explorer.exe","svchost.exe","GoogleUpdate.exe","OneDriveSetup.exe")
| table _time, host, ObjectName, NewValue, ProcessName
```
Alert: Run key modified by unexpected process. Severity: Medium. Requires tuning for legit software installers.

---

## 2. Credential Access Detection

### 2a. WDigest plaintext credential storage enabled
```
index=windows EventCode=4657
ObjectName="*WDigest*UseLogonCredential*"
NewValue="1"
| table _time, host, ProcessName
```
Alert: someone enabled WDigest — attacker pre-staging for LSASS dump. Severity: High.

### 2b. LSASS access by non-system process
```
index=windows EventCode=4656 OR EventCode=4663
ObjectType="Process"
ObjectName="*lsass*"
| where ProcessName NOT IN ("svchost.exe","csrss.exe","wininit.exe","services.exe","smss.exe","MsMpEng.exe","NisSrv.exe")
| stats count by host, ProcessName, AccessMask
```
Alert: non-system process touching LSASS — potential credential dump. Severity: High. Tune: add your EDR/AV process names.

### 2c. SAM/SYSTEM hive copy
```
index=windows EventCode=4663 OR EventCode=4656
ObjectName="*config\SAM*" OR ObjectName="*config\SYSTEM*" OR ObjectName="*repair\SAM*"
| where AccessMask IN ("0x10100","0x10200","0x10000")
| table _time, host, ProcessName, ObjectName
```
Alert: offline hash extraction prep. Severity: Critical.

### 2d. AppInit_DLLs modified
```
index=windows EventCode=4657
ObjectName="*AppInit_DLLs*"
| table _time, host, NewValue, ProcessName
```
Alert: global DLL injection config changed. Severity: High.

---

## 3. Defense Evasion Detection

### 3a. AMSI provider disabled
```
index=windows EventCode=4657
ObjectName="*AMSI*"
| where NewValue="0" OR NewValue=""
| table _time, host, ObjectName, ProcessName
```
Alert: AMSI tampering — attacker already on the box. Severity: Critical.

### 3b. Defender exclusions added
```
index=windows EventCode=4657
ObjectName="*Windows Defender*Exclusions*"
| table _time, host, ObjectName, NewValue, ProcessName
| where ProcessName NOT IN ("MsMpEng.exe","NisSrv.exe")
```
Alert: exclusion added by non-Defender process. Severity: High (attacker adding their tool path).

### 3c. PowerShell encoded command execution
```
index=windows source="*PowerShell*Operational*" EventCode=4104
ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Reflection.Assembly*Load*" OR ScriptBlockText="*Invoke-Expression*"
| stats count by host, user, ScriptBlockText
| eval risk = if(match(ScriptBlockText, "(?i)IEX.*DownloadString"), "critical", "high")
```
Alert: encoded/reflective PS execution. Severity: High (tune: exclude admin tooling like SCCM/Intune PS scripts).

### 3d. Process masquerading (svchost outside System32)
```
index=windows EventCode=4688
NewProcessName="*svchost*" OR NewProcessName="*lsass*" OR NewProcessName="*csrss*" OR NewProcessName="*winlogon*"
| where NewProcessName NOT LIKE "%System32%" AND NewProcessName NOT LIKE "%SysWOW64%"
| table _time, host, NewProcessName, ParentProcessName
```
Alert: critical binary running from non-standard path. Severity: Critical.

### 3e. Event log cleared
```
index=windows EventCode=1102 OR EventCode=104
| table _time, host, user, Channel
```
Alert: security log cleared. Severity: Critical. (BTFM references wevtutil epl as the backup command; clearing is Event 1102 for Security, 104 for System.)

---

## 4. Privilege Escalation Detection

### 4a. AlwaysInstallElevated enabled
```
index=windows EventCode=4657
ObjectName="*Installer*AlwaysInstallElevated*"
NewValue="1"
| table _time, host, ProcessName
```
Alert: MSI runs as SYSTEM. Severity: High.

### 4b. AppLocker disabled or policy removed
```
index=windows EventCode=4657
ObjectName="*AppLocker*"
| where NewValue="" OR NewValue="0"
| table _time, host, ObjectName, ProcessName
```
Alert: application control weakened. Severity: Medium.

### 4c. IFEO debugger set on system binary
```
index=windows EventCode=4657
ObjectName="*Image File Execution Options*Debugger*"
| table _time, host, ObjectName, NewValue, ProcessName
```
Alert: debugger planted on a system binary — code execution primitive. Severity: High.

---

## 5. Lateral Movement Detection

### 5a. RDP connection to non-standard host
```
index=windows EventCode=4624 LogonType=10
| where NOT (SourceWorkstation IN known_rdp_sources)
| stats count by host, SourceNetworkAddress, Account
| where count > 3
```
Alert: RDP from unexpected source. Severity: Medium. Requires baseline of authorized RDP sources.

### 5b. SMB admin share access from non-admin workstation
```
index=windows EventCode=5140 OR EventCode=5145
ShareName="*ADMIN$*" OR ShareName="*C$*"
| where NOT (SourceIP IN admin_workstation_range)
| stats count by host, SourceIP, ShareName
```
Alert: admin share mount from non-admin machine. Severity: High.

### 5c. Pass-the-hash authentication (NTLM logon to network share from machine account)
```
index=windows EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| where Account LIKE "%$"
| stats count by host, SourceNetworkAddress, Account
| where count > 10
```
Alert: machine-account NTLM to a share — possible PtH. Severity: Medium. Requires tuning.

---

## 6. Dashboard Ideas

### 6a. Host Posture Dashboard (from WinHostPEAS JSON reports)
```
# Panel 1: Findings by severity (from ingested WinHostPEAS JSON)
index=winhostpeas | stats count by Severity | sort 0 -Severity

# Panel 2: Critical/High findings over time per host
index=winhostpeas Severity=Critical OR Severity=High | timechart count by host

# Panel 3: Hardening gap heatmap by host
index=winhostpeas Category=Hardening | stats count by host, Title | sort host

# Panel 4: Persistence findings trend (golden image regression test)
index=winhostpeas Category=Persistence | timechart count by host

# Panel 5: Fleet severity distribution (single value)
index=winhostpeas | stats count(eval(Severity="Critical")) as Critical, count(eval(Severity="High")) as High
```

### 6b. Security Event Volume Dashboard (live event log)
```
# Panel 1: Failed logons by host (Event 4625)
index=windows EventCode=4625 | timechart count by host

# Panel 2: Process creation spike detection (Event 4688 rate)
index=windows EventCode=4688 | timechart count by host | eval spike = if(count > avg + 2*stdev, 1, 0)

# Panel 3: PowerShell script block logging volume
index=windows source="*PowerShell*Operational*" EventCode=4104 | timechart count by host

# Panel 4: WMI consumer creation events
index=windows source="*WMI*Operational*" EventCode=5861 | timechart count by host

# Panel 5: Firewall drops by source IP
index=windows source="*Firewall*" | stats count by src_ip | sort -count
```

### 6c. Fleet Compliance Dashboard
```
# Panel 1: % hosts with ASR enabled
index=winhostpeas Title="Defender ASR*" | stats dc(host) as asr_hosts
index=winhostpeas | stats dc(host) as total_hosts
# (use Splunk calc: asr_hosts / total_hosts * 100)

# Panel 2: % hosts with AppLocker/WDAC
index=winhostpeas Title="*AppLocker*" OR Title="*WDAC*" | stats dc(host) as appctrl_hosts

# Panel 3: Hosts with expired certificates
index=winhostpeas Title="EXPIRED*" | stats values(host) as hosts

# Panel 4: Hosts with pending reboots
index=winhostpeas Title="Reboot pending" | stats values(host) as hosts

# Panel 5: Patch staleness by host
index=winhostpeas Title="*No patches*" | stats values(host) as stale_hosts
```

---

## 7. Alert Action Ideas

- **Auto-isolate:** any Critical WinHostPEAS finding in Persistence or Masquerading category triggers host isolation via firewall GPO
- **Ticket creation:** any High finding auto-creates ServiceNow/Jira ticket with finding detail + remediation text (WinHostPEAS JSON includes a Remediation field — use it directly)
- **Slack/Teams notification:** Critical findings send immediate channel alert with host + finding summary
- **Golden image gate:** WinHostPEAS exit code > 0 on image build server blocks the build pipeline (CI/CD gate)

---

## 8. Windows Event ID Reference (for Splunk correlation rules)

| Event ID | Meaning | Detection use |
|---|---|---|
| 4624 | Successful logon | RDP (LogonType 10), network share (3), local (2) |
| 4625 | Failed logon | Brute force detection |
| 4688 | Process created | Masquerading, parent-child anomalies |
| 4657 | Registry value modified | Persistence (Run keys, WDigest, AMSI, AppInit, IFEO) |
| 4698 | Scheduled task created | Fileless persistence with encoded commands |
| 4104 | PowerShell script block | Encoded command detection |
| 5861 | WMI event consumer created | WMI persistence |
| 1102 | Security log cleared | Anti-forensics |
| 5140 | Share accessed | Admin share lateral movement |
| 5145 | File share accessed (detailed) | ADMIN$/C$ access from non-admin |
| 7045 | Service installed | Malicious service creation |
| 4697 | Service installed (Security log) | Same, with more detail |

---

## Notes for the Implementing Agent

1. All SPL queries need field-name verification against your Splunk Windows TA. Common differences: `host` vs `Computer`, `ProcessName` vs `Image`, `ObjectName` vs `RegistryKeyPath`.
2. Tune exclusion lists per environment — the `NOT IN (...)` filters need your actual admin tool process names.
3. The WinHostPEAS JSON ingestion assumes a Splunk custom source type. Create a JSON source type in `props.conf` for the WinHostPEAS report format.
4. Correlation searches should use a rolling 24h window for persistence checks (registry modifications are one-time events) and real-time for logon/lateral movement.
5. The BTFM auditpol subcategory list (15+ subcategories) maps directly to Splunk auditpol data model fields — check if your TA ingests `auditpol /subcategory:*` output.