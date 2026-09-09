# BlueWinPEAS

**A blue-team refit of winPEAS.ps1 — the attacker's local enumeration engine, rebuilt as a full defensive vulnerability-recon tool for Windows Server 2019/2022/2025 and Windows 10/11, including IIS and IIS Rewrite deep recon.**

BlueWinPEAS keeps the detection surface an attacker would enumerate against a host, but repurposes every check for defenders: structured findings with severity and remediation instead of exploit instructions, secret *detection* instead of secret *exfiltration*, OT-safe network discovery, and JSON/CSV/HTML reports built for unattended fleet runs.

Derived from [winPEAS.ps1 v1.3](https://github.com/peass-ng/PEASS-ng) (PEASS-ng / @RandolphConley). Original tooling preserved nowhere in this repo — this is the defensive fork.

---

## Why

winPEAS answers *"how would I escalate from here?"* BlueWinPEAS answers *"what would an attacker find if they landed on this host, and how do I fix it before they do?"* Same enumeration surface, opposite posture:

| | winPEAS.ps1 | BlueWinPEAS |
|---|---|---|
| Output | Raw console dump | 252+ structured findings (Severity/Category/Remediation) |
| Secrets | Prints passwords, WiFi keys, clipboard, DPAPI blobs | Detects + **redacts** — values never reach console or reports |
| Guidance | "Try mimikatz", msfvenom recipes | Fix instructions, MITRE technique IDs, IEC 62443 / CIS references |
| AV | Flagged by Defender at download **and** AMSI-blocked at run | Runs clean — pure PowerShell/.NET, no exploit strings |
| Network | None | ARP/neighbor discovery, ICMP-only subnet sweep, OT-safe banner grab |
| Reports | None | JSON + CSV + HTML per host |
| Unattended | No | Exit code = Critical+High count for fleet triage |
| Runtime (typical) | 30–60+ min full-drive regex crawl | ~2 min default, ~6 min `-FullCheck` |

Both were run side-by-side on the same host during development. winPEAS required a manual Defender exclusion to execute; BlueWinPEAS ran clean with realtime protection on.

## Usage

```powershell
# Fast posture audit (default) - ~2 minutes
pwsh -File BlueWinPEAS.ps1 -OutputDir .\BlueWinPEAS_Output

# Deep run: adds scoped secret-pattern sweep + full inventory - ~6 minutes
pwsh -File BlueWinPEAS.ps1 -OutputDir \\server\share\audits -FullCheck -TimeStamp

# Unattended fleet: exit code = Critical+High finding count (capped 250)
# schedule via GPO/SCCM/Intune/PDQ; centralize reports on a UNC path
```

Parameters:

| Switch | Effect |
|---|---|
| `-FullCheck` | Adds deep (redacted) secret-pattern sweep of credential-bearing dirs + registry areas |
| `-OutputDir <path>` | Report destination (default `.\BlueWinPEAS_Output`) — use UNC for fleet centralization |
| `-TimeStamp` | Per-section elapsed-time stamps |
| `-NoReport` | Console only, no files written |

Read-only: BlueWinPEAS changes nothing on the host.

## Feature writeup

### 1. Findings engine
Every check funnels into one engine. Each finding carries `Timestamp, Host, Severity (Critical/High/Medium/Low/Info), Category, Title, Detail, Evidence, Remediation`. Reports aggregate by severity, list top Critical/High first. Exit code equals the Critical+High count so deployment tooling can triage hosts without parsing anything.

### 2. Secret detection without secret exposure
The winPEAS regex corpus (AWS keys, GitHub/GitLab tokens, JWTs, private key blocks, Slack tokens, Stripe keys, connection strings, 25+ patterns) is kept for **detection**: matches are recorded as findings with the value replaced by a fingerprint (`<redacted:52ch, ends ...Xy9a>`). Removed outright: WiFi password dumps, clipboard content printing, UWP PasswordVault dumping, OpenVPN DPAPI decryption, PowerShell history echoing. What remains is *knowledge that a secret exists and where* — enough to rotate it, not enough to leak it from a report left on a share.

### 3. Credential-exposure hardening checks
WDigest plaintext storage, LSA Protection (RunAsPPL), Credential Guard, cached-domain-logon count, AutoAdminLogon + embedded Winlogon passwords (redacted), RDCMan artifacts, PuTTY stored proxy passwords, ssh-agent key registration, DPAPI key stores, unattend/sysprep answer files, cloud CLI credential files (`.aws`, `.azure`, `.kube`, `.docker`, `.git-credentials`, gcloud), Sticky Notes DB, SAM/SYSTEM hive copies, PSReadLine history credential patterns.

### 4. Privilege-escalation surface (attacker's view, defender's fixes)
AlwaysInstallElevated, unquoted service paths, weak ACLs on service binaries and service registry keys, user-writable startup items, Run/RunOnce persistence inventory, dangerous token privileges held by the current user (SeImpersonate, SeDebug, SeBackup...), UAC state, PrintNightmare-relevant PointAndPrint policy, WSUS-over-HTTP, writable scheduled-task actions.

### 5. Defender / AV posture
Defender realtime status + signature freshness + scan recency, **exclusion inventory** (the first thing attackers add — every exclusion path/process/extension is listed with a review recommendation), firewall profile states.

### 6. Logging & detection coverage
auditpol critical subcategories (Logon/Logoff, Privilege Use, Object Access), Security event log size, Windows Event Forwarding presence, PowerShell ScriptBlock/Module/Transcription logging gaps — the telemetry an attacker hopes is missing.

### 7. Network attack surface
SMBv1, SMB signing, LLMNR / NBT-NS (responder-class capture risk), RDP NLA + SecurityLayer, listening-port inventory with risky-classic flags (Telnet/FTP/SMB/RDP/WinRM), hosts-file overrides, WPAD, world-writable SMB shares.

### 8. Network discovery — ARP, neighbors, devices
Passive ARP/neighbor table snapshot first. Then ICMP-only ping sweep of each directly-connected /24 (async, sub-10s per subnet): every responding device recorded with IP, resolved MAC, RTT, and MAC-OUI vendor tag (Siemens, Rockwell, VMware, Raspberry Pi...). Virtualization MACs in an OT subnet raise a Medium finding — an unmanaged VM where a controller should be. Active-conversation inventory shows who the host actually talks to.

**OT-safe by design**: ICMP echo + TCP connect only. No SYN scans, no protocol frames at PLCs — active scanning can crash fragile legacy controllers; banner grabs send zero payload bytes, they only listen.

### 9. Service & version inventory
Local listeners mapped to owning process + binary version. Port dictionary covers IT (MSSQL, RDP, VNC...) and BMS/OT protocols: Modbus/TCP 502, BACnet 47808, EtherNet/IP 44818, OPC-UA 4840/4843, DNP3 20000, Niagara Fox 1911/5011/4911, Omron FINS 9600, Crestron 41794, CoDeSys, mDNS/SSDP discovery ports. OT-protocol listeners on the host are flagged Medium with IEC 62443 SR 5.1 (zone/conduit) remediation. Passive banner grab runs against discovered devices (12 common ports, short timeout). Installed-software scan matches a 19-vendor BMS dictionary (Tridium Niagara, JCI Metasys, Siemens Desigo/APOGEE, Schneider EcoStruxure, Trane, Carrier, ALC WebCTRL, Distech, Delta, Reliable, CoDeSys, KEPServerEX, MatrikonOPC, Wonderware, Ignition...) so controller/HMI/JACE software is versioned in the report for CVE watchlisting.

### 10. Loopback & tunnel detection
Seven checks for loopback abuse and covert channels: loopback-bound listeners (owning PID/process, deduped across IPv4/IPv6), loopback conversations, **netsh portproxy rules** (High — classic T1090 relay persistence), SSH/plink `-L/-R/-D` tunnel processes (with full command line), DNS terminating on loopback (DNS-tunneling indicator), hosts-file loopback overrides (silent traffic redirection), proxy localhost-bypass config.

### 11. Local account hygiene & AD
Passwordless local accounts (Critical), minimum password length, never-expiring passwords, local admin inventory, LAPS presence (legacy + Windows LAPS), BitLocker, screen-lock timeout. Domain-joined hosts add: LmCompatibilityLevel, insecure dynamic-DNS ACLs, Kerberoastable privileged SPN accounts, gMSA passwords readable by broad principals, ADCS ESC10 Schannel UPN mapping, Kerberos time skew.

### 12. Patch posture
Hotfix recency (60-day staleness = High), pending-reboot detection (patched-but-not-finalized CVE exposure).

### 13. IIS / web-server recon (Server 2019/2022, Win10/11 with IIS)
Full read-only IIS inventory via Microsoft.Web.Administration: sites + bindings (HTTP-only sites flagged Medium), app pools (identity — LocalSystem pools are High; legacy .NET 2.0 runtimes; 32-bit flags), web-root writability checks (writable root = webshell drop-in, High). Certificate store audit: expired certs (Critical), expiring <30d, weak MD5/SHA1 signatures. **IIS URL Rewrite module**: version check against known-fixed builds (2.1.2105+), stale-build advisory flag. web.config sweep across every site root + inetpub: plaintext DB passwords in connection strings (High), weak machineKey validation/short validationKey (ViewState forgery path, High), directoryBrowse enabled, `retail=false`, plus the full secret-pattern scan. applicationHost.config: Basic-auth-over-HTTP, anonymous auth inventory, password-shaped values, and a Critical if the file itself is user-writable (= total IIS takeover). IIS FTP/SMTP service presence. WinRM: HTTP-listener and AllowUnencrypted/Basic-auth checks.

### 14. OS vulnerability / crypto surface
OS build + end-of-support table (Server 2008–2025, Win10/11) with EOL = Critical and <1-year = Medium; Windows 11 feature-update currency (24H2=26100). TLS protocol inventory from SCHANNEL (SSLv2/3, TLS 1.0/1.1 active = High; TLS 1.2/1.3 presence confirmed), enabled cipher-suite audit (NULL/RC4/3DES = Medium), FIPS status. SMBv1 (Critical) + SMB signing server/client. .NET Framework version (pre-4.7 = Medium), legacy v2/v3.x runtimes, SchUseStrongCrypto machine.config gap. Legacy optional features (PowerShellv2, Telnet/TFTP clients, SMB1, NetFx3). secedit policy baseline: password minimum length, lockout threshold, anonymous SAM lookup. RDP encryption level + SecurityLayer. bcdedit testsigning/nointegritychecks (unsigned driver = rootkit path, High).

## Unattended fleet deployment

1. Copy `BlueWinPEAS.ps1` to a share or push via your deployment tool.
2. Schedule: `pwsh -NoProfile -ExecutionPolicy Bypass -File <path>\BlueWinPEAS.ps1 -OutputDir \\server\share\BlueWinPEAS -FullCheck`
3. Each host writes `BlueWinPEAS_<HOST>_<timestamp>.{json,csv,html}`.
4. Triage by exit code: 0 = no Critical/High; N = N Critical/High findings; or ingest the JSONs into your SIEM/CMDB (stable schema, one array of finding objects).

Runtime on a typical BMS box: ~2 min default, ~6 min `-FullCheck`. The slow winPEAS full-drive crawl was deliberately replaced with a scoped sweep of credential-bearing locations.

## Repo layout

```
BlueWinPEAS.ps1    the tool (single file, self-contained)
parts/          source modules in execution order (10_header ... 99_summary)
                cat parts/*.ps1 in filename order == BlueWinPEAS.ps1
```

Edit `parts/`, reassemble with `cat parts/10_header.ps1 parts/11_findings.ps1 parts/12_helpers.ps1 parts/03_adfuncs.ps1 parts/13_secrets.ps1 parts/20_system.ps1 parts/21_creds.ps1 parts/22_privesc.ps1 parts/23_network.ps1 parts/24_ad_software.ps1 parts/25_ot_discovery.ps1 parts/26_service_inventory.ps1 parts/27_loopback.ps1 parts/28_iis.ps1 parts/29_os_vulns.ps1 parts/99_summary.ps1 > BlueWinPEAS.ps1`.

## Extending

- **MAC OUI table**: `parts/25_ot_discovery.ps1` — `$ouiMap` (partial by design; extend with your fleet's vendors)
- **Port dictionary**: `parts/26_service_inventory.ps1` — `$portMap`
- **BMS vendor dictionary**: `parts/26_service_inventory.ps1` — `$otVendors`
- **Secret patterns**: `parts/13_secrets.ps1` — `Get-SecretPatterns`
- **Banner-grab ports**: `parts/26_service_inventory.ps1` — `$bannerPorts`

## Legal

For use only on systems you own or are explicitly authorized to audit. Derived from PEASS-ng's winPEAS (original: https://github.com/peass-ng/PEASS-ng, © PEASS-ng / @RandolphConley) — defensive modifications only.
