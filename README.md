# WinHostPEAS

**A blue-team refit of winPEAS.ps1: the attacker's local enumeration engine rebuilt as a passive, read-only posture audit for Windows Server 2019/2022/2025 and Windows 10/11, including IIS deep recon.**

WinHostPEAS keeps the enumeration surface an attacker would walk on a host, but turns every check around. You get structured findings with severity and remediation instead of exploit paths, secret detection instead of secret exfiltration, and JSON/CSV/HTML reports built for unattended fleet runs.

Derived from [winPEAS.ps1](https://github.com/peass-ng/PEASS-ng) (PEASS-ng / @RandolphConley). No offensive tooling is retained.

---

## Two guarantees

**It sends nothing.** Every check reads local state only: registry, WMI, local socket tables, local files. There are no ICMP sweeps, no port scans, no banner grabs, and no LDAP or NTP queries. Nothing is sent to a domain controller. Domain membership comes from `Win32_ComputerSystem`, never from contacting a DC. The external binaries it shells out to are all read-only verbs: `auditpol /get`, `secedit /export`, `bcdedit /enum`, `netsh ... show`, `whoami /groups`.

**It changes nothing.** No registry writes, no service or policy changes, no ACL edits. It writes its own reports to `-OutputDir` and one temporary secedit export to `%TEMP%`, which it then deletes. Remediation text tells you what to change; the tool never changes it for you.

You can verify both by grepping the single shipped script. Neither claim depends on trusting this document.

## Why it exists

winPEAS answers "how do I escalate from here?" WinHostPEAS answers "what would an attacker find if they landed here, and how do I close it first?"

| | winPEAS.ps1 | WinHostPEAS |
|---|---|---|
| Output | Console dump | Structured findings (Severity/Category/Remediation) |
| Secrets | Prints passwords, WiFi keys, DPAPI blobs | Detects and redacts; values never reach console or report |
| Guidance | "Try mimikatz" | Fix instructions, MITRE technique IDs, IEC 62443 / CIS references |
| AV | Defender-flagged, AMSI-blocked | Runs clean with realtime protection on |
| Network | Active scanning | Nothing sent, local reads only |
| Unattended | No | Exit code = Critical+High count |

## Usage

```powershell
# Fast posture audit
pwsh -File WinHostPEAS.ps1 -OutputDir .\WinHostPEAS_Output

# Deep run: adds a scoped, redacted secret-pattern sweep
pwsh -File WinHostPEAS.ps1 -OutputDir \\server\share\audits -FullCheck -TimeStamp
```

| Switch | Effect |
|---|---|
| `-FullCheck` | Adds a redacted secret-pattern sweep of credential-bearing directories and registry areas |
| `-OutputDir <path>` | Report destination (default `.\WinHostPEAS_Output`); use a UNC path for fleet centralization |
| `-TimeStamp` | Per-section elapsed-time stamps |
| `-NoReport` | Console only, no files written |
| `-NoLaunch` | Do not open the HTML dashboard; use this for unattended runs |
| `-Obfuscate` | Randomized report filenames and a generic tool label |

Reference runtimes on a Windows 11 workstation: about 35 seconds by default, about 2 minutes with `-FullCheck`.

## Run it elevated

The tool works fine as a standard user, but about a dozen checks need administrator: audit policy, the secedit baseline, boot configuration, Security event log settings, BitLocker, WMI event subscriptions, connectivity history, the scheduled-task file baseline, and other users' process details.

When a check cannot run, WinHostPEAS says so. It emits an explicit "not assessed (needs elevation)" finding instead of reporting a clean result. That rule drives a lot of the design: a check that could not execute must never look like a check that found nothing wrong. A banner at the top of every run states which context it ran in.

If you audit only non-elevated, expect partial coverage, and read the "not assessed" findings as gaps rather than passes.

## What it checks

### Findings engine

Every check funnels into one collector. Each finding carries `Timestamp, Host, Severity (Critical/High/Medium/Low/Info), Category, Title, Detail, Evidence, Remediation`. The process exit code equals the Critical+High count, so deployment tooling can triage without parsing anything.

### Secret detection without secret exposure

The winPEAS regex corpus (cloud keys, GitHub/GitLab tokens, JWTs, private-key blocks, connection strings, and more) is kept for detection only. Matches are recorded with the value replaced by a fingerprint such as `<redacted:52ch, ends ...Xy9a>`. Removed outright: WiFi password dumps, clipboard printing, PasswordVault dumping, DPAPI decryption, history echoing. You learn that a secret exists and where it lives, which is enough to rotate it and not enough to leak it from a report left on a share.

### Credential exposure

WDigest plaintext storage, LSA Protection (RunAsPPL), Credential Guard, cached logon count, AutoAdminLogon passwords (redacted), PuTTY stored proxy passwords, ssh-agent keys, unattend and sysprep answer files, cloud CLI credential files, SAM/SYSTEM hive copies.

### Privilege escalation

AlwaysInstallElevated, unquoted service paths, weak ACLs on service binaries and service registry keys, user-writable startup items, dangerous token privileges held by the caller (SeImpersonate, SeDebug, SeBackup), PointAndPrint policy, WSUS over HTTP, writable scheduled-task actions.

UAC coverage distinguishes *EnableLUA absent* from *EnableLUA = 0*, because a deleted value implies tampering and calls for different remediation. It also flags silent-elevation consent and `LocalAccountTokenFilterPolicy = 1`, the setting that makes pass-the-hash work against admin shares.

### Defender and AV posture

Realtime status, signature freshness, scan recency, and a full exclusion inventory. Exclusions are the first thing an attacker adds. A standard user only sees a subset of them, so a non-elevated run labels the count PARTIAL instead of presenting it as complete.

### Logging and detection coverage

auditpol subcategories, Security event log sizing, Windows Event Forwarding, and PowerShell ScriptBlock/Module/Transcription logging gaps. This is the telemetry an attacker hopes is missing.

### Network attack surface

SMBv1 and SMB signing, LLMNR/NBT-NS, RDP NLA and SecurityLayer, listening-port inventory with risky-classic flags, hosts-file overrides, WPAD, world-writable shares. Port visibility comes from the local socket table, not from scanning.

### Passive network visibility

ARP and neighbour cache plus established-connection inventory, with MAC-OUI vendor tagging. This shows who the host already talks to. Nothing is probed.

### Service and OT inventory

Local listeners mapped to owning process and binary version, against a port dictionary covering IT services and BMS/OT protocols (Modbus/TCP 502, BACnet 47808, EtherNet/IP 44818, OPC-UA 4840/4843, DNP3 20000, Niagara Fox, Omron FINS, CoDeSys). OT listeners are flagged with IEC 62443 SR 5.1 zone and conduit remediation. Installed software is matched against a BMS vendor dictionary so controller and HMI software is versioned for CVE watchlisting.

### Loopback and tunnel detection

Loopback-bound listeners with owning process, loopback conversations, `netsh portproxy` rules (classic T1090 relay persistence), SSH/plink `-L/-R/-D` tunnels, DNS terminating on loopback, hosts-file redirection, proxy bypass config.

### Account hygiene and identity

Accounts carrying the `PASSWD_NOTREQD` flag, password policy, never-expiring passwords, local admin inventory, LAPS presence, BitLocker, screen-lock timeout. Domain-joined hosts also get NTLM policy and ADCS ESC10 Schannel UPN mapping, both read from the local registry.

The blank-password check is worth explaining, because the obvious version of it is wrong. `PASSWD_NOTREQD` means a blank password is *permitted*, not that the account has one, and the flag is a routine artifact of programmatic account creation. Reporting it as "no password" raises a false alarm on ordinary service accounts. Confirming the real state would mean attempting authentication, which writes failed-logon events and can trip lockout policy, so the tool does not do it. Instead it reports the flag accurately and scales severity by `LimitBlankPasswordUse`, since a blank password that cannot be used over the network is a very different problem from one that can.

Domain-side hygiene such as Kerberoastable SPNs and gMSA read permissions is deliberately not assessed, because every way to check it means querying a domain controller.

### Patch posture

Hotfix recency and pending-reboot detection.

### IIS and web server

Read-only inventory via `Microsoft.Web.Administration`: sites and bindings, app pool identities, web-root writability, certificate expiry and weak signatures, URL Rewrite version currency. The web.config sweep looks for plaintext connection-string passwords, weak machineKey validation, directory browsing, and `retail=false`. applicationHost.config checks for Basic-auth-over-HTTP, and raises a Critical if the file itself is user-writable. WinRM transport and auth are covered too, including service state and listening ports when the listener config is unreadable.

### OS and crypto surface

Build and end-of-support status, SCHANNEL protocol inventory, enabled cipher-suite audit, FIPS status, SMB signing, .NET version and `SchUseStrongCrypto`, legacy optional features, secedit password and lockout baseline, RDP encryption level, and bcdedit testsigning and code-integrity state.

### Persistence deep-dive

The quieter slots beyond autoruns: Winlogon Shell/Userinit/Taskman hijacks, WMI permanent event subscriptions, per-user COM hijacks, IFEO Debuggers and SilentProcessExit monitors, AppInit_DLLs, non-standard LSA Security and Notification packages, Active Setup StubPaths, netsh helper DLLs, screensaver hijacks.

### Advanced persistence and obfuscation

UAC-bypass registry residue (fodhelper, eventvwr, sdclt), file-association and ProgID hijacks across HKLM and HKCU, non-standard service recovery commands, AMSI provider state including provider DLLs outside protected paths, encoded or reflective PowerShell in console history, and core Windows binaries running outside their expected directories.

Scheduled tasks are scanned for obfuscated commands, including tasks under `\Microsoft\`. Masquerading hides there, so excluding that tree would blind the check at its most useful target.

### Extended persistence and hardening baseline

The autostart slots that sit beside the ones everyone checks, drawn from the Blue Team Field Manual.

`RunOnceEx`, `RunServices` and `RunServicesOnce` under both hives, the policy `Explorer\Run` keys, `ShellServiceObjectDelayLoad`, and the legacy `Load`/`Run`/`Scripts` values under the HKCU Windows NT key. Group Policy logon and startup script registrations. Legacy startup files (`winstart.bat`, `wininit.ini`, `autoexec.bat`, `autoexec.nt`) and `win.ini` `run=`/`load=` directives.

`HKCU\Environment` gets two checks: `UserInitMprLogonScript`, which runs at every logon of that user and appears in no machine-wide autoruns audit (T1037.001), and user-writable directories on the user `PATH`, which can shadow a system binary invoked without a full path.

Session Manager `BootExecute` against its expected default, and `KnownDLLs` validated by signature rather than by name. The expected KnownDLLs set varies by Windows version and architecture, so this checks that each entry resolves to a Microsoft-signed DLL in System32 instead of comparing against a name list that would drift.

Browser Helper Objects, deduplicated across the native and Wow6432Node registrations, resolved to their backing DLL and flagged when that DLL sits outside Windows or Program Files.

Accessibility binaries (`sethc.exe`, `utilman.exe`, `osk.exe`, and others) are signature-checked. These are launchable from the logon screen before authentication, so a replaced one is a pre-authentication SYSTEM backdoor.

Firewall logging state per profile, Application and System event log sizing, IPv6 `DisabledComponents` recorded for baseline comparison, and a comparison of the scheduled-task registry cache against the enumerable task list, since a task present in `TaskCache` but absent from the scheduler API has been deliberately hidden.

Suspect commands and DLLs surfaced by these checks carry a SHA-256 in the finding's Evidence field for downstream IOC matching.

### Image hardening baseline

Every check reports current state plus the exact image change: Defender ASR rules (against Microsoft's canonical rule list), Controlled Folder Access, network and cloud-delivered protection, Exploit Protection, AppLocker/WDAC, SmartScreen, UAC consent level, Guest account, features to strip, admin-count trim, and null-session and remote-registry hardening.

## Hardening workflow

Run against the golden image, filter to Category `Hardening`, and treat each Remediation line as a build change. Re-run after each change; the exit code falls as the image hardens.

The `Persistence` and `PrivEsc` categories double as regression tests. A finished image should return zero Critical/High across `Persistence`, `PrivEsc`, and `Hardening` before rollout.

## Unattended fleet deployment

1. Copy `WinHostPEAS.ps1` to a share, or push it with your deployment tool.
2. Schedule: `pwsh -NoProfile -ExecutionPolicy Bypass -File <path>\WinHostPEAS.ps1 -OutputDir \\server\share\WinHostPEAS -FullCheck -NoLaunch`
3. Each host writes `WinHostPEAS_<HOST>_<timestamp>.{json,csv,html}`.
4. Triage on exit code, or ingest the JSON into a SIEM or CMDB. The schema is stable: one array of finding objects under `Findings`, with a `Meta` block.

Run it elevated. See the elevation section above for what you lose otherwise.

## Handle the reports carefully

Reports enumerate credential-adjacent material: paths, account names, exclusion lists, listening services. Secret values are redacted, but the reports still describe your attack surface in detail. Treat them as evidence rather than as logs. The supplied `.gitignore` excludes report artifacts for that reason.

The tool deliberately offers no encryption of its own. Report protection belongs to the storage layer, where it can be done properly: write to a share with real access controls, or to a BitLocker or EFS-protected volume. A passphrase switch bolted onto a scanner invites people to trust it more than it deserves.

## Building from source

The shipped script is one self-contained file assembled from `parts/`:

```powershell
pwsh -File build.ps1
```

`build.ps1` concatenates the parts in an explicit order, verifies the result parses, strips comments with the PowerShell AST tokenizer (so `#` inside strings and regexes survives), then re-verifies.

```
WinHostPEAS.ps1   the tool: single file, self-contained, no dependencies
build.ps1         assembles parts/ into the shipped script
parts/            source modules
```

Two notes for contributors. The assembly order in `build.ps1` is an explicit list, so a new part file that is not added to it will silently never ship. And `parts/04_installedapps.ps1` and `parts/05_regex.ps1` are inherited dead code, deliberately excluded from the build.

## Extending

| What | Where |
|---|---|
| MAC OUI table | `parts/25_ot_discovery.ps1`, `$ouiMap` |
| Port dictionary | `parts/26_service_inventory.ps1`, `$portMap` |
| BMS vendor dictionary | `parts/26_service_inventory.ps1`, `$otVendors` |
| Secret patterns | `parts/13_secrets.ps1`, `Get-SecretPatterns` |
| Obfuscation indicators | `parts/33_advanced.ps1`, `$script:ObfPattern` |

## Legal

For use only on systems you own or are explicitly authorized to audit. Derived from PEASS-ng's winPEAS (https://github.com/peass-ng/PEASS-ng, (c) PEASS-ng / @RandolphConley); defensive modifications only.
