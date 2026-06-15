# Sentinel Detection Lab

A hands-on detection engineering lab built in Microsoft Sentinel. Windows endpoint telemetry (Security audit logs + Sysmon) is ingested into a Log Analytics workspace, where custom KQL detections are authored, tuned against false positives, and deployed as scheduled analytics rules that raise incidents automatically.

This repo documents the detections I've written, the attacks I simulated to validate them, and — most importantly — the tuning decisions behind each one.

## Why this exists

Most "home SOC lab" projects stop at "I connected logs to a SIEM." This one focuses on the part that actually matters in a SOC: **writing detections that catch real attacker behavior while staying quiet on legitimate activity.** Every detection here was validated on both sides — it fires on a simulated attack, and it does *not* fire on benign noise.

## Architecture

```
Windows VM (Sysmon + Security auditing)
        │  Azure Monitor Agent
        ▼
Data Collection Rules ──► Log Analytics Workspace ──► Microsoft Sentinel
                                                            │
                                          Scheduled Analytics Rules
                                                            │
                                                      Incidents
```

- **Endpoint:** Windows Server 2022 with [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (SwiftOnSecurity config) + Windows Security auditing
- **Collection:** Azure Monitor Agent → Data Collection Rules → Log Analytics
- **Detection:** custom KQL → Microsoft Sentinel scheduled analytics rules
- **Note on tables:** logs land in the `Event` table (DCR-based collection), so detections parse `RenderedDescription` rather than reading pre-split columns — closer to real-world log-wrangling.

## Detections

| # | Detection | MITRE | Tactic | Data source |
|---|-----------|-------|--------|-------------|
| 1 | [Brute-Force Failed Logons](detections/01-brute-force-failed-logons.md) | T1110 | Credential Access | Security (4625) |
| 2 | [Suspicious PowerShell Execution](detections/02-suspicious-powershell.md) | T1059.001, T1027 | Execution / Defense Evasion | Sysmon (EID 1) |
| 3 | [Registry Run-Key Persistence](detections/03-registry-run-key-persistence.md) | T1547.001 | Persistence | Sysmon (EID 13) |

Each detection file documents: the threat, the KQL, the simulated attack used to validate it, false positives encountered and how they were tuned out, and the MITRE mapping.

## Key lessons captured here

- **Parsing matters.** Real log data is messier than column names suggest; extracting fields from `RenderedDescription` with regex is a core skill (see Detection 1).
- **The first regex match is often the wrong one.** Detection 1 initially flagged the legitimate user instead of the attacker.
- **A detection not firing isn't always a bug.** Sometimes test data doesn't match real attack tempo (see Detection 1).
- **Tuning out benign activity is the job.** Detection 3 fired on legitimate Windows behavior first; the writeup shows how it was tuned narrowly without going blind to real attacks.

## Disclaimer

This is a personal learning lab. All "attacks" are benign simulations run against my own isolated VM. No real malware, no real credentials, no production systems.
