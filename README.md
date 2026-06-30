# Sentinel Detection Lab

A hands-on detection engineering lab built in Microsoft Sentinel. Windows endpoint telemetry (Security audit logs + Sysmon) and Microsoft Entra ID identity telemetry (sign-in + audit logs) are ingested into a Log Analytics workspace, where custom KQL detections are authored, tuned against false positives, and deployed as scheduled analytics rules that raise incidents automatically — with select detections extended into automated first-response actions.

This repo documents the detections I've written, the attacks I simulated to validate them, and — most importantly — the tuning decisions behind each one.

## Why this exists

Most "home SOC lab" projects stop at "I connected logs to a SIEM." This one focuses on the part that actually matters in a SOC: **writing detections that catch real attacker behavior while staying quiet on legitimate activity.** Every detection here was validated on both sides where possible — it fires on a simulated attack, and ideally it does *not* fire on benign noise. Where that second half hasn't been done yet (detections 6 and 8), the writeup says so explicitly rather than implying a polish level that isn't there.

## Architecture

**Endpoint telemetry:**

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

**Identity telemetry + automated response (Detection 5 onward):**

```
Microsoft Entra ID (AuditLogs + SignInLogs)
        │  Diagnostic settings
        ▼
Log Analytics Workspace ──► Microsoft Sentinel
                                  │
                    Scheduled Analytics Rules
                                  │
                              Incidents
                                  │
                  Automation Rule ──► Azure Logic App
                                  │
                    Automated triage comment on incident
```

- **Endpoint:** Windows Server 2022 with [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (SwiftOnSecurity config) + Windows Security auditing
- **Identity:** Microsoft Entra ID diagnostic settings (AuditLogs + SignInLogs) → Log Analytics
- **Collection:** Azure Monitor Agent → Data Collection Rules → Log Analytics (endpoint) / native diagnostic settings (identity)
- **Detection:** custom KQL → Microsoft Sentinel scheduled analytics rules
- **Response:** select detections trigger a Sentinel automation rule on incident creation, which runs an Azure Logic App to post an automated triage comment (see Detection 5)
- **Note on tables:** endpoint logs land in the `Event` table (DCR-based collection), so those detections parse `RenderedDescription` rather than reading pre-split columns — closer to real-world log-wrangling.

## Detections

| # | Detection | MITRE | Tactic | Data source |
|---|-----------|-------|--------|-------------|
| 1 | [Brute-Force Failed Logons](detections/01-brute-force-failed-logons.md) | T1110 | Credential Access | Security (4625) |
| 2 | [Suspicious PowerShell Execution](detections/02-suspicious-powershell.md) | T1059.001, T1027 | Execution / Defense Evasion | Sysmon (EID 1) |
| 3 | [Registry Run-Key Persistence](detections/03-registry-run-key-persistence.md) | T1547.001 | Persistence | Sysmon (EID 13) |
| 4 | [Reconnaissance Command Burst](detections/04-reconnaissance-command-burst.md) | T1057, T1082, T1016 | Discovery | Sysmon (EID 1) |
| 5 | [Suspicious MFA Registration Following Sign-In from Untrusted IP](detections/05-suspicious-mfa-registration.md) | T1556.006 | Persistence | Entra ID (SignInLogs + AuditLogs) |
| 6 | [Shadow AI Tooling Execution](detections/06-shadow-ai-tooling-execution.md) | T1588.002 | Resource Development | Sysmon (EID 1) |
| 7 | [Endpoint-to-AI-Service Data Egress](detections/07-endpoint-to-ai-service-data-egress.md) | T1567 | Exfiltration | Sysmon (EID 3) |
| 8 | [Agentic AI Process Lineage: Shell Spawn](detections/08-agentic-ai-process-lineage-shell-spawn.md) | T1059 | Execution | Sysmon (EID 1) |

Each detection file documents: the threat, the KQL, the simulated attack used to validate it, false positives encountered (or honestly flagged as not-yet-tested) and how they were tuned out, and the MITRE mapping.

**A note on detections 6–8:** these extend the lab into an AI-threat-detection track — governance and visibility gaps created by AI tooling on the endpoint, rather than classic attacker tradecraft. Where the MITRE mapping is an imperfect fit for that shift (6 and 7 especially), each writeup says so directly instead of forcing the framing.

## Detection-to-response

Detection 5 extends the lab beyond "alert fires" into automated first response: a Sentinel automation rule fires on incident creation, runs an Azure Logic App, and posts a triage comment with the recommended containment step directly on the incident — no analyst action required to get that first step documented. See [Detection 5](detections/05-suspicious-mfa-registration.md) for the full writeup, including why I chose a reliable "add comment" action over a more ambitious but less reliable watchlist-write.

## Key lessons captured here

- **Parsing matters.** Real log data is messier than column names suggest; extracting fields from `RenderedDescription` with regex is a core skill (see Detection 1).
- **The first regex match is often the wrong one.** Detection 1 initially flagged the legitimate user instead of the attacker.
- **A detection not firing isn't always a bug.** Sometimes test data doesn't match real attack tempo (see Detection 1).
- **Tuning out benign activity is the job.** Detection 3 fired on legitimate Windows behavior first; the writeup shows how it was tuned narrowly without going blind to real attacks.
- **Not every false positive is fixed the same way.** Detection 3's fix was narrowing (excluding a benign pattern); Detection 4's was raising a threshold (4 → 5 distinct commands). Different false-positive shapes need different tuning levers — recognizing which one you're looking at matters more than memorizing a fix.
- **Behavioral detection is a different skill from signature matching.** Detections 1–3 catch a single bad pattern; Detection 4 measures *variety* of otherwise-benign commands clustered in time (`dcount`, not raw volume) — closer to how real behavioral detection works.
- **Build around the license you have, not the one you want.** Detection 5 was designed around Entra ID Protection P2's risk score; the P2 trial wouldn't activate in this tenant. Rather than block on it, I built a heuristic substitute (untrusted-IP correlation) and documented the tradeoff instead of hiding it.
- **Closing the loop matters more than another detection.** Detection 5 is the first one here that doesn't stop at "incident created" — it triggers an automated response, which is a meaningfully different skill from writing the query.
- **Pick the reliable action over the impressive one.** A flaky UI (Sentinel watchlists) initially looked like the right place to automate a block-list update. I scoped the automation down to a smaller, reliable action instead of shipping something that looked good in a demo but would fail in practice.
- **Dedup boundaries matter.** A scheduled query's `summarize`-based dedup only protects within a single run's lookback window — it doesn't prevent re-alerting across runs. Caught this from real duplicate incidents during testing, not from reading the docs.
- **A working detection and a tuned detection are different claims.** Detections 6 and 8 are validated true-positive catches with known, documented false-positive risk — not yet stress-tested at scale. The repo states that distinction rather than blurring it.
- **Know your telemetry's blind spots before trusting a detection's scope.** Detection 7's redesign came from discovering that the Sysmon baseline config silently excludes browser processes from network logging — a real limitation now documented in the rule itself, not buried.

## Disclaimer

This is a personal learning lab. All "attacks" are benign simulations run against my own isolated VM or personal Azure tenant. No real malware, no real credentials, no production systems.
