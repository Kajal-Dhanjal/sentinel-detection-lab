# Detection 7 — Endpoint-to-AI-Service Data Egress

**MITRE ATT&CK:** [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) (imperfect fit — see note below)
**Tactic:** Exfiltration
**Data source:** Sysmon (Event ID 3 — network connection)
**Severity:** Low / Informational

## A note on the MITRE mapping

T1567 describes deliberate attacker exfiltration via web services. The realistic case this rule actually catches — a local AI tool calling its own backend — is closer to a governance/DLP visibility gap than classic exfil tradecraft. Flagging that here rather than dressing the detection up as something it isn't.

## The threat

Local AI tooling or scripts making outbound network connections — a potential channel for sensitive data leaving the endpoint via an AI service backend, or simply unmanaged egress that bypasses standard DLP/proxy controls.

## The detection (redesigned after a telemetry dead end — see below)

```
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| extend Image = extract(@"Image:\s+(\S+)", 1, RenderedDescription)
| extend ProcessName = tolower(tostring(split(Image, "\\")[-1]))
| extend DestinationHostname = extract(@"DestinationHostname:\s+(\S+)", 1, RenderedDescription)
| extend DestinationIp = extract(@"DestinationIp:\s+(\S+)", 1, RenderedDescription)
| extend DestinationPort = extract(@"DestinationPort:\s+(\S+)", 1, RenderedDescription)
| where ProcessName has_any ("ollama.exe", "llamafile.exe", "lmstudio.exe", "python.exe", "node.exe")
   and DestinationPort in ("443", "80")
| project TimeGenerated, Computer, Image, DestinationHostname, DestinationIp, DestinationPort
```

**Logic:** Sysmon EID 3 fires on every outbound network connection. The original design matched `DestinationHostname` against a list of known AI-provider domains (`claude.ai`, `api.openai.com`, etc.) — that approach was abandoned after live testing (below) and replaced with a process+port match: any process from the known shadow-AI list making an HTTPS/HTTP connection, regardless of destination. This is a deliberate trade-off — less specific about *where* the data is going, but far more reliable given what the underlying telemetry can actually show.

## What broke the original design — the important part of this writeup

This wasn't a tuning exercise in the usual sense. Two real telemetry limitations forced a redesign:

**CDN-edge hostnames break domain matching.** Even confirmed real connections (Ollama calling out, a browser loading Hugging Face) showed `DestinationHostname` as either a CDN edge name (`*.bc.googleusercontent.com`) or blank (`-`) — never the literal domain typed in the browser. Domain-string allowlisting alone is unreliable for this data source.

**Browser traffic is invisible to this telemetry entirely.** A systematic check (`summarize count() by Image` on EID 3) showed zero `msedge.exe` rows despite multiple tabs open and loaded, including a confirmed Hugging Face page load. Root cause: the SwiftOnSecurity Sysmon baseline config excludes browser processes from network-connection logging by design, for noise reduction. This means the rule, as built, **cannot detect browser-based AI usage** — e.g. an employee pasting data into ChatGPT's web UI — only non-browser, direct-process egress (CLI tools, SDKs, scripts calling AI APIs directly).

This is documented as an open, known gap, not silently worked around.

## Validation

**True positive:** Ollama running on the VM was making real outbound calls to Google-hosted infrastructure (`googleusercontent.com`) on port 443 — observed organically, without deliberately triggering it, confirming the rule catches real egress from known AI tooling. 8 matching rows returned once the process+port logic was in place.

**False positive side:** Not tested for this rule's final form — the false-positive-shaped work here was identifying telemetry limitations, not tuning out benign noise from the rule itself.

## Rule status

Saved as a scheduled Analytics Rule, with the browser-exclusion limitation written directly into the rule description: *"Detects known AI-tooling processes making outbound connections. Does not cover browser-based AI usage — SwiftOnSecurity Sysmon baseline excludes browser processes from EID 3 logging."* Host entity mapped to `Computer`.

No incident screenshot for this detection — by design, since the focus here is the rule configuration and the documented telemetry limitation rather than an incident walkthrough.

**Detection rule configuration showing the description with the documented scope limitation:**

[![Endpoint-to-AI-Service Data Egress rule configured with browser-exclusion limitation documented in the description](https://github.com/Kajal-Dhanjal/sentinel-detection-lab/raw/main/evidences/0evidences/07-Endpoint-to-AI-Server.detection.png)](/Kajal-Dhanjal/sentinel-detection-lab/blob/main/evidences/07-Endpoint-to-AI-Server_detection.png)

## Possible improvements

- Custom Sysmon config rule to un-exclude browser processes from EID 3 — would close the biggest visibility gap, at the cost of significant additional log volume/noise.
- Expand `DestinationPort` beyond 443/80 if any AI tooling is found using non-standard ports.
