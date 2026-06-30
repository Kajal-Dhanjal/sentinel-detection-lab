# Detection 6 — Shadow AI Tooling Execution

**MITRE ATT&CK:** [T1588.002 — Obtain Capabilities: Tool](https://attack.mitre.org/techniques/T1588/002/) (imperfect fit — see note below)
**Tactic:** Resource Development (per the closest ATT&CK mapping); in practice this functions as a custom "Unsanctioned Software Execution" control
**Data source:** Sysmon (Event ID 1 — process creation)
**Severity:** Low / Informational

## A note on the MITRE mapping

T1588.002 describes an *attacker* acquiring tooling pre-compromise — it's not a clean match for an *employee* installing AI software on a managed endpoint. I'm flagging that mismatch explicitly rather than overstating the ATT&CK alignment to make the detection sound more "attacker-focused" than it is. This rule is closer to shadow-IT/governance visibility than classic threat detection, and the writeup says so.

## The threat

Employees installing and running local or desktop AI tooling — LLM runners, AI coding assistants, desktop chatbot clients — outside any sanctioned IT process. This isn't inherently malicious. It's a visibility gap: unsanctioned AI tools can move data through model context without enterprise DLP or logging, creating attack surface IT doesn't know exists.

## The detection

```
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend Image = extract(@"Image:\s+(\S+)", 1, RenderedDescription)
| extend ProcessName = tolower(tostring(split(Image, "\\")[-1]))
| where ProcessName has_any (
    "ollama.exe", "llamafile.exe", "lm-studio.exe", "lmstudio.exe",
    "chatgpt.exe", "claude.exe", "gemini.exe", "copilot.exe",
    "cursor.exe", "aider.exe", "openai.exe"
  )
| project TimeGenerated, Computer, Image, ProcessName
```

**Logic:** Sysmon EID 1 fires on every process creation. The query extracts `Image` (full binary path) from the unstructured `RenderedDescription` text via regex, isolates the filename with a path split, normalizes case with `tolower()` (Windows logs process names inconsistently — the same issue surfaced in Detection 4's recon-burst case-sensitivity bug), then checks the filename against a known list of AI tool binaries. This is a signature match — a single matching event is the full signal, no aggregation required (same design pattern as Detection 2).

## False positives

None encountered — but only one validation pass has been run (Ollama), so this hasn't been stress-tested against real endpoint diversity. Stated plainly rather than implying a clean bill of health: **this rule has not yet been false-positive tested at scale.**

## Validation

**True positive:** Installed real Ollama (`OllamaSetup.exe`, direct download — `winget` isn't available on Windows Server 2022) on `vm-win-lab`, confirmed the process running via `Get-Process ollama`, then queried Sentinel. Returned 5 matching rows with a clean, untruncated full path (`C:\Users\labadmin\AppData\Local\Programs\Ollama\ollama.exe`) — a useful counter-example to the path-truncation gotcha logged in Detection 2, since this install path contains no spaces for the regex to stop on.

**False positive side:** Not yet tested — no benign-but-similarly-named process has been run against this rule.

## Rule status

Saved as a scheduled Analytics Rule (5 min run / 10 min lookback, Host entity mapped to `Computer`). Confirmed live in Sentinel with 5 matching events surfaced.

**Detection rule configuration in Microsoft Sentinel:**

[![Shadow AI Tooling Execution rule configured and enabled](https://github.com/Kajal-Dhanjal/sentinel-detection-lab/raw/main/evidences/06-Shadow-AI-Tooling-detection.png)](/Kajal-Dhanjal/sentinel-detection-lab/blob/main/evidences/06-Shadow-AI-Tooling-detection.png)

**Incident raised with related events showing the captured Ollama execution:**

[![Shadow AI Tooling Execution incident showing ollama.exe process creation events](https://github.com/Kajal-Dhanjal/sentinel-detection-lab/raw/main/evidences/06-Shadow-AI-Tooling-incident.png)](/Kajal-Dhanjal/sentinel-detection-lab/blob/main/evidences/06-Shadow-AI-Tooling-incident.png)

## Possible improvements

- Expand the binary list as more AI tools are identified; the current list is a snapshot, not exhaustive.
- Correlate with Detection 7 (egress) — a host hitting both rules in the same window is a stronger combined signal than either alone.
