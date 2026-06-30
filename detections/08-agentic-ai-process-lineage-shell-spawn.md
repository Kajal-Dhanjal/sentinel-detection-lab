# Detection 8 — Agentic AI Process Lineage: Shell Spawn

**MITRE ATT&CK:** [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
**Tactic:** Execution
**Data source:** Sysmon (Event ID 1 — process creation, parent-child lineage)
**Severity:** Low / Informational

## The threat

AI agent frameworks and tools that autonomously execute commands on a host — LangChain-style agents, AI coding assistants, local LLM tools — by spawning a shell as a child process. Not inherently malicious; this is how agentic tools legitimately operate. But an agent shelling out is a meaningfully different risk profile from a human typing commands, and it's worth having visibility into.

## The detection

```
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend Image = extract(@"Image:\s+(\S+)", 1, RenderedDescription)
| extend ParentImage = extract(@"ParentImage:\s+(\S+)", 1, RenderedDescription)
| extend ProcessName = tolower(tostring(split(Image, "\\")[-1]))
| extend ParentProcessName = tolower(tostring(split(ParentImage, "\\")[-1]))
| where ParentProcessName has_any (
    "ollama.exe", "llamafile.exe", "lmstudio.exe",
    "claude.exe", "chatgpt.exe", "cursor.exe", "aider.exe",
    "python.exe", "node.exe"
  )
| where ProcessName has_any ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "bash.exe")
| project TimeGenerated, Computer, ParentImage, ParentProcessName, Image, ProcessName
```

**Logic:** A parent-child lineage join, not a single-event signature — conceptually closest to the behavioral approach used in Detection 4. The query extracts both `Image` (child) and `ParentImage` (parent) from the same EID 1 event using the established regex pattern, normalizes both names with `tolower()`, then checks that the parent is a known AI/scripting process **and** the child is a command interpreter. Both conditions must hold on the same event for a match.

## False positives

Not yet found — but explicitly flagged as a known risk rather than a clean result: `python.exe` and `node.exe` as parent processes is broad. Almost any Python or Node script that legitimately shells out for unrelated reasons (build tools, package managers, CI scripts) would trigger this. Only one validation data point exists so far (a synthetic test), so this hasn't been exercised against real-world Python/Node usage patterns yet. Stated honestly as an open tuning item, not pretended away.

## Validation

**True positive:** Wrote a 2-line Python script (`spawn_test.py`) calling `subprocess.run("cmd.exe /c echo agentic_test", shell=True)`, ran it with `python spawn_test.py`. This created a real `python.exe → cmd.exe` parent-child event. The query returned 1 matching row on first attempt: `ParentImage = C:\Users\labadmin\AppData\Local\Programs\Python\Python314\python.exe`, `Image = C:\Windows\System32\cmd.exe`. Worked first try, no debugging needed.

**False positive side:** Not yet tested.

## Rule status

Saved as a scheduled Analytics Rule ("Agentic AI Process Lineage - Shell Spawn", 5 min run / 10 min lookback, Host entity mapped to `Computer`). The FP-risk caveat is written into the rule description verbatim. Incident raised and confirmed via a fresh trigger of `spawn_test.py` after the rule was saved.

**Detection rule configuration, including the documented FP-risk caveat in the description:**

[![Agentic AI Process Lineage - Shell Spawn rule configured with FP-risk caveat in the description](https://github.com/Kajal-Dhanjal/sentinel-detection-lab/raw/main/evidences/08-Agentic-AI-Process-Lineage-Spawn-Detection.png)](/Kajal-Dhanjal/sentinel-detection-lab/blob/main/evidences/08-Agentic-AI-Process-Lineage-Spawn-Detection.png)

**Incident raised, confirming the python.exe → cmd.exe spawn was caught:**

[![Agentic AI Process Lineage - Shell Spawn incident showing the captured spawn_test.py trigger](https://github.com/Kajal-Dhanjal/sentinel-detection-lab/raw/main/evidences/08-Agentic-AI-Process-Lineage-Spawn-Incident.png)](/Kajal-Dhanjal/sentinel-detection-lab/blob/main/evidences/08-Agentic-AI-Process-Lineage-Spawn-Incident.png)

## Possible improvements

- Tighten `python.exe`/`node.exe` as parents with an allowlist of known-legitimate spawn patterns once enough real data exists to identify them — the same narrowing approach used in Detection 3's `ctfmon` tuning. Don't narrow blind without real data.
- Add `CommandLine` of the spawned shell to the projection, to distinguish a benign `echo`/build-script call from something with suspicious flags — mirroring Detection 2's flag-matching approach.
