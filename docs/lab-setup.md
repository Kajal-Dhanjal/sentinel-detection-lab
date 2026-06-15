# Lab Setup

How the environment is wired. All identifiers (subscription, tenant, IPs, hostnames) are placeholders — replace with your own.

## Components

| Component | Detail |
|-----------|--------|
| SIEM | Microsoft Sentinel on a Log Analytics workspace |
| Endpoint | Windows Server 2022 Datacenter VM |
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) + Windows Security auditing |
| Log shipping | Azure Monitor Agent (AMA) via Data Collection Rules |

## Build steps (high level)

1. **Workspace + Sentinel** — create a Log Analytics workspace, enable Microsoft Sentinel on it. Set a daily ingestion cap to control cost.
2. **Windows VM** — deploy Windows Server 2022 (Standard security type). Lock RDP to your own IP only.
3. **Sysmon** — install with the SwiftOnSecurity config:
   ```powershell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
   Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
   & "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"
   ```
4. **Data Collection Rules** (Azure Monitor → Data Collection Rules):
   - **Security events:** Windows Event Logs data source → Security log (Audit success + Audit failure) → workspace.
   - **Sysmon:** Windows Event Logs, Custom mode, XPath: `Microsoft-Windows-Sysmon/Operational!*` → workspace.
5. **Analytics rules** — author detections as scheduled query rules in Sentinel, MITRE-mapped, with host entity mapping.

## Notes

- Logs land in the **`Event`** table (DCR-based collection), so detections parse `RenderedDescription` rather than reading split columns like `SecurityEvent` provides. This is intentional — it mirrors messy real-world log handling.
- The VM is deallocated when not in active use to control cost.
- All attack simulations are benign and run only against this isolated VM.
