# SOC Lab – Sysmon PowerShell Detections (Encoded / Suspicious Commands) in Splunk

Small SOC-style homelab project showing practical SIEM work in Splunk: collecting Sysmon telemetry, hunting PowerShell execution, building basic detections (alerts), creating a simple dashboard, and documenting triage steps.

## Goal
Detect and investigate suspicious PowerShell activity on Windows, including:
- Encoded commands (`-enc` / `-EncodedCommand`)
- Suspicious keywords often seen in attacks (download/execute, obfuscation indicators)

## Environment / Data Source
- Splunk Enterprise (local lab)
- Splunk Universal Forwarder on Windows
- Sysmon (Sysinternals)
- Windows Event Log: `Microsoft-Windows-Sysmon/Operational`

### Key Sysmon Event IDs used
- **1** = Process Create (process execution + command line)

## Repository Structure
- `alerts/` – saved alert SPL queries (detections)
- `searches/` – dashboard / investigation searches (SPL)
- `playbook/` – triage notes
- `screenshots/` – evidence (setup, queries, dashboard, alerts)

## Setup (evidence)
Screenshots showing Sysmon + Splunk ingestion setup:
- `screenshots/setup/01_sysmon_operational_log.png`
- `screenshots/setup/02_inputs_conf_sysmon.png`

## Searches (investigation / dashboard building)
All investigation SPL is in `searches/`.

Screenshots:
- `screenshots/queries/00_sysmon_eventcodes.png`
- `screenshots/queries/01_sysmon_encoded_events.png`
- `screenshots/queries/02_powershell_keywords.png`
- `screenshots/queries/03_powershell_parent.png`

## Dashboard
Dashboard panels focus on visibility into PowerShell execution (Sysmon `EventCode=1`).

Screenshots:
- `screenshots/dashboard/dashboard_overview01.png`
- `screenshots/dashboard/dashboard_overview02.png`
- `screenshots/dashboard/dashboard_overview03.png`

## Detections / Alerts
All alert SPL is in `alerts/`.

### 1) PowerShell Encoded Command
Detects PowerShell executions with encoded commands (`-enc` / `-EncodedCommand`).
- SPL: `alerts/01_alert_powershell_encoded.spl`
- Screenshot: `screenshots/alerts/alert1_overview.png`

### 2) PowerShell Suspicious Keywords
Detects PowerShell commands containing suspicious keywords commonly used for download/execute and basic malicious activity.
- SPL:
