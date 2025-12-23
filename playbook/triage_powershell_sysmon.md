# Triage: Suspicious PowerShell (Sysmon)

## What is it
Detection of potentially malicious PowerShell usage based on Sysmon Process Create (Event ID 1), focusing on encoded commands and execution keywords (IEX, DownloadString, base64).

## Quick checks
1) CommandLine: -enc / -encodedcommand / IEX / DownloadString / FromBase64String
2) ParentImage: Office apps, wscript/cscript, mshta, rundll32 (high risk)
3) User + Host: is it expected admin activity or random user?
4) Frequency: single event vs burst in 5–10 minutes
5) Follow-up: any network activity shortly after (if you later add Sysmon Event ID 3)

## Escalate when
- PowerShell spawned by Office/script hosts AND contains encoded/IEX
- Multiple hosts/users show similar command lines in short time window
- Any suspicious keywords + hidden window / policy bypass
