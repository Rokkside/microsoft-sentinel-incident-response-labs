# Scenario 2 — Suspicious PowerShell Web Request

## Objective

The objective of this lab is to detect and investigate suspicious PowerShell activity where a system attempts to download external content using `Invoke-WebRequest`.

This type of behavior is commonly associated with malware staging, payload delivery, or attacker command execution.

The investigation demonstrates how Microsoft Sentinel and Microsoft Defender for Endpoint telemetry can be used to identify suspicious PowerShell execution and perform incident triage.

---

# Lab Environment

| Component | Description |
|--------|-------------|
| SIEM | Microsoft Sentinel |
| Endpoint Telemetry | Microsoft Defender for Endpoint |
| Log Source | DeviceProcessEvents |
| VM | Windows Virtual Machine |
| Query Language | Kusto Query Language (KQL) |

# Lab Architecture

Attacker
   │
   ▼
Internet
   │
   ▼
Azure VM
   │
   ▼
Microsoft Defender for Endpoint
   │
   ▼
Sentinel Analytics Rule
   │
   ▼
Incident Created
   │
   ▼
SOC Investigation
---

# Detection Logic

The detection focuses on identifying PowerShell commands attempting to download external resources from the internet using common download utilities such as:

- `Invoke-WebRequest`
- `wget`
- `curl`
- `DownloadString`

These commands are often used by attackers to retrieve malicious scripts or binaries.

---

# Detection Query (KQL)

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc



This query searches for PowerShell processes executing commands containing Invoke-WebRequest.

Investigation Steps
1. Incident Detection

Microsoft Sentinel analytics rule triggered an alert based on suspicious PowerShell activity.

Indicators included:

PowerShell execution

External web request

Command-line download attempt

2. Process Investigation

Using Microsoft Defender for Endpoint telemetry, the following was analyzed:

Process execution details

Command line arguments

Initiating parent process

Associated user account

Key telemetry source:
DeviceProcessEvents
