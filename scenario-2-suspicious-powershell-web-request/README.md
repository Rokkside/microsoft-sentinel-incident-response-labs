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

---

# Lab Architecture
<img width="330" height="395" alt="Screenshot 2026-03-08 at 5 01 43 PM" src="https://github.com/user-attachments/assets/196cdaef-8230-48f2-9c97-9b25862d2e51" />
# Detection Logic

The detection focuses on identifying PowerShell commands attempting to download external resources from the internet using common download utilities such as:

- `Invoke-WebRequest`
- `wget`
- `curl`
- `DownloadString`

These commands are often used by attackers to retrieve malicious scripts or binaries.

---

# Detection Query (KQL)

 <img width="1417" height="456" alt="Screenshot 2026-03-08 at 5 09 43 PM" src="https://github.com/user-attachments/assets/67959155-77a5-44f7-b37f-f19aff2b1ff7" />

This query searches for PowerShell processes executing commands containing Invoke-WebRequest.

## Investigation Steps

1. Incident Detection

Microsoft Sentinel analytics rule triggered an alert based on suspicious PowerShell activity.

Indicators included:

  - PowerShell execution

  - External web request

  - Command-line download attempt

2. Process Investigation

Using Microsoft Defender for Endpoint telemetry, the following was analyzed:

  - Process execution details

  - Command line arguments

  - Initiating parent process

  - Associated user account

Key telemetry source:
DeviceProcessEvents

