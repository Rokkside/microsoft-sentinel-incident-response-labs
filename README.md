# Incident Response Labs with Microsoft Sentinel

## Project Overview

<img width="322" height="479" alt="Screenshot 2026-03-08 at 4 31 40 PM" src="https://github.com/user-attachments/assets/eea7f73c-324a-4883-82b0-43d5f6cdffe5" />

This repository documents hands-on **Incident Response (IR) labs** performed using **Microsoft Sentinel** and **Microsoft Defender for Endpoint (MDE)**.

The goal of this project is to simulate real-world SOC investigations and demonstrate the full incident response lifecycle following **NIST 800-61** methodology.

Each scenario includes:

• Detection logic  
• Investigation process  
• Incident triage  
• Evidence collection  
• Containment recommendations  
• Lessons learned  

---

## Technologies Used

- Microsoft Sentinel
- Microsoft Defender for Endpoint
- Azure Log Analytics
- Kusto Query Language (KQL)
- Windows Virtual Machines
- MITRE ATT&CK Framework

---

## Incident Response Methodology

These labs follow the **NIST 800-61 Incident Response Lifecycle**:

1. Preparation
2. Detection & Analysis
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

---

# Lab Scenarios

## Scenario 1 — VM Brute Force Detection
Detect and investigate repeated authentication failures targeting a Windows VM.

**Skills Demonstrated**

- Alert triage
- Authentication log analysis
- Brute-force detection

---

## Scenario 2 — Suspicious PowerShell Web Request

Detect malicious PowerShell activity attempting to download external payloads using `Invoke-WebRequest`.

**Skills Demonstrated**

- PowerShell process analysis
- Suspicious command detection
- Investigation of outbound web activity

---

## Scenario 3 — Potential Impossible Travel

Identify suspicious authentication activity indicating a user account login from geographically impossible locations.

**Skills Demonstrated**

- Identity investigation
- Sign-in log correlation
- Risk-based analysis

---

## Scenario 4 — Excessive Resource Creation and Deletion

Investigate suspicious activity involving abnormal Azure resource creation and deletion events.

**Skills Demonstrated**

- Azure activity log analysis
- Cloud infrastructure monitoring
- Suspicious automation detection

---

# Repository Structure



Each scenario contains:

• Investigation notes  
• Detection queries  
• Incident summary  
• Screenshots of Sentinel investigation  

---

# Author

Cybersecurity Lab Portfolio  
Focused on:

- Threat Hunting
- Incident Response
- Detection Engineering
- Cloud Security
