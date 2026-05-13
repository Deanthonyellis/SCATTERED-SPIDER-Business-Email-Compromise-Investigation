[README.md](https://github.com/user-attachments/files/27678967/README.md)
# SCATTERED-SPIDER-Business-Email-Compromise-Investigation
🕷️ SCATTERED SPIDER — Business Email Compromise Investigation  
# 🔍 Threat Hunting Portfolio — Microsoft Sentinel

A collection of threat hunts, KQL queries, and detection playbooks built in Microsoft Sentinel. This repository documents my hands-on threat hunting work and methodology, aligned with the MITRE ATT&CK framework.

---

## 👤 About

Cybersecurity professional with 1–2 years of experience specializing in threat hunting and detection engineering using Microsoft Sentinel. Passionate about proactively identifying adversary behavior before alerts fire.

📫 **Contact:** [your-email@email.com]  
🔗 **LinkedIn:** [linkedin.com/in/yourprofile]  
📍 **Location:** [Your City, State]

---

## 📁 Repository Structure

```
threat-hunting-portfolio/
│
├── hunts/                        # Completed threat hunts
│   ├── lateral-movement/
│   ├── persistence/
│   ├── credential-access/
│   └── exfiltration/
│
├── kql-queries/                  # Reusable KQL query library
│   ├── detection/
│   ├── investigation/
│   └── enrichment/
│
├── playbooks/                    # Hunt playbooks and methodology docs
│
├── iocs/                         # Indicators of Compromise (sample/sanitized)
│
├── templates/                    # Reusable templates
│   ├── hunt-hypothesis-template.md
│   └── findings-report-template.md
│
└── README.md
```

---

## 🧪 Hunts

| Hunt | MITRE Tactic | MITRE Technique | Status |
|------|-------------|-----------------|--------|
| [Suspicious PowerShell Encoded Commands](./hunts/persistence/suspicious-powershell.md) | Execution | T1059.001 | ✅ Complete |
| [Lateral Movement via SMB](./hunts/lateral-movement/smb-lateral-movement.md) | Lateral Movement | T1021.002 | ✅ Complete |
| [LSASS Memory Dumping](./hunts/credential-access/lsass-dump.md) | Credential Access | T1003.001 | 🔄 In Progress |

---

## 🔎 Sample KQL Query

```kql
// Detect encoded PowerShell commands — T1059.001
SecurityEvent
| where EventID == 4688
| where CommandLine contains "-EncodedCommand" or CommandLine contains "-enc"
| extend DecodedCommand = base64_decode_tostring(extract(@"-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]\s+([A-Za-z0-9+/=]+)", 1, CommandLine))
| project TimeGenerated, Computer, Account, CommandLine, DecodedCommand
| order by TimeGenerated desc
```

---

## 🛠️ Tools & Skills

- **SIEM:** Microsoft Sentinel
- **Query Language:** KQL (Kusto Query Language)
- **Framework:** MITRE ATT&CK
- **Log Sources:** Windows Security Events, Sysmon, Azure AD, DNS, Network logs
- **Other:** OSINT, IOC analysis, incident triage

---

## 📋 Hunt Methodology

Each hunt in this repo follows a structured process:

1. **Hypothesis** — Define what adversary behavior we're looking for and why
2. **Data Sources** — Identify the relevant log sources in Sentinel
3. **KQL Query** — Build and tune the detection query
4. **Analysis** — Review results, remove false positives
5. **Findings** — Document what was found (or confirmed absence of activity)
6. **Recommendations** — Suggest detections or controls based on findings

---

## 📄 Templates

- [Hunt Hypothesis Template](./templates/hunt-hypothesis-template.md)
- [Findings Report Template](./templates/findings-report-template.md)

---

## ⚠️ Disclaimer

All hunts and IOCs in this repository are based on lab environments, publicly available threat intelligence, or sanitized/anonymized data. No real production data or sensitive information is included.

---

*Built with curiosity, coffee, and KQL.*
