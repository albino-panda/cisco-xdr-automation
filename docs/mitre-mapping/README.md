# MITRE ATT&CK mapping

Which workflow handles each technique. Built from the `mitre_attack` field of every `workflow.yaml`; the same data is in [`mitre-mapping.yaml`](mitre-mapping.yaml) for import into coverage tools such as ATT&CK Navigator.

| Technique | Name | Workflows |
|---|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | [`credential-dumping`](../../workflows/credential-dumping/README.md) |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | [`credential-dumping`](../../workflows/credential-dumping/README.md) |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | [`credential-dumping`](../../workflows/credential-dumping/README.md) |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | [`lateral-movement`](../../workflows/lateral-movement/README.md) |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | [`lateral-movement`](../../workflows/lateral-movement/README.md) |
| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management | [`lateral-movement`](../../workflows/lateral-movement/README.md) |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | [`powershell`](../../workflows/powershell/README.md) |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | [`exfiltration`](../../workflows/exfiltration/README.md) |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | [`exfiltration`](../../workflows/exfiltration/README.md) |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | [`persistence`](../../workflows/persistence/README.md) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | [`powershell`](../../workflows/powershell/README.md) |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | [`privilege-escalation`](../../workflows/privilege-escalation/README.md) |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | [`c2`](../../workflows/c2/README.md) |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | [`dns-tunneling`](../../workflows/dns-tunneling/README.md) |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | [`account-takeover`](../../workflows/account-takeover/README.md), [`cloud-compromise`](../../workflows/cloud-compromise/README.md) |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | [`privilege-escalation`](../../workflows/privilege-escalation/README.md) |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | [`cloud-compromise`](../../workflows/cloud-compromise/README.md) |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | [`malware`](../../workflows/malware/README.md) |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying | [`password-spray`](../../workflows/password-spray/README.md) |
| [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Email Forwarding Rule | [`bec`](../../workflows/bec/README.md) |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | [`persistence`](../../workflows/persistence/README.md) |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md), [`web-attacks`](../../workflows/web-attacks/README.md) |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | [`vulnerability-exploitation`](../../workflows/vulnerability-exploitation/README.md) |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | [`phishing`](../../workflows/phishing/README.md) |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | [`malware`](../../workflows/malware/README.md) |
| [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Tools | [`rmm`](../../workflows/rmm/README.md) |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | [`ransomware`](../../workflows/ransomware/README.md) |
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop | [`ransomware`](../../workflows/ransomware/README.md) |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | [`ransomware`](../../workflows/ransomware/README.md) |
| [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | [`mail-bombing`](../../workflows/mail-bombing/README.md) |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | [`web-attacks`](../../workflows/web-attacks/README.md) |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | [`cloud-compromise`](../../workflows/cloud-compromise/README.md) |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | [`cloud-compromise`](../../workflows/cloud-compromise/README.md) |
| [T1534](https://attack.mitre.org/techniques/T1534/) | Internal Spearphishing | [`bec`](../../workflows/bec/README.md) |
| [T1539](https://attack.mitre.org/techniques/T1539/) | Steal Web Session Cookie | [`account-takeover`](../../workflows/account-takeover/README.md) |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | [`persistence`](../../workflows/persistence/README.md) |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | [`persistence`](../../workflows/persistence/README.md) |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | [`privilege-escalation`](../../workflows/privilege-escalation/README.md) |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | [`phishing`](../../workflows/phishing/README.md) |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | [`phishing`](../../workflows/phishing/README.md) |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | [`exfiltration`](../../workflows/exfiltration/README.md) |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Domain Generation Algorithms | [`c2`](../../workflows/c2/README.md) |
| [T1570](https://attack.mitre.org/techniques/T1570/) | Lateral Tool Transfer | [`lateral-movement`](../../workflows/lateral-movement/README.md) |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | [`dns-tunneling`](../../workflows/dns-tunneling/README.md) |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | [`c2`](../../workflows/c2/README.md) |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning | [`web-attacks`](../../workflows/web-attacks/README.md) |
| [T1621](https://attack.mitre.org/techniques/T1621/) | Multi-Factor Authentication Request Generation | [`account-takeover`](../../workflows/account-takeover/README.md) |
| [T1656](https://attack.mitre.org/techniques/T1656/) | Impersonation | [`mail-bombing`](../../workflows/mail-bombing/README.md), [`bec`](../../workflows/bec/README.md) |

## Notes

- Mail bombing has no dedicated ATT&CK technique. It is mapped by effect (T1499) and by the impersonation that usually follows (T1656).
- T1219 was renamed *Remote Access Tools* in ATT&CK v17; the ID is unchanged.
- Keep technique IDs in the workflow specs as the single source of truth and update this page and `mitre-mapping.yaml` whenever they change.
