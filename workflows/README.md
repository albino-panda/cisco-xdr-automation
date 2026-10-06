# Workflows

One directory per incident type. Each holds a `README.md` for analysts and a `workflow.yaml` specification to build from. Exported XDR workflow JSON goes next to them as `workflow.export.json`.

| Workflow | Severity | ATT&CK | Containment |
|---|---|---|---|
| [`ransomware`](./ransomware/README.md) | critical | T1486, T1490, T1489 | `isolate-endpoint`, `block-hash`, `revoke-session`, `disable-user` |
| [`phishing`](./phishing/README.md) | medium | T1566.001, T1566.002, T1204 | `quarantine-email`, `block-url`, `block-domain`, `block-hash` |
| [`mail-bombing`](./mail-bombing/README.md) | high | T1499, T1656 | `quarantine-email`, `revoke-session` |
| [`bec`](./bec/README.md) | high | T1534, T1114.003, T1656 | `revoke-session`, `disable-user`, `quarantine-email`, `block-domain` |
| [`account-takeover`](./account-takeover/README.md) | high | T1078.004, T1621, T1539 | `revoke-session`, `disable-user`, `block-ip` |
| [`malware`](./malware/README.md) | medium | T1204.002, T1105 | `block-hash`, `isolate-endpoint`, `block-domain` |
| [`powershell`](./powershell/README.md) | medium | T1059.001, T1027 | `block-domain`, `isolate-endpoint` |
| [`lateral-movement`](./lateral-movement/README.md) | high | T1021.001, T1021.002, T1021.006, T1570 | `isolate-endpoint`, `revoke-session`, `disable-user` |
| [`c2`](./c2/README.md) | high | T1071.001, T1573, T1568.002 | `block-domain`, `block-ip`, `isolate-endpoint` |
| [`dns-tunneling`](./dns-tunneling/README.md) | high | T1071.004, T1572 | `block-domain`, `isolate-endpoint` |
| [`password-spray`](./password-spray/README.md) | medium | T1110.003 | `block-ip`, `revoke-session`, `disable-user` |
| [`credential-dumping`](./credential-dumping/README.md) | critical | T1003.001, T1003.002, T1003.003 | `isolate-endpoint`, `revoke-session`, `disable-user` |
| [`privilege-escalation`](./privilege-escalation/README.md) | high | T1068, T1548.002, T1098 | `isolate-endpoint`, `revoke-session`, `disable-user` |
| [`persistence`](./persistence/README.md) | medium | T1547.001, T1053.005, T1543.003, T1136 | `block-hash`, `isolate-endpoint` |
| [`rmm`](./rmm/README.md) | high | T1219 | `block-domain`, `block-hash`, `isolate-endpoint` |
| [`exfiltration`](./exfiltration/README.md) | critical | T1041, T1567.002, T1048 | `block-domain`, `block-ip`, `isolate-endpoint`, `disable-user` |
| [`vulnerability-exploitation`](./vulnerability-exploitation/README.md) | high | T1190, T1203 | `block-ip`, `block-url`, `isolate-endpoint` |
| [`cloud-compromise`](./cloud-compromise/README.md) | high | T1078.004, T1098.001, T1528, T1530 | `revoke-session`, `disable-user`, `block-ip` |
| [`web-attacks`](./web-attacks/README.md) | medium | T1190, T1595.002, T1505.003 | `block-ip`, `block-url`, `isolate-endpoint` |

## Common shape

Every workflow follows the same phases: intake, enrich, investigate, decide, contain, record, notify. Containment always passes through the guardrails and, unless configured otherwise, an approval task.
