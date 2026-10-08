# Workflows

One directory per incident type. Each holds a `README.md` for analysts. A workflow not yet migrated also holds its legacy `workflow.yaml` specification and `scenarios/`. Exported XDR workflow JSON goes next to them as `workflow.export.json`.

## Migrated workflows (Phases 2 and 3)

These run on the workflow framework (`src/xdr_response/workflows/<x_snake>/`); their scenarios are in `tests/fixtures/workflows/<id>/`. ATT&CK ids, recommended actions, integrations and scenario counts are in the generated index [`docs/workflows/README.md`](../docs/workflows/README.md).

A hand-off is a suggestion in the run notes, the workflow summary and the analyst notification: "run account-takeover for jsmith@example.com", with the record ids that justify it. It never starts the other workflow and never changes the package. When triggers overlap, the entry-vector workflow (phishing, password-spray, mfa-fatigue, mail-bombing, bec) handles the incident and hands the account off to account-takeover (architecture 14.10.2). The subjects of a hand-off are the entity the target workflow starts from: an account for `account-takeover`, an endpoint hostname for `persistence`, `unauthorized-rmm` and `credential-dumping`, a file hash for `malware`, a mailbox for `phishing` (14.11.2).

| Workflow | Phase | Hands off to (`handoff_to`; when its evidence points there) |
|---|---|---|
| [`ransomware`](./ransomware/README.md) | 2 | - |
| [`phishing`](./phishing/README.md) | 2 | `account-takeover` (a recipient signed in or was flagged after clicking) |
| [`account-takeover`](./account-takeover/README.md) | 2 | - |
| [`mail-bombing`](./mail-bombing/README.md) | 2 | `account-takeover` (takeover indications after the flood), `unauthorized-rmm` (malicious activity on the recipient's endpoint after the flood), `phishing` (a storm of malicious mail that is not a subscription bomb) |
| [`malware`](./malware/README.md) | 2 | - |
| [`mfa-fatigue`](./mfa-fatigue/README.md) | 2 | `account-takeover` (a fatigue prompt was approved) |
| [`password-spray`](./password-spray/README.md) | 2 | `account-takeover` (a sprayed account signed in successfully) |
| [`bec`](./bec/README.md) | 2 | `account-takeover` (identity compromise behind the mailbox abuse) |
| [`malicious-powershell`](./malicious-powershell/README.md) | 3 | `malware` (a malicious payload the run wrote or started: scope and quarantine the file), `persistence` (a malicious or suspicious persistence item on an endpoint of a malicious run) |
| [`credential-dumping`](./credential-dumping/README.md) | 3 | `account-takeover` (accounts exposed on a host with confirmed credential access: review sign-ins and cloud activity for use of the stolen credentials) |
| [`lateral-movement`](./lateral-movement/README.md) | 3 | `account-takeover` (an account used for or tied to the movement is compromised), `credential-dumping` (credential access reported on a host of the movement) |
| [`persistence`](./persistence/README.md) | 3 | - |
| [`unauthorized-rmm`](./unauthorized-rmm/README.md) | 3 | `persistence` (the tool persists as a service, task or run key), `account-takeover` (a user of an affected endpoint shows high or confirmed identity risk, or a high-severity anomaly) |

## Legacy specs (Phases 4 and 5)

| Workflow | Severity | ATT&CK | Containment |
|---|---|---|---|
| [`c2`](./c2/README.md) | high | T1071.001, T1573, T1568.002 | `block-domain`, `block-ip`, `isolate-endpoint` |
| [`dns-tunneling`](./dns-tunneling/README.md) | high | T1071.004, T1572 | `block-domain`, `isolate-endpoint` |
| [`privilege-escalation`](./privilege-escalation/README.md) | high | T1068, T1548.002, T1098 | `isolate-endpoint`, `revoke-session`, `disable-user` |
| [`exfiltration`](./exfiltration/README.md) | critical | T1041, T1567.002, T1048 | `block-domain`, `block-ip`, `isolate-endpoint`, `disable-user` |
| [`vulnerability-exploitation`](./vulnerability-exploitation/README.md) | high | T1190, T1203 | `block-ip`, `block-url`, `isolate-endpoint` |
| [`cloud-compromise`](./cloud-compromise/README.md) | high | T1078.004, T1098.001, T1528, T1530 | `revoke-session`, `disable-user`, `block-ip` |
| [`web-attacks`](./web-attacks/README.md) | medium | T1190, T1595.002, T1505.003 | `block-ip`, `block-url`, `isolate-endpoint` |

## Common shape

Every workflow follows the same phases: intake, enrich, investigate, decide, contain, record, notify. Workflows only investigate and recommend. Every containment action needs a human approval; protected (critical) assets and actions over a blast-radius cap need ELEVATED approval with a visible warning and are never dropped silently. After approval, the `xdr_response` lifecycle executes the approved actions and verifies them automatically; restoration needs a separate human release approval.

## Migration

The `workflow.yaml` and `scenarios/` here are legacy specs, checked by `PYTHONPATH=engine python -m xdr_plan check`. In Phases 2 to 5 each workflow migrates to `src/xdr_response/workflows/<x_snake>/` with simulation scenarios in `tests/fixtures/workflows/<id>/` and deletes its legacy spec in the same change (see [architecture section 14.5](../docs/architecture.md)). The generated index of all workflows, migrated or not, is [`docs/workflows/README.md`](../docs/workflows/README.md).
