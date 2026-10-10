# Workflows

One directory per incident type. Each holds a `README.md` for analysts. Every workflow is migrated (Phases 2 to 5): no legacy `workflow.yaml` specification or `scenarios/` remains. Exported XDR workflow JSON goes next to the README as `workflow.export.json`.

## Migrated workflows (Phases 2 to 5)

These run on the workflow framework (`src/xdr_response/workflows/<x_snake>/`); their scenarios are in `tests/fixtures/workflows/<id>/`. ATT&CK ids, recommended actions, integrations and scenario counts are in the generated index [`docs/workflows/README.md`](../docs/workflows/README.md).

A hand-off is a suggestion in the run notes, the workflow summary and the analyst notification: "run account-takeover for jsmith@example.com", with the record ids that justify it. It never starts the other workflow and never changes the package. When triggers overlap, the entry-vector workflow (phishing, password-spray, mfa-fatigue, mail-bombing, bec, suspicious-authentication) handles the incident and hands the account off to account-takeover (architecture 14.10.2, 14.12.2). In general a workflow outranks every workflow it hands off to, so the hand-off is still suggested when both match (14.11.2). The subjects of a hand-off are the entity the target workflow starts from: an account for `account-takeover`, an endpoint hostname for `persistence`, `unauthorized-rmm`, `credential-dumping` and `c2`, a file hash for `malware`, a mailbox for `phishing` (14.11.2, 14.13.2).

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
| [`c2`](./c2/README.md) | 4 | `malware` (a flagged beaconing process: scope its file across the estate, quarantine it and block its hash) |
| [`dns-tunneling`](./dns-tunneling/README.md) | 4 | - |
| [`exfiltration`](./exfiltration/README.md) | 4 | `account-takeover` (an account that drives the transfer is compromised) |
| [`suspicious-authentication`](./suspicious-authentication/README.md) | 4 | `account-takeover` (a suspicious sign-in concluded as a likely compromise) |
| [`cloud-compromise`](./cloud-compromise/README.md) | 4 | `account-takeover` (a compromised cloud account: review mailbox rules, sign-ins and endpoints beyond the cloud activity) |
| [`privilege-escalation`](./privilege-escalation/README.md) | 5 | `account-takeover` (a compromised account behind the escalation: review its sign-ins, mailbox rules and activity beyond the privilege changes) |
| [`threat-intel-sweep`](./threat-intel-sweep/README.md) | 5 | `malware` (a rated file indicator present on endpoints), `c2` (an endpoint that contacted a rated domain or IP), `phishing` (a mailbox that received a message carrying a rated indicator), `account-takeover` (an account that signed in from a rated IP) |
| [`vulnerability-exploitation`](./vulnerability-exploitation/README.md) | 5 | `persistence` (persistence on a host after a successful exploit), `malware` (a payload hash the exploit dropped; never a hash rated CLEAN) |
| [`web-attacks`](./web-attacks/README.md) | 5 | `malware` (the hash of a confirmed web shell) |

## Common shape

Every workflow follows the same phases: intake, enrich, investigate, decide, contain, record, notify. Workflows only investigate and recommend. Every containment action needs a human approval; protected (critical) assets and actions over a blast-radius cap need ELEVATED approval with a visible warning and are never dropped silently. After approval, the `xdr_response` lifecycle executes the approved actions and verifies them automatically; restoration needs a separate human release approval.

## Migration

Phases 2 to 5 migrated every workflow to `src/xdr_response/workflows/<x_snake>/`, with simulation scenarios in `tests/fixtures/workflows/<id>/`; each migration deleted the workflow's legacy `workflow.yaml` and `scenarios/` in the same change and kept its legacy scenarios as `legacy-*` fixtures (see [architecture section 14.5](../docs/architecture.md)). The legacy plan engine, its bridge and the legacy replay were retired after Phase 5 (architecture 14.4.3); the old atomic names map to the catalog in [`atomic/README.md`](../atomic/README.md). The generated index of all workflows is [`docs/workflows/README.md`](../docs/workflows/README.md).
