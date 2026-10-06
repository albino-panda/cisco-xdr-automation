# Testing

Workflows here change production systems, so testing focuses on proving the guardrails and the dry-run path before any live action.

## Levels

| Level | What it proves | How |
|---|---|---|
| Spec lint | YAML is valid and every reference resolves | `yamllint` plus a cross-reference check of workflows, atomics and integrations |
| Atomic contract | Each atomic returns its declared outputs | Mocked HTTP responses (for example `respx` in Python) for success, empty and error cases |
| Guardrails | Protected targets are skipped, caps stop runs | Feed protected hosts, users and allow-listed indicators; expect `skipped_*` statuses |
| Workflow dry-run | The plan is right for realistic incidents | Run in XDR with `dry_run = true` against test incidents built from sample observables |
| Tabletop | Analysts can follow and override the flow | Walk through the README with the SOC before enabling containment |

## Test data

- Use documentation ranges for IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.com` domains.
- Use a dedicated test endpoint group and test user accounts for any live containment check.
- The mail-bomb detector's synthetic replay data can drive the mail-bombing workflow end to end.

## Live checks

- Run live containment only against test assets, with an approver present, and record the rollback.
- Verify rollback for every reversible atomic: isolation stop, account re-enable, list removal, message restore.
- This repository contains response automation only. Adversary emulation for detection testing belongs in your red team's approved tooling and lab, not here.

## Before enabling containment

- [ ] Dry-run plans reviewed for at least two weeks with no unsafe proposals.
- [ ] Guardrails file reviewed by the SOC lead and the asset owners.
- [ ] Rollback tested for each containment atomic the workflow uses.
- [ ] Approval routing and notification channel confirmed.
