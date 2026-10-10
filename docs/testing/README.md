# Testing

> **Start here: [docs/testing.md](../testing.md).** It covers the `xdr_response` test layers, how to run them, the safety tests and what they prove, and the simulator. This page keeps the workflow-level checks and the live tests in Cisco XDR.

Workflows here change production systems, so testing focuses on proving the guardrails and the dry-run path before any live action.

## Levels (workflows)

| Level | What it proves | How |
|---|---|---|
| Repository lint | YAML is valid, every link and reference resolves, generated docs are current | `tests/test_repo.py`, `python tools/validation/check_workflow_readmes.py`, `python tools/validation/generate_workflow_docs.py --check` |
| Atomic contract | Each atomic returns its declared records | Mocked HTTP responses with `httpx.MockTransport` for success, empty and error cases |
| Guardrails | Critical assets come out ELEVATED with a warning, allow-listed targets are excluded visibly, caps elevate | Workflow scenarios with critical hosts, users and allow-listed indicators; never a silent skip |
| Workflow scenarios | Every scenario passes in dry run and simulated live | `python tools/simulator/simulate.py --all-workflows --check` and `... --all-workflows --live --check` |
| Framework dry run | The containment package is right and nothing changes | `python tools/simulator/simulate.py <scenario>`; see [docs/testing.md](../testing.md) section 5 |
| Workflow dry run | The recommendation is right for realistic incidents | Run the orchestrator with `DRY_RUN=true` against test incidents built from sample observables; compare with the [sample analyst output](../samples/README.md) |
| Tabletop | Analysts can follow and override the flow | Walk through the workflow README with the SOC before enabling containment |

## Test data

- Use documentation ranges for IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.com`, `*.example` or `*.test` domains.
- Use fake 64-hex hashes and hosts like `TH-LT-1047`.
- Use a dedicated test endpoint group and test user accounts for any live containment check.
- The mail-bomb detector's synthetic replay data can drive the mail-bombing workflow end to end.

## Live checks

- Run live containment only against test assets, with an approver present. Every live action needs a human approval through `xdr_response`.
- Verify rollback for every reversible action: isolation stop, account re-enable, list removal, message release. Each release needs its own release approval.
- Verify the audit trail after each live check: `python tools/validation/verify_audit_chain.py var/audit/audit.jsonl`.
- This repository contains response automation only. Adversary emulation for detection testing belongs in your red team's approved tooling and lab, not here.

## Before enabling containment

- [ ] Dry-run recommendations reviewed for at least two weeks with no unsafe proposals.
- [ ] Critical-asset, allow-list and exclusion files reviewed by the SOC lead and the asset owners.
- [ ] Rollback tested for each containment action the workflow uses.
- [ ] Approval routing and notification channel confirmed.
- [ ] The full test suite passes, including `tests/safety/` ([docs/testing.md](../testing.md) section 7).
