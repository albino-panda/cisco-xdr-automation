# Testing

> **Start here: [docs/testing.md](../testing.md).** It covers the `xdr_response` test layers, how to run them, the safety tests and what they prove, and the simulator. This page keeps the checks for the workflow specs and for live tests in Cisco XDR.

Workflows here change production systems, so testing focuses on proving the guardrails and the dry-run path before any live action.

## Levels (workflow specs)

| Level | What it proves | How |
|---|---|---|
| Spec lint | YAML is valid and every reference resolves | `tests/test_repo.py` and `PYTHONPATH=engine python -m xdr_plan check` |
| Atomic contract | Each atomic returns its declared outputs | Mocked HTTP responses with `httpx.MockTransport` for success, empty and error cases |
| Guardrails | Protected targets are skipped, caps stop runs | Feed protected hosts, users and allow-listed indicators; expect `skipped_*` statuses |
| Framework dry run | The containment package is right and nothing changes | `python tools/simulator/simulate.py <scenario>`; see [docs/testing.md](../testing.md) section 5 |
| Workflow dry run | The plan is right for realistic incidents | Run in XDR with `dry_run = true` and the orchestrator with `DRY_RUN=true` against test incidents built from sample observables |
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

- [ ] Dry-run plans reviewed for at least two weeks with no unsafe proposals.
- [ ] Critical-asset, allow-list and exclusion files reviewed by the SOC lead and the asset owners.
- [ ] Rollback tested for each containment action the workflow uses.
- [ ] Approval routing and notification channel confirmed.
- [ ] The full test suite passes, including `tests/safety/` ([docs/testing.md](../testing.md) section 7).
