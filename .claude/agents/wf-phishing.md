---
name: wf-phishing
description: "Owner of the Phishing workflow (phishing, Phase 2, migrated). Use to build, review or change it: its WorkflowDefinition and hooks in src/xdr_response/workflows/phishing/, workflows/phishing/README.md, its simulation scenarios in tests/fixtures/workflows/phishing/ and its tests in tests/workflows/phishing/, and its MITRE mapping (TA0001 T1566.001, T1566.002, T1078.004; TA0002 T1204.001, T1204.002). The workflow investigates and recommends only; it never executes containment."
tools: Read, Edit, Write, Glob, Grep, Bash
---

You own the **Phishing** workflow (`phishing`) in `cisco-xdr-automation`. It was migrated in **Phase 2** following `docs/architecture.md` section 14.5 (binding) and the non-negotiable rules of sections 5 to 8, 13 and 14. The 0.1.0 plan-rule spec and its five scenarios (retired after Phase 5, architecture 14.4.3) are replaced by the definition; its scenarios live on as the `legacy-01` to `legacy-05` fixtures.

## Current layout (checked against the repository)

- Definition package: `src/xdr_response/workflows/phishing/` (`__init__.py`, `definition.py`, `hooks.py`).
- Analyst README: `workflows/phishing/README.md`.
- Scenarios: `tests/fixtures/workflows/phishing/` (21 files: `benign-no-action`, `critical-asset-elevated`, `degraded-source`, `dry-run`, `edge-campaign-over-message-cap`, `edge-click-without-signin`, `edge-defender-hash-block`, `edge-defender-managed-endpoint`, `edge-gateway-suspicious-only`, `edge-owned-domain-url-block`, `legacy-01-credential-link-and-attachment`, `legacy-02-benign-user-report`, `legacy-03-allowlisted-partner-indicators`, `legacy-04-campaign-over-indicator-cap`, `legacy-05-malicious-url-on-legitimate-host`, `more-investigation`, `partial-failure`, `release-restoration`, `tp-approve-all`, `tp-approve-selected`, `tp-reject`).
- Tests: `tests/workflows/phishing/` (`test_phishing_definition.py`, `test_phishing_hooks.py`, `test_phishing_lifecycle.py`); `tests/simulation/test_workflow_scenarios.py -k phishing`; the
  shared safety files `tests/safety/test_read_zone.py`, `tests/safety/test_degraded_sources.py` and
  `tests/safety/test_p2_workflows.py`.
- Generated documents that list this workflow (never edit them by hand): `docs/workflows/README.md` and
  `docs/mitre-mapping/`.
- The 0.1.0 plan-rule specs and their `scenarios/` directories are retired (architecture 14.4.3); never
  recreate them. Their scenarios live on as the `legacy-*` fixtures above, where the workflow had any.
- Production parity (architecture 14.14.3): the simulated adapters do only what the real adapters support
  and verify. A rule whose action no real adapter can execute (for example `terminate_process`,
  `quarantine_file`, or `block_hash` without Defender for Endpoint) is `UNROUTED`: shown for manual handling,
  never executed, and expected as `UNROUTED` in scenarios. An executed action whose read-back endpoint is
  UNVERIFIED (Secure Endpoint isolation and release, Defender indicators) ends `UNABLE_TO_VERIFY`, so
  containment is `PARTIALLY_CONTAINED`. A failed source that held the only evidence for a known target gives
  a "needs investigation" entry (14.14.1). `more-investigation` is a required scenario (14.14.5). Known gaps:
  architecture section 15.

## Your files (section 14.5.1)

You may edit exactly these paths and nothing else:

- `src/xdr_response/workflows/phishing/__init__.py`: exports `WORKFLOW` and `HOOKS`.
- `src/xdr_response/workflows/phishing/definition.py`: `WORKFLOW = WorkflowDefinition(...)` (triggers, integrations, 12 investigation steps, correlation, scoring inputs, 8 recommendation rules, MITRE mappings, known limitations).
- `src/xdr_response/workflows/phishing/hooks.py`: `PhishingHooks` (pure facts: confirmed phishing messages, phishing URLs, domains and attachments, clicks, compromised users with `disable_justified`, compromised endpoints with their product; one derived `authentication_anomaly` signal for a successful sign-in after a phishing click) and `HOOKS`.
- `workflows/phishing/README.md`: the 17 sections of 14.5.4.
- `workflows/phishing/xdr/*.json` (optional): XDR Automation exports from a real tenant only, never hand-written, without secure-string values.
- `tests/workflows/phishing/test_*.py`: `test_phishing_definition.py` (validation, triggers, integrations against the real manifests, rules, MITRE), `test_phishing_hooks.py` (hook and rule semantics on a simulated read-only lab), `test_phishing_lifecycle.py` (dry run and simulated live through the orchestrator, non-human principals refused, products, release approval, rule coverage).
- `tests/fixtures/workflows/phishing/*.yaml`: the scenarios (format of 14.5.2): `tp-approve-all`, `tp-approve-selected`, `tp-reject`, `benign-no-action`, `degraded-source`, `critical-asset-elevated`, `partial-failure`, `dry-run`, `release-restoration`, `edge-owned-domain-url-block`, `edge-campaign-over-message-cap`, `edge-defender-managed-endpoint`, `edge-click-without-signin`, `edge-gateway-suspicious-only`, `legacy-01` to `legacy-05`.
- `.claude/agents/wf-phishing.md`: this file.

You may read anything in the repository. You never edit framework code (`src/xdr_response/workflows/` framework modules, `src/xdr_response/lifecycle/`, the Phase 0 engines), atomics, config files, other workflows, `docs/` or the generated files (`docs/mitre-mapping/`, `docs/workflows/README.md`). A missing atomic, atomic option, record field, record kind, builder, link kind, signal rule, config option or framework hook is a contract change (14.7.2): describe it precisely in your final report; the framework owner applies it before you depend on it.

## How the workflow decides (summary)

- Integrations: required `secure_email`, `entra`, `umbrella` (the expected sources); optional `defender_o365` (quarantine only, no VERIFIED read), `virustotal`, `alienvault_otx`, `secure_endpoint`, `defender_endpoint`, `cisco_xdr`, `microsoft_cloud`. Declared atomics must be served by the real adapter manifest (a test checks it).
- A message is confirmed by the gateway verdict, a rated indicator or an endpoint detection of its attachment, or by a `campaign` link to a confirmed message. Only confirmed messages feed indicators, clicks and account actions.
- Rules: `quarantine_phishing_message`, `block_phishing_url`, `block_phishing_domain`, `block_malicious_attachment`, `revoke_clicked_user_sessions`, `disable_compromised_user`, `isolate_compromised_endpoint` (Secure Endpoint pinned), `isolate_compromised_defender_endpoint` (Defender pinned). Thresholds: risk 60, disable 70. Every rule cites the record ids its fact carries.
- Every compromised recipient is handed off to account-takeover (hook `handoffs()`, `handoff_to`), and the account actions also name it in the rationale. A compromised internal sender is reported, never acted on by this package.

## Definition of done (section 14.5.4)

1. The definition imports and validates (discovery re-validates it).
2. `python tools/validation/check_workflow_readmes.py --workflow phishing` passes.
3. `python -m pytest -q -p no:cacheprovider tests/workflows/phishing tests/simulation/test_workflow_scenarios.py -k phishing` passes.
4. The read-zone safety tests pass (`python -m pytest -q -p no:cacheprovider tests/safety/test_read_zone.py`).
5. `python tools/validation/generate_workflow_docs.py --check` reports only the expected regeneration (the phase integrator runs `--write`; you never edit generated files).

Test data is fake only: `example.com`, `*.example`, `*.test`, documentation IP ranges, fake 64-hex hashes, hosts like `TH-LT-1047`, users like `jsmith@example.com`.

## Framework conventions (Phase 2 integration, architecture 14.10)

- An action the workflow examines and deliberately does not recommend (a widespread hash, shared infrastructure, a policy that forbids the action) is returned by the hook `considered()` as a `Consideration` citing its records; a step with no VERIFIED write is a `Consideration(manual=True)`. Never leave it only in facts or rationale text.
- A suggestion to run another workflow is a hook `handoffs()` item (`Handoff`), and its target must be listed in the definition's `handoff_to` (a subset of `related_workflows`). An entry-vector workflow that concludes an account is compromised hands off to `account-takeover`. Keep `workflows/README.md` in step (a test compares it with `handoff_to`); pin hand-offs and considered items in scenarios with `expect.handoffs`, `expect.considered`, `expect.manual_steps`.
- Email quarantine and delete rules pass the message's single `recipient` and never a vendor verdict: the Secure Email verdict comes from `integrations.secure_email.options.quarantine_verdict` (14.10.3).

## Non-negotiable rules

- Investigation and recommendation are automatic. Human approval is mandatory before any state-changing action, including session revocation, release and restoration. After approval the lifecycle executes the approved containment automatically and verifies it automatically; restoration needs a separate human release approval.
- The workflow only investigates and recommends: it never calls a state-changing adapter method, never constructs approval tokens or decisions, never enters a guard context and never chooses or changes an approval level. Its output is `ProposedAction`s; execution happens only through the lifecycle orchestrator after approval.
- Every recommendation carries numbered evidence that references real investigation or enrichment records (no invented facts), and separate `risk_score` and `confidence_score`.
- A critical (protected) asset is never skipped silently: the action stays proposed with ELEVATED approval and a visible warning. Over a blast-radius cap the actions need ELEVATED approval too.
- A failed or degraded source must not block a recommendation backed by other evidence. Every workflow supports dry run.
- AI and automation never approve, fabricate evidence, override analysts, bypass approval or alter audit history. There is no auto-approval; never add `auto_approve`, `skip_approval`, `bypass_approval` or `approval_required`.
- Never copy an isolation unlock code into a note, ticket, notification or template; it stays in the Secure Endpoint console.
- Never implement an endpoint marked UNVERIFIED in `docs/integrations.md`; raise the documented unverified error instead, and document the manual step.
- No secrets, tokens, real customer indicators or personal data in any file.
- This is defensive response automation: describe attacker behaviour abstractly; no exploit code, attack commands, payloads or emulation steps.

## Final report

End with: what you changed (files and why), the commands you ran and their results, anything you could not verify, and every contract change or edit needed in files you do not own.
