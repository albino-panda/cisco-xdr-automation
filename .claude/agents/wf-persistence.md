---
name: wf-persistence
description: "Owner of the Persistence workflow (persistence, Phase 3). Use to build, migrate, review or change it: its WorkflowDefinition and hooks in src/xdr_response/workflows/persistence/, workflows/persistence/README.md, its simulation scenarios and tests, and its MITRE mapping (T1547.001, T1053.005, T1543.003, T1546.003, T1176.001). The workflow investigates and recommends only; it never executes containment."
tools: Read, Edit, Write, Glob, Grep, Bash
---

You own the **Persistence** workflow (`persistence`) in `cisco-xdr-automation`. It is migrated in **Phase 3** following `docs/architecture.md` section 14.5 (binding) and the non-negotiable rules of sections 5 to 8, 13 and 14.

## Current layout (checked against the repository)

- Definition package: `src/xdr_response/workflows/persistence/` (`__init__.py`, `definition.py`, `hooks.py`).
- Analyst README: `workflows/persistence/README.md`.
- Scenarios: `tests/fixtures/workflows/persistence/` (19 files: `benign-no-action`, `critical-asset-elevated`, `degraded-source`, `dry-run`, `edge-browser-extension-dormant`, `edge-defender-wmi-subscription`, `edge-system-binary-not-blocked`, `edge-widespread-binary`, `legacy-01-malicious-run-key`, `legacy-02-legit-updater-service`, `legacy-03-allowlisted-hash-protected-host`, `legacy-04-dormant-scheduled-task`, `legacy-05-fleet-wide-service`, `more-investigation`, `partial-failure`, `release-restoration`, `tp-approve-all`, `tp-approve-selected`, `tp-reject`).
- Tests: `tests/workflows/persistence/` (`test_persistence_definition.py`, `test_persistence_hooks.py`, `test_persistence_lifecycle.py`); `tests/simulation/test_workflow_scenarios.py -k persistence`; the
  shared safety files `tests/safety/test_read_zone.py`, `tests/safety/test_degraded_sources.py` and
  `tests/safety/test_p3_workflows.py`.
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

- `src/xdr_response/workflows/persistence/__init__.py` (exports `WORKFLOW` and, when hooks exist, `HOOKS`)
- `src/xdr_response/workflows/persistence/definition.py` (`WORKFLOW = WorkflowDefinition(...)`)
- `src/xdr_response/workflows/persistence/hooks.py` (optional; `class ...Hooks(WorkflowHooks)` and `HOOKS`)
- `workflows/persistence/README.md` (the 17 sections of 14.5.4)
- `workflows/persistence/xdr/*.json` (optional; XDR Automation exports from a real tenant only, never hand-written, without secure-string values)
- `tests/workflows/persistence/test_*.py` (workflow-specific unit tests for rules and hooks)
- `tests/fixtures/workflows/persistence/*.yaml` (simulation scenarios, format of 14.5.2)
- `.claude/agents/wf-persistence.md` (this file)

You may read anything in the repository. You never edit framework code (`src/xdr_response/workflows/` framework modules, `src/xdr_response/lifecycle/`, the Phase 0 engines), atomics, config files, other workflows, `docs/` or the generated files (`docs/mitre-mapping/`, `docs/workflows/README.md`). A missing atomic, atomic option, record field, record kind, builder, link kind, signal rule, config option or framework hook is a contract change (14.7.2): describe it precisely in your final report; the framework owner applies it before you depend on it.

## Workflow state (migrated in Phase 3)

The 0.1.0 plan-rule spec and its five scenarios (retired after Phase 5, architecture 14.4.3) are migrated and deleted; its scenarios live on as `tests/fixtures/workflows/persistence/legacy-01` to `legacy-05` (aligned with C1-C5). Current files:

- `src/xdr_response/workflows/persistence/definition.py`: `WORKFLOW` (id `persistence`, version 2.0.0, phase 3, default severity MEDIUM). Triggers: ATT&CK T1547.001, T1053.005, T1543.003, T1546.003, T1176.001 (priority 120, above malware, below ransomware) and persistence title patterns with a hostname (priority 95). Required integrations `secure_endpoint`, `virustotal`; optional `defender_endpoint`, `alienvault_otx`, `cisco_xdr`. Five read steps (endpoint triage, persisted-binary reputation and prevalence, affected endpoints, persisted process tree; endpoint and process reads look back 168 hours). Four rules: `isolate_persistence_host_secure_endpoint`, `isolate_persistence_host_defender_endpoint` (malicious persistence item backed by active malicious execution), `terminate_running_persisted_process`, `block_malicious_persisted_binary` (at most 10 endpoints). Persistence signals weighted 1.0. MITRE: TA0003 with T1547/T1547.001, T1053/T1053.005, T1543/T1543.003, T1546/T1546.003, T1176/T1176.001 (Software Extensions / Browser Extensions, ATT&CK v17). T1136 (legacy) is deliberately not mapped: no VERIFIED source shows account creation.
- `src/xdr_response/workflows/persistence/hooks.py`: `PersistenceHooks` (facts `hashes`, `items`, `isolate`, `running`; `WORKFLOW` links item to binary and its execution events; `considered`: one **manual step** `remove_persistence:<ENDPOINT>/<item id>` per malicious item, plus items not rated malicious, dormant endpoints (`isolate_endpoint:<ENDPOINT>`), widespread binaries and unrated incident hashes (`block_hash:<sha256>`)). No hand-offs (`handoff_to` is empty).
- Removing a persistence item has no VERIFIED vendor write and no catalog integration (`remove_persistence` never routes), so it is never a rule: it is a manual step with records. A rule for it could never be PROPOSED, which `check_coverage` requires.
- A persistence item rated malicious whose binary is clean (a system tool with hostile arguments) never leads to a hash block or a termination of that binary.
- Browser extensions are recognised from mechanism `other` plus an extension path or name (`hooks.is_browser_extension`) until the record model gets a `browser_extension` mechanism (requested contract change).
- Scenarios: the minimum set of 14.5.3, edges `edge-defender-wmi-subscription`, `edge-system-binary-not-blocked`, `edge-browser-extension-dormant`, `edge-widespread-binary`, and `legacy-01` to `legacy-05`.
- Tests: `tests/workflows/persistence/test_persistence_definition.py`, `test_persistence_hooks.py`, `test_persistence_lifecycle.py` (unique basenames).
- Related workflows: `malware`, `privilege-escalation`, `c2` (network indicators the persisted binary contacted belong to c2).

## Definition of done (section 14.5.4)

1. The definition imports and validates.
2. `python tools/validation/check_workflow_readmes.py --workflow persistence` passes.
3. `python -m pytest -q -p no:cacheprovider tests/workflows/persistence tests/simulation/test_workflow_scenarios.py -k persistence` passes (every rule PROPOSED in some scenario, every scenario in dry run and simulated live).
4. The read-zone safety tests pass (`tests/safety/test_read_zone.py`).
5. `python tools/validation/generate_workflow_docs.py --check` reports only the expected regeneration (the phase integrator runs `--write`; you never edit generated files).

Scenarios (14.5.3): `tp-approve-all`, `tp-approve-selected`, `tp-reject`, `benign-no-action`, `degraded-source`, `critical-asset-elevated`, `partial-failure`, `dry-run`, `release-restoration`, at least two `edge-<slug>` (removal is a manual step, never an unrouted rule) and one `legacy-<NN>-<slug>` per legacy scenario. Test data is fake only: `example.com`, `*.example`, `*.test`, documentation IP ranges, fake 64-hex hashes, hosts like `TH-LT-1047`, users like `jsmith@example.com`.

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
- Never implement an endpoint marked UNVERIFIED in `docs/integrations.md`; raise the documented unverified error instead.
- No secrets, tokens, real customer indicators or personal data in any file.
- This is defensive response automation: describe attacker behaviour abstractly; no exploit code, attack commands, payloads or emulation steps.

## Final report

End with: what you changed (files and why), the commands you ran and their results, anything you could not verify, and every contract change or edit needed in files you do not own.
