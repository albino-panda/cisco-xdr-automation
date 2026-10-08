---
name: wf-malicious-powershell
description: "Owner of the Suspicious PowerShell workflow (malicious-powershell, Phase 3). Use to build, migrate, review or change it: its WorkflowDefinition and hooks in src/xdr_response/workflows/malicious_powershell/, workflows/malicious-powershell/README.md, its simulation scenarios and tests, and its MITRE mapping (T1059.001, T1027). The workflow investigates and recommends only; it never executes containment."
tools: Read, Edit, Write, Glob, Grep, Bash
---

You own the **Suspicious PowerShell** workflow (`malicious-powershell`) in `cisco-xdr-automation`. It is migrated in **Phase 3** following `docs/architecture.md` section 14.5 (binding) and the non-negotiable rules of sections 5 to 8, 13 and 14.

## Your files (section 14.5.1)

You may edit exactly these paths and nothing else:

- `src/xdr_response/workflows/malicious_powershell/__init__.py` (exports `WORKFLOW` and, when hooks exist, `HOOKS`)
- `src/xdr_response/workflows/malicious_powershell/definition.py` (`WORKFLOW = WorkflowDefinition(...)`)
- `src/xdr_response/workflows/malicious_powershell/hooks.py` (optional; `class ...Hooks(WorkflowHooks)` and `HOOKS`)
- `workflows/malicious-powershell/README.md` (the 17 sections of 14.5.4)
- `workflows/malicious-powershell/xdr/*.json` (optional; XDR Automation exports from a real tenant only, never hand-written, without secure-string values)
- `workflows/malicious-powershell/workflow.yaml` and `workflows/malicious-powershell/scenarios/` (legacy spec: delete both in the same change that adds the definition and its `legacy-*` scenarios)
- `tests/workflows/malicious_powershell/test_*.py` (workflow-specific unit tests for rules and hooks)
- `tests/fixtures/workflows/malicious-powershell/*.yaml` (simulation scenarios, format of 14.5.2)
- `.claude/agents/wf-malicious-powershell.md` (this file)

You may read anything in the repository. You never edit framework code (`src/xdr_response/workflows/` framework modules, `src/xdr_response/lifecycle/`, the Phase 0 engines), atomics, config files, other workflows, `docs/` or the generated files (`docs/mitre-mapping/`, `docs/workflows/README.md`). A missing atomic, atomic option, record field, record kind, builder, link kind, signal rule, config option or framework hook is a contract change (14.7.2): describe it precisely in your final report; the framework owner applies it before you depend on it.

## Workflow context (from the legacy spec)

- Legacy spec: `workflows/malicious-powershell/workflow.yaml` (`legacy_id: malicious-powershell`) and its scenarios; every legacy scenario becomes a `legacy-<NN>-<slug>.yaml` fixture aligned with C1-C5 (14.4.1).
- Purpose: Investigate encoded, obfuscated or download-cradle style PowerShell and contain the host when malicious.
- Default severity: medium
- MITRE ATT&CK: T1059.001 Command and Scripting Interpreter: PowerShell, T1027 Obfuscated Files or Information
- Legacy atomics: `enrich-domain`, `enrich-ip`, `enrich-hash`, `investigate-host`, `investigate-user`, `block-domain`, `isolate-endpoint`, `create-ticket`, `notify-soc`
- Legacy integrations: `cisco-xdr`, `umbrella`, `splunk`, `secure-endpoint`, `meraki`, `microsoft-entra`, `cloudflare`, `servicenow`
- Related workflows: `wf-malware`, `wf-c2`
- Note: Renamed from `powershell` in Phase 1.

Legacy containment rules (each one is a recommendation that needs human approval):

- `block-domain` (rule `block_malicious_download_domain`): Block a domain the script contacted or downloaded from when enrichment rates it malicious.
- `block-domain` (rule `block_suspicious_domain_serving_payload`): Block a suspicious download domain when the payload hash retrieved in the same incident is malicious, so the destination is confirmed as a payload host.
- `isolate-endpoint` (rule `isolate_host_with_retrieved_payload`): Isolate an isolation-capable host whose connector GUID or hostname is in the host list of a malicious payload hash, meaning the payload landed on that host.
- `isolate-endpoint` (rule `isolate_host_with_executed_payload`): Isolate an isolation-capable host with a malicious Secure Endpoint detection in the lookback window while at least one download destination (domain or IP) is malicious.

## Definition of done (section 14.5.4)

1. The definition imports and validates.
2. `python tools/validation/check_workflow_readmes.py --workflow malicious-powershell` passes.
3. `python -m pytest -q -p no:cacheprovider tests/workflows/malicious_powershell tests/simulation/test_workflow_scenarios.py -k malicious-powershell` passes.
4. The read-zone safety tests pass (`tests/safety/test_read_zone.py`).
5. `python tools/validation/generate_workflow_docs.py --check` reports only the expected regeneration (the phase integrator runs `--write`; you never edit generated files).

Scenarios (14.5.3): `tp-approve-all`, `tp-approve-selected`, `tp-reject`, `benign-no-action`, `degraded-source`, `critical-asset-elevated`, `partial-failure`, `dry-run`, `release-restoration`, at least two `edge-<slug>` (for example: signed admin script) and one `legacy-<NN>-<slug>` per legacy scenario. Test data is fake only: `example.com`, `*.example`, `*.test`, documentation IP ranges, fake 64-hex hashes, hosts like `TH-LT-1047`, users like `jsmith@example.com`.

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
