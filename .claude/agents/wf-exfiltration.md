---
name: wf-exfiltration
description: "Owner of the Data exfiltration workflow (exfiltration, Phase 4). Use to build, migrate, review or change it: its WorkflowDefinition and hooks in src/xdr_response/workflows/exfiltration/, workflows/exfiltration/README.md, its simulation scenarios and tests, and its MITRE mapping (T1041, T1567.002, T1048). The workflow investigates and recommends only; it never executes containment."
tools: Read, Edit, Write, Glob, Grep, Bash
---

You own the **Data exfiltration** workflow (`exfiltration`) in `cisco-xdr-automation`. It is migrated in **Phase 4** following `docs/architecture.md` section 14.5 (binding) and the non-negotiable rules of sections 5 to 8, 13 and 14.

## Your files (section 14.5.1)

You may edit exactly these paths and nothing else:

- `src/xdr_response/workflows/exfiltration/__init__.py` (exports `WORKFLOW` and, when hooks exist, `HOOKS`)
- `src/xdr_response/workflows/exfiltration/definition.py` (`WORKFLOW = WorkflowDefinition(...)`)
- `src/xdr_response/workflows/exfiltration/hooks.py` (optional; `class ...Hooks(WorkflowHooks)` and `HOOKS`)
- `workflows/exfiltration/README.md` (the 17 sections of 14.5.4)
- `workflows/exfiltration/xdr/*.json` (optional; XDR Automation exports from a real tenant only, never hand-written, without secure-string values)
- `workflows/exfiltration/workflow.yaml` and `workflows/exfiltration/scenarios/` (legacy spec: delete both in the same change that adds the definition and its `legacy-*` scenarios)
- `tests/workflows/exfiltration/test_*.py` (workflow-specific unit tests for rules and hooks)
- `tests/fixtures/workflows/exfiltration/*.yaml` (simulation scenarios, format of 14.5.2)
- `.claude/agents/wf-exfiltration.md` (this file)

You may read anything in the repository. You never edit framework code (`src/xdr_response/workflows/` framework modules, `src/xdr_response/lifecycle/`, the Phase 0 engines), atomics, config files, other workflows, `docs/` or the generated files (`docs/mitre-mapping/`, `docs/workflows/README.md`). A missing atomic, atomic option, record field, record kind, builder, link kind, signal rule, config option or framework hook is a contract change (14.7.2): describe it precisely in your final report; the framework owner applies it before you depend on it.

## Workflow context (from the legacy spec)

- Legacy spec: `workflows/exfiltration/workflow.yaml` (`legacy_id: exfiltration`) and its scenarios; every legacy scenario becomes a `legacy-<NN>-<slug>.yaml` fixture aligned with C1-C5 (14.4.1).
- Purpose: Stop large or unusual outbound transfers and preserve evidence for impact assessment.
- Default severity: critical
- MITRE ATT&CK: T1041 Exfiltration Over C2 Channel, T1567.002 Exfiltration to Cloud Storage, T1048 Exfiltration Over Alternative Protocol
- Legacy atomics: `enrich-domain`, `enrich-ip`, `investigate-host`, `investigate-user`, `block-domain`, `block-ip`, `isolate-endpoint`, `disable-user`, `create-ticket`, `notify-soc`
- Legacy integrations: `cisco-xdr`, `umbrella`, `splunk`, `secure-endpoint`, `meraki`, `microsoft-entra`, `cloudflare`, `servicenow`
- Related workflows: `wf-c2`, `wf-dns-tunneling`, `wf-cloud-compromise`

Legacy containment rules (each one is a recommendation that needs human approval):

- `block-domain` (rule `block_exfil_domains`): Domains with a malicious or suspicious verdict, and transfer destination domains with no reputation yet (verdict unknown, typical for a fresh drop site).
- `block-ip` (rule `block_exfil_ips`): IPs with a malicious or suspicious verdict, and transfer destination IPs with verdict unknown, that at most 3 internal hosts talk to.
- `isolate-endpoint` (rule `isolate_active_source_hosts`): Source hosts of a transfer that is still running, when the transfer shows exfiltration evidence (a destination domain or IP that is not clean, a malicious detection on the host, or an insider-risk flag from the source).
- `disable-user` (rule `disable_compromised_actor`): Accounts driving the transfer that look compromised.
- `disable-user` (rule `disable_insider_actor`): Accounts the detection source flags as insider risk (incident.context.insider_risk) and names explicitly in incident.context.actor_users.

## Definition of done (section 14.5.4)

1. The definition imports and validates.
2. `python tools/validation/check_workflow_readmes.py --workflow exfiltration` passes.
3. `python -m pytest -q -p no:cacheprovider tests/workflows/exfiltration tests/simulation/test_workflow_scenarios.py -k exfiltration` passes.
4. The read-zone safety tests pass (`tests/safety/test_read_zone.py`).
5. `python tools/validation/generate_workflow_docs.py --check` reports only the expected regeneration (the phase integrator runs `--write`; you never edit generated files).

Scenarios (14.5.3): `tp-approve-all`, `tp-approve-selected`, `tp-reject`, `benign-no-action`, `degraded-source`, `critical-asset-elevated`, `partial-failure`, `dry-run`, `release-restoration`, at least two `edge-<slug>` (for example: sanctioned cloud storage) and one `legacy-<NN>-<slug>` per legacy scenario. Test data is fake only: `example.com`, `*.example`, `*.test`, documentation IP ranges, fake 64-hex hashes, hosts like `TH-LT-1047`, users like `jsmith@example.com`.

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
