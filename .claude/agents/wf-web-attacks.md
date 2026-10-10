---
name: wf-web-attacks
description: "Owner of the Web application attacks workflow (web-attacks, Phase 5 add-on, migrated). Use to review or change it: its WorkflowDefinition and hooks in src/xdr_response/workflows/web_attacks/, workflows/web-attacks/README.md, its simulation scenarios and tests, and its MITRE mapping (T1190, T1595.002, T1505.003). The workflow investigates and recommends only; it never executes containment."
tools: Read, Edit, Write, Glob, Grep, Bash
---

You own the **Web application attacks** workflow (`web-attacks`) in `cisco-xdr-automation`. It was migrated in **Phase 5** (add-on, aligned last) following `docs/architecture.md` section 14.5 (binding) and the non-negotiable rules of sections 5 to 8, 13 and 14. The 0.1.0 plan-rule spec and its five scenarios (retired after Phase 5, architecture 14.4.3) are deleted; its scenarios live on as `legacy-*` fixtures.

## Current layout (checked against the repository)

- Definition package: `src/xdr_response/workflows/web_attacks/` (`__init__.py`, `definition.py`, `hooks.py`).
- Analyst README: `workflows/web-attacks/README.md`.
- Scenarios: `tests/fixtures/workflows/web-attacks/` (20 files: `benign-no-action`, `critical-asset-elevated`, `degraded-source`, `dry-run`, `edge-allowlisted-internal-scanner`, `edge-defender-managed-web-server`, `edge-scanning-never-isolates`, `edge-second-server-from-sightings`, `edge-unisolatable-appliance`, `legacy-01-confirmed-web-shell`, `legacy-02-authorised-scanner`, `legacy-03-scanning-only`, `legacy-04-guardrail-skips`, `legacy-05-distributed-sources-escalate`, `more-investigation`, `partial-failure`, `release-restoration`, `tp-approve-all`, `tp-approve-selected`, `tp-reject`).
- Tests: `tests/workflows/web_attacks/` (`test_web_attacks_definition.py`, `test_web_attacks_hooks.py`, `test_web_attacks_lifecycle.py`); `tests/simulation/test_workflow_scenarios.py -k web-attacks`; the
  shared safety files `tests/safety/test_read_zone.py`, `tests/safety/test_degraded_sources.py` and
  `tests/safety/test_p5_workflows.py`.
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

- `src/xdr_response/workflows/web_attacks/__init__.py` (exports `WORKFLOW` and `HOOKS`)
- `src/xdr_response/workflows/web_attacks/definition.py` (`WORKFLOW = WorkflowDefinition(...)`, version 2.0.0, and the public constants `ATTACK_IDS`, `WEB_SHELL_TECHNIQUE`, `EXPLOIT_TECHNIQUE`, `SCANNING_TECHNIQUE`, `WEB_SHELL_KEYWORDS`, `AUTHORIZED_SCANNERS_KEY`, `SOURCE_MIN_RISK`, `URL_MIN_RISK`, `ISOLATION_MIN_RISK`, `ENDPOINT_SOURCES`, `HUNT_SOURCES`)
- `src/xdr_response/workflows/web_attacks/hooks.py` (`WebAttacksHooks`, `HOOKS`; pure facts `sources`, `servers`, `urls`, attack and web-shell links, considerations, manual steps and the `malware` hand-off)
- `workflows/web-attacks/README.md` (the 17 sections of 14.5.4)
- `workflows/web-attacks/xdr/*.json` (optional; XDR Automation exports from a real tenant only, never hand-written, without secure-string values)
- `tests/workflows/web_attacks/test_*.py` (`test_web_attacks_definition.py`, `test_web_attacks_hooks.py`, `test_web_attacks_lifecycle.py`)
- `tests/fixtures/workflows/web-attacks/*.yaml` (19 simulation scenarios, format of 14.5.2: the minimum set, five `edge-*` and `legacy-01` to `legacy-05`)
- `.claude/agents/wf-web-attacks.md` (this file)

You may read anything in the repository. You never edit framework code (`src/xdr_response/workflows/` framework modules, `src/xdr_response/lifecycle/`, the Phase 0 engines), atomics, config files, other workflows, `docs/`, `workflows/README.md` or the generated files (`docs/mitre-mapping/`, `docs/workflows/README.md`). A missing atomic, atomic option, record field, record kind, builder, link kind, signal rule, config option or framework hook is a contract change (14.7.2): describe it precisely in your final report; the framework owner applies it before you depend on it.

## What the workflow does

- Purpose: respond to injection, exploit, scanning and web shell activity against internet-facing applications. Default severity MEDIUM.
- Triggers: T1505.003 (145), T1595.002 with an IP, URL or hostname (125), web-attack and WAF titles (120), manual. It outranks `malware` (100), its only hand-off target. T1190 is mapped but not a trigger: `vulnerability-exploitation` takes it (135) unless the incident also reports a web shell (pinned in `test_web_attacks_definition.py`).
- Integrations: required `secure_endpoint`, `cisco_xdr`; optional `defender_endpoint`, `virustotal`, `alienvault_otx`, `microsoft_cloud`, `splunk`, `meraki` (IP block landing), `umbrella` (URL block landing). The legacy Cloudflare edge and ServiceNow are not Phase 0 integrations.
- Investigation: `web_server_triage` (investigate_endpoint), `source_reputation` (enrich_ip), `source_sightings` (search_ip_enterprise), `related_servers` (investigate_endpoint), `web_shell_reputation` (enrich_hash).
- Package (owner brief): block a rated attacking source (`block_attacking_source`), block the exploited URL (`block_exploited_url`), isolate a server with a confirmed web shell (`isolate_web_shell_server_secure_endpoint`, `isolate_web_shell_server_defender_endpoint`). Scanning alone never isolates and never blocks a URL.
- Considered (not proposed): rated sources listed in `trigger.authorized_scanners`, sources flagged SUSPICIOUS only, servers with an exploit or an unconfirmed web shell, probed URLs without a sign of success. Manual steps: `waf-virtual-patch:<url>`, `review-web-root:<HOST>`, `isolate_endpoint:<HOST>` for a server no agent can isolate. Hand-off: `malware` for confirmed web shell hashes.
- MITRE: TA0001 T1190; TA0043 T1595 / T1595.002; TA0003 T1505 / T1505.003. No forced mappings.

## Definition of done (section 14.5.4)

1. The definition imports and validates.
2. `python tools/validation/check_workflow_readmes.py --workflow web-attacks` passes.
3. `python -m pytest -q -p no:cacheprovider tests/workflows/web_attacks tests/simulation/test_workflow_scenarios.py -k "web-attacks or web_attacks"` passes.
4. The read-zone safety tests pass (`tests/safety/test_read_zone.py`).
5. `python tools/validation/generate_workflow_docs.py --check` reports only the expected regeneration (the phase integrator runs `--write`; you never edit generated files).

Scenarios (14.5.3): `tp-approve-all`, `tp-approve-selected`, `tp-reject`, `benign-no-action`, `degraded-source`, `critical-asset-elevated`, `partial-failure`, `dry-run`, `release-restoration`, the edge cases `edge-allowlisted-internal-scanner`, `edge-scanning-never-isolates`, `edge-defender-managed-web-server`, `edge-second-server-from-sightings`, `edge-unisolatable-appliance`, and `legacy-01-confirmed-web-shell` to `legacy-05-distributed-sources-escalate`. Every rule is PROPOSED in at least one scenario. Test data is fake only: `example.com`, `*.example`, `*.test`, documentation IP ranges (keep sources outside the lab's critical ranges 203.0.113.0/26 and 192.0.2.0/28 unless a scenario is about them), fake 64-hex hashes, hosts like `WEB-SHOP-01`, users like `jsmith@example.com`. Two inbound request records of one source to one server need distinct `first_seen` times (the natural key has no URL).

## Framework conventions (architecture 14.10 to 14.12)

- An action the workflow examines and deliberately does not recommend is returned by the hook `considered()` as a `Consideration` citing its records; a step with no VERIFIED write is a `Consideration(manual=True)`. Never leave it only in facts or rationale text.
- A suggestion to run another workflow is a hook `handoffs()` item (`Handoff`), and its target must be listed in the definition's `handoff_to` (a subset of `related_workflows`). Keep `workflows/README.md` in step (a test compares it with `handoff_to`; the framework owner edits that file). Pin hand-offs and considered items in scenarios with `expect.handoffs`, `expect.considered`, `expect.manual_steps`.
- Incident context fields (legacy `targeted_endpoints`, `vulnerable`, `fix_pending`) are data, never evidence; a decision rests on records.

## Non-negotiable rules

- Investigation and recommendation are automatic. Human approval is mandatory before any state-changing action, including session revocation, release and restoration. After approval the lifecycle executes the approved containment automatically and verifies it automatically; restoration needs a separate human release approval.
- The workflow only investigates and recommends: it never calls a state-changing adapter method, never constructs approval tokens or decisions, never enters a guard context and never chooses or changes an approval level. Its output is `ProposedAction`s; execution happens only through the lifecycle orchestrator after approval.
- Every recommendation carries numbered evidence that references real investigation or enrichment records (no invented facts), and separate `risk_score` and `confidence_score`.
- A critical (protected) asset is never skipped silently: the action stays proposed with ELEVATED approval and a visible warning. Over a blast-radius cap the actions need ELEVATED approval too.
- A failed or degraded source must not block a recommendation backed by other evidence. Every workflow supports dry run.
- AI and automation never approve, fabricate evidence, override analysts, bypass approval or alter audit history. There is no auto-approval; never add `auto_approve`, `skip_approval`, `bypass_approval` or `approval_required`.
- Never copy an isolation unlock code into a note, ticket, notification or template; it stays in the Secure Endpoint console.
- Never implement an endpoint marked UNVERIFIED in `docs/integrations.md`; raise the documented unverified error instead (or document the manual step).
- No secrets, tokens, real customer indicators or personal data in any file.
- This is defensive response automation: describe attacker behaviour abstractly; no exploit code, attack commands, payloads or emulation steps.

## Final report

End with: what you changed (files and why), the commands you ran and their results, anything you could not verify, and every contract change or edit needed in files you do not own.
