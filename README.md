# cisco-xdr-automation

Human-in-the-loop incident response for Cisco XDR.

The repository has two layers:

- **Workflow specs and a plan engine** (since 0.1.0): 19 incident-type playbooks, the atomic actions they use, the integrations they call, and `xdr_plan`, which turns enrichment results and guardrails into a containment plan.
- **The `xdr_response` framework** (Phase 0, 0.2.0): Python code that runs the approval-gated lifecycle. It investigates, recommends, waits for a human, executes what the human approved, verifies it, and restores it only after a second human approval.

## The lifecycle

```
NOT_STARTED                 automatic, read-only: investigate, enrich, score, build the package
    │
    ▼
AWAITING_APPROVAL           HUMAN decides: approve all, approve selected, reject, more investigation
    │  signed containment token
    ▼
APPROVED ─► CONTAINMENT_RUNNING     automatic: execute approved actions, verify each one
    │
    ▼
CONTAINED | PARTIALLY_CONTAINED | CONTAINMENT_FAILED
    │
    ▼
AWAITING_RELEASE_APPROVAL   HUMAN decides again: which temporary controls to release
    │  signed release token
    ▼
RESTORATION_RUNNING         automatic: roll back the selected controls, verify each one
    │
    ▼
RESTORED ─► CLOSED          closing never removes a control that is still ACTIVE
```

The 12 states and every allowed transition (including `REMEDIATION_REQUIRED`, reject, reopen) are in [architecture section 2.2](docs/architecture.md#22-lifecycle-state-diagram). Any other transition raises an error.

| Stage | Who acts |
|---|---|
| Investigation, enrichment, scoring | Automatic, read-only adapter calls |
| Recommendation (containment package) | Automatic. A recommendation never executes anything |
| Approval of any state change (containment, remediation, release, restoration, removing blocks) | **A human only** |
| Execution of approved containment | Automatic, right after approval |
| Verification | Automatic, after every action |
| Restoration | A **separate** human release approval, then automatic |

## The non-negotiable control

AI and automation may summarize, correlate, explain and recommend. They may **never** approve, fabricate evidence, override an analyst, bypass approval or alter audit history.

This is enforced by code, not by prompts:

- **Approval tokens.** `ApprovalEngine` issues an HMAC-SHA256 token only to authenticated principals of kind `HUMAN`. `SERVICE`, `AUTOMATION` and `AI` principals are always refused. The token binds the purpose (`containment` or `release`), the package, the incident, the evidence hash, the workflow version and, per action, the idempotency key, action type, target, params hash and approval level. It expires and is single use per action. The signing key comes from the secret store (`APPROVAL_SIGNING_KEY`), never from code.
- **Execution guard.** Every state-changing adapter method carries `@state_changing` from [`guard.py`](src/xdr_response/guard.py). The HTTP client refuses state-changing requests the same way. Outside `guard.authorized(token, action)` the call raises `ApprovalRequiredError`, even when someone calls the adapter method directly. The guard fails closed: no verifier registered, dry run active, expired token or any mismatch means no write.
- **ELEVATED actions.** An action on a critical asset (domain controller, hypervisor, privileged account, ... see [`config/critical-assets.yaml`](config/critical-assets.yaml)) needs an approver with the elevated role (`xdr-elevated-approver` in [`config/thresholds.yaml`](config/thresholds.yaml)). The decision card shows the asset, role, action and potential impact. Nothing is silently dropped.
- **Audit.** Append-only JSONL with a SHA-256 hash chain. Editing, deleting or reordering a record is detected by the verifier. Secrets are redacted centrally before anything reaches a log or the audit trail.
- **Restoration.** Every control the automation creates goes into the temporary control registry. A release package lists only `ACTIVE` entries and needs its own `release` token. Closing an incident never removes a control.
- **Dry run by default.** `dry_run: true` in config and in the guard. In dry run the framework still investigates and recommends, then prints `Would isolate: TH-LT-1047`. The guard refuses every write, even with a valid token.

The tests in [`tests/safety/`](tests/safety/) prove these rules, for example `test_isolation_without_approval_fails`.

## Quick start (simulator, no vendor access)

Needs Python 3.12 or 3.13.

```
python -m pip install -r requirements-dev.txt
python -m pytest -q
python tools/simulator/simulate.py --list
python tools/simulator/simulate.py ransomware
```

The last command is a dry run. It prints the analyst decision card (numbered evidence, risk and confidence, recommended actions) and then:

```
=== Containment result (dry run) ===
DRY RUN
Would isolate: TH-LT-1047
Would block: 5c1d7e0b...
Would block: c2.ransom-ops.example
Would block: 198.51.100.23
No containment actions executed.
```

More runs:

```
python tools/simulator/simulate.py ransomware --live                    # simulated execution, verification, release, restoration
python tools/simulator/simulate.py phishing --live                      # APPROVE_SELECTED: disable_user is SKIPPED
python tools/simulator/simulate.py ransomware --live --approver ai      # refused: only HUMAN principals may decide
python tools/simulator/simulate.py ransomware_domain_controller --live --approver analyst   # refused: ELEVATED needs the lead
python tools/simulator/simulate.py ransomware --live --audit-out var/sim/audit.jsonl
python tools/validation/verify_audit_chain.py var/sim/audit.jsonl
```

`--live` is still simulated: adapters are in memory and nothing leaves the process. It goes through the real approval engine and the real guard. See [tools/simulator](tools/simulator/README.md) for scenarios, options and exit codes.

## Repository layout

```
cisco-xdr-automation/
├── src/xdr_response/     the framework (Phase 0)
│   ├── guard.py            execution guard: @state_changing, guard.authorized(...)
│   ├── models/             incidents, evidence, packages, decisions, tokens, results, enums
│   ├── config/ secrets/ logs/   settings, secret providers, central redaction
│   ├── audit/              hash-chained JSONL trail and verifier
│   ├── integrations/       16 adapters, guarded HTTP client, health checks, simulated adapters
│   ├── approval/           package builder, critical assets, authenticator, tokens, ledger, engine
│   ├── execution/ verification/ restoration/   executor, verification engine, control registry
│   ├── dryrun/ reporting/  dry-run output, decision card, result table, release checklist
│   ├── lifecycle/          state machine, orchestrator, runtime builder
│   └── scoring/            design only in Phase 0
├── config/               example configs (dry_run: true, Splunk disabled)
├── tools/simulator/      run a fixture incident end to end
├── tools/validation/     verify_audit_chain.py
├── tests/                unit/, integration/, simulation/, safety/, fixtures/ + spec-layer tests
├── workflows/            19 incident-type playbooks (README, workflow.yaml, scenarios/)
├── atomic/               15 atomic action contracts
├── integrations/         auth, permissions and API surface per product (spec docs)
├── engine/xdr_plan/      plan-rule engine for the workflow specs
└── docs/                 architecture, integrations, MITRE mapping, deployment, testing
```

## Configuration

Copy [`config/integrations.example.yaml`](config/integrations.example.yaml) to `config/integrations.yaml` (git-ignored). The other files in [`config/`](config/) hold thresholds, critical-asset classes, allow-lists and third-party lookup exclusions.

- Config holds secret **names**, never values. Values come from the environment or from mounted files in `XDR_RESPONSE_SECRETS_DIR`. See [`.env.example`](.env.example).
- The loader refuses `auto_approve`, `skip_approval`, `bypass_approval` and `approval_required` anywhere in a config file.
- `DRY_RUN=false` turns dry run off for a process. Any value other than `true` or `false` is a config error.
- Splunk is optional and disabled by default. Nothing depends on it.

## Status

**Phase 0 (foundation) is done.** It contains the models, config, secrets, redaction, audit trail, 16 integration adapters with health checks, approval engine and tokens, execution guard, containment executor, verification, temporary control registry and restoration, dry run, reporting, the lifecycle state machine and orchestrator, the simulator and the full test suite.

What Phase 0 does not do yet:

- No production identity provider. `InMemoryApproverAuthenticator` is for tests and the lab only. Plug in your own `ApproverAuthenticator` before live use.
- Scoring: the deterministic scoring engine ([`scoring/README.md`](src/xdr_response/scoring/README.md), [docs/threat-scoring.md](docs/threat-scoring.md)) scores workflow recommendations with separate risk and confidence. Incidents that no migrated workflow handles take the Phase 0 `RuleBasedRecommender` path.
- An adapter implements an endpoint only if [docs/integrations.md](docs/integrations.md) lists it as VERIFIED with a source. Other operations raise `UnverifiedEndpointError` ("unverified endpoint").
- No HTTP intake ships with the repository: a deployment exposes one that receives only the XDR incident ID (see [tools/deployment/xdr-trigger-workflow.md](tools/deployment/xdr-trigger-workflow.md)). No production workflow is migrated yet (Phases 2 to 5); the 19 legacy specs replay through the runtime in dry run.

Phases 1 to 5 are in [architecture section 12](docs/architecture.md#12-recommended-development-phases).

## Workflow specs and the plan engine

The spec layer from 0.1.0 is kept and still tested:

| | Count | Index |
|---|---|---|
| Workflows | 19 (105 scenarios) | [workflows/README.md](workflows/README.md) |
| Atomic actions | 15 | [atomic/README.md](atomic/README.md) |
| Integration specs | 9 | [integrations/README.md](integrations/README.md) |
| MITRE ATT&CK mapping | | [docs/mitre-mapping](docs/mitre-mapping/README.md) |

`engine/xdr_plan` evaluates each workflow's `plan` rules (no `eval`) against enrichment results and guardrails and returns a containment plan. Check every workflow and replay its scenarios:

```
PYTHONPATH=engine python -m xdr_plan check
PYTHONPATH=engine python -m xdr_plan plan ransomware workflows/ransomware/scenarios/01-workstation-encryption.yaml
```

How this feeds later phases:

- **Phase 1** (done) added `plan_bridge`: each planned action becomes a proposal for `PackageBuilder`, which adds numbered evidence, the idempotency key and the approval level. All 105 scenarios replay through the runtime in dry run (`tests/simulation/test_legacy_replay.py`, `python tools/simulator/simulate.py --legacy <workflow> [<scenario>]`).
- In the replay, spec guardrails become runtime policy: protected assets become critical assets (ELEVATED, never silently skipped), allow-lists become never-block lists, blast-radius caps become `thresholds` caps.
- The specs were aligned with the lifecycle (conflicts C1 to C5 in [architecture section 1.3](docs/architecture.md#13-conflicts-with-the-non-negotiable-lifecycle)): every containment atomic, `revoke-session` included, requires approval; `auto_approve` is gone and refused; protected and over-limit actions stay planned as ELEVATED; unlock codes are never copied.
- **Phases 2 to 5** turn each workflow into data for the framework: rules, scoring weights, MITRE mapping, scenarios. Workflows never hold vendor HTTP code or approval logic.

## Documentation

- [docs/architecture.md](docs/architecture.md): design, threat model, phases. [Section 13](docs/architecture.md#13-phase-0-contract) is the binding Phase 0 contract.
- [docs/approval-model.md](docs/approval-model.md): who may approve, what a token binds, how the guard enforces it.
- [docs/integrations.md](docs/integrations.md): vendor API verification. The source of truth for which endpoints may be implemented.
- [docs/deployment](docs/deployment/README.md): rollout order, approvals, guardrails.
- [docs/testing](docs/testing/README.md): test levels and the go-live checklist.
- [tools/simulator](tools/simulator/README.md): simulator scenarios and options.
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), [LICENSE](LICENSE) (MIT).

## Related project

The separate `cisco-xdr-mailbomb-detector` project (not part of this repository; locally it sits next to it under `Mail Bombing/`) raises the incidents handled by [`workflows/mail-bombing`](workflows/mail-bombing/README.md).

## Claude Code agents

Each workflow has a dedicated Claude Code subagent in [`.claude/agents/`](.claude/agents/), named `wf-<workflow>` (for example `wf-ransomware`).
An agent edits only its own `workflows/<workflow>/` directory and reports any change needed in shared atomics, integrations, docs or the framework.
All agents keep the safety defaults: dry run, guardrails, human approval and documented rollback. An agent never approves anything.

Ask Claude Code to use one by name, for example:

```
Use the wf-phishing agent to add a step that checks whether any recipient clicked the link.
```

There are 19 agents, one per directory in [`workflows/`](workflows/README.md).
