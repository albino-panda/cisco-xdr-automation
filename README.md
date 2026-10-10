# cisco-xdr-automation

Human-in-the-loop incident response for Cisco XDR.

The repository holds:

- **The `xdr_response` framework** (Phase 0): Python code that runs the approval-gated lifecycle. It investigates, recommends, waits for a human, executes what the human approved, verifies it, and restores it only after a second human approval.
- **The shared atomic library and workflow framework** (Phase 1): read-only enrichment and investigation atomics, deterministic scoring, evidence, containment builders that produce data only, and the declarative `WorkflowDefinition`.
- **22 incident-type workflows** (Phases 2 to 5): `WorkflowDefinition`s in `src/xdr_response/workflows/` that investigate and recommend only, with an analyst README per workflow in [`workflows/`](workflows/README.md) and 426 simulation scenarios in `tests/fixtures/workflows/`.

## Status

**Phases 0 to 5 are complete** ([architecture section 12](docs/architecture.md#12-recommended-development-phases); as-built notes and exit criteria in sections 14.8 to 14.14; known gaps in section 15). Release notes: [CHANGELOG.md](CHANGELOG.md).

| Phase | Delivered |
|---|---|
| 0 Foundation | Models, config, secrets, redaction, hash-chained audit trail, 16 integration adapters with health checks, approval engine and HMAC tokens, execution guard, containment executor, verification, temporary control registry and restoration, dry run, reporting, lifecycle state machine and orchestrator, simulator |
| 1 Shared atomics | Read zone (`ReadOnlyAdapters`), enrichment and investigation atomics, scoring engine with separate risk and confidence, correlation and blast radius, evidence builder, 15 containment recommendation builders, notifications, workflow framework (definitions, routing, runner), validation tools |
| 2 | `ransomware`, `phishing`, `account-takeover`, `mail-bombing`, `malware`, `mfa-fatigue` (new), `password-spray`, `bec` |
| 3 | `malicious-powershell`, `credential-dumping`, `lateral-movement`, `persistence`, `unauthorized-rmm` |
| 4 | `c2`, `dns-tunneling`, `exfiltration`, `cloud-compromise`, `suspicious-authentication` (new) |
| 5 | `privilege-escalation`, `threat-intel-sweep` (new), `vulnerability-exploitation`, `web-attacks`, cross-source correlation across incidents |

After Phase 5 the 0.1.0 plan-rule specs and their plan engine were retired (architecture 14.4.3, 14.13.8). Their scenarios live on as `legacy-*` workflow scenarios.

## Known gaps and owner decisions

The full list, with what would close each gap, is in [architecture section 15](docs/architecture.md#15-known-gaps-and-owner-decisions). In short:

- **Some executed actions cannot be verified.** Secure Endpoint isolation and release, every native Cisco XDR response action, Defender for Endpoint indicator blocks, Defender for Office 365 email actions, the Intune remote lock and Entra "confirm compromised" execute through VERIFIED writes, but cannot be read back through a VERIFIED endpoint. They end `UNABLE_TO_VERIFY`: the action ran, the result row says "verify manually", and containment is `PARTIALLY_CONTAINED` (a release keeps its control `RELEASE_FAILED`) while `unable_to_verify_counts_as_contained` stays false. Closing it means verifying each read-back endpoint in [docs/integrations.md](docs/integrations.md) and implementing it.
- **Some containment atomics only recommend.** `terminate_process`, `quarantine_file`, `remove_persistence`, `reset_password`, `reset_mfa`, `revoke_app_credentials` and `remove_application` have no VERIFIED write anywhere (nor does `block_hash` in a Secure Endpoint-only tenant). They show as `UNROUTED` or as manual steps, with their evidence, and the analyst performs them in the vendor console. Nothing is executed or dropped.
- **No production approver identity provider, intake service or analyst UI.** The interfaces exist (`ApproverAuthenticator`, `bootstrap()`, the orchestrator, the decision card renderers). `InMemoryApproverAuthenticator` is for tests, the lab and the simulator only. The owner must choose the IdP and where the intake, the UI and the scheduler for `threat-intel-sweep` are hosted ([docs/deployment.md](docs/deployment.md) sections 1, 6 and 8; the XDR side sends only the incident ID, [tools/deployment/xdr-trigger-workflow.md](tools/deployment/xdr-trigger-workflow.md)).
- **Notifications, tickets and audit forwarding stay local.** SOC notifications go to a local JSONL outbox; the Cisco XDR incident note endpoint is UNVERIFIED, so nothing is posted to XDR. `create_ticket` has no adapter (ServiceNow is a spec page only). Audit forwarding to Splunk HEC runs only when you schedule `tools/deployment/forward_audit.py`.
- **Secure Cloud Analytics is a stub.** Every operation raises `UnverifiedEndpointError`; its alerts arrive as Cisco XDR incidents.
- **Cross-incident correlation is informational.** `correlate_workflows` and `rollup_blast_radius` run over finished runs. The lifecycle does not call them, and they never change a package or an approval level.

An adapter implements an endpoint only if [docs/integrations.md](docs/integrations.md) lists it as VERIFIED with a source. Other operations raise `UnverifiedEndpointError` ("unverified endpoint"). The simulated adapters do exactly what the real ones support and verify, so the simulator and [docs/samples](docs/samples/README.md) show these production outcomes.

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
| Approval of any state change (containment, session revocation, remediation, release, restoration, removing blocks) | **A human only** |
| Execution of approved containment | Automatic, right after approval |
| Verification | Automatic, after every action |
| Restoration | A **separate** human release approval, then automatic |

Workflows sit entirely on the automatic, read-only side. They never call a state-changing adapter method, never build a token and never enter a guard context. `tests/safety/test_read_zone.py` enforces this with an AST lint and a runtime check over every workflow scenario. Execution happens only through the lifecycle orchestrator after a human approval.

## The non-negotiable control

AI and automation may summarize, correlate, explain and recommend. They may **never** approve, fabricate evidence, override an analyst, bypass approval or alter audit history.

This is enforced by code, not by prompts:

- **Approval tokens.** `ApprovalEngine` issues an HMAC-SHA256 token only to authenticated principals of kind `HUMAN`. `SERVICE`, `AUTOMATION` and `AI` principals are always refused. The token binds the purpose (`containment` or `release`), the package, the incident, the evidence hash, the workflow version and, per action, the idempotency key, action type, target, params hash and approval level. It expires and is single use per action. The signing key comes from the secret store (`APPROVAL_SIGNING_KEY`), never from code.
- **Execution guard.** Every state-changing adapter method carries `@state_changing` from [`guard.py`](src/xdr_response/guard.py). The HTTP client refuses state-changing requests the same way. Outside `guard.authorized(token, action)` the call raises `ApprovalRequiredError`, even when someone calls the adapter method directly. The guard fails closed: no verifier registered, dry run active, expired token or any mismatch means no write.
- **Evidence.** Every recommendation carries numbered evidence that cites records of the same run, and separate `risk_score` and `confidence_score`. The evidence builder cannot cite anything else. One vendor's verdict alone is never MALICIOUS, and a failed source lowers confidence but never blocks a recommendation that other evidence supports.
- **ELEVATED actions.** An action on a critical asset (domain controller, hypervisor, privileged account, ... see [`config/critical-assets.yaml`](config/critical-assets.yaml)) needs an approver with the elevated role (`xdr-elevated-approver` in [`config/thresholds.yaml`](config/thresholds.yaml)). The decision card shows the asset, role, action and potential impact. Nothing is silently dropped.
- **Audit.** Append-only JSONL with a SHA-256 hash chain. Editing, deleting or reordering a record is detected by the verifier. Secrets are redacted centrally before anything reaches a log or the audit trail.
- **Restoration.** Every control the automation creates goes into the temporary control registry. A release package lists only `ACTIVE` entries and needs its own `release` token. Closing an incident never removes a control.
- **Dry run by default.** `dry_run: true` in config and in the guard. In dry run the framework still investigates and recommends, then prints `Would isolate: TH-LT-1047`. The guard refuses every write, even with a valid token.

The tests in [`tests/safety/`](tests/safety/) prove these rules, for example `test_isolation_without_approval_fails`.

## Quick start (simulator, no vendor access)

Needs Python 3.12 or 3.13.

```
python -m pip install -r requirements-dev.txt
python -m pytest -q -p no:cacheprovider          # the whole suite takes several minutes
python tools/simulator/simulate.py --list-workflows
python tools/simulator/simulate.py --workflow ransomware --scenario dry-run --check
```

The last command routes a fake ransomware incident to the `ransomware` workflow, investigates it with simulated adapters and prints the analyst decision card (numbered evidence, risk and confidence, recommended actions), then the dry-run preview:

```
=== Containment preview (dry run) ===
DRY RUN
Would isolate: TH-LT-1047
Would revoke sessions: jsmith@example.com
No containment actions executed.
```

The payload hash block does not appear in the preview: no enabled adapter in this scenario has a VERIFIED hash-block write, so it is listed as `UNROUTED` for manual handling. The full output, and six more workflows, are in [docs/samples](docs/samples/README.md).

More workflow runs:

```
python tools/simulator/simulate.py --workflow credential-dumping --scenario critical-asset-elevated --live --check   # ELEVATED: the lead approves
python tools/simulator/simulate.py --workflow threat-intel-sweep --scenario degraded-source --live --check          # a source is down; the others still back the package
python tools/simulator/simulate.py --workflow account-takeover --scenario release-restoration --live --check        # contain, then a separate release approval and restoration
python tools/simulator/simulate.py --workflow web-attacks --scenario legacy-01-confirmed-web-shell --check           # a scenario carried over from the 0.1.0 specs
python tools/simulator/simulate.py --all-workflows --check                                                          # every workflow scenario, dry run
python tools/simulator/simulate.py --all-workflows --live --check                                                   # every workflow scenario, simulated live
```

The four bundled incident scenarios (`--list`) exercise the Phase 0 lifecycle and let you override the decision and the approvers:

```
python tools/simulator/simulate.py ransomware                                               # dry run
python tools/simulator/simulate.py ransomware --live                                        # simulated execution, verification (isolation UNABLE_TO_VERIFY), release, restoration
python tools/simulator/simulate.py phishing --live                                          # APPROVE_SELECTED: disable_user is SKIPPED
python tools/simulator/simulate.py ransomware --live --approver ai                          # refused: only HUMAN principals may decide
python tools/simulator/simulate.py ransomware_domain_controller --live --approver analyst   # refused: ELEVATED needs the lead
python tools/simulator/simulate.py ransomware --live --audit-out var/sim/audit.jsonl
python tools/validation/verify_audit_chain.py var/sim/audit.jsonl
```

`--live` is still simulated: adapters are in memory and nothing leaves the process. It goes through the real approval engine and the real guard. See [tools/simulator](tools/simulator/README.md) for scenarios, options and exit codes.

## Workflows

Every workflow investigates and recommends only; each action needs a human approval (ELEVATED for critical assets and over blast-radius caps) before the lifecycle executes it. Every workflow supports dry run and has at least the minimum scenario set (true positive approve all, approve selected, reject, benign, critical asset, degraded source, partial failure, release and restoration, dry run). ATT&CK ids, recommended actions, integrations, scenario counts and hand-offs are in the generated index [docs/workflows/README.md](docs/workflows/README.md).

| Workflow | Phase | Version | Default severity | Origin | Analyst README | Definition |
|---|---|---|---|---|---|---|
| `ransomware` | 2 | 2.0.0 | critical | 0.1.0 spec | [README](workflows/ransomware/README.md) | [`ransomware/`](src/xdr_response/workflows/ransomware/) |
| `phishing` | 2 | 1.0.0 | medium | 0.1.0 spec | [README](workflows/phishing/README.md) | [`phishing/`](src/xdr_response/workflows/phishing/) |
| `account-takeover` | 2 | 2.0.0 | high | 0.1.0 spec | [README](workflows/account-takeover/README.md) | [`account_takeover/`](src/xdr_response/workflows/account_takeover/) |
| `mail-bombing` | 2 | 1.0.0 | high | 0.1.0 spec | [README](workflows/mail-bombing/README.md) | [`mail_bombing/`](src/xdr_response/workflows/mail_bombing/) |
| `malware` | 2 | 2.0.0 | medium | 0.1.0 spec | [README](workflows/malware/README.md) | [`malware/`](src/xdr_response/workflows/malware/) |
| `mfa-fatigue` | 2 | 1.0.0 | high | new | [README](workflows/mfa-fatigue/README.md) | [`mfa_fatigue/`](src/xdr_response/workflows/mfa_fatigue/) |
| `password-spray` | 2 | 2.0.0 | medium | 0.1.0 spec | [README](workflows/password-spray/README.md) | [`password_spray/`](src/xdr_response/workflows/password_spray/) |
| `bec` | 2 | 1.0.0 | high | 0.1.0 spec | [README](workflows/bec/README.md) | [`bec/`](src/xdr_response/workflows/bec/) |
| `malicious-powershell` | 3 | 2.0.0 | medium | 0.1.0 spec | [README](workflows/malicious-powershell/README.md) | [`malicious_powershell/`](src/xdr_response/workflows/malicious_powershell/) |
| `credential-dumping` | 3 | 3.0.0 | critical | 0.1.0 spec | [README](workflows/credential-dumping/README.md) | [`credential_dumping/`](src/xdr_response/workflows/credential_dumping/) |
| `lateral-movement` | 3 | 3.0.0 | high | 0.1.0 spec | [README](workflows/lateral-movement/README.md) | [`lateral_movement/`](src/xdr_response/workflows/lateral_movement/) |
| `persistence` | 3 | 2.0.0 | medium | 0.1.0 spec | [README](workflows/persistence/README.md) | [`persistence/`](src/xdr_response/workflows/persistence/) |
| `unauthorized-rmm` | 3 | 3.0.0 | high | 0.1.0 spec | [README](workflows/unauthorized-rmm/README.md) | [`unauthorized_rmm/`](src/xdr_response/workflows/unauthorized_rmm/) |
| `c2` | 4 | 2.0.0 | high | 0.1.0 spec | [README](workflows/c2/README.md) | [`c2/`](src/xdr_response/workflows/c2/) |
| `dns-tunneling` | 4 | 2.0.0 | high | 0.1.0 spec | [README](workflows/dns-tunneling/README.md) | [`dns_tunneling/`](src/xdr_response/workflows/dns_tunneling/) |
| `exfiltration` | 4 | 2.0.0 | critical | 0.1.0 spec | [README](workflows/exfiltration/README.md) | [`exfiltration/`](src/xdr_response/workflows/exfiltration/) |
| `cloud-compromise` | 4 | 2.0.0 | high | 0.1.0 spec | [README](workflows/cloud-compromise/README.md) | [`cloud_compromise/`](src/xdr_response/workflows/cloud_compromise/) |
| `suspicious-authentication` | 4 | 1.0.0 | medium | new | [README](workflows/suspicious-authentication/README.md) | [`suspicious_authentication/`](src/xdr_response/workflows/suspicious_authentication/) |
| `privilege-escalation` | 5 | 2.0.0 | high | 0.1.0 spec | [README](workflows/privilege-escalation/README.md) | [`privilege_escalation/`](src/xdr_response/workflows/privilege_escalation/) |
| `threat-intel-sweep` | 5 | 1.0.0 | high | new | [README](workflows/threat-intel-sweep/README.md) | [`threat_intel_sweep/`](src/xdr_response/workflows/threat_intel_sweep/) |
| `vulnerability-exploitation` | 5 | 2.0.0 | high | 0.1.0 spec | [README](workflows/vulnerability-exploitation/README.md) | [`vulnerability_exploitation/`](src/xdr_response/workflows/vulnerability_exploitation/) |
| `web-attacks` | 5 | 2.0.0 | medium | 0.1.0 spec | [README](workflows/web-attacks/README.md) | [`web_attacks/`](src/xdr_response/workflows/web_attacks/) |

"0.1.0 spec" means the workflow replaced a 0.1.0 plan-rule spec and carries its scenarios as `legacy-*` fixtures. Incidents are routed to a workflow by `incident.workflow_id` or, failing that, by the workflow triggers (ATT&CK technique, title pattern, source, observable type; the highest priority wins). An incident no workflow handles takes the Phase 0 generic path (`RuleBasedRecommender`) and still needs the same human approval.

Workflow checks, as CI runs them:

```
python tools/validation/check_workflow_readmes.py
python tools/validation/generate_workflow_docs.py --check
```

## Repository layout

```
cisco-xdr-automation/
├── src/xdr_response/     the framework
│   ├── guard.py            execution guard: @state_changing, guard.authorized(...)
│   ├── models/             incidents, evidence, packages, decisions, tokens, results, enums, action catalog
│   ├── config/ secrets/ logs/   settings, secret providers, central redaction
│   ├── audit/              hash-chained JSONL trail and verifier
│   ├── integrations/       16 adapters, guarded HTTP client, health checks, simulated adapters
│   ├── approval/           package builder, critical assets, authenticator, tokens, ledger, engine
│   ├── execution/ verification/ restoration/   executor, verification engine, control registry
│   ├── dryrun/ reporting/  dry-run output, decision card, result table, release checklist
│   ├── lifecycle/          state machine, orchestrator, runtime builder, workflow adapter
│   ├── scoring/            deterministic scoring: separate risk and confidence
│   ├── atomics/            read-only enrichment, investigation, correlation, evidence; containment builders; notifications
│   └── workflows/          workflow framework and the 22 workflow definitions
├── config/               example configs (dry_run: true, Splunk disabled)
├── tools/simulator/      run a fixture incident or workflow scenario end to end
├── tools/validation/     config, endpoint, README and generated-doc checks; verify_audit_chain.py
├── tools/deployment/     the Cisco XDR trigger workflow (incident ID only), scheduled audit forwarding to Splunk HEC
├── tests/                unit/, integration/, simulation/, safety/, workflows/, fixtures/, repository checks
├── workflows/            analyst README per workflow (22)
├── atomic/               legacy atomic names mapped to catalog action types and xdr_response.atomics
├── integrations/         auth, permissions and API surface per product (spec docs)
└── docs/                 architecture, integrations, scoring, deployment, testing, samples, MITRE mapping
```

## Configuration

Copy [`config/integrations.example.yaml`](config/integrations.example.yaml) to `config/integrations.yaml` (git-ignored). The other files in [`config/`](config/) hold thresholds, critical-asset classes, allow-lists and third-party lookup exclusions.

- Config holds secret **names**, never values. Values come from the environment or from mounted files in `XDR_RESPONSE_SECRETS_DIR`. See [`.env.example`](.env.example).
- The loader refuses `auto_approve`, `skip_approval`, `bypass_approval` and `approval_required` anywhere in a config file.
- `DRY_RUN=false` turns dry run off for a process. Any value other than `true` or `false` is a config error.
- Splunk is optional and disabled by default. Nothing depends on it.

Deployment, enabling workflows and the Cisco XDR side: [docs/deployment.md](docs/deployment.md).

## Spec documents

| | Count | Index |
|---|---|---|
| Atomic actions | 15 legacy names, mapped to the catalog | [atomic/README.md](atomic/README.md) |
| Integration specs | 18 (the 16 runtime integrations, plus Cloudflare and ServiceNow, which have no adapter) | [integrations/README.md](integrations/README.md) |
| MITRE ATT&CK mapping | generated from the workflow definitions | [docs/mitre-mapping](docs/mitre-mapping/README.md) |

## Documentation

- [docs/architecture.md](docs/architecture.md): design, threat model, phases. [Section 13](docs/architecture.md#13-phase-0-contract) is the binding Phase 0 contract and [section 14](docs/architecture.md#14-phase-1-5-contract) the binding Phase 1-5 contract.
- [docs/approval-model.md](docs/approval-model.md): who may approve, what a token binds, how the guard enforces it.
- [docs/threat-scoring.md](docs/threat-scoring.md): risk and confidence, never merged.
- [docs/integrations.md](docs/integrations.md): vendor API verification. The source of truth for which endpoints may be implemented.
- [docs/deployment.md](docs/deployment.md): secrets, config, integrations, enabling workflows, dry run first, the Cisco XDR side. Rollout notes in [docs/deployment](docs/deployment/README.md).
- [docs/testing.md](docs/testing.md): test layers, safety tests, simulator. Go-live checks in [docs/testing](docs/testing/README.md).
- [docs/samples](docs/samples/README.md): analyst output for seven workflows, generated by the simulator, including restoration result tables.
- [docs/workflows/README.md](docs/workflows/README.md): generated workflow index.
- [tools/simulator](tools/simulator/README.md): simulator scenarios and options.
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), [LICENSE](LICENSE) (MIT).

## Related project

The separate `cisco-xdr-mailbomb-detector` project (not part of this repository; locally it sits next to it under `Mail Bombing/`) raises the incidents handled by [`workflows/mail-bombing`](workflows/mail-bombing/README.md).

## Claude Code agents

Each workflow has a dedicated Claude Code subagent in [`.claude/agents/`](.claude/agents/), named `wf-<workflow>` (for example `wf-ransomware`).
An agent edits only the paths its workflow owns (architecture 14.5.1) and reports any change needed in shared atomics, integrations, docs or the framework.
All agents keep the safety defaults: dry run, guardrails, human approval and documented rollback. An agent never approves anything.

Ask Claude Code to use one by name, for example:

```
Use the wf-phishing agent to add a step that checks whether any recipient clicked the link.
```

There are 22 agents, one per directory in [`workflows/`](workflows/README.md).
