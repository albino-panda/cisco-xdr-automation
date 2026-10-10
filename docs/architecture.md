# Architecture: Cisco XDR human-in-the-loop incident response framework

Status: owner deliverable 1 (brief section 49). This is the specification that the Phase 0 components are coded against. Date: 2026-10-06.

Implementation status (2026-10-08): **Phases 0 to 5 are complete.** All 22 workflows run on the framework, the 0.1.0 spec layer is retired (14.4.3, applied as 14.13.8), and the as-built notes of every phase are in 14.8 to 14.13. Sections 1 to 12 keep their original wording as design history where they describe the pre-Phase-1 repository; sections 13 and 14 are the binding contract.

Sections 1 to 12 answer the twelve questions in the brief. Section 13, **Phase 0 contract**, and section 14, **Phase 1-5 contract**, are binding for implementers: module paths, class names, enum values and signatures there must be used exactly as written. Where this document and an implementation disagree, the implementation is wrong until this document is changed in the same commit.

**The non-negotiable lifecycle.** Every component in this document serves it.

| Stage | Who acts | Enforcement |
|---|---|---|
| Investigation, enrichment, correlation, scoping, scoring | Automatic | Read-only adapter operations (`OperationKind.READ` / `VERIFY`) |
| Recommendation (containment package) | Automatic | `PackageBuilder`; recommendations never execute anything |
| Approval of any state-changing action (containment, remediation, release, restoration, removing blocks) | **Human only** | `ApprovalEngine` + HMAC token + `guard.py` (deterministic code, never prompts) |
| Execution of approved containment | Automatic, immediately after approval | `ContainmentExecutor` inside `guard.authorized(...)` |
| Verification | Automatic | `VerificationEngine` (read-only) |
| Restoration | Separate **human release approval**, then automatic | Release token (`purpose="release"`), `RestorationEngine` |
| AI / automation | May summarize, correlate, prioritize, explain, recommend, write narratives | May **never** approve, fabricate evidence, override analysts, bypass approval or alter audit history. `PrincipalKind.AI`, `SERVICE` and `AUTOMATION` are always rejected as approvers |

---

## 1. Current repository assessment

### 1.1 What exists today

**The repository is a design catalog plus a planning engine. It has no response runtime.** The README calls everything a "specification". Nothing in it calls a vendor API, carries an approval, executes an action, verifies a result, restores a control or writes an audit record.

| Area | Contents | Quality |
|---|---|---|
| `workflows/` (19) | Each has a README, a `workflow.yaml` and `scenarios/*.yaml` (105 in total). Each `workflow.yaml` holds metadata, MITRE IDs, triggers, inputs, `defaults.dry_run: true`, phased `steps` (intake, enrich, investigate, decide, contain, record, notify), `plan` rules (`for_each` / `when` / `target` / `args`) and note templates. | High. The format is consistent and machine-checked. Scenarios cover the happy path, benign look-alikes, protected assets, blast-radius overflow and allow-listed indicators. |
| `atomic/` (15) | Contracts for enrich-hash/domain/ip, investigate-host/user, 8 containment actions (isolate-endpoint, block-domain/url/ip/hash, disable-user, revoke-session, quarantine-email), create-ticket and notify-soc. Each declares inputs and outputs, `side_effects`, `requires_approval`, `reversible`, `rollback`, `idempotent` and `supports_dry_run`. | Good contracts, no code behind them. |
| `integrations/` (9) | cisco-xdr, secure-endpoint, secure-email, umbrella, microsoft-entra, meraki, splunk, cloudflare, servicenow: auth, permissions, API surface. | Every README says "Verify every endpoint". Verification now lives in `docs/integrations.md` (71 VERIFIED, 31 UNVERIFIED endpoints). |
| `engine/xdr_plan/` (~780 LOC) | `expr.py` (safe AST rule evaluator, no `eval`), `planner.py` (`build_plan` turns rules + results + guardrails into a `Plan` of `Action`s), `guardrails.py` (protected hosts/users/groups, CIDR and domain allow-lists, internal-IP and hash checks), `validate.py`, `repo.py`, CLI. | Clean, deterministic, well tested. |
| `docs/` | `integrations.md` (vendor API verification, source of truth for endpoints), `mitre-mapping/`, `deployment/` (README, `guardrails.example.yaml`), `testing/`. | Concise. |
| Tests and CI | 69 tests in `tests/test_engine.py`, `test_repo.py`, `test_workflows.py`. CI (Python 3.12) runs pytest and `python -m xdr_plan check`. | Solid regression net for the spec layer. |
| `.claude/agents/wf-*.md` | 19 agents, one per workflow, each limited to its own directory. | Useful for Phases 2 to 5. |

### 1.2 What is reused

- **Plan rules become the recommendation source.** `build_plan` already is the "generate containment plan" step. In Phase 1 a bridge (`xdr_response.lifecycle.plan_bridge`) wraps each planned `Action` as a `ProposedAction`, and `PackageBuilder` adds numbered evidence, risk and confidence scores, the idempotency key, `params` and `approval_level`. The expression engine and the `for_each` / `when` rules carry over unchanged.
- **105 scenarios become simulation fixtures** for `tests/simulation/` and `tools/simulator/` (dry-run output, decision cards, lifecycle tests against mocked adapters).
- **Guardrails become config:** `protected.*` becomes `config/critical-assets.yaml` (the brief's 10 classes); `allowlist.*` (including `approved_rmm`) becomes `config/allowlists.yaml` and `config/exclusions.yaml`; `blast_radius` becomes `config/thresholds.yaml`; `expiry_hours` becomes the release-review reminder TTL for temporary controls (never an automatic release).
- **MITRE mapping** (`docs/mitre-mapping/mitre-mapping.yaml` and per-workflow entries) is reused, with a tactic field added and a "no forced mappings" check.
- **Atomic contract metadata:** `reversible` and `rollback` seed the action catalog's `rollback_action_type`; `idempotent` and `supports_dry_run` seed adapter capability flags.

### 1.3 Conflicts with the non-negotiable lifecycle

| # | Conflict | Resolution |
|---|---|---|
| C1 | `atomic/revoke-session/atomic.yaml` sets `requires_approval: false`; ransomware, account-takeover, bec, cloud-compromise, credential-dumping, lateral-movement and others repeat it, and their scenarios assert it. | The runtime ignores spec-layer approval flags: approval is required whenever `ActionSpec.state_changing` is true, and `revoke_sessions` is state-changing. Phase 1 changes the YAML and the scenario assertions in the same commit. |
| C2 | `guardrails.example.yaml` has `auto_approve` (`account-takeover: revoke-session: true`) and `planner.py` honours it. | `xdr_response.config` refuses any config containing `auto_approve`, `skip_approval`, `bypass_approval` or `approval_required: false` (`ConfigError`). Phase 1 removes the section and the planner branch. |
| C3 | Protected assets are silently skipped (`skipped_protected`, no escalation). A protected domain controller with ransomware drops out of the plan. | Critical-asset matches make the action `ELEVATED` and attach a `CriticalAssetWarning` (asset, role, action, potential impact). Never silently blocked. |
| C4 | Isolation unlock codes are written into incident notes and rollback templates (`{plan.unlock_codes}` in c2, dns-tunneling, exfiltration, malware and others). | `unlock_code` is a sensitive key in the central redactor; it is never written to notes, logs or audit. Phase 1 removes the template references. |
| C5 | Over-limit actions are dropped (`skipped_limit`, `escalate`). | Over the blast-radius cap, actions become `ELEVATED` with a warning. Nothing disappears from the package. |

### 1.4 Gaps against the brief

- **Runtime code:** models, config, secrets, logging, audit, adapters, health checks, approval tokens, execution guard, execution, verification, restoration, dry-run, scoring. Lifecycle states, `risk_score` / `confidence_score` and numbered evidence do not exist yet.
- **Integrations missing from `integrations/`:** Defender for Endpoint, Defender for O365, Intune, Microsoft Cloud, VirusTotal, AlienVault OTX, HIBP, Secure Malware Analytics, Secure Cloud Analytics. (`docs/integrations.md` already covers all 16.)
- **Extra integrations, not in the brief:** cloudflare, servicenow. Kept as optional add-ons; no adapter in Phase 0.
- **Workflows missing:** mfa-fatigue (today only scenario `account-takeover/05-mfa-fatigue-approved`), suspicious-authentication, threat-intel-sweep.
- **Workflows named differently:** `powershell` (brief: `malicious-powershell`), `rmm` (brief: `unauthorized-rmm`). Phase 1 renames both directories (`workflows/malicious-powershell`, `workflows/unauthorized-rmm`) together with the legacy tests, agents and MITRE docs (section 14.5; this supersedes the earlier "name table, no rename" decision).
- **Extra workflows:** `vulnerability-exploitation`, `web-attacks`. Kept as add-ons.
- **Atomics missing:** enrich_url/email_address/user/endpoint; most investigate_* and search_*_enterprise; isolate_defender_endpoint, delete_malicious_email, intune_device_action, terminate_process, quarantine_file, remove_persistence, remove_privileged_role; all verification, restoration and approval atomics. In the runtime they are action types in the catalog (section 13.6).
- **Tests missing:** safety tests (`test_isolation_without_approval_fails` and the others in section 10), mocked-API integration tests, lifecycle tests.

### 1.5 Structural differences from the brief's tree

| Brief | Repo today | Decision |
|---|---|---|
| Snake_case integration dirs (`cisco_xdr`, `entra`) | Kebab-case spec dirs (`cisco-xdr`, `microsoft-entra`) | Runtime adapters live in `src/xdr_response/integrations/<snake_case>/`. Spec dirs stay. Mapping table in 3.3. |
| `atomic/` grouped by stage | One flat directory per action | Spec dirs stay flat. The grouping is the `ActionCategory` of each action type. |
| `models/`, `config/`, `tools/` | Missing | `src/xdr_response/models/`, top-level `config/`, `tools/`. |
| `tests/unit`, `integration`, `simulation`, `fixtures` | Flat `tests/test_*.py` | New dirs added; existing `tests/test_*.py` stay where they are. |
| docs: architecture, approval-model, containment-model, rollback, integrations, threat-scoring, workflows/ | Only integrations.md | This file now; the others in Phases 0 and 1 (section 3). |
| LICENSE, CHANGELOG, CONTRIBUTING, SECURITY | Missing | Added in Phase 0. |
| Example config under `config/` | `.env.example` and `docs/deployment/guardrails.example.yaml` | `config/*.yaml` added; the old files stay until Phase 1 removes `auto_approve`. |
| (not in brief) | `pyproject.toml` packages only `engine/`; CI uses Python 3.12 | Add `src` to package discovery and `pythonpath`; code must run on Python 3.12 and 3.13. |

### 1.6 Known open issues inherited from the spec layer

- **Undocumented nested fields** used by rules (`item.detections[].disposition`, `item.signins[].ip/result`, `item.profile.groups`, `is_protected`, `isolation_capable`, `prevalence`, `hosts`). Phase 1 defines them in pydantic investigation models.
- **`incident.context` workarounds:** 13 workflows read 115 facts no atomic produces (`previously_revoked_users`, `fraud_senders`, `mailbox_rules`, `lookalike_domains`, `malicious_urls`, `targeted_endpoints`, ...). They become investigation outputs or evidence in Phases 1 to 5.
- **Allow-lists are not per action.** `url_check` applies the domain allow-list, so a malicious path on an owned domain is always skipped. `allowlists.yaml` separates `never_block` from `url_block_allowed_domains`.
- **Rollback endpoints in templates were unverified.** Any endpoint not VERIFIED in `docs/integrations.md` raises `UnverifiedEndpointError` (a `NotImplementedError`). (`DELETE /v1/computers/{guid}/isolation` is now VERIFIED.)

---

## 2. Proposed architecture

### 2.1 Principles

1. **One framework, many workflows.** Workflows (Phases 2 to 5) are data: plan rules, scoring weights, MITRE mapping, scenarios. They call shared atomic operations; they never contain vendor HTTP code or approval logic.
2. **Enforcement in code, at the lowest layer.** Every state-changing adapter method is wrapped by `@state_changing`, and the HTTP client refuses any `STATE_CHANGING` request outside an authorized context. A bug or a prompt in a higher layer cannot cause a state change.
3. **Fail closed.** No verifier registered, dry run active, expired token, any mismatch, audit unavailable: the state change is refused.
4. **Native first.** Where Cisco XDR has a native response action (section 4), it is the preferred execution path, through the VERIFIED Response API trigger, wrapped by the guard.
5. **Vendor logic behind adapters.** No endpoint is implemented unless `docs/integrations.md` lists it as VERIFIED with a source.
6. **Evidence is data from sources, never from AI.** AI narratives are stored separately and flagged.
7. **Dry run by default.** `dry_run` defaults to `true` in config and in the guard itself.

### 2.2 Lifecycle state diagram

The brief's stages DETECT through GENERATE CONTAINMENT PLAN run inside `NOT_STARTED` (automatic, read-only). The 12 states and the transitions below are exactly `ALLOWED_TRANSITIONS` in section 13.9.

```mermaid
stateDiagram-v2
    [*] --> NOT_STARTED: incident detected
    note right of NOT_STARTED
        Automatic and read-only:
        investigation, enrichment, correlation,
        scoping, risk and confidence scoring,
        containment plan generation
    end note
    NOT_STARTED --> AWAITING_APPROVAL: containment package proposed
    NOT_STARTED --> CLOSED: nothing to contain, analyst closes
    AWAITING_APPROVAL --> APPROVED: HUMAN approves all or selected, signed token
    AWAITING_APPROVAL --> NOT_STARTED: more investigation requested or package expired
    AWAITING_APPROVAL --> CLOSED: REJECT
    APPROVED --> CONTAINMENT_RUNNING: automatic, no further human step
    APPROVED --> CONTAINMENT_FAILED: token refused at execution
    CONTAINMENT_RUNNING --> CONTAINED: all approved actions effective and verified
    CONTAINMENT_RUNNING --> PARTIALLY_CONTAINED: some effective
    CONTAINMENT_RUNNING --> CONTAINMENT_FAILED: none effective
    PARTIALLY_CONTAINED --> AWAITING_APPROVAL: new package for remaining actions
    CONTAINMENT_FAILED --> AWAITING_APPROVAL: new package
    CONTAINED --> REMEDIATION_REQUIRED
    PARTIALLY_CONTAINED --> REMEDIATION_REQUIRED
    CONTAINMENT_FAILED --> REMEDIATION_REQUIRED
    REMEDIATION_REQUIRED --> AWAITING_APPROVAL: remediation package needs human approval
    CONTAINED --> AWAITING_RELEASE_APPROVAL: release package proposed
    PARTIALLY_CONTAINED --> AWAITING_RELEASE_APPROVAL
    REMEDIATION_REQUIRED --> AWAITING_RELEASE_APPROVAL
    AWAITING_RELEASE_APPROVAL --> RESTORATION_RUNNING: HUMAN APPROVE RELEASE, release token
    AWAITING_RELEASE_APPROVAL --> REMEDIATION_REQUIRED: release rejected or more work
    AWAITING_RELEASE_APPROVAL --> CLOSED: analyst closes, controls stay active
    RESTORATION_RUNNING --> RESTORED: all selected controls released and verified
    RESTORATION_RUNNING --> AWAITING_RELEASE_APPROVAL: partial or failed release
    RESTORED --> AWAITING_RELEASE_APPROVAL: other controls still active
    RESTORED --> CLOSED
    CONTAINED --> CLOSED
    PARTIALLY_CONTAINED --> CLOSED
    CONTAINMENT_FAILED --> CLOSED
    REMEDIATION_REQUIRED --> CLOSED
    CLOSED --> AWAITING_RELEASE_APPROVAL: release controls of a closed incident
    CLOSED --> NOT_STARTED: reopen
    CLOSED --> [*]
```

Closing an incident never removes controls. `CLOSED` keeps every `ACTIVE` registry entry, and `CLOSED -> AWAITING_RELEASE_APPROVAL` exists so they can still be released later, with a human release approval.

### 2.3 Component diagram

```mermaid
flowchart LR
    subgraph XDR["Cisco XDR (SaaS)"]
        INC[Incidents and sightings]
        RULES[Automation rules: new incident, webhook, schedule]
        TASK[Request Approval task: notification only]
        RESP[Response API: respond/observables, respond/trigger]
    end

    subgraph ORCH["External orchestrator: src/xdr_response"]
        LC[lifecycle: state machine, orchestrator, stores]
        INV[investigation and enrichment: adapters READ]
        SC[scoring: design-only in Phase 0]
        PB[approval.package: PackageBuilder, CriticalAssetPolicy]
        AE[approval: ApprovalEngine, ApproverAuthenticator, ApprovalTokenService, TokenUseLedger]
        G[guard.py: contextvar execution guard, state_changing]
        EX[execution: ContainmentExecutor, ActionRunner]
        VE[verification: VerificationEngine]
        REG[restoration: TemporaryControlRegistry, RestorationEngine]
        DR[dryrun: DryRunSimulator]
        RP[reporting: decision card, result table, release checklist]
        AU[audit: hash-chained JSONL and verifier]
        LG[logs: central redaction, JSON logging]
        SE[secrets: SecretProvider]
        CF[config: Settings and policies]
        AD[integrations: 16 adapters, GuardedHttpClient, health]
    end

    subgraph VENDORS["Vendor APIs"]
        V1[Secure Endpoint, Secure Email, Umbrella, Meraki, SMA, SCA]
        V2[Entra, Defender for Endpoint, Defender O365, Intune, Microsoft Cloud]
        V3[VirusTotal, OTX, HIBP, Splunk optional]
    end

    ANALYST((Human analyst))

    RULES -->|webhook or poll| LC
    INC --> INV
    LC --> INV --> SC --> PB --> LC
    LC --> RP --> ANALYST
    TASK -.link.-> ANALYST
    ANALYST -->|decision and credential| AE
    AE -->|signed token| LC
    LC -->|approved package and token, automatic| EX
    EX --> G
    G -->|re-verify token| AE
    EX --> AD
    EX --> VE --> AD
    EX --> REG
    LC --> DR
    AD -->|native actions| RESP
    AD --> V1
    AD --> V2
    AD --> V3
    AD --> SE
    EX --> AU
    AE --> AU
    LC --> AU
    REG --> AU
    AU --> LG
    CF --> LC
```

### 2.4 Layering and import rules

| Layer | Packages | May import |
|---|---|---|
| 0 Foundation | `errors`, `clock`, `models` | stdlib, pydantic |
| 1 Contracts | `interfaces`, `guard` | layer 0 |
| 2 Services | `config`, `secrets`, `logs`, `audit` | layers 0 and 1 |
| 3 Adapters | `integrations` | layers 0 to 2, httpx |
| 4 Engines | `approval`, `execution`, `verification`, `restoration`, `dryrun`, `reporting`, `scoring` | layers 0 to 3 |
| 5 Composition | `lifecycle` (state machine, orchestrator, runtime builder) | everything |

Inside the package, imports are absolute (`from xdr_response.models import RecommendedAction`). No module is named `logging` or `secrets` at top level; the subpackages `xdr_response.logs` and `xdr_response.secrets` are safe because every import is absolute. `guard.py` never imports `approval`: the verifier is injected with `guard.register_verifier(...)` by `lifecycle.runtime.build_runtime`. Phase 1 adds the atomics (4a) and workflows (4b) layers and the read-zone import rules of section 14.0.

---

## 3. Files and directories to create

### 3.1 Phase 0 tree (new files only; existing content is kept)

```
LICENSE  CHANGELOG.md  CONTRIBUTING.md  SECURITY.md
pyproject.toml                      (edit: package src/, add pydantic and httpx, pythonpath engine + src)
.github/workflows/ci.yml            (edit: run the whole tests/ tree, tools/validation checks)
.gitignore                          (edit: var/, config/*.yaml copies without .example)
config/
  integrations.example.yaml         runtime section + 16 integrations (splunk enabled: false)
  thresholds.yaml                   scoring bands, blast radius, approval, verification, execution, temporary controls
  exclusions.yaml                   third-party lookup exclusions (never sent to VirusTotal/OTX/HIBP)
  critical-assets.yaml              the 10 critical asset classes and their match rules
  allowlists.yaml                   never_block, url_block_allowed_domains, approved_rmm
docs/
  architecture.md                   this file
  approval-model.md  containment-model.md  rollback.md  threat-scoring.md   (Phase 0, condensed from sections 5-9)
  integrations.md                   exists: endpoint verification, source of truth
src/xdr_response/
  __init__.py  errors.py  guard.py  interfaces.py  clock.py
  models/        __init__.py enums.py canonical.py catalog.py observable.py evidence.py incident.py
                 recommendation.py approval.py action.py verification.py restoration.py audit.py
                 health.py investigation.py
  config/        __init__.py schema.py loader.py policy.py
  secrets/       __init__.py provider.py
  logs/          __init__.py redaction.py setup.py
  audit/         __init__.py trail.py verify.py summary.py events.py hashing.py keys.py locking.py forwarding.py
  integrations/  __init__.py base.py http.py auth.py registry.py health.py simulated.py _graph.py _adapter_support.py
                 cisco_xdr/ secure_endpoint/ secure_email/ secure_malware_analytics/ secure_cloud_analytics/
                 umbrella/ meraki/ entra/ defender_endpoint/ defender_o365/ intune/ microsoft_cloud/
                 virustotal/ alienvault_otx/ hibp/ splunk/        (each: __init__.py manifest.py adapter.py)
  approval/      __init__.py authenticator.py tokens.py ledger.py critical_assets.py package.py engine.py
  execution/     __init__.py runner.py executor.py outcome.py
  verification/  __init__.py engine.py
  restoration/   __init__.py registry.py planner.py engine.py
  dryrun/        __init__.py simulator.py
  reporting/     __init__.py decision_card.py containment_report.py release_checklist.py
  lifecycle/     __init__.py states.py machine.py store.py investigation.py recommendation.py orchestrator.py runtime.py
  scoring/       __init__.py README.md                             (design-only in Phase 0)
tests/                                                             (as built; the Phase 0 plan listed other file names, see 10)
  test_repo.py conftest.py                                         (autouse fixture: guard._reset_for_test_harness())
  fixtures/      __init__.py factories.py http_mocks.py principals.py guard_helpers.py degraded.py
                 incidents/*.yaml  workflows/<id>/*.yaml  sample_workflows/  (fake data only)
  unit/          approval/ atomics/ audit/ core/ dryrun/ execution/ integrations/ legacy/ lifecycle/
                 reporting/ restoration/ scoring/ vendors/ verification/ workflows/
                 (vendors/: every real adapter over httpx.MockTransport, one file per vendor family)
  integration/   test_lifecycle_http_adapters.py test_atomics_scoring_evidence.py
                 test_cross_workflow_correlation.py _fake_vendors.py
  simulation/    test_dry_run_scenarios.py test_lifecycle_end_to_end.py test_workflow_scenarios.py
                 test_docs_samples.py test_production_parity.py
  workflows/     <workflow>/test_*_hooks.py test_*_lifecycle.py   (per-workflow behaviour)
  safety/        test_approval_bypass.py test_execution_integrity.py test_restoration_authority.py
                 test_secrets_and_audit.py test_read_zone.py test_phase1_atomics.py test_phase1_evidence.py
                 test_p2_workflows.py test_p3_workflows.py test_p4_workflows.py test_p5_workflows.py
                 test_degraded_sources.py
tools/                                                             (as built)
  simulator/     README.md simulate.py scenario.py workflow_scenario.py (fixture incident or workflow scenario end to end, dry run or simulated live)
  validation/    README.md validate_config.py verify_audit_chain.py check_endpoints.py check_workflow_readmes.py generate_workflow_docs.py
  deployment/    xdr-trigger-workflow.md forward_audit.py   (XDR trigger workflow, incident ID only; scheduled audit forwarding to Splunk HEC, 14.14.4)
var/                                             (git-ignored runtime data: audit, registry, ledger)
```

### 3.2 Phase 1 additions (for completeness)

`src/xdr_response/lifecycle/plan_bridge.py` (xdr_plan `Plan` to `ProposedAction`), `src/xdr_response/scoring/engine.py`, investigation models for the nested fields in 1.6, XDR workflow JSON exports under `workflows/<name>/xdr/`, `docs/workflows/`, spec alignment for conflicts C1 to C5 (atomic YAML, scenarios, planner) with the matching test updates.

### 3.3 Spec names to runtime names (integration and atomic dirs are not renamed; two workflow dirs are renamed in Phase 1, 14.5)

| Spec dir (`integrations/`) | Adapter (`src/xdr_response/integrations/`) |
|---|---|
| cisco-xdr | cisco_xdr |
| secure-endpoint | secure_endpoint |
| secure-email | secure_email |
| umbrella | umbrella |
| microsoft-entra | entra |
| meraki | meraki |
| splunk | splunk (optional, disabled by default) |
| cloudflare, servicenow | none in Phase 0 (optional add-ons) |
| (none yet) | secure_malware_analytics, secure_cloud_analytics, defender_endpoint, defender_o365, intune, microsoft_cloud, virustotal, alienvault_otx, hibp |

| Spec atomic (`atomic/`) | `ActionType` |
|---|---|
| isolate-endpoint | `isolate_endpoint` |
| block-domain / block-url / block-ip / block-hash | `block_domain` / `block_url` / `block_ip` / `block_hash` |
| disable-user | `disable_user` |
| revoke-session | `revoke_sessions` |
| quarantine-email | `quarantine_email` |
| enrich-hash / enrich-domain / enrich-ip | `enrich_hash` / `enrich_domain` / `enrich_ip` |
| investigate-host / investigate-user | `investigate_endpoint` / `investigate_user` |
| create-ticket / notify-soc | `create_ticket` / `notify_soc` |

| Spec workflow (`workflows/`) | Brief name |
|---|---|
| powershell | malicious-powershell (directory renamed in Phase 1, 14.5) |
| rmm | unauthorized-rmm (directory renamed in Phase 1, 14.5) |
| password-spray | password spraying |
| vulnerability-exploitation, web-attacks | add-ons, not in the brief |

---

## 4. Cisco XDR integration strategy

Based on `docs/integrations.md` (research date 2026-10-06). Every statement about an endpoint below refers to its status there.

### 4.1 What runs in XDR Automation and what runs in the external orchestrator

| Concern | Cisco XDR Automation | External orchestrator (`xdr_response`) |
|---|---|---|
| Detection, incident creation | Yes (XDR incidents and sightings; Secure Cloud Analytics alerts arrive as XDR incidents) | Reads them (incident summary and full incident view: VERIFIED) |
| Trigger | An automation rule on **new incident**, or a **webhook** rule, starts a small XDR workflow that sends the incident ID to the orchestrator; alternatively the orchestrator polls. Webhook limits (1 MB, 25 runs/min) come from search summaries and must be re-read before production. | Accepts only the incident ID from the trigger and re-reads the incident through the API. |
| Investigation, enrichment, correlation, scoping, scoring | Not used for decisions (no documented workflow schema or result guarantees) | Yes, through read-only adapters |
| Containment plan and evidence | No | Yes (`PackageBuilder`) |
| Analyst decision UI | Optional. A **Request Approval** task may notify the analyst and link to the orchestrator decision page. An XDR task approval **never authorizes anything by itself**: no binding to evidence, parameters, targets or human identity is documented, and no REST API to act on tasks is VERIFIED. | The decision goes to `ApprovalEngine` with an authenticated human credential. The HMAC token is the only authorization. |
| Execution of native actions | The native response action runs inside XDR when triggered | The orchestrator triggers it with `POST /iroh/iroh-response/respond/trigger/{module-instance-id}/{action-id}` (VERIFIED) inside `guard.authorized(...)` |
| Execution of non-native actions | No | Direct adapter calls: Entra revoke sessions, confirm compromised, role removal; Meraki; Intune; Secure Email Threat Defense release |
| Verification | The native trigger only returns `success` / `failure` | Product read calls (section 7) |
| Restoration | Native restore actions exist | Triggered only with a release token, built from registry entries |
| Incident notes and status | Worklog note path UNVERIFIED; status update VERIFIED on the Global Intelligence host only | Bookkeeping operations; unverified paths raise `UnverifiedEndpointError` |
| Audit | Run history, worklog, 72-hour trigger history (not tamper-evident) | Hash-chained JSONL audit trail (authoritative) |
| Secrets | Account keys and Secure Strings for XDR-side workflows | `SecretProvider` (environment or vault); never in code or config |
| Version control | Workflow JSON exports (Git commit from the editor), without secure-string values | Python code, YAML example config, workflow specs |

### 4.2 Native-first execution path

For action types with a native workflow in section 1.4 of `docs/integrations.md` (isolate, disable user, block domain/URL/IP, block hash, quarantine email, delete email for Defender for O365, and the matching restore actions), the preferred adapter is `cisco_xdr`:

1. **Plan time (read-only).** `CiscoXdrAdapter.list_response_actions(observable)` calls `POST /iroh/iroh-response/respond/observables` (VERIFIED, `OperationKind.READ`) and selects the action whose module matches the configured product. Its `module_instance_id` and `action_id` go into the recommendation `params`, with `observable_type`, `observable_value` and `verify_integration` (the product adapter that can read back state). `params` are hashed into the approval token, so the analyst approves exactly this module and action.
2. **Execution.** `CiscoXdrAdapter.execute(request)` dispatches to the `@state_changing` method for the action type, which calls `respond/trigger` with `kind=OperationKind.STATE_CHANGING`. The decorator re-verifies the token before the call, and the HTTP client checks the guard again.
3. **Verification.** `respond/trigger` returns only `success` / `failure`, so `VerificationEngine` calls `verify` on the `verify_integration` adapter (for example `defender_endpoint` for isolation through MDE). If that product has no VERIFIED read call, the result is `UNABLE_TO_VERIFY`.
4. **Registry.** The control is registered with `integration="cisco_xdr"`, the module-instance ID and the action ID. At release time the restore action is looked up the same way and bound into the release token.

The direct product adapter is chosen instead when (a) no native action exists, (b) the native module is not configured for the tenant, or (c) the package states a reason (for example direct MDE isolation returns a machine-action ID that can be verified). The choice is recorded in `params["integration"]` and is therefore part of what the analyst approves.

### 4.3 Coverage by action type

| Action type | Native XDR | Direct adapter (VERIFIED endpoint) | Verify |
|---|---|---|---|
| isolate_endpoint / release_endpoint | Yes (Secure Endpoint, MDE) | secure_endpoint PUT/DELETE isolation; defender_endpoint isolate/unisolate | MDE machine action: VERIFIED. Secure Endpoint isolation GET: UNVERIFIED, so `UNABLE_TO_VERIFY` |
| block_domain / unblock_domain, block_url / unblock_url | Yes (Umbrella, Secure Access) | umbrella destination lists (store the destination ID); defender_endpoint indicators | Umbrella list GET: VERIFIED. MDE indicator GET: UNVERIFIED |
| block_ip / unblock_ip | Yes (IPv4 only) | meraki MX L3 (read-modify-write, serialized per network); defender_endpoint indicators. Direct Umbrella IP blocking: UNVERIFIED/CONFLICT, not implemented | Meraki L3 GET: VERIFIED |
| block_hash / unblock_hash | Yes (Secure Endpoint, MDE) | defender_endpoint indicators. Secure Endpoint file lists: UNVERIFIED | `UNABLE_TO_VERIFY` until the MDE indicator GET is verified |
| disable_user / enable_user | Yes (Entra, Duo) | entra PATCH `accountEnabled` | entra GET user: VERIFIED |
| revoke_sessions | **No** | entra `revokeSignInSessions` | `signInSessionsValidFromDateTime` at or after the action time: VERIFIED |
| confirm_user_compromised | **No** | entra `riskyUsers/confirmCompromised` (P2 licence) | riskyUser GET UNVERIFIED, so `UNABLE_TO_VERIFY` |
| remove_privileged_role / restore_privileged_role | **No** | entra roleAssignments DELETE / POST (always ELEVATED) | roleAssignments list: VERIFIED |
| quarantine_email / release_email | Quarantine yes (ETD, Defender O365); native release only for Defender O365 | secure_email `messages/move` (`inbox` for release); defender_o365 `analyzedEmails/remediate` | ETD `messages/status`: VERIFIED. Defender O365: `UNABLE_TO_VERIFY` |
| delete_email | Yes (Defender O365 only) | defender_o365 `softDelete` / `moveToDeletedItems` (never `hardDelete`); secure_email move to `trash` | as above |
| block_network_client / restore_network_client | **No** | meraki client policy PUT (capture the previous policy first) | client policy GET: VERIFIED |
| lock_device | **No** | intune `remoteLock` | `UNABLE_TO_VERIFY` (actionName unknown) |
| terminate_process, quarantine_file, restore_file, remove_persistence, reset_password, reset_mfa, revoke_app_credentials, remove_application | **No** | none VERIFIED: the method raises `UnverifiedEndpointError` | n/a |

### 4.4 Rules for every adapter

- Implement only endpoints marked VERIFIED in `docs/integrations.md`, and copy the source URL into the operation's `OperationSpec.source`. `tools/validation/check_endpoints.py` cross-checks every manifest against the document.
- An UNVERIFIED operation raises `UnverifiedEndpointError`, whose message is exactly `unverified endpoint: <integration>.<operation> - see docs/integrations.md`. It subclasses `NotImplementedError`.
- Every call supports timeout, retry with exponential backoff, `429` with `Retry-After`, client-side rate limiting (VERIFIED limits: Umbrella policies 2000/min, Meraki 10 req/s per org, MDE 100/min and 1,500/h, VirusTotal public 4/min and 500/day; unknown limits rely on backoff), auth failure (one token refresh on 401; 403 is not retried), integration unavailable and invalid target.
- URLs are logged with query strings redacted (Secure Malware Analytics sends `api_key` in the query string).
- VirusTotal, OTX and HIBP receive only observables allowed by `DisclosurePolicy` (`config/exclusions.yaml`): never internal hostnames, internal URLs, internal domains or private IPs; HIBP receives only the investigated account. VirusTotal's public API is non-commercial only; the example config marks it as such.
- Meraki L3 writes replace the whole rule set: read, change exactly one rule tagged with the idempotency key, write, verify. Writes are serialized per network with a lock.
- Vendor-side expiry (`expirationTime` on MDE indicators and similar) is **not** set by default: an automatic expiry is a release without a human release approval. It can be enabled only through an explicit per-integration option, documented as such.
- Secure Cloud Analytics has no VERIFIED endpoint: its alerts are read as Cisco XDR incidents; all its adapter methods raise `UnverifiedEndpointError` and its health is `UNKNOWN`.

---

## 5. Approval architecture

### 5.1 Flow

```mermaid
sequenceDiagram
    participant O as ResponseOrchestrator
    participant PB as PackageBuilder
    participant A as Analyst (HUMAN)
    participant AE as ApprovalEngine
    participant AU as ApproverAuthenticator
    participant TS as ApprovalTokenService
    participant EX as ContainmentExecutor
    participant G as guard
    O->>PB: build(incident, proposals, evidence, scores)
    PB-->>O: ContainmentPackage (keys, levels, warnings, evidence hash)
    O->>A: decision card (reporting)
    A->>AE: DecisionRequest + ApproverCredential(s)
    AE->>AU: authenticate(credential)
    AU-->>AE: AuthenticatedPrincipal (kind, roles)
    AE->>AE: HUMAN only, roles, quorum, keys subset of package, evidence hash recomputed
    AE->>TS: issue(package, decision, approvers)
    TS-->>AE: ApprovalToken (HMAC-SHA256)
    AE-->>O: ApprovalOutcome (decision, token)
    O->>EX: execute(package, token) automatically
    EX->>G: authorized(token, ActionRequest)
    G->>TS: verify(token, purpose, binding) and mark_used
    G-->>EX: AuthorizationContext
```

### 5.2 Containment package

`ContainmentPackage` (section 13.5) carries: incident, endpoints, users, severity, `risk_score`, `confidence_score`, a summary, numbered evidence, the evidence snapshot hash, blast radius, excluded targets (allow-listed, with reason) and the `RecommendedAction` checklist. Each action has numbered sourced evidence, its own `risk_score` and `confidence_score`, the idempotency key `<incident_id>:<action_type>:<target>`, `params` (including `params["integration"]`) and `approval_level`.

`PackageBuilder` rules (deterministic, in this order):

1. Reject any proposal whose action type is not `state_changing` (read-only work never needs a package).
2. Normalize the target (`normalize_target`), compute the idempotency key, drop exact duplicates by key (keeping the higher risk score and merging evidence).
3. `AllowlistPolicy.excluded_reason(...)`: allow-listed targets move to `excluded_targets` with the reason. They are shown on the decision card, never dropped silently.
4. `CriticalAssetPolicy.evaluate(...)`: any match sets `approval_level=ELEVATED` and attaches a `CriticalAssetWarning` with asset, asset class, role, action and potential impact. Never blocked.
5. `ActionSpec.always_elevated` (privileged role removal and restore) sets `ELEVATED`.
6. Blast radius over the `thresholds.yaml` caps sets `ELEVATED` on every action of the capped kind, with a warning. Nothing is removed.
7. Number the evidence (1..n, stable order: source, observed_at, summary), compute `evidence_snapshot_hash`, set `expires_at = now + package_ttl`.

### 5.3 Analyst decisions

| Decision | Approved keys | Rejected keys | Token | Comment | Next state |
|---|---|---|---|---|---|
| `APPROVE_ALL` | all package keys | none | issued | optional | `APPROVED`, then automatic execution |
| `APPROVE_SELECTED` | non-empty strict or full subset given by analyst | the rest (computed; if given it must equal the rest) | issued for approved keys only | optional | `APPROVED`, then automatic execution |
| `REJECT` | none | all | none | **required** | containment: `CLOSED`; release: `REMEDIATION_REQUIRED` (controls stay `ACTIVE`; the analyst may close the incident afterwards) |
| `REQUEST_MORE_INVESTIGATION` | none | none | none | **required** | containment: `NOT_STARTED` (a new package will be built); release: `REMEDIATION_REQUIRED` |

Every decision is recorded as `AnalystDecision`: incident ID, analyst identity (all approver principals), timestamp, approved and rejected keys, comment, workflow ID and version, evidence snapshot hash, package ID, purpose and token ID. It is written to the audit trail **before** the token is returned. If the audit write fails, no token is issued (`AuditError`).

### 5.4 Who may approve

- Approvers are authenticated by a pluggable `ApproverAuthenticator` (`authenticate(credential) -> AuthenticatedPrincipal`). Phase 0 ships the protocol and `InMemoryApproverAuthenticator` (tests, lab and simulator: principals and salted secret hashes configured in code or fixtures, never in repo config). Production authenticators (OIDC/SSO) are added behind the same protocol.
- Only `PrincipalKind.HUMAN` may approve. `SERVICE`, `AUTOMATION` and `AI` are rejected with `ApproverNotAllowedError`, regardless of roles, and the denial is audited (`APPROVAL_DENIED`). The check is repeated in the token verifier.
- `STANDARD` actions need `standard_min_approvers` (default 1) distinct humans holding `standard_role` (default `xdr-approver`).
- `ELEVATED` actions need `elevated_min_approvers` (default 1) distinct humans holding `elevated_role` (default `xdr-elevated-approver`). If the elevated quorum is not met, `APPROVE_ALL` fails and `APPROVE_SELECTED` must exclude the elevated actions.
- Self-approval: when `package.requested_by` is a human principal, that principal does not count toward the quorum unless `allow_self_approval: true` (default false). Packages built by automation have `requested_by="automation:<component>"`.
- The decision must reference only keys present in the package, the package must not be expired, and its evidence hash is recomputed and must match `evidence_snapshot_hash` (a modified package is refused).

### 5.5 Approval token

`ApprovalToken` = `ApprovalTokenClaims` + `key_id` + `alg="HMAC-SHA256"` + `signature`.

- Claims (exactly): `version=1`, `token_id`, `purpose` (`"containment"` or `"release"`), `package_id`, `incident_id`, `evidence_snapshot_hash`, `workflow_id`, `workflow_version`, `decision_id`, `actions` (per action: `idempotency_key`, `action_type`, `target`, `params_hash`, `approval_level`), `approvers` (per approver: `principal_id`, `kind`, sorted `roles`), `issued_at`, `expires_at`.
- `signature = HMAC-SHA256(key, b"xdr-response/approval-token/v1\n" + canonical_json(claims))`, hex. Comparison uses `hmac.compare_digest`.
- `canonical_json`: UTF-8, `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`, datetimes as UTC ISO 8601 with `Z`, enums as their values, tuples as lists, no floats in signed data.
- Key: `SecretProvider.get("APPROVAL_SIGNING_KEY")`, at least 32 bytes after UTF-8 encoding, otherwise `ConfigError`. Optional `APPROVAL_SIGNING_KEY_PREVIOUS` is accepted for verification only (rotation). `key_id` comes from config (`approval.signing_key_id`, default `"primary"`). The key is never in code, config files, logs or audit.
- TTL: `containment_token_ttl_minutes` (default 30) and `release_token_ttl_minutes` (default 30). Execution starts immediately after approval, so a short TTL is enough. Maximum accepted lifetime is enforced at verification (`expires_at - issued_at <= ttl`).
- Serialization (`encode()` / `decode()`): `base64url(canonical_json(claims)) + "." + key_id + "." + signature`. The token is a bearer secret: `signature`, `approval_token` and `token` keys are redacted everywhere. The audit trail stores `token_id` and the claims hash, never the signature.

### 5.6 Token verification (deterministic, fail closed)

`ApprovalTokenService.verify(token, *, purpose, binding)` raises a subclass of `ApprovalRequiredError` on the first failed check:

1. `alg == "HMAC-SHA256"` and `key_id` known, else `TokenInvalidError`.
2. Signature valid over the claims, else `TokenInvalidError`.
3. `issued_at <= now + clock_skew`, `now < expires_at`, lifetime within TTL, else `TokenExpiredError`.
4. `claims.purpose == purpose`, where `purpose` comes from the action catalog (`ActionSpec.purpose`) and never from the caller's input, else `TokenMismatchError`.
5. `claims.incident_id == binding.incident_id`, else `TokenMismatchError`.
6. A grant exists with `idempotency_key == binding.idempotency_key`, and its `action_type`, `target` and `params_hash` all equal the binding, else `TokenMismatchError`.
7. Approvers non-empty, distinct, all `HUMAN`; quorum and elevated role rules of 5.4 hold for the grant's `approval_level`, else `TokenInvalidError` (a correctly signed token with such claims can only come from a bug or a stolen key, so it is treated as invalid).
8. `mark_used(token, idempotency_key)` (only from `guard.authorized`) consumes the pair in the `TokenUseLedger`; a second use raises `TokenReplayError`.

`verify_package(token, package)` additionally checks `package_id`, `evidence_snapshot_hash` (recomputed from the package evidence), `workflow_version` and that every grant matches the package action with the same key. The executor calls it once before any action.

### 5.7 Execution guard (`guard.py`)

- A `ContextVar[AuthorizationContext | None]` holds the current authorization; a second `ContextVar[bool]` holds a per-run dry-run flag; a module-level flag holds the global dry-run setting, **default `True`** until `guard.configure(dry_run=False)` is called by `build_runtime` from settings.
- `guard.authorized(token, action)` is a context manager. It refuses (raises) if no verifier is registered (`ApprovalRequiredError`), dry run is active (`DryRunViolationError`), an authorization is already active (nesting is not allowed), or verification fails (section 5.6). On success it consumes the token use and sets the context var; it resets it on exit, even on exceptions.
- `@state_changing` wraps every state-changing adapter method. The wrapped method takes an `ActionRequest` as first argument after `self`. Before calling it, the decorator requires an active context whose binding equals the request's binding, whose `params["integration"]` equals the adapter name, and re-verifies the token (without consuming). Otherwise `ApprovalRequiredError` (or a subclass). This holds even if the method is called directly.
- `GuardedHttpClient` calls `guard.require_active_authorization(integration)` before every attempt of a `STATE_CHANGING` request, so a vendor write cannot be sent from an unguarded method either.
- Dry run: `guard.dry_run()` context manager enables it per run; it can only switch dry run **on**, never off. With dry run active, every state-changing path raises `DryRunViolationError`, even with a valid token.

### 5.8 Release approval

Release uses the same engine with `purpose="release"`. A `ReleasePackage` is built only from `ACTIVE` registry entries (section 8). A containment token can never authorize a release action and vice versa, because the purpose is derived from the action catalog. The release checklist (restore endpoint connectivity, re-enable Entra account, remove temporary Umbrella domain block, remove temporary IP block, remove temporary hash block) is rendered from the release package, with `[APPROVE RELEASE]`.

---

## 6. Containment execution architecture

### 6.1 Automatic start

`ResponseOrchestrator.submit_decision(...)` transitions `AWAITING_APPROVAL -> APPROVED`, then immediately `APPROVED -> CONTAINMENT_RUNNING` and calls `ContainmentExecutor.execute(package, token)`. There is no other human step and no queue that a human must release. The only thing that can stop approved actions from executing is a failed safety check (token, guard, audit), which yields `CONTAINMENT_FAILED` with the reason.

### 6.2 Per-action pipeline (`ActionRunner.run`)

For each approved action, in package order (sequential in Phase 0; per-integration concurrency is a later option):

1. Build `ActionRequest.from_recommendation(action)`; select the adapter by `params["integration"]`. If the integration is disabled or missing: `SKIPPED` (`NO_CAPABLE_ADAPTER` or `INTEGRATION_DISABLED`), requires attention.
2. Audit `ACTION_STARTED`. If the audit write fails, the action is not executed: `FAILED` with `ErrorCode.AUDIT_UNAVAILABLE`.
3. `with guard.authorized(token, request):`
   1. `adapter.current_state(request)` (read-only). `IN_DESIRED_STATE` returns `ALREADY_CONTAINED`; no vendor write, **no registry entry** (the control was not created by this automation).
   2. Otherwise `adapter.execute(request)` returns an `ActionOutcome` (`SUCCESS` with `external_ref` and `rollback_params`, or raises).
   3. Integration exceptions map to `FAILED` with `ErrorInfo` (`TIMEOUT`, `RATE_LIMITED`, `AUTH_FAILED`, `UNAVAILABLE`, `INVALID_TARGET`, `API_ERROR`, `UNVERIFIED_ENDPOINT`, `NOT_SUPPORTED`) and the manifest's `escalation_hint` (for example "Microsoft 365 administrator" on a 403 from Graph).
4. Outside the guard context: `VerificationEngine.verify(request, outcome)` (section 7) for `SUCCESS` and `ALREADY_CONTAINED`.
5. If `SUCCESS` and the catalog says `creates_control`: `TemporaryControlRegistry.register(...)` with the rollback action type and `rollback_params`, then audit `CONTROL_REGISTERED`.
6. Audit `ACTION_RESULT` and `VERIFICATION_RESULT` with redacted API summaries.

Every exception inside one action is caught and recorded; it never stops the next action. Package actions that were not approved are reported as `SKIPPED` with `REJECTED_BY_ANALYST` and are excluded from the overall calculation.

### 6.3 Idempotency and double-execution protection

| Layer | Mechanism |
|---|---|
| Key | `<incident_id>:<action_type>:<target>`, target normalized (section 13.3), for example `XDR-83921:isolate_endpoint:TH-LT-1047` |
| Token | `TokenUseLedger` consumes `(token_id, idempotency_key)` once; replay raises `TokenReplayError` |
| Adapter | `current_state` pre-check returns `ALREADY_CONTAINED`; MDE "Action is already in progress" maps to `ALREADY_CONTAINED`; Umbrella checks list membership; Meraki finds its tagged rule |
| HTTP | State-changing requests are retried only when the request was provably not sent (connect error) or the server said so (`429`, `503` with `Retry-After`). A read timeout on a write is **not** blindly retried: the runner re-checks `current_state` |
| Registry | `register` is idempotent by key; an `ACTIVE` entry for the same key is returned unchanged |
| Lifecycle | `APPROVED -> CONTAINMENT_RUNNING` happens once per package; the package store marks the package `EXECUTED` |

A failed action is never retried later with the same token. Retrying needs a new package and a new human approval.

### 6.4 Overall result

`compute_containment_overall(results, unable_to_verify_counts_as_contained)` considers only approved actions that were not `SKIPPED` for `REJECTED_BY_ANALYST`:

- An action **failed** when its status is `FAILED`, or `SKIPPED` for any reason other than `REJECTED_BY_ANALYST`, or its verification is `NOT_VERIFIED`.
- An action is **confirmed** when its status is `SUCCESS` or `ALREADY_CONTAINED` **and** its verification is `VERIFIED` (or `UNABLE_TO_VERIFY` when the threshold flag `verification.unable_to_verify_counts_as_contained` is true; default **false**). `is_effective(...)` in 13.16 returns "confirmed".
- Every action failed: `CONTAINMENT_FAILED`. Every action confirmed: `CONTAINED`. Anything else (including executed but unverifiable actions with the flag false): `PARTIALLY_CONTAINED`.
- One unrelated integration failing never turns the whole run into `CONTAINMENT_FAILED` while other actions succeeded.
- `UNABLE_TO_VERIFY` actions always appear as "requires attention: verify manually" on the result table.
- Dry-run executions have no overall containment state; the incident stays where it was.

### 6.5 Result table (reporting)

```
CONTAINMENT RESULT  XDR-83921  PARTIALLY_CONTAINED
Action                                   Status             Verification       Note
isolate_endpoint TH-LT-1047              SUCCESS            VERIFIED
block_domain evil.example.com            SUCCESS            VERIFIED
revoke_sessions jsmith@example.com       FAILED             -                  HTTP 403 (AUTH_FAILED)
Requires attention: revoke_sessions jsmith@example.com
Recommended escalation: Microsoft 365 administrator
```

### 6.6 Error handling contract (every external call)

| Condition | HTTP client behaviour | Exception | Health |
|---|---|---|---|
| Timeout | retry (reads); state-changing: no blind retry | `IntegrationTimeoutError` | `DEGRADED` |
| `429` | honour `Retry-After`, else exponential backoff with jitter, up to `max_retries` | `RateLimitedError(retry_after)` | `RATE_LIMITED` |
| `401` | invalidate token, refresh once, retry once | `AuthFailedError` | `AUTH_FAILED` |
| `403` | no retry | `AuthFailedError(http_status=403)` | `AUTH_FAILED` |
| `404`, `400` on target lookup | no retry | `InvalidTargetError` | unchanged |
| other `4xx` | no retry | `ApiError` | unchanged |
| `5xx`, connect error | retry with backoff | `IntegrationUnavailableError` | `UNAVAILABLE` / `DEGRADED` |
| Unverified endpoint | never sent | `UnverifiedEndpointError` | unchanged |
| Already contained | adapter pre-check | (no exception) `ALREADY_CONTAINED` | unchanged |

---

## 7. Verification architecture

- `VerificationEngine.verify(request, outcome) -> VerificationResult` runs after every `SUCCESS` and `ALREADY_CONTAINED` action and after every restoration action. It uses only `READ` / `VERIFY` operations and never needs the guard.
- The verifying adapter is `params["verify_integration"]` when present (native XDR actions), else `params["integration"]`. `IntegrationAdapter.verify` must not assume it executed the action.
- Polling: up to `verification.timeout_seconds` (default 300) every `verification.poll_interval_seconds` (default 10), injected clock and sleep for tests. Asynchronous vendor actions (MDE machine actions, Entra session revocation delay) poll until a terminal state.
- Statuses:
  - `VERIFIED`: an independent read shows the desired state (for revoke sessions: `signInSessionsValidFromDateTime >= action time`).
  - `NOT_VERIFIED`: the read shows the state was not reached (terminal failure status, value still present after removal, account still enabled).
  - `UNABLE_TO_VERIFY`: no VERIFIED read call, unknown status values, the read failed, or polling timed out.
- Any exception during verification yields `UNABLE_TO_VERIFY` with the error recorded; it never raises out of the engine.
- Verification feeds the overall state (6.4). `NOT_VERIFIED` counts as not effective.
- The per-integration verify calls and their status are the table in section 3 of `docs/integrations.md`. Verify capability is declared per action type in the manifest (`verifiable_actions`); the engine returns `UNABLE_TO_VERIFY` immediately for undeclared ones.

---

## 8. Rollback architecture

### 8.1 Temporary control registry

`TemporaryControlRegistry` (Phase 0: `JsonlControlRegistry`, an append-only event log with an in-memory view; `SqliteControlRegistry`, an append-only table guarded by triggers; and `InMemoryControlRegistry` for tests and the simulator) records every control the automation created:

`control_key` (= idempotency key), `incident_id`, `action_type`, `target`, `target_kind`, `integration`, `workflow_id`, `workflow_version`, `package_id`, `token_id` (the approval), `decision_id`, `approval_level`, `created_at`, `rollback_action_type`, `rollback_params` (for example Umbrella destination ID, previous Meraki policy, Entra role assignment fields, ETD verdict, MDE indicator ID, XDR module-instance and restore action IDs), `external_ref`, `status` (`ACTIVE`, `RELEASE_PENDING`, `RELEASED`, `RELEASE_FAILED`), `review_due_at` (from `temporary_controls.review_after_hours`), `released_at`, `release_package_id`, `release_token_id`.

Rules:

- Only `SUCCESS` results of action types with `creates_control=True` are registered. `ALREADY_CONTAINED` is not registered, so a release never removes a control someone else created.
- Non-reversible actions (revoke sessions, confirm compromised, delete email, lock device, terminate process, remove persistence, password and MFA resets) create no control; they are in the audit trail only.
- Status changes are appended events (`REGISTERED`, `RELEASE_PENDING`, `RELEASED`, `RELEASE_FAILED`); entries are never deleted.
- `review_due_at` only produces a reminder ("release review due"). Nothing is released automatically, and closing an incident never changes the registry.

### 8.2 Release flow

1. `RestorationPlanner.build_release_package(incident_id, control_keys=None)` reads the controls still in force, `ACTIVE` or `RELEASE_FAILED` (all for the incident, or exactly the listed keys; unknown, `RELEASE_PENDING`, `RELEASED` or other-incident keys raise `RegistryError`). Each entry becomes a `RecommendedAction` with `action_type=rollback_action_type`, the same target, `params=rollback_params` (plus `integration` and `restores=<control_key>`), and `approval_level=ELEVATED` when the original was `ELEVATED` or the rollback spec is `always_elevated`. Its idempotency key is `<incident_id>:<rollback_action_type>:<target>`.
2. The analyst gets the release checklist and approves with purpose `"release"` (`AWAITING_RELEASE_APPROVAL -> RESTORATION_RUNNING`).
3. `RestorationEngine.execute(release_package, token)` re-reads each entry; if it is no longer in force (`ACTIVE` or `RELEASE_FAILED`) the action is `SKIPPED` (`CONTROL_NOT_ACTIVE`), which the overall calculation leaves out because there was nothing to release. Otherwise it marks `RELEASE_PENDING`, runs the rollback through `ActionRunner` (same guard, same pipeline), verifies, and marks `RELEASED` or `RELEASE_FAILED`.
4. Overall: all released and verified, `RESTORED`; otherwise the incident returns to `AWAITING_RELEASE_APPROVAL` and the remaining `ACTIVE` / `RELEASE_FAILED` entries need a new release approval.

### 8.3 Rollback catalog

| Control | Rollback action | Rollback params captured at containment |
|---|---|---|
| isolate_endpoint | release_endpoint | connector GUID or MDE machine ID; XDR restore action IDs if native |
| block_domain / block_url | unblock_domain / unblock_url | Umbrella destination list ID and destination ID; or MDE indicator ID |
| block_ip | unblock_ip | Meraki network ID and rule tag; or MDE indicator ID |
| block_hash | unblock_hash | MDE indicator ID; or XDR restore action IDs |
| disable_user | enable_user | user object ID |
| quarantine_email | release_email | ETD message IDs and original verdict; or Defender O365 networkMessageId and recipient |
| remove_privileged_role | restore_privileged_role | `roleDefinitionId`, `principalId`, `directoryScopeId` (read before the delete) |
| block_network_client | restore_network_client | previous `devicePolicy` and `groupPolicyId` |
| quarantine_file | restore_file | (endpoint UNVERIFIED; no implementation) |

---

## 9. Data models

All models are pydantic 2 (`ConfigDict(frozen=True, extra="forbid")` unless stated), with timezone-aware UTC datetimes. Section 13 gives the exact fields and signatures; this section explains them.

| Model | Purpose | Key fields |
|---|---|---|
| `Observable` | Normalized indicator | `type: ObservableType`, `value`, `source` |
| `EnrichmentResult` | Normalized enrichment (brief: `{type, value, risk_score, confidence, sources, verdict}`) | plus `integration`, `health`, `evidence`, `errors` |
| `EvidenceDraft` / `Evidence` | Sourced fact; `Evidence` adds `number` (1..n) | `source` (integration name, `analyst` or `temporary_control_registry`; never AI), `summary`, `observed_at`, `reference`, `data`, `audit_ref` |
| `Incident` | Incident and lifecycle state | `incident_id`, `title`, `severity`, `state`, `workflow_id`, `workflow_version`, `observables`, `assets`, `users`, `trigger`, `ai_narrative` (flagged, never evidence), `history` |
| `RecommendedAction` | One checklist item | `incident_id`, `idempotency_key`, `action_type`, `target`, `target_kind`, `params`, `evidence`, `risk_score`, `confidence_score`, `approval_level`, `warnings`, `rationale` |
| `CriticalAssetWarning` | ELEVATED reason | `asset`, `asset_class`, `role`, `action_type`, `potential_impact`, `message` |
| `ContainmentPackage` / `ReleasePackage` | What the human approves | see 5.2 and 8.2 |
| `DecisionRequest` / `AnalystDecision` | Analyst input / recorded decision | see 5.3 |
| `AuthenticatedPrincipal`, `ApproverCredential` | Approver identity | `kind: PrincipalKind`, `roles` |
| `ApprovalToken`, `ApprovalTokenClaims`, `TokenActionGrant`, `ApproverClaim`, `ActionBinding` | Signed approval | see 5.5 |
| `ActionRequest` | What an adapter executes | `incident_id`, `idempotency_key`, `action_type`, `target`, `target_kind`, `params` |
| `ActionOutcome` | Adapter result | `status`, `external_ref`, `rollback_params`, `api_calls`, `message` |
| `ActionResult`, `ContainmentReport`, `RestorationReport` | Executor results | per action status, verification, error, attention, escalation; overall |
| `VerificationResult` | Verification outcome | `status`, `method`, `details`, `checked_at` |
| `TemporaryControl` | Registry entry | see 8.1 |
| `AuditRecord`, `ChainVerification`, `ExecutionAuditSummary` | Audit | see 13.12 |
| `IntegrationHealth` | Health | `integration`, `status: HealthStatus`, `checked_at`, `detail` |
| `ApiCallSummary`, `ErrorInfo` | Redacted API summary / normalized error | method, redacted URL, status code, duration, attempt / code, message, http status, retryable |

**Risk and confidence** are separate integers 0 to 100: `risk_score` is impact (what happens if this is real), `confidence_score` is evidence strength (how sure we are). Bands: 0-29 `LOW`, 30-59 `MEDIUM`, 60-79 `HIGH`, 80-100 `CRITICAL` (`risk_band(score)`); confidence is shown as a percentage.

**Scoring (design-only in Phase 0).** Phase 1 adds `xdr_response.scoring.engine.ScoringEngine.score(signals: Sequence[ScoringSignal], *, context: ScoringContext) -> ScoreBreakdown` (binding definition: 14.2), with configurable weights in `thresholds.yaml` (`scoring.weights`). Inputs: Secure Endpoint and Defender detections, VirusTotal, OTX, Umbrella, Secure Malware Analytics, Secure Cloud Analytics behaviour, authentication anomaly, network behaviour, email verdict, persistence, lateral movement, campaign association, critical asset involvement. Vendor reputation is one signal with a capped weight, never absolute truth. A failed source lowers confidence and is listed in the breakdown; it never blocks a recommendation backed by other evidence. Every contribution names the record ids of its evidence (14.1.2); the decision card maps them to evidence numbers, so it can explain the score.

**Decision card** (`reporting.render_decision_card(package)`):

```
CRITICAL INCIDENT  XDR-83921
Potential ransomware
Endpoint: TH-LT-1047
User: jsmith@example.com
Risk 97/100   Confidence 94%
Primary evidence:
  [1] secure_endpoint: ransomware detection on TH-LT-1047 (sha256 aaaa...)
  [2] umbrella: TH-LT-1047 resolved evil.example.com (malicious)
Blast radius: 1 endpoint, 1 user, 1 domain
Recommended containment:
  [ ] isolate_endpoint TH-LT-1047                (STANDARD)
  [ ] block_domain evil.example.com              (STANDARD)
  [ ] revoke_sessions jsmith@example.com         (STANDARD)
WARNING (ELEVATED APPROVAL REQUIRED): ...      (only when present)
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]
```

**Dry-run output** (`dryrun.render_dry_run(report)`), exact format:

```
DRY RUN
Would isolate: TH-LT-1047
Would block: evil.example.com
Would revoke sessions: jsmith@example.com
No containment actions executed.
```

---

## 10. Testing strategy

Run: `python -m pytest -q -p no:cacheprovider <paths>`. No test touches the network: every HTTP call goes through `httpx.MockTransport`; `respx` is not used. Test data uses only `example.com`, `*.example`, `*.test`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, fake 64-hex hashes and hosts like `TH-LT-1047`. (Phase 0 kept the 69 tests then in `tests/test_*.py` passing; the legacy plan-engine tests were retired after Phase 5, 14.4.3. The layout as built is in 3.1 and [docs/testing.md](testing.md).)

| Level | Location | What it proves |
|---|---|---|
| Unit | `tests/unit/<component>/test_*.py` | Each module in isolation: models and validators, canonical JSON and hashes, catalog completeness, config loading and refusals, secret providers, redaction, audit chain, guard, HTTP client retry/backoff/rate limit/error mapping, approval engine and token service, executor outcome logic, verification statuses, registry, restoration planner, dry-run rendering, decision card, state machine |
| Integration (mocked vendor APIs) | `tests/unit/vendors/test_*.py` (one file per vendor family: `test_cisco_xdr.py`, `test_cisco_products.py`, `test_entra.py`, `test_microsoft_security.py`, `test_umbrella_meraki.py`, `test_intel_splunk.py`, `test_vendor_auth.py`, `test_vendor_contracts.py`) and `tests/integration/test_lifecycle_http_adapters.py` | Each adapter against `httpx.MockTransport` handlers: request method/path/headers/body match `docs/integrations.md`, success, already-contained, 401 refresh, 403, 404, 429 with `Retry-After`, 5xx retry, timeout, unverified operations raise `UnverifiedEndpointError`, secrets never appear in captured logs |
| Workflow lifecycle | `tests/simulation/test_lifecycle_end_to_end.py`, `tests/unit/lifecycle/` | Full path NOT_STARTED to CLOSED with fake adapters: approve all, approve selected, reject, request more investigation, partial containment, failed containment, release approval, partial release, close keeps controls, reopen |
| Safety / bypass | `tests/safety/` | Containment cannot happen before approval, by any path (list below) |
| Workflow | `tests/workflows/<workflow>/test_*_definition.py`, `test_*_hooks.py`, `test_*_lifecycle.py` | Each workflow's definition, hook semantics and lifecycle run (dry run and simulated live through the orchestrator) |
| Integration (runtime) | `tests/integration/` | `build_runtime` with real Umbrella, Entra and VirusTotal adapters over stateful fake vendor APIs; the Phase 1 read zone end to end; cross-workflow correlation over dry-run detections |
| Simulation | `tests/simulation/` (`test_dry_run_scenarios.py`, `test_lifecycle_end_to_end.py`, `test_workflow_scenarios.py`, `test_docs_samples.py`, `test_production_parity.py`), `tools/simulator/` | The bundled incident fixtures and all 426 workflow scenarios (22 workflows) in dry run and simulated live against simulated adapters that match the real manifests (14.14.3); exact DRY RUN output; samples in `docs/samples/` equal the simulator output; no state-changing call before approval |
| Repository checks | `tests/test_repo.py`, `tests/unit/legacy/` | YAML parses, Markdown links resolve, generated docs in sync, one agent per workflow, catalog `spec_ref` resolves to `atomic/README.md`, no reference to a retired legacy path |

**Required safety tests** (names are fixed, in `tests/safety/test_approval_bypass.py`). Each goes through the adapter method and `adapter.execute`, through `ContainmentExecutor` with a real `ActionRunner` around the real adapter (no token, and an unsigned token bound to the package), and through the adapter's own `GuardedHttpClient` over a recording `httpx.MockTransport`, first with a pristine guard and then with the production wiring (registered verifier, dry run off). Each expects `ApprovalRequiredError` (or a pure dry-run preview under the pristine default) and asserts that no vendor request left the process and that the executor refusal is audited (`GUARD_DENIED`):

- `test_isolation_without_approval_fails`
- `test_disable_user_without_approval_fails`
- `test_email_quarantine_without_approval_fails`
- `test_block_domain_without_approval_fails`

**Additional safety coverage (as built).** The Phase 0 plan named one file per concern (`test_approval_required.py`, `test_token_binding.py`, `test_principals.py`, `test_dry_run_guard.py`, `test_http_guard.py`, `test_adapter_guard_coverage.py`, `test_restoration_safety.py`, `test_audit_tamper.py`, `test_secret_redaction.py`, `test_config_safety.py`, `test_double_execution.py`). Those files were never created under those names: the safety reviews grouped the same behaviour by attack lens. Where each planned behaviour is tested now ([docs/testing.md](testing.md) is the maintained index):

| Planned behaviour | Where it is tested (file: representative tests) |
|---|---|
| Every catalog state-changing action requires approval; revoke_sessions and release need approval | `safety/test_approval_bypass.py`: `test_every_vendor_write_method_refuses_direct_call`, `test_every_simulated_write_method_refuses_direct_call`, `test_every_state_changing_action_type_is_covered_by_some_adapter_case`; `safety/test_restoration_authority.py`: `test_release_without_token_or_with_containment_token_is_refused` |
| Token binding: no verifier, other incident, other target, params tampering, action not in token, expiry, forged signature, wrong key, purpose confusion, replay, evidence tampering | `safety/test_approval_bypass.py`: `test_no_verifier_registered_refuses_even_valid_token`, `test_token_binding`, `test_params_tampering_rejected_inside_context`, `test_expired_token_rejected`, `test_forged_signature_and_edited_claims_rejected`, `test_wrong_key_rejected`, `test_release_token_cannot_authorize_containment`, `test_containment_token_cannot_authorize_release`, `test_token_replay_for_the_same_action_rejected`, `test_decoded_token_with_tampered_body_rejected`; `unit/approval/test_tokens.py` |
| Principals: AI, service and automation never approve; elevated role and quorum; self-approval; unauthenticated credentials | `safety/test_approval_bypass.py`: `test_ai_principal_cannot_approve`, `test_signed_token_naming_non_human_approver_rejected`, `test_automation_cannot_approve_its_own_recommendation`, `test_elevated_action_requires_elevated_role`, `test_elevated_quorum_of_two_is_enforced`, `test_human_requester_cannot_self_approve`, `test_unauthenticated_or_missing_credentials_cannot_approve`; `unit/approval/test_engine.py` |
| Dry run: blocks with a valid token, default on, per-run dry run cannot switch it off, output format | `safety/test_approval_bypass.py`: `test_dry_run_default_refuses_valid_token`, `test_per_run_dry_run_refuses_and_cannot_be_switched_off`, `test_executor_in_dry_run_never_reaches_an_adapter`; `safety/test_execution_integrity.py`: `test_dry_run_full_lifecycle_changes_nothing`; `unit/dryrun/`; `simulation/test_dry_run_scenarios.py` (exact DRY RUN output) |
| HTTP guard: mutation outside the guard, PUT/PATCH/DELETE never reads, bookkeeping allow-list, other integration | `safety/test_approval_bypass.py`: `test_http_mutation_outside_guard_denied`, `test_http_client_refuses_vendor_write_misdeclared_as_bookkeeping`, `test_http_mutation_for_another_integration_denied_inside_context`; `unit/integrations/test_http.py`: `test_bookkeeping_requires_allowlisted_operation` |
| Every state-changing adapter method is guarded; UNVERIFIED operations raise | `safety/test_approval_bypass.py`: `test_every_vendor_write_method_refuses_direct_call`, `test_undecorated_body_cannot_send_a_vendor_write`; `unit/core/test_integrations_base.py`: `test_supported_action_needs_guarded_method`; `unit/vendors/test_vendor_contracts.py`: `test_unverified_state_changing_operations_raise`, `test_unverified_read_operations_raise` |
| Restoration: close keeps controls, release only from active controls, already-contained creates no control, unknown control key refused | `safety/test_restoration_authority.py`: `test_closing_never_removes_controls`, `test_release_package_contains_only_registered_controls_of_the_incident`, `test_already_contained_manual_block_is_never_registered_nor_released`, `test_planner_refuses_unregistered_manual_control_key` |
| Audit tamper: modification, deletion, reordering, audit failure blocks execution, no update or delete API | `safety/test_secrets_and_audit.py`: `test_audit_edit_of_any_record_is_detected`, `test_audit_reorder_and_middle_delete_are_detected`, `test_audit_classes_expose_no_mutating_public_api`; `unit/audit/test_audit_tamper.py`; `unit/execution/`: `test_audit_failure_before_execution_blocks_the_action`; `safety/test_restoration_authority.py`: `test_release_runner_refuses_when_audit_is_unavailable` |
| Secret redaction: logs, audit, query-string keys, token signature, unlock codes | `safety/test_secrets_and_audit.py` (redactor, logs, API summaries, audit payloads, token repr); `safety/test_p3_workflows.py`, `test_p4_workflows.py`, `test_p5_workflows.py`: `test_isolation_unlock_codes_never_reach_outputs_or_audit` |
| Config safety: auto-approve keys, literal secrets, dry-run default, Splunk off by default, no secret-like literals | `unit/core/test_config.py`: `test_approval_required_refused_even_when_true`, `test_forbidden_keys_anywhere`; `unit/core/test_guard.py`: `test_non_human_approver_refused`; `safety/test_secrets_and_audit.py`: `test_config_literal_secret_is_refused_without_echoing_it`; `unit/dryrun/test_switch.py`: `test_example_config_defaults_to_dry_run`; `unit/vendors/test_vendor_contracts.py`: `test_splunk_is_optional_and_disabled_by_default` |
| Double execution: same action once, write timeout never blindly retried, failed action not retried with the same token | `safety/test_execution_integrity.py`: `test_same_package_executed_twice_calls_the_vendor_once`, `test_http_client_never_blindly_resends_a_write`, `test_failed_action_is_never_retried_with_the_same_token`, `test_crash_restart_with_fresh_execution_store_cannot_replay_the_token` |
| Workflows never write; degraded sources never block what other evidence backs | `safety/test_read_zone.py`; `safety/test_p2_workflows.py` to `test_p5_workflows.py`; `safety/test_degraded_sources.py` (14.14.1) |

Shared fixtures (`tests/fixtures/`): `factories.py` (incident, evidence, package, decision builders), `principals.py` (human analyst, elevated human, service, automation and AI principals, an `InMemoryApproverAuthenticator`, and `make_test_secrets()`: a `StaticSecretProvider` with a random 32-byte signing key per call), `http_mocks.py` (`MockRouter` that maps `(method, path)` to handlers and records requests), `guard_helpers.py` (`FakeVerifier`, `make_token`, `install_fake_verifier`), `degraded.py` (the shared degraded-source check of 14.14.1), `incidents/*.yaml` (bundled incident scenarios), `workflows/<id>/*.yaml` (workflow scenarios, 14.5.2) and `sample_workflows/` (the tests-only sample workflow). `tests/conftest.py` has an autouse fixture calling the private test-harness reset `guard._reset_for_test_harness()` before and after each test (the public `guard.reset_for_tests()` keeps the verifier seal, 13.25).

---

## 11. Security risks

### 11.1 Threat model of the approval path

Assets: the authority to change state in 16 security products; the audit trail; the signing key; vendor credentials. Trust boundary: only an authenticated human principal crossing the `ApprovalEngine` creates authority; everything upstream (XDR triggers, enrichment data, AI narratives, workflow specs, webhook payloads) is untrusted data.

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T1 | **Bypass**: code calls an adapter write directly, or a new adapter forgets the check | `@state_changing` on every state-changing method; HTTP client guard on every `STATE_CHANGING` request; catalog-driven introspection test over all adapters; guard defaults to dry run | `test_*_without_approval_fails`, `test_every_state_changing_adapter_method_is_guarded`, `test_http_mutation_outside_guard_denied` |
| T2 | **Token forgery** | HMAC-SHA256 with a key from the secret store (>= 32 bytes), domain-separated message, constant-time compare, key never logged | `test_forged_signature_rejected`, `test_wrong_key_rejected` |
| T3 | **Token replay / reuse** for another incident, target, parameters or purpose | Claims bind incident, package, evidence hash, workflow version, per-action key/type/target/params hash, purpose from the catalog; `TokenUseLedger` single use per action; short TTL | `test_token_binding.py` |
| T4 | **Parameter substitution** after approval (different integration, list ID or module) | `params_hash` covers all params including `integration`; package re-verified before execution | `test_params_tampering_rejected` |
| T5 | **AI or automation approval** (prompt injection, rogue service account) | Only `PrincipalKind.HUMAN`; checked at decision and again at verification; AI components never receive authenticator credentials; enforcement is code, not prompts | `test_ai_principal_cannot_approve` and peers |
| T6 | **Fabricated evidence** | Evidence `source` must be a registered integration, `analyst` or `temporary_control_registry`; each evidence item carries the `audit_ref` of the API call that produced it; AI text lives in `ai_narrative`, flagged and never numbered | `tests/unit/models` validators |
| T7 | **Analyst override by automation** | Decisions are immutable, audited before tokens issue; the orchestrator cannot change approved/rejected keys; rejected actions are `SKIPPED` | lifecycle tests |
| T8 | **Secret leakage** (logs, audit, notes, exceptions, query strings, unlock codes) | Central `Redactor` used by logging and audit; secret values registered on load and replaced by `[REDACTED]`; sensitive-key list; URL query redaction; `SecretValue` repr hides the value; config refuses literal secrets | `test_secret_redaction.py`, `test_config_safety.py` |
| T9 | **Audit tampering** (edit, delete, reorder, truncate) | Append-only JSONL, SHA-256 chain with `prev_hash` and `seq`, verifier tool; no update/delete API; recommended: periodic export of the head hash to an external system (Splunk HEC when enabled, or the XDR incident note) to detect truncation | `test_audit_tamper.py` |
| T10 | **Double execution** | Idempotency key, ledger, adapter pre-check, no blind write retries, idempotent registry, single lifecycle transition | `test_double_execution.py` |
| T11 | **Over-broad restoration** (removing controls the automation did not create, or all controls of a tenant) | Release packages only from `ACTIVE` registry entries, exact keys, no wildcards; `ALREADY_CONTAINED` never registered; release needs a `release` token; closing never releases; no vendor-side auto expiry by default | `test_restoration_safety.py` |
| T12 | **Critical assets** (isolating a domain controller or hypervisor, disabling a break-glass account) | `ELEVATED` approval with a structured warning, elevated role and configurable quorum; never silently skipped, never silently executed | `test_elevated_action_requires_elevated_role` |
| T13 | **Dry-run escape** | Global dry run default true; per-run flag can only enable it; guard refuses even with a valid token | `test_dry_run_guard.py` |
| T14 | **Untrusted trigger payload** (webhook spoofing) | Trigger carries only an incident ID, re-read from XDR; package building is read-only; nothing in a payload can create authority | lifecycle tests |
| T15 | **Data disclosure to third parties** (internal names sent to VirusTotal, bulk emails to HIBP) | `DisclosurePolicy` checks every third-party enrichment call | `tests/unit/integrations` |
| T16 | **Concurrent writers** (Meraki L3 rule set replacement) | Per-network lock, read-modify-write of one tagged rule, verify after write | `tests/integration/test_meraki_adapter.py` |
| T17 | **Signing key compromise** | Key in secret store only, rotation with `APPROVAL_SIGNING_KEY_PREVIOUS`, short TTL, audit of every token issue with token ID; compromise response documented in `SECURITY.md` | n/a (procedure) |
| T18 | **Config weakening** (`auto_approve`, zero quorum) | Loader refuses approval-bypass keys; `*_min_approvers >= 1` validated | `test_auto_approve_config_rejected` |

### 11.2 Residual risks

- Vendor APIs with no VERIFIED read call (Secure Endpoint isolation status, Defender O365 remediation, Intune lock) cannot be verified automatically; they surface as `UNABLE_TO_VERIFY` and as `PARTIALLY_CONTAINED` unless the operator opts in.
- The in-memory authenticator is for tests and lab only; a production identity integration is required before live use (go-live checklist in `docs/testing/`).
- A process with access to the signing key and the code can always sign tokens; separation of duties is an operational control (key in a vault, orchestrator service identity without approver roles).

---

## 12. Recommended development phases

| Phase | Scope | Exit criteria |
|---|---|---|
| **0 Foundation** | Models, configuration, secrets interface, logging and redaction, audit trail, 16 integration adapters (VERIFIED endpoints only) with health checks, approval engine and tokens, guard, containment execution engine, verification engine, restoration engine and registry, dry-run system, reporting (decision card, result table, release checklist), lifecycle state machine and orchestrator, simulator CLI, validation tools, docs (architecture, approval-model, containment-model, rollback, threat-scoring), LICENSE/CHANGELOG/CONTRIBUTING/SECURITY | All Phase 0 unit, integration, safety and simulation tests pass with the 69 existing tests; `tools/validation/check_endpoints.py` passes; the four required safety tests pass |
| **1 Shared atomic workflows** | `plan_bridge` from `xdr_plan` to packages; scoring engine; normalized investigation models (nested fields of 1.6); the brief's enrichment and investigation atomics as orchestrated operations; spec alignment C1 to C5 (revoke-session requires approval, `auto_approve` removed, protected becomes ELEVATED, unlock codes removed, over-limit becomes ELEVATED) with scenario updates; per-action allow-lists; XDR trigger workflow export | All 105 scenarios replay through the new runtime in dry run; no scenario asserts `requires_approval: false` |
| **2** | ransomware, phishing, account-takeover, mail-bombing, malware, **mfa-fatigue** (new; seeded from `account-takeover/05-mfa-fatigue-approved`), password-spray; **bec** also lands here (not named in the brief's phases; it shares the email atomics with phishing) | Each workflow README has the 17 headings of 14.5 (brief 46's 16 items, with required and optional integrations as separate sections); scenarios pass in dry run and through the lifecycle with mocked adapters |
| **3** | malicious-powershell (spec dir renamed from `powershell` in Phase 1), credential-dumping, lateral-movement, persistence, unauthorized-rmm (spec dir renamed from `rmm` in Phase 1, `approved_rmm` allow-list) | as above |
| **4** | c2, dns-tunneling, exfiltration, **suspicious-authentication** (new), cloud-compromise | as above |
| **5** | privilege-escalation, **threat-intel-sweep** (new), cross-source correlation; add-ons vulnerability-exploitation and web-attacks are aligned last | as above, plus cross-workflow correlation tests |

**Status (2026-10-08): every phase is done.** Exit criteria as met: Phase 1 in 14.7.1 and 14.9.5, Phase 2 in 14.10, Phase 3 in 14.11, Phase 4 in 14.12, Phase 5 in 14.13.5; the end-of-Phase-5 retirement in 14.13.8. The workflow scenarios (400 at the end of Phase 5, 426 after the gap fixes of 14.14) live in `tests/fixtures/workflows/` and run through `tests/simulation/test_workflow_scenarios.py`. Known gaps and owner decisions: section 15.

Existing scenario counts per phase (from `workflows/*/scenarios/`) move into `tests/simulation/` with their workflow. Each phase follows the brief's git discipline: inspect, plan, smallest unit, tests, run, safety review, docs, conventional commit (for example `feat(guard): ...`, `test: prevent containment without analyst approval`).

---

## 13. Phase 0 contract

This section is binding. Every Phase 0 component codes against these names and signatures. Bodies shown as `...` are for the owning component to implement. Anything not listed here is private to its module (prefix `_`) and may not be imported by another component. Python 3.12 compatible (CI runs 3.12; local is 3.13): `enum.StrEnum`, `typing.Protocol`, PEP 604 unions, no 3.13-only APIs.

### 13.1 Packaging

`pyproject.toml` changes (owner: `core`). `--import-mode=importlib` lets test modules in different `tests/unit/<component>/` directories share a basename without `__init__.py` files; import shared helpers as `tests.fixtures.<module>`:

```toml
[project]
dependencies = ["PyYAML>=6.0,<7.0", "pydantic>=2.6,<3", "httpx>=0.27,<1"]

[tool.setuptools.packages.find]
where = ["engine", "src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["engine", "src", "."]
addopts = "-ra --strict-markers --import-mode=importlib"
```

`src/xdr_response/__init__.py`: `__version__ = "0.1.0"` and `FRAMEWORK_VERSION = __version__`. It imports nothing else (keeps import cost and cycles at zero).

### 13.2 Module layout and ownership

| Module | Owner component | Contents |
|---|---|---|
| `xdr_response/__init__.py`, `errors.py`, `clock.py`, `interfaces.py` | core | 13.4, 13.7, 13.8 |
| `xdr_response/models/*` | core | 13.3, 13.5, 13.6 |
| `xdr_response/guard.py` | core (built in the core phase) | 13.10 |
| `xdr_response/config/*` | core (built in the core phase) | 13.11 |
| `xdr_response/secrets/*` | core (built in the core phase) | 13.11 |
| `xdr_response/logs/*` | core (built in the core phase) | 13.11 |
| `xdr_response/audit/*` | audit | 13.12 |
| `xdr_response/integrations/{__init__,base}.py` | core | 13.13 |
| `xdr_response/integrations/{http,auth,registry,health,simulated}.py` | integrations-core | 13.13 |
| `xdr_response/integrations/_adapter_support.py` (private base of the vendor adapters) | vendor-adapters | 13.23 |
| `integrations/{cisco_xdr,secure_endpoint,secure_email,secure_malware_analytics,secure_cloud_analytics,umbrella,meraki}/` | integrations-cisco | 13.14 |
| `integrations/{entra,defender_endpoint,defender_o365,intune,microsoft_cloud}/`, `integrations/_graph.py` | integrations-microsoft | 13.14 |
| `integrations/{virustotal,alienvault_otx,hibp,splunk}/` | integrations-intel | 13.14 |
| `xdr_response/approval/*` | approval | 13.15 |
| `xdr_response/execution/*`, `xdr_response/verification/*` | execution | 13.16 |
| `xdr_response/restoration/*` | restoration | 13.17 |
| `xdr_response/dryrun/*`, `xdr_response/reporting/*` | dryrun-reporting | 13.18 |
| `xdr_response/lifecycle/*` (except `states.py`, a core re-export of `models.states`) | lifecycle | 13.9, 13.19, 13.23 |
| `xdr_response/scoring/*` | core (design-only: docstring + README) | section 9 |
| `config/*.yaml` | core | 13.11 |
| `tests/fixtures/*`, `tests/conftest.py` | core (factories, principals, guard_helpers), integrations-core (`http_mocks.py`) | 13.20 |
| `tests/unit/<component>/` | the component itself | |
| `tests/integration/test_<integration>_adapter.py` | the adapter's owner | |
| `tests/safety/*` | safety-tests | section 10 |
| `tests/simulation/*`, `tools/simulator/*` | simulation-tools | |
| `tools/validation/*` | config (`validate_config.py`), audit (`verify_audit_chain.py`), integrations-core (`check_endpoints.py`) | |
| `tests/fixtures/incidents/*.yaml`, `tests/integration/*` | simulation-tools (integration phase) | 13.23 |
| `tools/deployment/README.md`, `docs/*.md` (except this file and integrations.md), LICENSE, CHANGELOG, CONTRIBUTING, SECURITY | docs | |
| `pyproject.toml`, `.github/workflows/ci.yml`, `.gitignore` | core | |

A component only edits files it owns. If it needs a contract change it reports it instead of editing another component's files.

### 13.3 `xdr_response.models.enums` and `xdr_response.models.canonical`

```python
# xdr_response/models/enums.py
from enum import StrEnum

class IncidentState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    CONTAINMENT_RUNNING = "CONTAINMENT_RUNNING"
    CONTAINED = "CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"
    REMEDIATION_REQUIRED = "REMEDIATION_REQUIRED"
    AWAITING_RELEASE_APPROVAL = "AWAITING_RELEASE_APPROVAL"
    RESTORATION_RUNNING = "RESTORATION_RUNNING"
    RESTORED = "RESTORED"
    CLOSED = "CLOSED"

class ApprovalLevel(StrEnum):
    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"

class DecisionType(StrEnum):
    APPROVE_ALL = "APPROVE_ALL"
    APPROVE_SELECTED = "APPROVE_SELECTED"
    REJECT = "REJECT"
    REQUEST_MORE_INVESTIGATION = "REQUEST_MORE_INVESTIGATION"

class PrincipalKind(StrEnum):
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"
    AUTOMATION = "AUTOMATION"
    AI = "AI"

class ApprovalPurpose(StrEnum):
    CONTAINMENT = "containment"
    RELEASE = "release"

class ActionResultStatus(StrEnum):
    SUCCESS = "SUCCESS"
    ALREADY_CONTAINED = "ALREADY_CONTAINED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    DRY_RUN = "DRY_RUN"

class SkipReason(StrEnum):
    REJECTED_BY_ANALYST = "REJECTED_BY_ANALYST"
    NO_CAPABLE_ADAPTER = "NO_CAPABLE_ADAPTER"
    INTEGRATION_DISABLED = "INTEGRATION_DISABLED"
    CONTROL_NOT_ACTIVE = "CONTROL_NOT_ACTIVE"

class ContainmentOverall(StrEnum):          # values equal IncidentState names
    CONTAINED = "CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"

class RestorationOverall(StrEnum):
    RESTORED = "RESTORED"                    # -> IncidentState.RESTORED
    PARTIALLY_RESTORED = "PARTIALLY_RESTORED"  # -> IncidentState.AWAITING_RELEASE_APPROVAL
    RESTORATION_FAILED = "RESTORATION_FAILED"  # -> IncidentState.AWAITING_RELEASE_APPROVAL

class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"

class HealthStatus(StrEnum):
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    UNKNOWN = "UNKNOWN"

class OperationKind(StrEnum):
    READ = "READ"                    # enrichment, investigation, token endpoints, search POSTs
    VERIFY = "VERIFY"                # read-back of a target's state
    BOOKKEEPING = "BOOKKEEPING"      # notes, incident status, tickets, notifications, audit forwarding
    STATE_CHANGING = "STATE_CHANGING"  # approval-gated; guard required

class EndpointStatus(StrEnum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class ActionCategory(StrEnum):
    ENRICHMENT = "ENRICHMENT"
    INVESTIGATION = "INVESTIGATION"
    BOOKKEEPING = "BOOKKEEPING"
    CONTAINMENT = "CONTAINMENT"
    REMEDIATION = "REMEDIATION"
    RESTORATION = "RESTORATION"

class TargetKind(StrEnum):
    ENDPOINT = "ENDPOINT"
    USER = "USER"
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    HASH = "HASH"
    EMAIL_MESSAGE = "EMAIL_MESSAGE"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PROCESS = "PROCESS"
    FILE = "FILE"
    PERSISTENCE_ITEM = "PERSISTENCE_ITEM"
    ROLE_ASSIGNMENT = "ROLE_ASSIGNMENT"
    NETWORK_CLIENT = "NETWORK_CLIENT"
    APPLICATION = "APPLICATION"
    CREDENTIAL = "CREDENTIAL"
    INCIDENT = "INCIDENT"

class ObservableType(StrEnum):
    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL_ADDRESS = "email_address"
    USER = "user"
    HOSTNAME = "hostname"
    ENDPOINT_ID = "endpoint_id"
    MAC_ADDRESS = "mac_address"
    EMAIL_MESSAGE_ID = "email_message_id"
    PROCESS = "process"
    FILE_PATH = "file_path"

class Verdict(StrEnum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"

class RiskBand(StrEnum):
    LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"

class Severity(StrEnum):
    INFO = "INFO"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"; CRITICAL = "CRITICAL"

class CriticalAssetClass(StrEnum):
    DOMAIN_CONTROLLER = "domain_controller"
    IDENTITY_INFRASTRUCTURE = "identity_infrastructure"
    EXECUTIVE_ENDPOINT = "executive_endpoint"
    PRODUCTION_SERVER = "production_server"
    HYPERVISOR = "hypervisor"
    NETWORK_INFRASTRUCTURE = "network_infrastructure"
    SECURITY_INFRASTRUCTURE = "security_infrastructure"
    SERVICE_ACCOUNT = "service_account"
    PRIVILEGED_ACCOUNT = "privileged_account"
    AUTOMATION_ACCOUNT = "automation_account"

class ControlStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RELEASE_PENDING = "RELEASE_PENDING"
    RELEASED = "RELEASED"
    RELEASE_FAILED = "RELEASE_FAILED"

class TargetState(StrEnum):
    IN_DESIRED_STATE = "IN_DESIRED_STATE"
    NOT_IN_DESIRED_STATE = "NOT_IN_DESIRED_STATE"
    UNKNOWN = "UNKNOWN"

class ErrorCode(StrEnum):
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILED = "AUTH_FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_TARGET = "INVALID_TARGET"
    API_ERROR = "API_ERROR"
    UNVERIFIED_ENDPOINT = "UNVERIFIED_ENDPOINT"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    DRY_RUN = "DRY_RUN"
    NO_CAPABLE_ADAPTER = "NO_CAPABLE_ADAPTER"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    INTERNAL = "INTERNAL"

class AuditEventType(StrEnum):
    INCIDENT_RECEIVED = "INCIDENT_RECEIVED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    ENRICHMENT_RESULT = "ENRICHMENT_RESULT"
    PACKAGE_PROPOSED = "PACKAGE_PROPOSED"
    DECISION_RECORDED = "DECISION_RECORDED"
    TOKEN_ISSUED = "TOKEN_ISSUED"              # token_id and claims hash only
    APPROVAL_DENIED = "APPROVAL_DENIED"
    GUARD_DENIED = "GUARD_DENIED"
    STATE_TRANSITION = "STATE_TRANSITION"
    ACTION_STARTED = "ACTION_STARTED"
    API_CALL = "API_CALL"                      # redacted ApiCallSummary
    ACTION_RESULT = "ACTION_RESULT"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"
    CONTROL_REGISTERED = "CONTROL_REGISTERED"
    CONTAINMENT_COMPLETED = "CONTAINMENT_COMPLETED"
    RELEASE_PACKAGE_PROPOSED = "RELEASE_PACKAGE_PROPOSED"
    RESTORATION_RESULT = "RESTORATION_RESULT"
    RESTORATION_COMPLETED = "RESTORATION_COMPLETED"
    DRY_RUN_SIMULATION = "DRY_RUN_SIMULATION"
    HEALTH_CHECK = "HEALTH_CHECK"
    ERROR = "ERROR"
```

```python
# xdr_response/models/canonical.py
def canonical_json(data: object) -> bytes: ...
    # json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    # normalization: pydantic models -> model_dump(mode="json"); datetime -> UTC "YYYY-MM-DDTHH:MM:SS.ffffffZ"
    # (naive datetimes raise ValueError); StrEnum -> value; tuple/set/frozenset -> list (sets sorted); float -> ValueError
def sha256_hex(data: bytes | str) -> str: ...          # lowercase 64-hex; str is UTF-8 encoded
def params_hash(params: Mapping[str, object]) -> str: ...   # sha256_hex(canonical_json(dict(params)))
def normalize_target(kind: TargetKind, value: str) -> str: ...
    # strip(); DOMAIN: lower, strip trailing "."; EMAIL_ADDRESS and USER: lower; HASH: lower;
    # IP: ipaddress.ip_address(value).compressed; ENDPOINT: upper (NetBIOS style, "TH-LT-1047");
    # URL, EMAIL_MESSAGE, others: unchanged after strip. Empty -> ValueError.
def make_idempotency_key(incident_id: str, action_type: "ActionType | str", target: str) -> str: ...
    # f"{incident_id}:{action_type_value}:{target}" with target already normalized
    # example: "XDR-83921:isolate_endpoint:TH-LT-1047"
```

Composite targets use `/` as separator: `PROCESS` `"<ENDPOINT>/<sha256 or pid>"`, `FILE` `"<ENDPOINT>/<sha256>"`, `PERSISTENCE_ITEM` `"<ENDPOINT>/<item id>"`, `ROLE_ASSIGNMENT` `"<user>/<roleDefinitionId>"`, `NETWORK_CLIENT` `"<networkId>/<clientId>"`.

### 13.4 `xdr_response.errors`

```python
class XdrResponseError(Exception): ...
class ConfigError(XdrResponseError): ...
class SecretNotFoundError(XdrResponseError):
    def __init__(self, name: str) -> None: ...       # message names the secret, never a value

class ApprovalError(XdrResponseError): ...
class ApprovalRequiredError(ApprovalError): ...       # no authorization context / no verifier registered
class DryRunViolationError(ApprovalRequiredError): ...
class TokenInvalidError(ApprovalRequiredError): ...   # alg, key id, signature, approver claims
class TokenExpiredError(TokenInvalidError): ...
class TokenMismatchError(TokenInvalidError): ...      # incident, key, action type, target, params hash, purpose, package
class TokenReplayError(TokenInvalidError): ...
class AuthenticationError(ApprovalError): ...         # approver credential rejected
class ApproverNotAllowedError(ApprovalError): ...     # non-HUMAN principal, missing role, quorum not met, self-approval
class DecisionError(ApprovalError): ...               # invalid decision for the package (keys, expiry, comment, evidence hash)

class InvalidTransitionError(XdrResponseError):
    def __init__(self, from_state: "IncidentState", to_state: "IncidentState", reason: str = "") -> None: ...

class IntegrationError(XdrResponseError):
    code: "ErrorCode"
    def __init__(self, message: str, *, integration: str, http_status: int | None = None,
                 retryable: bool = False) -> None: ...
    def to_error_info(self) -> "ErrorInfo": ...
class IntegrationTimeoutError(IntegrationError): ...           # code TIMEOUT
class RateLimitedError(IntegrationError):                     # code RATE_LIMITED
    retry_after: float | None
class AuthFailedError(IntegrationError): ...                   # code AUTH_FAILED
class IntegrationUnavailableError(IntegrationError): ...       # code UNAVAILABLE
class InvalidTargetError(IntegrationError): ...                # code INVALID_TARGET
class ApiError(IntegrationError): ...                          # code API_ERROR
class CapabilityNotSupportedError(IntegrationError): ...       # code NOT_SUPPORTED
class UnverifiedEndpointError(IntegrationError, NotImplementedError):   # code UNVERIFIED_ENDPOINT
    def __init__(self, integration: str, operation: str) -> None: ...
    # message exactly: f"unverified endpoint: {integration}.{operation} - see docs/integrations.md"

def unverified(integration: str, operation: str) -> NoReturn: ...   # raise UnverifiedEndpointError(...)

class AuditError(XdrResponseError): ...
class AuditIntegrityError(AuditError): ...
class RegistryError(XdrResponseError): ...
```

`errors.py` imports `ErrorCode` lazily or from `xdr_response.models.enums` (enums has no imports, so no cycle). `ErrorInfo` is in `models.action`.

### 13.5 Models (`xdr_response.models`)

`xdr_response/models/__init__.py` re-exports every public name below and in 13.3 and 13.6. Base config for all models: `model_config = ConfigDict(frozen=True, extra="forbid")`. `JsonDict = dict[str, Any]`. Datetimes are `pydantic.AwareDatetime`. Scores are `int` with `Field(ge=0, le=100)`.

```python
# models/observable.py
class Observable(BaseModel):
    type: ObservableType
    value: str
    source: str | None = None

class EnrichmentResult(BaseModel):            # brief's normalized enrichment output
    type: ObservableType
    value: str
    risk_score: int                           # 0-100
    confidence: int                           # 0-100
    sources: tuple[str, ...]
    verdict: Verdict
    integration: str
    health: HealthStatus = HealthStatus.CONNECTED
    evidence: tuple["EvidenceDraft", ...] = ()
    errors: tuple["ErrorInfo", ...] = ()

# models/evidence.py
ALLOWED_NON_INTEGRATION_SOURCES = frozenset({"analyst", "temporary_control_registry"})

class EvidenceDraft(BaseModel):
    source: str                               # integration name or ALLOWED_NON_INTEGRATION_SOURCES; never "ai"
    summary: str
    observed_at: AwareDatetime | None = None
    reference: str | None = None              # vendor object id or console link (no secrets)
    data: JsonDict = {}
    audit_ref: str | None = None              # record_id of the API_CALL audit record

class Evidence(EvidenceDraft):
    number: int                               # >= 1

def number_evidence(drafts: Sequence[EvidenceDraft]) -> tuple[Evidence, ...]: ...
    # stable order by (source, observed_at or min, summary); numbers 1..n; exact duplicates merged
def evidence_snapshot_hash(evidence: Sequence[Evidence]) -> str: ...
    # sha256_hex(canonical_json(sorted by number, model_dump(mode="json")))

# models/incident.py
class Asset(BaseModel):
    name: str                                 # normalized target value
    kind: TargetKind
    groups: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    ip: str | None = None
    ips: tuple[str, ...] = ()                 # further addresses (other interfaces), matched like ip (14.11.6)
    users: tuple[str, ...] = ()               # accounts that use the asset (14.10.8)
    privileged: bool = False                  # identity source marks the account privileged (14.11.6)

class StateTransition(BaseModel):
    from_state: IncidentState
    to_state: IncidentState
    at: AwareDatetime
    actor: str                                # principal id or "automation:<component>"
    reason: str = ""
    package_id: str | None = None
    token_id: str | None = None

class Incident(BaseModel):                    # frozen; changes produce copies (model_copy(update=...))
    incident_id: str
    title: str
    severity: Severity
    state: IncidentState = IncidentState.NOT_STARTED
    source: str = "cisco_xdr"
    created_at: AwareDatetime
    workflow_id: str
    workflow_version: str
    observables: tuple[Observable, ...] = ()
    assets: tuple[Asset, ...] = ()
    users: tuple[str, ...] = ()
    trigger: JsonDict = {}
    ai_narrative: str | None = None           # AI-written, flagged, never evidence
    history: tuple[StateTransition, ...] = ()

# models/recommendation.py
def risk_band(score: int) -> RiskBand: ...    # 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL; else ValueError

class CriticalAssetWarning(BaseModel):
    asset: str
    asset_class: CriticalAssetClass | None    # None for blast-radius warnings
    role: str
    action_type: "ActionType"
    potential_impact: str
    message: str                              # "WARNING: ELEVATED APPROVAL REQUIRED - ..."

class ExcludedTarget(BaseModel):
    action_type: "ActionType"
    target: str
    reason: str                               # e.g. "allowlists.never_block.domains: example.com"

class BlastRadius(BaseModel):
    endpoints: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    messages: int = 0

class ProposedAction(BaseModel):              # input to PackageBuilder (from workflows / plan bridge)
    action_type: "ActionType"
    target: str
    target_kind: TargetKind
    params: JsonDict                          # must contain "integration"
    evidence: tuple[EvidenceDraft, ...]       # >= 1
    risk_score: int
    confidence_score: int
    rationale: str
    asset: Asset | None = None

class RecommendedAction(BaseModel):
    incident_id: str
    idempotency_key: str                      # validator: == make_idempotency_key(incident_id, action_type, target)
    action_type: "ActionType"                 # validator: catalog spec.state_changing is True
    target: str                               # normalized
    target_kind: TargetKind                   # validator: == catalog spec.target_kind
    params: JsonDict                          # validator: contains "integration" (str)
    evidence: tuple[Evidence, ...]            # >= 1
    risk_score: int
    confidence_score: int
    approval_level: ApprovalLevel             # validator: ELEVATED if spec.always_elevated
    warnings: tuple[CriticalAssetWarning, ...] = ()   # validator: non-empty warnings => ELEVATED
    rationale: str = ""
    @property
    def params_hash(self) -> str: ...
    @property
    def integration(self) -> str: ...

class ActionPackage(BaseModel):
    package_id: str                           # uuid4 hex
    purpose: ApprovalPurpose
    incident_id: str
    workflow_id: str
    workflow_version: str
    created_at: AwareDatetime
    expires_at: AwareDatetime
    requested_by: str                         # "automation:<component>" or a human principal id
    severity: Severity
    risk_score: int
    confidence_score: int
    summary: str
    endpoints: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...]
    evidence_snapshot_hash: str               # validator: == evidence_snapshot_hash(evidence)
    actions: tuple[RecommendedAction, ...]    # validator: >= 1, unique keys, all incident_id equal
    excluded_targets: tuple[ExcludedTarget, ...] = ()
    blast_radius: BlastRadius = BlastRadius()
    dry_run: bool = False
    def action(self, idempotency_key: str) -> RecommendedAction: ...   # KeyError if absent
    @property
    def keys(self) -> tuple[str, ...]: ...
    @property
    def has_elevated(self) -> bool: ...

class ContainmentPackage(ActionPackage):
    purpose: Literal[ApprovalPurpose.CONTAINMENT] = ApprovalPurpose.CONTAINMENT
    # validator: every action's catalog purpose is CONTAINMENT

class ReleasePackage(ActionPackage):
    purpose: Literal[ApprovalPurpose.RELEASE] = ApprovalPurpose.RELEASE
    control_keys: tuple[str, ...]             # registry keys being released, same order as actions
    # validator: every action's catalog purpose is RELEASE and params["restores"] in control_keys

# models/approval.py
class ApproverCredential(BaseModel):
    principal_id: str
    scheme: str                               # e.g. "static", "oidc"
    secret: SecretStr                         # never logged; repr hidden

class AuthenticatedPrincipal(BaseModel):
    principal_id: str
    display_name: str
    kind: PrincipalKind
    roles: frozenset[str] = frozenset()
    authenticator: str
    authenticated_at: AwareDatetime

class DecisionRequest(BaseModel):
    package_id: str
    decision: DecisionType
    approved_keys: tuple[str, ...] = ()       # APPROVE_SELECTED only
    rejected_keys: tuple[str, ...] = ()       # optional; must equal the complement if given
    comment: str = ""

class AnalystDecision(BaseModel):
    decision_id: str                          # uuid4 hex
    package_id: str
    incident_id: str
    purpose: ApprovalPurpose
    decision: DecisionType
    analyst_identity: str                     # principal_id of the first approver
    approvers: tuple[AuthenticatedPrincipal, ...]
    decided_at: AwareDatetime
    approved_action_keys: tuple[str, ...]
    rejected_action_keys: tuple[str, ...]
    comment: str
    workflow_id: str
    workflow_version: str
    evidence_snapshot_hash: str
    token_id: str | None = None

class TokenActionGrant(BaseModel):
    idempotency_key: str
    action_type: "ActionType"
    target: str
    params_hash: str
    approval_level: ApprovalLevel

class ApproverClaim(BaseModel):
    principal_id: str
    kind: PrincipalKind
    roles: tuple[str, ...]                    # sorted

class ApprovalTokenClaims(BaseModel):
    version: Literal[1] = 1
    token_id: str                             # uuid4 hex
    purpose: ApprovalPurpose
    package_id: str
    incident_id: str
    evidence_snapshot_hash: str
    workflow_id: str
    workflow_version: str
    decision_id: str
    actions: tuple[TokenActionGrant, ...]     # >= 1
    approvers: tuple[ApproverClaim, ...]      # >= 1
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    def grant(self, idempotency_key: str) -> TokenActionGrant | None: ...

class ApprovalToken(BaseModel):
    claims: ApprovalTokenClaims
    key_id: str
    alg: Literal["HMAC-SHA256"] = "HMAC-SHA256"
    signature: str = Field(repr=False)        # 64 lowercase hex
    @property
    def token_id(self) -> str: ...
    def encode(self) -> str: ...              # base64url(canonical_json(claims)) + "." + key_id + "." + signature
    @classmethod
    def decode(cls, value: str) -> "ApprovalToken": ...   # TokenInvalidError on malformed input

TOKEN_SIGNING_CONTEXT = b"xdr-response/approval-token/v1\n"

class ActionBinding(BaseModel):
    incident_id: str
    idempotency_key: str
    action_type: "ActionType"
    target: str
    params_hash: str
    @classmethod
    def from_request(cls, request: "ActionRequest") -> "ActionBinding": ...

class ApprovalOutcome(BaseModel):
    decision: AnalystDecision
    token: ApprovalToken | None
    warnings: tuple[CriticalAssetWarning, ...] = ()

# models/action.py
class ErrorInfo(BaseModel):
    code: ErrorCode
    message: str                              # redacted
    integration: str | None = None
    http_status: int | None = None
    retryable: bool = False

class ApiCallSummary(BaseModel):
    integration: str
    operation: str
    method: str
    url: str                                  # redacted (query values of sensitive keys replaced)
    kind: OperationKind
    status_code: int | None
    duration_ms: int
    attempt: int
    request_summary: JsonDict = {}            # redacted, size-capped (4 KiB)
    response_summary: JsonDict = {}           # redacted, size-capped (4 KiB)
    error: ErrorInfo | None = None

class ActionRequest(BaseModel):
    incident_id: str
    idempotency_key: str                      # validator as RecommendedAction
    action_type: "ActionType"
    target: str
    target_kind: TargetKind
    params: JsonDict                          # contains "integration"
    @property
    def integration(self) -> str: ...
    @property
    def params_hash(self) -> str: ...
    @classmethod
    def from_recommendation(cls, action: RecommendedAction) -> "ActionRequest": ...

class TargetStateCheck(BaseModel):
    state: TargetState
    detail: str = ""
    api_calls: tuple[ApiCallSummary, ...] = ()

class ActionOutcome(BaseModel):              # returned by adapters for SUCCESS / ALREADY_CONTAINED
    status: Literal[ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED]
    integration: str
    message: str = ""
    external_ref: str | None = None           # machine action id, destination id, rule tag, ...
    rollback_params: JsonDict = {}
    api_calls: tuple[ApiCallSummary, ...] = ()
    executed_at: AwareDatetime

class ActionResult(BaseModel):
    idempotency_key: str
    action_type: "ActionType"
    target: str
    integration: str | None
    approval_level: ApprovalLevel
    status: ActionResultStatus
    skip_reason: SkipReason | None = None
    started_at: AwareDatetime
    finished_at: AwareDatetime
    message: str = ""
    error: ErrorInfo | None = None
    api_calls: tuple[ApiCallSummary, ...] = ()
    verification: "VerificationResult | None" = None
    control_registered: bool = False
    requires_attention: bool = False
    recommended_escalation: str | None = None
    dry_run_line: str | None = None           # "Would isolate: TH-LT-1047"

class ContainmentReport(BaseModel):
    report_id: str
    incident_id: str
    package_id: str
    token_id: str | None
    dry_run: bool
    started_at: AwareDatetime
    finished_at: AwareDatetime
    results: tuple[ActionResult, ...]
    overall: ContainmentOverall | None        # None when dry_run
    attention: tuple[str, ...] = ()

class RestorationReport(BaseModel):
    report_id: str
    incident_id: str
    package_id: str
    token_id: str | None
    dry_run: bool
    started_at: AwareDatetime
    finished_at: AwareDatetime
    results: tuple[ActionResult, ...]
    overall: RestorationOverall | None
    attention: tuple[str, ...] = ()

# models/verification.py
class VerificationResult(BaseModel):
    idempotency_key: str
    status: VerificationStatus
    integration: str | None
    method: str                               # operation name used, or "none"
    checked_at: AwareDatetime
    details: str = ""
    api_calls: tuple[ApiCallSummary, ...] = ()
    terminal: bool | None = None              # True: final vendor state (stop polling); False: pending;
                                              # None: engine default (VERIFIED and method "none" are final)

# models/restoration.py
class TemporaryControl(BaseModel):
    control_key: str                          # == idempotency key of the containment action
    incident_id: str
    action_type: "ActionType"
    target: str
    target_kind: TargetKind
    integration: str
    workflow_id: str
    workflow_version: str
    package_id: str
    token_id: str
    decision_id: str
    approval_level: ApprovalLevel
    created_at: AwareDatetime
    rollback_action_type: "ActionType"
    rollback_params: JsonDict                 # must contain "integration"
    external_ref: str | None = None
    status: ControlStatus = ControlStatus.ACTIVE
    review_due_at: AwareDatetime | None = None
    released_at: AwareDatetime | None = None
    release_package_id: str | None = None
    release_token_id: str | None = None
    last_error: ErrorInfo | None = None

# models/audit.py
GENESIS_HASH = "0" * 64

class AuditRecord(BaseModel):
    seq: int                                  # 0-based, contiguous
    record_id: str                            # uuid4 hex
    timestamp: AwareDatetime
    event_type: AuditEventType
    incident_id: str | None
    workflow_id: str | None
    workflow_version: str | None
    actor: str
    payload: JsonDict                         # already redacted
    prev_hash: str
    hash: str                                 # sha256_hex(canonical_json(record without "hash"))

class ChainVerification(BaseModel):
    ok: bool
    records: int
    head_hash: str
    first_bad_seq: int | None = None
    reason: str = ""

# models/health.py
class IntegrationHealth(BaseModel):
    integration: str
    status: HealthStatus
    checked_at: AwareDatetime
    detail: str = ""
    latency_ms: int | None = None

# models/investigation.py   (Phase 0 minimal; the Phase 1 typed records live in xdr_response.atomics.records, 14.1.2)
class InvestigationQuery(BaseModel):
    action_type: "ActionType"                 # an INVESTIGATION-category action type
    subject: Observable
    time_from: AwareDatetime | None = None
    time_to: AwareDatetime | None = None
    limit: int = 100
    options: JsonDict = {}

class InvestigationResult(BaseModel):
    integration: str
    action_type: "ActionType"
    subject: Observable
    findings: tuple[JsonDict, ...] = ()
    evidence: tuple[EvidenceDraft, ...] = ()
    api_calls: tuple[ApiCallSummary, ...] = ()
    health: HealthStatus = HealthStatus.CONNECTED
    errors: tuple[ErrorInfo, ...] = ()
```

### 13.6 Action catalog (`xdr_response.models.catalog`)

```python
class ActionType(StrEnum): ...                # members and values exactly as the tables below (value == lower snake name)

class ActionSpec(BaseModel):                  # frozen
    action_type: ActionType
    category: ActionCategory
    state_changing: bool
    reversible: bool
    rollback_action_type: ActionType | None
    target_kind: TargetKind
    purpose: ApprovalPurpose | None           # CONTAINMENT for CONTAINMENT/REMEDIATION, RELEASE for RESTORATION, None otherwise
    always_elevated: bool = False
    creates_control: bool = False             # == reversible for CONTAINMENT/REMEDIATION, False otherwise
    integrations: tuple[str, ...]             # candidate adapters, preference order (native first)
    dry_run_verb: str                         # "Would isolate", ...
    description: str
    spec_ref: str | None = None               # e.g. "atomic/isolate-endpoint"

ACTION_CATALOG: Mapping[ActionType, ActionSpec]   # types.MappingProxyType; one entry per ActionType
BOOKKEEPING_OPERATIONS: frozenset[str]            # {"add_incident_note", "update_incident_status", "create_ticket", "notify_soc", "forward_audit"}

def get_action_spec(action_type: ActionType | str) -> ActionSpec: ...   # KeyError for unknown
def is_state_changing(action_type: ActionType | str) -> bool: ...
def purpose_for(action_type: ActionType | str) -> ApprovalPurpose: ...   # ValueError if not state-changing
def rollback_for(action_type: ActionType | str) -> ActionType | None: ...
```

Catalog invariants (unit-tested): `state_changing` is true exactly for CONTAINMENT, REMEDIATION and RESTORATION; `reversible` implies `rollback_action_type` is a RESTORATION type with the same `target_kind`; every RESTORATION type is the rollback of at least one type; read and bookkeeping types are never state-changing.

**State-changing: containment and remediation** (`purpose=containment`)

| ActionType | Category | Reversible | Rollback | Target kind | Always elevated | Integrations (preference) | dry_run_verb | spec_ref |
|---|---|---|---|---|---|---|---|---|
| `isolate_endpoint` | CONTAINMENT | yes | `release_endpoint` | ENDPOINT | no | cisco_xdr, defender_endpoint, secure_endpoint | Would isolate | atomic/isolate-endpoint |
| `block_domain` | CONTAINMENT | yes | `unblock_domain` | DOMAIN | no | cisco_xdr, umbrella, defender_endpoint | Would block | atomic/block-domain |
| `block_url` | CONTAINMENT | yes | `unblock_url` | URL | no | cisco_xdr, umbrella, defender_endpoint | Would block | atomic/block-url |
| `block_ip` | CONTAINMENT | yes | `unblock_ip` | IP | no | cisco_xdr, meraki, defender_endpoint | Would block | atomic/block-ip |
| `block_hash` | CONTAINMENT | yes | `unblock_hash` | HASH | no | cisco_xdr, defender_endpoint, secure_endpoint | Would block | atomic/block-hash |
| `disable_user` | CONTAINMENT | yes | `enable_user` | USER | no | cisco_xdr, entra | Would disable user | atomic/disable-user |
| `revoke_sessions` | CONTAINMENT | no | none | USER | no | entra | Would revoke sessions | atomic/revoke-session |
| `confirm_user_compromised` | CONTAINMENT | no | none | USER | no | entra | Would mark compromised | none |
| `quarantine_email` | CONTAINMENT | yes | `release_email` | EMAIL_MESSAGE | no | cisco_xdr, secure_email, defender_o365 | Would quarantine email | atomic/quarantine-email |
| `block_network_client` | CONTAINMENT | yes | `restore_network_client` | NETWORK_CLIENT | no | meraki | Would block network client | none |
| `lock_device` | CONTAINMENT | no | none | ENDPOINT | no | intune | Would lock device | none |
| `remove_privileged_role` | CONTAINMENT | yes | `restore_privileged_role` | ROLE_ASSIGNMENT | **yes** | entra | Would remove role | none |
| `delete_email` | REMEDIATION | no | none | EMAIL_MESSAGE | no | cisco_xdr, defender_o365, secure_email | Would delete email | none |
| `terminate_process` | REMEDIATION | no | none | PROCESS | no | defender_endpoint, secure_endpoint | Would terminate process | none |
| `quarantine_file` | REMEDIATION | yes | `restore_file` | FILE | no | defender_endpoint, secure_endpoint | Would quarantine file | none |
| `remove_persistence` | REMEDIATION | no | none | PERSISTENCE_ITEM | no | (none verified) | Would remove persistence | none |
| `reset_password` | REMEDIATION | no | none | USER | no | entra | Would reset password | none |
| `reset_mfa` | REMEDIATION | no | none | USER | no | entra | Would reset MFA | none |
| `revoke_app_credentials` | REMEDIATION | no | none | CREDENTIAL | no | entra | Would revoke credentials | none |
| `remove_application` | REMEDIATION | no | none | APPLICATION | no | intune, defender_endpoint | Would remove application | none |

Brief mapping: isolate_secure_endpoint and isolate_defender_endpoint are `isolate_endpoint` landing on the product `secure_endpoint` / `defender_endpoint` (executed natively through `cisco_xdr` when a native action is configured for that product, else `params["integration"]` is the product adapter; section 4.2 and 14.1.7); block_domain_umbrella is `block_domain` with `umbrella`; revoke_entra_sessions is `revoke_sessions`; disable_entra_user is `disable_user`; delete_malicious_email is `delete_email`; intune_device_action is `lock_device` (other Intune actions are UNVERIFIED and out of scope).

**State-changing: restoration** (`purpose=release`, `reversible=False`, `creates_control=False`)

| ActionType | Target kind | Always elevated | Integrations | dry_run_verb |
|---|---|---|---|---|
| `release_endpoint` | ENDPOINT | no | cisco_xdr, defender_endpoint, secure_endpoint | Would release endpoint |
| `unblock_domain` | DOMAIN | no | cisco_xdr, umbrella, defender_endpoint | Would unblock |
| `unblock_url` | URL | no | cisco_xdr, umbrella, defender_endpoint | Would unblock |
| `unblock_ip` | IP | no | cisco_xdr, meraki, defender_endpoint | Would unblock |
| `unblock_hash` | HASH | no | cisco_xdr, defender_endpoint, secure_endpoint | Would unblock |
| `enable_user` | USER | no | cisco_xdr, entra | Would re-enable user |
| `release_email` | EMAIL_MESSAGE | no | cisco_xdr, secure_email, defender_o365 | Would release email |
| `restore_network_client` | NETWORK_CLIENT | no | meraki | Would restore network client |
| `restore_privileged_role` | ROLE_ASSIGNMENT | **yes** | entra | Would restore role |
| `restore_file` | FILE | no | defender_endpoint, secure_endpoint | Would restore file |

**Read-only** (`state_changing=False`, `reversible=False`, `purpose=None`, `dry_run_verb=""`)

| Category | ActionType (target kind) | Integrations |
|---|---|---|
| ENRICHMENT | `enrich_ip` (IP), `enrich_domain` (DOMAIN), `enrich_url` (URL), `enrich_hash` (HASH), `enrich_email_address` (EMAIL_ADDRESS), `enrich_user` (USER), `enrich_endpoint` (ENDPOINT) | cisco_xdr, virustotal, alienvault_otx, umbrella, secure_malware_analytics, hibp (email only), entra (user), defender_endpoint / secure_endpoint / intune (endpoint) |
| INVESTIGATION | `investigate_user` (USER), `investigate_endpoint` (ENDPOINT), `investigate_ip` (IP), `investigate_domain` (DOMAIN), `investigate_hash` (HASH), `investigate_email` (EMAIL_MESSAGE), `investigate_authentication` (USER), `investigate_process` (PROCESS), `investigate_network_connection` (IP), `search_hash_enterprise` (HASH), `search_domain_enterprise` (DOMAIN), `search_ip_enterprise` (IP), `search_user_activity` (USER), `search_email_campaign` (EMAIL_MESSAGE), `search_related_endpoints` (ENDPOINT), `search_related_users` (USER) | cisco_xdr, secure_endpoint, defender_endpoint, microsoft_cloud, entra, secure_email, intune, splunk (optional) |
| BOOKKEEPING | `add_incident_note` (INCIDENT), `update_incident_status` (INCIDENT), `create_ticket` (INCIDENT), `notify_soc` (INCIDENT) | cisco_xdr; ticketing and notification adapters later |

### 13.7 `xdr_response.clock`

```python
class Clock(Protocol):
    def now(self) -> datetime: ...            # timezone-aware UTC

class SystemClock:
    def now(self) -> datetime: ...

class FixedClock:
    def __init__(self, start: datetime) -> None: ...   # naive datetime -> ValueError
    def now(self) -> datetime: ...
    def advance(self, delta: timedelta) -> None: ...
    def set(self, value: datetime) -> None: ...

def utc(dt: datetime) -> datetime: ...        # convert aware dt to UTC; naive -> ValueError
DEFAULT_CLOCK: Clock                          # SystemClock()
```

### 13.8 `xdr_response.interfaces`

All cross-component protocols live here (concrete classes live in their subpackages). `@runtime_checkable` on each.

```python
class SecretProvider(Protocol):
    def get(self, name: str) -> "SecretValue": ...          # SecretNotFoundError
    def get_optional(self, name: str) -> "SecretValue | None": ...

class AuditSink(Protocol):
    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord: ...   # AuditError on failure
    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]: ...
    @property
    def head_hash(self) -> str: ...

class TokenVerifier(Protocol):
    def verify(self, token: ApprovalToken, *, purpose: ApprovalPurpose,
               binding: ActionBinding) -> TokenActionGrant: ...           # raises ApprovalRequiredError subclasses
    def mark_used(self, token: ApprovalToken, idempotency_key: str) -> None: ...   # TokenReplayError

class PackageTokenVerifier(Protocol):          # optional extension, implemented by ApprovalTokenService
    def verify_package(self, token: ApprovalToken, package: ActionPackage) -> None: ...   # TokenInvalidError subclasses
    # executor and restoration engine call it when the registered verifier implements it, and always
    # run their own deterministic package-binding check as well

class TokenUseLedger(Protocol):
    def consume(self, token_id: str, idempotency_key: str) -> None: ...  # TokenReplayError if already consumed
    def is_consumed(self, token_id: str, idempotency_key: str) -> bool: ...

class ApproverAuthenticator(Protocol):
    def authenticate(self, credential: ApproverCredential) -> AuthenticatedPrincipal: ...  # AuthenticationError

class ControlRegistry(Protocol):              # TemporaryControlRegistry
    def register(self, control: TemporaryControl) -> TemporaryControl: ...   # idempotent by control_key
    def get(self, control_key: str) -> TemporaryControl | None: ...
    def list(self, *, incident_id: str | None = None,
             status: ControlStatus | None = None) -> list[TemporaryControl]: ...
    def list_active(self, incident_id: str | None = None) -> list[TemporaryControl]: ...
    def mark_release_pending(self, control_key: str, *, release_package_id: str, token_id: str) -> TemporaryControl: ...
    def mark_released(self, control_key: str, *, at: datetime) -> TemporaryControl: ...
    def mark_release_failed(self, control_key: str, *, error: ErrorInfo) -> TemporaryControl: ...
    # no delete method exists

class IncidentStore(Protocol):
    def get(self, incident_id: str) -> Incident: ...        # KeyError
    def save(self, incident: Incident) -> None: ...
    def list(self) -> list[Incident]: ...

class PackageStore(Protocol):
    def get(self, package_id: str) -> ActionPackage: ...    # KeyError
    def save(self, package: ActionPackage) -> None: ...
    def mark_executed(self, package_id: str) -> None: ...   # RuntimeError if already executed
    def is_executed(self, package_id: str) -> bool: ...
    def latest_for_incident(self, incident_id: str, purpose: ApprovalPurpose) -> ActionPackage | None: ...
```

### 13.9 Lifecycle states (`xdr_response.lifecycle.states`, `machine`)

```python
ALLOWED_TRANSITIONS: Mapping[IncidentState, frozenset[IncidentState]] = {
    NOT_STARTED:               {AWAITING_APPROVAL, CLOSED},
    AWAITING_APPROVAL:         {APPROVED, NOT_STARTED, CLOSED},
    APPROVED:                  {CONTAINMENT_RUNNING, CONTAINMENT_FAILED},
    CONTAINMENT_RUNNING:       {CONTAINED, PARTIALLY_CONTAINED, CONTAINMENT_FAILED},
    CONTAINED:                 {REMEDIATION_REQUIRED, AWAITING_RELEASE_APPROVAL, CLOSED},
    PARTIALLY_CONTAINED:       {AWAITING_APPROVAL, REMEDIATION_REQUIRED, AWAITING_RELEASE_APPROVAL, CLOSED},
    CONTAINMENT_FAILED:        {AWAITING_APPROVAL, REMEDIATION_REQUIRED, CLOSED},
    REMEDIATION_REQUIRED:      {AWAITING_APPROVAL, AWAITING_RELEASE_APPROVAL, CLOSED},
    AWAITING_RELEASE_APPROVAL: {RESTORATION_RUNNING, REMEDIATION_REQUIRED, CLOSED},
    RESTORATION_RUNNING:       {RESTORED, AWAITING_RELEASE_APPROVAL},
    RESTORED:                  {AWAITING_RELEASE_APPROVAL, CLOSED},
    CLOSED:                    {AWAITING_RELEASE_APPROVAL, NOT_STARTED},
}   # wrapped in MappingProxyType; values frozensets (IncidentState members)

TOKEN_REQUIRED: Mapping[IncidentState, ApprovalPurpose] = {
    APPROVED: ApprovalPurpose.CONTAINMENT,
    RESTORATION_RUNNING: ApprovalPurpose.RELEASE,
}

def can_transition(from_state: IncidentState, to_state: IncidentState) -> bool: ...

class IncidentStateMachine:                   # lifecycle/machine.py
    def __init__(self, store: IncidentStore, audit: AuditSink, clock: Clock, *, tokens=None) -> None: ...
    def transition(self, incident_id: str, to_state: IncidentState, *, actor: str, reason: str = "",
                   package_id: str | None = None, token: ApprovalToken | None = None) -> Incident: ...
    # InvalidTransitionError if not allowed; for targets in TOKEN_REQUIRED: token must be present,
    # token.claims.purpose must match, token.claims.incident_id and package_id must match, actor must be
    # a token approver; a token_id or package_id that already entered that state for this incident ->
    # TokenReplayError; then tokens.verify_token(token, purpose=...) (signature, expiry/TTL, HUMAN
    # approvers and roles, not dry-run, issuance proof) when a verifier is injected (build_runtime
    # always injects the ApprovalTokenService; otherwise the guard's registered verifier is used if it
    # offers verify_token). Appends StateTransition to history, saves, audits STATE_TRANSITION.
```

### 13.10 `xdr_response.guard`

```python
@dataclass(frozen=True)
class AuthorizationContext:
    token: ApprovalToken
    request: ActionRequest
    binding: ActionBinding
    purpose: ApprovalPurpose
    grant: TokenActionGrant
    entered_at: datetime
    state: _ContextState                      # shared mutable flags: closed (block exited), consumed (single use
                                              # taken), in_flight (guarded call or raw write running), raw

def register_verifier(verifier: TokenVerifier) -> None: ...
    # the first registration SEALS the slot: afterwards only that identical instance can be registered
    # again; any other object (a permissive verifier, another ApprovalTokenService with another key or
    # an empty ledger) -> ApprovalRequiredError. One runtime per process (13.25).
def unregister_verifier() -> None: ...        # empties the slot, keeps the seal: fails closed for good
def get_verifier() -> TokenVerifier | None: ...
def configure(*, dry_run: bool, clock: Clock | None = None) -> None: ...   # global dry-run flag; default True until called
def is_dry_run() -> bool: ...                 # global flag OR per-run context flag

@contextmanager
def dry_run() -> Iterator[None]: ...          # sets the per-run flag True; can never set it False

@contextmanager
def authorized(token: ApprovalToken, action: ActionRequest) -> Iterator[AuthorizationContext]: ...
    # 1 verifier registered, else ApprovalRequiredError
    # 2 not is_dry_run(), else DryRunViolationError
    # 3 no active context in this contextvar, else ApprovalRequiredError("nested authorization")
    # 4 purpose = catalog.purpose_for(action.action_type)
    # 5 grant = verifier.verify(token, purpose=purpose, binding=ActionBinding.from_request(action))
    # 6 verifier.mark_used(token, action.idempotency_key)
    # 7 set contextvar; yield context; in finally: mark the context CLOSED (every copy captured inside
    #   the block, e.g. copy_context() / thread pool / asyncio task, is refused afterwards), reset
    # every denial is reported through the optional denial hook (audit GUARD_DENIED) before raising

def current() -> AuthorizationContext | None: ...

def check_token(token: ApprovalToken, action: ActionRequest) -> TokenActionGrant: ...
    # pre-flight verification with the registered verifier, nothing consumed (used by ActionRunner
    # before it claims an action, so a forged token can never poison the execution slot)

@contextmanager
def write_window(integration: str, carries_target: Callable[[ActionRequest], bool],
                 action_types: tuple[ActionType, ...] = ()) -> Iterator[AuthorizationContext]: ...
    # held by GuardedHttpClient around one logical STATE_CHANGING request (all its attempts):
    # inside the running guarded call -> allowed; otherwise (a raw client write in the authorized
    # block) allowed once, only when the request URL/body carries the approved target and the manifest
    # row serves the approved action type; the raw write CONSUMES the single use (no guarded call and
    # no further write can follow)

def require_authorization(request: ActionRequest, *, integration: str | None = None) -> AuthorizationContext: ...
    # dry run -> DryRunViolationError; no context -> ApprovalRequiredError;
    # ActionBinding.from_request(request) != context.binding -> TokenMismatchError;
    # integration given and != request.params["integration"] -> TokenMismatchError;
    # re-verify with verifier.verify(...) (no mark_used) -> may raise TokenExpiredError etc.

def require_active_authorization(integration: str) -> AuthorizationContext: ...
    # used by GuardedHttpClient before EVERY STATE_CHANGING attempt: dry run -> DryRunViolationError;
    # no context or closed context -> ApprovalRequiredError; context.request.params["integration"] !=
    # integration -> TokenMismatchError; no guarded call / write window in flight (before the guarded
    # call, after it returned, or from a context copy that outlived it; the in-flight state lives in
    # the shared context state) -> ApprovalRequiredError; re-verify (expiry etc.)

def state_changing(fn: F) -> F: ...
    # decorator for adapter methods with signature (self, request: ActionRequest, /, *args, **kwargs)
    # - request not an ActionRequest -> TypeError
    # - not catalog.is_state_changing(request.action_type) -> ValueError (programming error)
    # - fn.__name__ must be request.action_type.value or "execute" -> else ActionMethodMismatchError
    #   (TokenMismatchError and ValueError): approval for A can never drive the write method B
    # - require_authorization(request, integration=getattr(self, "name", None))
    # - one authorization = one guarded call: the outermost decorated call consumes it (nested guarded
    #   calls such as execute -> isolate_endpoint ride along); a second call -> ApprovalRequiredError
    # - then calls fn; sets wrapper.__xdr_state_changing__ = True; functools.wraps preserved

def is_state_changing_method(obj: object) -> bool: ...   # True if decorated

def set_denial_hook(hook: Callable[[str, ActionRequest | None, Exception], None] | None) -> None: ...

def reset_for_tests() -> None: ...            # only tightens: empties the slot (seal kept), clears the hook,
                                              # global dry_run=True, clears the caller's context vars
def _reset_for_test_harness() -> None: ...    # PRIVATE, tests/conftest.py only: also removes the seal
```

### 13.11 Config, secrets and logs

```python
# xdr_response/config/schema.py   (pydantic, extra="forbid" everywhere)
class RuntimeSettings(BaseModel):
    dry_run: bool = True
    environment: Literal["lab", "staging", "production"] = "lab"
    audit_path: Path = Path("var/audit/audit.jsonl")
    registry_path: Path = Path("var/registry/controls.jsonl")
    token_ledger_path: Path = Path("var/approval/token-ledger.jsonl")

class IntegrationConfig(BaseModel):
    enabled: bool = False
    base_url: str | None = None
    region: str | None = None
    timeout_seconds: float = 15.0
    max_retries: int = 3
    backoff_base_seconds: float = 1.0
    backoff_max_seconds: float = 30.0
    rate_limit_per_minute: int | None = None
    secrets: dict[str, str] = {}              # logical name -> secret NAME (env var), never a value
    options: dict[str, Any] = {}

class ApprovalSettings(BaseModel):
    signing_key_id: str = "primary"
    previous_signing_key_id: str | None = None   # key id of APPROVAL_SIGNING_KEY_PREVIOUS after a rotation that changed the id
    containment_token_ttl_minutes: int = 30
    release_token_ttl_minutes: int = 30
    package_ttl_minutes: int = 240
    standard_role: str = "xdr-approver"
    elevated_role: str = "xdr-elevated-approver"
    standard_min_approvers: int = 1           # >= 1
    elevated_min_approvers: int = 1           # >= 1
    allow_self_approval: bool = False
    clock_skew_seconds: int = 60

class BlastRadiusSettings(BaseModel):
    max_endpoints: int = 5
    max_users: int = 3
    max_indicators: int = 50
    max_messages: int = 500

class VerificationSettings(BaseModel):
    poll_interval_seconds: float = 10.0
    timeout_seconds: float = 300.0
    unable_to_verify_counts_as_contained: bool = False

class TemporaryControlSettings(BaseModel):
    review_after_hours: dict[str, int] = {}   # action_type value -> hours; reminder only, never auto-release

class ScoringSettings(BaseModel):
    bands: dict[str, int] = {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}
    weights: dict[str, float] = {}            # design-only in Phase 0

class Thresholds(BaseModel):
    scoring: ScoringSettings = ScoringSettings()
    blast_radius: BlastRadiusSettings = BlastRadiusSettings()
    approval: ApprovalSettings = ApprovalSettings()
    verification: VerificationSettings = VerificationSettings()
    temporary_controls: TemporaryControlSettings = TemporaryControlSettings()

class AssetMatch(BaseModel):
    hostnames: list[str] = []                 # exact, case-insensitive
    hostname_patterns: list[str] = []         # fnmatch, case-insensitive
    users: list[str] = []
    user_patterns: list[str] = []
    groups: list[str] = []
    tags: list[str] = []
    roles: list[str] = []                     # directory roles (Asset.roles), case-insensitive (14.9.7)
    ip_cidrs: list[str] = []
    used_by: bool = False                     # users also match Asset.users (14.10.8)

class CriticalAssetClassConfig(BaseModel):
    display_name: str
    role: str
    potential_impact: str
    match: AssetMatch = AssetMatch()

class CriticalAssetsConfig(BaseModel):
    classes: dict[CriticalAssetClass, CriticalAssetClassConfig] = {}

class AllowlistsConfig(BaseModel):
    never_block: dict[str, list[str]] = {}    # keys: domains, urls, ips, cidrs, hashes, users, endpoints
    url_block_allowed_domains: list[str] = [] # owned domains where URL-level blocks are allowed
    approved_rmm: list[dict[str, Any]] = []   # {name, hashes, domains, signers}

class ExclusionsConfig(BaseModel):
    third_party_lookup: dict[str, list[str]] = {}   # internal_domain_suffixes, cidrs, user_domains, hostnames
    internal_domains: list[str] = []

class Settings(BaseModel):
    runtime: RuntimeSettings = RuntimeSettings()
    integrations: dict[str, IntegrationConfig] = {}
    thresholds: Thresholds = Thresholds()
    critical_assets: CriticalAssetsConfig = CriticalAssetsConfig()
    allowlists: AllowlistsConfig = AllowlistsConfig()
    exclusions: ExclusionsConfig = ExclusionsConfig()

# xdr_response/config/loader.py
FORBIDDEN_KEYS = frozenset({"auto_approve", "skip_approval", "bypass_approval", "approval_required"})
SECRET_NAME_PATTERN = r"^[A-Z][A-Z0-9_]*$"
def load_settings(config_dir: Path | str = "config", *, env: Mapping[str, str] | None = None) -> Settings: ...
    # reads integrations.yaml (or integrations.example.yaml if absent), thresholds.yaml, exclusions.yaml,
    # critical-assets.yaml, allowlists.yaml; missing optional files -> defaults.
    # ConfigError if: any FORBIDDEN_KEYS key anywhere (approval_required is refused whatever its value),
    # a value under any key matching the sensitive-key pattern is not a secret NAME (SECRET_NAME_PATTERN),
    # *_min_approvers < 1, unknown integration name (must be one of INTEGRATION_NAMES).
    # Env overrides: DRY_RUN ("true"/"false", case-insensitive), XDR_RESPONSE_ENVIRONMENT,
    # XDR_RESPONSE_AUDIT_PATH. splunk.enabled defaults to False.
def load_yaml(path: Path) -> dict[str, Any]: ...       # yaml.safe_load; ConfigError on parse errors

INTEGRATION_NAMES: tuple[str, ...] = ("cisco_xdr", "secure_endpoint", "secure_email",
    "secure_malware_analytics", "secure_cloud_analytics", "umbrella", "meraki", "entra",
    "defender_endpoint", "defender_o365", "intune", "microsoft_cloud", "virustotal",
    "alienvault_otx", "hibp", "splunk")      # defined in config/schema.py, re-exported

# xdr_response/config/policy.py
class AllowlistPolicy:
    def __init__(self, config: AllowlistsConfig) -> None: ...
    def excluded_reason(self, action_type: ActionType, target: str, target_kind: TargetKind) -> str | None: ...
    # block_url on a never_block domain is allowed when the domain is in url_block_allowed_domains
class DisclosurePolicy:
    def __init__(self, config: ExclusionsConfig) -> None: ...
    def may_disclose(self, observable: Observable, integration: str) -> bool: ...
    # False for private/reserved IPs (ipaddress.is_private etc.), internal domains/suffixes, hostnames,
    # endpoint ids, process, file paths, email message ids; HIBP only EMAIL_ADDRESS
```

```python
# xdr_response/secrets/provider.py
class SecretValue:
    __slots__ = ("_value", "name")
    def __init__(self, name: str, value: str) -> None: ...
    def reveal(self) -> str: ...
    def __repr__(self) -> str: ...            # "SecretValue(name='X', value='***')"; __str__ == "***"
class EnvSecretProvider:                      # implements SecretProvider
    def __init__(self, environ: Mapping[str, str] | None = None, *, redactor: "Redactor | None" = None) -> None: ...
class StaticSecretProvider:                   # tests and lab only
    def __init__(self, values: Mapping[str, str], *, redactor: "Redactor | None" = None) -> None: ...
class ChainSecretProvider:
    def __init__(self, *providers: SecretProvider) -> None: ...
# every provider registers each value it returns with the redactor (default: get_redactor()); empty values -> SecretNotFoundError
```

```python
# xdr_response/logs/redaction.py
REDACTED = "[REDACTED]"
SENSITIVE_KEY_PATTERN: re.Pattern[str]
    # case-insensitive match on: authorization, proxy-authorization, cookie, set-cookie, password, passwd,
    # secret, client_secret, token, access_token, refresh_token, id_token, api_key, apikey, x-apikey,
    # x-api-key, hibp-api-key, x-otx-api-key, x-cisco-meraki-api-key, private_key, session, signature,
    # approval_token, unlock_code, credential, key (exact "key")
class Redactor:
    def __init__(self, extra_keys: Iterable[str] = ()) -> None: ...
    def register_secret(self, value: str) -> None: ...      # values shorter than 6 chars ignored
    def is_sensitive_key(self, key: str) -> bool: ...
    def redact(self, value: Any) -> Any: ...                # deep copy; mappings, sequences, pydantic models,
                                                            # SecretValue/SecretStr -> REDACTED; strings -> redact_text
    def redact_text(self, text: str) -> str: ...            # registered values, "Bearer <x>", "Basic <x>", JWT-shaped strings
    def redact_url(self, url: str) -> str: ...              # userinfo removed; query values of sensitive keys -> REDACTED
    def redact_headers(self, headers: Mapping[str, str]) -> dict[str, str]: ...
def get_redactor() -> Redactor: ...           # process-wide default instance

# xdr_response/logs/setup.py
class RedactingFilter(logging.Filter): ...    # redacts msg, args and extra fields with get_redactor()
class JsonFormatter(logging.Formatter): ...
def configure_logging(level: str = "INFO", *, json_format: bool = True, stream: IO[str] | None = None) -> None: ...
def get_logger(name: str) -> logging.Logger: ...   # logger with RedactingFilter attached; name prefixed "xdr_response."
```

Secret names (values only from the environment or a vault, never committed):

| Integration | Secret names |
|---|---|
| framework | `APPROVAL_SIGNING_KEY`, optional `APPROVAL_SIGNING_KEY_PREVIOUS` |
| cisco_xdr | `XDR_CLIENT_ID`, `XDR_CLIENT_SECRET` |
| secure_endpoint | `SE_CLIENT_ID`, `SE_API_KEY` |
| secure_email | `ETD_CLIENT_ID`, `ETD_CLIENT_SECRET`, `ETD_API_KEY` |
| secure_malware_analytics | `SMA_API_KEY` |
| secure_cloud_analytics | `SCA_API_KEY` (unused until an endpoint is VERIFIED) |
| umbrella | `UMBRELLA_API_KEY`, `UMBRELLA_API_SECRET` |
| meraki | `MERAKI_API_KEY` |
| entra, defender_o365, intune, microsoft_cloud | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` |
| defender_endpoint | `ENTRA_TENANT_ID`, `MDE_CLIENT_ID`, `MDE_CLIENT_SECRET` |
| virustotal | `VT_API_KEY` |
| alienvault_otx | `OTX_API_KEY` |
| hibp | `HIBP_API_KEY` |
| splunk | `SPLUNK_TOKEN`, `SPLUNK_HEC_TOKEN` |

### 13.12 Audit (`xdr_response.audit`)

```python
# audit/trail.py
class AuditTrail:                             # implements AuditSink; JSONL, one record per line, append-only
    def __init__(self, path: Path | str, *, clock: Clock | None = None,
                 redactor: Redactor | None = None, fsync: bool = True,
                 anchor_path: Path | str | None = None, chain_key: Any = None) -> None: ...
        # chain_key: AUDIT_CHAIN_KEY (bytes / str / SecretValue, >= 32 bytes); default resolution in
        # xdr_response.audit.keys (env AUDIT_CHAIN_KEY, else a per-user key file outside the audit
        # directory). The head anchor file is {"seq", "hash", "mac"} with mac = HMAC-SHA256(key,
        # "xdr-response-audit-anchor-v1\n" + canonical_json({"seq","hash"})); a missing or wrong MAC
        # -> AuditIntegrityError on open, verify() not ok (13.25)
        # creates parent dirs; on open verifies the whole file against the head anchor file
        # (default "<path>.head", rewritten atomically after every append); a broken chain, a missing
        # anchor for a non-empty file, fewer records (tail truncation) or more records (forged append)
        # than the anchor names -> AuditIntegrityError (refuses to append); verify() applies the same
        # head check; every stored line must be byte-for-byte canonical (no duplicate JSON keys)
    def append(...) -> AuditRecord: ...       # AuditSink signature; payload redacted before hashing;
                                              # thread lock; open in "a" mode, write line, flush, fsync
    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]: ...
    @property
    def head_hash(self) -> str: ...
    # there is no update, delete or truncate method

class MemoryAuditTrail:                       # same contract, in memory, for unit tests
    def __init__(self, *, clock: Clock | None = None, redactor: Redactor | None = None) -> None: ...

def compute_record_hash(record_without_hash: Mapping[str, Any]) -> str: ...   # sha256_hex(canonical_json(...))

# audit/verify.py
def verify_chain(path: Path | str) -> ChainVerification: ...
def verify_records(records: Iterable[AuditRecord]) -> ChainVerification: ...
    # checks: seq contiguous from 0, prev_hash of seq 0 == GENESIS_HASH, prev_hash == previous hash,
    # hash recomputed, JSON parse; first failure reported (no exception)

# audit/summary.py
class ExecutionAuditSummary(BaseModel):       # brief section 35 fields, one per incident execution
    incident_id: str
    workflow_id: str | None
    workflow_version: str | None
    timestamp: AwareDatetime
    trigger: JsonDict
    observables: list[JsonDict]
    evidence: list[JsonDict]
    risk_score: int | None
    confidence_score: int | None
    recommended_actions: list[JsonDict]
    analyst_identity: str | None
    approval_timestamp: AwareDatetime | None
    approved_actions: list[str]
    rejected_actions: list[str]
    api_requests: list[JsonDict]
    api_responses: list[JsonDict]
    containment_results: list[JsonDict]
    verification_results: list[JsonDict]
    restoration_results: list[JsonDict]
    errors: list[JsonDict]
def build_execution_summary(records: Iterable[AuditRecord], incident_id: str) -> ExecutionAuditSummary: ...
```

Payload conventions: `PACKAGE_PROPOSED` carries the package `model_dump(mode="json")`; `DECISION_RECORDED` the `AnalystDecision`; `TOKEN_ISSUED` `{token_id, purpose, package_id, claims_hash, expires_at}` (never the signature); `API_CALL` an `ApiCallSummary`; `ACTION_RESULT` an `ActionResult`; `VERIFICATION_RESULT` a `VerificationResult`; `CONTROL_REGISTERED` a `TemporaryControl`; `INCIDENT_RECEIVED` `{trigger, observables}`; `ERROR` an `ErrorInfo`.

### 13.13 Integrations core (`xdr_response.integrations`)

```python
# integrations/base.py
class OperationSpec(BaseModel):               # frozen
    name: str                                 # e.g. "isolate", "get_machine_action", "domain_categorization"
    kind: OperationKind
    status: EndpointStatus
    method: str | None = None
    path: str | None = None                   # as written in docs/integrations.md
    source: str | None = None                 # required when status == VERIFIED (URL from docs/integrations.md)
    action_types: tuple[ActionType, ...] = () # action types this operation serves

class CapabilityManifest(BaseModel):          # frozen
    integration: str                          # one of INTEGRATION_NAMES
    display_name: str
    optional: bool = False                    # True only for splunk
    enabled_by_default: bool = True           # False for splunk
    native_xdr: bool = False                  # True for cisco_xdr
    supported_actions: frozenset[ActionType] = frozenset()   # state-changing types with a VERIFIED write
    verifiable_actions: frozenset[ActionType] = frozenset()  # types whose verify() can return VERIFIED
    read_actions: frozenset[ActionType] = frozenset()        # ENRICHMENT/INVESTIGATION types served
    enrichment_types: frozenset[ObservableType] = frozenset()
    operations: tuple[OperationSpec, ...]
    escalation_hint: str = ""                 # e.g. "Microsoft 365 administrator"
    rate_limit_note: str = ""
    def operation(self, name: str) -> OperationSpec: ...      # KeyError

class IntegrationAdapter(ABC):
    name: ClassVar[str]
    manifest: ClassVar[CapabilityManifest]

    def __init__(self, config: IntegrationConfig, secrets: SecretProvider, *,
                 transport: httpx.BaseTransport | None = None, clock: Clock | None = None,
                 audit: AuditSink | None = None, settings: "Settings | None" = None,
                 sleep: Callable[[float], None] | None = None) -> None: ...
        # builds self.http: GuardedHttpClient from config (base_url, timeout, retries, rate limit, auth)
    @property
    def enabled(self) -> bool: ...

    @abstractmethod
    def health_check(self) -> IntegrationHealth: ...          # never raises; disabled -> UNKNOWN

    def enrich(self, observable: Observable) -> EnrichmentResult: ...           # default CapabilityNotSupportedError
    def investigate(self, query: InvestigationQuery) -> InvestigationResult: ...  # default CapabilityNotSupportedError
    def current_state(self, request: ActionRequest) -> TargetStateCheck: ...    # read-only; default UNKNOWN
    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult: ...
        # read-only; default UNABLE_TO_VERIFY; must not assume this adapter executed the action

    @state_changing
    def execute(self, request: ActionRequest) -> ActionOutcome: ...
        # dispatches to getattr(self, request.action_type.value); the target method must be decorated with
        # @state_changing (else CapabilityNotSupportedError); action type not in manifest.supported_actions
        # -> CapabilityNotSupportedError, or UnverifiedEndpointError if the operation exists as UNVERIFIED

    # Subclasses implement one method per supported state-changing ActionType, named exactly as the value:
    #   @state_changing
    #   def isolate_endpoint(self, request: ActionRequest) -> ActionOutcome: ...
    # Unverified ones:  def block_hash(self, request): unverified(self.name, "block_hash")  (also decorated)

# integrations/http.py
class RetryPolicy(BaseModel):                 # frozen
    max_retries: int = 3
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    jitter: bool = True

class RateLimiter:                            # token bucket
    def __init__(self, rate_per_minute: int | None, *, clock: Clock | None = None,
                 sleep: Callable[[float], None] | None = None) -> None: ...
    def acquire(self) -> None: ...            # no-op when rate is None

class HttpResult(BaseModel):
    status_code: int
    headers: dict[str, str]                   # redacted
    body: Any                                 # parsed JSON or None (repr=False)
    text: str                                 # raw text (not logged, repr=False)
    summary: ApiCallSummary

class GuardedHttpClient:
    def __init__(self, integration: str, base_url: str, *, timeout: float = 15.0,
                 retry: RetryPolicy | None = None, rate_limiter: RateLimiter | None = None,
                 auth: "AuthProvider | None" = None, default_headers: Mapping[str, str] | None = None,
                 transport: httpx.BaseTransport | None = None, redactor: Redactor | None = None,
                 clock: Clock | None = None, sleep: Callable[[float], None] | None = None,
                 audit: AuditSink | None = None, manifest: CapabilityManifest | None = None) -> None: ...
        # IntegrationAdapter attaches its manifest to every client it builds or is given (http setter)
    def request(self, method: str, url: str, *, kind: OperationKind, operation: str,
                params: Mapping[str, Any] | None = None, json: Any = None,
                data: Mapping[str, Any] | str | None = None, headers: Mapping[str, str] | None = None,
                expected: tuple[int, ...] = (200, 201, 202, 204)) -> HttpResult: ...
        # rules (checked before every attempt):
        # - PUT/PATCH/DELETE with any kind other than STATE_CHANGING -> ValueError
        # - kind STATE_CHANGING -> guard.require_active_authorization(self.integration)
        # - kind BOOKKEEPING -> POST only and operation in BOOKKEEPING_OPERATIONS (ValueError)
        # - manifest attached -> operation must exist, method and kind must match the row (ValueError)
        # - error excerpts: vendor body redacted first, then cut to 200 characters
        # - retries: READ/VERIFY/BOOKKEEPING on timeout, connect error and retry_on_status;
        #   STATE_CHANGING only on connect error before send, 429, and 503 with Retry-After
        # - 401: auth.invalidate() and one retry; 403: AuthFailedError; 404/400: InvalidTargetError;
        #   other 4xx: ApiError; exhausted 5xx/connect: IntegrationUnavailableError; timeout: IntegrationTimeoutError;
        #   exhausted 429: RateLimitedError
        # - every attempt produces an ApiCallSummary; if audit given, appended as API_CALL
    def get(self, url: str, *, kind: OperationKind = OperationKind.READ, operation: str, **kw: Any) -> HttpResult: ...
    def post(self, url: str, *, kind: OperationKind, operation: str, **kw: Any) -> HttpResult: ...   # kind required
    def put(self, url: str, *, operation: str, kind: OperationKind = OperationKind.STATE_CHANGING, **kw: Any) -> HttpResult: ...
    def patch(self, url: str, *, operation: str, kind: OperationKind = OperationKind.STATE_CHANGING, **kw: Any) -> HttpResult: ...
    def delete(self, url: str, *, operation: str, kind: OperationKind = OperationKind.STATE_CHANGING, **kw: Any) -> HttpResult: ...
    def close(self) -> None: ...

# integrations/auth.py
class AuthProvider(Protocol):
    def apply(self, request: httpx.Request) -> None: ...
    def invalidate(self) -> None: ...
class OAuth2ClientCredentials:                # token POSTs use kind=READ, operation="token"
    def __init__(self, *, token_url: str, client_id: SecretValue, client_secret: SecretValue,
                 scope: str | None = None, basic_auth: bool = True,
                 transport: httpx.BaseTransport | None = None, clock: Clock | None = None,
                 extra_headers: Mapping[str, str] | None = None) -> None: ...
class ApiKeyHeader:
    def __init__(self, header: str, key: SecretValue, *, prefix: str = "") -> None: ...
class ApiKeyQuery:                            # Secure Malware Analytics; URL redaction is mandatory
    def __init__(self, param: str, key: SecretValue) -> None: ...
class BasicAuth:
    def __init__(self, username: SecretValue, password: SecretValue) -> None: ...

# integrations/registry.py
ADAPTER_PATHS: Mapping[str, str] = {          # lazy import "module:Class"
    "cisco_xdr": "xdr_response.integrations.cisco_xdr.adapter:CiscoXdrAdapter",
    "secure_endpoint": "xdr_response.integrations.secure_endpoint.adapter:SecureEndpointAdapter",
    "secure_email": "xdr_response.integrations.secure_email.adapter:SecureEmailAdapter",
    "secure_malware_analytics": "xdr_response.integrations.secure_malware_analytics.adapter:SecureMalwareAnalyticsAdapter",
    "secure_cloud_analytics": "xdr_response.integrations.secure_cloud_analytics.adapter:SecureCloudAnalyticsAdapter",
    "umbrella": "xdr_response.integrations.umbrella.adapter:UmbrellaAdapter",
    "meraki": "xdr_response.integrations.meraki.adapter:MerakiAdapter",
    "entra": "xdr_response.integrations.entra.adapter:EntraAdapter",
    "defender_endpoint": "xdr_response.integrations.defender_endpoint.adapter:DefenderEndpointAdapter",
    "defender_o365": "xdr_response.integrations.defender_o365.adapter:DefenderO365Adapter",
    "intune": "xdr_response.integrations.intune.adapter:IntuneAdapter",
    "microsoft_cloud": "xdr_response.integrations.microsoft_cloud.adapter:MicrosoftCloudAdapter",
    "virustotal": "xdr_response.integrations.virustotal.adapter:VirusTotalAdapter",
    "alienvault_otx": "xdr_response.integrations.alienvault_otx.adapter:AlienVaultOtxAdapter",
    "hibp": "xdr_response.integrations.hibp.adapter:HibpAdapter",
    "splunk": "xdr_response.integrations.splunk.adapter:SplunkAdapter",
}
def load_adapter_class(name: str) -> type[IntegrationAdapter]: ...
class AdapterRegistry:
    def __init__(self, settings: Settings, secrets: SecretProvider, *, clock: Clock | None = None,
                 audit: AuditSink | None = None,
                 transport_factory: Callable[[str], httpx.BaseTransport | None] | None = None,
                 sleep: Callable[[float], None] | None = None) -> None: ...
    def get(self, name: str) -> IntegrationAdapter: ...      # KeyError if unknown; instantiated lazily
    def enabled(self) -> list[str]: ...
    def register(self, adapter: IntegrationAdapter) -> None: ...   # tests and fakes
    def for_action(self, action_type: ActionType) -> list[IntegrationAdapter]: ...
        # catalog preference order, filtered to enabled adapters whose manifest supports it

# integrations/health.py
def classify_exception(exc: BaseException) -> HealthStatus: ...
class HealthMonitor:
    def __init__(self, registry: AdapterRegistry, *, audit: AuditSink | None = None) -> None: ...
    def check_all(self) -> dict[str, IntegrationHealth]: ...  # never raises; disabled -> UNKNOWN
```

Each adapter package: `__init__.py` exports the adapter class and `MANIFEST`; `manifest.py` defines `MANIFEST: CapabilityManifest` with one `OperationSpec` per row of the adapter's table in `docs/integrations.md` (status and source copied); `adapter.py` defines the class with `name` and `manifest = MANIFEST`.

### 13.14 Adapter scope in Phase 0

| Adapter (class) | Implemented (VERIFIED) | Raises `UnverifiedEndpointError` |
|---|---|---|
| cisco_xdr (`CiscoXdrAdapter`) | token; enrich via deliberate/observe; refer; incident summary and full view; `list_response_actions(observable) -> list[NativeResponseAction]` (respond/observables, READ); native execution for every action type in its catalog row via respond/trigger; `update_incident_status` on the Global Intelligence host only (BOOKKEEPING); list automation workflows | worklog note, incident search, private-intel status host, run workflow, approval-task APIs |
| secure_endpoint (`SecureEndpointAdapter`) | list/get computer, trajectory, audit logs; `isolate_endpoint`, `release_endpoint`; `current_state` UNKNOWN; verify UNABLE_TO_VERIFY | isolation GET, events, `block_hash` / `unblock_hash` (file lists), `terminate_process`, `quarantine_file` |
| secure_email (`SecureEmailAdapter`) | token + `x-api-key`; message search; `quarantine_email`, `release_email` (verdict from `rollback_params`), `delete_email` (folder `trash`); verify via messages/status | none listed |
| secure_malware_analytics (`SecureMalwareAnalyticsAdapter`) | domain IOC feed (READ) | submission search, sample report |
| secure_cloud_analytics (`SecureCloudAnalyticsAdapter`) | health UNKNOWN | all operations |
| umbrella (`UmbrellaAdapter`) | token; domain categorization (enrich_domain); list destination lists and destinations; `block_domain`, `block_url`, `unblock_domain`, `unblock_url` (destination ID in `rollback_params`); `current_state` and verify via list destinations | security and risk scores, `block_ip` / `unblock_ip` (CONFLICT) |
| meraki (`MerakiAdapter`) | client search; client policy GET/PUT: `block_network_client`, `restore_network_client`; L3 rules GET/PUT: `block_ip`, `unblock_ip` (per-network lock, tagged rule) | none listed |
| entra (`EntraAdapter`) | get user; sign-ins; `disable_user`, `enable_user`, `revoke_sessions`, `confirm_user_compromised`, `remove_privileged_role`, `restore_privileged_role`; role assignment list; verify for disable/enable/revoke/role | riskyUser get/dismiss, `reset_password`, `reset_mfa`, `revoke_app_credentials` |
| defender_endpoint (`DefenderEndpointAdapter`) | get machine; `isolate_endpoint`, `release_endpoint` (400 "already in progress" maps to ALREADY_CONTAINED); machine action get/list; indicators POST/DELETE: `block_hash`, `block_ip`, `block_domain`, `block_url` and their `unblock_*` | indicator list/get (verify UNABLE_TO_VERIFY), `terminate_process`, `quarantine_file`, `restore_file`, `remove_application` |
| defender_o365 (`DefenderO365Adapter`) | analyzedEmails/remediate: `quarantine_email` (`moveToQuarantine` with `Prefer` header), `release_email` (`moveToInbox`), `delete_email` (`softDelete`); verify UNABLE_TO_VERIFY | list/search analyzed emails, quarantine release API |
| intune (`IntuneAdapter`) | get managed device; `lock_device` (remoteLock); verify UNABLE_TO_VERIFY | retire, wipe, sync, `remove_application` |
| microsoft_cloud (`MicrosoftCloudAdapter`) | alerts_v2, runHuntingQuery (READ) | incidents list |
| virustotal (`VirusTotalAdapter`) | file, domain, IP, URL reports (enrich); `DisclosurePolicy`; rate limit 4/min | none |
| alienvault_otx (`AlienVaultOtxAdapter`) | indicator sections for IPv4, IPv6, domain, hostname, file, URL | none |
| hibp (`HibpAdapter`) | breachedaccount, pasteaccount, breaches (user-agent header mandatory) | none (Pwned Passwords is never used) |
| splunk (`SplunkAdapter`) | disabled by default (health UNKNOWN); search job create and results (READ); `forward_audit` via HEC (BOOKKEEPING, redacted) | bearer-token auth, v2 export |

`NativeResponseAction` (in `cisco_xdr/adapter.py`): `module_instance_id: str`, `module_name: str`, `action_id: str`, `title: str`, `observable_type: str`, `observable_value: str`.

### 13.15 Approval (`xdr_response.approval`)

```python
# approval/authenticator.py
class InMemoryApproverAuthenticator:          # implements ApproverAuthenticator; tests, lab, simulator only
    def __init__(self, *, clock: Clock | None = None) -> None: ...
    def add_principal(self, principal_id: str, *, display_name: str, kind: PrincipalKind,
                      roles: Iterable[str], secret: str) -> None: ...   # stores salted PBKDF2-SHA256 hash only
    def authenticate(self, credential: ApproverCredential) -> AuthenticatedPrincipal: ...  # AuthenticationError

# approval/ledger.py
class InMemoryTokenUseLedger: ...             # implements TokenUseLedger
class JsonlTokenUseLedger:                    # append-only file, implements TokenUseLedger
    def __init__(self, path: Path | str) -> None: ...

# approval/tokens.py
class ApprovalTokenService:                   # implements TokenVerifier
    def __init__(self, secrets: SecretProvider, settings: ApprovalSettings, *,
                 ledger: TokenUseLedger, clock: Clock | None = None) -> None: ...
        # loads APPROVAL_SIGNING_KEY (>= 32 bytes else ConfigError) and optional APPROVAL_SIGNING_KEY_PREVIOUS
    def issue(self, package: ActionPackage, decision: AnalystDecision,
              approvers: Sequence[AuthenticatedPrincipal]) -> ApprovalToken: ...
        # grants only for decision.approved_action_keys; TTL by package.purpose; HUMAN-only re-checked
        # sets claims.dry_run = package.dry_run and claims.issuance_proof (HMAC over
        # TOKEN_ISSUANCE_CONTEXT + every claim except issued_at and the proof) after its policy checks
    def sign(self, claims: ApprovalTokenClaims) -> ApprovalToken: ...   # low level, no policy checks;
        # fabricated claims carry no valid issuance proof and never verify
    def verify(self, token: ApprovalToken, *, purpose: ApprovalPurpose, binding: ActionBinding) -> TokenActionGrant: ...
        # ... plus: claims.dry_run -> TokenInvalidError; missing/invalid issuance proof -> TokenInvalidError
    def verify_token(self, token: ApprovalToken, *, purpose: ApprovalPurpose) -> ApprovalTokenClaims: ...
        # whole-token check (no binding) used by the state machine
    def verify_package(self, token: ApprovalToken, package: ActionPackage) -> None: ...
        # ... plus: claims.dry_run must equal package.dry_run, then the dry-run and issuance checks
    def mark_used(self, token: ApprovalToken, idempotency_key: str) -> None: ...
def claims_hash(claims: ApprovalTokenClaims) -> str: ...   # sha256_hex(canonical_json(claims)), safe to audit

# approval/critical_assets.py
class CriticalAssetPolicy:
    def __init__(self, config: CriticalAssetsConfig) -> None: ...
    def classify(self, target: str, target_kind: TargetKind, asset: Asset | None = None) -> list[CriticalAssetClass]: ...
    def evaluate(self, action_type: ActionType, target: str, target_kind: TargetKind,
                 asset: Asset | None = None) -> list[CriticalAssetWarning]: ...

# approval/package.py
class PackageBuilder:
    def __init__(self, settings: Settings, *, critical_assets: CriticalAssetPolicy,
                 allowlists: AllowlistPolicy, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None) -> None: ...
    def build(self, incident: Incident, proposals: Sequence[ProposedAction], *,
              risk_score: int, confidence_score: int, summary: str,
              extra_evidence: Sequence[EvidenceDraft] = (), dry_run: bool = False,
              requested_by: str = "automation:package_builder") -> ContainmentPackage: ...
        # rules of section 5.2; ValueError if no actions remain (all excluded): caller keeps NOT_STARTED

# approval/engine.py
class ApprovalEngine:
    def __init__(self, settings: ApprovalSettings, *, authenticator: ApproverAuthenticator,
                 tokens: ApprovalTokenService, audit: AuditSink, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None) -> None: ...
    def decide(self, package: ActionPackage, request: DecisionRequest,
               credentials: Sequence[ApproverCredential]) -> ApprovalOutcome: ...
        # 1 request.package_id == package.package_id, package not expired, evidence hash recomputed (DecisionError)
        # 2 authenticate every credential (AuthenticationError); any non-HUMAN -> ApproverNotAllowedError
        #   (audited APPROVAL_DENIED before raising)
        # 3 decision semantics of 5.3 (DecisionError); quorum and roles of 5.4 (ApproverNotAllowedError)
        # 4 audit DECISION_RECORDED (AuditError -> no token)
        # 5 token = tokens.issue(...) only for APPROVE_ALL / APPROVE_SELECTED; audit TOKEN_ISSUED
```

### 13.16 Execution and verification

```python
# execution/outcome.py
def is_effective(result: ActionResult, *, unable_to_verify_counts: bool) -> bool: ...
def compute_containment_overall(results: Sequence[ActionResult], *,
                                unable_to_verify_counts_as_contained: bool = False) -> ContainmentOverall: ...
def compute_restoration_overall(results: Sequence[ActionResult], *,
                                unable_to_verify_counts_as_contained: bool = False) -> RestorationOverall: ...
def to_incident_state(overall: ContainmentOverall | RestorationOverall) -> IncidentState: ...
# single rule set: also exports ActionVerdict and classify_action(result, *, unable_to_verify_counts, restoration);
# restoration leaves out SKIPPED(CONTROL_NOT_ACTIVE); verification.outcome builds on these (13.23)

# execution/runner.py
class ActionRunner:
    def __init__(self, adapters: AdapterRegistry, verifier: "VerificationEngine", *,
                 registry: ControlRegistry, audit: AuditSink, clock: Clock | None = None) -> None: ...
    def run(self, action: RecommendedAction, token: ApprovalToken, *, package: ActionPackage,
            decision_id: str) -> ActionResult: ...   # pipeline of section 6.2; never raises for one action

# execution/executor.py
class ContainmentExecutor:
    def __init__(self, runner: ActionRunner, tokens: TokenVerifier, settings: Settings, *,
                 audit: AuditSink, simulator: "DryRunSimulator", clock: Clock | None = None) -> None: ...
    def execute(self, package: ContainmentPackage, token: ApprovalToken | None, *,
                dry_run: bool = False) -> ContainmentReport: ...
        # effective dry run = guard.is_dry_run() or dry_run or package.dry_run -> simulator, overall None
        # else token required (ApprovalRequiredError), tokens.verify_package(token, package),
        # run approved keys in package order, rejected keys -> SKIPPED(REJECTED_BY_ANALYST),
        # compute overall, audit CONTAINMENT_COMPLETED

# verification/engine.py
class VerificationEngine:
    def __init__(self, adapters: AdapterRegistry, settings: VerificationSettings, *,
                 clock: Clock | None = None, sleep: Callable[[float], None] | None = None) -> None: ...
    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult: ...
        # adapter = params["verify_integration"] or params["integration"]; poll until terminal or timeout;
        # exceptions -> UNABLE_TO_VERIFY; never raises
```

### 13.17 Restoration

```python
# restoration/registry.py
class InMemoryControlRegistry: ...            # implements ControlRegistry
class JsonlControlRegistry:                   # append-only event log + in-memory view; implements ControlRegistry
    def __init__(self, path: Path | str, *, clock: Clock | None = None) -> None: ...
        # every line carries prev_hash/hash (SHA-256 chain); replay refuses edited, inserted, removed or
        # unchained events, illegal status transitions and identity changes (check_event_sequence)
def control_from_result(action: RecommendedAction, result: ActionResult, outcome: ActionOutcome, *,
                        package: ActionPackage, token: ApprovalToken, decision_id: str,
                        review_after_hours: Mapping[str, int], clock: Clock) -> TemporaryControl: ...

# restoration/planner.py
class RestorationPlanner:
    def __init__(self, registry: ControlRegistry, settings: Settings, *, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None,
                 critical_assets: CriticalAssetPolicy | None = None,
                 executions: ExecutionStateStore | None = None) -> None: ...
        # release action ELEVATED (with warnings) when the control was ELEVATED, the rollback is always
        # elevated, the target is a critical asset under the CURRENT config, or another incident relies
        # on the same effective control (its registered control, or its approved ALREADY_CONTAINED
        # result); the warning names that incident
def required_release_level(control: TemporaryControl, critical_assets=None) -> ApprovalLevel: ...
def release_params(control: TemporaryControl) -> dict: ...   # rollback_params + {"restores": control_key}
    def build_release_package(self, incident: Incident, control_keys: Sequence[str] | None = None, *,
                              requested_by: str = "automation:restoration_planner") -> ReleasePackage: ...
        # only controls in force (ACTIVE or RELEASE_FAILED, RELEASABLE_STATUSES); unknown, other-incident,
        # RELEASE_PENDING or RELEASED key -> RegistryError; nothing releasable -> RegistryError

# restoration/engine.py
class RestorationEngine:
    def __init__(self, runner: ActionRunner, registry: ControlRegistry, tokens: TokenVerifier,
                 settings: Settings, *, audit: AuditSink, simulator: "DryRunSimulator",
                 clock: Clock | None = None, critical_assets: CriticalAssetPolicy | None = None) -> None: ...
    def execute(self, package: ReleasePackage, token: ApprovalToken | None, *,
                dry_run: bool = False) -> RestorationReport: ...
        # token refusals audited GUARD_DENIED; per action the registry entry must match: rollback type,
        # target, params == release_params(control) (integration included), approval level >=
        # required_release_level(control), and the package's registry evidence must name the current
        # registration (package_id, token_id, created_at) -> otherwise FAILED, nothing executed
```

### 13.18 Dry run and reporting

```python
# dryrun/simulator.py
DRY_RUN_HEADER = "DRY RUN"
DRY_RUN_FOOTER = "No containment actions executed."
class DryRunSimulator:
    def __init__(self, *, audit: AuditSink | None = None, clock: Clock | None = None) -> None: ...
    def simulate(self, package: ActionPackage) -> ContainmentReport: ...
        # inside guard.dry_run(); every action -> ActionResult(status=DRY_RUN,
        # dry_run_line=f"{spec.dry_run_verb}: {action.target}"); calls no adapter method; audit DRY_RUN_SIMULATION
    def simulate_restoration(self, package: ReleasePackage) -> RestorationReport: ...   # same rules, release package
def render_dry_run(report: ContainmentReport | RestorationReport) -> str: ...
    # lines: "DRY RUN", one dry_run_line per action in package order, "No containment actions executed."

# reporting/decision_card.py
def render_decision_card(package: ActionPackage, *, incident_title: str | None = None) -> str: ...
# reporting/containment_report.py
def render_containment_report(report: ContainmentReport | RestorationReport) -> str: ...
# reporting/release_checklist.py
def render_release_checklist(package: ReleasePackage) -> str: ...   # ends with "[APPROVE RELEASE] [REJECT]"
```

### 13.19 Lifecycle composition

```python
# lifecycle/store.py
class InMemoryIncidentStore: ...              # implements IncidentStore (thread-safe)
class InMemoryPackageStore: ...               # implements PackageStore; mark_executed raises RuntimeError the 2nd time;
                                              # save() refuses different content under an existing package_id

# lifecycle/machine.py
LIFECYCLE_ACTOR = "automation:lifecycle"
class IncidentStateMachine: ...               # 13.9; also: actor entering APPROVED / RESTORATION_RUNNING must be one of
                                              # the token's approvers; STATE_TRANSITION audited BEFORE save (AuditError -> unchanged)

# lifecycle/investigation.py
DEFAULT_INVESTIGATIONS: Mapping[ObservableType, tuple[ActionType, ...]]   # hostname -> investigate_endpoint, ...
class InvestigationReport:                    # frozen dataclass
    incident_id: str
    enrichments: tuple[EnrichmentResult, ...]
    investigations: tuple[InvestigationResult, ...]
    health: Mapping[str, HealthStatus]        # worst status seen per integration
    errors / evidence_drafts / evidence / degraded_sources (properties); enrichments_for(obs); investigations_for(obs)
class InvestigationService:
    def __init__(self, adapters: AdapterRegistry, *, audit: AuditSink | None = None, clock: Clock | None = None,
                 investigations=DEFAULT_INVESTIGATIONS, enrichment_sources=None, lookback=timedelta(hours=24),
                 query_options=None) -> None: ...
    def run(self, incident: Incident) -> InvestigationReport: ...
        # read methods only (enrich / investigate); any exception from one source -> UNKNOWN result with the
        # classified health and a redacted ErrorInfo; audits ENRICHMENT_RESULT per result, INVESTIGATION_COMPLETED once

# lifecycle/recommendation.py
class PlaybookRule:                           # observable types -> action types; fires on MALICIOUS, or SUSPICIOUS with risk >= min_risk (60)
DEFAULT_PLAYBOOK                              # hostname: isolate; sha256: block_hash; domain/url/ip: block_*; user: disable + revoke;
                                              # email_message_id: quarantine_email
class Recommendation:                         # proposals, risk_score, confidence_score, summary, unrouted, notes
class Recommender(Protocol):
    def recommend(self, incident: Incident, investigation: InvestigationReport) -> Recommendation: ...
class RuleBasedRecommender:                   # deterministic Phase 0 rules (module docstring); integration = first enabled
    def __init__(self, adapters, *, playbook=DEFAULT_PLAYBOOK, params_for=None, preferred_integrations=None): ...

# lifecycle/runtime.py
@dataclass
class Runtime:
    settings: Settings
    clock: Clock
    secrets: SecretProvider
    audit: AuditSink
    adapters: AdapterRegistry
    tokens: ApprovalTokenService
    approval: ApprovalEngine
    packages: PackageBuilder
    registry: ControlRegistry
    executor: ContainmentExecutor
    restoration: RestorationEngine
    planner: RestorationPlanner
    simulator: DryRunSimulator
    machine: IncidentStateMachine
    orchestrator: "ResponseOrchestrator"
    # additions: verification, runner, investigator, recommender, health (HealthMonitor),
    # incident_store, package_store, recorder (AuditRecorder); property dry_run; close()

def build_runtime(settings: Settings, secrets: SecretProvider, *, authenticator: ApproverAuthenticator,
                  clock: Clock | None = None, audit: AuditSink | None = None,
                  registry: ControlRegistry | None = None, ledger: TokenUseLedger | None = None,
                  transport_factory: Callable[[str], httpx.BaseTransport | None] | None = None,
                  incident_store: IncidentStore | None = None,
                  package_store: PackageStore | None = None,
                  sleep=None, execution_state_store=None, recommender=None, investigator=None,
                  id_factory=None, max_concurrency: int = 1, integration_concurrency=None) -> Runtime: ...
    # defaults: AuditTrail / JsonlControlRegistry / JsonlTokenUseLedger at settings.runtime paths;
    # runner gets control_factory=restoration.control_from_result;
    # guard.configure(dry_run=settings.runtime.dry_run, clock=clock); guard.register_verifier(tokens);
    # guard.set_denial_hook(AuditRecorder(audit).guard_denial_hook())   (process-global: one runtime per process)
def bootstrap(config_dir="config", *, authenticator, env=None, secrets=None, clock=None,
              transport_factory=None) -> Runtime: ...     # load_settings (DRY_RUN env wins) + default_secret_provider
def in_memory_runtime(settings, secrets, *, authenticator, clock=None, **kw) -> Runtime: ...   # tests, lab, simulator

# lifecycle/orchestrator.py
class ResponseOrchestrator:
    def __init__(self, runtime: Runtime, *, incidents: IncidentStore, packages: PackageStore) -> None: ...
    def open_incident(self, incident: Incident) -> Incident: ...                      # audit INCIDENT_RECEIVED; duplicates refused
    def investigate(self, incident_id: str) -> InvestigationReport: ...               # automatic, read-only
    def recommend(self, incident_id: str, investigation: InvestigationReport) -> Recommendation: ...
    def build_package(self, incident_id: str, recommendation: Recommendation) -> ContainmentPackage: ...
        # package.dry_run = guard.is_dry_run(): a package proposed in dry run is only ever simulated
    def handle_detection(self, incident: Incident) -> "DetectionResult": ...          # open + investigate_and_propose
    def investigate_and_propose(self, incident_id: str) -> "DetectionResult": ...     # NOT_STARTED only; nothing to propose
        # (or everything allow-listed) keeps NOT_STARTED; dry run also returns the DRY RUN report
    def reinvestigate(self, incident_id: str, *, actor: str, reason: str) -> "DetectionResult": ...
        # AWAITING_APPROVAL -> NOT_STARTED -> investigate_and_propose (expired packages)
    def propose(self, incident_id: str, package: ContainmentPackage) -> ContainmentPackage: ...
        # -> AWAITING_APPROVAL; audit PACKAGE_PROPOSED; a newer package supersedes a pending one
    def submit_decision(self, request: DecisionRequest,
                        credentials: Sequence[ApproverCredential]) -> "DecisionResult": ...
        # only the latest, unexecuted containment package of an AWAITING_APPROVAL incident (DecisionError otherwise)
        # approve: APPROVED (analyst + token) -> CONTAINMENT_RUNNING -> execute automatically -> verify ->
        #   CONTAINED / PARTIALLY_CONTAINED / CONTAINMENT_FAILED -> REMEDIATION_REQUIRED when verification says so;
        #   executor refusal (ApprovalRequiredError) -> CONTAINMENT_FAILED; dry run -> simulated, state unchanged
        # reject: CLOSED; more investigation: NOT_STARTED
    def propose_retry(self, incident_id: str, *, requested_by=...) -> ContainmentPackage: ...
        # new package with the FAILED approved actions of the last run (needs a new human approval)
    def dry_run(self, package: ContainmentPackage) -> ContainmentReport: ...          # no state change
    def mark_remediation_required(self, incident_id: str, *, actor: str, reason: str) -> Incident: ...
    def propose_release(self, incident_id: str, control_keys: Sequence[str] | None = None, *,
                        requested_by=...) -> ReleasePackage: ...
        # -> AWAITING_RELEASE_APPROVAL; audit RELEASE_PACKAGE_PROPOSED
    def submit_release_decision(self, request: DecisionRequest,
                                credentials: Sequence[ApproverCredential]) -> "DecisionResult": ...
        # approve: RESTORATION_RUNNING (analyst + release token) -> RESTORED or AWAITING_RELEASE_APPROVAL
        # reject or more investigation: REMEDIATION_REQUIRED (controls stay ACTIVE); close() is separate
    def close(self, incident_id: str, *, actor: str, reason: str) -> Incident: ...    # never touches the registry;
                                                                                       # lists controls still in force
    # read helpers: get_incident, get_package, latest_package, report_for, outstanding_controls, audit_summary

@dataclass(frozen=True)
class DecisionResult:
    outcome: ApprovalOutcome
    incident: Incident
    report: ContainmentReport | RestorationReport | None
    assessment: ContainmentAssessment | None = None   # verification.outcome assessment (attention, next state)
    error: str | None = None
    # properties: dry_run, recommended_next_state

@dataclass(frozen=True)
class DetectionResult:
    incident: Incident
    investigation: InvestigationReport
    recommendation: Recommendation
    package: ContainmentPackage | None
    dry_run_report: ContainmentReport | None = None
    notes: tuple[str, ...] = ()
```

### 13.20 Test fixtures contract

```python
# tests/fixtures/factories.py   (owner: core)
def make_incident(incident_id: str = "XDR-83921", **overrides: Any) -> Incident: ...
def make_evidence(n: int = 2, source: str = "secure_endpoint") -> tuple[Evidence, ...]: ...
def make_recommendation(action_type: ActionType = ActionType.ISOLATE_ENDPOINT, target: str = "TH-LT-1047",
                        integration: str = "secure_endpoint", incident_id: str = "XDR-83921",
                        approval_level: ApprovalLevel = ApprovalLevel.STANDARD, **params: Any) -> RecommendedAction: ...
def make_package(*actions: RecommendedAction, incident_id: str = "XDR-83921", **overrides: Any) -> ContainmentPackage: ...
FIXED_NOW: datetime                           # 2026-01-15T12:00:00Z

# tests/fixtures/principals.py   (owner: core)
ANALYST_ID = "analyst.one@example.com"; ELEVATED_ID = "lead.two@example.com"
def make_authenticator() -> InMemoryApproverAuthenticator: ...   # human analyst, elevated human, service, automation, AI
def credential(principal_id: str) -> ApproverCredential: ...
TEST_SIGNING_KEY_NAME = "APPROVAL_SIGNING_KEY"
def make_test_secrets(**extra: str) -> StaticSecretProvider: ...   # random 32-byte hex signing key per call

# tests/fixtures/http_mocks.py   (owner: integrations-core)
class MockRouter:
    def __init__(self) -> None: ...
    def add(self, method: str, path: str, *handlers: Callable[[httpx.Request], httpx.Response] | httpx.Response) -> None: ...
        # handlers are served in order, the last one repeats; unmatched routes answer HTTP 599
    def transport(self) -> httpx.MockTransport: ...
    @property
    def calls(self) -> list[httpx.Request]: ...
    def calls_to(self, method: str, path: str) -> list[httpx.Request]: ...
def json_response(status: int, body: Any = None, headers: Mapping[str, str] | None = None) -> httpx.Response: ...
```

### 13.21 Contract summary

| Shared type | Module |
|---|---|
| All enums (`IncidentState`, `ApprovalLevel`, `DecisionType`, `PrincipalKind`, `ApprovalPurpose`, `ActionResultStatus`, `SkipReason`, `ContainmentOverall`, `RestorationOverall`, `VerificationStatus`, `HealthStatus`, `OperationKind`, `EndpointStatus`, `ActionCategory`, `TargetKind`, `ObservableType`, `Verdict`, `RiskBand`, `Severity`, `CriticalAssetClass`, `ControlStatus`, `TargetState`, `ErrorCode`, `AuditEventType`) | `xdr_response.models.enums` |
| `ActionType`, `ActionSpec`, `ACTION_CATALOG`, `BOOKKEEPING_OPERATIONS`, `get_action_spec`, `is_state_changing`, `purpose_for`, `rollback_for` | `xdr_response.models.catalog` |
| `canonical_json`, `sha256_hex`, `params_hash`, `normalize_target`, `make_idempotency_key` | `xdr_response.models.canonical` |
| Data models of 13.5 | `xdr_response.models.<module>`, re-exported by `xdr_response.models` |
| Exceptions | `xdr_response.errors` |
| `Clock`, `SystemClock`, `FixedClock` | `xdr_response.clock` |
| Protocols | `xdr_response.interfaces` |
| Guard API | `xdr_response.guard` |
| `IntegrationAdapter`, `CapabilityManifest`, `OperationSpec`, `GuardedHttpClient`, `AdapterRegistry` | `xdr_response.integrations.*` |
| `ALLOWED_TRANSITIONS`, `TOKEN_REQUIRED`, `can_transition` | `xdr_response.models.states` (re-exported by `xdr_response.models` and `xdr_response.lifecycle.states`) |
| `INTEGRATION_NAMES` | `xdr_response.models.catalog` (re-exported by `xdr_response.config.schema`, `xdr_response.config`, `xdr_response.integrations`) |

### 13.22 Core implementation notes (binding additions, as built)

The core phase implemented 13.1 to 13.11, 13.13 (`base.py`, `__init__.py`) and the core fixtures of 13.20. Every name above exists with the signature shown. The points below are additions or clarifications; other components code against them.

**Models (`xdr_response.models`)**

- Private helpers: `models/_base.py` (`FrozenModel`, `JsonDict`, `Score`), `models/_common.py` (home of `ErrorInfo` and `ApiCallSummary`, re-exported by `models.action`), `models/_validation.py`. `FrozenModel` and `JsonDict` are also re-exported by `xdr_response.models`.
- `canonical_json(data, *, allow_floats=False)`: pydantic models are dumped with `model_dump(mode="python")` and then normalized by the same rules (datetime `...ffffffZ`, enums to values, tuples to lists, sets sorted, `SecretStr` to `"**********"`), so a model and its JSON round trip give identical bytes. `allow_floats=True` is used only for evidence hashing (vendor data contains floats); signed data (`params`, token claims) never allows floats. `format_datetime(dt)` is exported.
- `models/states.py` holds `ALLOWED_TRANSITIONS`, `TOKEN_REQUIRED`, `can_transition` (layer 0). `lifecycle/states.py` is a core-owned re-export; the lifecycle component adds `machine.py` etc. and may replace `lifecycle/__init__.py` (docstring only today).
- Extra validators (all deterministic, all raise `ValidationError`):
  - `EvidenceDraft.source` must be an integration name or `analyst` / `temporary_control_registry`; anything AI-like (`ai`, `ai:*`) is refused.
  - `RecommendedAction` and `ActionRequest`: `target` must already be normalized (`normalize_target`), `target_kind` equals the catalog kind, key equals `make_idempotency_key(...)`, `params["integration"]` is a non-empty string. `RecommendedAction` additionally requires `params` to be canonicalizable (no floats). `ActionRequest` accepts read action types too (the guard refuses them).
  - `ActionPackage`: `expires_at > created_at`, unique evidence numbers, and every action's catalog purpose equals the package purpose (a release action can never sit in a containment package). `ReleasePackage`: `control_keys[i] == actions[i].params["restores"]`, no duplicates.
  - `ActionResult`: `SKIPPED` requires `skip_reason` (and only `SKIPPED` may carry one); `DRY_RUN` requires `dry_run_line`; `finished_at >= started_at`. `ContainmentReport` / `RestorationReport`: `dry_run=True` requires `overall=None`.
  - `TemporaryControl`: the action type must have `creates_control=True`, `rollback_action_type` must equal the catalog rollback, and `control_key` must equal `make_idempotency_key(incident_id, action_type, target)`.
  - `AnalystDecision`: approved and rejected keys disjoint; `analyst_identity` equals the first approver; `REJECT` / `REQUEST_MORE_INVESTIGATION` carry no approved keys and no `token_id`.
  - `ApprovalTokenClaims`: `expires_at > issued_at`, unique grant keys; fields `dry_run: bool = False` and `issuance_proof: str | None = None` (13.24). `ApproverClaim.roles` is sorted and de-duplicated by a validator. `ApprovalToken.key_id` matches `[A-Za-z0-9_-]{1,64}`; `str(token)` and `repr(token)` never show the signature. `ApprovalToken.decode` checks shape only (never the signature).
  - `ApiCallSummary.request_summary` / `response_summary` are capped automatically: over 4 KiB they become `{"_truncated": true, "_original_bytes": n, "preview": "..."}`.
  - `InvestigationQuery.action_type` must be an INVESTIGATION type.
- `models.catalog` also exports `STATE_CHANGING_CATEGORIES`. Read-only types list their candidate integrations per type (for example `enrich_email_address`: cisco_xdr, hibp; `enrich_user`: cisco_xdr, entra).

**Errors.** `IntegrationTimeoutError`, `RateLimitedError` and `IntegrationUnavailableError` default to `retryable=True`; `RateLimitedError(message, *, integration, http_status=429, retryable=True, retry_after=None)`. `IntegrationError.to_error_info()` redacts the message with `get_redactor()` (lazy import). Model modules never import `xdr_response.errors` at import time.

**Interfaces.** Aliases `ApprovalVerifier = TokenVerifier` and `StateStore = IncidentStore`; `Clock` is re-exported from `xdr_response.clock`. All protocols are `runtime_checkable`.

**Guard.** In addition to 13.10:

- `register_verifier` raises `TypeError` unless the object implements `TokenVerifier`, and `ApprovalRequiredError` when a verifier of a different class is already registered (see 13.24).
- `authorized` raises `TypeError` for a non-`ActionRequest`, `ApprovalRequiredError` for a missing or non-`ApprovalToken` token, and `ValueError` for a read action type (after the verifier and dry-run checks). After `verifier.verify` it re-checks deterministically that the returned grant matches the binding and that the token purpose and incident match (a buggy verifier cannot widen an approval). Any non-`ApprovalRequiredError` exception from `verify` or `mark_used` becomes `TokenInvalidError` (fail closed).
- `configure(clock=...)` only sets the clock used for `AuthorizationContext.entered_at`; expiry is decided by the verifier.
- Denial hook exceptions are swallowed; the denial is still raised. `STATE_CHANGING_ATTR = "__xdr_state_changing__"`.

**Config.**

- `IntegrationConfig.base_url` must be `https://` (or `http://localhost` / `http://127.0.0.1` for local mocks) without credentials and without secret-bearing query or fragment parameters (any name `Redactor.is_sensitive_key` accepts, for example `api_key`); `secrets` values must match `SECRET_NAME_PATTERN`. `ApprovalSettings.elevated_role` must differ from `standard_role` (case-insensitive).
- `AllowlistsConfig` adds `approved_dns_tools: list[dict]` (same shape as `approved_rmm`), accepts `approved_rmm_allowlist` as an input alias of `approved_rmm`, and validates `never_block` keys (`domains, urls, ips, cidrs, hashes, users, endpoints`), CIDRs, IPs and hashes. `ExclusionsConfig.third_party_lookup` keys are limited to `internal_domain_suffixes, cidrs, user_domains, hostnames`. `review_after_hours` keys must be action type values.
- `Settings` always contains all 16 integrations (missing ones get `IntegrationConfig()`, disabled); `Settings.integration(name)` returns one (KeyError for unknown names).
- `load_settings`: a missing config directory is a `ConfigError`; `DRY_RUN` must be exactly `true` or `false` (case-insensitive), anything else is a `ConfigError`; extra overrides `XDR_RESPONSE_REGISTRY_PATH`, `XDR_RESPONSE_TOKEN_LEDGER_PATH`. Sensitive keys (per `Redactor.is_sensitive_key`) anywhere in any file may only hold a secret NAME or null. Error messages name the key path and never echo the value. Exported helpers: `parse_bool`, `CONFIG_FILES`.
- `AllowlistPolicy.excluded_reason` applies only to containment-purpose actions (restoration is never blocked by an allow-list); approved RMM and DNS tool hashes and domains are excluded with reason `allowlists.approved_rmm: <name>` / `allowlists.approved_dns_tools: <name>`; `FILE` and `PROCESS` composite targets are checked by endpoint and hash.
- `DisclosurePolicy(config, *, allow_documentation_ranges=False)` restricts only `THIRD_PARTY_INTEGRATIONS = {"virustotal", "alienvault_otx", "hibp"}`. Non-global IPs are never disclosed; the RFC 5737 / 3849 documentation ranges count as non-public unless `allow_documentation_ranges=True` (tests and lab only, so adapter tests can use 203.0.113.x). Single-label names and built-in internal suffixes (`local`, `localhost`, `internal`, `lan`, `home.arpa`, `intranet`, `corp`) are never disclosed. HIBP receives only email addresses outside `user_domains`.

**Secrets.** `FileSecretProvider(directory, *, redactor=None)` reads mounted secret files `<directory>/<NAME>`; `default_secret_provider(environ=None, *, mount_dir=None)` chains environment then files (`XDR_RESPONSE_SECRETS_DIR`). Secret names are validated against `SECRET_NAME_RE` (`ValueError`), which also prevents path traversal. `SecretValue` is immutable, unhashable, compares in constant time, and refuses pickling (`TypeError`); `json.dumps` of it fails, and `str`, `repr`, `format` show `***`.

**Logs and redaction.** `SENSITIVE_KEY_PATTERN` is applied with `fullmatch` to `normalize_key(key)` (camelCase to snake_case, lower case); always call `Redactor.is_sensitive_key`. Exact-only terms: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `key`, `session`, `credential(s)`, `signature`, `sig`. Suffix terms (also `<prefix>_<term>` / `<prefix>-<term>`): `password`, `passwd`, `passphrase`, `secret`, `client_secret`, `secret_key`, `token`, `access_token`, `refresh_token`, `id_token`, `session_token`, `session_key` / `sessionKey`, `session_id`, `signing_key`, `recovery_key`, `recovery_password`, `secret_access_key`, `api_key` / `apikey` / `api-key`, `private_key`, `approval_token`, `unlock_code`. So `idempotency_key`, `control_key`, `token_id`, `params_hash`, `claims_hash` stay readable in audit records, while `hec_token`, `api_secret`, `APPROVAL_SIGNING_KEY` and `X-Cisco-Meraki-API-Key` are redacted. `redact_text` scrubs registered values, JWT-shaped strings, encoded approval tokens for every legal key id, `<scheme> <credential>` with a case-insensitive scheme (Bearer, Basic, Splunk, ApiKey), and every `key=value` / `key: value` pair with a sensitive key, with optional quotes around key and value (JSON text, Python dict reprs, echoed headers, URL query strings inside free text such as `?key=` and `&sig=`). `get_logger` loggers live under `xdr_response`; `configure_logging` sets `propagate=False` on that logger (tests that use `caplog` must not call it, or must restore the logger).

**Integrations base.** `IntegrationAdapter` additionally provides: class attributes `default_base_url` and `secret_names` (logical name to default secret NAME); `base_url` (config or default, else `ConfigError`); `secret(logical)` (resolves through `config.secrets`, then `secret_names`); overridable `build_auth()` and `default_headers()`; `build_http_client()`, which lazily imports `GuardedHttpClient`, `RetryPolicy` and `RateLimiter` from `integrations/http.py` and calls them with the 13.13 keyword names (integrations-core must keep those names); `http` is a lazily built property with a setter (tests may assign a fake); `close()`; `disabled_health()`. Class creation fails with `TypeError` when a subclass defines a method named after a state-changing `ActionType` value (or overrides `execute`) without `@state_changing`, when `manifest.supported_actions` names an action without such a method, or when `name != manifest.integration`. `execute` raises `IntegrationUnavailableError` (not retryable) when the adapter is disabled. `CapabilityManifest` validates: known integration, unique operation names, every `supported_actions` entry served by a VERIFIED `STATE_CHANGING` operation, `verifiable_actions` state-changing only, `read_actions` not state-changing; `OperationSpec` with `VERIFIED` needs `source`, and `PUT`/`PATCH`/`DELETE` cannot be `READ` or `VERIFY`. `CapabilityManifest.unverified_operation_for(action_type)` is public. `integrations.STATE_CHANGING_ACTION_NAMES` lists the reserved method names. `xdr_response.integrations` resolves `GuardedHttpClient`, `RetryPolicy`, `RateLimiter`, `HttpResult`, auth classes, `ADAPTER_PATHS`, `AdapterRegistry`, `load_adapter_class`, `HealthMonitor` and `classify_exception` lazily from their modules.

**Test fixtures.** `tests/fixtures/factories.py` also exports `FAKE_SHA256`; `make_recommendation` forces `ELEVATED` for always-elevated types and puts extra keyword arguments into `params` (for example `restores=...`). `tests/fixtures/principals.py` also exports `SERVICE_ID`, `AUTOMATION_ID`, `AI_ID`, `STANDARD_ROLE`, `ELEVATED_ROLE` and `PRINCIPALS`; non-human principals hold every role on purpose. `tests/fixtures/guard_helpers.py` provides `FakeVerifier` (checks purpose, incident, grant binding, expiry, HUMAN approvers and single use, but not the signature), `make_token(*actions, purpose=None, issued_at=FIXED_NOW, ttl=30 min, approver_kind=HUMAN, incident_id=None, token_id=None)` and `install_fake_verifier(clock=None, *, dry_run=False)` so adapter tests can drive guarded methods without the approval package. `tests/conftest.py` calls `guard._reset_for_test_harness()` before and after every test; `install_fake_verifier` re-uses the FakeVerifier already sealed in the guard within one test (13.25).

### 13.23 Phase 0 integration notes (binding, as built)

The integration phase wired the components together, built `lifecycle/` (13.19), the simulator and the integration and simulation tests, and settled every interface issue the component reports raised. Resolutions:

**Integrations**

- `integrations/auth.py` exists with the 13.13 signatures. Additions: `OAuth2ClientCredentials(..., integration="oauth2", timeout=15.0, redactor=None, refresh_margin_seconds=120, client_factory=None)`; the token is cached per provider (thread-safe) and refreshed 120 s before `expires_in` (at most half the lifetime), so Umbrella's "expired token returns 400" never happens in practice. Token responses accept `access_token` / `accessToken` and `expires_in` / `expiresIn` (default 3600 s); the token is registered with the redactor. Token failures map to `AuthFailedError` (400/401/403, non-JSON or token-less body), `RateLimitedError` (429), `IntegrationUnavailableError` (5xx, connect errors), `IntegrationTimeoutError`. `token_url` must be `https://` (or localhost). The 21 auth-wiring vendor tests run.
- `tests/fixtures/http_mocks.py` (`MockRouter`, `json_response`) is the contract home; `tests/unit/integrations/_support.py` re-exports it. `MockRouter.add(method, path, *handlers)` (in order, last repeats; unmatched routes answer 599) and `calls_to(method, path)` are additions.
- `integrations/_adapter_support.py` (vendor adapter base: `ApiRequest`, `VendorAdapter._send` that refuses non-VERIFIED manifest rows, outcome/verification/enrichment helpers, `CompositeAuth`, disclosure mixin) is private to the vendor adapters. Per-vendor `REQUIRED_SECRETS`, `CONFIG_OPTIONS`, `HEALTH_PROBE` live in each `manifest.py` (not on `CapabilityManifest`).
- UNVERIFIED state-changing manifest rows are named after the action type so `execute()` and a direct call raise the same `UnverifiedEndpointError` message. Splunk HEC uses a second `GuardedHttpClient` inside the adapter (per-request auth override is not a client feature). Defender for Endpoint "Action is already in progress" maps to `ALREADY_CONTAINED`.
- `config/integrations.example.yaml` sets `options.oauth_scope` for entra, defender_o365, intune and microsoft_cloud, with a comment that the scope string is UNVERIFIED (docs/integrations.md 2.8); the adapters still refuse to build auth without an explicit value.
- `SimulatedEnvironment.set_reputation(..., integrations=None)`: a reputation can be limited to the integrations that would really know it (the others report `UNKNOWN`). Simulated `verify` sets `terminal=True` (the in-memory state is authoritative).
- Audit failure policy of `GuardedHttpClient`: READ/VERIFY audit failures are logged and the call continues; STATE_CHANGING/BOOKKEEPING audit failures raise `AuditError` after the response. Pre-execution audit gating is the runner's `ACTION_STARTED` (no audit, no execution).

**Approval and guard**

- `ApprovalSettings.previous_signing_key_id` (optional) names the key id of `APPROVAL_SIGNING_KEY_PREVIOUS` after a rotation that changed the id; `ApprovalTokenService(previous_key_id=...)` still overrides it.
- `interfaces.PackageTokenVerifier` (13.8) is the optional `verify_package` extension; `execution.protocols` re-exports it. The executor and the restoration engine call it when present and always run their own deterministic binding check.
- An expired package refuses every decision type (13.15 step 1). The orchestrator recovers with `reinvestigate()` (`AWAITING_APPROVAL -> NOT_STARTED -> new package`) or `close()`.
- Every decision, including REJECT and REQUEST_MORE_INVESTIGATION, needs authenticated HUMAN principals holding `standard_role` or `elevated_role`; quorum rules apply to approvals only.
- Blast radius: composite targets (FILE, PROCESS, PERSISTENCE_ITEM, ROLE_ASSIGNMENT) count by their endpoint or user part; DOMAIN, URL, IP, HASH count as indicators; EMAIL_MESSAGE as messages; NETWORK_CLIENT, CREDENTIAL, APPLICATION are not counted.
- `JsonlTokenUseLedger.consume` holds an OS-level exclusive lock (`<ledger>.lock`, same `InterProcessLock` as the audit trail) around refresh, check and append, so several instances or processes on one ledger file never consume the same `(token_id, idempotency_key)` twice. One runtime per process still applies to the guard (13.19).
- `dryrun.dry_run_scope()` is the way to lock dry run for a scope (it also enters `guard.dry_run()`, which `configure(dry_run=False)` cannot clear). A process-wide lock API is not part of Phase 0.

**Execution, verification, restoration**

- One rule set: `execution.outcome` owns `ActionVerdict`, `classify_action`, `is_effective`, `compute_*_overall` and `to_incident_state`; restoration leaves out `SKIPPED(CONTROL_NOT_ACTIVE)` and rejected actions. `verification.outcome` re-uses them, returns `None` for an all-`DRY_RUN` set (it filters `DRY_RUN` out of mixed sets), and adds the per-action assessment and the recommended next state. `execution.outcome` raises `ValueError` for `DRY_RUN` results.
- `VerificationResult.terminal` (13.5): adapters that know the vendor state is final set it; the engine stops polling on `terminal=True` (for example a terminal `NOT_VERIFIED`).
- `ActionRunner(..., control_factory=None)`: `build_runtime` injects `restoration.control_from_result`, so registry entries are built by one rule; without a factory the runner's equivalent private builder is used. Engines still never import each other (2.4).
- `execution.ExecutionStateStore` (in-memory and SQLite) holds per-(package, key) claims; `interfaces.StateStore` stays an alias of `IncidentStore`. `build_runtime(execution_state_store=..., max_concurrency=1, integration_concurrency=None)` exposes the executor knobs.
- `ContainmentExecutor.execute` raises an `ApprovalRequiredError` subclass (audited `GUARD_DENIED`) for a missing token or one that does not bind the package; the orchestrator turns that into `CONTAINMENT_FAILED`.
- Restoration: releasable statuses are `ACTIVE` and `RELEASE_FAILED` (`RELEASABLE_STATUSES`, 8.2); `list_active()` returns `ACTIVE` only and `list_releasable()` both. The restoration overall is computed from each approved control's final registry status (a re-run where every control was already released reports `RESTORED`). `RestorationEngine` uses `DryRunSimulator.simulate_restoration` when available. `register()` refuses secret-like `rollback_params` keys.
- REMEDIATION_REQUIRED rules (deterministic, `verification.outcome`): a control reported applied but not in effect (`NOT_VERIFIED`), a non-transient failure (auth, invalid target, unsupported/unverified endpoint, platform fault) or a `NO_CAPABLE_ADAPTER` / `INTEGRATION_DISABLED` skip. The orchestrator applies `REMEDIATION_REQUIRED` automatically (a lifecycle state, not a vendor change). Transient failures only *recommend* `AWAITING_APPROVAL`; `propose_retry()` builds the new package, which needs a new human approval.

**Reporting and dry run**

- `DryRunSimulator.simulate_restoration(package) -> RestorationReport` is an addition; the restoration dry-run report also ends with `DRY_RUN_FOOTER`.
- ELEVATED warnings without a critical-asset class are explained by the warning's role: the restoration planner's "control created under ELEVATED ..." gets "the original control was approved at ELEVATED level, or the rollback is privileged"; any other (the package builder's blast-radius warnings) gets "blast radius above the configured threshold".
- The decision card maps action evidence to package evidence numbers by content (the same key as `number_evidence` and `PackageBuilder`); changing evidence normalization must keep the three in step.

**Audit**

- The audit CLI is `tools/validation/verify_audit_chain.py` (13.2 and 3.1 updated). `verify_chain(path, *, anchors=())` and `AuditTrail.anchor()` / `MemoryAuditTrail.anchor()` export external checkpoints that detect tail truncation and full rewrites. `AuditTrail` additionally maintains its own head anchor file (13.12, 13.24) and checks it on open, on re-sync and in `verify()`. Record hashing allows floats (enrichment scores); non-finite floats are stored as strings. `ERROR` records carry a bare `ErrorInfo`; context goes in the event-specific records.

**Simulator and tests**

- `tools/simulator/simulate.py` runs a fixture incident end to end (`--live` for simulated-live, dry run by default) and prints the decision card, the containment result, the release checklist and the restoration result; `tools/simulator/scenario.py` holds `Scenario`, `load_scenario`, `ScenarioRun` and `SIMULATION_SUITE`. Scenarios live in `tests/fixtures/incidents/` (ransomware, phishing, account_takeover, ransomware_domain_controller).
- `tests/integration/` drives real Umbrella, Entra and VirusTotal adapters (real `GuardedHttpClient`, OAuth2 and API-key auth) with every engine over stateful fake vendors on `httpx.MockTransport`. `tests/simulation/` drives the full lifecycle on the simulated environment: approve all, approve selected, reject, more investigation, partial failure, already contained, domain-controller elevation, release and restoration, and dry run with zero state changes.

### 13.24 Safety review round 1 hardening (binding, as built)

The adversarial safety suite (`tests/safety/`) proved the weaknesses below; each is closed by deterministic code. Contract changes are also reflected in 13.9 to 13.23 above.

**Approval and guard**

- `guard.state_changing`: the decorated method's name must be the request's action type (or `execute`), else `ActionMethodMismatchError` (a `TokenMismatchError` and `ValueError`). An approval for `isolate_endpoint` can no longer drive `release_endpoint`, `disable_user` cannot drive `enable_user`, and so on.
- One authorization authorizes one guarded call (the outermost `@state_changing` call consumes it; nested guarded calls ride along). The HTTP client's STATE_CHANGING path is allowed only while that call runs (round 2 removed "or before any guarded call ran", 13.25).
- Leaving `guard.authorized` closes the context; copies captured inside the block (`copy_context()`, thread pools, asyncio tasks) are refused afterwards.
- `guard.register_verifier` refuses to replace a registered verifier with an object of a different class (round 2: the slot is sealed by the first registration, 13.25).
- `ApprovalTokenService.issue` adds `claims.issuance_proof` (HMAC with the signing key over `TOKEN_ISSUANCE_CONTEXT` and every claim except `issued_at` and the proof) after all policy checks; `verify`, `verify_token` and `verify_package` refuse tokens without a valid proof. Claims fabricated in code and signed with the public low-level `sign()` (for example a HUMAN approver that never decided) therefore never authorize containment or release. Round 2 (13.25) closed the remaining path: `issue()` requires the engine-bound `TokenIssuer` capability. Residual risk (11.2): code that holds the signing key itself can still sign.
- Tokens carry `claims.dry_run` (= `package.dry_run`). While dry run is active the orchestrator decides on a copy of the package marked `dry_run`, so a token issued for a simulation is refused by `verify`, by `verify_package` (flag must equal the package's) and by `check_token_binds_package`, even after dry run is switched off within the TTL.
- `IncidentStateMachine` verifies the token (13.9) and refuses a token or package that already entered `APPROVED` / `RESTORATION_RUNNING` for the incident.
- `ApprovalSettings.elevated_role` must differ from `standard_role`.

**Adapters and HTTP**

- `GuardedHttpClient`: `PUT`/`PATCH`/`DELETE` are always STATE_CHANGING; BOOKKEEPING is POST-only; a client owned by an adapter carries the adapter's manifest (attached by `IntegrationAdapter.build_http_client` and the `http` setter; Splunk's HEC client too) and every request must match its manifest row (operation, method, kind), so a manifest write can never be declared READ.
- Cisco XDR native actions act only on the approved target: `observable_value`, if given, must equal `target`, and `observable_type` must fit the target kind (`hostname` for endpoints, `domain`, `url`, `ip`/`ipv6`, `sha256`/`sha1`/`md5`, `user`/`email`, `email_messageid`); otherwise `InvalidTargetError` before anything is sent.
- Secure Email moves exactly the approved message; `params.message_ids` may only repeat the target (rollback params likewise).

**Secrets and audit**

- Redaction (13.22): JSON / dict-repr / query-string key-value pairs, case-insensitive auth schemes, encoded approval tokens for every key id, additional sensitive key names (`sig`, `signing_key`, `session_key`, `session_id`, `recovery_key`, `secret_access_key`, ...). Vendor error excerpts are redacted before truncation. `HttpResult.body` / `text` are hidden from `repr`.
- Config refuses secret-bearing query parameters in `base_url`.
- Audit lines must be byte-for-byte canonical (no duplicate keys). `AuditTrail` keeps a head anchor file and refuses (on open, on re-sync with other writers and in `verify()`) a chain that ends before or after the anchor, so tail truncation and offline appends of well-chained forged records are detected. Recovery after a crash between a record write and its anchor write is an operator action (verify the file with `tools/validation/verify_audit_chain.py`, then restore the anchor); there is no automatic adoption path. The simulator writes `--audit-out` files with `encode_record_line`.

**Execution and restoration**

- `JsonlTokenUseLedger` takes an OS-level file lock (13.23).
- `ActionRunner`: when an action finds its target `ALREADY_CONTAINED` and an earlier attempt for the same key in another package of the incident sent a write with unknown outcome (FAILED with code `TIMEOUT` and the marker `UNKNOWN_OUTCOME_MARKER`, or a claim that never completed), the control is registered (reconstructed rollback params from the request, flagged requires attention) instead of becoming an orphan.
- `RestorationEngine` binds every release action to the registry record (13.17): recorded rollback params and integration, approval level at least `required_release_level`, and the current registration (so a consumed release approval cannot be replayed after the same key was re-registered). Token refusals are audited `GUARD_DENIED`.
- `RestorationPlanner` applies the current critical-asset policy and warns (ELEVATED) when another incident relies on the same effective control (13.17).
- `TemporaryControl.control_key` must match its incident, action type and target. `JsonlControlRegistry` lines are hash-chained and replay validates the status table and identity fields (all backends validate the event sequence on append).

### 13.25 Safety review round 2 hardening (binding, as built)

Round 2 of the adversarial suite (`tests/safety/`, tests named `test_r2_*` plus the secrets/audit round-2 cases) proved the weaknesses below. Each is closed by deterministic code; 13.10, 13.12 and 13.24 are updated accordingly.

**Guard (13.10)**

- The verifier slot is sealed by the first `register_verifier`: afterwards only the identical instance may be registered again. `unregister_verifier()` and the public `reset_for_tests()` empty the slot but keep the seal (fail closed for good); neither can re-open it for a permissive verifier, another `ApprovalTokenService` with an attacker key, or a same-key service with an empty ledger (which would re-enable consumed tokens). Only the private `guard._reset_for_test_harness()` (tests/conftest.py) removes the seal. Consequence: one runtime per process; a second `build_runtime` is refused before it touches the dry-run flag (`build_runtime` now registers the verifier first, then configures dry run).
- STATE_CHANGING HTTP requests need the authorization's single use to be in flight: inside the running `@state_changing` call, or as one raw logical request (`guard.write_window`) that consumes the single use, must carry the approved target in its URL or body and (with a manifest) must use an operation that serves the approved action type. Writes before the guarded call (for example from the read-only pre-check), after it returned, a second raw write, or a raw write to another object are refused. The in-flight state lives in the shared `_ContextState`, so a context copied during the call loses the authority when the call returns.
- `guard.check_token(token, action)` verifies without consuming (used by the runner before it claims an action).

**Approval (13.15)**

- `ApprovalTokenService.issue(...)` requires the `TokenIssuer` capability from `bind_issuer()`, which works exactly once and is taken by the `ApprovalEngine` constructor. A caller with fabricated `AnalystDecision` / `AuthenticatedPrincipal` objects (no authenticator, no `DECISION_RECORDED`) cannot mint a token, whether or not it holds the service. The executor, restoration engine and state machine receive a verify-only `TokenVerifierView` (`verify`, `verify_token`, `verify_package`, `mark_used`, `is_revoked`, `was_used`).
- Decisions are final per package, with the state kept in the token-use ledger (durable and shared by every worker on the same ledger): a live package is approved once (`claim_approval`); REJECT and REQUEST_MORE_INVESTIGATION revoke the package (`revoke_package`), so a token issued earlier (double submit, second analyst) stops verifying everywhere (`verify`, `verify_token`, `verify_package`, guard); a revoked package is never approved again. `ResponseOrchestrator.close()` revokes the latest unexecuted containment and release packages of the incident, so an approval issued before closing can no longer run against the CLOSED incident.
- ELEVATED is enforced at decision time, not only by `PackageBuilder`: `PackageBuilder.policy_violations(package, incident)` re-runs the critical-asset rules (with the incident's asset context), `always_elevated` and the blast-radius caps; `ResponseOrchestrator.propose()` refuses (ValueError) and `ApprovalEngine.decide` refuses (DecisionError, `level_policy` wired by `build_runtime`) a package that marks such an action STANDARD.
- `PackageBuilder` always evaluates the incident's asset record; a proposal-supplied `Asset` (untrusted workflow data) is merged into it (union of groups, tags, roles) and can never replace or shrink it.

**Adapters and HTTP (13.13)**

- The manifest check matches the URL too: the request path (and host for absolute URLs; `{x}` matches one segment, a region label such as `us` matches any region) must be the manifest row's documented path, relative to the host or to the base URL path. An operation without a documented path cannot be sent. A client without a manifest still refuses a non-STATE_CHANGING request whose method and URL match a STATE_CHANGING operation of the integration's registered manifest. A VERIFIED write URL can therefore never be sent under a READ / VERIFY / BOOKKEEPING operation name.
- Writes act only on the approved target, never on an object named in params: Secure Endpoint looks up `GET /v1/computers/{guid}` and requires `hostname` = target before isolate / release; Defender for Endpoint looks up `GET /api/machines/{id}` (`computerDnsName`) when `params.machine_id` differs from the target; Intune looks up `GET managedDevices/{id}` (`deviceName`) before `remoteLock`; Entra `confirm_user_compromised` always resolves the object id from the approved UPN and refuses a differing `params.user_id`; Meraki refuses `params.client_id` / `network_id` that differ from the target `network/client`. Mismatch or an unidentifiable lookup -> `InvalidTargetError`, nothing written (`VendorAdapter._require_identity`).

**Execution (13.16)**

- The executor, restoration engine and orchestrator honour their own `settings.runtime.dry_run` in addition to the guard flag; flipping the process-wide guard flag alone never turns a `DRY_RUN=true` deployment live. The token is still checked in that case (a missing or wrong token is refused, not previewed).
- Dry-run previews of a decision apply the token's grants: actions the analyst rejected are shown as SKIPPED / REJECTED_BY_ANALYST ("Would skip ..."), never as "Would ...".
- `ActionRunner`: the token is verified (`guard.check_token`) before the action is claimed, so a forged token gets FAILED without occupying the slot; the `current_state` pre-check runs outside `guard.authorized` (no write can pass the guard there) under a process-wide lock per idempotency key (two packages sharing a key never both write in one process; multi-worker deployments must share the execution store and route one incident to one worker); a control this package already registered is never re-sent (durable registry check, survives a restart with an empty execution store; the approval is still consumed, so a replayed token is FAILED); a failed pre-check plus a write timeout plus a positive re-check is FAILED and never registered (the control in force may be someone else's); when a later package's SUCCESS write replaces an earlier registration of the same key, the registry entry is superseded (`TemporaryControlRegistry.supersede`, event `SUPERSEDED`, history kept) so it points at the control really in force.
- `IncidentStateMachine.transition(..., report=...)`: `CONTAINED`, `PARTIALLY_CONTAINED` and `RESTORED` need the live execution report of the package that entered `CONTAINMENT_RUNNING` / `RESTORATION_RUNNING` for this incident, whose overall result is exactly that state, recorded by `automation:verification` (`REPORT_REQUIRED`, `OUTCOME_ACTOR` in `models.states`); an `ai:` actor can never record any outcome state.

**Restoration (13.17)**

- Provenance: a registry entry counts as created by automation only when its token was consumed for exactly its control key (token-use ledger, `TokenVerifierView.was_used`) and its execution record, when present, succeeded (`control_provenance`). The planner never auto-selects an entry without provenance and marks an explicitly requested one with an ELEVATED warning; the engine refuses to release it. A manual block registered by hand (invented ids, or ids borrowed from a genuine control) is never released.
- `required_release_level(control, critical_assets, *, asset, dependents)` is the single rule for planner and engine: registry level, always-elevated rollback, critical assets including group / tag / IP rules of the incident's asset record (the engine reads the incident store), and dependent incidents (`dependent_incidents`).
- The engine re-validates the package (`control_keys` must be exactly what the actions restore; `model_construct` cannot smuggle a mismatch), computes the overall result over every control of the package (a selective release never reports RESTORED while package controls stay in force) and audits `released` / `still_in_force` from the controls the actions really restore.
- `RELEASE_PENDING` (a release that died before reaching the vendor) stays visible: `RestorationPlanner.outstanding` (close note) and `registry.due_for_review` include it.

**Secrets and audit (13.11, 13.12)**

- `RedactingFilter` formats `msg % args` first (args redacted individually) and redacts the resulting text; a placeholder after a sensitive key (`password=%s`, `Authorization: %s`) can no longer break formatting, drop the record or make `logging.handleError` print raw args to stderr. `configure_logging` and the HTTP module attach the filter to the `httpx` / `httpcore` loggers, whose INFO request lines carry full URLs.
- Redaction: escaped JSON pairs (`\"password\": \"...\"`) and XML elements of sensitive keys (`<sessionKey>`, `<password>`); registered secrets also match their JSON-escaped forms (unicode and slash escapes); `Redactor.redact_body` parses JSON error bodies (recursively decoding JSON inside string values) and redacts the structure before the text rules; `GuardedHttpClient` error excerpts use it.
- The audit head anchor is authenticated with HMAC-SHA256 under the audit chain key (`xdr_response.audit.keys`; `bootstrap` passes the `AUDIT_CHAIN_KEY` secret; fallback env `AUDIT_CHAIN_KEY`, then a per-user key file outside the audit directory, `XDR_RESPONSE_AUDIT_KEY_FILE` or `~/.xdr_response/audit-chain.key`). Rewriting history and re-anchoring with the public hashing helpers is detected (on open and by `verify()`). Anchors written before this change carry no MAC and are refused: verify the file with `tools/validation/verify_audit_chain.py` and re-anchor it with the key. A rollback of file and anchor to an older genuine state is still only detected with externally exported anchors (`AuditTrail.anchor()`), which production should write to write-once storage.

**Test infrastructure changes that follow from the contract** (no safety test was weakened): `tests/conftest.py` uses the private harness reset; `install_fake_verifier` re-uses the sealed FakeVerifier; the execution harness and restoration fixtures use live settings (`runtime.dry_run=false`); unit tests that sent raw writes inside an authorization now carry the approved target; manifests in test adapters document their paths; the vendor unit tests mock the identity lookups.

---

## 14. Phase 1-5 contract

Status: binding for Phases 1 to 5. Written by the Phase 1 design agent on 2026-10-08 from sections 1 to 13, `docs/integrations.md`, `docs/threat-scoring.md`, `src/xdr_response/lifecycle/*.py`, the legacy `workflows/*/workflow.yaml` specs and `engine/xdr_plan`.

The rules of section 13 apply unchanged: names, fields, signatures and file paths below are exact; bodies shown as `...` are for the owning key; anything not listed is private (`_` prefix) and may not be imported by another key; code runs on Python 3.12 and 3.13; models derive from `xdr_response.models._base.FrozenModel` (`frozen=True, extra="forbid"`), scores use `Score` (int 0-100), datetimes are `AwareDatetime`. Phase 1 model modules are **not** re-exported from `xdr_response.models` (that package stays core-owned and unchanged); import them from the module named here.

Ownership (14.6): every new or changed file of Phase 1 belongs to exactly one of the keys `scoring`, `enrichment`, `investigation`, `correlation-evidence`, `containment-atomics`, `notifications`, `workflow-framework`, `legacy-alignment`. A key only edits files it owns. A key that needs a contract change reports it; `workflow-framework` (the Phase 1 integrator) applies it to this section in the same commit as the code.

Contradictions with sections 1 to 13 fixed while writing this section (one-line edits there): workflow directory renames (1.4, 3.3, 12); the scoring signature and evidence references (9); the README heading count (12); the location of typed investigation records (13.5); native-first routing of the brief's `isolate_*_endpoint` names (13.6); layering pointer (2.4).

Phase 0 gap found while writing: `tools/validation/validate_config.py`, `tools/validation/check_endpoints.py` and `tools/validation/README.md` (3.1, 13.2) do not exist; the manifest-to-document cross-check runs as `tests/unit/vendors/test_vendor_contracts.py`. Phase 1 adds the two thin CLIs and the README (owner `workflow-framework`, 14.6).

### 14.0 Read zone, layering and build order

#### 14.0.1 The read zone

The owner rule becomes a code boundary. Investigation and recommendation are automatic and happen in the **read zone**; every state change happens in the Phase 0 **write zone**, reached only through `ResponseOrchestrator.submit_decision` / `submit_release_decision` with a token issued to authenticated humans.

| | Read zone | Write zone (Phase 0, unchanged) |
|---|---|---|
| Code | `xdr_response.scoring`, `xdr_response.atomics`, `xdr_response.workflows`, `xdr_response.lifecycle.plan_bridge`, `xdr_response.lifecycle.workflow_adapter` | `approval`, `execution`, `verification`, `restoration`, `dryrun`, driven by the orchestrator |
| Adapter access | only through `ReadOnlyAdapters` (14.1.1): `enrich`, `investigate`, health, manifests, adapter names, the Cisco XDR `respond/observables` listing (READ) | `ActionRunner` inside `guard.authorized(...)` |
| Output | records, enrichment reports, correlation, scores, `ProposedAction`s, notification drafts | executions, verifications, registry entries, tokens |

Code in the read zone never:

- holds an `IntegrationAdapter`, `AdapterRegistry` or `GuardedHttpClient` object (only `atomics/context.py` touches the registry, inside `ReadOnlyAdapters`);
- calls `execute`, or a method named after a state-changing `ActionType`, on any object other than the containment builder module of 14.1.7;
- imports `xdr_response.guard`, `xdr_response.approval.{tokens,engine,authenticator,ledger,package,_quorum}`, `xdr_response.execution`, `xdr_response.restoration`, `xdr_response.dryrun`, `xdr_response.verification`, `xdr_response.integrations.<vendor>` modules, `xdr_response.integrations.{http,auth}` or `httpx`;
- constructs `ApprovalToken`, `ApprovalTokenClaims`, `TokenActionGrant`, `ApproverClaim`, `AnalystDecision`, `DecisionRequest`, `ApproverCredential`, `AuthenticatedPrincipal`, `RecommendedAction`, `ActionPackage` or its subclasses, `ActionRequest` or `ActionBinding` (its output type is `ProposedAction`; numbering, approval levels, idempotency keys and packages stay with `PackageBuilder`);
- chooses or changes an approval level in either direction (ELEVATED comes only from the three Phase 0 rules: critical-asset policy, `always_elevated`, blast-radius caps; a workflow influences the first only by passing investigated asset context, which `PackageBuilder` merges and can never shrink, 13.25);
- writes audit records, except `ENRICHMENT_RESULT` and `INVESTIGATION_COMPLETED`, which `WorkflowInvestigator` (14.3.6) writes through `AuditRecorder`;
- uses `getattr`, `setattr`, `delattr`, `vars`, `globals`, `__import__`, `importlib`, `eval`, `exec`, `compile`, `open`, `subprocess`, `socket`, `os.system`, or reads a private attribute of another object (`x._y` where `x` is not `self` or `cls`).

Allowed exceptions: `atomics/context.py` imports `xdr_response.integrations.registry` and `xdr_response.integrations.simulated`; `atomics/notifications/sinks.py` opens its own JSONL outbox file; `lifecycle/workflow_adapter.py` imports `xdr_response.audit.events`; `approval.critical_assets` and `config.policy` are pure and may be imported anywhere in the read zone.

Enforcement (owner `workflow-framework`, `tests/safety/test_read_zone.py`): an AST lint over every read-zone file for the rules above; a runtime test that runs every workflow scenario and every legacy replay and asserts zero `STATE_CHANGING` operations recorded by `SimulatedEnvironment` and zero guard denials before the analyst decision; and the Phase 0 guard itself (a state-changing call outside an authorized context still fails closed).

#### 14.0.2 Layering (extends 2.4)

| Layer | Packages | May import |
|---|---|---|
| 0 Foundation | Phase 0 plus `models.scoring` and the **model modules** `atomics.records`, `atomics.enrichment.models`, `atomics.correlation.models`, `atomics.containment.models`, `atomics.notifications.models`, `workflows.definition` | layer 0 only (model modules import each other along the arrows below) |
| 4 Engines | Phase 0 plus `scoring` (engine) | layers 0 to 3 |
| 4a Atomics | `xdr_response.atomics` | layers 0 to 3, `scoring`, `approval.critical_assets`, `config.policy` |
| 4b Workflows | `xdr_response.workflows` | layers 0 to 4a |
| 5 Composition | `lifecycle` (adds `plan_bridge`, `workflow_adapter`, `observers`) | everything; `plan_bridge` alone may import `engine/xdr_plan` (until the end of Phase 5) |

Inside `atomics` (no cycles): `records` <- `context` <- {`enrichment`, `investigation`, `containment`}; `records` <- `evidence` <- `correlation`; `notifications` imports only the model modules and Phase 0 models; the model module `workflows.definition` imports `models.scoring` and `atomics.correlation.models`. `atomics/__init__.py` composes the atomic name table lazily (14.1.9).

#### 14.0.3 Build order (contract first, then parallel)

1. **Step 0 (one small commit per key):** each key lands its model module with exactly the names, fields, types and defaults of this section: `atomics/records.py` (investigation), `models/scoring.py` (scoring), `atomics/context.py` and `atomics/__init__.py` (workflow-framework), `atomics/enrichment/models.py` (enrichment), `atomics/correlation/models.py` (correlation-evidence), `atomics/containment/models.py` (containment-atomics), `atomics/notifications/models.py` (notifications), `workflows/definition.py` (workflow-framework).
2. **Step 1 (parallel):** all eight keys build their behaviour. A key may import other keys' step 0 modules; for another key's behaviour it tests against local fakes in its own test directory.
3. **Step 2 (integration, workflow-framework):** lifecycle wiring, legacy replay, scenario runner, CI, the Phase 1 exit criteria (14.7) and the "as built" notes appended to this section.

### 14.1 Atomic library

All atomics are plain functions taking an `AtomicContext` first. Read atomics (enrichment, investigation, search) never raise because of a source: a failing source becomes a `SourceStatus` with outcome `FAILED`, and the other sources still answer. They raise only for invalid caller input (`ValueError` for an unparseable subject).

#### 14.1.1 Context and the read-only adapter facade (owner: workflow-framework)

```python
# xdr_response/atomics/context.py
class ReadOnlyAdapters:
    """The only door from the read zone to the adapters. Never returns an adapter object."""
    __slots__ = ("__registry",)
    def __init__(self, registry: AdapterRegistry) -> None: ...
    def enabled(self) -> tuple[str, ...]: ...                          # registry.enabled(), INTEGRATION_NAMES order
    def is_simulated(self, integration: str) -> bool: ...              # isinstance(adapter, SimulatedAdapter)
    def manifest(self, integration: str) -> CapabilityManifest: ...    # KeyError for unknown names
    def health(self, integration: str) -> IntegrationHealth: ...       # adapter.health_check(); never raises
    def enrichers(self, observable_type: ObservableType) -> tuple[str, ...]: ...   # names, registry.for_observable order
    def enrich(self, integration: str, observable: Observable) -> EnrichmentResult: ...
        # integration must be in enrichers(observable.type), else CapabilityNotSupportedError; adapter errors propagate
    def investigators(self, action_type: ActionType) -> tuple[str, ...]: ...
        # INVESTIGATION types only (ValueError otherwise); names, registry.for_action order
    def investigate(self, integration: str, query: InvestigationQuery) -> InvestigationResult: ...
        # integration must be in investigators(query.action_type); adapter errors propagate
    def executors(self, action_type: ActionType) -> tuple[str, ...]: ...
        # CONTAINMENT / REMEDIATION types only (ValueError otherwise): names of enabled adapters whose manifest
        # supports the action, catalog preference order (native first). Names only: for routing, never for calling.
    def native_response_actions(self, observable: Observable, *, module: str | None = None
                                ) -> tuple[NativeResponseAction, ...]: ...
        # CiscoXdrAdapter.list_response_actions (READ, respond/observables); () when cisco_xdr is not enabled;
        # adapter errors propagate (the router records them and falls back)

@dataclass(frozen=True)
class AtomicContext:
    incident: Incident
    adapters: ReadOnlyAdapters
    settings: Settings
    clock: Clock
    disclosure: DisclosurePolicy
    critical_assets: CriticalAssetPolicy
    allowlists: AllowlistPolicy
    lookback: timedelta = timedelta(hours=24)
    dry_run: bool = True                         # informational for renderers; reads behave the same in dry run
    def now(self) -> datetime: ...               # clock.now()
    def window(self) -> tuple[datetime, datetime]: ...   # (min(incident.created_at, now) - lookback, now)

def build_context(incident: Incident, registry: AdapterRegistry, settings: Settings, *, clock: Clock,
                  dry_run: bool, lookback: timedelta | None = None) -> AtomicContext: ...
    # DisclosurePolicy(settings.exclusions), CriticalAssetPolicy(settings.critical_assets),
    # AllowlistPolicy(settings.allowlists), ReadOnlyAdapters(registry)
```

#### 14.1.2 Normalized records (owner: investigation)

Every fact an atomic learns is a typed **record** with a deterministic `record_id`. Evidence (14.1.6), scoring signals (14.2) and correlation links (14.1.5) refer to records by id only. Records are created only by the normalizers (14.1.4), the enrichment atomics (14.1.3) and, for legacy replay, `plan_bridge` (14.3.8). The framework never synthesizes a record from a computation: a computed pattern (for example "14 push prompts in 5 minutes") is a `ScoringSignal` or a `CorrelationLink` that cites the records it was computed from.

```python
# xdr_response/atomics/records.py
Level = Literal["none", "low", "medium", "high", "unknown"]

class RecordKind(StrEnum):
    ENRICHMENT = "enrichment"; ENDPOINT = "endpoint"; DETECTION = "detection"; PROCESS_EVENT = "process_event"
    NETWORK_CONNECTION = "network_connection"; DNS_QUERY = "dns_query"; HASH_PREVALENCE = "hash_prevalence"
    PERSISTENCE_ITEM = "persistence_item"; USER_PROFILE = "user_profile"; SIGN_IN = "sign_in"; ANOMALY = "anomaly"
    MFA_EVENT = "mfa_event"; MAILBOX_RULE = "mailbox_rule"; ROLE_CHANGE = "role_change"
    EMAIL_MESSAGE = "email_message"; CLOUD_APP = "cloud_app"; GENERIC = "generic"

def make_record_id(integration: str, kind: RecordKind, subject: Observable,
                   natural_key: Mapping[str, object]) -> str: ...
    # "rec_" + sha256_hex(canonical_json({"i": integration, "k": kind.value, "t": subject.type.value,
    #   "v": subject.value.strip().lower(), "n": natural_key}, allow_floats=True))[:32]

class RecordBase(FrozenModel):
    kind: RecordKind
    record_id: str                       # validator: == make_record_id(integration, kind, subject, natural_key())
    integration: str                     # validator: member of INTEGRATION_NAMES (never "ai" or "analyst")
    atomic: str                          # producing atomic, e.g. "investigate_endpoint" ("legacy:<atomic-id>" in replay)
    subject: Observable                  # what the atomic was asked about (normalized value)
    observed_at: AwareDatetime | None = None
    reference: str | None = None         # vendor object id or console link; validator: redact_text(reference) == reference
    def natural_key(self) -> dict[str, object]: ...   # per kind, table below
    def rule_item(self) -> dict[str, Any]: ...        # model_dump(mode="json"); every field present (None when unknown)
    def evidence_fields(self) -> dict[str, Any]: ...  # fields copied into EvidenceDraft.data["fields"] (table below)
```

Validators pass free-text fields (`command_line`, `subject_line`, `detail`, `conditions`, `failure_reason`, `GenericRecord.attributes`) through `get_redactor()` and cap them (command line 1024 characters, subject line 200, others 500, attributes 4 KiB). Entity values are normalized with `normalize_target` for their kind (hostnames upper case, users and email addresses lower case, domains lower case without trailing dot, IPs compressed with an IPv4-mapped IPv6 address unmapped to its IPv4 address (14.10.7), hashes lower case). `command_line` uses `Redactor.redact_command_line` (14.10.7). Records use the Phase 0 `Verdict` and `Severity` enums (upper-case values in rule items).

```python
class EnrichmentRecord(RecordBase):              # one source's answer about one observable (from an EnrichmentResult)
    kind: Literal[RecordKind.ENRICHMENT] = RecordKind.ENRICHMENT
    verdict: Verdict
    risk_score: Score
    confidence: Score
    categories: tuple[str, ...] = ()             # vendor categories, e.g. "Malware", "Phishing"
    first_seen: AwareDatetime | None = None
    detail: str = ""                             # the source's own summary (first EvidenceDraft.summary of the result)

class EndpointRecord(RecordBase):
    kind: Literal[RecordKind.ENDPOINT] = RecordKind.ENDPOINT
    hostname: str                                # ENDPOINT target value
    connector_guid: str | None = None            # Secure Endpoint
    mde_machine_id: str | None = None            # Defender for Endpoint
    intune_device_id: str | None = None
    os: str | None = None
    ip_addresses: tuple[str, ...] = ()
    mac_addresses: tuple[str, ...] = ()
    users: tuple[str, ...] = ()                  # logged-on or recent users
    groups: tuple[str, ...] = ()                 # vendor groups or OU names (fed to critical-asset matching)
    tags: tuple[str, ...] = ()
    isolation_capable: bool | None = None        # None = unknown (legacy item.isolation_capable)
    isolation_state: Literal["isolated", "not_isolated", "pending", "unknown"] = "unknown"
    health_state: str | None = None
    risk_level: Level = "unknown"
    last_seen: AwareDatetime | None = None

class DetectionRecord(RecordBase):
    kind: Literal[RecordKind.DETECTION] = RecordKind.DETECTION
    detection_id: str | None = None
    name: str                                    # e.g. "Ransomware.Generic"
    verdict: Verdict                             # vendor disposition (legacy item.detections[].disposition)
    severity: Severity
    category: str | None = None                  # vendor category, e.g. "Ransomware", "CredentialAccess"
    endpoint: str | None = None
    user: str | None = None
    sha256: str | None = None
    file_path: str | None = None
    process_name: str | None = None
    mitre_techniques: tuple[str, ...] = ()       # as reported by the vendor, never inferred
    status: Literal["active", "resolved", "unknown"] = "unknown"
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

class ProcessEventRecord(RecordBase):            # trajectory / device timeline entry (legacy item.trajectory[])
    kind: Literal[RecordKind.PROCESS_EVENT] = RecordKind.PROCESS_EVENT
    event_id: str | None = None
    endpoint: str
    timestamp: AwareDatetime
    event_type: Literal["process_start", "process_end", "file_create", "file_modify", "file_execute",
                        "file_delete", "file_rename", "network", "registry", "module_load", "service",
                        "scheduled_task", "other"]
    process_name: str | None = None
    pid: int | None = None
    sha256: str | None = None
    parent_process_name: str | None = None
    parent_pid: int | None = None
    parent_sha256: str | None = None
    file_path: str | None = None
    command_line: str | None = None              # redacted and capped; data only, never executed
    user: str | None = None
    verdict: Verdict = Verdict.UNKNOWN
    remote_ip: str | None = None
    remote_port: int | None = None
    domain: str | None = None
    count: int = 1                               # identical events aggregated by the source (e.g. 1204 renames)

class NetworkConnectionRecord(RecordBase):
    kind: Literal[RecordKind.NETWORK_CONNECTION] = RecordKind.NETWORK_CONNECTION
    endpoint: str | None = None
    user: str | None = None
    local_ip: str | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    protocol: Literal["tcp", "udp", "icmp", "other", "unknown"] = "unknown"
    direction: Literal["outbound", "inbound", "internal", "unknown"] = "unknown"
    domain: str | None = None
    url: str | None = None
    process_name: str | None = None
    pid: int | None = None                       # owning process when the source reports it (14.11.3)
    sha256: str | None = None
    bytes_out: int | None = None
    bytes_in: int | None = None
    count: int = 1
    action: Literal["allowed", "blocked", "unknown"] = "unknown"
    verdict: Verdict = Verdict.UNKNOWN
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

class DnsQueryRecord(RecordBase):
    kind: Literal[RecordKind.DNS_QUERY] = RecordKind.DNS_QUERY
    endpoint: str | None = None
    client_ip: str | None = None
    domain: str
    query_type: str | None = None                # "A", "AAAA", "TXT", ...
    response_ips: tuple[str, ...] = ()
    count: int = 1
    unique_subdomains: int | None = None         # distinct child labels seen, when the source reports it
    max_label_length: int | None = None
    categories: tuple[str, ...] = ()
    action: Literal["allowed", "blocked", "unknown"] = "unknown"
    verdict: Verdict = Verdict.UNKNOWN
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

class HashPrevalenceRecord(RecordBase):          # legacy enrich-hash prevalence / hosts
    kind: Literal[RecordKind.HASH_PREVALENCE] = RecordKind.HASH_PREVALENCE
    sha256: str
    file_name: str | None = None
    verdict: Verdict = Verdict.UNKNOWN
    prevalence: int                              # >= 0, endpoints that saw the file
    endpoints: tuple[str, ...] = ()              # hostnames (may be truncated by the source)
    truncated: bool = False
    signer: str | None = None
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

class PersistenceItemRecord(RecordBase):
    kind: Literal[RecordKind.PERSISTENCE_ITEM] = RecordKind.PERSISTENCE_ITEM
    endpoint: str
    item_id: str
    mechanism: Literal["run_key", "scheduled_task", "service", "wmi_subscription", "startup_folder",
                       "launch_agent", "cron", "browser_extension", "other"]   # browser_extension: 14.11.3
    name: str
    path: str | None = None
    sha256: str | None = None
    command_line: str | None = None
    user: str | None = None
    created_at: AwareDatetime | None = None
    verdict: Verdict = Verdict.UNKNOWN
    @property
    def target(self) -> str: ...                 # f"{endpoint}/{item_id}" (PERSISTENCE_ITEM target, 13.3)

class UserProfileRecord(RecordBase):             # legacy item.profile
    kind: Literal[RecordKind.USER_PROFILE] = RecordKind.USER_PROFILE
    user: str                                    # UPN
    object_id: str | None = None
    display_name: str | None = None
    department: str | None = None
    job_title: str | None = None
    manager: str | None = None
    groups: tuple[str, ...] = ()                 # legacy item.profile.groups
    roles: tuple[str, ...] = ()                  # directory role display names
    privileged: bool = False                     # the source says so, or a role is in PRIVILEGED_ROLE_NAMES
    account_enabled: bool | None = None
    risk_level: Level = "unknown"                # legacy item.risk_level
    risk_state: Literal["at_risk", "confirmed_compromised", "remediated", "dismissed", "none", "unknown"] = "unknown"
    mfa_registered: bool | None = None
    last_sign_in: AwareDatetime | None = None
    sessions_valid_from: AwareDatetime | None = None

class SignInRecord(RecordBase):                  # legacy item.signins[] (ip, location, app, result)
    kind: Literal[RecordKind.SIGN_IN] = RecordKind.SIGN_IN
    sign_in_id: str | None = None
    user: str
    timestamp: AwareDatetime
    ip: str | None = None
    country: str | None = None
    city: str | None = None
    app: str | None = None
    client_app: str | None = None
    device_id: str | None = None
    device_compliant: bool | None = None
    result: Literal["success", "failure", "interrupted", "unknown"]
    failure_reason: str | None = None
    mfa_required: bool | None = None
    mfa_result: Literal["satisfied", "denied", "timeout", "not_required", "unknown"] = "unknown"
    conditional_access: Literal["success", "failure", "not_applied", "unknown"] = "unknown"
    risk_level: Level = "unknown"
    authentication_method: str | None = None

class AnomalyRecord(RecordBase):                 # vendor risk detections only (legacy item.anomalies[])
    kind: Literal[RecordKind.ANOMALY] = RecordKind.ANOMALY
    anomaly_id: str | None = None
    anomaly_type: Literal["impossible_travel", "unfamiliar_location", "new_device", "anonymous_ip",
                          "malicious_ip", "mfa_fatigue", "password_spray", "brute_force", "token_replay",
                          "atypical_volume", "leaked_credentials", "other"]
    severity: Severity
    user: str | None = None
    endpoint: str | None = None
    ip: str | None = None
    detail: str = ""
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    related_record_ids: tuple[str, ...] = ()     # must exist in the same run (RecordIndex rejects unknown ids)

class MfaEventRecord(RecordBase):
    kind: Literal[RecordKind.MFA_EVENT] = RecordKind.MFA_EVENT
    user: str
    timestamp: AwareDatetime
    method: Literal["push", "sms", "voice", "totp", "fido2", "windows_hello", "other", "unknown"] = "unknown"
    result: Literal["approved", "denied", "timeout", "fraud_reported", "unknown"]
    ip: str | None = None
    country: str | None = None
    app: str | None = None
    device: str | None = None

class MailboxRuleRecord(RecordBase):
    kind: Literal[RecordKind.MAILBOX_RULE] = RecordKind.MAILBOX_RULE
    mailbox: str
    rule_id: str
    name: str
    enabled: bool | None = None
    forward_to: tuple[str, ...] = ()
    redirect_to: tuple[str, ...] = ()
    forward_as_attachment_to: tuple[str, ...] = ()
    move_to_folder: str | None = None
    delete: bool = False
    mark_as_read: bool = False
    external_forwarding: bool = False            # set by the normalizer: a forward/redirect address outside
                                                 # settings.exclusions.internal_domains
    conditions: tuple[str, ...] = ()             # normalized condition summaries
    created_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    created_by: str | None = None

class RoleChangeRecord(RecordBase):
    kind: Literal[RecordKind.ROLE_CHANGE] = RecordKind.ROLE_CHANGE
    user: str                                    # principal that received or lost the role
    role_name: str
    role_definition_id: str | None = None
    directory_scope_id: str | None = None
    change: Literal["assigned", "removed", "eligible_assigned", "activated", "unknown"]
    privileged: bool = False
    actor: str | None = None
    timestamp: AwareDatetime | None = None
    @property
    def target(self) -> str | None: ...          # f"{user}/{role_definition_id}" (ROLE_ASSIGNMENT target) or None

class EmailMessageRecord(RecordBase):
    kind: Literal[RecordKind.EMAIL_MESSAGE] = RecordKind.EMAIL_MESSAGE
    message_id: str                              # EMAIL_MESSAGE target value used by the executing adapter
    internet_message_id: str | None = None
    network_message_id: str | None = None        # Defender for Office 365
    sender: str | None = None
    sender_domain: str | None = None
    recipients: tuple[str, ...] = ()             # capped at 100; recipient_count is the true count
    recipient_count: int = 0
    subject_line: str | None = None              # redacted, capped at 200
    received_at: AwareDatetime | None = None
    direction: Literal["inbound", "outbound", "internal", "unknown"] = "unknown"
    verdict: Verdict = Verdict.UNKNOWN
    threat_types: tuple[str, ...] = ()           # "phish", "malware", "spam", "bec", ...
    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    attachment_hashes: tuple[str, ...] = ()
    attachment_names: tuple[str, ...] = ()
    delivery_location: Literal["inbox", "junk", "quarantine", "deleted", "failed", "unknown"] = "unknown"
    campaign_id: str | None = None
    spf: Literal["pass", "fail", "none", "unknown"] = "unknown"
    dkim: Literal["pass", "fail", "none", "unknown"] = "unknown"
    dmarc: Literal["pass", "fail", "none", "unknown"] = "unknown"

class CloudAppRecord(RecordBase):                # OAuth application / service principal facts
    kind: Literal[RecordKind.CLOUD_APP] = RecordKind.CLOUD_APP
    app_id: str
    display_name: str | None = None
    publisher_verified: bool | None = None
    permissions: tuple[str, ...] = ()
    consent_type: Literal["admin", "user", "unknown"] = "unknown"
    consented_by: str | None = None
    credential_added_at: AwareDatetime | None = None
    created_at: AwareDatetime | None = None
    verdict: Verdict = Verdict.UNKNOWN

class GenericRecord(RecordBase):                 # a finding no normalizer understands, and legacy replay data
    kind: Literal[RecordKind.GENERIC] = RecordKind.GENERIC
    name: str                                    # e.g. "microsoft_cloud:investigate_user", "legacy:investigate-host"
    attributes: JsonDict = {}                    # the finding as returned (redacted, capped at 4 KiB)

AnyRecord = Annotated[Union[EnrichmentRecord, EndpointRecord, DetectionRecord, ProcessEventRecord,
                            NetworkConnectionRecord, DnsQueryRecord, HashPrevalenceRecord, PersistenceItemRecord,
                            UserProfileRecord, SignInRecord, AnomalyRecord, MfaEventRecord, MailboxRuleRecord,
                            RoleChangeRecord, EmailMessageRecord, CloudAppRecord, GenericRecord],
                      Field(discriminator="kind")]
RECORD_TYPES: Mapping[RecordKind, type[RecordBase]]
PRIVILEGED_ROLE_NAMES: frozenset[str]            # lower-case Entra role names treated as privileged, at least
                                                 # "global administrator", "privileged role administrator",
                                                 # "security administrator", "exchange administrator"

class SourceOutcome(StrEnum):
    ANSWERED = "answered"; EMPTY = "empty"; FAILED = "failed"; NOT_QUERIED = "not_queried"; NOT_SUPPORTED = "not_supported"

class SourceStatus(FrozenModel):
    integration: str
    outcome: SourceOutcome
    health: HealthStatus
    reason: str = ""                             # disclosure-policy reason, error code, "not enabled", ...
    error: ErrorInfo | None = None               # redacted (IntegrationError.to_error_info)
    records: int = 0

class AtomicResult(FrozenModel):                 # base of every read-atomic result
    atomic: str
    action_type: ActionType                      # ENRICHMENT or INVESTIGATION catalog type
    subject: Observable                          # normalized value
    records: tuple[AnyRecord, ...] = ()          # validator: unique record ids, record.atomic == atomic
    sources: tuple[SourceStatus, ...] = ()       # one per integration considered, INTEGRATION_NAMES order
    raw: tuple[EnrichmentResult | InvestigationResult, ...] = Field(default=(), repr=False)   # for audit only
    started_at: AwareDatetime
    finished_at: AwareDatetime
    @property
    def degraded(self) -> bool: ...              # any FAILED source
    @property
    def answered(self) -> tuple[str, ...]: ...
    @property
    def failed(self) -> tuple[str, ...]: ...
    def of(self, kind: RecordKind) -> tuple[AnyRecord, ...]: ...
    def record_ids(self) -> tuple[str, ...]: ...
    def rule_item(self) -> dict[str, Any]: ...   # common keys plus the atomic's keys (14.1.4); overridden by subclasses

class InvestigationBundle(AtomicResult):         # result of every investigate_* and search_* atomic
    critical_asset_classes: tuple[CriticalAssetClass, ...] = ()   # ctx.critical_assets.classify(...) at run time;
                                                 # rule_item() has no ctx. Informs rules and the card, never skips
    def rule_item(self) -> dict[str, Any]: ...   # 14.1.4 table
```

Natural keys and evidence fields:

| Kind | `natural_key()` | `evidence_fields()` |
|---|---|---|
| enrichment | `{}` (one per integration and subject) | verdict, risk_score, confidence, categories |
| endpoint | `{"hostname", "id"}` (connector GUID, MDE id or Intune id, first present) | hostname, os, isolation_state, groups, tags |
| detection | `{"id": detection_id}` or `{"name", "endpoint", "sha256", "first_seen"}` | name, verdict, severity, category, endpoint, user, sha256, mitre_techniques |
| process_event | `{"id": event_id}` or `{"endpoint", "timestamp", "event_type", "pid", "sha256"}` | endpoint, timestamp, event_type, process_name, parent_process_name, sha256, command_line, verdict, count |
| network_connection | `{"endpoint", "remote_ip", "remote_port", "domain", "first_seen"}`, plus `"url"` when the source reports one (14.13.3) | endpoint, user, remote_ip, remote_port, domain, url, direction, action, verdict, bytes_out, count |
| dns_query | `{"endpoint", "client_ip", "domain", "query_type", "first_seen"}` | endpoint, domain, query_type, count, unique_subdomains, action, verdict |
| hash_prevalence | `{"sha256"}` | sha256, file_name, verdict, prevalence, endpoints |
| persistence_item | `{"endpoint", "item_id"}` | endpoint, mechanism, name, path, sha256, command_line, verdict |
| user_profile | `{"user"}` | user, risk_level, risk_state, account_enabled, privileged, roles |
| sign_in | `{"id": sign_in_id}` or `{"user", "timestamp", "ip"}` | user, timestamp, ip, country, app, result, mfa_result, risk_level |
| anomaly | `{"id": anomaly_id}` or `{"anomaly_type", "user", "endpoint", "first_seen"}` | anomaly_type, severity, user, endpoint, ip, detail |
| mfa_event | `{"user", "timestamp", "method"}` | user, timestamp, method, result, ip, country |
| mailbox_rule | `{"mailbox", "rule_id"}` | mailbox, name, enabled, forward_to, redirect_to, external_forwarding, delete |
| role_change | `{"user", "role_name", "change", "timestamp"}` | user, role_name, change, privileged, actor, timestamp |
| email_message | `{"message_id"}` | message_id, sender, recipient_count, verdict, threat_types, delivery_location, campaign_id |
| cloud_app | `{"app_id"}` | app_id, display_name, consent_type, permissions, publisher_verified |
| generic | `{"name", "attributes"}` | name, attributes |

#### 14.1.3 Enrichment atomics (owner: enrichment)

```python
# xdr_response/atomics/enrichment/models.py
class ObservableReport(AtomicResult):            # the brief's normalized observable, with per-source detail
    type: ObservableType
    value: str                                   # normalized (== subject.value)
    risk_score: Score
    confidence: Score
    verdict: Verdict                             # scoring.verdict.aggregate_verdict (never one vendor's word)
    breakdown: ScoreBreakdown                    # models.scoring (14.2)
    def normalized(self) -> dict[str, Any]: ...
        # exactly {"type", "value", "risk_score", "confidence", "sources": list(answered), "verdict"}
    def rule_item(self) -> dict[str, Any]: ...
        # normalized() + {"record_ids", "failed_sources", "not_queried", "degraded", "categories" (union),
        #   "source_verdicts": {integration: verdict}}

# xdr_response/atomics/enrichment/atomics.py
def enrich_ip(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...            # ip or ipv6
def enrich_domain(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...
def enrich_url(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...
def enrich_hash(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...          # sha256 / sha1 / md5 by length
def enrich_email_address(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...
def enrich_user(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...
def enrich_endpoint(ctx: AtomicContext, value: str | Observable) -> ObservableReport: ...      # hostname or endpoint_id
def enrich(ctx: AtomicContext, observable: Observable) -> ObservableReport: ...                # dispatch by type

ENRICHMENT_ATOMICS: Mapping[str, Callable[[AtomicContext, Observable], ObservableReport]]   # the seven names above
ENRICHMENT_SUBJECT_TYPES: Mapping[str, frozenset[ObservableType]]
```

Behaviour (deterministic, in this order):

1. Build the `Observable` (a `str` gets the atomic's type; `enrich_hash` picks sha256 / sha1 / md5 by length, `enrich_endpoint` uses `hostname`) and normalize its value; an invalid value raises `ValueError`.
2. For every name in `ctx.adapters.enrichers(type)`: a third-party source (`virustotal`, `alienvault_otx`, `hibp`) that `ctx.disclosure.may_disclose(observable, name)` refuses becomes `NOT_QUERIED` with reason `"disclosure policy"` (no confidence penalty, 14.2). Otherwise `ctx.adapters.enrich(...)`: an exception becomes `FAILED` (health from `classify_exception`, `ErrorInfo` from `to_error_info()` or an `INTERNAL` redacted message); a result with `errors` and verdict `UNKNOWN` becomes `FAILED` with the result's health; verdict `UNKNOWN` without evidence becomes `EMPTY`; anything else becomes `ANSWERED` plus one `EnrichmentRecord`.
3. `breakdown = ScoringEngine(ctx.settings.thresholds.scoring).score(signals_from_enrichment(records), context=...)` with the critical-asset classes of the observable (`ctx.critical_assets.classify` for its target kind), expected sources = every enricher, failed and not-queried sources from step 2.
4. `risk_score`, `confidence` from the breakdown; `verdict = aggregate_verdict(signals, breakdown)`.

No source ever blocks the report; a report with every source failed has risk 0, confidence 0, verdict `UNKNOWN` and lists the failures.

#### 14.1.4 Investigation and enterprise search atomics (owner: investigation)

```python
# xdr_response/atomics/investigation/atomics.py
InvestigationAtomic = Callable[..., InvestigationBundle]
# every function: (ctx: AtomicContext, subject: str | Observable, *, options: Mapping[str, Any] | None = None,
#                  integrations: Sequence[str] = (), limit: int = 100) -> InvestigationBundle
def investigate_user(...): ...                   # subject types: user, email_address
def investigate_endpoint(...): ...               # hostname, endpoint_id
def investigate_ip(...): ...                     # ip, ipv6
def investigate_domain(...): ...                 # domain
def investigate_hash(...): ...                   # sha256, sha1, md5
def investigate_email(...): ...                  # email_message_id
def investigate_authentication(...): ...         # user
def investigate_process(...): ...                # process ("<ENDPOINT>/<sha256 or pid>")
def investigate_network_connection(...): ...     # ip, ipv6
def search_hash_enterprise(...): ...             # sha256, sha1, md5
def search_domain_enterprise(...): ...           # domain
def search_ip_enterprise(...): ...               # ip, ipv6
def search_user_activity(...): ...               # user
def search_email_campaign(...): ...              # email_message_id
def search_related_endpoints(...): ...           # hostname, endpoint_id
def search_related_users(...): ...               # user

INVESTIGATION_ATOMICS: Mapping[str, InvestigationAtomic]           # the 16 names; name == ActionType value
INVESTIGATION_SUBJECT_TYPES: Mapping[str, frozenset[ObservableType]]

# xdr_response/atomics/investigation/normalize/__init__.py
Normalizer = Callable[[InvestigationResult, "NormalizeContext"], list[AnyRecord]]
@dataclass(frozen=True)
class NormalizeContext:
    atomic: str
    subject: Observable
    internal_domains: tuple[str, ...]            # settings.exclusions.internal_domains (mailbox external forwarding)
    typed_allowed: bool                          # ctx.adapters.is_simulated(integration)
NORMALIZERS: Mapping[str, Normalizer]            # cisco_xdr, secure_endpoint, defender_endpoint, entra,
                                                 # microsoft_cloud, secure_email, intune, splunk
def normalize(integration: str, result: InvestigationResult, nctx: NormalizeContext) -> list[AnyRecord]: ...
TYPED_RECORD_KEY = "xdr_record"
```

Behaviour: for every name in `ctx.adapters.investigators(action_type)` (restricted to `integrations` when given): build `InvestigationQuery(action_type, subject, time_from, time_to = ctx.window(), limit, options)`, call `ctx.adapters.investigate`, normalize, de-duplicate by `record_id` (first wins). Exceptions and results with `errors` become `FAILED`; no findings become `EMPTY`. Normalizer rules:

- A finding containing `TYPED_RECORD_KEY` is a typed record (`{"kind": ..., <fields>}` without `record_id`, `integration`, `atomic`, `subject`, which the normalizer fills). It is accepted only when `typed_allowed` (simulated adapters); from a real adapter the key is ignored and the finding becomes a `GenericRecord`. An optional `"xdr_integration"` key restricts the finding to that simulated adapter.
- Vendor normalizers map only fields documented by the vendor page cited in `docs/integrations.md` for that operation; anything else stays `None`. A finding they do not understand becomes one `GenericRecord(name=f"{integration}:{atomic}")`, so raw findings remain citable but produce no scoring signal.
- Normalizers never call adapters and never read secrets.

Rule items (`InvestigationBundle.rule_item()`), the shape workflow rules see. Every key is always present (`None`, `[]` or `0` when unknown); nested lists hold `record.rule_item()` dicts. Common keys of every read-atomic item: `atomic`, `subject_type`, `subject`, `record_ids`, `sources` (answered), `failed_sources`, `degraded`.

| Atomic | Additional keys |
|---|---|
| investigate_endpoint, search_related_endpoints | `hostname`, `endpoint` (first endpoint record or `None`), `endpoints` (all endpoint records), `connector_guid`, `mde_machine_id`, `intune_device_id`, `ip_addresses`, `users`, `groups`, `tags`, `isolation_capable`, `isolation_state`, `detections`, `trajectory` (process events), `network_connections`, `dns_queries`, `persistence`, `is_critical_asset`, `critical_asset_classes` |
| investigate_user, search_related_users, search_user_activity | `user`, `profile` (first user_profile or `None`), `users` (all profiles), `risk_level`, `risk_state`, `is_privileged`, `account_enabled`, `signins`, `anomalies`, `mfa_events`, `mailbox_rules`, `role_changes`, `cloud_apps`, `is_critical_asset`, `critical_asset_classes` |
| investigate_authentication | `user`, `signins`, `mfa_events`, `anomalies`, `success_count`, `failure_count`, `mfa_denied_count`, `mfa_approved_count`, `distinct_ips`, `distinct_countries` |
| investigate_ip, investigate_network_connection, search_ip_enterprise | `ip`, `network_connections`, `dns_queries`, `signins`, `endpoints` (distinct hostnames), `users` (distinct) |
| investigate_domain, search_domain_enterprise | `domain`, `dns_queries`, `network_connections`, `endpoints`, `users`, `query_count`, `first_seen` |
| investigate_hash, search_hash_enterprise | `sha256`, `prevalence` (highest hash_prevalence value or `None`), `endpoints` (union), `verdict` (worst reported), `detections`, `process_events`, `file_names` |
| investigate_email, search_email_campaign | `message_id`, `messages`, `recipients`, `senders`, `urls`, `domains`, `attachment_hashes`, `campaign_ids`, `delivered_count` (delivery_location inbox or junk) |
| investigate_process | `process`, `endpoint`, `events`, `network_connections`, `children` (events whose parent pid or hash is the subject) |

`is_critical_asset` / `critical_asset_classes` come from `ctx.critical_assets.classify(...)` with an `Asset` built from the bundle's own records (groups, tags, roles, first IP). They replace the legacy `is_protected`, and they never cause a skip: they only inform rules and the decision card (ELEVATED stays `PackageBuilder`'s decision).

#### 14.1.5 Correlation and blast radius (owner: correlation-evidence)

Pure functions over atomic results: no adapter calls, deterministic output order.

```python
# xdr_response/atomics/correlation/models.py
class EntityRef(FrozenModel):
    kind: TargetKind
    value: str                                   # validator: == normalize_target(kind, value)

class LinkKind(StrEnum):
    SAME_HASH = "same_hash"; SAME_DOMAIN = "same_domain"; SAME_IP = "same_ip"; SAME_URL = "same_url"
    SAME_USER = "same_user"; SAME_ENDPOINT = "same_endpoint"; PROCESS_LINEAGE = "process_lineage"
    SIGN_IN_TO_ACTIVITY = "sign_in_to_activity"; EMAIL_TO_CLICK = "email_to_click"; CAMPAIGN = "campaign"
    WORKFLOW = "workflow"                        # links contributed by a workflow hook (14.3.3)

class CorrelationLink(FrozenModel):
    link_id: str                                 # "lnk_" + sha256_hex(canonical_json([kind, entities, record_ids]))[:24]
    kind: LinkKind
    entities: tuple[EntityRef, ...]              # >= 2, unique, sorted by (kind, value)
    record_ids: tuple[str, ...]                  # >= 1, sorted; every id must be in the run's RecordIndex
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    note: str                                    # deterministic template, no AI text
    origin: str = "framework"                    # or "workflow:<workflow id>"

class TimelineEntry(FrozenModel):
    at: AwareDatetime
    record_id: str
    kind: RecordKind
    integration: str
    summary: str                                 # evidence_summary(record)

class CorrelationResult(FrozenModel):
    incident_id: str
    entities: tuple[EntityRef, ...]              # every entity mentioned by any record, sorted
    links: tuple[CorrelationLink, ...]           # sorted by link_id
    clusters: tuple[tuple[EntityRef, ...], ...]  # connected components of the link graph, sorted
    timeline: tuple[TimelineEntry, ...]          # records with a time, sorted by (at, record_id)
    def related(self, entity: EntityRef) -> tuple[EntityRef, ...]: ...       # same cluster, entity excluded
    def links_for(self, entity: EntityRef) -> tuple[CorrelationLink, ...]: ...
    def rule_item(self) -> dict[str, Any]: ...
        # {"entities": [{"kind", "value"}], "links": [link dicts], "clusters": [[...]],
        #  "related": {"<KIND>:<value>": [entity dicts]}}

class CriticalAssetHit(FrozenModel):
    entity: EntityRef
    classes: tuple[CriticalAssetClass, ...]      # >= 1
    record_ids: tuple[str, ...]

class BlastRadiusReport(FrozenModel):
    endpoints: tuple[str, ...]
    users: tuple[str, ...]
    indicators: tuple[str, ...]                  # domains, URLs, IPs, hashes
    messages: int
    critical_assets: tuple[CriticalAssetHit, ...]
    caps: Mapping[str, int]                      # thresholds.blast_radius as {"endpoints", "users", "indicators", "messages"}
    exceeds: tuple[str, ...]                     # cap names exceeded (informational; PackageBuilder decides ELEVATED)
    record_ids: tuple[str, ...]
    def to_blast_radius(self) -> BlastRadius: ...   # Phase 0 model
    def rule_item(self) -> dict[str, Any]: ...

# xdr_response/atomics/correlation/correlate.py
def correlate(ctx: AtomicContext, results: Sequence[AtomicResult], *,
              extra_links: Sequence[CorrelationLink] = (), window: timedelta = DEFAULT_WINDOW,   # 60 minutes
              link_kinds: Collection[LinkKind] = FRAMEWORK_LINK_KINDS) -> CorrelationResult: ...
    # the runner passes window=timedelta(minutes=spec.window_minutes), link_kinds=spec.link_kinds; extra_links
    # (hook links) are never filtered by link_kinds and must cite records of results (EvidenceError otherwise)
def build_timeline(results: Sequence[AtomicResult]) -> tuple[TimelineEntry, ...]: ...
# xdr_response/atomics/correlation/blast_radius.py
def blast_radius(ctx: AtomicContext, correlation: CorrelationResult, results: Sequence[AtomicResult], *,
                 scope: Sequence[EntityRef] | None = None) -> BlastRadiusReport: ...
    # scope default: the clusters that contain an incident observable, asset or user
```

Framework link rules (window `CorrelationSpec.window_minutes`, default 60):

| Link kind | Rule |
|---|---|
| `same_hash`, `same_domain`, `same_ip`, `same_url` | an indicator mentioned by records that also mention two or more distinct endpoints or users: one link with the indicator and those assets, citing those records |
| `same_user`, `same_endpoint` | a user (endpoint) mentioned together with two or more distinct endpoints (users) |
| `process_lineage` | process events on one endpoint whose parent pid or parent hash matches another event's pid or hash |
| `sign_in_to_activity` | a successful sign-in for a user followed within the window by a mailbox rule, role change or cloud app consent for the same user |
| `email_to_click` | an email message carrying URL or domain D, and a network connection or DNS query to D from a recipient's endpoint or user after `received_at` within the window |
| `campaign` | two or more email messages sharing a `campaign_id`, or the same sender domain and the same URL or attachment hash |

#### 14.1.6 Evidence builder (owner: correlation-evidence)

The evidence builder is the only way the read zone produces `EvidenceDraft`s. It cites records it was given, by id, and nothing else.

```python
# xdr_response/atomics/evidence.py
class EvidenceError(ValueError): ...

class RecordIndex:
    def __init__(self, results: Iterable[AtomicResult] = (), *, records: Iterable[AnyRecord] = ()) -> None: ...
        # the same record_id with different content -> EvidenceError; AnomalyRecord.related_record_ids and every
        # cited id must resolve inside the index
    def get(self, record_id: str) -> AnyRecord: ...                  # KeyError
    def require(self, record_ids: Iterable[str]) -> tuple[AnyRecord, ...]: ...   # EvidenceError naming unknown ids
    def ids(self) -> tuple[str, ...]: ...
    def __contains__(self, record_id: object) -> bool: ...
    def __len__(self) -> int: ...

def evidence_summary(record: AnyRecord) -> str: ...   # deterministic template per kind, <= 300 chars, redacted
def evidence_draft(record: AnyRecord) -> EvidenceDraft: ...
    # source=record.integration, summary=evidence_summary(record), observed_at=record.observed_at,
    # reference=record.reference,
    # data={"record_id": ..., "kind": ..., "atomic": ..., "fields": record.evidence_fields()}

class EvidenceBuilder:
    def __init__(self, index: RecordIndex) -> None: ...
    def cite(self, record_ids: Iterable[str]) -> tuple[EvidenceDraft, ...]: ...
        # >= 1 id (EvidenceError otherwise), every id known (EvidenceError), duplicates removed,
        # order (observed_at or min, record_id)
    def verify(self, drafts: Iterable[EvidenceDraft]) -> None: ...
        # every draft must equal evidence_draft(index.get(draft.data["record_id"])) exactly, else EvidenceError
    @staticmethod
    def record_ids(drafts: Iterable[EvidenceDraft]) -> tuple[str, ...]: ...
```

Summary templates (`unknown` for `None` values; hashes shortened to 12 characters plus `...`): enrichment `"{integration} rates {value} {verdict} (risk {risk_score}, confidence {confidence})"`; endpoint `"{integration}: endpoint {hostname} ({os}), isolation {isolation_state}"`; detection `"{integration}: {severity} detection '{name}' ({verdict}) on {endpoint}"`; process_event `"{integration}: {event_type} {process_name} on {endpoint} at {timestamp} (x{count})"`; network_connection `"{integration}: {endpoint or user} {direction} to {domain or remote_ip}:{remote_port} ({action})"`; dns_query `"{integration}: {endpoint or client_ip} queried {domain} x{count} ({action})"`; hash_prevalence `"{integration}: {sha256} seen on {prevalence} endpoint(s), {verdict}"`; persistence_item `"{integration}: {mechanism} '{name}' on {endpoint}"`; user_profile `"{integration}: user {user}, risk {risk_level}, enabled {account_enabled}, privileged {privileged}"`; sign_in `"{integration}: sign-in {result} for {user} from {ip} ({country}) to {app} at {timestamp}, MFA {mfa_result}"`; anomaly `"{integration}: {anomaly_type} ({severity}) for {user or endpoint}"`; mfa_event `"{integration}: MFA {method} {result} for {user} at {timestamp}"`; mailbox_rule `"{integration}: mailbox rule '{name}' on {mailbox}"` plus `", forwards externally"` when set; role_change `"{integration}: role {role_name} {change} for {user} by {actor}"`; email_message `"{integration}: message {message_id} from {sender} to {recipient_count} recipient(s), {verdict}, {delivery_location}"`; cloud_app `"{integration}: app {display_name} ({app_id}), consent {consent_type}, {n} permission(s)"`; generic `"{integration}: {name}"` plus up to three sorted `key=value` attributes.

Rules: an action's evidence is exactly `cite(...)` of the records its rule names (14.3.1) plus, when `include_target_enrichment`, the target's `ANSWERED` enrichment records rated `MALICIOUS` or `SUSPICIOUS`. Derived statements (correlation, scores, thresholds) go into the rationale, never into evidence. Numbering (1..n) and the snapshot hash stay with `PackageBuilder` and `number_evidence` (13.5); `data["record_id"]` lets the decision card map a contribution's record id to its evidence number.

#### 14.1.7 Containment recommendation builders (owner: containment-atomics)

The builders turn a decision of a workflow rule into a `ProposedAction`, choosing the integration native first (section 4.2). They **never execute**: they return data that `PackageBuilder` packages and a human approves.

```python
# xdr_response/atomics/containment/models.py
class RouteDecision(FrozenModel):
    action_type: ActionType
    integration: str | None                      # None: no execution path today
    native: bool = False                         # executed through cisco_xdr respond/trigger
    product: str | None = None                   # product the action lands on (verify_integration when native)
    params: JsonDict = {}                        # routing params: integration and, when native, module_instance_id,
                                                 # action_id, observable_type, observable_value, verify_integration
    considered: tuple[str, ...] = ()             # e.g. "cisco_xdr: no configured native action for secure_endpoint"
    reason: str = ""                             # why integration is None

class BuiltRecommendation(FrozenModel):
    action_type: ActionType
    target: str                                  # normalized
    proposal: ProposedAction | None              # None when unrouted
    route: RouteDecision
    warnings: tuple[CriticalAssetWarning, ...] = ()   # preview from CriticalAssetPolicy.evaluate; PackageBuilder decides
    excluded_reason: str | None = None           # AllowlistPolicy preview; the proposal is still built and
                                                 # PackageBuilder moves it to excluded_targets (shown, never dropped)
    unrouted_reason: str | None = None           # set exactly when proposal is None

# xdr_response/atomics/containment/routing.py
NATIVE_OBSERVABLE_TYPES: Mapping[TargetKind, str]   # ENDPOINT "hostname", DOMAIN "domain", URL "url", IP "ip"/"ipv6",
                                                    # HASH "sha256"/"sha1"/"md5", USER "user", EMAIL_MESSAGE "email_messageid"
def choose_route(ctx: AtomicContext, action_type: ActionType, target: str, *,
                 product: str | None = None) -> RouteDecision: ...

# xdr_response/atomics/containment/builders.py
RESERVED_PARAM_KEYS: frozenset[str]   # integration, verify_integration, restores, module_instance_id, action_id,
                                      # observable_type, observable_value, approval_level, plus config FORBIDDEN_KEYS
def build_containment(ctx: AtomicContext, action_type: ActionType, target: str, *,
                      evidence: Sequence[EvidenceDraft], risk_score: int, confidence_score: int, rationale: str,
                      asset: Asset | None = None, params: Mapping[str, Any] | None = None,
                      product: str | None = None) -> BuiltRecommendation: ...
    # ValueError (caller bug) when: action_type is not CONTAINMENT or REMEDIATION (restoration is only ever built
    # by RestorationPlanner); evidence is empty; params use a RESERVED_PARAM_KEYS key or a sensitive key
    # (Redactor.is_sensitive_key) or contain floats; target cannot be normalized for the catalog target kind.
    # route = choose_route(...); proposal params = caller params + route.params (route wins).
```

`choose_route` (deterministic):

1. `candidates = ctx.adapters.executors(action_type)`. With `product` given, only `cisco_xdr` (native, landing on that product) and `product` itself are eligible; the builder never silently switches product.
2. Native first: when `cisco_xdr` is a candidate and `settings.integrations["cisco_xdr"].options["native_actions"][action_type.value][product or <first non-cisco candidate>]` names `{"module": ..., "action_id": ...}`, call `ctx.adapters.native_response_actions(Observable(NATIVE_OBSERVABLE_TYPES[...], target), module=module)` and keep the actions with that `action_id`. Exactly one: native route with `params = {integration: "cisco_xdr", module_instance_id, action_id, observable_type, observable_value: target, verify_integration: product}`. None, several, no configuration or a read error: recorded in `considered`, fall through. Native action ids are copied by the operator from the tenant's `respond/observables` listing; the framework never guesses them.
3. Direct: `product` when it is a candidate, else the first non-`cisco_xdr` candidate.
4. Nothing: `integration=None` with reason `"no enabled adapter has a VERIFIED write for <action>"`. The recommendation is still reported (notes, decision card), marked for manual handling, never silently dropped.

Named builders (the brief's names). Each is `build_containment` with a fixed action type and product; the signature is `(ctx, target, *, evidence, risk_score, confidence_score, rationale, asset=None, params=None) -> BuiltRecommendation`.

| Builder | Action type | Product | Route today (docs/integrations.md) |
|---|---|---|---|
| `isolate_secure_endpoint` | isolate_endpoint | secure_endpoint | native or direct; verify `UNABLE_TO_VERIFY` |
| `isolate_defender_endpoint` | isolate_endpoint | defender_endpoint | native or direct; verify VERIFIED |
| `block_domain_umbrella` | block_domain | umbrella | native or direct |
| `block_url` | block_url | (catalog order) | umbrella / defender_endpoint / native |
| `block_ip` | block_ip | (catalog order) | meraki / defender_endpoint / native (IPv4) |
| `block_hash` | block_hash | (catalog order) | defender_endpoint / native |
| `revoke_entra_sessions` | revoke_sessions | entra | direct only |
| `disable_entra_user` | disable_user | entra | native or direct |
| `quarantine_email` | quarantine_email | (catalog order) | secure_email / defender_o365 / native |
| `delete_malicious_email` | delete_email | (catalog order) | defender_o365 softDelete / secure_email trash; never hard delete |
| `intune_device_action` | lock_device | intune | direct; extra keyword `action: Literal["lock"] = "lock"`, any other value raises `ValueError` (UNVERIFIED) |
| `terminate_process` | terminate_process | (catalog order) | unrouted with real adapters (UNVERIFIED); routes in the simulated lab |
| `quarantine_file` | quarantine_file | (catalog order) | unrouted with real adapters (UNVERIFIED) |
| `remove_persistence` | remove_persistence | (catalog order) | unrouted (no adapter) |
| `remove_privileged_role` | remove_privileged_role | entra | direct; always ELEVATED by the catalog |

Other catalog containment types (`confirm_user_compromised`, `block_network_client`, `reset_password`, `reset_mfa`, `revoke_app_credentials`, `remove_application`) are reachable through `build_containment`. `CONTAINMENT_BUILDERS: Mapping[str, Callable[..., BuiltRecommendation]]` maps the 15 names.

`containment-atomics` also documents `native_actions` (commented example, no real ids) in `config/integrations.example.yaml`.

#### 14.1.8 Notifications (owner: notifications)

Incident notes, SOC notifications and analyst summaries are **read-zone bookkeeping**: rendered text stored in an outbox. They never call a vendor write; the Cisco XDR worklog note path is UNVERIFIED, so nothing is posted to XDR in Phase 1.

```python
# xdr_response/atomics/notifications/models.py
class NotificationKind(StrEnum):
    INCIDENT_NOTE = "incident_note"; SOC_NOTIFICATION = "soc_notification"; ANALYST_SUMMARY = "analyst_summary"

class LifecycleEventKind(StrEnum):
    DETECTION_COMPLETED = "detection_completed"      # investigation done, nothing proposed
    PACKAGE_PROPOSED = "package_proposed"
    DECISION_RECORDED = "decision_recorded"
    CONTAINMENT_COMPLETED = "containment_completed"
    RELEASE_PROPOSED = "release_proposed"
    RESTORATION_COMPLETED = "restoration_completed"
    INCIDENT_CLOSED = "incident_closed"

class WorkflowSummary(FrozenModel):                  # read-zone facts of one workflow run
    workflow_id: str
    workflow_version: str
    risk_score: Score
    confidence_score: Score
    risk_band: RiskBand
    evidence: tuple[str, ...] = ()                   # "[<record_id>] <evidence summary>" of cited records
    degraded_sources: tuple[str, ...] = ()
    unrouted: tuple[str, ...] = ()                   # "<action_type> <target>: <reason>"
    below_threshold: tuple[str, ...] = ()
    blast_radius: BlastRadius = BlastRadius()

class LifecycleEvent(FrozenModel):
    kind: LifecycleEventKind
    at: AwareDatetime
    incident: Incident
    package: ContainmentPackage | ReleasePackage | None = None
    decision: AnalystDecision | None = None
    report: ContainmentReport | RestorationReport | None = None
    summary: WorkflowSummary | None = None
    notes: tuple[str, ...] = ()
    dry_run: bool = False

class NotificationDraft(FrozenModel):
    notification_id: str                             # sha256_hex(canonical_json([kind, incident_id, event, ref]))[:32]
    kind: NotificationKind
    event: LifecycleEventKind
    incident_id: str
    created_at: AwareDatetime
    audience: Literal["incident", "soc", "analyst"]
    title: str                                       # <= 200 chars; "[DRY RUN] " prefix in dry run
    body: str                                        # <= 16 KiB, redacted
    workflow_id: str | None = None
    workflow_version: str | None = None
    contains_ai_text: bool = False

class DeliveryStatus(StrEnum):
    STORED = "STORED"; DELIVERED = "DELIVERED"; NOT_DELIVERED_UNVERIFIED = "NOT_DELIVERED_UNVERIFIED"; FAILED = "FAILED"

class DeliveryRecord(FrozenModel):
    notification_id: str
    sink: str
    status: DeliveryStatus
    detail: str = ""
    at: AwareDatetime

# xdr_response/atomics/notifications/render.py
def render_incident_note(event: LifecycleEvent) -> NotificationDraft: ...
def render_soc_notification(event: LifecycleEvent) -> NotificationDraft: ...
def render_analyst_summary(event: LifecycleEvent) -> NotificationDraft: ...

# xdr_response/atomics/notifications/sinks.py
@runtime_checkable
class NotificationSink(Protocol):
    name: str
    def deliver(self, draft: NotificationDraft) -> DeliveryRecord: ...   # never raises
class MemoryNotificationSink: ...                    # name "memory"; .drafts list
class JsonlNotificationSink:                         # name "jsonl"; append-only file, one canonical JSON line per draft
    def __init__(self, path: Path | str, *, clock: Clock | None = None) -> None: ...
class XdrIncidentNoteSink:                           # name "cisco_xdr_note"; always NOT_DELIVERED_UNVERIFIED
    ...                                              # (worklog note path UNVERIFIED); never touches an adapter

# xdr_response/atomics/notifications/service.py
DEFAULT_ROUTING: Mapping[LifecycleEventKind, tuple[NotificationKind, ...]]
    # PACKAGE_PROPOSED: incident note, SOC notification, analyst summary; DECISION_RECORDED: incident note;
    # CONTAINMENT_COMPLETED and RESTORATION_COMPLETED: incident note, SOC notification;
    # RELEASE_PROPOSED: SOC notification; DETECTION_COMPLETED and INCIDENT_CLOSED: incident note
class NotificationService:                           # implements lifecycle.observers.LifecycleObserver
    def __init__(self, sinks: Sequence[NotificationSink], *, clock: Clock | None = None,
                 routing: Mapping[LifecycleEventKind, tuple[NotificationKind, ...]] = DEFAULT_ROUTING) -> None: ...
    def on_event(self, event: LifecycleEvent) -> tuple[DeliveryRecord, ...]: ...   # never raises
```

Content rules (unit-tested): deterministic text; risk and confidence shown separately; evidence as numbered package evidence when a package exists (else the summary's record lines); the human decision with approver identities, approved and rejected actions; per action the catalog rollback action (`rollback_for`) or "not reversible"; never `params`, `rollback_params`, `external_ref` values, tokens, token ids beyond the first 8 characters, signatures, unlock codes, secrets or credentials; never an approval link or button that acts (the decision is taken only in the orchestrator's decision flow). AI text appears only in the analyst summary, under the heading "AI narrative (not evidence, not reviewed)", and sets `contains_ai_text`. Every body passes `get_redactor().redact_text`.

#### 14.1.9 Atomic name table (owner: workflow-framework)

```python
# xdr_response/atomics/__init__.py   (lazy, like lifecycle/__init__.py)
def read_atomics() -> Mapping[str, Callable[..., AtomicResult]]: ...
    # ENRICHMENT_ATOMICS | INVESTIGATION_ATOMICS (23 names); names never collide
def atomic_subject_types() -> Mapping[str, frozenset[ObservableType]]: ...
def containment_builders() -> Mapping[str, Callable[..., BuiltRecommendation]]: ...   # CONTAINMENT_BUILDERS
```

No key edits another key's table; the framework only composes them.

### 14.2 Scoring engine (owner: scoring)

`docs/threat-scoring.md` sections 1, 2, 4 to 8 and 10 become binding with the changes below (the scoring key updates that document and `src/xdr_response/scoring/README.md` to say so). The one deliberate change: signals and contributions cite **record ids**, not evidence numbers, because numbers are only assigned later by `PackageBuilder`.

#### 14.2.1 Models

```python
# xdr_response/models/scoring.py   (layer 0)
class SignalCategory(StrEnum):
    ENDPOINT_DETECTION = "endpoint_detection"; SANDBOX_VERDICT = "sandbox_verdict"; REPUTATION = "reputation"
    NETWORK_BEHAVIOUR = "network_behaviour"; AUTHENTICATION_ANOMALY = "authentication_anomaly"
    EMAIL_VERDICT = "email_verdict"; PERSISTENCE = "persistence"; LATERAL_MOVEMENT = "lateral_movement"
    CAMPAIGN_ASSOCIATION = "campaign_association"

DEFAULT_WEIGHTS: Mapping[SignalCategory, float]   # endpoint_detection 1.0, sandbox_verdict 0.9, network_behaviour 0.9,
    # authentication_anomaly 0.9, email_verdict 0.8, persistence 0.8, lateral_movement 1.0,
    # campaign_association 0.7, reputation 0.6

class ScoringSignal(FrozenModel):
    category: SignalCategory
    integration: str                             # source adapter (INTEGRATION_NAMES)
    observable: Observable                       # the target the signal is about (normalized)
    verdict: Verdict
    severity: Score                              # impact if true
    confidence: Score                            # the source's confidence, or the record-kind default (14.2.3)
    record_ids: tuple[str, ...]                  # >= 1; validated against the run's RecordIndex by the caller
    health: HealthStatus = HealthStatus.CONNECTED
    origin: str = "framework"                    # or "workflow:<id>" for hook-derived signals (14.3.3)
    note: str = ""
    vendor_verdict: bool = False                 # True for an enrichment answer (a vendor's verdict, 14.2.3), never a
                                                 # behavioural detection; see 14.2.2 and 14.9.6

class ScoringContext(FrozenModel):
    critical_asset_classes: tuple[CriticalAssetClass, ...] = ()
    expected_sources: tuple[str, ...] = ()
    failed_sources: tuple[tuple[str, HealthStatus], ...] = ()     # (integration, health), sorted
    not_queried: tuple[tuple[str, str], ...] = ()                 # (integration, reason), sorted

class Contribution(FrozenModel):
    category: SignalCategory | Literal["corroboration", "critical_asset", "independent_sources",
                                       "contradiction", "failed_sources"]
    integration: str | None
    points: int                                  # signed; risk or confidence points
    applies_to: Literal["risk", "confidence"]
    record_ids: tuple[str, ...] = ()
    note: str = ""

class ScoreBreakdown(FrozenModel):
    risk_score: Score
    confidence_score: Score
    risk_band: RiskBand
    contributions: tuple[Contribution, ...]
    caps_applied: tuple[str, ...] = ()           # e.g. "reputation capped at 50"
    failed_sources: tuple[str, ...] = ()         # "<integration> (<HEALTH>)"
    not_queried: tuple[str, ...] = ()            # "<integration> (<reason>)"
    reputation_only: bool = False
    settings_hash: str                           # sha256_hex(canonical_json(scoring settings, allow_floats=True))
    def explain(self) -> str: ...
        # one deterministic line: "risk 90 CRITICAL (endpoint_detection secure_endpoint 80; corroboration +10),
        #  confidence 90 (base 85; independent sources +10; failed alienvault_otx -5), settings <hash[:12]>"
```

#### 14.2.2 Engine

```python
# xdr_response/scoring/engine.py
class ScoringEngine:
    def __init__(self, settings: ScoringSettings) -> None: ...
    def score(self, signals: Sequence[ScoringSignal], *, context: ScoringContext,
              weights: Mapping[SignalCategory, float] | None = None) -> ScoreBreakdown: ...
        # weights: workflow overrides (14.3.1) of category weights only; caps, steps and penalties are not overridable
    def package_scores(self, breakdowns: Sequence[ScoreBreakdown]) -> tuple[int, int]: ...
        # (max risk, round-half-up mean confidence); (0, 0) for none
    @property
    def settings_hash(self) -> str: ...

# xdr_response/scoring/verdict.py
def aggregate_verdict(signals: Sequence[ScoringSignal], breakdown: ScoreBreakdown, *,
                      bands: Mapping[str, int] | None = None) -> Verdict: ...
    # bands None: the built-in HIGH lower bound 60 (14.1.3 step 4 calls it without bands; enrichment passes
    # bands=settings.bands)
```

The calculation is exactly `docs/threat-scoring.md` 5.1 and 5.2 (risk: highest weighted category, reputation cap, corroboration bonus, critical-asset bonus; confidence: base, reputation-only cap, independent-source bonus, contradiction penalty, failed-source penalty), with these precisions:

- Signals with verdict `UNKNOWN` are ignored; `CLEAN` signals count only for the contradiction penalty and never lower risk.
- Rounding happens once, at the end, half up (`math.floor(x + 0.5)`); then clamp to 0-100. Input order never changes the output (signals are sorted by `(category, integration, observable.type, observable.value, record_ids)` first).
- No signal at all: risk 0, confidence 0, band LOW, the failed sources listed; the decision card shows "insufficient evidence".
- `risk_band` uses the configured bands (`risk_band(score, bands)`).
- `AI` text, analyst comments and anything without a record id are never inputs: there is no parameter that could carry them.

`aggregate_verdict`: `MALICIOUS` when risk is at least the HIGH band lower bound and there is a `MALICIOUS` **behavioural detection** (a non-reputation signal that is not a vendor verdict, `vendor_verdict=False`), or `MALICIOUS` vendor verdicts (reputation signals or enrichment answers, any category) from two or more distinct integrations and no `CLEAN` signal; otherwise `SUSPICIOUS` when any signal is `MALICIOUS` or `SUSPICIOUS`; otherwise `CLEAN` when at least one source answered `CLEAN` and no source failed; otherwise `UNKNOWN`. One vendor's `MALICIOUS` alone is therefore `SUSPICIOUS`, whether it is a reputation service, a sandbox, an email gateway or an identity provider answering an enrichment.

Risk precisions (threat-scoring 5.1 and 5.4, 14.9.6): a category corroborates only through a signal of an integration other than the base signal's (a source never corroborates itself); when every supporting signal that carries weight comes from one integration (another integration counts only when one of its signals is weighted at least `corroboration.min`, 14.9.7) and none is a `MALICIOUS` behavioural detection (not a vendor verdict, not `reputation` or `campaign_association`) with severity at least the CRITICAL band lower bound, the risk before the critical-asset bonus is capped at that bound minus one (`caps_applied`: "single source capped at 79"). Confidence precision (5.2 step 5): a failed source is penalised once, whatever mix of failing health values it reported.

#### 14.2.3 Signals from records

```python
# xdr_response/scoring/signals.py
ENRICHMENT_CATEGORY: Mapping[str, SignalCategory]
    # secure_malware_analytics: sandbox_verdict; secure_endpoint, defender_endpoint, intune: endpoint_detection;
    # entra: authentication_anomaly; secure_email, defender_o365: email_verdict; every other integration: reputation
SEVERITY_POINTS: Mapping[Severity, int]          # CRITICAL 95, HIGH 80, MEDIUM 60, LOW 30, INFO 10
LEVEL_POINTS: Mapping[str, int]                  # high 80, medium 60, low 40, none 0, unknown 0
RECORD_CONFIDENCE: Mapping[RecordKind, int]      # detection 80, process_event 70, network_connection 60, dns_query 60,
    # hash_prevalence 70, persistence_item 60, anomaly 70, mailbox_rule 70, role_change 75, email_message 80, cloud_app 60,
    # user_profile 70
def signals_from_enrichment(records: Sequence[EnrichmentRecord]) -> tuple[ScoringSignal, ...]: ...
def signals_from_records(records: Sequence[AnyRecord], *, observable: Observable) -> tuple[ScoringSignal, ...]: ...
```

| Record | Signal | Severity | Verdict |
|---|---|---|---|
| enrichment (not `UNKNOWN`) | `ENRICHMENT_CATEGORY[integration]`, `vendor_verdict=True` | risk_score | record verdict; confidence = record confidence |
| detection | endpoint_detection; persistence when `category` names persistence; lateral_movement when it names lateral movement | `SEVERITY_POINTS[severity]` | record verdict |
| process_event with verdict `MALICIOUS` or `SUSPICIOUS` | endpoint_detection | 70 (malicious), 50 (suspicious) | record verdict |
| network_connection / dns_query with verdict not `UNKNOWN` | network_behaviour | 70 / 50 | record verdict |
| hash_prevalence with verdict `MALICIOUS` | endpoint_detection | 70 | MALICIOUS |
| persistence_item with verdict `MALICIOUS` or `SUSPICIOUS` | persistence | 70 / 50 | record verdict |
| anomaly | authentication_anomaly | `SEVERITY_POINTS[severity]` | SUSPICIOUS (MALICIOUS when severity HIGH or CRITICAL) |
| user_profile with `risk_state == "confirmed_compromised"` or `risk_level == "high"` | authentication_anomaly | 85 / `LEVEL_POINTS[risk_level]` | MALICIOUS / SUSPICIOUS |
| mailbox_rule with `external_forwarding` or `delete` | persistence | 70 | SUSPICIOUS |
| role_change with `privileged` and change `assigned` or `activated` | persistence | 75 | SUSPICIOUS |
| email_message with verdict not `UNKNOWN` | email_verdict | 80 malicious, 50 suspicious, 0 clean | record verdict |
| cloud_app with verdict not `UNKNOWN` | persistence | 60 | record verdict |
| sign_in, mfa_event, endpoint, generic | none (context only; patterns over them are hook-derived signals) | | |

`campaign_association` and `lateral_movement` patterns come from correlation links and workflow hooks (14.3.3), always citing the records they were computed from.

#### 14.2.4 Configuration

```python
# xdr_response/config/schema.py   (scoring owns only these classes in this file)
class ScoringCaps(BaseModel):
    reputation_max_contribution: int = 50        # 0-100
    reputation_only_confidence_cap: int = 50
class CorroborationSettings(BaseModel):
    min: int = 30; step: int = 5; max: int = 15
class ConfidenceSettings(BaseModel):
    independent_source_step: int = 5; independent_source_max: int = 20; contradiction_penalty: int = 15
    failed_source_penalty: int = 5; failed_source_max_penalty: int = 20
class ScoringContextSettings(BaseModel):
    critical_asset_bonus: int = 10
class ScoringSettings(BaseModel):
    bands: dict[str, int] = {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}
        # validator: exactly the four RiskBand names, LOW == 0, strictly increasing in band order, all <= 100
    weights: dict[SignalCategory, float] = {}    # 0.0-1.0; missing categories use DEFAULT_WEIGHTS; unknown key refused
    caps: ScoringCaps = ScoringCaps()
    corroboration: CorroborationSettings = CorroborationSettings()
    confidence: ConfidenceSettings = ConfidenceSettings()
    context: ScoringContextSettings = ScoringContextSettings()
    def weight(self, category: SignalCategory) -> float: ...
```

`config/thresholds.yaml` gets the shape of `docs/threat-scoring.md` section 7 with the defaults above (`extra="forbid"` stays; a Phase 0 file with `weights: {}` still loads). `models/recommendation.py`: `risk_band(score: int, bands: Mapping[str, int] | None = None) -> RiskBand` (None: the built-in cut-offs; existing callers unchanged).

#### 14.2.5 What scores never do (tested)

Scores never approve, skip approval, execute or change `approval_level`; a low score never hides an action (below-threshold actions are listed in the notes, 14.3.4); a high score never adds an action no rule proposes; dry run and live runs score identically. Required tests are `docs/threat-scoring.md` section 10 plus: weights override cannot change caps; `explain()` is stable; record ids in every contribution exist in the input signals.

### 14.3 Workflow framework (owner: workflow-framework)

A workflow is a validated, declarative `WorkflowDefinition` (plus optional pure hooks) in its own package. The framework investigates, correlates, scores and turns the definition's rules into `ProposedAction`s; the Phase 0 lifecycle does everything after that. A workflow contains no vendor HTTP code, no approval logic and no execution path.

#### 14.3.1 `WorkflowDefinition`

```python
# xdr_response/workflows/definition.py   (layer 0 model module)
WORKFLOW_ID_RE = r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"        # kebab-case == workflows/<id>/
SEMVER_RE = r"^\d+\.\d+\.\d+$"
TACTICS: Mapping[str, str]   # ATT&CK Enterprise tactic ids: TA0043 Reconnaissance, TA0042 Resource Development,
    # TA0001 Initial Access, TA0002 Execution, TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion,
    # TA0006 Credential Access, TA0007 Discovery, TA0008 Lateral Movement, TA0009 Collection,
    # TA0011 Command and Control, TA0010 Exfiltration, TA0040 Impact
APPROVAL_LIKE_KEYS: frozenset[str]   # config FORBIDDEN_KEYS | {"approval_level", "requires_approval", "approve", "approved"}

class TriggerSpec(FrozenModel):
    type: Literal["xdr_incident_rule", "webhook", "schedule", "manual"]
    description: str
    mitre_techniques: tuple[str, ...] = ()       # match incident.trigger["mitre_techniques"]
    title_patterns: tuple[str, ...] = ()         # fnmatch, case-insensitive, on incident.title
    sources: tuple[str, ...] = ()                # incident.source or incident.trigger["source"]
    observable_types: tuple[ObservableType, ...] = ()   # the incident must carry at least one
    priority: int = 100                          # higher wins when several workflows match
    def matches(self, incident: Incident) -> bool: ...
        # every non-empty criterion must hold (AND); within a criterion any value may match (OR);
        # "manual" and "schedule" triggers never match automatically

class IntegrationRequirement(FrozenModel):
    integration: str                             # INTEGRATION_NAMES member
    purpose: str                                 # one line for the README
    atomics: tuple[str, ...] = ()                # read atomics that use it

class InvestigationStep(FrozenModel):
    id: str                                      # snake_case, unique in the workflow
    atomic: str                                  # a read_atomics() name (14.1.9)
    subjects: str | None = None                  # expression -> list[str]; default: incident observables of the
                                                 # atomic's subject types plus values found by earlier steps (below)
    subject_type: ObservableType | None = None   # required with `subjects` when the atomic accepts several types
    when: str | None = None                      # expression -> bool; step skipped (noted) when false
    integrations: tuple[str, ...] = ()           # restrict sources; subset of required + optional integrations
    options: JsonDict = {}                       # passed to the atomic (adapter query options)
    lookback_hours: int | None = None            # 1-720; default 24
    max_subjects: int = 25                       # 1-200; further subjects are listed in notes, not queried

class CorrelationSpec(FrozenModel):
    description: str                             # README "Correlation logic" source
    link_kinds: tuple[LinkKind, ...] = tuple(k for k in LinkKind if k is not LinkKind.WORKFLOW)
    window_minutes: int = 60                     # 1-1440

class ScoringInputs(FrozenModel):
    description: str                             # README "Risk calculation" source
    weights: Mapping[SignalCategory, float] = {} # category weight overrides, 0.0-1.0
    expected_sources: tuple[str, ...] = ()       # default: the required integrations

class RecommendationRule(FrozenModel):
    id: str                                      # snake_case, unique in the workflow
    description: str
    action: ActionType                           # validator: CONTAINMENT or REMEDIATION catalog type
    builder: str | None = None                   # a CONTAINMENT_BUILDERS name whose action type == action;
                                                 # default build_containment(action)
    for_each: str                                # expression -> list
    when: str | None = None                      # expression -> bool
    target: str                                  # expression -> str (normalized by the builder)
    evidence: str                                # expression -> list[str] of record ids (>= 1 at run time)
    include_target_enrichment: bool = True
    asset: str | None = None                     # expression -> {"groups", "tags", "roles", "ip", "ips", "users",
                                                 # "privileged"} (optional keys; 14.11.6)
    binaries: str | None = None                  # expression -> list of SHA-256: the binaries the action rests on
                                                 # alone; all sanctioned -> withheld ALLOWLISTED (14.11.6)
    indicators: str | None = None                # expression -> list of "<block action>:<target>": the indicators
                                                 # the action rests on alone; the allow-list excludes the block
                                                 # of every one -> withheld ALLOWLISTED (14.13.6)
    params: Mapping[str, str] = {}               # param name -> expression; RESERVED_PARAM_KEYS refused; no floats
    rationale: str                               # expression -> str
    min_risk: int = 0                            # below: "considered, not proposed" note, never silent
    min_confidence: int = 0
    mitre: tuple[str, ...] = ()                  # technique / sub-technique ids this rule responds to

class MitreMapping(FrozenModel):
    tactic: str                                  # key of TACTICS
    technique: str                               # r"^T\d{4}$"
    technique_name: str
    sub_technique: str | None = None             # r"^T\d{4}\.\d{3}$", must start with technique
    sub_technique_name: str | None = None
    rationale: str                               # why this workflow responds to it ("no forced mappings")
    @property
    def tactic_name(self) -> str: ...
    @property
    def attack_id(self) -> str: ...              # sub_technique or technique

class WorkflowDefinition(FrozenModel):
    id: str                                      # WORKFLOW_ID_RE
    version: str                                 # SEMVER_RE; bound into packages and tokens (workflow_version)
    name: str
    description: str                             # README "Purpose" source
    phase: Literal[2, 3, 4, 5]
    default_severity: Severity
    legacy_id: str | None = None                 # workflows/<legacy_id>/workflow.yaml this definition replaces
    triggers: tuple[TriggerSpec, ...]            # >= 1
    input_observables: tuple[ObservableType, ...]   # >= 1; README "Input data"
    required_integrations: tuple[IntegrationRequirement, ...]   # >= 1
    optional_integrations: tuple[IntegrationRequirement, ...] = ()
    investigation: tuple[InvestigationStep, ...] # >= 1
    correlation: CorrelationSpec
    scoring: ScoringInputs
    recommendations: tuple[RecommendationRule, ...]   # >= 1
    mitre: tuple[MitreMapping, ...]              # >= 1
    known_limitations: tuple[str, ...]           # >= 1
    related_workflows: tuple[str, ...] = ()
    handoff_to: tuple[str, ...] = ()             # workflows a hook may hand off to; subset of related_workflows (14.10.1)
```

Validators (all at import time, `ValueError`): unique step and rule ids; `related_workflows` and `handoff_to` kebab-case without duplicates, `handoff_to` within `related_workflows`; required and optional integrations disjoint; step `integrations` within them; every expression parses with `workflows.expr.parse` (syntax and function whitelist); `builder` matches `action`; rule `mitre` ids appear in `mitre`; no key in `APPROVAL_LIKE_KEYS` anywhere in the definition (walk of `model_dump`), so a workflow cannot carry an approval switch; `legacy_id` is either `id` or one of the legacy ids of 14.5.

"Required" integrations are the **expected** sources: they feed `ScoringContext.expected_sources`, the README and the readiness note. A required integration that is disabled or failing never blocks a recommendation that other evidence supports; the run notes it and confidence drops (14.2).

#### 14.3.2 Rule language: the `xdr_plan` evaluator is reused

Recommendation rules keep the legacy plan-rule shape (`for_each` / `when` / `target` / `args`, section 1.2) and the same safe evaluator, so there is one rule system. Phase 1 makes `xdr_response/workflows/expr.py` the canonical evaluator: a copy of `engine/xdr_plan/expr.py` (same AST whitelist, no builtins, dict-only attribute access, `ExprError`) plus these functions in `FUNCTIONS`: `ids(items)` (list of `item["record_id"]` or of each item's `record_ids`, flattened), `flatten(lists)`, `distinct(values)` (sorted unique), `within_minutes(t1, t2, n)` (ISO timestamps), `in_cidr(ip, cidr)`. `legacy-alignment` then replaces `engine/xdr_plan/expr.py` with a re-export shim of the canonical module (14.4), after `workflow-framework` has landed it.

Expression names available to rules and steps:

| Name | Value |
|---|---|
| `incident` | `Incident.model_dump(mode="json")` plus `observables_by_type` (`{type: [values]}`) |
| `results` | `{atomic name: [rule items of every subject]}`; atomics that did not run give `[]` |
| `enrichment` | `{"<type>:<value>": ObservableReport.rule_item()}` |
| `correlation` | `CorrelationResult.rule_item()` (empty structure before the correlation step) |
| `blast` | `BlastRadiusReport.rule_item()` |
| `facts` | the hook's `facts()` mapping (14.3.3), `{}` without hooks |
| `item` | the current `for_each` element |

Values found by earlier steps feed later default subjects: every entity value of the step's subject types mentioned in records of earlier steps (for example endpoints listed by `search_hash_enterprise` feed a later `investigate_endpoint`), de-duplicated, in first-seen order, capped by `max_subjects`.

#### 14.3.3 Hooks (optional, pure)

```python
# xdr_response/workflows/hooks.py
@dataclass(frozen=True)
class RunView:                                   # read-only facts; no context, no adapters
    workflow: WorkflowDefinition
    incident: Incident
    results: tuple[AtomicResult, ...]
    index: RecordIndex
    correlation: CorrelationResult | None
    blast_radius: BlastRadiusReport | None

class WorkflowHooks:
    def correlate(self, view: RunView) -> Sequence[CorrelationLink]: return ()       # kind WORKFLOW, origin "workflow:<id>"
    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]: return ()    # origin "workflow:<id>"
    def facts(self, view: RunView) -> Mapping[str, Any]: return {}                   # JSON values for rule expressions
    def considered(self, view: RunView) -> Sequence[Consideration]: return ()        # not proposed on purpose; manual steps (14.10.1)
    def handoffs(self, view: RunView) -> Sequence[Handoff]: return ()                # suggestions to run a handoff_to workflow (14.10.1)
```

Hooks are called with `correlation=None` for `correlate` and with the final correlation for the others. Every link and signal they return must cite existing record ids (`RecordIndex.require`); an invalid item, an exception or non-JSON facts are noted and ignored (never block, never crash the run). Hooks are read-zone code (14.0.1 lint applies) and get no context, so they cannot reach an adapter.

#### 14.3.4 Runner

```python
# xdr_response/workflows/runner.py
class RuleOutcomeStatus(StrEnum):
    PROPOSED = "PROPOSED"; BELOW_THRESHOLD = "BELOW_THRESHOLD"; UNROUTED = "UNROUTED"
    DUPLICATE = "DUPLICATE"; NO_EVIDENCE = "NO_EVIDENCE"; ERROR = "ERROR"
    ALLOWLISTED = "ALLOWLISTED"   # file signed by an approved tool's signer (14.10.7); shown as considered

class RuleOutcome(FrozenModel):
    rule_id: str
    status: RuleOutcomeStatus
    action_type: ActionType
    target: str | None = None
    risk_score: int = 0
    confidence_score: int = 0
    record_ids: tuple[str, ...] = ()
    detail: str = ""

@dataclass(frozen=True)
class WorkflowRun:
    workflow: WorkflowDefinition
    incident_id: str
    dry_run: bool
    started_at: datetime
    finished_at: datetime
    results: tuple[AtomicResult, ...]
    index: RecordIndex
    correlation: CorrelationResult
    blast_radius: BlastRadiusReport
    signals: tuple[ScoringSignal, ...]           # hook-derived, validated
    built: tuple[BuiltRecommendation, ...]
    outcomes: tuple[RuleOutcome, ...]
    proposals: tuple[ProposedAction, ...]        # == [b.proposal for b in built if b.proposal]
    breakdowns: Mapping[tuple[ActionType, str], ScoreBreakdown]
    risk_score: int                              # ScoringEngine.package_scores
    confidence_score: int
    health: Mapping[str, HealthStatus]           # worst status per integration
    notes: tuple[str, ...]
    def summary(self) -> WorkflowSummary: ...
    def raw_enrichments(self) -> tuple[EnrichmentResult, ...]: ...
    def raw_investigations(self) -> tuple[InvestigationResult, ...]: ...

class WorkflowRunner:
    def __init__(self, adapters: ReadOnlyAdapters, settings: Settings, *, clock: Clock,
                 scorer: ScoringEngine | None = None) -> None: ...
    def run(self, workflow: WorkflowDefinition, hooks: WorkflowHooks | None, incident: Incident, *,
            dry_run: bool) -> WorkflowRun: ...
```

`run` (deterministic; never raises for a source, rule or hook):

1. `ctx = AtomicContext(...)` with the workflow's lookback.
2. Investigation steps in order. A step whose `when` or `subjects` expression fails, or whose atomic raises, is noted and skipped; partial results stay.
3. `index = RecordIndex(results)`; hook links; `correlate`; `blast_radius`; hook signals and facts.
4. Rules in order. Per `for_each` item: `when`; `target`; `evidence` ids -> `EvidenceBuilder.cite` (unknown ids or an empty list: `NO_EVIDENCE`); scoring of the target: `signals_from_records(cited records)` + enrichment signals of the target + hook signals for the target, context = critical-asset classes of the target (with the rule's `asset`), expected sources, failed and not-queried sources of the results that concern the target; `min_risk` / `min_confidence` (`BELOW_THRESHOLD`); builder call (`UNROUTED` when no route); a second rule for the same `(action_type, target)` merges its evidence into the first and keeps the higher risk (`DUPLICATE`, as `PackageBuilder` would). Expression errors give `ERROR` with the message.
5. `rationale = <rule rationale> + "; " + breakdown.explain()`; the explanation (with the settings hash) therefore reaches the package and the `PACKAGE_PROPOSED` audit record.
6. Package scores, health, notes: degraded sources, disabled required integrations, skipped steps, truncated subjects, unrouted and below-threshold actions, rule and hook errors.

#### 14.3.5 Discovery and routing (no shared registry)

```python
# xdr_response/workflows/discovery.py
class WorkflowDiscoveryError(RuntimeError): ...

@dataclass(frozen=True)
class DiscoveredWorkflow:
    definition: WorkflowDefinition
    hooks: WorkflowHooks | None
    module: str                                  # e.g. "xdr_response.workflows.ransomware"

class WorkflowCatalog:
    def __init__(self, workflows: Iterable[DiscoveredWorkflow]) -> None: ...   # duplicate id -> WorkflowDiscoveryError
    def ids(self) -> tuple[str, ...]: ...                                    # sorted
    def get(self, workflow_id: str) -> DiscoveredWorkflow: ...               # KeyError
    def resolve(self, incident: Incident) -> DiscoveredWorkflow | None: ...
        # 1 incident.workflow_id is a catalog id -> that workflow
        # 2 else the matching automatic triggers, highest priority, then id; None when nothing matches
    def assign(self, incident: Incident) -> Incident: ...
        # copy with workflow_id / workflow_version of resolve(); unchanged when None

def discover_workflows(package: str = "xdr_response.workflows") -> WorkflowCatalog: ...
    # pkgutil.iter_modules(<package>.__path__): every sub-PACKAGE whose name does not start with "_" is a workflow;
    # import it; it must export WORKFLOW (WorkflowDefinition) and may export HOOKS (WorkflowHooks instance);
    # package name == WORKFLOW.id.replace("-", "_"). Import or validation errors raise WorkflowDiscoveryError
    # naming the package: a broken workflow fails loudly, it is never skipped.
```

Framework modules in `xdr_response/workflows/` are plain modules (`definition.py`, `expr.py`, `hooks.py`, `runner.py`, `discovery.py`), never sub-packages, so adding a workflow is adding a directory: no file lists workflows. An incident whose `workflow_id` names a workflow that is not migrated yet (a legacy spec only) resolves to `None` and takes the Phase 0 generic path (`InvestigationService` + `RuleBasedRecommender`) with the note "workflow <id> not migrated yet". Cross-workflow correlation (Phase 5) is a framework feature over several runs, not a workflow directory.

#### 14.3.6 Plugging into the lifecycle

```python
# xdr_response/lifecycle/workflow_adapter.py
@dataclass(frozen=True)
class WorkflowInvestigationReport(InvestigationReport):
    run: WorkflowRun | None = None

class WorkflowInvestigator:                      # same contract as InvestigationService.run
    def __init__(self, catalog: WorkflowCatalog, runner: WorkflowRunner, fallback: InvestigationService, *,
                 audit: AuditSink | None, dry_run: Callable[[], bool]) -> None: ...
    def run(self, incident: Incident) -> InvestigationReport: ...
        # resolve(); None -> fallback.run(incident). Else runner.run(...), then audit ENRICHMENT_RESULT per raw
        # enrichment and INVESTIGATION_COMPLETED once (same payloads and failure policy as InvestigationService),
        # and return WorkflowInvestigationReport(enrichments=raw, investigations=raw, health=run.health, run=run)

class WorkflowRecommender:                       # implements lifecycle.recommendation.Recommender
    def __init__(self, fallback: Recommender) -> None: ...
    def recommend(self, incident: Incident, investigation: InvestigationReport) -> Recommendation: ...
        # report with a run -> Recommendation(proposals=run.proposals, risk_score=run.risk_score,
        #   confidence_score=run.confidence_score, summary=..., unrouted=(UnroutedAction per UNROUTED outcome),
        #   notes=run.notes); otherwise fallback.recommend(...)

# xdr_response/lifecycle/observers.py
@runtime_checkable
class LifecycleObserver(Protocol):
    def on_event(self, event: LifecycleEvent) -> object: ...
```

Changes to Phase 0 lifecycle files (workflow-framework):

- `build_runtime(..., workflows: WorkflowCatalog | None = None, observers: Sequence[LifecycleObserver] = ())`: with a catalog, the runtime's investigator is `WorkflowInvestigator(catalog, WorkflowRunner(ReadOnlyAdapters(adapters), settings, clock=clock), fallback=InvestigationService(...), audit=audit, dry_run=<orchestrator's dry-run check>)` and its recommender `WorkflowRecommender(RuleBasedRecommender(adapters))`; explicit `investigator=` / `recommender=` arguments still win. Without a catalog everything behaves exactly as in Phase 0, so every Phase 0 test is unchanged. `Runtime` gains `workflows: WorkflowCatalog | None = None` and `observers: tuple[LifecycleObserver, ...] = ()`.
- `bootstrap(..., workflows: bool = True, notifications_path: Path | str | None = None)`: discovers the catalog; adds `NotificationService([JsonlNotificationSink(notifications_path or env XDR_RESPONSE_NOTIFICATIONS_PATH or "var/notifications/outbox.jsonl")])`.
- `ResponseOrchestrator.open_incident` stores `runtime.workflows.assign(incident)` when a catalog is wired (before `INCIDENT_RECEIVED` is audited), so packages and tokens carry the workflow id and version.
- The orchestrator emits a `LifecycleEvent` to every observer after `investigate_and_propose` (PACKAGE_PROPOSED or DETECTION_COMPLETED, with `run.summary()` when available), `submit_decision` (DECISION_RECORDED, then CONTAINMENT_COMPLETED when executed), `propose_release`, `submit_release_decision` and `close`. Observer exceptions are logged and swallowed; observers never change state and never see tokens.

Nothing else in the lifecycle changes: packages, approval, execution, verification and restoration are Phase 0 code. ELEVATED, allow-list exclusion and blast-radius rules are applied by `PackageBuilder` to every workflow package, and re-checked at decision time (13.25).

#### 14.3.7 Dry run

Dry run is a framework property; a workflow cannot opt out or add its own switch. The read zone behaves identically in dry run (reads are allowed, nothing writes). The orchestrator marks the package `dry_run` and the `DryRunSimulator` renders the exact Phase 0 output; notifications get the `[DRY RUN]` title prefix. Every workflow ships a `dry-run.yaml` scenario asserting the exact `DRY RUN` lines and zero state-changing operations (14.5.3).

#### 14.3.8 `plan_bridge` (section 12) and legacy replay

```python
# xdr_response/lifecycle/plan_bridge.py
LEGACY_CONTAINMENT: Mapping[str, ActionType]   # isolate-endpoint, block-domain, block-url, block-ip, block-hash,
                                               # disable-user, revoke-session (-> revoke_sessions), quarantine-email
LEGACY_RESULT_SOURCES: Mapping[str, str]       # enrich-ip cisco_xdr, enrich-domain umbrella, enrich-hash cisco_xdr,
                                               # investigate-host secure_endpoint, investigate-user entra
LEGACY_SEVERITY_RISK: Mapping[str, int]        # info 10, low 25, medium 50, high 75, critical 90
LEGACY_CONFIDENCE = 50

@dataclass(frozen=True)
class BridgedAction:
    rule: str
    legacy_atomic: str
    legacy_target: str
    status: str                                  # planned | skipped_allowlisted | skipped_internal (after C3, C5)
    elevated: bool
    action_type: ActionType
    target: str                                  # runtime target (isolate: host name from the result item)
    proposal: ProposedAction | None
    note: str = ""

@dataclass(frozen=True)
class BridgeResult:
    proposals: tuple[ProposedAction, ...]
    actions: tuple[BridgedAction, ...]
    records: tuple[GenericRecord, ...]
    unrouted: tuple[BridgedAction, ...]
    notes: tuple[str, ...]
    escalate: bool

def legacy_incident(data: Mapping[str, Any], *, workflow_id: str, created_at: datetime) -> Incident: ...
    # id -> incident_id, severity upper-cased, observables, title, source, targets -> users/assets;
    # workflow_version "legacy"
def legacy_records(results: Mapping[str, Sequence[Mapping[str, Any]]]) -> tuple[GenericRecord, ...]: ...
    # one GenericRecord per result item: integration LEGACY_RESULT_SOURCES[atomic], atomic "legacy:<atomic>",
    # name "legacy:<atomic>", attributes = the item
def guardrails_to_settings(guardrails: Mapping[str, Any], base: Settings) -> Settings: ...
    # protected.hosts -> critical_assets production_server (hostname patterns, CIDRs); protected.users / groups ->
    # privileged_account; allowlist.* -> allowlists.never_block (approved_rmm -> allowlists.approved_rmm);
    # blast_radius max_hosts_isolated / max_users_disabled / max_indicators_blocked / max_messages_quarantined ->
    # thresholds.blast_radius max_endpoints / max_users / max_indicators / max_messages
def bridge_plan(plan: "xdr_plan.planner.Plan", *, incident: Incident,
                results: Mapping[str, Sequence[Mapping[str, Any]]],
                route: Callable[[ActionType, str], RouteDecision],
                incident_data: Mapping[str, Any] | None = None) -> BridgeResult: ...
    # planned actions -> ProposedAction: evidence = the GenericRecord of Action.source (results key and index), else
    # every legacy record whose attributes mention the target; risk LEGACY_SEVERITY_RISK[severity], confidence
    # LEGACY_CONFIDENCE, rationale "legacy plan rule <id> (replay; scores not computed)"; isolate-endpoint targets
    # (connector GUIDs) map to the item's host name with params["connector_guid"]; skipped_* actions are not proposed

# tools/simulator/legacy_replay.py   (owner: workflow-framework; outside the read zone because it builds a lab runtime)
def replay_legacy_scenario(workflow_id: str, path: Path) -> "LegacyReplay": ...
    # dry run only, on the simulated lab (full SIMULATION_SUITE) with guardrails_to_settings(...): build_plan ->
    # bridge_plan -> PackageBuilder (dry_run=True) -> DryRunSimulator; returns the package, the DRY RUN report and
    # the list of mismatches against the scenario's expect block (empty list = pass): planned actions are in the
    # package, `elevated: true` matches ELEVATED, skipped_* actions are not in the package, `escalate` matches
```

Legacy replay is a migration and regression tool. In production an incident of an unmigrated workflow takes the Phase 0 generic path (14.3.5); `plan_bridge` is never on the production path. It is deleted at the end of Phase 5 with `engine/xdr_plan` (14.4).

#### 14.3.9 Simulator and automatic scenario discovery

- `tools/simulator/workflow_scenario.py`: `WorkflowScenario` (pydantic model of the 14.5.2 format), `load_workflow_scenario(path)`, `discover_workflow_scenarios(root=REPO_ROOT / "tests" / "fixtures" / "workflows") -> dict[str, list[Path]]` (every `<workflow id>/*.yaml`; the directory name must be a catalog id), `WorkflowScenarioRun` (extends `ScenarioRun`: `in_memory_runtime(..., workflows=discover_workflows())`, registers typed records as simulated findings, applies `config` overrides) and `check_coverage(workflow_id, scenarios, definition) -> list[str]` (14.5.3).
- `tools/simulator/simulate.py`: `--workflow <id> [--scenario <name>]`, `--list-workflows`, `--legacy <workflow> [<scenario>]`; dry run by default, `--live` for simulated live, `--check` to assert `expect`.
- `tests/simulation/test_workflow_scenarios.py` parametrizes over `discover_workflow_scenarios()` and runs every scenario in its modes, plus the implicit assertions of 14.5.3; `tests/simulation/test_legacy_replay.py` parametrizes over every remaining `workflows/<id>/scenarios/*.yaml`. Neither file lists workflows or scenarios, so workflow agents never edit them.

### 14.4 Legacy alignment (owner: legacy-alignment)

Phase 1 brings the spec layer (`atomic/`, `workflows/`, `engine/xdr_plan`, `docs/deployment/guardrails.example.yaml`) in line with the lifecycle, so that no legacy file, test or scenario asserts a weaker rule than the runtime enforces.

#### 14.4.1 Conflicts C1 to C5 (section 1.3)

| # | Change | Files | New check (fails `python -m xdr_plan check`) |
|---|---|---|---|
| C1 revoke-session requires approval | `atomic/revoke-session/atomic.yaml` `requires_approval: true` (README text too); every contain-phase step with `requires_approval: false` becomes `true`; every scenario expectation `requires_approval: false` becomes `true`; the planner sets `requires_approval=True` for every atomic whose category is `containment` | `atomic/revoke-session/*`, `workflows/*/workflow.yaml`, `workflows/*/scenarios/*.yaml`, `engine/xdr_plan/planner.py` | any containment atomic, contain-phase step or scenario expectation with `requires_approval: false` |
| C2 `auto_approve` removed | delete the `auto_approve` section from `docs/deployment/guardrails.example.yaml`; delete the planner branch; delete every "eligible for auto-approval" phrase from `workflow.yaml` notes, READMEs and agents; `repo.load_guardrails` raises `ValueError` for any key in `LEGACY_FORBIDDEN_KEYS` at any depth | `docs/deployment/guardrails.example.yaml`, `engine/xdr_plan/{planner,repo}.py`, `engine/README.md`, `workflows/**`, `.claude/agents/wf-*.md` | `LEGACY_FORBIDDEN_KEYS` (in `engine/xdr_plan/guardrails.py`, a test asserts it equals `xdr_response.config.loader.FORBIDDEN_KEYS`) in guardrails, specs or scenarios |
| C3 protected becomes ELEVATED | `host_protected` / `user_protected` return the marker `"elevated:protected"`; the planner keeps such actions with `status="planned"`, `elevated=True`, reason `"protected asset: ELEVATED approval required"`; status `skipped_protected` is removed | `engine/xdr_plan/{guardrails,planner,validate}.py`, scenarios | a scenario expecting `skipped_protected` |
| C4 unlock codes removed | delete every `{plan.unlock_codes}` placeholder and any template text that copies an unlock code; "the unlock code stays in the Secure Endpoint console" wording may stay | `workflows/*/workflow.yaml` (11 files), READMEs | a template containing `unlock_code` |
| C5 over-limit becomes ELEVATED | over a blast-radius cap the planned actions stay `planned` with `elevated=True` and reason `"<cap>: <n> planned > limit <limit>: ELEVATED approval required"`; `escalate` stays `True`; status `skipped_limit` is removed | `engine/xdr_plan/planner.py`, scenarios | a scenario expecting `skipped_limit` |

Planner contract after Phase 1 (`engine/xdr_plan/planner.py`):

```python
@dataclass
class Action:
    rule: str
    atomic: str
    target: str
    status: str                       # planned | skipped_allowlisted | skipped_internal
    requires_approval: bool           # always True for containment atomics
    args: dict[str, Any] = field(default_factory=dict)
    elevated: bool = False            # C3 protected asset or C5 over the cap
    reasons: list[str] = field(default_factory=list)
    source: tuple[str, int] | None = None   # (results key, index) when the for_each item is an element of results[key]
```

Scenario `expect.actions[*]` accepts `elevated` (default `false`, compared strictly) and `requires_approval` (only `true` allowed). The coverage rule "a scenario exercises a guardrail" accepts either a `skipped_*` status or `elevated: true`. `url_check` honours the per-action allow-list: a URL on an allow-listed domain is still planned when the domain is in `allowlist.url_block_allowed_domains` (mirrors `AllowlistPolicy`).

`engine/xdr_plan/expr.py` becomes `from xdr_response.workflows.expr import *` plus `ExprError`, `FUNCTIONS`, `parse`, `evaluate`, `_domain_of` re-exported, once `xdr_response/workflows/expr.py` exists (until then it stays unchanged).

#### 14.4.2 Renames and new directories

Phase 1 (legacy-alignment, one commit): move `workflows/powershell` to `workflows/malicious-powershell` and `workflows/rmm` to `workflows/unauthorized-rmm`; update their `id`, every `related_workflows` and atomic `used_by` reference, `workflows/README.md`, `engine/README.md`, rename `.claude/agents/wf-powershell.md` to `wf-malicious-powershell.md` and `wf-rmm.md` to `wf-unauthorized-rmm.md` (name, description and paths inside), and regenerate `docs/mitre-mapping/` (14.5.5). `repo.workflow_ids()` lists only directories that contain a `workflow.yaml`, so migrated and new workflows drop out of the legacy checks automatically; `tests/test_repo.py` accepts as a valid workflow id any directory under `workflows/` that holds a `README.md`.

The new directories `workflows/mfa-fatigue`, `workflows/suspicious-authentication` and `workflows/threat-intel-sweep` are created by their workflow owners in Phases 2, 4 and 5 (14.5), not in Phase 1.

Phase 1 also rewrites every `.claude/agents/wf-<X>.md` to the Phase 2-5 ownership model of 14.5.1 (owned paths, definition of done = 14.5.4, the non-negotiable rules of this document, no edits to framework or generated files).

#### 14.4.3 Fate of `engine/xdr_plan` and the legacy tests

| When | `engine/xdr_plan` | `tests/test_workflows.py`, `test_repo.py`, `test_engine.py` | Specs |
|---|---|---|---|
| Phase 1 | aligned (14.4.1); `expr.py` becomes a shim | updated for C1-C5 and renames; still run in CI with `python -m xdr_plan check` | all 19 specs replay through `plan_bridge` in dry run (`test_legacy_replay.py`) |
| Phases 2-5 | unchanged; covers only specs not yet migrated | parametrized over the remaining specs, so they shrink as workflows migrate | a migrating workflow deletes its `workflow.yaml` and `scenarios/` in the same commit that adds its definition and its `legacy-*` scenarios |
| End of Phase 5 (when no `workflows/*/workflow.yaml` remains; framework integrator) | deleted with `engine/README.md`; `pyproject.toml` packages and `pythonpath` drop `engine`; CI drops `python -m xdr_plan check` | `test_workflows.py` and `test_engine.py` deleted; `test_repo.py` keeps the YAML-parse and link checks and checks MITRE docs through the generator | `lifecycle/plan_bridge.py`, `tools/simulator/legacy_replay.py`, `test_legacy_replay.py` and `docs/deployment/guardrails.example.yaml` deleted; `atomic/` spec dirs replaced by a README pointing to `xdr_response.atomics` |

Status at the Phase 5 integration: no `workflows/*/workflow.yaml` remains; the end-of-Phase-5 deletions wait for the owner's go-ahead (14.13.1). Status now: the deletions are applied (14.13.8).

### 14.5 Workflow directory conventions (Phases 2 to 5)

#### 14.5.1 Workflows and owned paths

`<X>` is the workflow id (kebab-case), `<x_snake>` is `<X>` with `-` replaced by `_`.

| Phase | Workflow `<X>` | Package `<x_snake>` | Legacy spec (`legacy_id`) | Notes |
|---|---|---|---|---|
| 2 | ransomware | ransomware | ransomware | |
| 2 | phishing | phishing | phishing | |
| 2 | account-takeover | account_takeover | account-takeover | |
| 2 | mail-bombing | mail_bombing | mail-bombing | |
| 2 | malware | malware | malware | |
| 2 | mfa-fatigue | mfa_fatigue | none (new) | seeded from `account-takeover/05-mfa-fatigue-approved` (that scenario migrates here) |
| 2 | password-spray | password_spray | password-spray | |
| 2 | bec | bec | bec | shares email atomics with phishing |
| 3 | malicious-powershell | malicious_powershell | malicious-powershell (renamed in Phase 1) | |
| 3 | credential-dumping | credential_dumping | credential-dumping | |
| 3 | lateral-movement | lateral_movement | lateral-movement | |
| 3 | persistence | persistence | persistence | |
| 3 | unauthorized-rmm | unauthorized_rmm | unauthorized-rmm (renamed in Phase 1) | `allowlists.approved_rmm` |
| 4 | c2 | c2 | c2 | |
| 4 | dns-tunneling | dns_tunneling | dns-tunneling | `allowlists.approved_dns_tools` |
| 4 | exfiltration | exfiltration | exfiltration | |
| 4 | suspicious-authentication | suspicious_authentication | none (new) | |
| 4 | cloud-compromise | cloud_compromise | cloud-compromise | |
| 5 | privilege-escalation | privilege_escalation | privilege-escalation | |
| 5 | threat-intel-sweep | threat_intel_sweep | none (new) | `manual` / `schedule` triggers over indicator lists |
| 5 | vulnerability-exploitation | vulnerability_exploitation | vulnerability-exploitation | add-on, aligned last |
| 5 | web-attacks | web_attacks | web-attacks | add-on, aligned last |

Phase 5 cross-source correlation is a framework change (`correlation-evidence` and `workflow-framework` successors), not a workflow directory.

Each workflow agent owns exactly these paths and nothing else:

| Path | Contents |
|---|---|
| `src/xdr_response/workflows/<x_snake>/__init__.py` | exports `WORKFLOW` and, when hooks exist, `HOOKS` |
| `src/xdr_response/workflows/<x_snake>/definition.py` | `WORKFLOW = WorkflowDefinition(...)` |
| `src/xdr_response/workflows/<x_snake>/hooks.py` (optional) | `class <Name>Hooks(WorkflowHooks)`; `HOOKS = <Name>Hooks()` |
| `workflows/<X>/README.md` | the 17 sections of 14.5.4 |
| `workflows/<X>/xdr/*.json` (optional) | XDR Automation exports from a real tenant only (never hand-written), without secure-string values |
| `workflows/<X>/workflow.yaml`, `workflows/<X>/scenarios/` | legacy spec: deleted by the migration commit |
| `tests/workflows/<x_snake>/test_*.py` | workflow-specific unit tests (rules, hooks) |
| `tests/fixtures/workflows/<X>/*.yaml` | simulation scenarios (14.5.2, 14.5.3) |
| `.claude/agents/wf-<X>.md` | the workflow's agent file |

A workflow agent never edits framework code, atomics, config files, other workflows, `docs/` or the generated files of 14.5.5. A missing atomic, record field, builder or config option is reported as a contract change (14.7.2).

#### 14.5.2 Scenario fixture format

```yaml
schema: 1                                # required
name: tp-approve-all                     # == file stem
workflow: ransomware                     # == parent directory == WORKFLOW.id
description: >-
  True positive on one workstation; analyst approves everything.
tags: [true_positive, approve_all]       # closed vocabulary below
legacy_source: workflows/ransomware/scenarios/01-workstation-encryption.yaml   # legacy-* files only
mode: both                               # dry_run | live | both (default both)
suite: {secure_endpoint: [endpoint], entra: [identity]}   # optional; default SIMULATION_SUITE
config:                                  # optional, lab only, deep-merged over config/*.yaml; forbidden keys refused
  critical_assets: {}
  allowlists: {}
  thresholds: {blast_radius: {max_endpoints: 1}}
incident:                                # Phase 0 Incident fields; workflow_id == workflow; workflow_version omitted
  incident_id: XDR-RW-0001
  title: Ransomware detected on finance workstation
  severity: CRITICAL
  workflow_id: ransomware
  observables: [{type: hostname, value: TH-LT-1047}, {type: sha256, value: <fake 64-hex>}]
  users: [jsmith@example.com]
  trigger: {source: secure_endpoint, mitre_techniques: [T1486]}
environment:
  reputations: []                        # Phase 0 format (13.23)
  records:                               # typed records served by simulated adapters (14.1.4)
    - integration: secure_endpoint       # must be a suite member whose family serves the atomic
      atomic: investigate_endpoint
      subject: TH-LT-1047
      record: {kind: detection, name: Ransomware.Generic, verdict: MALICIOUS, severity: CRITICAL,
               endpoint: TH-LT-1047}     # never record_id / integration / atomic / subject: the normalizer fills them
  preexisting: []                        # Phase 0 format
  faults: []                             # Phase 0 format
  health: {}                             # Phase 0 format
  invalid_targets: []
analyst: {decision: APPROVE_ALL, approvers: [analyst], select: [], comment: ""}
release: {decision: APPROVE_ALL, approvers: [analyst], select: []}      # optional
expect:
  package: true                          # false: nothing proposed (state stays NOT_STARTED)
  actions: ["isolate_endpoint:TH-LT-1047", "block_hash:<fake 64-hex>"]  # exact set in the package
  elevated: []                           # exact set of ELEVATED actions
  excluded: []                           # exact set of allow-listed (excluded_targets) actions
  unrouted: []                           # exact set of UNROUTED outcomes
  below_threshold: []                    # exact set of BELOW_THRESHOLD outcomes
  risk: {min: 80, max: 100}
  confidence: {min: 70, max: 100}
  degraded_sources: []                   # exact set
  considered: []                         # exact set of hook Consideration subjects, not manual (14.10.1)
  manual_steps: []                       # exact set of hook manual-step subjects (14.10.1)
  handoffs: []                           # exact set of "<workflow>:<subject>" hook hand-offs (14.10.1)
  warnings: []                           # substrings that must appear in some CriticalAssetWarning
  evidence_min: 1                        # per action
  dry_run_lines: []                      # exact DRY RUN output (dry_run mode)
  decision_state: null                   # state after the decision when not executed (CLOSED, NOT_STARTED)
  containment: CONTAINED                 # CONTAINED | PARTIALLY_CONTAINED | CONTAINMENT_FAILED
  results: {}                            # {"action_type:target": ActionResultStatus}
  already_contained: []
  controls: 2                            # registry entries after containment
  restoration: null                      # RESTORED | PARTIALLY_RESTORED | RESTORATION_FAILED
  final_state: null
  notifications: []                      # NotificationKind values rendered
```

Tag vocabulary: `true_positive`, `benign`, `approve_all`, `approve_selected`, `reject`, `more_investigation`, `degraded_source`, `critical_asset`, `partial_failure`, `dry_run`, `release`, `edge_case`, `legacy`. All data is fake (section 10 test-data rules: `example.com`, `*.example`, `*.test`, documentation IP ranges, fake 64-hex hashes, hosts like `TH-LT-1047`, users like `jsmith@example.com`).

#### 14.5.3 Minimum scenario set per workflow

| File | Tags | Must assert |
|---|---|---|
| `tp-approve-all.yaml` | true_positive, approve_all | package, exact actions, `containment: CONTAINED`, controls; mode both |
| `tp-approve-selected.yaml` | true_positive, approve_selected | unselected actions `SKIPPED` / `REJECTED_BY_ANALYST` in `results`; only selected ones executed |
| `tp-reject.yaml` | true_positive, reject | `decision_state: CLOSED`, `controls: 0` |
| `benign-no-action.yaml` | benign | `package: false` (or only `below_threshold` entries) |
| `degraded-source.yaml` | degraded_source | a fault or health override on an expected source; `package: true`; `degraded_sources` lists it |
| `critical-asset-elevated.yaml` | critical_asset | `elevated` non-empty, `warnings`; approved by `lead` |
| `partial-failure.yaml` | partial_failure | an injected fault on one approved action; `containment: PARTIALLY_CONTAINED`; that action `FAILED` |
| `dry-run.yaml` | dry_run | `mode: dry_run`; exact `dry_run_lines`; state unchanged |
| `release-restoration.yaml` | release | approve, then release; `restoration: RESTORED` |
| `edge-<slug>.yaml` (at least two) | edge_case | workflow-specific behaviour (examples below) |
| `legacy-<NN>-<slug>.yaml` | legacy | one per legacy scenario of the workflow, converted to typed records, expectations aligned with C1-C5 |

Implicit assertions the framework test makes for every scenario (the scenario cannot switch them off): zero `STATE_CHANGING` operations and zero guard denials before the analyst decision; every proposed action has at least `evidence_min` evidence items and every item's `data["record_id"]` is in the run's `RecordIndex` (`EvidenceBuilder.verify`); risk and confidence are separate integers; every critical-asset target is ELEVATED with a warning, and for `critical_asset` scenarios an `APPROVE_ALL` by `analyst` alone is refused (`ApproverNotAllowedError`); `AI` and `automation` principals cannot approve any package; the audit chain verifies; no rule or hook `ERROR` outcome. `check_coverage` also requires: every tag of the table present, every recommendation rule `PROPOSED` in at least one scenario, at least one `BELOW_THRESHOLD` or `benign` scenario, every legacy scenario of `legacy_id` migrated while the legacy directory still exists.

Edge-case examples (each workflow picks at least two relevant to it): ransomware (domain controller, widespread hash not blocked, backup tool look-alike); phishing (malicious path on an owned domain with `url_block_allowed_domains`, campaign over `max_messages`); account-takeover (IP already blocked: `ALREADY_CONTAINED`, break-glass account); mfa-fatigue (approved after many denials vs denials only); password-spray (internal source IP, one success among many failures); bec (external forwarding rule, look-alike sender domain); mail-bombing (volume over the cap); malware (unknown verdict hash not blocked); malicious-powershell (signed admin script); credential-dumping (domain controller); lateral-movement (admin jump host); persistence (`remove_persistence` unrouted, manual note); unauthorized-rmm (approved RMM excluded); c2 (shared CDN IP); dns-tunneling (approved DNS tool); exfiltration (sanctioned cloud storage); suspicious-authentication (corporate VPN egress); cloud-compromise (OAuth consent by an admin); privilege-escalation (`remove_privileged_role` always ELEVATED); threat-intel-sweep (no hits; hits over the indicator cap); vulnerability-exploitation and web-attacks (allow-listed internal scanner).

#### 14.5.4 README (17 sections) and validator

Every `workflows/<X>/README.md` of a migrated or new workflow starts with `# <WORKFLOW.name>` and has exactly these `##` headings, in this order, each with at least one non-empty line (`###` sub-headings are free). Brief 46 lists 16 items with "required/optional integrations" as one; here they are two sections, so there are 17 headings:

1. Purpose
2. Trigger
3. Required integrations
4. Optional integrations
5. Input data
6. Investigation steps
7. Correlation logic
8. Risk calculation
9. Containment recommendations
10. Approval requirements
11. Containment execution
12. Verification
13. Rollback
14. Failure handling
15. MITRE mapping
16. Testing instructions
17. Known limitations

`tools/validation/check_workflow_readmes.py [--workflow <X>]` (owner workflow-framework) checks every discovered workflow: README present; H1 equals `WORKFLOW.name`; exact H2 list and order; non-empty sections; "Required integrations" and "Optional integrations" name exactly the definition's integrations (backticked); "MITRE mapping" names every tactic, technique and sub-technique id of the definition and no other ATT&CK id; "Approval requirements" states that every action needs human approval and when ELEVATED applies; "Testing instructions" names `tests/fixtures/workflows/<X>/` and `tests/workflows/<x_snake>/`; "Known limitations" has at least as many bullets as `known_limitations`; no `auto_approve`, `unlock_code`, secret-like literal or non-documentation IP address; and `check_coverage` (14.5.3). Exit code 1 with one line per problem. Legacy READMEs of unmigrated workflows are not checked.

A workflow is done when: its definition imports and validates; `check_workflow_readmes.py --workflow <X>` passes; `python -m pytest -q -p no:cacheprovider tests/workflows/<x_snake> tests/simulation/test_workflow_scenarios.py -k "<X> or <x_snake>"` passes (with `-k <X>` alone a kebab-case id deselects the workflow's own unit tests, whose node ids contain `<x_snake>`); the read-zone safety tests pass; `generate_workflow_docs.py --check` reports only the expected regeneration (applied by the phase integrator, 14.5.5).

#### 14.5.5 Generated documentation

`tools/validation/generate_workflow_docs.py [--write | --check]` (owner legacy-alignment) reads the discovered definitions (`discover_workflows()`) and the remaining legacy specs (`xdr_plan.repo`) and writes:

- `docs/mitre-mapping/mitre-mapping.yaml` (`schema_version: 2`): techniques sorted by ATT&CK id, each `{id, name, tactics: [{id, name}], workflows: [ids]}` (legacy specs contribute `tactics: []`);
- `docs/mitre-mapping/README.md`: the same as a table (technique, name, tactics, workflows with links to `workflows/<X>/README.md`);
- `docs/workflows/README.md`: index of all workflows (id, phase, status `migrated` / `legacy spec`, severity, ATT&CK ids, recommended action types, required integrations, scenario count).

Each generated file starts with `<!-- generated by tools/validation/generate_workflow_docs.py; do not edit -->` (YAML: a `#` comment). Output is deterministic. `--check` exits 1 on any difference and runs in CI. Nobody hand-edits these files: during Phases 2-5 workflow agents run `--check` only, and the phase integrator (the framework owner) runs `--write` once per merge batch. `tests/test_repo.py::test_mitre_mapping_in_sync` calls the generator in check mode.

### 14.6 Phase 1 file ownership

Every file created or changed in Phase 1 belongs to exactly one key. Paths are relative to the repository root; `src/` means `src/xdr_response/`. A directory entry covers every file under it. Files not listed are not changed in Phase 1.

| Key | Owns (new unless marked *changed*) |
|---|---|
| **scoring** | `src/models/scoring.py`; `src/scoring/engine.py`, `src/scoring/signals.py`, `src/scoring/verdict.py`; *changed*: `src/scoring/__init__.py`, `src/scoring/README.md`, `src/config/schema.py` (only `ScoringSettings` and the four new settings classes of 14.2.4), `src/models/recommendation.py` (only `risk_band`), `config/thresholds.yaml`, `docs/threat-scoring.md`; tests: `tests/unit/scoring/` |
| **enrichment** | `src/atomics/enrichment/` (`__init__.py`, `models.py`, `atomics.py`, private helpers); tests: `tests/unit/atomics/enrichment/` |
| **investigation** | `src/atomics/records.py`; `src/atomics/investigation/` (`__init__.py`, `atomics.py`, `normalize/__init__.py`, `normalize/{cisco_xdr,secure_endpoint,defender_endpoint,entra,microsoft_cloud,secure_email,intune,splunk,typed}.py`); tests: `tests/unit/atomics/investigation/`, `tests/unit/atomics/records/` |
| **correlation-evidence** | `src/atomics/evidence.py`; `src/atomics/correlation/` (`__init__.py`, `models.py`, `correlate.py`, `blast_radius.py`); tests: `tests/unit/atomics/correlation/`, `tests/unit/atomics/evidence/` |
| **containment-atomics** | `src/atomics/containment/` (`__init__.py`, `models.py`, `routing.py`, `builders.py`); *changed*: `config/integrations.example.yaml` (commented `native_actions` example only); tests: `tests/unit/atomics/containment/` |
| **notifications** | `src/atomics/notifications/` (`__init__.py`, `models.py`, `render.py`, `sinks.py`, `service.py`); tests: `tests/unit/atomics/notifications/` |
| **workflow-framework** | `src/atomics/__init__.py`, `src/atomics/context.py`; `src/workflows/` framework modules (`__init__.py`, `definition.py`, `expr.py`, `hooks.py`, `runner.py`, `discovery.py`); `src/lifecycle/plan_bridge.py`, `src/lifecycle/workflow_adapter.py`, `src/lifecycle/observers.py`; *changed*: `src/lifecycle/runtime.py`, `src/lifecycle/orchestrator.py`, `src/lifecycle/__init__.py`; `tools/simulator/workflow_scenario.py`, `tools/simulator/legacy_replay.py`; *changed*: `tools/simulator/simulate.py`, `tools/simulator/scenario.py`, `tools/simulator/README.md`; `tools/validation/check_workflow_readmes.py`, `tools/validation/validate_config.py`, `tools/validation/check_endpoints.py`, `tools/validation/README.md`; `tools/deployment/xdr-trigger-workflow.md` (the XDR trigger workflow of section 12: new-incident or webhook rule sending only the incident id; JSON exports only from a real tenant); *changed*: `.github/workflows/ci.yml`, `CHANGELOG.md`, `docs/architecture.md` (section 14 "as built" notes and contract changes); tests: `tests/unit/workflows/`, `tests/unit/atomics/test_context.py`, `tests/unit/lifecycle/test_plan_bridge.py`, `tests/unit/lifecycle/test_workflow_adapter.py`, `tests/simulation/test_workflow_scenarios.py`, `tests/simulation/test_legacy_replay.py`, `tests/safety/test_read_zone.py`, `tests/fixtures/sample_workflows/` (a tests-only workflow package and its scenarios, discovered with `discover_workflows("tests.fixtures.sample_workflows")`), `tests/fixtures/workflows/README.md`, `tests/workflows/README.md` |
| **legacy-alignment** | *changed*: `atomic/` (every `atomic.yaml` and README: C1, `used_by` renames), `workflows/` (all 19 legacy dirs, `workflows/README.md`, the two renames of 14.4.2), `engine/xdr_plan/` (`planner.py`, `guardrails.py`, `validate.py`, `repo.py`, `expr.py` shim, `cli.py`), `engine/README.md`, `docs/deployment/guardrails.example.yaml`, `docs/deployment/README.md`, `.claude/agents/` (all `wf-*.md`, two renamed), `docs/mitre-mapping/` (generated), `tests/test_workflows.py`, `tests/test_repo.py`, `tests/test_engine.py`; new: `docs/workflows/README.md` (generated), `tools/validation/generate_workflow_docs.py`; tests: `tests/unit/legacy/` |

Shared-file rule: `src/config/schema.py`, `src/models/recommendation.py`, `config/integrations.example.yaml` and the lifecycle files are Phase 0 files changed by exactly one key each, limited to the parts named. `src/models/__init__.py`, `src/models/enums.py`, `src/models/catalog.py`, `src/errors.py`, the adapters, `pyproject.toml` and the Phase 0 engines are not changed in Phase 1; a key that believes one must change reports it (14.7.2).

Cross-key ordering inside Phase 1 (everything else is parallel after step 0, 14.0.3):

- `legacy-alignment` turns `engine/xdr_plan/expr.py` into the shim only after `src/workflows/expr.py` exists, and runs `generate_workflow_docs.py --write` after the renames.
- `workflow-framework` wires the lifecycle (step 2) after the step 1 keys have landed; `test_legacy_replay.py` needs the planner contract of 14.4.1.

### 14.7 Phase 1 exit criteria and the process for Phases 2 to 5

#### 14.7.1 Phase 1 is done when

1. Every Phase 0 test and the legacy tests (`tests/test_*.py`, as updated by legacy-alignment) pass, with `python -m pytest -q -p no:cacheprovider` on Python 3.12 and 3.13.
2. `PYTHONPATH=engine python -m xdr_plan check` passes with the C1-C5 checks; no file asserts `requires_approval: false`, `auto_approve`, `skipped_protected`, `skipped_limit` or an unlock-code placeholder.
3. All 105 legacy scenarios replay in dry run through `plan_bridge` and the runtime (`tests/simulation/test_legacy_replay.py`) with zero state-changing operations.
4. Unit tests of every key pass, including `docs/threat-scoring.md` section 10, the record-id determinism and refusal tests, evidence-builder refusal of unknown ids, routing native-first and fallback, notification content rules, and the definition validators.
5. `tests/safety/test_read_zone.py` passes; the tests-only sample workflow runs every scenario category of 14.5.3 through the full lifecycle (approve all, approve selected, reject, benign, degraded source, critical asset, partial failure, dry run, release).
6. `generate_workflow_docs.py --check` is clean; `check_workflow_readmes.py` passes (no migrated workflow yet, plus its unit tests); CI runs both, the workflow scenario tests and the legacy replay.
7. The Phase 1 "as built" notes are appended to this section (14.8 onward), and `CHANGELOG.md` has the Phase 1 entry.

#### 14.7.2 Phases 2 to 5

- Each workflow is built by its own agent in its owned paths (14.5.1) and is done per 14.5.4; the phase exit criteria of section 12 apply.
- Contract changes (a new atomic option, record field, record kind, builder, link kind, signal rule, config option or framework hook) are reported by the workflow agent; the framework owner applies them to the owning module and to this section in one commit, with tests, before the workflow depends on them. Adding a record kind is such a change.
- The framework owner integrates each phase: runs the full test suite, regenerates the docs (14.5.5), updates `CHANGELOG.md`, and at the end of Phase 5 performs the retirement of 14.4.3.
- Nothing in Phases 2 to 5 may weaken a rule of sections 5 to 8, 13 or 14: workflows only investigate and recommend; approval stays human; containment executes only after approval; verification is automatic; release needs its own human approval.

### 14.8 As built: workflow framework (Phase 1, step 1 and lifecycle wiring)

Written by `workflow-framework` on 2026-10-08. Binding additions to 14.1.1, 14.1.9 and 14.3; everything else in 14.3 is implemented as written.

Additions (public, owned by workflow-framework):

- `workflows.definition`: `WorkflowDefinition.attack_ids()`, `.integrations()`, `.expected_sources()`, `.matches(incident) -> TriggerSpec | None`, `.package_name`; `InvestigationStep.subject_types()`. Extra validators: an automatic (`xdr_incident_rule` / `webhook`) trigger needs at least one criterion (an empty trigger would match every incident); an `enrich_*` step takes no `integrations` or `options` (enrichment asks every enricher under the disclosure policy); rule `params` keys are refused when reserved, approval-like or secret-like (`Redactor.is_sensitive_key`). A reported sub-technique (`T1204.002`) matches a trigger that lists its parent technique. The read-atomic subject types, builder action types and reserved param keys are mirrored as private constants (layer 0 may not import the atomics); `tests/unit/workflows/test_definition.py` asserts the mirrors equal `atomic_subject_types()`, `containment_builders()` and `RESERVED_PARAM_KEYS`.
- `workflows.expr`: dict literals with string keys (needed by a rule's `asset` expression) and `names_used(src)`. Dispatch goes through a fixed table (no `getattr`), so the module passes the read-zone lint; helper failures (including `ZeroDivisionError`) are wrapped in `ExprError` with the expression.
- `workflows.discovery`: `DEFAULT_PACKAGE`, `not_migrated(workflow_id, catalog)`. Discovery re-validates every `WORKFLOW` (`model_validate(model_dump())`), so a definition built with `model_construct` cannot skip a validator. `discovery.py` is the one documented read-zone exception to the "no `importlib`" rule (importing the packages it finds is its job). `resolve()` returns `None` for an incident whose `workflow_id` is a legacy spec id (14.5.1) without a definition, before triggers are tried.
- `workflows.runner`: `RuleOutcome.selector` (`"<action_type>:<target>"`), `WorkflowRun.outcomes_with(status)` and `.degraded_sources()`. Rule scoring never counts a record twice (target enrichment records already cited by the rule are not added again). The run notes critical-asset warnings and allow-list exclusions of built recommendations; a correlation failure caused by hook links is retried without them, then falls back to an empty `CorrelationResult`.
- `lifecycle.workflow_adapter`: `WorkflowInvestigationReport.notes` (routing notes such as `"workflow <id> not migrated yet: Phase 0 generic investigation used"`, prepended to the fallback recommendation's notes). A `WorkflowRunner` exception (a framework bug) falls back to the generic path with a redacted note instead of failing the detection.
- `lifecycle.observers.notify_observers(observers, event)`. Events: `PACKAGE_PROPOSED` / `DETECTION_COMPLETED` (with `run.summary()` when a workflow ran), `DECISION_RECORDED` for every containment or release decision, `CONTAINMENT_COMPLETED` / `RESTORATION_COMPLETED` only for live (non dry-run) reports, `RELEASE_PROPOSED`, `INCIDENT_CLOSED`. Without observers the orchestrator imports nothing new (Phase 0 behaviour unchanged).
- `lifecycle.runtime`: `DEFAULT_NOTIFICATIONS_PATH`, `NOTIFICATIONS_PATH_ENV`; `build_runtime` refuses an observer without `on_event`.
- `tools/simulator`: `ScenarioRun(..., workflows=None, observers=())`; `WorkflowScenarioRun(scenario, *, live=False, catalog=None, clock=None)` with `.play()`, `.check()`, `.implicit_problems()`, `.workflow_run` and an in-memory notification outbox; `check_coverage(..., proposed_rules=None, legacy_root=...)` (static check by expected action types when no runs are given). In scenario `expect`, an omitted key is not asserted; a given set is compared exactly. A `dry_run`-tagged scenario must use `mode: dry_run`; `legacy` tag and `legacy_source` go together; scenario `config` may override only `critical_assets`, `allowlists`, `thresholds`, `exclusions`.
- Read-zone lint (`tests/safety/test_read_zone.py`): imports inside `if TYPE_CHECKING:` are type-only and exempt; `xdr_response.audit` is forbidden except in `lifecycle/workflow_adapter.py`; `xdr_response.integrations.{registry,simulated}` only in `atomics/context.py`; `.execute()` and methods named after state-changing action types may be called only in `atomics/containment/builders.py`. The tests-only sample workflow packages are linted too.

Built at the Phase 1 integration step (14.9): `lifecycle/plan_bridge.py`, `tools/simulator/legacy_replay.py`, `simulate.py --legacy`, `tests/unit/lifecycle/test_plan_bridge.py`, `tests/simulation/test_legacy_replay.py` and `tools/deployment/xdr-trigger-workflow.md`.

### 14.9 As built: Phase 1 integration (contract amendments and decisions)

Written at the Phase 1 integration step (step 2 of 14.0.3) on 2026-10-08. It is binding. Where it differs from 14.0 to 14.8, it wins, and the signatures above are already updated (`aggregate_verdict`, `RECORD_CONFIDENCE`, `correlate`, `InvestigationBundle`, `bridge_plan`).

#### 14.9.1 Lifecycle, legacy replay and simulator

- **`lifecycle/plan_bridge.py`** (read zone, linted):
  - **Names.** Besides the contract names it has `LEGACY_RESULT_SUBJECTS` (the result item field that names a record's subject: `ip`, `domain`, `sha256`, `host` (or `hostname`), `user`), `LEGACY_VERSION = "legacy"`, `LEGACY_INCIDENT_ATOMIC = "legacy:incident"`, `LEGACY_PROTECTED_HOST_TAG` and `LEGACY_PROTECTED_USER_TAG`, `legacy_incident_record(data)`, and `BridgeResult.risk_score` / `.confidence_score` (max over proposals).
  - **Incident.** `legacy_incident` keeps the legacy context, targets and unmapped observable types (for example `email_subject`) in `incident.trigger`. These are data, never evidence on their own.
  - **Evidence.** It comes from, in order: the `Action.source` item's record; else every legacy record whose item has a string equal (case-insensitive) to the target; else the legacy **incident record** (integration `cisco_xdr`, attributes title, severity, source, observables, targets, context) when the incident mentions the target. Seven of the 294 planned legacy actions need the incident record: reported senders and alerted URLs. A planned action that nothing mentions is **not proposed**. It is reported in `unrouted` with "no evidence", never with invented evidence.
  - **Asset context.** An investigated legacy item with `is_protected: true` gives the proposal an asset tag (`legacy-protected-host` / `legacy-protected-user`). User items also contribute `profile.groups`. A host whose name is an IP gives `asset.ip`. `guardrails_to_settings` adds these tags to the `production_server` / `privileged_account` matches, so **PackageBuilder** decides ELEVATED. The legacy `elevated` flag is reported in `BridgedAction.elevated` and is never copied into a proposal as an approval level. When the legacy planner elevated an action for a **protected asset** (`PROTECTED_REASON` in `Action.reasons`, or an elevation with no reason at all), the proposal asset also gets the protected tag of its kind (isolation: host tag; disable / revoke: user tag). A host protected by connector GUID or IP glob, a user protected by `upn` / `email`, or a protected item that is not the plan source therefore never comes out weaker than the legacy verdict (14.9.6). An elevation explained only by blast-radius caps (C5) adds no tag.
  - **Guardrails.** `guardrails_to_settings` **replaces** the base critical assets and allow-lists, so a replay is judged by the scenario's own guardrails. Host patterns that are CIDRs become `ip_cidrs`. `approved_rmm` names become `{name}` entries.
- **`tools/simulator/legacy_replay.py`.** It provides `legacy_scenarios()`, `LegacyPlanRecommender` (bound to the runtime after build; it routes with `choose_route` over `build_context`), `LegacyReplay` (`package`, `ok`, `dry_run_text()`, `mismatches`) and `replay_legacy_scenario(workflow_id, path)`. The replay runs the Phase 0 runtime (`ScenarioRun(..., recommender=...)`, full `SIMULATION_SUITE`, global dry run ON). The detection uses the real `InvestigationService` (reads only), then `PackageBuilder`, then the DRY RUN simulation. A mismatch is any of the following:
  - a planned action missing from the package;
  - a skipped action present in the package;
  - an unexpected package action;
  - `elevated` ≠ ELEVATED;
  - ELEVATED without a warning;
  - the legacy `escalate` ≠ the expected value, or ≠ "a blast-radius warning is in the package";
  - a legacy action without `requires_approval`;
  - evidence that does not verify against the legacy records;
  - any state-changing call, guard denial or registered control;
  - a package not marked `dry_run`;
  - a DRY RUN report that does not cover every action.

  **The runtime may be stricter, never weaker.** The legacy `max_users_disabled` cap counts `disable-user` only, while `blast_radius.max_users` counts every user an action touches (`revoke_sessions` too). So when the legacy plan escalates, an action expected STANDARD may be ELEVATED, but only through blast-radius warnings. This affects 4 scenarios.
- **Result.** All 105 legacy scenarios replay with zero mismatches (`tests/simulation/test_legacy_replay.py`). The same file asserts that every scenario file is replayed and that no scenario asserts `requires_approval` other than `true`.
- **`simulate.py --legacy <workflow> [<scenario>]`** prints the bridged actions, the decision card and the DRY RUN block; `--check` lists the mismatches. The execution guard allows **one runtime per process** (its verifier slot is sealed), so `--workflow <id>` without `--scenario` and `--legacy <workflow>` without a scenario now run each scenario in a child process. Before this change, the second scenario was refused with `ApprovalRequiredError`.
- **Runner fixes.**
  - `WorkflowRunner` runs each read call at most once per run. The key is atomic + subject, plus options, sources and lookback for investigation. With a real clock, a second fetch would collide with the first record id.
  - `WorkflowRun.health` is the worst health over sources that were actually **called**. A source withheld by the disclosure policy or not enabled (`NOT_QUERIED`, health `UNKNOWN`) no longer hides a real `CONNECTED` answer. An integration seen only that way is reported `UNKNOWN`. `degraded_sources()` already counted only `FAILED`.
- **CI** additionally runs the legacy replay of every workflow and the sample workflow scenarios. `xdr_plan check` runs with `PYTHONPATH=engine:src`.
- **`tools/deployment/xdr-trigger-workflow.md`** describes the trigger (incident or webhook rule; payload `{"incident_id"}` only; the incident is re-read through the VERIFIED APIs). No export is committed: an export is accepted only from a real tenant. The repository ships no HTTP listener. A deployment's intake calls `handle_detection` after the re-read.
- **End-to-end integration tests.** `tests/integration/test_atomics_scoring_evidence.py` runs the real Umbrella, VirusTotal and Entra adapters over fake vendor APIs:
  - enrichment, scoring and evidence citation, with fabricated ids refused;
  - a failed source that degrades without blocking;
  - correlation and blast radius;
  - a builder followed by `PackageBuilder`;
  - typed investigation records, scoring signals and a critical asset that stays ELEVATED whatever the score;
  - a tests-only workflow through the production lifecycle: zero writes before the decision, AI and automation refused, then analyst approval, execution, verification and a separately approved release;
  - dry run scoring like live, and the Phase 0 path for unmatched incidents.

#### 14.9.2 Amendments by key (from the component reports)

**scoring**
- `aggregate_verdict(..., bands=None)` means the built-in HIGH bound 60.
- `RECORD_CONFIDENCE["user_profile"] = 70` is now a public table entry, no longer a private constant.
- `signals.py` dispatches on `str(record.kind)` and imports the record models only for typing.
- Interpretations confirmed:
  - (a) the critical-asset bonus applies only with at least one MALICIOUS or SUSPICIOUS signal;
  - (b) when `expected_sources` is empty, every failed source with health UNAVAILABLE, AUTH_FAILED or RATE_LIMITED is penalised;
  - (c) for reputation-only evidence, the independent-source bonus never lifts confidence above `reputation_only_confidence_cap`;
  - (d) the reputation risk cap does not cap the critical-asset bonus;
  - (e) `settings_hash` is computed over the settings with workflow overrides merged in;
  - (f) half-up rounding uses `round(x, 9)` before `floor(x + 0.5)`.
- Extra validators: `ScoringSignal.integration` must be in `INTEGRATION_NAMES`, `record_ids` must be non-empty and non-blank, and `origin` must be `framework` or `workflow:<id>`. `ScoringContext` sorts and deduplicates its tuples.
- `config/thresholds.yaml` spells out the defaults, so its `settings_hash` differs from `ScoringSettings()` while scoring identically.

**enrichment**
- `_sources.py` imports `integrations.health.classify_exception`, which is allowed. The lint forbids only vendor modules, `integrations.{http,auth,registry,simulated}` and `httpx`.
- A source withheld by `ctx.disclosure` is `NOT_QUERIED` with health `UNKNOWN`. Health aggregation ignores it (14.9.1).
- **Decision:** when `ctx.disclosure` allows an observable but the adapter's own built-in policy refuses it (`NOT_SUPPORTED` error, verdict UNKNOWN), the source is `FAILED`. Nothing is sent either way; production builds both policies from `settings.exclusions`, and the conservative mapping costs confidence.
- `ObservableReport.subject` drops `Observable.source`.
- The runner de-duplicates enrichment per subject (14.9.1).

**investigation**
- `InvestigationBundle.critical_asset_classes` (signature above).
- `RecordBase.record_id` may be omitted when building a record. A before-validator computes `make_record_id(...)`, and a supplied id is still checked and refused on mismatch.
- Typed simulated findings use `{"xdr_record": {"kind": ..., <fields>}, "xdr_integration": "<adapter>"}` (preferred) or the flat `{"xdr_record": true, "kind": ...}`. A body carrying `record_id`, `integration`, `atomic` or `subject` is refused. A malformed typed record fails only its own source (FAILED, INTERNAL).
- Rule items are chosen by `action_type`, so legacy-replay bundles (`legacy:<id>`, INVESTIGATION type) get the family keys of 14.1.4.
- Reported sources: the catalog integrations for the type plus the enabled investigators. Disabled ones are `NOT_QUERIED` ("not enabled"). Enabled ones that do not serve the type are `NOT_SUPPORTED`, and no health check is made for them.
- Confirmed interpretations: `mfa_denied_count` counts `denied` + `fraud_reported`; `distinct_ips` / `distinct_countries` count over sign-ins and MFA events; the hash item's verdict is the worst reported, or `None` without records; an alerts_v2 alert without a classification is SUSPICIOUS; severity `unknown` maps to INFO; MDE riskScore `Informational` maps to level `low`.

**correlation-evidence**
- The `correlate` signature is updated above. `CorrelationLink` computes `link_id` when it is omitted (a supplied id must match). Entities and record ids are sorted and deduplicated. Kind `WORKFLOW` is required exactly when the origin is `workflow:<id>`.
- `CorrelationResult` checks that the clusters partition the entities. Entities named only by a link are added to `entities`.
- New public names: `FRAMEWORK_ORIGIN`, `BLAST_RADIUS_CAP_NAMES`, `EntityRef.sort_key()`, `EntityRef.key()`, `CorrelationLink.rule_item()`, `CorrelationResult.cluster_of()`, `DEFAULT_WINDOW`, `FRAMEWORK_LINK_KINDS`, `SUMMARY_MAX_CHARS`, `RecordIndex.records()`, `EvidenceBuilder.index`. `BlastRadiusReport.rule_item()` adds `endpoint_count`, `user_count`, `indicator_count`, `critical_asset_classes` and `has_critical_asset`.
- Confirmed interpretations:
  - **Entity mentions.** Asset attributes are not entities (endpoint IPs and MACs, DNS `client_ip`, `local_ip`, `response_ips`, `sender_domain`, mailbox-rule `created_by`). Recipients are USER entities; senders and forward addresses are EMAIL_ADDRESS. Enrichment and generic records mention only their subject.
  - **Blast-radius default scope.** The incident clusters plus the incident entities, widened by one hop (endpoints and users of in-scope records; recipients, URLs, domains and hashes of in-scope messages). Hits are always reported and `exceeds` is informational.
  - **email_to_click.** The click domain must equal, or be a subdomain of, a domain the message carries. The click comes from a recipient user, or from an endpoint a record names together with a recipient, within `received_at` (or `observed_at`) plus the window.
  - **process_lineage.** `parent_pid` matches before `parent_sha256`.
- `evidence_draft` stores `data["fields"]` as canonical JSON. `verify()` also accepts numbered package `Evidence`, and `cite()` refuses a bare string. Evidence summaries start with the integration name (they stand alone in notifications), so the decision card shows `source: source: ...`; this is cosmetic and was kept.
- `correlation/__init__.py` imports its modules directly (no lazy loading in the read zone). Importing `atomics.correlation.models` therefore also loads `correlate`, `evidence` and `records`; this is acceptable at layer 0 because there is no cycle.

**containment-atomics**
- Read-only `BuiltRecommendation` properties: `routed`, `reversible`, `rollback_action_type` and `elevation_expected` (a preview only).
- Extra `ValueError`s:
  - evidence drafts must carry `data["record_id"]` (`rec_` + 32 hex), so they must come from the evidence builder;
  - scores must be ints in 0..100;
  - `rationale` must be non-empty and is redacted;
  - `delete_email.delete_action` must be `softDelete` or `moveToDeletedItems`;
  - target normalization is stricter (hex hashes; `FILE`/`PROCESS` as `<ENDPOINT>/<id>`; composites need both parts).
- `NATIVE_OBSERVABLE_TYPES` holds one CTIM type per target kind. IPv6 and sha1/md5 targets are chosen by value.
- A non-`lock` `intune_device_action` raises an error that is both `ValueError` and `UnverifiedEndpointError`.
- **Decision (limitation carried to Phase 2):** with `product=None`, a tenant whose only enabled executor is `cisco_xdr` has no landing product. The action is then **unrouted and reported** ("no product to land a native <action> on"), never dropped. Such tenants need product-pinned builders, which is a Phase 2 contract change if a workflow needs it.

**notifications**
- The `ref` in `notification_id` is the first of `report:<report_id>`, `decision:<decision_id>`, `package:<package_id>` and `at:<format_datetime(event.at)>`.
- A draft is dry run when `event.dry_run`, `package.dry_run` or `report.dry_run` is set.
- Draft validators: the id is 32 hex; the title is one line of at most 200 chars; the body is at most 16 KiB; the audience matches the kind; `contains_ai_text` is set exactly when the body has the AI narrative heading, and only for analyst summaries. `LifecycleEvent` refuses a package, decision or report of another incident. The orchestrator builds events that satisfy these checks (lifecycle tests).
- The `NotificationService` constructor may raise for invalid sinks or routing, while `on_event` never raises. Sinks do not deduplicate, so consumers deduplicate by `notification_id`.

**workflow-framework**
- The as-built notes are in 14.8. The fallback copies of `SignalCategory` / `LinkKind` in `workflows/definition.py` are removed: it imports the step 0 models.
- Event semantics are confirmed: in dry run only `PACKAGE_PROPOSED` / `DETECTION_COMPLETED` and `DECISION_RECORDED` are emitted, with `dry_run=True`.

**legacy-alignment**
- The C1 to C5 planner contract is in place.
- Rollback templates, READMEs and atomic specs no longer say blocks "auto-expire". `expires_hours` is a release-review reminder, and removal needs a separate human release approval (1.2).
- The legacy approval-template placeholder `{plan.elevated}` is not rendered by the runtime: the decision card and notifications show ELEVATED with its warnings. `BridgedAction.elevated` carries the legacy flag for any future renderer.
- Behaviour notes:
  - elevated actions count towards the legacy caps;
  - credential-dumping plans no account action when a protected DC is confirmed, and that DC's isolation stays planned and ELEVATED (kept for the Phase 3 owner to review);
  - every workflow directory with a README needs an agent file `wf-<id>.md` (`test_one_agent_per_workflow`).
- Phase 0 test fixtures now use the workflow id `malicious-powershell` instead of the old `powershell`.
- `docs/deployment.md`, `README.md` and `docs/testing.md` no longer describe `auto_approve` or the spec conflicts as pending.

#### 14.9.3 Phase 0 changes made at integration (14.7.2)

- `logs/redaction.py`: the `key=value` rule accepts a command-line flag prefix (`-key=value`, `--key=value`). Command lines in process and persistence records therefore no longer keep `--password=...`-style values. Hyphenated ordinary keys (`--control-key=...`) are unchanged. Tests are in `tests/unit/core/test_secrets_redaction.py`. Space-separated flags (`--password value`) are not recognised; normalizers must not rely on the redactor for them.
- `tests/conftest.py` gives every test a fresh process-wide redactor. Secrets one test registers no longer redact another test's text, which had made exact-text assertions order-dependent.
- `tools/simulator/scenario.py`: `ScenarioRun(..., recommender=None)` (legacy replay).

#### 14.9.4 Known limitations carried into Phase 2

- **Field schemas not documented.** docs/integrations.md does not document field schemas for Secure Endpoint trajectory events, Secure Email message search, Cisco XDR sightings, Splunk rows or `runHuntingQuery` rows. Those findings stay `GenericRecord`s: citable, never scored. A workflow that needs them first adds the verified schema and a typed mapping (a contract change, 14.7.2).
- **Python 3.12.** Only Python 3.13 was available locally. Every source file parses with the 3.12 grammar, and CI runs the 3.12 / 3.13 matrix.

#### 14.9.6 Safety hardening, Phase 1 round 1 (binding)

Fixes for the defects proven by `tests/safety/test_phase1_atomics.py` and `tests/safety/test_phase1_evidence.py`. They only add protection; no approval path changed.

- **Critical assets: IP-named endpoints.** `CriticalAssetPolicy` matches an `ENDPOINT` target (and the endpoint part of a `FILE` / `PROCESS` / `PERSISTENCE_ITEM` composite, and an `ENDPOINT` asset name) both as a host name and, when it parses as an IP address, against the class `ip_cidrs`. `isolate_*_endpoint("203.0.113.10")` or `quarantine_file("203.0.113.10/<sha256>")` inside a critical CIDR is ELEVATED with a warning in the builder preview and in `PackageBuilder`.
- **Runner duplicate merge.** When a second rule proposes the same `(action_type, target)`, `WorkflowRunner._merge` unions the proposal asset contexts (groups, tags, roles; the first IP wins, as in `PackageBuilder`) and the critical-asset warnings, besides merging evidence and keeping the higher risk. A duplicate rule that saw a critical asset therefore keeps the package ELEVATED.
- **Approval markers in params.** `containment.builders.APPROVAL_MARKER_KEYS` (equal to the workflow definition's `APPROVAL_LIKE_KEYS`: `FORBIDDEN_KEYS` plus `approval_level`, `requires_approval`, `approve`, `approved`) is refused at **every depth** of builder params (`ValueError`); `RESERVED_PARAM_KEYS` includes it at the top level. A rule param expression that yields such a key is a rule ERROR, never a proposal.
- **Hook signal attribution.** A hook signal is kept only when `signal.integration` is the integration of at least one record it cites; otherwise it is dropped and noted ("attributed to X but cites only records of Y"). A hook can no longer attribute evidence to sources that never answered, nor inflate the independent-source bonus. A hook signal citing only enrichment records is marked `vendor_verdict=True`.
- **Vendor verdicts.** Enrichment answers are vendor verdicts (`ScoringSignal.vendor_verdict`, 14.2.1 and 14.2.3): one vendor's MALICIOUS enrichment is never an aggregate MALICIOUS verdict and never CRITICAL on its own (14.2.2).
- **No self-corroboration, single-source cap, one penalty per failed source** (14.2.2 risk and confidence precisions; threat-scoring 5.1, 5.2 and 5.4). The runner passes the worst health per failed integration in `ScoringContext.failed_sources`.
- **Disclosure policy (Phase 0 `config/policy.py`, section 13).** HIBP never receives an address of an internal domain (`internal_domains`, `third_party_lookup.internal_domain_suffixes`, the built-in suffixes, single-label domains), in addition to `user_domains`. A URL with userinfo (`user:pass@`) or a sensitive query key (`sig`, `token`, `access_token` and the rest of `SENSITIVE_KEY_PATTERN`) is never disclosed to a third party. An IPv6 address that embeds an IPv4 address (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4, Teredo) is judged by the embedded address too.
- **Evidence data.** `RecordBase.evidence_fields()` (copied into `EvidenceDraft.data["fields"]`) redacts every string on the way out: URLs by `Redactor.redact_url` (userinfo removed, sensitive query values replaced), other strings by `redact_text`, sensitive mapping keys masked. Records keep their own values, so rule targets are unchanged.
- **Same fact from two atomics.** `RecordIndex` treats two records with the same id whose content differs only by `atomic` as one fact (the first copy is kept). The runner no longer drops the second atomic's whole result, including evidence only it held. Any other content difference is still refused.
- **Unlock codes in prose (Phase 0 `logs/redaction.py`).** `redact_text` also redacts an unlock code or passcode phrased in prose (`isolation unlock code: X`, `unlock code X`, `unlock code is X`, `Device passcode: X`) when the value looks like a code (it has a digit, or is all upper case). `passcode` / `pass_code` are sensitive keys. Notifications, notes and summaries therefore never carry them (14.1.8).

#### 14.9.7 Safety hardening, Phase 1 round 2 (binding)

Fixes for the round 2 defects proven by `tests/safety/test_phase1_atomics.py` and `tests/safety/test_phase1_evidence.py`. They only add protection; no approval path changed.

- **Runner duplicate merge, unrouted side.** The runner keeps, per `(action_type, target)`, the union of the asset contexts and the cited record ids of every rule that recommended it, routed or not. A routed proposal always carries that union (groups, tags, roles; the first IP wins) and the unioned critical-asset warnings, so an unrouted duplicate that saw the investigated critical asset (for example a rule pinned to a product that is not enabled) still makes the packaged action ELEVATED. Only a routed duplicate can raise the kept risk.
- **An unrouted rule never suppresses a routable duplicate.** When the first entry for a key is unrouted and a later rule routes the same action, the routed proposal replaces the unrouted entry (evidence, asset context and warnings unioned) and that rule's outcome is `PROPOSED`; the first rule's `UNROUTED` outcome and note stay visible. A missing product never blocks a recommendation another route can execute.
- **Critical assets: IPv6 forms of an IPv4 address.** `CriticalAssetPolicy` matches an IPv6 target or asset IP by the IPv4 address it embeds too (IPv4-mapped, IPv4-translated `::ffff:0:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4, Teredo; `config.policy.embedded_ipv4`, shared with the disclosure policy). `block_ip("::ffff:203.0.113.10")` is ELEVATED like `block_ip("203.0.113.10")`.
- **Critical assets: directory roles.** `AssetMatch.roles` (case-insensitive) is evaluated against `Asset.roles`. `config/critical-assets.yaml` lists the `PRIVILEGED_ROLE_NAMES` roles under `privileged_account`, so `disable_entra_user` / `revoke_entra_sessions` on a Global Administrator or Privileged Role Administrator is ELEVATED with a warning whatever the UPN or groups, and the 13.25 role union in `PackageBuilder` now has effect.
- **Incident asset lookup by IP.** The builder preview and `PackageBuilder._incident_asset` (also used by `policy_violations`) find the incident's asset record by name or, for an endpoint named by an IP address, by the asset's `ip` (`approval.critical_assets.find_incident_asset`; several matches are unioned).
- **Notification bodies keep the ELEVATED warning and the DRY RUN notice.** The header shows at most 300 characters of the incident title. When a body exceeds 16 KiB, the DRY RUN notice and the ELEVATED section are budgeted first and never truncated; the other sections share the rest in order (the overflowing one is cut and marked `[truncated]`).
- **Hook signals: vendor verdict by attribution.** A hook signal is marked `vendor_verdict=True` when every cited record **of its own integration** is an enrichment record. Citing another source's context record beside a vendor's answer no longer turns that answer into a behavioural detection.
- **Single-source cap: only weighty sources count.** The cap of 14.2.2 applies when only one integration carries weight; a second integration counts only when one of its supporting signals is weighted at least `corroboration.min`.
- **Disclosure policy (Phase 0 `config/policy.py`).** Fragment parameters are checked like query parameters (`#access_token=...`). `X-Amz-Signature`, `X-Goog-Signature` (suffix `signature`) and `X-Amz-Credential` / `X-Goog-Credential` (`x-<vendor>-credential(s)`) are sensitive keys of `SENSITIVE_KEY_PATTERN`. A URL with an email address in its path, query or fragment is never disclosed. A host or domain whose last label is numeric or `0x` hex is an IPv4 literal in any spelling (trailing dot, short form `10.0.258`, hex, octal, `127.1`) and is judged by the address it denotes (`host_ip`, `parse_ipv4_literal`); one no parser accepts is refused, and the enrichment `DOMAIN` normalizer refuses such names. IPv4-compatible and IPv4-translated IPv6 forms are judged by the embedded address, and site-local `fec0::/10` is never public.
- **Redaction (Phase 0 `logs/redaction.py`).** `redact_url` redacts sensitive fragment parameters too. `redact_text` also redacts an unlock code or passcode with words between the label and the value when an explicit separator (`:`, `=`, `is`) precedes it, on one line within 80 characters: `unlock code for TH-LT-1047 is X`, `unlock code (TH-LT-1047): X`, `the code to unlock TH-LT-1047 is X`.
- **Evidence verified at the lifecycle boundary.** `WorkflowRecommender.recommend` verifies every proposal's evidence against the run's `RecordIndex` (`EvidenceBuilder.verify`). A proposal whose evidence cites a record the run never produced, or differs from it, is not forwarded to `PackageBuilder`; the refusal is a recommendation note.

#### 14.9.5 Exit criteria (14.7.1)

1. The whole suite passes with `python -m pytest -q -p no:cacheprovider` (3.13 locally; CI runs 3.12 and 3.13).
2. `PYTHONPATH=engine python -m xdr_plan check` passes with C1 to C5. No scenario asserts `requires_approval: false` (test).
3. All 105 legacy scenarios replay in dry run through `plan_bridge` and the runtime with zero state-changing operations (`tests/simulation/test_legacy_replay.py`).
4. The unit tests of every key pass.
5. `tests/safety/test_read_zone.py` passes (it covers `plan_bridge.py`). The sample workflow runs every 14.5.3 category through the lifecycle.
6. `generate_workflow_docs.py --check` and `check_workflow_readmes.py` are clean, and CI runs them together with the workflow scenarios and the legacy replay.
7. The as-built notes are 14.8 and 14.9, and `CHANGELOG.md` has the Phase 1 entry.

### 14.10 As built: Phase 2 integration (contract amendments and decisions)

Written at the Phase 2 integration step on 2026-10-08 by the framework owner (14.7.2). It is binding. Where it differs from 14.0 to 14.9, it wins; the signatures above are already updated. Phase 2 migrated eight workflows: ransomware, phishing, account-takeover, mail-bombing, malware, mfa-fatigue (new), password-spray and bec. Each deleted its legacy `workflow.yaml` and `scenarios/` and carries its legacy scenarios as `legacy-*` fixtures (account-takeover 05 migrated to mfa-fatigue).

#### 14.10.1 Hooks: considered items, manual steps and hand-offs

Five workflow agents asked for the same contract change: a rule whose `when` is false leaves no outcome, so a deliberately withheld action, a manual step or a hand-off was visible only in facts or rationale text. The framework now carries them.

- **`Consideration(subject, reason, record_ids, manual=False)`** (`workflows.hooks`). `WorkflowHooks.considered(view)` returns items the workflow examined and deliberately did **not** recommend (a widespread payload hash, a shared sign-in IP, a host whose policy forbids isolation, a buried message kept in the mailbox) or, with `manual=True`, a **manual step** that has no VERIFIED write (removing a mailbox rule, revoking an OAuth consent). `subject` is `"<action_type>:<target>"` for a withheld action and a short name otherwise.
- **`Handoff(workflow_id, subjects, reason, record_ids)`**. `WorkflowHooks.handoffs(view)` suggests running another workflow for subjects this run found. `workflow_id` must be in the definition's new `handoff_to` field (a subset of `related_workflows`).
- **Runner validation.** Both are called with the final view, after `facts`. An item is kept only when it is the right type, has a non-empty subject (subjects) and reason, and cites at least one record id of the run (`RecordIndex.require`); a hand-off to a workflow outside `handoff_to` is refused. Anything else, and any exception, is noted and ignored (never blocks the run, never changes a recommendation). Text is one line, redacted and capped (subject 200, reason 500 characters, at most 50 items per method). The same subject twice (considerations) or the same workflow twice (hand-offs) is merged: first reason, records and subjects unioned.
- **Where they appear.** `WorkflowRun.considered` / `.handoffs`; run notes (`considered, not proposed: ...`, `manual step: ...`, `hand-off: run <workflow> for <subjects>: <reason> (suggestion only; nothing is started)`), and so `DetectionResult.notes`; `WorkflowSummary.considered`, `.manual_steps`, `.handoffs` (`"<subject>: <reason> [<record ids>]"`), rendered in the analyst summary and incident note under "Considered, deliberately not proposed", "Manual steps (no verified automated action; not in the package)" and "Suggested hand-offs to other workflows (nothing is started)". The decision card (built from the package only) is unchanged.
- **Scenarios.** `expect.considered`, `expect.manual_steps` (subjects) and `expect.handoffs` (`"<workflow>:<subject>"`) are exact sets when given (14.5.2).
- A hand-off never starts a workflow, never creates a package and never touches approval. It is a note backed by records; the analyst decides.

#### 14.10.2 Cross-workflow conventions (routing and hand-offs)

- **Routing between overlapping triggers** is decided by trigger priority (14.3.5) and pinned by `tests/unit/workflows/test_cross_workflow.py`: the entry-vector workflow handles the incident and account-takeover is reached by hand-off. ransomware (200) wins over malware (100); phishing (110), password-spray (110) and mfa-fatigue (200) win over account-takeover (100); mail-bombing (detector webhook 200, T1667 150) wins over bec (110); an incident reporting only T1656, T1534 or T1114.003 routes to bec; T1621 routes to mfa-fatigue (priority 200; account-takeover's triggers do not list it).
- **Hand-off convention.** Every entry-vector workflow that concludes an account is compromised hands off to `account-takeover` with the records that show the compromise: phishing (a recipient signed in or was flagged after clicking), password-spray (a sprayed account signed in), mfa-fatigue (a fatigue prompt was approved), mail-bombing (takeover indications inside the flood window) and bec (identity compromise behind the mailbox abuse). mail-bombing also hands off to `unauthorized-rmm` (malicious endpoint activity after the flood, the fake help-desk pattern) and to `phishing` (a storm of malicious mail that does not qualify as a subscription bomb). account-takeover, malware and ransomware hand off to nobody. The workflow keeps its own containment (revoke, disable); the hand-off adds the broader account review.
- **Withheld actions are visible.** ransomware: hosts whose policy forbids isolation, payload hashes on more than 50 endpoints, named hashes without a reputation verdict. malware: malicious hashes on more than 10 endpoints, unrated hashes. account-takeover and password-spray: rated sign-in or spray IPs that are shared infrastructure or internal. mail-bombing: buried messages kept in the mailbox. bec: mailbox-rule removal and OAuth-consent revocation as manual steps.
- `related_workflows` may name a workflow that exists (a directory with a README) or a new workflow planned in 14.5.1 (`suspicious-authentication`, `threat-intel-sweep`); `handoff_to` only one that exists. `workflows/README.md` lists each migrated workflow's hand-offs and a test keeps it equal to `handoff_to`; the generated `docs/workflows/README.md` has a "Hands off to" column.

#### 14.10.3 Containment: route-specific mandatory params

Phishing hard-coded an unverified Secure Email verdict (`phishing`), while bec, mail-bombing and ransomware passed nothing, so a real route would have failed after approval. `build_containment` now completes route params after `choose_route` (`containment.builders._route_params`), for direct routes only (a native Cisco XDR route is unchanged):

- `quarantine_email` / `delete_email` routed to **secure_email**: `params.verdict` comes from `integrations.secure_email.options.quarantine_verdict` (config wins over a caller value; without config the caller's `verdict` is used). docs/integrations.md does not list the accepted values, so the operator sets the tenant's value; `config/integrations.example.yaml` documents the option. Without a value the action is **unrouted** with a reason naming the option (reported for manual handling, never dropped, never failing after approval).
- the same actions routed to **defender_o365** need the caller's `params.recipient` (exactly one recipient per message); without it the action is unrouted with that reason.
- Every email workflow now passes `recipient` (the message's single recipient, else empty) and no verdict. The lab sets `quarantine_verdict` in `tools/simulator/scenario.LAB_INTEGRATION_OPTIONS` (fake value, vendor-test convention).
- Carried: the Defender for Office 365 target must be the `networkMessageId`; workflows target the message id they investigated, so a Defender route for an internet message id still needs the analyst (documented in phishing and bec known limitations).

#### 14.10.4 Other integration decisions

- **Legacy replay tests** (`tests/unit/workflows/test_framework_clis.py`) use `web-attacks`, which stays legacy until the end of Phase 5 (aligned last); `simulate.py`, `tools/simulator/README.md` and `docs/testing.md` examples follow. `--legacy malware` is now a usage error (migrated).
- **Legacy references.** Atomic `used_by` lists (and the atomic READMEs' "Used by") name exactly the remaining legacy specs whose steps use the atomic (`tests/test_repo.py` asserts equality); `quarantine-email` has none. `workflows/README.md` separates migrated workflows from legacy specs. Root `README.md` and `engine/README.md` examples use `c2`.
- **Critical-asset class `executive_endpoint`** keeps its key; its display name is now "Executive or VIP asset" because the class also matches executive mailboxes and accounts (the warning read "Executive endpoint" for a mailbox).
- **Generated docs** regenerated (`generate_workflow_docs.py --write`): the eight workflows are `migrated` with tactics; the mail-bombing note now names T1667 *Email Bombing* (ATT&CK v17) instead of the legacy forced T1499 mapping; the workflow index has a "Hands off to" column. Every technique has one name and one tactic set across workflows (checked at integration).
- **Python 3.12.** Every source file parses with the 3.12 grammar (`ast.parse(..., feature_version=(3, 12))`) and no 3.13-only standard-library API is used; CI runs 3.12 and 3.13.

#### 14.10.5 Contract change requests not applied (carried into Phase 3)

Each needs a VERIFIED vendor schema or endpoint in docs/integrations.md first (14.9.4); until then the workflows document the gap in `known_limitations` and their READMEs.

| Request (from) | Decision |
|---|---|
| Typed Secure Endpoint trajectory events (ransomware, malware) | Carried: no documented field schema; mass-modification and recovery-inhibition behaviour come from typed detections (Defender alerts_v2) or simulated sources. |
| Typed Cisco XDR sightings, Defender hunting rows, Splunk rows (phishing, password-spray, account-takeover) | Carried (14.9.4): they stay `GenericRecord`s; click and shared-infrastructure detection rely on typed sources. |
| Secure Email search built from the run window and a recipient (mail-bombing) | Carried: the search body fields are not documented ("a timestamp range is mandatory" only); flood quarantine stays a documented manual step on real tenants, and the detector should add a seed `email_message_id`. |
| Email search by attachment hash or URL (ransomware) | Carried: no VERIFIED endpoint. |
| Entra MFA details, risk detections, role names on profiles (mfa-fatigue, account-takeover) | Carried: the signIn fields used today are listed in the normalizer; `mfaDetail` / `authenticationDetails` and role definitions are not in docs/integrations.md, and riskDetections / riskyUser are UNVERIFIED. mfa-fatigue falls back to `SignInRecord.mfa_result`. |
| Entra sign-ins by IP for `investigate_ip` (password-spray) | Carried: needs an adapter operation and a VERIFIED filter on `ipAddress`. |
| Entra directory audit log / account-security-change record kind (mail-bombing, bec) | Carried: endpoint not in docs/integrations.md; password resets and MFA registration stay generic. |
| Sign-in device id to endpoint resolution (account-takeover) | Carried: no atomic. |
| Service-stop record kind for T1489 (ransomware) | Declined for now: no source produces it; T1489 stays unmapped and documented. |
| Mailbox-rule removal, OAuth-consent revocation, gateway sender block (bec) | Carried as manual steps (14.10.1); new action types need VERIFIED writes first. |
| Product-pinned native builders for Cisco XDR-only tenants (14.9.2) | Carried. |
| Third-party MFA provider adapter (mfa-fatigue) | Carried: a Phase 0 adapter change, out of workflow scope. |

#### 14.10.7 Safety hardening, Phase 2 round 1 (workflow-safety lens)

Fixes for the defects proven by `tests/safety/test_p2_workflows.py` (round 1). Binding.

- **One spelling of an IPv4-mapped address.** `normalize_target(IP, "::ffff:192.0.2.5")` is `"192.0.2.5"` (Phase 0 `models/canonical.py`): records, targets, idempotency keys, critical-asset and allow-list checks all see the IPv4 host. `AllowlistPolicy.excluded_reason` (IP) checks the address **and every IPv4 address it embeds** (`embedded_ipv4`: mapped, translated, compatible, NAT64, 6to4, Teredo) against `never_block.ips` and `cidrs`, the same expansion as `DisclosurePolicy` and `CriticalAssetPolicy`; an allow-listed IPv4-mapped spelling also lists its IPv4 address. password-spray keys sources by `normalize_target`, and mfa-fatigue's internal-address check unmaps mapped addresses. A mapped spelling of an allow-listed address is therefore shown as excluded and never executed. Consequence: the round-2 Phase 1 probe `test_block_ip_on_an_ipv6_form_of_a_critical_ipv4_is_elevated[::ffff:192.0.2.5]` (192.0.2.5 is both critical and allow-listed in the repository config) now gets an exclusion instead of an ELEVATED action; the allow-list wins over the critical-asset class, as it does for `192.0.2.5` itself.
- **Space-separated credential flags.** `Redactor.redact_text` also redacts the next argument after a command-line flag whose name is a sensitive key (`--password VALUE`, `-token VALUE`, quoted values kept quoted; a following flag is not a value). `Redactor.redact_command_line(text)` (used by `_CommandLine`, so every recorded process and persistence command line) adds the forms that are credentials only by command-line convention: `-p VALUE`, `-u user:password` / `--user user:password` / `--proxy-user` (the password part) and URL userinfo passwords (`scheme://user:password@host`). Records, package evidence, `PACKAGE_PROPOSED` and `INVESTIGATION_COMPLETED` audit payloads therefore never carry them.
- **Approved-tool signers.** `config/allowlists.yaml` identifies an approved tool (`approved_rmm`, `approved_dns_tools`) by hashes, domains **and signers**. `AllowlistPolicy.signer_reason(signer)` matches a signer (case and runs of whitespace ignored, otherwise exact) and returns `allowlists.<section>: <name> (signer <signer>)`. The workflow runner (`_approved_signer`, generic for every workflow) checks every HASH, FILE and PROCESS action before it is proposed: when a `HashPrevalenceRecord` of the run reports an approved signer for the file's SHA-256 (the target's hash, or for a `<HOST>/<pid>` process target the hashes of the run's process events of that pid), the action is **not proposed**; the rule outcome is `ALLOWLISTED`, a `Consideration` (`"<action>:<target>"`, reason, the signer records) and a note make it visible in the summary and notification. Isolation and network blocks are unaffected. Known limitation: the signer is the vendor-reported code-signing subject; a binary signed with a stolen approved certificate is withheld the same way (visible, the analyst can act by hand).
- **Granted roles count for critical assets (mail-bombing).** `user_asset` merges the roles of `role_change` records of the user that grant a role (`assigned`, `activated`, `eligible_assigned`) into the asset context, like account-takeover and mfa-fatigue: an account made Global Administrator during the incident is ELEVATED with a warning for `revoke_sessions` and `disable_user`.
- **Isolation evidence backs its claim (account-takeover, mfa-fatigue).** An isolation whose rationale says the endpoint belongs to (or is tied to) a compromised account cites, after its own detection and endpoint records, the records that prove that account's compromise (sign-ins, MFA events, anomalies, profile, role changes; mfa-fatigue: the user's cited prompts, approval, sign-in and anomaly). mfa-fatigue ties an endpoint only to the compromised users it is linked to (endpoint users, detection user, or the users of a prompt source it connected to), in facts and correlation links.
- **Identity outage never hides an active detection.** `workflows.hooks.failed_reads(view, atomics)` (pure) returns, per subject of the given read atomics, the integrations that FAILED. account-takeover (`investigate_user`, `investigate_authentication`, `search_user_activity`, `search_related_users`) and mfa-fatigue (`investigate_authentication`, `investigate_user`, `search_user_activity`) treat an investigated user with a failed identity read and no surviving compromise record as **unassessed**. An incident endpoint with an active (not resolved) MALICIOUS detection whose users include an unassessed user (or that names no user while one is unassessed) is still recommended for isolation on the detection alone; the fact carries `identity_assessed: false` and the rationale says the account could not be assessed because `<integration>` failed. Its evidence is the detection (and endpoint) records only, so the degraded identity source lowers confidence through the scorer and the human decides. Endpoints whose users were assessed and are not compromised stay out (the malware workflow's job).

#### 14.10.8 Safety hardening, Phase 2 round 2 (workflow-safety lens)

Fixes for the defects proven by `tests/safety/test_p2_workflows.py` (round 2). Binding. Every fix is framework level (policies, models, runner), so all workflows get it, not only the eight probed ones.

- **Endpoint identity: short name and FQDN.** `models/canonical.py` adds `endpoint_names(value) -> (full, short)` (upper case, one trailing dot removed; `short` is the first DNS label of an FQDN, `None` for a single-label name or an IP, which is never split) and `same_endpoint(a, b)` (equal, or one is a single-label name equal to the other's first label). `normalize_target(ENDPOINT)` also removes a trailing dot. `AllowlistPolicy` matches `never_block.endpoints` by host identity for ENDPOINT targets and the host part of FILE, PROCESS and PERSISTENCE_ITEM targets: a listed `TH-LT-1047` excludes `TH-LT-1047.CORP.EXAMPLE.COM`, and a listed FQDN excludes the reported short name (reason `allowlists.never_block.endpoints: <listed> (reported as <name>)`). `CriticalAssetPolicy` adds the FQDN's first label to the subject's host names (exact `hostnames` and `hostname_patterns` both see it) and matches a reported short name against the first label of an exact FQDN entry; `find_incident_asset` matches an ENDPOINT asset by host identity too. A listed FQDN never matches a different FQDN with the same first label.
- **URL allow-list in canonical spelling.** `canonical_url(value)` (comparison only, never sent to a vendor): scheme and host lower-cased, trailing dot on the host and the scheme's default port removed, empty path `/`; userinfo, path, query and fragment unchanged. `never_block.urls` entries and URL targets are compared in that form, so `HTTPS://FILES.DOCS-SHARE.TEST/...`, `https://host:443/...` and `https://host./...` are the listed URL. URL targets themselves are not rewritten (`normalize_target(URL)` only strips).
- **The organisation's own network is never blocked.** `config/policy.py` adds `NON_PUBLIC_NETWORKS` (RFC 1918, CGNAT 100.64.0.0/10, loopback, link-local, 0.0.0.0/8, multicast, reserved, IPv6 unspecified, loopback, ULA, link-local, site-local, multicast; the documentation ranges are deliberately absent) and `non_public_network(ip, extra)` (the address and every IPv4 address it embeds). `AllowlistPolicy(allowlists, *, exclusions=None)`: the runtime and every `AtomicContext` pass `settings.exclusions`. `excluded_reason` then also excludes (shown in `excluded_targets` with the reason, never executed): an IP target, or a URL whose host is an IP, in `NON_PUBLIC_NETWORKS` or `exclusions.third_party_lookup.cidrs` (the VPN pool); a DOMAIN target, or a URL host, under `exclusions.internal_domains`, `internal_domain_suffixes`, `third_party_lookup.hostnames`, a built-in internal suffix (`local`, `localhost`, `internal`, `lan`, `home.arpa`, `intranet`, `corp`, the same list as `DisclosurePolicy`) or a single-label name (`url_block_allowed_domains` lifts only the `never_block.domains` reason for a URL host, never an internal-domain or approved-tool reason; 14.12.6). The non-public ranges and built-in suffixes apply without `exclusions`. This covers every IP and domain block builder and every workflow (account-takeover, password-spray, ransomware, mail-bombing, phishing): a rated internal or non-public indicator is withheld visibly, never a silent STANDARD block. malware's `INTERNAL_NETWORKS` and mfa-fatigue's internal check stay as earlier filters.
- **The process of an allow-listed binary is not terminated.** `AllowlistPolicy.hash_reason(sha256)` (`never_block.hashes`, then the approved tools' `hashes`). The runner (`_allowlisted_binary`, after `_approved_signer`, every workflow) maps a `<HOST>/<pid>` PROCESS target to the SHA-256 of the run's `ProcessEventRecord`s of that pid on that host (host identity) and, when a hash is allow-listed and the target itself is not already excluded, does **not propose** the action: outcome `ALLOWLISTED`, a `Consideration` (`"<action>:<target>"`, the reason, the process events) and a note.
- **Who uses an asset counts (executive endpoint and mailbox).** `Asset.users` (Phase 0 model, default empty; merged by `find_incident_asset`, the builders' `_merge_assets` and the package builder's `_union_assets`) holds the accounts that *use* the asset. A rule's `asset` expression may return `users`; in addition the runner adds, for every workflow, the users of the run's `EndpointRecord`s of an endpoint target's host (ENDPOINT, FILE, PROCESS, PERSISTENCE_ITEM) and the recipients of the run's `EmailMessageRecord`s of an EMAIL_MESSAGE target (message id, internet or network message id), so `quarantine_email` / `delete_email` see the mailbox owners. `AssetMatch.used_by` (config schema, default `false`): when `true`, the class `users` / `user_patterns` also match `Asset.users`. `config/critical-assets.yaml` sets it on `executive_endpoint` ("Endpoint, mailbox or account used by an executive"); classes about the account itself (`privileged_account`, `service_account`) leave it `false`, so a flood quarantine in the break-glass mailbox stays STANDARD (mail-bombing `legacy-04`) while the account's own revocation is ELEVATED. Context is only ever added, never removed.
- **mail-bombing never buries a security notice.** `classify_subject` folds hyphens, underscores and whitespace runs to one space and matches the extended `BURIED_KEYWORDS`: any subject about the password (`password`, `passcode`, `passkey`, `reset code`, recovery, locked account), a one-time, verification, security, sign-in or confirmation code (`one time`, `otp`, `security code`, `sign in code`, ...) or a second-factor change (`two step`, `2 step`, `2sv`, `multi factor`, `security key`), with the short tokens (`mfa`, `2fa`, `2sv`, `otp`, `totp`) as whole words only. Such a message is kept out of the flood quarantine and shown as considered, and its identity evidence (and the recipient's revocation) is kept.
- **Codes and passwords in prose are credentials.** `Redactor.redact_text` adds labelled one-time codes (`verification`, `security`, `sign-in`, `login`, `one-time`, `reset`, `recovery`, `confirmation`, `2fa`, `mfa`, `otp`, `backup`, `single-use` code, `one-time password/PIN`, and right before the value only `access`, `auth`, `account`, `device`, `pairing` code, `OTP`, `PIN`), the code-first form (`482913 is your sign-in code`) and passwords in prose (`password: X`, `new/temporary/initial/default/one-time/generated/reset password is X`, `password is X` and `new password X` when X looks like a credential; status words such as `expiring`, `reset`, `required` are kept). Subject lines (`_SubjectLine`), notes, considerations and audit payloads therefore never carry the code of a buried notice.

#### 14.10.6 Exit criteria (section 12, Phase 2)

1. Each of the eight `workflows/<X>/README.md` has the 17 headings of 14.5.4 (brief 46's 16 items, required and optional integrations as two sections): `python tools/validation/check_workflow_readmes.py` reports "8 workflow README(s) OK".
2. Every workflow scenario passes in its modes (dry run and simulated live) through the lifecycle with simulated adapters, including the implicit assertions of 14.5.3 (`tests/simulation/test_workflow_scenarios.py`); each workflow has the minimum scenario set and every rule is PROPOSED in at least one scenario. The real adapters are exercised over `httpx.MockTransport` by the integration and vendor tests.
3. `generate_workflow_docs.py --check` is clean; `tests/safety/test_read_zone.py` passes; the remaining 65 legacy scenarios (11 specs) still replay in dry run.
4. The whole suite passes with `python -m pytest -q -p no:cacheprovider`.

### 14.11 As built: Phase 3 integration (contract amendments and decisions)

Written at the Phase 3 integration step on 2026-10-08 by the framework owner (14.7.2). It is binding. Where it differs from 14.0 to 14.10, it wins; the signatures above are already updated. Phase 3 migrated five workflows: malicious-powershell (2.0.0), credential-dumping (3.0.0), lateral-movement (3.0.0), persistence (2.0.0) and unauthorized-rmm (3.0.0). Each deleted its legacy `workflow.yaml` and `scenarios/` and carries its legacy scenarios as `legacy-*` fixtures (94 scenarios in all). Seven legacy specs remain (c2, dns-tunneling, exfiltration, cloud-compromise, privilege-escalation, vulnerability-exploitation, web-attacks; 39 scenarios).

#### 14.11.1 Legacy alignment

- Atomic `used_by` lists and the atomic READMEs' "Used by" are recomputed from the remaining legacy specs (14.10.4 rule); `block-hash` now has none, like `quarantine-email`.
- `tests/unit/legacy/test_legacy_alignment.py::test_renamed_workflows` (powershell to malicious-powershell, rmm to unauthorized-rmm) accepts a migrated workflow: when the legacy spec is gone, the discovered definition must carry the new id as `id` and `legacy_id`, and `workflows/<new>/README.md` must exist. The other checks (old directories and agent files absent, agent file names the new directory) are unchanged.
- `workflows/README.md` lists the five as migrated (phase 3) with their hand-offs; the legacy table covers Phases 4 and 5.

#### 14.11.2 Cross-workflow conventions (routing and hand-offs), extended

- **A workflow outranks every workflow it hands off to.** When both trigger, the workflow that hands off handles the incident, so the hand-off is still suggested (the 14.10.2 entry-vector rule, generalised). Pinned by `test_a_workflow_outranks_the_workflows_it_hands_off_to` (highest automatic trigger priority, strictly greater) and `test_handoff_graph_has_no_cycle`. Phase 3 priority changes: malicious-powershell technique trigger 115 to **125** (above persistence 120, which it hands off to); lateral-movement technique trigger 150 to **160** (above credential-dumping 150, which it hands off to; the tie used to go to credential-dumping by id, contradicting the lateral-movement README); unauthorized-rmm title trigger 120 to **145** (its specific patterns such as `*remote desktop tool*` ranked below the broader lateral-movement title `*remote desktop*` at 140).
- **Resulting order of technique triggers:** ransomware and mfa-fatigue 200; lateral-movement 160; credential-dumping, unauthorized-rmm and mail-bombing (T1667) 150; malicious-powershell 125; persistence 120; phishing, password-spray and bec 110; malware and account-takeover 100. Pinned pairs (`tests/unit/workflows/test_cross_workflow.py`): malicious-powershell over persistence and malware, persistence over malware, credential-dumping over malicious-powershell and account-takeover, lateral-movement over credential-dumping, ransomware over lateral-movement, unauthorized-rmm over persistence, an RMM title over the lateral-movement title.
- **Hand-off subjects are the entity the target workflow starts from:** an account for account-takeover, an endpoint hostname for persistence, unauthorized-rmm and credential-dumping, a file hash for malware, a mailbox for phishing. malicious-powershell now hands persistence off by endpoint (it used `<ENDPOINT>/<item_id>`) and names the items in the reason, like unauthorized-rmm.
- **Phase 3 hand-offs:** malicious-powershell to malware (payload hashes) and persistence (endpoints with a malicious or suspicious item); credential-dumping to account-takeover (exposed accounts); lateral-movement to account-takeover (movement accounts) and credential-dumping (hosts of the movement with credential access); unauthorized-rmm to persistence (the tool persists) and account-takeover (a user of an affected endpoint with high or confirmed identity risk, or a high-severity anomaly). persistence hands off to nobody. Every endpoint workflow that finds a compromised account hands it to account-takeover (pinned by a test).
- **MITRE.** Every technique has one name and one tactic set across workflows (checked at integration): T1047 is TA0002 in malicious-powershell and lateral-movement; T1105 stays TA0011 (malware, malicious-powershell); T1078 stays TA0001. Migrated workflows use the short sub-technique name; ATT&CK v17 names are used (T1176 *Software Extensions* with T1176.001 *Browser Extensions*, T1219 *Remote Access Tools* with T1219.002 *Remote Desktop Software*). The legacy forced mapping T1136 (persistence) is dropped and documented. `generate_workflow_docs.py --write` regenerated `docs/mitre-mapping/` and `docs/workflows/README.md`.

#### 14.11.3 Contract amendments

- **`NetworkConnectionRecord.pid: int | None = None`** (non-negative): the process that owns the connection, when the source reports it. It is not part of the natural key or the evidence fields, so record ids and evidence of existing records are unchanged. malicious-powershell attributes a connection to a run by image name (and image hash) on the same host and, when both carry a pid, only to the run with that pid. Without a pid the earlier behaviour (shared by the runs of the image) remains and stays in `known_limitations`.
- **`PersistenceItemRecord.mechanism` adds `"browser_extension"`.** persistence recognises it directly (label "browser extension", removal step "remove the browser extension and block it by browser policy"); a mechanism `other` item with an extension path or name is still recognised for sources that do not map the dedicated value.
- **Test update (consequence of 14.10.7).** In `tests/safety/test_phase1_atomics.py` the IPv4-mapped spelling of 192.0.2.5 (critical and allow-listed) moves from the ELEVATED probe to `test_block_ip_on_an_ipv6_form_of_an_allowlisted_critical_ipv4_is_excluded_visibly` (excluded with a reason, never an action). The mapped and NAT64 forms of 203.0.113.10 stay ELEVATED.

#### 14.11.4 Decisions on the Phase 3 reports

- **credential-dumping on a domain controller (the 14.9.2 item left to the Phase 3 owner): confirmed.** Account actions for accounts exposed on a domain controller stay proposed, never skipped; privileged ones are ELEVATED through the privileged-account class, and the domain-wide reset is the manual step `domain-credential-reset:<HOST>`. This is stricter than the legacy plan (no account action), never weaker.
- **Persistence removal stays a manual step**, not a rule. `remove_persistence` has no catalog integration, so a rule could never be PROPOSED, and `check_coverage` keeps requiring every rule to be PROPOSED or expected in a scenario. A rule that is always UNROUTED would show the analyst nothing the manual step (`remove_persistence:<ENDPOINT>/<item_id>`, with its records) does not already show. Revisit when a VERIFIED write exists.
- **Approved-RMM context for hooks (unauthorized-rmm) is deferred to Phase 4.** The safety-relevant part already holds in the framework: `PackageBuilder` excludes approved hashes and domains, and the runner withholds hash blocks and terminations of approved binaries and signers (14.10.7, 14.10.8). A read-only allow-list name for rule expressions and hooks would only change wording (no uninstall manual step, "sanctioned" in the rationale). When it is added it must never withhold the isolation of an untrusted session.
- **Admin jump-host allow-list (lateral-movement) is deferred.** Jump hosts are recognised from endpoint group or tag names (`hooks.JUMP_HOST_MARKERS`); a quiet jump host is shown as considered, never silently skipped. A configuration key needs a schema change in `config/` and its validator; it is planned with the Phase 4 suspicious-authentication workflow.
- **Not applied (each needs a VERIFIED vendor schema or endpoint first, 14.9.4):** typed Secure Endpoint trajectory and Defender timeline or hunting rows for process, network and persistence events (all five workflows; carried from 14.10.5); a logon type or session field on `DetectionRecord` (credential-dumping uses the endpoint's users and the detection and process users); terminate process, uninstall or remove application, remove persistence, password reset and Kerberos ticket-granting account rotation writes (manual steps or UNROUTED); an RMM console API; the Secure Cloud Analytics API (its alerts arrive as Cisco XDR incidents).
- **Command lines** are never parsed by malicious-powershell; characteristics come from vendor detections, reported techniques and verdicts, and a SUSPICIOUS vendor characteristic is cited, never acted on alone (kept as built).

#### 14.11.5 Exit criteria (section 12, Phase 3)

1. Each of the five `workflows/<X>/README.md` has the 17 headings of 14.5.4 (brief 46's 16 items, required and optional integrations as two sections): `python tools/validation/check_workflow_readmes.py` reports "13 workflow README(s) OK" (all migrated workflows).
2. Every workflow scenario passes in its modes (dry run and simulated live) through the lifecycle with simulated adapters, including the implicit assertions of 14.5.3 (`tests/simulation/test_workflow_scenarios.py`); each Phase 3 workflow has the minimum scenario set and every rule is PROPOSED in at least one scenario. The real adapters are exercised over `httpx.MockTransport` by the integration and vendor tests.
3. `generate_workflow_docs.py --check` is clean; `tests/safety/test_read_zone.py` passes; the remaining 39 legacy scenarios (7 specs) still replay in dry run.
4. The whole suite passes with `python -m pytest -q -p no:cacheprovider`.

#### 14.11.6 Safety review, Phase 3 round 1 (workflow safety)

Fixes for the defects proven by `tests/safety/test_p3_workflows.py`. Binding like the rest of 14.11; context is only ever added, nothing is withheld on a guess.

- **Sanctioned binary behind a hashless process event.** Defender timeline rows and some trajectory events report a process by name and pid only. For a `<HOST>/<pid>` PROCESS target whose process events carry no SHA-256, the runner (`_inferred_process_hashes`, generic for every workflow) identifies the binary from the run's other records on the same host that name the same executable and report a hash (process events, detections, connections, persistence items, hash prevalence records listing the host) or from a connection of that pid. `_allowlisted_binary` withholds the termination (outcome `ALLOWLISTED`, a `Consideration` that names the candidate hashes, never silent) only when **every** candidate is sanctioned: an allow-listed or approved-tool hash, or an approved signer on a prevalence record of that hash (`_sanctioned`). One unknown build of the same name keeps the action proposed. Known limitation: a hostile binary that reuses the sanctioned executable name and whose own hash appears in no record of the host is withheld the same way; the consideration shows it and the analyst can act by hand.
- **Rules that rest only on a tool's behaviour (`RecommendationRule.binaries`).** New optional expression: the SHA-256 values of the binaries the recommendation rests on alone. When every value is sanctioned (`_sanctioned`; a value that is not a SHA-256, for example a tool known only by name, never is) and the allow-list does not already exclude the target, the runner withholds the action as `ALLOWLISTED` with a `Consideration`. unauthorized-rmm `block_rmm_destination_domain` passes `[] if item.rated else item.flagged_tool_hashes` (new destination fact `flagged_tool_hashes`): an unrated relay of a tool sanctioned by hash or signer is never blocked fleet-wide on a PUA flag, while a relay that reputation itself rates malicious or suspicious is still proposed.
- **Accounts the identity provider marks privileged.** `Asset.privileged: bool = False` (also an `asset` expression key). The runner (`_record_asset`, every workflow) sets it for a USER or EMAIL_ADDRESS target when a `UserProfileRecord` of the run has `privileged: true` (the source's flag, or a role in `PRIVILEGED_ROLE_NAMES`). `CriticalAssetPolicy.classify` puts such an account in the `privileged_account` class (when configured) whatever its role names are, so a role outside the static list (Helpdesk Administrator) is ELEVATED with the privileged-account warning. This completes 14.11.4. Fixture consequence: credential-dumping `tp-approve-all`, `dry-run`, `partial-failure`, `release-restoration` and `legacy-01-workstation-lsass-access` now expect the privileged account's revocation and disable ELEVATED and are approved (and released) by the lead.
- **Every address of a host.** `Asset.ips: tuple[str, ...] = ()` (also an `asset` expression key): further addresses, matched against `ip_cidrs` like `ip`. The runner adds every `ip_addresses` entry of the run's endpoint records for the host of an ENDPOINT, FILE, PROCESS or PERSISTENCE_ITEM target, so a production address on a second interface makes every action on the host ELEVATED. Asset merges (`merge_asset_context`: `find_incident_asset`, `PackageBuilder`, the builders, the runner) union the addresses and `privileged` instead of keeping only the first IP.
- **Credentials in Windows and PowerShell command lines.** `Redactor.redact_command_line` also redacts `/name:VALUE` switches named as passwords (`cmdkey /pass:`, `/pw:`, `/pwd:`, `wmic /password:`) or sensitive keys, `/rp VALUE`, `/p VALUE` after a `/u USER`, the literal of `ConvertTo-SecureString 'X' -AsPlainText` and `-String X` (a `$variable` is kept), and the positional password of `net use [device] \\host\share X` and `net user NAME X` (`*` kept). `Redactor.redact` applies `redact_command_line` to every string under a command-line key (`COMMAND_LINE_KEY_PATTERN`: `command_line`, `commandLine`, `ProcessCommandLine`, `cmdline`, ...), so raw findings quoted in `INVESTIGATION_COMPLETED` and other audit payloads get the same treatment as the typed records' `command_line`.

#### 14.11.7 Safety review, Phase 3 round 2 (workflow safety)

Fixes for the round 2 defects proven by `tests/safety/test_p3_workflows.py`. Binding like the rest of 14.11; where it differs from 14.10.1 and 14.11.6, it wins.

- **Command credential forms in every text.** `Redactor.redact_text` (so `Redactor.redact`, every audit payload, evidence summaries and fields, notes, hook reasons, rationales, considerations and notifications) now applies the forms 14.11.6 gave only to command lines: the password in URL userinfo (`scheme://user:password@host`), `/name:VALUE` switches named as passwords or sensitive keys (`/pass:`, `/pw:`, `/pwd:`, `/password:`, `/rp:`), `/rp VALUE`, `/p VALUE` after a `/u USER`, the literal of `ConvertTo-SecureString 'X' -AsPlainText` and `-String X` (a `$variable` is kept) and the positional password of `net use [device] \\host\share X` and `net user NAME X` (`*` kept). A service ImagePath or task action (`PersistenceItemRecord.path`, `.name`), a detection title or file path, a process event's file path, Splunk `ScriptBlockText` and untyped `arguments` / `args` attributes of generic records quote commands with their arguments, so these fields need no command-line key. `Redactor.redact_command_line` keeps only the forms that are credentials by command-line convention alone: `-p VALUE` and `-u user:password` (`-p 8080` in prose is a port). The typed record fields stay plain strings (records keep their values; every output redacts on the way out).
- **URL destinations carry no userinfo.** malicious-powershell `destinations_of` (and so its basis texts, rationales, links and the `block_url` target) uses `url_destination(url)`: the URL without its `user:password@` part, everything else unchanged. A credential from telemetry never reaches a block target, a rationale, a notification or the audit trail; the evidence fields already used `redact_url`.
- **Process ids are reused: every binary of the pid.** `_process_candidates` (runner, every workflow) replaces `_inferred_process_hashes`: for a `<HOST>/<pid>` PROCESS target, every process event of that pid on that host counts. An event with a SHA-256 contributes it; a hashless event is identified by the host's records naming the same executable (or a connection of that pid), and an event whose binary nothing identifies makes the set incomplete. `_allowlisted_binary` withholds the termination (`ALLOWLISTED`, with a `Consideration`) only when the set is complete and **every** candidate is sanctioned (`_sanctioned`: allow-listed or approved-tool hash, or an approved signer on a prevalence record). `_approved_signer` no longer decides PROCESS targets (it matched any hash of the pid) and, for HASH and FILE targets, requires every hash the target names to carry an approved signer. An older event of the same pid that ran the approved RMM binary no longer shields the flagged process.
- **A privileged role gained during the incident.** `_record_privileged` (runner, every workflow) also sets `Asset.privileged` when a `RoleChangeRecord` of the run reports that the account was `assigned`, `activated` or `eligible_assigned` a privileged role (`privileged: true`), whatever an older profile record says; a later removal does not undo it (context is only added). The account is then in the `privileged_account` class: its revocation and disable are ELEVATED with the privileged-account warning in every workflow (credential-dumping and lateral-movement included). credential-dumping also treats such an account as privileged (disable justified, reason "role granted during the incident: <role>", the role change records cited).
- **Isolating a host that holds allow-listed infrastructure.** `AllowlistPolicy.address_reason(address)`: the `never_block.ips` / `never_block.cidrs` match of an address (and every IPv4 address it embeds), never the built-in non-public ranges. `PackageBuilder` (rule 6) adds a `CriticalAssetWarning` (role `allow-listed infrastructure address`, `asset_class` None) to every `isolate_endpoint` and `block_network_client` action whose asset context (the incident's asset and the addresses the run's endpoint records report, 14.11.6) holds such an address, so the action is ELEVATED with a visible warning; `policy_violations` re-checks it with the incident's asset. The isolation stays proposed (the host may be the compromised one); it is never a silent STANDARD action. The decision card's reason line names it.

### 14.12 As built: Phase 4 integration (contract amendments and decisions)

Written at the Phase 4 integration step on 2026-10-08 by the framework owner (14.7.2). It is binding. Where it differs from 14.0 to 14.11, it wins; the signatures above are already updated. Phase 4 migrated four workflows, c2 (2.0.0), dns-tunneling (2.0.0), exfiltration (2.0.0) and cloud-compromise (2.0.0), and added the new suspicious-authentication (1.0.0). The four migrated workflows deleted their legacy `workflow.yaml` and `scenarios/` and carry their legacy scenarios as `legacy-*` fixtures. Phase 4 adds 87 scenarios (c2 19, dns-tunneling 18, exfiltration 18, cloud-compromise 18, suspicious-authentication 14), for 328 in `tests/fixtures/workflows/`. Three legacy specs remain: privilege-escalation, vulnerability-exploitation and web-attacks (16 scenarios, Phase 5).

#### 14.12.1 Legacy alignment

- Atomic `used_by` lists and the atomic READMEs' "Used by" are recomputed from the remaining legacy specs (14.10.4 rule). `block-domain` now has none, like `block-hash` and `quarantine-email`.
- `workflows/README.md` lists the five as migrated (phase 4) with their hand-offs, and the legacy table covers Phase 5 only. `tests/unit/workflows/test_cross_workflow.py` no longer treats suspicious-authentication as planned (`PLANNED_NEW` is `threat-intel-sweep`).
- Root `README.md` and `engine/README.md` examples use `web-attacks` (legacy until the end of Phase 5), like the legacy replay examples (14.10.4); the c2 spec they named is gone.

#### 14.12.2 Routing and hand-offs (14.10.2 and 14.11.2 extended)

- **Ransomware's title trigger names encrypted files, not any encryption.** `*encrypted*` (priority 150) also matched C2 titles such as "Encrypted beaconing from ..." (T1573, an encrypted channel), so they routed to ransomware. The patterns are now `*ransom*`, `*mass file modification*`, `*shadow cop*`, `*files encrypted*`, `*file encrypted*`, `*encrypted files*`, `*share encrypted*`, `*mass encryption*` and `*file encryption*`. The ransomware title tests and the legacy title "File share encrypted from HR workstation" still match.
- **Resulting order of technique triggers:** ransomware and mfa-fatigue 200; dns-tunneling 170; lateral-movement 160; credential-dumping, unauthorized-rmm, mail-bombing (T1667) and exfiltration 150; cloud-compromise 130; malicious-powershell 125; persistence 120; c2 115; phishing, password-spray and bec 110; malware and account-takeover 100; suspicious-authentication (parent T1078) 95. **Title triggers:** mfa-fatigue 200; dns-tunneling 165; ransomware 150; unauthorized-rmm 145; exfiltration and lateral-movement 140; credential-dumping and mail-bombing 120; malicious-powershell 110; bec 100 (default); c2, cloud-compromise, suspicious-authentication and password-spray 105; c2 (Secure Cloud Analytics or Umbrella source) and persistence 95; account-takeover, phishing and malware 90.
- **Pinned pairs (Phase 4):** T1071.001 and T1573 to c2; c2 over malware; an "Encrypted beaconing" title to c2 and "Files encrypted" to ransomware; malicious-powershell over c2; T1071.004 to dns-tunneling; dns-tunneling over c2 and over exfiltration; T1567.002 to exfiltration; exfiltration over c2 and over account-takeover; ransomware over exfiltration (double extortion); T1098.001 to cloud-compromise; cloud-compromise over account-takeover; T1078 to suspicious-authentication; T1078.004 (with or without T1078) and the "Risky sign-in" title to account-takeover; password-spray and mfa-fatigue over suspicious-authentication.
- **Title ties at 105 resolve by workflow id (14.3.5) and are pinned where they matter:** a title naming both a suspicious sign-in and an OAuth consent goes to cloud-compromise (it investigates the consent and hands the account to account-takeover); a password-spray title that also names a suspicious login goes to password-spray.
- **suspicious-authentication and account-takeover.** account-takeover keeps its risky, high-risk, unfamiliar sign-in, impossible or atypical travel and token-replay titles: they name an identity-protection risk detection, which is account-takeover's starting point (Phase 2 routing unchanged). suspicious-authentication's titles do not repeat them, and its technique trigger lists only parent T1078 at 95, so T1078.004 stays with account-takeover. Its title trigger (105) outranks account-takeover (100), which it hands off to.
- **c2 and the endpoint workflows.** c2 ranks below ransomware, lateral-movement, credential-dumping, unauthorized-rmm, malicious-powershell, persistence, dns-tunneling and exfiltration, and above malware (its only hand-off). Parent T1071 is not a c2 trigger, so T1071.004 always reaches dns-tunneling.
- **Phase 4 hand-offs (subjects per 14.11.2):** c2 to malware (the SHA-256 of a flagged beaconing process); exfiltration to account-takeover (an account that drives the transfer is compromised); suspicious-authentication to account-takeover (a sign-in concluded as a likely compromise); cloud-compromise to account-takeover (a compromised cloud account). dns-tunneling hands off to nobody (14.12.4). Every one of them outranks its target (`test_a_workflow_outranks_the_workflows_it_hands_off_to`), the graph stays acyclic, and `test_phase4_workflows_that_find_compromised_accounts_hand_them_to_account_takeover` pins the account hand-offs. Across the 87 scenarios every account-takeover subject is an account and every malware subject a SHA-256.
- **MITRE.** Each technique has one name and one tactic set across all workflows (checked at integration). New: T1071.001 *Web Protocols*, T1573 *Encrypted Channel*, T1568 *Dynamic Resolution* with T1568.002 *Domain Generation Algorithms*, T1071.004 *DNS*, T1572 *Protocol Tunneling* (all TA0011; T1071 *Application Layer Protocol* is TA0011 as in ransomware); T1041, T1048, T1567 with T1567.002 (TA0010); T1098.001 and T1098.003 (TA0003, as in mfa-fatigue), T1528 (TA0006), T1078.004 (TA0001); T1090 *Proxy* with T1090.003 *Multi-hop Proxy* (TA0011, suspicious-authentication only; c2 does not map T1090). cloud-compromise drops the legacy forced T1530 mapping (documented in its README). `generate_workflow_docs.py --write` regenerated `docs/mitre-mapping/` and `docs/workflows/README.md`.

#### 14.12.3 Contract amendments

- **Entra role removal resolves the framework's target.** The `remove_privileged_role` builder targets `<user>/<roleDefinitionId>` (the `ROLE_ASSIGNMENT` normal form, `RoleChangeRecord.target`), while the Phase 0 Entra adapter matched `request.target` against assignment ids and needed `params.principal_id`. With a principal id a tenant would have reported `ALREADY_CONTAINED` and `VERIFIED` while the role was still assigned (safety defect). `EntraAdapter.remove_privileged_role` and `verify` now resolve a `<user>/<roleDefinitionId>` target through VERIFIED reads: the user's object id (`GET /users/{id or userPrincipalName}`, the lookup must name the approved account exactly, case-insensitive, and a `params.principal_id` must equal it), then the principal's role assignments, keeping those of the role definition (at `params.directory_scope_id` when given). No match is `ALREADY_CONTAINED`; assignments at several scopes without a scope are refused (`InvalidTargetError`, nothing deleted) so the rollback always recreates exactly what was removed; one match is deleted by its id, with the rollback triple captured before the delete. `verify` re-reads and reports `NOT_VERIFIED` while an assignment of the role remains. A bare assignment id with `params.principal_id` (the Phase 0 form) is still accepted. cloud-compromise passes the grant's `directory_scope_id` (new fact field from `RoleChangeRecord.directory_scope_id`, empty when unknown); its rule params are limited to that key. docs/integrations.md 2.8 documents the resolution.
- **Lab reputations carry vendor categories and first-seen.** `SimulatedEnvironment.set_reputation(..., categories=(), first_seen=None)` and scenario `environment.reputations[].categories` / `.first_seen` (ISO 8601 with offset). The simulated enricher reports them in the evidence data (`categories`, `first_seen`), so `EnrichmentRecord.categories` and `.first_seen` are filled as for a real enricher (14.1.3). Record ids and existing evidence are unchanged when they are absent.
- **Claims backed by vendor context cite it.** exfiltration cites the enrichment records that report a storage or newly-seen category, or a first-seen time inside `NEW_DESTINATION_DAYS`, when its block rests on them; dns-tunneling cites the enrichment records that put a parent in the DNS tunneling category. Before, the rationale named the category while the evidence cited only the transfer or DNS rows (the "no invented facts" rule of section 8). Both paths are tested over the lab.

#### 14.12.4 Decisions on the Phase 4 reports

- **dns-tunneling hands off to nobody (kept).** The data that may have left through a confirmed tunnel stays the manual step `assess data sent through <parent>` with the transfer pattern cited: exfiltration measures transfer volume and destinations, which a tunnel's DNS records do not carry beyond the query counts already shown. Adding the hand-off later needs no priority change (170 over 150).
- **Read-only allow-list context for hooks (approved DNS tools, `never_block`, corporate egress; the approved-RMM item of 14.11.4) is deferred to Phase 5.** The safety-relevant part already holds in the framework: `PackageBuilder` excludes allow-listed and approved targets visibly, and the runner withholds terminations, hash blocks and binary-only rules of sanctioned tools (14.10.7, 14.11.6, `RecommendationRule.binaries`). A hook view would only change wording (no "remove tunnel client" or "assess data exposure" note for a sanctioned tool, "sanctioned" in rationales). When it is added it must stay read-only and must never withhold the isolation of an untrusted host. The jump-host configuration key (14.11.4) is deferred with it; suspicious-authentication recognises corporate egress from shared-egress evidence (other accounts' sign-ins and enterprise sightings) and never counts a non-public or shared source as a new country, travel or hour.
- **Ransomware `*encrypted*` overlap:** applied (14.12.2).
- **Fixture data.** Destination IPs inside the lab's `production_server` range 203.0.113.0/26 and internal 10.x addresses in legacy scenarios were renumbered (c2 legacy-01, exfiltration legacy, cloud-compromise legacy), each change recorded in the scenario description. Scenarios keep destinations outside 203.0.113.0/26 and 192.0.2.0/28 unless they are about those classes.
- **Exfiltration "still running"** is judged from the transfer record's `last_seen` against `incident.created_at` minus 30 minutes (documented limitation); the legacy `transfer_ongoing` and `insider_risk` context flags are never evidence, an insider flag must come from a detection record.
- **README headings.** "16 sections" in the brief is the 17 headings of 14.5.4 (required and optional integrations as two sections), as in 14.10.6 and 14.11.5.
- **Not applied (each needs a VERIFIED vendor schema or endpoint first, 14.9.4):**

| Request (from) | Decision |
|---|---|
| Typed Secure Endpoint trajectory, Defender timeline and hunting rows, Cisco XDR sightings and Splunk rows (c2, dns-tunneling, exfiltration) | Carried (14.10.5, 14.11.4). Contacts, beacon counts, the process behind a connection, DNS volume and transfer bytes come from typed (lab) records only; on a tenant, blocks of unrated destinations and isolations rest on detections and reputation. Documented in each `known_limitations`. |
| Per-connection timestamps for periodicity analysis (c2) | Carried with the typed schemas; today count and first/last seen only. |
| Meraki `block_network_client` for an endpoint no EDR can isolate (c2) | Carried as a manual step: a rule needs a read atomic that resolves the host's MAC to a Meraki network and client id (the VERIFIED clients search) before it can build a `NETWORK_CLIENT` target; planned with Phase 5 cross-source correlation. |
| Umbrella DNS activity / reporting and security-score reads (c2, dns-tunneling) | Carried: UNVERIFIED in docs/integrations.md. Whether the real Umbrella enrichment answer names the "DNS Tunneling VPN" category stays unverified; the hooks read enrichment and DNS-row categories, and both paths are now tested. |
| `DnsQueryRecord.process` / `pid` (dns-tunneling) | Carried: needs a VERIFIED DNS activity source with a documented row schema. |
| Secure Cloud Analytics API (c2) | Not an integration; its alerts arrive as Cisco XDR incidents and are a trigger source only (14.11.4). |
| `SignInRecord.asn` from the Graph signIn `autonomousSystemNumber` (suspicious-authentication) | Carried: the field is not among the signIn fields docs/integrations.md lists for the VERIFIED sign-ins read. Unusual ASN stays a known limitation. |
| Entra riskDetections / riskyUser, sign-in device id to Intune device, Entra sign-ins by IP (suspicious-authentication) | Carried (14.10.5): UNVERIFIED or no VERIFIED filter. |
| Typed `RoleChangeRecord` and `CloudAppRecord` from real adapters: directoryAudits, servicePrincipals, oauth2PermissionGrants reads (cloud-compromise) | Carried: not in docs/integrations.md. Defender alerts_v2 (VERIFIED) already feeds cloud alerts as detections. |
| Remove app credentials (UNVERIFIED), revoke OAuth2 permission grants, disable a service principal (cloud-compromise) | Manual steps (14.10.1), like bec's consent revocation. |

#### 14.12.5 Exit criteria (section 12, Phase 4)

1. Each of the five `workflows/<X>/README.md` has the 17 headings of 14.5.4 (brief 46's 16 items, required and optional integrations as two sections): `python tools/validation/check_workflow_readmes.py` reports "18 workflow README(s) OK" (all migrated workflows).
2. Every workflow scenario passes in its modes (dry run and simulated live) through the lifecycle with simulated adapters, including the implicit assertions of 14.5.3 (`tests/simulation/test_workflow_scenarios.py`); each Phase 4 workflow has the minimum scenario set and every rule is PROPOSED in at least one scenario. The real adapters are exercised over `httpx.MockTransport` by the integration and vendor tests (the Entra role resolution in `tests/unit/vendors/test_entra.py`).
3. `generate_workflow_docs.py --check` is clean; `tests/safety/test_read_zone.py` passes; the remaining 16 legacy scenarios (3 specs) still replay in dry run and `xdr_plan check` passes.
4. The whole suite passes with `python -m pytest -q -p no:cacheprovider`.

#### 14.12.6 Safety review, Phase 4 round 1 (workflow safety)

Fixes for the defects proven by `tests/safety/test_p4_workflows.py`. Binding like the rest of 14.12; context is only ever added, nothing is withheld on a guess.

- **URL targets never carry credentials.** `normalize_target(TargetKind.URL, value)` applies the new `models.canonical.url_without_credentials`: the `user:password@` part of the authority is removed, and every query or fragment parameter whose key is sensitive (`Redactor.is_sensitive_key`, the keys `Redactor.redact_url` redacts: `token`, `password`, `sig`, `api_key`, `access_token`, ...) is dropped with its value (an emptied `?` or `#` goes too). A URL without credentials is kept exactly as written, and the function is stable. Every URL target (`ProposedAction.target`, `ActionRequest.target`, the idempotency key, the dry run, the vendor `block_url` call) is therefore free of credentials in every workflow, not only c2; the hook facts may keep the URL as reported (their texts are redacted on the way out). The parameter is dropped rather than replaced by a marker so the vendor never receives a literal `[REDACTED]` URL. `tests/unit/dryrun/test_simulator.py::test_secrets_in_targets_are_redacted` now expects the URL without the parameter (the secret is still asserted absent).
- **The owned-domain URL exception never lifts the internal-domain exclusion.** `AllowlistPolicy.excluded_reason` for a URL whose host is under `url_block_allowed_domains` returns the approved-tool domain reason or the internal-domain reason (`exclusions.internal_domains`, internal suffixes, listed host names, single-label names) and lifts only the `never_block.domains` reason. A beacon URL on `files.corp.example.com` (internal sub-zone of the owned `example.com`) is excluded with the reason, never a STANDARD `block_url`; a URL on a public host of the owned domain stays blockable as before.
- **dns-tunneling identifies a hashless query event's binary like the runner.** `clients[].binaries` and `tunnels[].client_hashes` (the `binaries` of the isolate and unrated-domain block rules) come from `_Facts._candidates`: an event with a SHA-256 is that binary; a hashless event takes the hashes of the process events of the same host and pid and of the host's records that name the same executable (process events, detections, connections, persistence items, prevalence records listing the host) or a connection of that pid, and adds `name:<executable>` (never sanctioned) unless a record names the same executable with a hash or a connection of that pid reports one, so an older binary of a reused pid shields nothing (the rule of `_process_candidates`, 14.11.7). The records that identified the binary are cited in the client's `record_ids`. An IT host whose only tunnel client is the approved DNS tool is no longer isolated while the tool's termination is withheld as sanctioned.
- **exfiltration never blocks the address of a service rated CLEAN.** `_Analysis._serves_clean`: an IP destination that a transfer or contact record names together with a domain, or that a DNS record resolved a domain to, where that domain is rated CLEAN (CLEAN aggregate and no flagging record reaching it), gets the destination fact `serves_clean` (the domains) and `serves_clean_ids`; it is never `blockable`, and an unrated one is `clean` (the same sanctioned service). It is shown as considered (`block_ip:<ip>`, reason naming the CLEAN service, citing the transfer, DNS and enrichment records). This mirrors c2's shared-hosting rule (an IP serving a CLEAN-rated domain).

#### 14.12.7 Safety review, Phase 4 round 2 (workflow safety)

Fixes for the round 2 defects proven by `tests/safety/test_p4_workflows.py` (`test_r2_*`; lens: c2, dns-tunneling, exfiltration, cloud-compromise, suspicious-authentication). Binding like the rest of 14.12; nothing is withheld on a guess, and every withheld action is shown as considered with the records behind it.

- **Archive, transfer and database credentials in command lines.** `ProcessEventRecord.command_line` is evidence, so whatever `Redactor.redact_command_line` (the `_CommandLine` validator) leaves reaches the package, notifications and the append-only audit trail. It now also redacts: an attached password `-pVALUE` / `-hpVALUE` (always when the command line names a 7-Zip, RAR or MySQL / MariaDB client; otherwise only a value that looks like a credential and holds no `:`, `=`, `/` or `\`, so `-pthread`, `-print`, `-priority:high` stay); `-P VALUE` when the command line names a zip-family tool (`zip`, `unzip`, `zipcloak`, `pkzipc`, `wzzip`, ...); and `-pw` / `-pwd` / `-pass` / `-passin` / `-passout VALUE` (also `=VALUE`, `:VALUE`; PuTTY `pscp` / `plink` / `psftp`, OpenSSL). `SENSITIVE_KEY_PATTERN` (every text, every structure) gains `account_key`, `shared_access_key`, `storage_key`, `storage_account_key` (Azure connection strings `AccountKey=`, `SharedAccessKey=`; `SharedAccessKeyName` stays readable), a password word glued to a prefix (`[a-z0-9]*password` / `passwd`: environment variables such as `PGPASSWORD`, `DBPASSWORD`) and `mysql_pwd`. (A bare `pwd` key was not sensitive here; since 14.13.7 the exact keys `pass`, `pwd` and `pw` are.)
- **c2: an IP that a connection record ties to a CLEAN domain is shared.** `_Facts._shared` also counts an outbound `NetworkConnectionRecord` of the destination that names a domain rated CLEAN together with the address (the case exfiltration calls `serves_clean`, 14.12.6), citing that record and the domain's enrichment records. `block_c2_ip` (`item.rated and not item.shared`) is then not proposed and the IP is shown as considered.
- **c2: a sanctioned binary never isolates its host.** `hosts[].binaries` lists the hashes the host's own malicious activity rests on when its only basis is "a process with a MALICIOUS hash holds the C2 connection" (an active malicious detection or a malicious process event stands on its own: `[]`). Both isolation rules pass `binaries="item.binaries"`, so the runner's `_sanctioned_binaries` withholds the isolation (ALLOWLISTED outcome, shown as considered) when every hash is sanctioned (`never_block.hashes`, an approved tool hash, or an approved signer on a prevalence record), exactly as it withholds that process's termination; dns-tunneling has the same rule (14.12.6).
- **cloud-compromise: a grant that predates the compromise is not removed.** `_Assessment` records the time of every dated record behind an indicator (sign-in `timestamp`, risk detection and alert `first_seen` / `last_seen`; a profile rating has none) and exposes the earliest (`since`). `_role_facts` ties a privileged grant to a compromised actor or grantee only when it is not dated more than `PRE_COMPROMISE_GRACE` (24 hours, the `sign_in_to_activity` correlation window) before that account's earliest dated compromise record. A grant tied only through accounts it predates goes to `withheld_roles` with `predates` and is shown as considered (`remove_privileged_role:<user>/<roleDefinitionId>`, "a pre-existing assignment this incident did not create"). An undated grant, or an account compromised only by a profile rating, cannot be placed before the compromise and keeps the earlier behaviour (proposed, always ELEVATED by the catalog). Sign-in age in `_assess` is unchanged (the authentication step reads 72 hours).
- **exfiltration: account decisions never spread by endpoint.** `actors[].drives` is true when a transfer record names the account, or names none and comes from an endpoint whose records list that account as its only user (a userless transfer from a shared endpoint is attributed to nobody). `revoke_actor_sessions` takes `(a.compromised and a.drives) or a.insider` and `disable_compromised_actor` takes `a.compromised and a.drives`; the revoke rationale says "drives the transfer" only when `drives` (an insider-named account without a transfer reads "no transfer record names it"). A compromised account that drives no transfer (another user of the source endpoint, or an account only the incident names) is shown as considered (`disable_user:<user>`, citing its compromise records) and still handed off to `account-takeover`, whose reason now says "an account tied to the transfer". Insider-risk accounts keep their own rule (named explicitly by the detection).

### 14.13 As built: Phase 5 integration (contract amendments and decisions)

Written at the Phase 5 integration step on 2026-10-08 by the framework owner (14.7.2). It is binding. Where it differs from 14.0 to 14.12, it wins; the signatures above are already updated. Phase 5 migrated privilege-escalation (2.0.0), vulnerability-exploitation (2.0.0) and web-attacks (2.0.0), added the new threat-intel-sweep (1.0.0) and added cross-source correlation (`xdr_response.atomics.correlation`: `aliases`, `sources`, `cross_workflow`). The three migrated workflows deleted their legacy `workflow.yaml` and `scenarios/` and carry their legacy scenarios as `legacy-*` fixtures. Phase 5 adds 72 scenarios (privilege-escalation 19, threat-intel-sweep 14, vulnerability-exploitation 20, web-attacks 19), for 400 in `tests/fixtures/workflows/` across 22 workflows. **No legacy spec remains.**

#### 14.13.1 Legacy alignment and the end-of-Phase-5 retirement

- Atomic `used_by` lists are recomputed from the remaining legacy specs (14.10.4 rule): every list is now `[]`, and every atomic README's "Used by" says that no legacy spec uses it and points to `docs/workflows/README.md`.
- `workflows/README.md` lists all 22 workflows as migrated (phases 2 to 5) with their hand-offs; the legacy table is gone. `tests/unit/workflows/test_cross_workflow.py` has no planned new workflow left (`PLANNED_NEW` is empty).
- Legacy replay has nothing left to replay: `simulate.py --legacy <id>` reports a usage error for every id ("known: []") and `tests/simulation/test_legacy_replay.py` has an empty parameter set. `tests/unit/workflows/test_framework_clis.py` pins that usage error and runs its child-process test over two sample workflow scenarios instead of `--legacy web-attacks` (14.10.4). The CI legacy replay loop is removed. Examples in `README.md`, `docs/testing.md`, `tools/simulator/README.md` and the `simulate.py` docstring use the `legacy-*` workflow scenarios (`--workflow web-attacks --scenario legacy-01-confirmed-web-shell`).
- `tests/unit/legacy/test_legacy_alignment.py::test_agents_follow_the_phase_2_to_5_model` checks the agent file of every discovered workflow (it was parametrized over the remaining legacy specs, so it had become empty) and compares whitespace-normalized text.
- **The 14.4.3 deletions were not applied at the integration step** (applied since by the legacy cleanup, 14.13.8). They delete files irreversibly and need the repository owner's go-ahead, which the integration run did not have. Until they are applied the legacy code is inert: it covers zero specs, `python -m xdr_plan check` still passes (repository checks of `atomic/` and the guardrails file), and nothing on the production path imports it. When the owner approves, the change is exactly 14.4.3: delete `engine/` (with `engine/README.md`), `src/xdr_response/lifecycle/plan_bridge.py`, `tools/simulator/legacy_replay.py`, `tests/simulation/test_legacy_replay.py`, `tests/unit/lifecycle/test_plan_bridge.py`, `tests/test_workflows.py`, `tests/test_engine.py`, `tests/unit/legacy/test_legacy_{expr_shim,guardrails,planner,repo,validate}.py` and `docs/deployment/guardrails.example.yaml`; replace the `atomic/<name>/` spec directories by `atomic/README.md` mapping each legacy name to its catalog action type and `xdr_response.atomics` name (the catalog `spec_ref` values `atomic/<name>` then resolve to that table); and in the same change: `pyproject.toml` packages and `pythonpath` drop `engine`; CI drops `python -m xdr_plan check`; `test_repo.py` keeps the YAML-parse, link, MITRE-generator and agent checks without `xdr_plan.repo`; `tests/safety/test_phase1_atomics.py` drops its legacy `plan_bridge` section and the `xdr_plan` imports; `tests/safety/test_read_zone.py` drops `plan_bridge.py` from `READ_ZONE_FILES`; `simulate.py` drops `--legacy` and the `engine` path; `generate_workflow_docs.py` drops its legacy-spec source; `test_legacy_alignment.py` keeps its agent and forbidden-key checks without `xdr_plan`; `integrations/*/README.md` link to `atomic/README.md`; `README.md`, `CONTRIBUTING.md`, `docs/testing.md`, `docs/testing/README.md`, `docs/deployment.md` and `docs/deployment/README.md` drop the plan-engine commands.

#### 14.13.2 Routing and hand-offs (14.10.2, 14.11.2 and 14.12.2 extended)

- **Phase 5 triggers.** privilege-escalation: T1068, T1548 (any sub-technique) and T1098 at 128 (below cloud-compromise 130, so T1098.001 and T1098.003 stay with cloud-compromise; above account-takeover, its hand-off target), titles at 104 (below cloud-compromise's directory-role titles at 105). vulnerability-exploitation: T1190 and T1203 at 135, exploitation titles at 115. web-attacks: T1505.003 at 145, T1595.002 at 125, web-attack, WAF and injection titles at 120. threat-intel-sweep: the threat-intelligence webhook (sources `threat_intel`, `threat_intelligence`, `threat-intel`), the schedule and sweep titles at 120, above every workflow it hands off to (c2 115, phishing 110, malware and account-takeover 100).
- **Resulting order of technique triggers:** ransomware and mfa-fatigue 200; dns-tunneling 170; lateral-movement 160; credential-dumping, unauthorized-rmm, mail-bombing (T1667) and exfiltration 150; web-attacks (T1505.003) 145; vulnerability-exploitation 135; cloud-compromise 130; privilege-escalation 128; malicious-powershell and web-attacks (T1595.002) 125; persistence 120; c2 115; phishing, password-spray and bec 110; malware and account-takeover 100; suspicious-authentication (parent T1078) 95. **Title triggers** add web-attacks and threat-intel-sweep 120, vulnerability-exploitation 115 and privilege-escalation 104.
- **vulnerability-exploitation and web-attacks.** web-attacks dropped its planned "T1190 with a URL" trigger (vulnerability-exploitation at 135 would always win). T1190 alone, and T1190 with T1595.002, route to vulnerability-exploitation; a web shell (T1505.003) routes to web-attacks even with T1190; T1595.002 alone and scan titles ("IPS exploit signatures from the scheduled vulnerability scan") route to web-attacks. Neither hands off to the other, so there is no cycle. A later vulnerability-exploitation hand-off of a confirmed web shell to web-attacks needs no priority change (145 over 135).
- **Pinned pairs (Phase 5):** T1068, T1548.002, T1098 and T1098.007 to privilege-escalation; cloud-compromise over privilege-escalation for T1098.003; privilege-escalation over account-takeover; credential-dumping over privilege-escalation; a privileged-role title to privilege-escalation; T1190 and T1203 to vulnerability-exploitation; vulnerability-exploitation over scanning and over malware; an exploit-attempt title to vulnerability-exploitation; a web shell with T1190 to web-attacks; T1595.002 and the scan title to web-attacks; the threat-intelligence webhook to threat-intel-sweep, also over malware; a sweep title over c2.
- **Phase 5 hand-offs (subjects per 14.11.2):** privilege-escalation to account-takeover (a compromised account behind the escalation); threat-intel-sweep to malware (a rated file indicator present on endpoints), c2 (an endpoint that reached a rated network indicator), phishing (a mailbox that received a delivered message carrying a rated indicator) and account-takeover (an account that signed in from a rated indicator); vulnerability-exploitation to persistence (a host with persistence after a successful exploit) and malware (a payload hash; never a hash rated CLEAN); web-attacks to malware (a confirmed web shell's hash). The subject of a **c2** hand-off is an endpoint hostname (new row of the 14.11.2 convention).
- **New cross-workflow tests** (`tests/unit/workflows/test_cross_workflow.py`): `test_phase5_handoffs`; `test_every_handoff_target_has_a_subject_convention` (every `handoff_to` target has a subject shape: an account for account-takeover, a mailbox for phishing, a hostname for persistence, unauthorized-rmm, credential-dumping and c2, a SHA-256 for malware); `test_scenario_handoff_subjects_are_the_entity_the_target_starts_from` (every `expect.handoffs` entry of the 400 scenarios); `test_every_attack_id_has_one_name_and_one_tactic_set_across_workflows` (the "checked at integration" rule of 14.11.2 and 14.12.2, now a test).
- **MITRE.** New: T1068 *Exploitation for Privilege Escalation* and T1548.002 *Bypass User Account Control* (TA0004); T1098 *Account Manipulation* and T1098.007 *Additional Local or Domain Groups* (TA0003, like T1098.001 and T1098.003); T1190 *Exploit Public-Facing Application* (TA0001, vulnerability-exploitation and web-attacks); T1203 *Exploitation for Client Execution* (TA0002); T1595.002 *Vulnerability Scanning* (TA0043); T1505.003 *Web Shell* (TA0003). threat-intel-sweep adds itself to T1078 (TA0001), T1204.002 (TA0002), T1566.001 and T1566.002 (TA0001). The generator's note on legacy tactics is replaced by the one-name, one-tactic-set rule. `generate_workflow_docs.py --write` regenerated `docs/mitre-mapping/` and `docs/workflows/README.md`.

#### 14.13.3 Contract amendments

- **`NetworkConnectionRecord` natural key adds `url` when the source reports one.** `natural_key()` is the 14.1.2 key plus `"url"` when `url` is not `None`. Two inbound requests of one source to one server at the same time with different URLs (an IPS or WAF event per exploited path) stay two records, so no exploited path is lost; a connection without a URL keeps its earlier key and id. The URL only enters the id hash, never an output. web-attacks drops the matching known limitation. Tested in `tests/unit/atomics/records/test_records_models.py::test_network_connection_key_adds_the_url_only_when_reported`.
- **Cross-source correlation (owner: correlation-evidence), as built.** Pure read-zone code (no adapter, guard, token or audit access; the read-zone lint covers it):
  - `aliases.EntityAliases`: one canonical spelling per entity (`EntityAliases.resolve(entities)`). A DNS-name ENDPOINT merges into its short name only when exactly one DNS name has that first label and the short name is also present (`models.canonical.endpoint_names`, the host identity of `same_endpoint`, the allow-lists and the critical-asset policy); an EMAIL_ADDRESS merges into the USER with the same value. Bare account names are never merged into a user principal name; ambiguous cases are never merged.
  - `correlate(..., merge_aliases: bool = False)` and `blast_radius(..., merge_aliases: bool = False)` (keyword-only): with `True` every mention is mapped to its canonical spelling before the link rules, and the critical-asset policy is checked against every spelling. The default output is unchanged. Both calls of one run must pass the same value.
  - `sources`: `SOURCE_FAMILIES`, `AGGREGATOR_PREFIX`, `source_family(integration)`, `independent_families(integrations)`, `worst_verdict(verdicts)`, `SourceObservation`, `EntityProfile`, `build_profile(entity, records, *, aliases=())`, `profile_entities(results | RecordIndex, *, entities=None, merge_aliases=True)`. An aggregator (`cisco_xdr`, `microsoft_cloud`, `splunk`) counts only when no first-hand source reported the entity; the entity's own rating (`verdict`, enrichment only) is kept apart from `activity_verdict`, and contradictions between independent ratings are flagged.
  - `cross_workflow`: `RunSnapshot`, `correlate_workflows(runs, *, window=DEFAULT_CROSS_WINDOW, ignore=(), caps=None) -> CrossWorkflowCorrelation`, `rollup_blast_radius(runs, *, caps=None) -> BlastRadiusRollup`, `link_confidence(first_hand_families, *, reputation_only=False, ip_only=False)`, `IncidentLink`, `SharedEntity`, `IncidentCitation`, `IncidentGroup`, `IncidentSummary`, `BlastRadiusRollup`, `RollupCriticalAsset`, `LinkBasis`, and the constants `DEFAULT_CROSS_WINDOW` (7 days), `LINK_CONFIDENCE_BASE` 40, `LINK_CONFIDENCE_STEP` 15, `LINK_CONFIDENCE_MAX` 85, `REPUTATION_ONLY_CONFIDENCE` 30, `SHARED_IP_ONLY_CAP` 50. `runs` are `WorkflowRun` objects (duck-typed protocol) or snapshots. Two incidents link when an endpoint, user, hash, domain, URL or IP is in both runs' blast-radius scope and cited by records of each run (every citation checked with `RecordIndex.require`); private and local IPs, `ignore` entities and evidence further apart than the window never link (each noted); degraded sources are reported and never block a link; output does not depend on input order. Link confidence counts only independent first-hand source families. A group's rollup unions scopes, takes the strictest caps and lists every critical asset with a visible warning, never dropped (also when ignored for linking).
- **c2 README.** "Known limitations" lists the sanctioned-binary limitation of 14.12.7 (12 bullets for 12 limitations).

#### 14.13.4 Decisions on the Phase 5 reports

- **Cross-workflow correlation stays informational and is not wired into the lifecycle in Phase 5.** `correlate_workflows` and `rollup_blast_radius` are callable over finished runs (analyst tooling, reports); the runner and the orchestrator do not call them, and `CorrelationSpec` has no `merge_aliases` flag yet. When wired: one flag passed to `correlate` and `blast_radius` together; the output may add context and warnings to a package but may never change another incident's package, approval level or decision (a critical asset unclassified in one incident is shown with `RollupCriticalAsset.unclassified_in`, never re-leveled from outside).
- **threat-intel-sweep preventive blocks: confirmed.** A rated indicator (MALICIOUS aggregate, or a security product's own MALICIOUS verdict; never one vendor alone, never the feed's claimed confidence) is proposed for a block even when the sweep finds no hit, with its enrichment records as evidence (scenario `edge-no-hits`). Every block needs a human approval like any other action. An owner who wants hit-only blocks adds `when="item.hit_count > 0"` to the four block rules and sets `edge-no-hits` to `package: false`.
- **threat-intel-sweep "hits over the indicator cap": confirmed** as the blast-radius `max_indicators` cap: every block over the cap is ELEVATED with a warning (`edge-hits-over-indicator-cap`). The sweep's own 25-indicators-per-type limit uses the framework's not-queried note.
- **privilege-escalation.** A privileged group membership arrives as a `RoleChangeRecord` with the group name as `role_name` and no `role_definition_id`; groups are recognised through `PRIVILEGED_GROUP_NAMES` and their removal is a manual step. An account an anomalous change made privileged, with no sign-in before the grant, is treated as attacker-created or staged and proposed for disable under ELEVATED approval. A change reference is taken only from `incident.trigger.change_reference`, shown as unverified, and never withholds or creates a recommendation. On a tenant the workflow depends on typed role-change records from another source until a VERIFIED directory audit read exists (documented in `known_limitations`).
- **vulnerability-exploitation and web-attacks.** IPS (Secure Firewall) and WAF (Cloudflare) are not framework integrations; their events arrive as Cisco XDR incidents and sightings or Splunk rows (generic records). The approved `block_url` and `block_ip` land on Umbrella, Defender indicators, Meraki or the Cisco XDR native action, which protect users and managed endpoints, not inbound internet traffic; the inbound rule is a manual step (`apply_vendor_fix:<service>`, `waf-virtual-patch:<url>`). Patch status comes only from `trigger.patch_status`. Fixture IPs inside the lab's production range 203.0.113.0/26 and internal 10.x sources were renumbered, each change recorded in the scenario description.
- **Read-only allow-list context for hooks (14.12.4) stays deferred.** The safety-relevant part holds in the framework (`PackageBuilder` exclusions, sanctioned-binary withholding, and since 14.13.6 the `RecommendationRule.indicators` withholding of an action that rests only on allow-listed or non-public indicators). vulnerability-exploitation documents that an allow-listed scanner's hostile traffic can still propose the virtual patch of the path it scanned (the source block itself is excluded visibly).
- **README headings.** "16 sections" in the brief is the 17 headings of 14.5.4 (required and optional integrations as two sections), as in 14.10.6, 14.11.5 and 14.12.4.
- **Not applied (each needs a VERIFIED vendor schema or endpoint first, 14.9.4):**

| Request (from) | Decision |
|---|---|
| A group-membership record kind, or an assignment type (`directory_role` / `group`) on `RoleChangeRecord` (privilege-escalation) | Carried with the VERIFIED Entra directory audit and group membership reads; until then group recognition by name and a manual removal step. |
| `UserProfileRecord.created_at` from Graph `createdDateTime` (privilege-escalation) | Carried: not among the VERIFIED user fields of docs/integrations.md. |
| A change-management read (ticket or reference lookup) (privilege-escalation) | Carried: no change-management integration; the incident's reference stays unverified context. |
| VERIFIED Entra directoryAudits, group membership, servicePrincipals and oauth2PermissionGrants reads; group-membership removal and application-permission or service-principal revocation writes; a sign-in device id to endpoint atomic (privilege-escalation; 14.10.5, 14.12.4) | Carried; manual steps meanwhile. |
| Typed mapping of Cisco XDR sightings and Defender XDR hunting rows (EmailEvents, EmailAttachmentInfo, EmailUrlInfo, DeviceFileEvents, DeviceNetworkEvents, sign-in tables) (threat-intel-sweep) | Carried (14.10.5, 14.11.4, 14.12.4): generic records on a tenant; asset actions rest on typed sources. |
| Secure Email Threat Defense message search by sender, URL or attachment hash; Defender for Office 365 analyzed-email search; a sender-block write; Umbrella DNS activity reads; Secure Endpoint events search (threat-intel-sweep) | Carried: undocumented or UNVERIFIED; sender block is the manual step `block_sender:<address>`. |
| IPS and WAF integrations, inbound WAF, reverse-proxy or IPS rule writes, a vulnerability-management source (vulnerability-exploitation, web-attacks) | Carried: manual steps (above). |

#### 14.13.5 Exit criteria (section 12, Phase 5)

1. Each of the four `workflows/<X>/README.md` has the 17 headings of 14.5.4 (brief 46's 16 items, required and optional integrations as two sections): `python tools/validation/check_workflow_readmes.py` reports "22 workflow README(s) OK" (all workflows).
2. Every workflow scenario passes in its modes (dry run and simulated live) through the lifecycle with simulated adapters, including the implicit assertions of 14.5.3 (`tests/simulation/test_workflow_scenarios.py`); each Phase 5 workflow has the minimum scenario set and every rule is PROPOSED in at least one scenario. The real adapters are exercised over `httpx.MockTransport` by the integration and vendor tests.
3. Cross-workflow correlation tests: `tests/integration/test_cross_workflow_correlation.py` (real dry-run detections of the phishing, account-takeover and c2 fixtures linked into one storyline, aliases, source families, link confidence, critical-asset rollup warnings, no state change and no adapter call) and the routing and hand-off tests of 14.13.2.
4. `generate_workflow_docs.py --check` is clean; `tests/safety/test_read_zone.py` passes; no legacy spec or legacy scenario remains.
5. The whole suite passes with `python -m pytest -q -p no:cacheprovider`.

#### 14.13.6 Safety review, Phase 5 round 1 (workflow safety)

Fixes for the defects proven by `tests/safety/test_p5_workflows.py`. Binding like the rest of 14.13; context is only ever added, nothing is withheld on a guess, and every withheld action is shown as considered with its records.

- **Rules that rest only on an indicator the allow-list excludes (`RecommendationRule.indicators`).** New optional expression (framework, every workflow): a list of `"<block action>:<target>"` entries naming the indicators whose meeting alone the recommendation rests on. When the allow-list excludes the block of **every** entry (`AllowlistPolicy.excluded_reason` of that block: `never_block` IPs, CIDRs, domains, URLs or hashes, an approved tool, a non-public address, an internal domain) and does not already exclude the target itself, the runner (`_allowlisted_indicators`, after `_sanctioned_binaries`) withholds the action as `ALLOWLISTED` with a `Consideration` citing the rule's records. One entry that is not excluded keeps the action proposed; a malformed entry is a rule `ERROR`. threat-intel-sweep `revoke_sessions_signed_in_from_indicator` passes `item.indicators` (`accounts[].indicators` = `block_ip:<ip>` for every rated IP the account signed in from): an account that signed in through the organisation's own infrastructure (`never_block.ips` 192.0.2.53, `never_block.cidrs` 192.0.2.0/28) or from a private or carrier-grade NAT address that a feed listed is no longer revoked (every user behind that egress would be). The account-takeover hand-off stays (a suggestion only).
- **Accounts in a critical group (framework and threat-intel-sweep).** `_record_asset` (runner, every workflow) now also adds the `groups` and `roles` of the run's `UserProfileRecord`s of a USER or EMAIL_ADDRESS target (`_record_directory`), so an account the identity source lists in Executives, Service Accounts or Domain Admins is ELEVATED with a warning whatever the rule's asset expression says. threat-intel-sweep `accounts[]` also carries `groups`, `roles` and `privileged` from the profile and the revocation rule passes them as `asset`. No other fixture changed.
- **threat-intel-sweep ratings.** A connection or DNS record rates a network indicator only when its destination is exactly the indicator (a verdict about `bad.cloudhost.test` never rates `cloudhost.test`); a process event's verdict rates only its own image (never a destination it reached); and for a domain, IP or URL a record's MALICIOUS verdict never overrides a CLEAN enrichment aggregate: the indicator stays unrated (`contradicted: true`, rating CLEAN) and is shown as considered with the flagged hit records and the CLEAN enrichment records. File hashes and sender addresses keep the 14.13.4 rule (a security product's own MALICIOUS detection rates them). A subdomain record's verdict is named in the parent's basis.
- **privilege-escalation: a sanctioned binary never isolates its host or contains its users.** A host whose only basis is files rated MALICIOUS (no active MALICIOUS detection) lists those hashes as `hosts[].binaries`; an account compromise that rests only on using such hosts carries their union, and so do the anomalous changes, application grants and the account facts built on it (`changes[].binaries`, `apps[].binaries`, `accounts[].revoke_binaries`, `accounts[].disable_binaries`; `[]` as soon as one reason stands on its own: a self-assigned grant, an application rating, a strong identity indicator). Both isolation rules, `remove_unauthorized_role`, `revoke_escalation_sessions` and `disable_escalation_identity` pass them as `binaries`, so the runner's `_sanctioned_binaries` withholds them (ALLOWLISTED, considered) when every hash is sanctioned. The account-takeover hand-off is still suggested.
- **web-attacks: the incident's observable list is not evidence.** A URL is exploited only when a flagged or attacker request that was not blocked reached a compromised server, or when the incident names both the URL and the compromised server **and** a request record to that server mentions the URL. A URL only the incident names is shown as considered (`block_url:<url>`, citing the server's compromise records) and never built. Fixture consequence: `legacy-01-confirmed-web-shell` no longer proposes `block_url:https://shop.example.net/upload` (considered; manual steps only `review-web-root:WEB-SHOP-01`; 2 controls) and `legacy-04-guardrail-skips` no longer builds the excluded `block_url:https://pay.example.com/upload` (considered; no `waf-virtual-patch` manual step); `test_web_attacks_lifecycle.py` follows.

#### 14.13.7 Safety review, Phase 5 round 2 (workflow safety)

Fixes for the round 2 defects proven by `tests/safety/test_p5_workflows.py` (`test_r2_*`). Binding like the rest of 14.13; context is only ever added and every withheld action is shown as considered with its records.

- **threat-intel-sweep: a carrier message never rests on an allow-listed indicator alone.** `messages[].block_indicators` lists `<block action>:<value>` (`block_domain`, `block_url`, `block_hash`, `block_ip`) for every rated indicator the message carries, and `quarantine_carrier_message` passes it as `indicators`. When the allow-list excludes the block of every one (the organisation's own domain, a `never_block` service domain or hash, the approved RMM tool's domain or hash), the runner's `_allowlisted_indicators` withholds the quarantine (`ALLOWLISTED`, shown as considered `quarantine_email:<message id>`). A rated sender address has no block action (`block_sender` is a manual step), so a message that carries one keeps `[]` and stays proposed.
- **Critical groups and tags under another spelling of the host (framework).** `_record_asset` (runner, every workflow) also adds the `groups` and `tags` of every `EndpointRecord` whose hostname is `same_endpoint` with the host of an ENDPOINT, FILE, PROCESS or PERSISTENCE_ITEM target (`_record_endpoint_labels`). A host reported by its short name with the connector and by its DNS name with the `Domain Controllers` group or the `production` tag is ELEVATED with a warning in every workflow (privilege-escalation, web-attacks, threat-intel-sweep, as vulnerability-exploitation already was).
- **Password parameters in URLs.** `SENSITIVE_KEY_PATTERN` gains the exact keys `pass`, `pwd` and `pw` (the common names of a password parameter in web forms and URL query strings). `Redactor.redact_text`, `redact_url` and `normalize_target(URL)` / `url_without_credentials` therefore redact or drop `?pass=`, `&pwd=` and `pw=` values: they reach neither the package, notes, notifications, decision report or audit trail, nor a vendor in a `block_url` call. A key-value pair named `pwd` (a working directory in an environment dump) is redacted too: the cost of never leaking a password.
- **web-attacks: the investigated server's own address is never an attacking source.** `_Facts.own_ips` holds every address an investigated `EndpointRecord` reports in `ip_addresses`; such an address is never rated (`sources[].own: true`, `rated: false`, so `block_attacking_source` never builds it and it never makes a URL exploited as a "rated source"). When its requests are flagged or enrichment flags it, it is shown as considered (`block_ip:<address>`, citing the endpoint record and the flagged requests), matching the vulnerability-exploitation contract.

#### 14.13.8 As built: legacy cleanup (end-of-Phase-5 retirement applied)

Applied in one change, exactly as 14.13.1 lists it; binding like the rest of 14.13. Nothing on the production path changes and the owner rule is untouched: workflows still only investigate and recommend, every state-changing action (session revocation, release and restoration included) waits for a human approval, critical assets are ELEVATED with a visible warning, and restoration needs its own release approval.

- **Deleted:** `engine/` (with `engine/README.md`), `src/xdr_response/lifecycle/plan_bridge.py`, `tools/simulator/legacy_replay.py`, `tests/simulation/test_legacy_replay.py`, `tests/unit/lifecycle/test_plan_bridge.py`, `tests/test_workflows.py`, `tests/test_engine.py`, `tests/unit/legacy/test_legacy_{expr_shim,guardrails,planner,repo,validate}.py`, `docs/deployment/guardrails.example.yaml`, the `atomic/<name>/` spec directories and the legacy plan-bridge section of `tests/safety/test_phase1_atomics.py` (its subject no longer exists; every other test in that file is unchanged). Nothing was left to migrate: every legacy scenario already runs as a `legacy-*` workflow scenario, and every key of the legacy guardrails file has its runtime home in `config/` (critical assets, allow-lists, thresholds caps).
- **`atomic/README.md`** maps each legacy name to its catalog action type, category, `xdr_response.atomics` name (`read_atomics()`, `containment_builders()`, or the notification service for `notify-soc`; `create-ticket` is a catalog bookkeeping operation) and catalog rollback. `tests/test_repo.py::test_catalog_spec_refs_resolve_to_the_atomic_table` pins that every catalog `spec_ref` resolves to exactly one row; `integrations/*/README.md` link to the table.
- **`tests/test_repo.py`** keeps the YAML-parse, link, MITRE-generator and agent checks without `xdr_plan.repo` (workflow ids are the `workflows/<id>/README.md` directories, equal to the discovered definitions) and adds `test_nothing_references_retired_legacy_paths` (only this document, `CHANGELOG.md` and the tests that pin the retirement may name a retired path). `tests/unit/legacy/test_legacy_alignment.py` keeps the agent, rename, wording and forbidden-key checks without `xdr_plan` (the forbidden keys are `xdr_response.config.loader.FORBIDDEN_KEYS`, checked over `config/`, `docs/` and every workflow scenario) and pins that every retired path stays gone.
- **Tools.** `simulate.py` drops `--legacy` and the `engine` path and adds `--all-workflows` (every scenario of every discovered workflow in the selected mode, one child process per scenario, a summary line). `generate_workflow_docs.py` drops its legacy-spec source (`collect(root, definitions)`); the generated documents were regenerated (wording only). `pyproject.toml` packages and `pythonpath` drop `engine`. `tests/safety/test_read_zone.py` drops `plan_bridge.py` from `READ_ZONE_FILES`.
- **CI** (`.github/workflows/ci.yml`) drops `python -m xdr_plan check` and runs: the full suite, `check_workflow_readmes.py` (README validator), `generate_workflow_docs.py --check` (MITRE generator check), `validate_config.py`, `check_endpoints.py`, the bundled incident scenarios live and dry run, `simulate.py --all-workflows --check` in dry run and with `--live`, and the tests-only sample workflow.
- **Docs.** `README.md`, `CONTRIBUTING.md`, `docs/testing.md`, `docs/testing/README.md`, `docs/deployment.md`, `docs/deployment/README.md`, `tools/simulator/README.md` and `workflows/README.md` drop the plan-engine commands. Earlier subsections of this document keep their references to the retired paths as design history.

#### 14.13.9 Documentation pass (Phases 0 to 5 complete)

Documentation only; no code, contract or behaviour change. `README.md` states that Phases 0 to 5 are complete and lists the 22 workflows with phase, version, default severity and links; `CHANGELOG.md` records Phase 1 as 0.3.0 and Phases 2 to 5 with the legacy cleanup as 0.4.0 (the package metadata still reads 0.1.0); `docs/deployment.md` 5.2 describes enabling workflows (discovery, routing, required integrations, a subset catalog, dry run per process) and the intake mapping on the Cisco XDR side; `docs/testing.md` lists the Phase 1 to 5 test layers and safety files. `docs/samples/` holds simulator output for ransomware (dry run), credential-dumping (ELEVATED) and threat-intel-sweep (degraded source); `tests/simulation/test_docs_samples.py` reruns each sample's simulator command and fails on any difference.

### 14.14 As built: gap fixes after the Phase 5 review (binding)

A critic review of the finished Phases 0 to 5 found that a failed source could still make actions vanish, that the simulated adapters could do more than the real ones, and that several documents were out of date. These fixes are binding like the rest of section 14. The owner rule is unchanged and was tightened, never relaxed: workflows still only investigate and recommend, every state-changing action (session revocation, release and restoration included) waits for a human approval, critical assets stay ELEVATED with a visible warning, and restoration needs its own release approval. What the fixes did **not** close is listed in section 15.

#### 14.14.1 Degraded-source accounting in the runner

Owner rule: a failed or degraded source never blocks a recommendation that other evidence backs, and nothing is dropped silently. `WorkflowRunner._degraded_accounting` (`src/xdr_response/workflows/runner.py`) runs after the rules and hooks of every workflow, only when a read FAILED, and never proposes anything:

- When a read about subject `S` failed and a rule whose target kind fits `S` produced nothing for `S` (no outcome, no built recommendation, no consideration), the action becomes a `Consideration` `"<action>:<S>"` that names the failed read and cites the records **of other sources** that mention `S`.
- When no answering source holds a record about `S`, but the run knows `S` (the failed read was about it, or the incident's observables or users name it, including incident entities no step read because the step took its subjects from the failed source), the action gets a `NeedsInvestigation` entry (`subject`, `reason`, `failed`, `record_ids`). `WorkflowRun.needs_investigation` and `WorkflowSummary.needs_investigation` carry them; the notes print `needs investigation, not proposed: ...`; the analyst notification lists them under "Needs investigation (a failed source held the only evidence; not proposed)". The analyst re-runs the investigation when the source recovers, or decides by hand.
- A `NO_EVIDENCE` outcome in a degraded run is not an assessment: it is annotated "decided in a degraded run" and still gets an entry. Considerations about a target with a failed read get `; degraded: <integration> failed for <atomic> <subject>`.
- Allow-listed targets and URLs already covered by a domain block are skipped, so a workflow's own policy is never bypassed. Healthy runs have an empty list.
- Limit (deliberate): a target that only the failed source reported, or that appears only in the incident's free text or incidentally in another record, gets no entry of its own; the run still lists the failed integration under `degraded source:`.

Tests: `tests/safety/test_degraded_sources.py` (the critic's cases, a sweep that fails each expected source of every `tp-approve-all` scenario, healthy runs empty, a self-check that the sweep fails with the accounting switched off) and the shared helper `tests/fixtures/degraded.py`, used without skips by `tests/safety/test_p2_workflows.py` to `test_p5_workflows.py`.

#### 14.14.2 Degraded-source fallbacks in workflow hooks

Where a failed read can hide the link between an incident entity and its evidence, the workflow's hook assesses the entity on the evidence that remains instead of dropping it, and never rates it higher than that evidence allows. Examples: `phishing` assesses an account the incident names on its identity records when the message, click or endpoint reads failed (`CLICK_TIE_ATOMICS`); `privilege-escalation` treats a role grant made by or to an incident account whose endpoint read failed as SUSPICIOUS (severity 60, never MALICIOUS) and still proposes the role removal, revocations and disable it backs (sample: [docs/samples/privilege-escalation-degraded-endpoint.md](samples/privilege-escalation-degraded-endpoint.md)). `account-takeover`, `bec`, `exfiltration`, `threat-intel-sweep` and `unauthorized-rmm` apply the same rule to their own entities.

#### 14.14.3 Production parity of the simulated adapters

The simulated adapters (`src/xdr_response/integrations/simulated.py`) do exactly what the real adapters support and verify, never more:

- `build_simulated_manifest` and `simulated_adapter_class` intersect each family's actions with the real manifest's `supported_actions` and mark only the real `verifiable_actions` as verifiable. A name with no real manifest raises `ValueError`. There is no lab-only mode: the `parity=` keyword, `LabCapabilityGap` and the simulator's "Lab-only capability" section are gone, and `simulate.py --production-parity` is still accepted for old command lines and changes nothing.
- Consequences in every scenario and sample: Secure Endpoint isolates and releases only and verifies nothing; Cisco XDR native actions, Defender for Office 365 and Intune verify nothing; Defender for Endpoint verifies isolation but not indicators; Umbrella does not block IPs. `terminate_process`, `quarantine_file`, `remove_persistence`, `reset_password`, `reset_mfa`, `revoke_app_credentials` and `remove_application` run nowhere (section 15.2).
- The router is unchanged (native first, then the first enabled adapter with a VERIFIED write). An action no enabled adapter can execute is `UNROUTED`: shown with its evidence for manual handling, never executed, never dropped. `atomics/containment/builders.py` adds the allow-list entry to the `unrouted_reason` of an allow-listed unrouted target ("allow-listed, never block it by hand").
- Scenario expectations (426 scenarios over 22 workflows) were regenerated: CONTAINED became PARTIALLY_CONTAINED where an isolation or indicator cannot be read back, RESTORED became PARTIALLY_RESTORED or RESTORATION_FAILED with AWAITING_RELEASE_APPROVAL. `check_coverage` counts a rule whose action no real adapter can execute as covered when a scenario expects it UNROUTED, and requires some executable action to be proposed. The `edge-defender-hash-block` scenarios (credential-dumping, lateral-movement, phishing) show the hash block routed to Defender for Endpoint.
- Not changed: simulated **reads** still follow the families (some fixtures ask a simulated Secure Endpoint or Defender for reads the real adapters do not list), and native Cisco XDR routes cannot be exercised in the lab because the read facade returns no response-action listing for a simulated `cisco_xdr`.

Tests: `tests/unit/integrations/test_simulated_parity.py` (every real integration against every family combination), `tests/unit/integrations/test_simulated.py`, `tests/simulation/test_production_parity.py` (end to end on every `tp-approve-all` and `release-restoration` scenario, no lab-only output), `tests/simulation/test_docs_samples.py` (no sample shows a lab-only capability or a VERIFIED Secure Endpoint result).

#### 14.14.4 Audit forwarding (outside the response path)

`xdr_response.audit.forwarding.forward_audit_file` and `tools/deployment/forward_audit.py` copy a verified audit trail to Splunk HEC through `SplunkAdapter.forward_audit` (VERIFIED `POST {hec_url}/services/collector/event`, a bookkeeping write that redacts each event again). It verifies the whole hash chain first and forwards nothing when the chain is broken, sends records in chain order after a checkpoint (the last acknowledged `seq`), stops at the first failure and resumes there next run (at-least-once delivery). It only reads the trail and runs from a scheduler next to the runtime, never inside the response path, so a slow or unavailable collector can never delay containment. The JSONL trail stays the system of record. Tests: `tests/unit/audit/test_audit_forwarding.py`.

#### 14.14.5 REQUEST_MORE_INVESTIGATION in every workflow

`more-investigation` is a required scenario (`tools/simulator/workflow_scenario.py` `REQUIRED_SCENARIOS`; only `legacy` remains optional), and all 22 workflows have `tests/fixtures/workflows/<id>/more-investigation.yaml`. After REJECT or REQUEST_MORE_INVESTIGATION the scenario harness checks implicitly: no token, no execution report, no state change, no control, a later approval of the same package is refused, and REQUEST_MORE_INVESTIGATION leaves the incident `NOT_STARTED`.

#### 14.14.6 Approval tests through the executor

The four required tests of section 10 now also go through `ContainmentExecutor` with a real `ActionRunner` around the real adapter (no token, and an unsigned token bound to the package), in pristine and production wiring, and assert that the refusal is audited (`GUARD_DENIED`).

#### 14.14.7 Documentation pass

`docs/samples/` was regenerated after 14.14.3 and covers 7 workflows (ransomware, account-takeover, phishing, credential-dumping, threat-intel-sweep, privilege-escalation, malware), including restoration tables that read `RESTORED`, `PARTIALLY_RESTORED` and `RESTORATION_FAILED`. Sections 3.1 and 10 describe the test layout as built. `integrations/<dir>/README.md` exists for all 16 runtime integrations (plus the spec-only Cloudflare and ServiceNow pages); each states its VERIFIED and UNVERIFIED operations as listed in `docs/integrations.md` and links the atomic table. `.claude/agents/wf-*.md` point at the definition package, analyst README, fixtures and tests of their workflow. `docs/workflows/README.md` and `docs/mitre-mapping/` were regenerated. Section 15 lists the known gaps.

---

## 15. Known gaps and owner decisions

The framework is complete for its contract (sections 12 to 14), but a production deployment meets the limits below. None of them weakens the owner rule: where automation cannot act or cannot confirm, it says so and hands the step to a human; it never guesses, never skips silently and never approves. Each entry says what it means operationally and what would close it. Closing any of them follows the usual rules: a vendor endpoint is implemented only after `docs/integrations.md` lists it as VERIFIED with a source (`tools/validation/check_endpoints.py` enforces it), a new state-changing method is `@state_changing` and covered by `tests/safety/test_approval_bypass.py`, and the simulated adapters follow the real manifests automatically (14.14.3).

### 15.1 Actions the real adapters cannot verify (UNVERIFIED read-back endpoints)

| Integration | Executes (VERIFIED write) | Read-back | Result after execution |
|---|---|---|---|
| `secure_endpoint` | `isolate_endpoint`, `release_endpoint` | `GET /v1/computers/{guid}/isolation` is UNVERIFIED | `UNABLE_TO_VERIFY` |
| `cisco_xdr` (native response actions, respond/trigger) | block domain, URL, IP and hash, isolate, disable user, quarantine or delete email, and their reversals | `verify_native_action` is UNVERIFIED | `UNABLE_TO_VERIFY` |
| `defender_endpoint` | indicator `block_*` / `unblock_*` (and isolation, which **is** verified) | indicator list read is UNVERIFIED | `UNABLE_TO_VERIFY` for indicators |
| `defender_o365` | `quarantine_email`, `delete_email`, `release_email` | remediation status read is UNVERIFIED | `UNABLE_TO_VERIFY` |
| `intune` | `lock_device` (remoteLock) | the managed-device read is VERIFIED, but the `actionName` of the lock in `deviceActionResults` was not read, so the lock cannot be matched | `UNABLE_TO_VERIFY` |
| `entra` | `confirm_user_compromised` | risky-user read is UNVERIFIED | `UNABLE_TO_VERIFY` |

`block_hash` and `unblock_hash` therefore never verify anywhere today. Verified end to end: Entra (disable, enable, revoke sessions, role removal and restore), Umbrella (domain and URL blocks), Meraki (IP and client blocks), Secure Email (quarantine, release, delete) and Defender for Endpoint isolation.

**What `UNABLE_TO_VERIFY` means operationally.** The action **was executed** after the human approval; automation only cannot confirm the vendor state. The result row carries `ATTENTION` and a "verify manually" line, the analyst checks the state in the vendor console, and the action is never retried automatically. With `verification.unable_to_verify_counts_as_contained: false` (the default in `config/thresholds.yaml`) one such action makes the containment `PARTIALLY_CONTAINED`; on release the control is kept `RELEASE_FAILED` and the incident stays in `AWAITING_RELEASE_APPROVAL` (restoration `PARTIALLY_RESTORED`, or `RESTORATION_FAILED` when no release could be confirmed). "Failed" there means "not confirmed": the release call did execute. Samples: [ransomware-release-restoration.md](samples/ransomware-release-restoration.md), [phishing-release-restoration.md](samples/phishing-release-restoration.md).

**Owner decisions.** (1) Keep the default (recommended): an unconfirmed action stays visible as needing attention. Setting the flag to `true` counts `UNABLE_TO_VERIFY` as contained and released, which hides the manual check; it is a deliberate configuration change for the owner (`config/thresholds.yaml` under change control), never a workflow choice. (2) Whether the restoration wording `RESTORATION_FAILED` should become a distinct "released, not confirmed" result (a change in `execution/outcome.py` and `restoration/`, with its tests).

**What would close it.** Verify each read-back endpoint against current vendor documentation (Secure Endpoint isolation status, Defender indicator list, Graph remediation status, Cisco XDR response-action status, Entra risky users), record it as VERIFIED with a source in `docs/integrations.md`, implement the `VERIFY` operation in the adapter and add the action to the manifest's `verifiable_actions` with a mocked-vendor test in `tests/unit/vendors/`. For Intune, read the exact `actionName` of the remote lock in `deviceActionResults` from the vendor documentation and match it in the existing device read.

### 15.2 Containment atomics that are recommendation-only (no VERIFIED write)

`terminate_process`, `quarantine_file` (and its rollback `restore_file`), `remove_persistence`, `reset_password`, `reset_mfa`, `revoke_app_credentials` and `remove_application` have no VERIFIED write endpoint in any adapter (Secure Endpoint and Defender for Endpoint process and file remediation, Entra password, MFA and app-credential operations, Intune and Defender application removal are UNVERIFIED; `remove_persistence` has no catalog integration at all). The adapter methods raise `UnverifiedEndpointError`.

**What happens.** The builder still returns the recommendation with its evidence and scores, but with no route: the rule outcome is `UNROUTED` ("no enabled adapter has a VERIFIED write for ...; manual handling required"), the action is **not** in the package, and the analyst notification lists it under "Not routable (no capable adapter)". Workflows that know a step has no VERIFIED write list it as a manual step instead (a `Consideration(manual=True)`, shown under "Manual steps (no verified automated action; not in the package)", for example `credential-reset:<host>` in `credential-dumping` and `remove_persistence:<host>/<item>` in `persistence`). The documented manual step is: the analyst performs the action in the vendor console (or through the help desk for password and MFA resets), records it in the incident, and verifies it there. Nothing is executed automatically and nothing is dropped. Workflows that still recommend `terminate_process` or `quarantine_file`: `c2`, `dns-tunneling`, `malicious-powershell`, `malware`, `persistence`, `unauthorized-rmm`, `threat-intel-sweep`. The same applies to `block_hash` in a tenant whose only endpoint product is Secure Endpoint; enabling Defender for Endpoint (file indicators) or a native Cisco XDR response action routes it (sample: [credential-dumping-defender-hash-block.md](samples/credential-dumping-defender-hash-block.md)). The builders `delete_malicious_email`, `intune_device_action` and `remove_persistence` are registered in the workflow builder map (`workflows/definition.py`) but no workflow uses them today. Tests that need verified execution and release paths (the safety suites for execution integrity and restoration authority) run the bundled incidents in a lab that also enables Defender for Endpoint and drops hash indicators (`tests/fixtures/verified_lab.py`); safety checks of what is or is never recommended count `UNROUTED` outcomes as recommendations, so an unroutable termination or hash block is still checked.

**What would close it.** Verify the vendor write endpoint and its read-back (for example the Defender for Endpoint machine actions for stopping a process and quarantining a file, Microsoft Graph authentication-method and password operations, application credential removal), add it to `docs/integrations.md` as VERIFIED, implement the `@state_changing` method and the `VERIFY` operation, add the action to `supported_actions` (and `verifiable_actions`), and give `remove_persistence` a catalog integration. The workflows need no change: the router picks the action up and the rule moves from `UNROUTED` to `PROPOSED`, still behind human approval.

### 15.3 No production approver identity provider, intake service or analyst UI

The interfaces exist: `xdr_response.interfaces.ApproverAuthenticator` (authenticate a credential into an `AuthenticatedPrincipal` with kind and roles), the `ApprovalEngine` that accepts only `HUMAN` principals, the lifecycle orchestrator with `bootstrap()` as the deployment entry point, and the decision card, containment report and release checklist renderers. What is missing:

- **Identity provider.** Only `InMemoryApproverAuthenticator` (tests, lab and simulator; salted hashes in memory, lost on restart) is shipped. A deployment must implement `ApproverAuthenticator` against its IdP (OIDC token or SAML assertion validation, mapping only real analysts to `PrincipalKind.HUMAN` and copying the analyst and `xdr-elevated-approver` roles; service principals and bots map to `SERVICE` or `AUTOMATION`, which can never approve).
- **Intake service.** There is no HTTP service. The Cisco XDR side sends only the incident ID ([tools/deployment/xdr-trigger-workflow.md](../tools/deployment/xdr-trigger-workflow.md)); the deployment hosts a process that re-reads the incident, builds the `Incident` and calls the orchestrator ([docs/deployment.md](deployment.md) sections 1, 6 and 8).
- **Analyst decision UI.** Decisions (approve all, approve selected, reject, request more investigation, release) are library calls with an authenticated credential; the rendered decision card and checklists are text, Markdown and JSON.
- **Scheduler.** `threat-intel-sweep`'s `schedule` trigger is declarative only: `schedule` and `manual` triggers never match on their own, so something must create the sweep incident on a schedule.

**Owner decision.** Choose the IdP (and the group names for the analyst and elevated approver roles) and where the intake, the UI and the scheduler are hosted (for example a small internal web service behind SSO next to the orchestrator). **What would close it.** An `ApproverAuthenticator` implementation for the chosen IdP with tests that non-human and unauthenticated principals are refused; an intake service that accepts only an XDR incident ID over an authenticated channel; a decision UI that shows the full decision card (evidence, both scores, every ELEVATED warning, UNROUTED and needs-investigation items) and submits decisions with the analyst's own credential; a scheduler that raises sweep incidents. None of them may hold the signing key outside the approval engine or approve on anyone's behalf.

### 15.4 Notifications, ticketing and audit forwarding write locally

- **SOC notifications** go to a local append-only JSONL outbox (`JsonlNotificationSink`, default `var/notifications/outbox.jsonl`, set by `bootstrap(notifications_path=...)` or `XDR_RESPONSE_NOTIFICATIONS_PATH`). `XdrIncidentNoteSink` always answers `NOT_DELIVERED_UNVERIFIED` because the Cisco XDR incident note endpoint (`cisco_xdr.add_incident_note`) is UNVERIFIED; nothing is posted to XDR, email or chat.
- **Ticketing.** `create_ticket` is a catalog bookkeeping operation with no executing adapter; ServiceNow exists only as a spec page ([integrations/servicenow](../integrations/servicenow/README.md)).
- **Audit forwarding** exists but is not automatic: `tools/deployment/forward_audit.py` forwards a verified trail to Splunk HEC when a scheduler runs it (14.14.4). The runtime never forwards on its own, by design.

**What would close it.** Verify the XDR incident note (or worklog) endpoint and implement `add_incident_note`, so `XdrIncidentNoteSink` can post; or add a sink for the SOC's chat or mail system that reads the outbox (a bookkeeping write, never a containment path). Add a ticketing adapter (for example ServiceNow) with VERIFIED endpoints for `create_ticket`. Schedule `forward_audit.py` next to the runtime and export audit anchors to write-once storage (docs/deployment.md section 9). Notifications and tickets must never carry secrets or isolation unlock codes (the redactor runs on every rendered draft).

### 15.5 Secure Cloud Analytics is a stub

`SecureCloudAnalyticsAdapter` raises `UnverifiedEndpointError` for every operation and reports health `UNKNOWN`. It is counted among the 16 adapters but adds no capability; Secure Cloud Analytics alerts reach the framework only as Cisco XDR incidents read through `cisco_xdr`. **What would close it.** Verify its alert and observation read endpoints in `docs/integrations.md`, implement them as read operations with a health probe, and add the reads to the workflows that use network telemetry (`c2`, `dns-tunneling`, `exfiltration`, `lateral-movement`).

### 15.6 Cross-incident correlation is informational only

`correlate_workflows` and `rollup_blast_radius` (`src/xdr_response/atomics/correlation/cross_workflow.py`) link finished runs that share entities and roll up their blast radius, but the lifecycle never calls them: they never change a package, an evidence list or an approval level (14.13.4). An analyst or a reporting job can run them over finished runs. **Owner decision.** Whether a cross-incident blast radius should raise approval levels. **What would close it.** A lifecycle observer that runs the correlation over recent runs and adds its result to the decision card as context, and, if the owner decides so, a rule in the package builder that marks an action ELEVATED when the rolled-up blast radius exceeds a cap or touches a critical asset. Correlation may only add context or raise an approval level; it may never lower one, add an action, or remove one.

### 15.7 Smaller gaps

- Simulated reads still follow the adapter families rather than the real read manifests (14.14.3), and native Cisco XDR routes are not exercised in the lab.
- Analyst samples cover 7 of the 22 workflows; every other scenario can be printed with the simulator (`simulate.py --workflow <id> --scenario <name> --live --check`).
- `integrations/cloudflare` and `integrations/servicenow` are spec pages for products with no adapter; nothing routes to them.
- In `exfiltration`, the incident's own domain and IP observables are enriched only through the endpoint investigation that finds the connections. When the endpoint read fails, they are reported as needs-investigation entries naming the failed source (14.14.1) instead of being enriched by Umbrella or VirusTotal directly. Owner decision: whether incident observables should always be enriched independently of the endpoint read.
