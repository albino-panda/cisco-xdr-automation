# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Phase 1: shared atomic workflows and the workflow framework. Investigation and recommendation
are automatic; every state-changing action still goes through the Phase 0 human approval, approved
containment executes automatically, and a release needs its own human approval. Exit criteria:
architecture 14.7.1 and 14.9.5.

### Added
- `xdr_response.atomics.context`: `ReadOnlyAdapters` (the only door from the read zone to the
  adapters: reads, health, manifests and names; never an adapter object), `AtomicContext` and
  `build_context`; `xdr_response.atomics` composes the read-atomic and containment-builder tables.
- `xdr_response.workflows`: declarative `WorkflowDefinition` with import-time validators (no
  approval switch anywhere, expressions parsed against the whitelist, builders matching actions,
  MITRE ids mapped), the canonical safe rule-expression evaluator (`ids`, `flatten`, `distinct`,
  `within_minutes`, `in_cidr`, dict literals), pure hooks, discovery and routing (no registry file;
  a broken workflow fails loudly) and the `WorkflowRunner` (deterministic, never raises for a source,
  rule or hook; evidence cites the run's records; separate risk and confidence per target).
- Lifecycle: `WorkflowInvestigator` / `WorkflowRecommender` (Phase 0 generic path as fallback, with
  a "not migrated yet" note), lifecycle observers and `LifecycleEvent`s from the orchestrator;
  `build_runtime(workflows=..., observers=...)`, `bootstrap(workflows=True, notifications_path=...)`;
  incidents are stored with the resolved workflow id and version.
- Simulator: workflow scenario fixtures (`tools/simulator/workflow_scenario.py`: model, loader,
  discovery, coverage check, `WorkflowScenarioRun` with implicit safety assertions) and
  `simulate.py --list-workflows / --workflow <id> [--scenario <name>]`.
- Validation: `check_workflow_readmes.py`, `validate_config.py`, `check_endpoints.py` and
  `tools/validation/README.md`.
- Tests: framework unit tests, a tests-only sample workflow with the full scenario set, the
  read-zone AST lint and runtime checks (`tests/safety/test_read_zone.py`); CI runs Python 3.12 and
  3.13 and the new validation tools.
- Scoring engine (`xdr_response.scoring`, `models/scoring.py`): deterministic, record-backed signals,
  separate risk and confidence, reputation caps, corroboration, failed-source penalty, configurable
  weights and bands (`config/thresholds.yaml`), `aggregate_verdict` (one vendor alone is never
  MALICIOUS); docs/threat-scoring.md is binding.
- Atomic library: normalized records with deterministic ids (`atomics/records.py`), enrichment and
  investigation atomics over `ReadOnlyAdapters` (a failing source never blocks the others; the
  disclosure policy withholds internal data from third parties), correlation and blast radius,
  the evidence builder (evidence can only cite records of the run), 15 containment recommendation
  builders (native Cisco XDR first, data only) and notifications (SOC notification, incident note,
  analyst summary; JSONL outbox).
- `lifecycle/plan_bridge.py` and `tools/simulator/legacy_replay.py`: all 105 legacy scenarios replay
  through the runtime in dry run (`tests/simulation/test_legacy_replay.py`,
  `simulate.py --legacy <workflow> [<scenario>]`).
- `tools/deployment/xdr-trigger-workflow.md`: the XDR trigger sends only the incident ID.
- `tests/integration/test_atomics_scoring_evidence.py`: atomics, scoring, evidence and a workflow
  through the production lifecycle over real adapters and fake vendor APIs.

### Changed
- Legacy specs aligned with the lifecycle (C1-C5): every containment atomic requires approval
  (`revoke-session` included), `auto_approve` is removed and refused, protected and over-limit
  actions stay planned as ELEVATED, unlock codes are never copied; `powershell` and `rmm` renamed to
  `malicious-powershell` and `unauthorized-rmm`; MITRE mapping and workflow index generated.
- Block "auto-expiry" wording in legacy specs replaced: `expires_hours` is a release-review
  reminder, and removal needs a separate human release approval.
- `simulate.py` runs each scenario in its own process when several are selected (the execution guard
  allows one runtime per process).
- CI also replays every legacy workflow and the sample workflow scenarios.

### Fixed
- The redactor now scrubs command-line flags such as `--password=...` (process and persistence
  command lines).
- `WorkflowRun.health` no longer reports a source as `UNKNOWN` because the disclosure policy withheld
  one observable from it; the runner no longer repeats an identical read in one run.
- Tests start with a fresh process-wide redactor (secrets registered by one test no longer affect
  another).
- Phase 1 safety round 1 (architecture 14.9.6): an endpoint named by its IP inside a critical CIDR
  is ELEVATED; a duplicate rule merge keeps every rule's asset context and warnings; approval-marker
  params are refused at any depth; hook signals must be attributed to a source of a cited record;
  one vendor's enrichment verdict is never an aggregate MALICIOUS or CRITICAL on its own; a source
  never corroborates itself; a failed source is penalised once; HIBP never receives internal
  mailboxes; URLs with credentials or secret query values and NAT64/6to4/Teredo-embedded private
  IPv4 are never disclosed; evidence data is redacted; the same fact from two atomics no longer
  discards the second result; prose unlock codes are redacted; the legacy bridge carries a legacy
  protected-asset verdict as a protected tag.
- Phase 1 safety round 2 (architecture 14.9.7): an unrouted duplicate rule's asset context reaches
  the routed proposal, and a routable duplicate replaces an unrouted entry instead of being dropped;
  IPv6 forms of a critical IPv4 address and holders of privileged directory roles
  (`AssetMatch.roles`, `config/critical-assets.yaml`) are ELEVATED; the incident asset is found by
  IP for an IP-named endpoint; long incident titles can no longer truncate the ELEVATED warning or
  the DRY RUN notice out of a notification; a hook cannot launder a vendor verdict as behaviour by
  citing another source's record; a negligible second source no longer lifts the single-source cap;
  fragment secrets, signed-URL signatures and credentials, mailbox addresses in URLs, IPv4 literals
  in any spelling and IPv4-compatible / IPv4-translated / site-local IPv6 are never disclosed;
  signed-URL signatures and unlock codes phrased with the host name are redacted; the workflow
  recommender verifies proposal evidence against the run's records.

## [0.2.0] - 2026-10-06

Phase 0: the `xdr_response` framework foundation. Investigation and recommendation are
automatic; every state-changing action needs a human approval that deterministic code enforces.

### Added
- `src/xdr_response/` package (src layout), Python 3.12 and 3.13.
- Models: incidents, observables, numbered and sourced evidence, `ContainmentPackage` of
  `RecommendedAction`s (separate `risk_score` and `confidence_score`, idempotency key
  `<incident_id>:<action_type>:<target>`, `STANDARD` / `ELEVATED` approval level), analyst
  decisions (`APPROVE_ALL`, `APPROVE_SELECTED`, `REJECT`, `REQUEST_MORE_INVESTIGATION`),
  canonical JSON and hashing, and an action catalog.
- Lifecycle state machine with 12 states and an explicit allowed-transition table, plus the
  `ResponseOrchestrator` and runtime builder.
- Approval: `PackageBuilder`, `CriticalAssetPolicy` (ELEVATED with a warning naming asset, role,
  action and potential impact; never silently blocked), pluggable `ApproverAuthenticator`,
  `ApprovalEngine`, HMAC-SHA256 `ApprovalTokenService` (key from `APPROVAL_SIGNING_KEY`, rotation
  with `APPROVAL_SIGNING_KEY_PREVIOUS`) and a single-use token ledger. Only `HUMAN` principals can
  approve; `SERVICE`, `AUTOMATION` and `AI` are always refused.
- `guard.py`: contextvar execution guard. `@state_changing` on every state-changing adapter
  method and a guarded HTTP client; any write outside `guard.authorized(...)` raises
  `ApprovalRequiredError`. Dry run is on by default and the guard refuses writes while it is on.
- Execution: `ContainmentExecutor` and `ActionRunner` with idempotency (`ALREADY_CONTAINED`),
  per-action results (`SUCCESS`, `ALREADY_CONTAINED`, `FAILED`, `SKIPPED`, `DRY_RUN`) and overall
  `CONTAINED` / `PARTIALLY_CONTAINED` / `CONTAINMENT_FAILED`.
- Verification after every action (`VERIFIED`, `NOT_VERIFIED`, `UNABLE_TO_VERIFY`).
- Restoration: temporary control registry (in-memory, JSONL and SQLite), release planner and
  `RestorationEngine`. Release packages come only from `ACTIVE` controls and need a separate
  `release` token. Closing an incident never removes controls.
- Audit: append-only JSONL trail with a SHA-256 hash chain, verifier and
  `tools/validation/verify_audit_chain.py`.
- Central secret redaction shared by logs and audit; secret providers for environment variables
  and mounted files.
- Config loader and example files in `config/` (`dry_run: true`, Splunk disabled). The loader
  refuses approval-bypass keys and literal secret values.
- 16 integration adapters (Cisco XDR, Secure Endpoint, Secure Email, Secure Malware Analytics,
  Secure Cloud Analytics, Umbrella, Meraki, Entra, Defender for Endpoint, Defender for O365,
  Intune, Microsoft Cloud, VirusTotal, AlienVault OTX, HIBP, Splunk) with health statuses,
  timeouts, retry with backoff and rate limiting. Endpoints not VERIFIED in
  `docs/integrations.md` raise `UnverifiedEndpointError`.
- Dry-run simulator ("Would isolate: TH-LT-1047") and reports: decision card, containment and
  restoration result tables, release checklist.
- `tools/simulator/simulate.py` with four fixture incidents, dry run and simulated-live modes.
- Tests: `tests/unit/`, `tests/integration/` (httpx `MockTransport`), `tests/simulation/`,
  `tests/safety/` (including `test_isolation_without_approval_fails`,
  `test_disable_user_without_approval_fails`, `test_email_quarantine_without_approval_fails`,
  `test_block_domain_without_approval_fails`) and shared `tests/fixtures/`.
- Docs: `docs/architecture.md`, `docs/integrations.md` (vendor API verification).
- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, this changelog.

### Changed
- README rewritten for the framework: lifecycle, safety controls, quick start, status.
- `pyproject.toml` packages `src/` and adds `pydantic` and `httpx`; pytest uses
  `--import-mode=importlib`.
- CI runs the whole `tests/` tree and replays every simulator scenario in dry run and
  simulated-live mode.

### Known limitations
- `InMemoryApproverAuthenticator` is for tests and the lab. Production needs a real identity
  integration.
- Scoring is design-only. The workflow specs are not yet bridged into the runtime (Phase 1).
- The spec layer still contains `requires_approval: false` (revoke-session) and `auto_approve`
  in `docs/deployment/guardrails.example.yaml`. The runtime ignores and refuses them; Phase 1
  fixes the specs.

## [0.1.0] - 2026-10-06

### Added
- 19 incident-type workflows under `workflows/`, each with a README, `workflow.yaml` (triggers,
  inputs, phased steps, plan rules, note templates, `dry_run: true`) and scenarios (105 in total).
- 15 atomic action contracts under `atomic/`, including 8 containment atomics.
- 9 integration specs under `integrations/` (auth, permissions, API surface).
- `engine/xdr_plan`: safe rule evaluator, planner, guardrails, validator and CLI
  (`python -m xdr_plan check`, `python -m xdr_plan plan`).
- MITRE ATT&CK mapping, deployment guide with `guardrails.example.yaml`, testing guide.
- 19 Claude Code `wf-*` agents in `.claude/agents/`, one per workflow.
- 69 tests (`tests/test_engine.py`, `tests/test_repo.py`, `tests/test_workflows.py`) and GitHub
  Actions CI.

