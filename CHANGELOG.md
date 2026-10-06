# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

