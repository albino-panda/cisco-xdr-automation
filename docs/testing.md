# Testing

How the `xdr_response` framework and the workflow specs are tested, how to run the tests, and what the safety tests prove. Audience: the SOC engineer who changes code or config, or who signs off a deployment.

The test strategy is in [architecture.md](architecture.md) section 10. Go-live checks for workflows in XDR are in [testing/README.md](testing/README.md).

## 1. Ground rules

- **No network.** Every HTTP call in a test goes through `httpx.MockTransport`. No test calls a vendor API.
- **Fake data only.** Domains `example.com`, `*.example`, `*.test`. IPs from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. Fake 64-hex hashes. Hosts like `TH-LT-1047`.
- **No real secrets.** Tests create random keys at run time (for example a 32-byte signing key in a `StaticSecretProvider`).
- **Every test starts from a clean guard.** `tests/conftest.py` resets the process-wide execution guard before and after each test.

## 2. Run the tests

From the repository root:

```bash
pip install -r requirements-dev.txt
python -m pytest -q -p no:cacheprovider
```

`pyproject.toml` already sets `pythonpath = ["engine", "src", "."]`, so no install of the package is needed.

Run one layer:

```bash
python -m pytest -q -p no:cacheprovider tests/safety
python -m pytest -q -p no:cacheprovider tests/unit/approval
python -m pytest -q -p no:cacheprovider tests/simulation
```

Run one test by name:

```bash
python -m pytest -q -p no:cacheprovider tests/safety -k test_isolation_without_approval_fails
```

`-p no:cacheprovider` keeps pytest from writing `.pytest_cache`. Use it when several runs share a checkout.

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs on every push to `main` and every pull request:

1. `python -m pytest` (the whole suite).
2. `PYTHONPATH=engine python -m xdr_plan check` (workflow specs and their scenarios).
3. The simulator for each bundled scenario, live and dry run, with `--check`.
4. The validation tools (`generate_workflow_docs.py --check`, `check_workflow_readmes.py`, `validate_config.py`, `check_endpoints.py`) and the legacy replay of every workflow (`simulate.py --legacy <id> --check`).

## 3. Test layers

| Layer | Location | What it proves |
|---|---|---|
| Unit | `tests/unit/<component>/` | Each module in isolation. Folders: `approval`, `atomics` (records, enrichment, investigation, correlation, evidence, containment builders, notifications, context), `audit`, `core` (models, config, secrets, redaction, guard, states), `dryrun`, `execution`, `integrations` (HTTP client, auth, health, registry), `legacy` (the aligned `xdr_plan` engine), `lifecycle` (including `plan_bridge` and the workflow adapter), `reporting`, `restoration`, `scoring`, `vendors` (the 16 adapters), `verification`, `workflows` (definitions, expressions, discovery, runner, scenario format, validation CLIs) |
| Integration | `tests/integration/` | The production runtime (`build_runtime`) with real Umbrella, Entra and VirusTotal adapters against stateful fake vendor APIs (`_fake_vendors.py`): detect, approve, contain, verify, release; token refresh; auth failure and outage on the write path; failed enrichment not blocking a recommendation. `test_atomics_scoring_evidence.py` runs the Phase 1 read zone end to end (enrichment and investigation atomics, scoring, correlation, evidence, containment builders) and a workflow through the lifecycle up to the human decision |
| Simulation | `tests/simulation/` | Every fixture incident through the whole lifecycle with simulated adapters. Dry run never reaches a state change. Live runs meet each scenario's expectations. Every workflow scenario (`test_workflow_scenarios.py`) and every legacy scenario replayed through `plan_bridge` in dry run (`test_legacy_replay.py`) |
| Safety | `tests/safety/` | Adversarial tests. Each one tries a real way to bypass approval, forge authority, leak a secret or rewrite history, and asserts that it is refused (section 4) |
| Legacy spec tests | `tests/test_engine.py`, `tests/test_repo.py`, `tests/test_workflows.py` | The 69 original tests: plan-rule engine, repository consistency (YAML parses, relative Markdown links resolve, MITRE mapping in sync), workflow scenarios |

Shared fixtures live in `tests/fixtures/`:

| File | Content |
|---|---|
| `factories.py` | Builders for incidents, evidence, packages and decisions |
| `principals.py` | Human analyst, elevated human, service, automation and AI principals, and an `InMemoryApproverAuthenticator` |
| `http_mocks.py` | `MockRouter`: maps `(method, path)` to handlers and records every request |
| `guard_helpers.py` | Helpers to run code inside or outside an authorized guard context |
| `incidents/*.yaml` | Scenario files shared by `tests/simulation/` and the simulator CLI |

Reporting tests compare the decision card, containment report, dry-run report, release checklist and restoration report with golden files in `tests/unit/reporting/golden/` (text, Markdown and JSON). If you change a report on purpose, update the golden file in the same change and review the diff.

## 4. Safety tests and what they prove

Every safety test asserts the **safe** behaviour. A failing safety test means there is a real path to a state change, or to authority, without a valid human approval. Never skip, weaken or mark one as expected-to-fail to get a build green.

### 4.1 Required tests

These four names are fixed by the architecture. For every adapter that can perform the action (including the native `cisco_xdr` path), each test calls the adapter method and `adapter.execute(...)` directly, first with no verifier registered and then with production wiring (HMAC verifier, dry run off), and finally inside `guard.authorized(...)` with a forged, unsigned token. Every attempt must raise `ApprovalRequiredError`, and the mock transport must record zero vendor requests:

- `test_isolation_without_approval_fails`
- `test_disable_user_without_approval_fails`
- `test_email_quarantine_without_approval_fails`
- `test_block_domain_without_approval_fails`

They are in `tests/safety/test_approval_bypass.py`. The HTTP-client path is covered there too, for example by `test_http_mutation_outside_guard_denied` and `test_undecorated_body_cannot_send_a_vendor_write`.

### 4.2 What each file covers

| File | Proves |
|---|---|
| `test_approval_bypass.py` | Every `@state_changing` method of all 16 adapters and the simulated adapters refuses a direct call. Undecorated internals and the guarded HTTP client cannot send a vendor write. Forged, self-built, wrong-key, edited, expired, replayed and other-purpose tokens are refused. A token for action A cannot run action B, another target, other params, another integration or another incident. `AI`, `SERVICE` and `AUTOMATION` principals cannot approve, alone or alongside a human. Self-approval is refused. ELEVATED actions need the elevated role and the configured quorum. Dry run refuses even a valid token. A permissive verifier cannot replace the registered one |
| `test_execution_integrity.py` | An approved package runs once, also under concurrency and after a crash and restart. A retry never resends actions that succeeded, and a failed action is never retried with the same token. Already-contained targets are not written and create no control. One failure gives PARTIALLY_CONTAINED and never stops the other actions. CONTAINED needs executed and verified actions. Rejected actions never reach the vendor. The state machine allows only listed transitions and refuses approval states without a token the token service accepts |
| `test_restoration_authority.py` | Release packages contain only controls the automation created for that incident, from the registry. Manual controls and other incidents' controls are never released. Release needs a release-purpose token from a human. A containment token cannot release. Closing an incident never removes controls. Critical-asset releases need elevated approval. The registry has no delete API and detects in-place edits. Restoration is audited and verified |
| `test_secrets_and_audit.py` | Secrets, OAuth tokens, the signing key, token signatures and session tokens never appear in logs, audit records, exceptions, reprs, decision cards or API summaries, including nested bodies, query strings and vendor error text. The config loader refuses literal secrets without echoing them. Editing, deleting, reordering, truncating or re-anchoring audit records is detected. Audit classes expose no update or delete API |

Unit tests add more safety checks next to the code they cover. Examples: `tests/unit/core/test_config.py` (forbidden keys such as `auto_approve`, secret values in config, dry run on by default), `tests/unit/core/test_guard.py`, `tests/unit/dryrun/test_switch.py` (a per-run dry run cannot be switched off), and `tests/unit/audit/test_audit_tamper.py`.

### 4.3 Adding a state-changing operation

When you add an adapter method that changes vendor state:

1. Decorate it with `@state_changing` and give its HTTP operation `OperationKind.STATE_CHANGING`.
2. Implement it only if [integrations.md](integrations.md) lists the endpoint as VERIFIED. Otherwise raise `UnverifiedEndpointError`.
3. Name the method after its `ActionType` value (for example `block_domain`). `tests/safety/test_approval_bypass.py` discovers every adapter method named after a state-changing action type in the catalog, so a new unguarded method fails there. Run it.
4. Add a mocked-vendor unit test in `tests/unit/vendors/` for success, already contained, 401, 403, 404, 429 with `Retry-After`, 5xx and timeout.

## 5. Simulator

`tools/simulator/simulate.py` runs a fixture incident through the real lifecycle against simulated adapters. Nothing leaves the process. The approvals are real: the production `ApprovalEngine` issues HMAC tokens only to authenticated HUMAN lab principals, and every simulated write still goes through the guard. Full reference: [tools/simulator/README.md](../tools/simulator/README.md).

```bash
python tools/simulator/simulate.py --list
python tools/simulator/simulate.py ransomware                       # dry run (default)
python tools/simulator/simulate.py ransomware --live --check        # simulated-live, check expectations
python tools/simulator/simulate.py phishing --live --decision APPROVE_SELECTED
python tools/simulator/simulate.py ransomware --live --approver ai  # refused: only HUMAN may approve
python tools/simulator/simulate.py account_takeover --live --audit-out var/sim/audit.jsonl
```

Bundled scenarios: `ransomware`, `phishing`, `account_takeover`, `ransomware_domain_controller`.

What you see, in order:

1. The decision card: evidence, risk and confidence, blast radius, ELEVATED warnings, the four decision buttons.
2. The containment result. In dry run this is the `DRY RUN` block (`Would isolate: TH-LT-1047`) and `Simulated vendor state changes: 0`. In `--live` mode it is the per-action results with verification.
3. In `--live` mode: the release checklist, the separate release approval and the restoration result.
4. The audit-chain check (`chain intact`).

Exit codes: 0 completed (and expectations met with `--check`), 1 expectations not met or a decision refused, 2 usage error.

Options: `--live` or `--dry-run`, `--decision {APPROVE_ALL,APPROVE_SELECTED,REJECT,REQUEST_MORE_INVESTIGATION}`, `--approver {analyst,lead,automation,ai}` (repeatable), `--no-release`, `--format {text,markdown,json}`, `--check`, `--audit-out PATH`.

Verify an audit file written with `--audit-out`:

```bash
python tools/validation/verify_audit_chain.py var/sim/audit.jsonl
```

### 5.1 Writing a scenario

Add a YAML file to `tests/fixtures/incidents/`. It is picked up by `--list` and by `tests/simulation/test_dry_run_scenarios.py` automatically. Keys:

| Key | Content |
|---|---|
| `incident` | `incident_id`, `title`, `severity`, `workflow_id`, `workflow_version`, `observables`, `users`, `trigger` |
| `environment` | `reputations` (verdict, risk_score, confidence, optional `integrations`), `findings`, `preexisting` controls, `faults`, `health`, `invalid_targets` |
| `analyst`, `release` | `decision`, `approvers`, optional `select` and `comment` |
| `expect` | `actions`, `already_contained`, `elevated`, `containment`, `controls`, `restoration`, checked by `--check` |

Use fake data only. Model failures with `faults` and `health` so the scenario shows partial containment or a degraded source.

## 6. Workflow specs and the plan engine

The workflow specs under `workflows/` have their own scenarios, replayed by the legacy plan engine:

```bash
PYTHONPATH=engine python -m xdr_plan check
```

`tests/test_workflows.py` runs the same scenarios inside pytest. `tests/simulation/test_legacy_replay.py` replays every one of them through the `xdr_response` runtime in dry run (`plan_bridge`, `PackageBuilder`, the DRY RUN simulator) and checks the `expect` block, zero state-changing calls and zero guard denials ([architecture.md](architecture.md) sections 12 and 14.3.8). One scenario from the command line:

```bash
python tools/simulator/simulate.py --legacy web-attacks 01-confirmed-web-shell --check
```

## 7. Before you merge

- [ ] `python -m pytest -q -p no:cacheprovider` passes, including all of `tests/safety/`.
- [ ] No safety test was removed, skipped or loosened.
- [ ] New or changed vendor calls match a VERIFIED row in [integrations.md](integrations.md).
- [ ] Golden report files changed only on purpose.
- [ ] Test data is fake. No secret, token or real indicator in any file.
- [ ] The simulator passes for every bundled scenario, live and dry run, with `--check`.
