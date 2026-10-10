# Testing

How the `xdr_response` framework, the Phase 1 read zone and the 22 workflows are tested, how to run the tests, and what the safety tests prove. Audience: the SOC engineer who changes code or config, or who signs off a deployment.

The test strategy is in [architecture.md](architecture.md) section 10. Go-live checks for workflows in XDR are in [testing/README.md](testing/README.md).

## 1. Ground rules

- **No network.** Every HTTP call in a test goes through `httpx.MockTransport`. No test calls a vendor API.
- **Fake data only.** Domains `example.com`, `*.example`, `*.test`. IPs from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. Fake 64-hex hashes. Hosts like `TH-LT-1047`, users like `jsmith@example.com`.
- **No real secrets.** Tests create random keys at run time (for example a 32-byte signing key in a `StaticSecretProvider`).
- **Every test starts from a clean guard.** `tests/conftest.py` resets the process-wide execution guard before and after each test.

## 2. Run the tests

From the repository root:

```bash
pip install -r requirements-dev.txt
python -m pytest -q -p no:cacheprovider
```

`pyproject.toml` already sets `pythonpath = ["src", "."]` and `--import-mode=importlib`, so no install of the package is needed. The whole suite takes several minutes because every workflow scenario runs through the lifecycle.

Run one layer:

```bash
python -m pytest -q -p no:cacheprovider tests/safety
python -m pytest -q -p no:cacheprovider tests/unit/approval
python -m pytest -q -p no:cacheprovider tests/simulation
python -m pytest -q -p no:cacheprovider tests/workflows/ransomware tests/simulation/test_workflow_scenarios.py -k ransomware
```

Run one test by name:

```bash
python -m pytest -q -p no:cacheprovider tests/safety -k test_isolation_without_approval_fails
```

`-p no:cacheprovider` keeps pytest from writing `.pytest_cache`. Use it when several runs share a checkout.

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs on every push to `main` and every pull request:

1. `python -m pytest -p no:cacheprovider` (the whole suite, including the workflow scenarios, the read-zone lint and the repository checks in `tests/test_repo.py`).
2. The README validator (`check_workflow_readmes.py`) and the MITRE generator check (`generate_workflow_docs.py --check`).
3. The other validation tools (`validate_config.py`, `check_endpoints.py`).
4. The simulator for each bundled incident scenario, live and dry run, with `--check`.
5. The simulator over every workflow scenario in dry run and in simulated live (`simulate.py --all-workflows --check` and `simulate.py --all-workflows --live --check`), plus the tests-only sample workflow.

The legacy plan engine, its repository-check step and the legacy replay loop were retired after Phase 5 (architecture 14.4.3).

## 3. Test layers

| Layer | Location | What it proves |
|---|---|---|
| Unit | `tests/unit/<component>/` | Each module in isolation. Folders: `approval`, `atomics` (records, enrichment, investigation, correlation, evidence, containment builders, notifications, context), `audit`, `core` (models, config, secrets, redaction, guard, states), `dryrun`, `execution`, `integrations` (HTTP client, auth, health, registry, simulated adapters; `test_simulated_parity.py` checks every real integration against every simulated family combination: the lab never does or verifies more than the real adapter), `legacy` (spec-text alignment checks, the retirement of the legacy layer and the MITRE/index generator), `lifecycle` (including the workflow adapter), `reporting`, `restoration`, `scoring`, `vendors` (the 16 adapters), `verification`, `workflows` (definitions, expressions, discovery, runner, scenario format, validation CLIs) |
| Workflow | `tests/workflows/<x_snake>/` | Each workflow's definition, hooks and lifecycle run (`test_<x_snake>_definition.py`, `_hooks.py`, `_lifecycle.py`), owned by that workflow's agent. See [tests/workflows/README.md](../tests/workflows/README.md) |
| Integration | `tests/integration/` | The production runtime (`build_runtime`) with real Umbrella, Entra and VirusTotal adapters against stateful fake vendor APIs (`_fake_vendors.py`): detect, approve, contain, verify, release; token refresh; auth failure and outage on the write path; failed enrichment not blocking a recommendation. `test_atomics_scoring_evidence.py` runs the Phase 1 read zone end to end (enrichment and investigation atomics, scoring, correlation, evidence, containment builders) and a workflow through the lifecycle up to the human decision. `test_cross_workflow_correlation.py` links real dry-run detections of several workflows into one storyline (aliases, source families, link confidence, critical-asset rollup) with no state change and no adapter call |
| Simulation | `tests/simulation/` | Every fixture incident through the whole lifecycle with simulated adapters. Dry run never reaches a state change. Live runs meet each scenario's expectations. Every workflow scenario in its modes (`test_workflow_scenarios.py`, 426 scenarios over 22 workflows, the 0.1.0 ones included as `legacy-*`). `test_production_parity.py` checks end to end that the simulated adapters report only what production can do: `UNROUTED` where no real adapter has a VERIFIED write, `UNABLE_TO_VERIFY` where the real read-back is UNVERIFIED, and no lab-only output (architecture 14.14.3). `test_docs_samples.py` reruns the simulator command of each [sample](samples/README.md) and compares the output |
| Safety | `tests/safety/` | Adversarial tests. Each one tries a real way to bypass approval, forge authority, leak a secret or rewrite history, and asserts that it is refused (section 4) |
| Repository checks | `tests/test_repo.py` | YAML parses, relative Markdown links resolve, MITRE mapping and workflow index in sync with the generator, one agent per workflow, catalog `spec_ref` values resolve to [atomic/README.md](../atomic/README.md), and nothing references a retired legacy path |

Shared fixtures live in `tests/fixtures/`:

| File | Content |
|---|---|
| `factories.py` | Builders for incidents, evidence, packages and decisions |
| `principals.py` | Human analyst, elevated human, service, automation and AI principals, and an `InMemoryApproverAuthenticator` |
| `http_mocks.py` | `MockRouter`: maps `(method, path)` to handlers and records every request |
| `guard_helpers.py` | `FakeVerifier`, `make_token`, `install_fake_verifier`: run code inside or outside an authorized guard context |
| `degraded.py` | The shared degraded-source check (architecture 14.14.1) used by `test_degraded_sources.py` and `test_p2_workflows.py` to `test_p5_workflows.py` |
| `incidents/*.yaml` | Bundled incident scenarios shared by `tests/simulation/` and the simulator CLI |
| `workflows/<id>/*.yaml` | Workflow scenarios (architecture 14.5.2), discovered by the simulator and `test_workflow_scenarios.py` |
| `sample_workflows/` | The tests-only sample workflow that exercises the framework |

Reporting tests compare the decision card, containment report, dry-run report, release checklist and restoration report with golden files in `tests/unit/reporting/golden/` (text, Markdown and JSON). If you change a report on purpose, update the golden file in the same change and review the diff.

## 4. Safety tests and what they prove

Every safety test asserts the **safe** behaviour. A failing safety test means there is a real path to a state change, or to authority, without a valid human approval, or a workflow that hides, invents or weakens something the analyst must see. Never skip, weaken or mark one as expected-to-fail to get a build green.

### 4.1 Required tests

These four names are fixed by the architecture. For every adapter that can perform the action (including the native `cisco_xdr` path), each test calls the adapter method and `adapter.execute(...)` directly, goes through `ContainmentExecutor` with a real `ActionRunner` around the real adapter (no token, and an unsigned token bound to the package), and finally enters `guard.authorized(...)` with a forged, unsigned token, first with no verifier registered and then with production wiring (HMAC verifier, dry run off). Every attempt must raise `ApprovalRequiredError` (or give a pure dry-run preview under the pristine default), the mock transport must record zero vendor requests, and the executor refusal is audited (`GUARD_DENIED`):

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
| `test_read_zone.py` | Investigation and recommendation code can never change state: an AST lint over every read-zone file (`scoring`, `atomics`, `workflows` with every workflow package, `lifecycle/workflow_adapter.py`, the sample workflow), a runtime check that every workflow scenario detects with zero state-changing operations and zero guard denials, and the guard failing closed outside an authorized context |
| `test_phase1_atomics.py` | Phase 1 read zone and approval: containment builders, routing, notifications, atomics and the workflow runner never reach a state-changing call, a guard context or a token; `revoke_sessions` and every restoration action always need approval; a critical-asset target always comes out ELEVATED with a warning; dry run stays side-effect free |
| `test_phase1_evidence.py` | Evidence, scoring and privacy: evidence cites only the run's records, one vendor alone is never MALICIOUS, a source never corroborates itself, a failed source is penalised once and never blocks, third-party lookups never receive internal data |
| `test_degraded_sources.py` | The owner rule on failed sources (architecture 14.14.1): failing each expected source of every `tp-approve-all` scenario never makes an action vanish. Each action is still proposed, or shown as considered or "needs investigation" naming the failed source, citing only real records and never added to the package. Healthy runs have no needs-investigation entries, and a self-check proves the sweep fails when the accounting is switched off |
| `test_p2_workflows.py` to `test_p5_workflows.py` | Workflow safety per phase. Each starts from the workflows' own scenarios and mutates them the way an attacker or a bad configuration would: allow-list or mark targets critical, sanction a tool, fail a source, fail an action, pre-contain a target, poison vendor records or a threat feed. The package must stay correct, ELEVATED must stay visible, and nothing may be skipped silently |

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

## 6. Workflow scenarios and the retired spec layer

Every workflow has at least the minimum scenario set of architecture 14.5.3 (`tp-approve-all`, `tp-approve-selected`, `tp-reject`, `benign-no-action`, `critical-asset-elevated`, `degraded-source`, `partial-failure`, `release-restoration`, `dry-run`) plus `more-investigation` (REQUEST_MORE_INVESTIGATION, required since 14.14.5) and its edge cases. After REJECT or REQUEST_MORE_INVESTIGATION, `--check` asserts no token, no execution report, no state change and no control, and that a later approval of the same package is refused. A rule whose action no real adapter can execute counts as covered when a scenario expects it `UNROUTED`. `--check` adds implicit assertions to every scenario: zero state changes and zero guard denials before the analyst decision, evidence that cites the run's records, separate risk and confidence, ELEVATED with a warning for every critical asset (and the lab analyst alone refused on a `critical_asset` scenario), AI and automation principals refused, an intact audit chain and no rule or hook error. `python tools/validation/check_workflow_readmes.py` checks the scenario coverage with the READMEs.

In workflow-scenario mode the decision, the approvers and the release come from the scenario file; `--decision`, `--approver`, `--no-release` and `--audit-out` apply only to the bundled incident scenarios of section 5.

Every workflow is migrated (Phases 2 to 5): no `workflows/<id>/workflow.yaml` or `scenarios/` is left. Each legacy scenario lives on as a `legacy-*` workflow scenario in `tests/fixtures/workflows/<id>/`, run by `tests/simulation/test_workflow_scenarios.py` in dry run and through the lifecycle:

```bash
python tools/simulator/simulate.py --workflow web-attacks --scenario legacy-01-confirmed-web-shell --check
```

Every scenario of every workflow, in dry run and in simulated live:

```bash
python tools/simulator/simulate.py --all-workflows --check
python tools/simulator/simulate.py --all-workflows --live --check
```

The legacy plan engine, the plan bridge, the legacy replay, the spec tests, the per-atomic spec files and the legacy guardrails file covered only specs that no longer exist and were deleted after Phase 5 ([architecture.md](architecture.md) 14.4.3). `tests/unit/legacy/test_legacy_alignment.py` pins that they stay gone; [atomic/README.md](../atomic/README.md) maps the old atomic names to the catalog.

## 7. Before you merge

- [ ] `python -m pytest -q -p no:cacheprovider` passes, including all of `tests/safety/`.
- [ ] No safety test was removed, skipped or loosened.
- [ ] New or changed vendor calls match a VERIFIED row in [integrations.md](integrations.md).
- [ ] Golden report files changed only on purpose.
- [ ] Test data is fake. No secret, token or real indicator in any file.
- [ ] The simulator passes for every bundled scenario and every workflow scenario (`--all-workflows`), live and dry run, with `--check`.
- [ ] `python tools/validation/check_workflow_readmes.py` and `python tools/validation/generate_workflow_docs.py --check` pass.
- [ ] If the decision card or a sampled workflow changed on purpose, the matching file in [samples/](samples/README.md) was regenerated.
