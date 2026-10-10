# Contributing

This project changes the state of security products: it isolates hosts, disables accounts and blocks indicators. A bug here can take a domain offline. Read this file before opening a pull request.

## Ground rules

1. **Human approval is mandatory before any state change.** Containment, remediation, release, restoration and removing blocks all need a human approval token. No change may add a path around it.
2. **Enforcement is code.** Approval rules live in `xdr_response.approval` and `xdr_response.guard`. Never move a safety rule into a prompt, a comment, a workflow note or a config flag that can turn it off.
3. **Never weaken a safety test.** Do not delete, skip, `xfail`, loosen or rename a test in `tests/safety/`. Do not mock the guard or the token verifier to make a test pass. If a safety test fails, the code is wrong.
4. **No real data.** No tenant IDs, real users, hostnames, internal IPs, real indicators, tokens or keys. Use `example.com`, `*.example`, `*.test`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, fake 64-hex hashes and hosts like `TH-LT-1047`.
5. **No invented endpoints.** An adapter implements a vendor endpoint only when [docs/integrations.md](docs/integrations.md) lists it as VERIFIED with the URL of the official page. Otherwise the method raises `UnverifiedEndpointError`. To promote an endpoint, read the official page and add its URL in the same change.
6. **Vendor logic stays behind adapters.** Workflows and engines never build vendor HTTP requests.
7. **The contract wins.** [Architecture section 13](docs/architecture.md#13-phase-0-contract) is binding. If code and contract disagree, change the contract in the same commit or fix the code.

## Development setup

```
python -m pip install -r requirements-dev.txt
python -m pytest -q -p no:cacheprovider
python tools/validation/check_workflow_readmes.py
python tools/validation/generate_workflow_docs.py --check
python tools/simulator/simulate.py ransomware --check
python tools/simulator/simulate.py ransomware --live --check
python tools/simulator/simulate.py --all-workflows --check          # every workflow scenario, dry run
python tools/simulator/simulate.py --all-workflows --live --check   # every workflow scenario, simulated live
```

CI runs the same on Python 3.12 (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)). Code must run on 3.12 and 3.13. No test may touch the network: mock HTTP with `httpx.MockTransport` (helpers in `tests/fixtures/http_mocks.py`).

Inside the package use absolute imports (`from xdr_response.models import RecommendedAction`). Never add a top-level module named `logging` or `secrets`.

## Git discipline

Work in small, reviewed steps. For every change:

1. **Inspect.** Read the code and docs you are about to touch, and the contract section that covers them.
2. **Plan.** Write down the smallest change that solves the problem and what could break.
3. **Smallest unit.** Change one thing at a time. One logical change per commit and per pull request.
4. **Tests.** Add or update tests with the change. A bug fix starts with a failing test.
5. **Run.** Run the full test suite, the README validator, the MITRE generator check and the simulator checks above. All must pass.
6. **Safety review.** Go through the checklist below and answer it in the pull request.
7. **Docs.** Update the README, `docs/` and [CHANGELOG.md](CHANGELOG.md) (under *Unreleased*) in the same change.
8. **Conventional commit.** `type(scope): summary`, for example:
   - `feat(guard): refuse writes when the token ledger is unavailable`
   - `fix(umbrella): verify the block after a 409 response`
   - `test: prevent containment without analyst approval`
   - `docs(integrations): verify Intune wipe endpoint`

Other rules:

- Work on a branch. Never push to `main` directly. Never force-push a shared branch.
- Never skip hooks (`--no-verify`) or bypass commit signing.
- Never commit `.env`, `config/integrations.yaml`, `var/`, keys or exported audit trails.
- Never rewrite history that contains an audit or safety change.
- Component ownership is listed in [architecture section 13.2](docs/architecture.md#132-module-layout-and-ownership). If you need a contract change in a component you do not own, say so in the pull request.

## Safety review checklist

Copy this into every pull request that touches `src/`, `config/`, `tools/` or `tests/safety/`, and answer each line.

**Approval and guard**

- [ ] Every new or changed state-changing adapter method has `@state_changing`, and its name matches the action type in the catalog.
- [ ] No new code path writes to a vendor outside `guard.authorized(...)`. No raw `httpx` client bypasses the guarded HTTP client.
- [ ] Only `HUMAN` principals can approve. No change lets `SERVICE`, `AUTOMATION` or `AI` principals approve, directly or through a default.
- [ ] Tokens still bind purpose, package, incident, evidence hash, workflow version and per-action key, type, target, params hash and approval level. No field was dropped from the signed claims.
- [ ] A containment token cannot release, and a release token cannot contain.
- [ ] ELEVATED actions still need the elevated role. Critical assets are never silently skipped or silently executed.
- [ ] No config key, flag or environment variable can turn approval off. `auto_approve` and similar keys are still refused.

**Dry run, idempotency, restoration**

- [ ] Dry run is still the default, and the guard still refuses writes in dry run with a valid token.
- [ ] Execution stays idempotent: the adapter checks current state and returns `ALREADY_CONTAINED`. Writes that time out are not blindly retried.
- [ ] Every control the automation creates is registered. `ALREADY_CONTAINED` creates no control.
- [ ] Release packages come only from `ACTIVE` registry entries. Closing an incident removes no control.

**Evidence, audit, secrets**

- [ ] Evidence comes from a registered integration, an analyst or the control registry. AI text is never numbered evidence.
- [ ] Every new decision, API call and result is audited. The audit API still has no update or delete.
- [ ] No secret, token, password, key, session token or unlock code can reach a log, the audit trail, an exception message or a report. New sensitive fields are added to the central redactor.
- [ ] No secret value is in code, config, tests or docs. Config holds secret names only.

**Tests**

- [ ] New behaviour has unit tests. New adapter operations have mocked-API tests for success, auth failure, rate limiting, timeout, unavailable and invalid target.
- [ ] No safety test was removed, skipped, loosened or rewritten to pass. The four required tests (`test_isolation_without_approval_fails`, `test_disable_user_without_approval_fails`, `test_email_quarantine_without_approval_fails`, `test_block_domain_without_approval_fails`) still pass.

A pull request that fails any line is not merged until it is fixed or a maintainer records why the line does not apply.

## Workflow specs and Claude Code agents

The `wf-*` agents in [`.claude/agents/`](.claude/agents/) each edit only their own `workflows/<workflow>/` directory. Changes to shared atomics (`src/xdr_response/atomics/`), integrations, docs or the framework go through a normal pull request. An agent never approves anything and never changes `tests/safety/`.

## Reporting bugs

Open an issue with the version or commit, Python version, the command you ran, and sanitized output. Remove every secret and real indicator first. Security problems go through [SECURITY.md](SECURITY.md), not public issues.
