# Containment execution and verification model

This page explains what happens after a human approves a containment package: how actions run, how
results are verified, how partial failure and integration errors are handled, and what state the
incident ends in. The design is in [architecture.md sections 6 and 7](architecture.md#6-containment-execution-architecture).
How the approval itself works is in [approval-model.md](approval-model.md). Releasing controls is in
[rollback.md](rollback.md).

## Automatic start

`ResponseOrchestrator.submit_decision` ([lifecycle/orchestrator.py](../src/xdr_response/lifecycle/orchestrator.py))
does this for `APPROVE_ALL` and `APPROVE_SELECTED`:

1. Marks the package executed first, so a later failure can never allow a second run.
2. `AWAITING_APPROVAL -> APPROVED` (the state machine verifies the token).
3. `APPROVED -> CONTAINMENT_RUNNING` as `automation:execution`. No further human step.
4. `ContainmentExecutor.execute(package, token)`.
5. The overall result becomes the incident state (`CONTAINED`, `PARTIALLY_CONTAINED` or
   `CONTAINMENT_FAILED`), recorded by `automation:verification`.
6. If verification says a human must act, the incident moves on to `REMEDIATION_REQUIRED`
   (a lifecycle state, not a vendor change).

The only things that stop approved actions are failed safety checks (token, guard, audit). A token
that does not bind the package makes the executor raise; the orchestrator records
`CONTAINMENT_FAILED` with the reason.

## Executor

`ContainmentExecutor` ([execution/executor.py](../src/xdr_response/execution/executor.py)):

- Dry run (guard flag, the executor's own `settings.runtime.dry_run`, a per-run flag or
  `package.dry_run`): the package is simulated inside `guard.dry_run()`. No adapter method is
  reachable and `overall` is `None`. See [Dry run](#dry-run).
- Live: a token is mandatory and must bind this exact package (package ID, incident, purpose,
  evidence snapshot hash, workflow and every grant). This is checked by the executor and by the token
  service's `verify_package`.
- Every package action goes through `ActionRunner`. Actions without a grant in the token are
  `SKIPPED` with `REJECTED_BY_ANALYST`.
- One failure never stops another action.
- Concurrency is sequential by default (`max_concurrency=1`). `build_runtime` exposes
  `max_concurrency` and `integration_concurrency` (per integration limits).
- `CONTAINMENT_COMPLETED` is audited at the end.

## Per-action pipeline

`ActionRunner.run` ([execution/runner.py](../src/xdr_response/execution/runner.py)) runs one approved
action and never raises for it.

1. **Pre-checks.** The token must hold a grant for the key (else `SKIPPED` / `REJECTED_BY_ANALYST`).
   The action must belong to the package and its key is recomputed. Dry run refuses execution here.
   The token is verified without being consumed (`guard.check_token`); a forged or foreign token gets
   `FAILED` and never occupies the slot.
2. **Claim.** The action is claimed in the `ExecutionStateStore`. An existing claim is never re-sent:
   a completed result is replayed, an unfinished one is reported as unknown outcome. A control this
   package already registered (durable registry) is never re-sent either, even after a restart.
3. **Adapter selection** by `params["integration"]`. Missing adapter: `SKIPPED` /
   `NO_CAPABLE_ADAPTER`. Disabled integration: `SKIPPED` / `INTEGRATION_DISABLED`.
4. **Audit `ACTION_STARTED`.** If this write fails, the action is not executed: `FAILED` with
   `AUDIT_UNAVAILABLE`.
5. **Execute** under a process-wide lock per idempotency key:
   - `adapter.current_state(request)` runs first, read-only and outside the authorization.
   - `guard.authorized(token, request)` consumes the approval for this key.
   - If the target is already in the desired state: `ALREADY_CONTAINED`, no vendor write.
   - Otherwise `adapter.execute(request)` (a `@state_changing` method) returns `SUCCESS` with an
     external reference and rollback parameters, or raises a typed integration error that becomes
     `FAILED`.
   - A timed-out write is never retried blindly. The runner re-reads the target state.
6. **Verify** outside the guard, for `SUCCESS` and `ALREADY_CONTAINED`.
7. **Register** a temporary control for `SUCCESS` of a control-creating action type (see
   [rollback.md](rollback.md)). `ALREADY_CONTAINED` is not registered: the control in force is
   someone else's.
8. **Audit** `ACTION_RESULT` and `VERIFICATION_RESULT` with redacted API summaries.

## Per-action results

| Status | Meaning |
|---|---|
| `SUCCESS` | the adapter applied the action |
| `ALREADY_CONTAINED` | the pre-check found the target already in the desired state; nothing was sent |
| `FAILED` | an error stopped the action; `error` carries the `ErrorCode` and a redacted message |
| `SKIPPED` | not attempted; `skip_reason` says why |
| `DRY_RUN` | simulated only; carries the `Would ...` line |

Skip reasons: `REJECTED_BY_ANALYST`, `NO_CAPABLE_ADAPTER`, `INTEGRATION_DISABLED`,
`CONTROL_NOT_ACTIVE` (restoration only).

Error codes on `FAILED`: `TIMEOUT`, `RATE_LIMITED`, `AUTH_FAILED`, `UNAVAILABLE`, `INVALID_TARGET`,
`API_ERROR`, `UNVERIFIED_ENDPOINT`, `NOT_SUPPORTED`, `APPROVAL_DENIED`, `DRY_RUN`,
`NO_CAPABLE_ADAPTER`, `AUDIT_UNAVAILABLE`, `INTERNAL`.

An action is flagged `requires_attention` when it is `FAILED`, skipped for any reason other than
`REJECTED_BY_ANALYST`, or its verification is anything but `VERIFIED`. It gets a recommended escalation
owner ([verification/escalation.py](../src/xdr_response/verification/escalation.py)): the adapter
manifest's escalation hint first (for example "Microsoft 365 administrator" for a 403 from Graph),
then the SOC analyst for an invalid target, then the platform owner for approval, audit and adapter
faults, then the integration's default administrator.

## Verification

`VerificationEngine.verify` ([verification/engine.py](../src/xdr_response/verification/engine.py))
runs after every `SUCCESS` and `ALREADY_CONTAINED` action, and after every restoration action.

- It calls only the adapter's read-only `verify` method. It never needs the guard and never raises.
- The verifying adapter is `params["verify_integration"]` when set (Cisco XDR native actions), else
  `params["integration"]`.
- Polling: every `poll_interval_seconds` (default 10) up to `timeout_seconds` (default 300), from
  [config/thresholds.yaml](../config/thresholds.yaml). The adapter can mark a result terminal to stop
  early. `VERIFIED` is always terminal.
- Action types the adapter manifest does not list in `verifiable_actions` return `UNABLE_TO_VERIFY`
  immediately.

| Status | Meaning |
|---|---|
| `VERIFIED` | an independent read shows the desired state |
| `NOT_VERIFIED` | the read shows the state was not reached (for example the account is still enabled) |
| `UNABLE_TO_VERIFY` | no verify call exists, the read failed, the status was unknown, or polling timed out |

The per-integration verify calls are listed in [integrations.md](integrations.md).

## Overall result

One rule set, in [execution/outcome.py](../src/xdr_response/execution/outcome.py):

- Only approved actions count. `SKIPPED` / `REJECTED_BY_ANALYST` is left out.
- An action **failed** when it is `FAILED`, `SKIPPED` for any other reason, or its verification is
  `NOT_VERIFIED`.
- An action is **confirmed** when it is `SUCCESS` or `ALREADY_CONTAINED` **and** its verification is
  `VERIFIED`. `UNABLE_TO_VERIFY` counts as confirmed only when
  `verification.unable_to_verify_counts_as_contained` is `true` (default `false`).
- Anything else (executed but unverifiable) is **unconfirmed**.

| Situation | Overall |
|---|---|
| every counted action confirmed | `CONTAINED` |
| every counted action failed, or none counted | `CONTAINMENT_FAILED` |
| anything else | `PARTIALLY_CONTAINED` |

One unrelated integration failing never turns the run into `CONTAINMENT_FAILED` while other actions
succeeded. `UNABLE_TO_VERIFY` actions always appear as "requires attention" on the result.

### Follow-up

`assess_containment` ([verification/outcome.py](../src/xdr_response/verification/outcome.py)) adds a
deterministic recommendation:

| Failures | Next step |
|---|---|
| a control reported applied but `NOT_VERIFIED`; a non-transient error (auth, invalid target, unsupported or unverified endpoint, platform fault); a `NO_CAPABLE_ADAPTER` / `INTEGRATION_DISABLED` skip | the orchestrator moves the incident to `REMEDIATION_REQUIRED` |
| only transient errors (`TIMEOUT`, `RATE_LIMITED`, `UNAVAILABLE`) | incident stays `PARTIALLY_CONTAINED` / `CONTAINMENT_FAILED`; recommended next state `AWAITING_APPROVAL` |
| everything confirmed | none |

A failed action is never retried with the same token. `ResponseOrchestrator.propose_retry()` builds a
new package with only the failed actions. It needs a new human approval.

## Idempotency

| Layer | Mechanism |
|---|---|
| Key | `<incident_id>:<action_type>:<target>`, target normalized, for example `XDR-RW-1047:isolate_endpoint:TH-LT-1047` |
| Token | the ledger consumes `(token_id, idempotency_key)` once; a replay raises `TokenReplayError` |
| Package | marked executed before execution starts; a package runs at most once |
| Execution store | one claim per `(package, key)`; a claim is never re-sent |
| Process lock | one lock per key, so two packages sharing a key never both write in one process |
| Adapter | `current_state` pre-check returns `ALREADY_CONTAINED` (for example Defender for Endpoint "Action is already in progress") |
| HTTP | writes retried only when provably not sent (connect error), on `429`, or on `503` with `Retry-After` |
| Registry | `register` is idempotent by key |

Multi-worker deployments must share the execution store and route one incident to one worker.

## Error handling for every external call

`GuardedHttpClient` ([integrations/http.py](../src/xdr_response/integrations/http.py)) gives every
adapter the same behaviour. Per integration settings in
[config/integrations.example.yaml](../config/integrations.example.yaml): `timeout_seconds` (default
15), `max_retries` (3), `backoff_base_seconds` (1), `backoff_max_seconds` (30),
`rate_limit_per_minute` (token bucket, optional).

| Condition | Client behaviour | Error | Health |
|---|---|---|---|
| Timeout | reads retried with backoff; writes not retried (runner re-reads state) | `IntegrationTimeoutError` | `DEGRADED` |
| `429` | honour `Retry-After` (give up if longer than `backoff_max_seconds`), else exponential backoff with jitter | `RateLimitedError` | `RATE_LIMITED` |
| `401` | invalidate the auth token, re-authenticate once, retry once | `AuthFailedError` | `AUTH_FAILED` |
| `403` | no retry | `AuthFailedError` | `AUTH_FAILED` |
| `400`, `404` | no retry | `InvalidTargetError` | `DEGRADED` |
| other `4xx` | no retry | `ApiError` | `DEGRADED` |
| `500`, `502`, `503`, `504`, connect error | reads retried with backoff; writes only if not sent or `503` with `Retry-After` | `IntegrationUnavailableError` | `UNAVAILABLE` |
| Unverified endpoint | never sent | `UnverifiedEndpointError` (`UNVERIFIED_ENDPOINT`) | unchanged |
| Already contained | adapter pre-check, no error | none (`ALREADY_CONTAINED`) | unchanged |

Rate limiting is applied before each request. Vendor error excerpts are redacted before they are
truncated. Every attempt produces a redacted `ApiCallSummary` (audited as `API_CALL`).

An endpoint is only implemented when [integrations.md](integrations.md) lists it as VERIFIED with a
source. Otherwise the adapter method raises `UnverifiedEndpointError` (a subclass of
`NotImplementedError`) with an "unverified endpoint" message and nothing is sent. The action result is
`FAILED` with `UNVERIFIED_ENDPOINT`, which leads to `REMEDIATION_REQUIRED`.

## Integration health

`HealthMonitor` ([integrations/health.py](../src/xdr_response/integrations/health.py)) checks every
integration and never raises.

| Status | Meaning |
|---|---|
| `CONNECTED` | health probe succeeded |
| `DEGRADED` | timeouts, invalid target or API errors; still usable for enrichment |
| `UNAVAILABLE` | 5xx, connect error, adapter could not be loaded |
| `AUTH_FAILED` | 401/403, authentication error or missing secret |
| `RATE_LIMITED` | 429 |
| `UNKNOWN` | integration disabled, unknown, or unrecognized failure |

Health checks are audited (`HEALTH_CHECK`). `usable()` returns integrations that are `CONNECTED` or
`DEGRADED`.

Failed enrichment never blocks a recommendation. In `InvestigationService`
([lifecycle/investigation.py](../src/xdr_response/lifecycle/investigation.py)) an error from one
source becomes a result with verdict `UNKNOWN`, the classified health status and a redacted error.
The other sources still run, and the recommender combines whatever verdicts came back (a failed
source contributes nothing).

## Dry run

`runtime.dry_run` defaults to `true` ([config/integrations.example.yaml](../config/integrations.example.yaml)
and the `DRY_RUN` environment variable, which must be exactly `true` or `false`).

- Investigation, enrichment, scoring, recommendation and the decision card run normally.
- Containment is simulated by `DryRunSimulator`
  ([dryrun/simulator.py](../src/xdr_response/dryrun/simulator.py)) inside `guard.dry_run()`. It calls
  no adapter method and never enters `guard.authorized`. Any guarded call would raise
  `DryRunViolationError`.
- Actions the analyst rejected are previewed as `Would skip ...`, never as `Would ...`.
- The token issued during a dry run carries `dry_run=true` and can never authorize a live action,
  even after dry run is switched off within the TTL.
- The incident state does not advance; there is no overall containment state.

## Sample containment results

All produced by [tools/simulator](../tools/simulator/README.md) against the in-process simulated
environment. No network calls.

### Dry run

`python tools/simulator/simulate.py ransomware` (dry run is the default):

```
=== Containment result (dry run) ===
DRY RUN
Would isolate: TH-LT-1047
Would block: c2.ransom-ops.example
Would block: 198.51.100.23
No containment actions executed.
```

The encryptor hash is not in the package: no adapter in the default lab has a VERIFIED hash-block write
(Secure Endpoint has none, and Defender for Endpoint is not in the default suite), so the run notes it as
not proposed, for manual handling (production parity, architecture 14.14.3 and 15.2).

`python tools/simulator/simulate.py phishing` (the scenario's `APPROVE_SELECTED` rejects
`disable_user`):

```
DRY RUN
Would quarantine email: <20260115.7781@mail.contoso-payroll.example>
Would block: https://login.contoso-payroll.example/reset
Would block: contoso-payroll.example
Would skip disable_user: jsmith@example.com (REJECTED_BY_ANALYST)
Would revoke sessions: jsmith@example.com
No containment actions executed.
```

The simulator reports `Simulated vendor state changes: 0 (dry run)`.

### Live, already contained

`python tools/simulator/simulate.py account_takeover --live`. The attacker IP was already blocked, so
nothing is sent and no control is registered:

```
CONTAINMENT RESULT  XDR-AT-3310
Overall: CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]            disable_user jsmith@example.com     via entra   verification VERIFIED  control registered
  [SUCCESS]            revoke_sessions jsmith@example.com  via entra   verification VERIFIED
  [ALREADY_CONTAINED]  block_ip 198.51.100.77              via meraki  verification VERIFIED
Temporary controls registered: 1 (release needs a separate release approval)
```

`revoke_sessions` is not reversible, so it creates no control.

### Live, partial failure

The `ransomware` scenario with two injected faults: Umbrella unavailable for `block_domain` and a
Meraki authentication failure for `block_ip`. To reproduce, copy
`tests/fixtures/incidents/ransomware.yaml`, remove its `expect` block, add the faults below and pass
the file path to the simulator with `--live`:

```yaml
environment:
  faults:
    - {kind: UNAVAILABLE, integration: umbrella, operation: block_domain, times: null}
    - {kind: AUTH_FAIL, integration: meraki, operation: block_ip, times: null}
```

```
Decision APPROVE_ALL by analyst.one@example.com; incident now REMEDIATION_REQUIRED

=== Containment result ===
CONTAINMENT RESULT  XDR-RW-1047
Overall: PARTIALLY_CONTAINED
Package 00000000000000000000000000000001  approval token 00000000000000000000000000000003
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  isolate_endpoint TH-LT-1047         via secure_endpoint  verification UNABLE_TO_VERIFY  control registered  ATTENTION
  [FAILED]   block_domain c2.ransom-ops.example  via umbrella         verification -                 ATTENTION
      error UNAVAILABLE: umbrella.block_domain: simulated outage
      escalation simulated environment: no vendor console
  [FAILED]   block_ip 198.51.100.23              via meraki           verification -                 ATTENTION
      error AUTH_FAILED: meraki.block_ip: simulated authentication failure
      escalation simulated environment: no vendor console
Attention:
  - Requires attention: isolate_endpoint TH-LT-1047 - verify manually (UNABLE_TO_VERIFY)
  - Requires attention: block_domain c2.ransom-ops.example - HTTP 503 (UNAVAILABLE)
  - Requires attention: block_ip 198.51.100.23 - HTTP 401 (AUTH_FAILED)
  - Recommended escalation: simulated environment: no vendor console
Temporary controls registered: 1 (release needs a separate release approval)
```

What to read from it:

- The Secure Endpoint isolation still ran; the failures did not stop it. Secure Endpoint has no
  verified read-back for isolation, so it is `UNABLE_TO_VERIFY` and flagged for manual verification
  (architecture 15.1).
- The overall result is `PARTIALLY_CONTAINED`. The `AUTH_FAILED` error is not transient, so the
  incident moved on to `REMEDIATION_REQUIRED`. With only the Umbrella outage (transient) the incident
  stays `PARTIALLY_CONTAINED` and the recommendation is a retry package for a new approval.
- Only the successful isolation is registered, so only it can be released later.
- The escalation text comes from the simulated adapters. Real adapters use their manifest's
  escalation hint.

## Code map

| Concern | Module |
|---|---|
| Executor | [execution/executor.py](../src/xdr_response/execution/executor.py) |
| Per-action pipeline | [execution/runner.py](../src/xdr_response/execution/runner.py) |
| Overall rules | [execution/outcome.py](../src/xdr_response/execution/outcome.py) |
| Execution claims | [execution/state_store.py](../src/xdr_response/execution/state_store.py) |
| Verification | [verification/engine.py](../src/xdr_response/verification/engine.py), [verification/outcome.py](../src/xdr_response/verification/outcome.py) |
| HTTP client, health | [integrations/http.py](../src/xdr_response/integrations/http.py), [integrations/health.py](../src/xdr_response/integrations/health.py) |
| Result rendering | [reporting/containment_report.py](../src/xdr_response/reporting/containment_report.py) |
| Safety tests | [tests/safety/test_execution_integrity.py](../tests/safety/test_execution_integrity.py) |
