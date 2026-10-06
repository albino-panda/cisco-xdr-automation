# Approval model

This page explains how a containment or release action gets approved and how the code enforces it.
It is written for SOC engineers who run, review or extend the framework. The full design is in
[architecture.md section 5](architecture.md#5-approval-architecture). Execution is covered in
[containment-model.md](containment-model.md) and release in [rollback.md](rollback.md).

## The rule

| Stage | Who acts | Human step? |
|---|---|---|
| Investigation and enrichment | automation (read-only adapter calls) | no |
| Recommendation (containment package) | automation | no |
| Containment, remediation | **human approval required** | yes |
| Execution of approved actions | automation, starts immediately | no |
| Verification | automation | no |
| Release / restoration | **separate human release approval required** | yes |

Approval is enforced by deterministic code, not by prompts or configuration. There is no
configuration switch that turns approval off. The config loader rejects keys such as
`auto_approve`, `skip_approval` and `bypass_approval` (see the header of
[config/thresholds.yaml](../config/thresholds.yaml)).

## Flow

1. Investigation produces evidence. Recommendation turns it into proposed actions.
2. `PackageBuilder` ([approval/package.py](../src/xdr_response/approval/package.py)) builds a
   `ContainmentPackage` and the orchestrator moves the incident to `AWAITING_APPROVAL`.
3. The analyst sees the decision card and submits a `DecisionRequest` with their credential(s).
4. `ApprovalEngine.decide` ([approval/engine.py](../src/xdr_response/approval/engine.py))
   authenticates, checks the decision, writes it to the audit trail and, for approvals, issues a
   signed token.
5. The orchestrator moves `AWAITING_APPROVAL -> APPROVED -> CONTAINMENT_RUNNING` and calls the
   executor with the token. No further human step.
6. Every adapter write re-verifies the token through the execution guard
   ([guard.py](../src/xdr_response/guard.py)).

## Containment package

A package is the unit the analyst approves. Fields (model `ActionPackage` in
[models/recommendation.py](../src/xdr_response/models/recommendation.py)):

- incident ID, workflow ID and version, severity, summary, endpoints, users;
- `risk_score` and `confidence_score` (0-100, separate concepts: how bad versus how sure);
- numbered evidence (`[1]`, `[2]`, ...), each item with its `source` integration, summary,
  reference and `observed_at`;
- `evidence_snapshot_hash`: SHA-256 over the canonical evidence. It binds the decision and the
  token to exactly the evidence the analyst saw;
- blast radius (endpoints, users, indicators, messages);
- `excluded_targets`: allow-listed targets with the reason. They are shown, never dropped silently;
- `requested_by` (for example `automation:...`), `created_at`, `expires_at`
  (`package_ttl_minutes`, default 240);
- the `RecommendedAction` checklist.

Each `RecommendedAction` has:

| Field | Meaning |
|---|---|
| `action_type`, `target`, `target_kind` | what and on what (target is normalized) |
| `idempotency_key` | `<incident_id>:<action_type>:<target>`, for example `XDR-RW-1047:isolate_endpoint:TH-LT-1047` |
| `params` | adapter parameters; `params["integration"]` names the executing integration |
| `evidence` | the numbered, sourced evidence behind this action |
| `risk_score`, `confidence_score` | per action |
| `approval_level` | `STANDARD` or `ELEVATED` |
| `warnings` | `CriticalAssetWarning` items (asset, class, role, action, potential impact) |

`PackageBuilder` applies these rules in order:

1. Refuse read-only and restoration action types (read-only work needs no package; release actions
   go in a release package).
2. Normalize targets, compute keys, merge duplicates (higher risk wins, evidence merged).
3. Move allow-listed targets ([config/allowlists.yaml](../config/allowlists.yaml)) to
   `excluded_targets`.
4. Critical-asset match ([config/critical-assets.yaml](../config/critical-assets.yaml)): set
   `ELEVATED` and attach a warning. Never blocked.
5. `always_elevated` action types (`remove_privileged_role`, `restore_privileged_role`): `ELEVATED`.
6. Blast radius above the caps in [config/thresholds.yaml](../config/thresholds.yaml)
   (`max_endpoints: 5`, `max_users: 3`, `max_indicators: 50`, `max_messages: 500`): every action of
   the capped kind becomes `ELEVATED` with a warning. Nothing is removed.
7. Number the evidence, compute the snapshot hash, set `expires_at`.

Evidence sources are integration names, `analyst` or `temporary_control_registry`. A source named
`ai`, `ai:*`, `ai_*` or `llm*` is refused by the model validator
([models/evidence.py](../src/xdr_response/models/evidence.py)). AI text lives in
`Incident.ai_narrative`, which is flagged and is never evidence.

## Elevated approval

An action is `ELEVATED` when its target matches a critical-asset class (domain controller, identity
infrastructure, executive endpoint, production server, hypervisor, network or security
infrastructure, service, privileged or automation account), when its type is always elevated, or
when the blast radius exceeds a cap.

`ELEVATED` is a warning plus a stricter quorum. It never blocks the action silently. The card shows
the asset, its role, the action and the potential impact.

`ELEVATED` is enforced twice:

- by `PackageBuilder` when the package is built, and
- at decision time: `ApprovalEngine` re-runs the level policy (`PackageBuilder.policy_violations`)
  and refuses a package that marks such an action `STANDARD` (`DecisionError`).

## Analyst decisions

| Decision | Approved keys | Rejected keys | Token | Comment | Next state (containment) |
|---|---|---|---|---|---|
| `APPROVE_ALL` | all | none | issued | optional | `APPROVED`, then automatic execution |
| `APPROVE_SELECTED` | the non-empty subset the analyst lists | the rest (computed) | issued for approved keys only | optional | `APPROVED`, then automatic execution |
| `REJECT` | none | all | none | **required** | `CLOSED` |
| `REQUEST_MORE_INVESTIGATION` | none | none | none | **required** | `NOT_STARTED` (a new package will be built) |

For a release package, `REJECT` and `REQUEST_MORE_INVESTIGATION` lead to `REMEDIATION_REQUIRED` and
the controls stay `ACTIVE`.

Every decision is recorded as an `AnalystDecision` with: decision ID, incident ID, package ID,
purpose, analyst identity (the first approver) and all approver principals, timestamp, approved and
rejected action keys, comment, workflow ID and version, evidence snapshot hash and token ID. It is
written to the audit trail (`DECISION_RECORDED`) **before** any token is issued. If the audit write
fails, no token is issued (`AuditError`).

Decisions are final per package:

- A live package can be approved once (`claim_approval` in the token-use ledger).
- `REJECT` and `REQUEST_MORE_INVESTIGATION` revoke the package. Any token issued for it earlier stops
  verifying everywhere (executor, restoration engine, guard).
- A revoked package can never be approved again.
- An expired package refuses every decision. The orchestrator recovers with `reinvestigate()` (new
  package) or `close()`.
- Closing an incident revokes its latest unexecuted containment and release packages.

## Who can approve

`ApprovalEngine.decide` runs these checks in order. The first failure raises, and the refusal is
audited as `APPROVAL_DENIED`.

1. The request names this package, the package is not expired, and the evidence snapshot hash
   recomputes to the stored value (a modified package is refused).
2. Every credential is authenticated through the pluggable `ApproverAuthenticator`
   (`authenticate(credential) -> AuthenticatedPrincipal`). An authenticator error never
   authenticates anyone.
3. Every principal must be `HUMAN`. `SERVICE`, `AUTOMATION` and `AI` are always refused
   (`ApproverNotAllowedError`), whatever roles they hold. This applies to every decision type,
   including `REJECT`.
4. Every principal must hold `standard_role` or `elevated_role`.
5. Decision semantics (keys must belong to the package, comment present where required).
6. Approval-level policy re-check (see above).
7. Quorum, per approval level present in the approved keys:

| Level | Role required | Distinct humans required |
|---|---|---|
| `STANDARD` | `standard_role` (default `xdr-approver`) | `standard_min_approvers` (default 1) |
| `ELEVATED` | `elevated_role` (default `xdr-elevated-approver`) | `elevated_min_approvers` (default 1) |

8. Finality (see above).

Notes:

- A principal counts once, however many credentials it presents.
- An `APPROVE_ALL` that contains both levels needs both quorums. An approver who should approve
  everything must hold both roles.
- If the elevated quorum is not met, `APPROVE_ALL` fails. Use `APPROVE_SELECTED` without the
  `ELEVATED` actions, or bring an elevated approver.
- Self-approval: the package's `requested_by` principal does not count toward the quorum unless
  `allow_self_approval: true` (default `false`).
- `elevated_role` must differ from `standard_role` (config validation).

Phase 0 ships `InMemoryApproverAuthenticator`
([approval/authenticator.py](../src/xdr_response/approval/authenticator.py)) for tests, the lab and
the simulator. It keeps salted PBKDF2-SHA256 hashes in memory and returns one generic error for
every failure. Production plugs an OIDC/SSO authenticator in behind the same protocol.

What the simulator prints when the wrong principal decides (real engine, lab principals):

```
$ python tools/simulator/simulate.py ransomware --live --approver ai
simulate: refused: ApproverNotAllowedError: only HUMAN principals may decide on containment or release; refused: ['ai-assistant@example.com']

$ python tools/simulator/simulate.py ransomware_domain_controller --live --approver analyst
simulate: refused: ApproverNotAllowedError: ELEVATED approval needs 1 distinct human approver(s) with role 'xdr-elevated-approver'; 0 qualifying approver(s) provided; ELEVATED actions ['XDR-RW-2002:isolate_endpoint:TH-DC-02'] must be excluded with APPROVE_SELECTED
```

The lab `ai` and `automation` principals hold both approver roles on purpose. They are refused
because of their kind, not their roles.

## Approval tokens

Implemented by `ApprovalTokenService` in [approval/tokens.py](../src/xdr_response/approval/tokens.py).

Claims (`ApprovalTokenClaims`):

| Claim | Content |
|---|---|
| `version`, `token_id` | format version 1, unique ID |
| `purpose` | `containment` or `release` |
| `package_id`, `incident_id`, `decision_id` | what was decided |
| `evidence_snapshot_hash` | the evidence the analyst saw |
| `workflow_id`, `workflow_version` | which workflow produced the package |
| `actions` | per approved action: `idempotency_key`, `action_type`, `target`, `params_hash` (SHA-256 of canonical params), `approval_level` |
| `approvers` | per approver: `principal_id`, `kind`, sorted `roles` |
| `issued_at`, `expires_at` | validity window |
| `dry_run` | true when issued for a dry-run package; such a token never authorizes a live action |
| `issuance_proof` | HMAC added by `issue()` after all policy checks |

Signing:

- `signature = HMAC-SHA256(key, "xdr-response/approval-token/v1\n" + canonical_json(claims))`, hex,
  compared with `hmac.compare_digest`.
- Canonical JSON: sorted keys, compact separators, UTC datetimes with `Z`, no floats in signed data.
- The key is the `APPROVAL_SIGNING_KEY` secret from the secrets interface, at least 32 bytes. It is
  never in code, config, logs or audit. `APPROVAL_SIGNING_KEY_PREVIOUS` is accepted for verification
  only, during rotation. The key ID comes from `approval.signing_key_id` (default `primary`).
- TTL: `containment_token_ttl_minutes` and `release_token_ttl_minutes` (default 30). Execution starts
  right after approval, so the short TTL is enough.
- Encoded form: `base64url(canonical_json(claims)).<key_id>.<signature>`. It is a bearer secret.
  The audit trail stores only `token_id` and the claims hash (`TOKEN_ISSUED`), never the signature.

Only the `ApprovalEngine` can mint tokens. `issue()` needs the `TokenIssuer` capability, which
`bind_issuer()` hands out exactly once, to the engine's constructor. Tokens signed with the low-level
`sign()` from fabricated claims carry no valid `issuance_proof` and are refused. The executor,
restoration engine and state machine get a verify-only `TokenVerifierView`.

### Verification (fail closed)

`verify(token, purpose=..., binding=...)` raises a subclass of `ApprovalRequiredError` on the first
failed check:

| Check | Error |
|---|---|
| 1. algorithm is `HMAC-SHA256` and key ID is known | `TokenInvalidError` |
| 2. signature valid (every known key evaluated, constant time) | `TokenInvalidError` |
| 3. not issued in the future (beyond `clock_skew_seconds`), not expired, lifetime within TTL | `TokenExpiredError` |
| 4. package not revoked (rejected later, or incident closed) | `TokenInvalidError` |
| 5. purpose equals the action catalog purpose of the action (never the caller's input) | `TokenMismatchError` |
| 6. incident matches | `TokenMismatchError` |
| 7. a grant exists for the idempotency key, and action type, target and params hash all match | `TokenMismatchError` |
| 8. approvers non-empty, distinct, all `HUMAN`, quorum and roles hold for the grant's level | `TokenInvalidError` |
| 9. not issued for a dry run, and the issuance proof is valid | `TokenInvalidError` |
| 10. `mark_used` (guard only): the `(token_id, idempotency_key)` pair is consumed once | `TokenReplayError` |

`verify_package(token, package)` also checks package ID, evidence snapshot hash, workflow version,
the dry-run flag and that every grant matches the package action with the same key. The executor and
restoration engine call it once before any action, and also run their own deterministic binding
check.

The token-use ledger (`JsonlTokenUseLedger`) holds an OS-level file lock, so several workers on one
ledger never consume the same pair twice.

## Execution guard

`guard.py` is the lowest-level enforcement point. It applies to every state-changing call, however
it is reached.

- `guard.authorized(token, request)` is a context manager. It refuses when no verifier is
  registered, when dry run is active (`DryRunViolationError`), when another authorization is already
  active, or when verification fails. On success it consumes the token use for that key.
- Every state-changing adapter method is decorated with `@state_changing`. Called outside an
  authorized context, or with a request that does not match the context binding, the integration or
  the method name, it raises `ApprovalRequiredError`. This holds when the method is called directly.
  An approval for `isolate_endpoint` cannot drive `release_endpoint`.
- One authorization authorizes one guarded call. Context copies taken inside the block (threads,
  tasks) are refused after it closes.
- `GuardedHttpClient` checks the guard before every attempt of a `STATE_CHANGING` request. `PUT`,
  `PATCH` and `DELETE` are always state-changing. Requests are matched against the adapter manifest
  (operation, method and documented path), so a vendor write cannot be sent as a read.
- The verifier slot is sealed by the first registration. A second, more permissive verifier cannot
  replace it. One runtime per process.
- Dry run defaults to `true` in the guard and in config (`runtime.dry_run`). `guard.dry_run()` can
  only switch dry run on, never off.

## What AI and automation may and may not do

| May | May not |
|---|---|
| Run investigation and enrichment (read-only calls) | Approve, reject or decide anything: non-`HUMAN` principals are refused by the engine and again by the token verifier |
| Score risk and confidence, build the recommendation and package | Supply evidence: AI-like evidence sources are refused; AI narrative is stored separately and flagged |
| Execute actions a human approved, automatically | Execute anything without a valid token: the guard refuses |
| Verify results and record outcome states as `automation:verification` | Record `CONTAINED`, `PARTIALLY_CONTAINED`, `CONTAINMENT_FAILED` or `RESTORED` as an `ai:` actor (state machine refuses) |
| Propose a retry package or a release package | Retry a failed action with the old token, or release a control without a release token |
| Write audit records | Edit or delete audit history: the trail is append-only and hash-chained, the head anchor is HMAC-authenticated |

The state machine also refuses `APPROVED` and `RESTORATION_RUNNING` without a verified token, and
refuses a token or package that already entered those states for the incident.

## Sample analyst decision card

Produced by `python tools/simulator/simulate.py ransomware_domain_controller` (dry run; the card is
the same in `--live` mode without the `DRY RUN package` line). TH-DC-02 matches the
`domain_controller` class. TH-DC-01 is on the `never_block` allow-list.

```
CRITICAL INCIDENT  XDR-RW-2002
Ransomware lateral movement to domain controllers
Endpoints: TH-DC-02, TH-LT-1047
User: none
Risk 96/100 (CRITICAL)   Confidence 83%
Primary evidence:
  [1] secure_endpoint: Secure Endpoint: encryptor executed via PsExec from TH-LT-1047
  [2] secure_endpoint: Secure Endpoint: ransomware encryption activity
Blast radius: 2 endpoints
Recommended containment:
  [ ] isolate_endpoint TH-LT-1047  (STANDARD)  risk 96  confidence 92%  via secure_endpoint  evidence [2]
  [ ] isolate_endpoint TH-DC-02    (ELEVATED)  risk 94  confidence 88%  via secure_endpoint  evidence [1]
Excluded (allow-listed, not proposed):
  - isolate_endpoint TH-DC-01: allowlists.never_block.endpoints: TH-DC-01
WARNING: ELEVATED APPROVAL REQUIRED
  Action: isolate_endpoint TH-DC-02
  Asset: TH-DC-02 (domain_controller)
  Role: Active Directory domain controller
  Potential impact: Isolating or disabling a domain controller can stop authentication, Group Policy and DNS for the whole domain.
  Detail: isolate_endpoint on Domain controller TH-DC-02 (role: Active Directory domain controller). Potential impact: Isolating or disabling a domain controller can stop authentication, Group Policy and DNS for the whole domain.
  Requires an approver holding the elevated approval role. The action is not blocked.
Package 00000000000000000000000000000001  workflow ransomware-containment 1.0.0  evidence sha256 a0e01024bcd8  approve before 2026-01-15T16:00:00Z
[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]
```

Reading the card:

- `Risk` and `Confidence` are separate. Risk is impact, confidence is certainty of the evidence.
- `evidence [1]` on an action points to the numbered evidence above.
- `via secure_endpoint` is `params["integration"]`, the adapter that will execute.
- `approve before` is the package expiry, not the token expiry.

Use `--format json` or `--format markdown` for machine-readable or ticket-ready output. Scenario
details and flags are in [tools/simulator/README.md](../tools/simulator/README.md).

## Code map

| Concern | Module |
|---|---|
| Package builder | [approval/package.py](../src/xdr_response/approval/package.py) |
| Critical assets | [approval/critical_assets.py](../src/xdr_response/approval/critical_assets.py) |
| Decisions, quorum | [approval/engine.py](../src/xdr_response/approval/engine.py), [approval/_quorum.py](../src/xdr_response/approval/_quorum.py) |
| Tokens, ledger | [approval/tokens.py](../src/xdr_response/approval/tokens.py), [approval/ledger.py](../src/xdr_response/approval/ledger.py) |
| Guard | [guard.py](../src/xdr_response/guard.py) |
| Lifecycle states | [models/states.py](../src/xdr_response/models/states.py), [lifecycle/machine.py](../src/xdr_response/lifecycle/machine.py) |
| Decision card | [reporting/decision_card.py](../src/xdr_response/reporting/decision_card.py) |
| Safety tests | [tests/safety/test_approval_bypass.py](../tests/safety/test_approval_bypass.py) |
