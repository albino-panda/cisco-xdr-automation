# Rollback and restoration

This page explains how controls created by containment are tracked and released. The design is in
[architecture.md section 8](architecture.md#8-rollback-architecture). Approvals are covered in
[approval-model.md](approval-model.md), execution in [containment-model.md](containment-model.md).

Three rules:

1. Every control the automation creates is recorded in the temporary control registry.
2. A control is released only through a release package and a **separate human release approval**
   (token purpose `release`). A containment token can never release anything.
3. Nothing is released automatically. Closing an incident never removes controls.

## Temporary control registry

`TemporaryControlRegistry` ([restoration/registry.py](../src/xdr_response/restoration/registry.py))
records each control as a `TemporaryControl`
([models/restoration.py](../src/xdr_response/models/restoration.py)):

| Field | Content |
|---|---|
| `control_key` | the containment idempotency key, `<incident_id>:<action_type>:<target>` |
| `incident_id`, `action_type`, `target`, `target_kind` | what was contained |
| `integration` | the adapter that created it |
| `workflow_id`, `workflow_version` | the workflow that proposed it |
| `package_id`, `token_id`, `decision_id`, `approval_level` | the approval it ran under |
| `created_at` | when it was applied |
| `rollback_action_type`, `rollback_params` | how to undo it (always includes `integration`) |
| `external_ref` | vendor reference, if any |
| `status` | `ACTIVE`, `RELEASE_PENDING`, `RELEASED` or `RELEASE_FAILED` |
| `review_due_at` | reminder time from `temporary_controls.review_after_hours` |
| `released_at`, `release_package_id`, `release_token_id`, `last_error` | release bookkeeping |

What gets registered:

- Only `SUCCESS` results of action types with `creates_control=True`: `isolate_endpoint`,
  `block_domain`, `block_url`, `block_ip`, `block_hash`, `disable_user`, `quarantine_email`,
  `block_network_client`, `remove_privileged_role`, `quarantine_file`.
- `ALREADY_CONTAINED` is not registered. The control in force was created by someone else, so a
  release must never remove it. (One exception: an earlier attempt of the same key in another package
  of the incident sent a write whose outcome stayed unknown. Then the control is registered, flagged
  "reconstructed" and requires attention, so it does not become an orphan.)
- Non-reversible actions create no control. They are only in the audit trail: `revoke_sessions`,
  `confirm_user_compromised`, `lock_device`, `delete_email`, `terminate_process`,
  `remove_persistence`, `reset_password`, `reset_mfa`, `revoke_app_credentials`,
  `remove_application`.
- `register()` refuses secret-like keys in `rollback_params`.

Storage rules:

- Append-only event log: `REGISTERED`, `SUPERSEDED`, `RELEASE_PENDING`, `RELEASED`, `RELEASE_FAILED`.
  There is no delete, remove, clear or close method.
- `register` is idempotent by `control_key`.
- Status changes follow a fixed table: `ACTIVE` / `RELEASE_FAILED` -> `RELEASE_PENDING` ->
  `RELEASED` or `RELEASE_FAILED`.
- The identity fields of a registration never change between events.
- `SUPERSEDED`: when a later approved package writes the same key again (the earlier write had no
  effect), the entry is replaced and the history kept, so it points at the control really in force.
- Backends: `InMemoryControlRegistry` (tests, simulator), `JsonlControlRegistry` (default; each line
  hash-chained, an edited or forged line is refused on replay) and `SqliteControlRegistry`
  (append-only table protected by triggers). Path: `runtime.registry_path`
  (default `var/registry/controls.jsonl`).

### Rollback catalog

| Control | Rollback action | Checklist line |
|---|---|---|
| `isolate_endpoint` | `release_endpoint` | Restore endpoint connectivity |
| `block_domain` | `unblock_domain` | Remove temporary {vendor} domain block |
| `block_url` | `unblock_url` | Remove temporary {vendor} URL block |
| `block_ip` | `unblock_ip` | Remove temporary {vendor} IP block |
| `block_hash` | `unblock_hash` | Remove temporary {vendor} hash block |
| `disable_user` | `enable_user` | Re-enable {vendor} account |
| `quarantine_email` | `release_email` | Release quarantined email |
| `block_network_client` | `restore_network_client` | Restore {vendor} network client policy |
| `remove_privileged_role` | `restore_privileged_role` (always ELEVATED) | Restore privileged role assignment |
| `quarantine_file` | `restore_file` | Restore quarantined file |

The rollback parameters are captured at containment time (for example the Umbrella destination ID,
the Defender indicator ID, the Entra role assignment fields). The endpoints each rollback uses, and
which are VERIFIED, are in [integrations.md](integrations.md).

### Review reminders

`review_after_hours` in [config/thresholds.yaml](../config/thresholds.yaml) sets `review_due_at` per
action type (for example `isolate_endpoint: 24`, `block_hash: 720`). `registry.due_for_review()`
lists `ACTIVE` / `RELEASE_FAILED` controls whose review is due, plus every `RELEASE_PENDING` control
(a release that may have died before reaching the vendor). It is a reminder only. Nothing is
released.

## Release flow

1. **Propose.** `ResponseOrchestrator.propose_release(incident_id, control_keys=None)` calls
   `RestorationPlanner.build_release_package`
   ([restoration/planner.py](../src/xdr_response/restoration/planner.py)) and moves the incident to
   `AWAITING_RELEASE_APPROVAL`. Allowed from `CONTAINED`, `PARTIALLY_CONTAINED`,
   `REMEDIATION_REQUIRED`, `RESTORED` (other controls still active) and `CLOSED`.
2. **Decide.** A human approves with purpose `release` (`APPROVE_ALL` or `APPROVE_SELECTED`), or
   rejects. Same `ApprovalEngine`, same rules: authenticated `HUMAN` principals only, roles, quorum,
   elevated role for `ELEVATED` actions.
3. **Execute.** `AWAITING_RELEASE_APPROVAL -> RESTORATION_RUNNING` and
   `RestorationEngine.execute(package, token)` runs automatically.
4. **Verify and finish.** Each rollback is verified. The incident moves to `RESTORED`, or back to
   `AWAITING_RELEASE_APPROVAL` when controls remain in force.

### Release package

`ReleasePackage` has the same shape as a containment package, plus `control_keys` (one per action,
in order). Each action:

- has `action_type` = the control's `rollback_action_type` and the same target;
- has `params` = the recorded `rollback_params` plus `restores=<control_key>` (nothing else);
- has idempotency key `<incident_id>:<rollback_action_type>:<target>`;
- cites registry evidence (`source: temporary_control_registry`) naming the containment package,
  token and status of the control.

Selection:

- Without `control_keys`: every control of the incident in force (`ACTIVE` or `RELEASE_FAILED`)
  **with confirmed automation provenance**.
- With `control_keys`: exactly those keys. An unknown key, a key of another incident, a control that
  is `RELEASE_PENDING` or `RELEASED`, or a duplicate raises `RegistryError`. No wildcards, no
  tenant-wide release.

Provenance: an entry counts as created by automation only when its approval token was consumed for
exactly that control key (token-use ledger) and its execution record, when present, succeeded. An
entry without provenance (for example a manual block registered by hand) is never auto-selected.
Named explicitly, it gets an `ELEVATED` warning and the engine refuses to release it.

A release action is `ELEVATED`, with an explicit warning, when any of these holds
(`required_release_level`, one rule for planner and engine):

- the control was created under `ELEVATED` approval, or the rollback type is always elevated;
- the target is a critical asset **now** ([config/critical-assets.yaml](../config/critical-assets.yaml)
  is evaluated at release time, including group, tag and IP context from the incident's asset
  record);
- another incident depends on the same control (it holds its own control on the target, or its
  approved containment found the target `ALREADY_CONTAINED`). Releasing lifts its containment too,
  so the warning names that incident.

Allow-lists never block a release.

### Release decisions

| Decision | Result |
|---|---|
| `APPROVE_ALL` / `APPROVE_SELECTED` | release token issued; `RESTORATION_RUNNING`; rollbacks run automatically |
| `REJECT` (comment required) | `REMEDIATION_REQUIRED`; controls stay `ACTIVE` |
| `REQUEST_MORE_INVESTIGATION` (comment required) | `REMEDIATION_REQUIRED`; controls stay `ACTIVE` |

### Restoration engine

`RestorationEngine.execute` ([restoration/engine.py](../src/xdr_response/restoration/engine.py)):

1. Dry run: simulated only (`Would release endpoint: ...`), registry untouched.
2. Live: re-validates the package (`control_keys` must be exactly what the actions restore). A
   release-purpose token is mandatory and must bind this package. Refusals are audited
   `GUARD_DENIED`.
3. Per approved action, in order, the engine re-reads the registry entry. It must exist, belong to
   the incident and still be in force. The action must match the record exactly: rollback type,
   target, params (`rollback_params` + `restores`, so also the original integration), approval level
   at least `required_release_level`, confirmed provenance, and the evidence must name the current
   registration (so a used release approval cannot be replayed after the key was re-registered).
   - Not in force any more: `SKIPPED` / `CONTROL_NOT_ACTIVE` (nothing to release; left out of the
     overall result).
   - Binding problem: `FAILED` / `APPROVAL_DENIED`, not executed.
   - Otherwise: mark `RELEASE_PENDING`, run the rollback through `ActionRunner` (same guard, same
     `@state_changing` re-verification), verify, then mark `RELEASED` (effective and verified) or
     `RELEASE_FAILED` (still in force; can be released again with a new approval).
4. One failure never stops other actions.
5. Overall, from the final registry status of **every** control in the package:

| Situation | Overall | Incident state |
|---|---|---|
| all released | `RESTORED` | `RESTORED` |
| none released | `RESTORATION_FAILED` | `AWAITING_RELEASE_APPROVAL` |
| some released | `PARTIALLY_RESTORED` | `AWAITING_RELEASE_APPROVAL` |

A selective release never reports `RESTORED` while package controls remain in force. Audit records:
`RESTORATION_RESULT` per action, `RESTORATION_COMPLETED` per run with `released` and
`still_in_force` lists.

## Closing never releases

- `ResponseOrchestrator.close()` changes the incident state only. It never touches the registry.
- The close reason gets a note listing the controls still in force (including `RELEASE_PENDING`).
- Closing revokes approvals of unexecuted packages, so nothing can run against a closed incident.
- `CLOSED -> AWAITING_RELEASE_APPROVAL` exists so controls of a closed incident can still be
  released later, with a human release approval.
- `AWAITING_RELEASE_APPROVAL -> CLOSED` is allowed: the analyst can close and leave controls active.

## Sample release package

Produced by `python tools/simulator/simulate.py ransomware_domain_controller --live` after
containment of TH-LT-1047 and TH-DC-02. The release of TH-DC-02 is `ELEVATED` twice over: the
original isolation was approved at `ELEVATED` level, and TH-DC-02 is still a domain controller.

```
RELEASE APPROVAL REQUIRED  XDR-RW-2002
Ransomware lateral movement to domain controllers
Temporary controls to release: 2
Evidence:
  [1] temporary_control_registry: Temporary control isolate_endpoint on TH-DC-02 was created by automation for incident XDR-RW-2002 via secure_endpoint (containment package 00000000000000000000000000000001, approval token 00000000000000000000000000000003); status ACTIVE
  [2] temporary_control_registry: Temporary control isolate_endpoint on TH-LT-1047 was created by automation for incident XDR-RW-2002 via secure_endpoint (containment package 00000000000000000000000000000001, approval token 00000000000000000000000000000003); status ACTIVE
Release checklist:
  [ ] Restore endpoint connectivity: TH-DC-02    (ELEVATED)  via secure_endpoint  restores XDR-RW-2002:isolate_endpoint:TH-DC-02
  [ ] Restore endpoint connectivity: TH-LT-1047  (STANDARD)  via secure_endpoint  restores XDR-RW-2002:isolate_endpoint:TH-LT-1047
WARNING: ELEVATED APPROVAL REQUIRED
  Action: release_endpoint TH-DC-02
  Role: control created under ELEVATED approval or privileged rollback
  Potential impact: Release an endpoint from isolation for TH-DC-02; restores access that was removed during containment
  Detail: release_endpoint on TH-DC-02 (control XDR-RW-2002:isolate_endpoint:TH-DC-02)
  Reason: the original control was approved at ELEVATED level, or the rollback is privileged
  Requires an approver holding the elevated approval role. The action is not blocked.
WARNING: ELEVATED APPROVAL REQUIRED
  Action: release_endpoint TH-DC-02
  Asset: TH-DC-02 (domain_controller)
  Role: Active Directory domain controller
  Potential impact: Isolating or disabling a domain controller can stop authentication, Group Policy and DNS for the whole domain.
  Detail: release_endpoint on Domain controller TH-DC-02 (role: Active Directory domain controller). Potential impact: Isolating or disabling a domain controller can stop authentication, Group Policy and DNS for the whole domain.
  Requires an approver holding the elevated approval role. The action is not blocked.
Controls not listed here stay ACTIVE. Closing the incident never removes controls.
Package 00000000000000000000000000000005  workflow ransomware-containment 1.0.0  evidence sha256 0c85e87a399f  approve before 2026-01-15T16:00:00Z
[APPROVE RELEASE] [REJECT]

Release APPROVE_ALL; incident now RESTORED

=== Restoration result ===
RESTORATION RESULT  XDR-RW-2002
Overall: RESTORED
Package 00000000000000000000000000000005  approval token 00000000000000000000000000000007
Started 2026-01-15T12:00:00Z  finished 2026-01-15T12:00:00Z
Results:
  [SUCCESS]  release_endpoint TH-DC-02    via secure_endpoint  verification VERIFIED
  [SUCCESS]  release_endpoint TH-LT-1047  via secure_endpoint  verification VERIFIED
```

Notes:

- The release token (`...0007`) is a different token from the containment token (`...0003`).
- After a partial containment only the successful controls appear. In the partial-failure example of
  [containment-model.md](containment-model.md#live-partial-failure) the release package lists the
  hash block and the isolation only. The failed Umbrella and Meraki blocks were never registered.
- In `account_takeover` the attacker IP was `ALREADY_CONTAINED`, so the release package holds only
  `Re-enable Entra account: jsmith@example.com`. The pre-existing IP block is left alone.
- A dry run creates no controls. The simulator prints
  `None: a dry run creates no temporary controls, so there is nothing to release.`

## Code map

| Concern | Module |
|---|---|
| Registry | [restoration/registry.py](../src/xdr_response/restoration/registry.py) |
| Release planning, provenance, release level | [restoration/planner.py](../src/xdr_response/restoration/planner.py) |
| Release execution | [restoration/engine.py](../src/xdr_response/restoration/engine.py) |
| Release checklist rendering | [reporting/release_checklist.py](../src/xdr_response/reporting/release_checklist.py) |
| Lifecycle | [lifecycle/orchestrator.py](../src/xdr_response/lifecycle/orchestrator.py) |
| Safety tests | [tests/safety/test_restoration_authority.py](../tests/safety/test_restoration_authority.py) |
