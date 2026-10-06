"""Record types: every lifecycle event has a payload type and a recorder method."""
from __future__ import annotations

import pytest

from xdr_response import guard
from xdr_response.audit import EVENT_PAYLOAD_TYPES, AuditRecorder, payload_type_for
from xdr_response.audit.events import DEFAULT_ACTOR, GuardDeniedPayload
from xdr_response.errors import ApprovalRequiredError
from xdr_response.models import (
    AuditEventType,
    ContainmentPackage,
    PrincipalKind,
    canonical_json,
    sha256_hex,
)

_RECORDER_METHOD = {e: e.value.lower() for e in AuditEventType}


def test_every_event_type_has_a_payload_type_and_recorder_method():
    assert set(EVENT_PAYLOAD_TYPES) == set(AuditEventType)
    for event, method in _RECORDER_METHOD.items():
        assert callable(getattr(AuditRecorder, method, None)), f"missing AuditRecorder.{method}"
        assert payload_type_for(event.value) is EVENT_PAYLOAD_TYPES[event]


def _record_everything(recorder: AuditRecorder, m) -> dict[AuditEventType, object]:
    """Call one recorder method per event type; returns the records keyed by event type."""
    incident_id = m.incident.incident_id
    out = {
        AuditEventType.INCIDENT_RECEIVED: recorder.incident_received(m.incident),
        AuditEventType.INVESTIGATION_COMPLETED: recorder.investigation_completed(
            incident_id, [m.investigation], evidence=m.evidence),
        AuditEventType.ENRICHMENT_RESULT: recorder.enrichment_result(incident_id, m.enrichment),
        AuditEventType.PACKAGE_PROPOSED: recorder.package_proposed(m.package),
        AuditEventType.DECISION_RECORDED: recorder.decision_recorded(m.decision),
        AuditEventType.TOKEN_ISSUED: recorder.token_issued(m.token),
        AuditEventType.APPROVAL_DENIED: recorder.approval_denied(
            incident_id, reason="AI principals cannot approve", package_id=m.package.package_id,
            principal_id="ai:assistant", principal_kind=PrincipalKind.AI,
            error=ApprovalRequiredError("denied")),
        AuditEventType.GUARD_DENIED: recorder.guard_denied(
            "no verifier registered", m.request, ApprovalRequiredError("denied")),
        AuditEventType.STATE_TRANSITION: recorder.state_transition(incident_id, m.transition),
        AuditEventType.ACTION_STARTED: recorder.action_started(
            m.request, approval_level=m.isolate.approval_level, package_id=m.package.package_id,
            token_id="tok-1"),
        AuditEventType.API_CALL: recorder.api_call(incident_id, m.api_call),
        AuditEventType.ACTION_RESULT: recorder.action_result(incident_id, m.success),
        AuditEventType.VERIFICATION_RESULT: recorder.verification_result(incident_id, m.verification),
        AuditEventType.CONTROL_REGISTERED: recorder.control_registered(m.control),
        AuditEventType.CONTAINMENT_COMPLETED: recorder.containment_completed(m.report),
        AuditEventType.RELEASE_PACKAGE_PROPOSED: recorder.release_package_proposed(m.release_package),
        AuditEventType.RESTORATION_RESULT: recorder.restoration_result(incident_id, m.restored),
        AuditEventType.RESTORATION_COMPLETED: recorder.restoration_completed(m.restoration_report),
        AuditEventType.DRY_RUN_SIMULATION: recorder.dry_run_simulation(
            incident_id, ["Would isolate: TH-LT-1047"], package_id=m.package.package_id),
        AuditEventType.HEALTH_CHECK: recorder.health_check(m.health),
        AuditEventType.ERROR: recorder.error(incident_id, m.error),
    }
    assert set(out) == set(AuditEventType)
    return out


@pytest.mark.parametrize("kind", ["file", "memory"])
def test_recorder_writes_every_event_and_chain_verifies(kind, make_trail, memory_trail, lifecycle):
    trail = make_trail() if kind == "file" else memory_trail
    recorded = _record_everything(AuditRecorder(trail), lifecycle)
    assert trail.verify().ok
    assert len(trail) == len(AuditEventType)
    for event, record in recorded.items():
        assert record.event_type is event
        # stored payloads parse back into the registered type (nothing in the fixture is redacted)
        EVENT_PAYLOAD_TYPES[event].model_validate(record.payload)


def test_payloads_are_deterministic_across_runs(memory_trail, lifecycle, redactor, clock, ids):
    from xdr_response.audit import MemoryAuditTrail

    first = _record_everything(AuditRecorder(memory_trail), lifecycle)
    other = MemoryAuditTrail(clock=clock, redactor=redactor, id_factory=ids())
    second = _record_everything(AuditRecorder(other), lifecycle)
    for event in AuditEventType:
        assert canonical_json(first[event].payload, allow_floats=True) == \
            canonical_json(second[event].payload, allow_floats=True)


def test_recorder_actor_and_workflow_selection(memory_trail, lifecycle):
    recorder = AuditRecorder(memory_trail, workflow_id="wf-default", workflow_version="9.9.9")
    decision = recorder.decision_recorded(lifecycle.decision)
    assert decision.actor == "analyst.one@example.com"
    assert (decision.workflow_id, decision.workflow_version) == ("powershell", "1.0.0")
    transition = recorder.state_transition("XDR-83921", lifecycle.transition)
    assert transition.actor == "automation:lifecycle"
    api = recorder.api_call("XDR-83921", lifecycle.api_call)
    assert api.actor == DEFAULT_ACTOR
    assert (api.workflow_id, api.workflow_version) == ("wf-default", "9.9.9")
    package = recorder.package_proposed(lifecycle.package)
    assert package.actor == lifecycle.package.requested_by
    health = recorder.health_check(lifecycle.health)
    assert health.incident_id is None


def test_incident_received_payload(memory_trail, lifecycle):
    record = AuditRecorder(memory_trail).incident_received(lifecycle.incident)
    assert record.payload["trigger"] == {"source": "cisco_xdr", "rule": "test-trigger"}
    assert {o["value"] for o in record.payload["observables"]} >= {"TH-LT-1047", "203.0.113.10"}


def test_token_issued_payload_binds_claims_hash(memory_trail, lifecycle):
    record = AuditRecorder(memory_trail).token_issued(lifecycle.token)
    assert record.payload["claims_hash"] == sha256_hex(canonical_json(lifecycle.token.claims))
    assert record.payload["action_keys"] == [lifecycle.isolate.idempotency_key]
    assert "signature" not in record.payload


def test_run_completed_payload_lists_statuses(memory_trail, lifecycle):
    record = AuditRecorder(memory_trail).containment_completed(lifecycle.report)
    assert record.payload["overall"] == "CONTAINED"
    assert record.payload["statuses"] == {lifecycle.isolate.idempotency_key: "SUCCESS",
                                          lifecycle.block.idempotency_key: "SKIPPED"}


def test_record_rejects_wrong_payload_type(memory_trail, lifecycle):
    recorder = AuditRecorder(memory_trail)
    with pytest.raises(TypeError, match="ContainmentPackage"):
        recorder.record(AuditEventType.PACKAGE_PROPOSED, lifecycle.health, incident_id="XDR-83921")
    assert EVENT_PAYLOAD_TYPES[AuditEventType.PACKAGE_PROPOSED] is ContainmentPackage
    assert len(memory_trail) == 0


def test_guard_denial_hook_audits_guard_denied(memory_trail, lifecycle):
    recorder = AuditRecorder(memory_trail)
    guard.set_denial_hook(recorder.guard_denial_hook())
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(lifecycle.token, lifecycle.request):
            pass  # pragma: no cover - never entered: no verifier registered
    records = list(memory_trail.records())
    assert [r.event_type for r in records] == [AuditEventType.GUARD_DENIED]
    payload = GuardDeniedPayload.model_validate(records[0].payload)
    assert payload.idempotency_key == lifecycle.request.idempotency_key
    assert records[0].incident_id == lifecycle.request.incident_id


def test_guard_denied_without_request(memory_trail):
    record = AuditRecorder(memory_trail).guard_denied("no context", None, ApprovalRequiredError("x"))
    assert record.incident_id is None and record.payload["idempotency_key"] is None
