"""IncidentStateMachine and the in-memory stores."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW, make_incident, make_package, make_recommendation
from tests.fixtures.guard_helpers import make_token
from xdr_response.audit import MemoryAuditTrail
from xdr_response.clock import FixedClock
from xdr_response.errors import ApprovalRequiredError, AuditError, InvalidTransitionError, TokenMismatchError
from xdr_response.lifecycle import IncidentStateMachine, InMemoryIncidentStore, InMemoryPackageStore
from xdr_response.models import ApprovalPurpose, AuditEventType, IncidentState, PrincipalKind

S = IncidentState
ANALYST = "analyst.one@example.com"


@pytest.fixture
def setup():
    clock = FixedClock(FIXED_NOW)
    store = InMemoryIncidentStore()
    audit = MemoryAuditTrail(clock=clock)
    store.save(make_incident())
    return IncidentStateMachine(store, audit, clock), store, audit, clock


def _token(package, purpose=ApprovalPurpose.CONTAINMENT, **kw):
    return make_token(*package.actions, purpose=purpose, **kw)


def test_allowed_transition_is_audited_then_saved(setup):
    machine, store, audit, _ = setup
    incident = machine.transition("XDR-83921", S.AWAITING_APPROVAL, actor="automation:lifecycle", reason="r")
    assert incident.state is S.AWAITING_APPROVAL and store.get("XDR-83921") == incident
    record = list(audit.records())[-1]
    assert record.event_type is AuditEventType.STATE_TRANSITION and record.actor == "automation:lifecycle"
    assert record.payload["from_state"] == "NOT_STARTED" and record.payload["to_state"] == "AWAITING_APPROVAL"


def test_disallowed_transition_is_refused(setup):
    machine, store, audit, _ = setup
    with pytest.raises(InvalidTransitionError):
        machine.transition("XDR-83921", S.CONTAINED, actor="automation:lifecycle")
    assert store.get("XDR-83921").state is S.NOT_STARTED and list(audit.records()) == []


def test_approved_requires_a_matching_containment_token_and_an_approver_actor(setup):
    machine, _, _, _ = setup
    package = make_package(make_recommendation())
    machine.transition("XDR-83921", S.AWAITING_APPROVAL, actor="automation:lifecycle")
    with pytest.raises(ApprovalRequiredError):
        machine.transition("XDR-83921", S.APPROVED, actor=ANALYST, package_id=package.package_id)
    token = _token(package)
    with pytest.raises(TokenMismatchError):  # wrong package
        machine.transition("XDR-83921", S.APPROVED, actor=ANALYST, package_id="other", token=token)
    with pytest.raises(TokenMismatchError):  # wrong purpose
        machine.transition("XDR-83921", S.APPROVED, actor=ANALYST, package_id=token.claims.package_id,
                           token=_token(package, ApprovalPurpose.RELEASE))
    with pytest.raises(TokenMismatchError):  # automation cannot enter APPROVED on a human's token
        machine.transition("XDR-83921", S.APPROVED, actor="automation:lifecycle",
                           package_id=token.claims.package_id, token=token)
    with pytest.raises(TokenMismatchError):  # another incident's token
        machine.transition("XDR-83921", S.APPROVED, actor=ANALYST, package_id=token.claims.package_id,
                           token=make_token(make_recommendation(incident_id="XDR-1"), incident_id="XDR-1"))
    approver = token.claims.approvers[0].principal_id
    incident = machine.transition("XDR-83921", S.APPROVED, actor=approver, package_id=token.claims.package_id,
                                  token=token)
    assert incident.state is S.APPROVED and incident.history[-1].token_id == token.token_id


def test_failed_audit_write_leaves_the_incident_unchanged():
    clock = FixedClock(FIXED_NOW)
    store = InMemoryIncidentStore()
    store.save(make_incident())
    audit = MemoryAuditTrail(clock=clock, fail_when=lambda event: event is AuditEventType.STATE_TRANSITION)
    machine = IncidentStateMachine(store, audit, clock)
    with pytest.raises(AuditError):
        machine.transition("XDR-83921", S.AWAITING_APPROVAL, actor="automation:lifecycle")
    assert store.get("XDR-83921").state is S.NOT_STARTED


def test_history_is_append_only(setup):
    machine, _, _, clock = setup
    machine.transition("XDR-83921", S.AWAITING_APPROVAL, actor="automation:lifecycle")
    clock.advance(timedelta(minutes=1))
    incident = machine.transition("XDR-83921", S.CLOSED, actor=ANALYST, reason="false positive")
    assert [(t.from_state, t.to_state) for t in incident.history] == [
        (S.NOT_STARTED, S.AWAITING_APPROVAL), (S.AWAITING_APPROVAL, S.CLOSED)]
    assert incident.history[1].at > incident.history[0].at


def test_actor_is_required(setup):
    machine, _, _, _ = setup
    with pytest.raises(ValueError):
        machine.transition("XDR-83921", S.AWAITING_APPROVAL, actor="")


# ------------------------------------------------------------------ stores --
def test_incident_store_round_trip_and_unknown():
    store = InMemoryIncidentStore()
    incident = make_incident()
    store.save(incident)
    assert store.get("XDR-83921") is incident and store.list() == [incident] and "XDR-83921" in store
    with pytest.raises(KeyError):
        store.get("nope")
    with pytest.raises(TypeError):
        store.save("not an incident")  # type: ignore[arg-type]


def test_package_store_executes_once_and_tracks_latest():
    store = InMemoryPackageStore()
    first = make_package(make_recommendation())
    second = make_package(make_recommendation(target="TH-LT-2000"))
    store.save(first)
    store.save(second)
    store.save(first)  # idempotent re-save of identical content
    assert store.latest_for_incident("XDR-83921", ApprovalPurpose.CONTAINMENT) == second
    assert store.latest_for_incident("XDR-83921", ApprovalPurpose.RELEASE) is None
    assert store.latest_for_incident("XDR-other", ApprovalPurpose.CONTAINMENT) is None
    assert not store.is_executed(first.package_id)
    store.mark_executed(first.package_id)
    assert store.is_executed(first.package_id)
    with pytest.raises(RuntimeError):
        store.mark_executed(first.package_id)
    with pytest.raises(KeyError):
        store.mark_executed("unknown")
    assert store.for_incident("XDR-83921") == [first, second]


def test_package_store_refuses_different_content_under_the_same_id():
    store = InMemoryPackageStore()
    first = make_package(make_recommendation())
    store.save(first)
    tampered = first.model_copy(update={"summary": "changed"})
    with pytest.raises(ValueError):
        store.save(tampered)


def test_kinds_are_human_in_the_token_fixture():
    token = make_token(make_recommendation())
    assert token.claims.approvers[0].kind is PrincipalKind.HUMAN
