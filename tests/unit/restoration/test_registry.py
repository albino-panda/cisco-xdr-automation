"""TemporaryControlRegistry backends and control_from_result."""
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from tests.fixtures.factories import FIXED_NOW, make_package, make_recommendation
from tests.fixtures.guard_helpers import make_token
from xdr_response.clock import FixedClock
from xdr_response.errors import RegistryError
from xdr_response.interfaces import ControlRegistry
from xdr_response.models import (
    ActionOutcome,
    ActionResult,
    ActionResultStatus,
    ActionType,
    ApprovalPurpose,
    ControlStatus,
    ErrorCode,
    ErrorInfo,
)
from xdr_response.restoration import (
    ControlEventType,
    InMemoryControlRegistry,
    JsonlControlRegistry,
    SqliteControlRegistry,
    control_from_result,
)

ERROR = ErrorInfo(code=ErrorCode.UNAVAILABLE, message="HTTP 503", integration="secure_endpoint")
BACKENDS = ("memory", "jsonl", "sqlite")


@pytest.fixture(params=BACKENDS)
def make_registry(request, tmp_path: Path, clock: FixedClock):
    """Factory returning a registry of the parametrized backend; reopening reuses the same storage."""
    opened: list[SqliteControlRegistry] = []

    def factory():
        if request.param == "memory":
            return InMemoryControlRegistry(clock=clock)
        if request.param == "jsonl":
            return JsonlControlRegistry(tmp_path / "registry" / "controls.jsonl", clock=clock)
        registry = SqliteControlRegistry(tmp_path / "registry" / "controls.db", clock=clock)
        opened.append(registry)
        return registry

    yield factory
    for registry in opened:
        registry.close()


@pytest.fixture
def registry(make_registry):
    return make_registry()


def test_backends_implement_the_protocol(registry) -> None:
    assert isinstance(registry, ControlRegistry)


def test_registry_has_no_removal_api(registry) -> None:
    for name in ("delete", "remove", "clear", "purge", "unregister", "drop", "close_incident"):
        assert not hasattr(registry, name)


def test_register_and_get(registry, control_factory) -> None:
    control = control_factory()
    assert registry.register(control) == control
    stored = registry.get(control.control_key)
    assert stored == control
    assert stored.status is ControlStatus.ACTIVE
    assert stored.rollback_action_type is ActionType.RELEASE_ENDPOINT
    assert registry.get("XDR-83921:isolate_endpoint:UNKNOWN") is None


def test_register_is_idempotent_by_key(registry, control_factory) -> None:
    first = registry.register(control_factory())
    again = registry.register(control_factory(rollback_params={"connector_guid": "different"}))
    assert again == first
    assert len(registry.history(first.control_key)) == 1


def test_register_rejects_non_active_and_release_fields(registry, control_factory) -> None:
    control = control_factory()
    with pytest.raises(RegistryError):
        registry.register(control.model_copy(update={"status": ControlStatus.RELEASE_FAILED}))
    with pytest.raises(RegistryError):
        registry.register(control.model_copy(update={"release_package_id": "rel-1"}))
    assert registry.get(control.control_key) is None


def test_register_refuses_secret_like_rollback_params(registry, control_factory) -> None:
    control = control_factory(rollback_params={"connector_guid": "g-1", "nested": {"api_key": "x"}})
    with pytest.raises(RegistryError, match="secret"):
        registry.register(control)


def test_release_lifecycle_appends_events(registry, control_factory, clock) -> None:
    key = registry.register(control_factory()).control_key
    pending = registry.mark_release_pending(key, release_package_id="rel-001", token_id="tok-1")
    assert pending.status is ControlStatus.RELEASE_PENDING
    assert (pending.release_package_id, pending.release_token_id) == ("rel-001", "tok-1")
    released = registry.mark_released(key, at=FIXED_NOW + timedelta(minutes=5))
    assert released.status is ControlStatus.RELEASED
    assert released.released_at == FIXED_NOW + timedelta(minutes=5)
    events = [e.event for e in registry.history(key)]
    assert events == [ControlEventType.REGISTERED, ControlEventType.RELEASE_PENDING, ControlEventType.RELEASED]


def test_failed_release_keeps_control_in_force_and_retryable(registry, control_factory) -> None:
    key = registry.register(control_factory()).control_key
    registry.mark_release_pending(key, release_package_id="rel-001", token_id="tok-1")
    failed = registry.mark_release_failed(key, error=ERROR)
    assert failed.status is ControlStatus.RELEASE_FAILED and failed.last_error == ERROR
    assert registry.list_releasable("XDR-83921") == [failed]
    assert registry.list_active("XDR-83921") == []
    retry = registry.mark_release_pending(key, release_package_id="rel-002", token_id="tok-2")
    assert retry.release_package_id == "rel-002"
    assert registry.mark_released(key, at=FIXED_NOW).last_error is None


@pytest.mark.parametrize("operation", ["released", "failed"])
def test_status_changes_require_release_pending(registry, control_factory, operation) -> None:
    key = registry.register(control_factory()).control_key
    with pytest.raises(RegistryError, match="not RELEASE_PENDING"):
        if operation == "released":
            registry.mark_released(key, at=FIXED_NOW)
        else:
            registry.mark_release_failed(key, error=ERROR)


def test_unknown_key_is_rejected(registry) -> None:
    with pytest.raises(RegistryError, match="unknown control key"):
        registry.mark_release_pending("XDR-1:isolate_endpoint:NOPE", release_package_id="r", token_id="t")


def test_released_or_pending_controls_cannot_be_released_again(registry, control_factory) -> None:
    key = registry.register(control_factory()).control_key
    registry.mark_release_pending(key, release_package_id="rel-001", token_id="tok-1")
    with pytest.raises(RegistryError):
        registry.mark_release_pending(key, release_package_id="rel-002", token_id="tok-2")
    with pytest.raises(RegistryError, match="being released"):
        registry.register(control_factory())
    registry.mark_released(key, at=FIXED_NOW)
    with pytest.raises(RegistryError):
        registry.mark_release_pending(key, release_package_id="rel-003", token_id="tok-3")


def test_released_control_can_be_registered_again(registry, control_factory) -> None:
    key = registry.register(control_factory()).control_key
    registry.mark_release_pending(key, release_package_id="rel-001", token_id="tok-1")
    registry.mark_released(key, at=FIXED_NOW)
    again = registry.register(control_factory())
    assert again.status is ControlStatus.ACTIVE
    assert len(registry.history(key)) == 4


def test_list_filters_by_incident_and_status(registry, control_factory) -> None:
    a = registry.register(control_factory())
    b = registry.register(control_factory(action_type=ActionType.BLOCK_DOMAIN, target="bad.example.test",
                                          integration="umbrella"))
    other = registry.register(control_factory(incident_id="XDR-00002"))
    registry.mark_release_pending(b.control_key, release_package_id="rel-1", token_id="tok-1")
    assert {c.control_key for c in registry.list(incident_id="XDR-83921")} == {a.control_key, b.control_key}
    assert registry.list_active("XDR-83921") == [a]
    assert [c.control_key for c in registry.list(status=ControlStatus.RELEASE_PENDING)] == [b.control_key]
    assert registry.list_active("XDR-00002") == [other]


def test_review_due_is_a_reminder_only(registry, control_factory, clock) -> None:
    control = registry.register(control_factory(review_after_hours={"isolate_endpoint": 24}))
    assert control.review_due_at == FIXED_NOW + timedelta(hours=24)
    assert registry.due_for_review(FIXED_NOW) == []
    due = registry.due_for_review(FIXED_NOW + timedelta(hours=25))
    assert [c.control_key for c in due] == [control.control_key]
    assert registry.get(control.control_key).status is ControlStatus.ACTIVE


@pytest.mark.parametrize("backend", ["jsonl", "sqlite"])
def test_state_survives_reopen(tmp_path: Path, control_factory, clock, backend) -> None:
    def open_registry():
        if backend == "jsonl":
            return JsonlControlRegistry(tmp_path / "controls.jsonl", clock=clock)
        return SqliteControlRegistry(tmp_path / "controls.db", clock=clock)

    first = open_registry()
    key = first.register(control_factory()).control_key
    first.mark_release_pending(key, release_package_id="rel-001", token_id="tok-1")
    first.mark_release_failed(key, error=ERROR)
    reopened = open_registry()
    control = reopened.get(key)
    assert control.status is ControlStatus.RELEASE_FAILED and control.last_error == ERROR
    assert [e.event for e in reopened.history(key)][-1] is ControlEventType.RELEASE_FAILED
    for registry in (first, reopened):
        if isinstance(registry, SqliteControlRegistry):
            registry.close()


# ---------------------------------------------------------------- backends --
def test_jsonl_tampered_line_fails_closed(tmp_path: Path, control_factory, clock) -> None:
    path = tmp_path / "controls.jsonl"
    JsonlControlRegistry(path, clock=clock).register(control_factory())
    path.write_text(path.read_text(encoding="utf-8") + "{not json\n", encoding="utf-8")
    with pytest.raises(RegistryError, match="invalid JSON"):
        JsonlControlRegistry(path, clock=clock)


def test_jsonl_sequence_gap_fails_closed(tmp_path: Path, control_factory, clock) -> None:
    path = tmp_path / "controls.jsonl"
    registry = JsonlControlRegistry(path, clock=clock)
    key = registry.register(control_factory()).control_key
    registry.mark_release_pending(key, release_package_id="rel-1", token_id="tok-1")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n", encoding="utf-8")  # drop the REGISTERED event
    with pytest.raises(RegistryError, match="sequence gap"):
        JsonlControlRegistry(path, clock=clock)


def test_jsonl_lines_are_append_only_events(tmp_path: Path, control_factory, clock) -> None:
    path = tmp_path / "controls.jsonl"
    registry = JsonlControlRegistry(path, clock=clock)
    key = registry.register(control_factory()).control_key
    registry.mark_release_pending(key, release_package_id="rel-1", token_id="tok-1")
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [(e["seq"], e["event"]) for e in events] == [(0, "REGISTERED"), (1, "RELEASE_PENDING")]


def test_sqlite_events_table_rejects_update_and_delete(tmp_path: Path, control_factory, clock) -> None:
    path = tmp_path / "controls.db"
    with SqliteControlRegistry(path, clock=clock) as registry:
        registry.register(control_factory())
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM control_events")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE control_events SET event = 'RELEASED'")
    finally:
        conn.close()


def test_sqlite_failed_transaction_rolls_back(control_factory, clock) -> None:
    with SqliteControlRegistry(clock=clock) as registry:
        key = registry.register(control_factory()).control_key
        with pytest.raises(RegistryError):
            registry.mark_released(key, at=FIXED_NOW)
        assert registry.get(key).status is ControlStatus.ACTIVE
        assert len(registry.history(key)) == 1


# ---------------------------------------------------------- control_from_result --
def _containment(action_type: ActionType = ActionType.ISOLATE_ENDPOINT, target: str = "TH-LT-1047",
                 integration: str = "secure_endpoint"):
    action = make_recommendation(action_type, target, integration)
    package = make_package(action, package_id="pkg-test")
    token = make_token(action, purpose=ApprovalPurpose.CONTAINMENT)
    return action, package, token


def _result(action, status: ActionResultStatus = ActionResultStatus.SUCCESS) -> ActionResult:
    return ActionResult(idempotency_key=action.idempotency_key, action_type=action.action_type,
                        target=action.target, integration=action.integration,
                        approval_level=action.approval_level, status=status,
                        started_at=FIXED_NOW, finished_at=FIXED_NOW)


def _outcome(status: ActionResultStatus = ActionResultStatus.SUCCESS, **params) -> ActionOutcome:
    return ActionOutcome(status=status, integration="secure_endpoint", rollback_params=params,
                         executed_at=FIXED_NOW, external_ref="ext-1")


def test_control_from_result_records_provenance(clock) -> None:
    action, package, token = _containment()
    control = control_from_result(action, _result(action), _outcome(connector_guid="g-1"), package=package,
                                  token=token, decision_id="dec-1", review_after_hours={}, clock=clock)
    assert control.control_key == action.idempotency_key == "XDR-83921:isolate_endpoint:TH-LT-1047"
    assert (control.package_id, control.token_id, control.decision_id) == ("pkg-test", token.token_id, "dec-1")
    assert control.rollback_params == {"connector_guid": "g-1", "integration": "secure_endpoint"}
    assert control.review_due_at is None and control.external_ref == "ext-1"


def test_already_contained_is_never_registered(clock) -> None:
    action, package, token = _containment()
    with pytest.raises(RegistryError, match="ALREADY_CONTAINED"):
        control_from_result(action, _result(action, ActionResultStatus.ALREADY_CONTAINED),
                            _outcome(ActionResultStatus.ALREADY_CONTAINED), package=package, token=token,
                            decision_id="dec-1", review_after_hours={}, clock=clock)


def test_non_reversible_action_creates_no_control(clock) -> None:
    action, package, token = _containment(ActionType.REVOKE_SESSIONS, "j.doe@example.com", "entra")
    with pytest.raises(RegistryError, match="does not create"):
        control_from_result(action, _result(action), _outcome(), package=package, token=token,
                            decision_id="dec-1", review_after_hours={}, clock=clock)


def test_control_needs_the_containment_token_of_its_package(clock) -> None:
    action, package, _ = _containment()
    other = make_recommendation(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella")
    for token in (make_token(other, purpose=ApprovalPurpose.CONTAINMENT),
                  make_token(action, purpose=ApprovalPurpose.RELEASE)):
        with pytest.raises(RegistryError):
            control_from_result(action, _result(action), _outcome(), package=package, token=token,
                                decision_id="dec-1", review_after_hours={}, clock=clock)
