"""RestorationPlanner: release packages only from controls in force of the same incident."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW, make_incident
from xdr_response.errors import RegistryError
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    ControlStatus,
    ErrorCode,
    ErrorInfo,
    IncidentState,
    ReleasePackage,
    StateTransition,
)
from xdr_response.restoration import RestorationPlanner

ENDPOINT_KEY = "XDR-83921:isolate_endpoint:TH-LT-1047"
DOMAIN_KEY = "XDR-83921:block_domain:bad.example.test"


def _contain_two(env) -> None:
    env.contain()
    env.contain(action_type=ActionType.BLOCK_DOMAIN, target="bad.example.test", integration="umbrella")


def test_package_contains_all_controls_in_force_of_the_incident(env) -> None:
    _contain_two(env)
    env.contain(incident_id="XDR-00002", target="TH-LT-2000")  # another incident
    package = env.planner.build_release_package(env.incident)
    assert isinstance(package, ReleasePackage)
    assert package.purpose is ApprovalPurpose.RELEASE
    assert set(package.control_keys) == {ENDPOINT_KEY, DOMAIN_KEY}
    assert all(a.incident_id == "XDR-83921" for a in package.actions)
    assert package.package_id == "rel-001"
    assert package.expires_at == FIXED_NOW + timedelta(minutes=240)
    assert package.endpoints == ("TH-LT-1047",)


def test_release_action_mirrors_the_registry_entry(env) -> None:
    control = env.contain()
    package = env.planner.build_release_package(env.incident, [control.control_key])
    (action,) = package.actions
    assert action.action_type is ActionType.RELEASE_ENDPOINT
    assert action.target == "TH-LT-1047"
    assert action.idempotency_key == "XDR-83921:release_endpoint:TH-LT-1047"
    assert action.params == {**control.rollback_params, "restores": ENDPOINT_KEY}
    assert action.params["integration"] == "secure_endpoint"
    assert action.approval_level is ApprovalLevel.STANDARD and action.warnings == ()
    (evidence,) = action.evidence
    assert evidence.source == "temporary_control_registry"
    assert evidence.reference == ENDPOINT_KEY
    assert evidence.data["token_id"] == control.token_id
    assert package.evidence == (evidence,)


def test_privileged_role_release_is_elevated_with_warning(env) -> None:
    env.contain(action_type=ActionType.REMOVE_PRIVILEGED_ROLE, target="role-assignment-0001",
                integration="entra")
    (action,) = env.planner.build_release_package(env.incident).actions
    assert action.action_type is ActionType.RESTORE_PRIVILEGED_ROLE
    assert action.approval_level is ApprovalLevel.ELEVATED
    assert action.warnings and action.warnings[0].message.startswith("WARNING: ELEVATED APPROVAL REQUIRED")


def test_elevated_containment_gives_elevated_release(env) -> None:
    env.contain(approval_level=ApprovalLevel.ELEVATED)
    (action,) = env.planner.build_release_package(env.incident).actions
    assert action.approval_level is ApprovalLevel.ELEVATED


def test_released_and_pending_controls_are_excluded(env) -> None:
    _contain_two(env)
    env.registry.mark_release_pending(DOMAIN_KEY, release_package_id="rel-x", token_id="tok-x")
    package = env.planner.build_release_package(env.incident)
    assert package.control_keys == (ENDPOINT_KEY,)
    with pytest.raises(RegistryError, match="RELEASE_PENDING"):
        env.planner.build_release_package(env.incident, [DOMAIN_KEY])
    env.registry.mark_released(DOMAIN_KEY, at=FIXED_NOW)
    with pytest.raises(RegistryError, match="RELEASED"):
        env.planner.build_release_package(env.incident, [DOMAIN_KEY])


def test_unregistered_control_key_is_rejected(env) -> None:
    env.contain()
    with pytest.raises(RegistryError, match="unknown control key"):
        env.planner.build_release_package(env.incident, ["XDR-83921:isolate_endpoint:TH-LT-9999"])


def test_control_of_another_incident_is_rejected(env) -> None:
    other = env.contain(incident_id="XDR-00002", target="TH-LT-2000")
    with pytest.raises(RegistryError, match="another incident"):
        env.planner.build_release_package(env.incident, [other.control_key])
    with pytest.raises(RegistryError, match="no temporary controls"):
        env.planner.build_release_package(env.incident)


def test_duplicate_or_string_keys_are_rejected(env) -> None:
    env.contain()
    with pytest.raises(RegistryError, match="duplicate"):
        env.planner.build_release_package(env.incident, [ENDPOINT_KEY, ENDPOINT_KEY])
    with pytest.raises(TypeError):
        env.planner.build_release_package(env.incident, ENDPOINT_KEY)


def test_failed_release_can_be_planned_again(env) -> None:
    env.contain()
    env.registry.mark_release_pending(ENDPOINT_KEY, release_package_id="rel-x", token_id="tok-x")
    env.registry.mark_release_failed(ENDPOINT_KEY, error=ErrorInfo(code=ErrorCode.TIMEOUT, message="timeout"))
    assert env.planner.build_release_package(env.incident).control_keys == (ENDPOINT_KEY,)


def test_closing_an_incident_keeps_controls_releasable(env) -> None:
    _contain_two(env)
    before = env.registry.list(incident_id="XDR-83921")
    closed = make_incident(state=IncidentState.CLOSED, history=(
        StateTransition(from_state=IncidentState.CONTAINED, to_state=IncidentState.CLOSED, at=FIXED_NOW,
                        actor="analyst.one@example.com", reason="closed by analyst"),
    ))
    assert env.registry.list(incident_id="XDR-83921") == before
    assert all(c.status is ControlStatus.ACTIVE for c in before)
    assert {c.control_key for c in env.planner.outstanding(closed.incident_id)} == {ENDPOINT_KEY, DOMAIN_KEY}
    package = env.planner.build_release_package(closed)
    assert set(package.control_keys) == {ENDPOINT_KEY, DOMAIN_KEY}
    assert not any(hasattr(RestorationPlanner, name) for name in ("close", "release_all", "expire"))
