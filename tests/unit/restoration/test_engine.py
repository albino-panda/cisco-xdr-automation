"""RestorationEngine: approved releases run automatically under the guard; everything else is refused."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW, make_evidence
from xdr_response import guard
from xdr_response.config.schema import RuntimeSettings, Settings, Thresholds, VerificationSettings
from xdr_response.errors import ApprovalRequiredError, RegistryError, TokenMismatchError
from xdr_response.models import (
    ActionRequest,
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    AuditEventType,
    ContainmentReport,
    ControlStatus,
    ErrorCode,
    RecommendedAction,
    ReleasePackage,
    RestorationOverall,
    SkipReason,
    TargetKind,
    VerificationStatus,
    evidence_snapshot_hash,
)

ENDPOINT_KEY = "XDR-83921:isolate_endpoint:TH-LT-1047"
DOMAIN_KEY = "XDR-83921:block_domain:bad.example.test"
USER_KEY = "XDR-83921:disable_user:j.doe@example.com"


def _contain_three(env) -> None:
    env.contain()
    env.contain(action_type=ActionType.BLOCK_DOMAIN, target="bad.example.test", integration="umbrella")
    env.contain(action_type=ActionType.DISABLE_USER, target="j.doe@example.com", integration="entra")


def _status(env, key: str) -> ControlStatus:
    return env.registry.get(key).status


# ------------------------------------------------------------ happy path --
def test_approved_release_runs_automatically_and_marks_released(env, token_factory) -> None:
    _contain_three(env)
    package = env.planner.build_release_package(env.incident)
    token = token_factory(package)
    report = env.engine().execute(package, token)
    assert report.overall is RestorationOverall.RESTORED
    assert not report.dry_run and report.token_id == token.token_id
    assert [r.status for r in report.results] == [ActionResultStatus.SUCCESS] * 3
    assert env.adapter_calls() == 3
    for key in (ENDPOINT_KEY, DOMAIN_KEY, USER_KEY):
        control = env.registry.get(key)
        assert control.status is ControlStatus.RELEASED
        assert (control.release_package_id, control.release_token_id) == (package.package_id, token.token_id)
        assert control.released_at == FIXED_NOW
    results = env.audit.of(AuditEventType.RESTORATION_RESULT)
    assert {r.payload["control_key"] for r in results} == {ENDPOINT_KEY, DOMAIN_KEY, USER_KEY}
    assert all(r.payload["control_status"] == "RELEASED" for r in results)
    (completed,) = env.audit.of(AuditEventType.RESTORATION_COMPLETED)
    assert completed.payload["overall"] == "RESTORED" and completed.payload["still_in_force"] == []


def test_already_released_at_vendor_counts_as_released(env, token_factory) -> None:
    env.contain()
    env.adapters["secure_endpoint"].already_released.add("TH-LT-1047")
    package = env.planner.build_release_package(env.incident)
    report = env.engine().execute(package, token_factory(package))
    assert report.results[0].status is ActionResultStatus.ALREADY_CONTAINED
    assert report.overall is RestorationOverall.RESTORED
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASED


# ------------------------------------------------------- approval required --
def test_release_without_approval_fails(env) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    with pytest.raises(ApprovalRequiredError, match="release approval"):
        env.engine().execute(package, None)
    assert env.adapter_calls() == 0 and env.runner.runs == []
    assert _status(env, ENDPOINT_KEY) is ControlStatus.ACTIVE


def test_containment_token_cannot_release(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    with pytest.raises(TokenMismatchError, match="containment"):
        env.engine().execute(package, token_factory(package, purpose=ApprovalPurpose.CONTAINMENT))
    assert env.adapter_calls() == 0 and _status(env, ENDPOINT_KEY) is ControlStatus.ACTIVE


def test_rollback_adapter_method_refuses_direct_calls(env) -> None:
    env.contain()
    action = env.planner.build_release_package(env.incident).actions[0]
    with pytest.raises(ApprovalRequiredError):
        env.adapters["secure_endpoint"].release_endpoint(ActionRequest.from_recommendation(action))
    assert env.adapters["secure_endpoint"].calls == []


def test_expired_release_token_is_denied_by_the_guard(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    token = token_factory(package, ttl=timedelta(minutes=30))
    env.verifier.clock.advance(timedelta(hours=1))
    report = env.engine().execute(package, token)
    assert report.results[0].status is ActionResultStatus.FAILED
    assert report.results[0].error.code is ErrorCode.APPROVAL_DENIED
    assert env.adapter_calls() == 0
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASE_FAILED  # still in force, retryable
    assert report.overall is RestorationOverall.RESTORATION_FAILED


def test_token_must_bind_this_package(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    other_package = package.model_copy(update={"package_id": "rel-other"})
    with pytest.raises(TokenMismatchError, match="package_id"):
        env.engine().execute(package, token_factory(other_package))
    assert env.adapter_calls() == 0


def test_tampered_params_do_not_match_the_grant(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    token = token_factory(package)
    action = package.actions[0]
    tampered_action = action.model_copy(update={"params": {**action.params, "connector_guid": "evil"}})
    tampered = package.model_copy(update={"actions": (tampered_action,)})
    with pytest.raises(TokenMismatchError, match="does not match"):
        env.engine().execute(tampered, token)
    assert env.adapter_calls() == 0


def test_verify_package_of_the_token_service_is_called(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    token = token_factory(package)

    class StrictTokens:
        def __init__(self, inner) -> None:
            self.inner, self.checked = inner, []

        def verify(self, *args, **kwargs):
            return self.inner.verify(*args, **kwargs)

        def mark_used(self, *args, **kwargs):
            return self.inner.mark_used(*args, **kwargs)

        def verify_package(self, tok, pkg) -> None:
            self.checked.append((tok.token_id, pkg.package_id))
            raise TokenMismatchError("signature invalid (test)")

    tokens = StrictTokens(env.verifier)
    with pytest.raises(TokenMismatchError, match="signature"):
        env.engine(tokens=tokens).execute(package, token)
    assert tokens.checked == [(token.token_id, package.package_id)]
    assert env.adapter_calls() == 0


# -------------------------------------------- other incident / unregistered --
def test_another_incident_cannot_release(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    with pytest.raises(TokenMismatchError, match="incident_id"):
        env.engine().execute(package, token_factory(package, incident_id="XDR-00002"))
    assert env.adapter_calls() == 0 and _status(env, ENDPOINT_KEY) is ControlStatus.ACTIVE


def _forged_package(env, *, incident_id: str, restores: str, target: str = "TH-LT-1047") -> ReleasePackage:
    """A release package built by hand, bypassing the planner."""
    evidence = make_evidence(1, source="temporary_control_registry")
    action = RecommendedAction(
        incident_id=incident_id, idempotency_key=f"{incident_id}:release_endpoint:{target}",
        action_type=ActionType.RELEASE_ENDPOINT, target=target, target_kind=TargetKind.ENDPOINT,
        params={"integration": "secure_endpoint", "restores": restores}, evidence=evidence,
        risk_score=0, confidence_score=100, approval_level=ApprovalLevel.STANDARD,
    )
    return ReleasePackage(
        package_id="rel-forged", incident_id=incident_id, workflow_id="powershell", workflow_version="1.0.0",
        created_at=FIXED_NOW, expires_at=FIXED_NOW + timedelta(hours=1), requested_by="analyst.one@example.com",
        severity="HIGH", risk_score=0, confidence_score=100, summary="forged", evidence=evidence,
        evidence_snapshot_hash=evidence_snapshot_hash(evidence), actions=(action,), control_keys=(restores,),
    )


def test_package_of_another_incident_cannot_release_this_incidents_control(env, token_factory) -> None:
    env.contain()  # control of XDR-83921
    package = _forged_package(env, incident_id="XDR-00002", restores=ENDPOINT_KEY)
    report = env.engine().execute(package, token_factory(package))  # validly approved for XDR-00002
    (result,) = report.results
    assert result.status is ActionResultStatus.FAILED and result.error.code is ErrorCode.APPROVAL_DENIED
    assert "another incident" in result.message
    assert env.adapter_calls() == 0 and env.runner.runs == []
    assert _status(env, ENDPOINT_KEY) is ControlStatus.ACTIVE
    assert report.overall is RestorationOverall.RESTORATION_FAILED and report.attention


def test_release_of_an_unregistered_control_fails(env, token_factory) -> None:
    package = _forged_package(env, incident_id="XDR-83921", restores=ENDPOINT_KEY)  # never registered
    report = env.engine().execute(package, token_factory(package))
    (result,) = report.results
    assert result.status is ActionResultStatus.FAILED and "not registered" in result.message
    assert env.adapter_calls() == 0 and env.runner.runs == []
    assert env.registry.get(ENDPOINT_KEY) is None


def test_action_must_match_the_recorded_rollback(env, token_factory) -> None:
    env.contain()
    package = _forged_package(env, incident_id="XDR-83921", restores=ENDPOINT_KEY, target="TH-LT-9999")
    (result,) = env.engine().execute(package, token_factory(package)).results
    assert result.status is ActionResultStatus.FAILED and "does not match" in result.message
    assert env.adapter_calls() == 0 and _status(env, ENDPOINT_KEY) is ControlStatus.ACTIVE


# --------------------------------------------------------------- partial --
def test_partial_restoration_then_new_approval_releases_the_rest(env, token_factory) -> None:
    _contain_three(env)
    env.adapters["umbrella"].fail_targets.add("bad.example.test")
    package = env.planner.build_release_package(env.incident)
    report = env.engine().execute(package, token_factory(package))
    assert report.overall is RestorationOverall.PARTIALLY_RESTORED
    by_key = {r.idempotency_key: r for r in report.results}
    failed = by_key["XDR-83921:unblock_domain:bad.example.test"]
    assert failed.status is ActionResultStatus.FAILED and failed.error.code is ErrorCode.UNAVAILABLE
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASED
    assert _status(env, USER_KEY) is ControlStatus.RELEASED
    domain = env.registry.get(DOMAIN_KEY)
    assert domain.status is ControlStatus.RELEASE_FAILED and domain.last_error.code is ErrorCode.UNAVAILABLE
    assert any("bad.example.test" in line for line in report.attention)
    # second human approval for what is still in force
    env.adapters["umbrella"].fail_targets.clear()
    retry = env.planner.build_release_package(env.incident)
    assert retry.control_keys == (DOMAIN_KEY,)
    second = env.engine().execute(retry, token_factory(retry))
    assert second.overall is RestorationOverall.RESTORED
    assert _status(env, DOMAIN_KEY) is ControlStatus.RELEASED


def test_one_runner_crash_does_not_stop_other_releases(env, token_factory) -> None:
    _contain_three(env)
    env.runner.raise_for.add("TH-LT-1047")
    package = env.planner.build_release_package(env.incident)
    report = env.engine().execute(package, token_factory(package))
    by_key = {r.idempotency_key: r for r in report.results}
    crashed = by_key["XDR-83921:release_endpoint:TH-LT-1047"]
    assert crashed.status is ActionResultStatus.FAILED and crashed.error.code is ErrorCode.INTERNAL
    assert report.overall is RestorationOverall.PARTIALLY_RESTORED
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASE_FAILED
    assert _status(env, DOMAIN_KEY) is ControlStatus.RELEASED


def test_unable_to_verify_is_not_released_by_default(env, token_factory) -> None:
    env.contain()
    env.adapters["secure_endpoint"].verification["TH-LT-1047"] = VerificationStatus.UNABLE_TO_VERIFY
    package = env.planner.build_release_package(env.incident)
    report = env.engine().execute(package, token_factory(package))
    assert report.overall is RestorationOverall.RESTORATION_FAILED
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASE_FAILED
    assert any("verify manually" in line for line in report.attention)


def test_unable_to_verify_counts_when_configured(env, token_factory) -> None:
    env.contain()
    env.adapters["secure_endpoint"].verification["TH-LT-1047"] = VerificationStatus.UNABLE_TO_VERIFY
    settings = Settings(runtime=RuntimeSettings(dry_run=False), thresholds=Thresholds(
        verification=VerificationSettings(unable_to_verify_counts_as_contained=True)))
    package = env.planner.build_release_package(env.incident)
    report = env.engine(settings=settings).execute(package, token_factory(package))
    assert report.overall is RestorationOverall.RESTORED
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASED


def test_not_verified_release_keeps_control_in_force(env, token_factory) -> None:
    env.contain()
    env.adapters["secure_endpoint"].verification["TH-LT-1047"] = VerificationStatus.NOT_VERIFIED
    package = env.planner.build_release_package(env.incident)
    report = env.engine().execute(package, token_factory(package))
    assert report.overall is RestorationOverall.RESTORATION_FAILED
    control = env.registry.get(ENDPOINT_KEY)
    assert control.status is ControlStatus.RELEASE_FAILED and "NOT_VERIFIED" in control.last_error.message


def test_approve_selected_releases_only_approved_controls(env, token_factory) -> None:
    _contain_three(env)
    package = env.planner.build_release_package(env.incident)
    approved = "XDR-83921:release_endpoint:TH-LT-1047"
    report = env.engine().execute(package, token_factory(package, keys=(approved,)))
    by_key = {r.idempotency_key: r for r in report.results}
    assert by_key[approved].status is ActionResultStatus.SUCCESS
    skipped = [r for r in report.results if r.idempotency_key != approved]
    assert all(r.skip_reason is SkipReason.REJECTED_BY_ANALYST for r in skipped)
    # every control of the package counts: the two controls the analyst left out are still in force
    assert report.overall is RestorationOverall.PARTIALLY_RESTORED
    assert _status(env, ENDPOINT_KEY) is ControlStatus.RELEASED
    assert _status(env, DOMAIN_KEY) is ControlStatus.ACTIVE and _status(env, USER_KEY) is ControlStatus.ACTIVE


# ------------------------------------------------------------ idempotency --
def test_idempotent_re_release(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    token = token_factory(package)
    env.engine().execute(package, token)
    events_before = len(env.registry.history(ENDPOINT_KEY))
    for again_token in (token, token_factory(package)):  # replayed token and a fresh approval
        report = env.engine().execute(package, again_token)
        (result,) = report.results
        assert result.status is ActionResultStatus.SKIPPED
        assert result.skip_reason is SkipReason.CONTROL_NOT_ACTIVE
        assert report.overall is RestorationOverall.RESTORED
    assert env.adapter_calls() == 1 and len(env.runner.runs) == 1
    assert len(env.registry.history(ENDPOINT_KEY)) == events_before
    with pytest.raises(RegistryError, match="no temporary controls"):
        env.planner.build_release_package(env.incident)


# ---------------------------------------------------------------- dry run --
def test_global_dry_run_simulates_without_token_or_changes(env) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    guard.configure(dry_run=True)
    report = env.engine().execute(package, None)
    assert report.dry_run and report.overall is None and report.token_id is None
    (result,) = report.results
    assert result.status is ActionResultStatus.DRY_RUN
    assert result.dry_run_line == "Would release endpoint: TH-LT-1047"
    assert env.adapter_calls() == 0 and _status(env, ENDPOINT_KEY) is ControlStatus.ACTIVE


def test_per_run_dry_run_never_executes_even_with_a_valid_token(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    report = env.engine().execute(package, token_factory(package), dry_run=True)
    assert report.dry_run and env.adapter_calls() == 0 and env.runner.runs == []
    assert len(env.registry.history(ENDPOINT_KEY)) == 1


def test_dry_run_uses_the_injected_simulator(env) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    seen = []

    class Simulator:
        def simulate(self, pkg):
            seen.append(guard.is_dry_run())
            return ContainmentReport(report_id="sim", incident_id=pkg.incident_id, package_id=pkg.package_id,
                                     token_id=None, dry_run=True, started_at=FIXED_NOW, finished_at=FIXED_NOW,
                                     results=(), overall=None)

    report = env.engine(simulator=Simulator()).execute(package, None, dry_run=True)
    assert seen == [True] and report.results == () and report.dry_run


# ------------------------------------------------------------------ audit --
def test_audit_failure_is_surfaced_not_hidden(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    env.audit.fail = True
    report = env.engine().execute(package, token_factory(package))
    assert any("audit write failed for RESTORATION_RESULT" in line for line in report.attention)
    assert any("audit write failed for RESTORATION_COMPLETED" in line for line in report.attention)


def test_audit_payload_never_contains_the_token_signature(env, token_factory) -> None:
    env.contain()
    package = env.planner.build_release_package(env.incident)
    token = token_factory(package)
    env.engine().execute(package, token)
    for record in env.audit.records():
        assert token.encode() not in str(record.payload)
