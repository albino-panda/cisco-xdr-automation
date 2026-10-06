"""Cross-component contracts settled during Phase 0 integration (architecture section 13.23)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW, make_recommendation
from tests.fixtures.principals import make_test_secrets
from tests.unit.verification.verification_fakes import (
    FakeRegistry,
    FakeSleep,
    ScriptedVerifyAdapter,
    make_outcome,
    make_request,
    make_result,
)
from xdr_response.approval import ApprovalTokenService, InMemoryTokenUseLedger
from xdr_response.clock import FixedClock
from xdr_response.config import ApprovalSettings, VerificationSettings
from xdr_response.execution import outcome as execution_outcome
from xdr_response.interfaces import PackageTokenVerifier, TokenVerifier
from xdr_response.models import (
    ActionResultStatus,
    RestorationOverall,
    SkipReason,
    VerificationResult,
    VerificationStatus,
)
from xdr_response.verification import PollPolicy, VerificationEngine
from xdr_response.verification import outcome as verification_outcome

V = VerificationStatus


# ----------------------------------------------------------- one rule set --
def test_verification_and_execution_share_one_classification():
    assert verification_outcome.classify_action is execution_outcome.classify_action
    assert verification_outcome.ActionVerdict is execution_outcome.ActionVerdict
    assert verification_outcome.to_incident_state is execution_outcome.to_incident_state


def test_control_not_active_is_excluded_from_restoration_everywhere():
    released = make_result(status=ActionResultStatus.SUCCESS, verified=V.VERIFIED)
    not_active = make_result(status=ActionResultStatus.SKIPPED, verified=None,
                             skip_reason=SkipReason.CONTROL_NOT_ACTIVE, target="TH-LT-2000")
    for module in (execution_outcome, verification_outcome):
        assert module.compute_restoration_overall([released, not_active]) is RestorationOverall.RESTORED
    # in containment the same skip is a failure (nothing was applied)
    assert execution_outcome.compute_containment_overall([released, not_active]).value == "PARTIALLY_CONTAINED"


def test_dry_run_results_have_no_overall():
    dry = make_result(status=ActionResultStatus.DRY_RUN, verified=None, dry_run_line="Would isolate: TH-LT-1047")
    assert verification_outcome.compute_containment_overall([dry]) is None
    with pytest.raises(ValueError):
        execution_outcome.compute_containment_overall([dry])


# --------------------------------------------------- verification terminal --
def _engine(adapter, clock):
    return VerificationEngine(FakeRegistry(adapter), VerificationSettings(), clock=clock, sleep=FakeSleep(clock),
                              policy=PollPolicy(interval_seconds=10, timeout_seconds=300, backoff_factor=1.5,
                                                max_interval_seconds=60))


def _scripted(status: VerificationStatus, terminal: bool | None, clock: FixedClock) -> ScriptedVerifyAdapter:
    request = make_request()
    result = VerificationResult(idempotency_key=request.idempotency_key, status=status, integration="secure_endpoint",
                                method="read_state", checked_at=FIXED_NOW, details="vendor state", terminal=terminal)
    return ScriptedVerifyAdapter([result], clock=clock)


def test_terminal_not_verified_stops_polling_immediately():
    clock = FixedClock(FIXED_NOW)
    adapter = _scripted(V.NOT_VERIFIED, True, clock)
    assert _engine(adapter, clock).verify(make_request(), make_outcome()).status is V.NOT_VERIFIED
    assert len(adapter.calls) == 1


def test_unknown_terminal_keeps_the_eventual_consistency_default():
    clock = FixedClock(FIXED_NOW)
    adapter = _scripted(V.NOT_VERIFIED, None, clock)
    _engine(adapter, clock).verify(make_request(), make_outcome())
    assert len(adapter.calls) > 1


# --------------------------------------------------------- token verifier --
def test_token_service_implements_both_verifier_protocols():
    service = ApprovalTokenService(make_test_secrets(), ApprovalSettings(), ledger=InMemoryTokenUseLedger())
    assert isinstance(service, TokenVerifier) and isinstance(service, PackageTokenVerifier)


def test_previous_signing_key_id_comes_from_settings():
    secrets = make_test_secrets(APPROVAL_SIGNING_KEY_PREVIOUS="ab" * 32)
    settings = ApprovalSettings(signing_key_id="key-2026", previous_signing_key_id="key-2025")
    service = ApprovalTokenService(secrets, settings, ledger=InMemoryTokenUseLedger())
    assert set(service._keys) == {"key-2026", "key-2025"}  # noqa: SLF001 - rotation wiring check


# --------------------------------------------------------- control factory --
def test_runner_registers_controls_through_the_injected_restoration_factory():
    from tests.fixtures.factories import make_package
    from tests.unit.execution.execution_harness import make_harness
    from xdr_response.execution import ActionRunner
    from xdr_response.restoration import control_from_result

    h = make_harness()
    calls = []

    def factory(*args, **kwargs):
        calls.append(kwargs["decision_id"])
        return control_from_result(*args, **kwargs)

    runner = ActionRunner(h.adapters, h.verification, registry=h.registry, audit=h.audit, clock=h.clock,
                          review_after_hours={"isolate_endpoint": 24}, control_factory=factory)
    action = make_recommendation()
    package = make_package(action)
    result = runner.run(action, h.approve(package), package=package, decision_id="decision-7")
    assert result.control_registered and calls == ["decision-7"]
    control = h.registry.get(action.idempotency_key)
    assert control.review_due_at == FIXED_NOW + timedelta(hours=24)
    assert control.rollback_params["integration"] == "secure_endpoint"
