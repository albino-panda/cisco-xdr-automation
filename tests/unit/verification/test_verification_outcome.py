"""Combining execution and verification into the overall state (architecture section 6.4)."""
from __future__ import annotations

import itertools

import pytest

from tests.unit.verification.verification_fakes import error, make_request, make_result, verification
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    ContainmentOverall,
    ErrorCode,
    IncidentState,
    RestorationOverall,
    SkipReason,
    VerificationStatus,
    can_transition,
)
from xdr_response.verification import (
    PLATFORM_OWNER,
    SOC_ANALYST,
    ActionVerdict,
    apply_verification,
    assess_containment,
    assess_restoration,
    classify_action,
    compute_containment_overall,
    compute_restoration_overall,
    is_effective,
    to_incident_state,
)

S = ActionResultStatus
V = VerificationStatus
INCIDENT = "XDR-83921"


def _ok(action=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047", integration="secure_endpoint"):
    return make_result(action, target, integration)


def _forbidden_email():
    return make_result(ActionType.QUARANTINE_EMAIL, "<MSG-0001@mail.example.com>", "defender_o365",
                       status=S.FAILED, verified=None,
                       error=error(ErrorCode.AUTH_FAILED, http_status=403, integration="defender_o365",
                                   message="Forbidden"))


# ------------------------------------------------------------------- verdicts --
@pytest.mark.parametrize("status, verified, flag, expected", [
    (S.SUCCESS, V.VERIFIED, False, ActionVerdict.CONFIRMED),
    (S.ALREADY_CONTAINED, V.VERIFIED, False, ActionVerdict.CONFIRMED),
    (S.SUCCESS, V.UNABLE_TO_VERIFY, False, ActionVerdict.UNCONFIRMED),
    (S.SUCCESS, V.UNABLE_TO_VERIFY, True, ActionVerdict.CONFIRMED),
    (S.SUCCESS, None, False, ActionVerdict.UNCONFIRMED),
    (S.SUCCESS, None, True, ActionVerdict.UNCONFIRMED),
    (S.SUCCESS, V.NOT_VERIFIED, True, ActionVerdict.FAILED),
    (S.ALREADY_CONTAINED, V.NOT_VERIFIED, False, ActionVerdict.FAILED),
    (S.FAILED, None, False, ActionVerdict.FAILED),
])
def test_classify(status, verified, flag, expected):
    err = error(ErrorCode.API_ERROR) if status is S.FAILED else None
    result = make_result(status=status, verified=verified, error=err)
    assert classify_action(result, unable_to_verify_counts=flag) is expected
    assert is_effective(result, unable_to_verify_counts=flag) is (expected is ActionVerdict.CONFIRMED)


def test_skips_and_dry_runs_classification():
    rejected = make_result(status=S.SKIPPED, verified=None, skip_reason=SkipReason.REJECTED_BY_ANALYST)
    no_adapter = make_result(status=S.SKIPPED, verified=None, skip_reason=SkipReason.NO_CAPABLE_ADAPTER)
    dry = make_result(status=S.DRY_RUN, verified=None, dry_run_line="Would isolate: TH-LT-1047")
    assert classify_action(rejected) is ActionVerdict.EXCLUDED
    assert classify_action(no_adapter) is ActionVerdict.FAILED
    assert classify_action(dry) is ActionVerdict.EXCLUDED


# -------------------------------------------------------------------- overall --
def test_contained_only_when_every_approved_action_is_executed_and_verified():
    results = [_ok(), _ok(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella"),
               make_result(status=S.ALREADY_CONTAINED)]
    assessment = assess_containment(INCIDENT, results)
    assert assessment.overall is ContainmentOverall.CONTAINED
    assert assessment.incident_state is IncidentState.CONTAINED
    assert assessment.attention == ()
    assert assessment.recommended_next_state is None


def test_unable_to_verify_makes_it_partial_by_default():
    results = [_ok(), make_result(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella",
                                  verified=V.UNABLE_TO_VERIFY, details="read timed out; verify manually")]
    assessment = assess_containment(INCIDENT, results)
    assert assessment.overall is ContainmentOverall.PARTIALLY_CONTAINED
    [item] = assessment.attention
    assert item.label == "block_domain bad.example.test"
    assert item.reason.startswith("unable to verify")
    assert item.escalation == SOC_ANALYST
    assert not assessment.remediation_required


def test_unable_to_verify_flag_counts_as_contained_but_still_needs_attention():
    results = [_ok(), make_result(verified=V.UNABLE_TO_VERIFY, target="TH-LT-2000")]
    assessment = assess_containment(INCIDENT, results, unable_to_verify_counts_as_contained=True)
    assert assessment.overall is ContainmentOverall.CONTAINED
    assert len(assessment.attention) == 1


def test_failed_403_on_email_quarantine_escalates_to_m365_admin():
    assessment = assess_containment(INCIDENT, [_ok(), _forbidden_email()])
    assert assessment.overall is ContainmentOverall.PARTIALLY_CONTAINED
    [item] = assessment.attention
    assert item.error is not None and item.error.http_status == 403
    assert item.reason == "HTTP 403 (AUTH_FAILED): Forbidden"
    assert item.escalation == "Microsoft 365 administrator"
    assert assessment.recommended_next_state is IncidentState.REMEDIATION_REQUIRED
    assert assessment.remediation_reasons == (
        "quarantine_email <MSG-0001@mail.example.com>: HTTP 403 (AUTH_FAILED): Forbidden",)


def test_every_action_failed_is_containment_failed():
    results = [_forbidden_email(),
               make_result(verified=V.NOT_VERIFIED, details="host still online")]
    assessment = assess_containment(INCIDENT, results)
    assert assessment.overall is ContainmentOverall.CONTAINMENT_FAILED
    assert assessment.incident_state is IncidentState.CONTAINMENT_FAILED
    assert assessment.remediation_required
    assert len(assessment.remediation_reasons) == 2


def test_not_verified_requires_remediation_and_integration_owner():
    assessment = assess_containment(INCIDENT, [_ok(target="TH-LT-2000"),
                                               make_result(verified=V.NOT_VERIFIED, details="still online")])
    assert assessment.overall is ContainmentOverall.PARTIALLY_CONTAINED
    [item] = assessment.attention
    assert item.reason == "control not in effect: still online"
    assert item.escalation == "Cisco Secure Endpoint administrator"
    assert assessment.recommended_next_state is IncidentState.REMEDIATION_REQUIRED


def test_transient_failures_recommend_a_new_approval_not_remediation():
    timeout = make_result(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella", status=S.FAILED,
                          verified=None, error=error(ErrorCode.TIMEOUT, integration="umbrella",
                                                     retryable=True))
    assessment = assess_containment(INCIDENT, [_ok(), timeout])
    assert assessment.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert assessment.recommended_next_state is IncidentState.AWAITING_APPROVAL
    assert assessment.remediation_reasons == ()
    assert assessment.attention[0].escalation == "Cisco Umbrella administrator"


def test_rejected_actions_are_excluded_from_overall():
    rejected = make_result(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella", status=S.SKIPPED,
                           verified=None, skip_reason=SkipReason.REJECTED_BY_ANALYST)
    assessment = assess_containment(INCIDENT, [_ok(), rejected])
    assert assessment.overall is ContainmentOverall.CONTAINED
    assert assessment.attention == ()


def test_skipped_without_adapter_needs_remediation_by_platform_owner():
    skipped = make_result(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella", status=S.SKIPPED,
                          verified=None, skip_reason=SkipReason.NO_CAPABLE_ADAPTER)
    assessment = assess_containment(INCIDENT, [_ok(), skipped])
    assert assessment.overall is ContainmentOverall.PARTIALLY_CONTAINED
    assert assessment.attention[0].escalation == PLATFORM_OWNER
    assert assessment.remediation_required


def test_one_unrelated_failure_never_fails_the_whole_run():
    failures = [_forbidden_email(),
                make_result(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella", status=S.FAILED,
                            verified=None, error=error(ErrorCode.UNAVAILABLE, integration="umbrella"))]
    for failed in failures:
        for order in itertools.permutations([_ok(), failed]):
            assert compute_containment_overall(order) is ContainmentOverall.PARTIALLY_CONTAINED


def test_dry_run_has_no_overall():
    dry = make_result(status=S.DRY_RUN, verified=None, dry_run_line="Would isolate: TH-LT-1047")
    assessment = assess_containment(INCIDENT, [dry])
    assert assessment.overall is None
    assert assessment.incident_state is None
    assert assessment.recommended_next_state is None


def test_nothing_executed_is_never_reported_as_contained():
    assert compute_containment_overall([]) is ContainmentOverall.CONTAINMENT_FAILED
    rejected = make_result(status=S.SKIPPED, verified=None, skip_reason=SkipReason.REJECTED_BY_ANALYST)
    assert compute_containment_overall([rejected]) is ContainmentOverall.CONTAINMENT_FAILED


def test_recommended_states_are_always_allowed_transitions():
    scenarios = [
        [_ok(), _forbidden_email()],
        [_forbidden_email()],
        [_ok(), make_result(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella", status=S.FAILED,
                            verified=None, error=error(ErrorCode.RATE_LIMITED, integration="umbrella"))],
        [_ok(), make_result(verified=V.NOT_VERIFIED, target="TH-LT-2000")],
    ]
    for results in scenarios:
        assessment = assess_containment(INCIDENT, results)
        assert assessment.recommended_next_state is not None
        assert can_transition(assessment.incident_state, assessment.recommended_next_state)


def test_attention_lines_for_report():
    assessment = assess_containment(INCIDENT, [_ok(), _forbidden_email()])
    assert assessment.attention_lines() == (
        "quarantine_email <MSG-0001@mail.example.com>: HTTP 403 (AUTH_FAILED): Forbidden",)


# ----------------------------------------------------------------- restoration --
def test_restoration_overall():
    release = lambda **kw: make_result(ActionType.RELEASE_ENDPOINT, **kw)  # noqa: E731
    assert compute_restoration_overall([release()]) is RestorationOverall.RESTORED
    partial = [release(), release(target="TH-LT-2000", verified=V.UNABLE_TO_VERIFY)]
    assert compute_restoration_overall(partial) is RestorationOverall.PARTIALLY_RESTORED
    failed = [release(status=S.FAILED, verified=None, error=error(ErrorCode.UNAVAILABLE))]
    assert compute_restoration_overall(failed) is RestorationOverall.RESTORATION_FAILED
    gone = release(target="TH-LT-3000", status=S.SKIPPED, verified=None,
                   skip_reason=SkipReason.CONTROL_NOT_ACTIVE)
    assert compute_restoration_overall([release(), gone]) is RestorationOverall.RESTORED


def test_restoration_assessment_states():
    release = make_result(ActionType.RELEASE_ENDPOINT, status=S.FAILED, verified=None,
                          error=error(ErrorCode.AUTH_FAILED, http_status=401))
    assessment = assess_restoration(INCIDENT, [release])
    assert assessment.restoration
    assert assessment.overall is RestorationOverall.RESTORATION_FAILED
    assert assessment.incident_state is IncidentState.AWAITING_RELEASE_APPROVAL
    assert assessment.recommended_next_state is IncidentState.REMEDIATION_REQUIRED


@pytest.mark.parametrize("overall, state", [
    (ContainmentOverall.CONTAINED, IncidentState.CONTAINED),
    (ContainmentOverall.PARTIALLY_CONTAINED, IncidentState.PARTIALLY_CONTAINED),
    (ContainmentOverall.CONTAINMENT_FAILED, IncidentState.CONTAINMENT_FAILED),
    (RestorationOverall.RESTORED, IncidentState.RESTORED),
    (RestorationOverall.PARTIALLY_RESTORED, IncidentState.AWAITING_RELEASE_APPROVAL),
    (RestorationOverall.RESTORATION_FAILED, IncidentState.AWAITING_RELEASE_APPROVAL),
])
def test_to_incident_state(overall, state):
    assert to_incident_state(overall) is state


# ------------------------------------------------------------ apply_verification --
def test_apply_verification_sets_attention_and_escalation():
    base = make_result(verified=None)
    request = make_request()
    unable = verification(request.idempotency_key, V.UNABLE_TO_VERIFY, details="pending")
    updated = apply_verification(base, unable)
    assert updated.verification == unable
    assert updated.requires_attention is True
    assert updated.recommended_escalation == SOC_ANALYST

    ok = apply_verification(base, verification(request.idempotency_key, V.VERIFIED))
    assert ok.requires_attention is False
    assert ok.recommended_escalation is None


def test_apply_verification_keeps_runner_escalation_hint():
    base = make_result(verified=None, escalation="Endpoint team on call")
    request = make_request()
    updated = apply_verification(base, verification(request.idempotency_key, V.NOT_VERIFIED))
    assert updated.recommended_escalation == "Endpoint team on call"


def test_apply_verification_refuses_foreign_result():
    base = make_result(verified=None)
    other = make_request(target="TH-LT-9999")
    with pytest.raises(ValueError):
        apply_verification(base, verification(other.idempotency_key, V.VERIFIED))
