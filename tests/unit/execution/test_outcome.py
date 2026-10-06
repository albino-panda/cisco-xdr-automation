"""Overall containment / restoration calculation (architecture section 6.4)."""
from __future__ import annotations

import pytest

from tests.unit.execution.execution_harness import make_result
from xdr_response.execution import (
    compute_containment_overall,
    compute_restoration_overall,
    is_effective,
    to_incident_state,
)
from xdr_response.models import (
    ActionResultStatus as S,
    ContainmentOverall as C,
    IncidentState,
    RestorationOverall as R,
    SkipReason,
    VerificationStatus as V,
)

OK = lambda n="1": make_result(S.SUCCESS, V.VERIFIED, key_suffix=n)  # noqa: E731
FAIL = lambda n="2": make_result(S.FAILED, None, key_suffix=n)  # noqa: E731
REJECTED = lambda n="3": make_result(S.SKIPPED, None, skip_reason=SkipReason.REJECTED_BY_ANALYST, key_suffix=n)  # noqa: E731


@pytest.mark.parametrize("results, expected", [
    ([OK("1"), OK("2")], C.CONTAINED),
    ([OK("1"), FAIL("2")], C.PARTIALLY_CONTAINED),
    ([FAIL("1"), FAIL("2")], C.CONTAINMENT_FAILED),
    ([OK("1"), REJECTED("2")], C.CONTAINED),
    ([REJECTED("1")], C.CONTAINMENT_FAILED),
    ([], C.CONTAINMENT_FAILED),
    ([make_result(S.ALREADY_CONTAINED, V.VERIFIED)], C.CONTAINED),
    ([make_result(S.SUCCESS, V.NOT_VERIFIED)], C.CONTAINMENT_FAILED),
    ([OK("1"), make_result(S.SUCCESS, V.NOT_VERIFIED, key_suffix="2")], C.PARTIALLY_CONTAINED),
    ([make_result(S.SUCCESS, V.UNABLE_TO_VERIFY)], C.PARTIALLY_CONTAINED),
    ([OK("1"), make_result(S.SKIPPED, None, skip_reason=SkipReason.NO_CAPABLE_ADAPTER, key_suffix="2")],
     C.PARTIALLY_CONTAINED),
    ([make_result(S.SKIPPED, None, skip_reason=SkipReason.INTEGRATION_DISABLED)], C.CONTAINMENT_FAILED),
])
def test_containment_overall(results, expected):
    assert compute_containment_overall(results) is expected


def test_unable_to_verify_counts_only_with_flag():
    results = [OK("1"), make_result(S.SUCCESS, V.UNABLE_TO_VERIFY, key_suffix="2")]
    assert compute_containment_overall(results) is C.PARTIALLY_CONTAINED
    assert compute_containment_overall(results, unable_to_verify_counts_as_contained=True) is C.CONTAINED


def test_success_without_verification_is_not_effective():
    result = make_result(S.SUCCESS, None)
    assert not is_effective(result, unable_to_verify_counts=True)
    assert compute_containment_overall([result]) is C.PARTIALLY_CONTAINED


def test_one_unrelated_failure_never_fails_the_whole_run():
    results = [OK("1"), OK("2"), FAIL("3")]
    assert compute_containment_overall(results) is C.PARTIALLY_CONTAINED


def test_dry_run_results_have_no_overall():
    with pytest.raises(ValueError):
        compute_containment_overall([make_result(S.DRY_RUN, None)])


@pytest.mark.parametrize("results, expected", [
    ([OK("1")], R.RESTORED),
    ([OK("1"), FAIL("2")], R.PARTIALLY_RESTORED),
    ([FAIL("1")], R.RESTORATION_FAILED),
    ([make_result(S.SKIPPED, None, skip_reason=SkipReason.CONTROL_NOT_ACTIVE)], R.RESTORATION_FAILED),
])
def test_restoration_overall(results, expected):
    assert compute_restoration_overall(results) is expected


@pytest.mark.parametrize("overall, state", [
    (C.CONTAINED, IncidentState.CONTAINED),
    (C.PARTIALLY_CONTAINED, IncidentState.PARTIALLY_CONTAINED),
    (C.CONTAINMENT_FAILED, IncidentState.CONTAINMENT_FAILED),
    (R.RESTORED, IncidentState.RESTORED),
    (R.PARTIALLY_RESTORED, IncidentState.AWAITING_RELEASE_APPROVAL),
    (R.RESTORATION_FAILED, IncidentState.AWAITING_RELEASE_APPROVAL),
])
def test_to_incident_state(overall, state):
    assert to_incident_state(overall) is state


def test_to_incident_state_rejects_other_values():
    with pytest.raises(TypeError):
        to_incident_state("CONTAINED")  # type: ignore[arg-type]
