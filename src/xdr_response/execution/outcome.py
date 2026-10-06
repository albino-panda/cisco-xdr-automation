"""Overall containment / restoration result calculation (architecture section 6.4).

Rules (deterministic):

* Only actions that were not ``SKIPPED`` for ``REJECTED_BY_ANALYST`` are considered.
* An action **failed** when its status is ``FAILED``, ``SKIPPED`` for any other reason, or its
  verification is ``NOT_VERIFIED``.
* An action is **confirmed** (:func:`is_effective`) when its status is ``SUCCESS`` or
  ``ALREADY_CONTAINED`` and its verification is ``VERIFIED`` (or ``UNABLE_TO_VERIFY`` when the
  ``unable_to_verify_counts_as_contained`` flag is set; default false).
* Every considered action failed (or none was considered): ``*_FAILED``. Every one confirmed:
  ``CONTAINED`` / ``RESTORED``. Anything else: ``PARTIALLY_*``.
* Restoration also leaves out ``SKIPPED`` for ``CONTROL_NOT_ACTIVE``: that control was no longer in
  force, so there was nothing to release.

This module is the single rule set. :mod:`xdr_response.verification.outcome` builds its per-action
assessments on :func:`classify_action` and delegates its overall calculation here.
"""
from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from xdr_response.models import (
    ActionResult,
    ActionResultStatus,
    ContainmentOverall,
    IncidentState,
    RestorationOverall,
    SkipReason,
    VerificationStatus,
)

__all__ = [
    "ActionVerdict",
    "classify_action",
    "is_effective",
    "is_failed",
    "is_considered",
    "compute_containment_overall",
    "compute_restoration_overall",
    "to_incident_state",
]

_EXECUTED = (ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED)


class ActionVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"  # executed (or already in place) and verified
    UNCONFIRMED = "UNCONFIRMED"  # executed, but verification could not confirm it
    FAILED = "FAILED"  # not executed, or verification shows it is not in effect
    EXCLUDED = "EXCLUDED"  # rejected by the analyst, dry run, or (restoration) nothing to release


def is_considered(result: ActionResult, *, restoration: bool = False) -> bool:
    """False for actions the analyst did not approve (and, in a release, controls no longer active)."""
    if result.status is ActionResultStatus.SKIPPED:
        if result.skip_reason is SkipReason.REJECTED_BY_ANALYST:
            return False
        if restoration and result.skip_reason is SkipReason.CONTROL_NOT_ACTIVE:
            return False
    return True


def is_failed(result: ActionResult) -> bool:
    """True for FAILED, SKIPPED (other than rejected) and NOT_VERIFIED actions."""
    if result.status is ActionResultStatus.FAILED:
        return True
    if result.status is ActionResultStatus.SKIPPED:
        return result.skip_reason is not SkipReason.REJECTED_BY_ANALYST
    verification = result.verification
    return verification is not None and verification.status is VerificationStatus.NOT_VERIFIED


def classify_action(result: ActionResult, *, unable_to_verify_counts: bool = False,
                    restoration: bool = False) -> ActionVerdict:
    """Verdict for one action under the rules of section 6.4 (DRY_RUN results are EXCLUDED)."""
    if result.status is ActionResultStatus.DRY_RUN or not is_considered(result, restoration=restoration):
        return ActionVerdict.EXCLUDED
    if is_failed(result):
        return ActionVerdict.FAILED
    if result.status in _EXECUTED and result.verification is not None:
        status = result.verification.status
        if status is VerificationStatus.VERIFIED:
            return ActionVerdict.CONFIRMED
        if status is VerificationStatus.UNABLE_TO_VERIFY and unable_to_verify_counts:
            return ActionVerdict.CONFIRMED
    return ActionVerdict.UNCONFIRMED


def is_effective(result: ActionResult, *, unable_to_verify_counts: bool) -> bool:
    """True when the action executed (or was already in place) and verification confirms it."""
    return classify_action(result, unable_to_verify_counts=unable_to_verify_counts) is ActionVerdict.CONFIRMED


def _classify(results: Sequence[ActionResult], unable_to_verify_counts: bool,
              restoration: bool = False) -> tuple[int, int, int]:
    """Return (considered, failed, confirmed) counts. DRY_RUN results are a programming error."""
    considered = failed = confirmed = 0
    for result in results:
        if result.status is ActionResultStatus.DRY_RUN:
            raise ValueError("dry-run results have no overall state")
        verdict = classify_action(result, unable_to_verify_counts=unable_to_verify_counts,
                                  restoration=restoration)
        if verdict is ActionVerdict.EXCLUDED:
            continue
        considered += 1
        if verdict is ActionVerdict.FAILED:
            failed += 1
        elif verdict is ActionVerdict.CONFIRMED:
            confirmed += 1
    return considered, failed, confirmed


def compute_containment_overall(results: Sequence[ActionResult], *,
                                unable_to_verify_counts_as_contained: bool = False) -> ContainmentOverall:
    """Overall containment state of a real (non dry-run) execution."""
    considered, failed, confirmed = _classify(results, unable_to_verify_counts_as_contained)
    if considered == 0 or failed == considered:
        return ContainmentOverall.CONTAINMENT_FAILED
    if confirmed == considered:
        return ContainmentOverall.CONTAINED
    return ContainmentOverall.PARTIALLY_CONTAINED


def compute_restoration_overall(results: Sequence[ActionResult], *,
                                unable_to_verify_counts_as_contained: bool = False) -> RestorationOverall:
    """Overall restoration state of a real (non dry-run) release execution."""
    considered, failed, confirmed = _classify(results, unable_to_verify_counts_as_contained, restoration=True)
    if considered == 0 or failed == considered:
        return RestorationOverall.RESTORATION_FAILED
    if confirmed == considered:
        return RestorationOverall.RESTORED
    return RestorationOverall.PARTIALLY_RESTORED


_STATE_MAP: dict[str, IncidentState] = {
    ContainmentOverall.CONTAINED.value: IncidentState.CONTAINED,
    ContainmentOverall.PARTIALLY_CONTAINED.value: IncidentState.PARTIALLY_CONTAINED,
    ContainmentOverall.CONTAINMENT_FAILED.value: IncidentState.CONTAINMENT_FAILED,
    RestorationOverall.RESTORED.value: IncidentState.RESTORED,
    RestorationOverall.PARTIALLY_RESTORED.value: IncidentState.AWAITING_RELEASE_APPROVAL,
    RestorationOverall.RESTORATION_FAILED.value: IncidentState.AWAITING_RELEASE_APPROVAL,
}


def to_incident_state(overall: ContainmentOverall | RestorationOverall) -> IncidentState:
    """Incident state that follows an overall result (partial/failed restoration -> awaiting release)."""
    if not isinstance(overall, (ContainmentOverall, RestorationOverall)):
        raise TypeError(f"expected ContainmentOverall or RestorationOverall, got {type(overall).__name__}")
    return _STATE_MAP[overall.value]
