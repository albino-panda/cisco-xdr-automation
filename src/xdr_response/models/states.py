"""Incident lifecycle transition table (architecture sections 2.2 and 13.9).

Defined here (layer 0) so every component can check transitions without importing the lifecycle
package; ``xdr_response.lifecycle.states`` re-exports these names.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from xdr_response.models.enums import ApprovalPurpose, IncidentState

__all__ = ["ALLOWED_TRANSITIONS", "TOKEN_REQUIRED", "REPORT_REQUIRED", "OUTCOME_ACTOR", "OUTCOME_STATES",
           "can_transition"]

_S = IncidentState

ALLOWED_TRANSITIONS: Mapping[IncidentState, frozenset[IncidentState]] = MappingProxyType({
    _S.NOT_STARTED: frozenset({_S.AWAITING_APPROVAL, _S.CLOSED}),
    _S.AWAITING_APPROVAL: frozenset({_S.APPROVED, _S.NOT_STARTED, _S.CLOSED}),
    _S.APPROVED: frozenset({_S.CONTAINMENT_RUNNING, _S.CONTAINMENT_FAILED}),
    _S.CONTAINMENT_RUNNING: frozenset({_S.CONTAINED, _S.PARTIALLY_CONTAINED, _S.CONTAINMENT_FAILED}),
    _S.CONTAINED: frozenset({_S.REMEDIATION_REQUIRED, _S.AWAITING_RELEASE_APPROVAL, _S.CLOSED}),
    _S.PARTIALLY_CONTAINED: frozenset(
        {_S.AWAITING_APPROVAL, _S.REMEDIATION_REQUIRED, _S.AWAITING_RELEASE_APPROVAL, _S.CLOSED}
    ),
    _S.CONTAINMENT_FAILED: frozenset({_S.AWAITING_APPROVAL, _S.REMEDIATION_REQUIRED, _S.CLOSED}),
    _S.REMEDIATION_REQUIRED: frozenset({_S.AWAITING_APPROVAL, _S.AWAITING_RELEASE_APPROVAL, _S.CLOSED}),
    _S.AWAITING_RELEASE_APPROVAL: frozenset({_S.RESTORATION_RUNNING, _S.REMEDIATION_REQUIRED, _S.CLOSED}),
    _S.RESTORATION_RUNNING: frozenset({_S.RESTORED, _S.AWAITING_RELEASE_APPROVAL}),
    _S.RESTORED: frozenset({_S.AWAITING_RELEASE_APPROVAL, _S.CLOSED}),
    _S.CLOSED: frozenset({_S.AWAITING_RELEASE_APPROVAL, _S.NOT_STARTED}),
})

#: Entering these states requires an approval token of the given purpose.
TOKEN_REQUIRED: Mapping[IncidentState, ApprovalPurpose] = MappingProxyType({
    _S.APPROVED: ApprovalPurpose.CONTAINMENT,
    _S.RESTORATION_RUNNING: ApprovalPurpose.RELEASE,
})


#: Entering these states records an execution outcome: it needs the (live, non dry-run) execution
#: report of the package whose overall result is exactly this state ("contained" / "restored"),
#: recorded by :data:`OUTCOME_ACTOR`. CONTAINED is never recorded without an executed, verified run.
REPORT_REQUIRED: Mapping[IncidentState, str] = MappingProxyType({
    _S.CONTAINED: "containment",
    _S.PARTIALLY_CONTAINED: "containment",
    _S.RESTORED: "restoration",
})
#: The only actor that records an execution outcome (the verification step of the lifecycle).
OUTCOME_ACTOR = "automation:verification"
#: Outcome states an AI actor may never record.
OUTCOME_STATES = frozenset({_S.CONTAINED, _S.PARTIALLY_CONTAINED, _S.CONTAINMENT_FAILED, _S.RESTORED})


def can_transition(from_state: IncidentState, to_state: IncidentState) -> bool:
    try:
        f, t = IncidentState(from_state), IncidentState(to_state)
    except ValueError:
        return False
    return t in ALLOWED_TRANSITIONS[f]
