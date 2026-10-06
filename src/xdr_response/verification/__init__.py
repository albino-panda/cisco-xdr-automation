"""Post-action verification, overall-state computation and the Containment Result table.

Verification only ever uses read-only adapter calls and never needs the execution guard.
"""
from __future__ import annotations

from xdr_response.verification.engine import (
    NO_VERIFY_METHOD,
    AdapterLookup,
    VerificationAttempt,
    VerificationEngine,
    VerificationTrace,
    resolve_verify_integration,
)
from xdr_response.verification.escalation import (
    DEFAULT_INTEGRATION_OWNERS,
    PLATFORM_OWNER,
    SOC_ANALYST,
    integration_owner,
    recommend_escalation,
)
from xdr_response.verification.outcome import (
    TRANSIENT_ERROR_CODES,
    ActionAssessment,
    ActionVerdict,
    ContainmentAssessment,
    apply_verification,
    assess_action,
    assess_containment,
    assess_restoration,
    classify_action,
    compute_containment_overall,
    compute_restoration_overall,
    is_effective,
    to_incident_state,
)
from xdr_response.verification.policy import PollPolicy
from xdr_response.verification.result_table import ResultRow, build_result_rows, render_result_table

__all__ = [
    "NO_VERIFY_METHOD",
    "AdapterLookup",
    "VerificationAttempt",
    "VerificationEngine",
    "VerificationTrace",
    "resolve_verify_integration",
    "DEFAULT_INTEGRATION_OWNERS",
    "PLATFORM_OWNER",
    "SOC_ANALYST",
    "integration_owner",
    "recommend_escalation",
    "TRANSIENT_ERROR_CODES",
    "ActionAssessment",
    "ActionVerdict",
    "ContainmentAssessment",
    "apply_verification",
    "assess_action",
    "assess_containment",
    "assess_restoration",
    "classify_action",
    "compute_containment_overall",
    "compute_restoration_overall",
    "is_effective",
    "to_incident_state",
    "PollPolicy",
    "ResultRow",
    "build_result_rows",
    "render_result_table",
]
