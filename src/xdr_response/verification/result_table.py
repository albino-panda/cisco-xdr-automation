"""The "Containment Result" table (architecture section 6.5).

Example::

    CONTAINMENT RESULT  XDR-83921  PARTIALLY_CONTAINED
    Action                                   Status             Verification       Note
    isolate_endpoint TH-LT-1047              SUCCESS            VERIFIED
    block_domain evil.example.com            SUCCESS            VERIFIED
    revoke_sessions jsmith@example.com       FAILED             -                  HTTP 403 (AUTH_FAILED)
    Requires attention: revoke_sessions jsmith@example.com
    Error: HTTP 403 (AUTH_FAILED): Forbidden
    Recommended escalation: Microsoft 365 administrator

Only already-redacted fields (``ErrorInfo.message``, verification details) are rendered.
"""
from __future__ import annotations

from dataclasses import dataclass

from xdr_response.models import ActionResultStatus, VerificationStatus
from xdr_response.verification.outcome import ActionAssessment, ActionVerdict, ContainmentAssessment

__all__ = ["ResultRow", "build_result_rows", "render_result_table", "NO_VALUE"]

NO_VALUE = "-"
_ACTION_WIDTH = 41
_STATUS_WIDTH = 19
_VERIFY_WIDTH = 19


@dataclass(frozen=True)
class ResultRow:
    """One table row."""

    action: str
    status: str
    verification: str
    note: str = ""


def _note(a: ActionAssessment) -> str:
    if a.verdict is ActionVerdict.EXCLUDED:
        return "rejected by analyst" if a.reason == "REJECTED_BY_ANALYST" else a.reason.lower()
    if a.status is ActionResultStatus.FAILED:
        if a.error is None:
            return "failed"
        prefix = f"HTTP {a.error.http_status} " if a.error.http_status else ""
        return f"{prefix}({a.error.code.value})"
    if a.status is ActionResultStatus.SKIPPED:
        return a.reason
    if a.verification is VerificationStatus.NOT_VERIFIED:
        return "control not in effect"
    if a.verification is not VerificationStatus.VERIFIED:
        return "verify manually"
    if a.status is ActionResultStatus.ALREADY_CONTAINED:
        return "already in place"
    return ""


def build_result_rows(assessment: ContainmentAssessment) -> tuple[ResultRow, ...]:
    """Rows in package (result) order."""
    return tuple(
        ResultRow(
            action=a.label,
            status=a.status.value,
            verification=a.verification.value if a.verification else NO_VALUE,
            note=_note(a),
        )
        for a in assessment.actions
    )


def _format_row(cells: tuple[str, str, str, str], action_width: int) -> str:
    action, status, verification, note = cells
    line = (action.ljust(action_width) + status.ljust(_STATUS_WIDTH)
            + verification.ljust(_VERIFY_WIDTH) + note)
    return line.rstrip()


def _title(assessment: ContainmentAssessment) -> str:
    kind = "RESTORATION RESULT" if assessment.restoration else "CONTAINMENT RESULT"
    overall = assessment.overall.value if assessment.overall is not None else "DRY RUN"
    return f"{kind}  {assessment.incident_id}  {overall}"


def _attention_block(a: ActionAssessment) -> list[str]:
    lines = [f"Requires attention: {a.label}"]
    if a.error is not None and a.status is ActionResultStatus.FAILED:
        lines.append(f"Error: {a.reason}")
    elif a.reason:
        lines.append(f"Reason: {a.reason}")
    if a.escalation:
        lines.append(f"Recommended escalation: {a.escalation}")
    return lines


def render_result_table(assessment: ContainmentAssessment) -> str:
    """Render the result table, then one block per action requiring attention."""
    rows = build_result_rows(assessment)
    width = max([_ACTION_WIDTH] + [len(r.action) + 2 for r in rows])
    lines = [_title(assessment),
             _format_row(("Action", "Status", "Verification", "Note"), width)]
    lines.extend(_format_row((r.action, r.status, r.verification, r.note), width) for r in rows)
    for a in assessment.attention:
        lines.extend(_attention_block(a))
    if assessment.recommended_next_state is not None:
        lines.append(f"Recommended next state: {assessment.recommended_next_state.value} "
                     "(requires analyst action)")
    return "\n".join(lines)
