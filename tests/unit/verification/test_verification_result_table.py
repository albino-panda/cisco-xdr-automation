"""The Containment Result table (architecture section 6.5)."""
from __future__ import annotations

from tests.unit.verification.verification_fakes import error, make_result
from xdr_response.models import ActionResultStatus, ActionType, ErrorCode, SkipReason, VerificationStatus
from xdr_response.verification import assess_containment, assess_restoration, build_result_rows, render_result_table

S = ActionResultStatus
V = VerificationStatus


def _doc_example():
    return [
        make_result(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", "secure_endpoint"),
        make_result(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella"),
        make_result(ActionType.REVOKE_SESSIONS, "jsmith@example.com", "entra", status=S.FAILED,
                    verified=None, error=error(ErrorCode.AUTH_FAILED, http_status=403, integration="entra",
                                               message="Forbidden")),
    ]


def test_matches_documented_layout():
    text = render_result_table(assess_containment("XDR-83921", _doc_example()))
    lines = text.splitlines()
    assert lines[:5] == [
        "CONTAINMENT RESULT  XDR-83921  PARTIALLY_CONTAINED",
        "Action                                   Status             Verification       Note",
        "isolate_endpoint TH-LT-1047              SUCCESS            VERIFIED",
        "block_domain evil.example.com            SUCCESS            VERIFIED",
        "revoke_sessions jsmith@example.com       FAILED             -                  HTTP 403 (AUTH_FAILED)",
    ]
    assert lines[5:8] == [
        "Requires attention: revoke_sessions jsmith@example.com",
        "Error: HTTP 403 (AUTH_FAILED): Forbidden",
        "Recommended escalation: Microsoft 365 administrator",
    ]
    assert lines[8] == "Recommended next state: REMEDIATION_REQUIRED (requires analyst action)"


def test_contained_run_has_no_attention_block():
    results = _doc_example()[:2]
    text = render_result_table(assess_containment("XDR-83921", results))
    assert text.splitlines()[0] == "CONTAINMENT RESULT  XDR-83921  CONTAINED"
    assert "Requires attention" not in text
    assert "Recommended next state" not in text


def test_unable_to_verify_says_verify_manually():
    results = [make_result(verified=V.UNABLE_TO_VERIFY, details="no read-back; verify manually")]
    assessment = assess_containment("XDR-83921", results)
    [row] = build_result_rows(assessment)
    assert (row.status, row.verification, row.note) == ("SUCCESS", "UNABLE_TO_VERIFY", "verify manually")
    text = render_result_table(assessment)
    assert "Requires attention: isolate_endpoint TH-LT-1047" in text
    assert "Reason: unable to verify: no read-back; verify manually" in text
    assert "Recommended escalation: SOC analyst on duty" in text


def test_rejected_and_already_contained_notes():
    results = [
        make_result(status=S.ALREADY_CONTAINED),
        make_result(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella", status=S.SKIPPED,
                    verified=None, skip_reason=SkipReason.REJECTED_BY_ANALYST),
    ]
    rows = build_result_rows(assess_containment("XDR-83921", results))
    assert [r.note for r in rows] == ["already in place", "rejected by analyst"]
    assert rows[1].verification == "-"


def test_long_labels_widen_the_action_column():
    target = "very-long-hostname-for-column-width-check.corp.example.com"
    results = [make_result(ActionType.BLOCK_DOMAIN, target, "umbrella")]
    lines = render_result_table(assess_containment("XDR-83921", results)).splitlines()
    assert lines[2].startswith(f"block_domain {target}  SUCCESS")
    assert lines[1].index("Status") == lines[2].index("SUCCESS")


def test_restoration_and_dry_run_titles():
    release = [make_result(ActionType.RELEASE_ENDPOINT)]
    assert render_result_table(assess_restoration("XDR-83921", release)).startswith(
        "RESTORATION RESULT  XDR-83921  RESTORED")
    dry = [make_result(status=S.DRY_RUN, verified=None, dry_run_line="Would isolate: TH-LT-1047")]
    assert render_result_table(assess_containment("XDR-83921", dry)).startswith(
        "CONTAINMENT RESULT  XDR-83921  DRY RUN")


def test_secrets_in_error_messages_are_not_rendered():
    leaky = make_result(status=S.FAILED, verified=None,
                        error=error(ErrorCode.API_ERROR, message="upstream said Bearer faketoken0123456789"))
    text = render_result_table(assess_containment("XDR-83921", [leaky]))
    assert "faketoken0123456789" not in text
