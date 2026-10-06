"""Recommended escalation owner."""
from __future__ import annotations

from tests.unit.verification.verification_fakes import error, make_result
from xdr_response.models import ActionResultStatus, ActionType, ErrorCode, SkipReason
from xdr_response.models.catalog import INTEGRATION_NAMES
from xdr_response.verification import (
    DEFAULT_INTEGRATION_OWNERS,
    PLATFORM_OWNER,
    SOC_ANALYST,
    integration_owner,
    recommend_escalation,
)

S = ActionResultStatus


def _failed(code: ErrorCode, integration: str = "defender_o365", http_status: int | None = None, **kw):
    return make_result(ActionType.QUARANTINE_EMAIL, "<MSG-0001@mail.example.com>", integration,
                       status=S.FAILED, verified=None,
                       error=error(code, http_status=http_status, integration=integration), **kw)


def test_every_integration_has_a_default_owner():
    assert set(DEFAULT_INTEGRATION_OWNERS) == set(INTEGRATION_NAMES)


def test_email_quarantine_403_goes_to_m365_admin():
    assert recommend_escalation(_failed(ErrorCode.AUTH_FAILED, http_status=403)) == "Microsoft 365 administrator"


def test_runner_hint_wins():
    result = _failed(ErrorCode.AUTH_FAILED, escalation="Messaging team")
    assert recommend_escalation(result) == "Messaging team"


def test_hints_override_defaults():
    hints = {"defender_o365": "Exchange Online administrator"}
    assert recommend_escalation(_failed(ErrorCode.AUTH_FAILED), hints=hints) == "Exchange Online administrator"


def test_platform_faults_go_to_platform_owner():
    for code in (ErrorCode.AUDIT_UNAVAILABLE, ErrorCode.INTERNAL, ErrorCode.APPROVAL_DENIED):
        assert recommend_escalation(_failed(code)) == PLATFORM_OWNER
    skipped = make_result(status=S.SKIPPED, verified=None, skip_reason=SkipReason.NO_CAPABLE_ADAPTER)
    assert recommend_escalation(skipped) == PLATFORM_OWNER


def test_invalid_target_goes_back_to_the_analyst():
    assert recommend_escalation(_failed(ErrorCode.INVALID_TARGET, http_status=404)) == SOC_ANALYST


def test_integration_override_and_unknowns():
    result = _failed(ErrorCode.UNAVAILABLE)
    assert recommend_escalation(result, integration="umbrella") == "Cisco Umbrella administrator"
    assert integration_owner(None) == PLATFORM_OWNER
    assert integration_owner("not_an_integration") == PLATFORM_OWNER
