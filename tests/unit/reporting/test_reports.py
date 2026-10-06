"""Containment / restoration result reports and the release checklist (golden snapshots included)."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.unit.reporting._scenario import (
    EV_UMB,
    INCIDENT_ID,
    action,
    assert_golden,
    containment_report,
    package_of,
    ransomware_package,
    release_package,
    restoration_report,
)
from xdr_response.clock import FixedClock
from xdr_response.dryrun import DryRunSimulator, render_dry_run
from xdr_response.logs.redaction import Redactor
from xdr_response.models import ActionType, ErrorCode, ErrorInfo
from xdr_response.reporting import (
    ELEVATED_TITLE,
    build_release_checklist,
    build_result_report,
    release_step,
    render_containment_report,
    render_release_checklist,
)

FORMATS = [("text", "txt"), ("markdown", "md"), ("json", "json")]


# ------------------------------------------------------------------ golden --
@pytest.mark.parametrize(("fmt", "ext"), FORMATS)
def test_golden_containment_report(fmt: str, ext: str) -> None:
    assert_golden(f"containment_report.{ext}", render_containment_report(containment_report(), fmt=fmt))


@pytest.mark.parametrize(("fmt", "ext"), FORMATS)
def test_golden_restoration_report(fmt: str, ext: str) -> None:
    assert_golden(f"restoration_report.{ext}", render_containment_report(restoration_report(), fmt=fmt))


@pytest.mark.parametrize(("fmt", "ext"), FORMATS)
def test_golden_release_checklist(fmt: str, ext: str) -> None:
    assert_golden(f"release_checklist.{ext}", render_release_checklist(release_package(), fmt=fmt))


@pytest.mark.parametrize(("fmt", "ext"), FORMATS)
def test_golden_dry_run_report(fmt: str, ext: str) -> None:
    report = DryRunSimulator(clock=FixedClock(FIXED_NOW), id_factory=lambda: "dry-0001").simulate(
        ransomware_package())
    assert_golden(f"dry_run_report.{ext}", render_containment_report(report, fmt=fmt))


# ------------------------------------------------------- containment report --
def test_containment_report_shows_overall_and_each_action() -> None:
    lines = render_containment_report(containment_report()).splitlines()
    assert lines[0] == f"CONTAINMENT RESULT  {INCIDENT_ID}"
    assert lines[1] == "Overall: PARTIALLY_CONTAINED"
    text = "\n".join(lines)
    assert "[SUCCESS]" in text and "verification VERIFIED" in text and "control registered" in text
    assert "[FAILED]" in text and "error RATE_LIMITED: rate limited after 3 attempts" in text
    assert "ATTENTION" in text and "escalation Block evil.example.com manually" in text
    assert "reason REJECTED_BY_ANALYST" in text
    assert lines[-1] == "Temporary controls registered: 1 (release needs a separate release approval)"


def test_restoration_report_title_and_overall() -> None:
    view = build_result_report(restoration_report())
    assert view.title == "RESTORATION RESULT" and view.overall == "RESTORED"
    assert "Temporary controls registered" not in render_containment_report(restoration_report())


def test_dry_run_report_text_is_the_exact_dry_run_output() -> None:
    report = DryRunSimulator(clock=FixedClock(FIXED_NOW)).simulate(ransomware_package())
    assert render_containment_report(report) == render_dry_run(report)
    data = json.loads(render_containment_report(report, fmt="json"))
    assert data["overall"] == "DRY_RUN" and data["dry_run"] is True and data["token_id"] is None
    assert data["dry_run_lines"][0] == "Would isolate: TH-LT-1047"


def test_error_messages_are_redacted() -> None:
    report = containment_report()
    failed = report.results[1].model_copy(update={"error": ErrorInfo(
        code=ErrorCode.AUTH_FAILED, message="401 for client_secret=abcdef0123456789", integration="umbrella")})
    edited = report.model_copy(update={"results": (report.results[0], failed, report.results[2])})
    for fmt in ("text", "markdown", "json"):
        assert "abcdef0123456789" not in render_containment_report(edited, fmt=fmt)


def test_registered_secret_in_attention_is_redacted() -> None:
    redactor = Redactor()
    redactor.register_secret("evil.example.com")
    text = render_containment_report(containment_report(), redactor=redactor)
    assert "evil.example.com" not in text


# -------------------------------------------------------- release checklist --
def test_release_checklist_ends_with_release_options() -> None:
    text = render_release_checklist(release_package())
    lines = text.splitlines()
    assert lines[0] == f"RELEASE APPROVAL REQUIRED  {INCIDENT_ID}"
    assert lines[-1] == "[APPROVE RELEASE] [REJECT]"
    assert "Controls not listed here stay ACTIVE. Closing the incident never removes controls." in lines
    assert "[APPROVE ALL]" not in text


def test_release_checklist_steps_and_restores() -> None:
    view = build_release_checklist(release_package())
    assert [i.step for i in view.items] == [
        "Restore endpoint connectivity: TH-LT-1047",
        "Remove temporary Umbrella domain block: evil.example.com",
        "Restore privileged role assignment: jsmith@example.com/62e90394-69f5-4237-9190-012177145e10",
    ]
    assert [i.restores for i in view.items] == list(release_package().control_keys)


def test_release_checklist_warns_for_elevated_release() -> None:
    text = render_release_checklist(release_package())
    assert text.count(ELEVATED_TITLE) == 1
    assert "Reason: restore_privileged_role always requires elevated approval" in text


@pytest.mark.parametrize(
    ("action_type", "target", "integration", "expected"),
    [
        (ActionType.UNBLOCK_IP, "203.0.113.10", "meraki", "Remove temporary Meraki IP block: 203.0.113.10"),
        (ActionType.UNBLOCK_HASH, "b" * 64, "defender_endpoint", f"Remove temporary Defender hash block: {'b' * 64}"),
        (ActionType.ENABLE_USER, "jsmith@example.com", "entra", "Re-enable Entra account: jsmith@example.com"),
    ],
)
def test_release_step_phrases(action_type: ActionType, target: str, integration: str, expected: str) -> None:
    item = action(action_type, target, integration, [EV_UMB], restores="k")
    assert release_step(item, item.target) == expected


def test_release_checklist_refuses_a_containment_package() -> None:
    with pytest.raises(TypeError):
        render_release_checklist(package_of([action(ActionType.BLOCK_IP, "203.0.113.10", "meraki", [EV_UMB])]))


def test_release_json_carries_redacted_params() -> None:
    pkg = release_package()
    data = json.loads(render_release_checklist(pkg, fmt="json"))
    assert data["kind"] == "release_checklist"
    assert data["release_actions"][1]["params"]["destination_id"] == "7654321"
    assert [o["label"] for o in data["decision_options"]] == ["APPROVE RELEASE", "REJECT"]
    assert data["package"]["expires_at"] == (FIXED_NOW + timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
