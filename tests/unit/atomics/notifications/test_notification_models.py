"""Notification model contract (architecture section 14.1.8)."""
from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from tests.unit.atomics.notifications import _builders as b
from xdr_response.atomics.notifications import (
    DeliveryRecord,
    DeliveryStatus,
    LifecycleEvent,
    LifecycleEventKind,
    NotificationDraft,
    NotificationKind,
    WorkflowSummary,
)
from xdr_response.models import RiskBand

AI_HEADING = "AI narrative (not evidence, not reviewed)"


def _draft(**overrides: object) -> NotificationDraft:
    data: dict[str, object] = {
        "notification_id": "0123456789abcdef0123456789abcdef", "kind": NotificationKind.INCIDENT_NOTE,
        "event": LifecycleEventKind.PACKAGE_PROPOSED, "incident_id": b.INCIDENT_ID, "created_at": b.NOW,
        "audience": "incident", "title": "Incident note", "body": "Incident: XDR-83921",
    }
    data.update(overrides)
    return NotificationDraft(**data)


def test_enum_values_match_the_contract() -> None:
    assert [k.value for k in NotificationKind] == ["incident_note", "soc_notification", "analyst_summary"]
    assert [k.value for k in LifecycleEventKind] == [
        "detection_completed", "package_proposed", "decision_recorded", "containment_completed",
        "release_proposed", "restoration_completed", "incident_closed"]
    assert [s.value for s in DeliveryStatus] == ["STORED", "DELIVERED", "NOT_DELIVERED_UNVERIFIED", "FAILED"]


def test_valid_draft_is_frozen() -> None:
    draft = _draft()
    with pytest.raises(ValidationError):
        draft.title = "changed"  # type: ignore[misc]


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        _draft(approve_url="https://example.com/approve")


@pytest.mark.parametrize("bad", ["", "ABCDEF0123456789abcdef0123456789", "0123", "g" * 32])
def test_notification_id_must_be_32_lower_hex(bad: str) -> None:
    with pytest.raises(ValidationError):
        _draft(notification_id=bad)


@pytest.mark.parametrize("bad", ["", "   ", "x" * 201, "line one\nline two", "a\rb"])
def test_title_limits(bad: str) -> None:
    with pytest.raises(ValidationError):
        _draft(title=bad)


def test_title_of_200_chars_is_allowed() -> None:
    assert len(_draft(title="x" * 200).title) == 200


def test_body_is_limited_to_16_kib_of_utf8() -> None:
    assert _draft(body="x" * 16384).body
    with pytest.raises(ValidationError):
        _draft(body="x" * 16385)
    with pytest.raises(ValidationError):
        _draft(body="é" * 8193)  # 16386 bytes
    with pytest.raises(ValidationError):
        _draft(body="  \n ")


@pytest.mark.parametrize(("kind", "audience"), [
    (NotificationKind.INCIDENT_NOTE, "soc"), (NotificationKind.SOC_NOTIFICATION, "analyst"),
    (NotificationKind.ANALYST_SUMMARY, "incident")])
def test_audience_must_match_kind(kind: NotificationKind, audience: str) -> None:
    with pytest.raises(ValidationError):
        _draft(kind=kind, audience=audience)


def test_unknown_audience_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _draft(audience="everyone")


def test_ai_text_only_in_analyst_summary_and_always_flagged() -> None:
    body = f"Incident\n{AI_HEADING}\n  narrative"
    ok = _draft(kind=NotificationKind.ANALYST_SUMMARY, audience="analyst", body=body, contains_ai_text=True)
    assert ok.contains_ai_text
    with pytest.raises(ValidationError):  # heading without the flag
        _draft(kind=NotificationKind.ANALYST_SUMMARY, audience="analyst", body=body)
    with pytest.raises(ValidationError):  # flag without the heading
        _draft(kind=NotificationKind.ANALYST_SUMMARY, audience="analyst", contains_ai_text=True)
    with pytest.raises(ValidationError):  # AI text in an incident note
        _draft(body=body, contains_ai_text=True)


def test_naive_datetimes_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _draft(created_at=datetime(2026, 1, 15, 12, 0, 0))
    with pytest.raises(ValidationError):
        DeliveryRecord(notification_id="x", sink="memory", status=DeliveryStatus.STORED,
                       at=datetime(2026, 1, 15, 12, 0, 0))


def test_workflow_summary_scores_are_bounded() -> None:
    assert b.summary().risk_band is RiskBand.MEDIUM
    with pytest.raises(ValidationError):
        b.summary(risk_score=101)
    with pytest.raises(ValidationError):
        b.summary(confidence_score=-1)
    assert WorkflowSummary(workflow_id="w", workflow_version="1", risk_score=0, confidence_score=0,
                           risk_band=RiskBand.LOW).evidence == ()


def test_event_parts_must_belong_to_the_event_incident() -> None:
    other = b.incident(incident_id="XDR-00001")
    for part in ("package", "decision", "report"):
        kind = LifecycleEventKind.CONTAINMENT_COMPLETED
        source = b.event(kind)
        data = {"kind": kind, "at": b.NOW, "incident": other, part: getattr(source, part)}
        with pytest.raises(ValidationError, match="belongs to incident"):
            LifecycleEvent(**data)


def test_event_keeps_package_and_report_types() -> None:
    contained = b.event(LifecycleEventKind.CONTAINMENT_COMPLETED)
    restored = b.event(LifecycleEventKind.RESTORATION_COMPLETED)
    assert type(contained.package).__name__ == "ContainmentPackage"
    assert type(contained.report).__name__ == "ContainmentReport"
    assert type(restored.package).__name__ == "ReleasePackage"
    assert type(restored.report).__name__ == "RestorationReport"


def test_event_has_no_token_field() -> None:
    assert not {"token", "approval_token", "signature"} & set(LifecycleEvent.model_fields)
