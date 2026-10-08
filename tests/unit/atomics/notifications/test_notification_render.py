"""Notification content rules (architecture section 14.1.8)."""
from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from tests.unit.atomics.notifications import _builders as b
from xdr_response.atomics.notifications import (
    LifecycleEvent,
    LifecycleEventKind,
    NotificationDraft,
    NotificationKind,
    render_analyst_summary,
    render_incident_note,
    render_soc_notification,
)
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import DecisionType, canonical_json, sha256_hex

Renderer = Callable[[LifecycleEvent], NotificationDraft]
RENDERERS: tuple[Renderer, ...] = (render_incident_note, render_soc_notification, render_analyst_summary)
KINDS = {render_incident_note: NotificationKind.INCIDENT_NOTE,
         render_soc_notification: NotificationKind.SOC_NOTIFICATION,
         render_analyst_summary: NotificationKind.ANALYST_SUMMARY}
AI_HEADING = "AI narrative (not evidence, not reviewed)"
FAKE_APPROVAL_TOKEN = "QUJDREVGR0hJSktMTU5PUA." + "test-key." + "b" * 64
ALL_EVENTS = tuple(LifecycleEventKind)


def _all_drafts(event: LifecycleEvent) -> list[NotificationDraft]:
    return [render(event) for render in RENDERERS]


# ------------------------------------------------------------------------------------- identity --
@pytest.mark.parametrize("kind", ALL_EVENTS)
@pytest.mark.parametrize("render", RENDERERS)
def test_every_event_renders_deterministically(render: Renderer, kind: LifecycleEventKind) -> None:
    first, second = render(b.event(kind)), render(b.event(kind))
    assert first == second
    assert first.kind is KINDS[render]
    assert first.event is kind
    assert first.incident_id == b.INCIDENT_ID
    assert first.created_at == b.event(kind).at  # no clock read while rendering
    assert first.body.endswith("Decisions are taken only by authenticated analysts in the orchestrator "
                               "decision flow.")


def test_notification_id_follows_the_contract_formula() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED)
    draft = render_incident_note(event)
    expected = sha256_hex(canonical_json(
        ["incident_note", b.INCIDENT_ID, "package_proposed", f"package:{b.PACKAGE_ID}"]))[:32]
    assert draft.notification_id == expected


def test_notification_ids_differ_by_kind_event_and_reference() -> None:
    proposed = b.event(LifecycleEventKind.PACKAGE_PROPOSED)
    ids = {d.notification_id for d in _all_drafts(proposed)}
    assert len(ids) == 3
    decided = render_incident_note(b.event(LifecycleEventKind.DECISION_RECORDED))
    contained = render_incident_note(b.event(LifecycleEventKind.CONTAINMENT_COMPLETED))
    assert len({render_incident_note(proposed).notification_id, decided.notification_id,
                contained.notification_id}) == 3
    closed_a = render_incident_note(b.event(LifecycleEventKind.INCIDENT_CLOSED))
    closed_b = render_incident_note(b.event(LifecycleEventKind.INCIDENT_CLOSED, at=b.NOW))
    assert closed_a.notification_id != closed_b.notification_id


@pytest.mark.parametrize("render", RENDERERS)
def test_audiences(render: Renderer) -> None:
    draft = render(b.event(LifecycleEventKind.PACKAGE_PROPOSED))
    assert draft.audience == {"incident_note": "incident", "soc_notification": "soc",
                              "analyst_summary": "analyst"}[draft.kind.value]


def test_workflow_comes_from_package_then_summary_then_incident() -> None:
    proposed = render_incident_note(b.event(LifecycleEventKind.PACKAGE_PROPOSED))
    assert (proposed.workflow_id, proposed.workflow_version) == ("ransomware", "1.0.0")
    detected = render_incident_note(b.event(LifecycleEventKind.DETECTION_COMPLETED,
                                            summary=b.summary(workflow_id="wf-summary")))
    assert detected.workflow_id == "wf-summary"
    closed = render_incident_note(b.event(LifecycleEventKind.INCIDENT_CLOSED,
                                          incident=b.incident(workflow_id="wf-incident")))
    assert closed.workflow_id == "wf-incident"


def test_render_rejects_a_non_event() -> None:
    for render in RENDERERS:
        with pytest.raises(TypeError):
            render({"kind": "package_proposed"})  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------- scores --
@pytest.mark.parametrize("render", RENDERERS)
def test_risk_and_confidence_are_shown_separately(render: Renderer) -> None:
    body = render(b.event(LifecycleEventKind.PACKAGE_PROPOSED)).body
    assert "Risk score: 97/100 (CRITICAL)" in body.splitlines()
    assert "Confidence score: 64/100" in body.splitlines()


def test_scores_fall_back_to_the_summary() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.DETECTION_COMPLETED)).body
    assert "Risk score: 42/100 (MEDIUM)" in body
    assert "Confidence score: 55/100" in body


def test_no_scores_without_package_or_summary() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.INCIDENT_CLOSED)).body
    assert "Risk score" not in body and "Confidence score" not in body


# ------------------------------------------------------------------------------------- evidence --
@pytest.mark.parametrize("render", RENDERERS)
def test_evidence_is_numbered_package_evidence(render: Renderer) -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED)
    body = render(event).body
    assert "Evidence (numbered, from the package):" in body
    for evidence in event.package.evidence:  # type: ignore[union-attr]
        assert f"[{evidence.number}] {evidence.source}: {evidence.summary}" in body
    assert "[rec-0001]" not in body  # summary lines are not used when a package exists


def test_evidence_falls_back_to_summary_records() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.DETECTION_COMPLETED)).body
    assert "Evidence (investigation records):" in body
    assert "[rec-0001] secure_endpoint: Ransomware detection on TH-LT-1047" in body


def test_action_evidence_numbers_are_package_numbers() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, package=b.elevated_package())
    numbers = {e.source: e.number for e in event.package.evidence}  # type: ignore[union-attr]
    body = render_incident_note(event).body
    assert f"block_domain evil.example.com [STANDARD] risk 90 confidence 85 evidence [{numbers['umbrella']}]" in body
    assert f"isolate_endpoint DC-01 [ELEVATED] risk 88 confidence 70 evidence [{numbers['cisco_xdr']}]" in body


def test_evidence_data_and_references_are_not_rendered() -> None:
    for draft in _all_drafts(b.event(LifecycleEventKind.PACKAGE_PROPOSED)):
        assert "se-evt-0001" not in draft.body
        assert b.PARAM_MARKER not in draft.body


# -------------------------------------------------------------------------------------- actions --
def test_every_action_shows_rollback_or_not_reversible() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.PACKAGE_PROPOSED)).body
    assert re.search(r"1\. isolate_endpoint TH-LT-1047 .*; rollback: release_endpoint$", body, re.M)
    assert re.search(r"2\. block_domain evil\.example\.com .*; rollback: unblock_domain$", body, re.M)
    assert re.search(r"3\. revoke_sessions jsmith@example\.com .*; not reversible$", body, re.M)


def test_release_actions_and_results_show_rollback_text() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.RESTORATION_COMPLETED)).body
    assert "Proposed restoration actions (2):" in body
    assert re.search(r"release_endpoint TH-LT-1047 .*not reversible$", body, re.M)
    assert "  - unblock_domain evil.example.com: SUCCESS; verification VERIFIED; not reversible" in body


def test_excluded_targets_and_blast_radius_are_listed() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, package=b.elevated_package())
    body = render_incident_note(event).body
    assert "  - block_domain example.com: allowlists.never_block.domains: example.com" in body
    assert "Blast radius: 1 endpoint, 1 user, 2 indicators" in body


# ------------------------------------------------------------------------------------- ELEVATED --
@pytest.mark.parametrize("render", RENDERERS)
def test_elevated_approval_is_always_visible(render: Renderer) -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, package=b.elevated_package())
    draft = render(event)
    assert "ELEVATED APPROVAL REQUIRED for 2 actions:" in draft.body
    assert "WARNING: ELEVATED APPROVAL REQUIRED - isolate_endpoint on DC-01 (domain controller)" in draft.body
    # the always-elevated catalog action has no asset warning but is still flagged
    assert f"  - remove_privileged_role {b.ROLE_TARGET}" in draft.body
    assert "WARNING: ELEVATED APPROVAL REQUIRED - catalog policy for this action type" in draft.body
    assert "(ELEVATED)" in draft.title


def test_standard_package_has_no_elevated_block() -> None:
    draft = render_soc_notification(b.event(LifecycleEventKind.PACKAGE_PROPOSED))
    assert "ELEVATED" not in draft.title
    assert "ELEVATED APPROVAL REQUIRED" not in draft.body


# ------------------------------------------------------------------------------------- decision --
def test_decision_shows_approvers_and_approved_and_rejected_actions() -> None:
    pkg = b.containment_package()
    people = (b.principal(), b.principal(b.LEAD, "Lead Two"))
    event = b.event(LifecycleEventKind.DECISION_RECORDED, package=pkg,
                    decision=b.decision(pkg, approvers=people))
    body = render_incident_note(event).body
    assert "Status: a human decision was recorded: APPROVE_SELECTED." in body
    assert "Human decision: APPROVE_SELECTED at 2026-01-15T12:03:00Z" in body
    assert ("Approvers: analyst.one@example.com (Analyst One, HUMAN); "
            "lead.two@example.com (Lead Two, HUMAN)") in body
    assert "Approved actions (2):\n  - isolate_endpoint TH-LT-1047\n  - block_domain evil.example.com" in body
    assert "Rejected actions (1):\n  - revoke_sessions jsmith@example.com" in body
    assert "Comment: Approved after review" in body


def test_rejection_lists_every_action_and_no_token() -> None:
    pkg = b.containment_package()
    event = b.event(LifecycleEventKind.DECISION_RECORDED, package=pkg,
                    decision=b.decision(pkg, kind=DecisionType.REJECT))
    body = render_incident_note(event).body
    assert "Approved actions: none" in body
    assert "Rejected actions (3):" in body
    assert "token" not in body.lower()


def test_decision_without_package_falls_back_to_keys() -> None:
    pkg = b.containment_package()
    event = b.event(LifecycleEventKind.DECISION_RECORDED, package=None, decision=b.decision(pkg))
    body = render_incident_note(event).body
    assert f"  - {b.INCIDENT_ID}:isolate_endpoint:TH-LT-1047" in body


def test_release_decision_is_labelled() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.RESTORATION_COMPLETED)).body
    assert "Human release decision: APPROVE_ALL" in body


@pytest.mark.parametrize("kind", ALL_EVENTS)
def test_token_ids_never_exceed_eight_characters(kind: LifecycleEventKind) -> None:
    for draft in _all_drafts(b.event(kind)):
        assert b.TOKEN_ID not in draft.body and b.TOKEN_ID[:9] not in draft.body
        assert b.TOKEN_ID not in draft.title
    body = render_incident_note(b.event(LifecycleEventKind.DECISION_RECORDED)).body
    assert f"Approval token id prefix: {b.TOKEN_ID[:8]}" in body


# --------------------------------------------------------------------------------------- report --
def test_containment_report_results_without_vendor_payloads() -> None:
    body = render_incident_note(b.event(LifecycleEventKind.CONTAINMENT_COMPLETED)).body
    assert "Overall: PARTIALLY_CONTAINED" in body
    assert "  - isolate_endpoint TH-LT-1047: SUCCESS; verification VERIFIED; rollback: release_endpoint" in body
    assert ("  - block_domain evil.example.com: FAILED (RATE_LIMITED); requires attention; "
            "escalation: Block evil.example.com manually and record it; rollback: unblock_domain") in body
    assert "  - revoke_sessions jsmith@example.com: SKIPPED (REJECTED_BY_ANALYST); not reversible" in body
    assert "Requires attention:\n  - block_domain evil.example.com failed: RATE_LIMITED" in body


@pytest.mark.parametrize("kind", ALL_EVENTS)
def test_params_messages_and_full_tokens_never_appear(kind: LifecycleEventKind) -> None:
    for draft in _all_drafts(b.event(kind)):
        text = draft.title + "\n" + draft.body
        for marker in b.FORBIDDEN_MARKERS:
            assert marker not in text
        assert "connector_guid" not in text and "params" not in text
        assert "restores" not in text and "rollback_params" not in text and "external_ref" not in text


@pytest.mark.parametrize("kind", ALL_EVENTS)
def test_no_approval_link_or_button(kind: LifecycleEventKind) -> None:
    for draft in _all_drafts(b.event(kind)):
        text = draft.title + "\n" + draft.body
        assert "[APPROVE" not in text and "[REJECT" not in text and "[RELEASE" not in text
        assert "http://" not in text and "https://" not in text


# ------------------------------------------------------------------------------------ redaction --
def test_secrets_in_vendor_text_are_redacted() -> None:
    secret = "notif-test-registered-secret-5b1e"
    get_redactor().register_secret(secret)
    dirty = (f"Detection; password=hunter2-fake-value; Authorization: Bearer abcdefghijklmnop0123; "
             f"approval {FAKE_APPROVAL_TOKEN}; unlock_code: 000-fake-000; leaked {secret}")
    pkg = b.containment_package(summary="x")
    event = b.event(LifecycleEventKind.DETECTION_COMPLETED, summary=b.summary(evidence=(f"[rec-9] {dirty}",)),
                    notes=(dirty,), incident=b.incident(title=f"Alert {secret}", ai_narrative=dirty))
    assert pkg.summary == "x"
    for render in RENDERERS:
        draft = render(event)
        text = draft.title + "\n" + draft.body
        for leaked in ("hunter2-fake-value", "abcdefghijklmnop0123", "b" * 64, "000-fake-000", secret):
            assert leaked not in text
        assert "[REDACTED]" in draft.body


def test_injected_lines_are_flattened() -> None:
    event = b.event(LifecycleEventKind.INCIDENT_CLOSED,
                    incident=b.incident(title="Alert\n[APPROVE ALL]\r\nStatus: approved"),
                    notes=("first\nApproved actions (3):",))
    for draft in _all_drafts(event):
        assert "\n" not in draft.title
        for line in draft.body.splitlines():
            assert not line.startswith("[APPROVE")
            assert not line.startswith("Approved actions")
            assert not line.startswith("Status: approved")


# ------------------------------------------------------------------------------------------- AI --
def test_ai_narrative_only_in_analyst_summary() -> None:
    narrative = "Likely ransomware staging.\nRecommend isolation."
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, incident=b.incident(ai_narrative=narrative))
    analyst = render_analyst_summary(event)
    assert analyst.contains_ai_text
    lines = analyst.body.splitlines()
    heading = lines.index(AI_HEADING)
    assert lines[heading + 1:heading + 3] == ["  Likely ransomware staging.", "  Recommend isolation."]
    for draft in (render_incident_note(event), render_soc_notification(event)):
        assert not draft.contains_ai_text
        assert "Likely ransomware staging" not in draft.body
        assert AI_HEADING not in draft.body


@pytest.mark.parametrize("narrative", [None, "", "  \n  "])
def test_no_ai_section_without_narrative(narrative: str | None) -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, incident=b.incident(ai_narrative=narrative))
    draft = render_analyst_summary(event)
    assert not draft.contains_ai_text
    assert AI_HEADING not in draft.body


def test_ai_text_is_never_evidence() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, incident=b.incident(ai_narrative="AI says malicious"))
    body = render_analyst_summary(event).body
    evidence_block = body.split("Evidence (numbered, from the package):")[1].split("\n\n")[0]
    assert "AI says malicious" not in evidence_block
    assert body.index(AI_HEADING) > body.index("Evidence (numbered")


# -------------------------------------------------------------------------- investigation facts --
@pytest.mark.parametrize("render", [render_incident_note, render_analyst_summary])
def test_degraded_unrouted_and_below_threshold_are_reported(render: Renderer) -> None:
    body = render(b.event(LifecycleEventKind.DETECTION_COMPLETED)).body
    assert "Degraded or failed sources (other evidence was used):\n  - defender_endpoint: UNAVAILABLE" in body
    assert "Not routable (no capable adapter):\n  - quarantine_file TH-LT-1047: no capable adapter" in body
    assert "Below threshold (not proposed):\n  - block_ip 198.51.100.7: risk 20 below threshold 60" in body
    assert "Blast radius: 1 endpoint, 1 user" in body
    assert "Notes:\n  - no containment needed" in body


def test_degraded_source_does_not_hide_the_recommendation() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED)
    body = render_analyst_summary(event).body
    assert "defender_endpoint: UNAVAILABLE" in body
    assert "Proposed containment actions (3):" in body


# -------------------------------------------------------------------------------------- dry run --
@pytest.mark.parametrize("variant", ["event", "package", "report"])
def test_dry_run_prefix_and_notice(variant: str) -> None:
    kind = LifecycleEventKind.CONTAINMENT_COMPLETED
    if variant == "event":
        event = b.event(kind, dry_run=True)
    elif variant == "package":
        event = b.event(kind, package=b.containment_package(dry_run=True))
    else:
        event = b.event(kind, report=b.containment_report(dry_run=True))
    for draft in _all_drafts(event):
        assert draft.title.startswith("[DRY RUN] ")
        assert "DRY RUN: simulation only. No state-changing action was performed on any system." in draft.body


def test_dry_run_report_lines() -> None:
    event = b.event(LifecycleEventKind.CONTAINMENT_COMPLETED, report=b.containment_report(dry_run=True),
                    dry_run=True)
    body = render_incident_note(event).body
    assert "Overall: DRY RUN (no overall state)" in body
    assert ("  - isolate_endpoint TH-LT-1047: DRY_RUN; DRY RUN: Would isolate_endpoint: TH-LT-1047; "
            "rollback: release_endpoint") in body


def test_live_events_have_no_dry_run_marker() -> None:
    for draft in _all_drafts(b.event(LifecycleEventKind.CONTAINMENT_COMPLETED)):
        assert not draft.title.startswith("[DRY RUN]")
        assert "DRY RUN" not in draft.body


# --------------------------------------------------------------------------------------- limits --
def test_long_title_is_capped_at_200_chars() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, incident=b.incident(title="T" * 500), dry_run=True)
    for draft in _all_drafts(event):
        assert len(draft.title) <= 200
        assert draft.title.startswith("[DRY RUN] ")


def test_large_body_is_capped_and_keeps_the_footer() -> None:
    notes = tuple(f"note {i} " + "x" * 200 for i in range(200))
    event = b.event(LifecycleEventKind.INCIDENT_CLOSED, notes=notes)
    for draft in _all_drafts(event):
        assert len(draft.body.encode("utf-8")) <= 16 * 1024
        assert ("[truncated]" in draft.body) is (draft.kind is not NotificationKind.SOC_NOTIFICATION)
        assert draft.body.endswith("orchestrator decision flow.")


def test_large_ai_narrative_cut_keeps_flag_consistent() -> None:
    notes = tuple("n" * 300 for _ in range(60))
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED, notes=notes,
                    incident=b.incident(ai_narrative="AI text " * 50))
    draft = render_analyst_summary(event)
    assert draft.contains_ai_text == (AI_HEADING in draft.body.splitlines())


# ------------------------------------------------------------------------------------ statuses --
@pytest.mark.parametrize(("kind", "expected"), [
    (LifecycleEventKind.DETECTION_COMPLETED, "No containment was proposed."),
    (LifecycleEventKind.PACKAGE_PROPOSED, "Human approval is required before any action runs."),
    (LifecycleEventKind.CONTAINMENT_COMPLETED, "verification ran automatically"),
    (LifecycleEventKind.RELEASE_PROPOSED, "A separate human release approval is required"),
    (LifecycleEventKind.RESTORATION_COMPLETED, "Overall: RESTORED"),
    (LifecycleEventKind.INCIDENT_CLOSED, "Status: incident closed."),
])
def test_status_lines(kind: LifecycleEventKind, expected: str) -> None:
    assert expected in render_soc_notification(b.event(kind)).body


def test_titles() -> None:
    event = b.event(LifecycleEventKind.PACKAGE_PROPOSED)
    assert render_incident_note(event).title == (
        "Incident note XDR-83921: containment proposed, awaiting human approval")
    assert render_soc_notification(event).title == (
        "[CRITICAL] XDR-83921 containment proposed, awaiting human approval: Potential ransomware on TH-LT-1047")
    assert render_analyst_summary(event).title == (
        "Analyst summary XDR-83921: containment proposed, awaiting human approval")
