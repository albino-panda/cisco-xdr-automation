"""ExecutionAuditSummary (brief section 35) built from the audit trail."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW
from xdr_response.audit import AuditRecorder, ExecutionAuditSummary, build_execution_summary
from xdr_response.errors import AuditError
from xdr_response.models import AuditEventType, PrincipalKind


def _run_incident(recorder: AuditRecorder, m) -> None:
    incident_id = m.incident.incident_id
    recorder.incident_received(m.incident)
    recorder.investigation_completed(incident_id, [m.investigation], evidence=m.evidence)
    recorder.package_proposed(m.package)
    recorder.approval_denied(incident_id, reason="AI principals cannot approve",
                             package_id=m.package.package_id, principal_id="ai:assistant",
                             principal_kind=PrincipalKind.AI)
    recorder.decision_recorded(m.decision)
    recorder.token_issued(m.token)
    recorder.action_started(m.request, token_id="tok-1")
    recorder.api_call(incident_id, m.api_call)
    recorder.action_result(incident_id, m.success)
    recorder.verification_result(incident_id, m.verification)
    recorder.control_registered(m.control)
    recorder.action_result(incident_id, m.failed)
    recorder.containment_completed(m.report)
    recorder.release_package_proposed(m.release_package)
    recorder.restoration_result(incident_id, m.restored)
    recorder.restoration_completed(m.restoration_report)
    recorder.error(incident_id, m.error)


@pytest.fixture
def summary(make_trail, lifecycle) -> ExecutionAuditSummary:
    trail = make_trail()
    recorder = AuditRecorder(trail)
    _run_incident(recorder, lifecycle)
    trail.append(AuditEventType.ERROR, incident_id="XDR-OTHER", actor="automation:test",
                 payload={"code": "API_ERROR", "message": "other incident"})
    return build_execution_summary(trail.records(), lifecycle.incident.incident_id)


def test_summary_identity_and_trigger(summary, lifecycle):
    assert summary.incident_id == "XDR-83921"
    assert (summary.workflow_id, summary.workflow_version) == ("powershell", "1.0.0")
    assert summary.timestamp == FIXED_NOW  # first record of the incident
    assert summary.trigger == {"source": "cisco_xdr", "rule": "test-trigger"}
    assert len(summary.observables) == len(lifecycle.incident.observables)


def test_summary_evidence_scores_and_recommendations(summary, lifecycle):
    assert [e["number"] for e in summary.evidence] == list(range(1, len(lifecycle.package.evidence) + 1))
    assert summary.risk_score == lifecycle.package.risk_score
    assert summary.confidence_score == lifecycle.package.confidence_score
    keys = [a["idempotency_key"] for a in summary.recommended_actions]
    assert keys == [lifecycle.isolate.idempotency_key, lifecycle.block.idempotency_key]
    assert set(summary.recommended_actions[0]) >= {"action_type", "target", "approval_level",
                                                   "risk_score", "confidence_score"}


def test_summary_analyst_decision(summary, lifecycle):
    assert summary.analyst_identity == "analyst.one@example.com"
    assert summary.approval_timestamp == FIXED_NOW + timedelta(minutes=5)
    assert summary.approved_actions == [lifecycle.isolate.idempotency_key]
    assert summary.rejected_actions == [lifecycle.block.idempotency_key]


def test_summary_api_calls_split_into_requests_and_responses(summary):
    assert len(summary.api_requests) == 1 and len(summary.api_responses) == 1
    request, response = summary.api_requests[0], summary.api_responses[0]
    assert request["method"] == "PUT" and request["operation"] == "isolate"
    assert "status_code" not in request
    assert response["status_code"] == 200 and response["response_summary"] == {"status": "pending_start"}
    assert request["seq"] == response["seq"]


def test_summary_results(summary, lifecycle):
    assert [r["status"] for r in summary.containment_results] == ["SUCCESS", "FAILED"]
    assert [r["status"] for r in summary.verification_results] == ["VERIFIED"]
    assert [r["status"] for r in summary.restoration_results] == ["SUCCESS"]


def test_summary_errors_include_denials_and_failed_actions(summary, lifecycle):
    kinds = [e["event_type"] for e in summary.errors]
    assert kinds == ["APPROVAL_DENIED", "ACTION_RESULT", "ERROR"]
    assert summary.errors[1]["idempotency_key"] == lifecycle.block.idempotency_key
    assert summary.errors[1]["code"] == "RATE_LIMITED"
    assert all(e.get("message") != "other incident" for e in summary.errors)


def test_summary_without_decision_or_package(memory_trail, lifecycle):
    AuditRecorder(memory_trail).incident_received(lifecycle.incident)
    summary = build_execution_summary(memory_trail.records(), "XDR-83921")
    assert summary.analyst_identity is None and summary.approval_timestamp is None
    assert summary.approved_actions == [] and summary.recommended_actions == []
    assert summary.risk_score is None and summary.evidence == []


def test_rejection_has_no_approval_timestamp(memory_trail, lifecycle):
    from xdr_response.models import DecisionType

    rejected = lifecycle.decision.model_copy(update={
        "decision": DecisionType.REJECT, "approved_action_keys": (),
        "rejected_action_keys": (lifecycle.isolate.idempotency_key, lifecycle.block.idempotency_key),
        "token_id": None})
    AuditRecorder(memory_trail).decision_recorded(rejected)
    summary = build_execution_summary(memory_trail.records(), "XDR-83921")
    assert summary.analyst_identity == "analyst.one@example.com"
    assert summary.approval_timestamp is None
    assert summary.approved_actions == [] and len(summary.rejected_actions) == 2


def test_release_decision_does_not_override_containment_decision(memory_trail, lifecycle):
    from xdr_response.models import ApprovalPurpose

    recorder = AuditRecorder(memory_trail)
    recorder.decision_recorded(lifecycle.decision)
    release = lifecycle.decision.model_copy(update={"purpose": ApprovalPurpose.RELEASE,
                                                    "decision_id": "dec-2", "approved_action_keys": ("x",),
                                                    "rejected_action_keys": ()})
    recorder.decision_recorded(release)
    summary = build_execution_summary(memory_trail.records(), "XDR-83921")
    assert summary.approved_actions == [lifecycle.isolate.idempotency_key]


def test_summary_tolerates_redacted_fields(memory_trail):
    memory_trail.append(AuditEventType.PACKAGE_PROPOSED, incident_id="XDR-83921", actor="automation:test",
                        payload={"risk_score": "[REDACTED]", "actions": "[REDACTED]", "evidence": None})
    summary = build_execution_summary(memory_trail.records(), "XDR-83921")
    assert summary.risk_score is None and summary.recommended_actions == [] and summary.evidence == []


def test_summary_requires_records(memory_trail):
    with pytest.raises(AuditError, match="no audit records"):
        build_execution_summary(memory_trail.records(), "XDR-NONE")
