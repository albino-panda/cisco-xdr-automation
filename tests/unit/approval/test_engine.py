"""ApprovalEngine: decision semantics, who may approve, audit ordering and every rejection path."""
from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr

from tests.fixtures.factories import FIXED_NOW, make_package, make_recommendation
from tests.fixtures.principals import (
    AI_ID,
    ANALYST_ID,
    AUTOMATION_ID,
    ELEVATED_ID,
    SERVICE_ID,
    credential,
    make_authenticator,
)
from tests.unit.approval._support import make_release_package
from xdr_response.approval import ApprovalEngine, ApprovalTokenService, InMemoryApproverAuthenticator
from xdr_response.config import ApprovalSettings
from xdr_response.errors import (
    ApproverNotAllowedError,
    AuditError,
    AuthenticationError,
    DecisionError,
    TokenMismatchError,
)
from xdr_response.models import (
    ActionBinding,
    ActionRequest,
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    ApproverCredential,
    AuditEventType,
    AuthenticatedPrincipal,
    CriticalAssetWarning,
    DecisionRequest,
    DecisionType,
    PrincipalKind,
)

A = DecisionType.APPROVE_ALL
S = DecisionType.APPROVE_SELECTED
R = DecisionType.REJECT
M = DecisionType.REQUEST_MORE_INVESTIGATION


def req(package, decision=A, **kw) -> DecisionRequest:
    return DecisionRequest(package_id=package.package_id, decision=decision, **kw)


def binding(action) -> ActionBinding:
    return ActionBinding.from_request(ActionRequest.from_recommendation(action))


def make_engine(settings, authenticator, secrets, ledger, audit, clock, **kw) -> ApprovalEngine:
    tokens = ApprovalTokenService(secrets, settings, ledger=ledger, clock=clock)
    return ApprovalEngine(settings, authenticator=authenticator, tokens=tokens, audit=audit, clock=clock, **kw)


# ---------------------------------------------------------------- outcomes --
def test_approve_all_issues_token_for_every_action(engine, package, audit, tokens):
    outcome = engine.decide(package, req(package), [credential(ANALYST_ID)])
    d = outcome.decision
    assert d.decision is A and d.approved_action_keys == package.keys and d.rejected_action_keys == ()
    assert d.analyst_identity == ANALYST_ID and [a.principal_id for a in d.approvers] == [ANALYST_ID]
    assert (d.incident_id, d.package_id, d.purpose) == (package.incident_id, package.package_id,
                                                        ApprovalPurpose.CONTAINMENT)
    assert (d.workflow_id, d.workflow_version) == ("powershell", "1.0.0")
    assert d.evidence_snapshot_hash == package.evidence_snapshot_hash
    assert outcome.token is not None and d.token_id == outcome.token.token_id
    assert outcome.token.claims.decision_id == d.decision_id
    tokens.verify_package(outcome.token, package)
    assert audit.events() == [AuditEventType.DECISION_RECORDED, AuditEventType.TOKEN_ISSUED]


def test_decision_audit_payload_and_token_issued_payload(engine, package, audit):
    outcome = engine.decide(package, req(package, comment="isolate now"), [credential(ANALYST_ID)])
    recorded = audit.of(AuditEventType.DECISION_RECORDED)[0]
    assert recorded.actor == ANALYST_ID and recorded.incident_id == package.incident_id
    assert recorded.workflow_version == "1.0.0"
    assert recorded.payload["decision_id"] == outcome.decision.decision_id
    assert recorded.payload["comment"] == "isolate now"
    issued = audit.of(AuditEventType.TOKEN_ISSUED)[0].payload
    assert set(issued) == {"token_id", "purpose", "package_id", "claims_hash", "expires_at"}
    assert issued["token_id"] == outcome.token.token_id and issued["purpose"] == "containment"
    text = str([r.payload for r in audit.records()])
    assert outcome.token.signature not in text and outcome.token.encode() not in text


def test_approve_selected_approves_subset_and_rejects_rest(engine, package, standard_action, tokens):
    other = [k for k in package.keys if k != standard_action.idempotency_key]
    outcome = engine.decide(package, req(package, S, approved_keys=(standard_action.idempotency_key,),
                                         rejected_keys=tuple(other)), [credential(ANALYST_ID)])
    assert outcome.decision.approved_action_keys == (standard_action.idempotency_key,)
    assert outcome.decision.rejected_action_keys == tuple(other)
    assert [g.idempotency_key for g in outcome.token.claims.actions] == [standard_action.idempotency_key]
    with pytest.raises(TokenMismatchError):
        rejected = package.action(other[0])
        tokens.verify(outcome.token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding(rejected))


def test_approve_selected_keeps_package_order(engine, package):
    outcome = engine.decide(package, req(package, S, approved_keys=tuple(reversed(package.keys))),
                            [credential(ANALYST_ID)])
    assert outcome.decision.approved_action_keys == package.keys


def test_reject_records_decision_without_token(engine, package, audit):
    outcome = engine.decide(package, req(package, R, comment="false positive"), [credential(ANALYST_ID)])
    assert outcome.token is None and outcome.decision.token_id is None
    assert outcome.decision.rejected_action_keys == package.keys and outcome.decision.approved_action_keys == ()
    assert audit.events() == [AuditEventType.DECISION_RECORDED]


def test_request_more_investigation_records_decision_without_token(engine, package, audit):
    outcome = engine.decide(package, req(package, M, comment="check the parent process"), [credential(ANALYST_ID)])
    assert outcome.token is None
    assert outcome.decision.approved_action_keys == () and outcome.decision.rejected_action_keys == ()
    assert audit.events() == [AuditEventType.DECISION_RECORDED]


def test_outcome_carries_warnings_of_approved_actions(engine):
    warning = CriticalAssetWarning(asset="DC-01", asset_class="domain_controller", role="AD DC",
                                   action_type=ActionType.ISOLATE_ENDPOINT, potential_impact="auth outage",
                                   message="WARNING: ELEVATED APPROVAL REQUIRED - test")
    critical = make_recommendation(target="DC-01", approval_level=ApprovalLevel.ELEVATED).model_copy(
        update={"warnings": (warning,)})
    package = make_package(critical)
    outcome = engine.decide(package, req(package), [credential(ELEVATED_ID)])
    assert outcome.warnings == (warning,)


def test_duplicate_credentials_count_once(engine, package):
    outcome = engine.decide(package, req(package), [credential(ANALYST_ID), credential(ANALYST_ID)])
    assert [a.principal_id for a in outcome.decision.approvers] == [ANALYST_ID]


def test_release_approval_issues_release_token(engine, tokens, audit):
    package = make_release_package()
    outcome = engine.decide(package, req(package), [credential(ANALYST_ID)])
    assert outcome.decision.purpose is ApprovalPurpose.RELEASE
    assert outcome.token.claims.purpose is ApprovalPurpose.RELEASE
    tokens.verify(outcome.token, purpose=ApprovalPurpose.RELEASE, binding=binding(package.actions[0]))
    with pytest.raises(TokenMismatchError, match="purpose"):
        tokens.verify(outcome.token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding(package.actions[0]))
    assert audit.of(AuditEventType.TOKEN_ISSUED)[0].payload["purpose"] == "release"


def test_release_reject_needs_no_token(engine):
    package = make_release_package()
    outcome = engine.decide(package, req(package, R, comment="keep the host isolated"), [credential(ANALYST_ID)])
    assert outcome.token is None and outcome.decision.purpose is ApprovalPurpose.RELEASE


# ---------------------------------------------------------- package checks --
def test_wrong_package_id_is_refused_and_audited(engine, package, audit):
    with pytest.raises(DecisionError, match="different package"):
        engine.decide(package, DecisionRequest(package_id="other", decision=A), [credential(ANALYST_ID)])
    denied = audit.of(AuditEventType.APPROVAL_DENIED)
    assert len(denied) == 1 and denied[0].payload["error"] == "DecisionError"
    assert audit.of(AuditEventType.DECISION_RECORDED) == []


def test_expired_package_is_refused(engine, package, clock):
    clock.advance(timedelta(minutes=240))
    with pytest.raises(DecisionError, match="expired"):
        engine.decide(package, req(package), [credential(ANALYST_ID)])


def test_modified_package_evidence_is_refused(engine, package, audit):
    tampered = package.model_copy(update={"evidence": package.evidence[:1]})
    with pytest.raises(DecisionError, match="evidence snapshot hash"):
        engine.decide(tampered, req(tampered), [credential(ANALYST_ID)])
    assert audit.events() == [AuditEventType.APPROVAL_DENIED]


def test_non_package_input_is_a_type_error(engine, package):
    with pytest.raises(TypeError):
        engine.decide(package, {"decision": "APPROVE_ALL"}, [credential(ANALYST_ID)])


# ---------------------------------------------------------- authentication --
def test_no_credentials_is_refused(engine, package, audit):
    with pytest.raises(ApproverNotAllowedError, match="at least one"):
        engine.decide(package, req(package), [])
    assert audit.events() == [AuditEventType.APPROVAL_DENIED]


def test_wrong_secret_is_refused_and_audited(engine, package, audit):
    bad = ApproverCredential(principal_id=ANALYST_ID, scheme="static", secret=SecretStr("wrong-secret-value"))
    with pytest.raises(AuthenticationError):
        engine.decide(package, req(package), [bad])
    denied = audit.of(AuditEventType.APPROVAL_DENIED)[0]
    assert denied.payload["claimed_principals"] == [ANALYST_ID] and denied.payload["approvers"] == []
    assert "wrong-secret-value" not in str(denied.payload)


def test_one_bad_credential_fails_the_whole_decision(engine, package):
    bad = ApproverCredential(principal_id="nobody@example.com", scheme="static", secret=SecretStr("x" * 12))
    with pytest.raises(AuthenticationError):
        engine.decide(package, req(package), [credential(ANALYST_ID), bad])


def test_non_credential_is_refused(engine, package):
    with pytest.raises(AuthenticationError):
        engine.decide(package, req(package), ["analyst.one@example.com"])


class _StubAuthenticator:
    def __init__(self, result):
        self.result = result

    def authenticate(self, credential):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _principal(pid=ANALYST_ID, kind=PrincipalKind.HUMAN, roles=("xdr-approver",)):
    return AuthenticatedPrincipal(principal_id=pid, display_name=pid, kind=kind, roles=frozenset(roles),
                                  authenticator="stub", authenticated_at=FIXED_NOW)


@pytest.mark.parametrize("result", [
    RuntimeError("idp down"),
    _principal(pid="someone.else@example.com"),
    "not-a-principal",
])
def test_misbehaving_authenticator_fails_closed(approval_settings, secrets, ledger, audit, clock, package, result):
    engine = make_engine(approval_settings, _StubAuthenticator(result), secrets, ledger, audit, clock)
    with pytest.raises(AuthenticationError):
        engine.decide(package, req(package), [credential(ANALYST_ID)])
    assert audit.events() == [AuditEventType.APPROVAL_DENIED]


# -------------------------------------------------------------- who approves --
@pytest.mark.parametrize("pid", [SERVICE_ID, AUTOMATION_ID, AI_ID])
@pytest.mark.parametrize("decision", [A, R, M])
def test_non_human_principals_can_never_decide(engine, package, audit, pid, decision):
    with pytest.raises(ApproverNotAllowedError, match="HUMAN"):
        engine.decide(package, req(package, decision, comment="x"), [credential(pid)])
    denied = audit.of(AuditEventType.APPROVAL_DENIED)
    assert len(denied) == 1 and denied[0].actor == pid
    assert audit.of(AuditEventType.TOKEN_ISSUED) == []


@pytest.mark.parametrize("pid", [SERVICE_ID, AUTOMATION_ID, AI_ID])
def test_non_human_co_approver_taints_the_decision(engine, package, pid):
    with pytest.raises(ApproverNotAllowedError, match="HUMAN"):
        engine.decide(package, req(package), [credential(ELEVATED_ID), credential(pid)])


def test_human_without_approver_role_is_refused(approval_settings, secrets, ledger, audit, clock, package):
    auth = InMemoryApproverAuthenticator(iterations=1)
    auth.add_principal("intern@example.com", display_name="Intern", kind=PrincipalKind.HUMAN, roles=["viewer"],
                       secret="intern-test-secret")
    engine = make_engine(approval_settings, auth, secrets, ledger, audit, clock)
    cred = ApproverCredential(principal_id="intern@example.com", scheme="static",
                              secret=SecretStr("intern-test-secret"))
    with pytest.raises(ApproverNotAllowedError, match="approver role"):
        engine.decide(package, req(package, R, comment="no"), [cred])


def test_elevated_action_needs_elevated_role(engine, mixed_package, audit):
    with pytest.raises(ApproverNotAllowedError, match="ELEVATED"):
        engine.decide(mixed_package, req(mixed_package), [credential(ANALYST_ID)])
    assert audit.events() == [AuditEventType.APPROVAL_DENIED]


def test_selected_without_elevated_actions_succeeds_for_standard_analyst(engine, mixed_package, standard_action):
    outcome = engine.decide(mixed_package, req(mixed_package, S, approved_keys=(standard_action.idempotency_key,)),
                            [credential(ANALYST_ID)])
    assert outcome.token is not None
    assert {g.approval_level for g in outcome.token.claims.actions} == {ApprovalLevel.STANDARD}


def test_selected_including_elevated_action_needs_elevated_role(engine, mixed_package, elevated_action):
    with pytest.raises(ApproverNotAllowedError, match="ELEVATED"):
        engine.decide(mixed_package, req(mixed_package, S, approved_keys=(elevated_action.idempotency_key,)),
                      [credential(ANALYST_ID)])


def test_elevated_approver_can_approve_all(engine, mixed_package, tokens, elevated_action):
    outcome = engine.decide(mixed_package, req(mixed_package), [credential(ELEVATED_ID)])
    tokens.verify(outcome.token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding(elevated_action))


def test_two_person_rule_for_elevated(authenticator, secrets, ledger, audit, clock, mixed_package):
    settings = ApprovalSettings(elevated_min_approvers=2)
    engine = make_engine(settings, authenticator, secrets, ledger, audit, clock)
    with pytest.raises(ApproverNotAllowedError, match="2 distinct"):
        engine.decide(mixed_package, req(mixed_package), [credential(ELEVATED_ID)])


def test_two_person_rule_for_standard(authenticator, secrets, ledger, audit, clock, package):
    settings = ApprovalSettings(standard_min_approvers=2)
    engine = make_engine(settings, authenticator, secrets, ledger, audit, clock)
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, req(package), [credential(ANALYST_ID)])
    outcome = engine.decide(package, req(package), [credential(ANALYST_ID), credential(ELEVATED_ID)])
    assert [a.principal_id for a in outcome.token.claims.approvers] == [ANALYST_ID, ELEVATED_ID]


def test_self_approval_is_refused_by_default(engine, package):
    own = package.model_copy(update={"requested_by": ANALYST_ID})
    with pytest.raises(ApproverNotAllowedError, match="self-approval"):
        engine.decide(own, req(own), [credential(ANALYST_ID)])


def test_self_approval_with_second_approver_succeeds(engine, package):
    own = package.model_copy(update={"requested_by": ANALYST_ID})
    outcome = engine.decide(own, req(own), [credential(ANALYST_ID), credential(ELEVATED_ID)])
    assert outcome.token is not None


def test_self_approval_allowed_when_configured(authenticator, secrets, ledger, audit, clock, package):
    engine = make_engine(ApprovalSettings(allow_self_approval=True), authenticator, secrets, ledger, audit, clock)
    own = package.model_copy(update={"requested_by": ANALYST_ID})
    assert engine.decide(own, req(own), [credential(ANALYST_ID)]).token is not None


def test_requester_may_still_reject_own_package(engine, package):
    own = package.model_copy(update={"requested_by": ANALYST_ID})
    assert engine.decide(own, req(own, R, comment="withdrawn"), [credential(ANALYST_ID)]).token is None


# ------------------------------------------------------- decision semantics --
@pytest.mark.parametrize("decision", [R, M])
@pytest.mark.parametrize("comment", ["", "   "])
def test_reject_and_more_investigation_require_comment(engine, package, decision, comment):
    with pytest.raises(DecisionError, match="comment"):
        engine.decide(package, req(package, decision, comment=comment), [credential(ANALYST_ID)])


def test_approve_all_comment_is_optional(engine, package):
    assert engine.decide(package, req(package), [credential(ANALYST_ID)]).decision.comment == ""


def test_approve_all_with_full_key_list_is_accepted(engine, package):
    assert engine.decide(package, req(package, approved_keys=package.keys), [credential(ANALYST_ID)]).token


@pytest.mark.parametrize("kwargs,match", [
    ({"decision": A, "approved_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",)}, "every package action"),
    ({"decision": A, "rejected_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",)}, "cannot reject"),
    ({"decision": S}, "at least one"),
    ({"decision": S, "approved_keys": ("XDR-83921:isolate_endpoint:TH-LT-0000",)}, "not in the package"),
    ({"decision": S, "approved_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",) * 2}, "duplicates"),
    ({"decision": S, "approved_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",),
      "rejected_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",)}, "rejected_keys"),
    ({"decision": S, "approved_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",),
      "rejected_keys": ("XDR-83921:block_domain:bad.example.test",) * 2}, "rejected_keys"),
    ({"decision": R, "comment": "no", "approved_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",)}, "cannot approve"),
    ({"decision": R, "comment": "no", "rejected_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",)},
     "every package action"),
    ({"decision": M, "comment": "more", "rejected_keys": ("XDR-83921:isolate_endpoint:TH-LT-1047",)},
     "approves and rejects nothing"),
])
def test_invalid_decisions_are_refused(engine, package, audit, kwargs, match):
    with pytest.raises(DecisionError, match=match):
        engine.decide(package, DecisionRequest(package_id=package.package_id, **kwargs), [credential(ANALYST_ID)])
    assert audit.events() == [AuditEventType.APPROVAL_DENIED]


# -------------------------------------------------------------- audit failures --
def test_decision_audit_failure_means_no_token(engine, package, audit):
    audit.fail_on = {AuditEventType.DECISION_RECORDED}
    with pytest.raises(AuditError):
        engine.decide(package, req(package), [credential(ANALYST_ID)])
    assert audit.of(AuditEventType.TOKEN_ISSUED) == []


def test_token_audit_failure_means_no_token(engine, package, audit):
    audit.fail_on = {AuditEventType.TOKEN_ISSUED}
    with pytest.raises(AuditError):
        engine.decide(package, req(package), [credential(ANALYST_ID)])
    assert audit.events() == [AuditEventType.DECISION_RECORDED]


def test_unexpected_audit_exception_becomes_audit_error(engine, package, audit, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(audit, "append", boom)
    with pytest.raises(AuditError):
        engine.decide(package, req(package), [credential(ANALYST_ID)])


def test_denial_is_raised_even_if_denial_audit_fails(engine, package, audit):
    audit.fail_on = {AuditEventType.APPROVAL_DENIED}
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, req(package), [credential(AI_ID)])


def test_engine_ids_are_injectable(engine, package):
    outcome = engine.decide(package, req(package), [credential(ANALYST_ID)])
    assert outcome.decision.decision_id == "id000001" and outcome.token.token_id == "id000002"


def test_fixture_authenticator_contract():
    auth = make_authenticator()
    assert auth.authenticate(credential(AI_ID)).kind is PrincipalKind.AI
