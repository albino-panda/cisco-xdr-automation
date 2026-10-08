"""Model validation: evidence, recommendations, packages, approval tokens, results, controls."""
from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr, ValidationError

from tests.fixtures.factories import FIXED_NOW, make_evidence, make_incident, make_package, make_recommendation
from xdr_response.errors import TokenInvalidError
from xdr_response.models import (
    TOKEN_SIGNING_CONTEXT,
    ActionBinding,
    ActionOutcome,
    ActionRequest,
    ActionResult,
    ActionResultStatus,
    AnalystDecision,
    ApiCallSummary,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    ApproverCredential,
    Asset,
    AuditRecord,
    ContainmentPackage,
    ContainmentReport,
    ContainmentOverall,
    CriticalAssetClass,
    CriticalAssetWarning,
    DecisionType,
    EvidenceDraft,
    InvestigationQuery,
    Observable,
    ObservableType,
    OperationKind,
    PrincipalKind,
    RecommendedAction,
    ReleasePackage,
    RiskBand,
    SkipReason,
    TargetKind,
    TemporaryControl,
    TokenActionGrant,
    ActionType,
    canonical_json,
    evidence_snapshot_hash,
    number_evidence,
    risk_band,
)


# ----------------------------------------------------------------- evidence --
def test_evidence_never_from_ai():
    for source in ("ai", "AI", "ai:summary"):
        with pytest.raises(ValidationError):
            EvidenceDraft(source=source, summary="AI says it is malicious")
    with pytest.raises(ValidationError):
        EvidenceDraft(source="random-blog", summary="unsourced claim")
    assert EvidenceDraft(source="analyst", summary="Analyst confirmed").source == "analyst"
    assert EvidenceDraft(source="temporary_control_registry", summary="Control active").source


def test_number_evidence_orders_and_dedupes():
    a = EvidenceDraft(source="virustotal", summary="b", observed_at=FIXED_NOW)
    b = EvidenceDraft(source="cisco_xdr", summary="z")
    c = EvidenceDraft(source="cisco_xdr", summary="a", observed_at=FIXED_NOW)
    numbered = number_evidence([a, b, c, a])
    assert [e.number for e in numbered] == [1, 2, 3]
    assert [(e.source, e.summary) for e in numbered] == [("cisco_xdr", "z"), ("cisco_xdr", "a"), ("virustotal", "b")]
    assert number_evidence([c, b, a]) == numbered


def test_evidence_snapshot_hash_detects_changes():
    ev = make_evidence(3)
    h = evidence_snapshot_hash(ev)
    assert h == evidence_snapshot_hash(tuple(reversed(ev)))
    changed = (ev[0].model_copy(update={"summary": "tampered"}),) + ev[1:]
    assert evidence_snapshot_hash(changed) != h


# ------------------------------------------------------------ recommendation --
def test_risk_band_boundaries():
    assert [risk_band(s) for s in (0, 29, 30, 59, 60, 79, 80, 100)] == [
        RiskBand.LOW, RiskBand.LOW, RiskBand.MEDIUM, RiskBand.MEDIUM,
        RiskBand.HIGH, RiskBand.HIGH, RiskBand.CRITICAL, RiskBand.CRITICAL]
    for bad in (-1, 101, True, 50.0):
        with pytest.raises(ValueError):
            risk_band(bad)  # type: ignore[arg-type]


def test_recommended_action_validators():
    rec = make_recommendation()
    assert rec.idempotency_key == "XDR-83921:isolate_endpoint:TH-LT-1047"
    assert rec.integration == "secure_endpoint" and len(rec.params_hash) == 64
    data = rec.model_dump()
    with pytest.raises(ValidationError):  # wrong key
        RecommendedAction(**{**data, "idempotency_key": "XDR-83921:isolate_endpoint:OTHER"})
    with pytest.raises(ValidationError):  # read action
        RecommendedAction(**{**data, "action_type": ActionType.ENRICH_IP})
    with pytest.raises(ValidationError):  # wrong target kind
        RecommendedAction(**{**data, "target_kind": TargetKind.USER})
    with pytest.raises(ValidationError):  # no integration
        RecommendedAction(**{**data, "params": {}})
    with pytest.raises(ValidationError):  # no evidence
        RecommendedAction(**{**data, "evidence": ()})
    with pytest.raises(ValidationError):  # score range
        RecommendedAction(**{**data, "risk_score": 101})
    with pytest.raises(ValidationError):  # target not normalized
        RecommendedAction(**{**data, "target": "th-lt-1047",
                             "idempotency_key": "XDR-83921:isolate_endpoint:th-lt-1047"})
    with pytest.raises(ValidationError):  # floats are not allowed in signed params
        RecommendedAction(**{**data, "params": {"integration": "secure_endpoint", "x": 0.5}})


def test_warnings_force_elevated_and_always_elevated():
    warning = CriticalAssetWarning(
        asset="DC-01", asset_class=CriticalAssetClass.DOMAIN_CONTROLLER, role="Domain controller",
        action_type=ActionType.ISOLATE_ENDPOINT, potential_impact="Authentication outage",
        message="WARNING: ELEVATED APPROVAL REQUIRED - isolate_endpoint on DC-01")
    data = make_recommendation(target="DC-01").model_dump()
    with pytest.raises(ValidationError):
        RecommendedAction(**{**data, "warnings": (warning,)})
    ok = RecommendedAction(**{**data, "warnings": (warning,), "approval_level": ApprovalLevel.ELEVATED})
    assert ok.approval_level is ApprovalLevel.ELEVATED
    role = make_recommendation(ActionType.REMOVE_PRIVILEGED_ROLE, "j.doe@example.com/role-1", "entra")
    assert role.approval_level is ApprovalLevel.ELEVATED
    with pytest.raises(ValidationError):
        RecommendedAction(**{**role.model_dump(), "approval_level": ApprovalLevel.STANDARD})


def test_models_are_frozen_and_forbid_extra():
    rec = make_recommendation()
    with pytest.raises(ValidationError):
        rec.target = "OTHER"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Observable(type=ObservableType.IP, value="192.0.2.1", unexpected=True)  # type: ignore[call-arg]


# ------------------------------------------------------------------ packages --
def test_package_validators():
    pkg = make_package(make_recommendation(), make_recommendation(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella"))
    assert pkg.purpose is ApprovalPurpose.CONTAINMENT
    assert pkg.keys == ("XDR-83921:isolate_endpoint:TH-LT-1047", "XDR-83921:block_domain:bad.example.test")
    assert pkg.action("XDR-83921:block_domain:bad.example.test").integration == "umbrella"
    with pytest.raises(KeyError):
        pkg.action("nope")
    assert not pkg.has_elevated
    data = pkg.model_dump()
    with pytest.raises(ValidationError):  # tampered evidence hash
        ContainmentPackage(**{**data, "evidence_snapshot_hash": "0" * 64})
    with pytest.raises(ValidationError):  # duplicate keys
        ContainmentPackage(**{**data, "actions": (pkg.actions[0], pkg.actions[0])})
    with pytest.raises(ValidationError):  # empty
        ContainmentPackage(**{**data, "actions": ()})
    with pytest.raises(ValidationError):  # other incident
        make_package(make_recommendation(incident_id="XDR-1"), incident_id="XDR-2")
    with pytest.raises(ValidationError):  # expired at creation
        ContainmentPackage(**{**data, "expires_at": FIXED_NOW})
    with pytest.raises(ValidationError):  # purpose cannot be switched
        ContainmentPackage(**{**data, "purpose": ApprovalPurpose.RELEASE})
    with pytest.raises(ValidationError):  # release action in a containment package
        make_package(make_recommendation(ActionType.RELEASE_ENDPOINT, restores="k"))


def test_release_package_requires_control_keys_in_order():
    control_key = "XDR-83921:isolate_endpoint:TH-LT-1047"
    rel = make_recommendation(ActionType.RELEASE_ENDPOINT, restores=control_key)
    base = make_package().model_dump(exclude={"purpose"})
    base["actions"] = (rel,)
    pkg = ReleasePackage(**base, control_keys=(control_key,))
    assert pkg.purpose is ApprovalPurpose.RELEASE
    with pytest.raises(ValidationError):
        ReleasePackage(**base, control_keys=("other",))
    base["actions"] = (make_recommendation(),)
    with pytest.raises(ValidationError):  # containment action in a release package
        ReleasePackage(**base, control_keys=(control_key,))


def test_package_json_roundtrip_keeps_hash():
    pkg = make_package()
    again = ContainmentPackage.model_validate_json(pkg.model_dump_json())
    assert again == pkg
    assert canonical_json(again) == canonical_json(pkg)


# ------------------------------------------------------------------ approval --
def _claims(**over) -> ApprovalTokenClaims:
    rec = make_recommendation()
    data = dict(
        token_id="t" * 32, purpose=ApprovalPurpose.CONTAINMENT, package_id="p" * 32,
        incident_id=rec.incident_id, evidence_snapshot_hash="e" * 64, workflow_id="malicious-powershell",
        workflow_version="1.0.0", decision_id="d" * 32,
        actions=(TokenActionGrant(idempotency_key=rec.idempotency_key, action_type=rec.action_type,
                                  target=rec.target, params_hash=rec.params_hash,
                                  approval_level=rec.approval_level),),
        approvers=(ApproverClaim(principal_id="analyst.one@example.com", kind=PrincipalKind.HUMAN,
                                 roles=("z-role", "xdr-approver")),),
        issued_at=FIXED_NOW, expires_at=FIXED_NOW + timedelta(minutes=30),
    )
    data.update(over)
    return ApprovalTokenClaims(**data)


def test_token_claims_and_grant():
    claims = _claims()
    assert claims.approvers[0].roles == ("xdr-approver", "z-role")
    assert claims.grant("XDR-83921:isolate_endpoint:TH-LT-1047") is not None
    assert claims.grant("missing") is None
    with pytest.raises(ValidationError):
        _claims(expires_at=FIXED_NOW)
    with pytest.raises(ValidationError):
        _claims(actions=())
    with pytest.raises(ValidationError):
        _claims(approvers=())
    assert TOKEN_SIGNING_CONTEXT == b"xdr-response/approval-token/v1\n"


def test_token_encode_decode_and_no_signature_in_repr():
    token = ApprovalToken(claims=_claims(), key_id="primary", signature="ab" * 32)
    encoded = token.encode()
    assert encoded.count(".") == 2 and encoded.endswith("ab" * 32)
    assert ApprovalToken.decode(encoded) == token
    assert "ab" * 32 not in repr(token) and "ab" * 32 not in str(token)
    for bad in ("", "a.b", "x.primary." + "ab" * 32, encoded + ".x", encoded[:-1] + "Z", 42):
        with pytest.raises(TokenInvalidError):
            ApprovalToken.decode(bad)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ApprovalToken(claims=_claims(), key_id="primary", signature="XYZ")


def test_action_binding_and_request():
    rec = make_recommendation()
    req = ActionRequest.from_recommendation(rec)
    assert req.integration == "secure_endpoint" and req.params_hash == rec.params_hash
    binding = ActionBinding.from_request(req)
    assert binding == ActionBinding(incident_id="XDR-83921", idempotency_key=rec.idempotency_key,
                                    action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047",
                                    params_hash=rec.params_hash)
    with pytest.raises(ValidationError):
        ActionRequest(**{**req.model_dump(), "target": "OTHER-HOST"})


def test_credential_secret_hidden():
    cred = ApproverCredential(principal_id="analyst.one@example.com", scheme="static",
                              secret=SecretStr("hunter2-not-real"))
    assert "hunter2" not in repr(cred) and "hunter2" not in cred.model_dump_json()
    assert b"hunter2" not in canonical_json(cred)


def test_analyst_decision_rules():
    common = dict(decision_id="d1", package_id="p1", incident_id="XDR-83921", purpose=ApprovalPurpose.CONTAINMENT,
                  analyst_identity="", approvers=(), decided_at=FIXED_NOW, comment="no",
                  workflow_id="malicious-powershell", workflow_version="1.0.0", evidence_snapshot_hash="e" * 64)
    AnalystDecision(**common, decision=DecisionType.REJECT, approved_action_keys=(), rejected_action_keys=("k",))
    with pytest.raises(ValidationError):
        AnalystDecision(**common, decision=DecisionType.REJECT, approved_action_keys=("k",), rejected_action_keys=())
    with pytest.raises(ValidationError):
        AnalystDecision(**common, decision=DecisionType.REJECT, approved_action_keys=(), rejected_action_keys=(),
                        token_id="t1")


# ---------------------------------------------------------- results / misc --
def test_action_outcome_and_result_rules():
    with pytest.raises(ValidationError):
        ActionOutcome(status=ActionResultStatus.FAILED, integration="x", executed_at=FIXED_NOW)  # type: ignore[arg-type]
    common = dict(idempotency_key="k", action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047",
                  integration="secure_endpoint", approval_level=ApprovalLevel.STANDARD,
                  started_at=FIXED_NOW, finished_at=FIXED_NOW)
    ActionResult(**common, status=ActionResultStatus.SKIPPED, skip_reason=SkipReason.REJECTED_BY_ANALYST)
    with pytest.raises(ValidationError):
        ActionResult(**common, status=ActionResultStatus.SKIPPED)
    with pytest.raises(ValidationError):
        ActionResult(**common, status=ActionResultStatus.DRY_RUN)
    r = ActionResult(**common, status=ActionResultStatus.DRY_RUN, dry_run_line="Would isolate: TH-LT-1047")
    with pytest.raises(ValidationError):
        ContainmentReport(report_id="r", incident_id="i", package_id="p", token_id=None, dry_run=True,
                          started_at=FIXED_NOW, finished_at=FIXED_NOW, results=(r,),
                          overall=ContainmentOverall.CONTAINED)


def test_api_call_summary_is_size_capped():
    big = {"blob": "x" * 10000}
    s = ApiCallSummary(integration="virustotal", operation="file_report", method="GET",
                       url="https://www.virustotal.com/api/v3/files/x", kind=OperationKind.READ,
                       status_code=200, duration_ms=5, attempt=1, response_summary=big)
    assert s.response_summary["_truncated"] is True
    assert len(s.model_dump_json()) < 6000


def test_temporary_control_validators():
    data = dict(control_key="XDR-83921:isolate_endpoint:TH-LT-1047", incident_id="XDR-83921",
                action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047", target_kind=TargetKind.ENDPOINT,
                integration="secure_endpoint", workflow_id="malicious-powershell", workflow_version="1.0.0",
                package_id="p", token_id="t", decision_id="d", approval_level=ApprovalLevel.STANDARD,
                created_at=FIXED_NOW, rollback_action_type=ActionType.RELEASE_ENDPOINT,
                rollback_params={"integration": "secure_endpoint"})
    TemporaryControl(**data)
    with pytest.raises(ValidationError):
        TemporaryControl(**{**data, "rollback_params": {}})
    with pytest.raises(ValidationError):
        TemporaryControl(**{**data, "rollback_action_type": ActionType.UNBLOCK_IP})
    with pytest.raises(ValidationError):  # non-reversible actions never create controls
        TemporaryControl(**{**data, "action_type": ActionType.REVOKE_SESSIONS})


def test_incident_asset_and_investigation_models():
    inc = make_incident()
    assert inc.assets[0].name == "TH-LT-1047"
    assert Asset(name="th-lt-2000", kind=TargetKind.ENDPOINT).name == "TH-LT-2000"
    moved = inc.model_copy(update={"title": "x"})
    assert moved.title == "x" and inc.title != "x"
    InvestigationQuery(action_type=ActionType.INVESTIGATE_ENDPOINT,
                       subject=Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"))
    with pytest.raises(ValidationError):
        InvestigationQuery(action_type=ActionType.ISOLATE_ENDPOINT,
                           subject=Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"))


def test_audit_record_hash_format():
    with pytest.raises(ValidationError):
        AuditRecord(seq=0, record_id="r", timestamp=FIXED_NOW, event_type="ERROR", incident_id=None,
                    workflow_id=None, workflow_version=None, actor="a", payload={}, prev_hash="0" * 64,
                    hash="not-a-hash")

