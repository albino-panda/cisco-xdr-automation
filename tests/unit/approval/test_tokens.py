"""ApprovalTokenService: signing, every verification failure path, tampering, replay and expiry."""
from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW, make_package, make_recommendation
from tests.fixtures.principals import ANALYST_ID, ELEVATED_ID, ELEVATED_ROLE, STANDARD_ROLE, make_test_secrets
from tests.unit.approval._support import make_release_package
from xdr_response import guard
from xdr_response.approval import ApprovalTokenService, InMemoryTokenUseLedger, claims_hash
from xdr_response.approval import tokens as tokens_module
from xdr_response.config import ApprovalSettings
from xdr_response.errors import (
    ApprovalRequiredError,
    ApproverNotAllowedError,
    ConfigError,
    DecisionError,
    DryRunViolationError,
    SecretNotFoundError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMismatchError,
    TokenReplayError,
)
from xdr_response.models import (
    ActionBinding,
    ActionRequest,
    ActionType,
    AnalystDecision,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ApproverClaim,
    AuthenticatedPrincipal,
    DecisionType,
    PrincipalKind,
    evidence_snapshot_hash,
)
from xdr_response.secrets import StaticSecretProvider

KEY_A = "k" * 40
KEY_B = "z" * 40


def human(pid: str = ANALYST_ID, roles=(STANDARD_ROLE,), kind: PrincipalKind = PrincipalKind.HUMAN):
    return AuthenticatedPrincipal(principal_id=pid, display_name=pid, kind=kind, roles=frozenset(roles),
                                  authenticator="test", authenticated_at=FIXED_NOW)


LEAD = (ELEVATED_ID, (STANDARD_ROLE, ELEVATED_ROLE))


def decision_for(package, approvers, keys=None, kind=DecisionType.APPROVE_ALL, **overrides):
    keys = tuple(package.keys if keys is None else keys)
    data = dict(
        decision_id="decision-1", package_id=package.package_id, incident_id=package.incident_id,
        purpose=package.purpose, decision=kind, analyst_identity=approvers[0].principal_id,
        approvers=tuple(approvers), decided_at=FIXED_NOW, approved_action_keys=keys,
        rejected_action_keys=tuple(k for k in package.keys if k not in keys), comment="",
        workflow_id=package.workflow_id, workflow_version=package.workflow_version,
        evidence_snapshot_hash=package.evidence_snapshot_hash, token_id="token-1",
    )
    data.update(overrides)
    return AnalystDecision(**data)


_ISSUERS: dict[int, object] = {}


def issuer_of(service):
    """The one-time minting capability of ``service`` (normally bound by the ApprovalEngine)."""
    issuer = _ISSUERS.get(id(service))
    if issuer is None or issuer._service is not service:  # type: ignore[attr-defined]
        issuer = _ISSUERS[id(service)] = service.bind_issuer()
    return issuer


def issue(service, package, approvers=None, keys=None):
    approvers = approvers or [human()]
    return issuer_of(service).issue(package, decision_for(package, approvers, keys), approvers)


def binding_of(action, **overrides) -> ActionBinding:
    data = ActionBinding.from_request(ActionRequest.from_recommendation(action)).model_dump()
    data.update(overrides)
    return ActionBinding(**data)


def tamper(token: ApprovalToken, **claims_update) -> ApprovalToken:
    return ApprovalToken(claims=token.claims.model_copy(update=claims_update), key_id=token.key_id,
                         signature=token.signature)


def service_with(values, settings=None, clock=None, **kwargs) -> ApprovalTokenService:
    return ApprovalTokenService(StaticSecretProvider(values), settings or ApprovalSettings(),
                                ledger=InMemoryTokenUseLedger(), clock=clock, **kwargs)


# ------------------------------------------------------------------ issuing --
def test_issue_binds_package_decision_and_actions(tokens, package):
    token = issue(tokens, package)
    c = token.claims
    assert (c.purpose, c.package_id, c.incident_id) == (ApprovalPurpose.CONTAINMENT, package.package_id,
                                                        package.incident_id)
    assert c.evidence_snapshot_hash == package.evidence_snapshot_hash
    assert (c.workflow_id, c.workflow_version, c.decision_id, c.token_id) == (
        "malicious-powershell", "1.0.0", "decision-1", "token-1")
    assert [g.idempotency_key for g in c.actions] == list(package.keys)
    for grant in c.actions:
        action = package.action(grant.idempotency_key)
        assert (grant.action_type, grant.target, grant.params_hash, grant.approval_level) == (
            action.action_type, action.target, action.params_hash, action.approval_level)
    assert c.approvers == (ApproverClaim(principal_id=ANALYST_ID, kind=PrincipalKind.HUMAN, roles=(STANDARD_ROLE,)),)
    assert c.issued_at == FIXED_NOW and c.expires_at == FIXED_NOW + timedelta(minutes=30)
    assert token.alg == "HMAC-SHA256" and token.key_id == "primary" and len(token.signature) == 64


def test_issue_grants_only_selected_keys(tokens, package):
    first = package.keys[0]
    token = issue(tokens, package, keys=[first])
    assert [g.idempotency_key for g in token.claims.actions] == [first]


def test_release_token_uses_release_ttl(secrets, ledger, clock):
    service = ApprovalTokenService(secrets, ApprovalSettings(release_token_ttl_minutes=10), ledger=ledger, clock=clock)
    token = issue(service, make_release_package())
    assert token.claims.purpose is ApprovalPurpose.RELEASE
    assert token.claims.expires_at - token.claims.issued_at == timedelta(minutes=10)


def test_claims_hash_is_deterministic_and_excludes_signature(tokens, package):
    token = issue(tokens, package)
    assert claims_hash(token.claims) == claims_hash(token.claims.model_copy())
    assert len(claims_hash(token.claims)) == 64 and claims_hash(token.claims) != token.signature


@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AUTOMATION, PrincipalKind.AI])
def test_issue_refuses_non_human_even_with_roles(tokens, package, kind):
    approvers = [human("bot@example.com", (STANDARD_ROLE, ELEVATED_ROLE), kind)]
    with pytest.raises(ApproverNotAllowedError, match="HUMAN"):
        issue(tokens, package, approvers)


def test_issue_refuses_elevated_without_elevated_role(tokens, mixed_package):
    with pytest.raises(ApproverNotAllowedError, match="ELEVATED"):
        issue(tokens, mixed_package)


def test_issue_accepts_elevated_with_lead(tokens, mixed_package):
    token = issue(tokens, mixed_package, [human(*LEAD)])
    assert {g.approval_level for g in token.claims.actions} == {ApprovalLevel.STANDARD, ApprovalLevel.ELEVATED}


def test_issue_refuses_non_approving_decision(tokens, package):
    approvers = [human()]
    decision = decision_for(package, approvers, keys=(), kind=DecisionType.REJECT, token_id=None, comment="no")
    with pytest.raises(DecisionError):
        issuer_of(tokens).issue(package, decision, approvers)


def test_issue_refuses_decision_for_other_package(tokens, package):
    other = make_package()
    approvers = [human()]
    with pytest.raises(DecisionError):
        issuer_of(tokens).issue(package, decision_for(other, approvers, keys=()), approvers)


def test_issue_refuses_approvers_that_differ_from_decision(tokens, package):
    with pytest.raises(DecisionError, match="approvers"):
        issuer_of(tokens).issue(package, decision_for(package, [human()]), [human(*LEAD)])


def test_issue_refuses_tampered_package_evidence(tokens, package):
    approvers = [human()]
    decision = decision_for(package, approvers)
    changed = package.model_copy(update={"evidence": package.evidence[:1]})
    with pytest.raises(DecisionError, match="evidence"):
        issuer_of(tokens).issue(changed, decision, approvers)


# --------------------------------------------------------------- key loading --
def test_missing_signing_key_is_refused():
    with pytest.raises(SecretNotFoundError):
        service_with({})


def test_short_signing_key_is_refused():
    with pytest.raises(ConfigError, match="32 bytes"):
        service_with({"APPROVAL_SIGNING_KEY": "short-key"})


def test_short_previous_key_is_refused():
    with pytest.raises(ConfigError):
        service_with({"APPROVAL_SIGNING_KEY": KEY_A, "APPROVAL_SIGNING_KEY_PREVIOUS": "short"})


def test_previous_key_id_requires_previous_key():
    with pytest.raises(ConfigError):
        service_with({"APPROVAL_SIGNING_KEY": KEY_A}, previous_key_id="old")


def test_repr_never_shows_key(tokens):
    assert "APPROVAL" not in repr(tokens) and "primary" in repr(tokens)


# ------------------------------------------------------------- verification --
def test_verify_returns_grant_for_bound_action(tokens, package, standard_action):
    token = issue(tokens, package)
    grant = tokens.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))
    assert grant.idempotency_key == standard_action.idempotency_key


def test_signature_compare_is_constant_time(tokens, package, standard_action, monkeypatch):
    calls = []
    original = tokens_module.hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return original(a, b)

    monkeypatch.setattr(tokens_module.hmac, "compare_digest", spy)
    tokens.verify(issue(tokens, package), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))
    assert calls


def test_verify_rejects_non_token(tokens, standard_action):
    with pytest.raises(TokenInvalidError):
        tokens.verify("not-a-token", purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_verify_rejects_unknown_key_id(tokens, package, standard_action):
    token = issue(tokens, package)
    forged = ApprovalToken(claims=token.claims, key_id="other", signature=token.signature)
    with pytest.raises(TokenInvalidError, match="key id"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_verify_rejects_unsupported_algorithm(tokens, package, standard_action):
    token = issue(tokens, package)
    forged = ApprovalToken.model_construct(claims=token.claims, key_id=token.key_id, alg="none",
                                           signature=token.signature)
    with pytest.raises(TokenInvalidError, match="algorithm"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_verify_rejects_altered_signature(tokens, package, standard_action):
    token = issue(tokens, package)
    flipped = ("0" if token.signature[0] != "0" else "1") + token.signature[1:]
    forged = ApprovalToken(claims=token.claims, key_id=token.key_id, signature=flipped)
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_verify_rejects_token_signed_with_another_key(package, standard_action, clock):
    signer = service_with({"APPROVAL_SIGNING_KEY": KEY_A}, clock=clock)
    verifier = service_with({"APPROVAL_SIGNING_KEY": KEY_B}, clock=clock)
    with pytest.raises(TokenInvalidError, match="signature"):
        verifier.verify(issue(signer, package), purpose=ApprovalPurpose.CONTAINMENT,
                        binding=binding_of(standard_action))


def test_previous_key_still_verifies_after_rotation(package, standard_action, clock):
    old = service_with({"APPROVAL_SIGNING_KEY": KEY_A}, clock=clock)
    rotated = service_with({"APPROVAL_SIGNING_KEY": KEY_B, "APPROVAL_SIGNING_KEY_PREVIOUS": KEY_A}, clock=clock)
    token = issue(old, package)
    rotated.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))
    assert rotated.sign(token.claims).signature != token.signature  # new tokens use the new key


def test_previous_key_id_rotation(package, standard_action, clock):
    old = service_with({"APPROVAL_SIGNING_KEY": KEY_A}, ApprovalSettings(signing_key_id="k2025"), clock)
    new = service_with({"APPROVAL_SIGNING_KEY": KEY_B, "APPROVAL_SIGNING_KEY_PREVIOUS": KEY_A},
                       ApprovalSettings(signing_key_id="k2026"), clock, previous_key_id="k2025")
    new.verify(issue(old, package), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


_GRANT_TAMPERS = {
    "idempotency_key": "XDR-83921:isolate_endpoint:TH-LT-9999",
    "action_type": ActionType.BLOCK_HASH,
    "target": "TH-LT-9999",
    "params_hash": "c" * 64,
    "approval_level": ApprovalLevel.ELEVATED,
}


@pytest.mark.parametrize("field,value", [
    ("token_id", "f" * 32),
    ("purpose", ApprovalPurpose.RELEASE),
    ("package_id", "another-package"),
    ("incident_id", "XDR-99999"),
    ("evidence_snapshot_hash", "b" * 64),
    ("workflow_id", "phishing"),
    ("workflow_version", "9.9.9"),
    ("decision_id", "another-decision"),
    ("issued_at", FIXED_NOW - timedelta(minutes=1)),
    ("expires_at", FIXED_NOW + timedelta(minutes=29)),
])
def test_tampering_any_claim_breaks_signature(tokens, package, standard_action, field, value):
    forged = tamper(issue(tokens, package), **{field: value})
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify_package(forged, package)


@pytest.mark.parametrize("field", sorted(_GRANT_TAMPERS))
def test_tampering_any_grant_field_breaks_signature(tokens, package, standard_action, field):
    token = issue(tokens, package)
    grants = list(token.claims.actions)
    grants[0] = grants[0].model_copy(update={field: _GRANT_TAMPERS[field]})
    forged = tamper(token, actions=tuple(grants))
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


@pytest.mark.parametrize("update", [
    {"principal_id": ELEVATED_ID},
    {"kind": PrincipalKind.AI},
    {"roles": (ELEVATED_ROLE, STANDARD_ROLE)},
])
def test_tampering_approver_claims_breaks_signature(tokens, package, standard_action, update):
    token = issue(tokens, package)
    forged = tamper(token, approvers=(token.claims.approvers[0].model_copy(update=update),))
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_adding_a_grant_breaks_signature(tokens, package, standard_action):
    token = issue(tokens, package, keys=[standard_action.idempotency_key])
    extra = make_recommendation(ActionType.BLOCK_IP, target="203.0.113.10", integration="meraki")
    grant = token.claims.actions[0].model_copy(update={
        "idempotency_key": extra.idempotency_key, "action_type": extra.action_type, "target": extra.target,
        "params_hash": extra.params_hash})
    forged = tamper(token, actions=token.claims.actions + (grant,))
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(extra))


def test_encode_decode_roundtrip_verifies(tokens, package, standard_action):
    decoded = ApprovalToken.decode(issue(tokens, package).encode())
    tokens.verify(decoded, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_tampered_encoded_body_is_refused(tokens, package, standard_action):
    body, key_id, signature = issue(tokens, package).encode().split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["incident_id"] = "XDR-99999"
    new_body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    forged = ApprovalToken.decode(f"{new_body}.{key_id}.{signature}")
    with pytest.raises(TokenInvalidError, match="signature"):
        tokens.verify(forged, purpose=ApprovalPurpose.CONTAINMENT,
                      binding=binding_of(standard_action, incident_id="XDR-99999"))


# ---------------------------------------------------------------- binding --
def test_replay_into_another_incident_is_refused(tokens, package):
    token = issue(tokens, package)
    other_incident = make_recommendation(incident_id="XDR-11111")  # same action type and target
    with pytest.raises(TokenMismatchError, match="incident"):
        tokens.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(other_incident))


def test_purpose_mismatch_is_refused(tokens, package, standard_action):
    with pytest.raises(TokenMismatchError, match="purpose"):
        tokens.verify(issue(tokens, package), purpose=ApprovalPurpose.RELEASE, binding=binding_of(standard_action))


def test_release_token_cannot_authorize_containment(tokens, standard_action):
    release = issue(tokens, make_release_package())
    with pytest.raises(TokenMismatchError, match="purpose"):
        tokens.verify(release, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_action_not_granted_is_refused(tokens, package, standard_action):
    token = issue(tokens, package, keys=[k for k in package.keys if k != standard_action.idempotency_key])
    with pytest.raises(TokenMismatchError, match="does not grant"):
        tokens.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


@pytest.mark.parametrize("override", [
    {"action_type": ActionType.BLOCK_HASH},
    {"target": "TH-LT-2000"},
    {"params_hash": "d" * 64},
])
def test_binding_field_mismatch_is_refused(tokens, package, standard_action, override):
    with pytest.raises(TokenMismatchError, match="does not match"):
        tokens.verify(issue(tokens, package), purpose=ApprovalPurpose.CONTAINMENT,
                      binding=binding_of(standard_action, **override))


def test_changed_params_are_refused(tokens, package, standard_action):
    changed = make_recommendation(integration="defender_endpoint")  # same key, different params
    assert changed.idempotency_key == standard_action.idempotency_key
    with pytest.raises(TokenMismatchError):
        tokens.verify(issue(tokens, package), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(changed))


def test_verify_requires_binding(tokens, package):
    with pytest.raises(TokenMismatchError):
        tokens.verify(issue(tokens, package), purpose=ApprovalPurpose.CONTAINMENT, binding=None)


# ------------------------------------------------------------------- time --
def test_token_valid_until_just_before_expiry(tokens, package, standard_action, clock):
    token = issue(tokens, package)
    clock.advance(timedelta(minutes=29, seconds=59))
    tokens.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


@pytest.mark.parametrize("delta", [timedelta(minutes=30), timedelta(hours=5)])
def test_expired_token_is_refused(tokens, package, standard_action, clock, delta):
    token = issue(tokens, package)
    clock.advance(delta)
    with pytest.raises(TokenExpiredError, match="expired"):
        tokens.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))
    with pytest.raises(TokenExpiredError):
        tokens.verify_package(token, package)


def test_token_issued_in_the_future_is_refused(tokens, package, standard_action):
    token = issue(tokens, package)
    claims = token.claims.model_copy(update={"issued_at": FIXED_NOW + timedelta(minutes=2),
                                             "expires_at": FIXED_NOW + timedelta(minutes=20)})
    with pytest.raises(TokenExpiredError, match="not valid yet"):
        tokens.verify(tokens.sign(claims), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_small_clock_skew_is_tolerated(tokens, package, standard_action):
    claims = issue(tokens, package).claims.model_copy(update={"issued_at": FIXED_NOW + timedelta(seconds=30)})
    tokens.verify(tokens.sign(claims), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_lifetime_longer_than_ttl_is_refused(tokens, package, standard_action):
    claims = issue(tokens, package).claims.model_copy(update={"expires_at": FIXED_NOW + timedelta(hours=8)})
    with pytest.raises(TokenExpiredError, match="TTL"):
        tokens.verify(tokens.sign(claims), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


# --------------------------------------------- correctly signed, bad approvers --
@pytest.mark.parametrize("kind", [PrincipalKind.SERVICE, PrincipalKind.AUTOMATION, PrincipalKind.AI])
def test_signed_token_with_non_human_approver_is_invalid(tokens, package, standard_action, kind):
    claims = issue(tokens, package).claims.model_copy(update={"approvers": (
        ApproverClaim(principal_id="bot@example.com", kind=kind, roles=(STANDARD_ROLE, ELEVATED_ROLE)),)})
    with pytest.raises(TokenInvalidError, match="non-human"):
        tokens.verify(tokens.sign(claims), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_signed_token_with_duplicate_approvers_is_invalid(tokens, package, standard_action):
    claims = issue(tokens, package).claims
    dup = claims.model_copy(update={"approvers": (claims.approvers[0], claims.approvers[0])})
    with pytest.raises(TokenInvalidError, match="duplicate"):
        tokens.verify(tokens.sign(dup), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


def test_signed_elevated_grant_without_elevated_approver_is_invalid(tokens, mixed_package, elevated_action):
    token = issue(tokens, mixed_package, [human(*LEAD)])
    claims = token.claims.model_copy(update={"approvers": (
        ApproverClaim(principal_id=ANALYST_ID, kind=PrincipalKind.HUMAN, roles=(STANDARD_ROLE,)),)})
    with pytest.raises(TokenInvalidError, match="insufficient"):
        tokens.verify(tokens.sign(claims), purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(elevated_action))


def test_quorum_is_rechecked_at_verification(secrets, ledger, clock, package, standard_action):
    one = ApprovalTokenService(secrets, ApprovalSettings(), ledger=ledger, clock=clock)
    two = ApprovalTokenService(secrets, ApprovalSettings(standard_min_approvers=2), ledger=ledger, clock=clock)
    token = issue(one, package)
    with pytest.raises(TokenInvalidError, match="insufficient"):
        two.verify(token, purpose=ApprovalPurpose.CONTAINMENT, binding=binding_of(standard_action))


# --------------------------------------------------------------- package --
def test_verify_package_accepts_matching_package(tokens, package):
    tokens.verify_package(issue(tokens, package), package)


def test_verify_package_rejects_other_package(tokens, package):
    other = make_package(*package.actions)
    with pytest.raises(TokenMismatchError, match="package"):
        tokens.verify_package(issue(tokens, package), other)


def test_verify_package_rejects_other_incident(tokens, package):
    other = make_package(make_recommendation(incident_id="XDR-11111"), incident_id="XDR-11111",
                         package_id=package.package_id)
    with pytest.raises(TokenMismatchError, match="incident"):
        tokens.verify_package(issue(tokens, package), other)


def test_verify_package_rejects_evidence_changed_after_approval(tokens, package):
    token = issue(tokens, package)
    fewer = package.evidence[:1]
    changed = package.model_copy(update={"evidence": fewer, "evidence_snapshot_hash": evidence_snapshot_hash(fewer)})
    with pytest.raises(TokenMismatchError, match="evidence"):
        tokens.verify_package(token, changed)


def test_verify_package_rejects_stored_hash_not_matching_evidence(tokens, package):
    token = issue(tokens, package)
    changed = package.model_copy(update={"evidence": package.evidence[:1]})
    with pytest.raises(TokenMismatchError, match="evidence"):
        tokens.verify_package(token, changed)


def test_verify_package_rejects_workflow_version_change(tokens, package):
    token = issue(tokens, package)
    with pytest.raises(TokenMismatchError, match="workflow"):
        tokens.verify_package(token, package.model_copy(update={"workflow_version": "2.0.0"}))


def test_verify_package_rejects_changed_action(tokens, package, standard_action):
    token = issue(tokens, package)
    changed_action = standard_action.model_copy(update={"params": {"integration": "defender_endpoint"}})
    actions = tuple(changed_action if a.idempotency_key == standard_action.idempotency_key else a
                    for a in package.actions)
    with pytest.raises(TokenMismatchError, match="does not match"):
        tokens.verify_package(token, package.model_copy(update={"actions": actions}))


def test_verify_package_rejects_grant_missing_from_package(tokens, package):
    token = issue(tokens, package)
    with pytest.raises(TokenMismatchError, match="not in the package"):
        tokens.verify_package(token, package.model_copy(update={"actions": package.actions[:1]}))


def test_verify_package_rejects_purpose_mismatch(tokens, package):
    release = make_release_package(package_id=package.package_id)
    with pytest.raises(TokenMismatchError, match="purpose"):
        tokens.verify_package(issue(tokens, package), release)


# --------------------------------------------------------------- single use --
def test_mark_used_is_single_use(tokens, package, standard_action, ledger):
    token = issue(tokens, package)
    tokens.mark_used(token, standard_action.idempotency_key)
    assert ledger.is_consumed(token.token_id, standard_action.idempotency_key)
    with pytest.raises(TokenReplayError):
        tokens.mark_used(token, standard_action.idempotency_key)


def test_mark_used_refuses_ungranted_key(tokens, package):
    with pytest.raises(TokenMismatchError):
        tokens.mark_used(issue(tokens, package), "XDR-83921:isolate_endpoint:TH-LT-0000")


# -------------------------------------------------------------------- guard --
class FakeAdapter:
    name = "secure_endpoint"

    def __init__(self) -> None:
        self.calls: list[str] = []

    @guard.state_changing
    def isolate_endpoint(self, request: ActionRequest) -> str:
        self.calls.append(request.target)
        return "isolated"


def test_service_is_a_guard_verifier_end_to_end(tokens, package, standard_action):
    guard.register_verifier(tokens)
    guard.configure(dry_run=False)
    adapter = FakeAdapter()
    request = ActionRequest.from_recommendation(standard_action)
    token = issue(tokens, package)
    with guard.authorized(token, request):
        assert adapter.isolate_endpoint(request) == "isolated"
    with pytest.raises(TokenReplayError):
        with guard.authorized(token, request):
            adapter.isolate_endpoint(request)
    with pytest.raises(ApprovalRequiredError):
        adapter.isolate_endpoint(request)  # direct call outside a context
    assert adapter.calls == ["TH-LT-1047"]


def test_guard_refuses_replay_into_another_incident(tokens, package):
    guard.register_verifier(tokens)
    guard.configure(dry_run=False)
    adapter = FakeAdapter()
    other = ActionRequest.from_recommendation(make_recommendation(incident_id="XDR-11111"))
    with pytest.raises(TokenMismatchError):
        with guard.authorized(issue(tokens, package), other):
            adapter.isolate_endpoint(other)
    assert adapter.calls == []


def test_guard_refuses_expired_token_inside_context(tokens, package, standard_action, clock):
    guard.register_verifier(tokens)
    guard.configure(dry_run=False)
    adapter = FakeAdapter()
    request = ActionRequest.from_recommendation(standard_action)
    with guard.authorized(issue(tokens, package), request):
        clock.advance(timedelta(minutes=31))
        with pytest.raises(TokenExpiredError):
            adapter.isolate_endpoint(request)
    assert adapter.calls == []


def test_guard_refuses_valid_token_in_dry_run(tokens, package, standard_action):
    guard.register_verifier(tokens)
    request = ActionRequest.from_recommendation(standard_action)
    with pytest.raises(DryRunViolationError):
        with guard.authorized(issue(tokens, package), request):
            pass


def test_fresh_test_secrets_differ():
    assert make_test_secrets().get("APPROVAL_SIGNING_KEY") != make_test_secrets().get("APPROVAL_SIGNING_KEY")
