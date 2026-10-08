"""Test doubles for exercising guarded (state-changing) code without the approval package.

``FakeVerifier`` checks purpose, incident, grant binding, expiry, HUMAN approvers and single use,
but NOT the HMAC signature: it exists only so adapter and guard tests can enter
``guard.authorized(...)``. Production code registers ``ApprovalTokenService`` instead.

Typical use in an adapter test::

    verifier = install_fake_verifier()            # registers it and turns global dry run off
    request = ActionRequest.from_recommendation(make_recommendation(...))
    with guard.authorized(make_token(request), request):
        adapter.execute(request)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from tests.fixtures.factories import FIXED_NOW
from xdr_response import guard
from xdr_response.clock import Clock, FixedClock
from xdr_response.errors import TokenExpiredError, TokenInvalidError, TokenMismatchError, TokenReplayError
from xdr_response.models import (
    ActionBinding,
    ActionRequest,
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    PrincipalKind,
    RecommendedAction,
    TokenActionGrant,
    get_action_spec,
)

__all__ = ["FakeVerifier", "make_token", "install_fake_verifier"]


class FakeVerifier:
    """TokenVerifier test double (no signature check). Never use outside tests."""

    def __init__(self, clock: Clock | None = None) -> None:
        self.clock = clock or FixedClock(FIXED_NOW)
        self.used: set[tuple[str, str]] = set()
        self.verify_calls = 0
        self.mark_used_calls = 0

    def verify(self, token: ApprovalToken, *, purpose: ApprovalPurpose, binding: ActionBinding) -> TokenActionGrant:
        self.verify_calls += 1
        c = token.claims
        if c.purpose != purpose:
            raise TokenMismatchError("purpose mismatch")
        if c.incident_id != binding.incident_id:
            raise TokenMismatchError("incident mismatch")
        now = self.clock.now()
        if not (c.issued_at <= now < c.expires_at):
            raise TokenExpiredError("token expired")
        grant = c.grant(binding.idempotency_key)
        if grant is None or (grant.action_type, grant.target, grant.params_hash) != (
                binding.action_type, binding.target, binding.params_hash):
            raise TokenMismatchError("no matching grant")
        if any(a.kind is not PrincipalKind.HUMAN for a in c.approvers):
            raise TokenInvalidError("non-human approver")
        return grant

    def mark_used(self, token: ApprovalToken, idempotency_key: str) -> None:
        self.mark_used_calls += 1
        key = (token.token_id, idempotency_key)
        if key in self.used:
            raise TokenReplayError("token already used for this action")
        self.used.add(key)


def make_token(
    *actions: ActionRequest | RecommendedAction,
    purpose: ApprovalPurpose | None = None,
    issued_at: datetime = FIXED_NOW,
    ttl: timedelta = timedelta(minutes=30),
    approver_kind: PrincipalKind = PrincipalKind.HUMAN,
    incident_id: str | None = None,
    token_id: str | None = None,
) -> ApprovalToken:
    """Unsigned (zero signature) token granting exactly ``actions``."""
    if not actions:
        raise ValueError("at least one action is required")
    first = actions[0]
    purpose = purpose or get_action_spec(first.action_type).purpose or ApprovalPurpose.CONTAINMENT
    grants = tuple(
        TokenActionGrant(
            idempotency_key=a.idempotency_key, action_type=a.action_type, target=a.target,
            params_hash=a.params_hash,
            approval_level=getattr(a, "approval_level", None) or "STANDARD",
        )
        for a in actions
    )
    claims = ApprovalTokenClaims(
        token_id=token_id or uuid.uuid4().hex, purpose=purpose, package_id="pkg-test",
        incident_id=incident_id or first.incident_id, evidence_snapshot_hash="0" * 64,
        workflow_id="malicious-powershell", workflow_version="1.0.0", decision_id="decision-test",
        actions=grants,
        approvers=(ApproverClaim(principal_id="analyst.one@example.com", kind=approver_kind,
                                 roles=("xdr-approver", "xdr-elevated-approver")),),
        issued_at=issued_at, expires_at=issued_at + ttl,
    )
    return ApprovalToken(claims=claims, key_id="test", signature="0" * 64)


def install_fake_verifier(clock: Clock | None = None, *, dry_run: bool = False) -> FakeVerifier:
    """Register a FakeVerifier with the guard and set the global dry-run flag (default off).

    The guard seals its verifier slot on the first registration, so within one test a second call
    re-uses the FakeVerifier that is already sealed (with the new clock, when one is given).
    """
    sealed = getattr(guard, "_sealed_verifier", None)
    if isinstance(sealed, FakeVerifier):
        verifier = sealed
        if clock is not None:
            verifier.clock = clock
    else:
        verifier = FakeVerifier(clock)
    guard.register_verifier(verifier)
    guard.configure(dry_run=dry_run)
    return verifier
