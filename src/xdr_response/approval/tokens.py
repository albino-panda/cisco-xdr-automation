"""Approval token issuing and verification (architecture sections 5.5 and 5.6).

:class:`ApprovalTokenService` signs :class:`ApprovalTokenClaims` with HMAC-SHA256 over
``TOKEN_SIGNING_CONTEXT + canonical_json(claims)`` using the ``APPROVAL_SIGNING_KEY`` secret, and
implements :class:`xdr_response.interfaces.TokenVerifier` (alias ``ApprovalVerifier``) for the
execution guard. Verification is deterministic and fails closed: the first failed check raises a
subclass of :class:`ApprovalRequiredError`.

Only :meth:`ApprovalTokenService.issue` produces tokens that verify: after its policy checks it adds
an ``issuance_proof`` (HMAC over ``TOKEN_ISSUANCE_CONTEXT`` and every claim except ``issued_at`` and
the proof itself) to the claims. ``issue`` is a capability, not a public API: it requires the
:class:`TokenIssuer` that :meth:`ApprovalTokenService.bind_issuer` hands out exactly once, to the
:class:`~xdr_response.approval.ApprovalEngine` (which authenticates the approvers and audits the
decision first). Any other caller, holding the service or not, cannot mint a token from a
fabricated decision or principal.

Decisions are final per package (state kept in the token-use ledger, so it is durable and shared
by every worker on the same ledger): a package gets at most one live approval, a REJECT or
REQUEST_MORE_INVESTIGATION revokes the package (every token issued for it stops verifying), and a
revoked package can never be approved again. Closing an incident revokes its unexecuted packages. :meth:`ApprovalTokenService.sign` is a low-level signer without
policy checks; tokens it signs from fabricated claims carry no valid proof and are refused by
:meth:`verify` and :meth:`verify_package`. Tokens issued for a dry-run package carry
``dry_run=True`` and are refused for every live action.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import uuid
from collections.abc import Callable, Sequence
from datetime import timedelta

from xdr_response.approval._quorum import duplicate_principals, non_human_principals, quorum_failure
from xdr_response.clock import Clock, SystemClock
from xdr_response.config import ApprovalSettings
from xdr_response.errors import (
    ApproverNotAllowedError,
    ConfigError,
    DecisionError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMismatchError,
    TokenReplayError,
)
from xdr_response.interfaces import SecretProvider, TokenUseLedger
from xdr_response.models import (
    TOKEN_ISSUANCE_CONTEXT,
    TOKEN_SIGNING_CONTEXT,
    ActionBinding,
    ActionPackage,
    AnalystDecision,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    AuthenticatedPrincipal,
    DecisionType,
    RecommendedAction,
    TokenActionGrant,
    canonical_json,
    evidence_snapshot_hash,
    sha256_hex,
)

__all__ = [
    "ApprovalTokenService",
    "TokenIssuer",
    "TokenVerifierView",
    "claims_hash",
    "SIGNING_KEY_NAME",
    "PREVIOUS_SIGNING_KEY_NAME",
    "MIN_SIGNING_KEY_BYTES",
    "TOKEN_ALG",
]

SIGNING_KEY_NAME = "APPROVAL_SIGNING_KEY"
PREVIOUS_SIGNING_KEY_NAME = "APPROVAL_SIGNING_KEY_PREVIOUS"
MIN_SIGNING_KEY_BYTES = 32
TOKEN_ALG = "HMAC-SHA256"
_APPROVING = frozenset({DecisionType.APPROVE_ALL, DecisionType.APPROVE_SELECTED})
#: Ledger markers (token_id column) for package decision state; the key column is _MARK_KEY.
_APPROVED_MARK = "package-approved:"
_REVOKED_MARK = "package-revoked:"
_MARK_KEY = "decision"


class TokenIssuer:
    """The minting capability of one :class:`ApprovalTokenService` (handed out once, to the engine)."""

    __slots__ = ("_service",)

    def __init__(self, service: "ApprovalTokenService") -> None:
        self._service = service

    def issue(self, package: ActionPackage, decision: AnalystDecision,
              approvers: Sequence[AuthenticatedPrincipal]) -> ApprovalToken:
        return self._service.issue(package, decision, approvers, issuer=self)

    def __repr__(self) -> str:
        return "TokenIssuer()"


def claims_hash(claims: ApprovalTokenClaims) -> str:
    """``sha256_hex(canonical_json(claims))``: identifies a token in the audit trail without the signature."""
    return sha256_hex(canonical_json(claims))


def _load_key(secrets: SecretProvider, name: str, *, required: bool) -> bytes | None:
    secret = secrets.get(name) if required else secrets.get_optional(name)
    if secret is None:
        return None
    key = secret.reveal().encode("utf-8")
    if len(key) < MIN_SIGNING_KEY_BYTES:
        raise ConfigError(f"{name} must be at least {MIN_SIGNING_KEY_BYTES} bytes")
    return key


def _grant_for(action: RecommendedAction) -> TokenActionGrant:
    return TokenActionGrant(
        idempotency_key=action.idempotency_key, action_type=action.action_type, target=action.target,
        params_hash=action.params_hash, approval_level=action.approval_level,
    )


def _grant_matches_binding(grant: TokenActionGrant, binding: ActionBinding) -> bool:
    return (grant.action_type == binding.action_type and grant.target == binding.target
            and hmac.compare_digest(grant.params_hash, binding.params_hash))


class ApprovalTokenService:
    """Issues, verifies and consumes approval tokens. Implements ``TokenVerifier``.

    ``previous_key_id`` names the key id that tokens signed with ``APPROVAL_SIGNING_KEY_PREVIOUS``
    carry after a rotation that also changed the key id; tokens carrying the current
    ``signing_key_id`` are checked against the current key, then the previous key.
    """

    def __init__(self, secrets: SecretProvider, settings: ApprovalSettings, *,
                 ledger: TokenUseLedger, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None,
                 previous_key_id: str | None = None) -> None:
        self._settings = settings
        self._ledger = ledger
        self._clock = clock or SystemClock()
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self._key_id = settings.signing_key_id
        self._keys = self._load_keys(secrets, previous_key_id or settings.previous_signing_key_id)
        self._issuer: TokenIssuer | None = None
        self._issuer_lock = threading.Lock()

    def _load_keys(self, secrets: SecretProvider, previous_key_id: str | None) -> dict[str, tuple[bytes, ...]]:
        current = _load_key(secrets, SIGNING_KEY_NAME, required=True)
        if current is None:  # pragma: no cover - SecretProvider.get raises SecretNotFoundError instead
            raise ConfigError(f"{SIGNING_KEY_NAME} is required")
        previous = _load_key(secrets, PREVIOUS_SIGNING_KEY_NAME, required=False)
        keys: dict[str, tuple[bytes, ...]] = {self._key_id: (current,) + ((previous,) if previous else ())}
        if previous_key_id and previous_key_id != self._key_id:
            if previous is None:
                raise ConfigError(f"previous_key_id is set but {PREVIOUS_SIGNING_KEY_NAME} is missing")
            keys[previous_key_id] = (previous,)
        return keys

    @property
    def settings(self) -> ApprovalSettings:
        """Approval settings used for TTLs and quorum rules."""
        return self._settings

    def __repr__(self) -> str:
        return f"ApprovalTokenService(key_id={self._key_id!r})"

    # ------------------------------------------------------------------ signing --
    @staticmethod
    def _mac(key: bytes, claims: ApprovalTokenClaims) -> str:
        return hmac.new(key, TOKEN_SIGNING_CONTEXT + canonical_json(claims), hashlib.sha256).hexdigest()

    def ttl(self, purpose: ApprovalPurpose) -> timedelta:
        """Maximum token lifetime for ``purpose``."""
        if ApprovalPurpose(purpose) is ApprovalPurpose.RELEASE:
            return timedelta(minutes=self._settings.release_token_ttl_minutes)
        return timedelta(minutes=self._settings.containment_token_ttl_minutes)

    @staticmethod
    def _proof(key: bytes, claims: ApprovalTokenClaims) -> str:
        body = claims.model_dump(mode="json", exclude={"issued_at", "issuance_proof"})
        return hmac.new(key, TOKEN_ISSUANCE_CONTEXT + canonical_json(body), hashlib.sha256).hexdigest()

    def sign(self, claims: ApprovalTokenClaims) -> ApprovalToken:
        """Sign ``claims`` with the current key. Performs no policy checks; prefer :meth:`issue`.

        A token signed here verifies only if its claims carry the ``issuance_proof`` that
        :meth:`issue` adds; fabricated claims are refused by every verification path.
        """
        signature = self._mac(self._keys[self._key_id][0], claims)
        return ApprovalToken(claims=claims, key_id=self._key_id, alg=TOKEN_ALG, signature=signature)

    # ---------------------------------------------------------- issuing capability --
    def bind_issuer(self) -> TokenIssuer:
        """Hand out the minting capability. Works exactly once (the runtime's ApprovalEngine)."""
        with self._issuer_lock:
            if self._issuer is not None:
                raise DecisionError("token issuance is already bound to an ApprovalEngine; "
                                    "no other component can mint approval tokens")
            self._issuer = TokenIssuer(self)
            return self._issuer

    # ------------------------------------------------------------ decision state --
    def _marked(self, mark: str, package_id: str) -> bool:
        try:
            return bool(self._ledger.is_consumed(mark + package_id, _MARK_KEY))
        except AttributeError:  # pragma: no cover - ledger without is_consumed: fail closed for revocation
            return mark == _REVOKED_MARK

    def is_revoked(self, package_id: str) -> bool:
        """True when a REJECT / REQUEST_MORE_INVESTIGATION / close voided every approval of the package."""
        return self._marked(_REVOKED_MARK, package_id)

    def revoke_package(self, package_id: str) -> None:
        """Void every token issued for ``package_id`` (idempotent, durable in the ledger)."""
        try:
            self._ledger.consume(_REVOKED_MARK + package_id, _MARK_KEY)
        except TokenReplayError:
            pass  # already revoked

    def claim_approval(self, package_id: str) -> None:
        """Record the single live approval of a package. Refused after a revocation or a first approval."""
        if self.is_revoked(package_id):
            raise DecisionError("the package was rejected (or its approval voided); "
                                "the decision is final and it can no longer be approved")
        try:
            self._ledger.consume(_APPROVED_MARK + package_id, _MARK_KEY)
        except TokenReplayError:
            raise DecisionError("the package already has a recorded approval; "
                                "a package is approved and executed once") from None
        if self.is_revoked(package_id):  # a concurrent revocation won the race
            raise DecisionError("the package was rejected while it was being approved")

    # ------------------------------------------------------------------ issuing --
    def issue(self, package: ActionPackage, decision: AnalystDecision,
              approvers: Sequence[AuthenticatedPrincipal], *, issuer: TokenIssuer | None = None) -> ApprovalToken:
        """Issue a token granting exactly ``decision.approved_action_keys`` of ``package``.

        Requires the :class:`TokenIssuer` capability (bound once to the ApprovalEngine): a caller
        without it cannot mint a token, whatever decision or principal it fabricates. Re-checks
        that the decision belongs to the package, the evidence hash, that every approver is a
        distinct HUMAN, and the quorum and role rules for every granted approval level.
        """
        if issuer is None or issuer is not self._issuer:
            raise DecisionError("approval tokens are only issued by the ApprovalEngine for an "
                                "authenticated, audited human decision")
        if self.is_revoked(package.package_id):
            raise DecisionError("the package was rejected (or its approval voided); no token is issued")
        self._check_decision(package, decision)
        approvers = tuple(approvers)
        actions = [package.action(key) for key in decision.approved_action_keys]
        self._check_issue_approvers(package, decision, approvers, {a.approval_level for a in actions})
        now = self._clock.now()
        claims = ApprovalTokenClaims(
            token_id=decision.token_id or self._id_factory(),
            purpose=package.purpose, package_id=package.package_id, incident_id=package.incident_id,
            evidence_snapshot_hash=package.evidence_snapshot_hash, workflow_id=package.workflow_id,
            workflow_version=package.workflow_version, decision_id=decision.decision_id,
            actions=tuple(_grant_for(a) for a in actions),
            approvers=tuple(ApproverClaim(principal_id=a.principal_id, kind=a.kind, roles=tuple(a.roles))
                            for a in approvers),
            issued_at=now, expires_at=now + self.ttl(package.purpose), dry_run=bool(package.dry_run),
        )
        claims = claims.model_copy(update={"issuance_proof": self._proof(self._keys[self._key_id][0], claims)})
        return self.sign(claims)

    @staticmethod
    def _check_decision(package: ActionPackage, decision: AnalystDecision) -> None:
        if decision.decision not in _APPROVING:
            raise DecisionError(f"{decision.decision.value} does not issue an approval token")
        if (decision.package_id, decision.incident_id, decision.purpose) != (
                package.package_id, package.incident_id, package.purpose):
            raise DecisionError("decision does not belong to this package")
        if (decision.workflow_id, decision.workflow_version) != (package.workflow_id, package.workflow_version):
            raise DecisionError("decision workflow does not match the package")
        recomputed = evidence_snapshot_hash(package.evidence)
        if recomputed != package.evidence_snapshot_hash or decision.evidence_snapshot_hash != recomputed:
            raise DecisionError("evidence snapshot hash mismatch: the package changed after review")
        if not decision.approved_action_keys:
            raise DecisionError("an approval must approve at least one action")
        unknown = [k for k in decision.approved_action_keys if k not in package.keys]
        if unknown:
            raise DecisionError(f"approved keys not in package: {unknown}")

    def _check_issue_approvers(self, package: ActionPackage, decision: AnalystDecision,
                               approvers: tuple[AuthenticatedPrincipal, ...],
                               levels: set[ApprovalLevel]) -> None:
        if not approvers:
            raise ApproverNotAllowedError("an approval token needs at least one approver")
        if [a.principal_id for a in approvers] != [a.principal_id for a in decision.approvers]:
            raise DecisionError("approvers do not match the recorded decision")
        bad = non_human_principals(approvers)
        if bad:
            raise ApproverNotAllowedError(f"only HUMAN principals may approve; refused: {bad}")
        if duplicate_principals(approvers):
            raise ApproverNotAllowedError("approvers must be distinct principals")
        excluded = () if self._settings.allow_self_approval else (package.requested_by,)
        for level in sorted(levels):
            reason = quorum_failure(approvers, level, self._settings, excluded=excluded)
            if reason:
                raise ApproverNotAllowedError(reason)

    # ------------------------------------------------------------- verification --
    def _authentic_claims(self, token: ApprovalToken) -> ApprovalTokenClaims:
        """Steps 1-2: algorithm, key id and signature (constant-time compare)."""
        if not isinstance(token, ApprovalToken):
            raise TokenInvalidError("an ApprovalToken is required")
        if token.alg != TOKEN_ALG:
            raise TokenInvalidError("unsupported token algorithm")
        keys = self._keys.get(token.key_id)
        if not keys:
            raise TokenInvalidError("unknown token key id")
        try:
            expected = [self._mac(key, token.claims) for key in keys]
        except (ValueError, TypeError) as exc:
            raise TokenInvalidError("token claims are not canonicalizable") from exc
        signature = token.signature if isinstance(token.signature, str) else ""
        matched = False
        for candidate in expected:  # evaluate every key: no early exit
            matched |= hmac.compare_digest(candidate.encode("ascii"), signature.encode("utf-8"))
        if not matched:
            raise TokenInvalidError("approval token signature is invalid")
        return token.claims

    def _check_time(self, claims: ApprovalTokenClaims) -> None:
        """Step 3: not issued in the future (beyond skew), not expired, lifetime within the TTL."""
        now = self._clock.now()
        if claims.issued_at > now + timedelta(seconds=self._settings.clock_skew_seconds):
            raise TokenExpiredError("approval token is not valid yet (issued in the future)")
        if now >= claims.expires_at:
            raise TokenExpiredError("approval token has expired")
        if claims.expires_at - claims.issued_at > self.ttl(claims.purpose):
            raise TokenExpiredError("approval token lifetime exceeds the configured TTL")

    def _check_approvers(self, claims: ApprovalTokenClaims, levels: set[ApprovalLevel]) -> None:
        """Step 7: non-empty, distinct, HUMAN-only approvers that satisfy every granted level."""
        approvers = claims.approvers
        if not approvers:
            raise TokenInvalidError("approval token names no approver")
        if duplicate_principals(approvers):
            raise TokenInvalidError("approval token names duplicate approvers")
        if non_human_principals(approvers):
            raise TokenInvalidError("approval token names a non-human approver")
        for level in sorted(levels):
            reason = quorum_failure(approvers, level, self._settings)
            if reason:
                raise TokenInvalidError(f"approval token approvers are insufficient: {reason}")

    def _verified_claims(self, token: ApprovalToken, purpose: ApprovalPurpose) -> ApprovalTokenClaims:
        claims = self._authentic_claims(token)
        self._check_time(claims)
        if self.is_revoked(claims.package_id):
            raise TokenInvalidError("approval was voided: the package was rejected after this token "
                                    "was issued, or its incident was closed")
        if claims.purpose != ApprovalPurpose(purpose):
            raise TokenMismatchError(
                f"token purpose {claims.purpose.value} does not authorize a {ApprovalPurpose(purpose).value} action"
            )
        return claims

    def _check_issued(self, token: ApprovalToken, claims: ApprovalTokenClaims) -> None:
        """Steps 8-9: the token was issued for a live decision by :meth:`issue` (issuance proof)."""
        if claims.dry_run:
            raise TokenInvalidError("approval token was issued for a dry-run approval; it can never "
                                    "authorize a live action")
        proof = claims.issuance_proof if isinstance(claims.issuance_proof, str) else ""
        matched = False
        for key in self._keys.get(token.key_id, ()):  # evaluate every key: no early exit
            matched |= hmac.compare_digest(self._proof(key, claims).encode("ascii"), proof.encode("utf-8"))
        if not matched:
            raise TokenInvalidError("approval token was not issued through a recorded approval decision "
                                    "(missing or invalid issuance proof)")

    def verify(self, token: ApprovalToken, *, purpose: ApprovalPurpose,
               binding: ActionBinding) -> TokenActionGrant:
        """Verify ``token`` for exactly the action in ``binding`` (section 5.6 steps 1-7).

        ``purpose`` must come from the action catalog, never from caller input. Does not consume
        the token; the guard calls :meth:`mark_used` once per action.
        """
        if not isinstance(binding, ActionBinding):
            raise TokenMismatchError("an ActionBinding is required")
        claims = self._verified_claims(token, purpose)
        if claims.incident_id != binding.incident_id:
            raise TokenMismatchError("approval token was issued for a different incident")
        grant = claims.grant(binding.idempotency_key)
        if grant is None:
            raise TokenMismatchError("approval token does not grant this action")
        if not _grant_matches_binding(grant, binding):
            raise TokenMismatchError("approval token grant does not match the action type, target or parameters")
        self._check_approvers(claims, {grant.approval_level})
        self._check_issued(token, claims)
        return grant

    def verify_token(self, token: ApprovalToken, *, purpose: ApprovalPurpose) -> ApprovalTokenClaims:
        """Verify ``token`` as a whole, without an action or package binding.

        Signature, key id, time window and TTL, purpose, HUMAN-only distinct approvers satisfying
        every granted level, not a dry-run approval, and the issuance proof. Used by the incident
        state machine before it records an approval (``APPROVED`` / ``RESTORATION_RUNNING``).
        """
        claims = self._verified_claims(token, purpose)
        self._check_approvers(claims, {g.approval_level for g in claims.actions})
        self._check_issued(token, claims)
        return claims

    def verify_package(self, token: ApprovalToken, package: ActionPackage) -> None:
        """Verify ``token`` against a whole package before execution starts.

        Checks signature, time, purpose, incident, package id, workflow, the evidence snapshot hash
        recomputed from the package evidence, and that every grant matches the package action with
        the same key (type, target, params hash, approval level).
        """
        claims = self._verified_claims(token, package.purpose)
        if claims.incident_id != package.incident_id:
            raise TokenMismatchError("approval token was issued for a different incident")
        if claims.package_id != package.package_id:
            raise TokenMismatchError("approval token was issued for a different package")
        if (claims.workflow_id, claims.workflow_version) != (package.workflow_id, package.workflow_version):
            raise TokenMismatchError("approval token was issued for a different workflow version")
        recomputed = evidence_snapshot_hash(package.evidence)
        if recomputed != package.evidence_snapshot_hash or claims.evidence_snapshot_hash != recomputed:
            raise TokenMismatchError("evidence snapshot hash mismatch: the package changed after approval")
        if claims.dry_run != bool(package.dry_run):
            raise TokenMismatchError("approval token dry-run flag does not match the package")
        for grant in claims.actions:
            self._check_grant_in_package(grant, package)
        self._check_approvers(claims, {g.approval_level for g in claims.actions})
        self._check_issued(token, claims)

    @staticmethod
    def _check_grant_in_package(grant: TokenActionGrant, package: ActionPackage) -> None:
        try:
            action = package.action(grant.idempotency_key)
        except KeyError:
            raise TokenMismatchError(f"granted action {grant.idempotency_key} is not in the package") from None
        if _grant_for(action) != grant:
            raise TokenMismatchError(f"granted action {grant.idempotency_key} does not match the package action")

    def mark_used(self, token: ApprovalToken, idempotency_key: str) -> None:
        """Consume the single use of ``(token_id, idempotency_key)``; a second use raises TokenReplayError."""
        if not isinstance(token, ApprovalToken) or token.claims.grant(idempotency_key) is None:
            raise TokenMismatchError("approval token does not grant this action")
        if token.token_id.startswith((_APPROVED_MARK, _REVOKED_MARK)):
            raise TokenInvalidError("invalid token id")
        self._ledger.consume(token.token_id, idempotency_key)

    def was_used(self, token_id: str, idempotency_key: str) -> bool:
        """True when the guard consumed ``(token_id, idempotency_key)``: an authorized write happened."""
        if not token_id or not idempotency_key or token_id.startswith((_APPROVED_MARK, _REVOKED_MARK)):
            return False
        return bool(self._ledger.is_consumed(token_id, idempotency_key))

    def view(self) -> "TokenVerifierView":
        """Verify-only facade for automation components (executor, restoration, state machine)."""
        return TokenVerifierView(self)


class TokenVerifierView:
    """Verify-only facade of an :class:`ApprovalTokenService`: it can check and consume tokens but
    never issue, sign or revoke them. Automation components receive this, not the service."""

    __slots__ = ("_service",)

    def __init__(self, service: ApprovalTokenService) -> None:
        self._service = service

    @property
    def settings(self) -> ApprovalSettings:
        return self._service.settings

    def ttl(self, purpose: ApprovalPurpose) -> timedelta:
        return self._service.ttl(purpose)

    def verify(self, token: ApprovalToken, *, purpose: ApprovalPurpose, binding: ActionBinding) -> TokenActionGrant:
        return self._service.verify(token, purpose=purpose, binding=binding)

    def verify_token(self, token: ApprovalToken, *, purpose: ApprovalPurpose) -> ApprovalTokenClaims:
        return self._service.verify_token(token, purpose=purpose)

    def verify_package(self, token: ApprovalToken, package: ActionPackage) -> None:
        self._service.verify_package(token, package)

    def mark_used(self, token: ApprovalToken, idempotency_key: str) -> None:
        self._service.mark_used(token, idempotency_key)

    def is_revoked(self, package_id: str) -> bool:
        return self._service.is_revoked(package_id)

    def was_used(self, token_id: str, idempotency_key: str) -> bool:
        return self._service.was_used(token_id, idempotency_key)

    def __repr__(self) -> str:
        return "TokenVerifierView()"
