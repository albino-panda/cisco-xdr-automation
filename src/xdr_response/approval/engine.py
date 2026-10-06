"""Approval engine: turns an analyst decision on a package into an audited decision and, for
approvals, a signed approval token (architecture sections 5.3 and 5.4).

Order of ``decide`` (deterministic, fail closed):

1. the request names this package, the package has not expired, and its evidence snapshot hash
   recomputes to the stored value (``DecisionError``);
2. every credential is authenticated through the pluggable ``ApproverAuthenticator``
   (``AuthenticationError``); any non-HUMAN principal is refused (``ApproverNotAllowedError``);
3. decision semantics (``DecisionError``), then the approval level the policy requires (a package
   that marks an action on a critical asset, an ``always_elevated`` type or an action above the
   blast-radius caps as ``STANDARD`` is refused: ``ELEVATED`` is enforced here, at decision time,
   not only by the package builder), then roles and quorum (``ApproverNotAllowedError``);
4. decisions are final: a package that was rejected (or whose approval was voided) can never be
   approved, and a package is approved live only once (``DecisionError``);
5. the ``AnalystDecision`` is written to the audit trail (``AuditError`` means no token);
6. REJECT / REQUEST_MORE_INVESTIGATION revoke the package: tokens issued for it earlier stop
   verifying everywhere (executor, restoration, guard);
7. approvals only: the token is issued through the engine's one-time :class:`TokenIssuer`
   capability and ``TOKEN_ISSUED`` audited before it is returned. Nobody else can mint tokens.

Every refusal is audited as ``APPROVAL_DENIED`` before it is raised.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from xdr_response.approval._quorum import has_any_approver_role, non_human_principals, quorum_failure
from xdr_response.approval.tokens import ApprovalTokenService, claims_hash
from xdr_response.clock import Clock, SystemClock
from xdr_response.config import ApprovalSettings
from xdr_response.errors import (
    ApprovalError,
    ApproverNotAllowedError,
    AuditError,
    AuthenticationError,
    DecisionError,
)
from xdr_response.interfaces import ApproverAuthenticator, AuditSink
from xdr_response.logs.setup import get_logger
from xdr_response.models import (
    ActionPackage,
    AnalystDecision,
    ApprovalLevel,
    ApprovalOutcome,
    ApprovalToken,
    ApproverCredential,
    AuditEventType,
    AuthenticatedPrincipal,
    CriticalAssetWarning,
    DecisionRequest,
    DecisionType,
    evidence_snapshot_hash,
    format_datetime,
)

__all__ = ["ApprovalEngine", "ENGINE_ACTOR"]

ENGINE_ACTOR = "automation:approval_engine"
_APPROVING = frozenset({DecisionType.APPROVE_ALL, DecisionType.APPROVE_SELECTED})
_COMMENT_REQUIRED = frozenset({DecisionType.REJECT, DecisionType.REQUEST_MORE_INVESTIGATION})
_log = get_logger("approval.engine")


class ApprovalEngine:
    """Records analyst decisions and issues approval tokens. Only authenticated humans approve."""

    def __init__(self, settings: ApprovalSettings, *, authenticator: ApproverAuthenticator,
                 tokens: ApprovalTokenService, audit: AuditSink, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None,
                 level_policy: Callable[[ActionPackage], Sequence[str]] | None = None) -> None:
        self._settings = settings
        self._authenticator = authenticator
        self._tokens = tokens
        self._issuer = tokens.bind_issuer()  # one-time minting capability (refused if already bound)
        #: Returns the policy violations of a package (actions marked below the level they require).
        self._level_policy = level_policy
        self._audit = audit
        self._clock = clock or SystemClock()
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)

    def decide(self, package: ActionPackage, request: DecisionRequest,
               credentials: Sequence[ApproverCredential]) -> ApprovalOutcome:
        """Validate, audit and (for approvals) issue a token for ``request`` on ``package``."""
        if not isinstance(package, ActionPackage) or not isinstance(request, DecisionRequest):
            raise TypeError("decide() needs an ActionPackage and a DecisionRequest")
        approvers: list[AuthenticatedPrincipal] = []
        try:
            self._check_package(package, request)
            approvers.extend(self._authenticate(credentials))
            self._check_principals(approvers)
            approved, rejected = self._resolve_keys(package, request)
            self._check_policy_level(package, request.decision)
            self._check_authority(package, request.decision, approvers, approved)
            self._check_final(package, request.decision)
        except ApprovalError as exc:
            self._audit_denial(package, request, approvers, credentials, exc)
            raise
        decision = self._record(package, request, approvers, approved, rejected)
        if decision.decision not in _APPROVING:
            self._tokens.revoke_package(package.package_id)  # earlier approvals of this package die
            return ApprovalOutcome(decision=decision, token=None)
        token = self._issue(package, decision, approvers)
        return ApprovalOutcome(decision=decision, token=token, warnings=self._warnings(package, approved))

    # --------------------------------------------------------------- step 1 --
    def _check_package(self, package: ActionPackage, request: DecisionRequest) -> None:
        if request.package_id != package.package_id:
            raise DecisionError("decision request names a different package")
        if self._clock.now() >= package.expires_at:
            raise DecisionError("package has expired; a new package must be built")
        if evidence_snapshot_hash(package.evidence) != package.evidence_snapshot_hash:
            raise DecisionError("evidence snapshot hash mismatch: the package was modified")

    # --------------------------------------------------------------- step 2 --
    def _authenticate(self, credentials: Sequence[ApproverCredential]) -> list[AuthenticatedPrincipal]:
        if not credentials:
            raise ApproverNotAllowedError("at least one approver credential is required")
        principals: dict[str, AuthenticatedPrincipal] = {}
        for credential in credentials:
            principal = self._authenticate_one(credential)
            principals.setdefault(principal.principal_id, principal)  # distinct approvers only
        return list(principals.values())

    def _authenticate_one(self, credential: ApproverCredential) -> AuthenticatedPrincipal:
        if not isinstance(credential, ApproverCredential):
            raise AuthenticationError("approver credential is required")
        try:
            principal = self._authenticator.authenticate(credential)
        except AuthenticationError:
            raise
        except Exception as exc:  # noqa: BLE001 - an authenticator fault never authenticates anyone
            raise AuthenticationError(f"approver authentication error: {type(exc).__name__}") from exc
        if not isinstance(principal, AuthenticatedPrincipal) or principal.principal_id != credential.principal_id:
            raise AuthenticationError("authenticator returned a principal that does not match the credential")
        return principal

    def _check_principals(self, approvers: Sequence[AuthenticatedPrincipal]) -> None:
        refused = non_human_principals(approvers)
        if refused:
            raise ApproverNotAllowedError(
                f"only HUMAN principals may decide on containment or release; refused: {refused}")
        missing = [a.principal_id for a in approvers if not has_any_approver_role(a, self._settings)]
        if missing:
            raise ApproverNotAllowedError(f"principals without an approver role: {missing}")

    # --------------------------------------------------------------- step 3 --
    def _resolve_keys(self, package: ActionPackage,
                      request: DecisionRequest) -> tuple[tuple[str, ...], tuple[str, ...]]:
        kind = request.decision
        if kind in _COMMENT_REQUIRED and not request.comment.strip():
            raise DecisionError(f"{kind.value} requires a comment")
        resolver = {
            DecisionType.APPROVE_ALL: self._keys_approve_all,
            DecisionType.APPROVE_SELECTED: self._keys_approve_selected,
            DecisionType.REJECT: self._keys_reject,
            DecisionType.REQUEST_MORE_INVESTIGATION: self._keys_more_investigation,
        }[kind]
        return resolver(package, request)

    @staticmethod
    def _keys_approve_all(package: ActionPackage, request: DecisionRequest) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if request.approved_keys and set(request.approved_keys) != set(package.keys):
            raise DecisionError("APPROVE_ALL approved_keys must be empty or list every package action")
        if request.rejected_keys:
            raise DecisionError("APPROVE_ALL cannot reject actions; use APPROVE_SELECTED")
        return package.keys, ()

    @staticmethod
    def _keys_approve_selected(package: ActionPackage,
                               request: DecisionRequest) -> tuple[tuple[str, ...], tuple[str, ...]]:
        selected = request.approved_keys
        if not selected:
            raise DecisionError("APPROVE_SELECTED needs at least one approved key")
        if len(set(selected)) != len(selected):
            raise DecisionError("APPROVE_SELECTED approved_keys contain duplicates")
        unknown = [k for k in selected if k not in package.keys]
        if unknown:
            raise DecisionError(f"approved keys are not in the package: {unknown}")
        approved = tuple(k for k in package.keys if k in set(selected))
        rejected = tuple(k for k in package.keys if k not in set(selected))
        if request.rejected_keys and (set(request.rejected_keys) != set(rejected)
                                      or len(set(request.rejected_keys)) != len(request.rejected_keys)):
            raise DecisionError("rejected_keys must equal the package actions that are not approved")
        return approved, rejected

    @staticmethod
    def _keys_reject(package: ActionPackage, request: DecisionRequest) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if request.approved_keys:
            raise DecisionError("REJECT cannot approve actions")
        if request.rejected_keys and set(request.rejected_keys) != set(package.keys):
            raise DecisionError("REJECT rejected_keys must be empty or list every package action")
        return (), package.keys

    @staticmethod
    def _keys_more_investigation(package: ActionPackage,
                                 request: DecisionRequest) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if request.approved_keys or request.rejected_keys:
            raise DecisionError("REQUEST_MORE_INVESTIGATION approves and rejects nothing")
        return (), ()

    def _check_policy_level(self, package: ActionPackage, decision: DecisionType) -> None:
        """ELEVATED is enforced at decision time: re-run the level policy on the package."""
        if decision not in _APPROVING or self._level_policy is None:
            return
        try:
            violations = list(self._level_policy(package))
        except Exception as exc:  # noqa: BLE001 - a failing policy never approves anything
            raise DecisionError(f"approval-level policy could not be evaluated: {type(exc).__name__}") from exc
        if violations:
            raise DecisionError("package approval levels are lower than the policy requires (rebuild the "
                                "package): " + "; ".join(violations))

    def _check_final(self, package: ActionPackage, decision: DecisionType) -> None:
        """A rejected package is never approved; a live package is approved once."""
        if decision not in _APPROVING:
            return
        if package.dry_run:
            if self._tokens.is_revoked(package.package_id):
                raise DecisionError("the package was rejected; the decision is final")
            return
        self._tokens.claim_approval(package.package_id)

    def _check_authority(self, package: ActionPackage, decision: DecisionType,
                         approvers: Sequence[AuthenticatedPrincipal], approved: tuple[str, ...]) -> None:
        if decision not in _APPROVING:
            return
        excluded = () if self._settings.allow_self_approval else (package.requested_by,)
        levels = {package.action(k).approval_level for k in approved}
        for level in sorted(levels):
            reason = quorum_failure(approvers, level, self._settings, excluded=excluded)
            if reason is None:
                continue
            if level is ApprovalLevel.ELEVATED:
                elevated = [k for k in approved if package.action(k).approval_level is ApprovalLevel.ELEVATED]
                reason += f"; ELEVATED actions {elevated} must be excluded with APPROVE_SELECTED"
            if package.requested_by in {a.principal_id for a in approvers} and excluded:
                reason += "; the package requester does not count toward the quorum (self-approval)"
            raise ApproverNotAllowedError(reason)

    # ------------------------------------------------------------- steps 4-5 --
    def _record(self, package: ActionPackage, request: DecisionRequest,
                approvers: Sequence[AuthenticatedPrincipal], approved: tuple[str, ...],
                rejected: tuple[str, ...]) -> AnalystDecision:
        decision = AnalystDecision(
            decision_id=self._id_factory(), package_id=package.package_id, incident_id=package.incident_id,
            purpose=package.purpose, decision=request.decision, analyst_identity=approvers[0].principal_id,
            approvers=tuple(approvers), decided_at=self._clock.now(), approved_action_keys=approved,
            rejected_action_keys=rejected, comment=request.comment, workflow_id=package.workflow_id,
            workflow_version=package.workflow_version, evidence_snapshot_hash=package.evidence_snapshot_hash,
            token_id=self._id_factory() if request.decision in _APPROVING else None,
        )
        self._append(AuditEventType.DECISION_RECORDED, package, decision.analyst_identity,
                     decision.model_dump(mode="json"))
        return decision

    def _issue(self, package: ActionPackage, decision: AnalystDecision,
               approvers: Sequence[AuthenticatedPrincipal]) -> ApprovalToken:
        try:
            token = self._issuer.issue(package, decision, approvers)
        except ApprovalError as exc:
            self._audit_denial(package, None, approvers, (), exc)
            raise
        self._append(AuditEventType.TOKEN_ISSUED, package, decision.analyst_identity, {
            "token_id": token.token_id, "purpose": token.claims.purpose.value, "package_id": package.package_id,
            "claims_hash": claims_hash(token.claims), "expires_at": format_datetime(token.claims.expires_at),
        })
        return token

    @staticmethod
    def _warnings(package: ActionPackage, approved: tuple[str, ...]) -> tuple[CriticalAssetWarning, ...]:
        return tuple(w for k in approved for w in package.action(k).warnings)

    # ----------------------------------------------------------------- audit --
    def _append(self, event: AuditEventType, package: ActionPackage, actor: str,
                payload: Mapping[str, Any]) -> None:
        try:
            self._audit.append(event, incident_id=package.incident_id, actor=actor, payload=payload,
                               workflow_id=package.workflow_id, workflow_version=package.workflow_version)
        except AuditError:
            raise
        except Exception as exc:  # noqa: BLE001 - any audit failure means no token
            raise AuditError(f"audit write failed for {event.value}: {type(exc).__name__}") from exc

    def _audit_denial(self, package: ActionPackage, request: DecisionRequest | None,
                      approvers: Sequence[AuthenticatedPrincipal], credentials: Sequence[Any],
                      exc: Exception) -> None:
        payload = {
            "package_id": package.package_id, "purpose": package.purpose.value,
            "decision": request.decision.value if request is not None else None,
            "error": type(exc).__name__, "reason": str(exc),
            "approvers": [a.principal_id for a in approvers],
            "claimed_principals": [getattr(c, "principal_id", None) for c in credentials or ()],
        }
        actor = approvers[0].principal_id if approvers else ENGINE_ACTOR
        try:
            self._append(AuditEventType.APPROVAL_DENIED, package, actor, payload)
        except AuditError:
            # The denial is raised regardless; nothing was approved.
            _log.error("could not audit approval denial for package %s", package.package_id)
