"""Incident state machine (architecture section 13.9).

Every state change goes through :meth:`IncidentStateMachine.transition`, which is deterministic code:

* the move must be in :data:`~xdr_response.models.states.ALLOWED_TRANSITIONS`
  (:class:`InvalidTransitionError` otherwise);
* entering a state listed in :data:`~xdr_response.models.states.TOKEN_REQUIRED` (``APPROVED`` and
  ``RESTORATION_RUNNING``) needs an approval token of the matching purpose that names this incident
  and the given package, and the transition actor must be one of the token's (human) approvers;
* with a token verifier (the runtime always injects the approval token service) the token is also
  verified before the approval is recorded: signature, expiry and TTL, HUMAN approvers and roles,
  not a dry-run approval, and the issuance proof, so a forged, expired or minted token can never
  produce an ``APPROVED`` / ``RESTORATION_RUNNING`` history entry. Without an injected verifier
  the machine uses the verifier registered with the execution guard, if any;
* a token or package that already entered that state for this incident can never enter it again
  (single use of the recorded approval, independent of the token-use ledger);
* outcome states are evidence-gated: ``CONTAINED`` / ``PARTIALLY_CONTAINED`` / ``RESTORED``
  (:data:`~xdr_response.models.states.REPORT_REQUIRED`) need the live execution report of the
  package that was approved and started for this incident, whose overall result is exactly that
  state, recorded by ``automation:verification``; an AI actor can never record any outcome state
  (including ``CONTAINMENT_FAILED``). "CONTAINED only when executed and verified" is enforced here,
  not only by the orchestrator's call order;
* the transition is audited (``STATE_TRANSITION``) **before** it is saved: if the audit write fails
  the incident keeps its previous state.

History is append-only: each transition adds a :class:`StateTransition`; nothing is ever removed.
"""
from __future__ import annotations

import threading

from typing import Any

from xdr_response import guard
from xdr_response.audit.events import AuditRecorder
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import (
    ApprovalRequiredError,
    InvalidTransitionError,
    TokenInvalidError,
    TokenMismatchError,
    TokenReplayError,
)
from xdr_response.interfaces import AuditSink, IncidentStore
from xdr_response.models import (
    OUTCOME_ACTOR,
    OUTCOME_STATES,
    REPORT_REQUIRED,
    TOKEN_REQUIRED,
    ApprovalToken,
    ContainmentReport,
    Incident,
    IncidentState,
    RestorationReport,
    StateTransition,
    can_transition,
)

__all__ = ["IncidentStateMachine", "LIFECYCLE_ACTOR"]

#: Actor recorded for transitions the automation performs on its own.
LIFECYCLE_ACTOR = "automation:lifecycle"


class IncidentStateMachine:
    """Applies allowed, audited transitions to incidents held in an :class:`IncidentStore`."""

    def __init__(self, store: IncidentStore, audit: AuditSink, clock: Clock | None = None, *,
                 tokens: Any = None) -> None:
        self._store = store
        self._audit = AuditRecorder(audit, actor=LIFECYCLE_ACTOR)
        self._clock: Clock = clock or DEFAULT_CLOCK
        self._lock = threading.RLock()
        self._tokens = tokens  # object with verify_token(token, *, purpose) (ApprovalTokenService)

    @property
    def store(self) -> IncidentStore:
        return self._store

    def transition(self, incident_id: str, to_state: IncidentState, *, actor: str, reason: str = "",
                   package_id: str | None = None, token: ApprovalToken | None = None,
                   report: ContainmentReport | RestorationReport | None = None) -> Incident:
        """Move ``incident_id`` to ``to_state`` (see module docstring for the checks)."""
        to_state = IncidentState(to_state)
        if not actor:
            raise ValueError("actor is required")
        with self._lock:
            incident = self._store.get(incident_id)
            from_state = incident.state
            if not can_transition(from_state, to_state):
                raise InvalidTransitionError(from_state, to_state, reason)
            self._check_token(incident, to_state, actor=actor, package_id=package_id, token=token)
            self._check_outcome(incident, to_state, actor=actor, package_id=package_id, report=report)
            transition = StateTransition(
                from_state=from_state, to_state=to_state, at=self._clock.now(), actor=actor,
                reason=reason, package_id=package_id,
                token_id=token.token_id if isinstance(token, ApprovalToken) else None,
            )
            updated = Incident.model_validate({
                **incident.model_dump(),
                "state": to_state,
                "history": (*incident.history, transition),
            })
            self._audit.state_transition(incident_id, transition)  # AuditError -> nothing saved
            self._store.save(updated)
            return updated

    def _check_token(self, incident: Incident, to_state: IncidentState, *, actor: str, package_id: str | None,
                     token: ApprovalToken | None) -> None:
        self._check_binding(incident, to_state, actor=actor, package_id=package_id, token=token)
        purpose = TOKEN_REQUIRED.get(to_state)
        if purpose is None or token is None:
            return
        for earlier in incident.history:
            if earlier.to_state is to_state and (earlier.token_id == token.token_id
                                                 or earlier.package_id == package_id):
                raise TokenReplayError(
                    f"{to_state.value} was already entered with this approval token or package; "
                    "a recorded approval can never be used twice")
        verifier = self._tokens if self._tokens is not None else guard.get_verifier()
        verify_token = getattr(verifier, "verify_token", None)
        if not callable(verify_token):
            return
        try:
            verify_token(token, purpose=purpose)
        except ApprovalRequiredError:
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected verifier failure: fail closed
            raise TokenInvalidError(f"approval token verification error: {type(exc).__name__}") from exc

    @staticmethod
    def _check_outcome(incident: Incident, to_state: IncidentState, *, actor: str, package_id: str | None,
                       report: ContainmentReport | RestorationReport | None) -> None:
        """Outcome states need the executed, verified run behind them (see module docstring)."""
        if to_state in OUTCOME_STATES and actor.strip().lower().startswith("ai:"):
            raise ApprovalRequiredError(f"an AI actor can never record {to_state.value}")
        kind = REPORT_REQUIRED.get(to_state)
        if kind is None:
            return
        if actor != OUTCOME_ACTOR:
            raise ApprovalRequiredError(f"{to_state.value} is recorded only by {OUTCOME_ACTOR} from an "
                                        f"execution report, not by {actor!r}")
        expected = ContainmentReport if kind == "containment" else RestorationReport
        if not isinstance(report, expected):
            raise ApprovalRequiredError(f"{to_state.value} needs the {kind} execution report of the run")
        if report.dry_run or report.overall is None or report.overall.value != to_state.value:
            raise ApprovalRequiredError(f"the {kind} report does not show {to_state.value} "
                                        f"(overall {getattr(report.overall, 'value', None)})")
        if report.incident_id != incident.incident_id or package_id is None or report.package_id != package_id:
            raise ApprovalRequiredError(f"the {kind} report belongs to another incident or package")
        started = IncidentState.CONTAINMENT_RUNNING if kind == "containment" else IncidentState.RESTORATION_RUNNING
        if not any(t.to_state is started and t.package_id == package_id for t in incident.history):
            raise ApprovalRequiredError(f"package {package_id} never entered {started.value} for this incident")
        if not report.token_id:
            raise ApprovalRequiredError(f"the {kind} report names no approval token")

    @staticmethod
    def _check_binding(incident: Incident, to_state: IncidentState, *, actor: str, package_id: str | None,
                       token: ApprovalToken | None) -> None:
        purpose = TOKEN_REQUIRED.get(to_state)
        if token is not None and not isinstance(token, ApprovalToken):
            raise ApprovalRequiredError("token must be an ApprovalToken")
        if purpose is None:
            if token is not None and token.claims.incident_id != incident.incident_id:
                raise TokenMismatchError("approval token names a different incident")
            return
        if token is None:
            raise ApprovalRequiredError(
                f"{to_state.value} requires a human {purpose.value} approval token")
        claims = token.claims
        if claims.purpose is not purpose:
            raise TokenMismatchError(f"{to_state.value} needs a {purpose.value} token, got {claims.purpose.value}")
        if claims.incident_id != incident.incident_id:
            raise TokenMismatchError("approval token names a different incident")
        if package_id is None or claims.package_id != package_id:
            raise TokenMismatchError("approval token does not bind the package of this transition")
        if actor not in {a.principal_id for a in claims.approvers}:
            raise TokenMismatchError(f"{to_state.value} must be entered by an approver named in the token")
