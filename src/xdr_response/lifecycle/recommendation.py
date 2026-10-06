"""Automatic recommendation: investigation results to :class:`ProposedAction` objects.

Phase 0 uses a deterministic, rule-based recommender (the plan-engine bridge and the weighted
scoring engine are Phase 1, see ``xdr_response/scoring/README.md``). The rules:

* Per observable, the verdicts of all sources are combined: the worst verdict wins
  (``MALICIOUS`` > ``SUSPICIOUS`` > ``UNKNOWN`` / ``CLEAN``); a failed source contributes nothing.
* A :class:`PlaybookRule` fires for an observable type when the combined verdict is ``MALICIOUS``,
  or ``SUSPICIOUS`` with a combined risk of at least ``min_risk`` (default 60, the HIGH band).
* ``risk_score`` is the highest risk reported by a source with the combined verdict.
  ``confidence_score`` is the highest confidence of those sources plus 10 per corroborating source
  (capped at 100). Risk and confidence are separate concepts and are never mixed.
* Evidence is every evidence item those sources returned for the observable, plus investigation
  findings about it. A source with a verdict but no evidence item contributes a synthesized
  ``"<integration> rates <value> <verdict>"`` item, so every action has numbered, sourced evidence.
* The executing integration is the first enabled adapter able to run the action type, in the
  catalog's preference order (Cisco XDR native first). Without one, the action is reported as
  unroutable instead of being proposed.

The output only *recommends*. The :class:`~xdr_response.approval.PackageBuilder` then applies
allow-lists, critical-asset elevation and blast-radius rules, and a human must approve the package.
AI text is never evidence and never an input to these rules.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from xdr_response.lifecycle.investigation import InvestigationReport, observable_key
from xdr_response.models import (
    ActionType,
    EnrichmentResult,
    EvidenceDraft,
    Incident,
    Observable,
    ObservableType,
    ProposedAction,
    Verdict,
    get_action_spec,
    normalize_target,
)

__all__ = [
    "PlaybookRule",
    "DEFAULT_PLAYBOOK",
    "Recommendation",
    "UnroutedAction",
    "Recommender",
    "RuleBasedRecommender",
    "combined_verdict",
]

_O = ObservableType
_A = ActionType

_VERDICT_RANK = {Verdict.CLEAN: 0, Verdict.UNKNOWN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}


@dataclass(frozen=True)
class PlaybookRule:
    """Containment actions recommended for a malicious or suspicious observable type."""

    observable_types: frozenset[ObservableType]
    action_types: tuple[ActionType, ...]
    min_risk: int = 60
    suspicious_fires: bool = True

    def fires(self, verdict: Verdict, risk: int) -> bool:
        if verdict is Verdict.MALICIOUS:
            return True
        return self.suspicious_fires and verdict is Verdict.SUSPICIOUS and risk >= self.min_risk


DEFAULT_PLAYBOOK: tuple[PlaybookRule, ...] = (
    PlaybookRule(frozenset({_O.HOSTNAME}), (_A.ISOLATE_ENDPOINT,)),
    PlaybookRule(frozenset({_O.SHA256}), (_A.BLOCK_HASH,)),
    PlaybookRule(frozenset({_O.DOMAIN}), (_A.BLOCK_DOMAIN,)),
    PlaybookRule(frozenset({_O.URL}), (_A.BLOCK_URL,)),
    PlaybookRule(frozenset({_O.IP, _O.IPV6}), (_A.BLOCK_IP,)),
    PlaybookRule(frozenset({_O.USER}), (_A.DISABLE_USER, _A.REVOKE_SESSIONS)),
    PlaybookRule(frozenset({_O.EMAIL_MESSAGE_ID}), (_A.QUARANTINE_EMAIL,)),
)


@dataclass(frozen=True)
class UnroutedAction:
    """An action the rules wanted but no enabled adapter can execute."""

    action_type: ActionType
    target: str
    reason: str


@dataclass(frozen=True)
class Recommendation:
    """Proposed actions plus package-level scores. Empty ``proposals`` means nothing to contain."""

    incident_id: str
    proposals: tuple[ProposedAction, ...]
    risk_score: int
    confidence_score: int
    summary: str
    unrouted: tuple[UnroutedAction, ...] = ()
    notes: tuple[str, ...] = field(default=())

    @property
    def empty(self) -> bool:
        return not self.proposals


@runtime_checkable
class Recommender(Protocol):
    def recommend(self, incident: Incident, investigation: InvestigationReport) -> Recommendation:
        ...


def combined_verdict(results: Sequence[EnrichmentResult]) -> tuple[Verdict, int, int, list[EnrichmentResult]]:
    """(worst verdict, its highest risk, corroborated confidence, the sources reporting it)."""
    usable = [r for r in results if not r.errors or r.verdict is not Verdict.UNKNOWN]
    if not usable:
        return Verdict.UNKNOWN, 0, 0, []
    worst = max(usable, key=lambda r: _VERDICT_RANK[r.verdict]).verdict
    agreeing = [r for r in usable if r.verdict is worst]
    risk = max(r.risk_score for r in agreeing)
    confidence = min(100, max(r.confidence for r in agreeing) + 10 * (len(agreeing) - 1))
    return worst, risk, confidence, agreeing


def _synthesized(result: EnrichmentResult) -> EvidenceDraft:
    return EvidenceDraft(
        source=result.integration,
        summary=f"{result.integration} rates {result.value} {result.verdict.value} "
                f"(risk {result.risk_score}, confidence {result.confidence})",
        data={"verdict": result.verdict.value, "risk_score": result.risk_score,
              "confidence": result.confidence},
    )


class RuleBasedRecommender:
    """Deterministic Phase 0 recommender (see module docstring)."""

    def __init__(self, adapters: object, *, playbook: Sequence[PlaybookRule] = DEFAULT_PLAYBOOK,
                 params_for: Callable[[ActionType, str, str], Mapping[str, Any]] | None = None,
                 preferred_integrations: Mapping[ActionType, str] | None = None) -> None:
        """``adapters`` is an ``AdapterRegistry`` (``for_action``).

        ``params_for(action_type, integration, target)`` may add adapter parameters (for example an
        Umbrella destination list id); ``preferred_integrations`` overrides the catalog preference.
        """
        self._adapters = adapters
        self._playbook = tuple(playbook)
        self._params_for = params_for
        self._preferred = dict(preferred_integrations or {})

    def recommend(self, incident: Incident, investigation: InvestigationReport) -> Recommendation:
        proposals: list[ProposedAction] = []
        unrouted: list[UnroutedAction] = []
        notes: list[str] = []
        seen: set[tuple[ActionType, str]] = set()
        for observable in self._observables(incident):
            verdict, risk, confidence, agreeing = combined_verdict(investigation.enrichments_for(observable))
            for rule in self._playbook:
                if observable.type not in rule.observable_types or not rule.fires(verdict, risk):
                    continue
                evidence = self._evidence(observable, agreeing, investigation)
                for action_type in rule.action_types:
                    proposal = self._proposal(incident, observable, action_type, verdict, risk, confidence,
                                              agreeing, evidence, unrouted)
                    if proposal is None:
                        continue
                    key = (proposal.action_type, proposal.target)
                    if key not in seen:
                        seen.add(key)
                        proposals.append(proposal)
        if investigation.degraded_sources:
            notes.append("sources not fully available during investigation: "
                         + ", ".join(investigation.degraded_sources))
        risk_score = max((p.risk_score for p in proposals), default=0)
        confidence_score = (round(sum(p.confidence_score for p in proposals) / len(proposals))
                            if proposals else 0)
        return Recommendation(
            incident_id=incident.incident_id, proposals=tuple(proposals), risk_score=risk_score,
            confidence_score=confidence_score, summary=self._summary(incident, proposals),
            unrouted=tuple(unrouted), notes=tuple(notes))

    # ----------------------------------------------------------- internals --
    @staticmethod
    def _observables(incident: Incident) -> list[Observable]:
        seen: set[tuple[ObservableType, str]] = set()
        out: list[Observable] = []
        for observable in incident.observables:
            key = observable_key(observable)
            if key not in seen:
                seen.add(key)
                out.append(observable)
        return out

    @staticmethod
    def _evidence(observable: Observable, agreeing: Sequence[EnrichmentResult],
                  investigation: InvestigationReport) -> list[EvidenceDraft]:
        drafts: list[EvidenceDraft] = []
        for result in agreeing:
            drafts.extend(result.evidence or (_synthesized(result),))
        for result in investigation.investigations_for(observable):
            drafts.extend(result.evidence)
        return drafts

    def _integration_for(self, action_type: ActionType) -> str | None:
        preferred = self._preferred.get(action_type)
        candidates = [getattr(a, "name", None) for a in self._adapters.for_action(action_type)]  # type: ignore[attr-defined]
        if preferred is not None:
            return preferred if preferred in candidates else None
        return candidates[0] if candidates else None

    def _proposal(self, incident: Incident, observable: Observable, action_type: ActionType, verdict: Verdict,
                  risk: int, confidence: int, agreeing: Sequence[EnrichmentResult],
                  evidence: Sequence[EvidenceDraft], unrouted: list[UnroutedAction]) -> ProposedAction | None:
        spec = get_action_spec(action_type)
        try:
            target = normalize_target(spec.target_kind, observable.value)
        except ValueError as exc:
            unrouted.append(UnroutedAction(action_type, observable.value, f"invalid target: {exc}"))
            return None
        integration = self._integration_for(action_type)
        if integration is None:
            unrouted.append(UnroutedAction(action_type, target, "no enabled adapter supports this action"))
            return None
        if not evidence:
            unrouted.append(UnroutedAction(action_type, target, "no evidence"))
            return None
        params: dict[str, Any] = {"integration": integration}
        if self._params_for is not None:
            params.update(self._params_for(action_type, integration, target))
            params["integration"] = integration
        sources = ", ".join(sorted({r.integration for r in agreeing}))
        rationale = (f"{target} rated {verdict.value} by {sources} (risk {risk}, confidence {confidence}); "
                     f"playbook: {spec.description or action_type.value}")
        return ProposedAction(action_type=action_type, target=target, target_kind=spec.target_kind,
                              params=params, evidence=tuple(evidence), risk_score=risk,
                              confidence_score=confidence, rationale=rationale)

    @staticmethod
    def _summary(incident: Incident, proposals: Sequence[ProposedAction]) -> str:
        if not proposals:
            return f"No containment recommended for {incident.incident_id}: no malicious observable met the rules"
        parts = ", ".join(f"{p.action_type.value} {p.target}" for p in proposals)
        return f"{len(proposals)} containment action(s) recommended for {incident.title}: {parts}"
