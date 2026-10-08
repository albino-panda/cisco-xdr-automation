"""Turn a workflow's ``plan`` rules plus enrichment/investigation results into a containment plan.

This mirrors the *decide* phase of every workflow: it is exactly what the
approver sees, and what a dry run records, before anything is changed. The
planner only recommends; it never approves or executes anything.

Rules of the Phase 1 contract (architecture 14.4.1):

- every containment atomic requires human approval (C1); there is no
  auto-approval (C2);
- a protected asset stays planned and is marked ``elevated`` (C3);
- over a blast-radius cap the actions stay planned, are marked ``elevated``
  and the plan escalates (C5).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from . import repo
from .expr import ExprError, evaluate
from .guardrails import CAPS, CHECKS, ELEVATED_PROTECTED

PROTECTED_REASON = "protected asset: ELEVATED approval required"
CONTAINMENT_CATEGORY = "containment"


class PlanError(ValueError):
    """A rule could not be evaluated against the given data."""


@dataclass
class Action:
    """One recommended containment action."""

    rule: str
    atomic: str
    target: str
    status: str  # planned | skipped_allowlisted | skipped_internal
    requires_approval: bool  # always True for containment atomics
    args: dict[str, Any] = field(default_factory=dict)
    elevated: bool = False  # C3 protected asset or C5 over the cap
    reasons: list[str] = field(default_factory=list)
    source: tuple[str, int] | None = None  # (results key, index) when the item is an element of results[key]


@dataclass
class Plan:
    """The full plan for one workflow run."""

    workflow: str
    actions: list[Action]
    escalate: bool
    reasons: list[str]

    def as_dict(self) -> dict:
        return asdict(self)


class Results(dict):
    """results['atomic-id'] -> list of records; unknown-but-valid ids give an empty list."""

    def __init__(self, data: dict[str, list], allowed: set[str]):
        super().__init__(data)
        self.allowed = allowed

    def __missing__(self, key):
        if key in self.allowed:
            return []
        raise KeyError(f"results[{key!r}] is not an enrichment or investigation atomic of this workflow "
                       f"(allowed: {sorted(self.allowed)})")


def requires_approval(atomic_id: str) -> bool:
    """Every containment atomic requires human approval (C1); others follow their atomic.yaml."""
    spec = repo.atomics().get(atomic_id) or {}
    return spec.get("category") == CONTAINMENT_CATEGORY or bool(spec.get("requires_approval"))


def find_source(item: Any, results: dict[str, list]) -> tuple[str, int] | None:
    """Return ``(key, index)`` when ``item`` is (by identity) an element of ``results[key]``."""
    if item is None:
        return None
    for key in sorted(results):
        for index, record in enumerate(results.get(key) or []):
            if record is item:
                return key, index
    return None


def _items(rule: dict, names: dict[str, Any]) -> list[Any]:
    rid = rule["id"]
    try:
        items = evaluate(rule["for_each"], names) if rule.get("for_each") else [None]
    except (ExprError, KeyError) as exc:
        raise PlanError(f"rule {rid}: for_each: {exc}") from exc
    if not isinstance(items, (list, tuple)):
        raise PlanError(f"rule {rid}: for_each must produce a list, got {type(items).__name__}")
    return list(items)


def _evaluate_item(rule: dict, env: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Return ``(target, args)`` for one item, or ``None`` when ``when`` is false."""
    rid = rule["id"]
    try:
        if rule.get("when") and not evaluate(rule["when"], env):
            return None
        target = evaluate(rule["target"], env)
        args = {k: evaluate(v, env) for k, v in (rule.get("args") or {}).items()}
    except (ExprError, KeyError) as exc:
        raise PlanError(f"rule {rid}: {exc}") from exc
    if target in (None, ""):
        raise PlanError(f"rule {rid}: target evaluated to {target!r}")
    return str(target), args


def _make_action(rule: dict, target: str, args: dict[str, Any], item: Any, g: dict,
                 results: dict[str, list]) -> Action:
    rid, atomic_id = rule["id"], rule["atomic"]
    try:
        marker = CHECKS[atomic_id](target, item, g)
    except ValueError as exc:
        raise PlanError(f"rule {rid}: {exc}") from exc
    action = Action(rid, atomic_id, target, "planned", requires_approval(atomic_id), args,
                    source=find_source(item, results))
    if marker == ELEVATED_PROTECTED:
        action.elevated = True
        action.reasons.append(PROTECTED_REASON)
    elif marker:
        action.status = marker
    return action


def _apply_caps(actions: list[Action], limits: dict) -> list[str]:
    """Mark every planned action of a group over its blast-radius cap as elevated (C5); return plan reasons."""
    by_cap: dict[str, list[Action]] = {}
    for action in actions:
        cap = CAPS.get(action.atomic)
        if cap and action.status == "planned":
            by_cap.setdefault(cap, []).append(action)
    reasons: list[str] = []
    for cap, planned in by_cap.items():
        limit = limits.get(cap)
        if limit is None or len(planned) <= int(limit):
            continue
        reason = f"{cap}: {len(planned)} planned > limit {limit}: ELEVATED approval required"
        reasons.append(reason)
        for action in planned:
            action.elevated = True
            action.reasons.append(reason)
    return reasons


def build_plan(workflow_id: str, incident: dict, results: dict[str, list],
               guardrails: dict | None = None, spec: dict | None = None) -> Plan:
    """Evaluate every plan rule and return the recommended (never executed) plan.

    Raises ``ValueError`` when the guardrails hold an approval-disabling key (C2) and
    ``PlanError`` when a rule cannot be evaluated.
    """
    spec = spec or repo.load_workflow(workflow_id)
    g = guardrails if guardrails is not None else repo.load_guardrails()
    repo.check_forbidden(g, "guardrails")
    phases = repo.workflow_atomics_by_phase(spec)
    readable = set(phases.get("enrich", [])) | set(phases.get("investigate", []))
    names = {"incident": incident, "results": Results(results, readable), "guardrails": g}

    actions: list[Action] = []
    seen: set[tuple[str, str]] = set()
    for rule in spec.get("plan", []):
        for item in _items(rule, names):
            evaluated = _evaluate_item(rule, {**names, "item": item})
            if evaluated is None:
                continue
            target, args = evaluated
            key = (rule["atomic"], target.lower())
            if key in seen:
                continue
            seen.add(key)
            actions.append(_make_action(rule, target, args, item, g, results))

    reasons = _apply_caps(actions, g.get("blast_radius") or {})
    return Plan(workflow_id, actions, bool(reasons), reasons)
