"""Turn a workflow's ``plan`` rules plus enrichment/investigation results into a containment plan.

This mirrors the *decide* phase of every workflow: it is exactly what the
approver sees, and what a dry run records, before anything is changed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from . import repo
from .expr import ExprError, evaluate
from .guardrails import CAPS, CHECKS


class PlanError(ValueError):
    """A rule could not be evaluated against the given data."""


@dataclass
class Action:
    rule: str
    atomic: str
    target: str
    status: str  # planned | skipped_protected | skipped_allowlisted | skipped_internal | skipped_limit
    requires_approval: bool
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Plan:
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


def build_plan(workflow_id: str, incident: dict, results: dict[str, list],
               guardrails: dict | None = None, spec: dict | None = None) -> Plan:
    spec = spec or repo.load_workflow(workflow_id)
    g = guardrails if guardrails is not None else repo.load_guardrails()
    phases = repo.workflow_atomics_by_phase(spec)
    readable = set(phases.get("enrich", [])) | set(phases.get("investigate", []))
    names = {"incident": incident, "results": Results(results, readable), "guardrails": g}
    auto = (g.get("auto_approve") or {}).get(workflow_id) or {}

    actions: list[Action] = []
    seen: set[tuple[str, str]] = set()
    for rule in spec.get("plan", []):
        rid, atomic_id = rule["id"], rule["atomic"]
        try:
            items = evaluate(rule["for_each"], names) if rule.get("for_each") else [None]
        except (ExprError, KeyError) as exc:
            raise PlanError(f"rule {rid}: for_each: {exc}") from exc
        if not isinstance(items, (list, tuple)):
            raise PlanError(f"rule {rid}: for_each must produce a list, got {type(items).__name__}")
        for item in items:
            env = {**names, "item": item}
            try:
                if rule.get("when") and not evaluate(rule["when"], env):
                    continue
                target = evaluate(rule["target"], env)
                args = {k: evaluate(v, env) for k, v in (rule.get("args") or {}).items()}
            except (ExprError, KeyError) as exc:
                raise PlanError(f"rule {rid}: {exc}") from exc
            if target in (None, ""):
                raise PlanError(f"rule {rid}: target evaluated to {target!r}")
            target = str(target)
            key = (atomic_id, target.lower())
            if key in seen:
                continue
            seen.add(key)
            try:
                status = CHECKS[atomic_id](target, item, g) or "planned"
            except ValueError as exc:
                raise PlanError(f"rule {rid}: {exc}") from exc
            approval = bool(repo.atomics()[atomic_id].get("requires_approval")) and not auto.get(atomic_id, False)
            actions.append(Action(rid, atomic_id, target, status, approval, args))

    escalate, reasons = False, []
    limits = g.get("blast_radius") or {}
    by_cap: dict[str, list[Action]] = {}
    for action in actions:
        cap = CAPS.get(action.atomic)
        if cap and action.status == "planned":
            by_cap.setdefault(cap, []).append(action)
    for cap, planned in by_cap.items():
        limit = limits.get(cap)
        if limit is not None and len(planned) > int(limit):
            escalate = True
            reasons.append(f"{cap}: {len(planned)} planned > limit {limit}; containment for this group needs a human")
            for action in planned:
                action.status = "skipped_limit"
    return Plan(workflow_id, actions, escalate, reasons)
