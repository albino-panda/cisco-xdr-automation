"""Static validation of a workflow spec and its scenarios, plus scenario execution.

Besides the structural checks, every spec, scenario and atomic is held to the
Phase 1 lifecycle rules (architecture 14.4.1): no ``requires_approval: false``
for containment (C1), no approval-disabling keys (C2), no ``skipped_protected``
(C3), no unlock codes in templates (C4) and no ``skipped_limit`` (C5).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import repo
from .expr import ExprError, parse
from .guardrails import find_forbidden_keys
from .planner import CONTAINMENT_CATEGORY, PlanError, build_plan

ON_ERROR = {"continue", "stop", "escalate"}
TEMPLATE_KEYS = ("approval", "incident_note", "ticket_title", "ticket_body", "notification")
TEMPLATE_ROOTS = {"incident", "plan", "ticket", "workflow", "approver"}
STATUSES = {"planned", "skipped_allowlisted", "skipped_internal"}
REMOVED_STATUSES = {
    "skipped_protected": "protected assets stay planned with elevated: true (C3)",
    "skipped_limit": "over a blast-radius cap actions stay planned with elevated: true (C5)",
}
EXPECT_ACTION_KEYS = {"atomic", "target", "status", "requires_approval", "elevated"}
RULE_KEYS = {"id", "description", "atomic", "for_each", "when", "target", "args"}
MIN_SCENARIOS = 4
INCIDENT_KEYS = {"id", "title", "severity", "source", "observables", "targets", "context"}
UNLOCK_CODE = re.compile(r"unlock[_ ]codes?", re.IGNORECASE)
UNLOCK_CODE_ALLOWED = re.compile(
    r"(the unlock code stays in the secure endpoint console( and is not copied here)?"
    r"|\(the unlock code stays (there|in the secure endpoint console)\))",
    re.IGNORECASE,
)


def copies_unlock_code(text: str) -> bool:
    """True when a template mentions an unlock code other than "it stays in the Secure Endpoint console" (C4)."""
    flat = UNLOCK_CODE_ALLOWED.sub("", " ".join(str(text).split()))
    return bool(UNLOCK_CODE.search(flat))


def check_atomics() -> list[str]:
    """C1: every containment atomic requires approval."""
    errors = []
    for atomic_id, spec in sorted(repo.atomics().items()):
        if spec.get("category") == CONTAINMENT_CATEGORY and spec.get("requires_approval") is not True:
            errors.append(f"atomic {atomic_id}: containment atomics must set requires_approval: true (C1)")
    return errors


def check_guardrails_file() -> list[str]:
    """C2: the example guardrails file holds no approval-disabling key."""
    base = repo.load_yaml(repo.ROOT / "docs" / "deployment" / "guardrails.example.yaml")
    return [f"guardrails.example.yaml: forbidden key {k} (C2)" for k in find_forbidden_keys(base)]


def check_repository() -> list[str]:
    """Repository-wide lifecycle checks that do not belong to one workflow."""
    return check_atomics() + check_guardrails_file()


def _check_steps(spec: dict) -> list[str]:
    errors: list[str] = []
    for step in spec.get("steps", []):
        if step.get("on_error") not in ON_ERROR:
            errors.append(f"step {step.get('id')}: on_error must be one of {sorted(ON_ERROR)}")
        if step.get("phase") == "contain":
            if step.get("atomic") not in repo.atomics():
                errors.append(f"step {step.get('id')}: unknown atomic {step.get('atomic')}")
            if step.get("requires_approval") is False:
                errors.append(f"step {step.get('id')}: contain-phase steps must not set requires_approval: false (C1)")
    return errors


def _check_rule(rule: dict, contain: list[str], readable: set[str]) -> list[str]:
    errors: list[str] = []
    rid = rule.get("id", "?")
    if not re.fullmatch(r"[a-z][a-z0-9_]*", str(rid)):
        errors.append(f"plan rule {rid}: id must be snake_case")
    unknown = set(rule) - RULE_KEYS
    if unknown:
        errors.append(f"plan rule {rid}: unknown keys {sorted(unknown)}")
    for key in ("description", "atomic", "target"):
        if not rule.get(key):
            errors.append(f"plan rule {rid}: '{key}' is required")
    if rule.get("atomic") and rule["atomic"] not in contain:
        errors.append(f"plan rule {rid}: atomic {rule['atomic']} is not a contain-phase step of this workflow {contain}")
    exprs = [rule.get(k) for k in ("for_each", "when", "target") if rule.get(k)]
    exprs += list((rule.get("args") or {}).values())
    for src in exprs:
        try:
            parse(src)
        except ExprError as exc:
            errors.append(f"plan rule {rid}: {exc}")
        for ref in re.findall(r"results\[['\"]([a-z0-9-]+)['\"]\]", str(src)):
            if ref not in readable:
                errors.append(f"plan rule {rid}: results['{ref}'] is not an enrich/investigate atomic here {sorted(readable)}")
    return errors


def _check_plan(spec: dict, contain: list[str], readable: set[str]) -> list[str]:
    plan = spec.get("plan")
    if not isinstance(plan, list) or not plan:
        return ["plan: missing or empty"]
    errors: list[str] = []
    ids: set[str] = set()
    for rule in plan:
        rid = rule.get("id", "?")
        if rid in ids:
            errors.append(f"plan rule {rid}: duplicate id")
        ids.add(rid)
        errors += _check_rule(rule, contain, readable)
    for atomic_id in contain:
        if not any(r.get("atomic") == atomic_id for r in plan):
            errors.append(f"plan: no rule for contain-phase atomic {atomic_id}")
    return errors


def _check_templates(spec: dict) -> list[str]:
    templates = spec.get("templates")
    if not isinstance(templates, dict):
        return ["templates: missing"]
    errors: list[str] = []
    for key in TEMPLATE_KEYS:
        if not str(templates.get(key) or "").strip():
            errors.append(f"templates.{key}: missing or empty")
    for key, text in templates.items():
        if copies_unlock_code(str(text)):
            errors.append(f"templates.{key}: must not contain an unlock code (C4)")
        for ph in re.findall(r"\{([^{}]+)\}", str(text)):
            if ph.split(".")[0] not in TEMPLATE_ROOTS:
                errors.append(f"templates.{key}: placeholder {{{ph}}} must start with one of {sorted(TEMPLATE_ROOTS)}")
    return errors


def validate_spec(workflow_id: str, spec: dict | None = None) -> list[str]:
    """Structural and lifecycle checks of one ``workflow.yaml``."""
    spec = spec or repo.load_workflow(workflow_id)
    phases = repo.workflow_atomics_by_phase(spec)
    contain = phases.get("contain", [])
    readable = set(phases.get("enrich", [])) | set(phases.get("investigate", []))
    errors = [f"forbidden key {k} (C2)" for k in find_forbidden_keys(spec)]
    errors += _check_steps(spec)
    errors += _check_plan(spec, contain, readable)
    errors += _check_templates(spec)
    return errors


def load_scenario(path: Path) -> dict:
    data = repo.load_yaml(path) or {}
    return data


def _check_expected_action(name: str, i: int, exp: Any) -> list[str]:
    if not isinstance(exp, dict):
        return [f"{name}: expect.actions[{i}] must be a mapping"]
    errors: list[str] = []
    unknown = set(exp) - EXPECT_ACTION_KEYS
    if unknown:
        errors.append(f"{name}: expect.actions[{i}] has unknown keys {sorted(unknown)}")
    status = exp.get("status")
    if status in REMOVED_STATUSES:
        errors.append(f"{name}: expect.actions[{i}].status {status} was removed: {REMOVED_STATUSES[status]}")
    elif status not in STATUSES:
        errors.append(f"{name}: expect.actions[{i}].status must be one of {sorted(STATUSES)}")
    if "requires_approval" in exp and exp["requires_approval"] is not True:
        errors.append(f"{name}: expect.actions[{i}].requires_approval may only be true (C1)")
    if "elevated" in exp and not isinstance(exp["elevated"], bool):
        errors.append(f"{name}: expect.actions[{i}].elevated must be true or false")
    return errors


def _check_results(name: str, s: dict, readable: set[str]) -> list[str]:
    errors: list[str] = []
    for atomic_id, records in (s.get("results") or {}).items():
        if atomic_id not in readable:
            errors.append(f"{name}: results.{atomic_id} is not an enrich/investigate atomic of this workflow")
            continue
        allowed = repo.atomic_fields(atomic_id)
        for i, rec in enumerate(records or []):
            extra = set(rec) - allowed
            if extra:
                errors.append(f"{name}: results.{atomic_id}[{i}] has fields not in atomic.yaml: {sorted(extra)} "
                              f"(allowed: {sorted(allowed)})")
    return errors


def validate_scenario(workflow_id: str, path: Path, spec: dict) -> list[str]:
    """Structural and lifecycle checks of one scenario file."""
    errors: list[str] = []
    s = load_scenario(path)
    errors += [f"{path.name}: forbidden key {k} (C2)" for k in find_forbidden_keys(s)]
    for key in ("name", "description", "incident", "expect"):
        if key not in s:
            errors.append(f"{path.name}: '{key}' is required")
    incident = s.get("incident") or {}
    for key in ("title", "severity"):
        if key not in incident:
            errors.append(f"{path.name}: incident.{key} is required")
    extra_incident = set(incident) - INCIDENT_KEYS
    if extra_incident:
        errors.append(f"{path.name}: incident has unknown keys {sorted(extra_incident)}; "
                      f"allowed {sorted(INCIDENT_KEYS)} (put source-specific facts under incident.context)")
    extra_top = set(s) - {"name", "description", "incident", "results", "guardrails", "expect"}
    if extra_top:
        errors.append(f"{path.name}: unknown top-level keys {sorted(extra_top)}")
    phases = repo.workflow_atomics_by_phase(spec)
    readable = set(phases.get("enrich", [])) | set(phases.get("investigate", []))
    errors += _check_results(path.name, s, readable)
    for i, exp in enumerate((s.get("expect") or {}).get("actions") or []):
        errors += _check_expected_action(path.name, i, exp)
    return errors


def _key(atomic: str, target: Any) -> tuple[str, str]:
    return atomic, str(target).lower()


def _compare_actions(plan_actions: list, expected: list[dict]) -> list[str]:
    got = {(a.atomic, a.target.lower(), a.status, a.elevated) for a in plan_actions}
    want = {(e["atomic"], str(e["target"]).lower(), e["status"], bool(e.get("elevated", False))) for e in expected}
    problems = []
    if want - got:
        problems.append("expected but not produced: " + ", ".join(map(str, sorted(want - got))))
    if got - want:
        problems.append("produced but not expected: " + ", ".join(map(str, sorted(got - want))))
    by_key = {_key(a.atomic, a.target): a for a in plan_actions}
    for e in expected:
        a = by_key.get(_key(e["atomic"], e["target"]))
        if a and "requires_approval" in e and a.requires_approval != e["requires_approval"]:
            problems.append(f"{e['atomic']} {e['target']}: requires_approval {a.requires_approval} != {e['requires_approval']}")
    return problems


def run_scenario(workflow_id: str, path: Path, spec: dict | None = None) -> tuple[bool, str, list]:
    """Return (passed, message, actions)."""
    spec = spec or repo.load_workflow(workflow_id)
    s = load_scenario(path)
    try:
        plan = build_plan(workflow_id, s.get("incident") or {}, s.get("results") or {},
                          repo.load_guardrails(s.get("guardrails")), spec)
    except (PlanError, ValueError) as exc:
        return False, f"{path.name}: plan error: {exc}", []
    expect = s.get("expect") or {}
    problems = _compare_actions(plan.actions, expect.get("actions") or [])
    if any(not a.requires_approval for a in plan.actions):
        problems.append("a containment action does not require approval (C1)")
    if bool(expect.get("escalate", False)) != plan.escalate:
        problems.append(f"escalate {plan.escalate} != expected {bool(expect.get('escalate', False))} {plan.reasons}")
    msg = f"{path.name}: " + ("ok" if not problems else "; ".join(problems))
    return not problems, msg, plan.actions


def _coverage(spec: dict, outcomes: list[list]) -> list[str]:
    errors: list[str] = []
    if not any(any(a.status == "planned" for a in acts) for acts in outcomes):
        errors.append("coverage: no scenario produces a planned action")
    if not any(not acts for acts in outcomes):
        errors.append("coverage: no benign scenario that produces zero actions")
    if not any(any(a.status.startswith("skipped_") or a.elevated for a in acts) for acts in outcomes):
        errors.append("coverage: no scenario exercises a guardrail (skipped_* status or elevated: true)")
    fired = {a.rule for acts in outcomes for a in acts}
    for rule in spec.get("plan", []):
        if rule.get("id") not in fired:
            errors.append(f"coverage: plan rule {rule.get('id')} never produces an action in any scenario")
    return errors


def check_workflow(workflow_id: str) -> list[str]:
    """Everything a workflow needs to be considered done. Empty list means pass."""
    spec = repo.load_workflow(workflow_id)
    errors = validate_spec(workflow_id, spec)
    plan_broken = any(e.startswith("plan") for e in errors)
    paths = repo.scenario_paths(workflow_id)
    if len(paths) < MIN_SCENARIOS:
        errors.append(f"scenarios: {len(paths)} found, at least {MIN_SCENARIOS} required in workflows/{workflow_id}/scenarios/")
    outcomes: list[list] = []
    for path in paths:
        scenario_errors = validate_scenario(workflow_id, path, spec)
        errors += scenario_errors
        if scenario_errors or plan_broken:
            continue
        ok, msg, actions = run_scenario(workflow_id, path, spec)
        if not ok:
            errors.append(msg)
        outcomes.append(actions)
    if paths and not plan_broken:
        errors += _coverage(spec, outcomes)
    return errors
