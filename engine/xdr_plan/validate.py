"""Static validation of a workflow spec and its scenarios, plus scenario execution."""
from __future__ import annotations

import re
from pathlib import Path

from . import repo
from .expr import ExprError, parse
from .planner import PlanError, build_plan

ON_ERROR = {"continue", "stop", "escalate"}
TEMPLATE_KEYS = ("approval", "incident_note", "ticket_title", "ticket_body", "notification")
TEMPLATE_ROOTS = {"incident", "plan", "ticket", "workflow", "approver"}
STATUSES = {"planned", "skipped_protected", "skipped_allowlisted", "skipped_internal", "skipped_limit"}
RULE_KEYS = {"id", "description", "atomic", "for_each", "when", "target", "args"}
MIN_SCENARIOS = 4
INCIDENT_KEYS = {"id", "title", "severity", "source", "observables", "targets", "context"}


def validate_spec(workflow_id: str, spec: dict | None = None) -> list[str]:
    spec = spec or repo.load_workflow(workflow_id)
    errors: list[str] = []
    phases = repo.workflow_atomics_by_phase(spec)
    contain = phases.get("contain", [])
    readable = set(phases.get("enrich", [])) | set(phases.get("investigate", []))

    for step in spec.get("steps", []):
        if step.get("on_error") not in ON_ERROR:
            errors.append(f"step {step.get('id')}: on_error must be one of {sorted(ON_ERROR)}")
        if step.get("phase") == "contain" and step.get("atomic") not in repo.atomics():
            errors.append(f"step {step.get('id')}: unknown atomic {step.get('atomic')}")

    plan = spec.get("plan")
    if not isinstance(plan, list) or not plan:
        errors.append("plan: missing or empty")
        plan = []
    ids = set()
    for rule in plan:
        rid = rule.get("id", "?")
        if not re.fullmatch(r"[a-z][a-z0-9_]*", str(rid)):
            errors.append(f"plan rule {rid}: id must be snake_case")
        if rid in ids:
            errors.append(f"plan rule {rid}: duplicate id")
        ids.add(rid)
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
    for atomic_id in contain:
        if not any(r.get("atomic") == atomic_id for r in plan):
            errors.append(f"plan: no rule for contain-phase atomic {atomic_id}")

    templates = spec.get("templates")
    if not isinstance(templates, dict):
        errors.append("templates: missing")
    else:
        for key in TEMPLATE_KEYS:
            if not str(templates.get(key) or "").strip():
                errors.append(f"templates.{key}: missing or empty")
        for key, text in templates.items():
            for ph in re.findall(r"\{([^{}]+)\}", str(text)):
                if ph.split(".")[0] not in TEMPLATE_ROOTS:
                    errors.append(f"templates.{key}: placeholder {{{ph}}} must start with one of {sorted(TEMPLATE_ROOTS)}")
    return errors


def load_scenario(path: Path) -> dict:
    data = repo.load_yaml(path) or {}
    return data


def validate_scenario(workflow_id: str, path: Path, spec: dict) -> list[str]:
    errors: list[str] = []
    s = load_scenario(path)
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
    for atomic_id, records in (s.get("results") or {}).items():
        if atomic_id not in readable:
            errors.append(f"{path.name}: results.{atomic_id} is not an enrich/investigate atomic of this workflow")
            continue
        allowed = repo.atomic_fields(atomic_id)
        for i, rec in enumerate(records or []):
            extra = set(rec) - allowed
            if extra:
                errors.append(f"{path.name}: results.{atomic_id}[{i}] has fields not in atomic.yaml: {sorted(extra)} "
                              f"(allowed: {sorted(allowed)})")
    for i, exp in enumerate((s.get("expect") or {}).get("actions") or []):
        if exp.get("status") not in STATUSES:
            errors.append(f"{path.name}: expect.actions[{i}].status must be one of {sorted(STATUSES)}")
    return errors


def run_scenario(workflow_id: str, path: Path, spec: dict | None = None) -> tuple[bool, str, list]:
    """Return (passed, message, actions)."""
    spec = spec or repo.load_workflow(workflow_id)
    s = load_scenario(path)
    try:
        plan = build_plan(workflow_id, s.get("incident") or {}, s.get("results") or {},
                          repo.load_guardrails(s.get("guardrails")), spec)
    except PlanError as exc:
        return False, f"{path.name}: plan error: {exc}", []
    expect = s.get("expect") or {}
    got = {(a.atomic, a.target.lower(), a.status) for a in plan.actions}
    want = {(e["atomic"], str(e["target"]).lower(), e["status"]) for e in expect.get("actions") or []}
    problems = []
    if got != want:
        if want - got:
            problems.append("expected but not produced: " + ", ".join(map(str, sorted(want - got))))
        if got - want:
            problems.append("produced but not expected: " + ", ".join(map(str, sorted(got - want))))
    by_key = {(a.atomic, a.target.lower()): a for a in plan.actions}
    for e in expect.get("actions") or []:
        if "requires_approval" in e:
            a = by_key.get((e["atomic"], str(e["target"]).lower()))
            if a and a.requires_approval != e["requires_approval"]:
                problems.append(f"{e['atomic']} {e['target']}: requires_approval {a.requires_approval} != {e['requires_approval']}")
    if bool(expect.get("escalate", False)) != plan.escalate:
        problems.append(f"escalate {plan.escalate} != expected {bool(expect.get('escalate', False))} {plan.reasons}")
    msg = f"{path.name}: " + ("ok" if not problems else "; ".join(problems))
    return not problems, msg, plan.actions


def check_workflow(workflow_id: str) -> list[str]:
    """Everything a workflow needs to be considered done. Empty list means pass."""
    spec = repo.load_workflow(workflow_id)
    errors = validate_spec(workflow_id, spec)
    plan_broken = any(e.startswith("plan") for e in errors)
    paths = repo.scenario_paths(workflow_id)
    if len(paths) < MIN_SCENARIOS:
        errors.append(f"scenarios: {len(paths)} found, at least {MIN_SCENARIOS} required in workflows/{workflow_id}/scenarios/")
    fired_rules: set[str] = set()
    statuses_seen: list[set[str]] = []
    for path in paths:
        scenario_errors = validate_scenario(workflow_id, path, spec)
        errors += scenario_errors
        if scenario_errors or plan_broken:
            continue
        ok, msg, actions = run_scenario(workflow_id, path, spec)
        if not ok:
            errors.append(msg)
        fired_rules |= {a.rule for a in actions}
        statuses_seen.append({a.status for a in actions})
    if paths and not plan_broken:
        if not any("planned" in s for s in statuses_seen):
            errors.append("coverage: no scenario produces a planned action")
        if not any(not s for s in statuses_seen):
            errors.append("coverage: no benign scenario that produces zero actions")
        if not any(any(x.startswith("skipped_") for x in s) for s in statuses_seen):
            errors.append("coverage: no scenario exercises a guardrail (skipped_* status)")
        for rule in spec.get("plan", []):
            if rule.get("id") not in fired_rules:
                errors.append(f"coverage: plan rule {rule.get('id')} never produces an action in any scenario")
    return errors
