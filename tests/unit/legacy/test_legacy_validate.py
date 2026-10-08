"""``xdr_plan check`` lifecycle checks C1-C5 (architecture 14.4.1) on synthetic specs and scenarios."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from xdr_plan import repo, validate
from xdr_plan.validate import (
    check_atomics,
    check_guardrails_file,
    copies_unlock_code,
    run_scenario,
    validate_scenario,
    validate_spec,
)

TEMPLATES = {k: f"{{incident.title}} {k}" for k in validate.TEMPLATE_KEYS}
SPEC = {
    "steps": [
        {"id": "investigate_host", "phase": "investigate", "atomic": "investigate-host", "on_error": "continue"},
        {"id": "isolate", "phase": "contain", "atomic": "isolate-endpoint", "requires_approval": True,
         "on_error": "escalate"},
    ],
    "plan": [
        {"id": "isolate_hosts", "description": "d", "atomic": "isolate-endpoint",
         "for_each": "results['investigate-host']", "when": "item.isolation_capable", "target": "item.connector_guid"},
    ],
    "templates": TEMPLATES,
}


def host(guid: str, name: str) -> dict:
    return {"host": name, "connector_guid": guid, "isolation_capable": True}


def scenario(tmp_path: Path, expect_actions: list, results: list | None = None, **extra) -> Path:
    data = {"name": "s", "description": "d", "incident": {"title": "T", "severity": "high"},
            "results": {"investigate-host": results if results is not None else [host("g1", "dc-01")]},
            "expect": {"actions": expect_actions}, **extra}
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def spec_with(**changes) -> dict:
    spec = copy.deepcopy(SPEC)
    spec.update(changes)
    return spec


def test_synthetic_spec_is_valid():
    assert validate_spec("synthetic", SPEC) == []


def test_c1_contain_step_with_requires_approval_false_fails():
    spec = copy.deepcopy(SPEC)
    spec["steps"][1]["requires_approval"] = False
    assert any("(C1)" in e for e in validate_spec("synthetic", spec))


def test_c1_containment_atomic_without_approval_fails(monkeypatch):
    fake = {"x-contain": {"category": "containment", "requires_approval": False},
            "y-contain": {"category": "containment", "requires_approval": True},
            "x-read": {"category": "enrichment", "requires_approval": False}}
    monkeypatch.setattr(repo, "atomics", lambda: fake)
    assert check_atomics() == ["atomic x-contain: containment atomics must set requires_approval: true (C1)"]


def test_c1_repository_atomics_and_guardrails_pass():
    assert check_atomics() == []
    assert check_guardrails_file() == []


@pytest.mark.parametrize("value", [False, "yes", None])
def test_c1_scenario_requires_approval_only_true(tmp_path, value):
    path = scenario(tmp_path, [{"atomic": "isolate-endpoint", "target": "g1", "status": "planned",
                                "elevated": True, "requires_approval": value}])
    assert any("requires_approval may only be true (C1)" in e for e in validate_scenario("synthetic", path, SPEC))


def test_c2_forbidden_key_in_spec_fails():
    spec = spec_with(defaults={"approval": {"auto_approve": True}})
    assert "forbidden key defaults.approval.auto_approve (C2)" in validate_spec("synthetic", spec)


def test_c2_forbidden_key_in_scenario_fails(tmp_path):
    path = scenario(tmp_path, [], guardrails={"auto_approve": {"synthetic": {"isolate-endpoint": True}}})
    errors = validate_scenario("synthetic", path, SPEC)
    assert "s.yaml: forbidden key guardrails.auto_approve (C2)" in errors


def test_c2_load_guardrails_refuses_nested_forbidden_keys():
    with pytest.raises(ValueError, match="skip_approval"):
        repo.load_guardrails({"blast_radius": {"overrides": [{"skip_approval": True}]}})


@pytest.mark.parametrize("status, code", [("skipped_protected", "C3"), ("skipped_limit", "C5")])
def test_c3_c5_removed_statuses_fail(tmp_path, status, code):
    path = scenario(tmp_path, [{"atomic": "isolate-endpoint", "target": "g1", "status": status}])
    errors = validate_scenario("synthetic", path, SPEC)
    assert any(f"({code})" in e and status in e for e in errors)


def test_unknown_expect_key_and_non_bool_elevated_fail(tmp_path):
    path = scenario(tmp_path, [{"atomic": "isolate-endpoint", "target": "g1", "status": "planned",
                                "elevated": "yes", "auto": 1}])
    errors = validate_scenario("synthetic", path, SPEC)
    assert any("unknown keys ['auto']" in e for e in errors)
    assert any("elevated must be true or false" in e for e in errors)


@pytest.mark.parametrize("text", [
    "Unlock codes: {plan.unlock_codes}",
    "Rollback: stop isolation with the unlock code in the incident note.",
    "The unlock_code is {plan.isolation.unlock_code}",
])
def test_c4_templates_copying_unlock_codes_fail(text):
    assert copies_unlock_code(text)
    spec = spec_with(templates={**TEMPLATES, "incident_note": text})
    assert "templates.incident_note: must not contain an unlock code (C4)" in validate_spec("synthetic", spec)


@pytest.mark.parametrize("text", [
    "Stop isolation. The unlock code stays in the Secure Endpoint console and is not copied here.",
    "Stop isolation. The unlock code\n      stays in the Secure Endpoint console.",
    "Stop isolation in Secure Endpoint (the unlock code stays there).",
    "No unlock reference at all.",
])
def test_c4_console_wording_is_allowed(text):
    assert not copies_unlock_code(text)


def test_run_scenario_expects_elevated_protected_host(tmp_path):
    ok_path = scenario(tmp_path, [{"atomic": "isolate-endpoint", "target": "g1", "status": "planned", "elevated": True}])
    ok, msg, actions = run_scenario("synthetic", ok_path, SPEC)
    assert ok, msg
    assert actions[0].elevated and actions[0].requires_approval


def test_run_scenario_compares_elevated_strictly(tmp_path):
    path = scenario(tmp_path, [{"atomic": "isolate-endpoint", "target": "g1", "status": "planned"}])
    ok, msg, _ = run_scenario("synthetic", path, SPEC)
    assert not ok and "elevated" not in msg.split(":")[0]
    assert "('isolate-endpoint', 'g1', 'planned', True)" in msg


def test_run_scenario_over_cap_escalates(tmp_path):
    hosts = [host("g1", "ws-01"), host("g2", "ws-02")]
    expect = [{"atomic": "isolate-endpoint", "target": g, "status": "planned", "elevated": True} for g in ("g1", "g2")]
    path = scenario(tmp_path, expect, results=hosts, guardrails={"blast_radius": {"max_hosts_isolated": 1}})
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    ok, msg, _ = run_scenario("synthetic", path, SPEC)
    assert not ok and "escalate True != expected False" in msg
    data["expect"]["escalate"] = True
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    ok, msg, _ = run_scenario("synthetic", path, SPEC)
    assert ok, msg


def test_coverage_accepts_elevated_as_a_guardrail(monkeypatch, tmp_path):
    scenarios = tmp_path / "scenarios"
    scenarios.mkdir()
    cases = {
        "01-protected.yaml": ([host("g1", "dc-01")], [{"atomic": "isolate-endpoint", "target": "g1", "status": "planned", "elevated": True}]),
        "02-planned.yaml": ([host("g2", "ws-02")], [{"atomic": "isolate-endpoint", "target": "g2", "status": "planned"}]),
        "03-benign.yaml": ([], []),
        "04-planned.yaml": ([host("g3", "ws-03")], [{"atomic": "isolate-endpoint", "target": "g3", "status": "planned"}]),
    }
    for name, (results, expect) in cases.items():
        data = {"name": name, "description": "d", "incident": {"title": "T", "severity": "high"},
                "results": {"investigate-host": results}, "expect": {"actions": expect}}
        (scenarios / name).write_text(yaml.safe_dump(data), encoding="utf-8")
    monkeypatch.setattr(repo, "load_workflow", lambda wid: SPEC)
    monkeypatch.setattr(repo, "scenario_paths", lambda wid: sorted(scenarios.glob("*.yaml")))
    assert validate.check_workflow("synthetic") == []
