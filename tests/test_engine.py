"""Unit tests for the plan engine using a synthetic workflow spec."""
from __future__ import annotations

import pytest

from xdr_plan import build_plan
from xdr_plan.expr import ExprError, evaluate, parse
from xdr_plan.planner import PlanError
from xdr_plan.repo import load_guardrails
from xdr_plan.validate import validate_spec

SPEC = {
    "steps": [
        {"id": "enrich_domain", "phase": "enrich", "atomic": "enrich-domain", "on_error": "continue"},
        {"id": "enrich_ip", "phase": "enrich", "atomic": "enrich-ip", "on_error": "continue"},
        {"id": "investigate_host", "phase": "investigate", "atomic": "investigate-host", "on_error": "continue"},
        {"id": "block_domain", "phase": "contain", "atomic": "block-domain", "on_error": "continue"},
        {"id": "block_ip", "phase": "contain", "atomic": "block-ip", "on_error": "continue"},
        {"id": "isolate_endpoint", "phase": "contain", "atomic": "isolate-endpoint", "on_error": "escalate"},
    ],
    "plan": [
        {"id": "block_bad_domains", "description": "d", "atomic": "block-domain",
         "for_each": "results['enrich-domain']", "when": "item.verdict == 'malicious'", "target": "item.domain"},
        {"id": "block_bad_ips", "description": "d", "atomic": "block-ip",
         "for_each": "results['enrich-ip']", "when": "item.verdict == 'malicious'", "target": "item.ip"},
        {"id": "isolate_hosts", "description": "d", "atomic": "isolate-endpoint",
         "for_each": "results['investigate-host']",
         "when": "any(d.disposition == 'malicious' for d in item.detections) and item.isolation_capable",
         "target": "item.connector_guid", "args": {"reason": "'Test: ' + incident.title"}},
    ],
    "templates": {k: f"{{incident.title}} {k}" for k in
                  ("approval", "incident_note", "ticket_title", "ticket_body", "notification")},
}


def host(name, guid, bad=True, capable=True, protected=False):
    return {"host": name, "connector_guid": guid, "isolation_capable": capable, "is_protected": protected,
            "detections": [{"disposition": "malicious" if bad else "clean"}]}


def plan(results, override=None):
    return build_plan("synthetic", {"title": "T", "severity": "high"}, results, load_guardrails(override), SPEC)


def statuses(p):
    return {(a.atomic, a.target, a.status, a.elevated) for a in p.actions}


def test_spec_is_valid():
    assert validate_spec("synthetic", SPEC) == []


def test_planned_and_guardrails():
    p = plan({
        "enrich-domain": [{"domain": "bad.example", "verdict": "malicious"},
                          {"domain": "login.example.com", "verdict": "malicious"},
                          {"domain": "ok.example", "verdict": "clean"}],
        "enrich-ip": [{"ip": "203.0.113.7", "verdict": "malicious"}, {"ip": "10.1.2.3", "verdict": "malicious"}],
        "investigate-host": [host("ws-01", "g1"), host("dc-01", "g2"), host("ws-02", "g3", bad=False)],
    })
    assert statuses(p) == {
        ("block-domain", "bad.example", "planned", False),
        ("block-domain", "login.example.com", "skipped_allowlisted", False),
        ("block-ip", "203.0.113.7", "planned", False),
        ("block-ip", "10.1.2.3", "skipped_internal", False),
        ("isolate-endpoint", "g1", "planned", False),
        ("isolate-endpoint", "g2", "planned", True),  # protected dc-01: ELEVATED, never dropped (C3)
    }
    iso = next(a for a in p.actions if a.target == "g1")
    assert iso.args == {"reason": "Test: T"} and iso.requires_approval
    dc = next(a for a in p.actions if a.target == "g2")
    assert dc.reasons == ["protected asset: ELEVATED approval required"]
    assert dc.source == ("investigate-host", 1)
    assert all(a.requires_approval for a in p.actions)
    assert not p.escalate


def test_blast_radius_escalates():
    hosts = [host(f"ws-{i}", f"g{i}") for i in range(6)]
    p = plan({"investigate-host": hosts})
    reason = "max_hosts_isolated: 6 planned > limit 5: ELEVATED approval required"
    assert p.escalate and p.reasons == [reason]
    assert {(a.status, a.elevated) for a in p.actions} == {("planned", True)}  # C5: kept, never skipped
    assert all(a.reasons == [reason] and a.requires_approval for a in p.actions)


def test_auto_approve_is_refused():
    with pytest.raises(ValueError, match="auto_approve"):
        plan({"enrich-domain": [{"domain": "bad.example", "verdict": "malicious"}]},
             {"auto_approve": {"synthetic": {"block-domain": True}}})


def test_dedupe():
    p = plan({"enrich-domain": [{"domain": "bad.example", "verdict": "malicious"}] * 2})
    assert len(p.actions) == 1 and p.actions[0].requires_approval is True


def test_benign_produces_nothing():
    assert plan({"enrich-domain": [{"domain": "ok.example", "verdict": "clean"}]}).actions == []


def test_missing_field_is_a_plan_error():
    with pytest.raises(PlanError, match="field 'verdict' is missing"):
        plan({"enrich-domain": [{"domain": "bad.example"}]})


@pytest.mark.parametrize("src", [
    "__import__('os')", "item.__class__", "open('x')", "(lambda: 1)()", "[x for x in y for z in x]",
])
def test_unsafe_expressions_rejected(src):
    with pytest.raises(ExprError):
        evaluate(src, {"item": {}, "y": []})


def test_expression_helpers():
    env = {"item": {"url": "https://Bad.Example/x", "sev": "high"}}
    assert evaluate("domain_of(item.url)", env) == "bad.example"
    assert evaluate("severity_at_least(item.sev, 'medium')", env) is True
    assert evaluate("get(item, 'missing', 3)", env) == 3
    parse("item.a if item.b else item.c")
