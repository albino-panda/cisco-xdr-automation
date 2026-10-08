"""Planner contract after Phase 1 (architecture 14.4.1): C1, C2, C3, C5 and ``Action.source``."""
from __future__ import annotations

import dataclasses

import pytest

from xdr_plan import repo
from xdr_plan.planner import PROTECTED_REASON, Action, build_plan, find_source, requires_approval
from xdr_plan.repo import load_guardrails

SPEC = {
    "steps": [
        {"id": "enrich_hash", "phase": "enrich", "atomic": "enrich-hash", "on_error": "continue"},
        {"id": "investigate_host", "phase": "investigate", "atomic": "investigate-host", "on_error": "continue"},
        {"id": "investigate_user", "phase": "investigate", "atomic": "investigate-user", "on_error": "continue"},
        {"id": "isolate", "phase": "contain", "atomic": "isolate-endpoint", "on_error": "escalate"},
        {"id": "block_hash", "phase": "contain", "atomic": "block-hash", "on_error": "continue"},
        {"id": "revoke", "phase": "contain", "atomic": "revoke-session", "on_error": "escalate"},
    ],
    "plan": [
        {"id": "isolate_hosts", "description": "d", "atomic": "isolate-endpoint",
         "for_each": "results['investigate-host']", "when": "item.bad", "target": "item.host"},
        {"id": "block_hashes", "description": "d", "atomic": "block-hash",
         "for_each": "[h for h in results['enrich-hash'] if h.disposition == 'malicious']", "target": "item.sha256"},
        {"id": "revoke_users", "description": "d", "atomic": "revoke-session",
         "for_each": "results['investigate-user']", "target": "item.user"},
        {"id": "revoke_incident_user", "description": "d", "atomic": "revoke-session",
         "when": "get(incident.context, 'user', '') != ''", "target": "incident.context.user"},
    ],
}
HASH_A = "a" * 64
HASH_B = "b" * 64


def plan(results, override=None, incident=None):
    incident = incident or {"title": "T", "severity": "high", "context": {}}
    return build_plan("synthetic", incident, results, load_guardrails(override), SPEC)


def by_target(p):
    return {a.target: a for a in p.actions}


def test_action_fields_match_contract():
    names = [f.name for f in dataclasses.fields(Action)]
    assert names == ["rule", "atomic", "target", "status", "requires_approval", "args", "elevated", "reasons", "source"]
    a = Action("r", "block-hash", "x", "planned", True)
    assert (a.args, a.elevated, a.reasons, a.source) == ({}, False, [], None)


@pytest.mark.parametrize("atomic_id", sorted(a for a, s in repo.atomics().items() if s.get("category") == "containment"))
def test_every_containment_atomic_requires_approval(atomic_id):
    assert requires_approval(atomic_id) is True


def test_containment_category_forces_approval_even_if_yaml_says_false(monkeypatch):
    fake = {"x-contain": {"category": "containment", "requires_approval": False},
            "x-read": {"category": "enrichment", "requires_approval": False}}
    monkeypatch.setattr(repo, "atomics", lambda: fake)
    assert requires_approval("x-contain") is True
    assert requires_approval("x-read") is False


def test_revoke_session_requires_approval_without_auto_approval():
    p = plan({"investigate-user": [{"user": "jsmith@example.com"}]})
    assert [(a.atomic, a.requires_approval) for a in p.actions] == [("revoke-session", True)]


def test_auto_approve_in_guardrails_is_refused():
    g = load_guardrails()
    g["auto_approve"] = {"synthetic": {"revoke-session": True}}
    with pytest.raises(ValueError, match="auto_approve"):
        build_plan("synthetic", {"context": {}}, {}, g, SPEC)


def test_protected_targets_stay_planned_and_elevated():
    p = plan({
        "investigate-host": [{"host": "dc-01", "bad": True}, {"host": "ws-01", "bad": True}],
        "investigate-user": [{"user": "breakglass-01@example.com"}],
    })
    t = by_target(p)
    for target in ("dc-01", "breakglass-01@example.com"):
        assert (t[target].status, t[target].elevated, t[target].reasons) == ("planned", True, [PROTECTED_REASON])
    assert (t["ws-01"].status, t["ws-01"].elevated, t["ws-01"].reasons) == ("planned", False, [])
    assert not p.escalate


def test_over_cap_actions_stay_planned_elevated_and_escalate():
    hashes = [{"sha256": c * 64, "disposition": "malicious"} for c in "abc"]
    p = plan({"enrich-hash": hashes}, {"blast_radius": {"max_indicators_blocked": 2}})
    reason = "max_indicators_blocked: 3 planned > limit 2: ELEVATED approval required"
    assert p.escalate and p.reasons == [reason]
    assert all((a.status, a.elevated, a.reasons) == ("planned", True, [reason]) for a in p.actions)


def test_at_the_cap_nothing_is_elevated():
    hashes = [{"sha256": c * 64, "disposition": "malicious"} for c in "ab"]
    p = plan({"enrich-hash": hashes}, {"blast_radius": {"max_indicators_blocked": 2}})
    assert not p.escalate and not any(a.elevated for a in p.actions)


def test_protected_actions_count_towards_the_cap_and_keep_both_reasons():
    hosts = [{"host": "dc-01", "bad": True}, {"host": "ws-01", "bad": True}]
    p = plan({"investigate-host": hosts}, {"blast_radius": {"max_hosts_isolated": 1}})
    cap = "max_hosts_isolated: 2 planned > limit 1: ELEVATED approval required"
    t = by_target(p)
    assert t["dc-01"].reasons == [PROTECTED_REASON, cap]
    assert t["ws-01"].reasons == [cap]
    assert p.escalate


def test_allowlisted_actions_do_not_count_towards_the_cap():
    hashes = [{"sha256": HASH_A, "disposition": "malicious"}, {"sha256": HASH_B, "disposition": "malicious"}]
    p = plan({"enrich-hash": hashes}, {"allowlist": {"hashes": [HASH_B]}, "blast_radius": {"max_indicators_blocked": 1}})
    assert {(a.target, a.status, a.elevated) for a in p.actions} == {
        (HASH_A, "planned", False), (HASH_B, "skipped_allowlisted", False)}
    assert not p.escalate


def test_source_points_at_the_results_record():
    hashes = [{"sha256": HASH_A, "disposition": "clean"}, {"sha256": HASH_B, "disposition": "malicious"}]
    p = plan({"enrich-hash": hashes, "investigate-user": [{"user": "jsmith@example.com"}]},
             incident={"context": {"user": "jsmith@example.com"}})
    t = by_target(p)
    assert t[HASH_B].source == ("enrich-hash", 1)  # filtered comprehension keeps the record identity
    # the for_each-less rule targets the same user, so the first (sourced) action wins the dedupe
    assert t["jsmith@example.com"].source == ("investigate-user", 0)


def test_source_is_none_without_for_each():
    p = plan({}, incident={"context": {"user": "jsmith@example.com"}})
    assert [(a.rule, a.source) for a in p.actions] == [("revoke_incident_user", None)]


def test_find_source_uses_identity_not_equality():
    record = {"user": "u"}
    twin = {"user": "u"}
    assert find_source(twin, {"investigate-user": [record]}) is None
    assert find_source(record, {"investigate-user": [twin, record]}) == ("investigate-user", 1)
    assert find_source(None, {"x": [None]}) is None


def test_as_dict_is_json_friendly():
    d = plan({}, incident={"context": {"user": "jsmith@example.com"}}).as_dict()
    assert set(d["actions"][0]) == {"rule", "atomic", "target", "status", "requires_approval", "args",
                                    "elevated", "reasons", "source"}
