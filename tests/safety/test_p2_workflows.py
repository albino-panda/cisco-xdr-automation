"""Adversarial safety tests, Phase 2 round 1, lens: workflow safety.

Every test asserts the SAFE behaviour required by docs/architecture.md (sections 13 and 14, as built
in 14.10) for the eight Phase 2 workflows (ransomware, phishing, account-takeover, mail-bombing,
malware, mfa-fatigue, password-spray, bec), so a failing test is a defect. The tests start from each
workflow's own scenario fixtures and mutate them the way an attacker or an unlucky configuration
would: allow-list the targets, mark them critical, fail a source, fail an action, pre-contain a
target, put credential-looking text into vendor records, and so on.

Fake data only: documentation IPs, example domains, fake hashes, hosts like TH-LT-1047 and users like
jsmith@example.com. Nothing here talks to a network or a real vendor; the simulated lab adapters
record every call they receive.
"""
from __future__ import annotations

import ast
import copy
import json
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools.simulator.scenario import REPO_ROOT
from tests.fixtures.degraded import degradation_findings
from tools.simulator.workflow_scenario import WorkflowScenario, WorkflowScenarioRun
from xdr_response import guard
from xdr_response.errors import ApprovalError
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    AuditEventType,
    ContainmentOverall,
    TargetKind,
    get_action_spec,
)
from xdr_response.workflows.discovery import discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "workflows"
PACKAGE_DIR = REPO_ROOT / "src" / "xdr_response" / "workflows"
CATALOG = discover_workflows()
P2_WORKFLOWS = ("account-takeover", "bec", "mail-bombing", "malware", "mfa-fatigue", "password-spray",
                "phishing", "ransomware")

#: Execution-side audit events that must never appear before (or without) a live approval.
_EXECUTION_EVENTS = frozenset({AuditEventType.ACTION_STARTED, AuditEventType.ACTION_RESULT,
                               AuditEventType.CONTROL_REGISTERED, AuditEventType.VERIFICATION_RESULT,
                               AuditEventType.CONTAINMENT_COMPLETED, AuditEventType.RESTORATION_RESULT})

#: Fake credential-looking values planted in vendor records. None may reach a package, a summary,
#: a note, a notification or the audit trail.
SECRET_PASSWORD = "Hunter2LabSecret77"
SECRET_UNLOCK = "48151623"
SECRET_TOKEN = "lab-bearer-token-ZX9QW8ER7TY6"


# ------------------------------------------------------------------------------------- helpers --
def _raw(workflow: str, name: str) -> dict[str, Any]:
    with (FIXTURES / workflow / f"{name}.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _scenario(data: Mapping[str, Any], workflow: str, name: str) -> WorkflowScenario:
    return WorkflowScenario.model_validate({**data, "path": FIXTURES / workflow / f"{name}.yaml"})


def _run(data: Mapping[str, Any], workflow: str, name: str, *, live: bool) -> WorkflowScenarioRun:
    return WorkflowScenarioRun(_scenario(data, workflow, name), live=live, catalog=CATALOG)


def _detect(data: Mapping[str, Any], workflow: str, name: str, *, live: bool) -> WorkflowScenarioRun:
    run = _run(data, workflow, name, live=live)
    run.detect()
    return run


def _baseline(workflow: str, name: str = "tp-approve-all") -> list[tuple[ActionType, str, TargetKind]]:
    """The package actions of the unmodified scenario (dry run), then a fresh guard."""
    run = _detect(_raw(workflow, name), workflow, name, live=False)
    package = run.detection.package
    guard._reset_for_test_harness()
    assert package is not None, f"{workflow}/{name}: the unmodified scenario must propose a package"
    return [(a.action_type, a.target, a.target_kind) for a in package.actions]


def _approvers(package: Any) -> list[str]:
    return ["analyst", "lead"] if package.has_elevated else ["analyst"]


def _approve_all(run: WorkflowScenarioRun) -> Any:
    package = run.orchestrator.latest_package(run.incident_id)
    return run.decide({"decision": "APPROVE_ALL"}, approvers=_approvers(package))


def _state_calls(run: WorkflowScenarioRun) -> list[tuple[str, str, str | None]]:
    return [(c.integration, c.operation, c.target) for c in run.environment.state_changing_calls()]


def _events(run: WorkflowScenarioRun) -> list[AuditEventType]:
    return [r.event_type for r in run.runtime.audit.records(run.incident_id)]


def _host_part(target: str) -> str:
    return target.split("/", 1)[0]


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _with_config(data: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(data))
    out["config"] = _deep_merge(out.get("config") or {}, override)
    return out


def _repo_allowlists() -> dict[str, Any]:
    with (REPO_ROOT / "config" / "allowlists.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _allowlist_override(targets: Iterable[tuple[ActionType, str, TargetKind]], *,
                        spell: Callable[[TargetKind, str], str] = lambda _k, v: v) -> dict[str, Any]:
    """Repository allow-lists plus every given target (the scenario config replaces lists)."""
    base = _repo_allowlists()
    never = {k: list(v or []) for k, v in (base.get("never_block") or {}).items()}
    slot = {TargetKind.DOMAIN: "domains", TargetKind.URL: "urls", TargetKind.IP: "ips", TargetKind.HASH: "hashes",
            TargetKind.USER: "users", TargetKind.ENDPOINT: "endpoints"}
    for _action, target, kind in targets:
        if kind in slot:
            never.setdefault(slot[kind], []).append(spell(kind, target))
        elif kind in (TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM):
            never.setdefault("endpoints", []).append(spell(TargetKind.ENDPOINT, _host_part(target)))
    return {"allowlists": {**base, "never_block": {k: sorted(set(v)) for k, v in never.items()}}}


_ALLOWLISTABLE = frozenset({TargetKind.DOMAIN, TargetKind.URL, TargetKind.IP, TargetKind.HASH, TargetKind.USER,
                            TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS})


def _walk_replace(node: Any, old: str, new: str) -> Any:
    if isinstance(node, str):
        return new if node == old else node
    if isinstance(node, list):
        return [_walk_replace(v, old, new) for v in node]
    if isinstance(node, dict):
        return {k: _walk_replace(v, old, new) for k, v in node.items()}
    return node


def _records(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [r["record"] for r in (data.get("environment") or {}).get("records") or ()]


def _outputs_text(run: WorkflowScenarioRun, *, audit: bool = True) -> str:
    """Everything an analyst or another system sees: package, run summary and notes, notifications,
    the dry-run report and (optionally) the audit trail."""
    parts: list[str] = []
    detection = run.detection
    if detection is not None and detection.package is not None:
        parts.append(detection.package.model_dump_json())
    if detection is not None:
        parts.append(json.dumps(list(detection.notes), default=str))
    wf = run.workflow_run
    if wf is not None:
        parts.append(wf.summary().model_dump_json())
        parts.append(json.dumps(list(wf.notes)))
        parts.extend(o.model_dump_json() for o in wf.outcomes)
    for draft in run.outbox.drafts:
        parts.append(draft.model_dump_json())
    if audit:
        for record in run.runtime.audit.records(run.incident_id):
            parts.append(record.model_dump_json())
    return "\n".join(parts)


# ============================================================ 1. no state change without approval --
@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
@pytest.mark.parametrize("decision", ["REJECT", "REQUEST_MORE_INVESTIGATION"])
def test_live_detection_and_non_approving_decision_never_change_state(workflow: str, decision: str):
    """Investigation and recommendation are automatic; nothing state-changing happens until a human
    approves, and a rejection or a request for more investigation never executes anything."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    assert run.detection.package is not None
    assert _state_calls(run) == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": decision, "comment": "lab decision"}, approvers=_approvers(package))
    assert _state_calls(run) == [], f"{workflow}: {decision} executed state-changing calls"
    assert run.runtime.registry.list(incident_id=run.incident_id) == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_non_human_principals_cannot_approve_any_workflow_package(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                             run.credentials(alias))
        with pytest.raises(ApprovalError):  # nor co-sign with a human to reach a quorum
            run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                             run.credentials("analyst", alias))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_workflow_packages_never_import_execution_or_approval_code(workflow: str):
    """Workflows only investigate and recommend: their code imports no execution, approval, guard,
    token, restoration, lifecycle, audit, secrets or adapter module, and never calls a state-changing
    operation by name."""
    forbidden = ("xdr_response.execution", "xdr_response.approval", "xdr_response.guard",
                 "xdr_response.restoration", "xdr_response.lifecycle", "xdr_response.audit",
                 "xdr_response.secrets", "xdr_response.integrations", "xdr_response.verification",
                 "xdr_response.dryrun", "xdr_response.atomics.containment", "xdr_response.atomics.context")
    state_ops = {a.value for a in ActionType if get_action_spec(a).state_changing}
    problems: list[str] = []
    for path in sorted((PACKAGE_DIR / workflow.replace("-", "_")).glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 12))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level == 0 and module.startswith(forbidden):
                    problems.append(f"{path.name}: from {module} import ...")
                if any(alias.name == "guard" for alias in node.names):
                    problems.append(f"{path.name}: imports guard")
            elif isinstance(node, ast.Import):
                problems += [f"{path.name}: import {a.name}" for a in node.names if a.name.startswith(forbidden)]
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in state_ops or node.func.attr in {"execute", "contain", "issue", "sign"}:
                    problems.append(f"{path.name}:{node.lineno}: calls .{node.func.attr}()")
    assert problems == []


# ============================================================================= 2. dry run is inert --
@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_dry_run_approve_all_is_side_effect_free_end_to_end(workflow: str):
    """Dry run end to end: even an approved package (analyst plus lead) performs no state-changing
    call, registers no temporary control and records no execution event."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    assert run.detection.package is not None and run.detection.package.dry_run
    run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []
    assert not ({AuditEventType.ACTION_RESULT, AuditEventType.CONTROL_REGISTERED,
                 AuditEventType.RESTORATION_RESULT} & set(_events(run)))
    assert run.decision.report is None or run.decision.report.dry_run


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_dry_run_release_attempt_is_side_effect_free(workflow: str):
    data = _raw(workflow, "release-restoration")
    run = _detect(data, workflow, "release-restoration", live=False)
    if run.detection.package is None:
        pytest.skip("no package in the release scenario")
    run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    try:
        run.propose_release()
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    except Exception:  # noqa: BLE001 - refusing a dry-run release is fine; touching state is not
        pass
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


# ================================================================== 3. benign produces no containment --
@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
@pytest.mark.parametrize("live", [False, True], ids=["dry_run", "live"])
def test_benign_scenario_produces_no_containment(workflow: str, live: bool):
    run = _detect(_raw(workflow, "benign-no-action"), workflow, "benign-no-action", live=live)
    package = run.detection.package
    assert package is None or not package.actions, (
        f"{workflow}: benign incident proposed {[(a.action_type.value, a.target) for a in package.actions]}")
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


# ========================================================== 4. allow-listed items are never blocked --
@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_allowlisted_targets_are_excluded_visibly_and_never_executed(workflow: str):
    baseline = _baseline(workflow)
    listed = [t for t in baseline if t[2] in _ALLOWLISTABLE]
    data = _with_config(_raw(workflow, "tp-approve-all"), _allowlist_override(listed))
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    excluded = {(e.action_type, e.target) for e in package.excluded_targets} if package else set()
    leaked = sorted(f"{a.value}:{t}" for a, t, _k in listed if (a, t) in proposed)
    assert leaked == [], f"{workflow}: allow-listed targets still proposed: {leaked}"
    hidden = sorted(f"{a.value}:{t}" for a, t, _k in listed
                    if (a, t) not in excluded and not any((a, t) == (o.action_type, o.target) for o in
                                                          run.workflow_run.outcomes))
    assert hidden == [], f"{workflow}: allow-listed targets silently dropped (not shown as excluded): {hidden}"
    if package is not None and package.actions:
        _approve_all(run)
    touched = {(op, (tgt or "").lower()) for _i, op, tgt in _state_calls(run)}
    hit = sorted(f"{a.value}:{t}" for a, t, _k in listed if (a.value, t.lower()) in touched)
    assert hit == [], f"{workflow}: state-changing calls on allow-listed targets: {hit}"


def _odd_spelling(kind: TargetKind, value: str) -> str:
    if kind is TargetKind.DOMAIN:
        return value.upper() + "."
    if kind in (TargetKind.HASH, TargetKind.USER):
        return value.upper()
    if kind is TargetKind.ENDPOINT:
        return value.lower()
    return value


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_allowlist_matching_ignores_case_and_trailing_dot(workflow: str):
    baseline = _baseline(workflow)
    listed = [t for t in baseline if t[2] in _ALLOWLISTABLE - {TargetKind.URL}]
    data = _with_config(_raw(workflow, "tp-approve-all"), _allowlist_override(listed, spell=_odd_spelling))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    leaked = sorted(f"{a.value}:{t}" for a, t, _k in listed if (a, t) in proposed)
    assert leaked == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_approved_rmm_and_dns_tool_indicators_are_never_blocked(workflow: str):
    """Hashes and domains of sanctioned tools (approved RMM, approved DNS tools) are never blocked."""
    baseline = _baseline(workflow)
    hashes = sorted({t for _a, t, k in baseline if k is TargetKind.HASH}
                    | {_host_rest for _a, t, k in baseline if k is TargetKind.FILE
                       for _host_rest in [t.split("/", 1)[1]]})
    domains = sorted({t for _a, t, k in baseline if k is TargetKind.DOMAIN})
    if not hashes and not domains:
        pytest.skip(f"{workflow} proposes no hash or domain block")
    base = _repo_allowlists()
    override = {"allowlists": {**base,
                               "approved_rmm": [{"name": "Lab RMM", "hashes": hashes, "domains": [], "signers": []}],
                               "approved_dns_tools": [{"name": "Lab DNS", "hashes": [], "domains": domains,
                                                       "signers": []}]}}
    data = _with_config(_raw(workflow, "tp-approve-all"), override)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    for action in package.actions if package else ():
        if action.target_kind is TargetKind.HASH:
            assert action.target not in hashes, f"approved RMM hash proposed: {action.action_type.value}"
        if action.target_kind is TargetKind.FILE:
            assert action.target.split("/", 1)[1] not in hashes, "approved RMM file proposed for quarantine"
        if action.target_kind is TargetKind.DOMAIN:
            assert action.target not in domains, "approved DNS tool domain proposed for blocking"


@pytest.mark.parametrize("workflow", ["malware", "ransomware"])
def test_binary_signed_by_an_approved_rmm_vendor_is_not_blocked(workflow: str):
    """An approved RMM tool is identified by hashes, domains and signers (config/allowlists.yaml). A
    build of the sanctioned tool whose hash is not listed yet but that carries the approved signer must
    not be recommended for a hash block or file quarantine."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    signer = _repo_allowlists()["approved_rmm"][0]["signers"][0]
    touched = False
    for record in _records(data):
        if record.get("kind") == "hash_prevalence":
            record["signer"] = signer
            touched = True
    if not touched:
        pytest.skip(f"{workflow} tp-approve-all has no hash prevalence record")
    signed = {r["sha256"].lower() for r in _records(data) if r.get("kind") == "hash_prevalence"}
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    blocked = sorted(f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
                     if (a.target_kind is TargetKind.HASH and a.target in signed)
                     or (a.target_kind is TargetKind.FILE and a.target.split("/", 1)[1] in signed))
    assert blocked == [], f"{workflow}: binary signed by approved RMM vendor {signer!r} proposed: {blocked}"


def test_phishing_never_proposes_blocking_the_organisations_own_domains():
    """Attacker-controlled message content naming the organisation's own domain (and a rated
    subdomain of it) must never lead to a domain block of an owned domain."""
    data = copy.deepcopy(_raw("phishing", "tp-approve-all"))
    own = ["login.example.com", "example.com"]
    data["environment"]["reputations"] += [
        {"type": "domain", "value": d, "verdict": "MALICIOUS", "risk_score": 90, "confidence": 85,
         "integrations": ["umbrella", "virustotal"], "summary": "lab"} for d in own]
    data["incident"]["observables"] += [{"type": "domain", "value": d} for d in own]
    for record in _records(data):
        if record.get("kind") == "email_message":
            record["domains"] = list(record.get("domains") or []) + own
    run = _detect(data, "phishing", "tp-approve-all", live=False)
    package = run.detection.package
    blocked = [a.target for a in package.actions if a.action_type is ActionType.BLOCK_DOMAIN
               and (a.target == "example.com" or a.target.endswith(".example.com"))]
    assert blocked == []


@pytest.mark.parametrize("workflow", ["password-spray", "account-takeover", "mfa-fatigue"])
def test_ipv4_mapped_ipv6_spelling_of_an_allowlisted_address_is_not_blocked(workflow: str):
    """192.0.2.0/28 is allow-listed core infrastructure. The same address written as an IPv4-mapped
    IPv6 address (``::ffff:192.0.2.5``) in a vendor sign-in record is the same host and must not
    become a block_ip that bypasses the allow-list."""
    baseline = _baseline(workflow)
    ips = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP]
    if not ips:
        pytest.skip(f"{workflow} proposes no block_ip")
    mapped = "::ffff:192.0.2.5"
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ips[0], mapped)
    for observable in data["incident"].get("observables") or ():
        if observable.get("value") == mapped:
            observable["type"] = "ipv6"
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    blocked = [a.target for a in (package.actions if package else ()) if a.action_type is ActionType.BLOCK_IP]
    assert all(not t.startswith("::ffff:") for t in blocked), (
        f"{workflow}: allow-listed 192.0.2.5 proposed for blocking as {blocked}")
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip" and (c[2] or "").startswith("::ffff:")]


# ============================================================ 5. critical assets come out ELEVATED --
def _critical_override(baseline: Iterable[tuple[ActionType, str, TargetKind]]) -> dict[str, Any]:
    hosts = sorted({_host_part(t) for _a, t, k in baseline
                    if k in (TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS)})
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    ips = sorted({f"{t}/32" for _a, t, k in baseline if k is TargetKind.IP})
    return {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": hosts, "users": users}},
        "production_server": {"match": {"ip_cidrs": ips or ["203.0.113.0/26"]}},
    }}}


_CRITICAL_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER, TargetKind.IP})


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_critical_asset_targets_are_elevated_with_a_warning_never_skipped(workflow: str):
    baseline = _baseline(workflow)
    critical = [t for t in baseline if t[2] in _CRITICAL_KINDS]
    assert critical, f"{workflow}: expected endpoint, user or IP targets in the baseline"
    data = _with_config(_raw(workflow, "tp-approve-all"), _critical_override(baseline))
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    assert package is not None
    by_key = {(a.action_type, a.target): a for a in package.actions}
    missing = [f"{a.value}:{t}" for a, t, _k in critical if (a, t) not in by_key]
    assert missing == [], f"{workflow}: critical targets silently skipped: {missing}"
    weak = [f"{a.value}:{t}" for a, t, _k in critical
            if by_key[(a, t)].approval_level is not ApprovalLevel.ELEVATED or not by_key[(a, t)].warnings]
    assert weak == [], f"{workflow}: critical targets without ELEVATED approval and warning: {weak}"
    with pytest.raises(ApprovalError):  # one analyst alone may not approve an ELEVATED package
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials("analyst"))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_critical_asset_known_only_from_vendor_records_is_elevated(workflow: str):
    """The critical-asset policy matches groups and directory roles. When the only place that says
    a host is a domain controller (group "Domain Controllers") or an account is a Global
    Administrator is the vendor record the workflow investigated, the action on it must still be
    ELEVATED with a warning."""
    baseline = _baseline(workflow)
    hosts = {_host_part(t) for _a, t, k in baseline if k in (TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS)}
    users = {t for _a, t, k in baseline if k is TargetKind.USER}
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked_hosts: set[str] = set()
    marked_users: set[str] = set()
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() in hosts:
            record["groups"] = list(record.get("groups") or []) + ["Domain Controllers"]
            marked_hosts.add(str(record["hostname"]).upper())
        if record.get("kind") == "user_profile" and str(record.get("user", "")).lower() in users:
            record["roles"] = list(record.get("roles") or []) + ["Global Administrator"]
            marked_users.add(str(record["user"]).lower())
    if not marked_hosts and not marked_users:
        pytest.skip(f"{workflow}: no endpoint or profile record for a proposed target")
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    assert package is not None
    weak = []
    for action in package.actions:
        host = _host_part(action.target) if action.target_kind in (
            TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS) else None
        user = action.target if action.target_kind is TargetKind.USER else None
        if (host in marked_hosts or user in marked_users) and (
                action.approval_level is not ApprovalLevel.ELEVATED or not action.warnings):
            weak.append(f"{action.action_type.value}:{action.target}")
    missing = [f"{a.value}:{t}" for a, t, k in baseline
               if (_host_part(t) in marked_hosts or t in marked_users)
               and not any((x.action_type, x.target) == (a, t) for x in package.actions)]
    assert missing == [], f"{workflow}: critical targets dropped: {missing}"
    assert weak == [], f"{workflow}: record-derived critical assets not ELEVATED: {weak}"


def _role_change_cases() -> list[Any]:
    return [pytest.param(w, id=w) for w in P2_WORKFLOWS
            if any(step.atomic == "search_user_activity" for step in CATALOG.get(w).definition.investigation)]


@pytest.mark.parametrize("workflow", _role_change_cases())
def test_account_granted_a_privileged_role_during_the_incident_is_elevated(workflow: str):
    """A directory role assignment the workflow itself found (search_user_activity, role_change
    "assigned Global Administrator") makes the account privileged now: every action on it is
    ELEVATED with a warning, never STANDARD and never dropped."""
    baseline = _baseline(workflow)
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    if not users:
        pytest.skip(f"{workflow}: no account action in the baseline")
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    suite = _scenario(data, workflow, "tp-approve-all").effective_suite()
    if "entra" not in suite:
        pytest.skip("entra is not simulated in this scenario")
    data["environment"]["records"] = list(data["environment"].get("records") or []) + [
        {"integration": "entra", "atomic": "search_user_activity", "subject": user,
         "record": {"kind": "role_change", "user": user, "role_name": "Global Administrator", "change": "assigned",
                    "actor": user, "timestamp": "2026-01-15T11:40:00Z"}} for user in users]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    on_users = [a for a in package.actions if a.target_kind is TargetKind.USER and a.target in users]
    missing = [f"{a.value}:{t}" for a, t, k in baseline if k is TargetKind.USER
               and not any((x.action_type, x.target) == (a, t) for x in package.actions)]
    assert missing == [], f"{workflow}: account actions dropped after a privileged role grant: {missing}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_users
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: newly privileged account not ELEVATED: {weak}"


# ======================================================= 6. evidence references real, relevant records --
def _all_scenarios() -> list[Any]:
    out = []
    for workflow in P2_WORKFLOWS:
        for path in sorted((FIXTURES / workflow).glob("*.yaml")):
            out.append(pytest.param(workflow, path.stem, id=f"{workflow}/{path.stem}"))
    return out


def _mentions(record: Any, needles: Iterable[str]) -> bool:
    text = json.dumps(record.rule_item(), default=str).lower()
    return any(n and n.lower() in text for n in needles)


def _needles(action: Any) -> list[str]:
    target = action.target
    if action.target_kind in (TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM):
        host, _, rest = target.partition("/")
        return [host, rest] if rest else [host]
    if action.target_kind is TargetKind.EMAIL_MESSAGE:
        return [target, target.strip("<>")]
    return [target]


@pytest.mark.parametrize("workflow, name", _all_scenarios())
def test_every_proposed_action_cites_a_record_about_its_target(workflow: str, name: str):
    """No invented facts: every package action cites numbered evidence from the run's own records, and
    at least one cited record is about the target itself (a record that never mentions the host,
    account, address or indicator cannot be the reason to contain it)."""
    run = _detect(_raw(workflow, name), workflow, name, live=False)
    package = run.detection.package
    wf = run.workflow_run
    assert wf is not None
    problems = []
    for action in package.actions if package else ():
        ids = [e.data.get("record_id") for e in action.evidence]
        unknown = [i for i in ids if i not in wf.index]
        if not ids or unknown:
            problems.append(f"{action.action_type.value}:{action.target}: unknown evidence {unknown or 'none'}")
            continue
        numbers = [getattr(e, "number", None) for e in action.evidence]
        if None in numbers or len(set(numbers)) != len(numbers):
            problems.append(f"{action.action_type.value}:{action.target}: evidence is not uniquely numbered: {numbers}")
        if not any(_mentions(wf.index.get(i), _needles(action)) for i in ids):
            problems.append(f"{action.action_type.value}:{action.target}: no cited record mentions the target")
        if type(action.risk_score) is not int or type(action.confidence_score) is not int:
            problems.append(f"{action.action_type.value}:{action.target}: scores are not separate integers")
    assert problems == []


# ======================================================== 7. degraded sources never block the rest --
def _degradation_cases() -> list[Any]:
    out = []
    for workflow in P2_WORKFLOWS:
        suite = _scenario(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all").effective_suite()
        for integration in sorted(suite):
            out.append(pytest.param(workflow, integration, id=f"{workflow}:{integration}"))
    return out


@pytest.mark.parametrize("workflow, failed", _degradation_cases())
def test_a_failed_source_does_not_block_actions_backed_by_other_sources(workflow: str, failed: str):
    """Fail every read of one integration (owner rule, architecture 14.14.1). An action whose evidence
    never came from it is still proposed; an action that also cites other sources whose records survive
    and name its target is proposed, or shown below threshold / considered with the failed source named;
    an action whose only evidence came from the failed source may be dropped, but never silently (a
    needs-investigation entry naming it when the run still knows the target, else the degraded-source
    note). No case is skipped: actions that cite the failed source alongside others are checked too."""
    findings = degradation_findings(_raw(workflow, "tp-approve-all"), failed,
                                    lambda data: _detect(data, workflow, "tp-approve-all", live=False))
    assert findings == [], f"{workflow}: failing {failed}: {findings}"


_IDENTITY_KINDS = frozenset({"sign_in", "mfa_event", "anomaly", "user_profile", "role_change"})


@pytest.mark.parametrize("workflow", ["account-takeover", "mfa-fatigue"])
def test_isolation_tied_to_an_account_compromise_cites_the_compromise_records(workflow: str):
    """The isolate_endpoint rationale of these workflows says the endpoint belongs to a compromised
    account. That claim must be backed by the cited evidence: at least one cited record shows the
    account compromise (sign-in, MFA event, anomaly, profile risk or role change), not only the
    endpoint's own detection."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=False)
    wf = run.workflow_run
    isolations = [a for a in run.detection.package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert isolations
    for action in isolations:
        kinds = {str(wf.index.get(e.data["record_id"]).kind) for e in action.evidence}
        assert kinds & _IDENTITY_KINDS, (
            f"{workflow}: isolate {action.target} claims an account compromise but cites only {sorted(kinds)}")


@pytest.mark.parametrize("workflow", ["account-takeover", "mfa-fatigue"])
def test_identity_outage_never_hides_an_active_malicious_detection_silently(workflow: str):
    """With the identity provider down, the incident's own endpoint still shows an active MALICIOUS
    detection (secure_endpoint answered). The run must not end with no recommendation and no word
    about it: either the isolation is still recommended or the run says why it was withheld."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": "UNAVAILABLE", "integration": "entra", "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    wf = run.workflow_run
    assert any(str(r.kind) == "detection" for r in (wf.index.get(i) for i in wf.index.ids())), "precondition"
    package = run.detection.package
    proposed = any(a.action_type is ActionType.ISOLATE_ENDPOINT and a.target == "TH-LT-1047"
                   for a in (package.actions if package else ()))
    mentioned = any("TH-LT-1047" in n for n in wf.notes) or any("TH-LT-1047" in c.subject for c in wf.considered)
    assert proposed or mentioned, (
        f"{workflow}: entra outage silently dropped the isolation of TH-LT-1047 (active MALICIOUS detection)")


# =============================================================== 8. partial failures are reported --
@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_one_failing_action_reports_partially_contained(workflow: str):
    baseline = _baseline(workflow)
    action_type, target, _kind = baseline[-1]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data.setdefault("environment", {}).setdefault("faults", [])
    data["environment"]["faults"] = list(data["environment"]["faults"]) + [
        {"kind": "FAIL", "operation": action_type.value, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report is not None
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED, (
        f"{workflow}: one failed action ({action_type.value} {target}) reported {decision.report.overall}")
    statuses = {(r.action_type, r.target): r.status.value for r in decision.report.results}
    assert statuses.get((action_type, target)) == "FAILED"
    assert any(v == "SUCCESS" for k, v in statuses.items() if k != (action_type, target))


# ============================================================= 9. release: approval and ownership --
_REVERSIBLE = frozenset({ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL,
                         ActionType.BLOCK_IP, ActionType.BLOCK_HASH, ActionType.DISABLE_USER,
                         ActionType.QUARANTINE_EMAIL, ActionType.QUARANTINE_FILE})


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_release_needs_release_approval_and_never_touches_preexisting_controls(workflow: str):
    baseline = _baseline(workflow)
    reversible = [(a, t) for a, t, _k in baseline if a in _REVERSIBLE]
    assert len(reversible) >= 2, f"{workflow}: need two reversible actions for this test"
    pre_action, pre_target = reversible[0]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data.setdefault("environment", {}).setdefault("preexisting", [])
    data["environment"]["preexisting"] = list(data["environment"]["preexisting"]) + [
        {"action_type": pre_action.value, "target": pre_target}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls, f"{workflow}: approved containment created no temporary control"
    assert all(c.incident_id == run.incident_id for c in controls)
    assert not [c for c in controls if (c.action_type, c.target) == (pre_action, pre_target)], (
        "a control was registered for a target that was already contained before this incident")
    assert all(c.action_type is not ActionType.REVOKE_SESSIONS for c in controls)

    calls_before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls_before, "proposing a release changed state"
    assert set(release.control_keys) <= {c.control_key for c in controls}
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_release_decision(
                run._request(release, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"), run.credentials(alias))
    assert len(run.environment.state_changing_calls()) == calls_before

    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    assert run.environment.in_desired_state(pre_action, pre_target), (
        f"{workflow}: release undid {pre_action.value} {pre_target}, which this incident did not create")
    restore_calls = run.environment.state_changing_calls()[calls_before:]
    released_targets = {(c.target or "").lower() for c in restore_calls}
    created_targets = {c.target.lower() for c in controls}
    assert released_targets <= created_targets, (
        f"{workflow}: release touched {sorted(released_targets - created_targets)} outside this incident's controls")


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_containment_approval_cannot_be_reused_as_release_approval(workflow: str):
    """Restoration needs its own human release approval: submitting the containment package id as a
    release decision, or a release decision before any release package exists, changes nothing."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    calls_before = len(run.environment.state_changing_calls())
    containment = run.detection.package
    with pytest.raises(Exception):  # noqa: B017 - any refusal is fine; executing a restore is not
        run.orchestrator.submit_release_decision(
            run._request(containment, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
            run.credentials("analyst", "lead"))
    assert len(run.environment.state_changing_calls()) == calls_before
    assert all(c.status.value == "ACTIVE" for c in run.runtime.registry.list(incident_id=run.incident_id))


# ===================================================== 10. no secrets or needless personal data out --
def _plant_secrets(workflow: str) -> dict[str, Any]:
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = False
    for record in _records(data):
        kind = record.get("kind")
        if kind == "mailbox_rule":
            record["name"] = f"Invoices password={SECRET_PASSWORD}"
            planted = True
        elif kind == "detection":
            record["name"] = f"Infostealer unlock code: {SECRET_UNLOCK}"
            planted = True
        elif kind == "anomaly":
            record["detail"] = f"token={SECRET_TOKEN} seen in sign-in"
            planted = True
        elif kind == "sign_in" and record.get("result") == "failure":
            record["failure_reason"] = f"Authorization: Bearer {SECRET_TOKEN}"
            planted = True
        elif kind == "email_message":
            record["subject_line"] = f"Reset: your password={SECRET_PASSWORD}"
            planted = True
        elif kind == "process_event":
            record["command_line"] = f"tool.exe --password {SECRET_PASSWORD} --token={SECRET_TOKEN}"
            planted = True
    if not planted:
        pytest.skip(f"{workflow}: no free-text record field to plant a fake secret in")
    return data


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_planted_credentials_never_reach_packages_summaries_notifications_or_audit(workflow: str):
    data = _plant_secrets(workflow)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    text = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_UNLOCK, SECRET_TOKEN) if s in text]
    assert leaked == [], f"{workflow}: planted secret(s) {leaked} reached analyst-facing output or audit"


@pytest.mark.parametrize("workflow", ["bec", "mfa-fatigue", "mail-bombing"])
def test_mailbox_rule_name_with_a_credential_is_redacted_in_rationale(workflow: str):
    """Mailbox rule names are attacker-controlled free text (MailboxRuleRecord.name is not a redacted
    field type); a hook that quotes them into a reason must not carry a credential into the package
    rationale, the summary or the notes."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = False
    for record in _records(data):
        if record.get("kind") == "mailbox_rule":
            record["name"] = f"sync password={SECRET_PASSWORD}"
            planted = True
    if not planted:
        pytest.skip(f"{workflow}: tp-approve-all has no mailbox rule record")
    run = _detect(data, workflow, "tp-approve-all", live=False)
    text = _outputs_text(run, audit=False)
    assert SECRET_PASSWORD not in text


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_profile_details_the_analyst_does_not_need_stay_out_of_the_package_and_notifications(workflow: str):
    """User profiles carry manager, job title and display name. None of it is needed to approve a
    containment action, so none of it may appear in the package or in a notification."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    manager, title, phone_name = "mgr.private.lab@example.com", "Lab Title Zeta Omega", "Pat Q. Labperson"
    planted = False
    for record in _records(data):
        if record.get("kind") == "user_profile":
            record.update({"manager": manager, "job_title": title, "display_name": phone_name})
            planted = True
    if not planted:
        pytest.skip(f"{workflow}: no user profile record")
    run = _detect(data, workflow, "tp-approve-all", live=False)
    text = _outputs_text(run, audit=False)
    leaked = [v for v in (manager, title, phone_name) if v in text]
    assert leaked == [], f"{workflow}: profile details {leaked} reached the package or notifications"


@pytest.mark.parametrize("workflow", ["malware", "ransomware"])
def test_space_separated_password_flag_in_a_command_line_is_redacted_in_package_evidence(workflow: str):
    """Process command lines are cited as package evidence. A credential passed as a separate
    argument (``--password VALUE``) is as sensitive as ``--password=VALUE`` and must be redacted
    before it reaches the package, the PACKAGE_PROPOSED audit record or a notification."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = False
    for record in _records(data):
        if record.get("kind") == "process_event":
            record["command_line"] = f"{record.get('command_line') or 'tool.exe'} --password {SECRET_PASSWORD}"
            planted = True
    if not planted:
        pytest.skip(f"{workflow}: no process event")
    run = _detect(data, workflow, "tp-approve-all", live=False)
    assert SECRET_PASSWORD not in run.detection.package.model_dump_json()
    proposed = [r for r in run.runtime.audit.records(run.incident_id)
                if r.event_type is AuditEventType.PACKAGE_PROPOSED]
    assert proposed and all(SECRET_PASSWORD not in r.model_dump_json() for r in proposed)


# ======================================================== 11. hooks cannot smuggle actions or approvals --
@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_hand_offs_and_considerations_never_start_anything(workflow: str):
    """A hand-off or a consideration is a note: it never starts a workflow, never adds an action to
    the package and never creates a second package."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    wf = run.workflow_run
    package = run.detection.package
    proposed = {f"{a.action_type.value}:{a.target}" for a in package.actions}
    considered = {c.subject for c in wf.considered if ":" in c.subject}
    assert not (considered & proposed), f"withheld actions also proposed: {sorted(considered & proposed)}"
    packages = [r for r in run.runtime.audit.records(run.incident_id)
                if r.event_type is AuditEventType.PACKAGE_PROPOSED]
    assert len(packages) == 1
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_rerunning_detection_after_containment_does_not_execute_without_new_approval(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    calls_before = len(run.environment.state_changing_calls())
    try:
        run.orchestrator.handle_detection(run.workflow_scenario.incident)
    except Exception:  # noqa: BLE001 - refusing a second detection is fine
        pass
    assert len(run.environment.state_changing_calls()) == calls_before


# =====================================================================================================
# Phase 2 round 2 (lens: workflow safety). Same rules as round 1: every test asserts the SAFE
# behaviour, so a failing test is a defect. The probes below vary spellings and identities that the
# round-1 tests kept fixed (FQDN host names, URL spellings, the process of a sanctioned binary,
# non-public addresses, internal domains, executive users of endpoints and mailboxes) and attack the
# mail-bombing workflow's own job (never bury a security notice, never leak the code it carries).
# =====================================================================================================
_FQDN_SUFFIX = ".corp.example.com"
_HOST = "TH-LT-1047"
_EXECUTIVE = "ceo@example.com"  # config/critical-assets.yaml executive_endpoint.match.users
_ENDPOINT_KINDS = (TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM)


def _text_replace(node: Any, old: str, new: str) -> Any:
    """Replace a substring in every string of a scenario fragment (keys untouched)."""
    if isinstance(node, str):
        return node.replace(old, new)
    if isinstance(node, list):
        return [_text_replace(v, old, new) for v in node]
    if isinstance(node, dict):
        return {k: _text_replace(v, old, new) for k, v in node.items()}
    return node


def _on_host(action: Any, host: str) -> bool:
    return (action.target_kind in _ENDPOINT_KINDS
            and _host_part(action.target).upper().split(".", 1)[0] == host.upper())


# ============================================== R2-1. allow-list and critical class by host FQDN --
@pytest.mark.parametrize("workflow", ["malware", "phishing", "ransomware"])
def test_allowlisted_endpoint_reported_by_its_fqdn_is_never_contained(workflow: str):
    """Endpoint agents commonly report a host by its fully qualified name. ``TH-LT-1047`` is
    allow-listed (never_block.endpoints) and the vendor records name it
    ``TH-LT-1047.corp.example.com``: the same machine, so it must never be isolated, nor its processes
    terminated or files quarantined, and approving the package must not touch it."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = _text_replace(data["environment"]["records"], _HOST, _HOST + _FQDN_SUFFIX)
    endpoints = list((_repo_allowlists().get("never_block") or {}).get("endpoints") or []) + [_HOST]
    data = _with_config(data, {"allowlists": {"never_block": {"endpoints": endpoints}}})
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    leaked = sorted(f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
                    if _on_host(a, _HOST))
    assert leaked == [], f"{workflow}: allow-listed {_HOST} proposed under its FQDN: {leaked}"
    if package is not None and package.actions:
        _approve_all(run)
    touched = [c for c in _state_calls(run) if (c[2] or "").upper().startswith(_HOST)]
    assert touched == [], f"{workflow}: state-changing calls on allow-listed {_HOST}: {touched}"


@pytest.mark.parametrize("workflow", ["malware", "phishing", "ransomware"])
def test_critical_endpoint_reported_by_its_fqdn_is_elevated(workflow: str):
    """A critical-asset class that names the host exactly (``hostnames: [TH-LT-1047]``) must still
    make every action on that host ELEVATED with a warning when the vendor reports its FQDN."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = _text_replace(data["environment"]["records"], _HOST, _HOST + _FQDN_SUFFIX)
    data = _with_config(data, {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": [_HOST]}}}}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    on_host = [a for a in (package.actions if package else ()) if _on_host(a, _HOST)]
    assert on_host, f"{workflow}: precondition, an action on {_HOST} is proposed"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: critical host under its FQDN not ELEVATED: {weak}"


# ======================================================== R2-2. allow-listed URL in another spelling --
_URL_CASES = [("phishing", "legacy-05-malicious-url-on-legitimate-host"),
              ("ransomware", "edge-email-origin-campaign"),
              ("malware", "edge-defender-managed-endpoint")]
_URL_LABELS = ("upper-case scheme and host", "explicit default port", "trailing dot on the host")


def _url_spelling(url: str, label: str) -> str:
    scheme, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    port = "443" if scheme.lower() == "https" else "80"
    return {"upper-case scheme and host": f"{scheme.upper()}://{host.upper()}/{path}",
            "explicit default port": f"{scheme}://{host}:{port}/{path}",
            "trailing dot on the host": f"{scheme}://{host}./{path}"}[label]


@pytest.mark.parametrize("workflow, name", _URL_CASES)
@pytest.mark.parametrize("label", _URL_LABELS)
def test_allowlisted_url_in_an_equivalent_spelling_is_not_blocked(workflow: str, name: str, label: str):
    """``never_block.urls`` lists a URL. A vendor record that writes the same URL with an upper-case
    scheme or host, the default port or a trailing dot on the host (the same resource) must not
    produce a block_url that bypasses the allow-list."""
    first = _detect(_raw(workflow, name), workflow, name, live=False)
    urls = [a.target for a in first.detection.package.actions if a.action_type is ActionType.BLOCK_URL]
    guard._reset_for_test_harness()
    assert urls, f"{workflow}/{name}: precondition, the scenario proposes a block_url"
    url = urls[0]
    spelled = _url_spelling(url, label)
    data = json.loads(json.dumps(_raw(workflow, name)).replace(url, spelled))
    data = _with_config(data, {"allowlists": {"never_block": {"urls": [url]}}})
    run = _detect(data, workflow, name, live=False)
    package = run.detection.package
    leaked = [a.target for a in (package.actions if package else ())
              if a.action_type is ActionType.BLOCK_URL and a.target in (url, spelled)]
    assert leaked == [], f"{workflow}: allow-listed {url} proposed for blocking as {leaked} ({label})"


# ===================================== R2-3. the running process of a sanctioned binary is not killed --
_MALWARE_HASH = "5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e5ca1ab1e"


def _hash_listing(section: str) -> dict[str, Any]:
    if section == "never_block.hashes":
        return {"allowlists": {"never_block": {"hashes": [_MALWARE_HASH]}}}
    return {"allowlists": {section: [{"name": "Lab sanctioned tool", "hashes": [_MALWARE_HASH], "domains": [],
                                      "signers": []}]}}


@pytest.mark.parametrize("section", ["never_block.hashes", "approved_rmm", "approved_dns_tools"])
def test_process_of_an_allowlisted_or_approved_tool_hash_is_never_terminated(section: str):
    """When the binary's SHA-256 is allow-listed or belongs to an approved tool, the hash block and
    the file quarantine are excluded; the running process of that very binary (``<HOST>/<pid>``,
    whose process events carry the hash) must not be terminated either, and approving must not kill
    it."""
    data = _with_config(_raw("malware", "tp-approve-all"), _hash_listing(section))
    run = _detect(data, "malware", "tp-approve-all", live=True)
    package = run.detection.package
    outcomes = run.workflow_run.outcomes
    # block_hash and terminate_process have no VERIFIED write in this lab (production parity, architecture
    # 14.14.3 and 15.2): an excluded hash shows as an unrouted outcome marked "never block it by hand", and
    # a termination would be recommended for manual handling as an UNROUTED outcome. Both count here.
    excluded = {(e.action_type, e.target) for e in package.excluded_targets} | {
        (o.action_type, o.target) for o in outcomes
        if o.status is RuleOutcomeStatus.UNROUTED and "never block it by hand" in o.detail}
    assert (ActionType.BLOCK_HASH, _MALWARE_HASH) in excluded, "precondition: the hash itself is excluded"
    killed = [a.target for a in package.actions if a.action_type is ActionType.TERMINATE_PROCESS] + [
        o.target for o in outcomes if o.action_type is ActionType.TERMINATE_PROCESS
        and o.status is RuleOutcomeStatus.UNROUTED and "never block it by hand" not in o.detail]
    assert killed == [], f"{section}: process of the sanctioned binary recommended for termination: {killed}"
    assert any(o.action_type is ActionType.TERMINATE_PROCESS and o.status is RuleOutcomeStatus.ALLOWLISTED
               for o in outcomes), f"{section}: the withheld termination must be shown, never silently dropped"
    if package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "terminate_process"], (
        f"{section}: the sanctioned binary's process was terminated after approval")


# ========================================================== R2-4. non-public addresses are not blocked --
_NON_PUBLIC = ["10.20.30.40", "127.0.0.1", "169.254.10.10", "100.64.1.9"]


@pytest.mark.parametrize("workflow", ["account-takeover", "mfa-fatigue", "password-spray", "malware", "ransomware"])
@pytest.mark.parametrize("address", _NON_PUBLIC)
def test_non_public_address_is_never_a_standard_ip_block(workflow: str, address: str):
    """A private, loopback, link-local or carrier-grade-NAT address (100.64.0.0/10 is the
    remote-access VPN pool in config/exclusions.yaml) is the organisation's own network (a NAT, proxy,
    VPN pool or federation server), never edge-blockable attacker infrastructure. Put in place of the
    attacker IP of each workflow's true-positive scenario (vendor ratings kept), it must not become a
    silent STANDARD block_ip: withhold it (as malware and mfa-fatigue do) or at least require ELEVATED
    approval with a warning."""
    baseline = _baseline(workflow)
    attacker = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP][0]
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), attacker, address)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type is ActionType.BLOCK_IP and a.target == address
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: non-public address {address} proposed as a STANDARD block_ip"


@pytest.mark.parametrize("address", _NON_PUBLIC)
def test_password_spray_never_blocks_an_unrated_non_public_source(address: str):
    """The classic false positive: on a federated or proxied tenant every failed sign-in carries the
    address of the organisation's own proxy. An unrated non-public spray source must never become a
    STANDARD block_ip (blocking it cuts every user off)."""
    baseline = _baseline("password-spray")
    attacker = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP][0]
    data = _walk_replace(copy.deepcopy(_raw("password-spray", "tp-approve-all")), attacker, address)
    data["environment"]["reputations"] = [r for r in data["environment"].get("reputations") or ()
                                          if r.get("value") != address]
    run = _detect(data, "password-spray", "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type is ActionType.BLOCK_IP and a.target == address
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"password-spray: unrated non-public source {address} proposed as a STANDARD block"


# ======================================================== R2-5. the organisation's internal domains --
@pytest.mark.parametrize("workflow", ["malware", "mail-bombing", "phishing", "ransomware"])
@pytest.mark.parametrize("internal", ["update.example.internal", "printer.local"])
def test_internal_domain_declared_by_configuration_is_never_silently_blocked(workflow: str, internal: str):
    """config/exclusions.yaml declares the organisation's own internal domains (``internal_domains``:
    example.internal; ``internal_domain_suffixes``: ..., local). Blocking one at the DNS layer takes
    down internal services, so a rated name under them must never become a STANDARD block without an
    exclusion or an ELEVATED warning."""
    baseline = _baseline(workflow)
    domain = [t for a, t, _k in baseline if a is ActionType.BLOCK_DOMAIN][0]
    data = json.loads(json.dumps(_raw(workflow, "tp-approve-all")).replace(domain, internal))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type in (ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL) and internal in a.target
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: internal domain {internal} proposed as a STANDARD block: {weak}"


# ======================================================= R2-6. executive endpoints and mailboxes --
@pytest.mark.parametrize("workflow", [w for w in P2_WORKFLOWS if w != "password-spray"])
def test_endpoint_used_by_an_executive_is_elevated(workflow: str):
    """critical-assets.yaml ``executive_endpoint`` ("Endpoint, mailbox or account used by an
    executive") matches users ceo@ and cfo@. When the endpoint record says the CEO uses the host, every
    action on that host is ELEVATED with a warning, never STANDARD."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == _HOST:
            record["users"] = list(record.get("users") or []) + [_EXECUTIVE]
            marked = True
    assert marked, f"{workflow}: precondition, an endpoint record for {_HOST}"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    on_host = [a for a in (package.actions if package else ()) if _on_host(a, _HOST)]
    assert on_host, f"{workflow}: precondition, an action on {_HOST}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: the CEO's endpoint is contained at STANDARD approval: {weak}"


@pytest.mark.parametrize("workflow, user", [("mail-bombing", "jsmith@example.com"),
                                            ("phishing", "ap-clerk-01@example.com")])
def test_quarantine_in_an_executive_mailbox_is_elevated(workflow: str, user: str):
    """The executive class also covers the executive's mailbox (14.10.4: "Executive or VIP asset").
    Quarantining messages out of the CEO's mailbox affects that critical asset and must be ELEVATED
    with a warning, as the revocation and disable of the same account already are."""
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), user, _EXECUTIVE)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    in_mailbox: set[str] = set()
    for record in _records(data):
        if record.get("kind") == "email_message" and _EXECUTIVE in (record.get("recipients") or []):
            in_mailbox |= {str(record.get("message_id")), str(record.get("internet_message_id"))}
    quarantines = [a for a in package.actions
                   if a.action_type is ActionType.QUARANTINE_EMAIL and a.target in in_mailbox]
    assert quarantines, f"{workflow}: precondition, a quarantine in {_EXECUTIVE}'s mailbox"
    weak = [a.target for a in quarantines if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: quarantine in the CEO's mailbox at STANDARD approval: {weak}"


# ===================================================== R2-7. mail-bombing: buried security notices --
_BURIED = "etd-mb-0011-003"  # the password-reset notice of mail-bombing/edge-buried-messages-kept


@pytest.mark.parametrize("subject", ["Your password has been reset", "Your security code", "Your sign-in code",
                                     "Your one-time passcode", "Two-step verification turned off",
                                     "Password reset requested for your account"])
def test_mail_bombing_never_quarantines_a_buried_security_notice(subject: str):
    """The point of a mail bomb is to bury a security notice (a password reset, a sign-in code, a
    two-step change). Such a notice inside the flood must never go into the flood quarantine (that
    finishes the attacker's job and hides the event from the user); it is kept and shown as
    considered."""
    data = copy.deepcopy(_raw("mail-bombing", "edge-buried-messages-kept"))
    for record in _records(data):
        if record.get("message_id") == _BURIED:
            record["subject_line"] = subject
    run = _detect(data, "mail-bombing", "edge-buried-messages-kept", live=False)
    package = run.detection.package
    quarantined = [a.target for a in package.actions
                   if a.action_type is ActionType.QUARANTINE_EMAIL and a.target == _BURIED]
    assert quarantined == [], f"security notice {subject!r} proposed for quarantine with the flood"
    assert f"quarantine_email:{_BURIED}" in {c.subject for c in run.workflow_run.considered}, (
        f"security notice {subject!r} is not shown as kept for the analyst")


@pytest.mark.parametrize("subject", ["Your verification code is 482913", "Password reset code: 482913",
                                     "Your new password is Hunter2LabSecret77"])
def test_mail_bombing_code_in_a_buried_notice_never_reaches_outputs_or_audit(subject: str):
    """A buried notice's subject can carry the one-time code or temporary password itself. That is a
    credential: it may not reach the package, the notes, the notifications or the (append-only,
    never editable) audit trail."""
    data = copy.deepcopy(_raw("mail-bombing", "edge-buried-messages-kept"))
    for record in _records(data):
        if record.get("message_id") == _BURIED:
            record["subject_line"] = subject
    run = _detect(data, "mail-bombing", "edge-buried-messages-kept", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    secret = SECRET_PASSWORD if SECRET_PASSWORD in subject else "482913"
    assert secret not in _outputs_text(run), (
        f"code from {subject!r} reached analyst-facing output or the audit trail")


# ================================================= R2-8. guarantees that hold (kept as guard rails) --
@pytest.mark.parametrize("workflow", [w for w in P2_WORKFLOWS if w != "password-spray"])
@pytest.mark.parametrize("mark", ["ip_in_critical_cidr", "production_tag"])
def test_endpoint_critical_by_vendor_ip_or_tag_is_elevated(workflow: str, mark: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "endpoint":
            if mark == "ip_in_critical_cidr":
                record["ip_addresses"] = ["203.0.113.10"]  # production_server ip_cidrs 203.0.113.0/26
            else:
                record["tags"] = list(record.get("tags") or []) + ["production"]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_hosts = [a for a in run.detection.package.actions if a.target_kind in _ENDPOINT_KINDS]
    assert on_hosts
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in on_hosts)


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_incident_asset_context_makes_actions_elevated(workflow: str):
    baseline = _baseline(workflow)
    hosts = sorted({_host_part(t) for _a, t, k in baseline if k in _ENDPOINT_KINDS})
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["incident"]["assets"] = ([{"name": h, "kind": "ENDPOINT", "tags": ["production"]} for h in hosts]
                                  + [{"name": u, "kind": "USER", "groups": ["Executives"]} for u in users])
    run = _detect(data, workflow, "tp-approve-all", live=False)
    weak = [f"{a.action_type.value}:{a.target}" for a in run.detection.package.actions
            if ((a.target_kind in _ENDPOINT_KINDS and _host_part(a.target) in hosts)
                or (a.target_kind is TargetKind.USER and a.target in users))
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == []


def test_ransomware_isolation_beyond_the_endpoint_cap_is_elevated():
    """blast_radius.max_endpoints (5): a payload staged on ten hosts makes every isolation ELEVATED."""
    data = copy.deepcopy(_raw("ransomware", "tp-approve-all"))
    hosts = [f"TH-LT-{2000 + i}" for i in range(8)]
    for record in _records(data):
        if record.get("kind") == "hash_prevalence":
            record["endpoints"] = list(record["endpoints"]) + hosts
            record["prevalence"] = len(record["endpoints"])
    data["environment"]["records"] += [
        {"integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": h,
         "record": {"kind": "endpoint", "hostname": h, "os": "Windows 11", "groups": ["Workstations"],
                    "isolation_capable": True, "isolation_state": "not_isolated"}} for h in hosts]
    run = _detect(data, "ransomware", "tp-approve-all", live=False)
    isolations = [a for a in run.detection.package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert len(isolations) > 5
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in isolations)


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_without_any_record_or_rating_nothing_is_recommended(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    data["environment"]["reputations"] = []
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    assert package is None or not package.actions
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_package_proposed_under_dry_run_never_executes_live_after_dry_run_is_switched_off(workflow: str):
    run = _run(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    guard.configure(dry_run=True)
    run.detect()
    assert run.detection.package.dry_run
    guard.configure(dry_run=False)
    try:
        decision = _approve_all(run)
        assert decision.report is None or decision.report.dry_run
    except ApprovalError:  # refusing is fine; executing live is not
        pass
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_rejected_package_cannot_be_approved_afterwards(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": "REJECT", "comment": "lab rejection"}, approvers=_approvers(package))
    with pytest.raises(Exception):  # noqa: B017 - any refusal is fine; executing is not
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials(*_approvers(package)))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
def test_release_of_elevated_controls_needs_the_elevated_approver(workflow: str):
    baseline = _baseline(workflow)
    data = _with_config(_raw(workflow, "tp-approve-all"), _critical_override(baseline))
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    release = run.propose_release()
    assert any(a.approval_level is ApprovalLevel.ELEVATED for a in release.actions)
    before = len(run.environment.state_changing_calls())
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert len(run.environment.state_changing_calls()) == before


@pytest.mark.parametrize("workflow", ["malware", "password-spray"])
def test_release_warns_when_another_incident_relies_on_the_control(workflow: str):
    from xdr_response.models import DecisionRequest, DecisionType

    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    other = run.workflow_scenario.incident.model_copy(update={"incident_id": run.incident_id + "-B"})
    second = run.orchestrator.handle_detection(other).package
    run.orchestrator.submit_decision(DecisionRequest(package_id=second.package_id, decision=DecisionType.APPROVE_ALL),
                                     run.credentials(*_approvers(second)))
    release = run.propose_release()
    assert release.actions
    for action in release.actions:
        assert action.approval_level is ApprovalLevel.ELEVATED
        assert any(other.incident_id in w.message for w in action.warnings)


@pytest.mark.parametrize("workflow", P2_WORKFLOWS)
@pytest.mark.parametrize("fault", ["NO_EFFECT", "TIMEOUT", "AUTH_FAIL", "RATE_LIMIT", "INVALID_TARGET"])
def test_any_failed_or_ineffective_first_action_reports_partially_contained(workflow: str, fault: str):
    baseline = _baseline(workflow)
    action_type, target, _kind = baseline[0]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": fault, "operation": action_type.value, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED
