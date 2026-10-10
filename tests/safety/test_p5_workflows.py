"""Adversarial safety tests, Phase 5 round 1, lens: workflow safety.

Every test asserts the SAFE behaviour required by docs/architecture.md (sections 13 and 14, as built
in 14.13) for the four Phase 5 workflows (privilege-escalation, vulnerability-exploitation,
web-attacks, threat-intel-sweep), so a failing test is a defect. The tests start from each workflow's
own scenario fixtures and mutate them the way an attacker, a poisoned threat feed or an unlucky
configuration would: allow-list the targets, mark them critical, sanction the tool, fail a source,
fail an action, pre-contain a target, put the organisation's own infrastructure into the feed, put
credential-looking text into vendor records, and so on.

Fake data only: documentation IPs, example domains, fake hashes, hosts like TH-LT-1047 and users like
jsmith@example.com. Nothing here talks to a network or a real vendor; the simulated lab adapters
record every call they receive. Attacker behaviour is described abstractly.
"""
from __future__ import annotations

import ast
import copy
import json
from collections.abc import Callable, Iterable, Mapping
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

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "workflows"
PACKAGE_DIR = REPO_ROOT / "src" / "xdr_response" / "workflows"
CATALOG = discover_workflows()
P5_WORKFLOWS = ("privilege-escalation", "vulnerability-exploitation", "web-attacks", "threat-intel-sweep")
#: Workflows whose baseline proposes a host isolation.
ENDPOINT_WORKFLOWS = P5_WORKFLOWS
#: Workflows whose baseline proposes a block_ip.
IP_WORKFLOWS = ("vulnerability-exploitation", "web-attacks", "threat-intel-sweep")
#: Workflows whose baseline proposes a block_url.
URL_WORKFLOWS = ("vulnerability-exploitation", "web-attacks", "threat-intel-sweep")
#: Workflows whose baseline proposes account actions.
ACCOUNT_WORKFLOWS = ("privilege-escalation", "threat-intel-sweep")

_EXECUTION_EVENTS = frozenset({AuditEventType.ACTION_STARTED, AuditEventType.ACTION_RESULT,
                               AuditEventType.CONTROL_REGISTERED, AuditEventType.VERIFICATION_RESULT,
                               AuditEventType.CONTAINMENT_COMPLETED, AuditEventType.RESTORATION_RESULT})

SECRET_PASSWORD = "Hunter2LabSecret77"
SECRET_UNLOCK = "48151623"
SECRET_TOKEN = "lab-bearer-token-ZX9QW8ER7TY6"

_ENDPOINT_KINDS = (TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM)
_PROD_LEAD = ["analyst", "lead"]
_TIS = "threat-intel-sweep"
_TIS_HASH = "7e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c57e3a91c5"
_TIS_IP = "198.51.100.77"
_TIS_DOMAIN = "update-relay.test"
_APPROVED_RMM_HASH = "1111111111111111111111111111111111111111111111111111111111111111"


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
    run = _detect(_raw(workflow, name), workflow, name, live=False)
    package = run.detection.package
    guard._reset_for_test_harness()
    assert package is not None, f"{workflow}/{name}: the unmodified scenario must propose a package"
    return [(a.action_type, a.target, a.target_kind) for a in package.actions]


def _approvers(package: Any) -> list[str]:
    return list(_PROD_LEAD) if package.has_elevated else ["analyst"]


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


def _text_replace(node: Any, old: str, new: str) -> Any:
    if isinstance(node, str):
        return node.replace(old, new)
    if isinstance(node, list):
        return [_text_replace(v, old, new) for v in node]
    if isinstance(node, dict):
        return {k: _text_replace(v, old, new) for k, v in node.items()}
    return node


def _records(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [r["record"] for r in (data.get("environment") or {}).get("records") or ()]


def _isolated_host(workflow: str) -> str:
    hosts = [t for a, t, _k in _baseline(workflow) if a is ActionType.ISOLATE_ENDPOINT]
    assert hosts, f"{workflow}: precondition, an isolation in the baseline"
    return hosts[0]


def _on_host(action: Any, host: str) -> bool:
    return (action.target_kind in _ENDPOINT_KINDS
            and _host_part(action.target).upper().split(".", 1)[0] == host.upper().split(".", 1)[0])


def _outputs_text(run: WorkflowScenarioRun, *, audit: bool = True) -> str:
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
        parts.extend(c.model_dump_json() if hasattr(c, "model_dump_json") else json.dumps(str(c))
                     for c in wf.considered)
        parts.extend(h.model_dump_json() if hasattr(h, "model_dump_json") else json.dumps(str(h))
                     for h in (getattr(wf, "handoffs", ()) or ()))
    for draft in run.outbox.drafts:
        parts.append(draft.model_dump_json())
    decision = getattr(run, "decision", None)
    if decision is not None and getattr(decision, "report", None) is not None:
        parts.append(decision.report.model_dump_json())
    if audit:
        for record in run.runtime.audit.records(run.incident_id):
            parts.append(record.model_dump_json())
    return "\n".join(parts)


def _considered_subjects(run: WorkflowScenarioRun) -> set[str]:
    return {c.subject for c in run.workflow_run.considered}


def _proposed(run: WorkflowScenarioRun) -> list[str]:
    package = run.detection.package
    return [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())]


def _weak(action: Any) -> bool:
    """True when the action is proposed at STANDARD approval or without a visible warning."""
    return action.approval_level is not ApprovalLevel.ELEVATED or not action.warnings


def _all_fixtures() -> list[Any]:
    return [pytest.param(w, p.stem, id=f"{w}/{p.stem}") for w in P5_WORKFLOWS
            for p in sorted((FIXTURES / w).glob("*.yaml"))]


# ============================================================ 1. no state change without approval --
@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
@pytest.mark.parametrize("decision", ["REJECT", "REQUEST_MORE_INVESTIGATION"])
def test_live_detection_and_non_approving_decision_never_change_state(workflow: str, decision: str):
    """Investigation and recommendation are automatic; nothing state-changing happens (session
    revocation and role removal included) until a human approves, and a rejection or a request for more
    investigation never executes anything."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    assert run.detection.package is not None
    assert _state_calls(run) == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": decision, "comment": "lab decision"}, approvers=_approvers(package))
    assert _state_calls(run) == [], f"{workflow}: {decision} executed state-changing calls"
    assert run.runtime.registry.list(incident_id=run.incident_id) == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))


@pytest.mark.parametrize("workflow, name", _all_fixtures())
def test_detection_alone_never_changes_state_for_any_scenario(workflow: str, name: str):
    """Every Phase 5 scenario, live: detection (investigation, scoring, package, notifications) reaches
    no vendor with anything but reads and registers no control."""
    run = _detect(copy.deepcopy(_raw(workflow, name)), workflow, name, live=True)
    writes = sorted({(c.kind.value, c.integration, c.operation) for c in run.environment.calls
                     if c.kind.value != "READ"})
    assert writes == [], f"{workflow}/{name}: detection reached vendors with {writes}"
    assert run.runtime.registry.list() == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_non_human_principals_cannot_approve_any_workflow_package(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                             run.credentials(alias))
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                             run.credentials("analyst", alias))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
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
    files = sorted((PACKAGE_DIR / workflow.replace("-", "_")).glob("*.py"))
    assert files, f"{workflow}: package not found"
    for path in files:
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
            elif isinstance(node, ast.Name) and node.id in {"__import__", "importlib", "getattr", "eval", "exec",
                                                            "setattr", "globals"}:
                problems.append(f"{path.name}:{node.lineno}: dynamic access via {node.id}")
    assert problems == []


def test_cross_workflow_correlation_module_never_imports_execution_or_approval_code():
    """14.13.3: cross-source correlation is pure read-zone code (no adapter, guard, token or audit)."""
    forbidden = ("xdr_response.execution", "xdr_response.approval", "xdr_response.guard",
                 "xdr_response.restoration", "xdr_response.lifecycle", "xdr_response.audit",
                 "xdr_response.secrets", "xdr_response.integrations", "xdr_response.verification",
                 "xdr_response.atomics.containment")
    problems: list[str] = []
    for path in sorted((REPO_ROOT / "src" / "xdr_response" / "atomics" / "correlation").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 12))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(forbidden):
                problems.append(f"{path.name}: from {node.module}")
            elif isinstance(node, ast.Import):
                problems += [f"{path.name}: import {a.name}" for a in node.names if a.name.startswith(forbidden)]
    assert problems == []


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_hand_offs_and_considerations_never_start_anything(workflow: str):
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


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_rerunning_detection_after_containment_does_not_execute_without_new_approval(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    calls_before = len(run.environment.state_changing_calls())
    try:
        run.orchestrator.handle_detection(run.workflow_scenario.incident)
    except Exception:  # noqa: BLE001 - refusing a second detection is fine
        pass
    assert len(run.environment.state_changing_calls()) == calls_before


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_rejected_package_cannot_be_approved_afterwards(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": "REJECT", "comment": "lab rejection"}, approvers=_approvers(package))
    with pytest.raises(Exception):  # noqa: B017 - any refusal is fine; executing is not
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials(*_approvers(package)))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
@pytest.mark.parametrize("which", ["first", "last"])
def test_approve_selected_executes_only_the_selected_actions(workflow: str, which: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    chosen = package.actions[0] if which == "first" else package.actions[-1]
    run.decide({"decision": "APPROVE_SELECTED", "select": [f"{chosen.action_type.value}:{chosen.target}"]},
               approvers=_approvers(package))
    touched = {(op, (tgt or "").lower()) for _i, op, tgt in _state_calls(run)}
    others = {(a.action_type.value, a.target.lower()) for a in package.actions} - {
        (chosen.action_type.value, chosen.target.lower())}
    assert not (touched & others), f"{workflow}: unselected actions executed: {sorted(touched & others)}"


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_standard_only_approver_cannot_execute_an_elevated_action(workflow: str):
    """An ELEVATED action (role removal, a critical asset, over a blast-radius cap) never executes on a
    single analyst's approval."""
    run = _detect(_raw(workflow, "critical-asset-elevated"), workflow, "critical-asset-elevated", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    assert package.has_elevated
    with pytest.raises(ApprovalError):
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials("analyst"))
    assert _state_calls(run) == []


# ============================================================================= 2. dry run is inert --
@pytest.mark.parametrize("workflow, name", _all_fixtures())
def test_every_scenario_in_dry_run_is_side_effect_free_through_approval_and_release(workflow: str, name: str):
    """Every workflow supports dry run: whatever the scenario, a dry-run run approved in full by two
    humans and then released reaches no vendor with anything but reads, registers no control and writes
    no execution result."""
    run = _detect(copy.deepcopy(_raw(workflow, name)), workflow, name, live=False)
    package = run.detection.package
    if package is not None and package.actions:
        assert package.dry_run
        run.decide({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
        assert run.decision.report is None or run.decision.report.dry_run
        try:
            run.propose_release()
            run.decide_release({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
        except Exception:  # noqa: BLE001 - refusing a dry-run release is fine
            pass
    writes = sorted({(c.kind.value, c.integration, c.operation) for c in run.environment.calls
                     if c.kind.value != "READ"})
    assert writes == [], f"{workflow}/{name}: dry run reached vendors with {writes}"
    assert run.runtime.registry.list() == []
    assert not ({AuditEventType.ACTION_RESULT, AuditEventType.CONTROL_REGISTERED,
                 AuditEventType.RESTORATION_RESULT} & set(_events(run)))


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_package_proposed_under_dry_run_never_executes_live_after_dry_run_is_switched_off(workflow: str):
    run = _run(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    guard.configure(dry_run=True)
    run.detect()
    assert run.detection.package.dry_run
    guard.configure(dry_run=False)
    try:
        decision = run.decide({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
        assert decision.report is None or decision.report.dry_run
    except ApprovalError:
        pass
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


# ================================================================== 3. benign produces no containment --
def _benign_cases() -> list[Any]:
    out = []
    for workflow in P5_WORKFLOWS:
        for path in sorted((FIXTURES / workflow).glob("*.yaml")):
            tags = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("tags") or []
            if "benign" in tags:
                out.append(pytest.param(workflow, path.stem, id=f"{workflow}/{path.stem}"))
    return out


@pytest.mark.parametrize("workflow, name", _benign_cases())
@pytest.mark.parametrize("live", [False, True], ids=["dry_run", "live"])
def test_benign_scenario_produces_no_containment(workflow: str, name: str, live: bool):
    run = _detect(_raw(workflow, name), workflow, name, live=live)
    package = run.detection.package
    assert package is None or not package.actions, (
        f"{workflow}/{name}: benign incident proposed {_proposed(run)}")
    if package is not None and package.actions:
        _approve_all(run)
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_without_any_record_or_rating_nothing_is_recommended(workflow: str):
    """No invented facts: the incident title, MITRE techniques, observables and trigger context (patch
    status, change reference, feed confidence) alone never produce a recommendation."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    data["environment"]["reputations"] = []
    trigger = dict(data["incident"].get("trigger") or {})
    trigger.update({"patch_status": "unpatched", "feed_confidence": "high", "change_reference": "CHG-0000"})
    data["incident"]["trigger"] = trigger
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    assert package is None or not package.actions, f"{workflow}: proposed without records {_proposed(run)}"
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_ratings_alone_without_records_never_isolate_or_touch_accounts(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    bad = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
           if a.action_type in (ActionType.ISOLATE_ENDPOINT, ActionType.TERMINATE_PROCESS, ActionType.DISABLE_USER,
                                ActionType.REVOKE_SESSIONS, ActionType.REMOVE_PRIVILEGED_ROLE,
                                ActionType.QUARANTINE_FILE, ActionType.QUARANTINE_EMAIL)]
    assert bad == [], f"{workflow}: asset actions without any asset record: {bad}"


def _flip_verdicts(data: Mapping[str, Any], to: str = "CLEAN") -> dict[str, Any]:
    text = json.dumps(data)
    for verdict in ("MALICIOUS", "SUSPICIOUS"):
        text = text.replace(f'"{verdict}"', f'"{to}"')
    return json.loads(text)


@pytest.mark.parametrize("workflow", ["vulnerability-exploitation", "web-attacks", _TIS])
@pytest.mark.parametrize("live", [False, True], ids=["dry_run", "live"])
def test_every_verdict_clean_produces_no_containment(workflow: str, live: bool):
    """With every verdict and reputation turned CLEAN, nothing in the incident is rated: no block, no
    isolation, no quarantine and no revocation."""
    data = _flip_verdicts(copy.deepcopy(_raw(workflow, "tp-approve-all")))
    run = _detect(data, workflow, "tp-approve-all", live=live)
    assert _proposed(run) == [], f"{workflow}: all-CLEAN incident proposed {_proposed(run)}"
    assert _state_calls(run) == []


# ========================================================== 4. allow-listed items are never blocked --
@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_allowlist_matching_ignores_case_and_trailing_dot(workflow: str):
    baseline = _baseline(workflow)
    listed = [t for t in baseline if t[2] in _ALLOWLISTABLE - {TargetKind.URL}]
    data = _with_config(_raw(workflow, "tp-approve-all"), _allowlist_override(listed, spell=_odd_spelling))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    leaked = sorted(f"{a.value}:{t}" for a, t, _k in listed if (a, t) in proposed)
    assert leaked == []


@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
def test_allowlisted_breakglass_account_is_never_disabled_revoked_or_stripped(workflow: str):
    baseline = _baseline(workflow)
    user = sorted({t for _a, t, k in baseline if k is TargetKind.USER})[0]
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), user, "breakglass@example.com")
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    bad = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
           if a.target.lower().startswith("breakglass@example.com")]
    assert bad == [], f"{workflow}: allow-listed break-glass account proposed: {bad}"
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if (c[2] or "").lower().startswith("breakglass@example.com")]


_NON_PUBLIC = ["10.20.30.40", "127.0.0.1", "169.254.10.10", "100.64.1.9", "172.16.5.4"]


@pytest.mark.parametrize("workflow", IP_WORKFLOWS)
@pytest.mark.parametrize("address", _NON_PUBLIC)
def test_non_public_address_is_never_a_standard_ip_block(workflow: str, address: str):
    """A private, loopback, link-local or carrier-grade-NAT (VPN pool) address is the organisation's
    own network: put in place of the attacker IP (vendor ratings kept), it never becomes a STANDARD
    block_ip."""
    baseline = _baseline(workflow)
    ips = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP]
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ips[0], address)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type is ActionType.BLOCK_IP and a.target == address and _weak(a)]
    assert weak == [], f"{workflow}: non-public address {address} proposed as a STANDARD block_ip"


@pytest.mark.parametrize("workflow", IP_WORKFLOWS)
@pytest.mark.parametrize("address", ["192.0.2.53", "192.0.2.9"])
def test_core_infrastructure_address_is_never_blocked(workflow: str, address: str):
    """192.0.2.53 (the internal resolver) is never_block.ips and 192.0.2.0/28 never_block.cidrs: put
    in place of the attacker IP, it is excluded visibly and never blocked."""
    baseline = _baseline(workflow)
    ip = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP][0]
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ip, address)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    blocked = [a.target for a in (package.actions if package else ())
               if a.action_type is ActionType.BLOCK_IP and a.target == address]
    assert blocked == [], f"{workflow}: allow-listed infrastructure address {address} proposed"
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip" and (c[2] or "") == address]


@pytest.mark.parametrize("workflow", IP_WORKFLOWS)
def test_ipv4_mapped_spelling_of_an_allowlisted_address_is_not_blocked(workflow: str):
    baseline = _baseline(workflow)
    ips = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP]
    mapped = "::ffff:192.0.2.5"
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ips[0], mapped)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    blocked = [a.target for a in (package.actions if package else ()) if a.action_type is ActionType.BLOCK_IP]
    assert all("192.0.2.5" not in t and not t.startswith("::ffff:") for t in blocked), blocked
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip" and "192.0.2.5" in (c[2] or "")]


@pytest.mark.parametrize("workflow", ["vulnerability-exploitation", "web-attacks"])
def test_url_on_a_never_block_domain_that_is_not_url_block_allowed_is_never_a_standard_block(workflow: str):
    """never_block.domains lists microsoft.com; url_block_allowed_domains lists only example.com. An
    exploited path on a microsoft.com host (a hosted service) never becomes a STANDARD block_url."""
    baseline = _baseline(workflow)
    url = [t for a, t, _k in baseline if a is ActionType.BLOCK_URL][0]
    host = url.split("/")[2]
    data = json.loads(json.dumps(_raw(workflow, "tp-approve-all")).replace(host, "portal.lab.microsoft.com"))
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    weak = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
            if a.action_type in (ActionType.BLOCK_URL, ActionType.BLOCK_DOMAIN) and "microsoft.com" in a.target
            and _weak(a)]
    assert weak == [], f"{workflow}: block on a never_block domain proposed: {weak}"


# -------------------------------------------------------------- 4b. threat-intel-sweep allow-lists --
def _tis_rename_ip(address: str) -> dict[str, Any]:
    return _walk_replace(copy.deepcopy(_raw(_TIS, "tp-approve-all")), _TIS_IP, address)


@pytest.mark.parametrize("address", ["192.0.2.53", "192.0.2.5"])
def test_tis_sign_ins_from_an_allowlisted_infrastructure_address_never_revoke_sessions(address: str):
    """The feed lists the organisation's own core infrastructure address (never_block.ips 192.0.2.53,
    never_block.cidrs 192.0.2.0/28) and two vendors rate it MALICIOUS. The IP block is excluded, and no
    action may rest on that allow-listed indicator alone: an account that signed in through the
    organisation's own infrastructure is never revoked at STANDARD approval because of it (every user
    behind the egress would be)."""
    run = _detect(_tis_rename_ip(address), _TIS, "tp-approve-all", live=True)
    package = run.detection.package
    assert f"block_ip:{address}" not in _proposed(run), "precondition: the allow-listed IP block is excluded"
    weak = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
            if a.action_type is ActionType.REVOKE_SESSIONS and _weak(a)]
    assert weak == [], (f"sessions revoked at STANDARD approval because the account signed in from the allow-listed "
                        f"address {address}: {weak}")


@pytest.mark.parametrize("address", ["10.20.30.40", "100.64.1.9"])
def test_tis_sign_ins_from_a_non_public_address_never_revoke_sessions_at_standard(address: str):
    """A feed indicator that is a private or VPN-pool address (the organisation's own network): every
    employee signs in from it. A successful sign-in from it never becomes a STANDARD revocation."""
    run = _detect(_tis_rename_ip(address), _TIS, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
            if a.action_type is ActionType.REVOKE_SESSIONS and _weak(a)]
    assert weak == [], f"sessions revoked at STANDARD approval for sign-ins from the internal address {address}: {weak}"


def _tis_own_domain_data() -> dict[str, Any]:
    """A poisoned feed entry: the organisation's own domain (never_block.domains example.com) as the only
    indicator, rated MALICIOUS by two vendors; the sweep finds ordinary internal mail and lookups."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    data["incident"]["observables"] = [{"type": "domain", "value": "example.com"}]
    data["environment"]["reputations"] = [
        {"type": "domain", "value": "example.com", "verdict": "MALICIOUS", "risk_score": 85, "confidence": 80,
         "integrations": ["cisco_xdr", "umbrella"], "summary": "feed listing", "categories": ["Malware"]}]
    data["environment"]["records"] = [
        {"integration": "secure_email", "atomic": "investigate_email", "subject": "etd-int-0001",
         "record": {"kind": "email_message", "message_id": "etd-int-0001",
                    "internet_message_id": "<int-0001@example.com>", "sender": "hr@example.com",
                    "sender_domain": "example.com", "recipients": ["jsmith@example.com"], "recipient_count": 1,
                    "subject_line": "Benefits enrolment reminder", "received_at": "2026-01-14T09:02:00Z",
                    "direction": "intra_org", "urls": ["https://intranet.example.com/benefits"],
                    "domains": ["intranet.example.com"], "delivery_location": "inbox"}},
        {"integration": "microsoft_cloud", "atomic": "search_domain_enterprise", "subject": "example.com",
         "record": {"kind": "dns_query", "endpoint": "TH-LT-1047", "domain": "intranet.example.com",
                    "query_type": "A", "response_ips": ["198.51.100.20"], "count": 40, "action": "allowed",
                    "first_seen": "2026-01-14T08:00:00Z", "last_seen": "2026-01-14T17:00:00Z"}},
    ]
    return data


def test_tis_own_domain_indicator_never_blocks_or_quarantines_internal_mail():
    """The organisation's own domain is never blocked (never_block.domains), and no action may rest on
    that allow-listed indicator alone: an internal message from hr@example.com that carries only
    intranet links is never quarantined because the feed listed example.com."""
    run = _detect(_tis_own_domain_data(), _TIS, "tp-approve-all", live=True)
    proposed = _proposed(run)
    assert "block_domain:example.com" not in proposed
    bad = [s for s in proposed if s.startswith(("quarantine_email:", "isolate_endpoint:", "revoke_sessions:"))]
    assert bad == [], f"actions resting only on the organisation's own (allow-listed) domain: {bad}"
    package = run.detection.package
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] in ("quarantine_email", "block_domain")]


def _tis_approved_tool_data() -> dict[str, Any]:
    """The feed lists the approved RMM tool's hash (allowlists.approved_rmm) and two vendors rate it
    MALICIOUS; the sweep finds it running on TH-LT-1047 and present on TH-LT-2210."""
    data = _text_replace(copy.deepcopy(_raw(_TIS, "tp-approve-all")), _TIS_HASH, _APPROVED_RMM_HASH)
    for record in _records(data):
        if record.get("kind") == "detection":
            record["verdict"] = "SUSPICIOUS"  # only the reputation flags it; the endpoint shows nothing else
        if record.get("kind") == "process_event":
            record["verdict"] = "CLEAN"
    return data


def test_tis_approved_rmm_hash_in_the_feed_is_never_blocked_quarantined_or_isolating():
    run = _detect(_tis_approved_tool_data(), _TIS, "tp-approve-all", live=True)
    bad = [s for s in _proposed(run) if _APPROVED_RMM_HASH in s or s == "isolate_endpoint:TH-LT-1047"]
    assert bad == [], f"the sanctioned RMM tool is blocked, quarantined or isolates its host: {bad}"
    package = run.detection.package
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if _APPROVED_RMM_HASH in (c[2] or "")
                or c[1] == "isolate_endpoint"]


def test_tis_never_block_hash_in_the_feed_is_never_quarantined_anywhere():
    data = _with_config(_raw(_TIS, "tp-approve-all"),
                        {"allowlists": {**_repo_allowlists(),
                                        "never_block": {**(_repo_allowlists().get("never_block") or {}),
                                                        "hashes": [_TIS_HASH]}}})
    run = _detect(data, _TIS, "tp-approve-all", live=True)
    bad = [s for s in _proposed(run) if _TIS_HASH in s]
    assert bad == [], f"allow-listed hash still acted on: {bad}"


# ------------------------------------------------------------ 4c. threat-intel-sweep rating integrity --
def test_tis_feed_claim_and_one_vendor_alone_never_block_anything():
    """The feed's confidence is never evidence and one vendor alone (the platform's private
    intelligence carries the feed's own verdict) is never an aggregate MALICIOUS verdict: with every
    rating from Cisco XDR alone and no record of a security product's own verdict, nothing is blocked
    and no asset is touched."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    for rep in data["environment"]["reputations"]:
        rep["integrations"] = ["cisco_xdr"]
    for record in _records(data):
        if "verdict" in record:
            record["verdict"] = "UNKNOWN"
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    assert _proposed(run) == [], f"single-vendor feed indicators acted on: {_proposed(run)}"


def test_tis_clean_rated_parent_domain_is_never_blocked_because_of_one_subdomain_record():
    """The feed lists a shared hosting parent (cloudhost.test) that two vendors rate CLEAN. One DNS row
    of a different name under it (bad.cloudhost.test) carries a MALICIOUS verdict. That verdict is about
    the subdomain, not the indicator: the parent is never blocked (it would cut every tenant of the
    hosting provider), and the contradiction is shown to a human."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    data["incident"]["observables"] = [{"type": "domain", "value": "cloudhost.test"}]
    data["environment"]["reputations"] = [
        {"type": "domain", "value": "cloudhost.test", "verdict": "CLEAN", "risk_score": 0, "confidence": 85,
         "integrations": ["cisco_xdr", "umbrella", "virustotal"], "summary": "popular hosting provider"}]
    data["environment"]["records"] = [
        {"integration": "microsoft_cloud", "atomic": "search_domain_enterprise", "subject": "cloudhost.test",
         "record": {"kind": "dns_query", "endpoint": "TH-LT-1047", "domain": "bad.cloudhost.test", "query_type": "A",
                    "response_ips": ["198.51.100.90"], "count": 2, "action": "allowed", "verdict": "MALICIOUS",
                    "first_seen": "2026-01-14T09:14:00Z", "last_seen": "2026-01-14T09:20:00Z"}}]
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    assert "block_domain:cloudhost.test" not in _proposed(run), (
        "a CLEAN-rated parent domain was blocked on the strength of one subdomain's verdict")


@pytest.mark.parametrize("kind", ["process_event", "network_connection"])
def test_tis_clean_rated_ip_is_never_blocked_on_the_verdict_of_the_process_that_reached_it(kind: str):
    """The feed lists an IP that three vendors rate CLEAN (a public service malware also uses for a
    connectivity check). The only MALICIOUS verdict is the endpoint product's verdict on the process (or
    on the connection of that process): it rates the malware, not the destination. The CLEAN-rated
    address is never blocked."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    data["incident"]["observables"] = [{"type": "ip", "value": "198.51.100.200"}]
    data["environment"]["reputations"] = [
        {"type": "ip", "value": "198.51.100.200", "verdict": "CLEAN", "risk_score": 0, "confidence": 85,
         "integrations": ["cisco_xdr", "umbrella", "virustotal"], "summary": "public time service"}]
    if kind == "process_event":
        record = {"kind": "process_event", "event_id": "evt-tis-clean-1", "endpoint": "TH-LT-1047",
                  "timestamp": "2026-01-14T09:15:00Z", "event_type": "network_connect", "process_name": "loader.exe",
                  "pid": 4410, "remote_ip": "198.51.100.200", "verdict": "MALICIOUS"}
    else:
        record = {"kind": "network_connection", "endpoint": "TH-LT-1047", "remote_ip": "198.51.100.200",
                  "protocol": "udp", "direction": "outbound", "process_name": "loader.exe", "count": 1,
                  "action": "allowed", "verdict": "MALICIOUS", "first_seen": "2026-01-14T09:15:00Z",
                  "last_seen": "2026-01-14T09:15:00Z"}
    data["environment"]["records"] = [{"integration": "microsoft_cloud", "atomic": "search_ip_enterprise",
                                       "subject": "198.51.100.200", "record": record}]
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    assert "block_ip:198.51.100.200" not in _proposed(run), (
        f"a CLEAN-rated address was blocked on a {kind} verdict about the process that reached it")


def test_tis_failed_sign_ins_only_never_revoke():
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "sign_in":
            record["result"] = "failure"
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    assert not [s for s in _proposed(run) if s.startswith("revoke_sessions:")]


def test_tis_already_quarantined_message_is_never_quarantined_again():
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "email_message":
            record["delivery_location"] = "quarantine"
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    assert not [s for s in _proposed(run) if s.startswith("quarantine_email:")]


def test_tis_endpoint_that_only_resolved_the_indicator_is_never_isolated():
    """Contact alone (a DNS lookup of the rated domain) without the file running and without malicious
    activity of its own never isolates (14.13, known limitation)."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    data["environment"]["records"] = [r for r in data["environment"]["records"]
                                      if r["record"].get("kind") in ("dns_query", "endpoint")]
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    assert not [s for s in _proposed(run) if s.startswith("isolate_endpoint:")]


# ------------------------------------------------- 4d. vulnerability-exploitation / web-attacks --
@pytest.mark.parametrize("workflow", ["vulnerability-exploitation", "web-attacks"])
def test_exploit_attempts_without_host_compromise_never_isolate(workflow: str):
    """Scanning or exploit attempts alone (inbound connections, IPS or WAF signatures) never isolate a
    server: only a detection or process event on the host itself does."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = [r for r in data["environment"]["records"]
                                      if r["record"].get("kind") not in ("detection", "process_event")]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    assert not [s for s in _proposed(run) if s.startswith("isolate_endpoint:")], _proposed(run)


@pytest.mark.parametrize("workflow", ["vulnerability-exploitation", "web-attacks"])
def test_allowlisted_scanner_source_is_never_blocked(workflow: str):
    """The organisation's own scanner (never_block.cidrs 192.0.2.0/28) attacks the application in an
    authorised test: it is excluded, never blocked."""
    baseline = _baseline(workflow)
    ip = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP][0]
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ip, "192.0.2.12")
    run = _detect(data, workflow, "tp-approve-all", live=True)
    assert "block_ip:192.0.2.12" not in _proposed(run)
    package = run.detection.package
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if (c[2] or "") == "192.0.2.12"]


def test_web_attacks_url_that_only_the_incident_names_is_never_blocked():
    """No invented facts: a second application URL that only the incident's observable list names (no
    request, no WAF or IPS event, no record of any kind mentions it) is never proposed for a block,
    even though the incident also names a server with a confirmed web shell."""
    data = copy.deepcopy(_raw("web-attacks", "tp-approve-all"))
    data["incident"]["observables"] = list(data["incident"]["observables"]) + [
        {"type": "url", "value": "https://shop.example.net/checkout"}]
    run = _detect(data, "web-attacks", "tp-approve-all", live=False)
    assert "block_url:https://shop.example.net/checkout" not in _proposed(run), (
        "an application URL no record mentions was proposed for a block on the incident's say-so")


# -------------------------------------------------------------- 4e. privilege-escalation specifics --
def test_privilege_escalation_pim_activation_and_approved_change_never_remove_a_role():
    for name in ("edge-pim-activation-normal", "legacy-02-approved-change-window"):
        run = _detect(_raw("privilege-escalation", name), "privilege-escalation", name, live=True)
        assert _proposed(run) == [], f"{name}: {_proposed(run)}"
        guard._reset_for_test_harness()


def test_privilege_escalation_change_reference_never_withholds_a_recommendation():
    """A change reference is unverified incident data: it never withholds a recommendation."""
    expected = {f"{a.value}:{t}" for a, t, _k in _baseline("privilege-escalation")}
    data = copy.deepcopy(_raw("privilege-escalation", "tp-approve-all"))
    data["incident"]["trigger"] = {**data["incident"]["trigger"], "change_reference": "CHG-12345 approved"}
    run = _detect(data, "privilege-escalation", "tp-approve-all", live=False)
    assert expected <= set(_proposed(run))


def test_privilege_escalation_role_removal_is_always_elevated():
    for name in ("tp-approve-all", "dry-run", "legacy-05-mass-account-creation"):
        run = _detect(_raw("privilege-escalation", name), "privilege-escalation", name, live=False)
        weak = [a.target for a in run.detection.package.actions
                if a.action_type is ActionType.REMOVE_PRIVILEGED_ROLE and _weak(a)]
        assert weak == [], f"{name}: role removal without ELEVATED approval and warning: {weak}"
        guard._reset_for_test_harness()


def test_privilege_escalation_grant_long_before_the_compromise_is_never_removed():
    data = copy.deepcopy(_raw("privilege-escalation", "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "role_change":
            record["timestamp"] = "2025-06-01T10:12:00Z"
    run = _detect(data, "privilege-escalation", "tp-approve-all", live=False)
    bad = [s for s in _proposed(run) if s.startswith("remove_privileged_role:")]
    assert bad == [], f"a grant made months before the compromise is proposed for removal: {bad}"


_PE_HASH = "7d1a0c3e9b4f2a6810c5e7d93b2f4a6c8e1d0b3a5c7e9f2d4b6a8c0e2f4a6b8c"


def test_privilege_escalation_sanctioned_rmm_binary_alone_never_isolates_or_strips_roles():
    """The only thing that makes TH-LT-1047 look compromised is that two vendors rate the approved RMM
    tool's binary (allowlists.approved_rmm, hash 1111...) MALICIOUS (riskware); the endpoint's own
    detection is only SUSPICIOUS. A sanctioned binary never isolates its host (14.11.6), so neither the
    isolation nor the account actions that rest on "uses a compromised endpoint" may be proposed."""
    data = _text_replace(copy.deepcopy(_raw("privilege-escalation", "tp-approve-all")), _PE_HASH, _APPROVED_RMM_HASH)
    for record in _records(data):
        if record.get("kind") == "detection":
            record["verdict"] = "SUSPICIOUS"
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": "TH-LT-1047",
        "record": {"kind": "process_event", "event_id": "evt-pe-rmm-1", "endpoint": "TH-LT-1047",
                   "timestamp": "2026-01-15T09:58:00Z", "event_type": "process_start", "process_name": "rmmagent.exe",
                   "pid": 3120, "sha256": _APPROVED_RMM_HASH, "user": "jsmith@example.com"}})
    run = _detect(data, "privilege-escalation", "tp-approve-all", live=False)
    bad = [s for s in _proposed(run) if s == "isolate_endpoint:TH-LT-1047" or s.endswith(":jsmith@example.com")]
    assert bad == [], f"the sanctioned RMM binary alone isolates its host or contains its user: {bad}"


# ============================================================ 5. critical assets come out ELEVATED --
def _critical_override(baseline: Iterable[tuple[ActionType, str, TargetKind]]) -> dict[str, Any]:
    hosts = sorted({_host_part(t) for _a, t, k in baseline if k in _ENDPOINT_KINDS})
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    users += sorted({t.split("/", 1)[0] for _a, t, k in baseline if k is TargetKind.ROLE_ASSIGNMENT})
    ips = sorted({f"{t}/32" for _a, t, k in baseline if k is TargetKind.IP})
    return {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": hosts, "users": sorted(set(users))}},
        "production_server": {"match": {"ip_cidrs": ips or ["203.0.113.0/26"]}},
    }}}


_CRITICAL_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER, TargetKind.IP, TargetKind.FILE})


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
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
    weak = [f"{a.value}:{t}" for a, t, _k in critical if _weak(by_key[(a, t)])]
    assert weak == [], f"{workflow}: critical targets without ELEVATED approval and warning: {weak}"
    with pytest.raises(ApprovalError):
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials("analyst"))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_critical_asset_fixture_is_elevated_and_never_skipped(workflow: str):
    run = _detect(_raw(workflow, "critical-asset-elevated"), workflow, "critical-asset-elevated", live=False)
    package = run.detection.package
    assert package is not None and package.has_elevated
    elevated = [a for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED]
    assert elevated and all(a.warnings for a in elevated), "ELEVATED action without a visible warning"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_host_actions_on_a_domain_controller_known_from_vendor_records_are_elevated(workflow: str):
    host = _isolated_host(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == host.upper():
            record["groups"] = list(record.get("groups") or []) + ["Domain Controllers"]
            marked = True
    assert marked
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, host)]
    assert on_host, f"{workflow}: the actions on the domain controller were dropped"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host if _weak(a)]
    assert weak == [], f"{workflow}: actions on a record-derived domain controller not ELEVATED: {weak}"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_endpoint_used_by_an_executive_is_elevated(workflow: str):
    host = _isolated_host(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == host.upper():
            record["users"] = list(record.get("users") or []) + ["ceo@example.com"]
            marked = True
    assert marked, f"{workflow}: precondition, an endpoint record for {host}"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, host)]
    assert on_host
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host if _weak(a)]
    assert weak == [], f"{workflow}: the CEO's endpoint is contained at STANDARD approval: {weak}"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_critical_endpoint_reported_by_its_fqdn_is_elevated(workflow: str):
    host = _isolated_host(workflow)
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), host, host + ".corp.example.com")
    data = _with_config(data, {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": [host]}}}}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    on_host = [a for a in (package.actions if package else ()) if _on_host(a, host)]
    assert on_host, f"{workflow}: precondition, an action on {host}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host if _weak(a)]
    assert weak == [], f"{workflow}: critical host under its FQDN not ELEVATED: {weak}"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_critical_ip_on_a_second_interface_makes_host_actions_elevated(workflow: str):
    host = _isolated_host(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == host.upper():
            record["ip_addresses"] = ["10.40.1.15", "203.0.113.10"]
            marked = True
    assert marked
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, host)]
    assert on_host, f"{workflow}: precondition, an action on {host}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host if _weak(a)]
    assert weak == [], f"{workflow}: production address on the second interface ignored: {weak}"


@pytest.mark.parametrize("tag", ["Production", "PRODUCTION"])
@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_critical_tag_matching_ignores_case(workflow: str, tag: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "endpoint":
            record["tags"] = list(record.get("tags") or []) + [tag]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_hosts = [a for a in run.detection.package.actions if a.target_kind in _ENDPOINT_KINDS]
    assert on_hosts
    weak = [f"{a.action_type.value}:{a.target}" for a in on_hosts if _weak(a)]
    assert weak == [], f"{workflow}: host actions on a {tag}-tagged endpoint not ELEVATED: {weak}"


@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
@pytest.mark.parametrize("group", ["Executives", "Service Accounts", "Domain Admins"])
def test_account_in_a_critical_group_is_elevated_with_a_warning(workflow: str, group: str):
    baseline = _baseline(workflow)
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = set()
    for record in _records(data):
        if record.get("kind") == "user_profile" and record.get("user") in users:
            record["groups"] = list(record.get("groups") or []) + [group]
            marked.add(record["user"])
    assert marked, f"{workflow}: precondition, a profile record of an account in the package"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    actions = [a for a in run.detection.package.actions if a.target_kind is TargetKind.USER and a.target in marked]
    missing = [f"{a.value}:{t}" for a, t, k in baseline if t in marked
               and not any((x.action_type, x.target) == (a, t) for x in actions)]
    assert missing == [], f"{workflow}: account actions on the {group} member dropped: {missing}"
    weak = [f"{a.action_type.value}:{a.target}" for a in actions if _weak(a)]
    assert weak == [], f"{workflow}: member of {group} contained at STANDARD approval: {weak}"


@pytest.mark.parametrize("roles", [["Global Administrator"], ["Privileged Role Administrator"]])
def test_tis_account_holding_an_administrator_role_is_revoked_only_under_elevated_approval(roles: list[str]):
    """The identity source reports the account that signed in from the rated IP as holding an
    administrator role (its profile, read by the sweep for exactly this purpose): the revocation is
    ELEVATED with a warning, never STANDARD."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "user_profile":
            record["roles"] = roles
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    actions = [a for a in run.detection.package.actions if a.action_type is ActionType.REVOKE_SESSIONS]
    assert actions
    weak = [a.target for a in actions if _weak(a)]
    assert weak == [], f"administrator ({roles}) revoked at STANDARD approval: {weak}"


def test_tis_critical_endpoint_file_quarantine_is_elevated():
    """The quarantine of a file on a critical endpoint is ELEVATED like its isolation."""
    run = _detect(_raw(_TIS, "critical-asset-elevated"), _TIS, "critical-asset-elevated", live=False)
    package = run.detection.package
    hosts = {a.target for a in package.actions
             if a.action_type is ActionType.ISOLATE_ENDPOINT and a.approval_level is ApprovalLevel.ELEVATED}
    assert hosts
    weak = [a.target for a in package.actions if a.action_type is ActionType.QUARANTINE_FILE
            and _host_part(a.target) in hosts and _weak(a)]
    assert weak == []


def test_tis_mailbox_of_an_executive_quarantine_is_elevated():
    """A delivered carrier message in the CEO's mailbox (critical-assets executive user) is quarantined
    only under ELEVATED approval with a warning, never STANDARD and never skipped."""
    data = _text_replace(copy.deepcopy(_raw(_TIS, "tp-approve-all")), "jsmith@example.com", "ceo@example.com")
    run = _detect(data, _TIS, "tp-approve-all", live=False)
    package = run.detection.package
    actions = [a for a in package.actions if a.action_type is ActionType.QUARANTINE_EMAIL]
    assert actions, "the CEO's carrier message was dropped"
    weak = [a.target for a in actions if _weak(a)]
    assert weak == [], f"message in an executive mailbox quarantined at STANDARD approval: {weak}"


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
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


def test_tis_hits_over_the_indicator_cap_are_elevated_never_dropped():
    run = _detect(_raw(_TIS, "edge-hits-over-indicator-cap"), _TIS, "edge-hits-over-indicator-cap", live=False)
    blocks = [a for a in run.detection.package.actions
              if a.action_type in (ActionType.BLOCK_HASH, ActionType.BLOCK_DOMAIN, ActionType.BLOCK_IP,
                                   ActionType.BLOCK_URL)]
    assert blocks
    assert all(not _weak(a) for a in blocks)


# ======================================================= 6. evidence references real, relevant records --
def _mentions(record: Any, needles: Iterable[str]) -> bool:
    text = json.dumps(record.rule_item(), default=str).lower()
    return any(n and n.lower() in text for n in needles)


def _needles(action: Any) -> list[str]:
    target = action.target
    if action.target_kind in (TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM):
        host, _, rest = target.partition("/")
        return [host, rest] if rest else [host]
    if action.target_kind is TargetKind.ROLE_ASSIGNMENT:
        return [p for p in target.split("/") if p]
    if action.target_kind is TargetKind.URL:
        return [target, target.split("?")[0]]
    return [target]


@pytest.mark.parametrize("workflow, name", _all_fixtures())
def test_every_proposed_action_cites_numbered_records_about_its_target(workflow: str, name: str):
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
            problems.append(f"{action.action_type.value}:{action.target}: evidence not uniquely numbered: {numbers}")
        if not any(_mentions(wf.index.get(i), _needles(action)) for i in ids):
            problems.append(f"{action.action_type.value}:{action.target}: no cited record mentions the target")
        if type(action.risk_score) is not int or type(action.confidence_score) is not int:
            problems.append(f"{action.action_type.value}:{action.target}: scores are not separate integers")
    assert problems == []


@pytest.mark.parametrize("workflow, name", _all_fixtures())
def test_hand_offs_and_manual_steps_cite_real_records(workflow: str, name: str):
    run = _detect(_raw(workflow, name), workflow, name, live=False)
    wf = run.workflow_run
    problems = []
    for item in wf.considered:
        unknown = [i for i in item.record_ids if i not in wf.index]
        if not item.record_ids or unknown:
            problems.append(f"considered {item.subject}: records {unknown or 'none'}")
    for handoff in getattr(wf, "handoffs", ()) or ():
        unknown = [i for i in handoff.record_ids if i not in wf.index]
        if not handoff.record_ids or unknown:
            problems.append(f"handoff {handoff.workflow_id}: records {unknown or 'none'}")
    assert problems == []


# ======================================================== 7. degraded sources never block the rest --
def _degradation_cases() -> list[Any]:
    out = []
    for workflow in P5_WORKFLOWS:
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


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_degraded_source_is_reported_not_hidden(workflow: str):
    base = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=False)
    answered = sorted({s.integration for r in base.workflow_run.results for s in r.sources
                       if s.outcome.value == "answered"})
    guard._reset_for_test_harness()
    assert answered
    failed = "virustotal" if "virustotal" in answered else answered[-1]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": "UNAVAILABLE", "integration": failed, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    summary = run.workflow_run.summary().model_dump_json()
    assert failed in summary, f"{workflow}: failed {failed} not reported"


# =============================================================== 8. partial failures are reported --
@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("fault", ["FAIL", "NO_EFFECT", "TIMEOUT", "AUTH_FAIL", "INVALID_TARGET", "RATE_LIMIT",
                                   "UNAVAILABLE"])
def test_one_failed_or_ineffective_action_reports_partially_contained(workflow: str, position: str, fault: str):
    baseline = _baseline(workflow)
    action_type, target, _kind = baseline[0] if position == "first" else baseline[-1]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": fault, "operation": action_type.value, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report is not None
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED, (
        f"{workflow}: {fault} on {action_type.value} {target} reported {decision.report.overall}")


def _every_action_cases() -> list[Any]:
    out = []
    for workflow in P5_WORKFLOWS:
        for action, target, _kind in _baseline(workflow):
            out.append(pytest.param(workflow, action.value, target, id=f"{workflow}:{action.value}:{target[:24]}"))
    return out


@pytest.mark.parametrize("workflow, operation, target", _every_action_cases())
def test_any_single_failed_action_reports_partially_contained(workflow: str, operation: str, target: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = [{"kind": "FAIL", "operation": operation, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_partial_failure_fixture_reports_partially_contained(workflow: str):
    run = _detect(_raw(workflow, "partial-failure"), workflow, "partial-failure", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_every_action_failing_is_never_reported_contained(workflow: str):
    baseline = _baseline(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = [{"kind": "FAIL", "operation": a.value, "target": t, "times": None}
                                     for a, t, _k in baseline]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report.overall not in (ContainmentOverall.CONTAINED, ContainmentOverall.PARTIALLY_CONTAINED)
    assert run.runtime.registry.list(incident_id=run.incident_id) == []


# ============================================================= 9. release: approval and ownership --
_REVERSIBLE = frozenset(a for a in ActionType if get_action_spec(a).rollback_action_type is not None)


def _reversible_cases() -> list[Any]:
    out = []
    for workflow in P5_WORKFLOWS:
        for action, target, _kind in _baseline(workflow):
            if action in _REVERSIBLE:
                out.append(pytest.param(workflow, action.value, target, id=f"{workflow}:{action.value}:{target[:20]}"))
    return out


@pytest.mark.parametrize("workflow, operation, target", _reversible_cases())
def test_release_never_undoes_a_control_that_existed_before_the_incident(workflow: str, operation: str,
                                                                         target: str):
    """Whatever reversible action is already in place before the incident (an IP already blocked, an
    account already disabled, a host already isolated), approving the package registers no control for
    it and an approved release never restores it."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["preexisting"] = list(data["environment"].get("preexisting") or []) + [
        {"action_type": operation, "target": target}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert not [c for c in controls if (c.action_type.value, c.target.lower()) == (operation, target.lower())]
    before = len(run.environment.state_changing_calls())
    if controls:
        run.propose_release()
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
    assert run.environment.in_desired_state(ActionType(operation), target), (
        f"{workflow}: release undid the pre-existing {operation} {target}")
    restored = [(c.operation, (c.target or "").lower()) for c in run.environment.state_changing_calls()[before:]]
    assert not [r for r in restored if r[1] == target.lower()], restored


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_release_needs_a_human_release_approval(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls, f"{workflow}: approved containment created no temporary control"
    assert all(c.incident_id == run.incident_id for c in controls)
    assert all(c.action_type not in (ActionType.REVOKE_SESSIONS, ActionType.TERMINATE_PROCESS) for c in controls)
    calls_before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert len(run.environment.state_changing_calls()) == calls_before, "proposing a release changed state"
    assert set(release.control_keys) <= {c.control_key for c in controls}
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_release_decision(
                run._request(release, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"), run.credentials(alias))
    assert len(run.environment.state_changing_calls()) == calls_before
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
    restore_calls = run.environment.state_changing_calls()[calls_before:]
    released = {(c.target or "").lower() for c in restore_calls}
    created = {c.target.lower() for c in controls}
    assert released <= created, f"{workflow}: release touched {sorted(released - created)}"
    restore_ops = {get_action_spec(c.action_type).rollback_action_type.value for c in controls}
    assert all(c.operation in restore_ops for c in restore_calls), [c.operation for c in restore_calls]


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_containment_approval_cannot_be_reused_as_release_approval(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    calls_before = len(run.environment.state_changing_calls())
    containment = run.detection.package
    with pytest.raises(Exception):  # noqa: B017
        run.orchestrator.submit_release_decision(
            run._request(containment, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
            run.credentials("analyst", "lead"))
    assert len(run.environment.state_changing_calls()) == calls_before
    assert all(c.status.value == "ACTIVE" for c in run.runtime.registry.list(incident_id=run.incident_id))


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_rejected_release_restores_nothing_and_keeps_controls_active(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    before = len(run.environment.state_changing_calls())
    run.propose_release()
    run.decide_release({"decision": "REJECT", "comment": "keep contained"}, approvers=_PROD_LEAD)
    assert len(run.environment.state_changing_calls()) == before
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls and all(c.status.value == "ACTIVE" for c in controls)


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_release_of_a_selected_control_restores_only_that_control(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    chosen = release.actions[0]
    run.decide_release({"decision": "APPROVE_SELECTED", "select": [f"{chosen.action_type.value}:{chosen.target}"]},
                       approvers=_PROD_LEAD)
    restored = [(c.operation, (c.target or "").lower()) for c in run.environment.state_changing_calls()[before:]]
    assert restored == [(chosen.action_type.value, chosen.target.lower())], restored
    still_active = [c for c in run.runtime.registry.list(incident_id=run.incident_id) if c.status.value == "ACTIVE"]
    assert len(still_active) == len(release.actions) - 1


def test_release_of_one_incident_never_touches_another_incidents_controls():
    """Two sweeps contain the same indicator set. Releasing the first incident restores only the
    controls the first created; the second incident's controls stay in place."""
    first = _detect(_raw(_TIS, "tp-approve-all"), _TIS, "tp-approve-all", live=True)
    _approve_all(first)
    mine = first.runtime.registry.list(incident_id=first.incident_id)
    other = [c for c in first.runtime.registry.list() if c.incident_id != first.incident_id]
    first.propose_release()
    first.decide_release({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
    assert all(c.status.value == "ACTIVE" for c in other)
    assert mine


def test_privilege_escalation_role_removal_release_needs_release_approval_and_restores_only_that_role():
    """Restoring a removed privileged role (re-granting it) needs its own human release approval, never
    an AI principal, and never touches another assignment."""
    run = _detect(_raw("privilege-escalation", "release-restoration"), "privilege-escalation",
                  "release-restoration", live=True)
    _approve_all(run)
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert any(c.action_type is ActionType.REMOVE_PRIVILEGED_ROLE for c in controls)
    before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    assert all(a.approval_level is ApprovalLevel.ELEVATED for a in release.actions
               if a.target_kind is TargetKind.ROLE_ASSIGNMENT)
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_release_decision(
                run._request(release, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"), run.credentials(alias))
    with pytest.raises(ApprovalError):
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst"])
    assert len(run.environment.state_changing_calls()) == before
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
    restored = {(c.target or "").lower() for c in run.environment.state_changing_calls()[before:]}
    assert restored <= {c.target.lower() for c in controls}


# ===================================================== 10. no secrets or needless personal data out --
def _plant_secrets(workflow: str) -> dict[str, Any]:
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = False
    for record in _records(data):
        kind = record.get("kind")
        if kind == "detection":
            record["name"] = f"Credential tool unlock code: {SECRET_UNLOCK}"
            planted = True
        elif kind == "anomaly":
            record["detail"] = f"token={SECRET_TOKEN} seen in sign-in"
            planted = True
        elif kind == "sign_in":
            record["failure_reason"] = f"Authorization: Bearer {SECRET_TOKEN}"
            planted = True
        elif kind == "process_event":
            record["command_line"] = f"tool.exe --password {SECRET_PASSWORD} --token={SECRET_TOKEN}"
            planted = True
        elif kind == "email_message":
            record["subject_line"] = f"Your new password is {SECRET_PASSWORD}"
            planted = True
        elif kind == "role_change":
            record["role_name"] = f"{record.get('role_name')}"
    assert planted
    return data


@pytest.mark.parametrize("workflow", P5_WORKFLOWS)
def test_planted_credentials_never_reach_packages_summaries_notifications_or_audit(workflow: str):
    data = _plant_secrets(workflow)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    text = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_UNLOCK, SECRET_TOKEN) if s in text]
    assert leaked == [], f"{workflow}: planted secret(s) {leaked} reached analyst-facing output or audit"


@pytest.mark.parametrize("workflow", URL_WORKFLOWS)
@pytest.mark.parametrize("form", ["userinfo", "query"])
def test_url_credentials_never_reach_outputs_or_audit(workflow: str, form: str):
    """The exploited path or the swept URL carries a credential (``user:password@`` or a ``token=``
    query parameter). The URL becomes evidence, a rationale and a block target: the credential must not
    reach the package, the notes, notifications, the decision report or the audit trail."""
    baseline = _baseline(workflow)
    old = [t for a, t, _k in baseline if a is ActionType.BLOCK_URL][0]
    scheme, rest = old.split("://", 1)
    new = (f"{scheme}://svc:{SECRET_PASSWORD}@{rest}" if form == "userinfo" else f"{old}?token={SECRET_TOKEN}")
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), old, new)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    assert run.detection.package is not None and run.detection.package.actions
    _approve_all(run)
    text = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_TOKEN) if s in text]
    assert leaked == [], f"{workflow}: URL credential ({form}) reached outputs or audit"


@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
def test_profile_details_the_analyst_does_not_need_stay_out_of_the_package_and_notifications(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    manager, title, phone = "mgr.private.lab@example.com", "Lab Title Zeta Omega", "+1-555-0100-7788"
    planted = False
    for record in _records(data):
        if record.get("kind") == "user_profile":
            record.update({"manager": manager, "job_title": title, "mobile_phone": phone})
            planted = True
    assert planted
    run = _detect(data, workflow, "tp-approve-all", live=False)
    text = _outputs_text(run, audit=False)
    leaked = [v for v in (manager, title, phone) if v in text]
    assert leaked == [], f"{workflow}: profile details {leaked} reached the package or notifications"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_isolation_unlock_codes_never_reach_outputs_or_audit(workflow: str):
    host = _isolated_host(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": host,
        "record": {"kind": "detection", "name": f"Endpoint isolation unlock code is {SECRET_UNLOCK}",
                   "verdict": "MALICIOUS", "severity": "HIGH", "endpoint": host, "status": "active"}})
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    assert SECRET_UNLOCK not in _outputs_text(run)


@pytest.mark.parametrize("label, text", [
    ("pass-switch", f"agent.exe /user:svc /pass:{SECRET_PASSWORD} LABMARK"),
    ("securestring", f"ConvertTo-SecureString '{SECRET_PASSWORD}' -AsPlainText -Force; LABMARK"),
    ("basic-auth-header", f"curl -H 'Authorization: Basic {SECRET_TOKEN}' LABMARK"),
    ("net-user", f"net user svc-sync-temp {SECRET_PASSWORD} /add LABMARK"),
])
@pytest.mark.parametrize("workflow, kind, field", [
    ("privilege-escalation", "detection", "name"),
    ("vulnerability-exploitation", "detection", "name"),
    ("web-attacks", "process_event", "file_path"),
    ("web-attacks", "detection", "file_path"),
    ("threat-intel-sweep", "email_message", "subject_line"),
    ("threat-intel-sweep", "detection", "name"),
])
def test_credential_forms_in_free_text_never_reach_outputs(workflow: str, kind: str, field: str, label: str,
                                                          text: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = 0
    for record in _records(data):
        if record.get("kind") == kind:
            record[field] = text
            planted += 1
    if not planted:
        pytest.skip(f"{workflow}: no {kind} record")
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    out = _outputs_text(run)
    if "LABMARK" not in out:
        pytest.skip(f"{workflow}: {kind}.{field} is not quoted in the outputs")
    leaked = [s for s in (SECRET_PASSWORD, SECRET_TOKEN) if s in out]
    assert leaked == [], f"{workflow}: secret in {kind}.{field} ({label}) reached outputs or audit"


def test_tis_message_bodies_and_subjects_with_credentials_never_reach_outputs():
    """A carrier message's subject line is attacker-chosen free text (phishing lures carry one-time
    codes and passwords). It must not be copied to the package or the audit trail with the code."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "email_message":
            record["subject_line"] = f"Mailbox unlock code {SECRET_UNLOCK}, password={SECRET_PASSWORD}"
    run = _detect(data, _TIS, "tp-approve-all", live=True)
    _approve_all(run)
    out = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_UNLOCK) if s in out]
    assert leaked == [], f"credential in a message subject reached outputs or audit: {leaked}"


# ===================================================== 11. cross-workflow correlation stays read-only --
def _finished(workflow: str, name: str) -> WorkflowScenarioRun:
    guard._reset_for_test_harness()
    run = _detect(copy.deepcopy(_raw(workflow, name)), workflow, name, live=False)
    guard._reset_for_test_harness()
    return run


def test_cross_workflow_correlation_changes_no_state_no_package_and_keeps_every_critical_asset():
    """14.13.4: correlation over finished runs is informational. Correlating two incidents that each
    affect a critical asset calls no adapter, changes neither package (nor its approval level), and the
    rollup reports every critical asset with a visible warning, also when it is ignored for linking."""
    from xdr_response.atomics.correlation import EntityRef, correlate_workflows, rollup_blast_radius

    first = _finished(_TIS, "critical-asset-elevated")
    second = _finished("privilege-escalation", "critical-asset-elevated")
    runs = [first.workflow_run, second.workflow_run]
    packages = [first.detection.package.model_dump_json(), second.detection.package.model_dump_json()]
    calls = [len(first.environment.calls), len(second.environment.calls)]
    critical_hosts = sorted({a.target for r in (first, second) for a in r.detection.package.actions
                             if a.action_type is ActionType.ISOLATE_ENDPOINT
                             and a.approval_level is ApprovalLevel.ELEVATED})
    assert critical_hosts
    ignore = tuple(EntityRef(kind=TargetKind.ENDPOINT, value=h) for h in critical_hosts)
    result = correlate_workflows(runs, ignore=ignore)
    rollup = rollup_blast_radius(runs)
    assert [first.detection.package.model_dump_json(), second.detection.package.model_dump_json()] == packages
    assert [len(first.environment.calls), len(second.environment.calls)] == calls
    assert _state_calls(first) == [] and _state_calls(second) == []
    listed = {c.entity.value.upper() for c in rollup.critical_assets}
    missing = [h for h in critical_hosts if h.upper() not in listed]
    assert missing == [], f"critical assets dropped from the rollup: {missing}"
    assert len(rollup.warnings) >= len(critical_hosts)
    group_listed = {c.entity.value.upper() for g in result.groups for c in g.blast_radius.critical_assets}
    assert not [h for h in critical_hosts if h.upper() not in group_listed], (
        "a critical asset ignored for linking was dropped from its group's rollup")


# =============================================================================================
# Phase 5 round 2 (lens: workflow safety). Same conventions as above: every test asserts the SAFE
# behaviour, so a failing test proves a defect. Fake lab data only.
# =============================================================================================

# --------------------------------------- R2-1. a carrier message resting on an allow-listed indicator --
_R2_MESSAGE_ID = "etd-r2-0101"
_R2_NEVER_BLOCK_HASH = "9c4e2b7a9c4e2b7a9c4e2b7a9c4e2b7a9c4e2b7a9c4e2b7a9c4e2b7a9c4e2b7a"


def _r2_carrier_message_data(kind: str, value: str, link: str | None) -> dict[str, Any]:
    """A poisoned feed entry: one indicator the allow-list excludes (the organisation's own domain, a
    sanctioned service's domain, the approved RMM tool's domain, an allow-listed or approved-tool hash),
    rated MALICIOUS by two vendors. The sweep finds one ordinary delivered message that carries it (a
    link under that domain, or the file as an attachment) and nothing else: the message has no verdict
    of its own and its sender is not an indicator."""
    data = copy.deepcopy(_raw(_TIS, "tp-approve-all"))
    data["incident"]["observables"] = [{"type": kind, "value": value},
                                       {"type": "email_message_id", "value": _R2_MESSAGE_ID}]
    vendors = ["cisco_xdr", "umbrella"] if kind == "domain" else ["cisco_xdr", "virustotal"]
    data["environment"]["reputations"] = [
        {"type": kind, "value": value, "verdict": "MALICIOUS", "risk_score": 85, "confidence": 80,
         "integrations": vendors, "summary": "feed listing"}]
    message: dict[str, Any] = {
        "kind": "email_message", "message_id": _R2_MESSAGE_ID, "internet_message_id": "<r2-0101@partner-mail.example>",
        "sender": "notify@partner-mail.example", "sender_domain": "partner-mail.example",
        "recipients": ["jsmith@example.com"], "recipient_count": 1, "subject_line": "Quarterly service notice",
        "received_at": "2026-01-14T09:02:00Z", "direction": "inbound", "delivery_location": "inbox",
        "urls": [link] if link else [], "domains": [link.split("/")[2]] if link else [],
        "attachment_hashes": [] if link else [value]}
    data["environment"]["records"] = [{"integration": "secure_email", "atomic": "investigate_email",
                                       "subject": _R2_MESSAGE_ID, "record": message}]
    if value == _R2_NEVER_BLOCK_HASH:
        base = _repo_allowlists()
        data = _with_config(data, {"allowlists": {**base, "never_block": {**(base.get("never_block") or {}),
                                                                          "hashes": [_R2_NEVER_BLOCK_HASH]}}})
    return data


_R2_ALLOWLISTED_INDICATORS = [
    pytest.param("domain", "example.com", "https://intranet.example.com/benefits", "block_domain",
                 id="own-domain"),
    pytest.param("domain", "microsoft.com", "https://login.microsoft.com/common/reprocess", "block_domain",
                 id="never-block-service-domain"),
    pytest.param("domain", "rmm.example.net", "https://rmm.example.net/agent/status", "block_domain",
                 id="approved-rmm-domain"),
    pytest.param("sha256", _R2_NEVER_BLOCK_HASH, None, "block_hash", id="never-block-hash-attachment"),
    pytest.param("sha256", _APPROVED_RMM_HASH, None, "block_hash", id="approved-rmm-hash-attachment"),
]


@pytest.mark.parametrize("kind, value, link, block", _R2_ALLOWLISTED_INDICATORS)
def test_r2_tis_message_resting_only_on_an_allowlisted_indicator_is_never_quarantined(kind: str, value: str,
                                                                                     link: str | None, block: str):
    """14.13.6: no action may rest only on an indicator the allow-list excludes. A poisoned feed lists
    the organisation's own domain (or a sanctioned service's domain, the approved RMM tool's domain or
    hash, an allow-listed hash): the block itself is excluded, and a delivered message whose only
    link to the sweep is that indicator (an intranet link, a sanctioned service's link, the approved
    tool's installer as an attachment) is never quarantined: every message carrying an ordinary
    internal link would be. The withheld quarantine is shown as considered, never silently dropped."""
    run = _detect(_r2_carrier_message_data(kind, value, link), _TIS, "tp-approve-all", live=True)
    package = run.detection.package
    proposed = _proposed(run)
    assert f"{block}:{value}" not in proposed, "precondition: the allow-listed indicator's block is excluded"
    assert f"quarantine_email:{_R2_MESSAGE_ID}" not in proposed, (
        f"a message is quarantined on the strength of the allow-listed indicator {value} alone: {proposed}")
    assert f"quarantine_email:{_R2_MESSAGE_ID}" in _considered_subjects(run), (
        "the withheld quarantine is not shown as considered")
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "quarantine_email"]


# ---------------------------- R2-2. a critical group or tag reported on the host's FQDN record --
@pytest.mark.parametrize("field, value", [("groups", "Domain Controllers"), ("tags", "production")])
@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_r2_critical_group_or_tag_on_the_hosts_fqdn_record_elevates_host_actions(workflow: str, field: str,
                                                                                  value: str):
    """Two sources report the same machine under two spellings: Secure Endpoint by its short name (with
    the connector) and a second source by its DNS name, which is the record that carries its
    ``Domain Controllers`` group or ``production`` tag. ``same_endpoint`` treats both as one host
    (14.13.3 aliases), so every action on that host is ELEVATED with a visible warning, never
    STANDARD because the critical context sat on the other spelling."""
    host = _isolated_host(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    source = next(r for r in data["environment"]["records"]
                  if r["record"].get("kind") == "endpoint" and str(r["record"].get("hostname", "")).upper() == host.upper())
    data["environment"]["records"].append({
        "integration": source["integration"], "atomic": source["atomic"], "subject": source["subject"],
        "record": {"kind": "endpoint", "hostname": host.lower() + ".corp.example.com", field: [value]}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, host)]
    assert on_host, f"{workflow}: precondition, an action on {host}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host if _weak(a)]
    assert weak == [], (f"{workflow}: {field} {value!r} reported on {host}'s DNS-name record is ignored, the "
                        f"actions stay STANDARD: {weak}")


# ------------------------------------------- R2-3. passwords in URL query strings never leak --
@pytest.mark.parametrize("key", ["pass", "pwd"])
@pytest.mark.parametrize("workflow", URL_WORKFLOWS)
def test_r2_url_password_parameters_never_reach_outputs_audit_or_vendors(workflow: str, key: str):
    """A login or upload URL carries a password as ``pass=`` or ``pwd=`` (the most common names of a
    password parameter in web forms and web-shell requests). The URL becomes evidence, a rationale and
    possibly a block target: the password must reach neither the package, notes, notifications,
    decision report and audit trail, nor a vendor in a block request."""
    baseline = _baseline(workflow)
    old = [t for a, t, _k in baseline if a is ActionType.BLOCK_URL][0]
    new = f"{old}?user=jsmith&{key}={SECRET_PASSWORD}"
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), old, new)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    assert run.detection.package is not None and run.detection.package.actions
    _approve_all(run)
    leaked_out = SECRET_PASSWORD in _outputs_text(run)
    leaked_vendor = [f"{c[1]}:{c[2]}" for c in _state_calls(run) if SECRET_PASSWORD in (c[2] or "")]
    assert not leaked_out and leaked_vendor == [], (
        f"{workflow}: the '{key}=' password of a URL reached outputs/audit ({leaked_out}) or vendors {leaked_vendor}")


# ------------------------------------------------- R2-4. the server's own address is never blocked --
@pytest.mark.parametrize("workflow", ["vulnerability-exploitation", "web-attacks"])
def test_r2_address_the_investigated_server_reports_as_its_own_is_never_blocked(workflow: str):
    """The source of the flagged inbound requests is an address an investigated server reports as its
    own (a health check or hairpin through the WAF, or a proxy that loses the client address). Blocking
    it cuts the organisation's own server off the network at STANDARD approval: it is never proposed
    as a block_ip (vulnerability-exploitation already never treats such an address as a source)."""
    host = _isolated_host(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    own = next(a for r in _records(data) if r.get("kind") == "endpoint"
               and str(r.get("hostname", "")).upper() == host.upper() for a in (r.get("ip_addresses") or []))
    attacker = [t for a, t, _k in _baseline(workflow) if a is ActionType.BLOCK_IP][0]
    data = _walk_replace(data, attacker, own)
    data["environment"]["reputations"] = [r for r in data["environment"]["reputations"] if r.get("type") != "ip"]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    blocked = [s for s in _proposed(run) if s == f"block_ip:{own}"]
    assert blocked == [], f"{workflow}: the server's own address {own} ({host}) is proposed for a block"
    package = run.detection.package
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip" and (c[2] or "") == own]
