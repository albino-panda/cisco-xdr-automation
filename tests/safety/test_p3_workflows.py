"""Adversarial safety tests, Phase 3 round 1, lens: workflow safety.

Every test asserts the SAFE behaviour required by docs/architecture.md (sections 13 and 14, as built
in 14.11) for the five Phase 3 workflows (malicious-powershell, credential-dumping, lateral-movement,
persistence, unauthorized-rmm), so a failing test is a defect. The tests start from each workflow's
own scenario fixtures and mutate them the way an attacker or an unlucky configuration would:
allow-list the targets, mark them critical, sanction the tool, fail a source, fail an action,
pre-contain a target, put credential-looking text into vendor records, and so on.

Fake data only: documentation IPs, example domains, fake hashes, hosts like TH-LT-1047 and users like
jsmith@example.com. Nothing here talks to a network or a real vendor; the simulated lab adapters
record every call they receive. Attacker behaviour is described abstractly; no command line below is
an attack: they are ordinary administrative commands that happen to carry a (fake) credential.
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
from xdr_response.workflows.runner import RuleOutcomeStatus

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "workflows"
PACKAGE_DIR = REPO_ROOT / "src" / "xdr_response" / "workflows"
CATALOG = discover_workflows()
P3_WORKFLOWS = ("malicious-powershell", "credential-dumping", "lateral-movement", "persistence", "unauthorized-rmm")

#: Execution-side audit events that must never appear before (or without) a live approval.
_EXECUTION_EVENTS = frozenset({AuditEventType.ACTION_STARTED, AuditEventType.ACTION_RESULT,
                               AuditEventType.CONTROL_REGISTERED, AuditEventType.VERIFICATION_RESULT,
                               AuditEventType.CONTAINMENT_COMPLETED, AuditEventType.RESTORATION_RESULT})

#: Fake credential-looking values planted in vendor records. None may reach a package, a summary,
#: a note, a notification or the audit trail.
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


def _baseline(workflow: str, name: str = "tp-approve-all", *,
              data: Mapping[str, Any] | None = None) -> list[tuple[ActionType, str, TargetKind]]:
    """The package actions of the unmodified scenario (dry run), then a fresh guard."""
    run = _detect(_raw(workflow, name) if data is None else data, workflow, name, live=False)
    package = run.detection.package
    guard._reset_for_test_harness()
    assert package is not None, f"{workflow}/{name}: the unmodified scenario must propose a package"
    return [(a.action_type, a.target, a.target_kind) for a in package.actions]


def _recommended(run: WorkflowScenarioRun) -> set[tuple[ActionType, str]]:
    """Everything the run recommends to a human: the package actions plus the UNROUTED outcomes.

    terminate_process, quarantine_file, remove_persistence and (without Defender for Endpoint) block_hash
    have no VERIFIED write on the enabled real-parity adapters (architecture 14.14.3, 15.2). The run still
    recommends them for manual handling as UNROUTED outcomes, so a check of what is (or is never)
    recommended must look there too, or it would pass vacuously. An unrouted outcome whose target the
    allow-list excludes ("never block it by hand") is not a recommendation.
    """
    package = run.detection.package if run.detection else None
    out = {(a.action_type, a.target) for a in (package.actions if package else ())}
    if run.workflow_run is not None:
        out |= {(o.action_type, o.target) for o in run.workflow_run.outcomes_with(RuleOutcomeStatus.UNROUTED)
                if o.target and "never block it by hand" not in o.detail}
    return out


def _recommended_baseline(workflow: str, name: str = "tp-approve-all") -> list[tuple[ActionType, str, TargetKind]]:
    """:func:`_recommended` of the unmodified scenario (dry run), then a fresh guard."""
    run = _detect(_raw(workflow, name), workflow, name, live=False)
    out = sorted(_recommended(run), key=lambda item: (item[0].value, item[1]))
    guard._reset_for_test_harness()
    return [(a, t, get_action_spec(a).target_kind) for a, t in out]


#: Workflows whose default lab executes fewer than two actions now that the simulated adapters mirror the
#: real ones (persistence: only the Secure Endpoint isolation has a write; the hash block, termination,
#: quarantine and persistence removal are unrouted). The multi-action checks (partial failure, release)
#: also enable Defender for Endpoint, a real-parity adapter with a hash-block write, so there are two
#: controls to work with.
_MULTI_ACTION_SUITE: Mapping[str, Mapping[str, list[str]]] = {"persistence": {"defender_endpoint": ["endpoint"]}}


def _multi_action_tp(workflow: str) -> dict[str, Any]:
    """tp-approve-all, with the extra real-parity adapter of :data:`_MULTI_ACTION_SUITE` when listed."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    extra = _MULTI_ACTION_SUITE.get(workflow)
    if extra:
        data["suite"] = {**(data.get("suite") or {}), **extra}
    return data


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


def _text_replace(node: Any, old: str, new: str) -> Any:
    """Replace a substring in every string of a scenario fragment (keys untouched)."""
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
    """The vendor reports the host by another spelling (its FQDN) inside its records; the lookup
    subject (what the investigation asked for) is unchanged."""
    for entry in data["environment"].get("records") or ():
        entry["record"] = _text_replace(entry["record"], old, new)


def _on_host(action: Any, host: str) -> bool:
    return (action.target_kind in _ENDPOINT_KINDS
            and _host_part(action.target).upper().split(".", 1)[0] == host.upper())


def _outputs_text(run: WorkflowScenarioRun, *, audit: bool = True) -> str:
    """Everything an analyst or another system sees: package, run summary and notes, notifications,
    the decision report and (optionally) the audit trail."""
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


# ============================================================ 1. no state change without approval --
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_rerunning_detection_after_containment_does_not_execute_without_new_approval(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    calls_before = len(run.environment.state_changing_calls())
    try:
        run.orchestrator.handle_detection(run.workflow_scenario.incident)
    except Exception:  # noqa: BLE001 - refusing a second detection is fine
        pass
    assert len(run.environment.state_changing_calls()) == calls_before


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_rejected_package_cannot_be_approved_afterwards(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    run.decide({"decision": "REJECT", "comment": "lab rejection"}, approvers=_approvers(package))
    with pytest.raises(Exception):  # noqa: B017 - any refusal is fine; executing is not
        run.orchestrator.submit_decision(run._request(package, {"decision": "APPROVE_ALL"}, "APPROVE_ALL"),
                                         run.credentials(*_approvers(package)))
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_approve_selected_executes_only_the_selected_actions(workflow: str):
    """An analyst approving one action approves only that action: nothing else in the package (for
    example the session revocation of credential-dumping) executes."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    package = run.orchestrator.latest_package(run.incident_id)
    chosen = package.actions[-1]
    run.decide({"decision": "APPROVE_SELECTED", "select": [f"{chosen.action_type.value}:{chosen.target}"]},
               approvers=_approvers(package))
    touched = {(op, (tgt or "").lower()) for _i, op, tgt in _state_calls(run)}
    others = {(a.action_type.value, a.target.lower()) for a in package.actions} - {
        (chosen.action_type.value, chosen.target.lower())}
    assert not (touched & others), f"{workflow}: unselected actions executed: {sorted(touched & others)}"


# ============================================================================= 2. dry run is inert --
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
@pytest.mark.parametrize("name", ["tp-approve-all", "dry-run", "critical-asset-elevated"])
def test_dry_run_approve_all_is_side_effect_free_end_to_end(workflow: str, name: str):
    """Dry run end to end: even an approved package (analyst plus lead) performs no state-changing
    call, registers no temporary control and records no execution event."""
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_dry_run_release_attempt_is_side_effect_free(workflow: str):
    run = _detect(_raw(workflow, "release-restoration"), workflow, "release-restoration", live=False)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


# ================================================================== 3. benign produces no containment --
def _benign_cases() -> list[Any]:
    out = []
    for workflow in P3_WORKFLOWS:
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
        f"{workflow}/{name}: benign incident proposed {[(a.action_type.value, a.target) for a in package.actions]}")
    assert _state_calls(run) == []
    assert run.runtime.registry.list() == []


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_without_any_record_or_rating_nothing_is_recommended(workflow: str):
    """No invented facts: with no investigation record and no rating, the incident title, its MITRE
    techniques and its observables alone never produce a recommendation."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    data["environment"]["reputations"] = []
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    assert package is None or not package.actions
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_ratings_alone_without_endpoint_records_never_isolate_or_disable(workflow: str):
    """Reputation answers about indicators are not evidence about a host or an account: with the
    endpoint and identity records removed (only the vendor ratings left), nothing may isolate an
    endpoint, terminate a process or touch an account."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"] = []
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    bad = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())
           if a.action_type in (ActionType.ISOLATE_ENDPOINT, ActionType.TERMINATE_PROCESS, ActionType.DISABLE_USER,
                                ActionType.REVOKE_SESSIONS)]
    assert bad == [], f"{workflow}: host or account actions without any host or account record: {bad}"


# ========================================================== 4. allow-listed items are never blocked --
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_allowlist_matching_ignores_case_and_trailing_dot(workflow: str):
    baseline = _baseline(workflow)
    listed = [t for t in baseline if t[2] in _ALLOWLISTABLE - {TargetKind.URL}]
    data = _with_config(_raw(workflow, "tp-approve-all"), _allowlist_override(listed, spell=_odd_spelling))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    leaked = sorted(f"{a.value}:{t}" for a, t, _k in listed if (a, t) in proposed)
    assert leaked == []


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_allowlisted_endpoint_reported_by_its_fqdn_is_never_contained(workflow: str):
    """``TH-LT-1047`` is allow-listed and the vendor records name it ``TH-LT-1047.corp.example.com``:
    the same machine, so nothing on it is contained and approving touches nothing on it."""
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_approved_rmm_and_dns_tool_indicators_are_never_blocked(workflow: str):
    """Hashes and domains of sanctioned tools (approved RMM, approved DNS tools) are never blocked,
    nor are the running processes of those binaries terminated."""
    baseline = _recommended_baseline(workflow)
    hashes = sorted({t for _a, t, k in baseline if k is TargetKind.HASH})
    domains = sorted({t for _a, t, k in baseline if k is TargetKind.DOMAIN})
    if not hashes and not domains:
        pytest.skip(f"{workflow} proposes no hash or domain block")
    base = _repo_allowlists()
    override = {"allowlists": {**base,
                               "approved_rmm": [{"name": "Lab RMM", "hashes": hashes, "domains": [], "signers": []}],
                               "approved_dns_tools": [{"name": "Lab DNS", "hashes": [], "domains": domains,
                                                       "signers": []}]}}
    data = _with_config(_raw(workflow, "tp-approve-all"), override)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    for action_type, target in _recommended(run):
        kind = get_action_spec(action_type).target_kind
        if kind is TargetKind.HASH:
            assert target not in hashes, f"approved RMM hash recommended: {action_type.value}"
        if kind is TargetKind.DOMAIN:
            assert target not in domains, "approved DNS tool domain recommended for blocking"
    if package is not None and package.actions:
        _approve_all(run)
    touched = {(op, (tgt or "").lower()) for _i, op, tgt in _state_calls(run)}
    hit = sorted(f"{op}:{t}" for op, t in touched if t in hashes or t in domains)
    assert hit == []


_NON_PUBLIC = ["10.20.30.40", "127.0.0.1", "169.254.10.10", "100.64.1.9"]


@pytest.mark.parametrize("workflow", ["malicious-powershell", "lateral-movement", "unauthorized-rmm"])
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


@pytest.mark.parametrize("workflow", ["malicious-powershell", "lateral-movement", "unauthorized-rmm"])
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


@pytest.mark.parametrize("workflow", ["malicious-powershell", "unauthorized-rmm"])
@pytest.mark.parametrize("internal", ["update.example.internal", "printer.local", "files.corp.example.com"])
def test_internal_domain_is_never_silently_blocked(workflow: str, internal: str):
    """The organisation's own internal names (exclusions.internal_domains and suffixes) are never a
    STANDARD domain block."""
    baseline = _baseline(workflow)
    domain = [t for a, t, _k in baseline if a is ActionType.BLOCK_DOMAIN][0]
    data = json.loads(json.dumps(_raw(workflow, "tp-approve-all")).replace(domain, internal))
    run = _detect(data, workflow, "tp-approve-all", live=False)
    package = run.detection.package
    weak = [a.target for a in (package.actions if package else ())
            if a.action_type in (ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL) and internal in a.target
            and (a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings)]
    assert weak == [], f"{workflow}: internal domain {internal} proposed as a STANDARD block: {weak}"


def test_malicious_powershell_never_blocks_the_organisations_own_domain():
    """A PowerShell process that contacted the organisation's own domain (example.com, never_block)
    which a vendor rates malicious must not lead to a block of the owned domain."""
    baseline = _baseline("malicious-powershell")
    domain = [t for a, t, _k in baseline if a is ActionType.BLOCK_DOMAIN][0]
    data = json.loads(json.dumps(_raw("malicious-powershell", "tp-approve-all")).replace(domain, "cdn.example.com"))
    run = _detect(data, "malicious-powershell", "tp-approve-all", live=True)
    package = run.detection.package
    blocked = [a.target for a in package.actions if a.action_type is ActionType.BLOCK_DOMAIN
               and (a.target == "example.com" or a.target.endswith(".example.com"))]
    assert blocked == []
    _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "block_domain" and "example.com" in (c[2] or "")]


# ===================================================== 4b. sanctioned remote access tools (RMM) --
_APPROVED_HASH = "1111111111111111111111111111111111111111111111111111111111111111"
_SIGNED_HASH = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"


def _strip_process_hashes(data: dict[str, Any]) -> dict[str, Any]:
    """Process events without the image hash (Defender timeline rows and some trajectory events
    carry the process name and pid only)."""
    for record in _records(data):
        if record.get("kind") == "process_event":
            record.pop("sha256", None)
    return data


def test_rmm_process_of_an_approved_tool_is_not_terminated_when_the_start_event_has_no_hash():
    """edge-approved-rmm-excluded: the approved Example RMM agent (hash in allowlists.approved_rmm)
    carries a hostile session. Its termination is withheld (ALLOWLISTED) because the process event
    reports the approved hash. When the start event carries only the name and pid (the hash is known
    from the detection, the connection and the prevalence record of the same tool), the process is
    still the sanctioned binary and must not be proposed for termination either."""
    data = _strip_process_hashes(copy.deepcopy(_raw("unauthorized-rmm", "edge-approved-rmm-excluded")))
    run = _detect(data, "unauthorized-rmm", "edge-approved-rmm-excluded", live=True)
    package = run.detection.package
    killed = [t for a, t in _recommended(run) if a is ActionType.TERMINATE_PROCESS]
    assert killed == [], f"approved RMM agent recommended for termination: {killed}"
    if package is not None and package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if c[1] == "terminate_process"]


def test_rmm_process_of_an_approved_signer_build_is_not_terminated_when_the_start_event_has_no_hash():
    """edge-approved-signer-new-build: a new build of the sanctioned agent is identified by the
    approved signer on its prevalence record. Without the hash on the process start event the
    termination of that same binary must still be withheld."""
    data = _strip_process_hashes(copy.deepcopy(_raw("unauthorized-rmm", "edge-approved-signer-new-build")))
    run = _detect(data, "unauthorized-rmm", "edge-approved-signer-new-build", live=False)
    killed = [t for a, t in _recommended(run) if a is ActionType.TERMINATE_PROCESS]
    assert killed == [], f"approved-signer RMM build recommended for termination: {killed}"


def test_rmm_relay_of_an_approved_signer_build_is_never_blocked():
    """A new build of the sanctioned agent (approved signer, hash not listed yet) that Secure
    Endpoint flags SUSPICIOUS as a PUA talks to a relay host of the vendor that the approved_rmm entry
    does not list yet. The tool is sanctioned: its hash block and termination are withheld, and the
    session shows no untrusted operator, so blocking its relay fleet-wide (cutting IT's remote
    support) must not be recommended on the PUA flag alone."""
    data = copy.deepcopy(_raw("unauthorized-rmm", "edge-approved-signer-new-build"))
    data = _text_replace(data, "rmm.example.net", "relay-eu.examplermm-cloud.test")
    run = _detect(data, "unauthorized-rmm", "edge-approved-signer-new-build", live=False)
    package = run.detection.package
    blocked = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())]
    assert blocked == [], f"sanctioned (approved-signer) tool's relay proposed for blocking: {blocked}"


def test_rmm_relay_subdomain_of_an_approved_domain_is_excluded():
    """approved_rmm domains cover their subdomains (relay-07.rmm.example.net is Example RMM)."""
    data = copy.deepcopy(_raw("unauthorized-rmm", "edge-approved-rmm-excluded"))
    data = _text_replace(data, "rmm.example.net", "relay-07.rmm.example.net")
    run = _detect(data, "unauthorized-rmm", "edge-approved-rmm-excluded", live=True)
    package = run.detection.package
    blocked = [a.target for a in package.actions if a.action_type is ActionType.BLOCK_DOMAIN]
    assert blocked == []
    assert (ActionType.BLOCK_DOMAIN, "relay-07.rmm.example.net") in {
        (e.action_type, e.target) for e in package.excluded_targets}
    # the hostile session still gets its isolation: sanctioning the tool never withholds it
    assert any(a.action_type is ActionType.ISOLATE_ENDPOINT for a in package.actions)


@pytest.mark.parametrize("signer", ["EXAMPLE RMM VENDOR INC.", "  Example   RMM Vendor Inc. "])
def test_rmm_approved_signer_matching_ignores_case_and_whitespace(signer: str):
    data = copy.deepcopy(_raw("unauthorized-rmm", "edge-approved-signer-new-build"))
    for record in _records(data):
        if record.get("kind") == "hash_prevalence":
            record["signer"] = signer
    run = _detect(data, "unauthorized-rmm", "edge-approved-signer-new-build", live=False)
    assert not [a for a, _t in _recommended(run) if a in (ActionType.BLOCK_HASH, ActionType.TERMINATE_PROCESS)]


def test_rmm_look_alike_signer_is_not_treated_as_approved():
    """Exact signer matching: "Example RMM Vendor Inc. Clone" is not the approved signer, so a flagged
    tool with that signer is still recommended for containment (no false sanctioning)."""
    data = copy.deepcopy(_raw("unauthorized-rmm", "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "hash_prevalence":
            record["signer"] = "Example RMM Vendor Inc. Clone"
    run = _detect(data, "unauthorized-rmm", "tp-approve-all", live=False)
    # The hash block has no VERIFIED write in this lab (unrouted, for manual handling): still recommended.
    assert any(a is ActionType.BLOCK_HASH for a, _t in _recommended(run))


def test_rmm_sanctioned_tool_in_persistence_workflow_is_never_blocked_or_terminated():
    """The persistence workflow sees the approved RMM agent installed as a service and rated
    malicious by a vendor: its hash block and the termination of its process are withheld
    (allowlists.approved_rmm), never proposed."""
    data = copy.deepcopy(_raw("persistence", "tp-approve-all"))
    baseline = _recommended_baseline("persistence")
    sha = [t for a, t, _k in baseline if a is ActionType.BLOCK_HASH][0]
    data = _walk_replace(data, sha, _APPROVED_HASH)
    for ref in data["incident"].get("observables") or ():
        if ref.get("value") == sha:
            ref["value"] = _APPROVED_HASH
    run = _detect(data, "persistence", "tp-approve-all", live=True)
    bad = [f"{a.value}:{t}" for a, t in sorted(_recommended(run), key=lambda i: (i[0].value, i[1]))
           if a in (ActionType.BLOCK_HASH, ActionType.TERMINATE_PROCESS)]
    assert bad == [], f"approved RMM binary blocked or terminated by persistence: {bad}"


# ============================================================ 5. critical assets come out ELEVATED --
def _critical_override(baseline: Iterable[tuple[ActionType, str, TargetKind]]) -> dict[str, Any]:
    hosts = sorted({_host_part(t) for _a, t, k in baseline if k in _ENDPOINT_KINDS})
    users = sorted({t for _a, t, k in baseline if k is TargetKind.USER})
    ips = sorted({f"{t}/32" for _a, t, k in baseline if k is TargetKind.IP})
    return {"critical_assets": {"classes": {
        "executive_endpoint": {"match": {"hostnames": hosts, "users": users}},
        "production_server": {"match": {"ip_cidrs": ips or ["203.0.113.0/26"]}},
    }}}


_CRITICAL_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER, TargetKind.IP})


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_host_actions_on_a_domain_controller_known_from_vendor_records_are_elevated(workflow: str):
    """When the only place that says a host is a domain controller (group "Domain Controllers") is
    the vendor record the workflow investigated, every action on that host (isolation, process
    termination) is still ELEVATED with a warning, never skipped."""
    baseline = _baseline(workflow)
    hosts = {_host_part(t) for _a, t, k in baseline if k in _ENDPOINT_KINDS}
    if not hosts:
        pytest.skip(f"{workflow}: no host action")
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


def _account_actions(package: Any, user: str) -> list[Any]:
    return [a for a in package.actions if a.target_kind is TargetKind.USER and a.target == user]


def test_credential_dumping_disable_of_an_account_the_identity_provider_marks_privileged_is_elevated():
    """credential-dumping/tp-approve-all: Entra reports it.support@example.com as privileged
    (``privileged: true``, role Helpdesk Administrator). The workflow itself says so ("account ... is
    privileged (identity provider: ...)") and proposes disabling the account because it is privileged.
    14.11.4: privileged accounts exposed by credential dumping are ELEVATED through the
    privileged-account class. Disabling (or revoking) a privileged account must never be a
    one-analyst STANDARD action without a warning."""
    run = _detect(_raw("credential-dumping", "tp-approve-all"), "credential-dumping", "tp-approve-all", live=False)
    package = run.detection.package
    actions = _account_actions(package, "it.support@example.com")
    assert any(a.action_type is ActionType.DISABLE_USER for a in actions), "precondition"
    assert any("privileged" in a.rationale for a in actions if a.action_type is ActionType.DISABLE_USER)
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"privileged account contained at STANDARD approval without a warning: {weak}"


def test_lateral_movement_account_the_identity_provider_marks_privileged_is_elevated():
    """lateral-movement: the account used for the movement is marked privileged by Entra
    (``privileged: true``) with a directory role outside the static role list. The disable and the
    revocation of that privileged account must be ELEVATED with a warning."""
    data = copy.deepcopy(_raw("lateral-movement", "tp-approve-all"))
    marked = False
    for record in _records(data):
        if record.get("kind") == "user_profile" and record.get("user") == "jsmith@example.com":
            record["privileged"] = True
            record["roles"] = ["Helpdesk Administrator"]
            marked = True
    assert marked
    run = _detect(data, "lateral-movement", "tp-approve-all", live=False)
    actions = _account_actions(run.detection.package, "jsmith@example.com")
    assert actions, "precondition: account actions on jsmith@example.com"
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"privileged account contained at STANDARD approval without a warning: {weak}"


@pytest.mark.parametrize("workflow", ["credential-dumping", "lateral-movement"])
@pytest.mark.parametrize("role", ["Global Administrator", "privileged role administrator"])
def test_account_with_a_listed_privileged_role_is_elevated(workflow: str, role: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "user_profile" and record.get("user") == "jsmith@example.com":
            record["roles"] = [role]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    actions = _account_actions(run.detection.package, "jsmith@example.com")
    assert actions
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in actions)


def test_credential_dumping_on_a_domain_controller_keeps_account_actions_and_elevates():
    """14.11.4: on a domain controller account actions stay proposed (never skipped), the isolation is
    ELEVATED with a warning and the domain-wide reset is a manual step."""
    run = _detect(_raw("credential-dumping", "edge-domain-controller-ntds"), "credential-dumping",
                  "edge-domain-controller-ntds", live=False)
    package = run.detection.package
    assert package is not None
    isolations = [a for a in package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert isolations and all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in isolations)
    assert any(a.target_kind is TargetKind.USER for a in package.actions)
    assert any(s.startswith("domain-credential-reset:") for s in _considered_subjects(run))


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


# ======================================================= 6. evidence references real, relevant records --
def _all_scenarios() -> list[Any]:
    out = []
    for workflow in P3_WORKFLOWS:
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
    return [target]


@pytest.mark.parametrize("workflow, name", _all_scenarios())
def test_every_proposed_action_cites_a_record_about_its_target(workflow: str, name: str):
    """No invented facts: every package action cites uniquely numbered evidence from the run's own
    records, at least one cited record is about the target itself, and risk and confidence are
    separate integers."""
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
    """Hand-offs and manual steps are shown to the analyst as findings: they cite records of the run,
    never an invented id."""
    run = _detect(_raw(workflow, name), workflow, name, live=False)
    wf = run.workflow_run
    problems = []
    for item in wf.considered:
        unknown = [i for i in item.record_ids if i not in wf.index]
        if unknown:
            problems.append(f"considered {item.subject}: unknown records {unknown}")
    for handoff in getattr(wf, "handoffs", ()) or ():
        unknown = [i for i in handoff.record_ids if i not in wf.index]
        if not handoff.record_ids or unknown:
            problems.append(f"handoff {handoff.workflow_id}: records {unknown or 'none'}")
    assert problems == []


# ======================================================== 7. degraded sources never block the rest --
def _degradation_cases() -> list[Any]:
    out = []
    for workflow in P3_WORKFLOWS:
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_degraded_source_is_reported_not_hidden(workflow: str):
    """A failed source is visible: the run lists it as degraded (never silently ignored)."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": "UNAVAILABLE", "integration": "virustotal", "times": None}]
    suite = _scenario(data, workflow, "tp-approve-all").effective_suite()
    if "virustotal" not in suite:
        pytest.skip("virustotal not simulated")
    run = _detect(data, workflow, "tp-approve-all", live=False)
    summary = run.workflow_run.summary().model_dump_json()
    assert "virustotal" in summary


# =============================================================== 8. partial failures are reported --
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("fault", ["FAIL", "NO_EFFECT", "TIMEOUT", "AUTH_FAIL", "INVALID_TARGET"])
def test_one_failed_or_ineffective_action_reports_partially_contained(workflow: str, position: str, fault: str):
    data = _multi_action_tp(workflow)
    baseline = _baseline(workflow, data=data)
    assert len(baseline) >= 2, f"{workflow}: need two executable actions for this test"
    action_type, target, _kind = baseline[0] if position == "first" else baseline[-1]
    data["environment"]["faults"] = list(data["environment"].get("faults") or []) + [
        {"kind": fault, "operation": action_type.value, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report is not None
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED, (
        f"{workflow}: {fault} on {action_type.value} {target} reported {decision.report.overall}")


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_partial_failure_fixture_reports_partially_contained(workflow: str):
    run = _detect(_raw(workflow, "partial-failure"), workflow, "partial-failure", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


# ============================================================= 9. release: approval and ownership --
_REVERSIBLE = frozenset({ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL,
                         ActionType.BLOCK_IP, ActionType.BLOCK_HASH, ActionType.DISABLE_USER,
                         ActionType.QUARANTINE_EMAIL, ActionType.QUARANTINE_FILE})


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_release_needs_release_approval_and_never_touches_preexisting_controls(workflow: str):
    data = _multi_action_tp(workflow)
    baseline = _baseline(workflow, data=data)
    reversible = [(a, t) for a, t, _k in baseline if a in _REVERSIBLE]
    assert len(reversible) >= 2, f"{workflow}: need two reversible actions for this test"
    pre_action, pre_target = reversible[0]
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_containment_approval_cannot_be_reused_as_release_approval(workflow: str):
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_release_never_touches_another_incidents_controls(workflow: str):
    """Two incidents contain different targets; releasing the first only restores its own controls."""
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    mine = {c.control_key for c in run.runtime.registry.list(incident_id=run.incident_id)}
    release = run.propose_release()
    assert set(release.control_keys) <= mine
    before = len(run.environment.state_changing_calls())
    run.decide_release({"decision": "APPROVE_ALL"}, approvers=["analyst", "lead"])
    restored = run.environment.state_changing_calls()[before:]
    restore_ops = {get_action_spec(c.action_type).rollback_action_type.value for c in run.runtime.registry.list(
        incident_id=run.incident_id) if get_action_spec(c.action_type).rollback_action_type is not None}
    assert all(c.operation in restore_ops for c in restored), (
        f"{workflow}: release performed a non-restoration call: {[c.operation for c in restored]}")


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
        elif kind == "persistence_item":
            record["command_line"] = f"agent.exe --password={SECRET_PASSWORD}"
            planted = True
    assert planted
    return data


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_planted_credentials_never_reach_packages_summaries_notifications_or_audit(workflow: str):
    data = _plant_secrets(workflow)
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    text = _outputs_text(run)
    leaked = [s for s in (SECRET_PASSWORD, SECRET_UNLOCK, SECRET_TOKEN) if s in text]
    assert leaked == [], f"{workflow}: planted secret(s) {leaked} reached analyst-facing output or audit"


#: Ordinary administrative command lines that carry a (fake) credential in a form the generic
#: ``--key value`` / ``key=value`` rules do not name. "LABMARK" is a harmless marker that proves the
#: command line itself reached the outputs (so the test is not vacuous).
_ADMIN_COMMAND_LINES = {
    "powershell-securestring-literal": (
        "powershell.exe -NoProfile -Command \"$p = ConvertTo-SecureString '" + SECRET_PASSWORD
        + "' -AsPlainText -Force; Write-Output LABMARK\""),
    "powershell-securestring-string-param": (
        "powershell.exe -NoProfile -Command \"ConvertTo-SecureString -String " + SECRET_PASSWORD
        + " -AsPlainText -Force; Write-Output LABMARK\""),
    "cmdkey-pass": f"cmdkey.exe /add:TH-SRV-0310 /user:jsmith /pass:{SECRET_PASSWORD} LABMARK",
    "schtasks-run-as-password": (
        f"schtasks.exe /create /tn LABMARK /tr C:\\lab\\agent.exe /sc onlogon /ru jsmith /rp {SECRET_PASSWORD}"),
    "net-use-positional-password": f"net.exe use \\\\TH-SRV-0310\\share {SECRET_PASSWORD} /user:jsmith LABMARK",
}


@pytest.mark.parametrize("workflow", ["malicious-powershell", "persistence", "credential-dumping"])
@pytest.mark.parametrize("label", sorted(_ADMIN_COMMAND_LINES))
def test_credential_in_an_admin_command_line_never_reaches_outputs(workflow: str, label: str):
    """Process and persistence command lines are cited as package evidence. A password given to an
    administrative command (a SecureString literal, ``/pass:``, ``/rp``, a positional ``net use``
    password) is as sensitive as ``--password=VALUE`` and must be redacted before it reaches the
    package, the notes, a notification or the (append-only) audit trail."""
    command = _ADMIN_COMMAND_LINES[label]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = False
    for record in _records(data):
        if record.get("kind") in ("process_event", "persistence_item"):
            record["command_line"] = command
            planted = True
    assert planted
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    text = _outputs_text(run)
    if "LABMARK" not in text:
        pytest.skip(f"{workflow}: command lines are not cited in the outputs")
    assert SECRET_PASSWORD not in text, f"{workflow}: password in a {label} command line reached outputs or audit"


@pytest.mark.parametrize("workflow", ["persistence", "unauthorized-rmm", "malicious-powershell"])
def test_persistence_item_name_with_a_credential_is_redacted(workflow: str):
    """Persistence item names and paths are attacker-controlled free text that hooks quote into
    reasons and hand-offs; a credential in them must not reach outputs."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    items = [r for r in _records(data) if r.get("kind") == "persistence_item"]
    if not items:
        host_records = [r for r in (data["environment"].get("records") or ())
                        if r["record"].get("kind") == "endpoint"]
        assert host_records
        template = host_records[0]
        sha = next((r.get("sha256") for r in _records(data) if r.get("kind") == "detection" and r.get("sha256")), None)
        data["environment"]["records"].append({
            "integration": template["integration"], "atomic": "investigate_endpoint", "subject": template["subject"],
            "record": {"kind": "persistence_item", "endpoint": template["record"]["hostname"],
                       "item_id": "svc-lab", "mechanism": "service", "name": f"Updater password={SECRET_PASSWORD}",
                       "path": "C:\\lab\\AnyDesk.exe", "sha256": sha, "verdict": "MALICIOUS"}})
    else:
        for item in items:
            item["name"] = f"Updater password={SECRET_PASSWORD}"
    run = _detect(data, workflow, "tp-approve-all", live=False)
    assert SECRET_PASSWORD not in _outputs_text(run)


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_profile_details_the_analyst_does_not_need_stay_out_of_the_package_and_notifications(workflow: str):
    """User profiles carry manager, job title and display name. None of it is needed to approve a
    containment action, so none of it may appear in the package or a notification."""
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_isolation_unlock_codes_never_reach_outputs_or_audit(workflow: str):
    """An isolation returns an unlock code in some products; a vendor detection may quote it. It is a
    credential for the host and must never reach the package, notes, notifications or audit."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "endpoint":
            record["isolation_state"] = "not_isolated"
        if record.get("kind") == "detection":
            record["name"] = f"Endpoint isolation unlock code for {_HOST} is {SECRET_UNLOCK}"
    run = _detect(data, workflow, "tp-approve-all", live=True)
    _approve_all(run)
    assert SECRET_UNLOCK not in _outputs_text(run)


# =====================================================================================================
# Deeper probes: second-source and multi-address asset context, blast radius, protected accounts,
# degraded endpoint sources on hosts another product manages.
# =====================================================================================================
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_critical_ip_on_a_second_interface_makes_host_actions_elevated(workflow: str):
    """A production server is often reported with a management address first and its production
    address second. critical-assets production_server matches 203.0.113.0/26: any of the host's
    addresses in that range makes every action on the host ELEVATED, not only the first one listed."""
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_critical_group_reported_by_a_second_endpoint_source_is_elevated(workflow: str):
    """Two products report the same host. Only the second (Defender, which does not manage the
    isolation here) says the host is a domain controller. The asset is the host, not one source's
    view of it: the actions on it are ELEVATED with a warning."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    suite = dict(_scenario(data, workflow, "tp-approve-all").effective_suite())
    suite["defender_endpoint"] = ("endpoint",)
    data["suite"] = {k: list(v) for k, v in suite.items()}
    data["environment"]["records"].append({
        "integration": "defender_endpoint", "atomic": "investigate_endpoint", "subject": _HOST,
        "record": {"kind": "endpoint", "hostname": _HOST, "os": "Windows Server 2022",
                   "groups": ["Domain Controllers"]}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_host = [a for a in run.detection.package.actions if _on_host(a, _HOST)]
    assert on_host, f"{workflow}: precondition, an action on {_HOST}"
    weak = [f"{a.action_type.value}:{a.target}" for a in on_host
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: domain controller known from the second source not ELEVATED: {weak}"


@pytest.mark.parametrize("tag", ["Production", "PRODUCTION"])
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_critical_tag_matching_ignores_case(workflow: str, tag: str):
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    for record in _records(data):
        if record.get("kind") == "endpoint":
            record["tags"] = list(record.get("tags") or []) + [tag]
    run = _detect(data, workflow, "tp-approve-all", live=False)
    on_hosts = [a for a in run.detection.package.actions if a.target_kind in _ENDPOINT_KINDS]
    assert on_hosts
    assert all(a.approval_level is ApprovalLevel.ELEVATED and a.warnings for a in on_hosts)


def test_malicious_powershell_isolation_beyond_the_endpoint_cap_is_elevated():
    """blast_radius.max_endpoints: a malicious payload present on many hosts (hash prevalence) makes
    every resulting isolation ELEVATED; none is silently dropped."""
    data = copy.deepcopy(_raw("malicious-powershell", "tp-approve-all"))
    hosts = [f"TH-LT-{2000 + i}" for i in range(8)]
    touched = False
    for record in _records(data):
        if record.get("kind") == "hash_prevalence":
            record["endpoints"] = list(record.get("endpoints") or []) + hosts
            record["prevalence"] = len(record["endpoints"])
            record["verdict"] = "MALICIOUS"
            touched = True
    assert touched
    data["environment"]["records"] += [
        {"integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": h,
         "record": {"kind": "endpoint", "hostname": h, "os": "Windows 11", "groups": ["Workstations"],
                    "connector_guid": f"00000000-0000-4000-8000-00000000{2000 + i:04d}",
                    "isolation_capable": True, "isolation_state": "not_isolated"}} for i, h in enumerate(hosts)]
    run = _detect(data, "malicious-powershell", "tp-approve-all", live=False)
    isolations = [a for a in run.detection.package.actions if a.action_type is ActionType.ISOLATE_ENDPOINT]
    assert len(isolations) > 5, f"precondition: isolations of the payload's hosts ({len(isolations)})"
    weak = [a.target for a in isolations if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"isolations beyond the endpoint cap at STANDARD approval: {weak}"


@pytest.mark.parametrize("workflow", ["credential-dumping", "lateral-movement"])
def test_allowlisted_breakglass_account_is_never_disabled_or_revoked(workflow: str):
    """breakglass@example.com is never_block.users: even exposed on a host with confirmed credential
    access (or used for movement) it is excluded visibly, never disabled or revoked."""
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), "jsmith@example.com",
                         "breakglass@example.com")
    run = _detect(data, workflow, "tp-approve-all", live=True)
    package = run.detection.package
    bad = [f"{a.action_type.value}:{a.target}" for a in package.actions if a.target == "breakglass@example.com"]
    assert bad == [], f"{workflow}: allow-listed break-glass account proposed: {bad}"
    shown = {e.target for e in package.excluded_targets} | {o.target for o in run.workflow_run.outcomes}
    assert "breakglass@example.com" in shown, "the excluded break-glass account is not shown to the analyst"
    if package.actions:
        _approve_all(run)
    assert not [c for c in _state_calls(run) if (c[2] or "").lower() == "breakglass@example.com"]


@pytest.mark.parametrize("workflow", ["credential-dumping", "lateral-movement"])
@pytest.mark.parametrize("account", ["svc-backup@example.com", "adm-jsmith@example.com", "ci-deploy@example.com"])
def test_service_admin_and_automation_accounts_are_elevated(workflow: str, account: str):
    data = _text_replace(copy.deepcopy(_raw(workflow, "tp-approve-all")), "jsmith@example.com", account)
    run = _detect(data, workflow, "tp-approve-all", live=False)
    actions = _account_actions(run.detection.package, account)
    assert actions, f"{workflow}: precondition, an action on {account}"
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: {account} contained at STANDARD approval: {weak}"


def _defender_degradation_cases() -> list[Any]:
    out = []
    for workflow in P3_WORKFLOWS:
        for path in sorted((FIXTURES / workflow).glob("edge-defender*.yaml")):
            for failed in ("secure_endpoint", "virustotal", "entra", "umbrella"):
                out.append(pytest.param(workflow, path.stem, failed, id=f"{workflow}/{path.stem}:{failed}"))
    return out


@pytest.mark.parametrize("workflow, name, failed", _defender_degradation_cases())
def test_failed_source_does_not_block_defender_backed_actions(workflow: str, name: str, failed: str):
    """Same accounting as the tp-approve-all degradation test (14.14.1), on the Defender-managed edge cases."""
    findings = degradation_findings(_raw(workflow, name), failed,
                                    lambda data: _detect(data, workflow, name, live=False))
    assert findings == [], f"{workflow}/{name}: failing {failed}: {findings}"


# =====================================================================================================
# Round 2 (P3, workflow safety). New probes: verdict flips, record removal, read-only dry run, release
# rejection and selection, every single failed action, credentials in free-text fields that are not
# named "command line", URL credentials in rationales, pid reuse behind a sanctioned binary,
# privileged role assignments reported by the identity source, and isolation of a host that owns an
# allow-listed infrastructure address.
# =====================================================================================================
def _flip_verdicts(data: Mapping[str, Any], to: str = "CLEAN") -> dict[str, Any]:
    text = json.dumps(data)
    for verdict in ("MALICIOUS", "SUSPICIOUS"):
        text = text.replace(f'"{verdict}"', f'"{to}"')
    return json.loads(text)


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
@pytest.mark.parametrize("live", [False, True], ids=["dry_run", "live"])
def test_every_verdict_clean_produces_no_containment(workflow: str, live: bool):
    """The true-positive scenario with every vendor verdict (detections, process events, connections,
    prevalence and reputation) turned CLEAN is a benign incident: nothing is contained."""
    data = _flip_verdicts(copy.deepcopy(_raw(workflow, "tp-approve-all")))
    run = _detect(data, workflow, "tp-approve-all", live=live)
    package = run.detection.package
    proposed = [f"{a.action_type.value}:{a.target}" for a in (package.actions if package else ())]
    assert proposed == [], f"{workflow}: all-CLEAN incident proposed {proposed}"
    assert _state_calls(run) == []


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_no_action_on_a_host_that_no_record_names(workflow: str):
    """Remove every record that names a host the baseline contains: no isolation or termination may
    still target that host (the title, the incident observables and ratings are not evidence about it)."""
    baseline = _recommended_baseline(workflow)
    hosts = sorted({_host_part(t) for a, t, _k in baseline
                    if a in (ActionType.ISOLATE_ENDPOINT, ActionType.TERMINATE_PROCESS)})
    assert hosts, f"{workflow}: precondition, a host action in the baseline"
    for host in hosts:
        data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
        data["environment"]["records"] = [
            e for e in data["environment"]["records"]
            if host.lower() not in json.dumps(e["record"]).lower() and str(e["subject"]).lower() != host.lower()]
        run = _detect(data, workflow, "tp-approve-all", live=False)
        bad = sorted(f"{a.value}:{t}" for a, t in _recommended(run)
                     if get_action_spec(a).target_kind in _ENDPOINT_KINDS
                     and _host_part(t).upper().split(".", 1)[0] == host.upper())  # as _on_host
        guard._reset_for_test_harness()
        assert bad == [], f"{workflow}: actions on {host} without any record naming it: {bad}"


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_dry_run_only_ever_reads_from_vendors(workflow: str):
    """Dry run end to end (detection, approval by analyst and lead, release attempt): every call that
    reached a simulated vendor is a read."""
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


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_rejected_release_restores_nothing_and_keeps_controls_active(workflow: str):
    run = _detect(_raw(workflow, "tp-approve-all"), workflow, "tp-approve-all", live=True)
    _approve_all(run)
    before = len(run.environment.state_changing_calls())
    run.propose_release()
    run.decide_release({"decision": "REJECT", "comment": "keep contained"}, approvers=["analyst", "lead"])
    assert len(run.environment.state_changing_calls()) == before
    controls = run.runtime.registry.list(incident_id=run.incident_id)
    assert controls and all(c.status.value == "ACTIVE" for c in controls)


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
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


def _every_action_cases() -> list[Any]:
    out = []
    for workflow in P3_WORKFLOWS:
        run = _detect(_multi_action_tp(workflow), workflow, "tp-approve-all", live=False)
        for action in run.detection.package.actions:
            out.append(pytest.param(workflow, action.action_type.value, action.target,
                                    id=f"{workflow}:{action.action_type.value}:{action.target[:24]}"))
        guard._reset_for_test_harness()
    return out


@pytest.mark.parametrize("workflow, operation, target", _every_action_cases())
def test_any_single_failed_action_reports_partially_contained(workflow: str, operation: str, target: str):
    """Not only the first or last action: whichever single action fails (session revocation and
    process termination included), the containment is PARTIALLY_CONTAINED."""
    data = _multi_action_tp(workflow)
    data["environment"]["faults"] = [{"kind": "FAIL", "operation": operation, "target": target, "times": None}]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report.overall is ContainmentOverall.PARTIALLY_CONTAINED


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_every_action_failing_is_never_reported_contained(workflow: str):
    baseline = _baseline(workflow)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["faults"] = [{"kind": "FAIL", "operation": a.value, "target": t, "times": None}
                                     for a, t, _k in baseline]
    run = _detect(data, workflow, "tp-approve-all", live=True)
    decision = _approve_all(run)
    assert decision.report.overall not in (ContainmentOverall.CONTAINED, ContainmentOverall.PARTIALLY_CONTAINED)
    assert run.runtime.registry.list(incident_id=run.incident_id) == []


# ---------------------------------------- credentials in free text that is not named "command line" --
#: Ordinary administrative forms that carry a (fake) credential. "LABMARK" proves the text reached
#: the outputs, so a pass is never vacuous.
_FREE_TEXT_CREDENTIALS = {
    "service-image-path-pass-switch": "C:\\lab\\agent.exe /user:svc /pass:" + SECRET_PASSWORD + " LABMARK",
    "task-action-run-as-password": "schtasks.exe /create /tn LABMARK /ru jsmith /rp " + SECRET_PASSWORD,
    "securestring-literal": "ConvertTo-SecureString '" + SECRET_PASSWORD + "' -AsPlainText -Force; LABMARK",
    "net-use-positional-password": "net.exe use \\\\TH-SRV-0310\\share " + SECRET_PASSWORD + " /user:jsmith LABMARK",
    "url-userinfo-password": "https://svc:" + SECRET_PASSWORD + "@files.example.test/LABMARK/agent.exe",
}
#: (workflow, record kind, field): vendor free text that the redactor sees only through redact_text.
_FREE_TEXT_FIELDS = [
    ("persistence", "persistence_item", "path"),      # a service ImagePath or task action with its arguments
    ("persistence", "persistence_item", "name"),
    ("unauthorized-rmm", "detection", "file_path"),
    ("malicious-powershell", "detection", "name"),     # a vendor title quoting the command it flagged
    ("credential-dumping", "detection", "file_path"),
    ("malicious-powershell", "process_event", "file_path"),
]


@pytest.mark.parametrize("workflow, kind, field", _FREE_TEXT_FIELDS,
                         ids=[f"{w}:{k}.{f}" for w, k, f in _FREE_TEXT_FIELDS])
@pytest.mark.parametrize("label", sorted(_FREE_TEXT_CREDENTIALS))
def test_command_line_credential_forms_in_other_fields_never_reach_outputs(workflow: str, kind: str, field: str,
                                                                          label: str):
    """Round 1 taught the redactor the Windows and PowerShell credential forms, but applies them only
    to fields and keys named "command line". A persistence item's path (a service ImagePath or a task
    action carries its arguments), its name, a detection title or file path carry the same text. A
    password in any of them must not reach the package, notes, notifications or the audit trail."""
    value = _FREE_TEXT_CREDENTIALS[label]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    planted = 0
    for record in _records(data):
        if record.get("kind") == kind:
            record[field] = value
            planted += 1
    if not planted:
        pytest.skip(f"{workflow}: no {kind} record")
    run = _detect(data, workflow, "tp-approve-all", live=True)
    if run.detection.package is not None and run.detection.package.actions:
        _approve_all(run)
    text = _outputs_text(run)
    assert "LABMARK" in text, "precondition: the field reaches the outputs"
    assert SECRET_PASSWORD not in text, f"{workflow}: password in {kind}.{field} ({label}) reached outputs or audit"


@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
@pytest.mark.parametrize("key", ["ScriptBlockText", "arguments"])
def test_credential_in_generic_record_attributes_never_reaches_the_audit_trail(workflow: str, key: str):
    """Generic records (Splunk script block logging, untyped trajectory rows) keep vendor attributes.
    A SecureString literal or a ``/pass:`` switch under a key that is not named "command line" must not
    be written to the append-only audit trail (or any other output)."""
    value = {"ScriptBlockText": "$c = New-Object PSCredential('svc', (ConvertTo-SecureString '" + SECRET_PASSWORD
                                + "' -AsPlainText -Force))",
             "arguments": "/user:svc /pass:" + SECRET_PASSWORD}[key]
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": _HOST,
        "record": {"kind": "generic", "name": "script block LABMARK", "attributes": {key: value}}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    text = _outputs_text(run)
    assert "LABMARK" in text, "precondition: the generic record reaches the outputs"
    assert SECRET_PASSWORD not in text, f"{workflow}: credential in generic attribute {key} reached outputs or audit"


def test_url_credentials_never_reach_rationales_or_notifications():
    """A PowerShell download from a URL with a user:password part. Evidence fields redact URLs
    (redact_url), but the rationales of other actions (the termination and the isolation quote the
    contacted destinations) and the SOC notifications must not carry the password either."""
    data = copy.deepcopy(_raw("malicious-powershell", "tp-approve-all"))
    planted = False
    for record in _records(data):
        if record.get("kind") == "network_connection":
            record["url"] = f"https://svc:{SECRET_PASSWORD}@cdn-update.test/a.ps1"
            record["domain"] = "cdn-update.test"
            planted = True
    assert planted
    run = _detect(data, "malicious-powershell", "tp-approve-all", live=False)
    package = run.detection.package
    assert package is not None and package.actions
    leaked = [a.action_type.value for a in package.actions if SECRET_PASSWORD in a.rationale]
    assert leaked == [], f"URL password quoted in the rationale of {leaked}"
    notified = [str(getattr(d, "kind", "?")) for d in run.outbox.drafts if SECRET_PASSWORD in d.model_dump_json()]
    assert notified == [], f"URL password in notifications {notified}"
    assert not [n for n in run.workflow_run.notes if SECRET_PASSWORD in n]


# ------------------------------------------------------- pid reuse behind a sanctioned binary --
@pytest.mark.parametrize("workflow", ["malicious-powershell", "persistence", "unauthorized-rmm"])
def test_termination_is_not_withheld_when_the_pid_also_ran_an_unsanctioned_binary(workflow: str):
    """Process ids are reused. An earlier process event of the same pid on the same host reports the
    approved RMM binary (allowlists.approved_rmm); the current process with that pid is the flagged
    binary of the baseline. 14.11.6: a process is treated as sanctioned only when *every* candidate
    binary is sanctioned; one unknown build keeps the action proposed. The hashed-event path must
    follow the same rule, or a hostile process escapes termination behind an old sanctioned event."""
    baseline = _recommended_baseline(workflow)
    kills = [t for a, t, _k in baseline if a is ActionType.TERMINATE_PROCESS]
    assert kills, f"{workflow}: precondition, a termination recommended in the baseline"
    host, pid = kills[0].split("/", 1)
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"].append({
        "integration": "secure_endpoint", "atomic": "investigate_endpoint", "subject": host,
        "record": {"kind": "process_event", "event_id": "evt-pid-reuse", "endpoint": host,
                   "timestamp": "2026-01-15T08:00:00Z", "event_type": "process_start",
                   "process_name": "ExampleRmmAgent.exe", "pid": int(pid), "sha256": _APPROVED_HASH}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    # terminate_process has no VERIFIED write (architecture 15.2): recommended as UNROUTED, never withheld.
    proposed = _recommended(run)
    assert (ActionType.TERMINATE_PROCESS, kills[0]) in proposed, (
        f"{workflow}: termination of {kills[0]} withheld because an older event of the same pid ran the "
        f"approved binary: {[c.subject for c in run.workflow_run.considered]}")


# ------------------------------------------ privileged role assigned during the incident --
@pytest.mark.parametrize("workflow", ["credential-dumping", "lateral-movement"])
@pytest.mark.parametrize("change", ["assigned", "activated"])
def test_account_the_identity_source_reports_holding_a_privileged_role_is_elevated(workflow: str, change: str):
    """Entra reports that jsmith@example.com was assigned (or activated) Global Administrator
    (RoleChangeRecord, ``privileged: true``) during the incident window; the profile record predates
    it. The account now holds a privileged role: revoking or disabling it is a privileged-account
    action and must be ELEVATED with a warning, never a one-analyst STANDARD action."""
    data = copy.deepcopy(_raw(workflow, "tp-approve-all"))
    data["environment"]["records"].append({
        "integration": "entra", "atomic": "investigate_user", "subject": "jsmith@example.com",
        "record": {"kind": "role_change", "user": "jsmith@example.com", "role_name": "Global Administrator",
                   "change": change, "privileged": True, "actor": "jsmith@example.com",
                   "timestamp": "2026-01-15T10:00:00Z"}})
    run = _detect(data, workflow, "tp-approve-all", live=False)
    assert any(str(r.kind) == "role_change" for r in run.workflow_run.index.records()), "precondition: indexed"
    actions = _account_actions(run.detection.package, "jsmith@example.com")
    assert actions, f"{workflow}: precondition, account actions on jsmith@example.com"
    weak = [f"{a.action_type.value}:{a.target}" for a in actions
            if a.approval_level is not ApprovalLevel.ELEVATED or not a.warnings]
    assert weak == [], f"{workflow}: account holding Global Administrator contained at STANDARD: {weak}"


# ------------------------------------- isolation of a host that owns allow-listed infrastructure --
@pytest.mark.parametrize("workflow", P3_WORKFLOWS)
def test_isolating_the_host_of_an_allowlisted_infrastructure_address_is_never_silent(workflow: str):
    """config/allowlists.yaml never blocks 192.0.2.53 (the internal resolver) and 192.0.2.0/28 (core
    network infrastructure). When the endpoint records report that address for the host, isolating
    the host cuts that address off the network for everyone: the isolation must be excluded with the
    reason or ELEVATED with a visible warning, never a silent STANDARD action."""
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
