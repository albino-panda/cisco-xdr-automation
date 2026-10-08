"""Legacy scenario replay through the new runtime, in dry run (architecture 12, 14.3.8, 14.7.1 item 3).

Every remaining ``workflows/<id>/scenarios/*.yaml`` is replayed:

1. ``xdr_plan.planner.build_plan`` evaluates the legacy plan rules (guardrails merged from the
   scenario, approval-disabling keys refused);
2. :func:`xdr_response.lifecycle.plan_bridge.bridge_plan` turns the planned actions into
   ``ProposedAction`` objects with evidence citing the legacy results (as GenericRecords), routed
   with the containment router (native Cisco XDR first);
3. a real Phase 0 runtime (:class:`tools.simulator.scenario.ScenarioRun`, full simulation suite,
   critical assets / allow-lists / caps from :func:`guardrails_to_settings`, global dry run ON)
   opens the incident, investigates read-only, takes the bridged recommendation, builds the package
   with ``PackageBuilder`` (allow-lists, ELEVATED, blast radius) and simulates it with the
   ``DryRunSimulator``.

:func:`replay_legacy_scenario` returns a :class:`LegacyReplay` whose ``mismatches`` lists every
difference from the scenario's ``expect`` block (empty: pass): planned actions are in the package,
``elevated: true`` matches ELEVATED (and only those are ELEVATED), ``skipped_*`` actions are not
in the package, ``escalate`` matches (a blast-radius warning in the package), every action requires
approval, evidence verifies against the legacy records, and no state-changing call or guard
denial happened. Nothing is approved and nothing is executed.

This module is outside the read zone because it builds a lab runtime. It is deleted at the end of
Phase 5 with ``engine/xdr_plan`` (14.4.3).
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tools.simulator.scenario import SIM_NOW, SIMULATION_SUITE, Scenario, ScenarioRun, simulation_settings
from xdr_plan import repo
from xdr_plan.planner import Plan, build_plan
from xdr_response.atomics.containment.routing import choose_route
from xdr_response.atomics.context import build_context
from xdr_response.atomics.evidence import EvidenceBuilder, EvidenceError, RecordIndex
from xdr_response.dryrun import render_dry_run
from xdr_response.lifecycle import DetectionResult
from xdr_response.lifecycle.investigation import InvestigationReport
from xdr_response.lifecycle.plan_bridge import (
    BridgeResult,
    bridge_plan,
    guardrails_to_settings,
    legacy_incident,
)
from xdr_response.lifecycle.recommendation import Recommendation, UnroutedAction
from xdr_response.lifecycle.runtime import Runtime
from xdr_response.models import ActionPackage, ApprovalLevel, AuditEventType, Incident

__all__ = ["LegacyReplay", "LegacyPlanRecommender", "replay_legacy_scenario", "legacy_scenarios"]


def legacy_scenarios() -> list[tuple[str, Path]]:
    """``(workflow id, path)`` of every remaining legacy scenario (``workflows/<id>/scenarios``)."""
    return [(workflow_id, path) for workflow_id in repo.workflow_ids() for path in repo.scenario_paths(workflow_id)]


class LegacyPlanRecommender:
    """``Recommender`` that returns the bridged legacy plan (routing needs the runtime, bound later)."""

    def __init__(self, plan: Plan, results: Mapping[str, Any], incident_data: Mapping[str, Any]) -> None:
        self._plan = plan
        self._results = results
        self._incident_data = incident_data
        self._runtime: Runtime | None = None
        self.bridge: BridgeResult | None = None

    def bind(self, runtime: Runtime) -> None:
        self._runtime = runtime

    def recommend(self, incident: Incident, investigation: InvestigationReport) -> Recommendation:
        if self._runtime is None:
            raise RuntimeError("LegacyPlanRecommender is not bound to a runtime")
        runtime = self._runtime
        ctx = build_context(incident, runtime.adapters, runtime.settings, clock=runtime.clock, dry_run=True)
        self.bridge = bridge = bridge_plan(self._plan, incident=incident, results=self._results,
                                           route=lambda action_type, target: choose_route(ctx, action_type, target),
                                           incident_data=self._incident_data)
        parts = ", ".join(f"{p.action_type.value} {p.target}" for p in bridge.proposals)
        summary = (f"Legacy plan {self._plan.workflow} (replay): {len(bridge.proposals)} action(s) recommended"
                   + (f": {parts}" if parts else ""))
        return Recommendation(
            incident_id=incident.incident_id, proposals=bridge.proposals, risk_score=bridge.risk_score,
            confidence_score=bridge.confidence_score, summary=summary,
            unrouted=tuple(UnroutedAction(a.action_type, a.target, a.note) for a in bridge.unrouted),
            notes=bridge.notes)


@dataclass
class LegacyReplay:
    """Result of one legacy scenario replay (dry run)."""

    workflow_id: str
    path: Path
    plan: Plan
    bridge: BridgeResult
    run: ScenarioRun
    detection: DetectionResult
    mismatches: list[str] = field(default_factory=list)

    @property
    def package(self) -> ActionPackage | None:
        return self.detection.package

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def dry_run_text(self) -> str:
        """The exact DRY RUN block of the simulated package ('' when nothing was proposed)."""
        report = self.detection.dry_run_report
        return render_dry_run(report) if report is not None else ""


def _load(path: Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict) or "incident" not in data:
        raise ValueError(f"{path}: a legacy scenario needs an 'incident' mapping")
    return data


def replay_legacy_scenario(workflow_id: str, path: Path | str) -> LegacyReplay:
    """Replay one legacy scenario in dry run on the simulated lab; see the module docstring."""
    path = Path(path)
    data = _load(path)
    guardrails = repo.load_guardrails(data.get("guardrails"))
    results = data.get("results") or {}
    plan = build_plan(workflow_id, data["incident"], results, guardrails, repo.load_workflow(workflow_id))
    incident = legacy_incident(data["incident"], workflow_id=workflow_id, created_at=SIM_NOW)
    settings = guardrails_to_settings(guardrails, simulation_settings(dry_run=True, suite=SIMULATION_SUITE))
    recommender = LegacyPlanRecommender(plan, results, data["incident"])
    scenario = Scenario(name=str(data.get("name") or path.stem), description=str(data.get("description") or ""),
                        incident=incident, suite=dict(SIMULATION_SUITE), path=path)
    run = ScenarioRun(scenario, live=False, settings=settings, recommender=recommender)
    recommender.bind(run.runtime)
    detection = run.detect()
    assert recommender.bridge is not None  # recommend() ran during detection
    replay = LegacyReplay(workflow_id=workflow_id, path=path, plan=plan, bridge=recommender.bridge, run=run,
                          detection=detection)
    replay.mismatches = _mismatches(replay, data.get("expect") or {})
    return replay


# ------------------------------------------------------------------------------------ checks --
def _expected(expect: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(e) for e in expect.get("actions") or () if isinstance(e, Mapping)]


def _mismatches(replay: LegacyReplay, expect: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    package = replay.package
    in_package = {f"{a.action_type.value}:{a.target}": a for a in (package.actions if package else ())}
    bridged = {(b.legacy_atomic, b.legacy_target.lower()): b for b in replay.bridge.actions}
    wanted: set[str] = set()
    for exp in _expected(expect):
        key = (str(exp.get("atomic")), str(exp.get("target")).lower())
        action = bridged.get(key)
        if action is None:
            problems.append(f"expected {key[0]} {key[1]} ({exp.get('status')}): not in the legacy plan")
            continue
        if action.status != exp.get("status"):
            problems.append(f"{key[0]} {key[1]}: legacy status {action.status} != expected {exp.get('status')}")
        selector = f"{action.action_type.value}:{action.target}"
        found = in_package.get(selector)
        if exp.get("status") != "planned":
            if found is not None:
                problems.append(f"{selector}: {exp.get('status')} in the legacy plan but in the package")
            continue
        wanted.add(selector)
        if found is None:
            problems.append(f"{selector}: planned but not in the package ({action.note or 'excluded'})")
            continue
        elevated = found.approval_level is ApprovalLevel.ELEVATED
        if elevated != bool(exp.get("elevated", False)) and not _stricter_blast_radius(found, replay):
            problems.append(f"{selector}: approval {found.approval_level.value} but expected elevated="
                            f"{bool(exp.get('elevated', False))}")
        if elevated and not found.warnings:
            problems.append(f"{selector}: ELEVATED without a visible warning")
    extra = sorted(set(in_package) - wanted)
    if extra:
        problems.append(f"package actions not expected by the scenario: {extra}")
    problems += _plan_problems(replay, expect)
    problems += _safety_problems(replay)
    return problems


def _stricter_blast_radius(action: Any, replay: LegacyReplay) -> bool:
    """The runtime may be stricter than the legacy planner, never weaker.

    The legacy ``max_users_disabled`` cap counts ``disable-user`` only; the runtime's
    ``blast_radius.max_users`` counts every user an action touches (``revoke_sessions`` too). So
    when the legacy plan escalates, an action the scenario expects STANDARD may be ELEVATED in the
    runtime, but only through blast-radius warnings (never a critical-asset class it lacks).
    """
    return (replay.bridge.escalate and action.approval_level is ApprovalLevel.ELEVATED and bool(action.warnings)
            and all(w.asset_class is None for w in action.warnings))


def _plan_problems(replay: LegacyReplay, expect: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    if any(not a.requires_approval for a in replay.plan.actions):
        problems.append("a legacy containment action does not require approval (C1)")
    escalate = bool(expect.get("escalate", False))
    if replay.bridge.escalate != escalate:
        problems.append(f"legacy plan escalate {replay.bridge.escalate} != expected {escalate}")
    package = replay.package
    blast = bool(package) and any(w.asset_class is None for a in package.actions for w in a.warnings)
    if blast != escalate:
        problems.append(f"package blast-radius warning {blast} != expected escalate {escalate}")
    return problems


def _safety_problems(replay: LegacyReplay) -> list[str]:
    problems: list[str] = []
    run = replay.run
    calls = run.environment.state_changing_calls()
    if calls:
        problems.append(f"{len(calls)} state-changing call(s) during a dry-run replay")
    denials = [r for r in run.runtime.audit.records(run.incident_id) if r.event_type is AuditEventType.GUARD_DENIED]
    if denials:
        problems.append(f"{len(denials)} guard denial(s) during a dry-run replay")
    if run.runtime.registry.list():
        problems.append("a temporary control was registered during a dry-run replay")
    package = replay.package
    if package is None:
        return problems
    if not package.dry_run:
        problems.append("the replay package is not marked dry_run")
    report = replay.detection.dry_run_report
    if report is None or not report.dry_run:
        problems.append("no DRY RUN report for the replay package")
    elif {r.idempotency_key for r in report.results} != set(package.keys):
        problems.append("the DRY RUN report does not cover every package action")
    builder = EvidenceBuilder(RecordIndex(records=replay.bridge.records))
    for action in package.actions:
        if not action.evidence:
            problems.append(f"{action.idempotency_key}: no evidence")
        try:
            builder.verify(action.evidence)
        except EvidenceError as exc:
            problems.append(f"{action.idempotency_key}: {exc}")
    return problems
