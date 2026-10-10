"""Workflow scenario fixtures (architecture 14.5.2, 14.5.3) and their simulated lifecycle runs.

A workflow scenario is a YAML file ``tests/fixtures/workflows/<workflow id>/<name>.yaml`` in the
format of 14.5.2. :func:`discover_workflow_scenarios` finds them (no file lists scenarios),
:class:`WorkflowScenario` validates them and :class:`WorkflowScenarioRun` plays one through the real
Phase 0 lifecycle with the workflow catalog wired in (``ScenarioRun`` plus typed records served by the
simulated adapters, lab ``config`` overrides and an in-memory notification outbox).

:meth:`WorkflowScenarioRun.check` compares a run with the scenario's ``expect`` block and
:meth:`WorkflowScenarioRun.implicit_problems` makes the assertions every scenario gets whether it
asks or not (zero state changes before the analyst decision, evidence that cites the run's records,
separate risk and confidence, ELEVATED with a warning for critical assets, non-human principals can
never approve, an intact audit chain, no rule or hook error). :func:`check_coverage` checks the
minimum scenario set of a workflow.

All data is fake (example.com, documentation IP ranges, fake hashes, hosts like TH-LT-1047).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, field_validator, model_validator

from tools.simulator.scenario import (
    CONFIG_DIR,
    LAB_PRINCIPALS,
    REPO_ROOT,
    SIM_NOW,
    SIMULATION_SUITE,
    Scenario,
    ScenarioRun,
    simulation_settings,
)
from xdr_response.approval.critical_assets import CriticalAssetPolicy
from xdr_response.atomics.evidence import EvidenceBuilder, EvidenceError
from xdr_response.atomics.investigation.normalize.typed import TYPED_INTEGRATION_KEY, TYPED_RECORD_KEY
from xdr_response.atomics.notifications.service import NotificationService
from xdr_response.atomics.notifications.sinks import MemoryNotificationSink
from xdr_response.clock import Clock, FixedClock
from xdr_response.config import Settings
from xdr_response.config.loader import FORBIDDEN_KEYS
from xdr_response.dryrun import render_dry_run
from xdr_response.errors import ApprovalError
from xdr_response.integrations.simulated import FAMILIES, production_manifest
from xdr_response.lifecycle import DecisionResult, DetectionResult
from xdr_response.lifecycle.workflow_adapter import WorkflowInvestigationReport
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionPackage,
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    AuditEventType,
    ContainmentOverall,
    DecisionType,
    FrozenModel,
    Incident,
    IncidentState,
    JsonDict,
    RestorationOverall,
)
from xdr_response.workflows.definition import APPROVAL_LIKE_KEYS, WorkflowDefinition
from xdr_response.workflows.discovery import WorkflowCatalog, discover_workflows
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun

__all__ = [
    "WORKFLOW_SCENARIO_DIR",
    "SCENARIO_TAGS",
    "REQUIRED_SCENARIOS",
    "ScoreRange",
    "ScenarioRecord",
    "ScenarioEnvironment",
    "DecisionSpec",
    "ScenarioExpect",
    "WorkflowScenario",
    "WorkflowScenarioRun",
    "load_workflow_scenario",
    "discover_workflow_scenarios",
    "check_coverage",
    "workflow_settings",
]

WORKFLOW_SCENARIO_DIR = REPO_ROOT / "tests" / "fixtures" / "workflows"
LEGACY_WORKFLOWS_DIR = REPO_ROOT / "workflows"

#: Closed tag vocabulary of 14.5.2.
SCENARIO_TAGS: frozenset[str] = frozenset({
    "true_positive", "benign", "approve_all", "approve_selected", "reject", "more_investigation",
    "degraded_source", "critical_asset", "partial_failure", "dry_run", "release", "edge_case", "legacy",
})

#: Minimum scenario set of 14.5.3: file stem -> tags it must carry.
REQUIRED_SCENARIOS: Mapping[str, frozenset[str]] = {
    "tp-approve-all": frozenset({"true_positive", "approve_all"}),
    "tp-approve-selected": frozenset({"true_positive", "approve_selected"}),
    "tp-reject": frozenset({"true_positive", "reject"}),
    "benign-no-action": frozenset({"benign"}),
    "degraded-source": frozenset({"degraded_source"}),
    "critical-asset-elevated": frozenset({"critical_asset"}),
    "partial-failure": frozenset({"partial_failure"}),
    "dry-run": frozenset({"dry_run"}),
    "release-restoration": frozenset({"release"}),
}
MIN_EDGE_SCENARIOS = 2

#: Top-level ``config`` keys a scenario may override (lab only).
_CONFIG_KEYS = frozenset({"critical_assets", "allowlists", "thresholds", "exclusions"})
_FILLED_RECORD_FIELDS = frozenset({"record_id", "integration", "atomic", "subject"})
_PLACEHOLDER_VERSION = "0.0.0"
_APPROVING = frozenset({DecisionType.APPROVE_ALL, DecisionType.APPROVE_SELECTED})


def _forbidden_paths(node: Any, path: str = "") -> list[str]:
    keys = FORBIDDEN_KEYS | APPROVAL_LIKE_KEYS
    found: list[str] = []
    if isinstance(node, Mapping):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).lower() in keys:
                found.append(here)
            found.extend(_forbidden_paths(value, here))
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            found.extend(_forbidden_paths(value, f"{path}[{index}]"))
    return found


# ------------------------------------------------------------------ models --
class ScoreRange(FrozenModel):
    """Inclusive score range of an expectation."""

    min: int = Field(default=0, ge=0, le=100)
    max: int = Field(default=100, ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> "ScoreRange":
        if self.min > self.max:
            raise ValueError("score range min must not exceed max")
        return self

    def contains(self, value: int) -> bool:
        return self.min <= value <= self.max


class ScenarioRecord(FrozenModel):
    """A typed record served by one simulated adapter for one atomic and subject (14.1.4)."""

    integration: str
    atomic: str
    subject: str
    record: JsonDict

    @field_validator("integration")
    @classmethod
    def _integration(cls, value: str) -> str:
        if value not in INTEGRATION_NAMES:
            raise ValueError(f"unknown integration {value!r}")
        return value

    @field_validator("atomic")
    @classmethod
    def _atomic(cls, value: str) -> str:
        try:
            ActionType(value)
        except ValueError:
            raise ValueError(f"{value!r} is not an investigation atomic") from None
        return value

    @field_validator("record")
    @classmethod
    def _record(cls, value: JsonDict) -> JsonDict:
        if not isinstance(value.get("kind"), str):
            raise ValueError("a typed record needs a 'kind'")
        filled = sorted(_FILLED_RECORD_FIELDS & set(value))
        if filled:
            raise ValueError(f"typed records never carry {filled}: the normalizer fills them")
        return value

    def finding(self) -> dict[str, Any]:
        """The simulated finding (typed record restricted to this scenario record's adapter)."""
        return {TYPED_RECORD_KEY: dict(self.record), TYPED_INTEGRATION_KEY: self.integration}


class ScenarioEnvironment(FrozenModel):
    """The simulated vendor world (Phase 0 format plus typed records)."""

    reputations: tuple[JsonDict, ...] = ()
    records: tuple[ScenarioRecord, ...] = ()
    findings: tuple[JsonDict, ...] = ()  # Phase 0 untyped findings (become generic records)
    preexisting: tuple[JsonDict, ...] = ()
    faults: tuple[JsonDict, ...] = ()
    health: dict[str, str] = {}
    invalid_targets: tuple[str, ...] = ()

    def phase0(self) -> dict[str, Any]:
        """The Phase 0 ``ScenarioRun`` environment mapping (records are registered separately)."""
        return self.model_dump(mode="json", exclude={"records"})


class DecisionSpec(FrozenModel):
    """A simulated human decision."""

    decision: DecisionType = DecisionType.APPROVE_ALL
    approvers: tuple[str, ...] = ("analyst",)
    select: tuple[str, ...] = ()
    comment: str = ""

    @field_validator("approvers")
    @classmethod
    def _aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = [a for a in value if a not in LAB_PRINCIPALS]
        if unknown or not value:
            raise ValueError(f"approvers must be lab principal aliases {sorted(LAB_PRINCIPALS)}, got {list(value)}")
        return value


class ScenarioExpect(FrozenModel):
    """Expectations; ``None`` means "not asserted", a given set is compared exactly."""

    package: bool = True
    actions: tuple[str, ...] | None = None
    elevated: tuple[str, ...] | None = None
    excluded: tuple[str, ...] | None = None
    unrouted: tuple[str, ...] | None = None
    below_threshold: tuple[str, ...] | None = None
    risk: ScoreRange | None = None
    confidence: ScoreRange | None = None
    degraded_sources: tuple[str, ...] | None = None
    considered: tuple[str, ...] | None = None  # subjects of hook considerations (not manual), exact set
    manual_steps: tuple[str, ...] | None = None  # subjects of hook manual steps, exact set
    handoffs: tuple[str, ...] | None = None  # "<workflow>:<subject>" of hook hand-offs, exact set
    warnings: tuple[str, ...] = ()
    evidence_min: int = Field(default=1, ge=1)
    dry_run_lines: tuple[str, ...] | None = None
    decision_state: IncidentState | None = None
    containment: ContainmentOverall | None = None
    results: dict[str, str] = {}
    already_contained: tuple[str, ...] | None = None
    controls: int | None = Field(default=None, ge=0)
    restoration: RestorationOverall | None = None
    final_state: IncidentState | None = None
    notifications: tuple[str, ...] | None = None


class WorkflowScenario(FrozenModel):
    """A parsed and validated workflow scenario file (14.5.2)."""

    schema_version: Literal[1] = Field(alias="schema")
    name: str
    workflow: str
    description: str
    tags: tuple[str, ...] = Field(min_length=1)
    legacy_source: str | None = None
    mode: Literal["dry_run", "live", "both"] = "both"
    suite: dict[str, tuple[str, ...]] | None = None
    config: JsonDict = {}
    incident: Incident
    environment: ScenarioEnvironment = ScenarioEnvironment()
    analyst: DecisionSpec | None = None
    release: DecisionSpec | None = None
    expect: ScenarioExpect = ScenarioExpect()
    path: Path | None = Field(default=None, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _incident_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("incident"), dict):
            incident = {"created_at": SIM_NOW, "workflow_version": _PLACEHOLDER_VERSION, **data["incident"]}
            data = {**data, "incident": incident}
        return data

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - SCENARIO_TAGS)
        if unknown:
            raise ValueError(f"unknown tags {unknown}; vocabulary: {sorted(SCENARIO_TAGS)}")
        return value

    @field_validator("suite")
    @classmethod
    def _suite(cls, value: dict[str, tuple[str, ...]] | None) -> dict[str, tuple[str, ...]] | None:
        for name, families in (value or {}).items():
            if name not in INTEGRATION_NAMES:
                raise ValueError(f"unknown integration {name!r} in suite")
            unknown = [f for f in families if f not in FAMILIES] or ([] if families else ["<none>"])
            if unknown:
                raise ValueError(f"suite {name}: unknown simulated families {unknown}")
        return value

    @field_validator("config")
    @classmethod
    def _config(cls, value: JsonDict) -> JsonDict:
        extra = sorted(set(value) - _CONFIG_KEYS)
        if extra:
            raise ValueError(f"config may only override {sorted(_CONFIG_KEYS)}, not {extra}")
        forbidden = _forbidden_paths(value)
        if forbidden:
            raise ValueError(f"config carries forbidden approval keys: {forbidden}")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> "WorkflowScenario":
        if self.incident.workflow_id != self.workflow:
            raise ValueError(f"incident.workflow_id {self.incident.workflow_id!r} must equal workflow {self.workflow!r}")
        if ("legacy" in self.tags) != (self.legacy_source is not None):
            raise ValueError("legacy_source is required exactly for scenarios tagged 'legacy'")
        if "dry_run" in self.tags and self.mode != "dry_run":
            raise ValueError("a 'dry_run' scenario must use mode: dry_run")
        for record in self.environment.records:
            self._check_record(record)
        return self

    def _check_record(self, record: ScenarioRecord) -> None:
        suite = self.effective_suite()
        if record.integration not in suite:
            raise ValueError(f"record for {record.integration} but the suite has {sorted(suite)}")
        served = {a for f in suite[record.integration] for a in FAMILIES[f].investigations}
        if ActionType(record.atomic) not in served:
            raise ValueError(f"simulated {record.integration} ({'+'.join(suite[record.integration])}) does not "
                             f"serve {record.atomic}")

    def effective_suite(self) -> dict[str, tuple[str, ...]]:
        """The scenario's suite, or the default simulation suite."""
        return dict(self.suite) if self.suite is not None else {k: tuple(v) for k, v in SIMULATION_SUITE.items()}

    def modes(self) -> tuple[bool, ...]:
        """``live`` flags to run: ``(False,)``, ``(True,)`` or both."""
        return {"dry_run": (False,), "live": (True,), "both": (False, True)}[self.mode]


def load_workflow_scenario(path: Path | str) -> WorkflowScenario:
    """Parse and validate one scenario; ``name`` must equal the file stem and ``workflow`` the directory."""
    source = Path(path)
    with source.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{source}: a scenario must be a mapping")
    scenario = WorkflowScenario.model_validate({**data, "path": source})
    if scenario.name != source.stem:
        raise ValueError(f"{source}: name {scenario.name!r} must equal the file stem {source.stem!r}")
    if scenario.workflow != source.parent.name:
        raise ValueError(f"{source}: workflow {scenario.workflow!r} must equal the directory {source.parent.name!r}")
    return scenario


def discover_workflow_scenarios(root: Path | str = WORKFLOW_SCENARIO_DIR, *,
                                catalog: WorkflowCatalog | None = None) -> dict[str, list[Path]]:
    """``{workflow id: sorted scenario paths}`` for every ``<root>/<workflow id>/*.yaml``.

    Every directory name must be a catalog id (default catalog: :func:`discover_workflows`).
    """
    base = Path(root)
    if not base.is_dir():
        return {}
    known = (catalog if catalog is not None else discover_workflows()).ids()
    found: dict[str, list[Path]] = {}
    for directory in sorted(p for p in base.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))):
        if directory.name not in known:
            raise ValueError(f"{directory}: scenario directory is not a workflow id (known: {list(known)})")
        files = sorted(directory.glob("*.yaml"))
        if files:
            found[directory.name] = files
    return found


def workflow_settings(scenario: WorkflowScenario, *, dry_run: bool, config_dir: Path = CONFIG_DIR) -> Settings:
    """Lab settings: repository policy, the scenario suite, and the scenario's ``config`` deep-merged."""
    base = simulation_settings(dry_run=dry_run, suite=scenario.effective_suite(), config_dir=config_dir)
    if not scenario.config:
        return base
    return Settings.model_validate(_deep_merge(base.model_dump(mode="json"), scenario.config))


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


# -------------------------------------------------------------------- run --
@dataclass
class _Probe:
    """Facts captured between detection and the analyst decision."""

    state_changes: int = 0
    guard_denials: int = 0
    refused: dict[str, bool] = field(default_factory=dict)  # alias -> refused
    elevated_refused_for_analyst: bool | None = None


class WorkflowScenarioRun(ScenarioRun):
    """One simulated lifecycle of a workflow scenario (dry run or simulated live)."""

    def __init__(self, scenario: WorkflowScenario, *, live: bool = False, catalog: WorkflowCatalog | None = None,
                 clock: Clock | None = None) -> None:
        self.workflow_scenario = scenario
        self.catalog = catalog if catalog is not None else discover_workflows()
        self.outbox = MemoryNotificationSink()
        self.probe = _Probe()
        base = Scenario(
            name=scenario.name, description=scenario.description, incident=scenario.incident,
            environment=scenario.environment.phase0(),
            analyst=scenario.analyst.model_dump(mode="json") if scenario.analyst else {},
            release=scenario.release.model_dump(mode="json") if scenario.release else {},
            expect=scenario.expect.model_dump(mode="json"), suite=scenario.effective_suite(), path=scenario.path)
        settings = workflow_settings(scenario, dry_run=not live)
        run_clock: Clock = clock if clock is not None else FixedClock(SIM_NOW)
        super().__init__(base, live=live, clock=run_clock, settings=settings, workflows=self.catalog,
                         observers=(NotificationService([self.outbox], clock=run_clock),))
        for record in scenario.environment.records:
            self.environment.add_findings(ActionType(record.atomic), record.subject, record.finding())

    # ------------------------------------------------------------- views --
    @property
    def workflow_run(self) -> WorkflowRun | None:
        """The workflow run behind the detection (None on the Phase 0 generic path)."""
        if self.detection is None or not isinstance(self.detection.investigation, WorkflowInvestigationReport):
            return None
        return self.detection.investigation.run

    @property
    def definition(self) -> WorkflowDefinition:
        return self.catalog.get(self.workflow_scenario.workflow).definition

    # --------------------------------------------------------- lifecycle --
    def play(self, *, probe: bool = True) -> "WorkflowScenarioRun":
        """Detect, probe the approval boundary, decide, and (live) release, per the scenario."""
        self.detect()
        self.probe.state_changes = len(self.environment.state_changing_calls())
        self.probe.guard_denials = self._guard_denials()
        package = self.detection.package if self.detection else None
        if package is None or self.workflow_scenario.analyst is None:
            return self
        if probe:
            self._probe_non_humans(package)
        self.decide()
        if self._should_release():
            self.propose_release()
            self.decide_release()
        return self

    def _should_release(self) -> bool:
        decision = self.decision
        return (self.live and self.workflow_scenario.release is not None and decision is not None
                and decision.report is not None and not decision.report.dry_run
                and bool(self.runtime.registry.list(incident_id=self.incident_id)))

    def _probe_non_humans(self, package: ActionPackage) -> None:
        spec = {"decision": "APPROVE_ALL"}
        for alias in ("ai", "automation"):
            self.probe.refused[alias] = self._refused(package, spec, alias)
        if package.has_elevated:
            self.probe.elevated_refused_for_analyst = self._refused(package, spec, "analyst")

    def _refused(self, package: ActionPackage, spec: Mapping[str, Any], alias: str) -> bool:
        try:
            self.orchestrator.submit_decision(self._request(package, spec, "APPROVE_ALL"), self.credentials(alias))
        except ApprovalError:
            return True
        return False

    def _guard_denials(self) -> int:
        return sum(1 for r in self.runtime.audit.records(self.incident_id)
                   if r.event_type is AuditEventType.GUARD_DENIED)

    # ------------------------------------------------------------ checks --
    def check(self) -> list[str]:
        """Differences between the run and ``expect`` (empty list: all met)."""
        expect = self.workflow_scenario.expect
        detection = self.detection
        if detection is None:
            return ["the scenario was not played"]
        problems = self._check_package(expect, detection)
        problems += self._check_outcomes(expect)
        problems += self._check_decision(expect)
        if expect.notifications is not None:
            rendered = sorted({d.kind.value for d in self.outbox.drafts})
            if rendered != sorted(set(expect.notifications)):
                problems.append(f"notifications {rendered} != expected {sorted(set(expect.notifications))}")
        return problems

    def _selectors(self, package: ActionPackage | None, values: Iterable[str]) -> set[str]:
        out: set[str] = set()
        for selector in values:
            action, _, target = str(selector).partition(":")
            out.add(f"{ActionType(action).value}:{self.target(action, target) if target else ''}")
        return out

    def _check_package(self, expect: ScenarioExpect, detection: DetectionResult) -> list[str]:
        package = detection.package
        problems: list[str] = []
        if expect.package != (package is not None):
            problems.append(f"package proposed: {package is not None}, expected {expect.package}")
        actions = {f"{a.action_type.value}:{a.target}" for a in package.actions} if package else set()
        elevated = {f"{a.action_type.value}:{a.target}" for a in package.actions
                    if a.approval_level is ApprovalLevel.ELEVATED} if package else set()
        excluded = {f"{e.action_type.value}:{e.target}" for e in package.excluded_targets} if package else set()
        for label, wanted, got in (("actions", expect.actions, actions), ("elevated", expect.elevated, elevated),
                                   ("excluded", expect.excluded, excluded)):
            if wanted is not None and self._selectors(package, wanted) != got:
                problems.append(f"{label} {sorted(got)} != expected {sorted(self._selectors(package, wanted))}")
        risk = package.risk_score if package else detection.recommendation.risk_score
        confidence = package.confidence_score if package else detection.recommendation.confidence_score
        if expect.risk is not None and not expect.risk.contains(risk):
            problems.append(f"risk {risk} outside {expect.risk.min}-{expect.risk.max}")
        if expect.confidence is not None and not expect.confidence.contains(confidence):
            problems.append(f"confidence {confidence} outside {expect.confidence.min}-{expect.confidence.max}")
        messages = [w.message for a in (package.actions if package else ()) for w in a.warnings]
        for wanted_text in expect.warnings:
            if not any(wanted_text in m for m in messages):
                problems.append(f"no critical-asset warning contains {wanted_text!r}")
        for action in package.actions if package else ():
            if len(action.evidence) < expect.evidence_min:
                problems.append(f"{action.idempotency_key}: {len(action.evidence)} evidence item(s) < "
                                f"{expect.evidence_min}")
        if expect.dry_run_lines is not None and not self.live:
            lines = render_dry_run(detection.dry_run_report).splitlines() if detection.dry_run_report else []
            if lines != list(expect.dry_run_lines):
                problems.append(f"dry run lines {lines} != expected {list(expect.dry_run_lines)}")
        return problems

    def _check_outcomes(self, expect: ScenarioExpect) -> list[str]:
        run = self.workflow_run
        problems: list[str] = []
        if run is None:
            return ["the incident did not run through its workflow (Phase 0 generic path)"]
        for label, wanted, status in (("unrouted", expect.unrouted, RuleOutcomeStatus.UNROUTED),
                                      ("below_threshold", expect.below_threshold, RuleOutcomeStatus.BELOW_THRESHOLD)):
            got = {o.selector for o in run.outcomes_with(status)}
            if wanted is not None and self._selectors(None, wanted) != got:
                problems.append(f"{label} {sorted(got)} != expected {sorted(self._selectors(None, wanted))}")
        if expect.degraded_sources is not None and set(run.degraded_sources()) != set(expect.degraded_sources):
            problems.append(f"degraded sources {list(run.degraded_sources())} != expected "
                            f"{sorted(expect.degraded_sources)}")
        hook_sets = (("considered", expect.considered, {c.subject for c in run.considered if not c.manual}),
                     ("manual steps", expect.manual_steps, {c.subject for c in run.considered if c.manual}),
                     ("hand-offs", expect.handoffs, {f"{h.workflow_id}:{s}" for h in run.handoffs for s in h.subjects}))
        for label, wanted, got in hook_sets:
            if wanted is not None and set(wanted) != got:
                problems.append(f"{label} {sorted(got)} != expected {sorted(set(wanted))}")
        return problems

    def _check_decision(self, expect: ScenarioExpect) -> list[str]:
        decision = self.decision
        problems: list[str] = []
        if decision is None:
            return problems
        if expect.decision_state is not None and decision.outcome.decision.decision not in _APPROVING:
            if decision.incident.state is not expect.decision_state:
                problems.append(f"state after decision {decision.incident.state.value} != {expect.decision_state.value}")
        if not self.live:
            return problems
        return problems + self._check_live(expect, decision)

    def _check_live(self, expect: ScenarioExpect, decision: DecisionResult) -> list[str]:
        problems: list[str] = []
        report = decision.report
        overall = report.overall if report is not None else None
        if expect.containment is not None and (overall is None or overall.value != expect.containment.value):
            problems.append(f"containment {overall} != expected {expect.containment.value}")
        statuses = self._result_statuses(decision)
        for selector, wanted in expect.results.items():
            key = next(iter(self._selectors(None, [selector])))
            if wanted not in statuses.get(key, set()):
                problems.append(f"result {key}: {sorted(statuses.get(key, set()))} does not include {wanted}")
        if expect.already_contained is not None:
            got = {k for k, v in statuses.items() if ActionResultStatus.ALREADY_CONTAINED.value in v}
            if got != self._selectors(None, expect.already_contained):
                problems.append(f"already contained {sorted(got)} != expected {sorted(expect.already_contained)}")
        if expect.controls is not None:
            count = len(self.runtime.registry.list(incident_id=self.incident_id))
            if count != expect.controls:
                problems.append(f"{count} temporary controls != expected {expect.controls}")
        if expect.restoration is not None:
            release = self.release_result.report if self.release_result is not None else None
            got = release.overall.value if release is not None and release.overall is not None else None
            if got != expect.restoration.value:
                problems.append(f"restoration {got} != expected {expect.restoration.value}")
        if expect.final_state is not None:
            state = self.orchestrator.get_incident(self.incident_id).state
            if state is not expect.final_state:
                problems.append(f"final state {state.value} != expected {expect.final_state.value}")
        return problems

    @staticmethod
    def _result_statuses(decision: DecisionResult) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        report = decision.report
        for result in report.results if report is not None else ():
            key = f"{result.action_type.value}:{result.target}"
            values = {result.status.value}
            if result.skip_reason is not None:
                values.add(result.skip_reason.value)
            out.setdefault(key, set()).update(values)
        return out

    # ------------------------------------------------------ implicit checks --
    def implicit_problems(self) -> list[str]:
        """The assertions every scenario gets (14.5.3); the scenario cannot switch them off."""
        problems: list[str] = []
        if self.probe.state_changes:
            problems.append(f"{self.probe.state_changes} state-changing call(s) before the analyst decision")
        if self.probe.guard_denials:
            problems.append(f"{self.probe.guard_denials} guard denial(s) before the analyst decision")
        problems += self._evidence_problems()
        problems += self._elevation_problems()
        for alias, refused in self.probe.refused.items():
            if not refused:
                problems.append(f"principal {alias!r} was able to approve a package")
        if "critical_asset" in self.workflow_scenario.tags and self.probe.elevated_refused_for_analyst is not True:
            problems.append("an APPROVE_ALL by 'analyst' alone was not refused on an ELEVATED package")
        verification = self.runtime.audit.verify()  # type: ignore[attr-defined]
        if not verification.ok:
            problems.append("the audit chain does not verify")
        problems += self._error_outcomes()
        return problems

    def _evidence_problems(self) -> list[str]:
        run = self.workflow_run
        if run is None:
            return ["no workflow run to verify evidence against"]
        problems: list[str] = []
        builder = EvidenceBuilder(run.index)
        for proposal in run.proposals:
            label = f"{proposal.action_type.value}:{proposal.target}"
            if len(proposal.evidence) < self.workflow_scenario.expect.evidence_min:
                problems.append(f"{label}: fewer than {self.workflow_scenario.expect.evidence_min} evidence item(s)")
            try:
                builder.verify(proposal.evidence)
            except (EvidenceError, KeyError) as exc:
                problems.append(f"{label}: evidence does not cite the run's records: {exc}")
            if type(proposal.risk_score) is not int or type(proposal.confidence_score) is not int:
                problems.append(f"{label}: risk and confidence must be separate integers")
        package = self.detection.package if self.detection else None
        for action in package.actions if package else ():
            missing = [e.data.get("record_id") for e in action.evidence if e.data.get("record_id") not in run.index]
            if missing:
                problems.append(f"{action.idempotency_key}: package evidence cites unknown records {missing}")
        return problems

    def _elevation_problems(self) -> list[str]:
        package = self.detection.package if self.detection else None
        if package is None:
            return []
        policy = CriticalAssetPolicy(self.settings.critical_assets)
        incident = self.orchestrator.get_incident(self.incident_id)
        assets = {(a.kind, a.name): a for a in incident.assets}
        problems: list[str] = []
        for action in package.actions:
            asset = assets.get((action.target_kind, action.target))
            if policy.classify(action.target, action.target_kind, asset):
                if action.approval_level is not ApprovalLevel.ELEVATED or not action.warnings:
                    problems.append(f"{action.idempotency_key}: critical asset without ELEVATED approval and warning")
        return problems

    def _error_outcomes(self) -> list[str]:
        run = self.workflow_run
        if run is None:
            return []
        problems = [f"rule {o.rule_id} ERROR: {o.detail}" for o in run.outcomes_with(RuleOutcomeStatus.ERROR)]
        problems += [f"hook problem: {n}" for n in run.notes if n.startswith(("hook ",))]
        return problems



# ------------------------------------------------------------------ coverage --
def check_coverage(workflow_id: str, scenarios: Sequence[WorkflowScenario], definition: WorkflowDefinition, *,
                   proposed_rules: Iterable[str] | None = None, unrouted_rules: Iterable[str] = (),
                   legacy_root: Path = LEGACY_WORKFLOWS_DIR) -> list[str]:
    """Problems with the minimum scenario set of 14.5.3 (empty list: covered).

    ``proposed_rules`` are the rule ids that were PROPOSED in played runs; without it a rule counts
    as covered when its action type appears in some scenario's expected actions. A rule whose action no
    real adapter can execute (no VERIFIED write anywhere, e.g. ``terminate_process``) can never be
    proposed: it counts as covered when a scenario expects it UNROUTED (``unrouted_rules`` with
    ``proposed_rules``). An executable action must be proposed somewhere: a scenario whose suite routes
    it (for example through Defender for Endpoint) shows the approved path.
    """
    problems: list[str] = []
    by_name = {s.name: s for s in scenarios}
    if any(s.workflow != workflow_id for s in scenarios):
        problems.append(f"scenarios of another workflow were passed for {workflow_id}")
    for name, tags in REQUIRED_SCENARIOS.items():
        scenario = by_name.get(name)
        if scenario is None:
            problems.append(f"{workflow_id}: missing scenario {name}.yaml")
        elif not tags <= set(scenario.tags):
            problems.append(f"{workflow_id}: {name}.yaml must carry tags {sorted(tags)}")
    edges = [s for s in scenarios if s.name.startswith("edge-") and "edge_case" in s.tags]
    if len(edges) < MIN_EDGE_SCENARIOS:
        problems.append(f"{workflow_id}: at least {MIN_EDGE_SCENARIOS} edge-<slug>.yaml scenarios tagged edge_case")
    present = {t for s in scenarios for t in s.tags}
    missing_tags = sorted(SCENARIO_TAGS - present - {"legacy", "more_investigation"})
    if missing_tags:
        problems.append(f"{workflow_id}: no scenario carries tags {missing_tags}")
    if not any("benign" in s.tags or s.expect.below_threshold for s in scenarios):
        problems.append(f"{workflow_id}: needs a benign or below-threshold scenario")
    problems += _rule_coverage(workflow_id, scenarios, definition, proposed_rules, unrouted_rules)
    problems += _legacy_coverage(workflow_id, scenarios, definition, legacy_root)
    return problems


def executable_anywhere(action: ActionType) -> bool:
    """True when some real adapter has a VERIFIED write for ``action`` (its manifest supports it)."""
    for name in INTEGRATION_NAMES:
        real = production_manifest(name)
        if real is not None and action in real.supported_actions:
            return True
    return False


def _rule_coverage(workflow_id: str, scenarios: Sequence[WorkflowScenario], definition: WorkflowDefinition,
                   proposed_rules: Iterable[str] | None, unrouted_rules: Iterable[str] = ()) -> list[str]:
    if proposed_rules is not None:
        covered = set(proposed_rules)
        unrouted = set(unrouted_rules)
        return [f"{workflow_id}: rule {r.id} is PROPOSED in no scenario" for r in definition.recommendations
                if r.id not in covered and not (r.id in unrouted and not executable_anywhere(r.action))]
    expected = {str(a).partition(":")[0] for s in scenarios for a in (s.expect.actions or ())}
    unrouted_expected = {str(a).partition(":")[0] for s in scenarios for a in (s.expect.unrouted or ())}
    problems = []
    for rule in definition.recommendations:
        action = rule.action.value
        if action in expected:
            continue
        if action in unrouted_expected and not executable_anywhere(rule.action):
            continue  # no real adapter can execute it: reported for manual handling is the covered outcome
        problems.append(f"{workflow_id}: rule {rule.id} ({action}) is expected in no scenario"
                        + (" (only UNROUTED, although a real adapter can execute it: add a scenario whose suite "
                           "routes it)" if action in unrouted_expected else ""))
    return problems


def _legacy_coverage(workflow_id: str, scenarios: Sequence[WorkflowScenario], definition: WorkflowDefinition,
                     legacy_root: Path) -> list[str]:
    if definition.legacy_id is None:
        return []
    legacy_dir = legacy_root / definition.legacy_id / "scenarios"
    if not legacy_dir.is_dir():
        return []
    migrated = {Path(s.legacy_source).as_posix() for s in scenarios if s.legacy_source}
    problems = []
    for legacy in sorted(legacy_dir.glob("*.yaml")):
        relative = legacy.relative_to(legacy_root.parent).as_posix()
        if relative not in migrated:
            problems.append(f"{workflow_id}: legacy scenario {relative} is not migrated (legacy-<NN>-<slug>.yaml)")
    return problems
