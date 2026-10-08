"""Scenario model and runner for the end-to-end simulator (no network, fake data only).

A scenario YAML file (see ``tests/fixtures/incidents/*.yaml``) describes:

* ``incident``: the detected incident (observables, assets, users, trigger);
* ``environment``: the simulated vendor world (reputations per observable and source,
  investigation findings, targets already contained, injected faults, health overrides);
* ``analyst`` / ``release``: the human decisions the simulator plays (decision type, approver
  aliases, selected actions, comment);
* ``expect``: what the scenario should produce (used by the simulation tests).

:class:`ScenarioRun` wires a real :func:`xdr_response.lifecycle.build_runtime` runtime with
in-memory audit, registry and ledger, the repository ``config/`` policy files (critical assets,
allow-lists, thresholds) and :mod:`xdr_response.integrations.simulated` adapters. Every component is
the production one: approval tokens are real HMAC tokens issued to authenticated HUMAN lab
principals, and every simulated write goes through the execution guard. Lab principals get random
credentials per run, kept in memory only.
"""
from __future__ import annotations

import secrets as _stdlib_secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr

from xdr_response.approval import InMemoryApproverAuthenticator
from xdr_response.clock import Clock, FixedClock
from xdr_response.config import Settings, load_settings
from xdr_response.integrations.simulated import FaultKind, SimulatedEnvironment, register_simulated_adapters
from xdr_response.lifecycle import DecisionResult, DetectionResult, in_memory_runtime
from xdr_response.lifecycle.runtime import Runtime
from xdr_response.models import (
    ActionPackage,
    ActionType,
    ApproverCredential,
    DecisionRequest,
    DecisionType,
    HealthStatus,
    Incident,
    ObservableType,
    PrincipalKind,
    ReleasePackage,
    Verdict,
    make_idempotency_key,
    normalize_target,
)
from xdr_response.secrets import StaticSecretProvider

__all__ = [
    "REPO_ROOT",
    "SCENARIO_DIR",
    "CONFIG_DIR",
    "SIMULATION_SUITE",
    "LAB_PRINCIPALS",
    "SIM_NOW",
    "Scenario",
    "ScenarioRun",
    "load_scenario",
    "list_scenarios",
]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = REPO_ROOT / "tests" / "fixtures" / "incidents"
CONFIG_DIR = REPO_ROOT / "config"
SIM_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

#: Simulated integrations of the default lab: one adapter per family where possible, so each
#: indicator is reported by the source that would really know it.
SIMULATION_SUITE: Mapping[str, tuple[str, ...]] = {
    "secure_endpoint": ("endpoint",),
    "entra": ("identity",),
    "secure_email": ("email",),
    "umbrella": ("network",),
    "meraki": ("network",),
    "virustotal": ("intel",),
}

#: alias -> (principal id, kind, roles). Only HUMAN principals can ever approve.
LAB_PRINCIPALS: Mapping[str, tuple[str, PrincipalKind, frozenset[str]]] = {
    "analyst": ("analyst.one@example.com", PrincipalKind.HUMAN, frozenset({"xdr-approver"})),
    "lead": ("lead.two@example.com", PrincipalKind.HUMAN,
             frozenset({"xdr-approver", "xdr-elevated-approver"})),
    "automation": ("automation-runner@example.com", PrincipalKind.AUTOMATION,
                   frozenset({"xdr-approver", "xdr-elevated-approver"})),
    "ai": ("ai-assistant@example.com", PrincipalKind.AI,
           frozenset({"xdr-approver", "xdr-elevated-approver"})),
}


@dataclass(frozen=True)
class Scenario:
    """A parsed scenario file."""

    name: str
    description: str
    incident: Incident
    environment: Mapping[str, Any] = field(default_factory=dict)
    analyst: Mapping[str, Any] = field(default_factory=dict)
    release: Mapping[str, Any] = field(default_factory=dict)
    expect: Mapping[str, Any] = field(default_factory=dict)
    suite: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: dict(SIMULATION_SUITE))
    path: Path | None = None


def _incident(data: Mapping[str, Any], now: datetime) -> Incident:
    payload = dict(data)
    payload.setdefault("created_at", now)
    return Incident.model_validate(payload)


def load_scenario(source: str | Path, *, now: datetime = SIM_NOW) -> Scenario:
    """Load a scenario by path or by name (``tests/fixtures/incidents/<name>.yaml``)."""
    path = Path(source)
    if not path.suffix:
        path = SCENARIO_DIR / f"{source}.yaml"
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict) or "incident" not in data:
        raise ValueError(f"{path}: a scenario needs an 'incident' mapping")
    suite_raw = data.get("suite")
    suite = {k: tuple(v) for k, v in suite_raw.items()} if isinstance(suite_raw, dict) else dict(SIMULATION_SUITE)
    return Scenario(name=str(data.get("name") or path.stem), description=str(data.get("description") or ""),
                    incident=_incident(data["incident"], now), environment=data.get("environment") or {},
                    analyst=data.get("analyst") or {}, release=data.get("release") or {},
                    expect=data.get("expect") or {}, suite=suite, path=path)


def list_scenarios() -> list[str]:
    """Names of the bundled scenario files."""
    return sorted(p.stem for p in SCENARIO_DIR.glob("*.yaml"))


def simulation_settings(*, dry_run: bool, suite: Iterable[str], config_dir: Path = CONFIG_DIR) -> Settings:
    """Repository policy files with every real integration disabled except the simulated suite."""
    base = load_settings(config_dir, env={})
    data = base.model_dump()
    data["runtime"] = {**data["runtime"], "dry_run": dry_run, "environment": "lab"}
    enabled = set(suite)
    data["integrations"] = {name: {"enabled": name in enabled} for name in data["integrations"]}
    data["thresholds"]["verification"] = {**data["thresholds"]["verification"],
                                          "poll_interval_seconds": 0.0}
    return Settings.model_validate(data)


class ScenarioRun:
    """One simulated lifecycle of a scenario (dry run or simulated live)."""

    def __init__(self, scenario: Scenario, *, live: bool = False, clock: Clock | None = None,
                 settings: Settings | None = None, workflows: Any = None, observers: Sequence[Any] = (),
                 recommender: Any = None) -> None:
        """``workflows`` (a ``WorkflowCatalog``) and ``observers`` are passed to the runtime (14.3.6);
        ``recommender`` replaces the runtime's recommender (legacy replay, 14.3.8)."""
        self.scenario = scenario
        self.live = live
        self.clock: Clock = clock or FixedClock(SIM_NOW)
        self.environment = SimulatedEnvironment(clock=self.clock)
        self._secrets = {alias: _stdlib_secrets.token_urlsafe(24) for alias in LAB_PRINCIPALS}
        self.authenticator = InMemoryApproverAuthenticator(clock=self.clock, iterations=1_000)
        for alias, (pid, kind, roles) in LAB_PRINCIPALS.items():
            self.authenticator.add_principal(pid, display_name=alias.title(), kind=kind, roles=roles,
                                             secret=self._secrets[alias])
        secrets = StaticSecretProvider({"APPROVAL_SIGNING_KEY": _stdlib_secrets.token_hex(32)})
        self.settings = settings or simulation_settings(dry_run=not live, suite=scenario.suite)
        counter = iter(range(1, 1_000_000))
        self.runtime: Runtime = in_memory_runtime(
            self.settings, secrets, authenticator=self.authenticator, clock=self.clock,
            sleep=lambda _s: None, id_factory=lambda: f"{next(counter):032x}", workflows=workflows,
            observers=tuple(observers), **({"recommender": recommender} if recommender is not None else {}))
        register_simulated_adapters(self.runtime.adapters, self.environment, suite=scenario.suite,
                                    audit=self.runtime.audit)
        self._apply_environment(scenario.environment)
        self.detection: DetectionResult | None = None
        self.decision: DecisionResult | None = None
        self.release_package: ReleasePackage | None = None
        self.release_result: DecisionResult | None = None

    # ------------------------------------------------------------ environment --
    def _apply_environment(self, env: Mapping[str, Any]) -> None:
        for rep in env.get("reputations") or ():
            self.environment.set_reputation(
                ObservableType(rep["type"]), str(rep["value"]), Verdict(rep["verdict"]),
                risk_score=int(rep.get("risk_score", 0)), confidence=int(rep.get("confidence", 0)),
                summary=str(rep.get("summary", "")), integrations=rep.get("integrations"))
        for item in env.get("findings") or ():
            self.environment.add_findings(ActionType(item["action_type"]), str(item["subject"]),
                                          *(item.get("items") or ()))
        for item in env.get("preexisting") or ():
            action_type = ActionType(item["action_type"])
            self.environment.force_desired_state(action_type, self.target(action_type, item["target"]))
        for fault in env.get("faults") or ():
            operation = fault.get("operation")
            self.environment.inject(FaultKind(fault["kind"]), integration=fault.get("integration"),
                                    operation=operation, target=fault.get("target"),
                                    times=fault.get("times", 1), retry_after=fault.get("retry_after"))
        for name, status in (env.get("health") or {}).items():
            self.environment.set_health(name, HealthStatus(status))
        for target in env.get("invalid_targets") or ():
            self.environment.mark_invalid_target(str(target))

    # ---------------------------------------------------------------- helpers --
    @property
    def orchestrator(self) -> Any:
        return self.runtime.orchestrator

    @property
    def incident_id(self) -> str:
        return self.scenario.incident.incident_id

    @staticmethod
    def target(action_type: ActionType | str, value: str) -> str:
        from xdr_response.models import get_action_spec

        return normalize_target(get_action_spec(action_type).target_kind, str(value))

    def credentials(self, *aliases: str) -> list[ApproverCredential]:
        """Valid lab credentials for the given principal aliases (``analyst``, ``lead`` ...)."""
        out = []
        for alias in aliases:
            pid = LAB_PRINCIPALS[alias][0]
            out.append(ApproverCredential(principal_id=pid, scheme="static", secret=SecretStr(self._secrets[alias])))
        return out

    def keys(self, package: ActionPackage, selectors: Iterable[str]) -> tuple[str, ...]:
        """Idempotency keys for ``"action_type:target"`` selectors (or bare action types)."""
        keys: list[str] = []
        for selector in selectors:
            action, _, value = str(selector).partition(":")
            action_type = ActionType(action)
            if value:
                key = make_idempotency_key(package.incident_id, action_type, self.target(action_type, value))
                package.action(key)  # KeyError if not in the package
                keys.append(key)
            else:
                keys.extend(a.idempotency_key for a in package.actions if a.action_type is action_type)
        return tuple(dict.fromkeys(keys))

    def _request(self, package: ActionPackage, spec: Mapping[str, Any], default: str) -> DecisionRequest:
        decision = DecisionType(spec.get("decision", default))
        approved = self.keys(package, spec.get("select") or ()) if decision is DecisionType.APPROVE_SELECTED else ()
        comment = str(spec.get("comment") or "")
        if decision in (DecisionType.REJECT, DecisionType.REQUEST_MORE_INVESTIGATION) and not comment:
            comment = f"{decision.value.lower().replace('_', ' ')} (simulated analyst)"
        return DecisionRequest(package_id=package.package_id, decision=decision, approved_keys=approved,
                               comment=comment)

    # -------------------------------------------------------------- lifecycle --
    def detect(self) -> DetectionResult:
        """Open, investigate, recommend and propose (automatic)."""
        self.detection = self.orchestrator.handle_detection(self.scenario.incident)
        return self.detection

    def decide(self, spec: Mapping[str, Any] | None = None, *, approvers: Sequence[str] | None = None
               ) -> DecisionResult:
        """Play the analyst decision on the pending containment package."""
        spec = dict(self.scenario.analyst if spec is None else spec)
        package = self.orchestrator.latest_package(self.incident_id)
        if package is None:
            raise RuntimeError("no containment package was proposed")
        who = list(approvers or spec.get("approvers") or ["analyst"])
        self.decision = self.orchestrator.submit_decision(self._request(package, spec, "APPROVE_ALL"),
                                                          self.credentials(*who))
        return self.decision

    def propose_release(self, control_keys: Sequence[str] | None = None) -> ReleasePackage:
        self.release_package = self.orchestrator.propose_release(self.incident_id, control_keys)
        return self.release_package

    def decide_release(self, spec: Mapping[str, Any] | None = None, *, approvers: Sequence[str] | None = None
                       ) -> DecisionResult:
        spec = dict(self.scenario.release if spec is None else spec)
        package = self.release_package or self.orchestrator.latest_package(self.incident_id)
        who = list(approvers or spec.get("approvers") or ["analyst"])
        self.release_result = self.orchestrator.submit_release_decision(
            self._request(package, spec, "APPROVE_ALL"), self.credentials(*who))
        return self.release_result

    def advance(self, minutes: int) -> None:
        """Move the fixed clock forward (simulated time)."""
        if isinstance(self.clock, FixedClock):
            self.clock.advance(timedelta(minutes=minutes))
