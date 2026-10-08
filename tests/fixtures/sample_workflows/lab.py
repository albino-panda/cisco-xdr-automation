"""A simulated read-only lab for workflow framework tests (no network, fixed clock, fake data)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from tools.simulator.scenario import SIM_NOW, simulation_settings
from xdr_response.atomics.context import ReadOnlyAdapters
from xdr_response.atomics.investigation.normalize.typed import TYPED_INTEGRATION_KEY, TYPED_RECORD_KEY
from xdr_response.clock import FixedClock
from xdr_response.config import Settings
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.integrations.simulated import SimulatedEnvironment, register_simulated_adapters
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity, Verdict
from xdr_response.secrets import StaticSecretProvider
from xdr_response.workflows.runner import WorkflowRunner

HASH = "9f2b7c1d" * 8
HOST = "TH-LT-1047"
SUITE: Mapping[str, tuple[str, ...]] = {"secure_endpoint": ("endpoint",), "virustotal": ("intel",)}


@dataclass
class Lab:
    """A simulated read-only lab: settings, environment, facade and runner."""

    settings: Settings
    clock: FixedClock
    environment: SimulatedEnvironment
    registry: AdapterRegistry
    adapters: ReadOnlyAdapters
    runner: WorkflowRunner

    def typed(self, atomic: str, subject: str, integration: str, **record: Any) -> None:
        self.environment.add_findings(ActionType(atomic), subject,
                                      {TYPED_RECORD_KEY: record, TYPED_INTEGRATION_KEY: integration})

    def infected(self, host: str = HOST, sha: str = HASH, *, verdict: str = "MALICIOUS") -> None:
        """Endpoint and detection records plus a malicious hash reputation."""
        self.typed("investigate_endpoint", host, "secure_endpoint", kind="endpoint", hostname=host,
                   groups=["Workstations"], isolation_state="not_isolated")
        self.typed("investigate_endpoint", host, "secure_endpoint", kind="detection", detection_id=f"det-{host}",
                   name="Sample.Trojan.Generic", verdict=verdict, severity="HIGH", endpoint=host, sha256=sha)
        self.environment.set_reputation(ObservableType.SHA256, sha, Verdict.MALICIOUS, risk_score=90,
                                        confidence=85, integrations=["secure_endpoint", "virustotal"])


def make_lab(suite: Mapping[str, Sequence[str]] = SUITE, *, dry_run: bool = True) -> Lab:
    settings = simulation_settings(dry_run=dry_run, suite=suite)
    clock = FixedClock(SIM_NOW)
    environment = SimulatedEnvironment(clock=clock)
    registry = AdapterRegistry(settings, StaticSecretProvider({}), clock=clock)
    register_simulated_adapters(registry, environment, suite=suite)
    adapters = ReadOnlyAdapters(registry)
    return Lab(settings=settings, clock=clock, environment=environment, registry=registry, adapters=adapters,
               runner=WorkflowRunner(adapters, settings, clock=clock))


def make_incident(*observables: tuple[ObservableType, str], workflow_id: str = "sample-malware",
                  title: str = "Sample malware detected on TH-LT-1047", **extra: Any) -> Incident:
    obs = observables or ((ObservableType.HOSTNAME, HOST),)
    return Incident(incident_id=extra.pop("incident_id", "XDR-SM-9001"), title=title, severity=Severity.HIGH,
                    created_at=extra.pop("created_at", SIM_NOW), workflow_id=workflow_id, workflow_version="1.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in obs), **extra)
