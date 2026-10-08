"""Test lab for the investigation atomics (fake data only; no network).

:func:`lab` builds a fixed clock, settings with every real integration disabled, an adapter registry
with a simulated suite registered, and the real :class:`AtomicContext` over it. Findings are served
by the shared :class:`SimulatedEnvironment`; typed records use ``{"xdr_record": {...}}``.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from tests.fixtures.factories import FIXED_NOW, make_incident
from xdr_response.atomics.context import AtomicContext, build_context
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig, Settings
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.integrations.simulated import (
    SimulatedEnvironment,
    register_simulated_adapters,
    simulated_adapter_class,
)
from xdr_response.models import INTEGRATION_NAMES, ActionType
from xdr_response.secrets import StaticSecretProvider

__all__ = ["FIXED_NOW", "FAKE_SHA256", "FAKE_SHA256_B", "FAKE_SHA1", "FAKE_MD5", "HOST", "USER", "SUITE",
           "Lab", "lab", "typed", "statuses"]

FAKE_SHA256 = "ab" * 32
FAKE_SHA256_B = "cd" * 32
FAKE_SHA1 = "ef" * 20
FAKE_MD5 = "12" * 16
HOST = "TH-LT-1047"
USER = "jsmith@example.com"

#: Investigating sources of the catalog, posing with the families that serve their atomics.
SUITE: Mapping[str, tuple[str, ...]] = {
    "secure_endpoint": ("endpoint",),
    "defender_endpoint": ("endpoint", "network"),
    "intune": ("endpoint",),
    "entra": ("identity",),
    "secure_email": ("email",),
}
#: Families a simulated Splunk serves (every investigation family).
SPLUNK_FAMILIES = ("endpoint", "identity", "email", "network")


def typed(kind: str, *, only: str | None = None, **fields: Any) -> dict[str, Any]:
    """A simulated finding carrying one typed record (optionally restricted to one adapter)."""
    finding: dict[str, Any] = {"xdr_record": {"kind": kind, **fields}}
    if only is not None:
        finding["xdr_integration"] = only
    return finding


def statuses(bundle: Any) -> dict[str, tuple[str, str]]:
    """``{integration: (outcome, reason)}`` of a bundle's sources."""
    return {s.integration: (s.outcome.value, s.reason) for s in bundle.sources}


@dataclass
class Lab:
    clock: FixedClock
    settings: Settings
    registry: AdapterRegistry
    env: SimulatedEnvironment

    def context(self, **changes: Any) -> AtomicContext:
        ctx = build_context(make_incident(), self.registry, self.settings, clock=self.clock, dry_run=True)
        return dataclasses.replace(ctx, **changes) if changes else ctx

    def add(self, action_type: ActionType, subject: str, *findings: Mapping[str, Any]) -> None:
        self.env.add_findings(action_type, subject, *findings)

    def add_splunk(self, *, enabled: bool) -> None:
        """Register a simulated Splunk (optional source) with the given enabled flag."""
        cls = simulated_adapter_class("splunk", SPLUNK_FAMILIES)
        self.registry.register(cls(IntegrationConfig(enabled=enabled), environment=self.env, clock=self.clock))


def lab(suite: Mapping[str, Sequence[str]] | None = None, **settings_overrides: Any) -> Lab:
    """Fixed clock, settings with real integrations disabled, a simulated suite registered."""
    clock = FixedClock(FIXED_NOW)
    data: dict[str, Any] = {"integrations": {n: IntegrationConfig(enabled=False) for n in INTEGRATION_NAMES}}
    data.update(settings_overrides)
    settings = Settings(**data)
    registry = AdapterRegistry(settings, StaticSecretProvider({}), clock=clock)
    env = SimulatedEnvironment(clock=clock)
    register_simulated_adapters(registry, env, suite=dict(suite if suite is not None else SUITE))
    return Lab(clock=clock, settings=settings, registry=registry, env=env)
