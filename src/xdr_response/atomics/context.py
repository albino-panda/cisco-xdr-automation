"""Atomic context and the read-only adapter facade (architecture 14.1.1).

:class:`ReadOnlyAdapters` is the only door from the read zone (atomics, workflows, scoring) to the
vendor adapters. It exposes reads only (enrichment, investigation, health, manifests, adapter names
and the Cisco XDR ``respond/observables`` listing) and never hands out an adapter object, so code in
the read zone cannot reach a state-changing method. Execution names (:meth:`executors`) are returned
for routing only; nothing here can call them.

This module and ``xdr_response.atomics.__init__`` are the only read-zone modules allowed to import
``xdr_response.integrations.registry`` and ``xdr_response.integrations.simulated`` (14.0.1).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from xdr_response.approval.critical_assets import CriticalAssetPolicy
from xdr_response.clock import Clock
from xdr_response.config import Settings
from xdr_response.config.policy import AllowlistPolicy, DisclosurePolicy
from xdr_response.errors import CapabilityNotSupportedError, IntegrationUnavailableError
from xdr_response.integrations.health import HealthMonitor
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.integrations.simulated import SimulatedAdapter
from xdr_response.models import (
    ActionCategory,
    ActionType,
    EnrichmentResult,
    Incident,
    IntegrationHealth,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    get_action_spec,
)

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.integrations.base import CapabilityManifest
    from xdr_response.integrations.cisco_xdr.adapter import NativeResponseAction

__all__ = ["ReadOnlyAdapters", "AtomicContext", "build_context", "DEFAULT_LOOKBACK"]

DEFAULT_LOOKBACK = timedelta(hours=24)
_EXECUTABLE = frozenset({ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION})


class ReadOnlyAdapters:
    """The only door from the read zone to the adapters. Never returns an adapter object."""

    __slots__ = ("__registry",)

    def __init__(self, registry: AdapterRegistry) -> None:
        if not isinstance(registry, AdapterRegistry):
            raise TypeError("ReadOnlyAdapters needs an AdapterRegistry")
        self.__registry = registry

    def __repr__(self) -> str:
        return f"ReadOnlyAdapters(enabled={list(self.enabled())})"

    # ------------------------------------------------------------- names --
    def enabled(self) -> tuple[str, ...]:
        """Enabled integration names, in ``INTEGRATION_NAMES`` order."""
        return tuple(self.__registry.enabled())

    def is_simulated(self, integration: str) -> bool:
        """True when the integration is served by a simulated (lab) adapter."""
        try:
            return isinstance(self.__registry.get(integration), SimulatedAdapter)
        except (KeyError, IntegrationUnavailableError):
            return False

    def manifest(self, integration: str) -> "CapabilityManifest":
        """Capability manifest of an integration (``KeyError`` for unknown names)."""
        return self.__registry.get(integration).manifest

    def health(self, integration: str) -> IntegrationHealth:
        """``adapter.health_check()``; never raises (disabled or unknown: ``UNKNOWN``)."""
        return HealthMonitor(self.__registry, audit=None).check(integration)

    # -------------------------------------------------------- enrichment --
    def enrichers(self, observable_type: ObservableType) -> tuple[str, ...]:
        """Names of enabled adapters that enrich ``observable_type`` (registry order)."""
        return tuple(a.name for a in self.__registry.for_observable(ObservableType(observable_type)))

    def enrich(self, integration: str, observable: Observable) -> EnrichmentResult:
        """Enrich through one integration. Adapter errors propagate to the calling atomic."""
        if integration not in self.enrichers(observable.type):
            raise CapabilityNotSupportedError(
                f"{integration} does not enrich {observable.type.value} (or is not enabled)",
                integration=integration)
        return self.__registry.get(integration).enrich(observable)

    # ----------------------------------------------------- investigation --
    def investigators(self, action_type: ActionType) -> tuple[str, ...]:
        """Names of enabled adapters serving an INVESTIGATION type (catalog order)."""
        spec = get_action_spec(action_type)
        if spec.category is not ActionCategory.INVESTIGATION:
            raise ValueError(f"{spec.action_type.value} is not an investigation action type")
        return tuple(a.name for a in self.__registry.for_action(spec.action_type))

    def investigate(self, integration: str, query: InvestigationQuery) -> InvestigationResult:
        """Run one investigation query. Adapter errors propagate to the calling atomic."""
        if integration not in self.investigators(query.action_type):
            raise CapabilityNotSupportedError(
                f"{integration} does not serve {query.action_type.value} (or is not enabled)",
                integration=integration)
        return self.__registry.get(integration).investigate(query)

    # ----------------------------------------------------------- routing --
    def executors(self, action_type: ActionType) -> tuple[str, ...]:
        """Names of enabled adapters able to execute a CONTAINMENT / REMEDIATION type.

        Catalog preference order (native Cisco XDR first). Names only: for routing, never for calling.
        """
        spec = get_action_spec(action_type)
        if spec.category not in _EXECUTABLE:
            raise ValueError(f"{spec.action_type.value} is not a containment or remediation action type")
        return tuple(a.name for a in self.__registry.for_action(spec.action_type))

    def native_response_actions(self, observable: Observable, *, module: str | None = None
                                ) -> tuple["NativeResponseAction", ...]:
        """Cisco XDR ``respond/observables`` listing (READ); ``()`` when cisco_xdr is not enabled.

        A simulated ``cisco_xdr`` lab adapter has no native listing and also returns ``()``.
        Adapter errors propagate (the router records them and falls back).
        """
        if "cisco_xdr" not in self.enabled():
            return ()
        adapter = self.__registry.get("cisco_xdr")
        if isinstance(adapter, SimulatedAdapter) or not adapter.manifest.native_xdr:
            return ()
        listing: Sequence[NativeResponseAction] = adapter.list_response_actions(  # type: ignore[attr-defined]
            observable, module=module)
        return tuple(listing)


@dataclass(frozen=True)
class AtomicContext:
    """Everything a read atomic may use. No adapter object, no token, no guard."""

    incident: Incident
    adapters: ReadOnlyAdapters
    settings: Settings
    clock: Clock
    disclosure: DisclosurePolicy
    critical_assets: CriticalAssetPolicy
    allowlists: AllowlistPolicy
    lookback: timedelta = DEFAULT_LOOKBACK
    dry_run: bool = True  # informational for renderers; reads behave the same in dry run

    def now(self) -> datetime:
        """The injected clock's current time."""
        return self.clock.now()

    def window(self) -> tuple[datetime, datetime]:
        """Investigation window: ``(min(incident.created_at, now) - lookback, now)``."""
        now = self.now()
        return min(self.incident.created_at, now) - self.lookback, now


def build_context(incident: Incident, registry: AdapterRegistry, settings: Settings, *, clock: Clock,
                  dry_run: bool, lookback: timedelta | None = None) -> AtomicContext:
    """Build an :class:`AtomicContext` with the policies derived from ``settings``.

    ``DisclosurePolicy(settings.exclusions)``, ``CriticalAssetPolicy(settings.critical_assets)``,
    ``AllowlistPolicy(settings.allowlists, exclusions=settings.exclusions)`` and ``ReadOnlyAdapters(registry)``.
    """
    return _context(incident, ReadOnlyAdapters(registry), settings, clock=clock, dry_run=dry_run,
                    lookback=lookback)


def _context(incident: Incident, adapters: ReadOnlyAdapters, settings: Settings, *,
             clock: Clock, dry_run: bool, lookback: timedelta | None = None) -> AtomicContext:
    """Context for a caller that already holds a facade (the workflow runner, same key)."""
    if not isinstance(adapters, ReadOnlyAdapters):
        raise TypeError("adapters must be a ReadOnlyAdapters facade")
    window = lookback if lookback is not None else DEFAULT_LOOKBACK
    if window <= timedelta(0):
        raise ValueError("lookback must be positive")
    return AtomicContext(
        incident=incident, adapters=adapters, settings=settings, clock=clock,
        disclosure=DisclosurePolicy(settings.exclusions),
        critical_assets=CriticalAssetPolicy(settings.critical_assets),
        allowlists=AllowlistPolicy(settings.allowlists, exclusions=settings.exclusions),
        lookback=window, dry_run=bool(dry_run),
    )
