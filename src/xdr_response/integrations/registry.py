"""Adapter registry (architecture section 13.13).

Adapters are imported lazily from :data:`ADAPTER_PATHS` and instantiated on first use with their
:class:`IntegrationConfig`. Disabled integrations (Splunk is disabled by default) are never
loaded for routing. An adapter whose module fails to import or whose constructor raises is
recorded in :attr:`AdapterRegistry.load_errors` and skipped by :meth:`for_action` and
:meth:`for_observable`, so one broken integration degrades the system instead of stopping it.
"""
from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import IntegrationUnavailableError
from xdr_response.integrations.base import IntegrationAdapter
from xdr_response.interfaces import AuditSink, SecretProvider
from xdr_response.logs.redaction import get_redactor
from xdr_response.logs.setup import get_logger
from xdr_response.models import INTEGRATION_NAMES, ActionType, ObservableType, get_action_spec

if TYPE_CHECKING:  # pragma: no cover
    import httpx

    from xdr_response.config.schema import Settings

__all__ = ["ADAPTER_PATHS", "load_adapter_class", "AdapterRegistry"]

_log = get_logger("integrations.registry")

ADAPTER_PATHS: Mapping[str, str] = MappingProxyType({
    "cisco_xdr": "xdr_response.integrations.cisco_xdr.adapter:CiscoXdrAdapter",
    "secure_endpoint": "xdr_response.integrations.secure_endpoint.adapter:SecureEndpointAdapter",
    "secure_email": "xdr_response.integrations.secure_email.adapter:SecureEmailAdapter",
    "secure_malware_analytics":
        "xdr_response.integrations.secure_malware_analytics.adapter:SecureMalwareAnalyticsAdapter",
    "secure_cloud_analytics":
        "xdr_response.integrations.secure_cloud_analytics.adapter:SecureCloudAnalyticsAdapter",
    "umbrella": "xdr_response.integrations.umbrella.adapter:UmbrellaAdapter",
    "meraki": "xdr_response.integrations.meraki.adapter:MerakiAdapter",
    "entra": "xdr_response.integrations.entra.adapter:EntraAdapter",
    "defender_endpoint": "xdr_response.integrations.defender_endpoint.adapter:DefenderEndpointAdapter",
    "defender_o365": "xdr_response.integrations.defender_o365.adapter:DefenderO365Adapter",
    "intune": "xdr_response.integrations.intune.adapter:IntuneAdapter",
    "microsoft_cloud": "xdr_response.integrations.microsoft_cloud.adapter:MicrosoftCloudAdapter",
    "virustotal": "xdr_response.integrations.virustotal.adapter:VirusTotalAdapter",
    "alienvault_otx": "xdr_response.integrations.alienvault_otx.adapter:AlienVaultOtxAdapter",
    "hibp": "xdr_response.integrations.hibp.adapter:HibpAdapter",
    "splunk": "xdr_response.integrations.splunk.adapter:SplunkAdapter",
})


def load_adapter_class(name: str) -> type[IntegrationAdapter]:
    """Import the adapter class for ``name``.

    Raises ``KeyError`` for an unknown integration, ``ImportError`` when the module or class is
    missing, and ``TypeError`` when the object is not an :class:`IntegrationAdapter` subclass
    whose ``name`` matches.
    """
    path = ADAPTER_PATHS.get(name)
    if path is None:
        raise KeyError(name)
    module_name, _, class_name = path.partition(":")
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name, None)
    if cls is None:
        raise ImportError(f"{module_name} has no attribute {class_name}")
    if not (isinstance(cls, type) and issubclass(cls, IntegrationAdapter)):
        raise TypeError(f"{path} is not an IntegrationAdapter subclass")
    if getattr(cls, "name", None) != name:
        raise TypeError(f"{path}.name must be {name!r}")
    return cls


class AdapterRegistry:
    """Holds one adapter instance per integration, created lazily from settings."""

    def __init__(
        self,
        settings: "Settings",
        secrets: SecretProvider,
        *,
        clock: Clock | None = None,
        audit: AuditSink | None = None,
        transport_factory: "Callable[[str], httpx.BaseTransport | None] | None" = None,
        sleep: Callable[[float], None] | None = None,
        class_loader: Callable[[str], type[IntegrationAdapter]] | None = None,
    ) -> None:
        self.settings = settings
        self.secrets = secrets
        self.clock: Clock = clock or DEFAULT_CLOCK
        self.audit = audit
        self.transport_factory = transport_factory
        self.sleep = sleep
        self._loader = class_loader or load_adapter_class
        self._adapters: dict[str, IntegrationAdapter] = {}
        self._registered: set[str] = set()
        self._load_errors: dict[str, str] = {}

    # ----------------------------------------------------------- lookups --
    def names(self) -> list[str]:
        """Every known integration name, in the canonical order."""
        return list(INTEGRATION_NAMES)

    def is_enabled(self, name: str) -> bool:
        """True when the integration is enabled (registered adapters use their own config)."""
        if name in self._registered:
            return self._adapters[name].enabled
        if name not in INTEGRATION_NAMES:
            raise KeyError(name)
        return bool(self.settings.integration(name).enabled)

    def enabled(self) -> list[str]:
        """Names of enabled integrations, in canonical order. Never loads an adapter."""
        return [n for n in INTEGRATION_NAMES if self.is_enabled(n)]

    @property
    def load_errors(self) -> dict[str, str]:
        """Integration name -> redacted reason the adapter could not be loaded."""
        return dict(self._load_errors)

    def get(self, name: str) -> IntegrationAdapter:
        """The adapter for ``name`` (instantiated on first use).

        ``KeyError`` for an unknown name; :class:`IntegrationUnavailableError` (not retryable)
        when the adapter cannot be loaded or constructed.
        """
        adapter = self._adapters.get(name)
        if adapter is not None:
            return adapter
        if name not in INTEGRATION_NAMES:
            raise KeyError(name)
        adapter = self._instantiate(name)
        self._adapters[name] = adapter
        return adapter

    def register(self, adapter: IntegrationAdapter) -> None:
        """Install an adapter instance (tests, simulator). Replaces any existing instance."""
        if not isinstance(adapter, IntegrationAdapter):
            raise TypeError("adapter must be an IntegrationAdapter")
        if adapter.name not in INTEGRATION_NAMES:
            raise ValueError(f"unknown integration {adapter.name!r}")
        old = self._adapters.get(adapter.name)
        if old is not None and old is not adapter:
            old.close()
        self._adapters[adapter.name] = adapter
        self._registered.add(adapter.name)
        self._load_errors.pop(adapter.name, None)

    # ----------------------------------------------------------- routing --
    def for_action(self, action_type: ActionType) -> list[IntegrationAdapter]:
        """Enabled adapters able to serve ``action_type``, in the catalog's preference order.

        State-changing types need the type in ``manifest.supported_actions``; read types need it
        in ``manifest.read_actions``. Adapters that fail to load are skipped (and recorded).
        """
        spec = get_action_spec(action_type)
        out: list[IntegrationAdapter] = []
        for name in spec.integrations:
            adapter = self._usable(name)
            if adapter is None:
                continue
            served = (adapter.manifest.supported_actions if spec.state_changing
                      else adapter.manifest.read_actions)
            if spec.action_type in served:
                out.append(adapter)
        return out

    def for_observable(self, observable_type: ObservableType) -> list[IntegrationAdapter]:
        """Enabled adapters whose manifest enriches ``observable_type`` (canonical order)."""
        out: list[IntegrationAdapter] = []
        for name in INTEGRATION_NAMES:
            adapter = self._usable(name)
            if adapter is not None and observable_type in adapter.manifest.enrichment_types:
                out.append(adapter)
        return out

    def close(self) -> None:
        """Close every instantiated adapter (errors are logged, never raised)."""
        for adapter in self._adapters.values():
            try:
                adapter.close()
            except Exception as exc:  # noqa: BLE001
                _log.warning("closing adapter %s failed: %s", adapter.name, type(exc).__name__)

    # ----------------------------------------------------------- private --
    def _usable(self, name: str) -> IntegrationAdapter | None:
        if not self.is_enabled(name):
            return None
        try:
            return self.get(name)
        except IntegrationUnavailableError:
            return None

    def _instantiate(self, name: str) -> IntegrationAdapter:
        try:
            cls = self._loader(name)
            transport = self.transport_factory(name) if self.transport_factory else None
            return cls(self.settings.integration(name), self.secrets, transport=transport,
                       clock=self.clock, audit=self.audit, settings=self.settings, sleep=self.sleep)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully, report why
            reason = get_redactor().redact_text(f"{type(exc).__name__}: {exc}")[:500]
            self._load_errors[name] = reason
            _log.warning("adapter %s unavailable: %s", name, reason)
            raise IntegrationUnavailableError(f"{name}: adapter could not be loaded ({reason})",
                                              integration=name, retryable=False) from exc
