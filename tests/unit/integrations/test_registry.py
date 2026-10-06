"""AdapterRegistry: lazy loading, disabled integrations skipped, graceful degradation, routing."""
from __future__ import annotations

import sys
import types

import httpx
import pytest

from tests.fixtures.principals import make_test_secrets
from tests.unit.integrations._support import fixed_clock
from xdr_response.config import IntegrationConfig
from xdr_response.config.schema import Settings
from xdr_response.errors import IntegrationUnavailableError
from xdr_response.integrations import registry as registry_module
from xdr_response.integrations.base import IntegrationAdapter
from xdr_response.integrations.registry import ADAPTER_PATHS, AdapterRegistry, load_adapter_class
from xdr_response.integrations.simulated import (
    SimulatedEnvironment,
    SimulatedIntelAdapter,
    register_simulated_adapters,
    simulated_adapter_class,
)
from xdr_response.models import INTEGRATION_NAMES, ActionType, ObservableType


def settings(*enabled: str) -> Settings:
    return Settings(integrations={n: IntegrationConfig(enabled=True) for n in enabled})


class Loader:
    """Injectable class loader returning simulated classes and recording what was loaded."""

    def __init__(self, families: dict[str, tuple[str, ...]], broken: set[str] | None = None) -> None:
        self.families = families
        self.broken = broken or set()
        self.loaded: list[str] = []

    def __call__(self, name: str) -> type[IntegrationAdapter]:
        self.loaded.append(name)
        if name in self.broken:
            raise ImportError(f"No module named 'xdr_response.integrations.{name}'")
        return simulated_adapter_class(name, self.families.get(name, ("intel",)))


def make_registry(*enabled: str, loader: Loader | None = None, **kw) -> AdapterRegistry:
    return AdapterRegistry(settings(*enabled), make_test_secrets(), clock=fixed_clock(),
                           class_loader=loader, **kw)


# ------------------------------------------------------------- adapter paths --
def test_adapter_paths_cover_every_integration() -> None:
    assert set(ADAPTER_PATHS) == set(INTEGRATION_NAMES)
    assert ADAPTER_PATHS["splunk"].endswith(":SplunkAdapter")
    for name, path in ADAPTER_PATHS.items():
        assert path.startswith(f"xdr_response.integrations.{name}.adapter:")


def test_load_adapter_class_unknown_name() -> None:
    with pytest.raises(KeyError):
        load_adapter_class("not_an_integration")


def test_load_adapter_class_imports_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("xdr_fake_adapter_module")
    module.Good = simulated_adapter_class("virustotal", ("intel",))  # type: ignore[attr-defined]
    module.Wrong = simulated_adapter_class("hibp", ("intel",))  # type: ignore[attr-defined]
    module.NotAdapter = object  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "xdr_fake_adapter_module", module)
    monkeypatch.setattr(registry_module, "ADAPTER_PATHS", {
        "virustotal": "xdr_fake_adapter_module:Good",
        "hibp": "xdr_fake_adapter_module:Missing",
        "splunk": "xdr_fake_adapter_module:NotAdapter",
        "umbrella": "xdr_fake_adapter_module:Wrong",
        "meraki": "xdr_no_such_module_anywhere:Thing",
    })
    assert load_adapter_class("virustotal") is module.Good
    with pytest.raises(ImportError):
        load_adapter_class("hibp")
    with pytest.raises(TypeError):
        load_adapter_class("splunk")
    with pytest.raises(TypeError):
        load_adapter_class("umbrella")
    with pytest.raises(ImportError):
        load_adapter_class("meraki")


# ----------------------------------------------------------------- lookups --
def test_enabled_lists_only_enabled_and_splunk_is_off_by_default() -> None:
    reg = make_registry("virustotal", "entra")
    assert reg.enabled() == ["entra", "virustotal"]
    assert reg.is_enabled("splunk") is False
    assert reg.names() == list(INTEGRATION_NAMES)
    with pytest.raises(KeyError):
        reg.is_enabled("nope")


def test_get_instantiates_lazily_once_with_config_and_transport() -> None:
    loader = Loader({"entra": ("identity",)})
    transports: list[str] = []

    def transport_factory(name: str) -> httpx.BaseTransport:
        transports.append(name)
        return httpx.MockTransport(lambda r: httpx.Response(200))

    reg = make_registry("entra", loader=loader, transport_factory=transport_factory)
    assert loader.loaded == []
    adapter = reg.get("entra")
    assert reg.get("entra") is adapter
    assert loader.loaded == ["entra"]
    assert transports == ["entra"]
    assert adapter.config.enabled is True
    assert adapter.transport is not None
    assert adapter.clock is reg.clock


def test_get_unknown_name_raises_key_error() -> None:
    with pytest.raises(KeyError):
        make_registry().get("not_an_integration")


def test_load_failure_is_reported_not_fatal() -> None:
    loader = Loader({}, broken={"virustotal"})
    reg = make_registry("virustotal", "alienvault_otx", loader=loader)
    with pytest.raises(IntegrationUnavailableError) as exc:
        reg.get("virustotal")
    assert exc.value.retryable is False
    assert "virustotal" in reg.load_errors
    assert [a.name for a in reg.for_observable(ObservableType.DOMAIN)] == ["alienvault_otx"]


# ----------------------------------------------------------------- routing --
def test_for_action_follows_catalog_order_and_skips_disabled() -> None:
    loader = Loader({"secure_endpoint": ("endpoint",), "defender_endpoint": ("endpoint",),
                     "cisco_xdr": ("endpoint",)})
    reg = make_registry("secure_endpoint", "defender_endpoint", loader=loader)
    names = [a.name for a in reg.for_action(ActionType.ISOLATE_ENDPOINT)]
    assert names == ["defender_endpoint", "secure_endpoint"]  # catalog order; cisco_xdr disabled
    assert "cisco_xdr" not in loader.loaded


def test_for_action_requires_manifest_support() -> None:
    loader = Loader({"entra": ("identity",), "cisco_xdr": ("intel",)})
    reg = make_registry("entra", "cisco_xdr", loader=loader)
    assert [a.name for a in reg.for_action(ActionType.DISABLE_USER)] == ["entra"]
    assert reg.for_action(ActionType.ISOLATE_ENDPOINT) == []


def test_for_action_read_types_use_read_actions() -> None:
    loader = Loader({"virustotal": ("intel",), "alienvault_otx": ("intel",)})
    reg = make_registry("virustotal", "alienvault_otx", loader=loader)
    assert [a.name for a in reg.for_action(ActionType.ENRICH_DOMAIN)] == ["virustotal", "alienvault_otx"]


def test_disabled_splunk_is_never_loaded() -> None:
    loader = Loader({"splunk": ("intel",)})
    reg = make_registry("virustotal", loader=loader)
    reg.for_action(ActionType.INVESTIGATE_USER)
    reg.for_observable(ObservableType.IP)
    assert "splunk" not in loader.loaded


# ---------------------------------------------------------------- register --
def test_register_overrides_settings_and_validates() -> None:
    reg = make_registry()
    adapter = SimulatedIntelAdapter()
    reg.register(adapter)
    assert reg.get("virustotal") is adapter
    assert reg.is_enabled("virustotal") is True  # registered adapters use their own config
    with pytest.raises(TypeError):
        reg.register(object())  # type: ignore[arg-type]


def test_register_replaces_and_closes_previous() -> None:
    reg = make_registry()
    first, second = SimulatedIntelAdapter(), SimulatedIntelAdapter()
    closed: list[str] = []
    first.close = lambda: closed.append("first")  # type: ignore[method-assign]
    reg.register(first)
    reg.register(second)
    assert reg.get("virustotal") is second
    assert closed == ["first"]


def test_register_disabled_adapter_is_not_routed() -> None:
    reg = make_registry()
    reg.register(SimulatedIntelAdapter(IntegrationConfig(enabled=False)))
    assert reg.for_observable(ObservableType.IP) == []
    assert reg.enabled() == []


def test_register_simulated_suite_routes_every_catalog_action() -> None:
    reg = make_registry()
    env = SimulatedEnvironment(clock=reg.clock)
    register_simulated_adapters(reg, env)
    assert [a.name for a in reg.for_action(ActionType.ISOLATE_ENDPOINT)] == ["defender_endpoint", "secure_endpoint"]
    assert [a.name for a in reg.for_action(ActionType.BLOCK_DOMAIN)] == ["umbrella", "defender_endpoint"]
    assert [a.name for a in reg.for_action(ActionType.LOCK_DEVICE)] == ["intune"]
    assert [a.name for a in reg.for_action(ActionType.QUARANTINE_EMAIL)] == ["secure_email", "defender_o365"]
    assert [a.name for a in reg.for_action(ActionType.BLOCK_NETWORK_CLIENT)] == ["meraki"]
    assert reg.for_action(ActionType.REMOVE_PERSISTENCE) == []  # no catalog integration


def test_close_closes_every_adapter_and_survives_errors() -> None:
    reg = make_registry()
    adapter = SimulatedIntelAdapter()

    def boom() -> None:
        raise RuntimeError("close failed")

    adapter.close = boom  # type: ignore[method-assign]
    reg.register(adapter)
    reg.close()  # does not raise
