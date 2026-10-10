"""ReadOnlyAdapters and AtomicContext (architecture 14.1.1): the only door from the read zone."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.sample_workflows.lab import HASH, HOST, make_incident, make_lab
from tools.simulator.scenario import SIM_NOW
from xdr_response.atomics import atomic_subject_types, containment_builders, read_atomics
from xdr_response.atomics.context import AtomicContext, ReadOnlyAdapters, build_context
from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.integrations.base import IntegrationAdapter
from xdr_response.models import (
    ActionType,
    HealthStatus,
    InvestigationQuery,
    Observable,
    ObservableType,
    TargetKind,
    Verdict,
)


@pytest.fixture
def lab():
    # One endpoint product and one intel source: the facade's name lists below are exact.
    return make_lab({"secure_endpoint": ("endpoint",), "virustotal": ("intel",)})


def test_only_a_registry_is_accepted_and_no_adapter_leaks(lab):
    with pytest.raises(TypeError):
        ReadOnlyAdapters(object())  # type: ignore[arg-type]
    facade = lab.adapters
    assert not hasattr(facade, "__dict__")  # __slots__ only
    with pytest.raises(AttributeError):
        facade.registry  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        facade.x = 1  # type: ignore[attr-defined]
    public = [getattr(facade, name) for name in dir(facade) if not name.startswith("_")]
    assert not any(isinstance(v, IntegrationAdapter) for v in public)
    assert "ReadOnlyAdapters(enabled=" in repr(facade)


def test_names_manifests_and_health(lab):
    facade = lab.adapters
    assert facade.enabled() == ("secure_endpoint", "virustotal")
    assert facade.is_simulated("secure_endpoint") and not facade.is_simulated("entra")
    assert facade.is_simulated("not_an_integration") is False
    assert facade.manifest("secure_endpoint").integration == "secure_endpoint"
    with pytest.raises(KeyError):
        facade.manifest("acme")
    assert facade.health("secure_endpoint").status is HealthStatus.CONNECTED
    assert facade.health("entra").status is HealthStatus.UNKNOWN  # disabled: never raises
    assert facade.health("acme").status is HealthStatus.UNKNOWN


def test_enrichment_goes_through_enabled_enrichers_only(lab):
    lab.infected()
    facade = lab.adapters
    sha = Observable(type=ObservableType.SHA256, value=HASH)
    assert facade.enrichers(ObservableType.SHA256) == ("secure_endpoint", "virustotal")
    assert facade.enrich("virustotal", sha).verdict is Verdict.MALICIOUS
    with pytest.raises(CapabilityNotSupportedError):
        facade.enrich("entra", sha)
    with pytest.raises(CapabilityNotSupportedError):
        facade.enrich("virustotal", Observable(type=ObservableType.HOSTNAME, value=HOST))


def test_investigation_names_and_calls(lab):
    lab.infected()
    facade = lab.adapters
    assert facade.investigators(ActionType.INVESTIGATE_ENDPOINT) == ("secure_endpoint",)
    with pytest.raises(ValueError, match="not an investigation"):
        facade.investigators(ActionType.ISOLATE_ENDPOINT)
    query = InvestigationQuery(action_type=ActionType.INVESTIGATE_ENDPOINT,
                               subject=Observable(type=ObservableType.HOSTNAME, value=HOST),
                               time_from=SIM_NOW - timedelta(hours=1), time_to=SIM_NOW)
    assert len(facade.investigate("secure_endpoint", query).findings) == 2
    with pytest.raises(CapabilityNotSupportedError):
        facade.investigate("virustotal", query)


def test_executors_are_names_for_routing_only(lab):
    facade = lab.adapters
    assert facade.executors(ActionType.ISOLATE_ENDPOINT) == ("secure_endpoint",)
    assert facade.executors(ActionType.BLOCK_DOMAIN) == ()
    for not_executable in (ActionType.RELEASE_ENDPOINT, ActionType.ENRICH_IP, ActionType.NOTIFY_SOC):
        with pytest.raises(ValueError, match="not a containment or remediation"):
            facade.executors(not_executable)
    assert lab.environment.state_changing_calls() == []


def test_native_listing_is_empty_without_a_real_cisco_xdr(lab):
    observable = Observable(type=ObservableType.HOSTNAME, value=HOST)
    assert lab.adapters.native_response_actions(observable) == ()
    simulated_xdr = make_lab({"cisco_xdr": ("endpoint",)})
    assert simulated_xdr.adapters.native_response_actions(observable, module="Secure Endpoint") == ()


def test_build_context_derives_the_policies(lab):
    incident = make_incident(created_at=SIM_NOW - timedelta(hours=2))
    ctx = build_context(incident, lab.registry, lab.settings, clock=lab.clock, dry_run=False,
                        lookback=timedelta(hours=6))
    assert isinstance(ctx, AtomicContext) and isinstance(ctx.adapters, ReadOnlyAdapters)
    assert ctx.now() == SIM_NOW and ctx.dry_run is False
    assert ctx.window() == (SIM_NOW - timedelta(hours=8), SIM_NOW)
    assert ctx.critical_assets.classify("PRD-DB-07", TargetKind.ENDPOINT)
    assert ctx.allowlists.excluded_reason(ActionType.ISOLATE_ENDPOINT, "TH-DC-01", TargetKind.ENDPOINT)
    default = build_context(make_incident(), lab.registry, lab.settings, clock=lab.clock, dry_run=True)
    assert default.lookback == timedelta(hours=24) and default.dry_run is True
    with pytest.raises(ValueError, match="lookback must be positive"):
        build_context(incident, lab.registry, lab.settings, clock=lab.clock, dry_run=True, lookback=timedelta(0))


def test_a_future_incident_never_moves_the_window_end(lab):
    incident = make_incident(created_at=SIM_NOW + timedelta(hours=1))
    ctx = build_context(incident, lab.registry, lab.settings, clock=lab.clock, dry_run=True)
    assert ctx.window() == (SIM_NOW - timedelta(hours=24), SIM_NOW)


def test_the_atomic_name_tables_compose_without_collisions():
    atomics = read_atomics()
    assert len(atomics) == 23 and set(atomics) == set(atomic_subject_types())
    assert {"enrich_hash", "investigate_endpoint", "search_related_users"} <= set(atomics)
    assert len(containment_builders()) == 15
    assert read_atomics() is atomics  # composed once
