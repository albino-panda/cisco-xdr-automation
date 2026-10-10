"""Simulated adapters never do more than the real adapters (architecture 14.14.3).

A simulated adapter posing as a real integration derives its state-changing actions and its
read-backs from the real manifest (``xdr_response.integrations.<name>.manifest.MANIFEST``) and
``docs/integrations.md`` (only VERIFIED endpoints are in a real manifest). These tests pin that:

* for every real integration and every family combination, the simulated manifest supports a subset of
  the real ``supported_actions`` and verifies a subset of the real ``verifiable_actions``;
* with every family, the simulated manifest equals the real one exactly, so a capability added to or
  removed from a real manifest reaches the lab without editing the simulator (no drift);
* the lab suites (``SIMULATED_SUITE`` and the simulator's ``SIMULATION_SUITE``) route an action only to an
  integration whose real adapter executes it, so actions without any VERIFIED write stay unrouted;
* there is no unconstrained lab adapter (a name without a real manifest is refused);
* the gaps the review named (Secure Endpoint hash blocks and isolation read-back, Cisco XDR native,
  Defender for Office 365 and Intune verification) are closed.

Fake lab data only; nothing leaves the process.
"""
from __future__ import annotations

import itertools
import pkgutil

import pytest

import xdr_response.integrations as integrations_pkg
from tools.simulator.scenario import SIMULATION_SUITE
from xdr_response.integrations.simulated import (
    FAMILIES,
    SIMULATED_SUITE,
    SimulatedEndpointAdapter,
    SimulatedEnvironment,
    build_simulated_adapters,
    build_simulated_manifest,
    production_manifest,
    simulated_adapter_class,
)
from xdr_response.models import ActionType, VerificationStatus, get_action_spec

REAL = sorted(name for name in (m.name for m in pkgutil.iter_modules(integrations_pkg.__path__) if m.ispkg)
              if production_manifest(name) is not None)
FAMILY_SETS = [combo for size in range(1, len(FAMILIES) + 1)
               for combo in itertools.combinations(sorted(FAMILIES), size)]
ALL_FAMILIES = tuple(sorted(FAMILIES))
STATE_CHANGING = frozenset(a for a in ActionType if get_action_spec(a).state_changing)


def test_every_runtime_integration_has_a_real_manifest_the_lab_can_read():
    assert len(REAL) >= 16
    assert {"secure_endpoint", "cisco_xdr", "defender_o365", "intune", "entra", "umbrella"} <= set(REAL)


@pytest.mark.parametrize("integration", REAL)
def test_simulated_manifest_never_exceeds_the_real_adapter(integration: str):
    real = production_manifest(integration)
    assert real is not None
    for families in FAMILY_SETS:
        sim = build_simulated_manifest(integration, families)
        assert sim.supported_actions <= real.supported_actions, (integration, families)
        assert sim.verifiable_actions <= real.verifiable_actions, (integration, families)
        assert sim.verifiable_actions <= sim.supported_actions, (integration, families)
        family_actions = frozenset().union(*(FAMILIES[f].actions for f in families))
        assert sim.supported_actions == family_actions & real.supported_actions, (integration, families)
        # the verify_state operation names exactly the verifiable actions
        verify_ops = [op for op in sim.operations if op.name == "verify_state"]
        assert len(verify_ops) == 1 and set(verify_ops[0].action_types) == sim.verifiable_actions


@pytest.mark.parametrize("integration", REAL)
def test_with_every_family_the_lab_equals_production(integration: str):
    """Derived, not copied: the lab follows any change to a real manifest."""
    real = production_manifest(integration)
    sim = build_simulated_manifest(integration, ALL_FAMILIES)
    assert sim.supported_actions == real.supported_actions & STATE_CHANGING
    assert sim.verifiable_actions == real.verifiable_actions & STATE_CHANGING


@pytest.mark.parametrize("suite_name, suite", [("SIMULATED_SUITE", SIMULATED_SUITE),
                                               ("SIMULATION_SUITE", SIMULATION_SUITE)])
def test_lab_suites_route_only_to_capable_integrations(suite_name: str, suite):
    env = SimulatedEnvironment()
    adapters = build_simulated_adapters(env, suite=suite)
    for action in sorted(STATE_CHANGING, key=lambda a: a.value):
        capable = [a.name for a in adapters if action in a.manifest.supported_actions]
        for name in capable:
            real = production_manifest(name)
            assert action in real.supported_actions, f"{suite_name}: {name} executes {action.value}"
        for adapter in adapters:
            if action in adapter.manifest.verifiable_actions:
                assert action in production_manifest(adapter.name).verifiable_actions


def test_actions_without_any_verified_write_are_executable_nowhere():
    """terminate_process, quarantine_file, remove_persistence, reset_password, reset_mfa,
    revoke_app_credentials and remove_application have no VERIFIED write in any real adapter."""
    nowhere = {a for a in STATE_CHANGING
               if not any(a in production_manifest(n).supported_actions for n in REAL)}
    assert {ActionType.TERMINATE_PROCESS, ActionType.QUARANTINE_FILE, ActionType.REMOVE_PERSISTENCE,
            ActionType.RESET_PASSWORD, ActionType.RESET_MFA, ActionType.REVOKE_APP_CREDENTIALS,
            ActionType.REMOVE_APPLICATION} <= nowhere
    for name in REAL:
        manifest = build_simulated_manifest(name, ALL_FAMILIES)
        assert not (manifest.supported_actions & nowhere), name


def test_the_review_gaps_are_closed():
    endpoint = SimulatedEndpointAdapter.manifest
    assert endpoint.supported_actions == {ActionType.ISOLATE_ENDPOINT, ActionType.RELEASE_ENDPOINT}
    assert endpoint.verifiable_actions == frozenset()
    for hidden in (ActionType.BLOCK_HASH, ActionType.UNBLOCK_HASH, ActionType.TERMINATE_PROCESS,
                   ActionType.QUARANTINE_FILE, ActionType.RESTORE_FILE, ActionType.REMOVE_PERSISTENCE,
                   ActionType.LOCK_DEVICE, ActionType.REMOVE_APPLICATION):
        assert hidden not in endpoint.supported_actions
    for name in ("cisco_xdr", "defender_o365", "intune", "secure_endpoint"):
        assert build_simulated_manifest(name, ALL_FAMILIES).verifiable_actions == frozenset(), name
    assert build_simulated_manifest("intune", ("endpoint",)).supported_actions == {ActionType.LOCK_DEVICE}
    # Defender for Endpoint blocks hashes but cannot read the indicator back
    defender = build_simulated_manifest("defender_endpoint", ("endpoint",))
    assert ActionType.BLOCK_HASH in defender.supported_actions
    assert ActionType.BLOCK_HASH not in defender.verifiable_actions
    assert ActionType.ISOLATE_ENDPOINT in defender.verifiable_actions


def test_unverifiable_simulated_action_reports_unable_to_verify():
    from tests.fixtures.factories import make_recommendation
    from xdr_response.models import ActionRequest

    env = SimulatedEnvironment()
    adapter = simulated_adapter_class("intune", ("endpoint",))(environment=env)
    request = ActionRequest.from_recommendation(make_recommendation(ActionType.LOCK_DEVICE, "device-0001",
                                                                    integration="intune"))
    env.force_desired_state(ActionType.LOCK_DEVICE, request.target)
    assert adapter.verify(request, None).status is VerificationStatus.UNABLE_TO_VERIFY


def test_a_simulated_adapter_always_mirrors_a_real_one():
    """There is no unconstrained lab adapter: a name without a real manifest is refused."""
    assert production_manifest("tests_only_vendor") is None
    with pytest.raises(ValueError, match="no real adapter manifest"):
        build_simulated_manifest("tests_only_vendor", ("endpoint",))
