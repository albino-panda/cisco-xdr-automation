"""Bundled incident scenarios in a lab where every proposed action can be verified automatically.

Production parity (architecture 14.14.3, 15.1): the simulated adapters do exactly what the real
ones do. Secure Endpoint isolation and release cannot be verified (UNABLE_TO_VERIFY), and no adapter
can verify a hash block. Safety tests of the verification gates (CONTAINED only when verified,
RELEASED only when verified, NOT_VERIFIED after a write with no effect, retries and replays of
verified controls) need a lab where those gates can actually open. In this variant Defender for
Endpoint is enabled next to Secure Endpoint; isolation routes to it first (catalog order) and its
isolate and release have a VERIFIED read-back. Hash observables and hash reputations are dropped,
because a hash block can never be verified. Secure Endpoint stays enabled for its reads.

Nothing here widens what a simulated adapter can do: the suite only enables another real-parity
simulated adapter. Fake data only.
"""
from __future__ import annotations

import dataclasses

from tools.simulator.scenario import Scenario, load_scenario
from xdr_response.models import ObservableType

#: The endpoint product whose isolation and release are verifiable (docs/integrations.md).
VERIFIED_EDR = "defender_endpoint"

_HASH_TYPES = frozenset({ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5})


def verifiable(scenario: Scenario) -> Scenario:
    """``scenario`` with Defender for Endpoint enabled and its hash indicators removed."""
    incident = scenario.incident.model_copy(
        update={"observables": tuple(o for o in scenario.incident.observables if o.type not in _HASH_TYPES)})
    environment = dict(scenario.environment)
    hash_names = {t.value for t in _HASH_TYPES}
    environment["reputations"] = [r for r in environment.get("reputations") or ()
                                  if str(r.get("type", "")).lower() not in hash_names]
    return dataclasses.replace(scenario, name=f"{scenario.name}-verifiable", incident=incident,
                               environment=environment, suite={**scenario.suite, VERIFIED_EDR: ("endpoint",)})


def load_verifiable_scenario(name: str) -> Scenario:
    """A bundled scenario (``tests/fixtures/incidents/<name>.yaml``) in the verifiable lab."""
    return verifiable(load_scenario(name))
