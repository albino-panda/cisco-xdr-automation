"""BuiltRecommendation / RouteDecision invariants (14.1.7 models, layer 0)."""
from __future__ import annotations

import pytest

from tests.unit.atomics.containment._support import evidence
from xdr_response.atomics.containment import BuiltRecommendation, RouteDecision
from xdr_response.models import ActionType, CriticalAssetClass, CriticalAssetWarning, ProposedAction, TargetKind

ROUTE = RouteDecision(action_type=ActionType.BLOCK_IP, integration="meraki", product="meraki",
                      params={"integration": "meraki"})
UNROUTED = RouteDecision(action_type=ActionType.BLOCK_IP, integration=None, reason="no enabled adapter")


def _proposal(**overrides):
    data = {"action_type": ActionType.BLOCK_IP, "target": "203.0.113.10", "target_kind": TargetKind.IP,
            "params": {"integration": "meraki"}, "evidence": evidence(1), "risk_score": 80,
            "confidence_score": 70, "rationale": "rule matched"}
    data.update(overrides)
    return ProposedAction(**data)


def _warning(action_type=ActionType.BLOCK_IP):
    return CriticalAssetWarning(asset="203.0.113.10", asset_class=CriticalAssetClass.NETWORK_INFRASTRUCTURE,
                                role="core router", action_type=action_type, potential_impact="outage",
                                message="WARNING: ELEVATED APPROVAL REQUIRED - test")


def test_valid_routed_and_unrouted():
    routed = BuiltRecommendation(action_type=ActionType.BLOCK_IP, target="203.0.113.10", proposal=_proposal(),
                                 route=ROUTE)
    assert routed.routed and routed.reversible and routed.rollback_action_type is ActionType.UNBLOCK_IP
    unrouted = BuiltRecommendation(action_type=ActionType.BLOCK_IP, target="203.0.113.10", proposal=None,
                                   route=UNROUTED, unrouted_reason=UNROUTED.reason, warnings=(_warning(),))
    assert not unrouted.routed and unrouted.elevation_expected


@pytest.mark.parametrize("kwargs", [
    {"proposal": None, "route": UNROUTED},                                       # no unrouted_reason
    {"proposal": _proposal(), "route": ROUTE, "unrouted_reason": "x"},          # reason with a proposal
    {"proposal": None, "route": ROUTE, "unrouted_reason": "x"},                 # routed but no proposal
    {"proposal": _proposal(target="203.0.113.11"), "route": ROUTE},             # target mismatch
    {"proposal": _proposal(params={"integration": "defender_endpoint"}), "route": ROUTE},  # integration mismatch
    {"proposal": _proposal(), "route": ROUTE, "warnings": (_warning(ActionType.BLOCK_URL),)},
    {"proposal": _proposal(), "route": RouteDecision(action_type=ActionType.BLOCK_URL, integration="umbrella",
                                                     params={"integration": "umbrella"})},
])
def test_invariants(kwargs):
    with pytest.raises(ValueError):
        BuiltRecommendation(action_type=ActionType.BLOCK_IP, target="203.0.113.10", **kwargs)


def test_restoration_types_are_refused():
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.RELEASE_ENDPOINT, integration=None, reason="x")


def test_models_are_frozen_and_closed():
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.BLOCK_IP, integration=None, reason="x", approval_level="STANDARD")
    with pytest.raises(Exception):
        ROUTE.integration = "umbrella"  # type: ignore[misc]
