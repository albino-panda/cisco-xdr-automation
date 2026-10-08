"""Containment recommendation builders (architecture 14.1.7, owner: containment-atomics).

Builders turn a workflow rule's decision into a :class:`BuiltRecommendation` (a ``ProposedAction``
plus the native-first route, the critical-asset warning preview, the allow-list preview and the
catalog rollback). They never execute: ``PackageBuilder`` packages the proposal, a human approves
it, and only the lifecycle orchestrator executes approved actions.
"""
from __future__ import annotations

from xdr_response.atomics.containment.builders import (
    CONTAINMENT_BUILDERS,
    RESERVED_PARAM_KEYS,
    block_domain_umbrella,
    block_hash,
    block_ip,
    block_url,
    build_containment,
    delete_malicious_email,
    disable_entra_user,
    intune_device_action,
    isolate_defender_endpoint,
    isolate_secure_endpoint,
    quarantine_email,
    quarantine_file,
    remove_persistence,
    remove_privileged_role,
    revoke_entra_sessions,
    terminate_process,
)
from xdr_response.atomics.containment.models import BuiltRecommendation, RouteDecision
from xdr_response.atomics.containment.routing import NATIVE_OBSERVABLE_TYPES, choose_route

__all__ = [
    "RouteDecision",
    "BuiltRecommendation",
    "NATIVE_OBSERVABLE_TYPES",
    "choose_route",
    "RESERVED_PARAM_KEYS",
    "build_containment",
    "CONTAINMENT_BUILDERS",
    "isolate_secure_endpoint",
    "isolate_defender_endpoint",
    "block_domain_umbrella",
    "block_url",
    "block_ip",
    "block_hash",
    "revoke_entra_sessions",
    "disable_entra_user",
    "quarantine_email",
    "delete_malicious_email",
    "intune_device_action",
    "terminate_process",
    "quarantine_file",
    "remove_persistence",
    "remove_privileged_role",
]
