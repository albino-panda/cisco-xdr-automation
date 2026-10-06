"""Incident lifecycle: state machine, stores, investigation, recommendation, orchestrator and runtime.

Names are resolved lazily so ``xdr_response.lifecycle.states`` stays cheap to import (layer 0
re-export) and importing this package never pulls in every engine.
"""
from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "ALLOWED_TRANSITIONS": "xdr_response.lifecycle.states",
    "TOKEN_REQUIRED": "xdr_response.lifecycle.states",
    "can_transition": "xdr_response.lifecycle.states",
    "IncidentStateMachine": "xdr_response.lifecycle.machine",
    "LIFECYCLE_ACTOR": "xdr_response.lifecycle.machine",
    "InMemoryIncidentStore": "xdr_response.lifecycle.store",
    "InMemoryPackageStore": "xdr_response.lifecycle.store",
    "InvestigationService": "xdr_response.lifecycle.investigation",
    "InvestigationReport": "xdr_response.lifecycle.investigation",
    "DEFAULT_INVESTIGATIONS": "xdr_response.lifecycle.investigation",
    "RuleBasedRecommender": "xdr_response.lifecycle.recommendation",
    "Recommendation": "xdr_response.lifecycle.recommendation",
    "Recommender": "xdr_response.lifecycle.recommendation",
    "PlaybookRule": "xdr_response.lifecycle.recommendation",
    "DEFAULT_PLAYBOOK": "xdr_response.lifecycle.recommendation",
    "ResponseOrchestrator": "xdr_response.lifecycle.orchestrator",
    "DecisionResult": "xdr_response.lifecycle.orchestrator",
    "DetectionResult": "xdr_response.lifecycle.orchestrator",
    "Runtime": "xdr_response.lifecycle.runtime",
    "build_runtime": "xdr_response.lifecycle.runtime",
    "bootstrap": "xdr_response.lifecycle.runtime",
    "in_memory_runtime": "xdr_response.lifecycle.runtime",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module 'xdr_response.lifecycle' has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
