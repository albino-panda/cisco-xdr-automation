"""Containment execution engine (architecture sections 6 and 13.16).

Approved actions run automatically after a human approval, each inside ``guard.authorized``;
nothing here can approve, widen an approval or bypass the guard.
"""
from __future__ import annotations

from xdr_response.execution.executor import ContainmentExecutor, check_token_binds_package
from xdr_response.execution.outcome import (
    compute_containment_overall,
    compute_restoration_overall,
    is_considered,
    is_effective,
    is_failed,
    to_incident_state,
)
from xdr_response.execution.protocols import (
    ActionVerifier,
    AdapterProvider,
    PackageSimulator,
    PackageTokenVerifier,
)
from xdr_response.execution.runner import ActionRunner
from xdr_response.execution.state_store import (
    ExecutionPhase,
    ExecutionRecord,
    ExecutionStateStore,
    InMemoryExecutionStateStore,
    SqliteExecutionStateStore,
)

__all__ = [
    "ActionRunner",
    "ContainmentExecutor",
    "check_token_binds_package",
    "is_effective",
    "is_failed",
    "is_considered",
    "compute_containment_overall",
    "compute_restoration_overall",
    "to_incident_state",
    "AdapterProvider",
    "ActionVerifier",
    "PackageSimulator",
    "PackageTokenVerifier",
    "ExecutionPhase",
    "ExecutionRecord",
    "ExecutionStateStore",
    "InMemoryExecutionStateStore",
    "SqliteExecutionStateStore",
]
