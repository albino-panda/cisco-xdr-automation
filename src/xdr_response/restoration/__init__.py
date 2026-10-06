"""Restoration: temporary control registry, release planning and release execution (section 13.17).

Controls created by automation are recorded in a :class:`TemporaryControlRegistry` implementation;
they are released only through a :class:`RestorationPlanner` release package that a human approved
with a ``release`` token, executed by :class:`RestorationEngine` under the execution guard. Closing
an incident never removes or changes a control.
"""
from __future__ import annotations

from xdr_response.restoration.engine import (
    RestorationEngine,
    ReleaseSimulator,
    RollbackRunner,
    compute_overall,
    is_release_effective,
)
from xdr_response.restoration.planner import RestorationPlanner
from xdr_response.restoration.registry import (
    RELEASABLE_STATUSES,
    ControlEvent,
    ControlEventType,
    InMemoryControlRegistry,
    JsonlControlRegistry,
    SqliteControlRegistry,
    control_from_result,
)

#: Contract name of the registry concept (section 8.1); the default durable backend.
TemporaryControlRegistry = JsonlControlRegistry

__all__ = [
    "RELEASABLE_STATUSES",
    "ControlEvent",
    "ControlEventType",
    "InMemoryControlRegistry",
    "JsonlControlRegistry",
    "SqliteControlRegistry",
    "TemporaryControlRegistry",
    "control_from_result",
    "RestorationPlanner",
    "RestorationEngine",
    "RollbackRunner",
    "ReleaseSimulator",
    "compute_overall",
    "is_release_effective",
]
