"""Optional, pure workflow hooks (architecture 14.3.3).

Hooks see a read-only :class:`RunView` (no context, no adapters), so they cannot reach a vendor.
They may contribute correlation links (kind ``WORKFLOW``, origin ``"workflow:<id>"``), scoring
signals (origin ``"workflow:<id>"``) and JSON facts for rule expressions. Every link and signal must
cite record ids of the run; the runner validates them and notes and ignores anything invalid, any
exception and non-JSON facts (a hook never blocks or crashes a run).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from xdr_response.models import Incident
from xdr_response.workflows.definition import WorkflowDefinition

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.correlation.models import BlastRadiusReport, CorrelationLink, CorrelationResult
    from xdr_response.atomics.evidence import RecordIndex
    from xdr_response.atomics.records import AtomicResult
    from xdr_response.models.scoring import ScoringSignal

__all__ = ["RunView", "WorkflowHooks"]


@dataclass(frozen=True)
class RunView:
    """Read-only facts of one run; no context, no adapters."""

    workflow: WorkflowDefinition
    incident: Incident
    results: "tuple[AtomicResult, ...]"
    index: "RecordIndex"
    correlation: "CorrelationResult | None"
    blast_radius: "BlastRadiusReport | None"

    @property
    def origin(self) -> str:
        """The origin every hook link and signal must carry: ``"workflow:<id>"``."""
        return f"workflow:{self.workflow.id}"


class WorkflowHooks:
    """Base class of a workflow's hooks; every method defaults to contributing nothing."""

    def correlate(self, view: RunView) -> "Sequence[CorrelationLink]":
        """Extra correlation links (called with ``view.correlation is None``)."""
        return ()

    def derive_signals(self, view: RunView) -> "Sequence[ScoringSignal]":
        """Extra scoring signals computed from cited records (final correlation available).

        The runner keeps a signal only when its origin is ``workflow:<id>``, every cited record
        exists in the run and ``signal.integration`` produced at least one of them (14.9.6).
        """
        return ()

    def facts(self, view: RunView) -> Mapping[str, Any]:
        """JSON values exposed to rule expressions as ``facts``."""
        return {}
