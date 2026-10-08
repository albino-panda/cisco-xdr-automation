"""Optional, pure workflow hooks (architecture 14.3.3).

Hooks see a read-only :class:`RunView` (no context, no adapters), so they cannot reach a vendor.
They may contribute correlation links (kind ``WORKFLOW``, origin ``"workflow:<id>"``), scoring
signals (origin ``"workflow:<id>"``) and JSON facts for rule expressions. Every link and signal must
cite record ids of the run; the runner validates them and notes and ignores anything invalid, any
exception and non-JSON facts (a hook never blocks or crashes a run).

Since Phase 2 (architecture 14.10.1) hooks may also report, from the same records:

* :class:`Consideration` items: something the workflow examined and deliberately did **not** recommend
  (a widespread hash, a shared IP, a host whose policy forbids isolation), or a **manual step** that has
  no VERIFIED write (removing a mailbox rule). They reach the run notes, the workflow summary and the
  analyst notification, so a withheld action is visible, never silently skipped.
* :class:`Handoff` items: a suggestion to run another workflow (one listed in the definition's
  ``handoff_to``) for subjects this run found. A hand-off never starts anything; it is a note for the
  analyst, with the record ids that justify it.

:func:`failed_reads` (Phase 2 round 1 hardening, 14.10.1) tells a hook which subjects of which read
atomics lost a source, so a hook whose usual reasoning needs that source (for example an account
compromise assessed from identity records) can still recommend what other evidence backs, and say
why, instead of silently dropping it.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from xdr_response.models import Incident
from xdr_response.workflows.definition import WorkflowDefinition

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.correlation.models import BlastRadiusReport, CorrelationLink, CorrelationResult
    from xdr_response.atomics.evidence import RecordIndex
    from xdr_response.atomics.records import AtomicResult
    from xdr_response.models.scoring import ScoringSignal

__all__ = ["Consideration", "Handoff", "RunView", "WorkflowHooks", "failed_reads"]


@dataclass(frozen=True)
class Consideration:
    """An item the workflow considered and deliberately did not recommend, or a manual step.

    ``subject`` names what was considered (``"block_hash:<sha256>"``, a host, a user); ``reason`` says
    why nothing is proposed (or what to do by hand when ``manual``); ``record_ids`` cite the records of
    the run that show it (at least one, all known to the run).
    """

    subject: str
    reason: str
    record_ids: tuple[str, ...]
    manual: bool = False


@dataclass(frozen=True)
class Handoff:
    """A suggestion to run workflow ``workflow_id`` for ``subjects`` (never starts it).

    ``workflow_id`` must be listed in the definition's ``handoff_to``; ``record_ids`` cite the records
    of the run that justify the hand-off (at least one, all known to the run).
    """

    workflow_id: str
    subjects: tuple[str, ...]
    reason: str
    record_ids: tuple[str, ...]


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


def failed_reads(view: RunView, atomics: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Subjects of the given read atomics with at least one FAILED source.

    Maps the result's (normalized) subject value to the sorted integrations that failed for it in any
    of ``atomics``. Pure: reads ``view.results`` only. Subjects whose sources all answered are absent.
    """
    wanted = frozenset(atomics)
    out: dict[str, set[str]] = {}
    for result in view.results:
        if result.atomic not in wanted:
            continue
        failed = result.failed
        if failed:
            out.setdefault(result.subject.value, set()).update(failed)
    return {subject: tuple(sorted(names)) for subject, names in sorted(out.items())}


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

    def considered(self, view: RunView) -> "Sequence[Consideration]":
        """Items considered and deliberately not recommended, and manual steps (final view)."""
        return ()

    def handoffs(self, view: RunView) -> "Sequence[Handoff]":
        """Suggested hand-offs to workflows of ``handoff_to`` (final view; never started)."""
        return ()
