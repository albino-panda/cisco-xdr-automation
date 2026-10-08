"""Normalizer for ``cisco_xdr`` investigation results (architecture 14.1.4).

Cisco XDR ``observe/observables`` returns per-module sighting counts (``{"module", "sightings"}``).
No record kind describes an aggregate sighting count, so every finding becomes a ``GenericRecord``:
citable as evidence, never a scoring signal.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from xdr_response.atomics.investigation.normalize.typed import _generic_only, _normalize_findings
from xdr_response.atomics.records import AnyRecord
from xdr_response.models import InvestigationResult

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.investigation.normalize import NormalizeContext

__all__: list[str] = []


def _normalize(result: InvestigationResult, nctx: "NormalizeContext") -> list[AnyRecord]:
    """Typed findings (simulated adapters only), every other finding as a generic record."""
    return _normalize_findings(result, nctx, _generic_only)
