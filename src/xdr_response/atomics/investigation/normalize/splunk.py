"""Normalizer for ``splunk`` investigation results (architecture 14.1.4).

Splunk search results (``/services/search/jobs/{sid}/results``). Result rows are whatever the
operator's SPL returns; no field is vendor-defined, so every row becomes a ``GenericRecord``.
Splunk is optional and disabled by default: when it is disabled it is never queried.
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
