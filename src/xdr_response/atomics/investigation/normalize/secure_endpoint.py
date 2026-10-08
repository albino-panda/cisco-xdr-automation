"""Normalizer for ``secure_endpoint`` investigation results (architecture 14.1.4).

Secure Endpoint device trajectory (``GET /v1/computers/{connector_guid}/trajectory``). The page
cited in ``docs/integrations.md`` (What's New) verifies the endpoint but documents no event fields, so
no field is mapped: every event becomes a ``GenericRecord`` until the event schema page is read and
recorded there (then the events become ``ProcessEventRecord``/``NetworkConnectionRecord``).
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
