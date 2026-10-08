"""Investigation normalizers (architecture 14.1.4): vendor findings to typed records.

``NORMALIZERS`` maps each investigating integration to its normalizer. Every normalizer:

* accepts typed records (``TYPED_RECORD_KEY``) only from simulated adapters
  (``NormalizeContext.typed_allowed``); from a real adapter such a finding becomes a generic record;
* maps only fields documented by the vendor page cited in ``docs/integrations.md`` for that
  operation; anything else stays ``None``, and a finding it does not understand becomes one
  ``GenericRecord(name=f"{integration}:{atomic}")``;
* never calls an adapter and never reads a secret.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from xdr_response.atomics.investigation.normalize.cisco_xdr import _normalize as _cisco_xdr
from xdr_response.atomics.investigation.normalize.defender_endpoint import _normalize as _defender_endpoint
from xdr_response.atomics.investigation.normalize.entra import _normalize as _entra
from xdr_response.atomics.investigation.normalize.intune import _normalize as _intune
from xdr_response.atomics.investigation.normalize.microsoft_cloud import _normalize as _microsoft_cloud
from xdr_response.atomics.investigation.normalize.secure_email import _normalize as _secure_email
from xdr_response.atomics.investigation.normalize.secure_endpoint import _normalize as _secure_endpoint
from xdr_response.atomics.investigation.normalize.splunk import _normalize as _splunk
from xdr_response.atomics.investigation.normalize.typed import (
    TYPED_INTEGRATION_KEY,
    TYPED_RECORD_KEY,
    _generic_only,
    _normalize_findings,
)
from xdr_response.atomics.records import AnyRecord
from xdr_response.models import InvestigationResult, Observable

__all__ = ["Normalizer", "NormalizeContext", "NORMALIZERS", "normalize", "TYPED_RECORD_KEY",
           "TYPED_INTEGRATION_KEY"]

Normalizer = Callable[[InvestigationResult, "NormalizeContext"], list[AnyRecord]]


@dataclass(frozen=True)
class NormalizeContext:
    """What a normalizer may know besides the result itself."""

    atomic: str
    subject: Observable
    internal_domains: tuple[str, ...]  # settings.exclusions.internal_domains (mailbox external forwarding)
    typed_allowed: bool  # ctx.adapters.is_simulated(integration)


NORMALIZERS: Mapping[str, Normalizer] = MappingProxyType({
    "cisco_xdr": _cisco_xdr,
    "secure_endpoint": _secure_endpoint,
    "defender_endpoint": _defender_endpoint,
    "entra": _entra,
    "microsoft_cloud": _microsoft_cloud,
    "secure_email": _secure_email,
    "intune": _intune,
    "splunk": _splunk,
})


def normalize(integration: str, result: InvestigationResult, nctx: NormalizeContext) -> list[AnyRecord]:
    """Records for one integration's result.

    An integration without a dedicated normalizer (for example a simulated adapter posing as an
    integration the catalog does not route investigations to) still gets the typed path and
    generic records. ``ValueError`` when ``result.integration`` differs from ``integration`` or a
    typed record from a simulated adapter is malformed.
    """
    if result.integration != integration:
        raise ValueError(f"result of {result.integration!r} passed as {integration!r}")
    normalizer = NORMALIZERS.get(integration)
    if normalizer is None:
        return _normalize_findings(result, nctx, _generic_only)
    return normalizer(result, nctx)
