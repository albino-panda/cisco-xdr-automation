"""Normalizer for ``intune`` investigation results (architecture 14.1.4).

Source: Get managedDevice, ``GET /deviceManagement/managedDevices/{managedDeviceId}``
(https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0).
Mapped managedDevice properties: ``id``, ``deviceName``, ``operatingSystem``, ``userPrincipalName``,
``complianceState``, ``lastSyncDateTime``, ``wiFiMacAddress``, ``ethernetMacAddress``.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from xdr_response.atomics.investigation.normalize.typed import (
    _datetime,
    _normalize_findings,
    _reference,
    _text,
)
from xdr_response.atomics.records import AnyRecord, EndpointRecord
from xdr_response.models import InvestigationResult

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.investigation.normalize import NormalizeContext

__all__: list[str] = []


def _managed_device(finding: Mapping[str, Any], nctx: "NormalizeContext",
                    result: InvestigationResult) -> list[AnyRecord]:
    """One ``EndpointRecord`` for a managedDevice (``ValueError`` when the finding is not one)."""
    device_id = _text(finding, "id")
    hostname = _text(finding, "deviceName")
    if device_id is None or hostname is None:
        raise ValueError("not an Intune managedDevice")
    user = _text(finding, "userPrincipalName")
    macs = tuple(m for m in (_text(finding, "wiFiMacAddress"), _text(finding, "ethernetMacAddress")) if m)
    synced = _datetime(finding.get("lastSyncDateTime"))
    return [EndpointRecord(
        integration=result.integration, atomic=nctx.atomic, subject=nctx.subject,
        observed_at=synced, reference=_reference(device_id),
        hostname=hostname, intune_device_id=device_id, os=_text(finding, "operatingSystem"),
        mac_addresses=tuple(dict.fromkeys(m.lower() for m in macs)), users=(user,) if user else (),
        health_state=_text(finding, "complianceState"), last_seen=synced,
    )]


def _normalize(result: InvestigationResult, nctx: "NormalizeContext") -> list[AnyRecord]:
    """Managed devices as endpoint records; anything else generic."""
    return _normalize_findings(result, nctx, _managed_device)
