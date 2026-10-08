"""Normalizer for ``defender_endpoint`` investigation results (architecture 14.1.4).

Source: Get machine, ``GET /api/machines/{id}``
(https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-by-id). Mapped Machine
properties: ``id``, ``computerDnsName``, ``osPlatform``, ``lastIpAddress``,
``lastExternalIpAddress``, ``healthStatus``, ``riskScore``, ``rbacGroupName``, ``machineTags``,
``lastSeen``. The isolation state is not a Machine property, so it stays ``unknown``.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from xdr_response.atomics.investigation.normalize.typed import (
    _datetime,
    _ips,
    _normalize_findings,
    _reference,
    _strings,
    _text,
)
from xdr_response.atomics.records import AnyRecord, EndpointRecord, Level
from xdr_response.models import InvestigationResult, ObservableType

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.investigation.normalize import NormalizeContext

__all__: list[str] = []

#: Machine ``riskScore`` values (None, Informational, Low, Medium, High) to record levels.
_RISK_LEVELS: Mapping[str, Level] = {"none": "none", "informational": "low", "low": "low",
                                     "medium": "medium", "high": "high"}


def _machine(finding: Mapping[str, Any], nctx: "NormalizeContext",
             result: InvestigationResult) -> list[AnyRecord]:
    """One ``EndpointRecord`` for a Machine entity (``ValueError`` when the finding is not one)."""
    machine_id = _text(finding, "id")
    if machine_id is None:
        raise ValueError("not a Defender for Endpoint machine entity")
    hostname = _text(finding, "computerDnsName")
    if hostname is None and nctx.subject.type is ObservableType.HOSTNAME:
        hostname = nctx.subject.value
    if hostname is None:
        raise ValueError("machine entity without computerDnsName")
    group = _text(finding, "rbacGroupName")
    risk = (_text(finding, "riskScore") or "").lower()
    return [EndpointRecord(
        integration=result.integration, atomic=nctx.atomic, subject=nctx.subject,
        observed_at=_datetime(finding.get("lastSeen")), reference=_reference(machine_id),
        hostname=hostname, mde_machine_id=machine_id, os=_text(finding, "osPlatform"),
        ip_addresses=_ips((finding.get("lastIpAddress"), finding.get("lastExternalIpAddress"))),
        groups=(group,) if group else (), tags=_strings(finding.get("machineTags")),
        health_state=_text(finding, "healthStatus"), risk_level=_RISK_LEVELS.get(risk, "unknown"),
        last_seen=_datetime(finding.get("lastSeen")),
    )]


def _normalize(result: InvestigationResult, nctx: "NormalizeContext") -> list[AnyRecord]:
    """Machine entities as endpoint records; anything else generic."""
    return _normalize_findings(result, nctx, _machine)
