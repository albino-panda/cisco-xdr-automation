"""Recommended escalation owner for actions that need human attention.

Deterministic lookup, in this order:

1. ``ActionResult.recommended_escalation`` already set by the runner (the adapter manifest's
   ``escalation_hint``) wins.
2. The error code: platform faults (approval, audit, internal, missing adapter) go to the
   automation platform owner; an invalid target goes back to the SOC analyst.
3. A caller-supplied ``hints`` mapping (integration name -> owner), for example built from the
   manifests' ``escalation_hint`` or site configuration.
4. The integration's default administrator (:data:`DEFAULT_INTEGRATION_OWNERS`).

Example: HTTP 403 on ``quarantine_email`` through ``defender_o365`` -> "Microsoft 365 administrator".
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from xdr_response.models import ActionResult, ErrorCode, SkipReason

__all__ = [
    "DEFAULT_INTEGRATION_OWNERS",
    "SOC_ANALYST",
    "PLATFORM_OWNER",
    "integration_owner",
    "recommend_escalation",
]

SOC_ANALYST = "SOC analyst on duty"
PLATFORM_OWNER = "Security automation platform owner"

DEFAULT_INTEGRATION_OWNERS: Mapping[str, str] = MappingProxyType({
    "cisco_xdr": "Cisco XDR administrator",
    "secure_endpoint": "Cisco Secure Endpoint administrator",
    "secure_email": "Cisco Secure Email administrator",
    "secure_malware_analytics": "Cisco Secure Malware Analytics administrator",
    "secure_cloud_analytics": "Cisco Secure Cloud Analytics administrator",
    "umbrella": "Cisco Umbrella administrator",
    "meraki": "Meraki network administrator",
    "entra": "Microsoft 365 administrator",
    "defender_endpoint": "Microsoft Defender for Endpoint administrator",
    "defender_o365": "Microsoft 365 administrator",
    "intune": "Microsoft Intune administrator",
    "microsoft_cloud": "Microsoft 365 administrator",
    "virustotal": PLATFORM_OWNER,
    "alienvault_otx": PLATFORM_OWNER,
    "hibp": PLATFORM_OWNER,
    "splunk": "Splunk administrator",
})

#: Error codes that point at the automation platform itself rather than the vendor tenant.
_PLATFORM_CODES = frozenset({
    ErrorCode.APPROVAL_DENIED,
    ErrorCode.AUDIT_UNAVAILABLE,
    ErrorCode.INTERNAL,
    ErrorCode.NO_CAPABLE_ADAPTER,
    ErrorCode.DRY_RUN,
})

_PLATFORM_SKIPS = frozenset({SkipReason.NO_CAPABLE_ADAPTER})


def integration_owner(integration: str | None, hints: Mapping[str, str] | None = None) -> str:
    """Administrator responsible for ``integration`` (hints first, then defaults)."""
    if not integration:
        return PLATFORM_OWNER
    if hints and hints.get(integration):
        return hints[integration]
    return DEFAULT_INTEGRATION_OWNERS.get(integration, PLATFORM_OWNER)


def recommend_escalation(result: ActionResult, *, integration: str | None = None,
                         hints: Mapping[str, str] | None = None) -> str:
    """Who should handle an action that requires attention.

    ``integration`` overrides ``result.integration`` (for example the verifying integration when a
    native XDR action could not be verified).
    """
    if result.recommended_escalation:
        return result.recommended_escalation
    if result.skip_reason in _PLATFORM_SKIPS:
        return PLATFORM_OWNER
    code = result.error.code if result.error else None
    if code in _PLATFORM_CODES:
        return PLATFORM_OWNER
    if code is ErrorCode.INVALID_TARGET:
        return SOC_ANALYST
    name = integration or result.integration or (result.error.integration if result.error else None)
    return integration_owner(name, hints)
