"""Capability manifest for Cisco Secure Cloud Analytics (docs/integrations.md section 2.5).

No official API reference page could be fetched, so every operation is UNVERIFIED. Its alerts are
read as Cisco XDR incidents and sightings instead.
"""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import EndpointStatus, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_U, _NA = EndpointStatus.UNVERIFIED, EndpointStatus.NOT_APPLICABLE
_R = OperationKind.READ

#: Unused until an endpoint is VERIFIED (architecture 13.11).
REQUIRED_SECRETS: Mapping[str, str] = {"api_key": "SCA_API_KEY"}
CONFIG_OPTIONS: Mapping[str, str] = {}
HEALTH_PROBE = None

MANIFEST = CapabilityManifest(
    integration="secure_cloud_analytics",
    display_name="Cisco Secure Cloud Analytics",
    operations=(
        OperationSpec(name="list_alerts", kind=_R, status=_U),
        OperationSpec(name="list_observations", kind=_R, status=_U),
        OperationSpec(name="get_device", kind=_R, status=_U),
        OperationSpec(name="state_changing_ops", kind=OperationKind.STATE_CHANGING, status=_NA),
    ),
    rate_limit_note="Unknown: no official API reference was read.",
)
