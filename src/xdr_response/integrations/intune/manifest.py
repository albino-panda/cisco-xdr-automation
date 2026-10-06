"""Capability manifest for Microsoft Intune through Graph (docs/integrations.md section 2.11)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations._graph import GRAPH_SECRET_NAMES, token_operation
from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _SC = OperationKind.READ, OperationKind.STATE_CHANGING

_GRAPH = "https://learn.microsoft.com/en-us/graph/api/"
SRC_GET = _GRAPH + "intune-devices-manageddevice-get?view=graph-rest-1.0"
SRC_LOCK = _GRAPH + "intune-devices-manageddevice-remotelock?view=graph-rest-1.0"

REQUIRED_SECRETS: Mapping[str, str] = GRAPH_SECRET_NAMES
CONFIG_OPTIONS: Mapping[str, str] = {
    "oauth_scope": "Graph client-credentials scope (required; the string is UNVERIFIED in section 2.8)",
}
#: No VERIFIED list endpoint: the device GET needs an ID.
HEALTH_PROBE = None

MANIFEST = CapabilityManifest(
    integration="intune",
    display_name="Microsoft Intune",
    supported_actions=frozenset({A.LOCK_DEVICE}),
    verifiable_actions=frozenset(),  # remoteLock actionName not read -> UNABLE_TO_VERIFY
    read_actions=frozenset({A.ENRICH_ENDPOINT, A.INVESTIGATE_ENDPOINT}),
    enrichment_types=frozenset({ObservableType.ENDPOINT_ID}),
    operations=(
        token_operation(),
        OperationSpec(name="get_managed_device", kind=_R, status=_V, method="GET",
                      path="https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{managedDeviceId}",
                      source=SRC_GET, action_types=(A.ENRICH_ENDPOINT, A.INVESTIGATE_ENDPOINT)),
        OperationSpec(name="remote_lock", kind=_SC, status=_V, method="POST",
                      path="https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{managedDeviceId}"
                           "/remoteLock", source=SRC_LOCK, action_types=(A.LOCK_DEVICE,)),
        OperationSpec(name="retire_wipe", kind=_SC, status=_U),
        OperationSpec(name="sync_scan", kind=_SC, status=_U),
        # Not in the section 2.11 table: no endpoint was read for app removal.
        OperationSpec(name="remove_application", kind=_SC, status=_U, action_types=(A.REMOVE_APPLICATION,)),
    ),
    escalation_hint="Intune administrator",
    rate_limit_note="Graph throttling: 429 with Retry-After. Requires an active Intune licence.",
)
