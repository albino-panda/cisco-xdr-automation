"""Capability manifest for Microsoft Defender for Endpoint (docs/integrations.md section 2.9)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations._graph import token_operation
from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE", "INDICATOR_BLOCKS",
           "INDICATOR_UNBLOCKS"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

_DOCS = "https://learn.microsoft.com/en-us/defender-endpoint/api/"
SRC_MACHINE = _DOCS + "get-machine-by-id"
SRC_ISOLATE = _DOCS + "isolate-machine"
SRC_UNISOLATE = _DOCS + "unisolate-machine"
SRC_ACTION = _DOCS + "get-machineaction-object"
SRC_ACTIONS = _DOCS + "get-machineactions-collection"
SRC_POST_INDICATOR = _DOCS + "post-ti-indicator"
SRC_DELETE_INDICATOR = _DOCS + "delete-ti-indicator-by-id"

INDICATOR_BLOCKS: tuple[A, ...] = (A.BLOCK_HASH, A.BLOCK_IP, A.BLOCK_DOMAIN, A.BLOCK_URL)
INDICATOR_UNBLOCKS: tuple[A, ...] = (A.UNBLOCK_HASH, A.UNBLOCK_IP, A.UNBLOCK_DOMAIN, A.UNBLOCK_URL)

REQUIRED_SECRETS: Mapping[str, str] = {
    "tenant_id": "ENTRA_TENANT_ID", "client_id": "MDE_CLIENT_ID", "client_secret": "MDE_CLIENT_SECRET",
}
CONFIG_OPTIONS: Mapping[str, str] = {
    "allow_vendor_expiry": "Send params.expiration_time on indicators (default false: an automatic expiry "
                           "is a release without a human release approval)",
}
HEALTH_PROBE = "list_machine_actions"

MANIFEST = CapabilityManifest(
    integration="defender_endpoint",
    display_name="Microsoft Defender for Endpoint",
    supported_actions=frozenset((A.ISOLATE_ENDPOINT, A.RELEASE_ENDPOINT) + INDICATOR_BLOCKS + INDICATOR_UNBLOCKS),
    verifiable_actions=frozenset({A.ISOLATE_ENDPOINT, A.RELEASE_ENDPOINT}),
    read_actions=frozenset({A.ENRICH_ENDPOINT, A.INVESTIGATE_ENDPOINT}),
    enrichment_types=frozenset({ObservableType.ENDPOINT_ID, ObservableType.HOSTNAME}),
    operations=(
        token_operation(),
        OperationSpec(name="get_machine", kind=_R, status=_V, method="GET", path="/api/machines/{id}",
                      source=SRC_MACHINE, action_types=(A.ENRICH_ENDPOINT, A.INVESTIGATE_ENDPOINT)),
        OperationSpec(name="isolate", kind=_SC, status=_V, method="POST", path="/api/machines/{id}/isolate",
                      source=SRC_ISOLATE, action_types=(A.ISOLATE_ENDPOINT,)),
        OperationSpec(name="unisolate", kind=_SC, status=_V, method="POST", path="/api/machines/{id}/unisolate",
                      source=SRC_UNISOLATE, action_types=(A.RELEASE_ENDPOINT,)),
        OperationSpec(name="get_machine_action", kind=_VF, status=_V, method="GET",
                      path="/api/machineactions/{id}", source=SRC_ACTION),
        OperationSpec(name="list_machine_actions", kind=_VF, status=_V, method="GET", path="/api/machineactions",
                      source=SRC_ACTIONS),
        OperationSpec(name="submit_indicator", kind=_SC, status=_V, method="POST", path="/api/indicators",
                      source=SRC_POST_INDICATOR, action_types=INDICATOR_BLOCKS),
        OperationSpec(name="delete_indicator", kind=_SC, status=_V, method="DELETE", path="/api/indicators/{id}",
                      source=SRC_DELETE_INDICATOR, action_types=INDICATOR_UNBLOCKS),
        OperationSpec(name="list_indicators", kind=_VF, status=_U, method="GET", path="/api/indicators"),
        # "Restrict app execution, stop and quarantine file, AV scan": not read (one row per action type).
        OperationSpec(name="terminate_process", kind=_SC, status=_U, action_types=(A.TERMINATE_PROCESS,)),
        OperationSpec(name="quarantine_file", kind=_SC, status=_U, action_types=(A.QUARANTINE_FILE,)),
        OperationSpec(name="restore_file", kind=_SC, status=_U, action_types=(A.RESTORE_FILE,)),
        OperationSpec(name="remove_application", kind=_SC, status=_U, action_types=(A.REMOVE_APPLICATION,)),
    ),
    escalation_hint="Defender for Endpoint security administrator",
    rate_limit_note="100 calls/min and 1,500 calls/h per API; at most 15,000 active indicators.",
)
