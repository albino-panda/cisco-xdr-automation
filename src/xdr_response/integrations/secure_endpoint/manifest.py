"""Capability manifest for Cisco Secure Endpoint (docs/integrations.md section 2.2)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

SRC_ISOLATION = ("https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/"
                 "222226-automate-start-stop-isolation-on-multipl.html")
SRC_WHATS_NEW = "https://developer.cisco.com/docs/secure-endpoint/whats-new/"

REQUIRED_SECRETS: Mapping[str, str] = {"client_id": "SE_CLIENT_ID", "api_key": "SE_API_KEY"}
CONFIG_OPTIONS: Mapping[str, str] = {}
HEALTH_PROBE = "list_computers"

MANIFEST = CapabilityManifest(
    integration="secure_endpoint",
    display_name="Cisco Secure Endpoint",
    supported_actions=frozenset({A.ISOLATE_ENDPOINT, A.RELEASE_ENDPOINT}),
    verifiable_actions=frozenset(),  # isolation GET is UNVERIFIED -> UNABLE_TO_VERIFY
    read_actions=frozenset({A.ENRICH_ENDPOINT, A.INVESTIGATE_ENDPOINT}),
    enrichment_types=frozenset({ObservableType.ENDPOINT_ID}),
    operations=(
        OperationSpec(name="list_computers", kind=_R, status=_V, method="GET", path="/v1/computers",
                      source=SRC_ISOLATION),
        OperationSpec(name="get_computer", kind=_R, status=_V, method="GET",
                      path="/v1/computers/{connector_guid}", source=SRC_WHATS_NEW,
                      action_types=(A.ENRICH_ENDPOINT,)),
        OperationSpec(name="get_trajectory", kind=_R, status=_V, method="GET",
                      path="/v1/computers/{connector_guid}/trajectory", source=SRC_WHATS_NEW,
                      action_types=(A.INVESTIGATE_ENDPOINT,)),
        OperationSpec(name="list_audit_logs", kind=_R, status=_V, method="GET", path="/v1/audit_logs",
                      source=SRC_WHATS_NEW),
        OperationSpec(name="isolate", kind=_SC, status=_V, method="PUT",
                      path="/v1/computers/{connector_guid}/isolation", source=SRC_ISOLATION,
                      action_types=(A.ISOLATE_ENDPOINT,)),
        OperationSpec(name="stop_isolation", kind=_SC, status=_V, method="DELETE",
                      path="/v1/computers/{connector_guid}/isolation", source=SRC_ISOLATION,
                      action_types=(A.RELEASE_ENDPOINT,)),
        OperationSpec(name="get_isolation", kind=_VF, status=_U, method="GET",
                      path="/v1/computers/{connector_guid}/isolation"),
        OperationSpec(name="list_events", kind=_R, status=_U, method="GET", path="/v1/events"),
        OperationSpec(name="block_hash", kind=_SC, status=_U, method="POST",
                      path="/v1/file_lists/{guid}/files/{sha256}", action_types=(A.BLOCK_HASH,)),
        OperationSpec(name="unblock_hash", kind=_SC, status=_U, method="DELETE",
                      path="/v1/file_lists/{guid}/files/{sha256}", action_types=(A.UNBLOCK_HASH,)),
        OperationSpec(name="get_file_list_entry", kind=_VF, status=_U, method="GET",
                      path="/v1/file_lists/{guid}/files/{sha256}"),
        # Not in the section 2.2 table: no endpoint was read for these remediation types.
        OperationSpec(name="terminate_process", kind=_SC, status=_U, action_types=(A.TERMINATE_PROCESS,)),
        OperationSpec(name="quarantine_file", kind=_SC, status=_U, action_types=(A.QUARANTINE_FILE,)),
        OperationSpec(name="restore_file", kind=_SC, status=_U, action_types=(A.RESTORE_FILE,)),
    ),
    escalation_hint="Secure Endpoint administrator",
    rate_limit_note="Hourly quota reported in X-RateLimit-* headers; 429 when exceeded.",
)
