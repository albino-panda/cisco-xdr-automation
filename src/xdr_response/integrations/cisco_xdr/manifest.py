"""Capability manifest for the Cisco XDR platform (docs/integrations.md section 2.1).

One :class:`OperationSpec` per row of the section 2.1 table; status and source are copied from the
document. Native response actions (section 1.4) are served by ``trigger_response_action``.
"""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE",
           "NATIVE_CONTAINMENT", "NATIVE_RESTORATION"]

_V, _U, _NA = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED, EndpointStatus.NOT_APPLICABLE
_R, _VF = OperationKind.READ, OperationKind.VERIFY
_SC, _BK = OperationKind.STATE_CHANGING, OperationKind.BOOKKEEPING

SRC_AUTH = "https://developer.cisco.com/docs/cisco-xdr/authentication/"
SRC_ENRICH = "https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/"
SRC_RESPONSE = "https://developer.cisco.com/docs/cisco-xdr/response-api-guide/"
SRC_TRIGGER = "https://developer.cisco.com/docs/cisco-xdr/trigger-an-action/"
SRC_INCIDENT = "https://developer.cisco.com/docs/cisco-xdr/incident-management-api-guide/"
SRC_FULL = ("https://developer.cisco.com/docs/cisco-xdr/"
            "get-a-full-summary-of-the-incident-everything-seen-in-xdr/")
SRC_STATUS = ("https://developer.cisco.com/docs/cisco-xdr/"
              "global-intelligence-api-incident-update-an-incident-status/")
SRC_AUTOMATION = "https://developer.cisco.com/docs/cisco-xdr/automation-api-guide/"

#: Containment / remediation types with a native XDR workflow (section 1.4).
NATIVE_CONTAINMENT: tuple[A, ...] = (
    A.ISOLATE_ENDPOINT, A.BLOCK_DOMAIN, A.BLOCK_URL, A.BLOCK_IP, A.BLOCK_HASH, A.DISABLE_USER,
    A.QUARANTINE_EMAIL, A.DELETE_EMAIL,
)
#: Restoration types with a native XDR workflow (section 1.4).
NATIVE_RESTORATION: tuple[A, ...] = (
    A.RELEASE_ENDPOINT, A.UNBLOCK_DOMAIN, A.UNBLOCK_URL, A.UNBLOCK_IP, A.UNBLOCK_HASH, A.ENABLE_USER,
    A.RELEASE_EMAIL,
)

#: Logical secret name -> default secret NAME (architecture 13.11).
REQUIRED_SECRETS: Mapping[str, str] = {"client_id": "XDR_CLIENT_ID", "client_secret": "XDR_CLIENT_SECRET"}

#: ``IntegrationConfig.options`` keys this adapter reads.
CONFIG_OPTIONS: Mapping[str, str] = {
    "automation_base_url": "Automation API host (default: derived from region us/eu/apjc)",
}

#: Operation used by ``health_check``.
HEALTH_PROBE = "list_workflows"

_ENRICH = (A.ENRICH_IP, A.ENRICH_DOMAIN, A.ENRICH_URL, A.ENRICH_HASH, A.ENRICH_EMAIL_ADDRESS,
           A.ENRICH_USER, A.ENRICH_ENDPOINT)
_INVESTIGATE = (A.INVESTIGATE_USER, A.INVESTIGATE_ENDPOINT, A.INVESTIGATE_IP, A.INVESTIGATE_DOMAIN,
                A.INVESTIGATE_HASH, A.INVESTIGATE_EMAIL, A.SEARCH_HASH_ENTERPRISE,
                A.SEARCH_DOMAIN_ENTERPRISE, A.SEARCH_IP_ENTERPRISE)

MANIFEST = CapabilityManifest(
    integration="cisco_xdr",
    display_name="Cisco XDR",
    native_xdr=True,
    supported_actions=frozenset(NATIVE_CONTAINMENT + NATIVE_RESTORATION),
    verifiable_actions=frozenset(),  # respond/trigger returns only success/failure (section 2.1)
    read_actions=frozenset(_ENRICH + _INVESTIGATE + (A.UPDATE_INCIDENT_STATUS,)),
    enrichment_types=frozenset({
        ObservableType.IP, ObservableType.IPV6, ObservableType.DOMAIN, ObservableType.URL,
        ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5, ObservableType.EMAIL_ADDRESS,
        ObservableType.USER, ObservableType.HOSTNAME, ObservableType.MAC_ADDRESS,
        ObservableType.EMAIL_MESSAGE_ID, ObservableType.FILE_PATH,
    }),
    operations=(
        OperationSpec(name="token", kind=_R, status=_V, method="POST",
                      path="https://visibility.amp.cisco.com/iroh/oauth2/token", source=SRC_AUTH),
        OperationSpec(name="deliberate_observables", kind=_R, status=_V, method="POST",
                      path="/iroh/iroh-enrich/deliberate/observables", source=SRC_ENRICH,
                      action_types=_ENRICH),
        OperationSpec(name="observe_observables", kind=_R, status=_V, method="POST",
                      path="/iroh/iroh-enrich/observe/observables", source=SRC_ENRICH,
                      action_types=_INVESTIGATE),
        OperationSpec(name="refer_observables", kind=_R, status=_V, method="POST",
                      path="/iroh/iroh-enrich/refer/observables", source=SRC_ENRICH),
        OperationSpec(name="list_response_actions", kind=_R, status=_V, method="POST",
                      path="/iroh/iroh-response/respond/observables", source=SRC_RESPONSE),
        OperationSpec(name="trigger_response_action", kind=_SC, status=_V, method="POST",
                      path="/iroh/iroh-response/respond/trigger/{module-instance-id}/{action-id}",
                      source=SRC_TRIGGER, action_types=NATIVE_CONTAINMENT + NATIVE_RESTORATION),
        OperationSpec(name="get_incident_summary", kind=_R, status=_V, method="GET",
                      path="https://visibility.amp.cisco.com/iroh/private-intel/incident/{incident_id}/summary",
                      source=SRC_INCIDENT),
        OperationSpec(name="get_incident_full", kind=_R, status=_V, method="GET",
                      path="https://conure.us.security.cisco.com/incidents/{incident-id}", source=SRC_FULL),
        # VERIFIED but not needed by the framework: no adapter method sends it.
        OperationSpec(name="create_incident_bundle", kind=_SC, status=_V, method="POST",
                      path="/iroh/private-intel/bundle/import", source=SRC_INCIDENT),
        OperationSpec(name="update_incident_status", kind=_BK, status=_V, method="POST",
                      path="https://intel.amp.cisco.com/ctia/incident/{id}/status", source=SRC_STATUS,
                      action_types=(A.UPDATE_INCIDENT_STATUS,)),
        OperationSpec(name="update_incident_status_private_intel", kind=_BK, status=_U, method="POST",
                      path="https://private.intel.amp.cisco.com/ctia/incident/{id}/status"),
        OperationSpec(name="add_incident_note", kind=_BK, status=_U, action_types=(A.ADD_INCIDENT_NOTE,)),
        OperationSpec(name="search_incidents", kind=_R, status=_U),
        OperationSpec(name="inspect", kind=_R, status=_U),
        OperationSpec(name="list_workflows", kind=_R, status=_V, method="GET",
                      path="https://automate.us.security.cisco.com/api/v1/workflows", source=SRC_AUTOMATION),
        OperationSpec(name="run_workflow", kind=_SC, status=_U),
        OperationSpec(name="approval_tasks", kind=_R, status=_U),
        OperationSpec(name="verify_native_action", kind=_VF, status=_NA),
    ),
    escalation_hint="Cisco XDR administrator",
    rate_limit_note="Not documented: honor 429 and Retry-After, otherwise exponential backoff.",
)
