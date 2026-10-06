"""Capability manifest for Cisco Umbrella / Secure Access (docs/integrations.md section 2.6)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE", "MAX_DESTINATIONS_PER_CALL"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

_DOCS = "https://developer.cisco.com/docs/cloud-security/"
SRC_AUTH = _DOCS + "umbrella-api-getting-started/"
SRC_CATEGORIZATION = (_DOCS + "umbrella-api-api-reference-investigate-investigate-api-domain-status-and-"
                      "categorization-get-domain-status-and-categorization/")
SRC_LISTS = _DOCS + "umbrella-api-reference-destination-lists-overview/"
SRC_ADD = (_DOCS + "umbrella-api-api-reference-policies-destination-lists-api-destinations-add-"
           "destinations-to-destination-list/")
SRC_REMOVE = (_DOCS + "umbrella-api-api-reference-policies-destination-lists-api-destinations-delete-"
              "destinations-from-destination-list/")

#: Add and remove both accept at most 500 entries per call.
MAX_DESTINATIONS_PER_CALL = 500

REQUIRED_SECRETS: Mapping[str, str] = {"api_key": "UMBRELLA_API_KEY", "api_secret": "UMBRELLA_API_SECRET"}
CONFIG_OPTIONS: Mapping[str, str] = {
    "destination_list_id": "Default block destination list when params.destination_list_id is absent",
}
HEALTH_PROBE = "list_destination_lists"

MANIFEST = CapabilityManifest(
    integration="umbrella",
    display_name="Cisco Umbrella",
    supported_actions=frozenset({A.BLOCK_DOMAIN, A.BLOCK_URL, A.UNBLOCK_DOMAIN, A.UNBLOCK_URL}),
    verifiable_actions=frozenset({A.BLOCK_DOMAIN, A.BLOCK_URL, A.UNBLOCK_DOMAIN, A.UNBLOCK_URL}),
    read_actions=frozenset({A.ENRICH_DOMAIN}),
    enrichment_types=frozenset({ObservableType.DOMAIN}),
    operations=(
        OperationSpec(name="token", kind=_R, status=_V, method="POST",
                      path="https://api.umbrella.com/auth/v2/token", source=SRC_AUTH),
        OperationSpec(name="domain_categorization", kind=_R, status=_V, method="GET",
                      path="https://api.umbrella.com/investigate/v2/domains/categorization/{domain}",
                      source=SRC_CATEGORIZATION, action_types=(A.ENRICH_DOMAIN,)),
        OperationSpec(name="security_scores", kind=_R, status=_U, method="GET",
                      path="/investigate/v2/security/name/{domain}"),
        OperationSpec(name="risk_score", kind=_R, status=_U, method="GET",
                      path="/investigate/v2/domains/risk-score/{domain}"),
        OperationSpec(name="list_destination_lists", kind=_R, status=_V, method="GET",
                      path="https://api.umbrella.com/policies/v2/destinationlists", source=SRC_LISTS),
        OperationSpec(name="list_destinations", kind=_VF, status=_V, method="GET",
                      path="/policies/v2/destinationlists/{destinationListId}/destinations", source=SRC_LISTS),
        OperationSpec(name="add_destinations", kind=_SC, status=_V, method="POST",
                      path="/policies/v2/destinationlists/{destinationListId}/destinations", source=SRC_ADD,
                      action_types=(A.BLOCK_DOMAIN, A.BLOCK_URL)),
        OperationSpec(name="remove_destinations", kind=_SC, status=_V, method="DELETE",
                      path="/policies/v2/destinationlists/{destinationListId}/destinations/remove",
                      source=SRC_REMOVE, action_types=(A.UNBLOCK_DOMAIN, A.UNBLOCK_URL)),
        # UNVERIFIED / CONFLICT: overview says block lists do not take IPv4; use XDR native or Meraki.
        OperationSpec(name="block_ip", kind=_SC, status=_U, method="POST",
                      path="/policies/v2/destinationlists/{destinationListId}/destinations",
                      action_types=(A.BLOCK_IP,)),
        OperationSpec(name="unblock_ip", kind=_SC, status=_U, method="DELETE",
                      path="/policies/v2/destinationlists/{destinationListId}/destinations/remove",
                      action_types=(A.UNBLOCK_IP,)),
    ),
    escalation_hint="Umbrella / Secure Access policy administrator",
    rate_limit_note="Token 20/min per key; policies 2000/min and 6000/h; Investigate 3 req/s; on 429 wait 1 s.",
)
