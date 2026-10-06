"""Capability manifest for the Cisco Meraki Dashboard API v1 (docs/integrations.md section 2.7)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V = EndpointStatus.VERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

_DOCS = "https://developer.cisco.com/meraki/api-v1/"
SRC_AUTH = _DOCS + "authorization/"
SRC_SEARCH = _DOCS + "get-organization-clients-search/"
SRC_GET_POLICY = _DOCS + "get-network-client-policy/"
SRC_PUT_POLICY = _DOCS + "update-network-client-policy/"
SRC_GET_L3 = _DOCS + "get-network-appliance-firewall-l-3-firewall-rules/"
SRC_PUT_L3 = _DOCS + "update-network-appliance-firewall-l-3-firewall-rules/"

REQUIRED_SECRETS: Mapping[str, str] = {"api_key": "MERAKI_API_KEY"}
CONFIG_OPTIONS: Mapping[str, str] = {
    "organization_id": "Meraki organization used by client search",
    "health_network_id": "Network whose L3 rules are read by health_check (optional)",
}
HEALTH_PROBE = "get_l3_rules"  # only when options.health_network_id is set

MANIFEST = CapabilityManifest(
    integration="meraki",
    display_name="Cisco Meraki",
    supported_actions=frozenset({A.BLOCK_NETWORK_CLIENT, A.RESTORE_NETWORK_CLIENT, A.BLOCK_IP, A.UNBLOCK_IP}),
    verifiable_actions=frozenset({A.BLOCK_NETWORK_CLIENT, A.RESTORE_NETWORK_CLIENT, A.BLOCK_IP, A.UNBLOCK_IP}),
    operations=(
        OperationSpec(name="search_clients", kind=_R, status=_V, method="GET",
                      path="/organizations/{organizationId}/clients/search", source=SRC_SEARCH),
        OperationSpec(name="get_client_policy", kind=_VF, status=_V, method="GET",
                      path="/networks/{networkId}/clients/{clientId}/policy", source=SRC_GET_POLICY),
        OperationSpec(name="update_client_policy", kind=_SC, status=_V, method="PUT",
                      path="/networks/{networkId}/clients/{clientId}/policy", source=SRC_PUT_POLICY,
                      action_types=(A.BLOCK_NETWORK_CLIENT, A.RESTORE_NETWORK_CLIENT)),
        OperationSpec(name="get_l3_rules", kind=_VF, status=_V, method="GET",
                      path="/networks/{networkId}/appliance/firewall/l3FirewallRules", source=SRC_GET_L3),
        OperationSpec(name="update_l3_rules", kind=_SC, status=_V, method="PUT",
                      path="/networks/{networkId}/appliance/firewall/l3FirewallRules", source=SRC_PUT_L3,
                      action_types=(A.BLOCK_IP, A.UNBLOCK_IP)),
    ),
    escalation_hint="Meraki network administrator",
    rate_limit_note="10 req/s per organization (burst +10 in the first second); 429 with Retry-After.",
)
