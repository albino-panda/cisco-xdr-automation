"""Pure request builders for the Meraki Dashboard API v1 (docs/integrations.md section 2.7).

Base ``https://api.meraki.com/api/v1`` (VERIFIED, https://developer.cisco.com/meraki/api-v1/authorization/).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.models import OperationKind

__all__ = ["BASE_URL", "DEVICE_POLICIES", "DEFAULT_RULE_COMMENT", "search_clients", "get_client_policy",
           "update_client_policy", "get_l3_rules", "update_l3_rules", "deny_rule"]

BASE_URL = "https://api.meraki.com/api/v1"
#: ``devicePolicy`` values documented for the client policy PUT.
DEVICE_POLICIES = ("Whitelisted", "Blocked", "Normal", "Group policy")
#: The implicit last rule returned by the GET; it is never sent back in a PUT.
DEFAULT_RULE_COMMENT = "Default rule"


def search_clients(organization_id: str, mac: str) -> ApiRequest:
    """``GET /organizations/{organizationId}/clients/search?mac=..``."""
    return ApiRequest(operation="search_clients", method="GET",
                      path=f"organizations/{segment(organization_id)}/clients/search", params={"mac": mac})


def _policy_path(network_id: str, client_id: str) -> str:
    return f"networks/{segment(network_id)}/clients/{segment(client_id)}/policy"


def get_client_policy(network_id: str, client_id: str) -> ApiRequest:
    """``GET /networks/{networkId}/clients/{clientId}/policy`` (VERIFY)."""
    return ApiRequest(operation="get_client_policy", method="GET", path=_policy_path(network_id, client_id),
                      kind=OperationKind.VERIFY)


def update_client_policy(network_id: str, client_id: str, device_policy: str,
                         group_policy_id: str | None = None) -> ApiRequest:
    """``PUT /networks/{networkId}/clients/{clientId}/policy`` (STATE_CHANGING)."""
    if device_policy not in DEVICE_POLICIES:
        raise ValueError(f"devicePolicy must be one of {DEVICE_POLICIES}")
    body: dict[str, Any] = {"devicePolicy": device_policy}
    if device_policy == "Group policy":
        if not group_policy_id:
            raise ValueError("'Group policy' needs groupPolicyId")
        body["groupPolicyId"] = group_policy_id
    return ApiRequest(operation="update_client_policy", method="PUT", path=_policy_path(network_id, client_id),
                      kind=OperationKind.STATE_CHANGING, json=body)


def _l3_path(network_id: str) -> str:
    return f"networks/{segment(network_id)}/appliance/firewall/l3FirewallRules"


def get_l3_rules(network_id: str) -> ApiRequest:
    """``GET /networks/{networkId}/appliance/firewall/l3FirewallRules`` (VERIFY)."""
    return ApiRequest(operation="get_l3_rules", method="GET", path=_l3_path(network_id), kind=OperationKind.VERIFY)


def update_l3_rules(network_id: str, rules: Sequence[Mapping[str, Any]]) -> ApiRequest:
    """``PUT .../l3FirewallRules`` with the **complete ordered rule list** (replaces the set)."""
    return ApiRequest(operation="update_l3_rules", method="PUT", path=_l3_path(network_id),
                      kind=OperationKind.STATE_CHANGING, json={"rules": [dict(r) for r in rules]})


def deny_rule(dest_cidr: str, comment: str) -> dict[str, str]:
    """An outbound deny rule for one destination, tagged with ``comment``."""
    return {"comment": comment, "policy": "deny", "protocol": "any", "srcPort": "Any", "srcCidr": "Any",
            "destPort": "Any", "destCidr": dest_cidr}
