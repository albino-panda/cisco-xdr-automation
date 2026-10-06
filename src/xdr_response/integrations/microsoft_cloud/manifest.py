"""Capability manifest for Microsoft Defender XDR / Graph Security reads (docs/integrations.md section 2.12)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations._graph import GRAPH_SECRET_NAMES, token_operation
from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE", "INVESTIGATIONS"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _SC = OperationKind.READ, OperationKind.STATE_CHANGING

_GRAPH = "https://learn.microsoft.com/en-us/graph/api/"
SRC_ALERTS = _GRAPH + "security-list-alerts_v2?view=graph-rest-1.0"
SRC_HUNTING = _GRAPH + "security-security-runhuntingquery?view=graph-rest-1.0"

INVESTIGATIONS: tuple[A, ...] = (
    A.INVESTIGATE_USER, A.INVESTIGATE_ENDPOINT, A.INVESTIGATE_IP, A.INVESTIGATE_DOMAIN, A.INVESTIGATE_HASH,
    A.INVESTIGATE_EMAIL, A.INVESTIGATE_PROCESS, A.INVESTIGATE_NETWORK_CONNECTION, A.SEARCH_HASH_ENTERPRISE,
    A.SEARCH_DOMAIN_ENTERPRISE, A.SEARCH_IP_ENTERPRISE, A.SEARCH_USER_ACTIVITY, A.SEARCH_RELATED_ENDPOINTS,
    A.SEARCH_RELATED_USERS,
)

REQUIRED_SECRETS: Mapping[str, str] = GRAPH_SECRET_NAMES
CONFIG_OPTIONS: Mapping[str, str] = {
    "oauth_scope": "Graph client-credentials scope (required; the string is UNVERIFIED in section 2.8)",
}
HEALTH_PROBE = "list_alerts"

MANIFEST = CapabilityManifest(
    integration="microsoft_cloud",
    display_name="Microsoft Defender XDR (Graph Security)",
    read_actions=frozenset(INVESTIGATIONS),
    operations=(
        token_operation(),
        OperationSpec(name="list_alerts", kind=_R, status=_V, method="GET",
                      path="https://graph.microsoft.com/v1.0/security/alerts_v2", source=SRC_ALERTS,
                      action_types=INVESTIGATIONS),
        OperationSpec(name="run_hunting_query", kind=_R, status=_V, method="POST",
                      path="https://graph.microsoft.com/v1.0/security/runHuntingQuery", source=SRC_HUNTING,
                      action_types=INVESTIGATIONS),
        OperationSpec(name="list_incidents", kind=_R, status=_U, method="GET", path="/security/incidents"),
        OperationSpec(name="cloud_resource_actions", kind=_SC, status=_U),
    ),
    escalation_hint="Microsoft 365 Defender administrator",
    rate_limit_note="Graph throttling: 429 with Retry-After.",
)
