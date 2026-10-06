"""Capability manifest for Microsoft Defender for Office 365 (docs/integrations.md section 2.10)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations._graph import GRAPH_SECRET_NAMES, token_operation
from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

SRC_REMEDIATE = "https://learn.microsoft.com/en-us/graph/api/security-analyzedemail-remediate?view=graph-rest-beta"
_PATH = "https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate"

REQUIRED_SECRETS: Mapping[str, str] = GRAPH_SECRET_NAMES
CONFIG_OPTIONS: Mapping[str, str] = {
    "oauth_scope": "Graph client-credentials scope (required; the string is UNVERIFIED in section 2.8)",
}
#: No VERIFIED read endpoint exists for this integration.
HEALTH_PROBE = None

MANIFEST = CapabilityManifest(
    integration="defender_o365",
    display_name="Microsoft Defender for Office 365",
    supported_actions=frozenset({A.QUARANTINE_EMAIL, A.DELETE_EMAIL, A.RELEASE_EMAIL}),
    verifiable_actions=frozenset(),  # the 202 Location is a portal URL: UNABLE_TO_VERIFY
    operations=(
        token_operation(),
        OperationSpec(name="remediate", kind=_SC, status=_V, method="POST", path=_PATH, source=SRC_REMEDIATE,
                      action_types=(A.QUARANTINE_EMAIL, A.DELETE_EMAIL)),
        OperationSpec(name="rollback_to_inbox", kind=_SC, status=_V, method="POST", path=_PATH,
                      source=SRC_REMEDIATE, action_types=(A.RELEASE_EMAIL,)),
        OperationSpec(name="list_analyzed_emails", kind=_R, status=_U),
        OperationSpec(name="quarantine_release", kind=_SC, status=_U),
        OperationSpec(name="verify_remediation", kind=_VF, status=_U),
    ),
    escalation_hint="Microsoft 365 security administrator",
    rate_limit_note="Graph throttling: 429 with Retry-After. Application permission and global cloud only.",
)
