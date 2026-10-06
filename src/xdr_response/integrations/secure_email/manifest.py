"""Capability manifest for Cisco Secure Email Threat Defense (docs/integrations.md section 2.3)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE", "MAX_IDS_PER_CALL"]

_V = EndpointStatus.VERIFIED
_R, _VF, _SC = OperationKind.READ, OperationKind.VERIFY, OperationKind.STATE_CHANGING

SRC_AUTH = "https://developer.cisco.com/docs/message-search-api/authentication/"
SRC_SEARCH = "https://developer.cisco.com/docs/message-search-api/message-search-api/"
SRC_MOVE = "https://developer.cisco.com/docs/message-search-api/remediation-and-reclassification-api/"
SRC_STATUS = "https://developer.cisco.com/docs/message-search-api/status-api/"

#: Remediation accepts at most 100 message IDs per call (section 2.3).
MAX_IDS_PER_CALL = 100

REQUIRED_SECRETS: Mapping[str, str] = {
    "client_id": "ETD_CLIENT_ID", "client_secret": "ETD_CLIENT_SECRET", "api_key": "ETD_API_KEY",
}
CONFIG_OPTIONS: Mapping[str, str] = {}
#: No side-effect-free probe: search needs a time range and status needs message IDs.
HEALTH_PROBE = None

MANIFEST = CapabilityManifest(
    integration="secure_email",
    display_name="Cisco Secure Email Threat Defense",
    supported_actions=frozenset({A.QUARANTINE_EMAIL, A.RELEASE_EMAIL, A.DELETE_EMAIL}),
    verifiable_actions=frozenset({A.QUARANTINE_EMAIL, A.RELEASE_EMAIL, A.DELETE_EMAIL}),
    read_actions=frozenset({A.INVESTIGATE_EMAIL, A.SEARCH_EMAIL_CAMPAIGN}),
    operations=(
        OperationSpec(name="token", kind=_R, status=_V, method="POST",
                      path="https://api.{us|de|au|in|ae}.etd.cisco.com/v1/oauth/token", source=SRC_AUTH),
        OperationSpec(name="search_messages", kind=_R, status=_V, method="POST", path="/v1/messages/search",
                      source=SRC_SEARCH, action_types=(A.INVESTIGATE_EMAIL, A.SEARCH_EMAIL_CAMPAIGN)),
        OperationSpec(name="move_messages", kind=_SC, status=_V, method="POST", path="/v1/messages/move",
                      source=SRC_MOVE, action_types=(A.QUARANTINE_EMAIL, A.DELETE_EMAIL)),
        OperationSpec(name="release_to_inbox", kind=_SC, status=_V, method="POST", path="/v1/messages/move",
                      source=SRC_MOVE, action_types=(A.RELEASE_EMAIL,)),
        OperationSpec(name="message_status", kind=_VF, status=_V, method="POST", path="/v1/messages/status",
                      source=SRC_STATUS),
    ),
    escalation_hint="Microsoft 365 administrator (403 means the tenant lacks write permission)",
    rate_limit_note="Not documented; search pages hold at most 100 messages, remediation 100 IDs per call.",
)
