"""Pure request builders for Defender for Office 365 remediation (docs/integrations.md section 2.10).

``POST https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate`` (202).
Source: https://learn.microsoft.com/en-us/graph/api/security-analyzedemail-remediate?view=graph-rest-beta
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from xdr_response.integrations._adapter_support import ApiRequest
from xdr_response.models import OperationKind

__all__ = ["REMEDIATE_PATH", "ACTIONS", "CONTAINMENT_ACTIONS", "remediate"]

REMEDIATE_PATH = "beta/security/collaboration/analyzedEmails/remediate"
#: Documented ``action`` values. ``hardDelete`` exists but is never proposed (it cannot be rolled back).
ACTIONS = ("moveToJunk", "moveToInbox", "hardDelete", "softDelete", "moveToDeletedItems", "moveToQuarantine")
#: Actions this framework sends.
CONTAINMENT_ACTIONS = ("moveToQuarantine", "softDelete", "moveToDeletedItems", "moveToInbox")


def remediate(action: str, emails: Sequence[Mapping[str, str]], *, display_name: str, description: str,
              severity: str = "medium", remediate_senders_copy: bool = False) -> ApiRequest:
    """Remediation request. ``moveToQuarantine`` needs ``Prefer: include-unknown-enum-members``.

    ``emails`` items carry ``networkMessageId`` and ``recipientEmailAddress``.
    """
    if action not in CONTAINMENT_ACTIONS:
        raise ValueError(f"action must be one of {CONTAINMENT_ACTIONS} (hardDelete is never used)")
    if not emails:
        raise ValueError("at least one analyzed email is required")
    headers = {"Prefer": "include-unknown-enum-members"} if action == "moveToQuarantine" else None
    return ApiRequest(
        operation="rollback_to_inbox" if action == "moveToInbox" else "remediate",
        method="POST", path=REMEDIATE_PATH, kind=OperationKind.STATE_CHANGING, headers=headers,
        json={"displayName": display_name, "description": description, "severity": severity, "action": action,
              "remediateSendersCopy": remediate_senders_copy,
              "analyzedEmails": [{"networkMessageId": e["networkMessageId"],
                                  "recipientEmailAddress": e["recipientEmailAddress"]} for e in emails]},
        expected=(200, 202),
    )
