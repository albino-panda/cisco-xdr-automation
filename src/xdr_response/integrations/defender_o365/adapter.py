"""Microsoft Defender for Office 365 adapter (docs/integrations.md section 2.10).

Containment uses ``analyzedEmails/remediate`` (beta, application permission, global cloud only):
``moveToQuarantine`` (quarantine_email), ``softDelete`` or ``moveToDeletedItems`` (delete_email;
never ``hardDelete``) and ``moveToInbox`` (release_email, the documented false-positive path). The
target is the ``networkMessageId``; ``params.recipient`` is the recipient address. The 202
``Location`` is a portal URL, so verification is UNABLE_TO_VERIFY.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import VendorAdapter
from xdr_response.integrations._graph import GRAPH_BASE_URL, graph_scope, microsoft_auth
from xdr_response.integrations.defender_o365 import builders
from xdr_response.integrations.defender_o365.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import ActionOutcome, ActionRequest, ActionResultStatus, VerificationResult, VerificationStatus

__all__ = ["DefenderO365Adapter"]

_DELETE_ACTIONS = ("softDelete", "moveToDeletedItems")


class DefenderO365Adapter(VendorAdapter):
    """Defender for Office 365: email remediation through Microsoft Graph."""

    name: ClassVar[str] = "defender_o365"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = GRAPH_BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """Client credentials at the identity platform with ``options.oauth_scope``."""
        return microsoft_auth(self, scope=graph_scope(self))

    def list_analyzed_emails(self, **criteria: Any) -> NoReturn:
        """UNVERIFIED."""
        self._unverified("list_analyzed_emails")

    def release_from_quarantine(self, message_id: str) -> NoReturn:
        """Quarantine release API: UNVERIFIED (release uses ``moveToInbox`` instead)."""
        self._unverified("quarantine_release")

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """UNABLE_TO_VERIFY: the remediation result is only visible in the Defender action center."""
        return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none",
                                  details="defender_o365 remediation has no VERIFIED read-back")

    def _remediate(self, request: ActionRequest, action: str, *, reversible: bool) -> ActionOutcome:
        recipient = str(self._param(request, "recipient"))
        req = builders.remediate(
            action, [{"networkMessageId": request.target, "recipientEmailAddress": recipient}],
            display_name=f"xdr-response {request.idempotency_key}",
            description=f"Approved {request.action_type.value} for incident {request.incident_id}",
            severity=str(request.params.get("severity") or "medium"),
        )
        result = self._send(req)
        location = result.headers.get("location") or result.headers.get("Location")
        rollback = {"recipient": recipient} if reversible else None
        return self._outcome(ActionResultStatus.SUCCESS, results=[result], rollback=rollback,
                             external_ref=location or None, message=f"{action} accepted for {request.target}")

    @state_changing
    def quarantine_email(self, request: ActionRequest) -> ActionOutcome:
        """``moveToQuarantine`` (with ``Prefer: include-unknown-enum-members``)."""
        return self._remediate(request, "moveToQuarantine", reversible=True)

    @state_changing
    def delete_email(self, request: ActionRequest) -> ActionOutcome:
        """``softDelete`` (default) or ``moveToDeletedItems``; never ``hardDelete``."""
        action = str(request.params.get("delete_action") or "softDelete")
        if action not in _DELETE_ACTIONS:
            raise InvalidTargetError(f"defender_o365: delete_action must be one of {_DELETE_ACTIONS}",
                                     integration=self.name)
        return self._remediate(request, action, reversible=False)

    @state_changing
    def release_email(self, request: ActionRequest) -> ActionOutcome:
        """``moveToInbox`` (the documented false-positive path)."""
        return self._remediate(request, "moveToInbox", reversible=False)
