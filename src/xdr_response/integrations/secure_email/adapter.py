"""Cisco Secure Email Threat Defense adapter (docs/integrations.md section 2.3).

Auth (VERIFIED, https://developer.cisco.com/docs/message-search-api/authentication/): OAuth2 token
from ``POST /v1/oauth/token`` with HTTP Basic ``client_id:client_secret``, plus an ``x-api-key``
header on **all** calls (the token call included).

Containment is ``POST /v1/messages/move``: ``quarantine`` (quarantine_email), ``trash``
(delete_email) and ``inbox`` (release_email). ``verdict`` is mandatory; the release uses the verdict
recorded at containment time (``rollback_params``). Verification reads ``/v1/messages/status``.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, ClassVar

from xdr_response.errors import ApiError, CapabilityNotSupportedError, InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import CompositeAuth, VendorAdapter, body_dict, body_list
from xdr_response.integrations.secure_email import builders
from xdr_response.integrations.secure_email.manifest import MANIFEST, MAX_IDS_PER_CALL, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    InvestigationQuery,
    InvestigationResult,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["SecureEmailAdapter"]

_FOLDER_FOR: Mapping[ActionType, str] = {
    ActionType.QUARANTINE_EMAIL: "quarantine",
    ActionType.DELETE_EMAIL: "trash",
    ActionType.RELEASE_EMAIL: "inbox",
}


def _walk(value: Any) -> Iterator[tuple[str, Any]]:
    """Every (key, value) pair in a nested JSON structure."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _failed_ids(body: Any) -> list[str]:
    """IDs whose ``queueSuccess`` is false in a move response."""
    failed: list[str] = []
    for item in _walk_dicts(body):
        if item.get("queueSuccess") is False:
            failed.append(str(item.get("id") or item.get("messageId") or "unknown"))
    return failed


def _walk_dicts(value: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for item in value.values():
            yield from _walk_dicts(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_dicts(item)


def _folders_seen(body: Any) -> set[str]:
    """Folder words found under keys that name an action or folder (the field names are not documented)."""
    seen: set[str] = set()
    for key, value in _walk(body):
        lowered = key.lower()
        if isinstance(value, str) and ("folder" in lowered or "action" in lowered):
            for folder in builders.FOLDERS:
                if folder in value.lower():
                    seen.add(folder)
    return seen


class SecureEmailAdapter(VendorAdapter):
    """Secure Email Threat Defense: message search, move (quarantine / trash / inbox), status."""

    name: ClassVar[str] = "secure_email"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.base_url_for("us")
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """OAuth2 (HTTP Basic) plus the mandatory ``x-api-key`` header on every call."""
        from xdr_response.integrations.auth import ApiKeyHeader, OAuth2ClientCredentials

        api_key = self.secret("api_key")
        oauth = OAuth2ClientCredentials(
            token_url=builders.token_url(self.base_url), client_id=self.secret("client_id"),
            client_secret=self.secret("client_secret"), basic_auth=True, transport=self.transport,
            clock=self.clock, extra_headers={"x-api-key": api_key.reveal()},
        )
        return CompositeAuth(oauth, ApiKeyHeader("x-api-key", api_key))

    # ---------------------------------------------------------------- reads --
    def search_messages(self, body: Mapping[str, Any]) -> list[Any]:
        """Message search; ``body`` must carry the mandatory timestamp range."""
        result = body_dict(self._send(builders.search_messages(body)).body)
        return body_list(result) or body_list(result, "messages")

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """Message search with the body in ``query.options["search"]``."""
        search = query.options.get("search")
        if query.action_type not in (ActionType.INVESTIGATE_EMAIL, ActionType.SEARCH_EMAIL_CAMPAIGN) \
                or not isinstance(search, Mapping):
            raise CapabilityNotSupportedError(
                "secure_email investigation needs investigate_email/search_email_campaign and "
                "options.search (the search body with its mandatory timestamp range)", integration=self.name)
        result = self._send(builders.search_messages(search))
        body = body_dict(result.body)
        messages = [m for m in (body_list(body) or body_list(body, "messages")) if isinstance(m, dict)]
        messages = messages[: query.limit]
        evidence = [self._evidence(f"{len(messages)} message(s) matched the Secure Email search")] \
            if messages else []
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=tuple(messages), evidence=tuple(evidence),
                                   api_calls=self._calls([result]))

    def message_status(self, ids: list[str]) -> Any:
        """Up to five most recent action and verdict statuses per message."""
        return self._send(builders.message_status(ids)).body

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Read ``/v1/messages/status`` and look for the expected folder.

        VERIFIED when only the expected folder appears, NOT_VERIFIED when another folder appears
        without it, UNABLE_TO_VERIFY when the answer is empty or ambiguous (the status ordering is
        not documented).
        """
        folder = _FOLDER_FOR.get(request.action_type)
        if folder is None:
            return super().verify(request, outcome)
        result = self._send(builders.message_status(self._ids(request)))
        seen = _folders_seen(result.body)
        if seen == {folder}:
            status, detail = VerificationStatus.VERIFIED, f"status shows {folder}"
        elif seen and folder not in seen:
            status, detail = VerificationStatus.NOT_VERIFIED, f"status shows {sorted(seen)}, not {folder}"
        else:
            status, detail = VerificationStatus.UNABLE_TO_VERIFY, f"status ambiguous or empty: {sorted(seen)}"
        return self._verification(request, status, method="message_status", details=detail, results=[result])

    # --------------------------------------------------------------- writes --
    def _ids(self, request: ActionRequest) -> list[str]:
        """Exactly the approved message. ``params.message_ids`` may only repeat the target.

        Params are untrusted proposal data; blast-radius caps and the decision card count targets,
        so params can never substitute or add messages.
        """
        ids = request.params.get("message_ids") or [request.target]
        if not isinstance(ids, list) or not ids or len(ids) > MAX_IDS_PER_CALL:
            raise InvalidTargetError(f"secure_email: params.message_ids must hold 1 to {MAX_IDS_PER_CALL} ids",
                                     integration=self.name)
        if {str(i) for i in ids} != {request.target}:
            raise InvalidTargetError(
                "secure_email: params.message_ids must name only the approved message "
                f"{request.target}", integration=self.name)
        return [request.target]

    def _move(self, request: ActionRequest, *, reversible: bool) -> ActionOutcome:
        folder = _FOLDER_FOR[request.action_type]
        ids, verdict = self._ids(request), str(self._param(request, "verdict"))
        result = self._send(builders.move_messages(ids, folder, verdict))
        failed = _failed_ids(result.body)
        if failed:
            raise ApiError(f"secure_email move to {folder} not queued for {len(failed)} message(s): "
                           f"{', '.join(failed[:10])}", integration=self.name, http_status=result.status_code)
        rollback = {"message_ids": ids, "verdict": verdict} if reversible else None
        return self._outcome(ActionResultStatus.SUCCESS, results=[result], rollback=rollback,
                             message=f"{len(ids)} message(s) queued for move to {folder}")

    @state_changing
    def quarantine_email(self, request: ActionRequest) -> ActionOutcome:
        """Move the approved message(s) to quarantine."""
        return self._move(request, reversible=True)

    @state_changing
    def release_email(self, request: ActionRequest) -> ActionOutcome:
        """Move the message(s) back to the inbox with the verdict recorded at containment."""
        return self._move(request, reversible=False)

    @state_changing
    def delete_email(self, request: ActionRequest) -> ActionOutcome:
        """Move the approved message(s) to trash (never a hard delete)."""
        return self._move(request, reversible=False)
