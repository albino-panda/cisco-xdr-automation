"""Pure request builders for Cisco Secure Email Threat Defense (docs/integrations.md section 2.3).

Regional bases (VERIFIED, https://developer.cisco.com/docs/message-search-api/getting-started/):
``api.{us|de|au|in|ae}.etd.cisco.com``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from xdr_response.integrations._adapter_support import ApiRequest
from xdr_response.integrations.secure_email.manifest import MAX_IDS_PER_CALL
from xdr_response.models import OperationKind

__all__ = ["REGIONS", "FOLDERS", "base_url_for", "token_url", "search_messages", "move_messages",
           "message_status"]

REGIONS = ("us", "de", "au", "in", "ae")
#: ``folder`` values documented for ``/v1/messages/move``.
FOLDERS = ("quarantine", "trash", "inbox")


def base_url_for(region: str) -> str:
    """The documented regional base URL (ValueError for an unknown region)."""
    if region not in REGIONS:
        raise ValueError(f"unknown Secure Email region {region!r}; documented: {REGIONS}")
    return f"https://api.{region}.etd.cisco.com"


def token_url(base_url: str) -> str:
    """``POST {base}/v1/oauth/token``. Source: message-search-api/authentication."""
    return f"{base_url.rstrip('/')}/v1/oauth/token"


def search_messages(body: Mapping[str, Any]) -> ApiRequest:
    """``POST /v1/messages/search`` (a timestamp range is mandatory; the caller supplies the body).

    Source: https://developer.cisco.com/docs/message-search-api/message-search-api/
    """
    return ApiRequest(operation="search_messages", method="POST", path="v1/messages/search", json=dict(body))


def move_messages(ids: Sequence[str], folder: str, verdict: str) -> ApiRequest:
    """``POST /v1/messages/move`` with ``{"ids", "folder", "verdict"}`` (STATE_CHANGING).

    ``folder`` ``inbox`` is the release path (operation ``release_to_inbox``).
    Source: https://developer.cisco.com/docs/message-search-api/remediation-and-reclassification-api/
    """
    if folder not in FOLDERS:
        raise ValueError(f"folder must be one of {FOLDERS}")
    if not ids or len(ids) > MAX_IDS_PER_CALL:
        raise ValueError(f"between 1 and {MAX_IDS_PER_CALL} message ids are required")
    if not verdict:
        raise ValueError("verdict is mandatory")
    operation = "release_to_inbox" if folder == "inbox" else "move_messages"
    return ApiRequest(operation=operation, method="POST", path="v1/messages/move",
                      kind=OperationKind.STATE_CHANGING,
                      json={"ids": list(ids), "folder": folder, "verdict": verdict})


def message_status(ids: Sequence[str]) -> ApiRequest:
    """``POST /v1/messages/status`` (VERIFY; up to 5 most recent statuses per message).

    Source: https://developer.cisco.com/docs/message-search-api/status-api/
    """
    return ApiRequest(operation="message_status", method="POST", path="v1/messages/status",
                      kind=OperationKind.VERIFY, json={"ids": list(ids)})
