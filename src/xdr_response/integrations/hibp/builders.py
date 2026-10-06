"""Pure request builders for Have I Been Pwned v3 (docs/integrations.md section 2.15).

Base ``https://haveibeenpwned.com/api/v3``; ``hibp-api-key`` header (auth provider) and a mandatory
user-agent (default headers). Source: https://haveibeenpwned.com/API/v3
"""
from __future__ import annotations

from xdr_response.integrations._adapter_support import ApiRequest, segment

__all__ = ["BASE_URL", "breached_account", "paste_account", "all_breaches"]

BASE_URL = "https://haveibeenpwned.com/api/v3"


def breached_account(account: str, *, truncate: bool = False) -> ApiRequest:
    """``GET /breachedaccount/{account}`` (404 = no breach). ``truncateResponse=false`` for full detail."""
    params = None if truncate else {"truncateResponse": "false"}
    return ApiRequest(operation="breached_account", method="GET", path=f"breachedaccount/{segment(account)}",
                      params=params, expected=(200, 404))


def paste_account(account: str) -> ApiRequest:
    """``GET /pasteaccount/{account}`` (404 = no paste)."""
    return ApiRequest(operation="paste_account", method="GET", path=f"pasteaccount/{segment(account)}",
                      expected=(200, 404))


def all_breaches() -> ApiRequest:
    """``GET /breaches`` (no key needed)."""
    return ApiRequest(operation="all_breaches", method="GET", path="breaches")
