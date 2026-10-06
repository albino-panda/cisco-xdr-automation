"""Pure request builders for OTX indicator details (docs/integrations.md section 2.14).

``GET /api/v1/indicators/{type}/{value}/{section}`` on ``https://otx.alienvault.com``.
Source: https://otx.alienvault.com/assets/static/external_api.html
"""
from __future__ import annotations

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.integrations.alienvault_otx.manifest import SECTIONS

__all__ = ["BASE_URL", "API_KEY_HEADER", "indicator"]

BASE_URL = "https://otx.alienvault.com"
#: VERIFIED from the official SDK source (OTXv2.py).
API_KEY_HEADER = "X-OTX-API-KEY"


def indicator(kind: str, value: str, section: str = "general") -> ApiRequest:
    """Indicator details for one documented ``kind`` and ``section``."""
    if kind not in SECTIONS:
        raise ValueError(f"unknown OTX indicator type {kind!r}; documented: {sorted(SECTIONS)}")
    if section not in SECTIONS[kind]:
        raise ValueError(f"section {section!r} is not documented for {kind}: {SECTIONS[kind]}")
    safe = ":/" if kind == "url" else ":"
    return ApiRequest(operation=f"indicators_{kind.lower()}", method="GET",
                      path=f"api/v1/indicators/{kind}/{segment(value, safe=safe)}/{section}")
