"""Pure request builders for Graph Security reads (docs/integrations.md section 2.12)."""
from __future__ import annotations

from datetime import datetime

from xdr_response.integrations._adapter_support import ApiRequest
from xdr_response.models import format_datetime

__all__ = ["list_alerts", "run_hunting_query"]


def list_alerts(*, since: datetime | None = None) -> ApiRequest:
    """``GET /v1.0/security/alerts_v2`` with an optional ``createdDateTime`` filter. Source: security-list-alerts_v2."""
    params: dict[str, str] = {}
    if since is not None:
        params["$filter"] = f"createdDateTime ge {format_datetime(since)}"
    return ApiRequest(operation="list_alerts", method="GET", path="v1.0/security/alerts_v2", params=params or None)


def run_hunting_query(query: str, timespan: str | None = None) -> ApiRequest:
    """``POST /v1.0/security/runHuntingQuery`` with ``{"Query", "Timespan"}`` (default lookback 30 days).

    Source: https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0
    """
    if not query.strip():
        raise ValueError("a KQL query is required")
    body = {"Query": query}
    if timespan:
        body["Timespan"] = timespan
    return ApiRequest(operation="run_hunting_query", method="POST", path="v1.0/security/runHuntingQuery", json=body)
