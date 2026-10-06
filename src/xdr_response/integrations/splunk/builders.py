"""Pure request builders for Splunk REST search and HEC (docs/integrations.md section 2.16)."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.models import OperationKind

__all__ = ["normalize_spl", "quoted_term_search", "create_search_job", "get_search_results", "hec_event"]


def normalize_spl(spl: str) -> str:
    """REST searches must start with ``search`` or a generating command (``|``)."""
    text = spl.strip()
    if not text:
        raise ValueError("an SPL query is required")
    return text if text.startswith(("search ", "|")) else f"search {text}"


def quoted_term_search(value: str) -> str:
    """``search "<value>"`` with quotes and backslashes escaped."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'search "{escaped}"'


def create_search_job(spl: str, earliest_time: str, latest_time: str) -> ApiRequest:
    """``POST /services/search/jobs`` (form body) returning an ``sid``. Source: creating-searches-using-the-rest-api."""
    return ApiRequest(operation="create_search_job", method="POST", path="services/search/jobs",
                      data={"search": normalize_spl(spl), "earliest_time": earliest_time,
                            "latest_time": latest_time, "output_mode": "json"})


def get_search_results(sid: str) -> ApiRequest:
    """``GET /services/search/jobs/{sid}/results?output_mode=json`` (204 while the job runs)."""
    return ApiRequest(operation="get_search_results", method="GET",
                      path=f"services/search/jobs/{segment(sid)}/results", params={"output_mode": "json"},
                      expected=(200, 204))


def hec_event(event: Mapping[str, Any], sourcetype: str) -> ApiRequest:
    """``POST {hec}/services/collector/event`` (BOOKKEEPING; the event must already be redacted)."""
    return ApiRequest(operation="forward_audit", method="POST", path="services/collector/event",
                      kind=OperationKind.BOOKKEEPING, json={"event": dict(event), "sourcetype": sourcetype})
