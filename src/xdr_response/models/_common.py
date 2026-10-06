"""ErrorInfo and ApiCallSummary live here to avoid a cycle between action.py and verification.py.

Both are re-exported by :mod:`xdr_response.models.action` (their contract home).
"""
from __future__ import annotations

import json
from typing import Any

from pydantic import Field, field_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.enums import ErrorCode, OperationKind

__all__ = ["ErrorInfo", "ApiCallSummary", "SUMMARY_MAX_BYTES"]

SUMMARY_MAX_BYTES = 4096


class ErrorInfo(FrozenModel):
    code: ErrorCode
    message: str  # redacted by the producer
    integration: str | None = None
    http_status: int | None = None
    retryable: bool = False


def _cap(value: Any) -> Any:
    if value is None:
        return {}
    try:
        encoded = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return {"_unserializable": True}
    if len(encoded.encode("utf-8")) <= SUMMARY_MAX_BYTES:
        return value
    preview = encoded.encode("utf-8")[: SUMMARY_MAX_BYTES - 256].decode("utf-8", errors="ignore")
    return {"_truncated": True, "_original_bytes": len(encoded.encode("utf-8")), "preview": preview}


class ApiCallSummary(FrozenModel):
    integration: str
    operation: str
    method: str
    url: str  # redacted
    kind: OperationKind
    status_code: int | None
    duration_ms: int = Field(ge=0)
    attempt: int = Field(ge=1)
    request_summary: JsonDict = {}  # redacted, size-capped (4 KiB)
    response_summary: JsonDict = {}  # redacted, size-capped (4 KiB)
    error: ErrorInfo | None = None

    @field_validator("request_summary", "response_summary", mode="before")
    @classmethod
    def _size_cap(cls, value: Any) -> Any:
        return _cap(value)
