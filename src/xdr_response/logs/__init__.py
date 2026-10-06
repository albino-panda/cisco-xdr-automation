"""Structured logging and the central redaction function (used by logs and audit)."""
from __future__ import annotations

from xdr_response.logs.redaction import (
    REDACTED,
    SENSITIVE_KEY_PATTERN,
    Redactor,
    get_redactor,
    normalize_key,
)
from xdr_response.logs.setup import JsonFormatter, RedactingFilter, configure_logging, get_logger

__all__ = [
    "REDACTED",
    "SENSITIVE_KEY_PATTERN",
    "Redactor",
    "get_redactor",
    "normalize_key",
    "RedactingFilter",
    "JsonFormatter",
    "configure_logging",
    "get_logger",
]
