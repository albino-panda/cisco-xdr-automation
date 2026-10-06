"""Structured JSON logging with mandatory redaction."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import IO, Any

from xdr_response.logs.redaction import get_redactor

__all__ = ["RedactingFilter", "JsonFormatter", "configure_logging", "get_logger", "ROOT_LOGGER_NAME",
           "protect_third_party_loggers", "THIRD_PARTY_LOGGERS"]

ROOT_LOGGER_NAME = "xdr_response"

_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()
) | {"message", "asctime", "taskName"}


#: Third-party loggers that log request URLs (httpx logs ``HTTP Request: GET <full url>`` at INFO).
THIRD_PARTY_LOGGERS = ("httpx", "httpcore")


def _format_message(record: logging.LogRecord, r: Any) -> str:
    """``msg % args`` with every arg redacted first; never raises (args are appended on mismatch)."""
    msg = record.msg if isinstance(record.msg, str) else str(r.redact(record.msg))
    args = record.args
    if not args:
        return msg
    if isinstance(args, dict):
        safe_args: Any = r.redact(args)
    else:
        safe_args = tuple(r.redact(a) for a in args)
    try:
        return msg % safe_args
    except Exception:  # noqa: BLE001 - a format/args mismatch must never drop or leak the record
        return f"{msg} {safe_args!r}"


class RedactingFilter(logging.Filter):
    """Redacts msg, args and extra fields of every record with :func:`get_redactor`.

    The message is formatted FIRST (``msg % args``, args redacted individually) and the resulting
    text is redacted as a whole; ``args`` are then cleared. Redacting the template on its own
    would treat a placeholder as a secret value (``password=%s`` -> ``password=[REDACTED]``),
    break the formatting, and make ``logging`` print the raw args to stderr.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        r = get_redactor()
        if getattr(record, "_xdr_redacted", False):
            return True
        try:
            record.msg = r.redact_text(_format_message(record, r))
            record.args = None
            for key, value in list(vars(record).items()):
                if key in _STANDARD_ATTRS or key.startswith("_"):
                    continue
                if r.is_sensitive_key(key):
                    setattr(record, key, "[REDACTED]")
                else:
                    setattr(record, key, r.redact(value))
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = r.redact_text(record.exc_text)
                record.exc_info = None
        except Exception:  # pragma: no cover - never let logging break the caller
            record.msg = "[log record dropped: redaction failed]"
            record.args = None
        record._xdr_redacted = True
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: timestamp, level, logger, message, extra fields, exception."""

    def format(self, record: logging.LogRecord) -> str:
        r = get_redactor()
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": r.redact_text(record.getMessage()),
        }
        for key, value in vars(record).items():
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            payload[key] = "[REDACTED]" if r.is_sensitive_key(key) else r.redact(value)
        if record.exc_info:
            payload["exception"] = r.redact_text(self.formatException(record.exc_info))
        elif record.exc_text:
            payload["exception"] = r.redact_text(record.exc_text)
        return json.dumps(payload, default=lambda o: r.redact_text(str(o)), ensure_ascii=False)


class _TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return get_redactor().redact_text(super().format(record))


_HANDLER_FLAG = "_xdr_response_handler"


def protect_third_party_loggers() -> None:
    """Attach :class:`RedactingFilter` to the httpx / httpcore loggers (idempotent).

    Their records (full request URLs, possibly with a query-string API key) reach whatever handler
    the host application configured on the root logger; the filter redacts them at the source.
    """
    for name in THIRD_PARTY_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(RedactingFilter())


def configure_logging(level: str = "INFO", *, json_format: bool = True, stream: IO[str] | None = None) -> None:
    """Configure the ``xdr_response`` logger tree (idempotent: replaces our previous handler).

    Also protects the httpx / httpcore loggers (:func:`protect_third_party_loggers`).
    """
    protect_third_party_loggers()
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    for h in list(logger.handlers):
        if getattr(h, _HANDLER_FLAG, False):
            logger.removeHandler(h)
    handler = logging.StreamHandler(stream or sys.stderr)
    setattr(handler, _HANDLER_FLAG, True)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(
        JsonFormatter() if json_format else _TextFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(level.upper() if isinstance(level, str) else level)
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Logger named ``xdr_response.<name>`` with a :class:`RedactingFilter` attached."""
    full = name if name == ROOT_LOGGER_NAME or name.startswith(ROOT_LOGGER_NAME + ".") else f"{ROOT_LOGGER_NAME}.{name}"
    logger = logging.getLogger(full)
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger
