"""Private formatting helpers shared by the reporting renderers.

Every value that reaches analyst output passes through :func:`clean`: secrets are redacted with the
central :class:`~xdr_response.logs.redaction.Redactor` and control characters are collapsed, so a
vendor string can never inject extra lines (for example a fake ``[APPROVE ALL]`` row) into a card.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from xdr_response.logs.redaction import Redactor, get_redactor

__all__ = [
    "OutputFormat",
    "clean",
    "count_phrase",
    "fmt_dt",
    "dump_json",
    "md_code",
    "md_text",
    "pad_columns",
    "resolve_redactor",
    "short_hash",
]

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\u0085  ]+")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~])")


class OutputFormat(StrEnum):
    """Analyst output formats."""

    TEXT = "text"
    MARKDOWN = "markdown"
    JSON = "json"


def resolve_redactor(redactor: Redactor | None) -> Redactor:
    """The given redactor or the process-wide default."""
    return redactor if redactor is not None else get_redactor()


def clean(value: object, redactor: Redactor) -> str:
    """Redacted, single-line text with collapsed whitespace."""
    text = redactor.redact_text("" if value is None else str(value))
    return " ".join(_CONTROL_CHARS.sub(" ", text).split())


def fmt_dt(value: datetime | None) -> str | None:
    """UTC timestamp with second precision, e.g. ``2026-01-15T12:00:00Z``."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def count_phrase(count: int, singular: str, plural: str | None = None) -> str:
    """``"1 endpoint"``, ``"2 endpoints"``."""
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def short_hash(value: str, length: int = 12) -> str:
    """Leading characters of a hex digest (for display only)."""
    return value[:length]


def pad_columns(rows: Sequence[Sequence[str]], *, gap: int = 2) -> list[str]:
    """Left-align columns; the last column is never padded and empty trailing cells are dropped."""
    if not rows:
        return []
    columns = max(len(r) for r in rows)
    widths = [max((len(r[i]) for r in rows if i < len(r)), default=0) for i in range(columns)]
    lines = []
    for row in rows:
        cells = [cell.ljust(widths[i]) if i < len(row) - 1 else cell for i, cell in enumerate(row)]
        lines.append((" " * gap).join(cells).rstrip())
    return lines


def md_text(value: str) -> str:
    """Escape Markdown control characters in already-cleaned text."""
    return _MD_SPECIAL.sub(r"\\\1", value)


def md_code(value: str) -> str:
    """Inline code span (backticks inside the value are replaced)."""
    return "`" + value.replace("`", "'") + "`"


def dump_json(data: Mapping[str, Any]) -> str:
    """Stable, human-readable JSON (sorted keys, 2-space indent, UTF-8 text)."""
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
