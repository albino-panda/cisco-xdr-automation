"""Typed records from simulated adapters, generic records, and the helpers every normalizer shares.

A finding that carries :data:`TYPED_RECORD_KEY` is a typed record written by a lab scenario. It is
accepted only from a simulated adapter (``NormalizeContext.typed_allowed``); from a real adapter the
key is ignored and the finding becomes a :class:`GenericRecord`, so no vendor response can ever
smuggle a typed record in. The record body never carries ``record_id``, ``integration``, ``atomic``
or ``subject``: those are filled here. An optional ``"xdr_integration"`` key restricts the finding to
one simulated adapter (the simulated environment serves the same findings to every adapter).

Vendor normalizers hand each non-typed finding to a *finding mapper*. A mapper raises ``ValueError``
(or ``KeyError`` / ``TypeError``) for a finding it does not understand; the finding then becomes one
``GenericRecord(name=f"{integration}:{atomic}")``, so raw findings stay citable but never score.
Normalizers never call adapters and never read secrets.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from xdr_response.atomics.records import RECORD_TYPES, AnyRecord, GenericRecord, RecordKind
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import INTEGRATION_NAMES, InvestigationResult

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.investigation.normalize import NormalizeContext

__all__ = ["TYPED_RECORD_KEY", "TYPED_INTEGRATION_KEY"]

TYPED_RECORD_KEY = "xdr_record"
TYPED_INTEGRATION_KEY = "xdr_integration"

_FILLED_FIELDS = frozenset({"record_id", "integration", "atomic", "subject"})
_FRACTION = re.compile(r"(\.\d{6})\d+")

#: ``(finding, nctx, result) -> records``; raises ValueError/KeyError/TypeError when not understood.
_FindingMapper = Callable[[Mapping[str, Any], "NormalizeContext", InvestigationResult], list[AnyRecord]]


class _TypedRecordError(ValueError):
    """A typed record from a simulated adapter is malformed (a scenario bug, never hidden)."""


# --------------------------------------------------------------- dispatcher --
def _normalize_findings(result: InvestigationResult, nctx: "NormalizeContext",
                        mapper: _FindingMapper) -> list[AnyRecord]:
    """Typed findings go to the typed path, everything else to ``mapper`` (generic fallback)."""
    records: list[AnyRecord] = []
    for finding in result.findings:
        if TYPED_RECORD_KEY in finding and nctx.typed_allowed:
            records.extend(_typed_records(finding, nctx, result.integration))
        elif TYPED_RECORD_KEY in finding:
            records.append(_generic_record(finding, nctx, result.integration))
        else:
            records.extend(_mapped_or_generic(finding, nctx, result, mapper))
    return records


def _mapped_or_generic(finding: Mapping[str, Any], nctx: "NormalizeContext", result: InvestigationResult,
                       mapper: _FindingMapper) -> list[AnyRecord]:
    try:
        return mapper(finding, nctx, result)
    except (ValueError, KeyError, TypeError):  # ValidationError is a ValueError
        return [_generic_record(finding, nctx, result.integration)]


def _generic_only(finding: Mapping[str, Any], nctx: "NormalizeContext",
                  result: InvestigationResult) -> list[AnyRecord]:
    """Mapper for sources whose finding fields are not documented on the cited vendor page."""
    return [_generic_record(finding, nctx, result.integration)]


def _generic_record(finding: Mapping[str, Any], nctx: "NormalizeContext", integration: str) -> GenericRecord:
    """The finding as returned (redacted, capped at 4 KiB) under ``"<integration>:<atomic>"``."""
    return GenericRecord(integration=integration, atomic=nctx.atomic, subject=nctx.subject,
                         name=f"{integration}:{nctx.atomic}", attributes=dict(finding))


# --------------------------------------------------------------- typed path --
def _typed_records(finding: Mapping[str, Any], nctx: "NormalizeContext", integration: str) -> list[AnyRecord]:
    """The typed record of a simulated finding, or ``[]`` when restricted to another adapter."""
    restricted = finding.get(TYPED_INTEGRATION_KEY)
    if restricted is not None:
        if restricted not in INTEGRATION_NAMES:
            raise _TypedRecordError(f"{TYPED_INTEGRATION_KEY} {restricted!r} is not an integration name")
        if restricted != integration:
            return []
    body = _typed_body(finding)
    kind = _typed_kind(body.get("kind"))
    if kind is RecordKind.MAILBOX_RULE and "external_forwarding" not in body:
        body["external_forwarding"] = _forwards_externally(body, nctx.internal_domains)
    try:
        record = RECORD_TYPES[kind].model_validate(
            {**body, "integration": integration, "atomic": nctx.atomic, "subject": nctx.subject})
    except ValidationError as exc:
        raise _TypedRecordError(f"invalid typed {kind.value} record: {exc.error_count()} error(s): "
                                f"{_first_error(exc)}") from exc
    return [record]  # type: ignore[list-item]


def _typed_body(finding: Mapping[str, Any]) -> dict[str, Any]:
    """``{"xdr_record": {...}}`` or ``{"xdr_record": true, "kind": ..., <fields>}``."""
    marker = finding[TYPED_RECORD_KEY]
    if isinstance(marker, Mapping):
        body = dict(marker)
    elif marker is True:
        body = {k: v for k, v in finding.items() if k not in (TYPED_RECORD_KEY, TYPED_INTEGRATION_KEY)}
    else:
        raise _TypedRecordError(f"{TYPED_RECORD_KEY} must be a record mapping or true")
    filled = sorted(_FILLED_FIELDS & set(body))
    if filled:
        raise _TypedRecordError(f"typed records never carry {filled}: the normalizer fills them")
    return body


def _is_internal(address: str, internal_domains: Iterable[str]) -> bool:
    domain = address.strip().lower().rpartition("@")[2].rstrip(".")
    for internal in internal_domains:
        d = internal.strip().lower().rstrip(".")
        if d and (domain == d or domain.endswith("." + d)):
            return True
    return False


def _forwards_externally(body: Mapping[str, Any], internal_domains: Iterable[str]) -> bool:
    """True when a forward / redirect address is outside ``internal_domains``.

    With no internal domains configured nothing can be proven internal, so any forwarding address
    counts as external (the analyst sees the rule either way).
    """
    domains = tuple(internal_domains)
    targets = [a for key in ("forward_to", "redirect_to", "forward_as_attachment_to")
               for a in _strings(body.get(key))]
    return any(not _is_internal(a, domains) for a in targets)


def _typed_kind(value: Any) -> RecordKind:
    try:
        return RecordKind(value)
    except ValueError as exc:
        raise _TypedRecordError(f"unknown typed record kind {value!r}") from exc


def _first_error(exc: ValidationError) -> str:
    err = exc.errors()[0]
    where = ".".join(str(p) for p in err.get("loc", ()))
    return get_redactor().redact_text(f"{where}: {err.get('msg', '')}")[:300]


# -------------------------------------------------------- field extraction --
def _path(data: Any, *keys: str) -> Any:
    """``data[k1][k2]...`` through mappings; ``None`` when any step is missing."""
    for key in keys:
        if not isinstance(data, Mapping):
            return None
        data = data.get(key)
    return data


def _text(data: Any, *keys: str) -> str | None:
    """A non-empty stripped string at ``keys``, else ``None``."""
    value = _path(data, *keys)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _flag(data: Any, *keys: str) -> bool | None:
    value = _path(data, *keys)
    return value if isinstance(value, bool) else None


def _strings(value: Any) -> tuple[str, ...]:
    """Distinct non-empty strings of a list (first-seen order); ``()`` for anything else."""
    if not isinstance(value, (list, tuple)):
        return ()
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip() and item.strip() not in out:
            out.append(item.strip())
    return tuple(out)


def _datetime(value: Any) -> datetime | None:
    """A timezone-aware datetime from an ISO 8601 string (``Z`` and 7-digit fractions accepted)."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = _FRACTION.sub(r"\1", value.strip())
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def _ips(values: Iterable[Any]) -> tuple[str, ...]:
    """Valid IP strings among ``values`` (invalid or empty ones dropped)."""

    out: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            ip = ipaddress.ip_address(value.strip()).compressed
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return tuple(out)


def _reference(value: Any) -> str | None:
    """A vendor id or console link, redacted (records refuse references that need redaction)."""
    if not isinstance(value, str) or not value.strip():
        return None
    return get_redactor().redact_text(value.strip())

