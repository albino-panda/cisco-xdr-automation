"""Canonical JSON, hashing and target normalization (architecture section 13.3).

Every signature and every hash in the framework is computed over
``canonical_json`` so that two components can never disagree about bytes.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from collections.abc import Mapping
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import PurePath
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote_plus
from uuid import UUID

from pydantic import BaseModel, SecretBytes, SecretStr

from xdr_response.models.enums import TargetKind

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.models.catalog import ActionType

__all__ = [
    "canonical_json",
    "sha256_hex",
    "params_hash",
    "normalize_target",
    "endpoint_names",
    "same_endpoint",
    "canonical_url",
    "url_without_credentials",
    "make_idempotency_key",
    "format_datetime",
]

_SECRET_PLACEHOLDER = "**********"


def format_datetime(dt: datetime) -> str:
    """UTC ``YYYY-MM-DDTHH:MM:SS.ffffffZ``. Naive datetimes raise ValueError."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("naive datetime cannot be canonicalized")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _key(k: Any) -> str:
    if isinstance(k, Enum):
        return str(k.value)
    if isinstance(k, str):
        return str(k)
    if isinstance(k, bool):
        raise ValueError("boolean mapping keys are not canonicalizable")
    if isinstance(k, int):
        return str(k)
    raise ValueError(f"unsupported mapping key type: {type(k).__name__}")


def _normalize(obj: Any, allow_floats: bool) -> Any:
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, Enum):
        return _normalize(obj.value, allow_floats)
    if isinstance(obj, str):
        return str(obj)
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, float):
        if not allow_floats:
            raise ValueError("floats are not allowed in canonical JSON")
        if not math.isfinite(obj):
            raise ValueError("non-finite floats are not allowed in canonical JSON")
        return obj
    if isinstance(obj, (SecretStr, SecretBytes)):
        return _SECRET_PLACEHOLDER
    if isinstance(obj, BaseModel):
        return _normalize(obj.model_dump(mode="python"), allow_floats)
    if isinstance(obj, datetime):
        return format_datetime(obj)
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, (UUID, PurePath)):
        return str(obj)
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            key = _key(k)
            if key in out:
                raise ValueError(f"duplicate key after normalization: {key}")
            out[key] = _normalize(v, allow_floats)
        return out
    if isinstance(obj, (set, frozenset)):
        items = [_normalize(v, allow_floats) for v in obj]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False))
    if isinstance(obj, (list, tuple)):
        return [_normalize(v, allow_floats) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        raise ValueError("bytes are not canonicalizable; encode them first")
    # objects that refuse to reveal themselves (SecretValue) or unknown types
    raise ValueError(f"unsupported type in canonical JSON: {type(obj).__name__}")


def canonical_json(data: object, *, allow_floats: bool = False) -> bytes:
    """Deterministic UTF-8 JSON.

    ``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=False``. Pydantic models are
    dumped, datetimes become UTC ``...ffffffZ`` (naive raises ValueError), enums become their
    values, tuples/sets become lists (sets sorted). Floats raise ValueError unless
    ``allow_floats=True`` (used only for hashing evidence data, never for signed claims).
    """
    normalized = _normalize(data, allow_floats)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def params_hash(params: Mapping[str, object]) -> str:
    return sha256_hex(canonical_json(dict(params)))


def normalize_target(kind: TargetKind | str, value: str) -> str:
    """Normalize a target value for its kind. Empty values raise ValueError."""
    kind = TargetKind(kind)
    if not isinstance(value, str):
        raise ValueError("target must be a string")
    v = value.strip()
    if not v:
        raise ValueError("target must not be empty")
    if kind is TargetKind.DOMAIN:
        v = v.lower().rstrip(".")
        if not v:
            raise ValueError("target must not be empty")
    elif kind in (TargetKind.EMAIL_ADDRESS, TargetKind.USER, TargetKind.HASH):
        v = v.lower()
    elif kind is TargetKind.IP:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"invalid IP address target: {v!r}") from exc
        # An IPv4-mapped IPv6 address (``::ffff:192.0.2.5``) is the IPv4 host itself: one canonical
        # spelling, so allow-lists, critical-asset CIDRs and dedup see the same address.
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        v = (mapped or ip).compressed
    elif kind is TargetKind.ENDPOINT:
        # One trailing dot is the DNS root ("TH-LT-1047.corp.example.com."): the same host.
        v = v.upper().rstrip(".")
        if not v:
            raise ValueError("target must not be empty")
    elif kind is TargetKind.URL:
        v = url_without_credentials(v)
        if not v:
            raise ValueError("target must not be empty")
    return v


def url_without_credentials(value: str) -> str:
    """``value`` without the credentials a URL can carry (14.12.6).

    The ``user:password@`` part of the authority is removed, and every query or fragment parameter
    whose key is sensitive (the keys :meth:`Redactor.redact_url
    <xdr_response.logs.redaction.Redactor.redact_url>` redacts: ``token``, ``password``, ``sig``,
    ``api_key``, ...) is dropped with its value; an emptied query or fragment loses its ``?`` / ``#``.
    Everything else (scheme, host, port, path, the other parameters and their order) is kept as
    written. A credential is never part of the destination, so a URL target, its idempotency key and
    the vendor call never carry one. The result is stable: applying the function again changes nothing.
    """
    from xdr_response.logs.redaction import get_redactor  # local: models stay importable on their own

    text = value.strip()
    scheme, sep, rest = text.partition("://")
    if not sep or not scheme or "/" in scheme or "?" in scheme or "#" in scheme:
        scheme, sep, rest = "", "", text
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0), default=len(rest))
    netloc, tail = rest[:cut], rest[cut:]
    userinfo, _at, host = netloc.rpartition("@")
    before, hash_sep, fragment = tail.partition("#")
    path, query_sep, query = before.partition("?")
    redactor = get_redactor()

    def secret(pair: str) -> bool:
        return bool(pair) and redactor.is_sensitive_key(unquote_plus(pair.partition("=")[0]))

    query_pairs = query.split("&") if query_sep else []
    fragment_pairs = fragment.split("&") if hash_sep else []
    if not _at and not any(secret(p) for p in (*query_pairs, *fragment_pairs)):
        return text  # nothing to remove: the URL is kept exactly as written
    query = "&".join(p for p in query_pairs if p and not secret(p))
    fragment = "&".join(p for p in fragment_pairs if p and not secret(p))
    rebuilt = f"{host}{path}{'?' + query if query else ''}{'#' + fragment if fragment else ''}"
    return f"{scheme}{sep}{rebuilt}"


def _is_ip_literal(value: str) -> bool:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def endpoint_names(value: str) -> tuple[str, str | None]:
    """``(full, short)`` upper-case identities of an endpoint name (trailing dot removed).

    ``short`` is the first DNS label of a fully qualified host name (``TH-LT-1047`` for
    ``TH-LT-1047.corp.example.com``) and ``None`` when ``value`` is a single-label name or an IP
    address (an IP is never split at its dots). Endpoint agents report a host by its short name or
    its FQDN; allow-lists and critical-asset classes treat a listed short name and the FQDN with
    that first label as the same machine.
    """
    full = value.strip().upper().rstrip(".")
    if not full or _is_ip_literal(full) or "." not in full:
        return full, None
    short = full.split(".", 1)[0]
    return full, short or None


def same_endpoint(first: str, second: str) -> bool:
    """Two endpoint names denote one machine: equal (case and a trailing dot ignored), or one is a
    single-label name equal to the other's FQDN first label."""
    full_a, short_a = endpoint_names(first)
    full_b, short_b = endpoint_names(second)
    if not full_a or not full_b:
        return False
    return full_a == full_b or (short_a is None and full_a == short_b) or (short_b is None and full_b == short_a)


_DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21", "ws": "80", "wss": "443"}


def canonical_url(value: str) -> str:
    """One spelling of a URL for comparison (allow-list matching), never sent to a vendor.

    The scheme and the host are lower-cased, a trailing dot on the host and the scheme's default port
    are removed and an empty path becomes ``/``. Userinfo, the path, the query and the fragment are
    kept as written (paths are case-sensitive). A value that does not parse is returned stripped.
    """
    text = value.strip()
    scheme, sep, rest = text.partition("://")
    if not sep or not scheme:
        scheme, rest = "", text
    scheme = scheme.lower()
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0), default=len(rest))
    netloc, tail = rest[:cut], rest[cut:]
    userinfo, at, hostport = netloc.rpartition("@")
    host, port = hostport, ""
    if hostport.startswith("["):
        end = hostport.find("]")
        if end >= 0:
            host, port = hostport[:end + 1], hostport[end + 1:].lstrip(":")
    elif hostport.count(":") == 1:
        host, _, port = hostport.partition(":")
    host = host.lower().rstrip(".")
    if port and port == _DEFAULT_PORTS.get(scheme):
        port = ""
    if not tail or tail[0] in "?#":
        tail = "/" + tail
    rebuilt = f"{userinfo}{at}{host}{':' + port if port else ''}{tail}"
    return f"{scheme}://{rebuilt}" if scheme else rebuilt


def make_idempotency_key(incident_id: str, action_type: "ActionType | str", target: str) -> str:
    """``f"{incident_id}:{action_type}:{target}"`` (target already normalized)."""
    at = action_type.value if isinstance(action_type, Enum) else str(action_type)
    if not incident_id or not at or not target:
        raise ValueError("incident_id, action_type and target are required")
    return f"{incident_id}:{at}:{target}"
