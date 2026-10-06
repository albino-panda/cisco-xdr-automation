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
            v = ipaddress.ip_address(v).compressed
        except ValueError as exc:
            raise ValueError(f"invalid IP address target: {v!r}") from exc
    elif kind is TargetKind.ENDPOINT:
        v = v.upper()
    return v


def make_idempotency_key(incident_id: str, action_type: "ActionType | str", target: str) -> str:
    """``f"{incident_id}:{action_type}:{target}"`` (target already normalized)."""
    at = action_type.value if isinstance(action_type, Enum) else str(action_type)
    if not incident_id or not at or not target:
        raise ValueError("incident_id, action_type and target are required")
    return f"{incident_id}:{at}:{target}"
