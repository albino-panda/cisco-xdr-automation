"""Hashing and line encoding of audit records (architecture section 13.12).

The record hash is ``sha256_hex(canonical_json(record without "hash"))``. Canonical JSON is the
same encoder the approval tokens use, so a record and its JSON round trip hash to the same value.
Floats are allowed (vendor data in payloads contains them); non-finite floats are rejected by
``canonical_json`` and are converted to strings before a payload is stored.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, NoReturn

from xdr_response.models.audit import AuditRecord
from xdr_response.models.canonical import canonical_json, sha256_hex

__all__ = ["compute_record_hash", "hash_of_record", "encode_record_line", "parse_record_line",
           "parse_canonical_record_line"]

_HASH_FIELD = "hash"


def compute_record_hash(record_without_hash: Mapping[str, Any]) -> str:
    """Return the SHA-256 hex digest of the canonical JSON of a record body.

    A ``"hash"`` key, if present, is ignored, so the function can be applied to a full record dump.
    Raises ``ValueError`` when the body is not canonicalizable.
    """
    body = {key: value for key, value in record_without_hash.items() if key != _HASH_FIELD}
    return sha256_hex(canonical_json(body, allow_floats=True))


def hash_of_record(record: AuditRecord) -> str:
    """Recompute the hash of ``record`` from its content (ignores the stored ``hash``)."""
    return compute_record_hash(record.model_dump(mode="python", exclude={_HASH_FIELD}))


def encode_record_line(record: AuditRecord) -> bytes:
    """One JSONL line (canonical JSON plus ``\n``), UTF-8 encoded."""
    return canonical_json(record, allow_floats=True) + b"\n"


def _reject_constant(token: str) -> NoReturn:
    raise ValueError(f"non-standard JSON constant {token!r}")


def parse_record_line(line: bytes | str) -> AuditRecord:
    """Parse one JSONL line into an :class:`AuditRecord`.

    Raises ``ValueError`` (``UnicodeDecodeError``, ``json.JSONDecodeError`` and pydantic's
    ``ValidationError`` are all subclasses) for anything that is not a well-formed record.
    """
    text = line.decode("utf-8") if isinstance(line, (bytes, bytearray)) else line
    data = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys)
    if not isinstance(data, dict):
        raise ValueError("audit line is not a JSON object")
    return AuditRecord.model_validate(data)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("audit line contains a duplicated JSON key")
    return dict(pairs)


def parse_canonical_record_line(line: bytes) -> AuditRecord:
    """Parse one stored JSONL line and insist that it is byte-for-byte the canonical encoding.

    A line that parses to a valid, correctly hashed record but is not exactly
    ``encode_record_line(record)`` (duplicated keys, reordered keys, extra whitespace) is refused:
    consumers that read the raw line differently (first duplicate wins, streaming parsers) could
    otherwise be shown content that the hash chain never covered. Raises ``ValueError``.
    """
    record = parse_record_line(line)
    raw = bytes(line) if not isinstance(line, bytes) else line
    if not raw.endswith(b"\n"):
        raw += b"\n"
    if encode_record_line(record) != raw:
        raise ValueError("audit line is not the canonical encoding of its record")
    return record
