"""Audit chain key: authenticates the head anchor of the hash-chained audit trail (section 13.12).

The record chain itself is plain SHA-256, so anybody who can write the audit directory could
recompute every hash. The head anchor ``(seq, hash)`` therefore carries an HMAC-SHA256 ``mac``
keyed with the audit chain key: rewriting history (editing, dropping or appending records) needs a
new head hash, and a new head hash needs a new MAC, which needs the key.

Key resolution (first match wins), never from the audit directory:

1. an explicit key passed to :class:`~xdr_response.audit.trail.AuditTrail` (``bootstrap`` reads the
   ``AUDIT_CHAIN_KEY`` secret through the secrets interface);
2. the ``AUDIT_CHAIN_KEY`` environment variable;
3. a per-user key file outside the audit directory: ``XDR_RESPONSE_AUDIT_KEY_FILE`` or
   ``~/.xdr_response/audit-chain.key`` (created on first use with owner-only permissions).

Production deployments should provide ``AUDIT_CHAIN_KEY`` from the secret store and export
anchors to write-once storage (a rollback of both the file and its anchor to an older, genuine
state cannot be detected from the files alone).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets as _stdlib_secrets
import threading
import time
from pathlib import Path
from typing import Any

from xdr_response.errors import AuditError
from xdr_response.logs.redaction import get_redactor
from xdr_response.models.canonical import canonical_json

__all__ = ["AUDIT_CHAIN_KEY_NAME", "AUDIT_KEY_FILE_ENV", "MIN_CHAIN_KEY_BYTES", "anchor_mac",
           "default_key_file", "resolve_chain_key"]

AUDIT_CHAIN_KEY_NAME = "AUDIT_CHAIN_KEY"
AUDIT_KEY_FILE_ENV = "XDR_RESPONSE_AUDIT_KEY_FILE"
MIN_CHAIN_KEY_BYTES = 32
_ANCHOR_CONTEXT = b"xdr-response-audit-anchor-v1\n"

_cache: dict[str, bytes] = {}
_lock = threading.Lock()


def _as_bytes(value: Any) -> bytes:
    reveal = getattr(value, "reveal", None)
    if callable(reveal):  # SecretValue
        value = reveal()
    get_secret = getattr(value, "get_secret_value", None)
    if callable(get_secret):  # pydantic SecretStr
        value = get_secret()
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        raise AuditError("audit chain key must be bytes, str or a secret value")
    key = bytes(value)
    if len(key) < MIN_CHAIN_KEY_BYTES:
        raise AuditError(f"{AUDIT_CHAIN_KEY_NAME} must be at least {MIN_CHAIN_KEY_BYTES} bytes")
    return key


def default_key_file() -> Path:
    """Location of the per-user fallback key file (outside every audit directory)."""
    configured = os.environ.get(AUDIT_KEY_FILE_ENV)
    if configured:
        return Path(configured)
    return Path.home() / ".xdr_response" / "audit-chain.key"


def _load_or_create(path: Path) -> bytes:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AuditError(f"cannot create the audit key directory: {type(exc).__name__}") from None
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = None
    except OSError as exc:
        raise AuditError(f"cannot create the audit chain key file: {type(exc).__name__}") from None
    if fd is not None:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(_stdlib_secrets.token_hex(32))
            fh.flush()
            os.fsync(fh.fileno())
    for _ in range(200):  # another process may be writing it right now
        try:
            text = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise AuditError(f"cannot read the audit chain key file: {type(exc).__name__}") from None
        if len(text) >= 2 * MIN_CHAIN_KEY_BYTES:
            return text.encode("ascii")
        time.sleep(0.005)
    raise AuditError("the audit chain key file is empty or too short")


def resolve_chain_key(explicit: Any = None) -> bytes:
    """The audit chain key (see the module docstring). Registered with the redactor."""
    if explicit is not None:
        key = _as_bytes(explicit)
    else:
        env = os.environ.get(AUDIT_CHAIN_KEY_NAME)
        if env:
            key = _as_bytes(env)
        else:
            path = default_key_file()
            with _lock:
                key = _cache.get(str(path)) or _load_or_create(path)
                _cache[str(path)] = key
    try:
        get_redactor().register_secret(key.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    return key


def anchor_mac(key: bytes, seq: int, head_hash: str) -> str:
    """HMAC-SHA256 of the head anchor ``(seq, hash)``."""
    body = canonical_json({"seq": int(seq), "hash": str(head_hash)})
    return hmac.new(key, _ANCHOR_CONTEXT + body, hashlib.sha256).hexdigest()
