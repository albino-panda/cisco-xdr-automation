"""Audit record and chain verification result. Hashing lives in ``xdr_response.audit``."""
from __future__ import annotations

from pydantic import AwareDatetime, Field

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.enums import AuditEventType

__all__ = ["GENESIS_HASH", "AuditRecord", "ChainVerification"]

GENESIS_HASH = "0" * 64


class AuditRecord(FrozenModel):
    seq: int = Field(ge=0)  # 0-based, contiguous
    record_id: str
    timestamp: AwareDatetime
    event_type: AuditEventType
    incident_id: str | None
    workflow_id: str | None
    workflow_version: str | None
    actor: str
    payload: JsonDict  # already redacted
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")  # sha256_hex(canonical_json(record without "hash"))


class ChainVerification(FrozenModel):
    ok: bool
    records: int = Field(ge=0)
    head_hash: str
    first_bad_seq: int | None = None
    reason: str = ""
