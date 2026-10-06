"""Evidence models. Evidence is always sourced from an integration or an analyst; never from AI."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from pydantic import AwareDatetime, Field, field_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.canonical import canonical_json, sha256_hex
from xdr_response.models.catalog import INTEGRATION_NAMES

__all__ = [
    "ALLOWED_NON_INTEGRATION_SOURCES",
    "EvidenceDraft",
    "Evidence",
    "number_evidence",
    "evidence_snapshot_hash",
]

ALLOWED_NON_INTEGRATION_SOURCES = frozenset({"analyst", "temporary_control_registry"})
_ALLOWED_SOURCES = frozenset(INTEGRATION_NAMES) | ALLOWED_NON_INTEGRATION_SOURCES
_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)


class EvidenceDraft(FrozenModel):
    source: str
    summary: str = Field(min_length=1)
    observed_at: AwareDatetime | None = None
    reference: str | None = None  # vendor object id or console link (no secrets)
    data: JsonDict = {}
    audit_ref: str | None = None  # record_id of the API_CALL audit record

    @field_validator("source")
    @classmethod
    def _source_allowed(cls, value: str) -> str:
        v = value.strip()
        if v.lower() == "ai" or v.lower().startswith(("ai:", "ai_", "llm")):
            raise ValueError("AI output can never be evidence")
        if v not in _ALLOWED_SOURCES:
            raise ValueError(
                f"evidence source {v!r} must be an integration name or one of "
                f"{sorted(ALLOWED_NON_INTEGRATION_SOURCES)}"
            )
        return v


class Evidence(EvidenceDraft):
    number: int = Field(ge=1)


def _draft_fields(d: EvidenceDraft) -> dict:
    return {name: getattr(d, name) for name in EvidenceDraft.model_fields}


def number_evidence(drafts: Sequence[EvidenceDraft]) -> tuple[Evidence, ...]:
    """Merge exact duplicates, order by (source, observed_at, summary), number 1..n."""
    unique: dict[bytes, EvidenceDraft] = {}
    for d in drafts:
        fields = _draft_fields(d)
        key = canonical_json(fields, allow_floats=True)
        unique.setdefault(key, d)
    ordered = sorted(
        unique.items(),
        key=lambda kv: (kv[1].source, kv[1].observed_at or _MIN_DT, kv[1].summary, kv[0]),
    )
    return tuple(Evidence(number=i, **_draft_fields(d)) for i, (_, d) in enumerate(ordered, start=1))


def evidence_snapshot_hash(evidence: Sequence[Evidence]) -> str:
    """sha256 over the canonical JSON of the evidence list sorted by number."""
    ordered = sorted(evidence, key=lambda e: e.number)
    return sha256_hex(canonical_json([e.model_dump(mode="python") for e in ordered], allow_floats=True))
