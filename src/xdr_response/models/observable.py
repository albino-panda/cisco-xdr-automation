"""Observables and the normalized enrichment result."""
from __future__ import annotations

from pydantic import Field, field_validator

from xdr_response.models._base import FrozenModel, Score
from xdr_response.models._common import ErrorInfo
from xdr_response.models.enums import HealthStatus, ObservableType, Verdict
from xdr_response.models.evidence import EvidenceDraft

__all__ = ["Observable", "EnrichmentResult"]


class Observable(FrozenModel):
    type: ObservableType
    value: str = Field(min_length=1)
    source: str | None = None

    @field_validator("value")
    @classmethod
    def _strip(cls, value: str) -> str:
        v = value.strip()
        if not v:
            raise ValueError("observable value must not be empty")
        return v


class EnrichmentResult(FrozenModel):
    type: ObservableType
    value: str
    risk_score: Score
    confidence: Score
    sources: tuple[str, ...]
    verdict: Verdict
    integration: str
    health: HealthStatus = HealthStatus.CONNECTED
    evidence: tuple[EvidenceDraft, ...] = ()
    errors: tuple[ErrorInfo, ...] = ()
