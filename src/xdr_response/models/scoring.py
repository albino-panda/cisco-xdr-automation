"""Scoring models (architecture section 14.2.1, layer 0).

Risk and confidence are two separate numbers that are never merged. Every signal and every
contribution cites the ids of the investigation or enrichment records it was computed from;
there is no field that could carry AI text or analyst comments.

This module is not re-exported from ``xdr_response.models``; import it by its full name.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Literal

from pydantic import field_validator

from xdr_response.models._base import FrozenModel, Score
from xdr_response.models.catalog import INTEGRATION_NAMES
from xdr_response.models.enums import CriticalAssetClass, HealthStatus, RiskBand, Verdict
from xdr_response.models.observable import Observable

__all__ = [
    "SignalCategory",
    "DEFAULT_WEIGHTS",
    "ScoringSignal",
    "ScoringContext",
    "Contribution",
    "ScoreBreakdown",
]


class SignalCategory(StrEnum):
    """What kind of evidence a signal is (docs/threat-scoring.md section 4)."""

    ENDPOINT_DETECTION = "endpoint_detection"
    SANDBOX_VERDICT = "sandbox_verdict"
    REPUTATION = "reputation"
    NETWORK_BEHAVIOUR = "network_behaviour"
    AUTHENTICATION_ANOMALY = "authentication_anomaly"
    EMAIL_VERDICT = "email_verdict"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    CAMPAIGN_ASSOCIATION = "campaign_association"


DEFAULT_WEIGHTS: Mapping[SignalCategory, float] = MappingProxyType({
    SignalCategory.ENDPOINT_DETECTION: 1.0,
    SignalCategory.SANDBOX_VERDICT: 0.9,
    SignalCategory.NETWORK_BEHAVIOUR: 0.9,
    SignalCategory.AUTHENTICATION_ANOMALY: 0.9,
    SignalCategory.EMAIL_VERDICT: 0.8,
    SignalCategory.PERSISTENCE: 0.8,
    SignalCategory.LATERAL_MOVEMENT: 1.0,
    SignalCategory.CAMPAIGN_ASSOCIATION: 0.7,
    SignalCategory.REPUTATION: 0.6,
})

_ORIGIN_PREFIX = "workflow:"


def _check_integration(value: str) -> str:
    if value not in INTEGRATION_NAMES:
        raise ValueError(f"integration must be one of INTEGRATION_NAMES, got {value!r}")
    return value


def _check_record_ids(value: tuple[str, ...]) -> tuple[str, ...]:
    for record_id in value:
        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("record ids must be non-empty strings")
    return value


class ScoringSignal(FrozenModel):
    """One source's statement about one target, citing the records it came from."""

    category: SignalCategory
    integration: str  # source adapter (INTEGRATION_NAMES)
    observable: Observable  # the target the signal is about (normalized)
    verdict: Verdict
    severity: Score  # impact if true
    confidence: Score  # the source's confidence, or the record-kind default (14.2.3)
    record_ids: tuple[str, ...]  # >= 1; validated against the run's RecordIndex by the caller
    health: HealthStatus = HealthStatus.CONNECTED
    origin: str = "framework"  # or "workflow:<id>" for hook-derived signals (14.3.3)
    note: str = ""
    # True for an enrichment answer (a vendor's verdict about an observable, 14.2.3), never a
    # behavioural detection: one vendor verdict alone is never MALICIOUS and never CRITICAL (14.2.2).
    vendor_verdict: bool = False

    @field_validator("integration")
    @classmethod
    def _integration(cls, value: str) -> str:
        return _check_integration(value)

    @field_validator("record_ids")
    @classmethod
    def _record_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("a signal must cite at least one record id")
        return _check_record_ids(value)

    @field_validator("origin")
    @classmethod
    def _origin(cls, value: str) -> str:
        if value == "framework":
            return value
        if value.startswith(_ORIGIN_PREFIX) and len(value) > len(_ORIGIN_PREFIX):
            return value
        raise ValueError('origin must be "framework" or "workflow:<id>"')


class ScoringContext(FrozenModel):
    """Facts about the target that are not signals: asset criticality and source coverage."""

    critical_asset_classes: tuple[CriticalAssetClass, ...] = ()
    expected_sources: tuple[str, ...] = ()
    failed_sources: tuple[tuple[str, HealthStatus], ...] = ()  # (integration, health), sorted
    not_queried: tuple[tuple[str, str], ...] = ()  # (integration, reason), sorted

    @field_validator("critical_asset_classes")
    @classmethod
    def _classes(cls, value: tuple[CriticalAssetClass, ...]) -> tuple[CriticalAssetClass, ...]:
        return tuple(sorted(set(value), key=lambda c: c.value))

    @field_validator("failed_sources")
    @classmethod
    def _failed(cls, value: tuple[tuple[str, HealthStatus], ...]) -> tuple[tuple[str, HealthStatus], ...]:
        # One source may fail with several health values in one run (UNAVAILABLE on one call,
        # RATE_LIMITED on another); all are listed, and the engine penalises the source once.
        return tuple(sorted(set(value), key=lambda item: (item[0], item[1].value)))

    @field_validator("not_queried")
    @classmethod
    def _not_queried(cls, value: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        return tuple(sorted(set(value)))


_ContributionCategory = SignalCategory | Literal[
    "corroboration", "critical_asset", "independent_sources", "contradiction", "failed_sources"]


class Contribution(FrozenModel):
    """One explained step of the risk or confidence calculation."""

    category: _ContributionCategory
    integration: str | None
    points: int  # signed; risk or confidence points
    applies_to: Literal["risk", "confidence"]
    record_ids: tuple[str, ...] = ()
    note: str = ""


def _signed(points: int) -> str:
    return f"+{points}" if points >= 0 else str(points)


def _risk_parts(contributions: tuple[Contribution, ...]) -> list[str]:
    parts: list[str] = []
    for c in contributions:
        if c.applies_to != "risk":
            continue
        if c.note == "base":
            parts.append(f"{c.category} {c.integration} {c.points}")
        elif c.category == "corroboration":
            parts.append(f"corroboration {_signed(c.points)}")
        elif c.category == "critical_asset":
            parts.append(f"critical asset {_signed(c.points)}")
    return parts


def _confidence_parts(contributions: tuple[Contribution, ...]) -> list[str]:
    parts: list[str] = []
    for c in contributions:
        if c.applies_to != "confidence":
            continue
        if c.note == "base":
            parts.append(f"base {c.points}")
        elif c.category == "independent_sources":
            parts.append(f"independent sources {_signed(c.points)}")
        elif c.category == "contradiction":
            parts.append(f"contradiction {c.integration} {_signed(c.points)}")
        elif c.category == "failed_sources":
            parts.append(f"failed {c.integration} {_signed(c.points)}")
    return parts


class ScoreBreakdown(FrozenModel):
    """Result of one scoring run: two separate scores and how they were reached."""

    risk_score: Score
    confidence_score: Score
    risk_band: RiskBand
    contributions: tuple[Contribution, ...]
    caps_applied: tuple[str, ...] = ()  # e.g. "reputation capped at 50"
    failed_sources: tuple[str, ...] = ()  # "<integration> (<HEALTH>)"
    not_queried: tuple[str, ...] = ()  # "<integration> (<reason>)"
    reputation_only: bool = False
    settings_hash: str  # sha256_hex(canonical_json(scoring settings, allow_floats=True))

    def explain(self) -> str:
        """One deterministic line for the decision card and the audit trail."""
        risk = _risk_parts(self.contributions) or ["insufficient evidence"]
        confidence = _confidence_parts(self.contributions)
        if not any(c.note == "base" for c in self.contributions if c.applies_to == "confidence"):
            confidence = ["insufficient evidence", *(f"failed {f}" for f in self.failed_sources)]
        if self.reputation_only:
            confidence.append("reputation only")
        return (f"risk {self.risk_score} {self.risk_band.value} ({'; '.join(risk)}), "
                f"confidence {self.confidence_score} ({'; '.join(confidence)}), "
                f"settings {self.settings_hash[:12]}")
