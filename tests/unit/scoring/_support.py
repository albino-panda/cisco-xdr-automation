"""Shared builders for the scoring tests (fake data only)."""
from __future__ import annotations

from collections.abc import Sequence

from xdr_response.config.schema import ScoringSettings
from xdr_response.models.enums import CriticalAssetClass, HealthStatus, ObservableType, Verdict
from xdr_response.models.observable import Observable
from xdr_response.models.scoring import ScoringContext, ScoringSignal, SignalCategory
from xdr_response.scoring import ScoringEngine

HOST = Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047")
DOMAIN = Observable(type=ObservableType.DOMAIN, value="login-update.example")
DC = CriticalAssetClass.DOMAIN_CONTROLLER

CAT = SignalCategory


def sig(category: SignalCategory | str, integration: str, severity: int, confidence: int, *record_ids: str,
        verdict: Verdict = Verdict.MALICIOUS, observable: Observable = HOST,
        health: HealthStatus = HealthStatus.CONNECTED) -> ScoringSignal:
    """A signal citing ``record_ids`` (default: one id derived from category and integration)."""
    ids = record_ids or (f"rec_{SignalCategory(category).value}_{integration}",)
    return ScoringSignal(category=SignalCategory(category), integration=integration, observable=observable,
                         verdict=verdict, severity=severity, confidence=confidence, record_ids=ids,
                         health=health)


def ctx(*, critical: Sequence[CriticalAssetClass] = (), expected: Sequence[str] = (),
        failed: Sequence[tuple[str, HealthStatus]] = (),
        not_queried: Sequence[tuple[str, str]] = ()) -> ScoringContext:
    return ScoringContext(critical_asset_classes=tuple(critical), expected_sources=tuple(expected),
                          failed_sources=tuple(failed), not_queried=tuple(not_queried))


def engine(**settings: object) -> ScoringEngine:
    return ScoringEngine(ScoringSettings.model_validate(settings))


def worked_example_signals() -> list[ScoringSignal]:
    """docs/threat-scoring.md section 9 (fake data)."""
    return [
        sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 80, 80, "rec_se_2"),
        sig(CAT.NETWORK_BEHAVIOUR, "umbrella", 85, 85, "rec_um_5"),
        sig(CAT.REPUTATION, "virustotal", 90, 80, "rec_vt_8"),
    ]


def worked_example_context() -> ScoringContext:
    return ctx(expected=("alienvault_otx", "virustotal"), failed=(("alienvault_otx", HealthStatus.RATE_LIMITED),))
