"""Test doubles for the enrichment atomics (fake data only; no network).

* :func:`lab` - fixed clock, settings with every real integration disabled, an adapter registry
  and an :class:`AtomicContext`; simulated or HTTP-mocked adapters are registered by the test.
* :class:`FakeScorer` - a local stand-in for the scoring key's engine (14.0.3): it records what the
  atomic handed over and returns a simple, documented breakdown.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tests.fixtures.factories import FIXED_NOW, make_incident
from xdr_response.atomics.context import AtomicContext, build_context
from xdr_response.atomics.records import EnrichmentRecord
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig, Settings
from xdr_response.config.policy import DisclosurePolicy
from xdr_response.config.schema import ScoringSettings
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.models import INTEGRATION_NAMES, Verdict
from xdr_response.models.recommendation import risk_band
from xdr_response.models.scoring import ScoreBreakdown, ScoringContext
from xdr_response.secrets import StaticSecretProvider

__all__ = ["FIXED_NOW", "FAKE_SHA256", "FAKE_SHA1", "FAKE_MD5", "Lab", "lab", "FakeScorer", "lab_disclosure"]

FAKE_SHA256 = "ab" * 32
FAKE_SHA1 = "cd" * 20
FAKE_MD5 = "ef" * 16


def lab_settings(**overrides: Any) -> Settings:
    """Settings with every real integration disabled (tests register the adapters they need)."""
    data: dict[str, Any] = {"integrations": {n: IntegrationConfig(enabled=False) for n in INTEGRATION_NAMES}}
    data.update(overrides)
    return Settings(**data)


def lab_disclosure(settings: Settings) -> DisclosurePolicy:
    """The settings' disclosure policy with the RFC 5737 documentation ranges treated as public."""
    return DisclosurePolicy(settings.exclusions, allow_documentation_ranges=True)


@dataclass
class Lab:
    clock: FixedClock
    settings: Settings
    registry: AdapterRegistry

    def context(self, *, public_documentation_ranges: bool = False, **changes: Any) -> AtomicContext:
        """A context over the registry; optionally treat documentation IPs as public."""
        ctx = build_context(make_incident(), self.registry, self.settings, clock=self.clock, dry_run=True)
        if public_documentation_ranges:
            changes.setdefault("disclosure", lab_disclosure(self.settings))
        return dataclasses.replace(ctx, **changes) if changes else ctx


def lab(**settings_overrides: Any) -> Lab:
    """Fixed clock, lab settings and an empty registry."""
    clock = FixedClock(FIXED_NOW)
    settings = lab_settings(**settings_overrides)
    registry = AdapterRegistry(settings, StaticSecretProvider({}), clock=clock)
    return Lab(clock=clock, settings=settings, registry=registry)


@dataclass
class FakeScorer:
    """Stand-in engine: risk = highest supporting record risk, confidence = highest record confidence.

    Verdict: ``MALICIOUS`` / ``SUSPICIOUS`` when a record says so (MALICIOUS only with two or more
    malicious sources), ``CLEAN`` when a record says so and nothing failed, else ``UNKNOWN``.
    """

    calls: list[tuple[ScoringSettings, tuple[EnrichmentRecord, ...], ScoringContext]] = field(default_factory=list)

    def __call__(self, settings: ScoringSettings, records: Sequence[EnrichmentRecord],
                 context: ScoringContext) -> tuple[ScoreBreakdown, Verdict]:
        self.calls.append((settings, tuple(records), context))
        supporting = [r for r in records if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]
        risk = max((r.risk_score for r in supporting), default=0)
        confidence = max((r.confidence for r in records if r.verdict is not Verdict.UNKNOWN), default=0)
        breakdown = ScoreBreakdown(
            risk_score=risk, confidence_score=confidence, risk_band=risk_band(risk), contributions=(),
            failed_sources=tuple(f"{n} ({h.value})" for n, h in context.failed_sources),
            not_queried=tuple(f"{n} ({reason})" for n, reason in context.not_queried),
            settings_hash="0" * 64)
        return breakdown, self._verdict(records, context)

    @staticmethod
    def _verdict(records: Sequence[EnrichmentRecord], context: ScoringContext) -> Verdict:
        malicious = {r.integration for r in records if r.verdict is Verdict.MALICIOUS}
        if len(malicious) >= 2:
            return Verdict.MALICIOUS
        if malicious or any(r.verdict is Verdict.SUSPICIOUS for r in records):
            return Verdict.SUSPICIOUS
        if any(r.verdict is Verdict.CLEAN for r in records) and not context.failed_sources:
            return Verdict.CLEAN
        return Verdict.UNKNOWN

    @property
    def last_context(self) -> ScoringContext:
        assert self.calls, "the scorer was not called"
        return self.calls[-1][2]

    @property
    def last_records(self) -> tuple[EnrichmentRecord, ...]:
        assert self.calls, "the scorer was not called"
        return self.calls[-1][1]


def statuses(report: Any) -> Mapping[str, str]:
    """``{integration: outcome value}`` of a report's sources, in order."""
    return {s.integration: s.outcome.value for s in report.sources}
