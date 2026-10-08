"""Golden breakdowns for the bundled incident fixtures (docs/threat-scoring.md section 10).

Each reputation entry of ``tests/fixtures/incidents/*.yaml`` becomes one enrichment-style signal per
listed integration (category from ENRICHMENT_CATEGORY). Critical-asset classes come from the
repository's example policy and the incident's asset context, as the enrichment atomics do.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from xdr_response.approval.critical_assets import CriticalAssetPolicy
from xdr_response.config import load_settings
from xdr_response.models.enums import ObservableType, RiskBand, TargetKind, Verdict
from xdr_response.models.incident import Asset
from xdr_response.models.observable import Observable
from xdr_response.models.scoring import ScoringContext, ScoringSignal
from xdr_response.scoring import ENRICHMENT_CATEGORY, ScoringEngine, aggregate_verdict

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "fixtures" / "incidents"
_KIND = {ObservableType.HOSTNAME: TargetKind.ENDPOINT, ObservableType.USER: TargetKind.USER,
         ObservableType.IP: TargetKind.IP, ObservableType.DOMAIN: TargetKind.DOMAIN,
         ObservableType.URL: TargetKind.URL, ObservableType.SHA256: TargetKind.HASH,
         ObservableType.EMAIL_MESSAGE_ID: TargetKind.EMAIL_MESSAGE}

C, H, M, L = RiskBand.CRITICAL, RiskBand.HIGH, RiskBand.MEDIUM, RiskBand.LOW
MAL, SUS = Verdict.MALICIOUS, Verdict.SUSPICIOUS

# (fixture, observable value) -> (risk, band, confidence, reputation_only, critical, verdict)
GOLDEN: dict[tuple[str, str], tuple[int, RiskBand, int, bool, bool, Verdict]] = {
    ("ransomware", "TH-LT-1047"): (96, C, 92, False, False, MAL),
    ("ransomware", "5c1d7e0b9a8f6e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d"): (100, C, 93, False, False, MAL),
    ("ransomware", "c2.ransom-ops.example"): (50, M, 50, True, False, MAL),
    ("ransomware", "198.51.100.23"): (43, M, 50, True, False, SUS),
    ("ransomware", "jsmith@example.com"): (32, M, 50, False, False, SUS),
    ("account_takeover", "jsmith@example.com"): (81, C, 85, False, False, MAL),
    ("account_takeover", "198.51.100.77"): (50, M, 50, True, False, SUS),
    ("phishing", "<20260115.7781@mail.contoso-payroll.example>"): (70, H, 90, False, False, MAL),
    ("phishing", "https://login.contoso-payroll.example/reset"): (50, M, 50, True, False, MAL),
    ("phishing", "contoso-payroll.example"): (50, M, 50, True, False, SUS),
    ("phishing", "jsmith@example.com"): (61, H, 70, False, False, SUS),
    ("ransomware_domain_controller", "TH-LT-1047"): (96, C, 92, False, False, MAL),
    ("ransomware_domain_controller", "TH-DC-02"): (100, C, 88, False, True, MAL),
    ("ransomware_domain_controller", "TH-DC-01"): (90, C, 70, False, True, MAL),
}


def _fixtures() -> list[tuple[str, dict[str, Any]]]:
    return [(p.stem, yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(FIXTURES.glob("*.yaml"))]


def _signals(name: str, entry: dict[str, Any]) -> list[ScoringSignal]:
    observable = Observable(type=entry["type"], value=entry["value"])
    return [ScoringSignal(category=ENRICHMENT_CATEGORY[integration], integration=integration, observable=observable,
                          verdict=entry["verdict"], severity=entry["risk_score"], confidence=entry["confidence"],
                          record_ids=(f"rec_{name}_{integration}_{entry['type']}",))
            for integration in entry["integrations"]]


def _context(policy: CriticalAssetPolicy, data: dict[str, Any], entry: dict[str, Any]) -> ScoringContext:
    kind = _KIND[ObservableType(entry["type"])]
    assets = {a["name"].upper(): Asset(**a) for a in data["incident"].get("assets") or []}
    asset = assets.get(entry["value"].upper()) if kind is TargetKind.ENDPOINT else None
    return ScoringContext(critical_asset_classes=tuple(policy.classify(entry["value"], kind, asset)),
                          expected_sources=tuple(entry["integrations"]))


@pytest.fixture(scope="module")
def scored() -> dict[tuple[str, str], Any]:
    settings = load_settings(ROOT / "config", env={})
    policy = CriticalAssetPolicy(settings.critical_assets)
    engine = ScoringEngine(settings.thresholds.scoring)
    out = {}
    for name, data in _fixtures():
        for entry in data["environment"].get("reputations", []):
            signals = _signals(name, entry)
            context = _context(policy, data, entry)
            breakdown = engine.score(signals, context=context)
            verdict = aggregate_verdict(signals, breakdown, bands=settings.thresholds.scoring.bands)
            out[(name, entry["value"])] = (breakdown, context, verdict)
    return out


def test_every_fixture_observable_has_a_golden_entry(scored):
    assert set(scored) == set(GOLDEN)


@pytest.mark.parametrize("key", sorted(GOLDEN))
def test_golden_breakdown(scored, key):
    breakdown, context, verdict = scored[key]
    risk, band, confidence, reputation_only, critical, expected_verdict = GOLDEN[key]
    assert (breakdown.risk_score, breakdown.risk_band, breakdown.confidence_score) == (risk, band, confidence)
    assert breakdown.reputation_only is reputation_only
    assert bool(context.critical_asset_classes) is critical
    assert verdict is expected_verdict
    assert bool([c for c in breakdown.contributions if c.category == "critical_asset"]) is critical


def test_golden_explanations_are_stable(scored):
    first = {k: v[0].explain() for k, v in scored.items()}
    again = {k: v[0].explain() for k, v in scored.items()}
    assert first == again
    assert first[("ransomware_domain_controller", "TH-DC-01")].startswith(
        "risk 90 CRITICAL (endpoint_detection secure_endpoint 80; critical asset +10), confidence 70 (base 70)")
