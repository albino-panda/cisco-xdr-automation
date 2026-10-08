"""Scoring configuration (architecture 14.2.4) and configurable risk bands."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from xdr_response.config import load_settings
from xdr_response.config.schema import (
    ConfidenceSettings,
    CorroborationSettings,
    ScoringCaps,
    ScoringContextSettings,
    ScoringSettings,
    Thresholds,
)
from xdr_response.models.enums import RiskBand
from xdr_response.models.recommendation import risk_band
from xdr_response.models.scoring import DEFAULT_WEIGHTS, SignalCategory

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
DEFAULT_BANDS = {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}


# ----------------------------------------------------------------- defaults --
def test_defaults_match_the_contract():
    s = ScoringSettings()
    assert s.bands == DEFAULT_BANDS and s.weights == {}
    assert s.caps == ScoringCaps(reputation_max_contribution=50, reputation_only_confidence_cap=50)
    assert s.corroboration == CorroborationSettings(min=30, step=5, max=15)
    assert s.confidence == ConfidenceSettings(independent_source_step=5, independent_source_max=20,
                                              contradiction_penalty=15, failed_source_penalty=5,
                                              failed_source_max_penalty=20)
    assert s.context == ScoringContextSettings(critical_asset_bonus=10)


def test_default_weights_table():
    assert dict(DEFAULT_WEIGHTS) == {
        SignalCategory.ENDPOINT_DETECTION: 1.0, SignalCategory.SANDBOX_VERDICT: 0.9,
        SignalCategory.NETWORK_BEHAVIOUR: 0.9, SignalCategory.AUTHENTICATION_ANOMALY: 0.9,
        SignalCategory.EMAIL_VERDICT: 0.8, SignalCategory.PERSISTENCE: 0.8, SignalCategory.LATERAL_MOVEMENT: 1.0,
        SignalCategory.CAMPAIGN_ASSOCIATION: 0.7, SignalCategory.REPUTATION: 0.6,
    }
    assert set(DEFAULT_WEIGHTS) == set(SignalCategory)
    with pytest.raises(TypeError):
        DEFAULT_WEIGHTS[SignalCategory.REPUTATION] = 1.0  # type: ignore[index]


def test_weight_falls_back_to_default_and_reads_overrides():
    s = ScoringSettings(weights={"reputation": 0.3})
    assert s.weight(SignalCategory.REPUTATION) == 0.3
    assert s.weight(SignalCategory.ENDPOINT_DETECTION) == 1.0
    assert s.weight("sandbox_verdict") == 0.9  # type: ignore[arg-type]
    assert isinstance(s.weight(SignalCategory.REPUTATION), float)


# --------------------------------------------------------------- validation --
@pytest.mark.parametrize("weights", [
    {"made_up_category": 0.5},
    {"reputation": 1.01},
    {"reputation": -0.1},
    {"reputation": float("nan")},
    {"reputation": float("inf")},
    {"reputation": "high"},
])
def test_bad_weights_are_refused(weights):
    with pytest.raises(ValidationError):
        ScoringSettings(weights=weights)


@pytest.mark.parametrize("bands", [
    {"LOW": 0, "MEDIUM": 30, "HIGH": 60},                             # missing a band
    {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80, "EXTREME": 95},  # unknown band
    {"LOW": 5, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80},             # LOW must be 0
    {"LOW": 0, "MEDIUM": 30, "HIGH": 30, "CRITICAL": 80},             # not strictly increasing
    {"LOW": 0, "MEDIUM": 60, "HIGH": 30, "CRITICAL": 80},             # wrong order
    {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 101},            # above 100
    {"low": 0, "medium": 30, "high": 60, "critical": 80},             # names are exact
])
def test_bad_bands_are_refused(bands):
    with pytest.raises(ValidationError):
        ScoringSettings(bands=bands)


def test_custom_bands_are_accepted_and_ordered():
    s = ScoringSettings(bands={"CRITICAL": 90, "LOW": 0, "HIGH": 70, "MEDIUM": 40})
    assert list(s.bands) == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@pytest.mark.parametrize("section,field", [
    ("caps", "reputation_max_contribution"), ("caps", "reputation_only_confidence_cap"),
    ("corroboration", "min"), ("corroboration", "step"), ("corroboration", "max"),
    ("confidence", "independent_source_step"), ("confidence", "independent_source_max"),
    ("confidence", "contradiction_penalty"), ("confidence", "failed_source_penalty"),
    ("confidence", "failed_source_max_penalty"), ("context", "critical_asset_bonus"),
])
@pytest.mark.parametrize("value", [-1, 101])
def test_points_must_be_in_0_100(section, field, value):
    with pytest.raises(ValidationError):
        ScoringSettings.model_validate({section: {field: value}})


@pytest.mark.parametrize("data", [
    {"caps": {"reputation_cap": 10}},
    {"corroboration": {"bonus": 5}},
    {"confidence": {"approval_bonus": 5}},
    {"context": {"auto_approve": True}},
    {"auto_approve": True},
])
def test_unknown_keys_are_refused(data):
    with pytest.raises(ValidationError):
        ScoringSettings.model_validate(data)


def test_phase0_shape_still_loads():
    t = Thresholds.model_validate({"scoring": {"bands": DEFAULT_BANDS, "weights": {}}})
    assert t.scoring == ScoringSettings()


def test_repository_thresholds_file_loads_with_contract_defaults():
    settings = load_settings(CONFIG_DIR, env={})
    s = settings.thresholds.scoring
    assert s.bands == DEFAULT_BANDS
    assert {c: s.weight(c) for c in SignalCategory} == dict(DEFAULT_WEIGHTS)
    assert s.model_dump(exclude={"weights"}) == ScoringSettings().model_dump(exclude={"weights"})


def test_thresholds_yaml_scoring_section_has_the_documented_shape():
    data = yaml.safe_load((CONFIG_DIR / "thresholds.yaml").read_text(encoding="utf-8"))["scoring"]
    assert set(data) == {"bands", "weights", "caps", "corroboration", "confidence", "context"}
    assert set(data["weights"]) == {c.value for c in SignalCategory}


# ------------------------------------------------------------------- bands --
@pytest.mark.parametrize("score,band", [
    (0, RiskBand.LOW), (29, RiskBand.LOW), (30, RiskBand.MEDIUM), (59, RiskBand.MEDIUM),
    (60, RiskBand.HIGH), (79, RiskBand.HIGH), (80, RiskBand.CRITICAL), (100, RiskBand.CRITICAL),
])
def test_band_boundaries_default_and_configured(score, band):
    assert risk_band(score) is band
    assert risk_band(score, DEFAULT_BANDS) is band
    assert risk_band(score, ScoringSettings().bands) is band


@pytest.mark.parametrize("score,band", [
    (39, RiskBand.LOW), (40, RiskBand.MEDIUM), (69, RiskBand.MEDIUM), (70, RiskBand.HIGH),
    (89, RiskBand.HIGH), (90, RiskBand.CRITICAL),
])
def test_band_boundaries_custom(score, band):
    assert risk_band(score, {"LOW": 0, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}) is band


@pytest.mark.parametrize("bands", [
    {"LOW": 0, "MEDIUM": 30, "HIGH": 60},
    {"LOW": 1, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80},
    {"LOW": 0, "MEDIUM": 60, "HIGH": 60, "CRITICAL": 80},
    {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 120},
    {"LOW": 0, "MEDIUM": 30.5, "HIGH": 60, "CRITICAL": 80},
])
def test_risk_band_refuses_bad_band_tables(bands):
    with pytest.raises(ValueError):
        risk_band(50, bands)


@pytest.mark.parametrize("bad", [-1, 101, 50.0, True, "50", None])
def test_risk_band_refuses_bad_scores_with_bands(bad):
    with pytest.raises(ValueError):
        risk_band(bad, DEFAULT_BANDS)  # type: ignore[arg-type]
