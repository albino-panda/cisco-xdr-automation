"""Typed configuration loading and validation (``config/*.yaml``)."""
from __future__ import annotations

from xdr_response.config.loader import FORBIDDEN_KEYS, load_settings, load_yaml, parse_bool
from xdr_response.config.policy import (
    DOCUMENTATION_NETWORKS,
    THIRD_PARTY_INTEGRATIONS,
    AllowlistPolicy,
    DisclosurePolicy,
)
from xdr_response.config.schema import (
    INTEGRATION_NAMES,
    SECRET_NAME_PATTERN,
    AllowlistsConfig,
    ApprovalSettings,
    AssetMatch,
    BlastRadiusSettings,
    CriticalAssetClassConfig,
    CriticalAssetsConfig,
    ExclusionsConfig,
    IntegrationConfig,
    RuntimeSettings,
    ScoringSettings,
    Settings,
    TemporaryControlSettings,
    Thresholds,
    VerificationSettings,
)

__all__ = [
    "FORBIDDEN_KEYS", "load_settings", "load_yaml", "parse_bool",
    "AllowlistPolicy", "DisclosurePolicy", "THIRD_PARTY_INTEGRATIONS", "DOCUMENTATION_NETWORKS",
    "INTEGRATION_NAMES", "SECRET_NAME_PATTERN", "AllowlistsConfig", "ApprovalSettings", "AssetMatch",
    "BlastRadiusSettings", "CriticalAssetClassConfig", "CriticalAssetsConfig", "ExclusionsConfig",
    "IntegrationConfig", "RuntimeSettings", "ScoringSettings", "Settings", "TemporaryControlSettings",
    "Thresholds", "VerificationSettings",
]
