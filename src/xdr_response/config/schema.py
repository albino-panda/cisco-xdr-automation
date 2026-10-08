"""Typed configuration (architecture section 13.11). ``extra="forbid"`` everywhere."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from xdr_response.logs.redaction import Redactor
from xdr_response.models.catalog import INTEGRATION_NAMES, ActionType
from xdr_response.models.enums import CriticalAssetClass, RiskBand
from xdr_response.models.scoring import DEFAULT_WEIGHTS, SignalCategory

__all__ = [
    "INTEGRATION_NAMES",
    "SECRET_NAME_PATTERN",
    "NEVER_BLOCK_KEYS",
    "RuntimeSettings",
    "IntegrationConfig",
    "ApprovalSettings",
    "BlastRadiusSettings",
    "VerificationSettings",
    "TemporaryControlSettings",
    "ScoringCaps",
    "CorroborationSettings",
    "ConfidenceSettings",
    "ScoringContextSettings",
    "ScoringSettings",
    "Thresholds",
    "AssetMatch",
    "CriticalAssetClassConfig",
    "CriticalAssetsConfig",
    "AllowlistsConfig",
    "ExclusionsConfig",
    "Settings",
]

SECRET_NAME_PATTERN = r"^[A-Z][A-Z0-9_]*$"
_SECRET_NAME_RE = re.compile(SECRET_NAME_PATTERN)
NEVER_BLOCK_KEYS = frozenset({"domains", "urls", "ips", "cidrs", "hashes", "users", "endpoints"})
_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_KEY_CHECKER = Redactor()  # only used for is_sensitive_key (no registered values)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _check_cidrs(values: list[str]) -> list[str]:
    for v in values:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR {v!r}") from exc
    return values


def _check_hashes(values: list[str]) -> list[str]:
    for v in values:
        if not isinstance(v, str) or not _HASH_RE.match(v):
            raise ValueError(f"invalid hash {v!r} (expected MD5, SHA-1 or SHA-256 hex)")
    return [v.lower() for v in values]


class RuntimeSettings(_Model):
    dry_run: bool = True
    environment: Literal["lab", "staging", "production"] = "lab"
    audit_path: Path = Path("var/audit/audit.jsonl")
    registry_path: Path = Path("var/registry/controls.jsonl")
    token_ledger_path: Path = Path("var/approval/token-ledger.jsonl")


class IntegrationConfig(_Model):
    enabled: bool = False
    base_url: str | None = None
    region: str | None = None
    timeout_seconds: float = Field(default=15.0, gt=0, le=600)
    max_retries: int = Field(default=3, ge=0, le=10)
    backoff_base_seconds: float = Field(default=1.0, ge=0)
    backoff_max_seconds: float = Field(default=30.0, ge=0)
    rate_limit_per_minute: int | None = Field(default=None, ge=1)
    secrets: dict[str, str] = {}  # logical name -> secret NAME (env var), never a value
    options: dict[str, Any] = {}

    @field_validator("secrets")
    @classmethod
    def _names_only(cls, value: dict[str, str]) -> dict[str, str]:
        for logical, name in value.items():
            if not isinstance(name, str) or not _SECRET_NAME_RE.match(name):
                raise ValueError(
                    f"secrets.{logical} must be a secret NAME matching {SECRET_NAME_PATTERN}, not a value"
                )
        return value

    @field_validator("base_url")
    @classmethod
    def _https(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ValueError("base_url must use https://")
        if value is not None and "@" in value.split("//", 1)[-1].split("/", 1)[0]:
            raise ValueError("base_url must not contain credentials")
        if value is not None:
            try:
                parts = urlsplit(value)
            except ValueError:
                raise ValueError("base_url is not a valid URL") from None
            for raw in (parts.query, parts.fragment):
                for name, _ in parse_qsl(raw, keep_blank_values=True):
                    if _KEY_CHECKER.is_sensitive_key(name):
                        # never echo the value: it is a literal secret in a config file
                        raise ValueError(
                            f"base_url must not carry the secret-bearing query parameter {name!r}; "
                            "configure secrets by NAME under 'secrets:'")
        return value


class ApprovalSettings(_Model):
    signing_key_id: str = Field(default="primary", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    # key id of APPROVAL_SIGNING_KEY_PREVIOUS after a rotation that changed the key id (optional)
    previous_signing_key_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    containment_token_ttl_minutes: int = Field(default=30, ge=1, le=24 * 60)
    release_token_ttl_minutes: int = Field(default=30, ge=1, le=24 * 60)
    package_ttl_minutes: int = Field(default=240, ge=1)
    standard_role: str = Field(default="xdr-approver", min_length=1)
    elevated_role: str = Field(default="xdr-elevated-approver", min_length=1)
    standard_min_approvers: int = Field(default=1, ge=1)
    elevated_min_approvers: int = Field(default=1, ge=1)
    allow_self_approval: bool = False
    clock_skew_seconds: int = Field(default=60, ge=0, le=600)

    @model_validator(mode="after")
    def _distinct_roles(self) -> "ApprovalSettings":
        if self.elevated_role.strip().lower() == self.standard_role.strip().lower():
            raise ValueError(
                "elevated_role must differ from standard_role: otherwise ELEVATED (critical-asset) "
                "approval collapses into STANDARD approval")
        return self


class BlastRadiusSettings(_Model):
    max_endpoints: int = Field(default=5, ge=0)
    max_users: int = Field(default=3, ge=0)
    max_indicators: int = Field(default=50, ge=0)
    max_messages: int = Field(default=500, ge=0)


class VerificationSettings(_Model):
    poll_interval_seconds: float = Field(default=10.0, ge=0)
    timeout_seconds: float = Field(default=300.0, ge=0)
    unable_to_verify_counts_as_contained: bool = False


class TemporaryControlSettings(_Model):
    review_after_hours: dict[str, int] = {}  # action_type value -> hours; reminder only

    @field_validator("review_after_hours")
    @classmethod
    def _known_types(cls, value: dict[str, int]) -> dict[str, int]:
        for k, hours in value.items():
            try:
                ActionType(k)
            except ValueError as exc:
                raise ValueError(f"unknown action type {k!r} in review_after_hours") from exc
            if hours < 1:
                raise ValueError("review_after_hours values must be >= 1")
        return value


_Points = Annotated[int, Field(ge=0, le=100)]
_Weight = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
_BAND_ORDER: tuple[str, ...] = tuple(b.value for b in RiskBand)


class ScoringCaps(_Model):
    """Reputation caps (docs/threat-scoring.md 5.1 step 3 and 5.2 step 2). Never overridable by workflows."""

    reputation_max_contribution: _Points = 50
    reputation_only_confidence_cap: _Points = 50


class CorroborationSettings(_Model):
    """Risk bonus for other categories at or above ``min`` (5.1 step 5)."""

    min: _Points = 30
    step: _Points = 5
    max: _Points = 15


class ConfidenceSettings(_Model):
    """Confidence bonus and penalties (5.2 steps 3 to 5)."""

    independent_source_step: _Points = 5
    independent_source_max: _Points = 20
    contradiction_penalty: _Points = 15
    failed_source_penalty: _Points = 5
    failed_source_max_penalty: _Points = 20


class ScoringContextSettings(_Model):
    """Context bonuses (5.1 step 7)."""

    critical_asset_bonus: _Points = 10


class ScoringSettings(_Model):
    """``thresholds.yaml`` ``scoring:`` (architecture 14.2.4)."""

    bands: dict[str, int] = {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}
    weights: dict[SignalCategory, _Weight] = {}  # missing categories use DEFAULT_WEIGHTS
    caps: ScoringCaps = ScoringCaps()
    corroboration: CorroborationSettings = CorroborationSettings()
    confidence: ConfidenceSettings = ConfidenceSettings()
    context: ScoringContextSettings = ScoringContextSettings()

    @field_validator("bands")
    @classmethod
    def _bands(cls, value: dict[str, int]) -> dict[str, int]:
        if set(value) != set(_BAND_ORDER):
            raise ValueError(f"scoring.bands must name exactly {list(_BAND_ORDER)}, got {sorted(value)}")
        bounds = [value[name] for name in _BAND_ORDER]
        if bounds[0] != 0:
            raise ValueError("scoring.bands.LOW must be 0")
        if any(upper <= lower for lower, upper in zip(bounds, bounds[1:])):
            raise ValueError(f"scoring.bands must be strictly increasing in order {list(_BAND_ORDER)}")
        if bounds[-1] > 100:
            raise ValueError("scoring.bands values must be <= 100")
        return {name: value[name] for name in _BAND_ORDER}

    def weight(self, category: SignalCategory) -> float:
        """Configured weight of ``category``, or its DEFAULT_WEIGHTS value."""
        category = SignalCategory(category)
        return float(self.weights.get(category, DEFAULT_WEIGHTS[category]))


class Thresholds(_Model):
    scoring: ScoringSettings = ScoringSettings()
    blast_radius: BlastRadiusSettings = BlastRadiusSettings()
    approval: ApprovalSettings = ApprovalSettings()
    verification: VerificationSettings = VerificationSettings()
    temporary_controls: TemporaryControlSettings = TemporaryControlSettings()


class AssetMatch(_Model):
    hostnames: list[str] = []  # exact, case-insensitive
    hostname_patterns: list[str] = []  # fnmatch, case-insensitive
    users: list[str] = []
    user_patterns: list[str] = []
    groups: list[str] = []
    tags: list[str] = []
    roles: list[str] = []  # directory roles (Asset.roles, e.g. "Global Administrator"), case-insensitive
    ip_cidrs: list[str] = []

    @field_validator("ip_cidrs")
    @classmethod
    def _cidrs(cls, value: list[str]) -> list[str]:
        return _check_cidrs(value)


class CriticalAssetClassConfig(_Model):
    display_name: str = Field(min_length=1)
    role: str = Field(min_length=1)
    potential_impact: str = Field(min_length=1)
    match: AssetMatch = AssetMatch()


class CriticalAssetsConfig(_Model):
    classes: dict[CriticalAssetClass, CriticalAssetClassConfig] = {}


class AllowlistsConfig(_Model):
    never_block: dict[str, list[str]] = {}  # keys: domains, urls, ips, cidrs, hashes, users, endpoints
    url_block_allowed_domains: list[str] = []  # owned domains where URL-level blocks are allowed
    approved_rmm: list[dict[str, Any]] = Field(
        default=[], validation_alias=AliasChoices("approved_rmm", "approved_rmm_allowlist")
    )  # {name, hashes, domains, signers}
    approved_dns_tools: list[dict[str, Any]] = []  # {name, hashes, domains, signers}

    @field_validator("never_block")
    @classmethod
    def _never_block(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        unknown = set(value) - NEVER_BLOCK_KEYS
        if unknown:
            raise ValueError(f"unknown never_block keys {sorted(unknown)}; allowed {sorted(NEVER_BLOCK_KEYS)}")
        if "cidrs" in value:
            _check_cidrs(value["cidrs"])
        if "ips" in value:
            for ip in value["ips"]:
                ipaddress.ip_address(ip)
        if "hashes" in value:
            value = {**value, "hashes": _check_hashes(value["hashes"])}
        return value

    @field_validator("approved_rmm", "approved_dns_tools")
    @classmethod
    def _tools(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        allowed = {"name", "hashes", "domains", "signers", "notes"}
        for entry in value:
            if not isinstance(entry.get("name"), str) or not entry["name"]:
                raise ValueError("every approved tool needs a name")
            unknown = set(entry) - allowed
            if unknown:
                raise ValueError(f"unknown keys {sorted(unknown)} in approved tool {entry['name']!r}")
            _check_hashes(list(entry.get("hashes", []) or []))
        return value


class ExclusionsConfig(_Model):
    third_party_lookup: dict[str, list[str]] = {}  # internal_domain_suffixes, cidrs, user_domains, hostnames
    internal_domains: list[str] = []

    @field_validator("third_party_lookup")
    @classmethod
    def _keys(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        allowed = {"internal_domain_suffixes", "cidrs", "user_domains", "hostnames"}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown third_party_lookup keys {sorted(unknown)}; allowed {sorted(allowed)}")
        if "cidrs" in value:
            _check_cidrs(value["cidrs"])
        return value


class Settings(_Model):
    runtime: RuntimeSettings = RuntimeSettings()
    integrations: dict[str, IntegrationConfig] = {}
    thresholds: Thresholds = Thresholds()
    critical_assets: CriticalAssetsConfig = CriticalAssetsConfig()
    allowlists: AllowlistsConfig = AllowlistsConfig()
    exclusions: ExclusionsConfig = ExclusionsConfig()

    @field_validator("integrations")
    @classmethod
    def _known(cls, value: dict[str, IntegrationConfig]) -> dict[str, IntegrationConfig]:
        unknown = set(value) - set(INTEGRATION_NAMES)
        if unknown:
            raise ValueError(f"unknown integrations {sorted(unknown)}; known: {list(INTEGRATION_NAMES)}")
        return value

    @model_validator(mode="after")
    def _fill(self) -> "Settings":
        for name in INTEGRATION_NAMES:
            if name not in self.integrations:
                self.integrations[name] = IntegrationConfig()
        return self

    def integration(self, name: str) -> IntegrationConfig:
        """Config for ``name`` (KeyError for unknown integrations)."""
        if name not in INTEGRATION_NAMES:
            raise KeyError(name)
        return self.integrations.get(name) or IntegrationConfig()
