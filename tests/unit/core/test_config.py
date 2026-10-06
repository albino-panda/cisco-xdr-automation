"""Config loading, validation, env overrides and the allow-list / disclosure policies."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from xdr_response.config import (
    FORBIDDEN_KEYS,
    INTEGRATION_NAMES,
    AllowlistPolicy,
    AllowlistsConfig,
    DisclosurePolicy,
    ExclusionsConfig,
    IntegrationConfig,
    Settings,
    load_settings,
    load_yaml,
)
from xdr_response.errors import ConfigError
from xdr_response.models import ActionType, CriticalAssetClass, Observable, ObservableType, TargetKind

REPO = Path(__file__).resolve().parents[3]
CONFIG = REPO / "config"


@pytest.fixture()
def cfg_dir(tmp_path: Path) -> Path:
    d = tmp_path / "config"
    shutil.copytree(CONFIG, d)
    return d


def _edit(path: Path, mutate) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    mutate(data)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


# ------------------------------------------------------------- shipped files --
def test_shipped_config_loads_with_safe_defaults():
    s = load_settings(CONFIG, env={})
    assert s.runtime.dry_run is True
    assert set(s.integrations) == set(INTEGRATION_NAMES)
    assert s.integrations["splunk"].enabled is False
    assert s.thresholds.approval.standard_min_approvers >= 1
    assert s.thresholds.approval.elevated_min_approvers >= 1
    assert set(s.critical_assets.classes) == set(CriticalAssetClass)
    for cls in s.critical_assets.classes.values():
        assert cls.role and cls.potential_impact
    assert s.allowlists.approved_rmm and s.allowlists.approved_dns_tools
    for cfg in s.integrations.values():
        for name in cfg.secrets.values():
            assert name.isupper()


def test_settings_defaults_without_files(tmp_path: Path):
    s = load_settings(tmp_path, env={})
    assert s.runtime.dry_run is True and s.integrations["cisco_xdr"].enabled is False
    assert Settings().runtime.dry_run is True


def test_missing_config_dir_is_an_error(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "nope", env={})


def test_integrations_yaml_preferred_over_example(cfg_dir: Path):
    (cfg_dir / "integrations.yaml").write_text("runtime:\n  environment: staging\n", encoding="utf-8")
    assert load_settings(cfg_dir, env={}).runtime.environment == "staging"


# ---------------------------------------------------------------- env vars --
@pytest.mark.parametrize(("value", "expected"), [("true", True), ("FALSE", False), ("False", False), ("TRUE", True)])
def test_dry_run_env_override(cfg_dir: Path, value: str, expected: bool):
    assert load_settings(cfg_dir, env={"DRY_RUN": value}).runtime.dry_run is expected


@pytest.mark.parametrize("value", ["", "0", "no", "yes", "off"])
def test_dry_run_env_must_be_explicit(cfg_dir: Path, value: str):
    with pytest.raises(ConfigError):
        load_settings(cfg_dir, env={"DRY_RUN": value})


def test_other_env_overrides(cfg_dir: Path):
    s = load_settings(cfg_dir, env={"XDR_RESPONSE_ENVIRONMENT": "production",
                                    "XDR_RESPONSE_AUDIT_PATH": "var/x/audit.jsonl"})
    assert s.runtime.environment == "production" and s.runtime.audit_path == Path("var/x/audit.jsonl")
    with pytest.raises(ConfigError):
        load_settings(cfg_dir, env={"XDR_RESPONSE_ENVIRONMENT": "moon"})


# -------------------------------------------------------------- fail closed --
@pytest.mark.parametrize("key", sorted(FORBIDDEN_KEYS))
@pytest.mark.parametrize("file", ["thresholds.yaml", "integrations.example.yaml", "allowlists.yaml"])
def test_forbidden_keys_anywhere(cfg_dir: Path, key: str, file: str):
    def mutate(d):
        d.setdefault("nested", {})[key] = False  # even a "safe looking" value is refused
    _edit(cfg_dir / file, mutate)
    with pytest.raises(ConfigError, match="forbidden key"):
        load_settings(cfg_dir, env={})


def test_approval_required_refused_even_when_true(cfg_dir: Path):
    _edit(cfg_dir / "thresholds.yaml", lambda d: d["approval"].__setitem__("approval_required", True))
    with pytest.raises(ConfigError):
        load_settings(cfg_dir, env={})


def test_secret_values_refused_and_not_echoed(cfg_dir: Path):
    fake = "zz-not-a-name-but-a-value-1234"
    _edit(cfg_dir / "integrations.example.yaml",
          lambda d: d["integrations"]["cisco_xdr"]["secrets"].__setitem__("client_secret", fake))
    with pytest.raises(ConfigError) as exc:
        load_settings(cfg_dir, env={})
    assert fake not in str(exc.value)


def test_secret_value_under_sensitive_key_outside_secrets_refused(cfg_dir: Path):
    fake = "plaintext-password-value"
    _edit(cfg_dir / "integrations.example.yaml",
          lambda d: d["integrations"]["meraki"]["options"].__setitem__("password", fake))
    with pytest.raises(ConfigError) as exc:
        load_settings(cfg_dir, env={})
    assert fake not in str(exc.value)


@pytest.mark.parametrize("field", ["standard_min_approvers", "elevated_min_approvers"])
def test_min_approvers_at_least_one(cfg_dir: Path, field: str):
    _edit(cfg_dir / "thresholds.yaml", lambda d: d["approval"].__setitem__(field, 0))
    with pytest.raises(ConfigError, match=field):
        load_settings(cfg_dir, env={})


def test_unknown_integration_and_keys_refused(cfg_dir: Path):
    _edit(cfg_dir / "integrations.example.yaml", lambda d: d["integrations"].__setitem__("cloudflare", {}))
    with pytest.raises(ConfigError, match="unknown integrations"):
        load_settings(cfg_dir, env={})


def test_unknown_threshold_key_refused(cfg_dir: Path):
    _edit(cfg_dir / "thresholds.yaml", lambda d: d["approval"].__setitem__("auto_release", True))
    with pytest.raises(ConfigError):
        load_settings(cfg_dir, env={})


def test_invalid_yaml(cfg_dir: Path):
    (cfg_dir / "allowlists.yaml").write_text("never_block: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_yaml(cfg_dir / "allowlists.yaml")


def test_integration_config_rules():
    with pytest.raises(ValueError):
        IntegrationConfig(secrets={"api_key": "lowercase-value"})
    with pytest.raises(ValueError):
        IntegrationConfig(base_url="http://insecure.example.com")
    with pytest.raises(ValueError):
        IntegrationConfig(base_url="https://user:pw@api.example.com")
    assert IntegrationConfig().enabled is False


# ---------------------------------------------------------------- policies --
@pytest.fixture()
def allow() -> AllowlistPolicy:
    return AllowlistPolicy(load_settings(CONFIG, env={}).allowlists)


def test_allowlist_domains_and_urls(allow: AllowlistPolicy):
    assert allow.excluded_reason(ActionType.BLOCK_DOMAIN, "www.example.com", TargetKind.DOMAIN) == \
        "allowlists.never_block.domains: example.com"
    assert allow.excluded_reason(ActionType.BLOCK_DOMAIN, "bad.example.test", TargetKind.DOMAIN) is None
    # URL-level block allowed on an owned domain
    assert allow.excluded_reason(ActionType.BLOCK_URL, "https://www.example.com/phish", TargetKind.URL) is None
    assert allow.excluded_reason(ActionType.BLOCK_URL, "https://login.microsoft.com/x", TargetKind.URL)
    assert allow.excluded_reason(ActionType.BLOCK_DOMAIN, "rmm.example.net", TargetKind.DOMAIN) == \
        "allowlists.approved_rmm: Example RMM"


def test_allowlist_ips_hashes_users_endpoints(allow: AllowlistPolicy):
    assert allow.excluded_reason(ActionType.BLOCK_IP, "192.0.2.53", TargetKind.IP)
    assert allow.excluded_reason(ActionType.BLOCK_IP, "192.0.2.5", TargetKind.IP) == \
        "allowlists.never_block.cidrs: 192.0.2.0/28"
    assert allow.excluded_reason(ActionType.BLOCK_IP, "203.0.113.10", TargetKind.IP) is None
    assert allow.excluded_reason(ActionType.BLOCK_HASH, "1" * 64, TargetKind.HASH) == \
        "allowlists.approved_rmm: Example RMM"
    assert allow.excluded_reason(ActionType.BLOCK_HASH, "2" * 64, TargetKind.HASH) == \
        "allowlists.approved_dns_tools: Example DNS diagnostics"
    assert allow.excluded_reason(ActionType.DISABLE_USER, "BreakGlass@example.com", TargetKind.USER)
    assert allow.excluded_reason(ActionType.ISOLATE_ENDPOINT, "th-dc-01", TargetKind.ENDPOINT)
    assert allow.excluded_reason(ActionType.QUARANTINE_FILE, "TH-LT-1047/" + "1" * 64, TargetKind.FILE)
    # restoration is never blocked by the allow-list
    assert allow.excluded_reason(ActionType.UNBLOCK_DOMAIN, "example.com", TargetKind.DOMAIN) is None


def test_allowlist_config_validation():
    with pytest.raises(ValueError):
        AllowlistsConfig(never_block={"everything": ["*"]})
    with pytest.raises(ValueError):
        AllowlistsConfig(never_block={"cidrs": ["not-a-cidr"]})
    with pytest.raises(ValueError):
        AllowlistsConfig(approved_rmm=[{"name": "x", "hashes": ["xyz"]}])
    cfg = AllowlistsConfig.model_validate({"approved_rmm_allowlist": [{"name": "Alias RMM"}]})
    assert cfg.approved_rmm[0]["name"] == "Alias RMM"


def test_disclosure_policy():
    s = load_settings(CONFIG, env={})
    policy = DisclosurePolicy(s.exclusions)
    obs = lambda t, v: Observable(type=t, value=v)  # noqa: E731
    assert policy.may_disclose(obs(ObservableType.SHA256, "a" * 64), "virustotal")
    assert policy.may_disclose(obs(ObservableType.DOMAIN, "bad.example.test"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.DOMAIN, "host.corp.example.com"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.DOMAIN, "fileserver"), "alienvault_otx")
    assert not policy.may_disclose(obs(ObservableType.DOMAIN, "printer.local"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.IP, "10.1.2.3"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.IP, "100.64.1.1"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.IP, "203.0.113.10"), "virustotal")  # documentation range
    assert DisclosurePolicy(s.exclusions, allow_documentation_ranges=True).may_disclose(
        obs(ObservableType.IP, "203.0.113.10"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.HOSTNAME, "TH-LT-1047"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.FILE_PATH, "C:\\Users\\x\\a.ps1"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.EMAIL_MESSAGE_ID, "<m@example.com>"), "virustotal")
    assert not policy.may_disclose(obs(ObservableType.URL, "https://intranet.corp.example.com/x"), "virustotal")
    # HIBP only receives email addresses, and not from excluded user domains
    assert policy.may_disclose(obs(ObservableType.EMAIL_ADDRESS, "j.doe@example.com"), "hibp")
    assert not policy.may_disclose(obs(ObservableType.EMAIL_ADDRESS, "x@partner.example.net"), "hibp")
    assert not policy.may_disclose(obs(ObservableType.DOMAIN, "bad.example.test"), "hibp")
    assert not policy.may_disclose(obs(ObservableType.EMAIL_ADDRESS, "j.doe@example.com"), "virustotal")
    # internal tools are not third parties
    assert policy.may_disclose(obs(ObservableType.HOSTNAME, "TH-LT-1047"), "cisco_xdr")
    assert ExclusionsConfig().internal_domains == []
