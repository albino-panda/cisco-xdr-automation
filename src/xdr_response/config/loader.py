"""Load and validate the YAML configuration in ``config/`` (architecture section 13.11).

Fail closed: any approval-bypass key, any secret value written into config, any unknown key or
integration, or any invalid threshold raises :class:`ConfigError`. Error messages name the path
of the offending key and never echo its value.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from xdr_response.config.schema import (
    INTEGRATION_NAMES,
    SECRET_NAME_PATTERN,
    AllowlistsConfig,
    CriticalAssetsConfig,
    ExclusionsConfig,
    Settings,
    Thresholds,
)
from xdr_response.errors import ConfigError
from xdr_response.logs.redaction import Redactor

__all__ = [
    "FORBIDDEN_KEYS",
    "SECRET_NAME_PATTERN",
    "INTEGRATION_NAMES",
    "CONFIG_FILES",
    "load_settings",
    "load_yaml",
    "parse_bool",
]

FORBIDDEN_KEYS = frozenset({"auto_approve", "skip_approval", "bypass_approval", "approval_required"})
_SECRET_NAME_RE = re.compile(SECRET_NAME_PATTERN)
_KEY_CHECKER = Redactor()  # only used for is_sensitive_key (no registered values)

CONFIG_FILES = {
    "integrations": ("integrations.yaml", "integrations.example.yaml"),
    "thresholds": ("thresholds.yaml",),
    "exclusions": ("exclusions.yaml",),
    "critical_assets": ("critical-assets.yaml",),
    "allowlists": ("allowlists.yaml",),
}


def load_yaml(path: Path) -> dict[str, Any]:
    """``yaml.safe_load`` a file; empty files give ``{}``; parse errors raise ConfigError."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {getattr(exc, 'problem', None) or 'parse error'}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def parse_bool(name: str, value: str) -> bool:
    v = value.strip().lower()
    if v == "true":
        return True
    if v == "false":
        return False
    raise ConfigError(f'environment variable {name} must be "true" or "false"')


def _scan(node: Any, path: str, source: str) -> None:
    """Recursive safety scan: forbidden keys anywhere, sensitive keys only hold secret NAMES."""
    if isinstance(node, Mapping):
        for k, v in node.items():
            key = str(k)
            here = f"{path}.{key}" if path else key
            if key.strip().lower() in FORBIDDEN_KEYS:
                raise ConfigError(
                    f"{source}: forbidden key {here!r}: approval can never be disabled or automated by config"
                )
            if _KEY_CHECKER.is_sensitive_key(key):
                if v is None:
                    continue
                if not isinstance(v, str) or not _SECRET_NAME_RE.match(v):
                    raise ConfigError(
                        f"{source}: {here!r} must name a secret (pattern {SECRET_NAME_PATTERN}); "
                        "secret values are never allowed in config files"
                    )
                continue
            _scan(v, here, source)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _scan(item, f"{path}[{i}]", source)


def _format_validation(exc: ValidationError, source: str) -> ConfigError:
    parts = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(p) for p in err.get("loc", ()))
        parts.append(f"{loc}: {err.get('msg', 'invalid')}")
    return ConfigError(f"{source}: " + "; ".join(parts))


def _read(config_dir: Path, key: str) -> tuple[dict[str, Any], str]:
    for filename in CONFIG_FILES[key]:
        path = config_dir / filename
        if path.is_file():
            data = load_yaml(path)
            _scan(data, "", filename)
            return data, filename
    return {}, CONFIG_FILES[key][0]


def load_settings(config_dir: Path | str = "config", *, env: Mapping[str, str] | None = None) -> Settings:
    """Load every config file from ``config_dir`` and apply environment overrides.

    Env overrides: ``DRY_RUN`` ("true"/"false"), ``XDR_RESPONSE_ENVIRONMENT``,
    ``XDR_RESPONSE_AUDIT_PATH``, ``XDR_RESPONSE_REGISTRY_PATH``, ``XDR_RESPONSE_TOKEN_LEDGER_PATH``.
    """
    environ = os.environ if env is None else env
    config_dir = Path(config_dir)
    if not config_dir.is_dir():
        raise ConfigError(f"config directory not found: {config_dir}")

    integ, integ_src = _read(config_dir, "integrations")
    unknown_top = set(integ) - {"runtime", "integrations"}
    if unknown_top:
        raise ConfigError(f"{integ_src}: unknown top-level keys {sorted(unknown_top)}")
    integrations = integ.get("integrations") or {}
    if not isinstance(integrations, dict):
        raise ConfigError(f"{integ_src}: integrations must be a mapping")
    unknown = set(integrations) - set(INTEGRATION_NAMES)
    if unknown:
        raise ConfigError(f"{integ_src}: unknown integrations {sorted(unknown)}")
    runtime = dict(integ.get("runtime") or {})

    if "DRY_RUN" in environ:
        runtime["dry_run"] = parse_bool("DRY_RUN", environ["DRY_RUN"])
    if environ.get("XDR_RESPONSE_ENVIRONMENT"):
        runtime["environment"] = environ["XDR_RESPONSE_ENVIRONMENT"]
    if environ.get("XDR_RESPONSE_AUDIT_PATH"):
        runtime["audit_path"] = environ["XDR_RESPONSE_AUDIT_PATH"]
    if environ.get("XDR_RESPONSE_REGISTRY_PATH"):
        runtime["registry_path"] = environ["XDR_RESPONSE_REGISTRY_PATH"]
    if environ.get("XDR_RESPONSE_TOKEN_LEDGER_PATH"):
        runtime["token_ledger_path"] = environ["XDR_RESPONSE_TOKEN_LEDGER_PATH"]

    sections: dict[str, Any] = {"runtime": runtime, "integrations": integrations}
    for key, model in (("thresholds", Thresholds), ("exclusions", ExclusionsConfig),
                       ("critical_assets", CriticalAssetsConfig), ("allowlists", AllowlistsConfig)):
        data, src = _read(config_dir, key)
        try:
            sections[key] = model.model_validate(data)
        except ValidationError as exc:
            raise _format_validation(exc, src) from None
    try:
        return Settings.model_validate(sections)
    except ValidationError as exc:
        raise _format_validation(exc, integ_src) from None
