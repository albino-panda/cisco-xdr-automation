"""Global dry-run switch: resolution from config/env, guard configuration and the guard lock."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.factories import make_recommendation
from tests.fixtures.guard_helpers import install_fake_verifier, make_token
from xdr_response import guard
from xdr_response.config import load_settings
from xdr_response.config.schema import RuntimeSettings, Settings
from xdr_response.dryrun import apply_global_dry_run, dry_run_scope, is_dry_run, resolve_dry_run
from xdr_response.errors import ConfigError, DryRunViolationError
from xdr_response.models import ActionRequest

REPO_CONFIG = Path(__file__).resolve().parents[3] / "config"


def _settings(dry_run: bool) -> Settings:
    return Settings(runtime=RuntimeSettings(dry_run=dry_run))


def _request() -> ActionRequest:
    return ActionRequest.from_recommendation(make_recommendation())


@pytest.mark.parametrize(
    ("settings", "env", "force", "expected"),
    [
        (None, {}, False, True),                              # nothing configured: fail safe
        (_settings(False), {}, False, False),
        (_settings(True), {}, False, True),
        (_settings(False), {"DRY_RUN": "TRUE"}, False, True),  # env wins, case-insensitive
        (_settings(True), {"DRY_RUN": "false"}, False, False),
        (_settings(False), {"DRY_RUN": "false"}, True, True),  # per-run force only switches ON
    ],
)
def test_resolution_precedence(settings: Settings | None, env: dict[str, str], force: bool,
                               expected: bool) -> None:
    assert resolve_dry_run(settings, env=env, force=force) is expected


@pytest.mark.parametrize("value", ["yes", "1", "", "off"])
def test_invalid_env_value_is_a_config_error(value: str) -> None:
    with pytest.raises(ConfigError, match="DRY_RUN"):
        resolve_dry_run(_settings(False), env={"DRY_RUN": value})


def test_example_config_defaults_to_dry_run() -> None:
    settings = load_settings(REPO_CONFIG, env={})
    assert resolve_dry_run(settings, env={}) is True


def test_apply_sets_the_guard_switch() -> None:
    assert apply_global_dry_run(_settings(False), env={}) is False
    assert guard.is_dry_run() is False and is_dry_run() is False
    assert apply_global_dry_run(_settings(False), env={"DRY_RUN": "true"}) is True
    assert guard.is_dry_run() is True


def test_dry_run_switch_makes_the_guard_refuse_valid_tokens() -> None:
    install_fake_verifier()
    request = _request()
    apply_global_dry_run(_settings(True), env={})
    with pytest.raises(DryRunViolationError):
        with guard.authorized(make_token(request), request):
            pass  # pragma: no cover


def test_scope_locks_the_guard_against_configure_false() -> None:
    install_fake_verifier()
    request = _request()
    with dry_run_scope(_settings(True), env={}) as active:
        assert active is True
        guard.configure(dry_run=False)            # an attempt to unlock inside the scope
        assert guard.is_dry_run() is True
        with pytest.raises(DryRunViolationError):
            with guard.authorized(make_token(request), request):
                pass  # pragma: no cover
    assert guard.is_dry_run() is False            # the per-run lock ends with the scope


def test_scope_with_force_locks_even_when_config_says_live() -> None:
    install_fake_verifier()
    with dry_run_scope(_settings(False), env={}, force=True) as active:
        assert active is True and guard.is_dry_run() is True


def test_scope_never_switches_dry_run_off() -> None:
    assert guard.is_dry_run() is True             # fail-closed default
    with dry_run_scope(_settings(False), env={}) as active:
        assert active is True                     # reports the guard state, which stays ON
        assert guard.is_dry_run() is True
