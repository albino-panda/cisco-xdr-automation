"""Guardrail checks of the legacy plan engine after Phase 1 (architecture 14.4.1, C2, C3, url allow-list)."""
from __future__ import annotations

import pytest

from xdr_plan.guardrails import (
    CHECKS,
    ELEVATED_PROTECTED,
    LEGACY_FORBIDDEN_KEYS,
    find_forbidden_keys,
    host_protected,
    ip_check,
    url_check,
    user_protected,
)
from xdr_plan.repo import load_guardrails
from xdr_response.config.loader import FORBIDDEN_KEYS

G = load_guardrails()


def test_legacy_forbidden_keys_equal_runtime_forbidden_keys():
    assert LEGACY_FORBIDDEN_KEYS == FORBIDDEN_KEYS


@pytest.mark.parametrize("data, expected", [
    ({"auto_approve": {"x": True}}, ["auto_approve"]),
    ({"a": {"b": [{"skip_approval": 1}]}}, ["a.b[0].skip_approval"]),
    ({"a": [{"ok": 1}, {" Bypass_Approval ": True}]}, ["a[1]. Bypass_Approval "]),
    ({"approval_required": False, "nested": {"approval_required": True}}, ["approval_required", "nested.approval_required"]),
    ({"protected": {"hosts": ["dc-*"]}}, []),
    (["auto_approve"], []),  # a value, not a key
])
def test_find_forbidden_keys_at_any_depth(data, expected):
    assert find_forbidden_keys(data) == expected


@pytest.mark.parametrize("target, item", [
    ("dc-01", None),                                   # glob on the target
    ("0f3c2a10-guid", {"host": "HV-ESX-02"}),          # glob on a host field, case-insensitive
    ("guid-ot", {"ip": "10.0.10.25"}),                 # CIDR on the ip field
    ("ws-01", {"is_protected": True}),                 # investigation flag
])
def test_protected_host_is_elevated_not_skipped(target, item):
    assert host_protected(target, item, G) == ELEVATED_PROTECTED


def test_unprotected_host_passes():
    assert host_protected("ws-01", {"host": "ws-01", "ip": "10.1.2.3"}, G) is None


@pytest.mark.parametrize("target, item", [
    ("breakglass-01@example.com", None),
    ("jsmith@example.com", {"profile": {"groups": ["domain admins"]}}),
    ("jsmith@example.com", {"is_protected": True}),
])
def test_protected_user_is_elevated_not_skipped(target, item):
    assert user_protected(target, item, G) == ELEVATED_PROTECTED


def test_unprotected_user_passes():
    assert user_protected("jsmith@example.com", {"profile": {"groups": ["Finance"]}}, G) is None


def test_no_check_returns_a_removed_status():
    assert {"isolate-endpoint", "disable-user", "revoke-session"} <= set(CHECKS)
    assert CHECKS["revoke-session"] is user_protected


def test_url_on_allowlisted_domain_is_skipped():
    assert url_check("https://share.example.com/x/payload", None, G) == "skipped_allowlisted"


def test_url_block_allowed_domain_is_still_planned():
    g = load_guardrails({"allowlist": {"url_block_allowed_domains": ["share.example.com"]}})
    assert url_check("https://share.example.com/x/payload", None, g) is None
    assert url_check("https://intranet.example.com/x", None, g) == "skipped_allowlisted"


def test_url_off_allowlist_is_planned():
    assert url_check("https://invoice-portal.example/login", None, G) is None


@pytest.mark.parametrize("ip, expected", [
    ("203.0.113.7", None),
    ("10.1.2.3", "skipped_internal"),
    ("127.0.0.1", "skipped_internal"),
])
def test_ip_check_unchanged(ip, expected):
    assert ip_check(ip, None, G) == expected


def test_ip_check_rejects_non_ip():
    with pytest.raises(ValueError, match="not an IP"):
        ip_check("bad.example", None, G)
