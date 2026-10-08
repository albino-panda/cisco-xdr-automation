"""Unit tests of the Phase 1 round 2 hardening helpers (architecture 14.9.7). Fake data only."""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from xdr_response.approval.critical_assets import CriticalAssetPolicy, find_incident_asset
from xdr_response.atomics.records import PRIVILEGED_ROLE_NAMES
from xdr_response.config import load_settings
from xdr_response.config.policy import embedded_ipv4, ends_in_number, host_ip, parse_ipv4_literal
from xdr_response.models import ActionType, Asset, CriticalAssetClass, TargetKind

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"


@pytest.fixture(scope="module")
def policy() -> CriticalAssetPolicy:
    return CriticalAssetPolicy(load_settings(CONFIG_DIR, env={}).critical_assets)


def test_config_lists_every_privileged_directory_role(policy):
    for role in sorted(PRIVILEGED_ROLE_NAMES):
        asset = Asset(name="jdoe@example.com", kind=TargetKind.USER, roles=(role.upper(),))
        assert CriticalAssetClass.PRIVILEGED_ACCOUNT in policy.classify("jdoe@example.com", TargetKind.USER, asset)


def test_an_ordinary_user_is_not_critical(policy):
    asset = Asset(name="jdoe@example.com", kind=TargetKind.USER, roles=("Reports Reader",))
    assert policy.evaluate(ActionType.DISABLE_USER, "jdoe@example.com", TargetKind.USER, asset) == []


@pytest.mark.parametrize("target", ["::ffff:203.0.113.10", "64:ff9b::cb00:710a", "::ffff:0:cb00:710a"])
def test_ipv6_forms_of_a_critical_ipv4_match(policy, target):
    assert CriticalAssetClass.PRODUCTION_SERVER in policy.classify(target, TargetKind.IP)


def test_incident_asset_found_by_ip_for_an_ip_named_endpoint():
    dc = Asset(name="TH-SRV-2000", kind=TargetKind.ENDPOINT, groups=("Domain Controllers",), ip="198.51.100.20")
    other = Asset(name="198.51.100.20", kind=TargetKind.ENDPOINT, tags=("server",))
    found = find_incident_asset((dc, other), "198.51.100.20", TargetKind.ENDPOINT)
    assert found is not None and set(found.groups) == {"Domain Controllers"} and set(found.tags) == {"server"}
    assert find_incident_asset((dc,), "198.51.100.21", TargetKind.ENDPOINT) is None
    assert find_incident_asset((dc,), "198.51.100.20", TargetKind.USER) is None


@pytest.mark.parametrize(("host", "expected"), [
    ("10.1.2.3.", "10.1.2.3"), ("10.0.258", "10.0.1.2"), ("0x0a.0.0.1", "10.0.0.1"),
    ("10.1.2.03", "10.1.2.3"), ("127.1", "127.0.0.1"), ("167772161", "10.0.0.1"),
])
def test_lenient_ipv4_literals(host, expected):
    assert ends_in_number(host)
    assert parse_ipv4_literal(host) == ipaddress.IPv4Address(expected)
    assert host_ip(host) == ipaddress.IPv4Address(expected)


@pytest.mark.parametrize("host", ["1.2.3.4.5", "08.1.1.1", "10.256.1.1", "10.0.0.256"])
def test_invalid_numeric_hosts_parse_to_nothing(host):
    assert ends_in_number(host) and parse_ipv4_literal(host) is None


@pytest.mark.parametrize("host", ["example.com", "cdn-1.example.com", "1e3", "a.0x"])
def test_names_are_not_ip_literals(host):
    assert host_ip(host) is None


@pytest.mark.parametrize(("value", "embedded"), [
    ("::a00:1", "10.0.0.1"), ("::ffff:0:a00:1", "10.0.0.1"), ("::ffff:10.0.0.1", "10.0.0.1"),
    ("64:ff9b::a00:1", "10.0.0.1"), ("64:ff9b:1::a00:1", "10.0.0.1"),
])
def test_embedded_ipv4_forms(value, embedded):
    assert ipaddress.IPv4Address(embedded) in embedded_ipv4(ipaddress.ip_address(value))
