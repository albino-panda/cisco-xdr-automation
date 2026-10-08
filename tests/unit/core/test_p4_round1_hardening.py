"""Regression tests for the Phase 4 round 1 workflow-safety fixes below the workflows (architecture 14.12.6).

URL targets never carry credentials (userinfo, secret query or fragment parameters), and the owned-domain
URL exception (``url_block_allowed_domains``) never lifts the internal-domain exclusion. Fake lab values only.
"""
from __future__ import annotations

import pytest

from xdr_response.config.policy import AllowlistPolicy
from xdr_response.config.schema import AllowlistsConfig, ExclusionsConfig
from xdr_response.models import ActionType, TargetKind, make_idempotency_key, normalize_target
from xdr_response.models.canonical import url_without_credentials

SECRET = "Hunter2LabSecret77"


@pytest.mark.parametrize("url, expected", [
    (f"https://svc:{SECRET}@beacon-gate.test/api/checkin", "https://beacon-gate.test/api/checkin"),
    (f"https://beacon-gate.test/api/checkin?token={SECRET}", "https://beacon-gate.test/api/checkin"),
    (f"https://beacon-gate.test/p?id=7&api_key={SECRET}&v=2", "https://beacon-gate.test/p?id=7&v=2"),
    (f"https://beacon-gate.test/cb#access_token={SECRET}", "https://beacon-gate.test/cb"),
    (f"beacon-gate.test/p?sig={SECRET}", "beacon-gate.test/p"),
])
def test_url_targets_lose_their_credentials(url, expected):
    assert url_without_credentials(url) == expected
    assert normalize_target(TargetKind.URL, url) == expected
    assert normalize_target(TargetKind.URL, expected) == expected  # stable
    assert SECRET not in make_idempotency_key("INC-1", ActionType.BLOCK_URL, normalize_target(TargetKind.URL, url))


@pytest.mark.parametrize("url", [
    "https://beacon-gate.test/api/checkin",
    "https://beacon-gate.test/p?id=7&&v=2#frag",
    "https://beacon-gate.test/?",
    "HTTPS://Beacon-Gate.test/Path",
])
def test_url_without_credentials_is_kept_as_written(url):
    assert normalize_target(TargetKind.URL, url) == url


def _policy() -> AllowlistPolicy:
    allow = AllowlistsConfig.model_validate({"never_block": {"domains": ["example.com"]},
                                             "url_block_allowed_domains": ["example.com"]})
    exclusions = ExclusionsConfig.model_validate({"internal_domains": ["corp.example.com"]})
    return AllowlistPolicy(allow, exclusions=exclusions)


def test_owned_domain_url_exception_does_not_lift_the_internal_domain_exclusion():
    policy = _policy()
    reason = policy.excluded_reason(ActionType.BLOCK_URL, "https://files.corp.example.com/api/checkin",
                                    TargetKind.URL)
    assert reason and "internal_domains" in reason


def test_owned_public_domain_url_stays_blockable():
    policy = _policy()
    assert policy.excluded_reason(ActionType.BLOCK_URL, "https://share.example.com/bad/page",
                                  TargetKind.URL) is None
    assert policy.excluded_reason(ActionType.BLOCK_DOMAIN, "share.example.com", TargetKind.DOMAIN)
