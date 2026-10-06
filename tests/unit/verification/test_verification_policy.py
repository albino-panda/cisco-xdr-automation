"""PollPolicy: bounded exponential backoff for verification reads."""
from __future__ import annotations

import pytest

from xdr_response.config.schema import VerificationSettings
from xdr_response.verification import PollPolicy


def test_delays_grow_and_are_capped():
    policy = PollPolicy(interval_seconds=10, timeout_seconds=300, backoff_factor=2.0, max_interval_seconds=35)
    assert [policy.delay_after(n) for n in range(1, 5)] == [10, 20, 35, 35]


def test_constant_interval_with_factor_one():
    policy = PollPolicy(interval_seconds=10, backoff_factor=1.0)
    assert {policy.delay_after(n) for n in range(1, 10)} == {10}


def test_from_settings_uses_threshold_values():
    policy = PollPolicy.from_settings(VerificationSettings(poll_interval_seconds=3, timeout_seconds=90))
    assert (policy.interval_seconds, policy.timeout_seconds) == (3, 90)
    assert PollPolicy.from_settings(VerificationSettings(), max_attempts=4).max_attempts == 4


def test_from_settings_keeps_large_intervals_valid():
    policy = PollPolicy.from_settings(VerificationSettings(poll_interval_seconds=120))
    assert policy.max_interval_seconds == 120


@pytest.mark.parametrize("kwargs", [
    {"interval_seconds": -1},
    {"timeout_seconds": -1},
    {"backoff_factor": 0.5},
    {"interval_seconds": 10, "max_interval_seconds": 5},
    {"max_attempts": 0},
])
def test_invalid_policies_are_refused(kwargs):
    with pytest.raises(ValueError):
        PollPolicy(**kwargs)


def test_attempt_numbers_are_one_based():
    with pytest.raises(ValueError):
        PollPolicy().delay_after(0)
