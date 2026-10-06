"""Shared pytest configuration.

Every test starts and ends with a clean execution guard: no verifier registered, no verifier seal,
no denial hook, global dry run ON (the fail-closed default) and no authorization context. The
private harness reset is used because the public ``guard.reset_for_tests()`` deliberately keeps
the verifier seal (it may never re-open the slot for another verifier).
"""
from __future__ import annotations

import pytest

from xdr_response import guard


@pytest.fixture(autouse=True)
def _reset_guard():
    guard._reset_for_test_harness()
    yield
    guard._reset_for_test_harness()
