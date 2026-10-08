"""Fixtures for the enrichment atomic tests.

Unit tests score through :class:`FakeScorer`, a local stand-in for the scoring key's engine
(architecture 14.0.3). A test module that sets ``USE_REAL_ENGINE = True`` runs against the real
scoring engine instead.
"""
from __future__ import annotations

import pytest

from tests.unit.atomics.enrichment._support import FakeScorer
from xdr_response.atomics.enrichment import _scoring


@pytest.fixture(autouse=True)
def scorer(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> FakeScorer | None:
    """Install the fake scorer unless the module asks for the real engine."""
    if getattr(request.module, "USE_REAL_ENGINE", False):
        return None
    fake = FakeScorer()
    monkeypatch.setattr(_scoring, "_backend", fake)
    return fake
