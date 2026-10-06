"""Shared fixtures for the approval component tests. Fake values only; no network."""
from __future__ import annotations

import itertools
from collections.abc import Iterator

import pytest

from tests.fixtures.factories import FIXED_NOW, make_package, make_recommendation
from tests.fixtures.principals import make_authenticator, make_test_secrets
from tests.unit.approval._support import RecordingAudit
from xdr_response.approval import ApprovalEngine, ApprovalTokenService, InMemoryTokenUseLedger
from xdr_response.clock import FixedClock
from xdr_response.config import ApprovalSettings
from xdr_response.models import ActionType, ApprovalLevel, ContainmentPackage


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(FIXED_NOW)


@pytest.fixture
def approval_settings() -> ApprovalSettings:
    return ApprovalSettings()


@pytest.fixture
def ledger() -> InMemoryTokenUseLedger:
    return InMemoryTokenUseLedger()


@pytest.fixture
def secrets():
    return make_test_secrets()


@pytest.fixture
def ids() -> Iterator[str]:
    counter = itertools.count(1)
    return (f"id{n:06d}" for n in counter)


@pytest.fixture
def tokens(secrets, approval_settings, ledger, clock) -> ApprovalTokenService:
    return ApprovalTokenService(secrets, approval_settings, ledger=ledger, clock=clock)


@pytest.fixture(scope="session")
def authenticator():
    # Stateless after setup; session scope keeps the PBKDF2 cost of adding principals to one run.
    return make_authenticator()


@pytest.fixture
def audit() -> RecordingAudit:
    return RecordingAudit()


@pytest.fixture
def engine(approval_settings, authenticator, tokens, audit, clock, ids) -> ApprovalEngine:
    return ApprovalEngine(approval_settings, authenticator=authenticator, tokens=tokens, audit=audit,
                          clock=clock, id_factory=lambda: next(ids))


@pytest.fixture
def standard_action():
    return make_recommendation()


@pytest.fixture
def elevated_action():
    return make_recommendation(ActionType.DISABLE_USER, target="adm-j.doe@example.com", integration="entra",
                               approval_level=ApprovalLevel.ELEVATED)


@pytest.fixture
def package(standard_action) -> ContainmentPackage:
    return make_package(standard_action, make_recommendation(ActionType.BLOCK_DOMAIN, target="bad.example.test",
                                                             integration="umbrella"))


@pytest.fixture
def mixed_package(standard_action, elevated_action) -> ContainmentPackage:
    return make_package(standard_action, elevated_action)
