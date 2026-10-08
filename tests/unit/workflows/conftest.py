"""Shared fixtures of the workflow framework unit tests (tests-only sample workflow, simulated lab)."""
from __future__ import annotations

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE
from tests.fixtures.sample_workflows.lab import Lab, make_lab
from xdr_response.workflows.discovery import WorkflowCatalog, discover_workflows


@pytest.fixture(scope="session")
def sample_catalog() -> WorkflowCatalog:
    return discover_workflows(SAMPLE_PACKAGE)


@pytest.fixture
def lab() -> Lab:
    return make_lab()
