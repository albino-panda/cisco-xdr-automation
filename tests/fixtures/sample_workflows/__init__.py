"""Tests-only workflow packages (architecture 14.6), discovered with
``discover_workflows("tests.fixtures.sample_workflows")``.

Each sub-package is a workflow exactly like those under ``xdr_response.workflows``; its scenarios
live in ``scenarios/<workflow id>/`` (a plain directory, not a package, so discovery ignores it).
Everything here is fake lab data.
"""
from __future__ import annotations

from pathlib import Path

SAMPLE_PACKAGE = "tests.fixtures.sample_workflows"
SAMPLE_SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
