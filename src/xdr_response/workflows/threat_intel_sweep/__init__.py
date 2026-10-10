"""Threat intelligence sweep workflow (Phase 5, new): sweeps the estate for high-confidence indicators.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, indicator-hit links,
considerations and hand-offs). The workflow only investigates and recommends; a human approves every
action.
"""
from __future__ import annotations

from xdr_response.workflows.threat_intel_sweep.definition import WORKFLOW
from xdr_response.workflows.threat_intel_sweep.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
