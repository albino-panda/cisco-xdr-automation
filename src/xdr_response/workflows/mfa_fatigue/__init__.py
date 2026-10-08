"""Workflow ``mfa-fatigue`` (exports ``WORKFLOW`` and ``HOOKS``; architecture 14.5.1)."""
from __future__ import annotations

from xdr_response.workflows.mfa_fatigue.definition import WORKFLOW
from xdr_response.workflows.mfa_fatigue.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
