"""Lateral-movement workflow (Phase 3): exports ``WORKFLOW`` and ``HOOKS`` (architecture 14.5.1)."""
from __future__ import annotations

from xdr_response.workflows.lateral_movement.definition import WORKFLOW
from xdr_response.workflows.lateral_movement.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
