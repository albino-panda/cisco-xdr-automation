"""Persistence workflow (Phase 3): investigates an attacker foothold and recommends containment.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, item links and the manual
removal steps). The workflow only investigates and recommends; a human approves every action.
"""
from __future__ import annotations

from xdr_response.workflows.persistence.definition import WORKFLOW
from xdr_response.workflows.persistence.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
