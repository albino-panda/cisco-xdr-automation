"""Command and control workflow (Phase 4): investigates beaconing to attacker infrastructure and
recommends containment.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, beacon links,
considerations and hand-offs). The workflow only investigates and recommends; a human approves every
action before the lifecycle executes it.
"""
from __future__ import annotations

from xdr_response.workflows.c2.definition import WORKFLOW
from xdr_response.workflows.c2.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
