"""Web application attacks workflow (Phase 5 add-on): investigates injection, scanning and web shell
activity against internet-facing applications and recommends containment.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, attack links,
considerations and hand-offs). The workflow only investigates and recommends; a human approves every
action before the lifecycle executes it.
"""
from __future__ import annotations

from xdr_response.workflows.web_attacks.definition import WORKFLOW
from xdr_response.workflows.web_attacks.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
