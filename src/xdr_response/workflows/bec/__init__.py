"""Business email compromise workflow (``bec``, Phase 2; architecture 14.5). Investigates and recommends only."""
from __future__ import annotations

from xdr_response.workflows.bec.definition import WORKFLOW
from xdr_response.workflows.bec.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
