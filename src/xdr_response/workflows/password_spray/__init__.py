"""Password spray workflow (``password-spray``): exports ``WORKFLOW`` and ``HOOKS`` (architecture 14.5.1)."""
from __future__ import annotations

from xdr_response.workflows.password_spray.definition import WORKFLOW
from xdr_response.workflows.password_spray.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
