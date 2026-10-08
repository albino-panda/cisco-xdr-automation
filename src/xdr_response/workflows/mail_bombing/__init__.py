"""Workflow ``mail-bombing`` (Phase 2): exports ``WORKFLOW`` and ``HOOKS`` (architecture 14.5.1)."""
from __future__ import annotations

from xdr_response.workflows.mail_bombing.definition import WORKFLOW
from xdr_response.workflows.mail_bombing.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
