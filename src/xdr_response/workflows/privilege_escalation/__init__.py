"""Privilege escalation workflow (Phase 5, ``privilege-escalation``): exports ``WORKFLOW`` and ``HOOKS``.

Investigates and recommends only; every containment action waits for a human approval.
"""
from __future__ import annotations

from xdr_response.workflows.privilege_escalation.definition import WORKFLOW
from xdr_response.workflows.privilege_escalation.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
