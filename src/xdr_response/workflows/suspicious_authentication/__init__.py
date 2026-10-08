"""Suspicious authentication workflow (Phase 4, ``suspicious-authentication``): exports ``WORKFLOW`` and ``HOOKS``.

Investigates and recommends only; every containment action waits for a human approval.
"""
from __future__ import annotations

from xdr_response.workflows.suspicious_authentication.definition import WORKFLOW
from xdr_response.workflows.suspicious_authentication.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
