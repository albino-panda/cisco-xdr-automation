"""Account takeover workflow (Phase 2, ``account-takeover``): exports ``WORKFLOW`` and ``HOOKS``.

Investigates and recommends only; every containment action waits for a human approval.
"""
from __future__ import annotations

from xdr_response.workflows.account_takeover.definition import WORKFLOW
from xdr_response.workflows.account_takeover.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
