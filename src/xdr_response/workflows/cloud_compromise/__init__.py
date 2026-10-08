"""Cloud compromise workflow (Phase 4, ``cloud-compromise``): exports ``WORKFLOW`` and ``HOOKS``.

Investigates and recommends only; every containment action waits for a human approval.
"""
from __future__ import annotations

from xdr_response.workflows.cloud_compromise.definition import WORKFLOW
from xdr_response.workflows.cloud_compromise.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
