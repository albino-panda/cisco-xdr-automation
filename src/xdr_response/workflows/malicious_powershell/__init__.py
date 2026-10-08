"""Suspicious PowerShell workflow (Phase 3): investigates PowerShell and system binary (LOLBin) activity.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, links, considered items
and hand-offs). The workflow only investigates and recommends; a human approves every action.
"""
from __future__ import annotations

from xdr_response.workflows.malicious_powershell.definition import WORKFLOW
from xdr_response.workflows.malicious_powershell.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
