"""Data exfiltration workflow (Phase 4): investigates a large or unusual outbound transfer and recommends
containment (block the destination, isolate a running source, revoke and disable the driving account).

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, transfer signals and links,
considerations and hand-offs). The workflow only investigates and recommends; a human approves every
action, and allow-listed (sanctioned) destinations are excluded by the framework on every proposal.
"""
from __future__ import annotations

from xdr_response.workflows.exfiltration.definition import WORKFLOW
from xdr_response.workflows.exfiltration.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
