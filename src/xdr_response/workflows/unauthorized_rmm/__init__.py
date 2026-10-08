"""Unauthorised remote access tool workflow (Phase 3): investigates an RMM or remote desktop tool on an
endpoint and recommends containment.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, session links,
considerations and hand-offs). The workflow only investigates and recommends; a human approves every
action, and ``allowlists.approved_rmm`` is enforced by the framework on every proposal.
"""
from __future__ import annotations

from xdr_response.workflows.unauthorized_rmm.definition import WORKFLOW
from xdr_response.workflows.unauthorized_rmm.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
