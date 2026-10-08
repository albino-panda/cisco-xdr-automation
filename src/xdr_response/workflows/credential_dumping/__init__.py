"""Credential dumping workflow (Phase 3): investigates credential access on endpoints and recommends containment.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, considerations, manual steps,
the account-takeover hand-off and credential-exposure links). The workflow only investigates and
recommends; a human approves every action.
"""
from __future__ import annotations

from xdr_response.workflows.credential_dumping.definition import WORKFLOW
from xdr_response.workflows.credential_dumping.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
