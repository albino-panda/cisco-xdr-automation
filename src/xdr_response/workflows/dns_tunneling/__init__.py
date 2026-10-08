"""DNS tunneling workflow (Phase 4): investigates data or command traffic hidden in DNS queries and
recommends containment.

Exports ``WORKFLOW`` (the validated definition) and ``HOOKS`` (pure facts, tunnel-pattern signals,
client links and considerations). The workflow only investigates and recommends; a human approves
every action, and ``allowlists.approved_dns_tools`` is enforced by the framework on every proposal.
"""
from __future__ import annotations

from xdr_response.workflows.dns_tunneling.definition import WORKFLOW
from xdr_response.workflows.dns_tunneling.hooks import HOOKS

__all__ = ["WORKFLOW", "HOOKS"]
