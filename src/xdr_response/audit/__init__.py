"""Tamper-evident audit trail (architecture section 13.12).

- :class:`AuditTrail`: append-only JSONL file, SHA-256 hash chain, cross-process file lock.
- :class:`MemoryAuditTrail`: the same contract in memory, for tests.
- :func:`verify_chain` / :func:`verify_records`: report the first broken record, never raise.
- :class:`AuditRecorder`: one typed method per lifecycle event.
- :func:`build_execution_summary`: the brief's per-execution audit summary.

Payloads always pass through the central redactor before they are hashed or written.
"""
from __future__ import annotations

from xdr_response.audit.events import EVENT_PAYLOAD_TYPES, AuditRecorder, payload_type_for
from xdr_response.audit.hashing import compute_record_hash
from xdr_response.audit.summary import ExecutionAuditSummary, build_execution_summary
from xdr_response.audit.trail import AuditTrail, MemoryAuditTrail, prepare_payload
from xdr_response.audit.verify import AuditAnchor, verify_chain, verify_records

__all__ = [
    "AuditTrail",
    "MemoryAuditTrail",
    "AuditRecorder",
    "AuditAnchor",
    "EVENT_PAYLOAD_TYPES",
    "ExecutionAuditSummary",
    "build_execution_summary",
    "compute_record_hash",
    "payload_type_for",
    "prepare_payload",
    "verify_chain",
    "verify_records",
]
