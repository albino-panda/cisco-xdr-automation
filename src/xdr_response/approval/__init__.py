"""Human approval: packages, analyst decisions, approval tokens and the guard's token verifier.

Public API (architecture section 13.15):

* :class:`PackageBuilder` and :class:`CriticalAssetPolicy` build containment packages with
  evidence snapshot hashes, ELEVATED marking and critical-asset warnings.
* :class:`ApprovalEngine` accepts APPROVE_ALL / APPROVE_SELECTED / REJECT /
  REQUEST_MORE_INVESTIGATION from authenticated HUMAN approvers only, audits every decision and
  denial, and issues tokens for approvals (containment or release).
* :class:`ApprovalTokenService` signs and verifies HMAC-SHA256 approval tokens and implements the
  ``TokenVerifier`` (``ApprovalVerifier``) protocol registered with :mod:`xdr_response.guard`.
* :class:`InMemoryApproverAuthenticator`, :class:`InMemoryTokenUseLedger` and
  :class:`JsonlTokenUseLedger` are the Phase 0 implementations of their protocols.
"""
from __future__ import annotations

from xdr_response.approval.authenticator import InMemoryApproverAuthenticator
from xdr_response.approval.critical_assets import CriticalAssetPolicy
from xdr_response.approval.engine import ApprovalEngine
from xdr_response.approval.ledger import InMemoryTokenUseLedger, JsonlTokenUseLedger
from xdr_response.approval.package import PackageBuilder
from xdr_response.approval.tokens import ApprovalTokenService, claims_hash

__all__ = [
    "ApprovalEngine",
    "ApprovalTokenService",
    "CriticalAssetPolicy",
    "InMemoryApproverAuthenticator",
    "InMemoryTokenUseLedger",
    "JsonlTokenUseLedger",
    "PackageBuilder",
    "claims_hash",
]
