"""Post-action verification result."""
from __future__ import annotations

from pydantic import AwareDatetime

from xdr_response.models._base import FrozenModel
from xdr_response.models._common import ApiCallSummary
from xdr_response.models.enums import VerificationStatus

__all__ = ["VerificationResult"]


class VerificationResult(FrozenModel):
    idempotency_key: str
    status: VerificationStatus
    integration: str | None
    method: str  # operation name used, or "none"
    checked_at: AwareDatetime
    details: str = ""
    api_calls: tuple[ApiCallSummary, ...] = ()
    # True: the vendor reported a final state (do not poll again); False: still pending (poll);
    # None: unknown, the VerificationEngine applies its default rule (VERIFIED is final).
    terminal: bool | None = None
