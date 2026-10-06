"""Integration health model."""
from __future__ import annotations

from pydantic import AwareDatetime

from xdr_response.models._base import FrozenModel
from xdr_response.models.enums import HealthStatus

__all__ = ["IntegrationHealth"]


class IntegrationHealth(FrozenModel):
    integration: str
    status: HealthStatus
    checked_at: AwareDatetime
    detail: str = ""
    latency_ms: int | None = None
