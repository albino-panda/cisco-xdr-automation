"""Shared test doubles for the integrations-core unit tests (no network, deterministic)."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import httpx

from tests.fixtures.factories import FIXED_NOW
from tests.fixtures.http_mocks import MockRouter, json_response  # contract home (13.20)
from xdr_response.clock import FixedClock
from xdr_response.models import AuditEventType

__all__ = ["MockRouter", "json_response", "FakeAudit", "FakeAuth", "SleepRecorder", "fixed_clock"]

class FakeAudit:
    """Minimal AuditSink: records appended events; can be told to fail."""

    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[dict[str, Any]] = []
        self.fail = fail

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> None:
        if self.fail:
            raise OSError("audit disk full")
        self.events.append({"event_type": event_type, "incident_id": incident_id, "actor": actor,
                            "payload": dict(payload)})

    def records(self, incident_id: str | None = None):  # pragma: no cover - unused
        return iter(())

    @property
    def head_hash(self) -> str:  # pragma: no cover - unused
        return "0" * 64


class FakeAuth:
    """Bearer auth double. ``invalidate`` rotates to a new token value."""

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = list(tokens)
        self.invalidations = 0

    def apply(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {self._tokens[min(self.invalidations, len(self._tokens) - 1)]}"

    def invalidate(self) -> None:
        self.invalidations += 1


class SleepRecorder:
    """Injectable ``sleep`` that records delays and (optionally) advances a FixedClock."""

    def __init__(self, clock: FixedClock | None = None) -> None:
        self.delays: list[float] = []
        self.clock = clock

    def __call__(self, seconds: float) -> None:
        from datetime import timedelta

        self.delays.append(seconds)
        if self.clock is not None:
            self.clock.advance(timedelta(seconds=seconds))


def fixed_clock() -> FixedClock:
    return FixedClock(FIXED_NOW)
