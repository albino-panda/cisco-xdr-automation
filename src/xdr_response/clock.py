"""Injectable clock. All framework code reads time through a :class:`Clock`."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "SystemClock", "FixedClock", "utc", "DEFAULT_CLOCK"]


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime:  # timezone-aware UTC
        ...


def utc(dt: datetime) -> datetime:
    """Convert an aware datetime to UTC. Naive datetimes raise ValueError."""
    if not isinstance(dt, datetime):
        raise TypeError(f"expected datetime, got {type(dt).__name__}")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("naive datetime is not allowed; use a timezone-aware datetime")
    return dt.astimezone(timezone.utc)


class SystemClock:
    """Wall clock, always UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return "SystemClock()"


class FixedClock:
    """Deterministic clock for tests and simulations."""

    def __init__(self, start: datetime) -> None:
        self._now = utc(start)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        if not isinstance(delta, timedelta):
            raise TypeError("delta must be a timedelta")
        self._now = self._now + delta

    def set(self, value: datetime) -> None:
        self._now = utc(value)

    def __repr__(self) -> str:
        return f"FixedClock({self._now.isoformat()})"


DEFAULT_CLOCK: Clock = SystemClock()
