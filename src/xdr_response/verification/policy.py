"""Polling policy for post-action verification (architecture section 7).

Vendor state is eventually consistent: a control that was just applied may not be visible to the
read-back call yet. The engine therefore polls with a bounded, exponentially growing delay until the
read shows a terminal answer or the overall timeout is reached.
"""
from __future__ import annotations

from dataclasses import dataclass

from xdr_response.config.schema import VerificationSettings

__all__ = ["PollPolicy", "DEFAULT_BACKOFF_FACTOR", "DEFAULT_MAX_INTERVAL_SECONDS"]

DEFAULT_BACKOFF_FACTOR = 1.5
DEFAULT_MAX_INTERVAL_SECONDS = 60.0


@dataclass(frozen=True)
class PollPolicy:
    """How often and for how long the engine re-reads a target's state.

    ``interval_seconds`` is the first delay; each later delay is multiplied by ``backoff_factor``
    and capped at ``max_interval_seconds``. Polling stops when ``timeout_seconds`` of (clock or
    slept) time has elapsed or after ``max_attempts`` reads, whichever comes first.
    """

    interval_seconds: float = 10.0
    timeout_seconds: float = 300.0
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR
    max_interval_seconds: float = DEFAULT_MAX_INTERVAL_SECONDS
    max_attempts: int = 50

    def __post_init__(self) -> None:
        if self.interval_seconds < 0 or self.timeout_seconds < 0:
            raise ValueError("interval_seconds and timeout_seconds must be >= 0")
        if self.backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1.0")
        if self.max_interval_seconds < self.interval_seconds:
            raise ValueError("max_interval_seconds must be >= interval_seconds")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

    @classmethod
    def from_settings(cls, settings: VerificationSettings, **overrides: float | int) -> "PollPolicy":
        """Build a policy from ``thresholds.yaml`` verification settings (keyword overrides win)."""
        interval = float(settings.poll_interval_seconds)
        values: dict[str, float | int] = {
            "interval_seconds": interval,
            "timeout_seconds": float(settings.timeout_seconds),
            "max_interval_seconds": max(DEFAULT_MAX_INTERVAL_SECONDS, interval),
        }
        values.update(overrides)
        return cls(**values)  # type: ignore[arg-type]

    def delay_after(self, attempt: int) -> float:
        """Delay to wait after read number ``attempt`` (1-based) before the next read."""
        if attempt < 1:
            raise ValueError("attempt is 1-based")
        delay = self.interval_seconds * (self.backoff_factor ** (attempt - 1))
        return min(delay, self.max_interval_seconds)
