"""Record and context factories for the correlation-evidence unit tests. Fake data only.

Records are built through the real ``xdr_response.atomics.records`` models, so their ``record_id``
is the deterministic id the contract defines (``make_record_id`` over the record's natural key).
Inputs are given already normalized (upper-case hostnames, lower-case users and hashes).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from xdr_response.atomics.context import AtomicContext, build_context
from xdr_response.atomics.records import AtomicResult, RecordBase, make_record_id
from xdr_response.clock import FixedClock
from xdr_response.config import Settings
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.models import ActionType, Incident, Observable, ObservableType, Severity
from xdr_response.secrets import StaticSecretProvider

T0 = datetime(2026, 10, 8, 9, 0, 0, tzinfo=timezone.utc)
HASH_A = "a1" * 32
HASH_B = "b2" * 32
HASH_C = "c3" * 32
HOST_1 = "TH-LT-1047"
HOST_2 = "TH-LT-2210"
HOST_3 = "TH-DC-01"
USER_1 = "jsmith@example.com"
USER_2 = "akumar@example.com"
EVIL_DOMAIN = "login-portal.example"
EVIL_IP = "203.0.113.10"


def at(minutes: int = 0) -> datetime:
    """``T0`` plus ``minutes``."""
    return T0 + timedelta(minutes=minutes)


def obs(kind: str, value: str) -> Observable:
    return Observable(type=ObservableType(kind), value=value)


def record(cls: type[RecordBase], *, integration: str = "secure_endpoint", atomic: str = "investigate_endpoint",
           subject: Observable | None = None, **fields: Any) -> Any:
    """A validated record of ``cls``; the model derives its deterministic ``record_id``."""
    subject = subject or obs("hostname", HOST_1)
    built = cls(integration=integration, atomic=atomic, subject=subject, **fields)
    assert built.record_id == make_record_id(integration, built.kind, built.subject, built.natural_key())
    return built


def result(*records: Any, atomic: str | None = None, subject: Observable | None = None,
           action_type: ActionType = ActionType.INVESTIGATE_ENDPOINT) -> AtomicResult:
    """An ``AtomicResult`` holding ``records`` (they must share ``atomic``)."""
    name = atomic or (records[0].atomic if records else "investigate_endpoint")
    return AtomicResult(atomic=name, action_type=action_type, subject=subject or obs("hostname", HOST_1),
                        records=tuple(records), started_at=T0, finished_at=T0)


def incident(*observables: Observable, users: tuple[str, ...] = (), assets: tuple[Any, ...] = (),
             incident_id: str = "inc-test-0001") -> Incident:
    return Incident(incident_id=incident_id, title="test incident", severity=Severity.HIGH, created_at=T0,
                    workflow_id="test_workflow", workflow_version="1.0.0", observables=observables,
                    users=users, assets=assets)


def context(inc: Incident | None = None, settings: Settings | None = None) -> AtomicContext:
    """A real ``AtomicContext`` over an empty adapter registry (correlation never calls an adapter)."""
    settings = settings or Settings()
    clock = FixedClock(T0)
    registry = AdapterRegistry(settings, StaticSecretProvider({}), clock=clock)
    return build_context(inc or incident(), registry, settings, clock=clock, dry_run=True)
