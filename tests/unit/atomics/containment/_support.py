"""Shared helpers for the containment-atomics tests (fake data only, no network).

``FakeAdapters`` is a local stand-in for ``ReadOnlyAdapters`` that serves executor names and a
canned native listing and records every call; any other attribute access fails the test, so a
builder that tried to reach anything but the two routing reads would be caught.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from tests.fixtures.factories import FAKE_SHA256, FIXED_NOW, make_incident
from xdr_response.approval.critical_assets import CriticalAssetPolicy
from xdr_response.atomics.context import AtomicContext
from xdr_response.clock import FixedClock
from xdr_response.config import Settings
from xdr_response.config.policy import AllowlistPolicy, DisclosurePolicy
from xdr_response.models import ActionType, EvidenceDraft, Incident, Observable, get_action_spec
from xdr_response.models.canonical import sha256_hex

__all__ = ["FAKE_SHA256", "FIXED_NOW", "NativeAction", "FakeAdapters", "record_id", "evidence", "make_settings",
           "make_context", "CRITICAL_ASSETS", "ALLOWLISTS"]

#: Critical-asset classes used by the tests (fake hosts and users).
CRITICAL_ASSETS: dict[str, Any] = {"classes": {
    "domain_controller": {"display_name": "Domain controller", "role": "Active Directory DC",
                          "potential_impact": "authentication outage for the whole domain",
                          "match": {"hostname_patterns": ["th-dc-*"]}},
    "executive_endpoint": {"display_name": "Executive endpoint", "role": "executive laptop",
                           "potential_impact": "executive productivity loss",
                           "match": {"groups": ["Executives"]}},
    "privileged_account": {"display_name": "Privileged account", "role": "tenant administrator",
                           "potential_impact": "loss of tenant administration",
                           "match": {"users": ["admin.ops@example.com"]}},
}}

#: Allow-lists used by the tests.
ALLOWLISTS: dict[str, Any] = {"never_block": {"domains": ["example.com"], "ips": ["198.51.100.53"]}}


@dataclass(frozen=True)
class NativeAction:
    """Duck-typed ``NativeResponseAction`` (the read zone never imports the vendor module)."""

    module_instance_id: str
    action_id: str
    module_name: str = "Secure Endpoint"
    title: str = "Native action"
    observable_type: str = "hostname"
    observable_value: str = "TH-LT-1047"


@dataclass
class FakeAdapters:
    """Routing reads only: ``executors`` and ``native_response_actions``; records every call."""

    enabled_names: Sequence[str] = ()
    native: Sequence[NativeAction] = ()
    listing_error: Exception | None = None
    calls: list[tuple[str, Any]] = field(default_factory=list)

    def executors(self, action_type: ActionType) -> tuple[str, ...]:
        self.calls.append(("executors", ActionType(action_type)))
        spec = get_action_spec(action_type)
        return tuple(n for n in spec.integrations if n in self.enabled_names)

    def native_response_actions(self, observable: Observable, *, module: str | None = None) -> tuple[Any, ...]:
        self.calls.append(("native_response_actions", (observable, module)))
        if self.listing_error is not None:
            raise self.listing_error
        return tuple(self.native)

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - only hit by a misbehaving builder
        raise AssertionError(f"containment builders may not use adapters.{name}")


def record_id(n: int) -> str:
    """A well-formed fake record id (``rec_`` + 32 hex)."""
    return "rec_" + sha256_hex(f"fake-record-{n}".encode())[:32]


def evidence(n: int = 1, source: str = "secure_endpoint") -> tuple[EvidenceDraft, ...]:
    """Evidence drafts citing fake records the way ``evidence_draft`` does."""
    return tuple(EvidenceDraft(source=source, summary=f"{source}: fake finding {i}", observed_at=FIXED_NOW,
                               data={"record_id": record_id(i), "kind": "detection", "atomic": "investigate_endpoint",
                                     "fields": {"name": "Fake.Detection"}})
                 for i in range(1, n + 1))


TEST_VERDICT = "test-verdict"


def make_settings(*, native_actions: Mapping[str, Any] | None = None, critical: Mapping[str, Any] | None = None,
                  allowlists: Mapping[str, Any] | None = None) -> Settings:
    """Settings with the test critical assets, allow-lists and an optional native action table."""
    options = {"native_actions": dict(native_actions)} if native_actions is not None else {}
    return Settings.model_validate({
        "integrations": {"cisco_xdr": {"enabled": True, "options": options},
                         # the tenant's Secure Email move verdict (14.10.3); a fake test value
                         "secure_email": {"enabled": True, "options": {"quarantine_verdict": TEST_VERDICT}}},
        "critical_assets": dict(critical if critical is not None else CRITICAL_ASSETS),
        "allowlists": dict(allowlists if allowlists is not None else ALLOWLISTS),
    })


def make_context(adapters: Any, settings: Settings | None = None, *, incident: Incident | None = None,
                 dry_run: bool = True) -> AtomicContext:
    """An ``AtomicContext`` around ``adapters`` (a fake or a real ``ReadOnlyAdapters``)."""
    settings = settings or make_settings()
    return AtomicContext(
        incident=incident or make_incident(), adapters=adapters, settings=settings, clock=FixedClock(FIXED_NOW),
        disclosure=DisclosurePolicy(settings.exclusions),
        critical_assets=CriticalAssetPolicy(settings.critical_assets),
        allowlists=AllowlistPolicy(settings.allowlists), dry_run=dry_run,
    )
