"""DryRunSimulator and render_dry_run: exact output, no guard entry, no state change."""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import timedelta
from itertools import count
from typing import Any

import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.fixtures.guard_helpers import install_fake_verifier
from tests.unit.reporting._scenario import (
    EV_UMB,
    INCIDENT_ID,
    PACKAGE_ID,
    action,
    containment_report,
    package_of,
    ransomware_package,
    release_package,
)
from xdr_response import guard
from xdr_response.clock import FixedClock
from xdr_response.dryrun import (
    DRY_RUN_ACTOR,
    DRY_RUN_FOOTER,
    DRY_RUN_HEADER,
    DryRunSimulator,
    dry_run_line,
    render_dry_run,
    simulate_and_render,
)
from xdr_response.interfaces import AuditSink
from xdr_response.logs.redaction import Redactor
from xdr_response.models import (
    GENESIS_HASH,
    ActionResult,
    ActionResultStatus,
    ActionType,
    ApprovalLevel,
    AuditEventType,
    AuditRecord,
    ContainmentReport,
    RestorationReport,
    SkipReason,
)

EXPECTED = (
    "DRY RUN\n"
    "Would isolate: TH-LT-1047\n"
    "Would block: evil.example.com\n"
    "Would revoke sessions: jsmith@example.com\n"
    "No containment actions executed."
)


class RecordingAudit:
    """Minimal AuditSink that also records whether the guard was in dry run at append time."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Mapping[str, Any], workflow_id: str | None = None,
               workflow_version: str | None = None) -> AuditRecord:
        self.calls.append({"event_type": event_type, "incident_id": incident_id, "actor": actor,
                           "payload": dict(payload), "workflow_id": workflow_id,
                           "workflow_version": workflow_version, "dry_run": guard.is_dry_run()})
        return AuditRecord(seq=len(self.calls) - 1, record_id=f"rec-{len(self.calls)}", timestamp=FIXED_NOW,
                           event_type=event_type, incident_id=incident_id, workflow_id=workflow_id,
                           workflow_version=workflow_version, actor=actor, payload=dict(payload),
                           prev_hash=GENESIS_HASH, hash="b" * 64)

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        return iter(())

    @property
    def head_hash(self) -> str:
        return GENESIS_HASH


def _ids() -> Any:
    counter = count(1)
    return lambda: f"dry-{next(counter):04d}"


def _simulator(audit: AuditSink | None = None) -> DryRunSimulator:
    return DryRunSimulator(audit=audit, clock=FixedClock(FIXED_NOW), id_factory=_ids())


def test_render_matches_the_exact_brief_format() -> None:
    report = _simulator().simulate(ransomware_package())
    assert render_dry_run(report) == EXPECTED


def test_simulate_and_render_convenience() -> None:
    assert simulate_and_render(ransomware_package(), clock=FixedClock(FIXED_NOW)) == EXPECTED


def test_report_is_a_dry_run_report_with_dry_run_results() -> None:
    report = _simulator().simulate(ransomware_package())
    assert isinstance(report, ContainmentReport)
    assert report.dry_run is True and report.overall is None and report.token_id is None
    assert report.report_id == "dry-0001" and report.package_id == PACKAGE_ID
    assert report.started_at == FIXED_NOW == report.finished_at
    assert [r.status for r in report.results] == [ActionResultStatus.DRY_RUN] * 3
    assert [r.dry_run_line for r in report.results] == EXPECTED.splitlines()[1:-1]
    assert all(not r.control_registered and r.api_calls == () for r in report.results)


def test_simulation_never_enters_the_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = install_fake_verifier()  # global dry run OFF and a verifier registered
    assert guard.is_dry_run() is False

    def _forbidden(*_: Any, **__: Any) -> Any:
        raise AssertionError("dry run must never enter guard.authorized")

    monkeypatch.setattr(guard, "authorized", _forbidden)
    monkeypatch.setattr(guard, "require_authorization", _forbidden)
    report = _simulator().simulate(ransomware_package())
    assert render_dry_run(report) == EXPECTED
    assert verifier.verify_calls == 0 and verifier.mark_used_calls == 0
    assert guard.current() is None


def test_simulation_runs_with_the_guard_locked_in_dry_run() -> None:
    install_fake_verifier()
    audit = RecordingAudit()
    _simulator(audit).simulate(ransomware_package())
    assert audit.calls[0]["dry_run"] is True      # the guard refused writes during the simulation
    assert guard.is_dry_run() is False            # the per-run flag is reset afterwards


def test_audits_one_dry_run_simulation_record() -> None:
    audit = RecordingAudit()
    report = _simulator(audit).simulate(ransomware_package())
    assert len(audit.calls) == 1
    call = audit.calls[0]
    assert call["event_type"] is AuditEventType.DRY_RUN_SIMULATION
    assert call["incident_id"] == INCIDENT_ID and call["actor"] == DRY_RUN_ACTOR
    assert (call["workflow_id"], call["workflow_version"]) == ("ransomware", "1.0.0")
    payload = call["payload"]
    assert payload["report_id"] == report.report_id and payload["package_id"] == PACKAGE_ID
    assert payload["executed_actions"] == 0 and payload["dry_run"] is True
    assert payload["lines"] == EXPECTED.splitlines()[1:-1]
    assert [a["action_type"] for a in payload["actions"]] == ["isolate_endpoint", "block_domain",
                                                              "revoke_sessions"]


def test_simulate_restoration_returns_a_restoration_report() -> None:
    report = _simulator().simulate_restoration(release_package())
    assert isinstance(report, RestorationReport) and report.dry_run and report.overall is None
    assert render_dry_run(report).splitlines() == [
        DRY_RUN_HEADER,
        "Would release endpoint: TH-LT-1047",
        "Would unblock: evil.example.com",
        "Would restore role: jsmith@example.com/62e90394-69f5-4237-9190-012177145e10",
        DRY_RUN_FOOTER,
    ]


def test_simulate_and_render_handles_release_packages() -> None:
    assert simulate_and_render(release_package()).splitlines()[1] == "Would release endpoint: TH-LT-1047"


def test_dry_run_line_uses_catalog_verb() -> None:
    elevated = action(ActionType.DISABLE_USER, "JSmith@Example.com", "entra", [EV_UMB])
    assert dry_run_line(elevated) == "Would disable user: jsmith@example.com"


def test_render_refuses_a_real_report() -> None:
    with pytest.raises(ValueError, match="not a dry-run report"):
        render_dry_run(containment_report())


def test_skipped_result_is_shown_not_dropped() -> None:
    report = _simulator().simulate(ransomware_package())
    first = report.results[0]
    skipped = ActionResult(idempotency_key=first.idempotency_key, action_type=first.action_type,
                           target=first.target, integration=first.integration,
                           approval_level=ApprovalLevel.STANDARD, status=ActionResultStatus.SKIPPED,
                           skip_reason=SkipReason.REJECTED_BY_ANALYST, started_at=FIXED_NOW,
                           finished_at=FIXED_NOW)
    edited = report.model_copy(update={"results": (skipped, *report.results[1:])})
    lines = render_dry_run(edited).splitlines()
    assert lines[1] == "Would skip isolate_endpoint: TH-LT-1047 (REJECTED_BY_ANALYST)"
    assert lines[-1] == DRY_RUN_FOOTER


def test_secrets_in_targets_are_redacted() -> None:
    url_action = action(ActionType.BLOCK_URL, "https://evil.example.com/p?token=abcdef123456", "umbrella",
                        [EV_UMB])
    package = package_of([url_action])
    text = render_dry_run(_simulator().simulate(package))
    assert "abcdef123456" not in text
    assert "Would block: https://evil.example.com/p?token=[REDACTED]" in text


def test_registered_secret_never_rendered() -> None:
    redactor = Redactor()
    redactor.register_secret("TH-LT-1047")
    text = render_dry_run(_simulator().simulate(ransomware_package()), redactor=redactor)
    assert "TH-LT-1047" not in text and "Would isolate: [REDACTED]" in text


def test_clock_drives_timestamps() -> None:
    clock = FixedClock(FIXED_NOW + timedelta(hours=1))
    report = DryRunSimulator(clock=clock).simulate(ransomware_package())
    assert report.started_at == FIXED_NOW + timedelta(hours=1)
    assert len(report.report_id) == 32  # uuid4 hex by default


def test_satisfies_the_executor_simulator_protocol() -> None:
    protocols = pytest.importorskip("xdr_response.execution.protocols")
    assert isinstance(_simulator(), protocols.PackageSimulator)
