"""Dry-run simulation of an action package (architecture sections 9 and 13.18).

A dry run performs no state change and can never reach one:

* :class:`DryRunSimulator` builds its results from the package alone. It calls no adapter method,
  never calls :func:`xdr_response.guard.authorized` and needs no approval token.
* All of its work runs inside :func:`xdr_response.guard.dry_run`, so even if some code path tried to
  call a guarded adapter method during the simulation, the guard would refuse it.

The rendered output has an exact format::

    DRY RUN
    Would isolate: TH-LT-1047
    Would block: evil.example.com
    Would revoke sessions: jsmith@example.com
    No containment actions executed.
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime

from xdr_response import guard
from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.interfaces import AuditSink
from xdr_response.logs.redaction import Redactor, get_redactor
from xdr_response.models import (
    ActionPackage,
    ActionResult,
    ActionResultStatus,
    AuditEventType,
    ContainmentReport,
    RecommendedAction,
    ReleasePackage,
    RestorationReport,
    SkipReason,
    get_action_spec,
)

__all__ = [
    "apply_token_grants",
    "DRY_RUN_HEADER",
    "DRY_RUN_FOOTER",
    "DRY_RUN_ACTOR",
    "DryRunSimulator",
    "dry_run_line",
    "dry_run_lines",
    "render_dry_run",
    "simulate_and_render",
]

DRY_RUN_HEADER = "DRY RUN"
DRY_RUN_FOOTER = "No containment actions executed."
DRY_RUN_ACTOR = "automation:dryrun"
_DRY_RUN_MESSAGE = "dry run: simulated, not executed"
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\u0085  ]+")


def apply_token_grants(results: Sequence[ActionResult], token: object | None) -> tuple[ActionResult, ...]:
    """A dry run of a decision previews what the live run would do with that token.

    Results of actions the token does not grant (rejected with APPROVE_SELECTED) become
    ``SKIPPED`` / ``REJECTED_BY_ANALYST`` (rendered "Would skip ..."), never "Would isolate ...".
    Without a token (simulation of a proposal) every action is previewed.
    """
    claims = getattr(token, "claims", None)
    if claims is None:
        return tuple(results)
    granted = {g.idempotency_key for g in getattr(claims, "actions", ())}
    out: list[ActionResult] = []
    for result in results:
        if result.idempotency_key in granted or result.status is not ActionResultStatus.DRY_RUN:
            out.append(result)
            continue
        out.append(result.model_copy(update={
            "status": ActionResultStatus.SKIPPED, "skip_reason": SkipReason.REJECTED_BY_ANALYST,
            "dry_run_line": None, "message": "dry run: not approved by the analyst; would be skipped"}))
    return tuple(out)


def dry_run_line(action: RecommendedAction) -> str:
    """The simulation line of one action, for example ``"Would isolate: TH-LT-1047"``."""
    return f"{get_action_spec(action.action_type).dry_run_verb}: {action.target}"


def _one_line(text: str, redactor: Redactor) -> str:
    """Redact secrets and collapse control characters so a value can never forge extra lines."""
    return " ".join(_CONTROL_CHARS.sub(" ", redactor.redact_text(text)).split())


class DryRunSimulator:
    """Simulates a package: every action becomes a ``DRY_RUN`` result; nothing is executed."""

    def __init__(self, *, audit: AuditSink | None = None, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None) -> None:
        """``audit`` receives one ``DRY_RUN_SIMULATION`` record per simulation (optional).

        ``id_factory`` makes report ids deterministic in tests (default: uuid4 hex).
        """
        self._audit = audit
        self._clock = clock or DEFAULT_CLOCK
        self._new_id = id_factory or (lambda: uuid.uuid4().hex)

    def simulate(self, package: ActionPackage) -> ContainmentReport:
        """Simulate ``package`` and return a dry-run :class:`ContainmentReport` (``overall=None``)."""
        with guard.dry_run():
            started = self._clock.now()
            results = self._results(package)
            report = ContainmentReport(
                report_id=self._new_id(), incident_id=package.incident_id,
                package_id=package.package_id, token_id=None, dry_run=True,
                started_at=started, finished_at=self._finished(started), results=results,
                overall=None,
            )
            self._record(package, report.report_id, results)
        return report

    def simulate_restoration(self, package: ReleasePackage) -> RestorationReport:
        """Simulate a release package and return a dry-run :class:`RestorationReport`."""
        with guard.dry_run():
            started = self._clock.now()
            results = self._results(package)
            report = RestorationReport(
                report_id=self._new_id(), incident_id=package.incident_id,
                package_id=package.package_id, token_id=None, dry_run=True,
                started_at=started, finished_at=self._finished(started), results=results,
                overall=None,
            )
            self._record(package, report.report_id, results)
        return report

    # ------------------------------------------------------------ internals --
    def _finished(self, started: datetime) -> datetime:
        now = self._clock.now()
        return now if now >= started else started

    def _results(self, package: ActionPackage) -> tuple[ActionResult, ...]:
        now = self._clock.now()
        return tuple(
            ActionResult(
                idempotency_key=action.idempotency_key, action_type=action.action_type,
                target=action.target, integration=action.integration,
                approval_level=action.approval_level, status=ActionResultStatus.DRY_RUN,
                started_at=now, finished_at=now, message=_DRY_RUN_MESSAGE,
                dry_run_line=dry_run_line(action),
            )
            for action in package.actions
        )

    def _record(self, package: ActionPackage, report_id: str, results: Sequence[ActionResult]) -> None:
        if self._audit is None:
            return
        payload = {
            "report_id": report_id,
            "package_id": package.package_id,
            "purpose": package.purpose.value,
            "dry_run": True,
            "executed_actions": 0,
            "lines": [r.dry_run_line for r in results],
            "actions": [
                {"idempotency_key": r.idempotency_key, "action_type": r.action_type.value,
                 "target": r.target, "integration": r.integration,
                 "approval_level": r.approval_level.value}
                for r in results
            ],
        }
        self._audit.append(
            AuditEventType.DRY_RUN_SIMULATION, incident_id=package.incident_id, actor=DRY_RUN_ACTOR,
            payload=payload, workflow_id=package.workflow_id,
            workflow_version=package.workflow_version,
        )


def dry_run_lines(report: ContainmentReport | RestorationReport, *,
                  redactor: Redactor | None = None) -> tuple[str, ...]:
    """The per-action lines of a dry-run report, in package order (one line each, redacted).

    A result without a ``dry_run_line`` (for example an action skipped by the caller) is shown as
    ``"Would skip <action_type>: <target> (<reason>)"`` so that nothing is dropped silently.
    """
    if not report.dry_run:
        raise ValueError("not a dry-run report: use reporting.render_containment_report")
    red = redactor or get_redactor()
    lines = []
    for result in report.results:
        if result.dry_run_line:
            line = result.dry_run_line
        else:
            reason = result.skip_reason.value if result.skip_reason else result.status.value
            line = f"Would skip {result.action_type.value}: {result.target} ({reason})"
        lines.append(_one_line(line, red))
    return tuple(lines)


def render_dry_run(report: ContainmentReport | RestorationReport, *,
                   redactor: Redactor | None = None) -> str:
    """Render the exact DRY RUN output: header, one line per action, footer (no trailing newline)."""
    return "\n".join((DRY_RUN_HEADER, *dry_run_lines(report, redactor=redactor), DRY_RUN_FOOTER))


def simulate_and_render(package: ActionPackage, *, audit: AuditSink | None = None,
                        clock: Clock | None = None) -> str:
    """Convenience runner: simulate ``package`` and return the rendered DRY RUN text."""
    simulator = DryRunSimulator(audit=audit, clock=clock)
    if isinstance(package, ReleasePackage):
        return render_dry_run(simulator.simulate_restoration(package))
    return render_dry_run(simulator.simulate(package))
