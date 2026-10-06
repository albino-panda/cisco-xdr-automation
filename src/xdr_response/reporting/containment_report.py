"""Containment and restoration result reports.

Plain-text layout::

    CONTAINMENT RESULT  XDR-83921
    Overall: PARTIALLY_CONTAINED
    Package <id>  approval token <token_id>
    Started 2026-01-15T12:05:00Z  finished 2026-01-15T12:06:10Z
    Results:
      [SUCCESS]  isolate_endpoint TH-LT-1047  via secure_endpoint  verification VERIFIED  control registered
      [FAILED]   block_domain evil.example.com  via umbrella  verification -  ATTENTION
          error RATE_LIMITED: rate limited by umbrella
    Attention:
      - ...
    Temporary controls registered: 1 (release needs a separate release approval)

A dry-run report renders as the exact DRY RUN output (see :mod:`xdr_response.dryrun`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from xdr_response.dryrun.simulator import DRY_RUN_FOOTER, dry_run_lines, render_dry_run
from xdr_response.logs.redaction import Redactor
from xdr_response.models import ActionResult, ContainmentReport, RestorationReport
from xdr_response.reporting._text import (
    OutputFormat,
    clean,
    dump_json,
    fmt_dt,
    md_code,
    md_text,
    pad_columns,
    resolve_redactor,
)

__all__ = [
    "ResultItem",
    "ResultReport",
    "build_result_report",
    "render_containment_report",
    "result_report_text",
    "result_report_markdown",
    "result_report_json",
]

_CONTROLS_NOTE = "release needs a separate release approval"


@dataclass(frozen=True)
class ResultItem:
    """One action result (strings redacted, single-line)."""

    key: str
    action_type: str
    target: str
    integration: str | None
    approval_level: str
    status: str
    skip_reason: str | None
    verification: str | None
    verification_details: str | None
    control_registered: bool
    requires_attention: bool
    error: str | None
    message: str | None
    escalation: str | None
    dry_run_line: str | None
    started_at: str | None
    finished_at: str | None

    def text_cells(self) -> list[str]:
        """Cells of the plain-text result row."""
        cells = [f"[{self.status}]", f"{self.action_type} {self.target}",
                 f"via {self.integration or '-'}", f"verification {self.verification or '-'}"]
        if self.skip_reason:
            cells.append(f"reason {self.skip_reason}")
        if self.control_registered:
            cells.append("control registered")
        if self.requires_attention:
            cells.append("ATTENTION")
        return cells

    def detail_lines(self) -> list[str]:
        """Indented detail lines (error, message of a failure, escalation)."""
        lines = []
        if self.error:
            lines.append(f"error {self.error}")
        elif self.message and self.status == "FAILED":
            lines.append(f"note {self.message}")
        if self.escalation:
            lines.append(f"escalation {self.escalation}")
        return lines

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping."""
        return {"idempotency_key": self.key, "action_type": self.action_type, "target": self.target,
                "integration": self.integration, "approval_level": self.approval_level,
                "status": self.status, "skip_reason": self.skip_reason,
                "verification": self.verification, "verification_details": self.verification_details,
                "control_registered": self.control_registered,
                "requires_attention": self.requires_attention, "error": self.error,
                "message": self.message, "recommended_escalation": self.escalation,
                "dry_run_line": self.dry_run_line, "started_at": self.started_at,
                "finished_at": self.finished_at}


@dataclass(frozen=True)
class ResultReport:
    """Render-ready view of a containment or restoration report."""

    kind: str
    incident_id: str
    report_id: str
    package_id: str
    token_id: str | None
    dry_run: bool
    overall: str
    started_at: str | None
    finished_at: str | None
    items: tuple[ResultItem, ...]
    attention: tuple[str, ...]
    dry_run_lines: tuple[str, ...]

    @property
    def title(self) -> str:
        """``CONTAINMENT RESULT`` or ``RESTORATION RESULT``."""
        return f"{self.kind.upper()} RESULT"

    @property
    def controls_registered(self) -> int:
        """Number of temporary controls created by this run."""
        return sum(1 for i in self.items if i.control_registered)


def _opt(value: object, redactor: Redactor) -> str | None:
    text = clean(value, redactor) if value is not None else ""
    return text or None


def _item(result: ActionResult, redactor: Redactor) -> ResultItem:
    error = None
    if result.error is not None:
        error = f"{result.error.code.value}: {clean(result.error.message, redactor)}"
    verification = result.verification
    return ResultItem(
        key=clean(result.idempotency_key, redactor), action_type=result.action_type.value,
        target=clean(result.target, redactor), integration=_opt(result.integration, redactor),
        approval_level=result.approval_level.value, status=result.status.value,
        skip_reason=result.skip_reason.value if result.skip_reason else None,
        verification=verification.status.value if verification else None,
        verification_details=_opt(verification.details, redactor) if verification else None,
        control_registered=result.control_registered, requires_attention=result.requires_attention,
        error=error, message=_opt(result.message, redactor),
        escalation=_opt(result.recommended_escalation, redactor),
        dry_run_line=_opt(result.dry_run_line, redactor),
        started_at=fmt_dt(result.started_at), finished_at=fmt_dt(result.finished_at),
    )


def build_result_report(report: ContainmentReport | RestorationReport, *,
                        redactor: Redactor | None = None) -> ResultReport:
    """Build the view of an executor or restoration report (strings redacted, single-line)."""
    red = resolve_redactor(redactor)
    kind = "restoration" if isinstance(report, RestorationReport) else "containment"
    return ResultReport(
        kind=kind, incident_id=clean(report.incident_id, red), report_id=clean(report.report_id, red),
        package_id=clean(report.package_id, red), token_id=_opt(report.token_id, red),
        dry_run=report.dry_run, overall=report.overall.value if report.overall else "DRY_RUN",
        started_at=fmt_dt(report.started_at), finished_at=fmt_dt(report.finished_at),
        items=tuple(_item(r, red) for r in report.results),
        attention=tuple(clean(a, red) for a in report.attention),
        dry_run_lines=dry_run_lines(report, redactor=red) if report.dry_run else (),
    )


def result_report_text(view: ResultReport) -> str:
    """Plain-text result report (no trailing newline)."""
    lines = [f"{view.title}  {view.incident_id}", f"Overall: {view.overall}",
             f"Package {view.package_id}  approval token {view.token_id or '-'}",
             f"Started {view.started_at}  finished {view.finished_at}", "Results:"]
    rows = pad_columns([i.text_cells() for i in view.items])
    for row, item in zip(rows, view.items):
        lines.append(f"  {row}")
        lines += [f"      {detail}" for detail in item.detail_lines()]
    if view.attention:
        lines.append("Attention:")
        lines += [f"  - {a}" for a in view.attention]
    if view.kind == "containment":
        lines.append(f"Temporary controls registered: {view.controls_registered} ({_CONTROLS_NOTE})")
    return "\n".join(lines)


def result_report_markdown(view: ResultReport) -> str:
    """Markdown result report."""
    lines = [f"## {view.title} {md_code(view.incident_id)}", "", f"- **Overall:** {view.overall}",
             f"- **Package:** {md_code(view.package_id)}",
             f"- **Approval token:** {md_code(view.token_id) if view.token_id else '-'}",
             f"- **Started:** {view.started_at}", f"- **Finished:** {view.finished_at}", ""]
    if view.dry_run:
        lines += ["```text", "DRY RUN", *view.dry_run_lines, DRY_RUN_FOOTER, "```"]
        return "\n".join(lines)
    lines += ["| Status | Action | Integration | Verification | Notes |", "|---|---|---|---|---|"]
    for i in view.items:
        notes = [n for n in (i.skip_reason, "control registered" if i.control_registered else None,
                             "ATTENTION" if i.requires_attention else None, *i.detail_lines()) if n]
        lines.append(f"| {i.status} | {md_code(i.action_type + ' ' + i.target)} | {i.integration or '-'} "
                     f"| {i.verification or '-'} | {md_text('; '.join(notes)) or '-'} |")
    if view.attention:
        lines += ["", "### Attention", "", *(f"- {md_text(a)}" for a in view.attention)]
    if view.kind == "containment":
        lines += ["", f"Temporary controls registered: {view.controls_registered} ({_CONTROLS_NOTE})"]
    return "\n".join(lines)


def result_report_json(view: ResultReport) -> str:
    """JSON result report (sorted keys, 2-space indent)."""
    data = {
        "kind": f"{view.kind}_report", "incident_id": view.incident_id, "report_id": view.report_id,
        "package_id": view.package_id, "token_id": view.token_id, "dry_run": view.dry_run,
        "overall": view.overall, "started_at": view.started_at, "finished_at": view.finished_at,
        "results": [i.to_dict() for i in view.items], "attention": list(view.attention),
        "controls_registered": view.controls_registered,
        "dry_run_lines": list(view.dry_run_lines),
    }
    return dump_json(data)


def render_containment_report(report: ContainmentReport | RestorationReport, *,
                              fmt: OutputFormat | str = OutputFormat.TEXT,
                              redactor: Redactor | None = None) -> str:
    """Render a containment or restoration report as text (default), Markdown or JSON.

    In text form a dry-run report is the exact DRY RUN output.
    """
    fmt = OutputFormat(fmt)
    if fmt is OutputFormat.TEXT and report.dry_run:
        return render_dry_run(report, redactor=redactor)
    view = build_result_report(report, redactor=redactor)
    renderers = {OutputFormat.TEXT: result_report_text, OutputFormat.MARKDOWN: result_report_markdown,
                 OutputFormat.JSON: result_report_json}
    return renderers[fmt](view)
