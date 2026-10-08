"""Deterministic renderers for incident notes, SOC notifications and analyst summaries (14.1.8).

Content rules:

* the text depends only on the event (no clock, no randomness); ``created_at`` is ``event.at``;
* risk and confidence are shown separately;
* evidence is the numbered package evidence when a package exists, else the summary's record lines;
* the human decision shows approver identities and the approved and rejected actions;
* every action shows its catalog rollback action (``rollback_for``) or "not reversible";
* ELEVATED approval is always shown with its warnings (never silently skipped);
* never ``params``, ``rollback_params``, ``external_ref`` values, tokens, token ids beyond the first
  8 characters, signatures, unlock codes, secrets or credentials, and never a link or button that
  acts: decisions are taken only in the orchestrator's decision flow;
* AI text appears only in the analyst summary, under :data:`_AI_NARRATIVE_HEADING`, and sets
  ``contains_ai_text``;
* every value is redacted and flattened to one line, and the whole body passes
  ``get_redactor().redact_text``.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from xdr_response.atomics.notifications.models import (
    _AI_NARRATIVE_HEADING,
    _AUDIENCE,
    _MAX_BODY_BYTES,
    _MAX_TITLE_CHARS,
    LifecycleEvent,
    LifecycleEventKind,
    NotificationDraft,
    NotificationKind,
)
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    ActionPackage,
    ActionResult,
    ActionType,
    AnalystDecision,
    ApprovalLevel,
    ApprovalPurpose,
    BlastRadius,
    ContainmentReport,
    Evidence,
    RecommendedAction,
    ReleasePackage,
    RiskBand,
    canonical_json,
    format_datetime,
    risk_band,
    rollback_for,
    sha256_hex,
)

__all__ = ["render_incident_note", "render_soc_notification", "render_analyst_summary"]

_DRY_RUN_PREFIX = "[DRY RUN] "
_TRUNCATION_MARK = "[truncated]"
#: Incident titles quote detection text (attacker-chosen strings such as an email subject or a file
#: name) and have no length limit: the body header shows at most this many characters of the title.
_HEADER_TITLE_CHARS = 300
_TOKEN_PREFIX_CHARS = 8
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\u0085  ]+")
_FOOTER = (
    "Bookkeeping only: this notification cannot approve, execute or release anything. "
    "Decisions are taken only by authenticated analysts in the orchestrator decision flow."
)
_DRY_RUN_NOTICE = "DRY RUN: simulation only. No state-changing action was performed on any system."

_EVENT_LABELS: dict[LifecycleEventKind, str] = {
    LifecycleEventKind.DETECTION_COMPLETED: "investigation completed, no containment proposed",
    LifecycleEventKind.PACKAGE_PROPOSED: "containment proposed, awaiting human approval",
    LifecycleEventKind.DECISION_RECORDED: "human decision recorded",
    LifecycleEventKind.CONTAINMENT_COMPLETED: "approved containment finished",
    LifecycleEventKind.RELEASE_PROPOSED: "release proposed, awaiting human release approval",
    LifecycleEventKind.RESTORATION_COMPLETED: "approved restoration finished",
    LifecycleEventKind.INCIDENT_CLOSED: "incident closed",
}

_STATUS_LINES: dict[LifecycleEventKind, str] = {
    LifecycleEventKind.DETECTION_COMPLETED: (
        "Status: investigation completed automatically. No containment was proposed."),
    LifecycleEventKind.PACKAGE_PROPOSED: (
        "Status: containment recommended. Human approval is required before any action runs."),
    LifecycleEventKind.DECISION_RECORDED: "Status: a human decision was recorded.",
    LifecycleEventKind.CONTAINMENT_COMPLETED: (
        "Status: approved containment finished; verification ran automatically."),
    LifecycleEventKind.RELEASE_PROPOSED: (
        "Status: release proposed. A separate human release approval is required before anything "
        "is restored."),
    LifecycleEventKind.RESTORATION_COMPLETED: (
        "Status: approved restoration finished; verification ran automatically."),
    LifecycleEventKind.INCIDENT_CLOSED: "Status: incident closed.",
}

_NEXT_STEPS: dict[LifecycleEventKind, str] = {
    LifecycleEventKind.PACKAGE_PROPOSED: (
        "Next step: an authenticated analyst reviews the evidence and decides in the orchestrator "
        "decision flow."),
    LifecycleEventKind.RELEASE_PROPOSED: (
        "Next step: an authenticated analyst decides on the release in the orchestrator release "
        "decision flow."),
}

Section = Callable[[LifecycleEvent], list[str]]


# --------------------------------------------------------------------------------- text helpers --
def _clean(value: object) -> str:
    """Redacted, single-line text with collapsed whitespace."""
    text = get_redactor().redact_text("" if value is None else str(value))
    return " ".join(_CONTROL_CHARS.sub(" ", text).split())


def _fmt_dt(value: datetime) -> str:
    """UTC timestamp with second precision, for example ``2026-01-15T12:00:00Z``."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plural(count: int, singular: str) -> str:
    """``"1 endpoint"`` / ``"2 endpoints"``."""
    return f"{count} {singular}" if count == 1 else f"{count} {singular}s"


def _cap_utf8(text: str, limit: int) -> str:
    """``text`` cut to at most ``limit`` UTF-8 bytes, marked when truncated."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    mark = "\n" + _TRUNCATION_MARK
    head = encoded[: max(0, limit - len(mark.encode("utf-8")))].decode("utf-8", errors="ignore")
    return head.rstrip() + mark


def _cap_chars(text: str, limit: int) -> str:
    """``text`` cut to at most ``limit`` characters, marked with ``...`` when cut."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _cap_title(title: str) -> str:
    """Title cut to the model limit."""
    if len(title) <= _MAX_TITLE_CHARS:
        return title
    return title[: _MAX_TITLE_CHARS - 3].rstrip() + "..."


# ------------------------------------------------------------------------------- event helpers --
def _is_dry_run(event: LifecycleEvent) -> bool:
    """True when the event, its package or its report is a dry run (never mislabel a simulation)."""
    return bool(
        event.dry_run
        or (event.package is not None and event.package.dry_run)
        or (event.report is not None and event.report.dry_run)
    )


def _event_ref(event: LifecycleEvent) -> str:
    """The object that makes this event unique: report, decision, package, else the event time."""
    if event.report is not None:
        return f"report:{event.report.report_id}"
    if event.decision is not None:
        return f"decision:{event.decision.decision_id}"
    if event.package is not None:
        return f"package:{event.package.package_id}"
    return f"at:{format_datetime(event.at)}"


def _notification_id(kind: NotificationKind, event: LifecycleEvent) -> str:
    """``sha256_hex(canonical_json([kind, incident_id, event, ref]))[:32]``."""
    data = [kind.value, event.incident.incident_id, event.kind.value, _event_ref(event)]
    return sha256_hex(canonical_json(data))[:32]


def _workflow(event: LifecycleEvent) -> tuple[str | None, str | None]:
    """Workflow id and version: package, then decision, then summary, then incident."""
    for source in (event.package, event.decision, event.summary, event.incident):
        if source is not None and source.workflow_id:
            return source.workflow_id, source.workflow_version
    return None, None


def _scores(event: LifecycleEvent) -> tuple[int, int, RiskBand] | None:
    """Risk score, confidence score and risk band from the package, else the summary."""
    if event.package is not None:
        pkg = event.package
        return pkg.risk_score, pkg.confidence_score, risk_band(pkg.risk_score)
    if event.summary is not None:
        s = event.summary
        return s.risk_score, s.confidence_score, s.risk_band
    return None


def _action_label(action: RecommendedAction) -> str:
    """``"<action_type> <target>"`` (never params)."""
    return f"{action.action_type.value} {_clean(action.target)}"


def _rollback_text(action_type: ActionType) -> str:
    """Catalog rollback action or "not reversible"."""
    rollback = rollback_for(action_type)
    return f"rollback: {rollback.value}" if rollback is not None else "not reversible"


def _key_label(package: ActionPackage | None, key: str) -> str:
    """Action label for an idempotency key, or the cleaned key when the package is unknown."""
    if package is not None:
        for action in package.actions:
            if action.idempotency_key == key:
                return _action_label(action)
    return _clean(key)


# ------------------------------------------------------------------------------------ sections --
def _header(event: LifecycleEvent) -> list[str]:
    """Incident identity, event and workflow."""
    incident = event.incident
    lines = [
        f"Incident: {_clean(incident.incident_id)} - {_cap_chars(_clean(incident.title), _HEADER_TITLE_CHARS)}",
        f"Severity: {incident.severity.value}  State: {incident.state.value}",
        f"Event: {event.kind.value} at {_fmt_dt(event.at)}",
    ]
    workflow_id, version = _workflow(event)
    if workflow_id:
        lines.append(f"Workflow: {_clean(workflow_id)} {_clean(version or '')}".rstrip())
    return lines


def _dry_run(event: LifecycleEvent) -> list[str]:
    """Dry-run notice."""
    return [_DRY_RUN_NOTICE] if _is_dry_run(event) else []


def _status(event: LifecycleEvent) -> list[str]:
    """What happened and what comes next."""
    if event.decision is not None and event.kind is LifecycleEventKind.DECISION_RECORDED:
        lines = [f"Status: a human decision was recorded: {event.decision.decision.value}."]
    else:
        lines = [_STATUS_LINES[event.kind]]
    if event.report is not None:
        lines.append(f"Overall: {_overall(event)}")
    if event.kind in _NEXT_STEPS:
        lines.append(_NEXT_STEPS[event.kind])
    return lines


def _overall(event: LifecycleEvent) -> str:
    """Overall report state; dry-run reports have none."""
    report = event.report
    if report is None or report.overall is None:
        return "DRY RUN (no overall state)"
    return report.overall.value


def _elevated(event: LifecycleEvent) -> list[str]:
    """Every ELEVATED action with its warnings (always visible)."""
    package = event.package
    if package is None:
        return []
    elevated = [a for a in package.actions if a.approval_level is ApprovalLevel.ELEVATED]
    if not elevated:
        return []
    lines = [f"ELEVATED APPROVAL REQUIRED for {_plural(len(elevated), 'action')}:"]
    for action in elevated:
        lines.append(f"  - {_action_label(action)}")
        if not action.warnings:
            lines.append("    WARNING: ELEVATED APPROVAL REQUIRED - catalog policy for this action type")
        lines.extend(f"    {_clean(w.message)}" for w in action.warnings)
    return lines


def _score_lines(event: LifecycleEvent) -> list[str]:
    """Risk and confidence, separately."""
    scores = _scores(event)
    if scores is None:
        return []
    risk, confidence, band = scores
    return [f"Risk score: {risk}/100 ({band.value})", f"Confidence score: {confidence}/100"]


def _evidence(event: LifecycleEvent) -> list[str]:
    """Numbered package evidence, else the summary's record lines."""
    if event.package is not None:
        items = sorted(event.package.evidence, key=lambda e: e.number)
        return ["Evidence (numbered, from the package):", *(_evidence_line(e) for e in items)]
    if event.summary is not None and event.summary.evidence:
        return ["Evidence (investigation records):", *(f"  {_clean(line)}" for line in event.summary.evidence)]
    return []


def _evidence_line(evidence: Evidence) -> str:
    """``[n] source: summary (observed <ts>)`` (no data, no reference)."""
    line = f"  [{evidence.number}] {_clean(evidence.source)}: {_clean(evidence.summary)}"
    if evidence.observed_at is not None:
        line += f" (observed {_fmt_dt(evidence.observed_at)})"
    return line


def _actions(event: LifecycleEvent) -> list[str]:
    """Proposed actions with approval level, scores, evidence numbers and rollback."""
    package = event.package
    if package is None:
        return []
    noun = "restoration" if isinstance(package, ReleasePackage) else "containment"
    lines = [f"Proposed {noun} actions ({len(package.actions)}):"]
    for index, action in enumerate(package.actions, start=1):
        numbers = ", ".join(str(n) for n in _package_numbers(action, package)) or "n/a"
        lines.append(
            f"  {index}. {_action_label(action)} [{action.approval_level.value}] "
            f"risk {action.risk_score} confidence {action.confidence_score} "
            f"evidence [{numbers}]; {_rollback_text(action.action_type)}"
        )
    lines.extend(_excluded(package))
    lines.extend(_blast_radius(package.blast_radius))
    return lines


def _evidence_key(evidence: Evidence) -> bytes:
    """Content identity of an evidence item (everything but its number)."""
    return canonical_json(evidence.model_dump(mode="python", exclude={"number"}), allow_floats=True)


def _package_numbers(action: RecommendedAction, package: ActionPackage) -> tuple[int, ...]:
    """Package evidence numbers supporting ``action``, matched by content (never by local number)."""
    index = {_evidence_key(e): e.number for e in package.evidence}
    return tuple(sorted({index[k] for k in map(_evidence_key, action.evidence) if k in index}))


def _excluded(package: ActionPackage) -> list[str]:
    """Targets the package deliberately did not propose."""
    if not package.excluded_targets:
        return []
    return ["Excluded (not proposed):", *(
        f"  - {x.action_type.value} {_clean(x.target)}: {_clean(x.reason)}" for x in package.excluded_targets
    )]


def _blast_radius(radius: BlastRadius) -> list[str]:
    """One-line blast radius, only when something is affected."""
    parts = []
    if radius.endpoints:
        parts.append(_plural(len(radius.endpoints), "endpoint"))
    if radius.users:
        parts.append(_plural(len(radius.users), "user"))
    if radius.indicators:
        parts.append(_plural(len(radius.indicators), "indicator"))
    if radius.messages:
        parts.append(_plural(radius.messages, "message"))
    return [f"Blast radius: {', '.join(parts)}"] if parts else []


def _decision(event: LifecycleEvent) -> list[str]:
    """The human decision: who decided, what was approved and rejected."""
    decision = event.decision
    if decision is None:
        return []
    kind = "release decision" if decision.purpose is ApprovalPurpose.RELEASE else "decision"
    lines = [
        f"Human {kind}: {decision.decision.value} at {_fmt_dt(decision.decided_at)}",
        f"Approvers: {_approvers(decision)}",
    ]
    lines.extend(_key_list("Approved actions", event.package, decision.approved_action_keys))
    lines.extend(_key_list("Rejected actions", event.package, decision.rejected_action_keys))
    if decision.comment.strip():
        lines.append(f"Comment: {_clean(decision.comment)}")
    if decision.token_id:
        lines.append(f"Approval token id prefix: {_clean(decision.token_id[:_TOKEN_PREFIX_CHARS])}")
    return lines


def _approvers(decision: AnalystDecision) -> str:
    """``principal (display name, KIND); ...`` or ``none``."""
    if not decision.approvers:
        return _clean(decision.analyst_identity) if decision.analyst_identity else "none"
    return "; ".join(
        f"{_clean(p.principal_id)} ({_clean(p.display_name)}, {p.kind.value})" for p in decision.approvers
    )


def _key_list(heading: str, package: ActionPackage | None, keys: Sequence[str]) -> list[str]:
    """Heading with a count and one line per action key."""
    if not keys:
        return [f"{heading}: none"]
    return [f"{heading} ({len(keys)}):", *(f"  - {_key_label(package, k)}" for k in keys)]


def _report(event: LifecycleEvent) -> list[str]:
    """Per-action execution results with verification and rollback (no vendor payloads)."""
    report = event.report
    if report is None:
        return []
    noun = "Containment" if isinstance(report, ContainmentReport) else "Restoration"
    lines = [f"{noun} results ({len(report.results)}):"]
    lines.extend(_result_line(r) for r in report.results)
    if report.attention:
        lines.append("Requires attention:")
        lines.extend(f"  - {_clean(item)}" for item in report.attention)
    return lines


def _result_line(result: ActionResult) -> str:
    """``- <action> <target>: STATUS (detail); verification X; rollback ...``."""
    parts = [f"  - {result.action_type.value} {_clean(result.target)}: {result.status.value}"]
    if result.skip_reason is not None:
        parts[0] += f" ({result.skip_reason.value})"
    if result.error is not None:
        parts[0] += f" ({result.error.code.value})"
    if result.dry_run_line:
        parts.append(f"DRY RUN: {_clean(result.dry_run_line)}")
    if result.verification is not None:
        parts.append(f"verification {result.verification.status.value}")
    if result.requires_attention:
        parts.append("requires attention")
    if result.recommended_escalation:
        parts.append(f"escalation: {_clean(result.recommended_escalation)}")
    parts.append(_rollback_text(result.action_type))
    return "; ".join(parts)


def _investigation(event: LifecycleEvent) -> list[str]:
    """Degraded sources, unrouted actions and below-threshold findings from the workflow run."""
    summary = event.summary
    if summary is None:
        return []
    lines: list[str] = []
    lines.extend(_bullets("Degraded or failed sources (other evidence was used)", summary.degraded_sources))
    lines.extend(_bullets("Not routable (no capable adapter)", summary.unrouted))
    lines.extend(_bullets("Below threshold (not proposed)", summary.below_threshold))
    if event.package is None:
        lines.extend(_blast_radius(summary.blast_radius))
    return lines


def _bullets(heading: str, items: Sequence[str]) -> list[str]:
    """``heading:`` followed by one cleaned bullet per item; empty when there are no items."""
    if not items:
        return []
    return [f"{heading}:", *(f"  - {_clean(item)}" for item in items)]


def _notes(event: LifecycleEvent) -> list[str]:
    """Workflow and lifecycle notes."""
    return _bullets("Notes", event.notes)


def _ai_narrative(event: LifecycleEvent) -> list[str]:
    """AI text under its heading, line by line (analyst summary only)."""
    narrative = event.incident.ai_narrative
    if not narrative or not narrative.strip():
        return []
    lines = [_clean(line) for line in narrative.splitlines()]
    body = [f"  {line}" for line in lines if line]
    return [_AI_NARRATIVE_HEADING, *body] if body else []


_INCIDENT_SECTIONS: tuple[Section, ...] = (
    _header, _dry_run, _status, _elevated, _score_lines, _evidence, _actions, _decision, _report,
    _investigation, _notes,
)
_SOC_SECTIONS: tuple[Section, ...] = (
    _header, _dry_run, _status, _elevated, _score_lines, _actions, _decision, _report, _evidence,
)
_ANALYST_SECTIONS: tuple[Section, ...] = (*_INCIDENT_SECTIONS, _ai_narrative)


# ----------------------------------------------------------------------------------- assembly --
#: Sections never truncated out of a body: the DRY RUN notice and the ELEVATED warnings stay
#: visible whatever the length of the free text around them (titles, notes, evidence, narrative).
_PINNED_SECTIONS: frozenset[Section] = frozenset({_dry_run, _elevated})
_BLOCK_SEPARATOR = "\n\n"


def _utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _fit_blocks(blocks: list[tuple[bool, str]], limit: int) -> list[str]:
    """Blocks that fit in ``limit`` UTF-8 bytes (joined by blank lines), pinned blocks always kept.

    Pinned blocks are budgeted first; the other blocks share what is left in order. The block that
    overflows is cut and marked ``[truncated]``, and later unpinned blocks are dropped.
    """
    sep = _utf8_len(_BLOCK_SEPARATOR)
    total = sum(_utf8_len(text) for _, text in blocks) + sep * max(0, len(blocks) - 1)
    if total <= limit:
        return [text for _, text in blocks]
    budget = limit - sum(_utf8_len(text) + sep for pinned, text in blocks if pinned)
    kept: list[str] = []
    cut = False
    for pinned, text in blocks:
        if pinned:
            kept.append(text)
            continue
        if cut:
            continue
        need = _utf8_len(text) + sep
        if need <= budget:
            kept.append(text)
            budget -= need
            continue
        cut = True
        room = budget - sep
        if room > _utf8_len(_TRUNCATION_MARK) + 1:
            kept.append(_cap_utf8(text, room))
        elif room >= _utf8_len(_TRUNCATION_MARK):
            kept.append(_TRUNCATION_MARK)
    return kept


def _body(event: LifecycleEvent, sections: Sequence[Section]) -> str:
    """Sections joined by blank lines, redacted, capped at 16 KiB; the footer is always kept.

    The DRY RUN notice and the ELEVATED warnings (:data:`_PINNED_SECTIONS`) are never truncated
    out: free text can only shorten the other sections (:func:`_fit_blocks`).
    """
    redactor = get_redactor()
    blocks = [(section in _PINNED_SECTIONS, redactor.redact_text("\n".join(lines)))
              for section, lines in ((s, s(event)) for s in sections) if lines]
    footer = _BLOCK_SEPARATOR + _FOOTER
    limit = _MAX_BODY_BYTES - _utf8_len(footer)
    text = redactor.redact_text(_BLOCK_SEPARATOR.join(_fit_blocks(blocks, limit)))
    return _cap_utf8(text, limit) + footer


def _title(text: str, event: LifecycleEvent) -> str:
    """Cleaned title with the ``[DRY RUN] `` prefix in dry run, at most 200 characters."""
    prefix = _DRY_RUN_PREFIX if _is_dry_run(event) else ""
    return _cap_title(prefix + _clean(text))


def _elevated_flag(event: LifecycleEvent) -> str:
    """`` (ELEVATED)`` when the package needs ELEVATED approval."""
    return " (ELEVATED)" if event.package is not None and event.package.has_elevated else ""


def _draft(kind: NotificationKind, event: LifecycleEvent, title: str, sections: Sequence[Section]) -> NotificationDraft:
    """Assemble one draft."""
    body = _body(event, sections)
    workflow_id, version = _workflow(event)
    return NotificationDraft(
        notification_id=_notification_id(kind, event),
        kind=kind,
        event=event.kind,
        incident_id=event.incident.incident_id,
        created_at=event.at,
        audience=_AUDIENCE[kind],  # type: ignore[arg-type]
        title=_title(title, event),
        body=body,
        workflow_id=workflow_id,
        workflow_version=version,
        contains_ai_text=_AI_NARRATIVE_HEADING in body.splitlines(),
    )


def _check(event: object) -> LifecycleEvent:
    """Type check before any attribute is read."""
    if not isinstance(event, LifecycleEvent):
        raise TypeError(f"expected LifecycleEvent, got {type(event).__name__}")
    return event


def render_incident_note(event: LifecycleEvent) -> NotificationDraft:
    """The incident record: full facts of this lifecycle moment (no AI text)."""
    event = _check(event)
    title = f"Incident note {event.incident.incident_id}: {_EVENT_LABELS[event.kind]}{_elevated_flag(event)}"
    return _draft(NotificationKind.INCIDENT_NOTE, event, title, _INCIDENT_SECTIONS)


def render_soc_notification(event: LifecycleEvent) -> NotificationDraft:
    """Concise SOC notice: status, warnings, scores, actions, decision, results, evidence."""
    event = _check(event)
    incident = event.incident
    title = (f"[{incident.severity.value}] {incident.incident_id} {_EVENT_LABELS[event.kind]}"
             f"{_elevated_flag(event)}: {incident.title}")
    return _draft(NotificationKind.SOC_NOTIFICATION, event, title, _SOC_SECTIONS)


def render_analyst_summary(event: LifecycleEvent) -> NotificationDraft:
    """Everything in the incident note plus the flagged AI narrative, when one exists."""
    event = _check(event)
    title = f"Analyst summary {event.incident.incident_id}: {_EVENT_LABELS[event.kind]}{_elevated_flag(event)}"
    return _draft(NotificationKind.ANALYST_SUMMARY, event, title, _ANALYST_SECTIONS)
