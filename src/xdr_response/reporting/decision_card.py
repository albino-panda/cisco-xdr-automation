"""Concise analyst decision card for a containment package (architecture section 9).

Plain-text layout::

    CRITICAL INCIDENT  XDR-83921
    Potential ransomware
    Endpoint: TH-LT-1047
    User: jsmith@example.com
    Risk 97/100 (CRITICAL)   Confidence 94%
    Primary evidence:
      [1] secure_endpoint: ransomware detection on TH-LT-1047
    Blast radius: 1 endpoint, 1 user, 1 domain
    Recommended containment:
      [ ] isolate_endpoint TH-LT-1047  (STANDARD)  risk 97  confidence 94%  via ...  evidence [1]
    Excluded (allow-listed, not proposed):          (only when present)
    WARNING: ELEVATED APPROVAL REQUIRED             (one block per reason, only when present)
    Package <id>  workflow <id> <version>  evidence sha256 <12 hex>  approve before <ts>
    [APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]

The card only renders; it never approves, executes or changes anything. Every string is redacted
and flattened to one line before it is shown.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from xdr_response.logs.redaction import Redactor
from xdr_response.models import ActionPackage, DecisionType, ReleasePackage, risk_band
from xdr_response.reporting._package import (
    ActionItem,
    action_items,
    blast_radius,
    blast_radius_phrase,
    package_footer,
    package_meta,
)
from xdr_response.reporting._text import (
    OutputFormat,
    clean,
    dump_json,
    md_code,
    md_text,
    pad_columns,
    resolve_redactor,
)
from xdr_response.reporting.elevated import ElevatedWarning, elevated_warnings
from xdr_response.reporting.evidence import EvidenceItem, evidence_items

__all__ = [
    "DECISION_OPTIONS",
    "DEFAULT_MAX_EVIDENCE",
    "DRY_RUN_PACKAGE_NOTICE",
    "DecisionCard",
    "ExcludedItem",
    "build_decision_card",
    "render_decision_card",
    "decision_card_text",
    "decision_card_markdown",
    "decision_card_json",
]

#: (button label, decision type) in display order.
DECISION_OPTIONS: tuple[tuple[str, DecisionType], ...] = (
    ("APPROVE ALL", DecisionType.APPROVE_ALL),
    ("APPROVE SELECTED", DecisionType.APPROVE_SELECTED),
    ("REQUEST MORE INVESTIGATION", DecisionType.REQUEST_MORE_INVESTIGATION),
    ("REJECT", DecisionType.REJECT),
)
DEFAULT_MAX_EVIDENCE = 10
DRY_RUN_PACKAGE_NOTICE = "DRY RUN package: approval is simulated; no containment actions will be executed."


@dataclass(frozen=True)
class ExcludedItem:
    """An allow-listed target that was not proposed (shown, never dropped silently)."""

    action_type: str
    target: str
    reason: str

    def text(self) -> str:
        """``block_domain example.com: allowlists.never_block.domains: example.com``."""
        return f"{self.action_type} {self.target}: {self.reason}"

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping."""
        return {"action_type": self.action_type, "target": self.target, "reason": self.reason}


@dataclass(frozen=True)
class DecisionCard:
    """Render-ready view of a containment package. Build with :func:`build_decision_card`."""

    incident_id: str
    severity: str
    title: str
    endpoints: tuple[str, ...]
    users: tuple[str, ...]
    risk_score: int
    risk_band: str
    confidence_score: int
    evidence: tuple[EvidenceItem, ...]
    evidence_total: int
    blast_radius: dict[str, int]
    actions: tuple[ActionItem, ...]
    excluded: tuple[ExcludedItem, ...]
    warnings: tuple[ElevatedWarning, ...]
    meta: dict[str, Any]

    @property
    def blast_radius_phrase(self) -> str:
        """Blast radius as a short phrase."""
        return blast_radius_phrase(self.blast_radius)

    @property
    def hidden_evidence(self) -> int:
        """Evidence items not shown on the card (see the full package)."""
        return self.evidence_total - len(self.evidence)


def build_decision_card(package: ActionPackage, *, incident_title: str | None = None,
                        redactor: Redactor | None = None,
                        max_evidence: int = DEFAULT_MAX_EVIDENCE) -> DecisionCard:
    """Build the card view of ``package`` (all strings redacted and single-line)."""
    red = resolve_redactor(redactor)
    items = evidence_items(package.evidence, red)
    return DecisionCard(
        incident_id=clean(package.incident_id, red),
        severity=package.severity.value,
        title=clean(incident_title if incident_title else package.summary, red),
        endpoints=tuple(clean(e, red) for e in package.endpoints),
        users=tuple(clean(u, red) for u in package.users),
        risk_score=package.risk_score,
        risk_band=risk_band(package.risk_score).value,
        confidence_score=package.confidence_score,
        evidence=items[:max(max_evidence, 1)],
        evidence_total=len(items),
        blast_radius=blast_radius(package),
        actions=action_items(package, red),
        excluded=tuple(
            ExcludedItem(action_type=x.action_type.value, target=clean(x.target, red),
                         reason=clean(x.reason, red))
            for x in package.excluded_targets
        ),
        warnings=elevated_warnings(package.actions, red),
        meta=package_meta(package, red),
    )


def _labelled(label: str, plural: str, values: tuple[str, ...]) -> str:
    return f"{plural if len(values) > 1 else label}: {', '.join(values) or 'none'}"


def _md_labelled(label: str, plural: str, values: tuple[str, ...]) -> str:
    joined = ", ".join(md_code(v) for v in values) or "none"
    return f"- **{plural if len(values) > 1 else label}:** {joined}"


def decision_card_text(card: DecisionCard) -> str:
    """Plain-text card (no trailing newline)."""
    lines = [f"{card.severity} INCIDENT  {card.incident_id}", card.title]
    if card.meta["dry_run"]:
        lines.append(DRY_RUN_PACKAGE_NOTICE)
    lines += [
        _labelled("Endpoint", "Endpoints", card.endpoints),
        _labelled("User", "Users", card.users),
        f"Risk {card.risk_score}/100 ({card.risk_band})   Confidence {card.confidence_score}%",
        "Primary evidence:",
        *(f"  {item.text()}" for item in card.evidence),
    ]
    if card.hidden_evidence:
        lines.append(f"  ... {card.hidden_evidence} more evidence items in the full package")
    lines.append(f"Blast radius: {card.blast_radius_phrase}")
    lines.append("Recommended containment:")
    lines += [f"  {row}" for row in pad_columns([a.text_cells() for a in card.actions])]
    if card.excluded:
        lines.append("Excluded (allow-listed, not proposed):")
        lines += [f"  - {x.text()}" for x in card.excluded]
    for warning in card.warnings:
        lines += warning.text_lines()
    lines.append(package_footer(card.meta))
    lines.append(" ".join(f"[{label}]" for label, _ in DECISION_OPTIONS))
    return "\n".join(lines)


def decision_card_markdown(card: DecisionCard) -> str:
    """Markdown card (no trailing newline)."""
    lines = [f"## {card.severity} INCIDENT {md_code(card.incident_id)}", "", f"**{md_text(card.title)}**", ""]
    if card.meta["dry_run"]:
        lines += [f"> **{md_text(DRY_RUN_PACKAGE_NOTICE)}**", ""]
    lines += [
        _md_labelled("Endpoint", "Endpoints", card.endpoints),
        _md_labelled("User", "Users", card.users),
        f"- **Risk:** {card.risk_score}/100 ({card.risk_band})",
        f"- **Confidence:** {card.confidence_score}%",
        f"- **Blast radius:** {card.blast_radius_phrase}",
        "", "### Primary evidence", "",
        *(item.markdown() for item in card.evidence),
    ]
    if card.hidden_evidence:
        lines.append(f"- ... {card.hidden_evidence} more evidence items in the full package")
    lines += ["", "### Recommended containment", "", *(a.markdown() for a in card.actions)]
    if card.excluded:
        lines += ["", "### Excluded (allow-listed, not proposed)", ""]
        lines += [f"- {md_code(x.action_type + ' ' + x.target)}: {md_text(x.reason)}" for x in card.excluded]
    for warning in card.warnings:
        lines += ["", *warning.markdown_lines()]
    lines += ["", package_footer(card.meta, markdown=True), "",
              " ".join(f"**[{label}]**" for label, _ in DECISION_OPTIONS)]
    return "\n".join(lines)


def decision_card_json(card: DecisionCard) -> str:
    """JSON card (sorted keys, 2-space indent)."""
    data = {
        "kind": "decision_card",
        "incident_id": card.incident_id,
        "severity": card.severity,
        "title": card.title,
        "endpoints": list(card.endpoints),
        "users": list(card.users),
        "risk_score": card.risk_score,
        "risk_band": card.risk_band,
        "confidence_score": card.confidence_score,
        "evidence": [item.to_dict() for item in card.evidence],
        "evidence_total": card.evidence_total,
        "blast_radius": dict(card.blast_radius, summary=card.blast_radius_phrase),
        "recommended_actions": [a.to_dict() for a in card.actions],
        "excluded_targets": [x.to_dict() for x in card.excluded],
        "elevated_warnings": [w.to_dict() for w in card.warnings],
        "package": card.meta,
        "decision_options": [{"label": label, "decision": d.value} for label, d in DECISION_OPTIONS],
    }
    return dump_json(data)


def render_decision_card(package: ActionPackage, *, incident_title: str | None = None,
                         fmt: OutputFormat | str = OutputFormat.TEXT,
                         redactor: Redactor | None = None,
                         max_evidence: int = DEFAULT_MAX_EVIDENCE) -> str:
    """Render the decision card of ``package`` as text (default), Markdown or JSON.

    A :class:`ReleasePackage` is rendered as the release checklist instead (it is approved with a
    separate release approval, never with the containment options).
    """
    if isinstance(package, ReleasePackage):
        from xdr_response.reporting.release_checklist import render_release_checklist

        return render_release_checklist(package, incident_title=incident_title, fmt=fmt,
                                        redactor=redactor, max_evidence=max_evidence)
    card = build_decision_card(package, incident_title=incident_title, redactor=redactor,
                               max_evidence=max_evidence)
    renderers = {OutputFormat.TEXT: decision_card_text, OutputFormat.MARKDOWN: decision_card_markdown,
                 OutputFormat.JSON: decision_card_json}
    return renderers[OutputFormat(fmt)](card)
