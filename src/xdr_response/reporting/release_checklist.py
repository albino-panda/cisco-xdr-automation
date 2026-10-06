"""Release checklist for a release package (architecture sections 5.8 and 8.2).

Plain-text layout::

    RELEASE APPROVAL REQUIRED  XDR-83921
    Release temporary controls for XDR-83921
    Temporary controls to release: 2
    Evidence:
      [1] temporary_control_registry: ...
    Release checklist:
      [ ] Restore endpoint connectivity: TH-LT-1047  (STANDARD)  via secure_endpoint  restores ...
    WARNING: ELEVATED APPROVAL REQUIRED             (only when present)
    Controls not listed here stay ACTIVE. Closing the incident never removes controls.
    Package <id>  workflow <id> <version>  evidence sha256 <12 hex>  approve before <ts>
    [APPROVE RELEASE] [REJECT]

Release needs its own approval (purpose ``release``); a containment approval never covers it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from xdr_response.logs.redaction import Redactor
from xdr_response.models import ActionType, DecisionType, RecommendedAction, ReleasePackage
from xdr_response.reporting._package import action_items, package_footer, package_meta
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
    "RELEASE_OPTIONS",
    "RELEASE_NOTICE",
    "ReleaseItem",
    "ReleaseChecklist",
    "release_step",
    "build_release_checklist",
    "render_release_checklist",
    "release_checklist_text",
    "release_checklist_markdown",
    "release_checklist_json",
]

RELEASE_OPTIONS: tuple[tuple[str, DecisionType], ...] = (
    ("APPROVE RELEASE", DecisionType.APPROVE_ALL),
    ("REJECT", DecisionType.REJECT),
)
RELEASE_NOTICE = "Controls not listed here stay ACTIVE. Closing the incident never removes controls."

_INTEGRATION_NAMES: dict[str, str] = {
    "cisco_xdr": "Cisco XDR", "secure_endpoint": "Secure Endpoint", "secure_email": "Secure Email",
    "umbrella": "Umbrella", "meraki": "Meraki", "entra": "Entra", "defender_endpoint": "Defender",
    "defender_o365": "Defender for Office 365", "intune": "Intune",
}

_STEPS: dict[ActionType, str] = {
    ActionType.RELEASE_ENDPOINT: "Restore endpoint connectivity",
    ActionType.UNBLOCK_DOMAIN: "Remove temporary {vendor} domain block",
    ActionType.UNBLOCK_URL: "Remove temporary {vendor} URL block",
    ActionType.UNBLOCK_IP: "Remove temporary {vendor} IP block",
    ActionType.UNBLOCK_HASH: "Remove temporary {vendor} hash block",
    ActionType.ENABLE_USER: "Re-enable {vendor} account",
    ActionType.RELEASE_EMAIL: "Release quarantined email",
    ActionType.RESTORE_NETWORK_CLIENT: "Restore {vendor} network client policy",
    ActionType.RESTORE_PRIVILEGED_ROLE: "Restore privileged role assignment",
    ActionType.RESTORE_FILE: "Restore quarantined file",
}


def release_step(action: RecommendedAction, target: str) -> str:
    """Human checklist step, e.g. ``"Remove temporary Umbrella domain block: evil.example.com"``."""
    vendor = _INTEGRATION_NAMES.get(action.integration, action.integration)
    template = _STEPS.get(action.action_type, action.action_type.value.replace("_", " ").capitalize())
    return f"{template.format(vendor=vendor)}: {target}"


@dataclass(frozen=True)
class ReleaseItem:
    """One release checklist row."""

    key: str
    action_type: str
    target: str
    integration: str
    approval_level: str
    step: str
    restores: str
    params: dict[str, Any]

    def text_cells(self) -> list[str]:
        """Cells of the plain-text checkbox row."""
        return [f"[ ] {self.step}", f"({self.approval_level})", f"via {self.integration}",
                f"restores {self.restores}"]

    def markdown(self) -> str:
        """Markdown task-list row."""
        return (f"- [ ] {md_text(self.step)} **{self.approval_level}**, via {md_code(self.integration)}, "
                f"restores {md_code(self.restores)}")

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping (params already redacted)."""
        return {"idempotency_key": self.key, "action_type": self.action_type, "target": self.target,
                "integration": self.integration, "approval_level": self.approval_level,
                "step": self.step, "restores": self.restores, "params": self.params}


@dataclass(frozen=True)
class ReleaseChecklist:
    """Render-ready view of a release package. Build with :func:`build_release_checklist`."""

    incident_id: str
    title: str
    evidence: tuple[EvidenceItem, ...]
    evidence_total: int
    items: tuple[ReleaseItem, ...]
    warnings: tuple[ElevatedWarning, ...]
    meta: dict[str, Any]


def build_release_checklist(package: ReleasePackage, *, incident_title: str | None = None,
                            redactor: Redactor | None = None, max_evidence: int = 10) -> ReleaseChecklist:
    """Build the checklist view of ``package`` (all strings redacted and single-line)."""
    red = resolve_redactor(redactor)
    rows = action_items(package, red, label=release_step)
    evidence = evidence_items(package.evidence, red)
    return ReleaseChecklist(
        incident_id=clean(package.incident_id, red),
        title=clean(incident_title if incident_title else package.summary, red),
        evidence=evidence[:max(max_evidence, 1)],
        evidence_total=len(evidence),
        items=tuple(
            ReleaseItem(key=row.key, action_type=row.action_type, target=row.target,
                        integration=row.integration, approval_level=row.approval_level,
                        step=row.label, restores=clean(control_key, red), params=row.params)
            for row, control_key in zip(rows, package.control_keys)
        ),
        warnings=elevated_warnings(package.actions, red),
        meta=package_meta(package, red),
    )


def release_checklist_text(view: ReleaseChecklist) -> str:
    """Plain-text checklist; the last line is ``[APPROVE RELEASE] [REJECT]``."""
    lines = [f"RELEASE APPROVAL REQUIRED  {view.incident_id}", view.title,
             f"Temporary controls to release: {len(view.items)}", "Evidence:",
             *(f"  {item.text()}" for item in view.evidence)]
    if view.evidence_total > len(view.evidence):
        lines.append(f"  ... {view.evidence_total - len(view.evidence)} more evidence items in the full package")
    lines.append("Release checklist:")
    lines += [f"  {row}" for row in pad_columns([i.text_cells() for i in view.items])]
    for warning in view.warnings:
        lines += warning.text_lines()
    lines += [RELEASE_NOTICE, package_footer(view.meta),
              " ".join(f"[{label}]" for label, _ in RELEASE_OPTIONS)]
    return "\n".join(lines)


def release_checklist_markdown(view: ReleaseChecklist) -> str:
    """Markdown checklist."""
    lines = [f"## RELEASE APPROVAL REQUIRED {md_code(view.incident_id)}", "", f"**{md_text(view.title)}**",
             "", f"- **Temporary controls to release:** {len(view.items)}", "", "### Evidence", "",
             *(item.markdown() for item in view.evidence)]
    if view.evidence_total > len(view.evidence):
        lines.append(f"- ... {view.evidence_total - len(view.evidence)} more evidence items in the full package")
    lines += ["", "### Release checklist", "", *(i.markdown() for i in view.items)]
    for warning in view.warnings:
        lines += ["", *warning.markdown_lines()]
    lines += ["", md_text(RELEASE_NOTICE), "", package_footer(view.meta, markdown=True), "",
              " ".join(f"**[{label}]**" for label, _ in RELEASE_OPTIONS)]
    return "\n".join(lines)


def release_checklist_json(view: ReleaseChecklist) -> str:
    """JSON checklist (sorted keys, 2-space indent)."""
    data = {
        "kind": "release_checklist",
        "incident_id": view.incident_id,
        "title": view.title,
        "evidence": [item.to_dict() for item in view.evidence],
        "evidence_total": view.evidence_total,
        "release_actions": [i.to_dict() for i in view.items],
        "elevated_warnings": [w.to_dict() for w in view.warnings],
        "notice": RELEASE_NOTICE,
        "package": view.meta,
        "decision_options": [{"label": label, "decision": d.value} for label, d in RELEASE_OPTIONS],
    }
    return dump_json(data)


def render_release_checklist(package: ReleasePackage, *, incident_title: str | None = None,
                             fmt: OutputFormat | str = OutputFormat.TEXT,
                             redactor: Redactor | None = None, max_evidence: int = 10) -> str:
    """Render the release checklist as text (default; ends with ``[APPROVE RELEASE] [REJECT]``),
    Markdown or JSON."""
    if not isinstance(package, ReleasePackage):
        raise TypeError("render_release_checklist needs a ReleasePackage")
    view = build_release_checklist(package, incident_title=incident_title, redactor=redactor,
                                   max_evidence=max_evidence)
    renderers = {OutputFormat.TEXT: release_checklist_text, OutputFormat.MARKDOWN: release_checklist_markdown,
                 OutputFormat.JSON: release_checklist_json}
    return renderers[OutputFormat(fmt)](view)
