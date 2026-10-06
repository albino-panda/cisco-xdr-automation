"""Analyst output: decision card, containment/restoration result, release checklist.

Renderers only format data; they never approve, execute or change state. Every string shown is
redacted with the central redactor and flattened to one line. Formats: text (default), Markdown,
JSON.
"""
from __future__ import annotations

from xdr_response.reporting._text import OutputFormat
from xdr_response.reporting.containment_report import (
    ResultReport,
    build_result_report,
    render_containment_report,
)
from xdr_response.reporting.decision_card import (
    DECISION_OPTIONS,
    DecisionCard,
    build_decision_card,
    render_decision_card,
)
from xdr_response.reporting.elevated import ELEVATED_TITLE, ElevatedWarning, elevated_warnings
from xdr_response.reporting.evidence import EvidenceItem, evidence_items, evidence_numbers
from xdr_response.reporting.release_checklist import (
    RELEASE_OPTIONS,
    ReleaseChecklist,
    build_release_checklist,
    release_step,
    render_release_checklist,
)

__all__ = [
    "DECISION_OPTIONS",
    "ELEVATED_TITLE",
    "RELEASE_OPTIONS",
    "DecisionCard",
    "ElevatedWarning",
    "EvidenceItem",
    "OutputFormat",
    "ReleaseChecklist",
    "ResultReport",
    "build_decision_card",
    "build_release_checklist",
    "build_result_report",
    "elevated_warnings",
    "evidence_items",
    "evidence_numbers",
    "release_step",
    "render_containment_report",
    "render_decision_card",
    "render_release_checklist",
]
