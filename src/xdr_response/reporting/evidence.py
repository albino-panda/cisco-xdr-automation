"""Numbered, sourced evidence statements for analyst output."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from xdr_response.logs.redaction import Redactor
from xdr_response.models import Evidence, EvidenceDraft, RecommendedAction, canonical_json
from xdr_response.reporting._text import clean, fmt_dt, md_code, md_text

__all__ = ["EvidenceItem", "evidence_items", "evidence_numbers"]


@dataclass(frozen=True)
class EvidenceItem:
    """One evidence statement: ``[n] source: summary``. All strings are redacted, single-line."""

    number: int
    source: str
    summary: str
    reference: str | None
    observed_at: str | None

    def text(self) -> str:
        """Plain-text form, e.g. ``[1] secure_endpoint: ransomware detection on TH-LT-1047``."""
        return f"[{self.number}] {self.source}: {self.summary}"

    def markdown(self) -> str:
        """Markdown list item with the reference (if any) as a code span."""
        line = f"- **[{self.number}]** {md_code(self.source)}: {md_text(self.summary)}"
        if self.reference:
            line += f" (ref {md_code(self.reference)})"
        return line

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping."""
        return {"number": self.number, "source": self.source, "summary": self.summary,
                "reference": self.reference, "observed_at": self.observed_at}


def evidence_items(evidence: Sequence[Evidence], redactor: Redactor) -> tuple[EvidenceItem, ...]:
    """Evidence ordered by number, with every string redacted and flattened to one line."""
    return tuple(
        EvidenceItem(
            number=e.number, source=clean(e.source, redactor), summary=clean(e.summary, redactor),
            reference=clean(e.reference, redactor) if e.reference else None,
            observed_at=fmt_dt(e.observed_at),
        )
        for e in sorted(evidence, key=lambda item: item.number)
    )


def _draft_key(evidence: EvidenceDraft) -> bytes:
    fields = {name: getattr(evidence, name) for name in EvidenceDraft.model_fields}
    return canonical_json(fields, allow_floats=True)


def evidence_numbers(action: RecommendedAction, package_evidence: Sequence[Evidence]) -> tuple[int, ...]:
    """Package evidence numbers that support ``action`` (matched by content, not by number).

    Actions number their own evidence; the package renumbers the merged set. Matching on the
    evidence content maps each action back to the numbers the analyst sees on the card.
    """
    index = {_draft_key(e): e.number for e in package_evidence}
    numbers = {index[key] for key in map(_draft_key, action.evidence) if key in index}
    return tuple(sorted(numbers))
