"""Private view pieces shared by the decision card and the release checklist."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from xdr_response.logs.redaction import Redactor
from xdr_response.models import ActionPackage, RecommendedAction, TargetKind
from xdr_response.reporting._text import clean, count_phrase, fmt_dt, md_code, short_hash
from xdr_response.reporting.evidence import evidence_numbers

__all__ = ["ActionItem", "action_items", "blast_radius", "blast_radius_phrase", "package_meta",
           "package_footer", "format_numbers"]

# (target kind, json key, singular, plural) in display order
_INDICATOR_KINDS: tuple[tuple[TargetKind, str, str, str], ...] = (
    (TargetKind.DOMAIN, "domains", "domain", "domains"),
    (TargetKind.URL, "urls", "URL", "URLs"),
    (TargetKind.IP, "ips", "IP address", "IP addresses"),
    (TargetKind.HASH, "hashes", "file hash", "file hashes"),
)


def format_numbers(numbers: tuple[int, ...]) -> str:
    """``(1, 2)`` -> ``"[1, 2]"``; empty -> ``"[-]"``."""
    return "[" + (", ".join(str(n) for n in numbers) or "-") + "]"


@dataclass(frozen=True)
class ActionItem:
    """One checklist row (strings redacted, single-line)."""

    key: str
    action_type: str
    target: str
    integration: str
    approval_level: str
    risk_score: int
    confidence_score: int
    evidence: tuple[int, ...]
    rationale: str
    params: dict[str, Any]
    label: str

    def text_cells(self) -> list[str]:
        """Cells of the plain-text checkbox row."""
        return [f"[ ] {self.label}", f"({self.approval_level})", f"risk {self.risk_score}",
                f"confidence {self.confidence_score}%", f"via {self.integration}",
                f"evidence {format_numbers(self.evidence)}"]

    def markdown(self) -> str:
        """Markdown task-list row."""
        return (f"- [ ] {md_code(self.label)} **{self.approval_level}**, risk {self.risk_score}, "
                f"confidence {self.confidence_score}%, via {md_code(self.integration)}, "
                f"evidence {format_numbers(self.evidence)}")

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping (params already redacted)."""
        return {"idempotency_key": self.key, "action_type": self.action_type, "target": self.target,
                "integration": self.integration, "approval_level": self.approval_level,
                "risk_score": self.risk_score, "confidence_score": self.confidence_score,
                "evidence": list(self.evidence), "rationale": self.rationale, "params": self.params,
                "label": self.label}


def _default_label(action: RecommendedAction, target: str) -> str:
    return f"{action.action_type.value} {target}"


def action_items(package: ActionPackage, redactor: Redactor,
                 label: Callable[[RecommendedAction, str], str] = _default_label) -> tuple[ActionItem, ...]:
    """Checklist rows in package order."""
    items = []
    for action in package.actions:
        target = clean(action.target, redactor)
        items.append(ActionItem(
            key=clean(action.idempotency_key, redactor), action_type=action.action_type.value,
            target=target, integration=clean(action.integration, redactor),
            approval_level=action.approval_level.value, risk_score=action.risk_score,
            confidence_score=action.confidence_score,
            evidence=evidence_numbers(action, package.evidence),
            rationale=clean(action.rationale, redactor), params=redactor.redact(dict(action.params)),
            label=clean(label(action, target), redactor),
        ))
    return tuple(items)


def _targets(package: ActionPackage, kind: TargetKind) -> set[str]:
    return {a.target for a in package.actions if a.target_kind is kind}


def blast_radius(package: ActionPackage) -> dict[str, int]:
    """Counts of affected objects: package blast radius merged with the action targets."""
    br = package.blast_radius
    counts = {
        "endpoints": len(set(br.endpoints) | set(package.endpoints) | _targets(package, TargetKind.ENDPOINT)),
        "users": len(set(br.users) | set(package.users) | _targets(package, TargetKind.USER)),
    }
    indicator_targets: set[str] = set()
    for kind, key, _, _ in _INDICATOR_KINDS:
        targets = _targets(package, kind)
        indicator_targets |= targets
        counts[key] = len(targets)
    counts["other_indicators"] = len(set(br.indicators) - indicator_targets)
    counts["messages"] = max(br.messages, len(_targets(package, TargetKind.EMAIL_MESSAGE)))
    return counts


def blast_radius_phrase(counts: dict[str, int]) -> str:
    """``"1 endpoint, 1 user, 1 domain"``; zero counts are omitted; nothing -> ``"none"``."""
    words = [("endpoints", "endpoint", "endpoints"), ("users", "user", "users")]
    words += [(key, singular, plural) for _, key, singular, plural in _INDICATOR_KINDS]
    words += [("other_indicators", "other indicator", "other indicators"),
              ("messages", "email message", "email messages")]
    parts = [count_phrase(counts[key], s, p) for key, s, p in words if counts.get(key)]
    return ", ".join(parts) or "none"


def package_meta(package: ActionPackage, redactor: Redactor) -> dict[str, Any]:
    """Identifiers the analyst needs to submit a decision (no secrets)."""
    return {
        "package_id": clean(package.package_id, redactor),
        "purpose": package.purpose.value,
        "workflow_id": clean(package.workflow_id, redactor),
        "workflow_version": clean(package.workflow_version, redactor),
        "evidence_snapshot_hash": package.evidence_snapshot_hash,
        "created_at": fmt_dt(package.created_at),
        "expires_at": fmt_dt(package.expires_at),
        "requested_by": clean(package.requested_by, redactor),
        "dry_run": package.dry_run,
    }


def package_footer(meta: dict[str, Any], *, markdown: bool = False) -> str:
    """``Package <id>  workflow <id> <version>  evidence sha256 <12 hex>  approve before <ts>``."""
    if markdown:
        return (f"Package {md_code(meta['package_id'])}, workflow "
                f"{md_code(meta['workflow_id'] + ' ' + meta['workflow_version'])}, evidence sha256 "
                f"{md_code(short_hash(meta['evidence_snapshot_hash']))}, approve before "
                f"{md_code(meta['expires_at'])}")
    return (f"Package {meta['package_id']}  workflow {meta['workflow_id']} {meta['workflow_version']}  "
            f"evidence sha256 {short_hash(meta['evidence_snapshot_hash'])}  "
            f"approve before {meta['expires_at']}")
