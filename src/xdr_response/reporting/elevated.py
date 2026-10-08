"""ELEVATED approval warning blocks.

An action on a critical asset (or over a blast-radius threshold, or of an always-elevated type) is
never blocked silently: the analyst sees one warning block per reason, naming the asset, its role,
the action and the potential impact.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from xdr_response.logs.redaction import Redactor
from xdr_response.models import ApprovalLevel, CriticalAssetWarning, RecommendedAction, get_action_spec
from xdr_response.reporting._text import clean, md_code, md_text

__all__ = ["ELEVATED_TITLE", "ELEVATED_NOTICE", "ElevatedWarning", "elevated_warnings"]

ELEVATED_TITLE = "WARNING: ELEVATED APPROVAL REQUIRED"
ELEVATED_NOTICE = "Requires an approver holding the elevated approval role. The action is not blocked."
_MESSAGE_PREFIXES = (f"{ELEVATED_TITLE} - ", f"{ELEVATED_TITLE}: ", ELEVATED_TITLE)


@dataclass(frozen=True)
class ElevatedWarning:
    """One warning block (all strings redacted, single-line)."""

    action_key: str
    action_type: str
    target: str
    asset: str
    asset_class: str | None
    role: str | None
    potential_impact: str | None
    detail: str | None
    reason: str | None

    def _fields(self) -> list[tuple[str, str]]:
        asset = f"{self.asset} ({self.asset_class})" if self.asset_class else self.asset
        rows = [("Action", f"{self.action_type} {self.target}")]
        if self.asset_class or self.asset != self.target:
            rows.append(("Asset", asset))
        optional = (("Role", self.role), ("Potential impact", self.potential_impact),
                    ("Detail", self.detail), ("Reason", self.reason))
        rows.extend((label, value) for label, value in optional if value)
        return rows

    def text_lines(self) -> list[str]:
        """Plain-text block: title line, indented fields, closing notice."""
        body = [f"  {label}: {value}" for label, value in self._fields()]
        return [ELEVATED_TITLE, *body, f"  {ELEVATED_NOTICE}"]

    def markdown_lines(self) -> list[str]:
        """Markdown blockquote."""
        body = [f"> - **{label}:** {md_text(value)}" for label, value in self._fields()]
        body[0] = f"> - **Action:** {md_code(self.action_type)} {md_code(self.target)}"
        return [f"> **{ELEVATED_TITLE}**", ">", *body, ">", f"> {md_text(ELEVATED_NOTICE)}"]

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping."""
        return {"action_key": self.action_key, "action_type": self.action_type, "target": self.target,
                "asset": self.asset, "asset_class": self.asset_class, "role": self.role,
                "potential_impact": self.potential_impact, "detail": self.detail, "reason": self.reason}


def _detail(message: str, redactor: Redactor) -> str | None:
    text = clean(message, redactor)
    for prefix in _MESSAGE_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):].strip(" -:")
            break
    return text or None


#: ``CriticalAssetWarning.role`` prefix the restoration planner uses for an ELEVATED release.
RELEASE_ROLE_PREFIX = "control created under ELEVATED"


def _reason(warning: CriticalAssetWarning) -> str | None:
    """Why an action without a critical-asset class is elevated (shown as the "Reason" line)."""
    if warning.asset_class is not None:
        return None
    if warning.role.startswith(RELEASE_ROLE_PREFIX):  # restoration planner: elevated release
        return "the original control was approved at ELEVATED level, or the rollback is privileged"
    if warning.role == "allow-listed infrastructure address":  # package builder (14.11.7)
        return "the host holds an allow-listed infrastructure address (never_block ips / cidrs)"
    return "blast radius above the configured threshold"  # package builder (role "blast radius")


def _from_warning(action: RecommendedAction, warning: CriticalAssetWarning,
                  redactor: Redactor) -> ElevatedWarning:
    asset_class = warning.asset_class.value if warning.asset_class else None
    return ElevatedWarning(
        action_key=clean(action.idempotency_key, redactor), action_type=action.action_type.value,
        target=clean(action.target, redactor), asset=clean(warning.asset, redactor),
        asset_class=asset_class, role=clean(warning.role, redactor) or None,
        potential_impact=clean(warning.potential_impact, redactor) or None,
        detail=_detail(warning.message, redactor),
        reason=_reason(warning),
    )


def _without_warning(action: RecommendedAction, redactor: Redactor) -> ElevatedWarning:
    spec = get_action_spec(action.action_type)
    reason = (f"{spec.action_type.value} always requires elevated approval" if spec.always_elevated
              else "marked ELEVATED by policy")
    target = clean(action.target, redactor)
    return ElevatedWarning(
        action_key=clean(action.idempotency_key, redactor), action_type=action.action_type.value,
        target=target, asset=target, asset_class=None, role=None, potential_impact=None,
        detail=None, reason=reason,
    )


def elevated_warnings(actions: Sequence[RecommendedAction], redactor: Redactor) -> tuple[ElevatedWarning, ...]:
    """One block per warning of every ELEVATED action, in action order.

    An ELEVATED action that carries no warning (an always-elevated type) still gets a block
    stating the reason, so elevation is never invisible to the analyst.
    """
    blocks: list[ElevatedWarning] = []
    for action in actions:
        if action.approval_level is not ApprovalLevel.ELEVATED:
            continue
        if action.warnings:
            blocks.extend(_from_warning(action, w, redactor) for w in action.warnings)
        else:
            blocks.append(_without_warning(action, redactor))
    return tuple(blocks)
