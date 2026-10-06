"""Who-may-approve rules (architecture section 5.4), shared by the engine and the token verifier.

Pure functions over anything that carries ``principal_id``, ``kind`` and ``roles``
(:class:`AuthenticatedPrincipal` at decision time, :class:`ApproverClaim` inside a token), so the
decision and every later verification apply exactly the same deterministic rules.
"""
from __future__ import annotations

from collections.abc import Collection, Iterable, Sequence
from typing import Protocol

from xdr_response.config import ApprovalSettings
from xdr_response.models import ApprovalLevel, PrincipalKind

__all__ = [
    "ApproverLike",
    "required_role",
    "min_approvers",
    "non_human_principals",
    "duplicate_principals",
    "quorum_failure",
    "has_any_approver_role",
]


class ApproverLike(Protocol):
    """Structural type of an approver: an authenticated principal or a token approver claim."""

    @property
    def principal_id(self) -> str: ...

    @property
    def kind(self) -> PrincipalKind: ...

    @property
    def roles(self) -> Collection[str]: ...


def required_role(level: ApprovalLevel, settings: ApprovalSettings) -> str:
    """Role an approver must hold to count toward the quorum of ``level``."""
    return settings.elevated_role if level is ApprovalLevel.ELEVATED else settings.standard_role


def min_approvers(level: ApprovalLevel, settings: ApprovalSettings) -> int:
    """Number of distinct qualifying HUMAN approvers ``level`` needs."""
    if level is ApprovalLevel.ELEVATED:
        return settings.elevated_min_approvers
    return settings.standard_min_approvers


def non_human_principals(approvers: Iterable[ApproverLike]) -> list[str]:
    """Principal ids whose kind is not HUMAN (SERVICE, AUTOMATION and AI may never approve)."""
    return [a.principal_id for a in approvers if a.kind is not PrincipalKind.HUMAN]


def duplicate_principals(approvers: Sequence[ApproverLike]) -> list[str]:
    """Principal ids that appear more than once."""
    seen: set[str] = set()
    dupes: list[str] = []
    for a in approvers:
        if a.principal_id in seen and a.principal_id not in dupes:
            dupes.append(a.principal_id)
        seen.add(a.principal_id)
    return dupes


def has_any_approver_role(approver: ApproverLike, settings: ApprovalSettings) -> bool:
    """True when the approver holds the standard or the elevated approver role."""
    return bool({settings.standard_role, settings.elevated_role} & set(approver.roles))


def quorum_failure(approvers: Iterable[ApproverLike], level: ApprovalLevel,
                   settings: ApprovalSettings, *, excluded: Collection[str] = ()) -> str | None:
    """Reason the approvers do not satisfy ``level``, or None when they do.

    Only distinct HUMAN principals holding the level's role count; ids in ``excluded`` (the package
    requester when self-approval is not allowed) never count.
    """
    role = required_role(level, settings)
    needed = min_approvers(level, settings)
    qualifying = {
        a.principal_id for a in approvers
        if a.kind is PrincipalKind.HUMAN and role in a.roles and a.principal_id not in excluded
    }
    if len(qualifying) >= needed:
        return None
    return (f"{level.value} approval needs {needed} distinct human approver(s) with role "
            f"{role!r}; {len(qualifying)} qualifying approver(s) provided")
