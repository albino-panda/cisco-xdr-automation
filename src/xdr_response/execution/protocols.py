"""Local protocols for the collaborators the execution engine depends on.

The concrete classes (``AdapterRegistry``, ``VerificationEngine``, ``DryRunSimulator``) are built by
other components. The execution engine only needs the narrow shapes below, so it codes against
these structural protocols and never imports those modules at import time.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from xdr_response.interfaces import PackageTokenVerifier  # contract home (13.8)
from xdr_response.models import ActionOutcome, ActionPackage, ActionRequest, ContainmentReport, VerificationResult

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.integrations.base import IntegrationAdapter

__all__ = ["AdapterProvider", "ActionVerifier", "PackageSimulator", "PackageTokenVerifier"]


@runtime_checkable
class AdapterProvider(Protocol):
    """What :class:`ActionRunner` needs from ``AdapterRegistry``."""

    def get(self, name: str) -> "IntegrationAdapter":  # KeyError if unknown
        ...


@runtime_checkable
class ActionVerifier(Protocol):
    """What :class:`ActionRunner` needs from ``VerificationEngine`` (must never raise)."""

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        ...


@runtime_checkable
class PackageSimulator(Protocol):
    """What :class:`ContainmentExecutor` needs from ``DryRunSimulator``."""

    def simulate(self, package: ActionPackage) -> ContainmentReport:
        ...
