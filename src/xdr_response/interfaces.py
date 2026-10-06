"""Cross-component protocols (architecture section 13.8). Concrete classes live in their subpackages.

Aliases kept for readability in older notes: ``ApprovalVerifier`` == :class:`TokenVerifier`,
``StateStore`` == :class:`IncidentStore`.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from xdr_response.clock import Clock
from xdr_response.models import (
    ActionBinding,
    ActionPackage,
    ApprovalPurpose,
    ApprovalToken,
    ApproverCredential,
    AuditEventType,
    AuditRecord,
    AuthenticatedPrincipal,
    ControlStatus,
    ErrorInfo,
    Incident,
    TemporaryControl,
    TokenActionGrant,
)

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.secrets.provider import SecretValue

__all__ = [
    "Clock",
    "SecretProvider",
    "AuditSink",
    "TokenVerifier",
    "ApprovalVerifier",
    "PackageTokenVerifier",
    "TokenUseLedger",
    "ApproverAuthenticator",
    "ControlRegistry",
    "IncidentStore",
    "StateStore",
    "PackageStore",
]


@runtime_checkable
class SecretProvider(Protocol):
    def get(self, name: str) -> "SecretValue":  # SecretNotFoundError
        ...

    def get_optional(self, name: str) -> "SecretValue | None":
        ...


@runtime_checkable
class AuditSink(Protocol):
    def append(
        self,
        event_type: AuditEventType,
        *,
        incident_id: str | None,
        actor: str,
        payload: Mapping[str, Any],
        workflow_id: str | None = None,
        workflow_version: str | None = None,
    ) -> AuditRecord:  # AuditError on failure
        ...

    def records(self, incident_id: str | None = None) -> Iterator[AuditRecord]:
        ...

    @property
    def head_hash(self) -> str:
        ...


@runtime_checkable
class TokenVerifier(Protocol):
    def verify(self, token: ApprovalToken, *, purpose: ApprovalPurpose,
               binding: ActionBinding) -> TokenActionGrant:  # raises ApprovalRequiredError subclasses
        ...

    def mark_used(self, token: ApprovalToken, idempotency_key: str) -> None:  # TokenReplayError
        ...


ApprovalVerifier = TokenVerifier


@runtime_checkable
class PackageTokenVerifier(Protocol):
    """Optional extension of :class:`TokenVerifier` (``ApprovalTokenService.verify_package``).

    The containment executor and the restoration engine call ``verify_package`` before running a
    package when the registered verifier implements it (signature, expiry, approvers, package id,
    workflow, evidence hash and every grant). They always run their own deterministic binding check
    as well, so a verifier without this method is still safe.
    """

    def verify_package(self, token: ApprovalToken, package: ActionPackage) -> None:  # TokenInvalidError
        ...


@runtime_checkable
class TokenUseLedger(Protocol):
    def consume(self, token_id: str, idempotency_key: str) -> None:  # TokenReplayError if consumed
        ...

    def is_consumed(self, token_id: str, idempotency_key: str) -> bool:
        ...


@runtime_checkable
class ApproverAuthenticator(Protocol):
    def authenticate(self, credential: ApproverCredential) -> AuthenticatedPrincipal:  # AuthenticationError
        ...


@runtime_checkable
class ControlRegistry(Protocol):
    """TemporaryControlRegistry. There is deliberately no delete method."""

    def register(self, control: TemporaryControl) -> TemporaryControl:  # idempotent by control_key
        ...

    def get(self, control_key: str) -> TemporaryControl | None:
        ...

    def list(self, *, incident_id: str | None = None,
             status: ControlStatus | None = None) -> list[TemporaryControl]:
        ...

    def list_active(self, incident_id: str | None = None) -> list[TemporaryControl]:
        ...

    def mark_release_pending(self, control_key: str, *, release_package_id: str,
                             token_id: str) -> TemporaryControl:
        ...

    def mark_released(self, control_key: str, *, at: datetime) -> TemporaryControl:
        ...

    def mark_release_failed(self, control_key: str, *, error: ErrorInfo) -> TemporaryControl:
        ...


@runtime_checkable
class IncidentStore(Protocol):
    def get(self, incident_id: str) -> Incident:  # KeyError
        ...

    def save(self, incident: Incident) -> None:
        ...

    def list(self) -> list[Incident]:
        ...


StateStore = IncidentStore


@runtime_checkable
class PackageStore(Protocol):
    def get(self, package_id: str) -> ActionPackage:  # KeyError
        ...

    def save(self, package: ActionPackage) -> None:
        ...

    def mark_executed(self, package_id: str) -> None:  # RuntimeError if already executed
        ...

    def is_executed(self, package_id: str) -> bool:
        ...

    def latest_for_incident(self, incident_id: str, purpose: ApprovalPurpose) -> ActionPackage | None:
        ...
