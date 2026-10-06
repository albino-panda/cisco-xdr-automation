"""Typed errors shared by every component (architecture section 13.4).

This module only imports :mod:`xdr_response.models.enums` (which has no
imports of its own). ``ErrorInfo`` and the redactor are imported lazily inside
``IntegrationError.to_error_info`` to keep the import graph acyclic. Model
modules never import this module at import time (only inside functions).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

from xdr_response.models.enums import ErrorCode

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.models.action import ErrorInfo
    from xdr_response.models.enums import IncidentState

__all__ = [
    "XdrResponseError",
    "ConfigError",
    "SecretNotFoundError",
    "ApprovalError",
    "ApprovalRequiredError",
    "DryRunViolationError",
    "TokenInvalidError",
    "TokenExpiredError",
    "TokenMismatchError",
    "TokenReplayError",
    "ActionMethodMismatchError",
    "AuthenticationError",
    "ApproverNotAllowedError",
    "DecisionError",
    "InvalidTransitionError",
    "IntegrationError",
    "IntegrationTimeoutError",
    "RateLimitedError",
    "AuthFailedError",
    "IntegrationUnavailableError",
    "InvalidTargetError",
    "ApiError",
    "CapabilityNotSupportedError",
    "UnverifiedEndpointError",
    "unverified",
    "AuditError",
    "AuditIntegrityError",
    "RegistryError",
]


class XdrResponseError(Exception):
    """Base class of every framework error."""


class ConfigError(XdrResponseError):
    """Invalid or unsafe configuration."""


class SecretNotFoundError(XdrResponseError):
    """A secret is missing or empty. The message names the secret, never a value."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"secret not found or empty: {name}")


# ---------------------------------------------------------------- approval ---
class ApprovalError(XdrResponseError):
    """Base class of approval failures."""


class ApprovalRequiredError(ApprovalError):
    """No authorization context, no verifier registered, or the approval does not cover the call."""


class DryRunViolationError(ApprovalRequiredError):
    """A state-changing path was reached while dry run is active."""


class TokenInvalidError(ApprovalRequiredError):
    """Malformed token, unknown key id, bad signature or invalid approver claims."""


class TokenExpiredError(TokenInvalidError):
    """Token outside its validity window."""


class TokenMismatchError(TokenInvalidError):
    """Token does not bind this incident, key, action type, target, params hash, purpose or package."""


class TokenReplayError(TokenInvalidError):
    """Token use for this action key was already consumed."""


class ActionMethodMismatchError(TokenMismatchError, ValueError):
    """A guarded method was called with a request approved for a different action type."""


class AuthenticationError(ApprovalError):
    """Approver credential rejected."""


class ApproverNotAllowedError(ApprovalError):
    """Non-HUMAN principal, missing role, quorum not met or self-approval."""


class DecisionError(ApprovalError):
    """Invalid decision for the package (keys, expiry, comment, evidence hash)."""


# --------------------------------------------------------------- lifecycle ---
class InvalidTransitionError(XdrResponseError):
    def __init__(self, from_state: "IncidentState", to_state: "IncidentState", reason: str = "") -> None:
        self.from_state = from_state
        self.to_state = to_state
        self.reason = reason
        f = getattr(from_state, "value", from_state)
        t = getattr(to_state, "value", to_state)
        msg = f"invalid incident state transition {f} -> {t}"
        if reason:
            msg = f"{msg}: {reason}"
        super().__init__(msg)


# ------------------------------------------------------------ integrations ---
class IntegrationError(XdrResponseError):
    """Base class of errors raised by an external integration call."""

    code: ErrorCode = ErrorCode.API_ERROR

    def __init__(
        self,
        message: str,
        *,
        integration: str,
        http_status: int | None = None,
        retryable: bool = False,
    ) -> None:
        self.message = message
        self.integration = integration
        self.http_status = http_status
        self.retryable = retryable
        super().__init__(message)

    def to_error_info(self) -> "ErrorInfo":
        """Convert to the serializable :class:`ErrorInfo` (message redacted)."""
        from xdr_response.logs.redaction import get_redactor
        from xdr_response.models.action import ErrorInfo

        return ErrorInfo(
            code=self.code,
            message=get_redactor().redact_text(str(self.message)),
            integration=self.integration,
            http_status=self.http_status,
            retryable=self.retryable,
        )


class IntegrationTimeoutError(IntegrationError):
    code = ErrorCode.TIMEOUT

    def __init__(self, message: str, *, integration: str, http_status: int | None = None,
                 retryable: bool = True) -> None:
        super().__init__(message, integration=integration, http_status=http_status, retryable=retryable)


class RateLimitedError(IntegrationError):
    code = ErrorCode.RATE_LIMITED
    retry_after: float | None

    def __init__(self, message: str, *, integration: str, http_status: int | None = 429,
                 retryable: bool = True, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        super().__init__(message, integration=integration, http_status=http_status, retryable=retryable)


class AuthFailedError(IntegrationError):
    code = ErrorCode.AUTH_FAILED


class IntegrationUnavailableError(IntegrationError):
    code = ErrorCode.UNAVAILABLE

    def __init__(self, message: str, *, integration: str, http_status: int | None = None,
                 retryable: bool = True) -> None:
        super().__init__(message, integration=integration, http_status=http_status, retryable=retryable)


class InvalidTargetError(IntegrationError):
    code = ErrorCode.INVALID_TARGET


class ApiError(IntegrationError):
    code = ErrorCode.API_ERROR


class CapabilityNotSupportedError(IntegrationError):
    code = ErrorCode.NOT_SUPPORTED


class UnverifiedEndpointError(IntegrationError, NotImplementedError):
    """Raised by every adapter operation whose endpoint is not VERIFIED in docs/integrations.md."""

    code = ErrorCode.UNVERIFIED_ENDPOINT

    def __init__(self, integration: str, operation: str) -> None:
        self.operation = operation
        super().__init__(
            f"unverified endpoint: {integration}.{operation} - see docs/integrations.md",
            integration=integration,
        )


def unverified(integration: str, operation: str) -> NoReturn:
    """Raise :class:`UnverifiedEndpointError` for ``integration.operation``."""
    raise UnverifiedEndpointError(integration, operation)


# ------------------------------------------------------------ audit/registry -
class AuditError(XdrResponseError):
    """The audit trail could not be written or read."""


class AuditIntegrityError(AuditError):
    """The audit hash chain is broken (tampering or corruption)."""


class RegistryError(XdrResponseError):
    """Temporary control registry error (unknown key, wrong status, no active controls)."""
