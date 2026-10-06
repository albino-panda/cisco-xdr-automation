"""In-memory approver authenticator (tests, lab and simulator only).

Production deployments plug an OIDC/SSO authenticator in behind the same
:class:`xdr_response.interfaces.ApproverAuthenticator` protocol. This implementation stores only a
salted PBKDF2-SHA256 hash of each principal's secret, compares in constant time and returns the same
generic error for every failure so a caller cannot learn which principal ids exist.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import threading
from collections.abc import Iterable
from dataclasses import dataclass

from xdr_response.clock import Clock, SystemClock
from xdr_response.errors import AuthenticationError
from xdr_response.models import ApproverCredential, AuthenticatedPrincipal, PrincipalKind

__all__ = ["InMemoryApproverAuthenticator", "STATIC_SCHEME", "DEFAULT_PBKDF2_ITERATIONS"]

#: Credential scheme accepted by :class:`InMemoryApproverAuthenticator`.
STATIC_SCHEME = "static"
#: PBKDF2-SHA256 iteration count (hashes live only in memory; never persisted).
DEFAULT_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16
_GENERIC_FAILURE = "approver authentication failed"


@dataclass(frozen=True)
class _StoredPrincipal:
    principal_id: str
    display_name: str
    kind: PrincipalKind
    roles: frozenset[str]
    salt: bytes
    digest: bytes


class InMemoryApproverAuthenticator:
    """Authenticates static credentials against salted PBKDF2-SHA256 hashes held in memory."""

    name = "in_memory"

    def __init__(self, *, clock: Clock | None = None,
                 iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> None:
        if iterations < 1:
            raise ValueError("iterations must be >= 1")
        self._clock = clock or SystemClock()
        self._iterations = iterations
        self._principals: dict[str, _StoredPrincipal] = {}
        self._lock = threading.Lock()
        self._dummy_salt = os.urandom(_SALT_BYTES)

    def _hash(self, secret: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, self._iterations)

    def add_principal(self, principal_id: str, *, display_name: str, kind: PrincipalKind,
                      roles: Iterable[str], secret: str) -> None:
        """Register a principal. Only a salted hash of ``secret`` is kept.

        Any kind can be registered (so tests can prove non-HUMAN principals are refused later);
        authentication never decides who may approve, the approval engine does.
        """
        if not principal_id or not principal_id.strip():
            raise ValueError("principal_id must not be empty")
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret must be a non-empty string")
        salt = os.urandom(_SALT_BYTES)
        stored = _StoredPrincipal(
            principal_id=principal_id, display_name=display_name, kind=PrincipalKind(kind),
            roles=frozenset(roles), salt=salt, digest=self._hash(secret, salt),
        )
        with self._lock:
            self._principals[principal_id] = stored

    def authenticate(self, credential: ApproverCredential) -> AuthenticatedPrincipal:
        """Return the authenticated principal or raise :class:`AuthenticationError`."""
        if not isinstance(credential, ApproverCredential):
            raise AuthenticationError(_GENERIC_FAILURE)
        stored = self._principals.get(credential.principal_id)
        secret = credential.secret.get_secret_value()
        # Hash even for unknown principals so timing does not reveal which ids exist.
        digest = self._hash(secret, stored.salt if stored else self._dummy_salt)
        valid = stored is not None and hmac.compare_digest(digest, stored.digest)
        if not valid or credential.scheme != STATIC_SCHEME or stored is None:
            raise AuthenticationError(_GENERIC_FAILURE)
        return AuthenticatedPrincipal(
            principal_id=stored.principal_id, display_name=stored.display_name, kind=stored.kind,
            roles=stored.roles, authenticator=self.name, authenticated_at=self._clock.now(),
        )

    def __repr__(self) -> str:
        return f"InMemoryApproverAuthenticator(principals={len(self._principals)})"
