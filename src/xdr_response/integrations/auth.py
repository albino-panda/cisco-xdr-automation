"""Authentication providers for :class:`~xdr_response.integrations.http.GuardedHttpClient`.

Every provider implements :class:`AuthProvider`: ``apply(request)`` adds credentials to an outgoing
``httpx.Request`` and ``invalidate()`` drops any cached token (the HTTP client calls it once after a
401 and retries). Secret values arrive as :class:`~xdr_response.secrets.SecretValue` and are revealed
only at the point where a header or query value is built. Access tokens obtained from a token
endpoint are registered with the central redactor, so they never reach logs or audit records.

Token endpoints are the VERIFIED URLs listed in docs/integrations.md; this module never decides a URL
itself. Token requests are ``READ`` operations named ``"token"`` (architecture section 13.13); they
are never STATE_CHANGING and never need an approval token.
"""
from __future__ import annotations

import base64
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any, Protocol, runtime_checkable

import httpx

from xdr_response.clock import DEFAULT_CLOCK, Clock
from xdr_response.errors import (
    AuthFailedError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    RateLimitedError,
)
from xdr_response.logs.redaction import Redactor, get_redactor
from xdr_response.secrets.provider import SecretValue

__all__ = [
    "AuthProvider",
    "OAuth2ClientCredentials",
    "ApiKeyHeader",
    "ApiKeyQuery",
    "BasicAuth",
    "DEFAULT_TOKEN_LIFETIME_SECONDS",
    "REFRESH_MARGIN_SECONDS",
]

#: Used when a token response carries no ``expires_in`` (Secure Email documents 60 minutes).
DEFAULT_TOKEN_LIFETIME_SECONDS = 3600
#: Tokens are refreshed this long before they expire. Umbrella answers an expired token with 400,
#: not 401 (docs/integrations.md 2.6), so the provider must never send a token close to expiry.
REFRESH_MARGIN_SECONDS = 120


@runtime_checkable
class AuthProvider(Protocol):
    def apply(self, request: httpx.Request) -> None:
        ...

    def invalidate(self) -> None:
        ...


def _require_secret(value: object, what: str) -> SecretValue:
    if not isinstance(value, SecretValue):
        raise TypeError(f"{what} must be a SecretValue (got {type(value).__name__})")
    if not value.reveal():
        raise ValueError(f"{what} is empty")
    return value


class ApiKeyHeader:
    """A static API key in a header, e.g. ``x-apikey: <key>`` or ``Authorization: Bearer <key>``."""

    def __init__(self, header: str, key: SecretValue, *, prefix: str = "") -> None:
        if not header or any(c in header for c in "\r\n:"):
            raise ValueError("invalid header name")
        self.header = header
        self._key = _require_secret(key, "api key")
        self._prefix = prefix

    def apply(self, request: httpx.Request) -> None:
        request.headers[self.header] = f"{self._prefix}{self._key.reveal()}"

    def invalidate(self) -> None:
        """Static keys have nothing to refresh."""

    def __repr__(self) -> str:
        return f"ApiKeyHeader(header={self.header!r}, key='***')"


class ApiKeyQuery:
    """A static API key in the query string (Secure Malware Analytics).

    The GuardedHttpClient redacts URL query values of sensitive keys in every summary, so the key
    never reaches the audit trail.
    """

    def __init__(self, param: str, key: SecretValue) -> None:
        if not param:
            raise ValueError("param is required")
        self.param = param
        self._key = _require_secret(key, "api key")

    def apply(self, request: httpx.Request) -> None:
        request.url = request.url.copy_set_param(self.param, self._key.reveal())

    def invalidate(self) -> None:
        """Static keys have nothing to refresh."""

    def __repr__(self) -> str:
        return f"ApiKeyQuery(param={self.param!r}, key='***')"


def _basic(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


class BasicAuth:
    """HTTP Basic authentication."""

    def __init__(self, username: SecretValue, password: SecretValue) -> None:
        self._username = _require_secret(username, "username")
        self._password = _require_secret(password, "password")

    def apply(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = _basic(self._username.reveal(), self._password.reveal())

    def invalidate(self) -> None:
        """Basic credentials have nothing to refresh."""

    def __repr__(self) -> str:
        return "BasicAuth(username='***', password='***')"


class OAuth2ClientCredentials:
    """OAuth2 client-credentials grant with an in-memory, thread-safe token cache.

    * ``basic_auth=True`` sends the client id and secret as HTTP Basic (Cisco XDR, Umbrella, Secure
      Email); ``False`` sends them in the form body (Microsoft identity platform).
    * The token is refreshed :data:`REFRESH_MARGIN_SECONDS` before ``expires_in`` runs out.
    * Failures raise typed :class:`~xdr_response.errors.IntegrationError` subclasses; the token
      response body is never put into an error message.
    """

    def __init__(
        self,
        *,
        token_url: str,
        client_id: SecretValue,
        client_secret: SecretValue,
        scope: str | None = None,
        basic_auth: bool = True,
        transport: httpx.BaseTransport | None = None,
        clock: Clock | None = None,
        extra_headers: Mapping[str, str] | None = None,
        integration: str = "oauth2",
        timeout: float = 15.0,
        redactor: Redactor | None = None,
        refresh_margin_seconds: int = REFRESH_MARGIN_SECONDS,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        if not token_url.startswith("https://") and not token_url.startswith(("http://localhost",
                                                                               "http://127.0.0.1")):
            raise ValueError("token_url must be https://")
        self.token_url = token_url
        self._client_id = _require_secret(client_id, "client id")
        self._client_secret = _require_secret(client_secret, "client secret")
        self.scope = scope
        self.basic_auth = basic_auth
        self.integration = integration
        self._clock = clock or DEFAULT_CLOCK
        self._extra_headers = dict(extra_headers or {})
        self._redactor = redactor or get_redactor()
        self._margin = timedelta(seconds=max(0, refresh_margin_seconds))
        self._timeout = timeout
        self._transport = transport
        self._client_factory = client_factory
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at: datetime | None = None
        self._refresh_at: datetime | None = None
        self.token_requests = 0

    # ----------------------------------------------------------------- api --
    def apply(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {self._current_token()}"

    def invalidate(self) -> None:
        with self._lock:
            self._token = None
            self._expires_at = None
            self._refresh_at = None

    @property
    def has_token(self) -> bool:
        return self._token is not None

    # ----------------------------------------------------------- internals --
    def _current_token(self) -> str:
        with self._lock:
            now = self._clock.now()
            if self._token is not None and self._refresh_at is not None and now < self._refresh_at:
                return self._token
            token, lifetime = self._fetch()
            margin = min(self._margin, timedelta(seconds=lifetime / 2))
            self._token = token
            self._expires_at = now + timedelta(seconds=lifetime)
            self._refresh_at = self._expires_at - margin
            return token

    def _client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(timeout=httpx.Timeout(self._timeout), transport=self._transport,
                            follow_redirects=False)

    def _fetch(self) -> tuple[str, int]:
        self.token_requests += 1
        form: dict[str, str] = {"grant_type": "client_credentials"}
        if self.scope:
            form["scope"] = self.scope
        headers = {"Accept": "application/json", **self._extra_headers}
        if self.basic_auth:
            headers["Authorization"] = _basic(self._client_id.reveal(), self._client_secret.reveal())
        else:
            form["client_id"] = self._client_id.reveal()
            form["client_secret"] = self._client_secret.reveal()
        where = f"{self.integration}.token"
        try:
            with self._client() as client:
                response = client.post(self.token_url, data=form, headers=headers)
                response.read()
        except httpx.TimeoutException as exc:
            raise IntegrationTimeoutError(f"{where}: timed out ({type(exc).__name__})",
                                          integration=self.integration) from None
        except httpx.TransportError as exc:
            raise IntegrationUnavailableError(f"{where}: connection failed ({type(exc).__name__})",
                                              integration=self.integration) from None
        status = response.status_code
        if status in (400, 401, 403):
            raise AuthFailedError(f"{where}: token request rejected (HTTP {status})",
                                  integration=self.integration, http_status=status)
        if status == 429:
            raise RateLimitedError(f"{where}: token endpoint rate limited", integration=self.integration)
        if status >= 500:
            raise IntegrationUnavailableError(f"{where}: token endpoint HTTP {status}",
                                              integration=self.integration, http_status=status)
        if status != 200:
            raise AuthFailedError(f"{where}: unexpected HTTP {status}", integration=self.integration,
                                  http_status=status)
        token, lifetime = self._parse(response, where)
        self._redactor.register_secret(token)
        return token, lifetime

    def _parse(self, response: httpx.Response, where: str) -> tuple[str, int]:
        try:
            body: Any = response.json()
        except ValueError:
            raise AuthFailedError(f"{where}: token response is not JSON", integration=self.integration,
                                  http_status=response.status_code) from None
        if not isinstance(body, Mapping):
            raise AuthFailedError(f"{where}: token response is not an object", integration=self.integration)
        token = body.get("access_token") or body.get("accessToken")
        if not isinstance(token, str) or not token:
            raise AuthFailedError(f"{where}: token response has no access token", integration=self.integration)
        raw = body.get("expires_in", body.get("expiresIn"))
        try:
            lifetime = int(raw) if raw is not None else DEFAULT_TOKEN_LIFETIME_SECONDS
        except (TypeError, ValueError):
            lifetime = DEFAULT_TOKEN_LIFETIME_SECONDS
        return token, max(1, lifetime)

    def __repr__(self) -> str:
        return (f"OAuth2ClientCredentials(token_url={self.token_url!r}, client_id='***', "
                f"client_secret='***', scope={self.scope!r})")

