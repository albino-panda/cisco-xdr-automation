"""Stateful fake vendor APIs for integration tests, served through ``httpx.MockTransport``.

Each fake implements only the VERIFIED endpoints the adapters call (docs/integrations.md), keeps
vendor state in memory, demands the auth the real API demands (OAuth bearer tokens issued by its
own fake token endpoint) and records every request. Fake data only.
"""
from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx

from xdr_response.models.canonical import format_datetime

__all__ = ["FakeUmbrella", "FakeGraph", "FakeVirusTotal", "WRITE_METHODS"]

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _json(status: int, body: Any = None) -> httpx.Response:
    return httpx.Response(status, json=body) if body is not None else httpx.Response(status)


class _Fake:
    """Request recording, fault injection and bearer-token checks shared by the fakes."""

    token_path = ""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.tokens_issued: list[str] = []
        self.faults: dict[tuple[str, str], list[httpx.Response]] = {}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def fail(self, method: str, path_prefix: str, *responses: httpx.Response) -> None:
        """Serve ``responses`` (in order, last repeats) for requests matching method + path prefix."""
        self.faults[(method.upper(), path_prefix)] = list(responses)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.method in WRITE_METHODS and not r.url.path.endswith(self.token_path)]

    def _fault(self, request: httpx.Request) -> httpx.Response | None:
        for (method, prefix), queue in self.faults.items():
            if request.method == method and request.url.path.startswith(prefix):
                response = queue.pop(0) if len(queue) > 1 else queue[0]
                return httpx.Response(response.status_code, headers=response.headers, content=response.content)
        return None

    def _issue(self) -> httpx.Response:
        token = f"fake-access-token-{type(self).__name__.lower()}-{len(self.tokens_issued) + 1:04d}"
        self.tokens_issued.append(token)
        return _json(200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600})

    def _authorized(self, request: httpx.Request) -> bool:
        header = request.headers.get("authorization", "")
        return header.startswith("Bearer ") and header[len("Bearer "):] in self.tokens_issued

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        fault = self._fault(request)
        if fault is not None:
            return fault
        if request.url.path.endswith(self.token_path) and request.method == "POST":
            return self._token(request)
        if not self._authorized(request):
            return _json(401, {"error": "invalid_token"})
        return self._route(request)

    def _token(self, request: httpx.Request) -> httpx.Response:  # pragma: no cover - overridden
        return self._issue()

    def _route(self, request: httpx.Request) -> httpx.Response:  # pragma: no cover - overridden
        return _json(404)


class FakeUmbrella(_Fake):
    """Umbrella token, Investigate categorization and destination lists."""

    token_path = "/auth/v2/token"

    def __init__(self, *, key: str, secret: str, categorization: dict[str, int] | None = None) -> None:
        super().__init__()
        self._basic = "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode()
        self.categorization = dict(categorization or {})
        self.lists: dict[str, dict[int, str]] = {}
        self._next_id = 9000

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        if request.headers.get("authorization") != self._basic or form.get("grant_type") != ["client_credentials"]:
            return _json(401, {"error": "invalid_client"})
        return self._issue()

    def _route(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        if parts[:4] == ["investigate", "v2", "domains", "categorization"] and request.method == "GET":
            domain = unquote(parts[4])
            return _json(200, {domain: {"status": self.categorization.get(domain, 0),
                                        "security_categories": ["Command and Control"]
                                        if self.categorization.get(domain) == -1 else []}})
        if parts == ["policies", "v2", "destinationlists"] and request.method == "GET":
            return _json(200, {"status": {"code": 200},
                               "data": [{"id": int(k), "name": f"list {k}", "access": "block"} for k in self.lists]})
        if parts[:3] == ["policies", "v2", "destinationlists"] and len(parts) >= 5 and parts[4] == "destinations":
            entries = self.lists.setdefault(parts[3], {})
            if request.method == "GET" and len(parts) == 5:
                return _json(200, {"status": {"code": 200},
                                   "data": [{"id": i, "destination": d} for i, d in entries.items()]})
            if request.method == "POST" and len(parts) == 5:
                for item in json.loads(request.content):
                    self._next_id += 1
                    entries[self._next_id] = item["destination"]
                return _json(200, {"status": {"code": 200}})
            if request.method == "DELETE" and parts[5:] == ["remove"]:
                for destination_id in json.loads(request.content):
                    entries.pop(int(destination_id), None)
                return _json(200, {"status": {"code": 200}})
        return _json(404, {"message": "not found"})

    def blocked(self, list_id: str, value: str) -> bool:
        return value in self.lists.get(list_id, {}).values()


class FakeGraph(_Fake):
    """Microsoft identity platform token endpoint plus the Graph user endpoints Entra uses."""

    token_path = "/oauth2/v2.0/token"

    def __init__(self, *, client_id: str, client_secret: str, clock: Callable[[], datetime]) -> None:
        super().__init__()
        self._client = (client_id, client_secret)
        self._clock = clock
        self.users: dict[str, dict[str, Any]] = {}

    def add_user(self, upn: str, *, enabled: bool = True) -> None:
        self.users[upn.lower()] = {"id": f"id-{len(self.users) + 1:04d}", "userPrincipalName": upn,
                                   "displayName": upn.split("@")[0], "accountEnabled": enabled,
                                   "signInSessionsValidFromDateTime": "2025-12-01T00:00:00Z"}

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        if (form.get("client_id"), form.get("client_secret")) != ([self._client[0]], [self._client[1]]) \
                or not form.get("scope"):
            return _json(401, {"error": "invalid_client"})
        return self._issue()

    def _route(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")
        if parts[:2] == ["v1.0", "users"] and len(parts) >= 3:
            user = self.users.get(unquote(parts[2]).lower())
            if user is None:
                return _json(404, {"error": {"code": "Request_ResourceNotFound"}})
            if request.method == "GET" and len(parts) == 3:
                return _json(200, dict(user))
            if request.method == "PATCH" and len(parts) == 3:
                user.update(json.loads(request.content))
                return _json(204)
            if request.method == "POST" and parts[3:] == ["revokeSignInSessions"]:
                user["signInSessionsValidFromDateTime"] = format_datetime(self._clock())
                return _json(200, {"value": True})
        if parts[:3] == ["v1.0", "auditLogs", "signIns"] and request.method == "GET":
            return _json(200, {"value": [{"userPrincipalName": "jsmith@example.com", "ipAddress": "198.51.100.77",
                                          "status": {"errorCode": 0}}]})
        return _json(404, {"error": {"code": "NotFound"}})


class FakeVirusTotal(_Fake):
    """VirusTotal v3 reports (API key header, no OAuth)."""

    def __init__(self, *, api_key: str, malicious: dict[str, int] | None = None) -> None:
        super().__init__()
        self._key = api_key
        self.malicious = dict(malicious or {})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        fault = self._fault(request)
        if fault is not None:
            return fault
        if request.headers.get("x-apikey") != self._key:
            return _json(401, {"error": {"code": "WrongCredentialsError"}})
        parts = request.url.path.strip("/").split("/")
        if parts[:2] == ["api", "v3"] and len(parts) == 4 and request.method == "GET":
            value = unquote(parts[3])
            if value not in self.malicious:
                return _json(404, {"error": {"code": "NotFoundError"}})
            stats = {"malicious": self.malicious[value], "suspicious": 0, "harmless": 50, "undetected": 10}
            return _json(200, {"data": {"attributes": {"last_analysis_stats": stats}}})
        return _json(404)
