"""HTTP mocks for adapter and integration tests (architecture section 13.20). No network.

``MockRouter`` maps ``(METHOD, path)`` to a handler, a fixed ``httpx.Response`` or several of them
(used in order; the last one repeats). Unmatched routes answer HTTP 599 so a missing mock is loud.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import httpx

__all__ = ["MockRouter", "json_response", "Handler"]

Handler = Callable[[httpx.Request], httpx.Response] | httpx.Response


def json_response(status: int, body: Any = None, headers: Mapping[str, str] | None = None) -> httpx.Response:
    """A JSON response (``body=None`` gives an empty body)."""
    if body is None:
        return httpx.Response(status, headers=dict(headers or {}))
    return httpx.Response(status, json=body, headers=dict(headers or {}))


class MockRouter:
    """Routes requests of an ``httpx.MockTransport`` by method and URL path; records every call."""

    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], list[Handler]] = {}
        self._calls: list[httpx.Request] = []

    def add(self, method: str, path: str, *handlers: Handler) -> None:
        if not handlers:
            raise ValueError("at least one handler is required")
        self._routes[(method.upper(), path)] = list(handlers)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._dispatch)

    @property
    def calls(self) -> list[httpx.Request]:
        return list(self._calls)

    def calls_to(self, method: str, path: str) -> list[httpx.Request]:
        return [c for c in self._calls if c.method == method.upper() and c.url.path == path]

    def _dispatch(self, request: httpx.Request) -> httpx.Response:
        self._calls.append(request)
        handlers = self._routes.get((request.method, request.url.path))
        if not handlers:
            return httpx.Response(599, text=f"no mock route for {request.method} {request.url.path}")
        handler = handlers.pop(0) if len(handlers) > 1 else handlers[0]
        if isinstance(handler, httpx.Response):
            return httpx.Response(handler.status_code, headers=handler.headers, content=handler.content)
        return handler(request)
