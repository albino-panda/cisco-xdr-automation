"""Shared helpers for vendor adapter tests (no network: httpx.MockTransport only).

Adapters get the real :class:`GuardedHttpClient` (no auth provider, no retries, no-op sleep) on top of
a :class:`Router` mock transport, so tests see exactly the method, URL and body each adapter sends,
and STATE_CHANGING requests are still checked against the guard by the HTTP client.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import httpx

from tests.fixtures.factories import FAKE_SHA256, FIXED_NOW, make_recommendation
from tests.fixtures.guard_helpers import install_fake_verifier, make_token
from tests.fixtures.principals import make_test_secrets
from xdr_response import guard
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig
from xdr_response.integrations.base import IntegrationAdapter
from xdr_response.integrations.http import GuardedHttpClient, RetryPolicy
from xdr_response.integrations.registry import ADAPTER_PATHS, load_adapter_class
from xdr_response.models import ActionRequest, ActionType, TargetKind, get_action_spec

__all__ = ["ALL_ADAPTERS", "TARGETS", "FAKE_SECRETS", "Router", "json_response", "make_adapter", "action_request",
           "authorized", "run_authorized", "body_of"]

#: Every shipped adapter class, keyed by integration name.
ALL_ADAPTERS: dict[str, type[IntegrationAdapter]] = {name: load_adapter_class(name) for name in ADAPTER_PATHS}

#: A valid fake target per target kind (documentation ranges, example domains, fake hashes).
TARGETS: Mapping[TargetKind, str] = {
    TargetKind.ENDPOINT: "TH-LT-1047",
    TargetKind.USER: "j.doe@example.com",
    TargetKind.DOMAIN: "bad.example.test",
    TargetKind.URL: "https://bad.example.test/payload",
    TargetKind.IP: "203.0.113.10",
    TargetKind.HASH: FAKE_SHA256,
    TargetKind.EMAIL_MESSAGE: "msg-0001@example.test",
    TargetKind.EMAIL_ADDRESS: "j.doe@example.com",
    TargetKind.PROCESS: "TH-LT-1047:4242",
    TargetKind.FILE: f"TH-LT-1047:{FAKE_SHA256}",
    TargetKind.PERSISTENCE_ITEM: "TH-LT-1047:run-key-0001",
    TargetKind.ROLE_ASSIGNMENT: "ra-0001",
    TargetKind.NETWORK_CLIENT: "k74272e",
    TargetKind.APPLICATION: "app-0001",
    TargetKind.CREDENTIAL: "cred-0001",
    TargetKind.INCIDENT: "XDR-83921",
}

#: Fake values for every secret NAME any adapter reads (never real credentials).
FAKE_SECRETS: Mapping[str, str] = {
    "XDR_CLIENT_ID": "fake-xdr-client-id", "XDR_CLIENT_SECRET": "fake-xdr-client-secret",
    "SE_CLIENT_ID": "fake-se-client-id", "SE_API_KEY": "fake-se-api-key-000",
    "ETD_CLIENT_ID": "fake-etd-client-id", "ETD_CLIENT_SECRET": "fake-etd-client-secret",
    "ETD_API_KEY": "fake-etd-api-key-000", "SMA_API_KEY": "fake-sma-api-key-000",
    "SCA_API_KEY": "fake-sca-api-key-000", "UMBRELLA_API_KEY": "fake-umbrella-key",
    "UMBRELLA_API_SECRET": "fake-umbrella-secret", "MERAKI_API_KEY": "fake-meraki-api-key",
    "ENTRA_TENANT_ID": "00000000-0000-0000-0000-000000000000", "ENTRA_CLIENT_ID": "fake-entra-client-id",
    "ENTRA_CLIENT_SECRET": "fake-entra-client-secret", "MDE_CLIENT_ID": "fake-mde-client-id",
    "MDE_CLIENT_SECRET": "fake-mde-client-secret", "VT_API_KEY": "fake-vt-api-key-000",
    "OTX_API_KEY": "fake-otx-api-key-000", "HIBP_API_KEY": "fake-hibp-api-key-000",
    "SPLUNK_TOKEN": "fake-splunk-session-key", "SPLUNK_HEC_TOKEN": "fake-splunk-hec-token",
}

Handler = Callable[[httpx.Request], httpx.Response] | httpx.Response


def json_response(status: int, body: Any = None, headers: Mapping[str, str] | None = None) -> httpx.Response:
    """A JSON response (empty body when ``body`` is None)."""
    if body is None:
        return httpx.Response(status, headers=dict(headers or {}))
    return httpx.Response(status, json=body, headers=dict(headers or {}))


class Router:
    """Mock transport routing on (method, path) and optionally host; records every request.

    A list of responses for one route is served in order (the last one repeats).
    """

    def __init__(self, fallback: Handler | None = None) -> None:
        self._routes: dict[tuple[str, str | None, str], list[Handler]] = {}
        self._fallback = fallback
        self.calls: list[httpx.Request] = []

    def add(self, method: str, path: str, *responses: Handler, host: str | None = None) -> "Router":
        self._routes[(method.upper(), host, path)] = list(responses) or [json_response(200, {})]
        return self

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        queue = self._routes.get((request.method, request.url.host, path)) or \
            self._routes.get((request.method, None, path))
        if queue is None:
            if self._fallback is None:
                raise AssertionError(f"unexpected request {request.method} {request.url}")
            return self._serve(self._fallback, request)
        return self._serve(queue.pop(0) if len(queue) > 1 else queue[0], request)

    @staticmethod
    def _serve(handler: Handler, request: httpx.Request) -> httpx.Response:
        if callable(handler) and not isinstance(handler, httpx.Response):
            return handler(request)
        # a fresh copy per call: a Response object must not be sent twice
        return httpx.Response(handler.status_code, headers=handler.headers, content=handler.content)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def last(self) -> httpx.Request:
        assert self.calls, "no request was sent"
        return self.calls[-1]


def body_of(request: httpx.Request) -> Any:
    """Parsed JSON body of a recorded request (None when empty)."""
    content = request.content
    return json.loads(content) if content else None


def make_adapter(name: str, router: Router | None = None, *, enabled: bool = True,
                 options: Mapping[str, Any] | None = None, base_url: str | None = None,
                 region: str | None = None, **adapter_kwargs: Any) -> IntegrationAdapter:
    """An adapter with fixed clock, fake secrets and a guarded client over ``router``."""
    cls = ALL_ADAPTERS[name]
    config = IntegrationConfig(enabled=enabled, base_url=base_url, region=region, options=dict(options or {}))
    clock = FixedClock(FIXED_NOW)
    adapter = cls(config, make_test_secrets(**FAKE_SECRETS), clock=clock, sleep=lambda _s: None,
                  **adapter_kwargs)
    if router is not None:
        url = base_url or cls.default_base_url or "https://splunk.example.test:8089"
        adapter.http = GuardedHttpClient(name, url, retry=RetryPolicy(max_retries=0, jitter=False),
                                         default_headers=adapter.default_headers(),
                                         transport=router.transport(), clock=clock, sleep=lambda _s: None)
    return adapter


def action_request(action_type: ActionType, integration: str, target: str | None = None,
                   **params: Any) -> ActionRequest:
    """A valid ActionRequest for ``action_type`` routed to ``integration``."""
    kind = get_action_spec(action_type).target_kind
    return ActionRequest.from_recommendation(
        make_recommendation(action_type, target or TARGETS[kind], integration, **params))


@contextmanager
def authorized(request: ActionRequest) -> Iterator[None]:
    """Install the fake verifier (dry run off) and enter an authorization context for ``request``."""
    install_fake_verifier()
    with guard.authorized(make_token(request), request):
        yield


def run_authorized(adapter: IntegrationAdapter, request: ActionRequest) -> Any:
    """Execute ``request`` through ``adapter.execute`` inside an approved context."""
    with authorized(request):
        return adapter.execute(request)
