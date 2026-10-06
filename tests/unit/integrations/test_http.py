"""GuardedHttpClient: guard on the mutating path, retries/backoff, rate limiting, error mapping, audit."""
from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from tests.fixtures.factories import FIXED_NOW, make_recommendation
from tests.fixtures.guard_helpers import install_fake_verifier, make_token
from tests.unit.integrations._support import (
    FakeAudit,
    FakeAuth,
    MockRouter,
    SleepRecorder,
    fixed_clock,
    json_response,
)
from xdr_response import guard
from xdr_response.errors import (
    ApiError,
    ApprovalRequiredError,
    AuditError,
    AuthFailedError,
    DryRunViolationError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
    TokenMismatchError,
)
from xdr_response.integrations.http import (
    GuardedHttpClient,
    HttpResult,
    RateLimiter,
    RetryPolicy,
    parse_retry_after,
)
from xdr_response.logs.redaction import REDACTED
from xdr_response.models import ActionRequest, ActionType, AuditEventType, ErrorCode, OperationKind

BASE = "https://api.example.com"
SECRET_KEY = "test-api-key-value-not-real-123"
BEARER = "test-bearer-value-not-real-456"


def make_client(router: MockRouter, *, retries: int = 3, jitter: bool = False, sleep: SleepRecorder | None = None,
                audit: FakeAudit | None = None, auth: FakeAuth | None = None,
                integration: str = "secure_endpoint", **kw) -> GuardedHttpClient:
    return GuardedHttpClient(
        integration, BASE, timeout=5.0,
        retry=RetryPolicy(max_retries=retries, backoff_base=1.0, backoff_max=30.0, jitter=jitter),
        transport=router.transport(), clock=fixed_clock(), sleep=sleep or SleepRecorder(),
        audit=audit, auth=auth, rand=lambda: 0.5, **kw,
    )


def isolate_request(integration: str = "secure_endpoint") -> ActionRequest:
    return ActionRequest.from_recommendation(
        make_recommendation(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", integration=integration))


def raises_transport(exc_type: type[httpx.TransportError]):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc_type("simulated transport failure", request=request)
    return handler


# --------------------------------------------------------------- success --
def test_get_success_parses_json_and_summarizes() -> None:
    router = MockRouter()
    router.add("GET", "/v1/computers", json_response(200, {"data": [{"hostname": "TH-LT-1047"}]}))
    result = make_client(router).get("/v1/computers", operation="list_computers", params={"hostname": "TH-LT-1047"})
    assert isinstance(result, HttpResult)
    assert result.status_code == 200
    assert result.body == {"data": [{"hostname": "TH-LT-1047"}]}
    assert result.summary.operation == "list_computers"
    assert result.summary.kind is OperationKind.READ
    assert result.summary.attempt == 1
    assert result.summary.request_summary == {"params": {"hostname": "TH-LT-1047"}}
    assert result.summary.url == f"{BASE}/v1/computers?hostname=TH-LT-1047"
    assert len(result.attempts) == 1


def test_non_json_body_gives_none_and_text() -> None:
    router = MockRouter()
    router.add("GET", "/plain", httpx.Response(200, text="hello", headers={"content-type": "text/plain"}))
    result = make_client(router).get("/plain", operation="plain")
    assert result.body is None
    assert result.text == "hello"


def test_response_headers_are_redacted() -> None:
    router = MockRouter()
    router.add("GET", "/h", httpx.Response(200, json={}, headers={"set-cookie": "session=abcdef123456"}))
    result = make_client(router).get("/h", operation="h")
    assert result.headers["set-cookie"] == REDACTED


def test_query_string_api_key_is_redacted_in_summary() -> None:
    router = MockRouter()
    router.add("GET", "/search", json_response(200, {}))
    result = make_client(router).get("/search", operation="search", params={"q": "x", "api_key": SECRET_KEY})
    assert SECRET_KEY not in result.summary.model_dump_json()
    assert "api_key=" in result.summary.url


def test_custom_expected_status() -> None:
    router = MockRouter()
    router.add("GET", "/accepted", json_response(299, {"ok": True}))
    assert make_client(router).get("/accepted", operation="x", expected=(299,)).status_code == 299


def test_redirect_is_not_followed() -> None:
    router = MockRouter()
    router.add("GET", "/moved", httpx.Response(302, headers={"location": "https://elsewhere.example/"}))
    with pytest.raises(ApiError) as exc:
        make_client(router).get("/moved", operation="moved")
    assert exc.value.http_status == 302
    assert len(router.calls) == 1


# ---------------------------------------------------------- retry/backoff --
def test_read_retries_5xx_with_exponential_backoff_then_succeeds() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(503), json_response(502), json_response(200, {"ok": 1}))
    sleep = SleepRecorder()
    result = make_client(router, sleep=sleep).get("/r", operation="r")
    assert result.body == {"ok": 1}
    assert sleep.delays == [1.0, 2.0]
    assert [a.attempt for a in result.attempts] == [1, 2, 3]
    assert result.attempts[0].error is not None and result.attempts[0].error.code is ErrorCode.UNAVAILABLE


def test_exhausted_5xx_raises_unavailable_with_all_attempts() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(500))
    sleep = SleepRecorder()
    with pytest.raises(IntegrationUnavailableError) as exc:
        make_client(router, retries=2, sleep=sleep).get("/r", operation="r")
    assert exc.value.http_status == 500
    assert len(router.calls) == 3
    assert len(exc.value.api_calls) == 3  # type: ignore[attr-defined]
    assert sleep.delays == [1.0, 2.0]


def test_non_retryable_5xx_is_not_retried() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(501))
    with pytest.raises(IntegrationUnavailableError):
        make_client(router).get("/r", operation="r")
    assert len(router.calls) == 1


def test_backoff_is_capped_and_jittered() -> None:
    policy = RetryPolicy(backoff_base=1.0, backoff_max=5.0, jitter=False)
    assert [policy.backoff(n) for n in (1, 2, 3, 4, 5)] == [1.0, 2.0, 4.0, 5.0, 5.0]
    jittered = RetryPolicy(backoff_base=4.0, backoff_max=30.0, jitter=True)
    assert jittered.backoff(1, rand=lambda: 0.0) == 2.0
    assert jittered.backoff(1, rand=lambda: 1.0) == 4.0
    with pytest.raises(ValueError):
        policy.backoff(0)


def test_jitter_source_is_injectable_in_client() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(503), json_response(200, {}))
    sleep = SleepRecorder()
    make_client(router, jitter=True, sleep=sleep).get("/r", operation="r")
    assert sleep.delays == [0.75]  # base 1.0 -> 0.5 + 0.5 * 0.5


def test_429_honours_retry_after_then_succeeds() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(429, headers={"Retry-After": "7"}), json_response(200, {}))
    sleep = SleepRecorder()
    make_client(router, sleep=sleep).get("/r", operation="r")
    assert sleep.delays == [7.0]


def test_exhausted_429_raises_rate_limited_with_retry_after() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(429, headers={"Retry-After": "3"}))
    with pytest.raises(RateLimitedError) as exc:
        make_client(router, retries=1).get("/r", operation="r")
    assert exc.value.retry_after == 3.0
    assert exc.value.http_status == 429
    assert len(router.calls) == 2


def test_retry_after_longer_than_backoff_max_gives_up_immediately() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(429, headers={"Retry-After": "3600"}))
    sleep = SleepRecorder()
    with pytest.raises(RateLimitedError) as exc:
        make_client(router, sleep=sleep).get("/r", operation="r")
    assert exc.value.retry_after == 3600.0
    assert sleep.delays == []
    assert len(router.calls) == 1


def test_429_without_retry_after_uses_backoff() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(429), json_response(429), json_response(200, {}))
    sleep = SleepRecorder()
    make_client(router, sleep=sleep).get("/r", operation="r")
    assert sleep.delays == [1.0, 2.0]


def test_parse_retry_after_forms() -> None:
    assert parse_retry_after("5", FIXED_NOW) == 5.0
    assert parse_retry_after(" 0 ", FIXED_NOW) == 0.0
    assert parse_retry_after("-3", FIXED_NOW) == 0.0
    assert parse_retry_after(None, FIXED_NOW) is None
    assert parse_retry_after("", FIXED_NOW) is None
    assert parse_retry_after("soon", FIXED_NOW) is None
    later = (FIXED_NOW + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(later, FIXED_NOW) == 90.0


def test_read_timeout_is_retried_then_raises_timeout() -> None:
    router = MockRouter()
    router.add("GET", "/r", raises_transport(httpx.ReadTimeout))
    with pytest.raises(IntegrationTimeoutError) as exc:
        make_client(router, retries=2).get("/r", operation="r")
    assert exc.value.retryable is True
    assert len(router.calls) == 3


def test_connect_error_maps_to_unavailable() -> None:
    router = MockRouter()
    router.add("GET", "/r", raises_transport(httpx.ConnectError))
    with pytest.raises(IntegrationUnavailableError) as exc:
        make_client(router, retries=1).get("/r", operation="r")
    assert exc.value.http_status is None
    assert len(router.calls) == 2


def test_timeout_is_configured_on_requests() -> None:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions["timeout"])
        return json_response(200, {})

    router = MockRouter()
    router.add("GET", "/r", handler)
    make_client(router).get("/r", operation="r")
    assert seen[0]["read"] == 5.0


# ------------------------------------------------------------ error mapping --
def test_401_invalidates_auth_and_retries_once() -> None:
    router = MockRouter()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return json_response(401) if len(seen) == 1 else json_response(200, {"ok": True})

    router.add("GET", "/r", handler)
    auth = FakeAuth(["first-token-value", "second-token-value"])
    sleep = SleepRecorder()
    result = make_client(router, auth=auth, sleep=sleep).get("/r", operation="r")
    assert result.body == {"ok": True}
    assert auth.invalidations == 1
    assert seen == ["Bearer first-token-value", "Bearer second-token-value"]
    assert sleep.delays == []


def test_repeated_401_raises_auth_failed() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(401))
    auth = FakeAuth(["a-token-value", "b-token-value"])
    with pytest.raises(AuthFailedError) as exc:
        make_client(router, auth=auth).get("/r", operation="r")
    assert exc.value.http_status == 401
    assert auth.invalidations == 1
    assert len(router.calls) == 2


def test_401_without_auth_provider_is_not_retried() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(401))
    with pytest.raises(AuthFailedError):
        make_client(router).get("/r", operation="r")
    assert len(router.calls) == 1


def test_403_raises_auth_failed_without_retry() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(403, {"error": "forbidden"}))
    auth = FakeAuth(["a-token-value"])
    with pytest.raises(AuthFailedError) as exc:
        make_client(router, auth=auth).get("/r", operation="r")
    assert exc.value.http_status == 403
    assert auth.invalidations == 0
    assert len(router.calls) == 1


@pytest.mark.parametrize("status", [400, 404])
def test_400_404_raise_invalid_target(status: int) -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(status, {"error": "no such computer"}))
    with pytest.raises(InvalidTargetError) as exc:
        make_client(router).get("/r", operation="get_computer")
    assert exc.value.http_status == status
    assert "no such computer" in str(exc.value)
    assert len(router.calls) == 1


def test_other_4xx_raise_api_error() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(409))
    with pytest.raises(ApiError) as exc:
        make_client(router).get("/r", operation="r")
    assert exc.value.http_status == 409
    assert exc.value.to_error_info().code is ErrorCode.API_ERROR


def test_error_message_excerpt_is_redacted() -> None:
    router = MockRouter()
    router.add("GET", "/r", httpx.Response(422, text=f"bad request, client_secret={SECRET_KEY}"))
    with pytest.raises(ApiError) as exc:
        make_client(router).get("/r", operation="r")
    assert SECRET_KEY not in str(exc.value)


# --------------------------------------------------------- call validation --
@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("kind", [OperationKind.READ, OperationKind.VERIFY])
def test_put_patch_delete_cannot_be_read_or_verify(method: str, kind: OperationKind) -> None:
    router = MockRouter()
    with pytest.raises(ValueError):
        make_client(router).request(method, "/x", kind=kind, operation="sneaky")
    assert router.calls == []


def test_bookkeeping_requires_allowlisted_operation() -> None:
    router = MockRouter()
    router.add("POST", "/notes", json_response(201, {}))
    client = make_client(router, integration="cisco_xdr")
    with pytest.raises(ValueError):
        client.post("/notes", kind=OperationKind.BOOKKEEPING, operation="isolate_endpoint")
    assert router.calls == []
    assert client.post("/notes", kind=OperationKind.BOOKKEEPING, operation="add_incident_note").status_code == 201


def test_unknown_method_and_missing_operation_rejected() -> None:
    client = make_client(MockRouter())
    with pytest.raises(ValueError):
        client.request("TRACE", "/x", kind=OperationKind.READ, operation="x")
    with pytest.raises(ValueError):
        client.request("GET", "/x", kind=OperationKind.READ, operation="")


def test_constructor_validation() -> None:
    with pytest.raises(ValueError):
        GuardedHttpClient("", BASE)
    with pytest.raises(ValueError):
        GuardedHttpClient("x", BASE, timeout=0)


# ------------------------------------------------------------ guarded path --
def test_mutation_outside_guard_denied_while_dry_run_default() -> None:
    router = MockRouter()
    router.add("POST", "/isolate/TH-LT-1047", json_response(200, {}))
    with pytest.raises(DryRunViolationError):
        make_client(router).post("/isolate/TH-LT-1047", kind=OperationKind.STATE_CHANGING, operation="isolate")
    assert router.calls == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutation_without_authorization_context_denied(method: str) -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add(method, "/isolate/TH-LT-1047", json_response(200, {}))
    with pytest.raises(ApprovalRequiredError):
        make_client(router).request(method, "/isolate/TH-LT-1047", kind=OperationKind.STATE_CHANGING, operation="isolate")
    assert router.calls == []


def test_mutation_inside_authorized_context_is_sent_and_reverified_each_attempt() -> None:
    verifier = install_fake_verifier()
    router = MockRouter()
    router.add("PUT", "/computers/TH-LT-1047/isolation", json_response(429, headers={"Retry-After": "1"}), json_response(200, {"ok": 1}))
    request = isolate_request()
    audit = FakeAudit()
    with guard.authorized(make_token(request), request):
        calls_before = verifier.verify_calls
        result = make_client(router, audit=audit).put("/computers/TH-LT-1047/isolation", operation="isolate")
    assert result.body == {"ok": 1}
    assert verifier.verify_calls - calls_before == 2  # one re-verification per attempt
    assert [e["incident_id"] for e in audit.events] == [request.incident_id] * 2
    assert all(e["event_type"] is AuditEventType.API_CALL for e in audit.events)


def test_mutation_for_other_integration_denied() -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("PUT", "/computers/TH-LT-1047/isolation", json_response(200, {}))
    request = isolate_request("secure_endpoint")
    with guard.authorized(make_token(request), request):
        with pytest.raises(TokenMismatchError):
            make_client(router, integration="defender_endpoint").put("/computers/TH-LT-1047/isolation", operation="isolate")
    assert router.calls == []


def test_mutation_after_context_exit_denied() -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("PUT", "/computers/TH-LT-1047/isolation", json_response(200, {}))
    request = isolate_request()
    client = make_client(router)
    with guard.authorized(make_token(request), request):
        pass
    with pytest.raises(ApprovalRequiredError):
        client.put("/computers/TH-LT-1047/isolation", operation="isolate")
    assert router.calls == []


def test_per_run_dry_run_blocks_mutation_even_in_context() -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("PUT", "/computers/TH-LT-1047/isolation", json_response(200, {}))
    request = isolate_request()
    with guard.authorized(make_token(request), request):
        with guard.dry_run(), pytest.raises(DryRunViolationError):
            make_client(router).put("/computers/TH-LT-1047/isolation", operation="isolate")
    assert router.calls == []


def test_write_read_timeout_not_blindly_retried() -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("POST", "/isolate/TH-LT-1047", raises_transport(httpx.ReadTimeout))
    request = isolate_request()
    with guard.authorized(make_token(request), request):
        with pytest.raises(IntegrationTimeoutError) as exc:
            make_client(router).post("/isolate/TH-LT-1047", kind=OperationKind.STATE_CHANGING, operation="isolate")
    assert len(router.calls) == 1
    assert "outcome unknown" in str(exc.value)


def test_write_connect_error_is_retried() -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("POST", "/isolate/TH-LT-1047", raises_transport(httpx.ConnectError), json_response(200, {}))
    request = isolate_request()
    with guard.authorized(make_token(request), request):
        make_client(router).post("/isolate/TH-LT-1047", kind=OperationKind.STATE_CHANGING, operation="isolate")
    assert len(router.calls) == 2


@pytest.mark.parametrize(("responses", "calls"), [
    ([json_response(500)], 1),
    ([json_response(502)], 1),
    ([json_response(503)], 1),
    ([json_response(503, headers={"Retry-After": "2"}), json_response(200, {})], 2),
    ([json_response(429), json_response(200, {})], 2),
])
def test_write_retries_only_on_safe_statuses(responses: list[httpx.Response], calls: int) -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("POST", "/isolate/TH-LT-1047", *responses)
    request = isolate_request()
    with guard.authorized(make_token(request), request):
        try:
            make_client(router).post("/isolate/TH-LT-1047", kind=OperationKind.STATE_CHANGING, operation="isolate")
        except IntegrationUnavailableError:
            pass
    assert len(router.calls) == calls


# ------------------------------------------------------------------ audit --
def test_secrets_never_reach_audit_or_summary() -> None:
    router = MockRouter()
    router.add("POST", "/oauth/token", json_response(200, {"access_token": BEARER, "expires_in": 3600}))
    audit = FakeAudit()
    client = make_client(router, audit=audit, default_headers={"X-Api-Key": SECRET_KEY},
                         auth=FakeAuth([BEARER]))
    result = client.post("/oauth/token", kind=OperationKind.READ, operation="token",
                         data={"grant_type": "client_credentials", "client_secret": SECRET_KEY})
    dumped = str(audit.events) + result.summary.model_dump_json()
    assert SECRET_KEY not in dumped
    assert BEARER not in dumped
    assert audit.events[0]["payload"]["response_summary"]["access_token"] == REDACTED
    assert audit.events[0]["payload"]["request_summary"]["data"]["client_secret"] == REDACTED
    assert audit.events[0]["incident_id"] is None


def test_audit_failure_on_read_is_swallowed() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(200, {}))
    assert make_client(router, audit=FakeAudit(fail=True)).get("/r", operation="r").status_code == 200


def test_audit_failure_on_write_raises() -> None:
    install_fake_verifier()
    router = MockRouter()
    router.add("POST", "/isolate/TH-LT-1047", json_response(200, {}))
    request = isolate_request()
    with guard.authorized(make_token(request), request):
        with pytest.raises(AuditError):
            make_client(router, audit=FakeAudit(fail=True)).post(
                "/isolate/TH-LT-1047", kind=OperationKind.STATE_CHANGING, operation="isolate")


def test_list_response_summary_counts_items() -> None:
    router = MockRouter()
    router.add("GET", "/l", json_response(200, [1, 2, 3]))
    assert make_client(router).get("/l", operation="l").summary.response_summary == {"items": 3}


# ------------------------------------------------------------- rate limit --
def test_rate_limiter_none_is_noop() -> None:
    sleep = SleepRecorder()
    limiter = RateLimiter(None, clock=fixed_clock(), sleep=sleep)
    assert not limiter.enabled
    for _ in range(100):
        assert limiter.acquire() == 0.0
    assert sleep.delays == []


def test_rate_limiter_token_bucket_waits_when_empty() -> None:
    sleep = SleepRecorder()
    limiter = RateLimiter(2, clock=fixed_clock(), sleep=sleep)
    assert [limiter.acquire() for _ in range(4)] == [0.0, 0.0, 30.0, 30.0]
    assert sleep.delays == [30.0, 30.0]


def test_rate_limiter_refills_over_time() -> None:
    clock = fixed_clock()
    sleep = SleepRecorder()
    limiter = RateLimiter(4, clock=clock, sleep=sleep)
    for _ in range(4):
        limiter.acquire()
    clock.advance(timedelta(seconds=30))  # 2 tokens back
    assert limiter.acquire() == 0.0
    assert limiter.acquire() == 0.0
    assert limiter.acquire() == 15.0


def test_rate_limiter_with_advancing_clock_sleep() -> None:
    clock = fixed_clock()
    sleep = SleepRecorder(clock)
    limiter = RateLimiter(60, clock=clock, sleep=sleep)
    for _ in range(62):
        limiter.acquire()
    assert sleep.delays == pytest.approx([1.0, 1.0])


def test_rate_limiter_rejects_bad_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(0)


def test_client_uses_rate_limiter_before_each_attempt() -> None:
    router = MockRouter()
    router.add("GET", "/r", json_response(200, {}))
    sleep = SleepRecorder()
    limiter = RateLimiter(1, clock=fixed_clock(), sleep=sleep)
    client = make_client(router, rate_limiter=limiter, sleep=sleep)
    client.get("/r", operation="r")
    client.get("/r", operation="r")
    assert sleep.delays == [60.0]


def test_client_context_manager_closes() -> None:
    router = MockRouter()
    with make_client(router) as client:
        assert client.integration == "secure_endpoint"
    assert client._client.is_closed
