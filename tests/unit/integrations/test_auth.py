"""Auth providers (integrations/auth.py): headers, query keys, OAuth2 token cache, errors, redaction."""
from __future__ import annotations

import base64
from datetime import timedelta
from urllib.parse import parse_qs

import httpx
import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.fixtures.http_mocks import MockRouter, json_response
from xdr_response.clock import FixedClock
from xdr_response.errors import AuthFailedError, IntegrationTimeoutError, IntegrationUnavailableError, RateLimitedError
from xdr_response.integrations.auth import (
    ApiKeyHeader,
    ApiKeyQuery,
    AuthProvider,
    BasicAuth,
    OAuth2ClientCredentials,
)
from xdr_response.integrations.http import GuardedHttpClient, RetryPolicy
from xdr_response.logs.redaction import Redactor
from xdr_response.models import OperationKind
from xdr_response.secrets import SecretValue

TOKEN_URL = "https://auth.example.test/oauth2/token"
CLIENT_ID = SecretValue("CLIENT_ID", "fake-client-id-0001")
CLIENT_SECRET = SecretValue("CLIENT_SECRET", "fake-client-secret-0001")


def _request() -> httpx.Request:
    return httpx.Request("GET", "https://api.example.test/v1/things?x=1")


def _oauth(router: MockRouter, **kwargs) -> OAuth2ClientCredentials:
    kwargs.setdefault("clock", FixedClock(FIXED_NOW))
    return OAuth2ClientCredentials(token_url=TOKEN_URL, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                                   transport=router.transport(), **kwargs)


def test_every_provider_implements_the_protocol():
    providers = [ApiKeyHeader("x-apikey", CLIENT_SECRET), ApiKeyQuery("api_key", CLIENT_SECRET),
                 BasicAuth(CLIENT_ID, CLIENT_SECRET), _oauth(MockRouter())]
    assert all(isinstance(p, AuthProvider) for p in providers)


def test_reprs_never_show_secret_values():
    for provider in (ApiKeyHeader("x-apikey", CLIENT_SECRET), ApiKeyQuery("api_key", CLIENT_SECRET),
                     BasicAuth(CLIENT_ID, CLIENT_SECRET), _oauth(MockRouter())):
        assert "fake-client" not in repr(provider)


def test_api_key_header_with_prefix():
    request = _request()
    ApiKeyHeader("Authorization", CLIENT_SECRET, prefix="Bearer ").apply(request)
    assert request.headers["authorization"] == "Bearer fake-client-secret-0001"


def test_api_key_query_keeps_existing_params():
    request = _request()
    ApiKeyQuery("api_key", CLIENT_SECRET).apply(request)
    assert request.url.params["api_key"] == "fake-client-secret-0001"
    assert request.url.params["x"] == "1"


def test_basic_auth_header():
    request = _request()
    BasicAuth(CLIENT_ID, CLIENT_SECRET).apply(request)
    expected = base64.b64encode(b"fake-client-id-0001:fake-client-secret-0001").decode()
    assert request.headers["authorization"] == f"Basic {expected}"


def test_providers_refuse_plain_strings_and_empty_secrets():
    with pytest.raises(TypeError):
        ApiKeyHeader("x-apikey", "plain-string")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        BasicAuth(CLIENT_ID, SecretValue("EMPTY", ""))
    with pytest.raises(ValueError):
        ApiKeyHeader("bad:header", CLIENT_SECRET)


def test_oauth_basic_auth_token_request_and_cache():
    router = MockRouter()
    router.add("POST", "/oauth2/token", json_response(200, {"access_token": "tok-aaaaaaaa", "expires_in": 3600}))
    oauth = _oauth(router, scope="api.read")
    for _ in range(3):
        request = _request()
        oauth.apply(request)
        assert request.headers["authorization"] == "Bearer tok-aaaaaaaa"
    assert oauth.token_requests == 1
    call = router.calls[0]
    assert call.headers["authorization"].startswith("Basic ")
    form = parse_qs(call.content.decode())
    assert form == {"grant_type": ["client_credentials"], "scope": ["api.read"]}


def test_oauth_form_credentials_when_basic_auth_is_off():
    router = MockRouter()
    router.add("POST", "/oauth2/token", json_response(200, {"access_token": "tok-bbbbbbbb", "expires_in": 3600}))
    oauth = _oauth(router, basic_auth=False, scope="https://graph.example.test/.default")
    oauth.apply(_request())
    call = router.calls[0]
    assert "authorization" not in call.headers
    form = parse_qs(call.content.decode())
    assert form["client_id"] == ["fake-client-id-0001"] and form["client_secret"] == ["fake-client-secret-0001"]


def test_oauth_refreshes_before_expiry_and_after_invalidate():
    router = MockRouter()
    router.add("POST", "/oauth2/token",
               json_response(200, {"access_token": "tok-first-0001", "expires_in": 3600}),
               json_response(200, {"access_token": "tok-second-0002", "expires_in": 3600}),
               json_response(200, {"access_token": "tok-third-0003", "expires_in": 3600}))
    clock = FixedClock(FIXED_NOW)
    oauth = _oauth(router, clock=clock)
    oauth.apply(_request())
    clock.advance(timedelta(seconds=3600 - 121))
    request = _request()
    oauth.apply(request)
    assert request.headers["authorization"] == "Bearer tok-first-0001"  # still outside the refresh margin
    clock.advance(timedelta(seconds=2))  # inside the 120 s margin: refreshed (Umbrella 400-on-expiry safe)
    request = _request()
    oauth.apply(request)
    assert request.headers["authorization"] == "Bearer tok-second-0002"
    oauth.invalidate()
    request = _request()
    oauth.apply(request)
    assert request.headers["authorization"] == "Bearer tok-third-0003"


def test_oauth_registers_the_token_with_the_redactor():
    router = MockRouter()
    router.add("POST", "/oauth2/token", json_response(200, {"access_token": "tok-must-be-hidden-0001"}))
    redactor = Redactor()
    _oauth(router, redactor=redactor).apply(_request())
    assert "tok-must-be-hidden-0001" not in redactor.redact_text("value tok-must-be-hidden-0001 here")


@pytest.mark.parametrize(("status", "error"), [(400, AuthFailedError), (401, AuthFailedError),
                                               (403, AuthFailedError), (429, RateLimitedError),
                                               (503, IntegrationUnavailableError)])
def test_oauth_error_mapping(status, error):
    router = MockRouter()
    router.add("POST", "/oauth2/token", json_response(status, {"error": "fake-client-secret-0001 rejected"}))
    with pytest.raises(error) as excinfo:
        _oauth(router, integration="umbrella").apply(_request())
    assert "fake-client-secret-0001" not in str(excinfo.value)
    assert excinfo.value.integration == "umbrella"


def test_oauth_invalid_bodies_fail_closed():
    for body in ({"no": "token"}, ["list"]):
        router = MockRouter()
        router.add("POST", "/oauth2/token", json_response(200, body))
        with pytest.raises(AuthFailedError):
            _oauth(router).apply(_request())
    router = MockRouter()
    router.add("POST", "/oauth2/token", httpx.Response(200, text="not json"))
    with pytest.raises(AuthFailedError):
        _oauth(router).apply(_request())


def test_oauth_transport_errors():
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    for handler, error in ((timeout, IntegrationTimeoutError), (refused, IntegrationUnavailableError)):
        router = MockRouter()
        router.add("POST", "/oauth2/token", handler)
        with pytest.raises(error):
            _oauth(router).apply(_request())


def test_token_url_must_be_https():
    with pytest.raises(ValueError):
        OAuth2ClientCredentials(token_url="http://auth.example.test/token", client_id=CLIENT_ID,
                                client_secret=CLIENT_SECRET)


def test_guarded_client_reauthenticates_once_after_401():
    router = MockRouter()
    router.add("POST", "/oauth2/token",
               json_response(200, {"access_token": "tok-stale-0001", "expires_in": 3600}),
               json_response(200, {"access_token": "tok-fresh-0002", "expires_in": 3600}))
    router.add("GET", "/v1/things", json_response(401), json_response(200, {"ok": True}))
    client = GuardedHttpClient("umbrella", "https://api.example.test", auth=_oauth(router),
                               transport=router.transport(), retry=RetryPolicy(max_retries=0, jitter=False),
                               sleep=lambda _s: None)
    result = client.request("GET", "v1/things", kind=OperationKind.READ, operation="list")
    assert result.body == {"ok": True}
    api_calls = router.calls_to("GET", "/v1/things")
    assert [c.headers["authorization"] for c in api_calls] == ["Bearer tok-stale-0001", "Bearer tok-fresh-0002"]
    assert "tok-fresh-0002" not in str(result.summary.model_dump())
