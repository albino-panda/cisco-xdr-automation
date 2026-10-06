"""Adversarial review (round 1, lens: secrets-audit).

Every test asserts the SAFE behaviour. A failing test is proof of a real weakness in
``src/xdr_response``. Attack surface covered:

* secrets, OAuth tokens, passwords, private keys, the approval signing key and session tokens must
  never appear in logs, audit records, exceptions, reprs, analyst output or API summaries, including
  inside nested request/response bodies and vendor error messages;
* audit history cannot be altered undetected;
* the AI / automation layer has no API to modify or delete audit records.

Only fake values are used (example.com / *.test, obviously fake secrets). No network: every HTTP
exchange goes through ``httpx.MockTransport``.
"""
from __future__ import annotations

import copy
import io
import json
import logging
import pickle
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from tests.fixtures.factories import FIXED_NOW, make_evidence, make_package, make_recommendation
from tests.fixtures.principals import (
    AI_ID,
    ANALYST_ID,
    SERVICE_ID,
    credential,
    make_authenticator,
    make_test_secrets,
)
from xdr_response.approval import ApprovalEngine, ApprovalTokenService, InMemoryTokenUseLedger
from xdr_response.audit import AuditRecorder, AuditTrail, MemoryAuditTrail, verify_chain
from xdr_response.audit.hashing import compute_record_hash
from xdr_response.clock import FixedClock
from xdr_response.config import ApprovalSettings
from xdr_response.config.loader import load_settings
from xdr_response.errors import (
    ApprovalError,
    AuditIntegrityError,
    ConfigError,
    IntegrationError,
    SecretNotFoundError,
)
from xdr_response.integrations.auth import ApiKeyQuery, BasicAuth, OAuth2ClientCredentials
from xdr_response.integrations.http import GuardedHttpClient, RetryPolicy
from xdr_response.logs.redaction import REDACTED, Redactor
from xdr_response.logs.setup import JsonFormatter, RedactingFilter, get_logger
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    ApproverCredential,
    AuditEventType,
    DecisionRequest,
    DecisionType,
    OperationKind,
    PrincipalKind,
    TokenActionGrant,
    canonical_json,
    evidence_snapshot_hash,
)
from xdr_response.reporting.decision_card import render_decision_card
from xdr_response.secrets import StaticSecretProvider

BASE = "https://api.example.com"

# Obviously fake values. Each one is unique to this file so registering them with the process-wide
# redactor cannot change the expectations of any other test module.
FAKE_CLIENT_SECRET = "fake-client-secret-zq81-not-real"
FAKE_API_KEY = "fake-api-key-mx93-not-real-0001"
FAKE_PASSWORD = "fake-password-kv27-not-real"
FAKE_OPAQUE_TOKEN = "fakeOpaqueSessionTok3nQ7w9e5r1t"  # not JWT-shaped, never registered
FAKE_SESSION_KEY = "fakeSplunkSessKey0a1b2c3d4e5f6a7b"
FAKE_SAS_SIG = "fakeSasSig0123456789abcdefABCDEF0123456789zz"
FAKE_SIGNING_KEY = "fake-signing-key-for-tests-only-0123456789abcdef"  # >= 32 bytes


def _blob(*values: object) -> str:
    """Everything a reader could see, as one string."""
    return "\n".join(v if isinstance(v, str) else json.dumps(v, default=str, sort_keys=True)
                     for v in values)


def _audit_text(trail) -> str:
    return "\n".join(canonical_json(r, allow_floats=True).decode("utf-8") for r in trail.records())


def _client(handler, *, audit=None, auth=None, redactor=None) -> GuardedHttpClient:
    return GuardedHttpClient(
        "secure_endpoint", BASE, transport=httpx.MockTransport(handler),
        retry=RetryPolicy(max_retries=0, jitter=False), sleep=lambda _s: None,
        audit=audit, auth=auth, redactor=redactor)


@pytest.fixture
def log_capture():
    """A redacting JSON handler attached to an ``xdr_response.*`` logger; restored afterwards."""
    stream = io.StringIO()
    logger = get_logger("safety_secrets_test")
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JsonFormatter())
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield logger, stream
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


# =============================================================================================
# 1. SecretValue and provider objects never reveal themselves
# =============================================================================================
def test_secret_value_never_reveals_through_repr_str_format_or_serialization():
    sv = StaticSecretProvider({"SE_API_KEY": FAKE_API_KEY}).get("SE_API_KEY")
    seen = [repr(sv), str(sv), f"{sv}", f"{sv!r}", "%s" % sv, "{}".format(sv), f"{sv:>40}",
            repr([sv]), repr({"k": sv}), json.dumps({"k": sv}, default=str)]
    for text in seen:
        assert FAKE_API_KEY not in text
    with pytest.raises(TypeError):
        pickle.dumps(sv)
    with pytest.raises(TypeError):
        json.dumps(sv)  # no implicit serialization
    assert copy.deepcopy(sv) is sv  # never duplicated into a plain container
    with pytest.raises((AttributeError, TypeError)):
        vars(sv)


def test_secret_providers_and_auth_objects_repr_hide_values():
    provider = StaticSecretProvider({"XDR_CLIENT_SECRET": FAKE_CLIENT_SECRET, "SE_API_KEY": FAKE_API_KEY})
    secret = provider.get("XDR_CLIENT_SECRET")
    key = provider.get("SE_API_KEY")
    objects = [
        provider,
        BasicAuth(provider.get("SE_API_KEY"), secret),
        ApiKeyQuery("api_key", key),
        OAuth2ClientCredentials(token_url="https://id.example.com/oauth2/token", client_id=key,
                                client_secret=secret),
    ]
    for obj in objects:
        text = repr(obj) + str(obj)
        assert FAKE_CLIENT_SECRET not in text and FAKE_API_KEY not in text


def test_missing_secret_error_names_the_secret_only():
    with pytest.raises(SecretNotFoundError) as info:
        StaticSecretProvider({"OTHER": FAKE_PASSWORD}).get("XDR_CLIENT_SECRET")
    assert "XDR_CLIENT_SECRET" in str(info.value)
    assert FAKE_PASSWORD not in str(info.value)


def test_approval_signing_key_never_in_service_repr_or_logs(log_capture):
    logger, stream = log_capture
    secrets = StaticSecretProvider({"APPROVAL_SIGNING_KEY": FAKE_SIGNING_KEY})
    service = ApprovalTokenService(secrets, ApprovalSettings(), ledger=InMemoryTokenUseLedger(),
                                   clock=FixedClock(FIXED_NOW))
    logger.info("token service %r, key %s", service, FAKE_SIGNING_KEY)
    logger.info(f"debug: key is {FAKE_SIGNING_KEY}")
    assert FAKE_SIGNING_KEY not in repr(service)
    assert FAKE_SIGNING_KEY not in stream.getvalue()


# =============================================================================================
# 2. The central redactor: text forms of secrets that are NOT registered values
# =============================================================================================
def test_redactor_registered_secret_is_scrubbed_everywhere():
    r = Redactor()
    r.register_secret(FAKE_PASSWORD)
    data = {"a": [f"x {FAKE_PASSWORD} y", {"b": (FAKE_PASSWORD,)}], "set": {FAKE_PASSWORD}}
    out = r.redact(data)
    assert FAKE_PASSWORD not in json.dumps(out, default=str)
    assert FAKE_PASSWORD not in r.redact_text(f"Exception: login failed for {FAKE_PASSWORD}")


@pytest.mark.parametrize("text", [
    'vendor error body: {"error":"invalid_grant","access_token":"%s"}' % FAKE_OPAQUE_TOKEN,
    'vendor error body: {"session_token": "%s"}' % FAKE_OPAQUE_TOKEN,
    'vendor error body: {"password":"%s"}' % FAKE_OPAQUE_TOKEN,
], ids=["access_token", "session_token", "password"])
def test_redact_text_scrubs_secrets_in_json_text(text):
    """JSON serialized into a string (vendor error bodies, nested request bodies) keeps its keys."""
    assert FAKE_OPAQUE_TOKEN not in Redactor().redact_text(text)


def test_redact_text_scrubs_secrets_in_python_dict_repr():
    """``f"... {payload}"`` / ``str(dict)`` is the most common way a dict reaches a log message."""
    payload = {"client_secret": FAKE_OPAQUE_TOKEN, "grant_type": "client_credentials"}
    assert FAKE_OPAQUE_TOKEN not in Redactor().redact_text(f"token request failed: {payload}")


def test_redact_text_scrubs_basic_credentials_regardless_of_scheme_case():
    """RFC 7235: auth schemes are case-insensitive; vendors echo headers in lower case."""
    b64 = "ZmFrZS11c2VyOmZha2UtcGFzc3dvcmQta3YyNw=="  # fake-user:fake-password-kv27
    for text in (f"Authorization: Basic {b64}", f"authorization: basic {b64}",
                 f"AUTHORIZATION: BASIC {b64}"):
        assert b64 not in Redactor().redact_text(text), text


def test_redact_text_scrubs_azure_sas_signature_in_url():
    """Defender/Graph return SAS download URIs; ``sig`` is the bearer secret of a SAS URL."""
    url = ("https://fakestore.blob.core.windows.net/pkgs/TH-LT-1047.zip?sv=2020-08-04&se=2026-01-15"
           f"&sr=b&sp=r&sig={FAKE_SAS_SIG}")
    r = Redactor()
    assert FAKE_SAS_SIG not in r.redact_text(f"package uri: {url}")
    assert FAKE_SAS_SIG not in r.redact_url(url)


def test_redact_text_and_redact_url_agree_on_key_query_parameter():
    url = f"https://api.example.com/v1/lookup?key={FAKE_API_KEY}&q=example.com"
    r = Redactor()
    assert FAKE_API_KEY not in r.redact_url(url)
    assert FAKE_API_KEY not in r.redact_text(f"GET {url} failed")  # e.g. inside an error message


@pytest.mark.parametrize("key", [
    "password", "client_secret", "access_token", "refresh_token", "Authorization", "x-api-key",
    "apiKey", "private_key", "privateKey", "session_token", "approval_token", "unlock_code",
    "hec_token", "Cookie", "Set-Cookie",
])
def test_known_sensitive_keys_are_redacted(key):
    out = Redactor().redact({"outer": {"inner": [{key: FAKE_OPAQUE_TOKEN}]}})
    assert FAKE_OPAQUE_TOKEN not in json.dumps(out)


@pytest.mark.parametrize("key", [
    "APPROVAL_SIGNING_KEY",   # the framework's own signing key name
    "signing_key",
    "sessionKey",             # Splunk /services/auth/login response field
    "session_id",
    "recovery_key",           # BitLocker recovery key (Intune / Defender)
    "aws_secret_access_key",
])
def test_secret_bearing_key_names_used_in_this_domain_are_redacted(key):
    out = Redactor().redact({"response": {key: FAKE_OPAQUE_TOKEN}})
    assert FAKE_OPAQUE_TOKEN not in json.dumps(out), f"value under {key!r} leaked"


# =============================================================================================
# 3. Logs
# =============================================================================================
def test_log_args_extra_and_nested_mappings_are_redacted(log_capture):
    logger, stream = log_capture
    logger.info("call %s", {"headers": {"Authorization": f"Bearer {FAKE_OPAQUE_TOKEN}"}},
                extra={"ctx": {"body": {"client_secret": FAKE_CLIENT_SECRET}}, "api_key": FAKE_API_KEY})
    out = stream.getvalue()
    assert FAKE_OPAQUE_TOKEN not in out
    assert FAKE_CLIENT_SECRET not in out
    assert FAKE_API_KEY not in out


def test_log_exception_traceback_redacts_registered_secret(log_capture):
    logger, stream = log_capture
    StaticSecretProvider({"SE_API_KEY": FAKE_API_KEY}).get("SE_API_KEY")  # registers globally
    try:
        raise RuntimeError(f"upstream rejected key {FAKE_API_KEY}")
    except RuntimeError:
        logger.exception("call failed")
    assert FAKE_API_KEY not in stream.getvalue()


def test_log_message_with_interpolated_dict_is_redacted(log_capture):
    logger, stream = log_capture
    body = {"username": "svc-test@example.com", "password": FAKE_OPAQUE_TOKEN}
    logger.warning(f"login body rejected: {body}")
    assert FAKE_OPAQUE_TOKEN not in stream.getvalue()


# =============================================================================================
# 4. API summaries, HTTP errors and exceptions
# =============================================================================================
def test_api_summary_redacts_nested_request_and_response_bodies_and_query_keys():
    audit = MemoryAuditTrail()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"items": [{"name": "TH-LT-1047",
                                                            "credentials": {"password": FAKE_PASSWORD}}],
                                                  "refreshToken": FAKE_OPAQUE_TOKEN}})

    client = _client(handler, audit=audit)
    result = client.post("/v1/search", kind=OperationKind.READ, operation="search",
                         params={"api_key": FAKE_API_KEY, "q": "example.com"},
                         json={"filter": {"nested": [{"client_secret": FAKE_CLIENT_SECRET}]}})
    text = _blob(result.summary.model_dump(mode="json"), _audit_text(audit))
    for value in (FAKE_PASSWORD, FAKE_OPAQUE_TOKEN, FAKE_API_KEY, FAKE_CLIENT_SECRET):
        assert value not in text


def test_api_summary_url_never_contains_query_api_key_auth():
    """Secure Malware Analytics sends ``api_key`` in the query string (ApiKeyQuery)."""
    audit = MemoryAuditTrail()
    key = StaticSecretProvider({"SMA_API_KEY": FAKE_API_KEY}).get("SMA_API_KEY")
    client = _client(lambda req: httpx.Response(200, json={"ok": True}), audit=audit,
                     auth=ApiKeyQuery("api_key", key))
    result = client.get("/api/v2/search/submissions", operation="search", params={"q": "abc"})
    assert FAKE_API_KEY not in _blob(result.summary.model_dump(mode="json"), _audit_text(audit))


def test_http_error_excerpt_never_leaks_part_of_a_registered_secret():
    """The 200-char excerpt must be cut AFTER redaction, or a secret straddling the cut leaks."""
    StaticSecretProvider({"SE_API_KEY": FAKE_API_KEY}).get("SE_API_KEY")  # registered globally
    audit = MemoryAuditTrail()
    filler = "x" * (200 - 12)  # the excerpt boundary falls 12 characters into the secret
    body = f"{filler}{FAKE_API_KEY} is not a valid key"

    client = _client(lambda req: httpx.Response(400, text=body), audit=audit)
    with pytest.raises(IntegrationError) as info:
        client.get("/v1/computers", operation="list_computers")
    exc = info.value
    seen = _blob(str(exc), repr(exc), exc.to_error_info().message, _audit_text(audit))
    prefix = FAKE_API_KEY[:12]
    assert prefix not in seen, "a 12-character prefix of a registered secret leaked"


def test_http_error_excerpt_never_leaks_vendor_session_token_in_json_body():
    audit = MemoryAuditTrail()
    body = json.dumps({"error": "invalid_request", "session_token": FAKE_OPAQUE_TOKEN})
    client = _client(lambda req: httpx.Response(400, text=body,
                                                headers={"content-type": "application/json"}),
                     audit=audit)
    with pytest.raises(IntegrationError) as info:
        client.get("/v1/computers", operation="list_computers")
    exc = info.value
    seen = _blob(str(exc), exc.to_error_info().message, _audit_text(audit))
    assert FAKE_OPAQUE_TOKEN not in seen


def test_api_summary_redacts_sas_uri_returned_in_response_body():
    audit = MemoryAuditTrail()
    uri = f"https://fakestore.blob.core.windows.net/pkgs/p.zip?sv=2020-08-04&sr=b&sp=r&sig={FAKE_SAS_SIG}"
    client = _client(lambda req: httpx.Response(200, json={"value": uri}), audit=audit)
    result = client.get("/api/machineactions/abc/GetPackageUri", operation="get_package_uri")
    assert FAKE_SAS_SIG not in _blob(result.summary.model_dump(mode="json"), _audit_text(audit))


def test_http_result_repr_does_not_expose_secret_bearing_response_body():
    """A response carrying a credential under a well-known sensitive key: the summary is redacted,
    but ``repr(result)`` (tracebacks with locals, debug logging, pytest output) must not print it."""
    client = _client(lambda req: httpx.Response(200, json={"access_token": FAKE_SESSION_KEY}))
    result = client.post("/services/auth/login", kind=OperationKind.READ, operation="login")
    assert FAKE_SESSION_KEY not in json.dumps(result.summary.model_dump(mode="json"))
    assert FAKE_SESSION_KEY not in repr(result)


def test_oauth_access_token_and_client_secret_never_reach_audit_or_errors():
    audit = MemoryAuditTrail()
    provider = StaticSecretProvider({"XDR_CLIENT_ID": "fake-client-id-0001",
                                     "XDR_CLIENT_SECRET": FAKE_CLIENT_SECRET})
    issued = "fakeOauthAccessTok3nNotJwt9988776655"

    def idp(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"access_token": issued, "expires_in": 600, "token_type": "bearer"})

    auth = OAuth2ClientCredentials(token_url="https://id.example.com/oauth2/token",
                                   client_id=provider.get("XDR_CLIENT_ID"),
                                   client_secret=provider.get("XDR_CLIENT_SECRET"),
                                   transport=httpx.MockTransport(idp), clock=FixedClock(FIXED_NOW))

    def api(request: httpx.Request) -> httpx.Response:
        # A vendor echoing the caller's credential back in an error body.
        return httpx.Response(401, text=f"token {issued} rejected; Authorization: Bearer {issued}")

    client = _client(api, audit=audit, auth=auth)
    with pytest.raises(IntegrationError) as info:
        client.get("/iroh/iroh-enrich/observe/observables", operation="observe")
    seen = _blob(str(info.value), info.value.to_error_info().message, _audit_text(audit))
    assert issued not in seen
    assert FAKE_CLIENT_SECRET not in seen


# =============================================================================================
# 5. Audit records: redaction before hashing/writing
# =============================================================================================
def test_audit_payload_actor_and_ids_are_redacted_before_write(tmp_path: Path):
    StaticSecretProvider({"SE_API_KEY": FAKE_API_KEY}).get("SE_API_KEY")
    trail = AuditTrail(tmp_path / "audit.jsonl", fsync=False)
    trail.append(AuditEventType.ERROR, incident_id=f"XDR-1 {FAKE_API_KEY}",
                 actor=f"integration:secure_endpoint {FAKE_API_KEY}",
                 payload={"request": {"headers": {"Authorization": f"Bearer {FAKE_OPAQUE_TOKEN}"}},
                          "list": [{"password": FAKE_PASSWORD}, f"api_key={FAKE_CLIENT_SECRET}"],
                          FAKE_API_KEY: "secret used as a key",
                          "comment": f"analyst pasted key {FAKE_API_KEY}"})
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for value in (FAKE_API_KEY, FAKE_OPAQUE_TOKEN, FAKE_PASSWORD, FAKE_CLIENT_SECRET):
        assert value not in raw
    assert REDACTED in raw
    assert trail.verify().ok


def _claims() -> ApprovalTokenClaims:
    return ApprovalTokenClaims(
        token_id="tok-0001", purpose=ApprovalPurpose.CONTAINMENT, package_id="pkg-0001",
        incident_id="XDR-83921", evidence_snapshot_hash="a" * 64, workflow_id="powershell",
        workflow_version="1.0.0", decision_id="dec-0001",
        actions=(TokenActionGrant(idempotency_key="XDR-83921:isolate_endpoint:TH-LT-1047",
                                  action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047",
                                  params_hash="b" * 64, approval_level=ApprovalLevel.STANDARD),),
        approvers=(ApproverClaim(principal_id=ANALYST_ID, kind=PrincipalKind.HUMAN,
                                 roles=("xdr-approver",)),),
        issued_at=FIXED_NOW, expires_at=FIXED_NOW + timedelta(minutes=15))


def test_audit_never_stores_approval_token_signature_or_encoded_token():
    trail = MemoryAuditTrail()
    secrets = StaticSecretProvider({"APPROVAL_SIGNING_KEY": FAKE_SIGNING_KEY})
    service = ApprovalTokenService(secrets, ApprovalSettings(), ledger=InMemoryTokenUseLedger(),
                                   clock=FixedClock(FIXED_NOW))
    token = service.sign(_claims())
    AuditRecorder(trail).token_issued(token)
    trail.append(AuditEventType.ERROR, incident_id="XDR-1", actor="automation:test",
                 payload={"approval": token, "dump": token.model_dump(mode="json"),
                          "encoded": token.encode(), "note": f"token {token.encode()}"})
    text = _audit_text(trail)
    assert token.signature not in text
    assert token.encode() not in text
    assert FAKE_SIGNING_KEY not in text


def test_approval_token_str_and_repr_hide_signature():
    token = ApprovalToken(claims=_claims(), key_id="primary", signature="c" * 64)
    assert "c" * 64 not in str(token)
    assert "c" * 64 not in repr(token)


@pytest.mark.parametrize("key_id", ["primary", "k"])
def test_encoded_approval_token_is_redacted_from_text_for_every_legal_key_id(key_id):
    """``signing_key_id`` accepts ``[A-Za-z0-9_-]{1,64}``; the encoded bearer token must never be logged."""
    token = ApprovalToken(claims=_claims(), key_id=key_id, signature="d" * 64)
    out = Redactor().redact_text(f"approval token issued: {token.encode()}")
    assert token.signature not in out


def test_approver_credentials_and_signing_key_never_reach_audit_or_exceptions():
    trail = MemoryAuditTrail()
    secrets = make_test_secrets()
    signing_key = secrets.get("APPROVAL_SIGNING_KEY").reveal()
    clock = FixedClock(FIXED_NOW)
    service = ApprovalTokenService(secrets, ApprovalSettings(), ledger=InMemoryTokenUseLedger(), clock=clock)
    engine = ApprovalEngine(ApprovalSettings(), authenticator=make_authenticator(), tokens=service,
                            audit=trail, clock=clock)
    package = make_package(make_recommendation())
    req = DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL)
    errors: list[str] = []
    wrong = ApproverCredential(principal_id=ANALYST_ID, scheme="static", secret=SecretStr(FAKE_PASSWORD))
    for creds in ([credential(AI_ID)], [credential(SERVICE_ID)], [wrong]):
        with pytest.raises(ApprovalError) as info:
            engine.decide(package, req, creds)
        errors.append(f"{info.value} {info.value!r}")
    outcome = engine.decide(package, req, [credential(ANALYST_ID)])
    assert outcome.token is not None
    inputs = [credential(p).secret.get_secret_value() for p in (AI_ID, SERVICE_ID, ANALYST_ID)]
    seen = _blob(_audit_text(trail), *errors, repr(outcome), str(outcome))
    for value in inputs + [FAKE_PASSWORD, signing_key, outcome.token.signature]:
        assert value not in seen


# =============================================================================================
# 6. Analyst output
# =============================================================================================
def test_decision_card_redacts_registered_secrets_and_sensitive_params():
    StaticSecretProvider({"UMBRELLA_API_KEY": FAKE_API_KEY}).get("UMBRELLA_API_KEY")
    action = make_recommendation(ActionType.BLOCK_DOMAIN, target="bad.example.test", integration="umbrella",
                                 api_key=FAKE_CLIENT_SECRET, list_id="12345")
    package = make_package(action)
    tainted = make_evidence(1)[0].model_copy(update={
        "summary": f"lookup with key {FAKE_API_KEY} returned malicious",
        "reference": f"https://console.example.com/x?api_key={FAKE_API_KEY}"})
    package = package.model_copy(update={"evidence": (tainted,),
                                         "evidence_snapshot_hash": evidence_snapshot_hash((tainted,))})
    for fmt in ("text", "markdown", "json"):
        out = render_decision_card(package, fmt=fmt)
        assert FAKE_API_KEY not in out, fmt
        assert FAKE_CLIENT_SECRET not in out, fmt


# =============================================================================================
# 7. Config never accepts or echoes literal secrets
# =============================================================================================
def _write_config(tmp_path: Path, integrations_yaml: str) -> Path:
    (tmp_path / "integrations.yaml").write_text(integrations_yaml, encoding="utf-8")
    return tmp_path


def test_config_literal_secret_is_refused_without_echoing_it(tmp_path: Path):
    cfg = _write_config(tmp_path, (
        "integrations:\n  cisco_xdr:\n    enabled: true\n    base_url: https://visibility.amp.cisco.com\n"
        f"    secrets:\n      client_secret: {FAKE_CLIENT_SECRET}\n"))
    with pytest.raises(ConfigError) as info:
        load_settings(cfg, env={})
    assert FAKE_CLIENT_SECRET not in str(info.value)


def test_config_refuses_literal_secret_in_base_url_query(tmp_path: Path):
    cfg = _write_config(tmp_path, (
        "integrations:\n  secure_malware_analytics:\n    enabled: true\n"
        f"    base_url: https://panacea.threatgrid.example/api?api_key={FAKE_API_KEY}\n"))
    with pytest.raises(ConfigError) as info:
        load_settings(cfg, env={})
    assert FAKE_API_KEY not in str(info.value)


# =============================================================================================
# 8. Audit history cannot be altered undetected
# =============================================================================================
def _filled_trail(path: Path, n: int = 4) -> AuditTrail:
    trail = AuditTrail(path, fsync=False)
    for i in range(n):
        trail.append(AuditEventType.STATE_TRANSITION if i % 2 else AuditEventType.DECISION_RECORDED,
                     incident_id="XDR-83921", actor=ANALYST_ID if i % 2 == 0 else "automation:test",
                     payload={"index": i, "decision": "REJECT" if i == n - 1 else "APPROVE_SELECTED"})
    return trail


def test_audit_edit_of_any_record_is_detected(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    _filled_trail(path)
    lines = path.read_bytes().splitlines(keepends=True)
    lines[1] = lines[1].replace(b'"index":1', b'"index":7')
    path.write_bytes(b"".join(lines))
    assert not verify_chain(path).ok
    with pytest.raises(AuditIntegrityError):
        AuditTrail(path, fsync=False)


def test_audit_duplicate_key_injection_is_detected(tmp_path: Path):
    """A line with a duplicated JSON key parses (last wins) and re-hashes to the same value, but
    any consumer that keeps the FIRST value (SIEMs, streaming parsers, other languages) reads a
    forged actor. The verifier must insist on the canonical encoding of every line."""
    path = tmp_path / "audit.jsonl"
    _filled_trail(path)
    lines = path.read_bytes().splitlines(keepends=True)
    assert lines[0].startswith(b'{"actor":')
    lines[0] = b'{"actor":"ai-assistant@example.com",' + lines[0][1:]
    path.write_bytes(b"".join(lines))
    result = verify_chain(path)
    assert not result.ok, "a line with a forged duplicate 'actor' key passed verification"


def test_audit_tail_truncation_is_detected_after_restart(tmp_path: Path):
    """Deleting the newest records (e.g. the final REJECT decision) between process runs must be
    detected by the trail the framework actually opens, without the operator supplying anchors."""
    path = tmp_path / "audit.jsonl"
    _filled_trail(path, 4)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]))
    detected = False
    try:
        detected = not AuditTrail(path, fsync=False).verify().ok
    except AuditIntegrityError:
        detected = True
    assert detected, "dropping the last audit record went unnoticed"


def test_audit_forged_record_appended_offline_is_detected(tmp_path: Path):
    """Anyone who can write the file can append a well-chained forged record: the chain is an
    unkeyed SHA-256 over public data, so nothing distinguishes it from a genuine one."""
    path = tmp_path / "audit.jsonl"
    trail = _filled_trail(path, 3)
    forged = {"seq": 3, "record_id": "aud-forged", "timestamp": "2026-01-15T12:00:00.000000Z",
              "event_type": "DECISION_RECORDED", "incident_id": "XDR-83921", "workflow_id": None,
              "workflow_version": None, "actor": ANALYST_ID,
              "payload": {"decision": "APPROVE_ALL", "comment": "forged"}, "prev_hash": trail.head_hash}
    forged["hash"] = compute_record_hash(forged)
    with path.open("ab") as fh:
        fh.write(canonical_json(forged, allow_floats=True) + b"\n")
    detected = False
    try:
        detected = not AuditTrail(path, fsync=False).verify().ok
    except AuditIntegrityError:
        detected = True
    assert detected, "a forged, correctly chained record was accepted as genuine"


def test_live_writer_detects_truncation(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    trail = _filled_trail(path, 3)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]))
    with pytest.raises(AuditIntegrityError):
        trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})


# =============================================================================================
# 9. The AI / automation layer has no API to modify or delete audit records
# =============================================================================================
_MUTATING_NAMES = ("update", "delete", "remove", "truncate", "clear", "pop", "rewrite", "replace",
                   "edit", "purge", "insert", "set", "drop", "reset", "rollback", "erase", "modify")


@pytest.mark.parametrize("cls", [AuditTrail, MemoryAuditTrail, AuditRecorder])
def test_audit_classes_expose_no_mutating_public_api(cls):
    public = [name for name in dir(cls) if not name.startswith("_")]
    offending = [n for n in public if any(n.lower().startswith(m) or f"_{m}" in n.lower()
                                          for m in _MUTATING_NAMES)]
    assert offending == [], f"{cls.__name__} exposes {offending}"
    for dunder in ("__setitem__", "__delitem__"):
        assert not hasattr(cls, dunder)


def test_records_returned_to_callers_cannot_rewrite_history_undetected():
    trail = MemoryAuditTrail()
    for i in range(3):
        trail.append(AuditEventType.DECISION_RECORDED, incident_id="XDR-83921", actor=ANALYST_ID,
                     payload={"decision": "REJECT", "index": i})
    record = list(trail.records())[1]
    with pytest.raises(Exception):
        record.actor = AI_ID  # frozen model
    records = list(trail.records())
    records.clear()  # callers get a copy, not the store
    assert len(trail) == 3
    try:
        record.payload["decision"] = "APPROVE_ALL"  # payload dict is mutable in place
    except TypeError:
        return  # immutable payload: safe
    assert not trail.verify().ok, "in-place payload edit of a stored record went undetected"


def test_audit_file_is_append_only_through_the_api(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    trail = _filled_trail(path, 2)
    before = path.read_bytes()
    trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={"n": 1})
    after = path.read_bytes()
    assert after.startswith(before) and len(after) > len(before)


# =============================================================================================
# ROUND 2 (adversarial review, lens: secrets-audit)
# =============================================================================================
import hashlib as _hashlib  # noqa: E402
import hmac as _hmac  # noqa: E402
import re as _re  # noqa: E402
import traceback as _traceback  # noqa: E402

from xdr_response.audit.verify import AuditAnchor  # noqa: E402
from xdr_response.errors import TokenInvalidError  # noqa: E402
from xdr_response.integrations.health import health_from_exception  # noqa: E402
from xdr_response.logs.setup import ROOT_LOGGER_NAME, configure_logging  # noqa: E402
from xdr_response.models import TOKEN_ISSUANCE_CONTEXT, TOKEN_SIGNING_CONTEXT  # noqa: E402

R2_TOKEN = "fakeR2SessTok3nZx81Qw5Lp0Mn7"     # opaque, never registered
R2_API_KEY = "fake-r2-sma-api-key-0f9e8d7c6b"  # registered via a provider in the test using it


def _exception_text(exc: BaseException) -> str:
    """Everything a handler without our formatter could print about ``exc`` and its chain."""
    parts: list[str] = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        parts += [str(cur), repr(cur), repr(cur.args)]
        cur = cur.__cause__ or cur.__context__
    parts.append("".join(_traceback.format_exception(exc)))
    return "\n".join(parts)


@pytest.fixture
def isolated_log():
    """Redacting JSON handler on a non-propagating ``xdr_response.*`` logger (no pytest handlers)."""
    stream = io.StringIO()
    logger = get_logger("safety_secrets_r2")
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JsonFormatter())
    saved = (logger.level, logger.propagate)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield logger, stream
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]


# ---------------------------------------------------------------------------------------------
# R2-1 Logging: a sensitive key in the FORMAT STRING whose value is a %-placeholder.
# The filter redacts the placeholder itself ("password=%s" -> "password=[REDACTED]"), so
# msg % args raises TypeError; logging's handleError then prints the raw args to stderr and
# the record is lost.
# ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("fmt,args", [
    ("vendor login password=%s", (R2_TOKEN,)),
    ("Authorization: %s", (f"Splunk {R2_TOKEN}",)),
    ('session body {"session_token": "%s"} for %s', (R2_TOKEN, "TH-LT-1047")),
], ids=["kv-equals", "auth-header", "json-quoted"])
def test_log_placeholder_after_sensitive_key_never_leaks_args(isolated_log, capsys, fmt, args):
    logger, stream = isolated_log
    logger.warning(fmt, *args)
    err = capsys.readouterr().err
    out = stream.getvalue()
    assert R2_TOKEN not in err, "secret printed to stderr by logging.handleError (format/args mismatch)"
    assert R2_TOKEN not in out
    assert out.strip(), "the log record was dropped instead of being emitted redacted"


def test_log_secret_objects_in_extra_and_args_are_masked(isolated_log):
    """Passing attempt: SecretValue / SecretStr objects never reveal themselves through a log line."""
    logger, stream = isolated_log
    sv = StaticSecretProvider({"R2_LOG_SECRET": "fake-r2-log-secret-value-01"}).get("R2_LOG_SECRET")
    logger.info("using %s / %r", sv, SecretStr("fake-r2-secretstr-value-02"),
                extra={"cred": sv, "nested": {"x": [SecretStr("fake-r2-secretstr-value-03")]}})
    out = stream.getvalue()
    for value in ("fake-r2-log-secret-value-01", "fake-r2-secretstr-value-02", "fake-r2-secretstr-value-03"):
        assert value not in out


# ---------------------------------------------------------------------------------------------
# R2-2 Vendor error bodies whose secrets are not in plain key=value / "key":"value" form
# ---------------------------------------------------------------------------------------------
def _error_seen(body: str, content_type: str) -> str:
    audit = MemoryAuditTrail()
    client = _client(lambda req: httpx.Response(400, text=body, headers={"content-type": content_type}),
                     audit=audit)
    with pytest.raises(IntegrationError) as info:
        client.get("/v1/computers", operation="list_computers")
    exc = info.value
    return _blob(str(exc), exc.to_error_info().message, _audit_text(audit))


@pytest.mark.parametrize("body,ctype", [
    # Double-encoded JSON (an inner request/response body serialized into an error message).
    (json.dumps({"error": {"code": "BadRequest",
                           "message": "invalid body: " + json.dumps({"password": R2_TOKEN})}}),
     "application/json"),
    (json.dumps({"errors": [{"detail": json.dumps({"session_token": R2_TOKEN, "user": "svc"})}]}),
     "application/json"),
    # XML bodies (Splunk REST answers XML by default; <sessionKey> is its session credential).
    (f"<response><sessionKey>{R2_TOKEN}</sessionKey></response>", "text/xml"),
    (f"<error><password>{R2_TOKEN}</password></error>", "application/xml"),
], ids=["escaped-json-password", "escaped-json-session_token", "xml-sessionKey", "xml-password"])
def test_http_error_excerpt_redacts_nested_and_xml_secret_fields(body, ctype):
    assert R2_TOKEN not in _error_seen(body, ctype)


def _slash_escaped(s: str) -> str:
    return json.dumps({"detail": f"bad key {s}"}).replace("/", "\\/")


def _unicode_escaped(s: str) -> str:
    return json.dumps({"detail": f"login failed: {s}"})  # ensure_ascii: a-umlaut -> ä


@pytest.mark.parametrize("secret,encode", [
    ("fake-pässwörd-kv27-not-real", _unicode_escaped),
    ("fake/r2+secret/kv27/not/real0", _slash_escaped),
], ids=["unicode-escaped", "slash-escaped"])
def test_registered_secret_echoed_json_escaped_in_error_body_is_redacted(secret, encode):
    """A registered secret is matched literally; vendor JSON escapes it (ensure_ascii, PHP/Java '\\/')."""
    StaticSecretProvider({"R2_VENDOR_SECRET": secret}).get("R2_VENDOR_SECRET")  # registered globally
    seen = _error_seen(encode(secret), "application/json")
    decoded = _re.sub(r"\\+u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), seen)
    decoded = _re.sub(r"\\+/", "/", decoded)
    assert secret not in decoded, "registered secret recoverable from the JSON-escaped error excerpt"


# ---------------------------------------------------------------------------------------------
# R2-3 Third-party loggers: httpx logs every request URL at INFO (logger "httpx"), outside the
# xdr_response tree that configure_logging() redacts. ApiKeyQuery puts the key in that URL.
# ---------------------------------------------------------------------------------------------
def test_httpx_request_log_never_contains_query_api_key():
    key = StaticSecretProvider({"R2_SMA_API_KEY": R2_API_KEY}).get("R2_SMA_API_KEY")
    host_stream = io.StringIO()
    host_handler = logging.StreamHandler(host_stream)  # a host application's ordinary root handler
    host_handler.setFormatter(logging.Formatter("%(name)s %(message)s"))
    root = logging.getLogger()
    fw = logging.getLogger(ROOT_LOGGER_NAME)
    saved_root = root.level
    saved_fw = (fw.level, fw.propagate, list(fw.handlers))
    root.addHandler(host_handler)
    root.setLevel(logging.INFO)
    try:
        configure_logging("INFO", stream=io.StringIO())
        client = _client(lambda req: httpx.Response(200, json={"ok": True}),
                         auth=ApiKeyQuery("api_key", key))
        client.get("/api/v2/search/submissions", operation="search", params={"q": "abc"})
    finally:
        root.removeHandler(host_handler)
        root.setLevel(saved_root)
        for h in list(fw.handlers):
            if h not in saved_fw[2]:
                fw.removeHandler(h)
        fw.setLevel(saved_fw[0])
        fw.propagate = saved_fw[1]
    assert R2_API_KEY not in host_stream.getvalue(), (
        "httpx INFO request line logged the query-string API key: " + host_stream.getvalue().strip())


# ---------------------------------------------------------------------------------------------
# R2-4 Approval token verification errors never reveal the correct MAC / issuance proof
# ---------------------------------------------------------------------------------------------
def _issued_token():
    secrets = make_test_secrets()
    key = secrets.get("APPROVAL_SIGNING_KEY").reveal().encode("utf-8")
    clock = FixedClock(FIXED_NOW)
    service = ApprovalTokenService(secrets, ApprovalSettings(), ledger=InMemoryTokenUseLedger(), clock=clock)
    engine = ApprovalEngine(ApprovalSettings(), authenticator=make_authenticator(), tokens=service,
                            audit=MemoryAuditTrail(), clock=clock)
    package = make_package(make_recommendation())
    outcome = engine.decide(package, DecisionRequest(package_id=package.package_id,
                                                     decision=DecisionType.APPROVE_ALL),
                            [credential(ANALYST_ID)])
    return service, key, outcome.token


def test_bad_signature_error_never_reveals_expected_signature():
    service, key, token = _issued_token()
    tampered_claims = token.claims.model_copy(update={"incident_id": "XDR-99999"})
    tampered = token.model_copy(update={"claims": tampered_claims})
    expected = _hmac.new(key, TOKEN_SIGNING_CONTEXT + canonical_json(tampered_claims), _hashlib.sha256).hexdigest()
    with pytest.raises(TokenInvalidError) as info:
        service.verify_token(tampered, purpose=ApprovalPurpose.CONTAINMENT)
    text = _exception_text(info.value)
    assert expected not in text and token.signature not in text and key.decode() not in text


def test_bad_issuance_proof_error_never_reveals_expected_proof():
    service, key, token = _issued_token()
    forged_claims = token.claims.model_copy(update={"decision_id": "dec-forged"})
    forged = service.sign(forged_claims)  # low-level signer: valid MAC, stale proof
    body = forged_claims.model_dump(mode="json", exclude={"issued_at", "issuance_proof"})
    expected_proof = _hmac.new(key, TOKEN_ISSUANCE_CONTEXT + canonical_json(body), _hashlib.sha256).hexdigest()
    with pytest.raises(TokenInvalidError) as info:
        service.verify_token(forged, purpose=ApprovalPurpose.CONTAINMENT)
    text = _exception_text(info.value)
    assert expected_proof not in text and forged.signature not in text


def test_token_decode_error_never_echoes_the_bearer_token():
    _, _, token = _issued_token()
    encoded = token.encode()
    body, _kid, sig = encoded.split(".")
    for bad in (f"{body}.bad key id!.{sig}", f"{body[:-3]}.primary.{sig}", f"{encoded}.extra"):
        with pytest.raises(TokenInvalidError) as info:
            ApprovalToken.decode(bad)
        assert sig not in _exception_text(info.value)


# ---------------------------------------------------------------------------------------------
# R2-5 Health results and audit of nested secret models (passing attempts)
# ---------------------------------------------------------------------------------------------
def test_health_detail_redacts_secret_before_truncation():
    secret = "fake-r2-health-key-77aa66bb55"
    StaticSecretProvider({"R2_HEALTH_KEY": secret}).get("R2_HEALTH_KEY")
    filler = "y" * (500 - len("health check failed: RuntimeError: ") - 10)
    health = health_from_exception("umbrella", RuntimeError(filler + secret))
    assert secret[:10] not in health.detail


def test_audit_payload_with_nested_secret_models_is_redacted():
    trail = MemoryAuditTrail()
    cred = ApproverCredential(principal_id=ANALYST_ID, scheme="static", secret=SecretStr("fake-r2-cred-pw-001"))
    sv = StaticSecretProvider({"R2_AUDIT_SV": "fake-r2-audit-sv-002"}).get("R2_AUDIT_SV")
    trail.append(AuditEventType.ERROR, incident_id="XDR-1", actor="automation:test",
                 payload={"credential": cred, "items": [{"value": sv}], "raw": cred.model_dump()})
    text = _audit_text(trail)
    assert "fake-r2-cred-pw-001" not in text and "fake-r2-audit-sv-002" not in text


# ---------------------------------------------------------------------------------------------
# R2-6 Audit history rewrite: the chain is unkeyed SHA-256 and the head anchor is an unauthenticated
# sidecar next to the file, so whoever can write the audit directory (or uses the public helpers
# compute_record_hash / canonical_json plus AuditTrail.path / anchor_path) can rewrite history.
# ---------------------------------------------------------------------------------------------
def _rewrite(path: Path, anchor_path: Path, mutate) -> None:
    records = mutate([json.loads(line) for line in path.read_bytes().splitlines()])
    prev = "0" * 64
    out = b""
    for seq, rec in enumerate(records):
        rec["seq"] = seq
        rec["prev_hash"] = prev
        rec["hash"] = compute_record_hash(rec)
        prev = rec["hash"]
        out += canonical_json(rec, allow_floats=True) + b"\n"
    path.write_bytes(out)
    anchor = AuditAnchor(seq=len(records) - 1, hash=prev)
    anchor_path.write_text(json.dumps(anchor.model_dump(mode="json"), sort_keys=True), encoding="utf-8")


def _flip_reject(records):
    records[-1]["payload"]["decision"] = "APPROVE_ALL"
    records[-1]["actor"] = AI_ID
    return records


def _drop_last(records):
    return records[:-1]


@pytest.mark.parametrize("mutate", [_flip_reject, _drop_last],
                         ids=["edit-final-REJECT-to-APPROVE_ALL", "drop-final-record"])
def test_audit_history_rewrite_with_reanchored_head_is_detected(tmp_path: Path, mutate):
    path = tmp_path / "audit.jsonl"
    trail = _filled_trail(path, 4)
    _rewrite(path, trail.anchor_path, mutate)
    detected = False
    try:
        detected = not AuditTrail(path, fsync=False).verify().ok
    except AuditIntegrityError:
        detected = True
    assert detected, ("rewritten audit history verified as genuine: the chain is unkeyed and the "
                      "head anchor is an unauthenticated sidecar file")


def test_audit_reorder_and_middle_delete_are_detected(tmp_path: Path):
    """Passing attempt: without re-hashing, reordering or deleting a middle record breaks the chain."""
    for change in ("reorder", "delete"):
        path = tmp_path / f"{change}.jsonl"
        _filled_trail(path, 4)
        lines = path.read_bytes().splitlines(keepends=True)
        lines = [lines[0], lines[2], lines[1], lines[3]] if change == "reorder" else [lines[0], lines[2], lines[3]]
        path.write_bytes(b"".join(lines))
        assert not verify_chain(path).ok, change
        with pytest.raises(AuditIntegrityError):
            AuditTrail(path, fsync=False)
