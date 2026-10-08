"""Secrets never leak (repr/str/format/json/pickle/logging) and the central redactor scrubs them."""
from __future__ import annotations

import copy
import io
import json
import logging
import pickle

import pytest
from pydantic import BaseModel, SecretStr

from tests.fixtures.factories import FIXED_NOW
from tests.fixtures.principals import TEST_SIGNING_KEY_NAME, make_test_secrets
from xdr_response.errors import SecretNotFoundError
from xdr_response.logs import (
    REDACTED,
    JsonFormatter,
    RedactingFilter,
    Redactor,
    configure_logging,
    get_logger,
    get_redactor,
)
from xdr_response.models import (
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    ActionType,
    ApprovalLevel,
    PrincipalKind,
    TokenActionGrant,
)
from xdr_response.secrets import (
    ChainSecretProvider,
    EnvSecretProvider,
    FileSecretProvider,
    SecretValue,
    StaticSecretProvider,
    default_secret_provider,
)

FAKE = "fake-secret-value-0123456789"


# -------------------------------------------------------------- SecretValue --
def test_secret_value_never_reveals_itself():
    s = SecretValue("XDR_CLIENT_SECRET", FAKE)
    assert s.reveal() == FAKE
    assert repr(s) == "SecretValue(name='XDR_CLIENT_SECRET', value='***')"
    assert str(s) == "***" and f"{s}" == "***" and "{}".format(s) == "***" and "%s" % s == "***"
    assert FAKE not in repr([s, {"k": s}])
    with pytest.raises(TypeError):
        json.dumps({"k": s})
    assert FAKE not in json.dumps({"k": s}, default=str)
    with pytest.raises(TypeError):
        pickle.dumps(s)
    assert copy.deepcopy(s) is s and copy.copy(s) is s
    with pytest.raises(AttributeError):
        s._value = "x"  # type: ignore[misc]
    assert s == SecretValue("OTHER", FAKE) and s != SecretValue("XDR_CLIENT_SECRET", "other-value")
    with pytest.raises(TypeError):
        hash(s)


def test_secret_value_not_leaked_by_logging(caplog):
    s = SecretValue("VT_API_KEY", FAKE)
    log = get_logger("test.secrets")
    with caplog.at_level(logging.INFO, logger="xdr_response"):
        log.info("using key %s and %r", s, s, extra={"api_key": FAKE, "detail": {"secret": FAKE}})
    assert caplog.records, "record should have been captured"
    text = caplog.text + "".join(str(vars(r)) for r in caplog.records)
    assert FAKE not in text


# ---------------------------------------------------------------- providers --
def test_env_provider_and_registration():
    red = Redactor()
    p = EnvSecretProvider({"VT_API_KEY": FAKE, "EMPTY": ""}, redactor=red)
    assert p.get("VT_API_KEY").reveal() == FAKE
    assert red.redact_text(f"key={FAKE} ok") == f"key={REDACTED} ok"
    assert red.redact_text(f"value {FAKE} seen") == f"value {REDACTED} seen"
    with pytest.raises(SecretNotFoundError) as exc:
        p.get("EMPTY")
    assert "EMPTY" in str(exc.value)
    assert p.get_optional("MISSING") is None
    with pytest.raises(ValueError):
        p.get("../etc/passwd")


def test_env_provider_reads_os_environ(monkeypatch):
    monkeypatch.setenv("XDR_TEST_SECRET_NAME", FAKE)
    assert EnvSecretProvider().get("XDR_TEST_SECRET_NAME").reveal() == FAKE
    assert FAKE not in repr(EnvSecretProvider())


def test_file_provider(tmp_path):
    (tmp_path / "HIBP_API_KEY").write_text(FAKE + "\n", encoding="utf-8")
    p = FileSecretProvider(tmp_path)
    assert p.get("HIBP_API_KEY").reveal() == FAKE
    assert p.get_optional("NOPE") is None
    with pytest.raises(ValueError):
        p.get("..")
    chain = default_secret_provider({}, mount_dir=tmp_path)
    assert chain.get("HIBP_API_KEY").reveal() == FAKE


def test_static_and_chain_providers():
    a = StaticSecretProvider({"A_KEY": "value-from-a-123"})
    b = StaticSecretProvider({"A_KEY": "value-from-b-123", "B_KEY": "value-from-b-456"})
    chain = ChainSecretProvider(a, b)
    assert chain.get("A_KEY").reveal() == "value-from-a-123"
    assert chain.get("B_KEY").reveal() == "value-from-b-456"
    with pytest.raises(SecretNotFoundError):
        chain.get("C_KEY")
    assert "value-from" not in repr(chain)
    with pytest.raises(ValueError):
        StaticSecretProvider({"lower": "x"})
    with pytest.raises(ValueError):
        ChainSecretProvider()


def test_make_test_secrets_signing_key():
    s1, s2 = make_test_secrets(), make_test_secrets(VT_API_KEY=FAKE)
    k1 = s1.get(TEST_SIGNING_KEY_NAME).reveal()
    assert len(k1.encode()) >= 32 and k1 != s2.get(TEST_SIGNING_KEY_NAME).reveal()
    assert s2.get("VT_API_KEY").reveal() == FAKE


# ---------------------------------------------------------------- redaction --
@pytest.mark.parametrize("key", [
    "Authorization", "proxy-authorization", "Cookie", "Set-Cookie", "password", "passwd", "secret",
    "client_secret", "clientSecret", "token", "access_token", "accessToken", "refresh_token", "id_token",
    "api_key", "apikey", "apiKey", "x-apikey", "X-API-Key", "hibp-api-key", "X-OTX-API-KEY",
    "X-Cisco-Meraki-API-Key", "private_key", "session", "signature", "approval_token", "unlock_code",
    "credential", "key", "hec_token", "api_secret", "db_password", "session_id", "sessionKey", "sig",
])
def test_sensitive_keys(key):
    assert Redactor().is_sensitive_key(key)


@pytest.mark.parametrize("key", [
    "idempotency_key", "token_id", "params_hash", "control_key", "control_keys", "signing_key_id",
    "containment_token_ttl_minutes", "revoke_sessions", "keys", "integration", "target",
    "evidence_snapshot_hash", "claims_hash",
])
def test_non_sensitive_keys(key):
    assert not Redactor().is_sensitive_key(key)


def test_redact_nested_structures_deep_copy():
    data = {"headers": {"Authorization": "Bearer abc.def.ghi", "Accept": "json"},
            "items": [{"password": "p4ss-word"}, ("token", {"api_key": "k"})],
            "idempotency_key": "XDR-1:block_ip:192.0.2.1", "count": 3, "secret_obj": SecretStr("x")}
    out = Redactor().redact(data)
    assert out["headers"]["Authorization"] == REDACTED and out["headers"]["Accept"] == "json"
    assert out["items"][0]["password"] == REDACTED and out["items"][1][1]["api_key"] == REDACTED
    assert out["idempotency_key"] == "XDR-1:block_ip:192.0.2.1" and out["count"] == 3
    assert out["secret_obj"] == REDACTED
    assert data["items"][0]["password"] == "p4ss-word"  # input untouched


def test_redact_text_patterns():
    r = Redactor()
    r.register_secret("short")  # < 6 chars ignored
    r.register_secret("registered-secret-1")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
    text = (f"Authorization: Bearer opaque-token-123 basic short registered-secret-1 {jwt} "
            "client_secret=abc123 Basic dXNlcjpwYXNzd29yZA== Splunk 11111111-2222-3333-4444-555555555555")
    out = r.redact_text(text)
    for leaked in ("opaque-token-123", "registered-secret-1", jwt, "abc123", "dXNlcjpwYXNzd29yZA==",
                   "11111111-2222-3333-4444-555555555555"):
        assert leaked not in out
    assert "short" in out  # not registered (too short), ordinary words survive
    assert r.redact_text("approval token expired for XDR-1") == "approval token expired for XDR-1"


def test_redact_url_and_headers():
    r = Redactor()
    url = "https://user:pw@panacea.threatgrid.com/api/v2/search?api_key=SECRETKEY99&q=evil.example.test"
    out = r.redact_url(url)
    assert "SECRETKEY99" not in out and "user:pw" not in out and "q=evil.example.test" in out
    assert out.startswith("https://panacea.threatgrid.com/")
    h = r.redact_headers({"x-apikey": "VTKEY-123456", "User-Agent": "xdr-response", "Authorization": "Bearer x"})
    assert h == {"x-apikey": REDACTED, "User-Agent": "xdr-response", "Authorization": REDACTED}


def test_encoded_approval_token_is_redacted():
    claims = ApprovalTokenClaims(
        token_id="t" * 32, purpose=ApprovalPurpose.CONTAINMENT, package_id="p", incident_id="XDR-1",
        evidence_snapshot_hash="e" * 64, workflow_id="w", workflow_version="1", decision_id="d",
        actions=(TokenActionGrant(idempotency_key="XDR-1:block_ip:192.0.2.1", action_type=ActionType.BLOCK_IP,
                                  target="192.0.2.1", params_hash="0" * 64, approval_level=ApprovalLevel.STANDARD),),
        approvers=(ApproverClaim(principal_id="analyst.one@example.com", kind=PrincipalKind.HUMAN, roles=()),),
        issued_at=FIXED_NOW, expires_at=FIXED_NOW.replace(hour=13))
    token = ApprovalToken(claims=claims, key_id="primary", signature="cd" * 32)
    encoded = token.encode()
    assert "cd" * 32 not in get_redactor().redact_text(f"token was {encoded}")
    dumped = get_redactor().redact(token)
    assert dumped["signature"] == REDACTED and dumped["claims"]["token_id"] == "t" * 32


def test_redact_pydantic_model():
    class M(BaseModel):
        client_secret: str
        name: str

    assert Redactor().redact(M(client_secret="v", name="n")) == {"client_secret": REDACTED, "name": "n"}


def test_redactor_extra_keys():
    assert Redactor(extra_keys=["tenantSecretRef"]).is_sensitive_key("tenant_secret_ref")


# ------------------------------------------------------------------ logging --
@pytest.fixture()
def restore_logging():
    logger = logging.getLogger("xdr_response")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    yield
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]


def test_json_logging_redacts_everything(restore_logging):
    get_redactor().register_secret(FAKE)
    stream = io.StringIO()
    configure_logging("DEBUG", json_format=True, stream=stream)
    log = get_logger("unit")
    assert log.name == "xdr_response.unit" and get_logger("xdr_response.x").name == "xdr_response.x"
    log.info("calling with %s", FAKE, extra={"headers": {"Authorization": "Bearer zzzzzzzzzz"},
                                              "access_token": "tok-value-xyz", "incident_id": "XDR-1"})
    try:
        raise RuntimeError(f"failure with {FAKE}")
    except RuntimeError:
        log.exception("boom")
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert len(lines) == 2
    blob = stream.getvalue()
    for leaked in (FAKE, "zzzzzzzzzz", "tok-value-xyz"):
        assert leaked not in blob
    assert lines[0]["incident_id"] == "XDR-1" and lines[0]["level"] == "INFO"
    assert "exception" in lines[1]
    configure_logging("INFO", json_format=False, stream=io.StringIO())  # idempotent reconfigure


def test_redacting_filter_on_plain_record():
    get_redactor().register_secret(FAKE)
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "secret %s", (FAKE,), None)
    assert RedactingFilter().filter(rec) is True
    assert FAKE not in rec.getMessage()
    assert FAKE not in JsonFormatter().format(rec)


@pytest.mark.parametrize("text, kept", [
    ("tool.exe --password=Hunter2x -v", "tool.exe --password=[REDACTED] -v"),
    ("tool.exe -token=abcdef123 next", "tool.exe -token=[REDACTED] next"),
    ("agent --api-key=XYZ12345 --verbose", "agent --api-key=[REDACTED] --verbose"),
])
def test_command_line_flags_with_sensitive_keys_are_redacted(text, kept):
    """Command lines kept in process and persistence records must not keep ``--password=...`` values."""
    assert Redactor().redact_text(text) == kept


@pytest.mark.parametrize("text", ["run --mode=fast", "x --control-key=abc", "sync --idempotency-key=k1"])
def test_command_line_flags_with_ordinary_keys_are_kept(text):
    assert Redactor().redact_text(text) == text
