"""Secrets never reach the audit file: redaction happens before hashing and writing."""
from __future__ import annotations

import pytest
from pydantic import SecretStr

from tests.fixtures.factories import make_recommendation
from tests.fixtures.guard_helpers import make_token
from xdr_response.audit import AuditRecorder, AuditTrail, verify_chain
from xdr_response.logs.redaction import REDACTED, Redactor
from xdr_response.models import ActionRequest, AuditEventType
from xdr_response.secrets.provider import StaticSecretProvider

# Fake values only; built at runtime so no literal secret-looking string sits in the repo.
CLIENT_SECRET = "fake-client-secret-" + "q7" * 8
API_KEY = "fakeapikey" + "0123456789abcdef" * 2
SIGNATURE = "f00d" * 16


@pytest.fixture
def trail(make_trail) -> AuditTrail:
    return make_trail()


def _disk(trail: AuditTrail) -> bytes:
    return trail.path.read_bytes()


def test_registered_secret_values_never_on_disk(trail, redactor, audit_path):
    redactor.register_secret(CLIENT_SECRET)
    trail.append(AuditEventType.API_CALL, incident_id="XDR-83921", actor="automation:test", payload={
        "note": f"auth failed with {CLIENT_SECRET} for TH-LT-1047",
        "nested": [{"deep": {"text": CLIENT_SECRET}}],
        "tuple": ("x", CLIENT_SECRET),
    })
    raw = _disk(trail)
    assert CLIENT_SECRET.encode() not in raw
    assert REDACTED.encode() in raw
    assert verify_chain(audit_path).ok


def test_secret_provider_values_are_scrubbed(trail, redactor):
    provider = StaticSecretProvider({"XDR_CLIENT_SECRET": CLIENT_SECRET}, redactor=redactor)
    value = provider.get("XDR_CLIENT_SECRET")
    trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={
        "secret_value_object": value,
        "message": f"token request with {value.reveal()} rejected",
    })
    assert CLIENT_SECRET.encode() not in _disk(trail)


@pytest.mark.parametrize("key", ["password", "client_secret", "api_key", "X-Cisco-Meraki-API-Key",
                                 "Authorization", "access_token", "refreshToken", "unlock_code",
                                 "approval_token", "signature", "hec_token", "private_key", "cookie"])
def test_values_under_sensitive_keys_never_on_disk(trail, key):
    record = trail.append(AuditEventType.API_CALL, incident_id="XDR-83921", actor="automation:test",
                          payload={"headers": {key: API_KEY}, key: {"nested": API_KEY}})
    assert API_KEY.encode() not in _disk(trail)
    assert record.payload[key] == REDACTED
    assert record.payload["headers"][key] == REDACTED


@pytest.mark.parametrize("text", [
    "Authorization: Bearer " + API_KEY,
    "Basic " + API_KEY,
    "client_secret=" + API_KEY,
    "token: " + API_KEY,
])
def test_credentials_in_free_text_never_on_disk(trail, text):
    trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test",
                 payload={"message": text})
    assert API_KEY.encode() not in _disk(trail)


def test_pydantic_secret_fields_never_on_disk(trail):
    trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test",
                 payload={"credential_material": SecretStr(API_KEY)})
    assert API_KEY.encode() not in _disk(trail)


def test_secrets_in_keys_actor_and_ids_are_scrubbed(trail, redactor):
    redactor.register_secret(CLIENT_SECRET)
    trail.append(AuditEventType.ERROR, incident_id=f"XDR-{CLIENT_SECRET}",
                 actor=f"svc {CLIENT_SECRET}", workflow_id=CLIENT_SECRET,
                 payload={CLIENT_SECRET: "value-under-secret-key"})
    assert CLIENT_SECRET.encode() not in _disk(trail)


def test_approval_token_signature_and_encoding_never_on_disk(trail):
    token = make_token(make_recommendation()).model_copy(update={"signature": SIGNATURE})
    encoded = token.encode()
    trail.append(AuditEventType.ERROR, incident_id="XDR-83921", actor="automation:test", payload={
        "token_object": token,
        "approval_token": encoded,
        "message": f"rejected token {encoded}",
    })
    raw = _disk(trail)
    assert SIGNATURE.encode() not in raw
    assert encoded.encode() not in raw


def test_recorder_token_issued_stores_only_id_and_claims_hash(trail):
    token = make_token(make_recommendation()).model_copy(update={"signature": SIGNATURE})
    record = AuditRecorder(trail).token_issued(token)
    assert set(record.payload) == {"token_id", "purpose", "package_id", "decision_id",
                                   "claims_hash", "issued_at", "expires_at", "action_keys"}
    assert record.payload["token_id"] == token.claims.token_id
    assert SIGNATURE.encode() not in _disk(trail)


def test_idempotency_keys_and_hashes_stay_readable(trail):
    action = make_recommendation()
    record = trail.append(AuditEventType.ACTION_STARTED, incident_id="XDR-83921",
                          actor="automation:test", payload={
                              "idempotency_key": action.idempotency_key, "token_id": "tok-1",
                              "params_hash": "b" * 64, "claims_hash": "c" * 64})
    assert record.payload["idempotency_key"] == action.idempotency_key
    assert record.payload["token_id"] == "tok-1"
    assert record.payload["params_hash"] == "b" * 64


def test_unlock_code_in_action_params_never_on_disk(trail):
    request = ActionRequest.from_recommendation(make_recommendation())
    params = dict(request.params, unlock_code="UNLOCK-" + API_KEY)
    trail.append(AuditEventType.ACTION_RESULT, incident_id="XDR-83921", actor="automation:test",
                 payload={"params": params})
    assert API_KEY.encode() not in _disk(trail)


def test_default_redactor_is_the_process_wide_one(audit_path, clock, monkeypatch):
    from xdr_response.logs import redaction

    shared = Redactor()
    monkeypatch.setattr(redaction, "_DEFAULT", shared)
    shared.register_secret(CLIENT_SECRET)
    trail = AuditTrail(audit_path, clock=clock, fsync=False)
    trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test",
                 payload={"message": CLIENT_SECRET})
    assert CLIENT_SECRET.encode() not in audit_path.read_bytes()


def test_redacted_record_hash_covers_redacted_payload(trail, redactor):
    redactor.register_secret(CLIENT_SECRET)
    record = trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test",
                          payload={"message": CLIENT_SECRET})
    assert record.payload == {"message": REDACTED}
    assert verify_chain(trail.path).ok
