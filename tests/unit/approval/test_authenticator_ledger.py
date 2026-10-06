"""InMemoryApproverAuthenticator and the token use ledgers."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest
from pydantic import SecretStr

from tests.fixtures.factories import FIXED_NOW
from xdr_response.approval import InMemoryApproverAuthenticator, InMemoryTokenUseLedger, JsonlTokenUseLedger
from xdr_response.clock import FixedClock
from xdr_response.errors import AuthenticationError, ConfigError, TokenReplayError
from xdr_response.interfaces import ApproverAuthenticator, TokenUseLedger
from xdr_response.models import ApproverCredential, PrincipalKind

SECRET = "unit-test-credential-not-real"


@pytest.fixture
def auth() -> InMemoryApproverAuthenticator:
    a = InMemoryApproverAuthenticator(clock=FixedClock(FIXED_NOW), iterations=1_000)
    a.add_principal("analyst@example.com", display_name="Analyst", kind=PrincipalKind.HUMAN,
                    roles=["xdr-approver"], secret=SECRET)
    a.add_principal("bot@example.com", display_name="Bot", kind=PrincipalKind.AI,
                    roles=["xdr-approver"], secret=SECRET + "-bot")
    return a


def cred(pid="analyst@example.com", secret=SECRET, scheme="static") -> ApproverCredential:
    return ApproverCredential(principal_id=pid, scheme=scheme, secret=SecretStr(secret))


# ------------------------------------------------------------ authenticator --
def test_authenticator_implements_protocol(auth):
    assert isinstance(auth, ApproverAuthenticator)


def test_valid_credential_authenticates(auth):
    p = auth.authenticate(cred())
    assert (p.principal_id, p.display_name, p.kind) == ("analyst@example.com", "Analyst", PrincipalKind.HUMAN)
    assert p.roles == frozenset({"xdr-approver"}) and p.authenticator == "in_memory"
    assert p.authenticated_at == FIXED_NOW


def test_authenticator_reports_non_human_kind_faithfully(auth):
    assert auth.authenticate(cred("bot@example.com", SECRET + "-bot")).kind is PrincipalKind.AI


@pytest.mark.parametrize("credential", [
    cred(secret="wrong-secret"),
    cred(pid="unknown@example.com"),
    cred(scheme="oidc"),
    cred(secret=SECRET.upper()),
])
def test_bad_credentials_get_the_same_generic_error(auth, credential):
    with pytest.raises(AuthenticationError) as info:
        auth.authenticate(credential)
    assert str(info.value) == "approver authentication failed"


def test_non_credential_is_refused(auth):
    with pytest.raises(AuthenticationError):
        auth.authenticate({"principal_id": "analyst@example.com", "secret": SECRET})


def test_secret_is_never_stored_in_clear(auth):
    stored = auth._principals["analyst@example.com"]  # white-box: only salt and digest kept
    assert SECRET not in repr(stored) and SECRET.encode() not in stored.digest
    assert SECRET not in repr(auth)


def test_same_secret_gets_different_salts():
    a = InMemoryApproverAuthenticator(iterations=10)
    for pid in ("one@example.com", "two@example.com"):
        a.add_principal(pid, display_name=pid, kind=PrincipalKind.HUMAN, roles=[], secret=SECRET)
    assert a._principals["one@example.com"].digest != a._principals["two@example.com"].digest


@pytest.mark.parametrize("kwargs", [{"principal_id": " "}, {"secret": ""}])
def test_add_principal_validates(kwargs):
    a = InMemoryApproverAuthenticator(iterations=10)
    data = {"principal_id": "x@example.com", "secret": SECRET} | kwargs
    with pytest.raises(ValueError):
        a.add_principal(data["principal_id"], display_name="x", kind=PrincipalKind.HUMAN, roles=[],
                        secret=data["secret"])


def test_iterations_must_be_positive():
    with pytest.raises(ValueError):
        InMemoryApproverAuthenticator(iterations=0)


# ------------------------------------------------------------------ ledgers --
@pytest.fixture(params=["memory", "jsonl"])
def any_ledger(request, tmp_path):
    if request.param == "memory":
        return InMemoryTokenUseLedger()
    return JsonlTokenUseLedger(tmp_path / "ledger" / "uses.jsonl", clock=FixedClock(FIXED_NOW), fsync=False)


def test_ledger_implements_protocol(any_ledger):
    assert isinstance(any_ledger, TokenUseLedger)


def test_ledger_consumes_once_per_pair(any_ledger):
    assert not any_ledger.is_consumed("tok-1", "key-a")
    any_ledger.consume("tok-1", "key-a")
    assert any_ledger.is_consumed("tok-1", "key-a")
    any_ledger.consume("tok-1", "key-b")  # same token, another approved action
    any_ledger.consume("tok-2", "key-a")  # another token, same action
    with pytest.raises(TokenReplayError):
        any_ledger.consume("tok-1", "key-a")


@pytest.mark.parametrize("args", [("", "key"), ("tok", ""), (None, "key")])
def test_ledger_rejects_empty_ids(any_ledger, args):
    with pytest.raises(ValueError):
        any_ledger.consume(*args)


def test_jsonl_ledger_survives_restart(tmp_path):
    path = tmp_path / "uses.jsonl"
    clock = FixedClock(FIXED_NOW)
    JsonlTokenUseLedger(path, clock=clock, fsync=False).consume("tok-1", "key-a")
    clock.advance(timedelta(minutes=1))
    reopened = JsonlTokenUseLedger(path, clock=clock, fsync=False)
    assert reopened.is_consumed("tok-1", "key-a")
    with pytest.raises(TokenReplayError):
        reopened.consume("tok-1", "key-a")
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines == [{"consumed_at": "2026-01-15T12:00:00.000000Z", "idempotency_key": "key-a", "token_id": "tok-1"}]


def test_jsonl_ledger_sees_uses_by_another_instance(tmp_path):
    path = tmp_path / "uses.jsonl"
    first = JsonlTokenUseLedger(path, fsync=False)
    second = JsonlTokenUseLedger(path, fsync=False)
    first.consume("tok-1", "key-a")
    assert second.is_consumed("tok-1", "key-a")
    with pytest.raises(TokenReplayError):
        second.consume("tok-1", "key-a")


def test_jsonl_ledger_fsync_path(tmp_path):
    ledger = JsonlTokenUseLedger(tmp_path / "uses.jsonl")
    ledger.consume("tok-1", "key-a")
    assert ledger.path.exists()


@pytest.mark.parametrize("content", [
    b'{"token_id": "tok-1"}\n',
    b"not json\n",
    b'{"token_id": "tok-1", "idempotency_key": "key-a"}',  # truncated final line
])
def test_jsonl_ledger_refuses_corrupt_file(tmp_path, content):
    path = tmp_path / "uses.jsonl"
    path.write_bytes(content)
    with pytest.raises(ConfigError):
        JsonlTokenUseLedger(path, fsync=False)
