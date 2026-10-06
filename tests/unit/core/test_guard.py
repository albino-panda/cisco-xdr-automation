"""Execution guard: deterministic, fail-closed enforcement of approval before any state change."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import make_recommendation
from tests.fixtures.guard_helpers import FakeVerifier, install_fake_verifier, make_token
from xdr_response import guard
from xdr_response.errors import (
    ApprovalRequiredError,
    DryRunViolationError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMismatchError,
    TokenReplayError,
)
from xdr_response.models import ActionRequest, ActionType, ApprovalPurpose, PrincipalKind


def _req(action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047", integration="secure_endpoint", **params):
    return ActionRequest.from_recommendation(make_recommendation(action_type, target, integration, **params))


class FakeAdapter:
    name = "secure_endpoint"

    def __init__(self) -> None:
        self.calls: list[str] = []

    @guard.state_changing
    def isolate_endpoint(self, request: ActionRequest) -> str:
        self.calls.append(request.target)
        return "isolated"

    @guard.state_changing
    def enrich_anything(self, request: ActionRequest) -> str:  # misuse: read action decorated
        return "never"


# ------------------------------------------------------------------ defaults --
def test_dry_run_is_on_by_default_and_no_verifier():
    assert guard.is_dry_run() is True
    assert guard.get_verifier() is None
    assert guard.current() is None


def test_denied_without_verifier():
    guard.configure(dry_run=False)
    req = _req()
    with pytest.raises(ApprovalRequiredError, match="no approval verifier"):
        with guard.authorized(make_token(req), req):
            pass


def test_denied_in_global_dry_run_even_with_valid_token():
    v = install_fake_verifier(dry_run=True)
    req = _req()
    with pytest.raises(DryRunViolationError):
        with guard.authorized(make_token(req), req):
            pass
    assert v.verify_calls == 0 and v.mark_used_calls == 0


def test_denied_in_per_run_dry_run_and_cannot_be_switched_off():
    install_fake_verifier()
    req = _req()
    assert guard.is_dry_run() is False
    with guard.dry_run():
        assert guard.is_dry_run() is True
        guard.configure(dry_run=False)  # global flag off does not cancel the per-run flag
        assert guard.is_dry_run() is True
        with pytest.raises(DryRunViolationError):
            with guard.authorized(make_token(req), req):
                pass
    assert guard.is_dry_run() is False


def test_configure_requires_bool():
    with pytest.raises(TypeError):
        guard.configure(dry_run="false")  # type: ignore[arg-type]
    assert guard.is_dry_run() is True


def test_register_verifier_type_checked():
    with pytest.raises(TypeError):
        guard.register_verifier(object())  # type: ignore[arg-type]


# ------------------------------------------------------------- happy path --
def test_authorized_sets_and_resets_context_and_consumes_use():
    v = install_fake_verifier()
    adapter = FakeAdapter()
    req = _req()
    token = make_token(req)
    with guard.authorized(token, req) as ctx:
        assert guard.current() is ctx
        assert ctx.purpose is ApprovalPurpose.CONTAINMENT and ctx.grant.idempotency_key == req.idempotency_key
        assert adapter.isolate_endpoint(req) == "isolated"
    assert guard.current() is None
    assert adapter.calls == ["TH-LT-1047"]
    assert v.mark_used_calls == 1 and v.verify_calls >= 2  # enter + re-verify at call time
    with pytest.raises(TokenReplayError):  # single use per action key
        with guard.authorized(token, req):
            pass


def test_context_reset_after_exception():
    install_fake_verifier()
    req = _req()
    with pytest.raises(RuntimeError):
        with guard.authorized(make_token(req), req):
            raise RuntimeError("adapter failed")
    assert guard.current() is None


def test_nested_authorization_refused():
    install_fake_verifier()
    a, b = _req(), _req(ActionType.BLOCK_DOMAIN, "bad.example.test", "umbrella")
    with guard.authorized(make_token(a, b), a):
        with pytest.raises(ApprovalRequiredError, match="nested"):
            with guard.authorized(make_token(a, b), b):
                pass


# -------------------------------------------------------------- mismatches --
def test_token_for_other_action_refused():
    install_fake_verifier()
    approved = _req()
    other = _req(target="TH-LT-2000")
    with pytest.raises(TokenMismatchError):
        with guard.authorized(make_token(approved), other):
            pass


def test_changed_params_refused():
    install_fake_verifier()
    approved = _req(reason="approved reason")
    tampered = _req(reason="different reason")
    with pytest.raises(TokenMismatchError):
        with guard.authorized(make_token(approved), tampered):
            pass


def test_containment_token_cannot_authorize_release():
    install_fake_verifier()
    release = _req(ActionType.RELEASE_ENDPOINT, restores="XDR-83921:isolate_endpoint:TH-LT-1047")
    token = make_token(release, purpose=ApprovalPurpose.CONTAINMENT)
    with pytest.raises(TokenMismatchError):
        with guard.authorized(token, release):
            pass


def test_expired_token_refused():
    v = install_fake_verifier()
    req = _req()
    token = make_token(req)
    v.clock.advance(timedelta(minutes=31))
    with pytest.raises(TokenExpiredError):
        with guard.authorized(token, req):
            pass


def test_expiry_rechecked_at_call_time():
    v = install_fake_verifier()
    adapter = FakeAdapter()
    req = _req()
    with guard.authorized(make_token(req), req):
        v.clock.advance(timedelta(hours=1))
        with pytest.raises(TokenExpiredError):
            adapter.isolate_endpoint(req)
    assert adapter.calls == []


def test_non_human_approver_refused():
    install_fake_verifier()
    req = _req()
    for kind in (PrincipalKind.AI, PrincipalKind.SERVICE, PrincipalKind.AUTOMATION):
        with pytest.raises(TokenInvalidError):
            with guard.authorized(make_token(req, approver_kind=kind), req):
                pass


def test_missing_token_refused():
    install_fake_verifier()
    req = _req()
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(None, req):  # type: ignore[arg-type]
            pass


def test_verifier_bug_fails_closed():
    class BrokenVerifier(FakeVerifier):
        def verify(self, token, *, purpose, binding):
            raise KeyError("bug")

    guard.register_verifier(BrokenVerifier())
    guard.configure(dry_run=False)
    req = _req()
    with pytest.raises(TokenInvalidError):
        with guard.authorized(make_token(req), req):
            pass


def test_lying_verifier_is_double_checked():
    class LyingVerifier(FakeVerifier):
        def verify(self, token, *, purpose, binding):
            return token.claims.actions[0]  # grant for a different action

    guard.register_verifier(LyingVerifier())
    guard.configure(dry_run=False)
    approved, other = _req(), _req(target="TH-LT-9999")
    with pytest.raises(TokenMismatchError):
        with guard.authorized(make_token(approved), other):
            pass


def test_read_action_cannot_be_authorized():
    install_fake_verifier()
    req = ActionRequest(incident_id="XDR-1", idempotency_key="XDR-1:enrich_ip:192.0.2.1",
                        action_type=ActionType.ENRICH_IP, target="192.0.2.1", target_kind="IP",
                        params={"integration": "virustotal"})
    with pytest.raises(ValueError):
        with guard.authorized(make_token(_req()), req):
            pass


# --------------------------------------------------------------- decorator --
def test_decorated_method_refuses_direct_call():
    install_fake_verifier()
    adapter = FakeAdapter()
    with pytest.raises(ApprovalRequiredError):
        adapter.isolate_endpoint(_req())
    assert adapter.calls == []


def test_decorated_method_refuses_in_dry_run_even_inside_context():
    install_fake_verifier()
    adapter = FakeAdapter()
    req = _req()
    with guard.authorized(make_token(req), req):
        with guard.dry_run():
            with pytest.raises(DryRunViolationError):
                adapter.isolate_endpoint(req)
    assert adapter.calls == []


def test_decorated_method_refuses_other_action_inside_context():
    install_fake_verifier()
    adapter = FakeAdapter()
    approved, other = _req(), _req(target="TH-LT-2000")
    with guard.authorized(make_token(approved, other), approved):
        with pytest.raises(TokenMismatchError):
            adapter.isolate_endpoint(other)
    assert adapter.calls == []


def test_decorated_method_refuses_other_integration():
    install_fake_verifier()
    adapter = FakeAdapter()  # name == secure_endpoint
    req = _req(integration="defender_endpoint")
    with guard.authorized(make_token(req), req):
        with pytest.raises(TokenMismatchError, match="integration"):
            adapter.isolate_endpoint(req)


def test_decorator_type_and_catalog_checks():
    adapter = FakeAdapter()
    with pytest.raises(TypeError):
        adapter.isolate_endpoint("TH-LT-1047")  # type: ignore[arg-type]
    read = ActionRequest(incident_id="XDR-1", idempotency_key="XDR-1:enrich_ip:192.0.2.1",
                         action_type=ActionType.ENRICH_IP, target="192.0.2.1", target_kind="IP",
                         params={"integration": "secure_endpoint"})
    with pytest.raises(ValueError):
        adapter.enrich_anything(read)
    assert guard.is_state_changing_method(FakeAdapter.isolate_endpoint)
    assert guard.is_state_changing_method(adapter.isolate_endpoint)
    assert FakeAdapter.isolate_endpoint.__name__ == "isolate_endpoint"
    assert not guard.is_state_changing_method(FakeAdapter.__init__)


def test_require_active_authorization_for_http_client():
    install_fake_verifier()
    with pytest.raises(ApprovalRequiredError):
        guard.require_active_authorization("secure_endpoint")
    req = _req()
    seen: list[object] = []

    class WritingAdapter(FakeAdapter):
        @guard.state_changing
        def isolate_endpoint(self, request: ActionRequest) -> str:
            seen.append(guard.require_active_authorization("secure_endpoint").request)
            with pytest.raises(TokenMismatchError):
                guard.require_active_authorization("umbrella")
            return "isolated"

    with guard.authorized(make_token(req), req):
        # inside the context but outside the guarded call: no write may be sent
        with pytest.raises(ApprovalRequiredError):
            guard.require_active_authorization("secure_endpoint")
        WritingAdapter().isolate_endpoint(req)
        # after the guarded call returned: refused again
        with pytest.raises(ApprovalRequiredError):
            guard.require_active_authorization("secure_endpoint")
    assert seen == [req]
    guard.configure(dry_run=True)
    with pytest.raises(DryRunViolationError):
        guard.require_active_authorization("secure_endpoint")


def test_verifier_unregistered_mid_context_denies():
    install_fake_verifier()
    adapter = FakeAdapter()
    req = _req()
    with guard.authorized(make_token(req), req):
        guard.unregister_verifier()
        with pytest.raises(ApprovalRequiredError):
            adapter.isolate_endpoint(req)


# ------------------------------------------------------------ denial hook --
def test_denial_hook_receives_every_denial_and_cannot_allow():
    seen: list[tuple[str, object, type]] = []

    def hook(reason, request, exc):
        seen.append((reason, request, type(exc)))
        raise RuntimeError("audit sink down")  # must not turn the denial into an allow

    guard.set_denial_hook(hook)
    adapter = FakeAdapter()
    req = _req()
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(make_token(req), req):
            pass
    with pytest.raises(DryRunViolationError):
        adapter.isolate_endpoint(req)
    assert [s[2] for s in seen] == [ApprovalRequiredError, DryRunViolationError]
    assert seen[0][1] == req and seen[0][0] == "no verifier registered"


def test_reset_for_tests_restores_fail_closed_defaults():
    install_fake_verifier()
    guard.set_denial_hook(lambda *a: None)
    guard.reset_for_tests()
    assert guard.get_verifier() is None and guard.is_dry_run() is True and guard.current() is None
