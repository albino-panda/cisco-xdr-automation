"""Adversarial approval-bypass tests (safety review, round 1, lens: approval-bypass).

Every test asserts the SAFE behaviour. A failing test is proof of a real way to reach a
state-changing vendor call (or to obtain authority) without a valid, matching, human approval.

Attack surface covered:

* direct calls of every ``@state_changing`` adapter method and of ``execute`` (all 16 adapters and
  the simulated families), with and without a registered verifier, with dry run on and off;
* undecorated internals (``__wrapped__`` and private write helpers) and the guarded HTTP client
  called directly, including a misdeclared operation kind;
* forged and self-built tokens and authorization contexts, wrong signing key, edited claims,
  tokens minted through the public ``sign`` API, a permissive verifier registered at runtime;
* AI / SERVICE / AUTOMATION approvers, automation approving its own package, self-approval;
* dry run (global and per run), expired tokens, single use / replay, approved action A used for
  action B, swapped target / params / integration, replay into another incident, release token
  for containment and vice versa, ELEVATED actions with standard approval;
* the approved target differing from the object the vendor call actually acts on.

No network: every adapter talks to an ``httpx.MockTransport`` that records requests. Fake data only.
"""
from __future__ import annotations

import contextvars
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest

from tests.fixtures.factories import FAKE_SHA256, FIXED_NOW, make_package, make_recommendation
from tests.fixtures.guard_helpers import make_token
from tests.fixtures.principals import (
    AI_ID,
    ANALYST_ID,
    AUTOMATION_ID,
    ELEVATED_ID,
    ELEVATED_ROLE,
    SERVICE_ID,
    STANDARD_ROLE,
    credential,
    make_authenticator,
    make_test_secrets,
)
from xdr_response import guard
from xdr_response.approval import ApprovalEngine, ApprovalTokenService, InMemoryTokenUseLedger
from xdr_response.clock import FixedClock
from xdr_response.config import ApprovalSettings, IntegrationConfig
from xdr_response.config.schema import Settings
from xdr_response.errors import (
    ApprovalError,
    ApprovalRequiredError,
    ApproverNotAllowedError,
    AuthenticationError,
    DecisionError,
    DryRunViolationError,
    IntegrationError,
    TokenExpiredError,
    TokenInvalidError,
    TokenMismatchError,
    TokenReplayError,
)
from xdr_response.execution.executor import ContainmentExecutor
from xdr_response.integrations.base import STATE_CHANGING_ACTION_NAMES, IntegrationAdapter
from xdr_response.integrations.http import GuardedHttpClient, RetryPolicy
from xdr_response.integrations.registry import ADAPTER_PATHS, load_adapter_class
from xdr_response.integrations.simulated import (
    SimulatedEmailAdapter,
    SimulatedEndpointAdapter,
    SimulatedIdentityAdapter,
    SimulatedNetworkAdapter,
)
from xdr_response.models import (
    ActionBinding,
    ActionRequest,
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    AuditEventType,
    ContainmentPackage,
    DecisionRequest,
    DecisionType,
    EvidenceDraft,
    OperationKind,
    PrincipalKind,
    RecommendedAction,
    ReleasePackage,
    Severity,
    TargetKind,
    TokenActionGrant,
    evidence_snapshot_hash,
    get_action_spec,
    number_evidence,
)
from xdr_response.restoration.engine import RestorationEngine

INCIDENT = "XDR-83921"
OTHER_INCIDENT = "XDR-99999"

#: Valid fake target per target kind (documentation ranges, example domains, fake hashes).
TARGETS: dict[TargetKind, str] = {
    TargetKind.ENDPOINT: "TH-LT-1047",
    TargetKind.USER: "j.doe@example.com",
    TargetKind.DOMAIN: "bad.example.test",
    TargetKind.URL: "https://bad.example.test/payload",
    TargetKind.IP: "203.0.113.10",
    TargetKind.HASH: FAKE_SHA256,
    TargetKind.EMAIL_MESSAGE: "msg-0001@example.test",
    TargetKind.EMAIL_ADDRESS: "j.doe@example.com",
    TargetKind.PROCESS: "TH-LT-1047/4242",
    TargetKind.FILE: f"TH-LT-1047/{FAKE_SHA256}",
    TargetKind.PERSISTENCE_ITEM: "TH-LT-1047/run-key-0001",
    TargetKind.ROLE_ASSIGNMENT: "j.doe@example.com/role-0001",
    TargetKind.NETWORK_CLIENT: "N_0001/k74272e",
    TargetKind.APPLICATION: "app-0001",
    TargetKind.CREDENTIAL: "cred-0001",
    TargetKind.INCIDENT: INCIDENT,
}

#: Params that make the write bodies of most adapters reach their vendor write call (fake values).
WRITE_PARAMS: dict[str, Any] = {
    "connector_guid": "00000000-0000-0000-0000-00000000c0de",
    "destination_list_id": "1001",
    "destination_id": "2002",
    "module_instance_id": "mi-0001",
    "action_id": "act-0001",
    "observable_type": "hostname",
    "machine_id": "machine-0001",
    "managed_device_id": "device-0001",
    "message_ids": ["msg-0001@example.test"],
    "verdict": "phishing",
    "recipient": "j.doe@example.com",
    "principal_id": "principal-0001",
    "role_definition_id": "role-0001",
    "directory_scope_id": "/",
    "network_id": "N_0001",
    "client_id": "k74272e",
    "indicator_id": "indicator-0001",
    "user_id": "user-0001",
    "group_policy_id": "101",
}

#: Fake values for every secret NAME any adapter may read (never real credentials).
FAKE_SECRETS: dict[str, str] = {
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

WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})


# =================================================================== helpers ==
class RecordingAudit:
    """Minimal AuditSink that keeps every append (no hash chain needed for these tests)."""

    def __init__(self) -> None:
        self.entries: list[tuple[AuditEventType, str | None, str, dict[str, Any]]] = []

    def append(self, event_type: AuditEventType, *, incident_id: str | None, actor: str,
               payload: Any, workflow_id: str | None = None, workflow_version: str | None = None) -> None:
        self.entries.append((event_type, incident_id, actor, dict(payload)))

    def records(self, incident_id: str | None = None):  # pragma: no cover - protocol completeness
        return iter(())

    def of(self, event_type: AuditEventType) -> list[dict[str, Any]]:
        return [p for e, _, _, p in self.entries if e is event_type]

    def state_changing_api_calls(self) -> list[dict[str, Any]]:
        return [p for p in self.of(AuditEventType.API_CALL) if p.get("kind") == OperationKind.STATE_CHANGING.value]


class Recorder:
    """httpx mock transport that records every request; default answer 200 with a generic body."""

    def __init__(self, responder: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.calls: list[httpx.Request] = []
        self._responder = responder

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self._responder is not None:
            return self._responder(request)
        return httpx.Response(200, json={"data": {"status": "success"}})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def writes(self) -> list[httpx.Request]:
        return [c for c in self.calls if c.method in WRITE_METHODS]


ALL_ADAPTERS: dict[str, type[IntegrationAdapter]] = {n: load_adapter_class(n) for n in ADAPTER_PATHS}
SIMULATED: dict[str, type[IntegrationAdapter]] = {
    f"simulated:{c.name}": c for c in (SimulatedEndpointAdapter, SimulatedIdentityAdapter,
                                       SimulatedEmailAdapter, SimulatedNetworkAdapter)
}


def make_vendor_adapter(name: str, recorder: Recorder, clock: FixedClock,
                        api_audit: RecordingAudit | None = None) -> IntegrationAdapter:
    """A real adapter with fake secrets and a real GuardedHttpClient over ``recorder`` (no auth, no retry)."""
    cls = ALL_ADAPTERS[name]
    base = cls.default_base_url or f"https://{name.replace('_', '-')}.example.test"
    adapter = cls(IntegrationConfig(enabled=True, base_url=base), make_test_secrets(**FAKE_SECRETS),
                  clock=clock, sleep=lambda _s: None)
    adapter.http = GuardedHttpClient(name, base, retry=RetryPolicy(max_retries=0, jitter=False),
                                     transport=recorder.transport(), clock=clock, sleep=lambda _s: None,
                                     audit=api_audit, default_headers=adapter.default_headers())
    return adapter


def recommendation(action_type: ActionType, integration: str, target: str | None = None, *,
                   incident_id: str = INCIDENT, approval_level: ApprovalLevel = ApprovalLevel.STANDARD,
                   **params: Any) -> RecommendedAction:
    kind = get_action_spec(action_type).target_kind
    return make_recommendation(action_type, target or TARGETS[kind], integration, incident_id=incident_id,
                               approval_level=approval_level, **params)


def request_for(action_type: ActionType, integration: str, target: str | None = None, *,
                incident_id: str = INCIDENT, **params: Any) -> ActionRequest:
    return ActionRequest.from_recommendation(
        recommendation(action_type, integration, target, incident_id=incident_id, **params))


def make_release_package(*actions: RecommendedAction, incident_id: str = INCIDENT) -> ReleasePackage:
    drafts = [EvidenceDraft(**e.model_dump(exclude={"number"})) for a in actions for e in a.evidence]
    evidence = number_evidence(drafts)
    return ReleasePackage(
        package_id=uuid.uuid4().hex, incident_id=incident_id, workflow_id="powershell",
        workflow_version="1.0.0", created_at=FIXED_NOW, expires_at=FIXED_NOW + timedelta(minutes=240),
        requested_by="automation:restoration_planner", severity=Severity.HIGH, risk_score=40,
        confidence_score=90, summary="Test release package", evidence=evidence,
        evidence_snapshot_hash=evidence_snapshot_hash(evidence), actions=tuple(actions),
        control_keys=tuple(a.params["restores"] for a in actions),
    )


# ================================================================== fixtures ==
@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(FIXED_NOW)


@pytest.fixture(scope="module")
def authenticator():
    return make_authenticator()


@pytest.fixture
def approval_settings() -> ApprovalSettings:
    return ApprovalSettings()


@pytest.fixture
def audit() -> RecordingAudit:
    return RecordingAudit()


@pytest.fixture
def tokens(approval_settings, clock) -> ApprovalTokenService:
    return ApprovalTokenService(make_test_secrets(), approval_settings, ledger=InMemoryTokenUseLedger(),
                                clock=clock)


@pytest.fixture
def engine(approval_settings, authenticator, tokens, audit, clock) -> ApprovalEngine:
    return ApprovalEngine(approval_settings, authenticator=authenticator, tokens=tokens, audit=audit, clock=clock)


@pytest.fixture
def live_guard(tokens, clock):
    """The production wiring of build_runtime: real token verifier registered, global dry run OFF."""
    guard.register_verifier(tokens)
    guard.configure(dry_run=False, clock=clock)
    return tokens


def approve(engine: ApprovalEngine, package, *principals: str, decision: DecisionType = DecisionType.APPROVE_ALL,
            keys: tuple[str, ...] = ()) -> ApprovalToken:
    """Real human approval through the engine; returns the signed token."""
    outcome = engine.decide(package, DecisionRequest(package_id=package.package_id, decision=decision,
                                                     approved_keys=keys),
                            [credential(p) for p in principals or (ANALYST_ID,)])
    assert outcome.token is not None
    return outcome.token


def approved(engine: ApprovalEngine, *actions: RecommendedAction,
             principals: tuple[str, ...] = (ANALYST_ID,)) -> tuple[ContainmentPackage, ApprovalToken]:
    package = make_package(*actions, incident_id=actions[0].incident_id)
    return package, approve(engine, package, *principals)


def assert_denied(call: Callable[[], Any], recorder: Recorder | None = None,
                  exc: type[BaseException] | tuple[type[BaseException], ...] = ApprovalRequiredError) -> None:
    with pytest.raises(exc):
        call()
    if recorder is not None:
        assert recorder.calls == [], f"vendor request(s) left the process: {[str(c.url) for c in recorder.calls]}"


# ============================================== 1. the four named brief tests ==
def _direct_attempts(clock: FixedClock, tokens: ApprovalTokenService, integration: str,
                     action_type: ActionType, **params: Any) -> None:
    """Call the adapter method and ``execute`` directly: pristine guard, then production wiring."""
    request = request_for(action_type, integration, **params)
    for wiring in ("pristine", "live"):
        guard.reset_for_tests()
        if wiring == "live":
            guard.register_verifier(tokens)
            guard.configure(dry_run=False, clock=clock)
        recorder = Recorder()
        adapter = make_vendor_adapter(integration, recorder, clock)
        method = getattr(adapter, action_type.value)
        assert_denied(lambda: method(request), recorder)
        assert_denied(lambda: adapter.execute(request), recorder)
        # a forged, unsigned token is never enough either
        if wiring == "live":
            def forged() -> None:
                with guard.authorized(make_token(request), request):
                    method(request)
            assert_denied(forged, recorder)


@pytest.mark.parametrize("integration,params", [
    ("secure_endpoint", {"connector_guid": WRITE_PARAMS["connector_guid"]}),
    ("defender_endpoint", {"machine_id": "machine-0001"}),
    ("cisco_xdr", {"module_instance_id": "mi-0001", "action_id": "isolate-host", "observable_type": "hostname"}),
])
def test_isolation_without_approval_fails(clock, tokens, integration, params):
    _direct_attempts(clock, tokens, integration, ActionType.ISOLATE_ENDPOINT, **params)


@pytest.mark.parametrize("integration,params", [
    ("entra", {}),
    ("cisco_xdr", {"module_instance_id": "mi-0001", "action_id": "disable-user", "observable_type": "user"}),
])
def test_disable_user_without_approval_fails(clock, tokens, integration, params):
    _direct_attempts(clock, tokens, integration, ActionType.DISABLE_USER, **params)


@pytest.mark.parametrize("integration,params", [
    ("secure_email", {"verdict": "phishing"}),
    ("defender_o365", {"recipient": "j.doe@example.com"}),
    ("cisco_xdr", {"module_instance_id": "mi-0001", "action_id": "quarantine", "observable_type": "email"}),
])
def test_email_quarantine_without_approval_fails(clock, tokens, integration, params):
    _direct_attempts(clock, tokens, integration, ActionType.QUARANTINE_EMAIL, **params)


@pytest.mark.parametrize("integration,params", [
    ("umbrella", {"destination_list_id": "1001"}),
    ("defender_endpoint", {}),
    ("cisco_xdr", {"module_instance_id": "mi-0001", "action_id": "block-domain", "observable_type": "domain"}),
])
def test_block_domain_without_approval_fails(clock, tokens, integration, params):
    _direct_attempts(clock, tokens, integration, ActionType.BLOCK_DOMAIN, **params)


# ============================ 2. every state-changing method of every adapter ==
def _method_cases(adapters: dict[str, type[IntegrationAdapter]]) -> list[tuple[str, str]]:
    cases = []
    for key, cls in adapters.items():
        for name in sorted(STATE_CHANGING_ACTION_NAMES | {"execute"}):
            if callable(getattr(cls, name, None)):
                cases.append((key, name))
    return cases


def _action_for(method: str, integration: str) -> ActionType:
    if method != "execute":
        return ActionType(method)
    for spec_type in ActionType:
        spec = get_action_spec(spec_type)
        if spec.state_changing and integration in spec.integrations:
            return spec_type
    return ActionType.ISOLATE_ENDPOINT


REAL_CASES = _method_cases(ALL_ADAPTERS)
SIM_CASES = _method_cases(SIMULATED)


def test_every_state_changing_action_type_is_covered_by_some_adapter_case():
    covered = {m for _, m in REAL_CASES + SIM_CASES}
    assert STATE_CHANGING_ACTION_NAMES <= covered, sorted(STATE_CHANGING_ACTION_NAMES - covered)


@pytest.mark.parametrize("integration,method", REAL_CASES, ids=[f"{a}.{m}" for a, m in REAL_CASES])
def test_every_vendor_write_method_refuses_direct_call(clock, live_guard, integration, method):
    """Guard comes first: no context -> ApprovalRequiredError (never UnverifiedEndpoint, never a request)."""
    recorder = Recorder()
    adapter = make_vendor_adapter(integration, recorder, clock)
    request = request_for(_action_for(method, integration), integration, **WRITE_PARAMS)
    assert_denied(lambda: getattr(adapter, method)(request), recorder)


@pytest.mark.parametrize("key,method", SIM_CASES, ids=[f"{a}.{m}" for a, m in SIM_CASES])
def test_every_simulated_write_method_refuses_direct_call(clock, live_guard, key, method):
    cls = SIMULATED[key]
    adapter = cls(clock=clock)
    request = request_for(_action_for(method, cls.name), cls.name)
    assert_denied(lambda: getattr(adapter, method)(request))
    assert adapter.environment.state_changing_calls() == []


@pytest.mark.parametrize("integration,method", REAL_CASES, ids=[f"{a}.{m}" for a, m in REAL_CASES])
def test_undecorated_body_cannot_send_a_vendor_write(clock, live_guard, integration, method):
    """``method.__wrapped__`` skips the decorator; the guarded HTTP client must still refuse the write."""
    recorder, api_audit = Recorder(), RecordingAudit()
    adapter = make_vendor_adapter(integration, recorder, clock, api_audit)
    request = request_for(_action_for(method, integration), integration, **WRITE_PARAMS)
    body = getattr(type(adapter), method).__wrapped__
    try:
        body(adapter, request)
    except Exception:  # noqa: BLE001 - any refusal is fine; what matters is what was sent
        pass
    assert api_audit.state_changing_api_calls() == []
    assert recorder.writes() == []


@pytest.mark.parametrize("integration,call", [
    ("umbrella", lambda a, r: a._block(r)),
    ("umbrella", lambda a, r: a._unblock(r)),
    ("entra", lambda a, r: a._set_enabled(r, False)),
    ("cisco_xdr", lambda a, r: a._trigger(r)),
    ("secure_email", lambda a, r: a._move(r, reversible=True)),
    ("defender_o365", lambda a, r: a._remediate(r, "moveToQuarantine", reversible=True)),
], ids=["umbrella._block", "umbrella._unblock", "entra._set_enabled", "cisco_xdr._trigger",
        "secure_email._move", "defender_o365._remediate"])
def test_private_write_helpers_cannot_send_a_vendor_write(clock, live_guard, integration, call):
    action = {"umbrella": ActionType.BLOCK_DOMAIN, "entra": ActionType.DISABLE_USER,
              "cisco_xdr": ActionType.ISOLATE_ENDPOINT, "secure_email": ActionType.QUARANTINE_EMAIL,
              "defender_o365": ActionType.QUARANTINE_EMAIL}[integration]
    recorder, api_audit = Recorder(), RecordingAudit()
    adapter = make_vendor_adapter(integration, recorder, clock, api_audit)
    request = request_for(action, integration, **WRITE_PARAMS)
    with pytest.raises(ApprovalRequiredError):
        call(adapter, request)
    assert api_audit.state_changing_api_calls() == [] and recorder.writes() == []


# ============================================ 3. the guarded HTTP client itself ==
def test_http_mutation_outside_guard_denied(clock, live_guard):
    recorder = Recorder()
    client = GuardedHttpClient("secure_endpoint", "https://se.example.test", transport=recorder.transport(),
                               retry=RetryPolicy(max_retries=0), clock=clock, sleep=lambda _s: None)
    for send in (lambda: client.put("v1/computers/x/isolation", operation="isolate"),
                 lambda: client.delete("v1/computers/x/isolation", operation="stop_isolation"),
                 lambda: client.post("v1/x", kind=OperationKind.STATE_CHANGING, operation="write")):
        assert_denied(send, recorder)
    with pytest.raises(ValueError):  # a PUT can never be declared a read
        client.put("v1/computers/x/isolation", operation="isolate", kind=OperationKind.READ)
    assert recorder.calls == []


def test_http_mutation_for_another_integration_denied_inside_context(clock, live_guard, engine):
    """An authorized secure_endpoint action does not open the umbrella client."""
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                               connector_guid="guid-1"))
    recorder = Recorder()
    umbrella = GuardedHttpClient("umbrella", "https://umbrella.example.test", transport=recorder.transport(),
                                 retry=RetryPolicy(max_retries=0), clock=clock, sleep=lambda _s: None)
    with guard.authorized(token, req):
        assert_denied(lambda: umbrella.post("policies/v2/destinationlists/1/destinations",
                                            kind=OperationKind.STATE_CHANGING, operation="add_destinations"),
                      recorder, TokenMismatchError)


def test_http_client_refuses_vendor_write_misdeclared_as_bookkeeping(clock, live_guard):
    """PUT .../isolation declared BOOKKEEPING (an allow-listed operation name) must not leave unguarded."""
    recorder = Recorder()
    client = GuardedHttpClient("secure_endpoint", "https://se.example.test", transport=recorder.transport(),
                               retry=RetryPolicy(max_retries=0), clock=clock, sleep=lambda _s: None)
    with pytest.raises((ApprovalRequiredError, ValueError)):
        client.put("v1/computers/00000000-0000-0000-0000-00000000c0de/isolation",
                   operation="update_incident_status", kind=OperationKind.BOOKKEEPING)
    assert recorder.writes() == []


def test_adapter_http_client_refuses_manifest_write_declared_read(clock, live_guard):
    """The adapter's own client: the manifest says revoke_sign_in_sessions is STATE_CHANGING."""
    recorder = Recorder()
    entra = make_vendor_adapter("entra", recorder, clock)
    with pytest.raises((ApprovalRequiredError, ValueError)):
        entra.http.post("v1.0/users/j.doe@example.com/revokeSignInSessions", kind=OperationKind.READ,
                        operation="revoke_sign_in_sessions")
    assert recorder.calls == []


# ============================================= 4. forged / self-built authority ==
def test_unsigned_self_built_token_rejected(clock, live_guard):
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)

    def attempt() -> None:
        with guard.authorized(make_token(req), req):
            adapter.isolate_endpoint(req)
    assert_denied(attempt, recorder, TokenInvalidError)


def test_wrong_key_rejected(clock, live_guard, approval_settings, authenticator, audit):
    """A correctly formed token from a different signing key (another deployment / attacker key)."""
    rogue_tokens = ApprovalTokenService(make_test_secrets(), approval_settings, ledger=InMemoryTokenUseLedger(),
                                        clock=clock)
    rogue_engine = ApprovalEngine(approval_settings, authenticator=authenticator, tokens=rogue_tokens,
                                  audit=audit, clock=clock)
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(rogue_engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)

    def attempt() -> None:
        with guard.authorized(token, req):
            adapter.isolate_endpoint(req)
    assert_denied(attempt, recorder, TokenInvalidError)


def test_forged_signature_and_edited_claims_rejected(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    other = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", "DC01", connector_guid="guid-dc")
    grant = TokenActionGrant(idempotency_key=other.idempotency_key, action_type=other.action_type,
                             target=other.target, params_hash=other.params_hash,
                             approval_level=ApprovalLevel.STANDARD)
    edited = token.model_copy(update={"claims": token.claims.model_copy(update={"actions": (grant,)})})
    flipped = token.model_copy(update={"signature": ("0" if token.signature[0] != "0" else "1") + token.signature[1:]})
    other_kid = token.model_copy(update={"key_id": "previous"})
    for bad, req in ((edited, other), (flipped, ActionRequest.from_recommendation(action)),
                     (other_kid, ActionRequest.from_recommendation(action))):
        with pytest.raises(TokenInvalidError):
            with guard.authorized(bad, req):
                pytest.fail("forged token entered an authorization context")


def test_decoded_token_with_tampered_body_rejected(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    body, kid, sig = token.encode().split(".")
    claims = token.claims.model_copy(update={"incident_id": OTHER_INCIDENT})
    forged = ApprovalToken(claims=claims, key_id=kid, signature=sig)
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", incident_id=OTHER_INCIDENT,
                      connector_guid="guid-1")
    with pytest.raises(TokenInvalidError):
        with guard.authorized(ApprovalToken.decode(forged.encode()), req):
            pytest.fail("tampered token accepted")


def test_forged_authorization_context_cannot_drive_an_adapter(clock, live_guard):
    """Injecting a self-built AuthorizationContext (private context var) still needs a valid token."""
    req = request_for(ActionType.DISABLE_USER, "entra")
    fake = guard.AuthorizationContext(
        token=make_token(req), request=req, binding=ActionBinding.from_request(req),
        purpose=ApprovalPurpose.CONTAINMENT,
        grant=make_token(req).claims.actions[0], entered_at=FIXED_NOW)
    recorder = Recorder()
    entra = make_vendor_adapter("entra", recorder, clock)
    reset = guard._ctx.set(fake)  # noqa: SLF001 - adversarial
    try:
        assert_denied(lambda: entra.disable_user(req), exc=TokenInvalidError)
    finally:
        guard._ctx.reset(reset)  # noqa: SLF001
    assert recorder.writes() == []


def test_no_verifier_registered_refuses_even_valid_token(clock, tokens, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    guard.configure(dry_run=False, clock=clock)  # dry run off but NO verifier registered
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(token, ActionRequest.from_recommendation(action)):
            pytest.fail("entered without a verifier")


def test_token_minted_with_public_sign_api_and_fabricated_human_is_refused(clock, live_guard, tokens):
    """No analyst decision, no authentication: claims fabricated in code and signed via tokens.sign()."""
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    claims = ApprovalTokenClaims(
        token_id="minted-without-decision", purpose=ApprovalPurpose.CONTAINMENT, package_id="never-approved",
        incident_id=req.incident_id, evidence_snapshot_hash="0" * 64, workflow_id="powershell",
        workflow_version="1.0.0", decision_id="never-recorded",
        actions=(TokenActionGrant(idempotency_key=req.idempotency_key, action_type=req.action_type,
                                  target=req.target, params_hash=req.params_hash,
                                  approval_level=ApprovalLevel.STANDARD),),
        approvers=(ApproverClaim(principal_id=ANALYST_ID, kind=PrincipalKind.HUMAN, roles=(STANDARD_ROLE,)),),
        issued_at=FIXED_NOW, expires_at=FIXED_NOW + timedelta(minutes=30),
    )
    minted = tokens.sign(claims)
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)

    def attempt() -> None:
        with guard.authorized(minted, req):
            adapter.isolate_endpoint(req)
    assert_denied(attempt, recorder)


@pytest.mark.parametrize("kind", [PrincipalKind.AI, PrincipalKind.SERVICE, PrincipalKind.AUTOMATION])
def test_signed_token_naming_non_human_approver_rejected(clock, live_guard, tokens, kind):
    req = request_for(ActionType.DISABLE_USER, "entra")
    claims = make_token(req, approver_kind=kind).claims.model_copy(update={"package_id": "p"})
    with pytest.raises(TokenInvalidError):
        with guard.authorized(tokens.sign(claims), req):
            pytest.fail("non-human approver accepted")


def test_permissive_verifier_cannot_replace_the_registered_one(clock, live_guard):
    """Once build_runtime registered the token service, a permissive verifier must not be swappable in."""

    class Permissive:
        def verify(self, token, *, purpose, binding):
            return token.claims.actions[0]

        def mark_used(self, token, idempotency_key):
            return None

    with pytest.raises(Exception):
        guard.register_verifier(Permissive())
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(make_token(req), req):
            pass


# ======================================================== 5. who may approve ==
@pytest.mark.parametrize("principal", [AI_ID, SERVICE_ID, AUTOMATION_ID])
def test_ai_principal_cannot_approve(engine, audit, principal):
    """Non-human principals hold every role in the fixtures; roles must not matter."""
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"))
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                      [credential(principal)])
    assert audit.of(AuditEventType.TOKEN_ISSUED) == []
    assert audit.of(AuditEventType.APPROVAL_DENIED), "denial must be audited"


@pytest.mark.parametrize("principal", [AI_ID, SERVICE_ID, AUTOMATION_ID])
def test_non_human_cannot_ride_along_with_a_human(engine, principal):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"))
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                      [credential(ELEVATED_ID), credential(principal)])


def test_automation_cannot_approve_its_own_recommendation(engine):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"),
                           requested_by=f"automation:{AUTOMATION_ID}")
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                      [credential(AUTOMATION_ID)])


def test_human_requester_cannot_self_approve(engine):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"),
                           requested_by=ELEVATED_ID)
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                      [credential(ELEVATED_ID)])


def test_unauthenticated_or_missing_credentials_cannot_approve(engine):
    from pydantic import SecretStr

    from xdr_response.models import ApproverCredential

    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"))
    request = DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL)
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, request, [])
    with pytest.raises(AuthenticationError):
        engine.decide(package, request, [ApproverCredential(principal_id=ANALYST_ID, scheme="static",
                                                            secret=SecretStr("wrong-password-not-real"))])


@pytest.mark.parametrize("decision", [DecisionType.REJECT, DecisionType.REQUEST_MORE_INVESTIGATION])
def test_reject_and_more_investigation_never_issue_a_token(engine, decision):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"))
    outcome = engine.decide(package, DecisionRequest(package_id=package.package_id, decision=decision,
                                                     comment="analyst comment"), [credential(ANALYST_ID)])
    assert outcome.token is None


def test_approve_selected_cannot_smuggle_a_key_outside_the_package(engine):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"))
    foreign = f"{INCIDENT}:isolate_endpoint:DC01"
    with pytest.raises(DecisionError):
        engine.decide(package, DecisionRequest(package_id=package.package_id,
                                               decision=DecisionType.APPROVE_SELECTED,
                                               approved_keys=(package.keys[0], foreign)),
                      [credential(ANALYST_ID)])


# ================================================================ 6. dry run ==
def test_dry_run_default_refuses_valid_token(clock, tokens, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    guard.register_verifier(tokens)  # verifier present, global dry run still at its default (True)
    with pytest.raises(DryRunViolationError):
        with guard.authorized(token, ActionRequest.from_recommendation(action)):
            pytest.fail("entered while dry run is the default")


def test_per_run_dry_run_refuses_and_cannot_be_switched_off(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    with guard.dry_run():
        guard.configure(dry_run=False)  # an attempt to switch it off from inside the run
        assert guard.is_dry_run()
        with pytest.raises(DryRunViolationError):
            with guard.authorized(token, req):
                pytest.fail("entered during a dry run")


def test_dry_run_enabled_inside_context_blocks_adapter_and_http(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        with guard.dry_run():
            assert_denied(lambda: adapter.isolate_endpoint(req), recorder, DryRunViolationError)
            assert_denied(lambda: adapter.http.put("v1/computers/guid-1/isolation", operation="isolate"),
                          recorder, DryRunViolationError)


def test_executor_in_dry_run_never_reaches_an_adapter(clock, live_guard, engine, audit):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    package, token = approved(engine, action)

    class ExplodingRunner:
        def run(self, *a, **k):  # pragma: no cover - must never be called
            raise AssertionError("runner reached in dry run")

    executor = ContainmentExecutor(ExplodingRunner(), live_guard, Settings(), audit=audit, clock=clock)
    report = executor.execute(package, token, dry_run=True)
    assert report.dry_run and report.overall is None
    assert all(r.status.value == "DRY_RUN" for r in report.results)


# ============================================== 7. expiry, single use, binding ==
def test_expired_token_rejected(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    clock.advance(timedelta(minutes=31))
    with pytest.raises(TokenExpiredError):
        with guard.authorized(token, ActionRequest.from_recommendation(action)):
            pytest.fail("expired token accepted")


def test_token_expiring_during_context_stops_further_writes(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        clock.advance(timedelta(minutes=31))
        assert_denied(lambda: adapter.isolate_endpoint(req), recorder, TokenExpiredError)


def test_token_replay_for_the_same_action_rejected(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    with guard.authorized(token, req):
        pass
    with pytest.raises(TokenReplayError):
        with guard.authorized(token, req):
            pytest.fail("replayed token accepted")


def test_nested_authorization_refused(clock, live_guard, engine):
    a = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    b = recommendation(ActionType.BLOCK_DOMAIN, "umbrella", destination_list_id="1001")
    _, token = approved(engine, a, b)
    with guard.authorized(token, ActionRequest.from_recommendation(a)):
        with pytest.raises(ApprovalRequiredError):
            with guard.authorized(token, ActionRequest.from_recommendation(b)):
                pytest.fail("nested authorization accepted")


def _binding_attacks() -> list[tuple[str, ActionRequest]]:
    return [
        ("action A used for action B",
         request_for(ActionType.BLOCK_DOMAIN, "umbrella", destination_list_id="1001")),
        ("swapped target", request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", "DC01",
                                       connector_guid="guid-1")),
        ("swapped params", request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                       connector_guid="guid-of-a-domain-controller")),
        ("swapped integration", request_for(ActionType.ISOLATE_ENDPOINT, "defender_endpoint",
                                            connector_guid="guid-1")),
        ("extra param", request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1",
                                    comment="harmless looking")),
        ("replay into another incident", request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                     incident_id=OTHER_INCIDENT, connector_guid="guid-1")),
        ("release instead of isolate", request_for(ActionType.RELEASE_ENDPOINT, "secure_endpoint",
                                                   connector_guid="guid-1")),
    ]


@pytest.mark.parametrize("label,attack", _binding_attacks(), ids=[label for label, _ in _binding_attacks()])
def test_token_binding(clock, live_guard, engine, label, attack):
    """Token approved for isolate TH-LT-1047 (secure_endpoint, guid-1) in XDR-83921 only."""
    _, token = approved(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                               connector_guid="guid-1"))
    with pytest.raises(TokenMismatchError):
        with guard.authorized(token, attack):
            pytest.fail(f"{label}: accepted")


def test_params_tampering_rejected_inside_context(clock, live_guard, engine):
    """Context entered for the approved request; a call with tampered params is refused by the decorator."""
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    tampered = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-of-dc")
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        assert_denied(lambda: adapter.isolate_endpoint(tampered), recorder, TokenMismatchError)


def test_context_for_one_integration_does_not_authorize_another_adapter(clock, live_guard, engine):
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    mde = make_vendor_adapter("defender_endpoint", recorder, clock)
    with guard.authorized(token, req):
        assert_denied(lambda: mde.isolate_endpoint(req), recorder, TokenMismatchError)


@pytest.mark.parametrize("integration,approved_type,other_method,params", [
    ("secure_endpoint", ActionType.ISOLATE_ENDPOINT, "release_endpoint", {"connector_guid": "guid-1"}),
    ("entra", ActionType.DISABLE_USER, "enable_user", {}),
    ("umbrella", ActionType.BLOCK_DOMAIN, "unblock_domain", {"destination_list_id": "1001",
                                                             "destination_id": "2002"}),
    ("secure_email", ActionType.QUARANTINE_EMAIL, "release_email", {"verdict": "phishing"}),
])
def test_approved_request_cannot_drive_a_different_write_method(clock, live_guard, engine, integration,
                                                                approved_type, other_method, params):
    """Approval for containment A, then the (opposite) method B is called with A's own request."""
    action = recommendation(approved_type, integration, **params)
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder, api_audit = Recorder(), RecordingAudit()
    adapter = make_vendor_adapter(integration, recorder, clock, api_audit)
    with guard.authorized(token, req):
        try:
            getattr(adapter, other_method)(req)
        except Exception:  # noqa: BLE001 - a refusal is the safe outcome
            pass
    sent = api_audit.state_changing_api_calls()
    assert sent == [], f"{integration}.{other_method} ran under an approval for {approved_type.value}: " \
                       f"{[c['operation'] for c in sent]}"


def test_authorization_does_not_outlive_its_context(clock, live_guard, engine):
    """A context copied inside the guarded block (thread pool, asyncio task) must not keep the authority."""
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        leaked = contextvars.copy_context()
    assert guard.current() is None
    with pytest.raises(ApprovalRequiredError):
        leaked.run(adapter.isolate_endpoint, req)
    with pytest.raises(ApprovalRequiredError):
        leaked.run(adapter.isolate_endpoint, req)  # and certainly not repeatedly (single use)
    assert recorder.writes() == []


# ==================================================== 8. release vs containment ==
def _release_action(**params: Any) -> RecommendedAction:
    return recommendation(ActionType.RELEASE_ENDPOINT, "secure_endpoint",
                          restores=f"{INCIDENT}:isolate_endpoint:TH-LT-1047", connector_guid="guid-1", **params)


def test_release_token_cannot_authorize_containment(clock, live_guard, engine):
    release_pkg = make_release_package(_release_action())
    release_token = approve(engine, release_pkg)
    assert release_token.claims.purpose is ApprovalPurpose.RELEASE
    isolate = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    with pytest.raises(TokenMismatchError):
        with guard.authorized(release_token, isolate):
            pytest.fail("release token authorized containment")


def test_containment_token_cannot_authorize_release(clock, live_guard, engine):
    _, token = approved(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                               connector_guid="guid-1"))
    release = ActionRequest.from_recommendation(_release_action())
    with pytest.raises(TokenMismatchError):
        with guard.authorized(token, release):
            pytest.fail("containment token authorized a release")


def test_signed_token_cannot_relabel_purpose(clock, live_guard, tokens):
    """Even a validly signed token whose purpose says 'release' cannot run a containment action."""
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    claims = make_token(req).claims.model_copy(update={"purpose": ApprovalPurpose.RELEASE})
    with pytest.raises(TokenMismatchError):
        with guard.authorized(tokens.sign(claims), req):
            pytest.fail("purpose relabel accepted")


def test_executors_refuse_tokens_of_the_other_purpose(clock, live_guard, engine, audit):
    containment_pkg, containment_token = approved(
        engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1"))
    release_pkg = make_release_package(_release_action())
    release_token = approve(engine, release_pkg)

    class ExplodingRunner:
        def run(self, *a, **k):  # pragma: no cover - must never be called
            raise AssertionError("runner reached with a wrong-purpose token")

    executor = ContainmentExecutor(ExplodingRunner(), live_guard, Settings(), audit=audit, clock=clock)
    with pytest.raises(ApprovalRequiredError):
        executor.execute(containment_pkg, release_token)
    with pytest.raises(ApprovalRequiredError):
        executor.execute(containment_pkg, None)
    restoration = RestorationEngine(ExplodingRunner(), object(), live_guard, Settings(), audit=audit, clock=clock)
    with pytest.raises(ApprovalRequiredError):
        restoration.execute(release_pkg, containment_token)
    with pytest.raises(ApprovalRequiredError):
        restoration.execute(release_pkg, None)


# ============================================================ 9. ELEVATED ==
def _elevated_action() -> RecommendedAction:
    return recommendation(ActionType.DISABLE_USER, "entra", "adm-j.doe@example.com",
                          approval_level=ApprovalLevel.ELEVATED)


def test_elevated_action_requires_elevated_role(engine):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"),
                           _elevated_action())
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                      [credential(ANALYST_ID)])
    elevated_key = package.actions[1].idempotency_key
    with pytest.raises(ApproverNotAllowedError):
        engine.decide(package, DecisionRequest(package_id=package.package_id,
                                               decision=DecisionType.APPROVE_SELECTED,
                                               approved_keys=(elevated_key,)), [credential(ANALYST_ID)])


def test_standard_subset_token_cannot_run_the_elevated_action(clock, live_guard, engine):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"),
                           _elevated_action())
    token = approve(engine, package, ANALYST_ID, decision=DecisionType.APPROVE_SELECTED,
                    keys=(package.actions[0].idempotency_key,))
    with pytest.raises(TokenMismatchError):
        with guard.authorized(token, ActionRequest.from_recommendation(package.actions[1])):
            pytest.fail("elevated action ran on a standard-only approval")


def test_elevated_quorum_of_two_is_enforced(clock, authenticator, audit):
    settings = ApprovalSettings(elevated_min_approvers=2)
    svc = ApprovalTokenService(make_test_secrets(), settings, ledger=InMemoryTokenUseLedger(), clock=clock)
    eng = ApprovalEngine(settings, authenticator=authenticator, tokens=svc, audit=audit, clock=clock)
    package = make_package(_elevated_action())
    with pytest.raises(ApproverNotAllowedError):
        eng.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                   [credential(ELEVATED_ID), credential(ELEVATED_ID)])  # same human twice
    with pytest.raises(ApproverNotAllowedError):
        eng.decide(package, DecisionRequest(package_id=package.package_id, decision=DecisionType.APPROVE_ALL),
                   [credential(ELEVATED_ID), credential(ANALYST_ID)])  # second one lacks the elevated role


def test_signed_elevated_grant_with_standard_only_approver_rejected(clock, live_guard, tokens):
    req = request_for(ActionType.DISABLE_USER, "entra", "adm-j.doe@example.com")
    claims = make_token(req).claims
    claims = claims.model_copy(update={
        "actions": (claims.actions[0].model_copy(update={"approval_level": ApprovalLevel.ELEVATED}),),
        "approvers": (ApproverClaim(principal_id=ANALYST_ID, kind=PrincipalKind.HUMAN, roles=(STANDARD_ROLE,)),),
    })
    with pytest.raises(TokenInvalidError):
        with guard.authorized(tokens.sign(claims), req):
            pytest.fail("elevated grant accepted with a standard-only approver")


def test_always_elevated_action_cannot_be_approved_with_standard_role(clock, live_guard, engine):
    """remove_privileged_role is ELEVATED by catalog. A package copy that says STANDARD must not lower the bar."""
    action = recommendation(ActionType.REMOVE_PRIVILEGED_ROLE, "entra", principal_id="principal-0001")
    assert action.approval_level is ApprovalLevel.ELEVATED
    downgraded = action.model_copy(update={"approval_level": ApprovalLevel.STANDARD})
    try:
        package = make_package(downgraded)  # the package model re-validates its actions
        outcome = engine.decide(package, DecisionRequest(package_id=package.package_id,
                                                         decision=DecisionType.APPROVE_ALL),
                                [credential(ANALYST_ID)])  # ANALYST_ID has no elevated role
    except (ApprovalError, ValueError):
        return  # safe: refused at decision time
    assert outcome.token is not None
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(outcome.token, ActionRequest.from_recommendation(downgraded)):
            pytest.fail("always-elevated action authorized by a standard-only approver")


def test_elevated_role_cannot_be_configured_equal_to_standard_role():
    """Config weakening: if both roles are the same string, ELEVATED approval collapses into STANDARD."""
    with pytest.raises(ValueError):
        ApprovalSettings(elevated_role=STANDARD_ROLE, standard_role=STANDARD_ROLE)


@pytest.mark.parametrize("field", ["standard_min_approvers", "elevated_min_approvers"])
def test_zero_quorum_config_rejected(field):
    with pytest.raises(ValueError):
        ApprovalSettings(**{field: 0})


# ============================== 10. approved target vs object actually acted on ==
def test_cisco_xdr_native_action_acts_only_on_the_approved_target(clock, live_guard, engine):
    """Approved: block_domain bad.example.test. The params must not redirect the trigger to another object.

    ``observable_value`` / ``observable_type`` come from proposal params (untrusted workflow data);
    critical-asset evaluation and the decision card only see ``target``.
    """
    action = recommendation(ActionType.BLOCK_DOMAIN, "cisco_xdr", "bad.example.test",
                            module_instance_id="mi-0001", action_id="isolate-host",
                            observable_type="hostname", observable_value="DC01")
    assert action.approval_level is ApprovalLevel.STANDARD
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    adapter = make_vendor_adapter("cisco_xdr", recorder, clock)
    with guard.authorized(token, req):
        try:
            adapter.execute(req)
        except (IntegrationError, ValueError):
            pass  # refusing the mismatched observable is the safe outcome
    triggers = [c for c in recorder.calls if "/respond/trigger/" in c.url.path]
    acted_on = [(c.url.params.get("observable_type"), c.url.params.get("observable_value")) for c in triggers]
    assert all(value == req.target and kind == "domain" for kind, value in acted_on), \
        f"approved block_domain {req.target} but the native action ran on {acted_on}"


def test_secure_email_moves_only_the_approved_message(clock, live_guard, engine):
    """Approved: quarantine msg-0001. params.message_ids must not substitute or add other messages."""
    action = recommendation(ActionType.QUARANTINE_EMAIL, "secure_email", "msg-0001@example.test",
                            verdict="phishing",
                            message_ids=["msg-0002@example.test", "msg-0003@example.test"])
    _, token = approved(engine, action)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder(lambda r: httpx.Response(200, json={"data": [{"queueSuccess": True}]}))
    adapter = make_vendor_adapter("secure_email", recorder, clock)
    with guard.authorized(token, req):
        try:
            adapter.execute(req)
        except (IntegrationError, ValueError):
            pass
    import json as _json

    moved = [i for c in recorder.calls if c.url.path.endswith("/messages/move")
             for i in _json.loads(c.content).get("ids", [])]
    assert set(moved) <= {req.target}, f"approved quarantine of {req.target} but moved {moved}"


def test_rejected_action_is_skipped_and_never_authorized(clock, live_guard, engine):
    package = make_package(recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="g"),
                           recommendation(ActionType.BLOCK_DOMAIN, "umbrella", destination_list_id="1001"))
    token = approve(engine, package, ANALYST_ID, decision=DecisionType.APPROVE_SELECTED,
                    keys=(package.actions[0].idempotency_key,))
    rejected = ActionRequest.from_recommendation(package.actions[1])
    with pytest.raises(TokenMismatchError):
        with guard.authorized(token, rejected):
            pytest.fail("analyst-rejected action authorized")


def test_role_holders_are_checked_against_elevated_role_constant():
    """Sanity: the fixture principals used above hold the roles this file assumes."""
    from tests.fixtures.principals import PRINCIPALS

    assert ELEVATED_ROLE not in PRINCIPALS[ANALYST_ID][2]
    assert ELEVATED_ROLE in PRINCIPALS[ELEVATED_ID][2]


# ############################################################################################
# Safety review ROUND 2 (lens: approval-bypass).
#
# New attack angles not covered by round 1:
#   R2.1  the guard's verifier slot can be emptied and refilled, or refilled with a same-class
#         verifier holding another key / an empty ledger, through public guard APIs;
#   R2.2  ApprovalTokenService.issue() mints a fully valid token from a fabricated decision and a
#         fabricated "HUMAN" principal (no authenticator, no audit);
#   R2.3  the guarded HTTP client trusts the caller-declared operation NAME: a vendor write URL
#         sent as POST under a manifest READ / VERIFY / BOOKKEEPING operation skips the guard;
#   R2.4  inside an authorization context, undecorated bodies / raw client writes are not bound to
#         the approved target or params and are not limited to one write;
#   R2.5  adapter params (connector GUID, machine ID, device ID, user object ID, client ID) redirect
#         the approved write to another object than the approved, critical-asset-evaluated target;
#   R2.6  ELEVATED is only advisory package metadata: a proposal-supplied asset suppresses the
#         critical-asset match, and a hand-proposed package marking a domain controller STANDARD
#         is approved by a standard analyst and executed;
#   R2.7  the executor ignores runtime.dry_run from settings (DRY_RUN=true) once any code flips the
#         process-wide guard flag.
# ############################################################################################
from xdr_response.models import AnalystDecision, Asset, AuthenticatedPrincipal, ProposedAction  # noqa: E402


def _approved_request(engine: ApprovalEngine, action: RecommendedAction) -> tuple[ApprovalToken, ActionRequest]:
    _, token = approved(engine, action)
    return token, ActionRequest.from_recommendation(action)


def _sent_writes(recorder: Recorder) -> list[httpx.Request]:
    """Every non-GET request that left the process."""
    return [c for c in recorder.calls if c.method not in ("GET", "HEAD")]


# ============================================ R2.1 verifier slot replacement ==
class _PermissiveVerifier:
    """Approves anything whose grant matches the binding (what a rogue component would install)."""

    def verify(self, token, *, purpose, binding):
        return token.claims.grant(binding.idempotency_key)

    def mark_used(self, token, idempotency_key):
        return None


def test_r2_verifier_cannot_be_unregistered_then_replaced_by_a_permissive_one(clock, live_guard):
    """guard.unregister_verifier() is public; afterwards register_verifier() accepts ANY verifier."""
    try:
        guard.unregister_verifier()
        guard.register_verifier(_PermissiveVerifier())
    except Exception:  # noqa: BLE001 - refusing the swap is the safe outcome
        pass
    req = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)

    def attempt() -> None:
        with guard.authorized(make_token(req), req):  # unsigned, never approved by anyone
            adapter.isolate_endpoint(req)
    assert_denied(attempt, recorder)


def test_r2_reset_for_tests_in_production_module_cannot_open_the_verifier_slot(clock, live_guard):
    """guard.reset_for_tests() is a public production function; it must not enable a verifier swap."""
    try:
        guard.reset_for_tests()
        guard.register_verifier(_PermissiveVerifier())
        guard.configure(dry_run=False, clock=clock)
    except Exception:  # noqa: BLE001
        pass
    req = request_for(ActionType.DISABLE_USER, "entra")
    recorder = Recorder()
    entra = make_vendor_adapter("entra", recorder, clock)

    def attempt() -> None:
        with guard.authorized(make_token(req), req):
            entra.disable_user(req)
    assert_denied(attempt, recorder)


def test_r2_same_class_verifier_with_attacker_key_cannot_replace_the_registered_one(
        clock, live_guard, approval_settings, authenticator, audit):
    """register_verifier only checks type(); a second ApprovalTokenService with another key is accepted."""
    rogue_tokens = ApprovalTokenService(make_test_secrets(), approval_settings,
                                        ledger=InMemoryTokenUseLedger(), clock=clock)
    rogue_engine = ApprovalEngine(approval_settings, authenticator=authenticator, tokens=rogue_tokens,
                                  audit=audit, clock=clock)
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    token, req = _approved_request(rogue_engine, action)  # signed with a key the deployment never had
    try:
        guard.register_verifier(rogue_tokens)
    except Exception:  # noqa: BLE001
        pass
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)

    def attempt() -> None:
        with guard.authorized(token, req):
            adapter.isolate_endpoint(req)
    assert_denied(attempt, recorder)


def test_r2_same_class_verifier_with_fresh_ledger_cannot_reenable_a_used_token(
        clock, approval_settings, authenticator, audit):
    """Re-registering an identically keyed service with an empty ledger must not re-allow a consumed token."""
    secrets = make_test_secrets()
    first = ApprovalTokenService(secrets, approval_settings, ledger=InMemoryTokenUseLedger(), clock=clock)
    guard.register_verifier(first)
    guard.configure(dry_run=False, clock=clock)
    eng = ApprovalEngine(approval_settings, authenticator=authenticator, tokens=first, audit=audit, clock=clock)
    token, req = _approved_request(
        eng, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1"))
    with guard.authorized(token, req):
        pass  # the single use is consumed
    try:
        guard.register_verifier(ApprovalTokenService(secrets, approval_settings,
                                                     ledger=InMemoryTokenUseLedger(), clock=clock))
    except Exception:  # noqa: BLE001
        pass
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(token, req):
            pytest.fail("consumed approval replayed after the verifier was re-registered with an empty ledger")


# ============================================= R2.2 issue() without a decision ==
def test_r2_issue_with_fabricated_decision_and_principal_cannot_authorize(clock, live_guard, tokens, audit):
    """Automation calls tokens.issue() directly: no ApprovalEngine, no authenticator, no audit record.

    The runtime hands the same ApprovalTokenService object to the executor and restoration engine,
    so any automation component holding it can mint containment authority this way.
    """
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    package = make_package(action)
    principal = AuthenticatedPrincipal(
        principal_id=ANALYST_ID, display_name="fabricated by automation", kind=PrincipalKind.HUMAN,
        roles=frozenset({STANDARD_ROLE, ELEVATED_ROLE}), authenticator="none", authenticated_at=FIXED_NOW)
    decision = AnalystDecision(
        decision_id="fabricated-decision", package_id=package.package_id, incident_id=package.incident_id,
        purpose=package.purpose, decision=DecisionType.APPROVE_ALL, analyst_identity=ANALYST_ID,
        approvers=(principal,), decided_at=FIXED_NOW, approved_action_keys=package.keys,
        rejected_action_keys=(), comment="", workflow_id=package.workflow_id,
        workflow_version=package.workflow_version, evidence_snapshot_hash=package.evidence_snapshot_hash)
    req = ActionRequest.from_recommendation(action)
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)

    def attempt() -> None:
        minted = tokens.issue(package, decision, [principal])
        with guard.authorized(minted, req):
            adapter.isolate_endpoint(req)
    assert_denied(attempt, recorder, (ApprovalError, ApprovalRequiredError))
    assert audit.of(AuditEventType.DECISION_RECORDED) == []


# ===================================== R2.3 HTTP guard trusts the operation name ==
_MISLABELLED_WRITES = [
    # (integration, url, borrowed operation, declared kind, body) - every url is a VERIFIED vendor write
    ("cisco_xdr", "/iroh/iroh-response/respond/trigger/mi-0001/isolate-host", "observe_observables",
     OperationKind.READ, None),
    ("cisco_xdr", "/iroh/iroh-response/respond/trigger/mi-0001/isolate-host", "update_incident_status",
     OperationKind.BOOKKEEPING, None),
    ("secure_email", "/v1/messages/move", "search_messages", OperationKind.READ,
     {"ids": ["msg-0009@example.test"], "action": "quarantine"}),
    ("secure_email", "/v1/messages/move", "message_status", OperationKind.VERIFY,
     {"ids": ["msg-0009@example.test"], "action": "quarantine"}),
    ("umbrella", "/policies/v2/destinationlists/1001/destinations", "token", OperationKind.READ,
     [{"destination": "victim.example.test"}]),
    ("entra", "v1.0/users/ceo@example.com/revokeSignInSessions", "token", OperationKind.READ, None),
    ("entra", "v1.0/identityProtection/riskyUsers/confirmCompromised", "token", OperationKind.READ,
     {"userIds": ["00000000-0000-0000-0000-0000000000ce"]}),
    ("defender_endpoint", "/api/machines/machine-dc02/isolate", "token", OperationKind.READ,
     {"Comment": "x", "IsolationType": "Full"}),
    ("defender_endpoint", "/api/indicators", "token", OperationKind.READ,
     {"indicatorValue": "victim.example.test", "indicatorType": "DomainName", "action": "Block"}),
    ("defender_o365", "https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate",
     "token", OperationKind.READ, {"action": "softDelete"}),
    ("intune", "v1.0/deviceManagement/managedDevices/device-exec-0001/remoteLock", "token",
     OperationKind.READ, None),
    ("microsoft_cloud", "v1.0/users/ceo@example.com/revokeSignInSessions", "run_hunting_query",
     OperationKind.READ, None),
]


@pytest.mark.parametrize("integration,url,operation,kind,body", _MISLABELLED_WRITES,
                         ids=[f"{i}:{op}:{k.value}" for i, _, op, k, _ in _MISLABELLED_WRITES])
def test_r2_adapter_client_refuses_vendor_write_sent_under_a_read_operation_name(
        clock, live_guard, integration, url, operation, kind, body):
    """The manifest check compares operation name, method and kind, never the URL against the
    manifest path, so a write URL borrowed under a POST READ/VERIFY/BOOKKEEPING operation name
    (``token`` exists in every Graph / Umbrella / XDR manifest) is sent without any approval."""
    recorder = Recorder()
    adapter = make_vendor_adapter(integration, recorder, clock)
    assert adapter.http.manifest is not None  # the adapter's own, manifest-checked client
    with pytest.raises((ApprovalRequiredError, ValueError)):
        adapter.http.post(url, kind=kind, operation=operation, json=body)
    assert recorder.calls == [], f"unapproved vendor write left the process: {[str(c.url) for c in recorder.calls]}"


def test_r2_raw_client_with_the_adapters_auth_cannot_send_a_write_as_read(clock, live_guard):
    """A client built without a manifest (reusing the adapter's base URL and auth) accepts a POST write as READ."""
    recorder = Recorder()
    entra = make_vendor_adapter("entra", recorder, clock)
    raw = GuardedHttpClient("entra", entra.http.base_url, transport=recorder.transport(),
                            retry=RetryPolicy(max_retries=0), clock=clock, sleep=lambda _s: None,
                            auth=entra.http.auth)
    with pytest.raises((ApprovalRequiredError, ValueError)):
        raw.post("v1.0/users/ceo@example.com/revokeSignInSessions", kind=OperationKind.READ,
                 operation="lookup")
    assert recorder.calls == []


# ============================== R2.4 writes inside a context are not bound ==
def test_r2_undecorated_body_inside_context_cannot_act_on_swapped_params(clock, live_guard, engine):
    """Approved: isolate TH-LT-1047 (guid-1). Inside the approved context, ``__wrapped__`` with a
    request whose connector GUID is a domain controller's must not reach the vendor."""
    token, req = _approved_request(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                          connector_guid="guid-1"))
    tampered = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-dc02")
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        try:
            type(adapter).isolate_endpoint.__wrapped__(adapter, tampered)
        except Exception:  # noqa: BLE001 - a refusal is the safe outcome
            pass
    hit = [str(c.url) for c in recorder.writes() if "guid-dc02" in c.url.path]
    assert hit == [], f"approval for guid-1 isolated another computer: {hit}"


def test_r2_raw_client_write_inside_context_is_bound_to_the_approved_target(clock, live_guard, engine):
    """Before the guarded call runs, the adapter's client accepts ANY write for the integration."""
    token, req = _approved_request(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                          connector_guid="guid-1"))
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        for guid in ("guid-dc01", "guid-dc02", "guid-esx01"):
            try:
                adapter.http.put(f"v1/computers/{guid}/isolation", operation="isolate")
            except Exception:  # noqa: BLE001
                pass
    assert recorder.writes() == [], \
        f"one approval (isolate guid-1) sent {len(recorder.writes())} unrelated writes: " \
        f"{[c.url.path for c in recorder.writes()]}"


def test_r2_one_authorization_allows_at_most_one_vendor_write(clock, live_guard, engine):
    """One approval authorizes one write: repeated raw writes before the guarded call must be refused."""
    token, req = _approved_request(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                          connector_guid="guid-1"))
    recorder = Recorder()
    adapter = make_vendor_adapter("secure_endpoint", recorder, clock)
    with guard.authorized(token, req):
        for _ in range(3):
            try:
                adapter.http.put("v1/computers/guid-1/isolation", operation="isolate")
            except Exception:  # noqa: BLE001
                pass
        try:
            adapter.isolate_endpoint(req)
        except Exception:  # noqa: BLE001
            pass
    assert len(recorder.writes()) <= 1, f"{len(recorder.writes())} writes under one single-use approval"


# ============================== R2.5 params redirect the write to another object ==
def _identity_responder(request: httpx.Request) -> httpx.Response:
    """Every lookup says the referenced object is a critical asset that is NOT the approved target."""
    if request.method == "GET":
        return httpx.Response(200, json={
            "data": {"hostname": "TH-DC-02", "connector_guid": "guid-dc02", "active": True},
            "id": "obj-0001", "computerDnsName": "th-dc-02.corp.example.test", "deviceName": "TH-DC-02",
            "userPrincipalName": "breakglass@example.com", "mail": "breakglass@example.com",
            "accountEnabled": True, "devicePolicy": "Normal", "description": "TH-DC-02",
        })
    return httpx.Response(200, json={"data": {"status": "success"}, "id": "action-0001", "status": "Pending"})


_REDIRECTS = [
    # (integration, action type, params that point at another object, the redirected identifier)
    ("secure_endpoint", ActionType.ISOLATE_ENDPOINT, {"connector_guid": "guid-dc02"}, "guid-dc02"),
    ("defender_endpoint", ActionType.ISOLATE_ENDPOINT, {"machine_id": "machine-dc02"}, "machine-dc02"),
    ("intune", ActionType.LOCK_DEVICE, {"managed_device_id": "device-exec-0001"}, "device-exec-0001"),
    ("entra", ActionType.CONFIRM_USER_COMPROMISED, {"user_id": "00000000-0000-0000-0000-0000000000ce"},
     "00000000-0000-0000-0000-0000000000ce"),
    ("meraki", ActionType.BLOCK_NETWORK_CLIENT, {"network_id": "N_0001", "client_id": "kdc0002"}, "kdc0002"),
]


@pytest.mark.parametrize("integration,action_type,params,redirected", _REDIRECTS,
                         ids=[f"{i}.{a.value}" for i, a, _, _ in _REDIRECTS])
def test_r2_params_cannot_redirect_the_write_away_from_the_approved_target(
        clock, live_guard, engine, integration, action_type, params, redirected):
    """The analyst and the critical-asset policy only see ``target`` (a STANDARD workstation / user);
    the adapter writes to the object named in params (a domain controller, an executive device, a
    break-glass account). The same class of flaw round 1 closed for cisco_xdr and secure_email."""
    action = recommendation(action_type, integration, **params)
    assert action.approval_level is ApprovalLevel.STANDARD
    token, req = _approved_request(engine, action)
    recorder = Recorder(_identity_responder)
    adapter = make_vendor_adapter(integration, recorder, clock)
    with guard.authorized(token, req):
        try:
            adapter.execute(req)
        except Exception:  # noqa: BLE001 - refusing the mismatched object is the safe outcome
            pass
    hits = [f"{c.method} {c.url}" for c in _sent_writes(recorder)
            if redirected in str(c.url) or redirected in c.content.decode("utf-8", "replace")]
    assert hits == [], f"approved {action_type.value} {req.target} but the vendor write acted on {redirected}: {hits}"


# ============================== R2.6 ELEVATED is advisory package metadata ==
def _builder():
    from tools.simulator.scenario import CONFIG_DIR
    from xdr_response.approval import CriticalAssetPolicy, PackageBuilder
    from xdr_response.config import AllowlistPolicy, load_settings

    settings = load_settings(CONFIG_DIR, env={})
    return PackageBuilder(settings, critical_assets=CriticalAssetPolicy(settings.critical_assets),
                          allowlists=AllowlistPolicy(settings.allowlists), clock=FixedClock(FIXED_NOW))


def test_r2_proposal_supplied_asset_cannot_suppress_critical_asset_elevation():
    """The incident (re-read from XDR) tags TH-SRV-0042 as a domain controller. A proposal (workflow
    data, untrusted per threat model 11.1) carrying its own, tag-less Asset replaces the incident's
    asset context, so the critical-asset policy never sees the tag and the action is STANDARD."""
    from tests.fixtures.factories import make_incident

    dc = Asset(name="TH-SRV-0042", kind=TargetKind.ENDPOINT, groups=("Domain Controllers",),
               tags=("domain-controller",))
    incident = make_incident(assets=(dc,))
    evidence = (EvidenceDraft(source="secure_endpoint", summary="encryptor executed on TH-SRV-0042",
                              observed_at=FIXED_NOW - timedelta(minutes=5), reference="evt-0042"),)

    def proposal(asset: Asset | None) -> ProposedAction:
        return ProposedAction(action_type=ActionType.ISOLATE_ENDPOINT, target="TH-SRV-0042",
                              target_kind=TargetKind.ENDPOINT,
                              params={"integration": "secure_endpoint", "connector_guid": "guid-srv-0042"},
                              evidence=evidence, risk_score=90, confidence_score=90, rationale="test",
                              asset=asset)

    builder = _builder()
    baseline = builder.build(incident, [proposal(None)], risk_score=90, confidence_score=90, summary="s")
    assert baseline.actions[0].approval_level is ApprovalLevel.ELEVATED  # sanity: the tag is critical
    spoofed = builder.build(incident, [proposal(Asset(name="TH-SRV-0042", kind=TargetKind.ENDPOINT))],
                            risk_score=90, confidence_score=90, summary="s")
    assert spoofed.actions[0].approval_level is ApprovalLevel.ELEVATED, \
        "a proposal-supplied asset removed the domain-controller ELEVATED requirement"


def test_r2_hand_proposed_standard_package_cannot_isolate_a_domain_controller_with_standard_approval():
    """ResponseOrchestrator.propose() and ApprovalEngine.decide() accept a package whose action on a
    critical asset (TH-DC-09 matches ``*-DC-*``) is marked STANDARD without warnings; a standard
    analyst approves it and it executes. ELEVATED must be enforced at decision time, not only by
    PackageBuilder."""
    from tools.simulator.scenario import ScenarioRun, load_scenario

    run = ScenarioRun(load_scenario("ransomware"), live=True)
    detected = run.detect().package
    isolate = next(a for a in detected.actions if a.action_type is ActionType.ISOLATE_ENDPOINT)
    dc_action = RecommendedAction(
        incident_id=run.incident_id, idempotency_key=f"{run.incident_id}:isolate_endpoint:TH-DC-09",
        action_type=ActionType.ISOLATE_ENDPOINT, target="TH-DC-09", target_kind=TargetKind.ENDPOINT,
        params=dict(isolate.params), evidence=isolate.evidence, risk_score=90, confidence_score=90,
        approval_level=ApprovalLevel.STANDARD, rationale="hand-built")
    package = make_package(dc_action, incident_id=run.incident_id, workflow_id=detected.workflow_id,
                           workflow_version=detected.workflow_version, created_at=run.clock.now(),
                           expires_at=run.clock.now() + timedelta(minutes=60))
    try:
        run.orchestrator.propose(run.incident_id, package)
        run.decide({"decision": "APPROVE_ALL"}, approvers=["analyst"])  # analyst: standard role only
    except (ApprovalError, ValueError):
        pass  # refused: the safe outcome
    assert not run.environment.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-DC-09"), \
        "a domain controller was isolated on a STANDARD-only approval"


# ============================================ R2.7 settings DRY_RUN honoured ==
def test_r2_executor_honours_settings_dry_run_even_if_guard_flag_was_flipped(clock, live_guard, engine, audit):
    """Settings say DRY_RUN=true (the default). Any code calling guard.configure(dry_run=False) (for
    example a second runtime built in the same process) turns the executor live."""
    settings = Settings()
    assert settings.runtime.dry_run is True
    package, token = approved(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                     connector_guid="guid-1"))

    class RecordingRunner:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, *a, **k):
            self.calls += 1
            raise RuntimeError("live runner reached")

    runner = RecordingRunner()
    executor = ContainmentExecutor(runner, live_guard, settings, audit=audit, clock=clock)
    report = executor.execute(package, token)
    assert runner.calls == 0 and report.dry_run, "DRY_RUN=true in settings, yet the executor ran live"


# ======================================= R2.8 further attempts (round 2) ==
def test_r2_context_copied_during_the_guarded_call_cannot_write_after_it_returned(clock, live_guard, engine):
    """``_call_depth`` lives in the context var, not in the shared context state: a context copied while
    the guarded call runs keeps depth 1 after the call returned, so raw writes stay possible until the
    ``with`` block ends (arbitrary target, any number)."""
    from xdr_response.integrations.secure_endpoint.adapter import SecureEndpointAdapter

    leaked: list[contextvars.Context] = []

    class CapturingAdapter(SecureEndpointAdapter):
        @guard.state_changing
        def isolate_endpoint(self, request: ActionRequest) -> Any:  # noqa: D401 - test double
            leaked.append(contextvars.copy_context())  # e.g. a worker thread / task started here
            return None

    token, req = _approved_request(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                          connector_guid="guid-1"))
    recorder = Recorder()
    adapter = CapturingAdapter(IntegrationConfig(enabled=True, base_url="https://se.example.test"),
                               make_test_secrets(**FAKE_SECRETS), clock=clock, sleep=lambda _s: None)
    adapter.http = GuardedHttpClient("secure_endpoint", "https://se.example.test",
                                     retry=RetryPolicy(max_retries=0), transport=recorder.transport(),
                                     clock=clock, sleep=lambda _s: None)
    with guard.authorized(token, req):
        adapter.isolate_endpoint(req)  # the single guarded call, completed
        try:
            leaked[0].run(adapter.http.put, "v1/computers/guid-dc02/isolation", operation="isolate")
        except Exception:  # noqa: BLE001 - refusal is the safe outcome
            pass
    assert recorder.writes() == [], "a context copied during the guarded call wrote after the call returned"


def test_r2_token_issued_for_a_dry_run_package_cannot_authorize_live(clock, live_guard, engine):
    """Expected SAFE: a simulation approval never authorizes a live write."""
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    package = make_package(action, dry_run=True)
    token = approve(engine, package)
    assert token.claims.dry_run is True
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(token, ActionRequest.from_recommendation(action)):
            pytest.fail("dry-run approval authorized a live action")


def test_r2_executor_refuses_token_of_another_package_with_identical_actions(clock, live_guard, engine, audit):
    """Expected SAFE: approval of package A cannot run package B even when the action keys match."""
    action = recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid="guid-1")
    _, token_a = approved(engine, action)
    package_b = make_package(action)

    class ExplodingRunner:
        def run(self, *a, **k):  # pragma: no cover - must never be called
            raise AssertionError("runner reached with another package's token")

    executor = ContainmentExecutor(ExplodingRunner(), live_guard, Settings(), audit=audit, clock=clock)
    with pytest.raises(ApprovalRequiredError):
        executor.execute(package_b, token_a)


def test_r2_concurrent_use_of_one_approval_consumes_it_once(clock, live_guard, engine):
    """Expected SAFE: two threads racing guard.authorized() with the same token and action."""
    import threading

    token, req = _approved_request(engine, recommendation(ActionType.ISOLATE_ENDPOINT, "secure_endpoint",
                                                          connector_guid="guid-1"))
    barrier = threading.Barrier(8)
    entered: list[int] = []

    def worker(i: int) -> None:
        barrier.wait()
        try:
            with guard.authorized(token, req):
                entered.append(i)
        except ApprovalRequiredError:
            pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(entered) == 1, f"{len(entered)} threads entered with one single-use approval"


def test_r2_configure_rejects_truthy_strings():
    """Expected SAFE: configure(dry_run='false') must not silently switch dry run off."""
    with pytest.raises(TypeError):
        guard.configure(dry_run="false")  # type: ignore[arg-type]
    assert guard.is_dry_run()
