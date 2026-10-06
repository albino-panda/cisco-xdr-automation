"""Simulated adapter family: guard enforcement, every action type, verify, rollback, fault injection."""
from __future__ import annotations

import pytest

from tests.fixtures.factories import FAKE_SHA256, make_recommendation
from tests.fixtures.guard_helpers import install_fake_verifier, make_token
from tests.unit.integrations._support import FakeAudit, fixed_clock
from xdr_response import guard
from xdr_response.config import IntegrationConfig
from xdr_response.errors import (
    ApiError,
    ApprovalRequiredError,
    AuditError,
    AuthFailedError,
    CapabilityNotSupportedError,
    DryRunViolationError,
    IntegrationError,
    IntegrationTimeoutError,
    IntegrationUnavailableError,
    InvalidTargetError,
    RateLimitedError,
    TokenMismatchError,
)
from xdr_response.guard import is_state_changing_method
from xdr_response.integrations import STATE_CHANGING_ACTION_NAMES
from xdr_response.integrations.simulated import (
    ACTION_EFFECTS,
    FAMILIES,
    SIMULATED_SUITE,
    FaultKind,
    SimulatedAdapter,
    SimulatedEmailAdapter,
    SimulatedEndpointAdapter,
    SimulatedEnvironment,
    SimulatedIdentityAdapter,
    SimulatedIntelAdapter,
    SimulatedNetworkAdapter,
    build_simulated_adapters,
    simulated_adapter_class,
)
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    ApprovalPurpose,
    AuditEventType,
    HealthStatus,
    InvestigationQuery,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    Verdict,
    VerificationStatus,
    get_action_spec,
)

STATE_CHANGING = sorted((a for a in ActionType if get_action_spec(a).state_changing), key=lambda a: a.value)

TARGETS = {
    "ENDPOINT": "TH-LT-1047", "USER": "j.doe@example.com", "DOMAIN": "bad.example.test",
    "URL": "https://bad.example.test/payload", "IP": "203.0.113.10", "HASH": FAKE_SHA256,
    "EMAIL_MESSAGE": "<msg-0001@example.com>", "PROCESS": "TH-LT-1047:4242", "FILE": f"TH-LT-1047:{FAKE_SHA256}",
    "PERSISTENCE_ITEM": "TH-LT-1047:HKCU\\Run\\updater", "ROLE_ASSIGNMENT": "j.doe@example.com:global-admin",
    "NETWORK_CLIENT": "00:11:22:33:44:55", "APPLICATION": "app-1234", "CREDENTIAL": "app-1234:cred-1",
}


def family_of(action: ActionType) -> str:
    return next(name for name, fam in FAMILIES.items() if action in fam.actions)


def request_for(action: ActionType, integration: str, target: str | None = None) -> ActionRequest:
    spec = get_action_spec(action)
    return ActionRequest.from_recommendation(
        make_recommendation(action, target or TARGETS[spec.target_kind.value], integration=integration))


def contain_first(action: ActionType, env: SimulatedEnvironment, target: str) -> None:
    """For a restoration type, put the target in the contained state it would undo."""
    for candidate in STATE_CHANGING:
        if get_action_spec(candidate).rollback_action_type is action:
            env.force_desired_state(candidate, target)


def run(adapter: SimulatedAdapter, request: ActionRequest) -> ActionOutcome:
    """Execute ``request`` inside a fresh authorized context (purpose taken from the catalog)."""
    with guard.authorized(make_token(request), request):
        return adapter.execute(request)


@pytest.fixture
def env() -> SimulatedEnvironment:
    return SimulatedEnvironment(clock=fixed_clock())


@pytest.fixture
def endpoint(env: SimulatedEnvironment) -> SimulatedEndpointAdapter:
    return SimulatedEndpointAdapter(environment=env, clock=env.clock)


# ------------------------------------------------------------------ coverage --
def test_every_state_changing_action_has_an_effect_and_a_family() -> None:
    assert set(ACTION_EFFECTS) == set(STATE_CHANGING)
    covered = set().union(*(f.actions for f in FAMILIES.values()))
    assert covered == set(STATE_CHANGING)


def test_every_write_method_is_guarded() -> None:
    for name in STATE_CHANGING_ACTION_NAMES | {"execute"}:
        assert is_state_changing_method(getattr(SimulatedAdapter, name)), name


def test_family_classes_and_suite_manifests_are_valid() -> None:
    assert SimulatedEndpointAdapter.manifest.integration == "secure_endpoint"
    assert SimulatedIdentityAdapter.name == "entra"
    assert SimulatedEmailAdapter.manifest.supported_actions == FAMILIES["email"].actions
    assert ActionType.BLOCK_IP in SimulatedNetworkAdapter.manifest.supported_actions
    assert SimulatedIntelAdapter.manifest.supported_actions == frozenset()
    for adapter in build_simulated_adapters(SimulatedEnvironment()):
        assert adapter.manifest.verifiable_actions == adapter.manifest.supported_actions
        assert adapter.name in SIMULATED_SUITE
    assert simulated_adapter_class("meraki", ["network"]) is simulated_adapter_class("meraki", ("network",))


def test_simulated_adapters_make_no_http_calls(endpoint: SimulatedEndpointAdapter) -> None:
    with pytest.raises(RuntimeError):
        _ = endpoint.http


# ------------------------------------------------------------------- guard --
@pytest.mark.parametrize("action", STATE_CHANGING, ids=lambda a: a.value)
def test_every_write_refused_without_approval(action: ActionType, env: SimulatedEnvironment) -> None:
    adapter = simulated_adapter_class("cisco_xdr", (family_of(action),))(environment=env)
    request = request_for(action, "cisco_xdr")
    with pytest.raises(DryRunViolationError):  # fail-closed default: dry run on
        adapter.execute(request)
    install_fake_verifier()
    with pytest.raises(ApprovalRequiredError):
        getattr(adapter, action.value)(request)
    assert env.state_changing_calls() == []
    assert env.state == {}


def test_dry_run_blocks_even_with_valid_token(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    with guard.dry_run(), pytest.raises(DryRunViolationError):
        run(endpoint, request)
    assert env.state_changing_calls() == []


def test_token_for_other_integration_rejected(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    request = request_for(ActionType.ISOLATE_ENDPOINT, "defender_endpoint")
    with pytest.raises(TokenMismatchError):
        run(endpoint, request)
    assert not env.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")


def test_containment_token_cannot_release(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.force_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    request = request_for(ActionType.RELEASE_ENDPOINT, "secure_endpoint")
    with pytest.raises(ApprovalRequiredError):
        with guard.authorized(make_token(request, purpose=ApprovalPurpose.CONTAINMENT), request):
            endpoint.execute(request)
    assert env.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")


# --------------------------------------------- execution / verify / rollback --
@pytest.mark.parametrize("action", STATE_CHANGING, ids=lambda a: a.value)
def test_every_action_executes_verifies_and_is_idempotent(action: ActionType, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    adapter = simulated_adapter_class("cisco_xdr", (family_of(action),))(environment=env, clock=env.clock)
    request = request_for(action, "cisco_xdr")
    contain_first(action, env, request.target)
    assert adapter.current_state(request).state is TargetState.NOT_IN_DESIRED_STATE
    assert adapter.verify(request, None).status is VerificationStatus.NOT_VERIFIED

    outcome = run(adapter, request)
    assert outcome.status is ActionResultStatus.SUCCESS
    assert outcome.integration == "cisco_xdr"
    assert outcome.api_calls[0].kind is OperationKind.STATE_CHANGING
    assert adapter.current_state(request).state is TargetState.IN_DESIRED_STATE
    assert adapter.verify(request, outcome).status is VerificationStatus.VERIFIED

    again = run(adapter, request)
    assert again.status is ActionResultStatus.ALREADY_CONTAINED
    assert again.external_ref is None


@pytest.mark.parametrize("action", [a for a in STATE_CHANGING if get_action_spec(a).creates_control],
                         ids=lambda a: a.value)
def test_reversible_actions_roll_back(action: ActionType, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    adapter = simulated_adapter_class("cisco_xdr", (family_of(action),))(environment=env, clock=env.clock)
    request = request_for(action, "cisco_xdr")
    outcome = run(adapter, request)
    rollback_type = get_action_spec(action).rollback_action_type
    assert rollback_type is not None
    assert outcome.rollback_params["rollback_action_type"] == rollback_type.value

    release = request_for(rollback_type, "cisco_xdr", target=request.target)
    released = run(adapter, release)
    assert released.status is ActionResultStatus.SUCCESS
    assert adapter.verify(release, released).status is VerificationStatus.VERIFIED
    assert adapter.current_state(request).state is TargetState.NOT_IN_DESIRED_STATE
    assert [c.operation for c in env.state_changing_calls()] == [action.value, rollback_type.value]


def test_unsupported_action_for_family_is_refused(endpoint: SimulatedEndpointAdapter,
                                                  env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    request = request_for(ActionType.DISABLE_USER, "secure_endpoint")
    with pytest.raises(CapabilityNotSupportedError):
        run(endpoint, request)
    with guard.authorized(make_token(request), request), pytest.raises(CapabilityNotSupportedError):
        endpoint.disable_user(request)  # direct call is checked against the manifest too
    assert endpoint.current_state(request).state is TargetState.UNKNOWN
    assert endpoint.verify(request, None).status is VerificationStatus.UNABLE_TO_VERIFY
    assert env.state == {}


def test_method_must_match_request_type(endpoint: SimulatedEndpointAdapter) -> None:
    install_fake_verifier()
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    with guard.authorized(make_token(request), request), pytest.raises(ValueError):
        endpoint.lock_device(request)


def test_disabled_adapter_refuses_writes_and_reports_unknown_health(env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    adapter = SimulatedEndpointAdapter(IntegrationConfig(enabled=False), environment=env)
    assert adapter.health_check().status is HealthStatus.UNKNOWN
    with pytest.raises(IntegrationUnavailableError):
        run(adapter, request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint"))
    with pytest.raises(IntegrationUnavailableError):
        adapter.enrich(Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"))


def test_write_is_audited(env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    audit = FakeAudit()
    adapter = SimulatedEndpointAdapter(environment=env, audit=audit)
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    run(adapter, request)
    assert audit.events[0]["event_type"] is AuditEventType.API_CALL
    assert audit.events[0]["incident_id"] == request.incident_id
    failing = SimulatedEndpointAdapter(environment=SimulatedEnvironment(), audit=FakeAudit(fail=True))
    with pytest.raises(AuditError):
        run(failing, request)


# ----------------------------------------------------------- fault injection --
@pytest.mark.parametrize(("kind", "error"), [
    (FaultKind.FAIL, ApiError),
    (FaultKind.UNAVAILABLE, IntegrationUnavailableError),
    (FaultKind.AUTH_FAIL, AuthFailedError),
    (FaultKind.RATE_LIMIT, RateLimitedError),
    (FaultKind.TIMEOUT, IntegrationTimeoutError),
    (FaultKind.INVALID_TARGET, InvalidTargetError),
])
def test_write_faults_raise_typed_errors_once(kind: FaultKind, error: type[IntegrationError],
                                              endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.inject(kind, integration="secure_endpoint", operation=ActionType.ISOLATE_ENDPOINT, retry_after=5.0)
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    with pytest.raises(error) as exc:
        run(endpoint, request)
    assert exc.value.integration == "secure_endpoint"
    if kind is FaultKind.RATE_LIMIT:
        assert exc.value.retry_after == 5.0  # type: ignore[attr-defined]
    assert not env.in_desired_state(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    assert run(endpoint, request).status is ActionResultStatus.SUCCESS  # fault consumed


def test_persistent_fault_until_cleared(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.inject(FaultKind.UNAVAILABLE, integration="secure_endpoint", times=None)
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    for _ in range(3):
        with pytest.raises(IntegrationUnavailableError):
            run(endpoint, request)
    env.clear_faults()
    assert run(endpoint, request).status is ActionResultStatus.SUCCESS


def test_fault_selectors(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.inject(FaultKind.FAIL, integration="defender_endpoint")
    env.inject(FaultKind.FAIL, target="TH-LT-9999")
    assert run(endpoint, request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")).status is \
        ActionResultStatus.SUCCESS
    with pytest.raises(ApiError):
        run(endpoint, request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", target="TH-LT-9999"))
    with pytest.raises(ValueError):
        env.inject(FaultKind.FAIL, times=0)


def test_already_contained_fault(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.inject(FaultKind.ALREADY_CONTAINED, operation="isolate_endpoint")
    outcome = run(endpoint, request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint"))
    assert outcome.status is ActionResultStatus.ALREADY_CONTAINED
    assert outcome.rollback_params == {}


def test_no_effect_fault_is_caught_by_verification(endpoint: SimulatedEndpointAdapter,
                                                   env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.inject(FaultKind.NO_EFFECT, operation="isolate_endpoint")
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    outcome = run(endpoint, request)
    assert outcome.status is ActionResultStatus.SUCCESS
    assert endpoint.verify(request, outcome).status is VerificationStatus.NOT_VERIFIED


def test_verify_fault_gives_unable_to_verify(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint")
    outcome = run(endpoint, request)
    env.inject(FaultKind.TIMEOUT, operation="verify")
    assert endpoint.verify(request, outcome).status is VerificationStatus.UNABLE_TO_VERIFY
    assert endpoint.verify(request, outcome).status is VerificationStatus.VERIFIED


def test_invalid_target(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    install_fake_verifier()
    env.mark_invalid_target("TH-LT-0000")
    request = request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", target="TH-LT-0000")
    with pytest.raises(InvalidTargetError):
        endpoint.current_state(request)
    with pytest.raises(InvalidTargetError):
        run(endpoint, request)


def test_current_state_fault_raises(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    env.inject(FaultKind.AUTH_FAIL, operation="current_state")
    with pytest.raises(AuthFailedError):
        endpoint.current_state(request_for(ActionType.ISOLATE_ENDPOINT, "secure_endpoint"))


# -------------------------------------------------------------- read paths --
def test_enrichment_from_environment(env: SimulatedEnvironment) -> None:
    intel = SimulatedIntelAdapter(environment=env, clock=env.clock)
    env.set_reputation(ObservableType.DOMAIN, "bad.example.test", Verdict.MALICIOUS, risk_score=90, confidence=80,
                       summary="known phishing domain (simulated)")
    result = intel.enrich(Observable(type=ObservableType.DOMAIN, value="BAD.example.test"))
    assert result.verdict is Verdict.MALICIOUS
    assert (result.risk_score, result.confidence) == (90, 80)
    assert result.evidence[0].source == "virustotal"
    unknown = intel.enrich(Observable(type=ObservableType.IP, value="198.51.100.7"))
    assert unknown.verdict is Verdict.UNKNOWN and unknown.evidence == ()
    with pytest.raises(CapabilityNotSupportedError):
        intel.enrich(Observable(type=ObservableType.USER, value="j.doe@example.com"))
    env.inject(FaultKind.RATE_LIMIT, integration="virustotal", operation="enrich")
    with pytest.raises(RateLimitedError):
        intel.enrich(Observable(type=ObservableType.DOMAIN, value="bad.example.test"))
    assert [c.operation for c in env.calls] == ["enrich", "enrich", "enrich"]


def test_investigation_findings(env: SimulatedEnvironment) -> None:
    identity = SimulatedIdentityAdapter(environment=env, clock=env.clock)
    env.add_findings(ActionType.INVESTIGATE_AUTHENTICATION, "j.doe@example.com",
                     {"summary": "sign-in from 203.0.113.50", "ip": "203.0.113.50"}, {"ip": "198.51.100.9"})
    subject = Observable(type=ObservableType.USER, value="j.doe@example.com")
    result = identity.investigate(InvestigationQuery(action_type=ActionType.INVESTIGATE_AUTHENTICATION,
                                                     subject=subject))
    assert len(result.findings) == 2
    assert result.evidence[0].summary == "sign-in from 203.0.113.50"
    assert all(e.source == "entra" for e in result.evidence)
    with pytest.raises(CapabilityNotSupportedError):
        identity.investigate(InvestigationQuery(action_type=ActionType.INVESTIGATE_ENDPOINT, subject=subject))


@pytest.mark.parametrize(("kind", "status"), [
    (FaultKind.AUTH_FAIL, HealthStatus.AUTH_FAILED),
    (FaultKind.RATE_LIMIT, HealthStatus.RATE_LIMITED),
    (FaultKind.TIMEOUT, HealthStatus.DEGRADED),
    (FaultKind.UNAVAILABLE, HealthStatus.UNAVAILABLE),
])
def test_health_faults(kind: FaultKind, status: HealthStatus, endpoint: SimulatedEndpointAdapter,
                       env: SimulatedEnvironment) -> None:
    env.inject(kind, operation="health_check")
    assert endpoint.health_check().status is status
    assert endpoint.health_check().status is HealthStatus.CONNECTED


def test_state_faults_do_not_apply_to_reads(endpoint: SimulatedEndpointAdapter, env: SimulatedEnvironment) -> None:
    env.inject(FaultKind.ALREADY_CONTAINED)
    assert endpoint.health_check().status is HealthStatus.CONNECTED
    assert len(env.faults) == 1
