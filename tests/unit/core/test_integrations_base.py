"""Adapter base class: guard enforcement on every write path, manifests, default read behavior."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.fixtures.factories import FIXED_NOW, make_recommendation
from tests.fixtures.guard_helpers import install_fake_verifier, make_token
from tests.fixtures.principals import make_test_secrets
from xdr_response import guard, integrations
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig
from xdr_response.errors import (
    ApprovalRequiredError,
    CapabilityNotSupportedError,
    ConfigError,
    DryRunViolationError,
    IntegrationUnavailableError,
    SecretNotFoundError,
    UnverifiedEndpointError,
    unverified,
)
from xdr_response.integrations import (
    STATE_CHANGING_ACTION_NAMES,
    CapabilityManifest,
    IntegrationAdapter,
    OperationSpec,
)
from xdr_response.interfaces import SecretProvider
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    EndpointStatus,
    HealthStatus,
    IntegrationHealth,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    VerificationStatus,
)

DOC = "https://docs.example.com/verified-page"
SC = OperationKind.STATE_CHANGING

MANIFEST = CapabilityManifest(
    integration="secure_endpoint",
    display_name="Test Secure Endpoint",
    supported_actions=frozenset({ActionType.ISOLATE_ENDPOINT, ActionType.RELEASE_ENDPOINT}),
    operations=(
        OperationSpec(name="isolate", kind=SC, status=EndpointStatus.VERIFIED, method="PUT",
                      path="/v1/computers/{connector_guid}/isolation", source=DOC,
                      action_types=(ActionType.ISOLATE_ENDPOINT,)),
        OperationSpec(name="release", kind=SC, status=EndpointStatus.VERIFIED, method="DELETE",
                      path="/v1/computers/{connector_guid}/isolation", source=DOC,
                      action_types=(ActionType.RELEASE_ENDPOINT,)),
        OperationSpec(name="block_hash", kind=SC, status=EndpointStatus.UNVERIFIED,
                      action_types=(ActionType.BLOCK_HASH,)),
    ),
)


class FakeSecureEndpoint(IntegrationAdapter):
    name = "secure_endpoint"
    manifest = MANIFEST
    secret_names = {"api_key": "SE_API_KEY"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls: list[str] = []

    def health_check(self) -> IntegrationHealth:
        if not self.enabled:
            return self.disabled_health()
        return IntegrationHealth(integration=self.name, status=HealthStatus.CONNECTED, checked_at=self.clock.now())

    @guard.state_changing
    def isolate_endpoint(self, request: ActionRequest) -> ActionOutcome:
        self.calls.append(f"isolate:{request.target}")
        return ActionOutcome(status=ActionResultStatus.SUCCESS, integration=self.name, executed_at=self.clock.now())

    @guard.state_changing
    def release_endpoint(self, request: ActionRequest) -> ActionOutcome:
        self.calls.append(f"release:{request.target}")
        return ActionOutcome(status=ActionResultStatus.SUCCESS, integration=self.name, executed_at=self.clock.now())

    @guard.state_changing
    def block_hash(self, request: ActionRequest) -> ActionOutcome:
        unverified(self.name, "block_hash")


def _adapter(enabled: bool = True, **cfg) -> FakeSecureEndpoint:
    return FakeSecureEndpoint(IntegrationConfig(enabled=enabled, **cfg),
                              make_test_secrets(SE_API_KEY="fake-se-api-key-123456"), clock=FixedClock(FIXED_NOW))


def _req(action_type=ActionType.ISOLATE_ENDPOINT, target="TH-LT-1047", integration="secure_endpoint", **params):
    return ActionRequest.from_recommendation(make_recommendation(action_type, target, integration, **params))


# -------------------------------------------------------- class-time checks --
def test_undecorated_write_method_rejected_at_class_creation():
    with pytest.raises(TypeError, match="must be decorated"):
        class Bad(IntegrationAdapter):  # noqa: F841
            name = "secure_endpoint"

            def health_check(self):  # pragma: no cover
                ...

            def isolate_endpoint(self, request):  # pragma: no cover - never guarded
                ...


def test_undecorated_execute_override_rejected():
    with pytest.raises(TypeError):
        class Bad(IntegrationAdapter):  # noqa: F841
            name = "secure_endpoint"

            def health_check(self):  # pragma: no cover
                ...

            def execute(self, request):  # pragma: no cover
                ...


def test_supported_action_needs_guarded_method():
    with pytest.raises(TypeError, match="no @state_changing method"):
        class Bad(IntegrationAdapter):  # noqa: F841
            name = "secure_endpoint"
            manifest = MANIFEST

            def health_check(self):  # pragma: no cover
                ...


def test_name_must_match_manifest():
    with pytest.raises(TypeError, match="manifest.integration"):
        class Bad(FakeSecureEndpoint):  # noqa: F841
            name = "umbrella"
            manifest = MANIFEST


def test_reserved_names_cover_every_state_changing_type():
    assert "isolate_endpoint" in STATE_CHANGING_ACTION_NAMES
    assert "release_endpoint" in STATE_CHANGING_ACTION_NAMES
    assert "enrich_ip" not in STATE_CHANGING_ACTION_NAMES
    assert len(STATE_CHANGING_ACTION_NAMES) == 30


# --------------------------------------------------------------- manifests --
def test_manifest_validation():
    with pytest.raises(ValidationError):  # VERIFIED needs a source
        OperationSpec(name="x", kind=OperationKind.READ, status=EndpointStatus.VERIFIED)
    with pytest.raises(ValidationError):  # PUT is never a read
        OperationSpec(name="x", kind=OperationKind.READ, status=EndpointStatus.UNVERIFIED, method="PUT")
    with pytest.raises(ValidationError):  # supported without a VERIFIED write op
        CapabilityManifest(integration="umbrella", display_name="U",
                           supported_actions=frozenset({ActionType.BLOCK_IP}),
                           operations=(OperationSpec(name="block_ip", kind=SC, status=EndpointStatus.UNVERIFIED,
                                                     action_types=(ActionType.BLOCK_IP,)),))
    with pytest.raises(ValidationError):  # unknown integration
        CapabilityManifest(integration="cloudflare", display_name="C", operations=())
    with pytest.raises(ValidationError):  # read actions only
        CapabilityManifest(integration="umbrella", display_name="U", operations=(),
                           read_actions=frozenset({ActionType.BLOCK_DOMAIN}))
    assert MANIFEST.operation("isolate").method == "PUT"
    with pytest.raises(KeyError):
        MANIFEST.operation("nope")
    assert MANIFEST.unverified_operation_for(ActionType.BLOCK_HASH).name == "block_hash"


# ------------------------------------------------------------- write paths --
def test_execute_dispatches_under_authorization():
    install_fake_verifier()
    adapter = _adapter()
    req = _req()
    with guard.authorized(make_token(req), req):
        outcome = adapter.execute(req)
    assert outcome.status is ActionResultStatus.SUCCESS and adapter.calls == ["isolate:TH-LT-1047"]


def test_execute_and_direct_calls_refused_without_authorization():
    install_fake_verifier()
    adapter = _adapter()
    req = _req()
    for call in (adapter.execute, adapter.isolate_endpoint, adapter.block_hash):
        with pytest.raises(ApprovalRequiredError):
            call(req)
    assert adapter.calls == []


def test_execute_refused_in_dry_run():
    adapter = _adapter()
    with pytest.raises(DryRunViolationError):
        adapter.execute(_req())
    assert adapter.calls == []


def test_execute_unverified_and_unsupported():
    install_fake_verifier()
    adapter = _adapter()
    h = _req(ActionType.BLOCK_HASH, "b" * 64)
    with guard.authorized(make_token(h), h):
        with pytest.raises(UnverifiedEndpointError, match="unverified endpoint: secure_endpoint.block_hash"):
            adapter.execute(h)
    d = _req(ActionType.BLOCK_DOMAIN, "bad.example.test")
    with guard.authorized(make_token(d), d):
        with pytest.raises(CapabilityNotSupportedError):
            adapter.execute(d)


def test_execute_refuses_other_integration_request():
    install_fake_verifier()
    adapter = _adapter()
    req = _req(integration="defender_endpoint")
    with guard.authorized(make_token(req), req):
        with pytest.raises(ApprovalRequiredError):
            adapter.execute(req)
    assert adapter.calls == []


def test_disabled_adapter_refuses_execution():
    install_fake_verifier()
    adapter = _adapter(enabled=False)
    req = _req()
    with guard.authorized(make_token(req), req):
        with pytest.raises(IntegrationUnavailableError):
            adapter.execute(req)
    assert adapter.health_check().status is HealthStatus.UNKNOWN


def test_release_needs_release_purpose():
    install_fake_verifier()
    adapter = _adapter()
    req = _req(ActionType.RELEASE_ENDPOINT, restores="XDR-83921:isolate_endpoint:TH-LT-1047")
    with guard.authorized(make_token(req), req):
        assert adapter.execute(req).status is ActionResultStatus.SUCCESS
    assert adapter.calls == ["release:TH-LT-1047"]


# -------------------------------------------------------------- read paths --
def test_default_read_methods():
    adapter = _adapter()
    req = _req()
    with pytest.raises(CapabilityNotSupportedError):
        adapter.enrich(Observable(type=ObservableType.DOMAIN, value="bad.example.test"))
    assert adapter.current_state(req).state is TargetState.UNKNOWN
    v = adapter.verify(req, None)
    assert v.status is VerificationStatus.UNABLE_TO_VERIFY and v.integration == "secure_endpoint"
    assert v.checked_at == FIXED_NOW
    assert adapter.health_check().status is HealthStatus.CONNECTED


def test_secret_and_base_url_resolution():
    adapter = _adapter(secrets={"client_id": "SE_CLIENT_ID"})
    assert adapter.secret("api_key").reveal() == "fake-se-api-key-123456"
    with pytest.raises(SecretNotFoundError):
        adapter.secret("client_id")  # SE_CLIENT_ID not provided
    with pytest.raises(ConfigError):
        adapter.secret("unknown")
    with pytest.raises(ConfigError):
        _ = adapter.base_url
    assert _adapter(base_url="https://api.amp.cisco.com").base_url == "https://api.amp.cisco.com"
    sentinel = object()
    adapter.http = sentinel  # type: ignore[assignment]
    assert adapter.http is sentinel
    assert isinstance(adapter.secrets, SecretProvider)


def test_integrations_package_lazy_exports():
    assert integrations.IntegrationAdapter is IntegrationAdapter
    with pytest.raises(AttributeError):
        integrations.DoesNotExist  # noqa: B018
