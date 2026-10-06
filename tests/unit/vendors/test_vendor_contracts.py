"""Contract tests that hold for every shipped vendor adapter.

* manifests load, match the registry and the secret table of architecture 13.11, and cite sources
  that appear in docs/integrations.md;
* every state-changing method raises ApprovalRequiredError outside an authorization context (and
  sends nothing), even when called directly;
* every UNVERIFIED operation raises ``unverified endpoint: <integration>.<operation> - see
  docs/integrations.md`` (a NotImplementedError) and sends nothing;
* health checks never raise; disabled adapters report UNKNOWN; Splunk is optional and disabled.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tests.fixtures.guard_helpers import install_fake_verifier
from tests.unit.vendors._helpers import (
    ALL_ADAPTERS,
    Router,
    action_request,
    authorized,
    json_response,
    make_adapter,
)
from xdr_response import guard
from xdr_response.errors import (
    ApprovalRequiredError,
    DryRunViolationError,
    IntegrationUnavailableError,
    UnverifiedEndpointError,
)
from xdr_response.integrations import STATE_CHANGING_ACTION_NAMES, IntegrationAdapter
from xdr_response.integrations._adapter_support import ApiRequest
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionType,
    EndpointStatus,
    HealthStatus,
    Observable,
    ObservableType,
    OperationKind,
)

DOCS = (Path(__file__).resolve().parents[3] / "docs" / "integrations.md").read_text(encoding="utf-8")

#: Architecture 13.11 secret table (logical name -> NAME).
SECRET_TABLE = {
    "cisco_xdr": {"XDR_CLIENT_ID", "XDR_CLIENT_SECRET"},
    "secure_endpoint": {"SE_CLIENT_ID", "SE_API_KEY"},
    "secure_email": {"ETD_CLIENT_ID", "ETD_CLIENT_SECRET", "ETD_API_KEY"},
    "secure_malware_analytics": {"SMA_API_KEY"},
    "secure_cloud_analytics": {"SCA_API_KEY"},
    "umbrella": {"UMBRELLA_API_KEY", "UMBRELLA_API_SECRET"},
    "meraki": {"MERAKI_API_KEY"},
    "entra": {"ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"},
    "defender_o365": {"ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"},
    "intune": {"ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"},
    "microsoft_cloud": {"ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"},
    "defender_endpoint": {"ENTRA_TENANT_ID", "MDE_CLIENT_ID", "MDE_CLIENT_SECRET"},
    "virustotal": {"VT_API_KEY"},
    "alienvault_otx": {"OTX_API_KEY"},
    "hibp": {"HIBP_API_KEY"},
    "splunk": {"SPLUNK_TOKEN", "SPLUNK_HEC_TOKEN"},
}

#: Params that let every guarded method get past argument checks if it were ever reached.
PARAMS = {"connector_guid": "guid-0001", "module_instance_id": "mi-0001", "action_id": "act-0001",
          "observable_type": "hostname", "verdict": "phishing", "destination_list_id": "17",
          "destination_id": "9001", "network_id": "N_0001", "previous_device_policy": "Normal",
          "principal_id": "pr-0001", "role_definition_id": "rd-0001", "directory_scope_id": "/",
          "indicator_id": "ind-0001", "recipient": "j.doe@example.com", "managed_device_id": "md-0001",
          "restores": "XDR-83921:block_ip:203.0.113.10"}

GUARDED = sorted((name, attr) for name, cls in ALL_ADAPTERS.items() for attr in STATE_CHANGING_ACTION_NAMES
                 if hasattr(cls, attr))
UNSUPPORTED_GUARDED = [(n, a) for n, a in GUARDED if ActionType(a) not in ALL_ADAPTERS[n].manifest.supported_actions]
UNVERIFIED_OPS = sorted((name, op.name) for name, cls in ALL_ADAPTERS.items() for op in cls.manifest.operations
                        if op.status is EndpointStatus.UNVERIFIED)

#: Non-guarded adapter methods backed by UNVERIFIED operations: (integration, method, args, operation).
UNVERIFIED_CALLS = [
    ("cisco_xdr", "update_incident_status_private_intel", ("XDR-1", "Open"), "update_incident_status_private_intel"),
    ("cisco_xdr", "add_incident_note", ("XDR-1", "note"), "add_incident_note"),
    ("cisco_xdr", "search_incidents", (), "search_incidents"),
    ("cisco_xdr", "inspect", ("free text",), "inspect"),
    ("cisco_xdr", "run_workflow", ("wf-1",), "run_workflow"),
    ("cisco_xdr", "list_approval_tasks", (), "approval_tasks"),
    ("cisco_xdr", "respond_to_approval_task", ("task-1", "approve"), "approval_tasks"),
    ("secure_endpoint", "get_isolation", ("guid-0001",), "get_isolation"),
    ("secure_endpoint", "list_events", (), "list_events"),
    ("secure_malware_analytics", "search_submissions", ("q",), "search_submissions"),
    ("secure_malware_analytics", "sample_report", ("s-1",), "sample_report"),
    ("secure_cloud_analytics", "list_alerts", (), "list_alerts"),
    ("secure_cloud_analytics", "list_observations", (), "list_observations"),
    ("secure_cloud_analytics", "get_device", ("d-1",), "get_device"),
    ("umbrella", "security_scores", ("example.com",), "security_scores"),
    ("umbrella", "risk_score", ("example.com",), "risk_score"),
    ("entra", "get_risky_user", ("u-1",), "risky_user"),
    ("entra", "dismiss_risky_user", ("u-1",), "dismiss_risky_user"),
    ("defender_endpoint", "list_indicators", (), "list_indicators"),
    ("defender_o365", "list_analyzed_emails", (), "list_analyzed_emails"),
    ("defender_o365", "release_from_quarantine", ("m-1",), "quarantine_release"),
    ("intune", "retire_device", ("md-1",), "retire_wipe"),
    ("intune", "wipe_device", ("md-1",), "retire_wipe"),
    ("intune", "sync_device", ("md-1",), "sync_scan"),
    ("microsoft_cloud", "list_incidents", (), "list_incidents"),
    ("splunk", "export", ("search index=main",), "export"),
]


def _message(integration: str, operation: str) -> str:
    return f"unverified endpoint: {integration}.{operation} - see docs/integrations.md"


# ------------------------------------------------------------------ manifests --
@pytest.mark.parametrize("name", INTEGRATION_NAMES)
def test_package_exports_manifest_and_adapter(name):
    package = importlib.import_module(f"xdr_response.integrations.{name}")
    cls = ALL_ADAPTERS[name]
    assert package.MANIFEST is cls.manifest
    assert getattr(package, cls.__name__) is cls
    assert cls.name == name == cls.manifest.integration
    assert issubclass(cls, IntegrationAdapter)


@pytest.mark.parametrize("name", INTEGRATION_NAMES)
def test_required_secrets_match_contract_table(name):
    manifest_module = importlib.import_module(f"xdr_response.integrations.{name}.manifest")
    assert set(manifest_module.REQUIRED_SECRETS.values()) == SECRET_TABLE[name]
    assert dict(ALL_ADAPTERS[name].secret_names) == dict(manifest_module.REQUIRED_SECRETS)
    assert isinstance(manifest_module.CONFIG_OPTIONS, dict)


@pytest.mark.parametrize("name", INTEGRATION_NAMES)
def test_health_probe_names_a_verified_read(name):
    manifest_module = importlib.import_module(f"xdr_response.integrations.{name}.manifest")
    probe = manifest_module.HEALTH_PROBE
    if probe is not None:
        op = ALL_ADAPTERS[name].manifest.operation(probe)
        assert op.status is EndpointStatus.VERIFIED
        assert op.kind in (OperationKind.READ, OperationKind.VERIFY)


@pytest.mark.parametrize("name", INTEGRATION_NAMES)
def test_verified_operations_cite_a_source_listed_in_docs(name):
    for op in ALL_ADAPTERS[name].manifest.operations:
        if op.status is EndpointStatus.VERIFIED:
            assert op.source and op.source in DOCS, f"{name}.{op.name}: {op.source}"
            assert op.method, f"{name}.{op.name} has no method"
        else:
            assert op.source is None, f"{name}.{op.name}: only VERIFIED rows cite sources"


@pytest.mark.parametrize("name", INTEGRATION_NAMES)
def test_supported_actions_have_guarded_methods(name):
    cls = ALL_ADAPTERS[name]
    for action in cls.manifest.supported_actions:
        assert guard.is_state_changing_method(getattr(cls, action.value))
    for attr in STATE_CHANGING_ACTION_NAMES:
        if hasattr(cls, attr):
            assert guard.is_state_changing_method(getattr(cls, attr)), f"{name}.{attr} is unguarded"


def test_splunk_is_optional_and_disabled_by_default():
    for name, cls in ALL_ADAPTERS.items():
        assert cls.manifest.optional is (name == "splunk")
        assert cls.manifest.enabled_by_default is (name != "splunk")
    splunk = make_adapter("splunk", enabled=False)
    assert splunk.health_check().status is HealthStatus.UNKNOWN
    assert splunk.forward_audit({"event": "x"}) is False


def test_only_cisco_xdr_is_native():
    assert [n for n, c in ALL_ADAPTERS.items() if c.manifest.native_xdr] == ["cisco_xdr"]


# ------------------------------------------------- guard: approval is mandatory --
@pytest.mark.parametrize(("name", "method"), GUARDED)
def test_state_changing_methods_refused_outside_guard(name, method):
    router = Router()
    adapter = make_adapter(name, router)
    request = action_request(ActionType(method), name, **PARAMS)
    with pytest.raises(DryRunViolationError):  # default: dry run on (fail closed)
        getattr(adapter, method)(request)
    install_fake_verifier()  # dry run off, verifier registered, but no authorization context
    with pytest.raises(ApprovalRequiredError) as excinfo:
        getattr(adapter, method)(request)
    assert not isinstance(excinfo.value, DryRunViolationError)
    with pytest.raises(ApprovalRequiredError):
        adapter.execute(request)
    assert router.calls == []


@pytest.mark.parametrize(("name", "method"), GUARDED)
def test_state_changing_methods_refused_in_dry_run_even_when_approved(name, method):
    router = Router()
    adapter = make_adapter(name, router)
    request = action_request(ActionType(method), name, **PARAMS)
    install_fake_verifier()
    with guard.dry_run(), pytest.raises(DryRunViolationError):
        with authorized(request):
            getattr(adapter, method)(request)
    assert router.calls == []


@pytest.mark.parametrize("name", sorted(n for n, c in ALL_ADAPTERS.items() if c.manifest.supported_actions))
def test_approval_for_another_integration_is_refused(name):
    cls = ALL_ADAPTERS[name]
    action = sorted(cls.manifest.supported_actions)[0]
    other = "cisco_xdr" if name != "cisco_xdr" else "defender_endpoint"
    request = action_request(action, other, **PARAMS)
    router = Router()
    adapter = make_adapter(name, router)
    with authorized(request), pytest.raises(ApprovalRequiredError):
        getattr(adapter, action.value)(request)
    assert router.calls == []


# ----------------------------------------------------- unverified endpoints --
@pytest.mark.parametrize(("name", "method"), UNSUPPORTED_GUARDED)
def test_unverified_state_changing_operations_raise(name, method):
    cls = ALL_ADAPTERS[name]
    action = ActionType(method)
    op = cls.manifest.unverified_operation_for(action)
    assert op is not None, f"{name}.{method} exists but no UNVERIFIED manifest row covers it"
    router = Router()
    adapter = make_adapter(name, router)
    request = action_request(action, name, **PARAMS)
    with authorized(request):
        with pytest.raises(UnverifiedEndpointError) as direct:
            getattr(adapter, method)(request)
    with authorized(request):
        with pytest.raises(NotImplementedError) as via_execute:
            adapter.execute(request)
    assert str(direct.value) == str(via_execute.value) == _message(name, op.name)
    assert router.calls == []


@pytest.mark.parametrize(("name", "method", "args", "operation"), UNVERIFIED_CALLS)
def test_unverified_read_operations_raise(name, method, args, operation):
    cls = ALL_ADAPTERS[name]
    assert cls.manifest.operation(operation).status is EndpointStatus.UNVERIFIED
    router = Router()
    adapter = make_adapter(name, router)
    with pytest.raises(NotImplementedError) as excinfo:
        getattr(adapter, method)(*args)
    assert isinstance(excinfo.value, UnverifiedEndpointError)
    assert str(excinfo.value) == _message(name, operation)
    assert router.calls == []


@pytest.mark.parametrize(("name", "operation"), UNVERIFIED_OPS)
def test_send_refuses_every_unverified_operation(name, operation):
    """Defense in depth: even a hand-built request for an UNVERIFIED row is never sent."""
    router = Router()
    adapter = make_adapter(name, router)
    with pytest.raises(UnverifiedEndpointError, match="unverified endpoint"):
        adapter._send(ApiRequest(operation=operation, method="GET", path="anything"))
    assert router.calls == []


def test_send_refuses_unknown_operation_and_method_mismatch():
    adapter = make_adapter("umbrella", Router())
    with pytest.raises(ValueError, match="not in the manifest"):
        adapter._send(ApiRequest(operation="made_up", method="GET", path="x"))
    with pytest.raises(ValueError, match="method"):
        adapter._send(ApiRequest(operation="list_destination_lists", method="POST", path="x"))
    with pytest.raises(ValueError, match="kind"):
        adapter._send(ApiRequest(operation="add_destinations", method="POST", path="x"))


def test_unverified_enrichment_paths_raise():
    sma = make_adapter("secure_malware_analytics", Router())
    with pytest.raises(UnverifiedEndpointError, match="secure_malware_analytics.search_submissions"):
        sma.enrich(Observable(type=ObservableType.SHA256, value="a" * 64))
    xdr = make_adapter("cisco_xdr", Router(), region="eu")
    with pytest.raises(UnverifiedEndpointError, match="cisco_xdr.get_incident_full"):
        xdr.get_incident("XDR-83921")


# ------------------------------------------------------- health and disabled --
@pytest.mark.parametrize("name", INTEGRATION_NAMES)
def test_disabled_adapter_reports_unknown_and_refuses_execution(name):
    router = Router()
    adapter = make_adapter(name, router, enabled=False)
    assert adapter.health_check().status is HealthStatus.UNKNOWN
    supported = sorted(adapter.manifest.supported_actions)
    if supported:
        request = action_request(supported[0], name, **PARAMS)
        with authorized(request), pytest.raises(IntegrationUnavailableError):
            adapter.execute(request)
    assert router.calls == []


HEALTH_OPTIONS = {"meraki": {"health_network_id": "N_0001"}}


@pytest.mark.parametrize("name", INTEGRATION_NAMES)
@pytest.mark.parametrize(("status", "expected"), [
    (200, HealthStatus.CONNECTED), (401, HealthStatus.AUTH_FAILED), (403, HealthStatus.AUTH_FAILED),
    (429, HealthStatus.RATE_LIMITED), (503, HealthStatus.UNAVAILABLE), (418, HealthStatus.DEGRADED),
])
def test_health_check_maps_probe_results_and_never_raises(name, status, expected):
    router = Router(fallback=json_response(status, {"data": []}))
    adapter = make_adapter(name, router, options=HEALTH_OPTIONS.get(name))
    health = adapter.health_check()
    if not router.calls:  # no VERIFIED side-effect-free probe for this integration
        assert health.status is HealthStatus.UNKNOWN
        return
    assert health.status is expected
    assert len(router.calls) == 1 and router.calls[0].method in ("GET", "POST")
