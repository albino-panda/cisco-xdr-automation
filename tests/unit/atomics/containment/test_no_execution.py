"""Proof that the containment builders only recommend: nothing can execute (14.0.1, 14.1.7).

Four independent proofs:

1. Static: an AST lint of every ``atomics/containment`` module (no write-zone imports, no adapter
   or vendor imports, no ``execute`` / state-changing method calls, no token, request, decision or
   package construction, no approval level, no dynamic attribute or code access).
2. Simulated lab: every builder and every containment type against the real ``ReadOnlyAdapters``
   over the simulated suite, with dry run OFF and ``execute`` booby-trapped: zero vendor calls,
   zero guard denials, no authorization context ever entered.
3. Real adapters (fake secrets, a transport that records and refuses every request): routing reads
   only manifests, so zero HTTP requests; the documented "route today" table holds.
4. Native route against the real Cisco XDR adapter over ``httpx.MockTransport``: exactly one READ
   (``respond/observables``) and never ``respond/trigger``.
"""
from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest

from tests.fixtures.factories import FIXED_NOW, make_incident
from tests.fixtures.principals import make_test_secrets
from tests.unit.atomics.containment._support import FAKE_SHA256, FakeAdapters, evidence, make_context, make_settings
from tests.unit.vendors._helpers import FAKE_SECRETS, Router, json_response, make_adapter
from xdr_response import guard
from xdr_response.atomics import containment as containment_pkg
from xdr_response.atomics.containment import CONTAINMENT_BUILDERS, BuiltRecommendation, build_containment
from xdr_response.atomics.context import ReadOnlyAdapters
from xdr_response.clock import FixedClock
from xdr_response.config import Settings
from xdr_response.integrations.base import IntegrationAdapter
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.integrations.simulated import SimulatedEnvironment, register_simulated_adapters
from xdr_response.models import ACTION_CATALOG, ActionType, ApprovalPurpose, OperationKind, ProposedAction

PACKAGE_DIR = Path(containment_pkg.__file__).parent
SOURCES = sorted(PACKAGE_DIR.glob("*.py"))

TARGETS = {
    "isolate_secure_endpoint": "TH-LT-1047", "isolate_defender_endpoint": "TH-LT-1047",
    "block_domain_umbrella": "bad.example.test", "block_url": "https://bad.example.test/payload",
    "block_ip": "203.0.113.10", "block_hash": FAKE_SHA256, "revoke_entra_sessions": "jsmith@example.com",
    "disable_entra_user": "jsmith@example.com", "quarantine_email": "msg-0001@example.test",
    "delete_malicious_email": "msg-0001@example.test", "intune_device_action": "TH-LT-1047",
    "terminate_process": "TH-LT-1047/4242", "quarantine_file": f"TH-LT-1047/{FAKE_SHA256}",
    "remove_persistence": "TH-LT-1047/run-key-0001", "remove_privileged_role": "jsmith@example.com/role-def-0001",
}
KIND_TARGETS = {
    "ENDPOINT": "TH-LT-1047", "USER": "jsmith@example.com", "DOMAIN": "bad.example.test",
    "URL": "https://bad.example.test/payload", "IP": "203.0.113.10", "HASH": FAKE_SHA256,
    "EMAIL_MESSAGE": "msg-0001@example.test", "PROCESS": "TH-LT-1047/4242", "FILE": f"TH-LT-1047/{FAKE_SHA256}",
    "PERSISTENCE_ITEM": "TH-LT-1047/run-key-0001", "ROLE_ASSIGNMENT": "jsmith@example.com/role-def-0001",
    "NETWORK_CLIENT": "N_0001/k74272e", "APPLICATION": "app-0001", "CREDENTIAL": "cred-0001",
}
CONTAINMENT_TYPES = [t for t, s in ACTION_CATALOG.items() if s.purpose is ApprovalPurpose.CONTAINMENT]
KW = {"evidence": evidence(1), "risk_score": 90, "confidence_score": 80, "rationale": "rule matched"}
#: Caller params a route needs: Defender for Office 365 takes one recipient per message (14.10.3).
PARAMS = {"delete_malicious_email": {"recipient": "jsmith@example.com"}}


def _build_everything(ctx) -> list[BuiltRecommendation]:
    built = [builder(ctx, TARGETS[name], **KW) for name, builder in CONTAINMENT_BUILDERS.items()]
    built += [build_containment(ctx, t, KIND_TARGETS[ACTION_CATALOG[t].target_kind.value], **KW)
              for t in CONTAINMENT_TYPES]
    return built


# ------------------------------------------------------------ 1. static --
FORBIDDEN_MODULE_PREFIXES = (
    "xdr_response.guard", "xdr_response.approval.tokens", "xdr_response.approval.engine",
    "xdr_response.approval.authenticator", "xdr_response.approval.ledger", "xdr_response.approval.package",
    "xdr_response.approval._quorum", "xdr_response.execution", "xdr_response.restoration", "xdr_response.dryrun",
    "xdr_response.verification", "xdr_response.integrations", "xdr_response.lifecycle", "xdr_response.audit",
    "xdr_response.workflows", "httpx", "importlib", "subprocess", "socket", "os",
)
FORBIDDEN_NAMES = {
    "ApprovalToken", "ApprovalTokenClaims", "TokenActionGrant", "ApproverClaim", "AnalystDecision",
    "DecisionRequest", "ApproverCredential", "AuthenticatedPrincipal", "RecommendedAction", "ActionPackage",
    "ContainmentPackage", "ReleasePackage", "ActionRequest", "ActionBinding", "ApprovalLevel",
    "getattr", "setattr", "delattr", "vars", "globals", "__import__", "eval", "exec", "compile", "open",
}
STATE_CHANGING_METHODS = {t.value for t, s in ACTION_CATALOG.items() if s.state_changing} | {"execute"}


def _imports(tree: ast.AST) -> list[tuple[str, tuple[str, ...]]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(alias.name, ()) for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            found.append((node.module or "", tuple(alias.name for alias in node.names)))
    return found


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_static_no_write_zone_access(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for module, names in _imports(tree):
        assert not module.startswith(FORBIDDEN_MODULE_PREFIXES), f"{path.name} imports {module}"
        assert not set(names) & FORBIDDEN_NAMES, f"{path.name} imports {set(names) & FORBIDDEN_NAMES}"
        private = [n for n in names if n.startswith("_")]
        assert not private or module.startswith("xdr_response.atomics.containment."), (path.name, module, private)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            assert node.id not in FORBIDDEN_NAMES, f"{path.name}:{node.lineno} uses {node.id}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in STATE_CHANGING_METHODS, f"{path.name}:{node.lineno} calls .{node.func.attr}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and path.name != "__init__.py":
            assert node.func.id not in STATE_CHANGING_METHODS, f"{path.name}:{node.lineno} calls {node.func.id}"
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
            owner = node.value.id if isinstance(node.value, ast.Name) else None
            assert owner in ("self", "cls"), f"{path.name}:{node.lineno} reads private .{node.attr}"
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in ("ELEVATED", "STANDARD"), f"{path.name}:{node.lineno} names an approval level"


def test_static_lint_covers_every_module():
    assert {p.name for p in SOURCES} == {"__init__.py", "models.py", "routing.py", "builders.py"}


def test_output_is_a_proposal_never_an_approved_action():
    fields = set(BuiltRecommendation.model_fields)
    assert fields == {"action_type", "target", "proposal", "route", "warnings", "excluded_reason", "unrouted_reason"}
    assert "approval_level" not in ProposedAction.model_fields and "idempotency_key" not in ProposedAction.model_fields


# ------------------------------------------------------- 2. simulated lab --
@pytest.fixture
def lab(monkeypatch):
    environment = SimulatedEnvironment(clock=FixedClock(FIXED_NOW))
    registry = AdapterRegistry(Settings(), make_test_secrets(), clock=FixedClock(FIXED_NOW))
    register_simulated_adapters(registry, environment)
    denials: list[str] = []
    guard.set_denial_hook(lambda reason, request, exc: denials.append(reason))
    guard.configure(dry_run=False)  # prove safety without leaning on dry run

    def trap(*_args, **_kwargs):
        raise AssertionError("a containment builder reached an execution path")

    monkeypatch.setattr(IntegrationAdapter, "execute", trap)
    monkeypatch.setattr(guard, "authorized", trap)
    ctx = make_context(ReadOnlyAdapters(registry), make_settings(), incident=make_incident(), dry_run=False)
    yield ctx, environment, denials
    guard.set_denial_hook(None)


def test_simulated_lab_builders_never_reach_a_vendor(lab):
    ctx, environment, denials = lab
    built = _build_everything(ctx)
    assert len(built) == 15 + len(CONTAINMENT_TYPES)
    assert environment.state_changing_calls() == []
    assert environment.calls == []  # routing needs no vendor read at all in the lab
    assert denials == [] and guard.current() is None
    assert environment.state == {}


def test_simulated_lab_routes(lab):
    ctx, _, _ = lab
    routes = {name: builder(ctx, TARGETS[name], params=PARAMS.get(name), **KW).route.integration
              for name, builder in CONTAINMENT_BUILDERS.items()}
    assert routes == {
        "isolate_secure_endpoint": "secure_endpoint", "isolate_defender_endpoint": "defender_endpoint",
        "block_domain_umbrella": "umbrella", "block_url": "umbrella", "block_ip": "meraki",
        "block_hash": "defender_endpoint", "revoke_entra_sessions": "entra", "disable_entra_user": "entra",
        "quarantine_email": "secure_email", "delete_malicious_email": "defender_o365",
        "intune_device_action": "intune", "terminate_process": "defender_endpoint",
        "quarantine_file": "defender_endpoint", "remove_persistence": None, "remove_privileged_role": "entra",
    }


# ------------------------------------------------------ 3. real adapters --
def test_real_adapters_route_without_any_http_request():
    sent: list[httpx.Request] = []

    def refuse(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    names = ("cisco_xdr", "secure_endpoint", "secure_email", "umbrella", "meraki", "entra", "defender_endpoint",
             "defender_o365", "intune")
    settings = Settings.model_validate({"integrations": {n: {"enabled": True} for n in names}})
    registry = AdapterRegistry(settings, make_test_secrets(**FAKE_SECRETS), clock=FixedClock(FIXED_NOW),
                               transport_factory=lambda _name: httpx.MockTransport(refuse), sleep=lambda _s: None)
    ctx = make_context(ReadOnlyAdapters(registry), make_settings())
    routes = {name: builder(ctx, TARGETS[name], params=PARAMS.get(name), **KW).route
              for name, builder in CONTAINMENT_BUILDERS.items()}
    assert sent == []
    assert {name: route.integration for name, route in routes.items()} == {
        "isolate_secure_endpoint": "secure_endpoint", "isolate_defender_endpoint": "defender_endpoint",
        "block_domain_umbrella": "umbrella", "block_url": "umbrella", "block_ip": "meraki",
        "block_hash": "defender_endpoint", "revoke_entra_sessions": "entra", "disable_entra_user": "entra",
        "quarantine_email": "secure_email", "delete_malicious_email": "defender_o365",
        "intune_device_action": "intune", "remove_privileged_role": "entra",
        "terminate_process": None, "quarantine_file": None,      # UNVERIFIED with real adapters
        "remove_persistence": None,                              # no adapter at all
    }
    # no native configuration: cisco_xdr is considered, recorded and skipped, never guessed
    assert "cisco_xdr: no configured native action for secure_endpoint" in routes["isolate_secure_endpoint"].considered


# -------------------------------------------------- 4. native, real adapter --
def test_native_route_uses_only_the_read_listing_of_the_real_cisco_xdr_adapter():
    listing = {"data": [{"id": "se-isolate", "title": "Isolate", "module": "Secure Endpoint",
                         "module_instance_id": "mi-se-1",
                         "query-params": {"observable_type": "hostname", "observable_value": "TH-LT-1047"}}]}
    router = Router().add("POST", "/iroh/iroh-response/respond/observables", json_response(200, listing))
    native = {"isolate_endpoint": {"secure_endpoint": {"module": "Secure Endpoint", "action_id": "se-isolate"}}}
    settings = make_settings(native_actions=native)
    registry = AdapterRegistry(settings, make_test_secrets(**FAKE_SECRETS), clock=FixedClock(FIXED_NOW))
    registry.register(make_adapter("cisco_xdr", router, options=settings.integration("cisco_xdr").options))
    environment = SimulatedEnvironment(clock=FixedClock(FIXED_NOW))
    register_simulated_adapters(registry, environment)
    ctx = make_context(ReadOnlyAdapters(registry), settings)
    built = CONTAINMENT_BUILDERS["isolate_secure_endpoint"](ctx, "th-lt-1047", **KW)
    assert built.route.native and built.proposal.params["module_instance_id"] == "mi-se-1"
    assert [(r.method, r.url.path) for r in router.calls] == [("POST", "/iroh/iroh-response/respond/observables")]
    assert not any("trigger" in r.url.path for r in router.calls)
    assert environment.state_changing_calls() == []


def test_fake_facade_sees_only_routing_reads():
    adapters = FakeAdapters(enabled_names=("cisco_xdr", "secure_endpoint", "defender_endpoint", "umbrella",
                                           "meraki", "entra", "secure_email", "defender_o365", "intune"))
    _build_everything(make_context(adapters, make_settings(native_actions={
        t.value: {"secure_endpoint": {"module": "M", "action_id": "a"}} for t in CONTAINMENT_TYPES})))
    assert {name for name, _ in adapters.calls} <= {"executors", "native_response_actions"}


def test_no_operation_kind_other_than_read_is_possible_from_the_facade():
    # ReadOnlyAdapters exposes no adapter object and no execute path at all.
    exposed = {n for n in dir(ReadOnlyAdapters) if not n.startswith("_")}
    assert "execute" not in exposed and not exposed & STATE_CHANGING_METHODS
    assert OperationKind.STATE_CHANGING.value not in exposed
