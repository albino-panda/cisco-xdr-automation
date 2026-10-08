"""choose_route: native first, product pinning, direct fallback, unrouted, determinism (14.1.7)."""
from __future__ import annotations

import pytest

from tests.unit.atomics.containment._support import FAKE_SHA256, FakeAdapters, NativeAction, make_context, make_settings
from xdr_response.atomics.containment import NATIVE_OBSERVABLE_TYPES, RouteDecision, choose_route
from xdr_response.errors import IntegrationUnavailableError
from xdr_response.models import ActionType, ObservableType, TargetKind

ISOLATE_NATIVE = {"isolate_endpoint": {"secure_endpoint": {"module": "Secure Endpoint", "action_id": "se-isolate"},
                                       "defender_endpoint": {"module": "Defender", "action_id": "mde-isolate"}}}
EDR = ("cisco_xdr", "secure_endpoint", "defender_endpoint")


def _ctx(enabled=EDR, native=(), native_actions=None, listing_error=None):
    adapters = FakeAdapters(enabled_names=enabled, native=native, listing_error=listing_error)
    return make_context(adapters, make_settings(native_actions=native_actions)), adapters


def test_native_route_when_exactly_one_configured_action_is_offered():
    ctx, adapters = _ctx(native=[NativeAction("mi-se-1", "se-isolate"), NativeAction("mi-se-1", "se-scan")],
                         native_actions=ISOLATE_NATIVE)
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, " th-lt-1047 ", product="secure_endpoint")
    assert route.integration == "cisco_xdr" and route.native and route.product == "secure_endpoint"
    assert route.params == {"integration": "cisco_xdr", "module_instance_id": "mi-se-1", "action_id": "se-isolate",
                            "observable_type": "hostname", "observable_value": "TH-LT-1047",
                            "verify_integration": "secure_endpoint"}
    observable, module = adapters.calls[1][1]
    assert (observable.type, observable.value, module) == (ObservableType.HOSTNAME, "TH-LT-1047", "Secure Endpoint")


def test_native_landing_defaults_to_first_non_native_candidate():
    ctx, _ = _ctx(native=[NativeAction("mi-mde", "mde-isolate")], native_actions=ISOLATE_NATIVE)
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047")
    # catalog order: cisco_xdr, defender_endpoint, secure_endpoint
    assert route.native and route.params["verify_integration"] == "defender_endpoint"


@pytest.mark.parametrize(("native", "fragment"), [
    ((), "se-isolate for secure_endpoint not offered"),
    ((NativeAction("mi-1", "se-isolate"), NativeAction("mi-2", "se-isolate")),
     "se-isolate for secure_endpoint ambiguous (2 module instances)"),
])
def test_native_none_or_several_falls_back_to_direct(native, fragment):
    ctx, _ = _ctx(native=native, native_actions=ISOLATE_NATIVE)
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert (route.integration, route.native, route.params) == ("secure_endpoint", False,
                                                                {"integration": "secure_endpoint"})
    assert any(fragment in line for line in route.considered)


def test_duplicate_listing_of_one_instance_is_not_ambiguous():
    ctx, _ = _ctx(native=[NativeAction("mi-1", "se-isolate")] * 2, native_actions=ISOLATE_NATIVE)
    assert choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint").native


def test_no_native_configuration_is_recorded_and_falls_back():
    ctx, adapters = _ctx(native=[NativeAction("mi-1", "se-isolate")])
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert route.integration == "secure_endpoint" and not route.native
    assert "cisco_xdr: no configured native action for secure_endpoint" in route.considered
    assert [c[0] for c in adapters.calls] == ["executors"]  # the router never guesses an action id


@pytest.mark.parametrize("entry", [{"module": "Secure Endpoint"}, {"action_id": "x"}, "se-isolate",
                                   {"module": " ", "action_id": "x"}, {"module": "m", "action_id": 7}])
def test_invalid_native_configuration_falls_back(entry):
    ctx, _ = _ctx(native_actions={"isolate_endpoint": {"secure_endpoint": entry}})
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert route.integration == "secure_endpoint"
    assert any("invalid native action configuration for secure_endpoint" in c for c in route.considered)


def test_listing_error_is_recorded_without_detail_and_falls_back():
    ctx, _ = _ctx(native_actions=ISOLATE_NATIVE,
                  listing_error=IntegrationUnavailableError("down: secret-ish detail", integration="cisco_xdr"))
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert route.integration == "secure_endpoint"
    assert "cisco_xdr: native action listing failed (IntegrationUnavailableError)" in route.considered
    assert not any("secret-ish" in c for c in route.considered)


def test_pinned_product_is_never_silently_switched():
    ctx, _ = _ctx(enabled=("defender_endpoint",))
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert route.integration is None and route.params == {} and route.product == "secure_endpoint"
    assert route.reason == "no enabled adapter has a VERIFIED write for isolate_endpoint"
    assert "secure_endpoint: not enabled or no VERIFIED write for isolate_endpoint" in route.considered
    assert "defender_endpoint: not eligible (pinned to secure_endpoint)" in route.considered


def test_native_can_land_on_a_pinned_product_that_is_not_directly_enabled():
    ctx, _ = _ctx(enabled=("cisco_xdr",), native=[NativeAction("mi-1", "se-isolate")], native_actions=ISOLATE_NATIVE)
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert route.native and route.params["verify_integration"] == "secure_endpoint"


def test_only_cisco_xdr_enabled_without_product_is_unrouted():
    ctx, _ = _ctx(enabled=("cisco_xdr",), native=[NativeAction("mi-1", "x")])
    route = choose_route(ctx, ActionType.BLOCK_URL, "https://bad.example.test/payload")
    assert route.integration is None
    assert "cisco_xdr: no product to land a native block_url on" in route.considered


def test_direct_catalog_order_without_native():
    ctx, _ = _ctx(enabled=("umbrella", "defender_endpoint"))
    route = choose_route(ctx, ActionType.BLOCK_URL, "https://bad.example.test/payload")
    assert route.integration == "umbrella" and route.product == "umbrella"
    assert route.considered == ("cisco_xdr: not an enabled executor for block_url", "umbrella: direct block_url")


def test_nothing_enabled_is_unrouted_with_documented_reason():
    ctx, _ = _ctx(enabled=())
    route = choose_route(ctx, ActionType.REMOVE_PERSISTENCE, "TH-LT-1047/run-key-0001")
    assert route.integration is None and not route.native
    assert route.reason == "no enabled adapter has a VERIFIED write for remove_persistence"


@pytest.mark.parametrize(("action", "target", "ctim", "otype"), [
    (ActionType.BLOCK_IP, "2001:DB8::10", "ipv6", ObservableType.IPV6),
    (ActionType.BLOCK_IP, "203.0.113.10", "ip", ObservableType.IP),
    (ActionType.BLOCK_HASH, FAKE_SHA256.upper(), "sha256", ObservableType.SHA256),
    (ActionType.BLOCK_HASH, "b" * 40, "sha1", ObservableType.SHA1),
    (ActionType.BLOCK_HASH, "c" * 32, "md5", ObservableType.MD5),
    (ActionType.QUARANTINE_EMAIL, "msg-0001@example.test", "email_messageid", ObservableType.EMAIL_MESSAGE_ID),
    (ActionType.DISABLE_USER, "J.Doe@Example.com", "user", ObservableType.USER),
])
def test_native_observable_type_follows_the_target(action, target, ctim, otype):
    landing = {"block_ip": "defender_endpoint", "block_hash": "defender_endpoint",
               "quarantine_email": "secure_email", "disable_user": "entra"}[action.value]
    native = {action.value: {landing: {"module": "M", "action_id": "act"}}}
    ctx, adapters = _ctx(enabled=("cisco_xdr", landing), native=[NativeAction("mi-1", "act")], native_actions=native)
    route = choose_route(ctx, action, target)
    assert route.native and route.params["observable_type"] == ctim
    observable, _ = adapters.calls[-1][1]
    assert observable.type is otype and observable.value == route.params["observable_value"]


def test_native_observable_type_table_matches_the_contract():
    assert dict(NATIVE_OBSERVABLE_TYPES) == {
        TargetKind.ENDPOINT: "hostname", TargetKind.DOMAIN: "domain", TargetKind.URL: "url", TargetKind.IP: "ip",
        TargetKind.HASH: "sha256", TargetKind.USER: "user", TargetKind.EMAIL_MESSAGE: "email_messageid"}


@pytest.mark.parametrize(("action", "kwargs"), [
    (ActionType.RELEASE_ENDPOINT, {}), (ActionType.ENRICH_IP, {}), (ActionType.INVESTIGATE_USER, {}),
    (ActionType.ADD_INCIDENT_NOTE, {}),
    (ActionType.ISOLATE_ENDPOINT, {"product": "cisco_xdr"}), (ActionType.ISOLATE_ENDPOINT, {"product": "umbrella"}),
    (ActionType.ISOLATE_ENDPOINT, {"product": "not-a-product"}),
])
def test_invalid_requests_raise_value_error(action, kwargs):
    ctx, adapters = _ctx()
    with pytest.raises(ValueError):
        choose_route(ctx, action, "TH-LT-1047", **kwargs)
    assert adapters.calls == []


def test_routing_is_deterministic():
    ctx, _ = _ctx(native=[NativeAction("mi-1", "se-isolate")], native_actions=ISOLATE_NATIVE)
    first = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert all(choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "th-lt-1047", product="secure_endpoint") == first
               for _ in range(5))


def test_route_decision_validators():
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.BLOCK_IP, integration=None)  # no reason
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.BLOCK_IP, integration="meraki", params={"integration": "umbrella"})
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.BLOCK_IP, integration="meraki", native=True,
                      params={"integration": "meraki"})
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.UNBLOCK_IP, integration="meraki", params={"integration": "meraki"})
    with pytest.raises(ValueError):
        RouteDecision(action_type=ActionType.BLOCK_IP, integration=None, reason="x", params={"integration": "m"})


def test_documented_native_actions_example_parses_and_routes():
    """The commented ``native_actions`` example in config/integrations.example.yaml is valid config."""
    from pathlib import Path

    import yaml

    text = (Path(__file__).resolve().parents[4] / "config" / "integrations.example.yaml").read_text(encoding="utf-8")
    lines = text.splitlines()
    start = lines.index("    # options:")
    block = []
    for line in lines[start:]:
        if not line.startswith("    #"):
            break
        block.append(line.replace("    # ", "", 1))
    options = yaml.safe_load("\n".join(block))["options"]
    assert "isolate_endpoint" in options["native_actions"]
    entry = options["native_actions"]["isolate_endpoint"]["secure_endpoint"]
    ctx, _ = _ctx(native=[NativeAction("mi-1", entry["action_id"])], native_actions=options["native_actions"])
    route = choose_route(ctx, ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", product="secure_endpoint")
    assert route.native and route.params["action_id"] == entry["action_id"]
