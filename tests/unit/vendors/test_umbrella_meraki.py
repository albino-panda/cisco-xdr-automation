"""Umbrella destination lists and Meraki client policy / MX L3 firewall adapters."""
from __future__ import annotations

import pytest

from tests.unit.vendors._helpers import Router, action_request, body_of, json_response, make_adapter, run_authorized
from xdr_response.errors import InvalidTargetError
from xdr_response.integrations.meraki import builders as meraki
from xdr_response.integrations.meraki.adapter import rule_tag
from xdr_response.integrations.umbrella import builders as umbrella
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    Observable,
    ObservableType,
    OperationKind,
    TargetState,
    Verdict,
    VerificationStatus,
)

LIST = "/policies/v2/destinationlists/17/destinations"
DOMAIN = "bad.example.test"


def _destinations(*entries: tuple[int, str]):
    return json_response(200, {"status": {"code": 200}, "data": [{"id": i, "destination": d} for i, d in entries]})


# ------------------------------------------------------------------- Umbrella --
def test_umbrella_builders_match_documentation():
    add = umbrella.add_destinations(17, [DOMAIN], "xdr-response key")
    assert (add.method, add.path, add.kind) == ("POST", "policies/v2/destinationlists/17/destinations",
                                                OperationKind.STATE_CHANGING)
    assert add.json == [{"destination": DOMAIN, "comment": "xdr-response key"}]
    remove = umbrella.remove_destinations(17, ["9001"])
    assert (remove.method, remove.json) == ("DELETE", [9001])
    assert remove.path == "policies/v2/destinationlists/17/destinations/remove"
    assert umbrella.domain_categorization(DOMAIN).path == f"investigate/v2/domains/categorization/{DOMAIN}"
    with pytest.raises(ValueError):
        umbrella.add_destinations(17, ["x"] * 501, "c")


def test_umbrella_block_reads_adds_and_records_destination_id():
    router = Router().add("GET", LIST, _destinations(), _destinations((9001, DOMAIN)))
    router.add("POST", LIST, json_response(200, {"status": {"code": 200}}))
    adapter = make_adapter("umbrella", router)
    request = action_request(ActionType.BLOCK_DOMAIN, "umbrella", destination_list_id="17")
    outcome = run_authorized(adapter, request)
    assert [c.method for c in router.calls] == ["GET", "POST", "GET"]
    assert body_of(router.calls[1]) == [{"destination": DOMAIN, "comment": f"xdr-response {request.idempotency_key}"}]
    assert outcome.status is ActionResultStatus.SUCCESS
    assert outcome.rollback_params == {"integration": "umbrella", "destination_list_id": "17", "destination_id": "9001"}


def test_umbrella_block_is_idempotent():
    router = Router().add("GET", LIST, _destinations((9001, DOMAIN)))
    adapter = make_adapter("umbrella", router)
    request = action_request(ActionType.BLOCK_DOMAIN, "umbrella", destination_list_id="17")
    assert run_authorized(adapter, request).status is ActionResultStatus.ALREADY_CONTAINED
    assert [c.method for c in router.calls] == ["GET"]
    assert adapter.current_state(request).state is TargetState.IN_DESIRED_STATE


def test_umbrella_unblock_removes_by_id_and_verifies():
    router = Router().add("DELETE", f"{LIST}/remove", json_response(200, {}))
    router.add("GET", LIST, _destinations())
    adapter = make_adapter("umbrella", router)
    request = action_request(ActionType.UNBLOCK_DOMAIN, "umbrella", destination_list_id="17", destination_id="9001")
    assert run_authorized(adapter, request).status is ActionResultStatus.SUCCESS
    assert router.calls[0].method == "DELETE" and body_of(router.calls[0]) == [9001]
    verification = adapter.verify(request, None)
    assert verification.status is VerificationStatus.VERIFIED and verification.method == "list_destinations"


def test_umbrella_unblock_without_id_looks_it_up_or_reports_already_released():
    router = Router().add("GET", LIST, _destinations())
    adapter = make_adapter("umbrella", router)
    request = action_request(ActionType.UNBLOCK_URL, "umbrella", target="https://bad.example.test/payload",
                             destination_list_id="17")
    assert run_authorized(adapter, request).status is ActionResultStatus.ALREADY_CONTAINED


def test_umbrella_block_needs_a_list():
    adapter = make_adapter("umbrella", Router())
    with pytest.raises(InvalidTargetError, match="destination_list_id"):
        run_authorized(adapter, action_request(ActionType.BLOCK_DOMAIN, "umbrella"))


def test_umbrella_verify_not_verified_when_missing():
    router = Router().add("GET", LIST, _destinations())
    adapter = make_adapter("umbrella", router)
    request = action_request(ActionType.BLOCK_DOMAIN, "umbrella", destination_list_id="17")
    assert adapter.verify(request, None).status is VerificationStatus.NOT_VERIFIED


@pytest.mark.parametrize(("status", "verdict"), [(-1, Verdict.MALICIOUS), (0, Verdict.UNKNOWN), (1, Verdict.CLEAN)])
def test_umbrella_categorization_enrichment(status, verdict):
    router = Router().add("GET", f"/investigate/v2/domains/categorization/{DOMAIN}",
                          json_response(200, {DOMAIN: {"status": status, "security_categories": []}}))
    result = make_adapter("umbrella", router).enrich(Observable(type=ObservableType.DOMAIN, value=DOMAIN))
    assert result.verdict is verdict


# --------------------------------------------------------------------- Meraki --
POLICY = "/api/v1/networks/N_0001/clients/k74272e/policy"
L3 = "/api/v1/networks/N_0001/appliance/firewall/l3FirewallRules"
EXISTING = {"comment": "allow dns", "policy": "allow", "protocol": "udp", "srcPort": "Any", "srcCidr": "Any",
            "destPort": "53", "destCidr": "198.51.100.53/32"}
DEFAULT = {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcPort": "Any", "srcCidr": "Any",
           "destPort": "Any", "destCidr": "Any"}


def test_meraki_builders():
    put = meraki.update_client_policy("N_1", "c1", "Group policy", "101")
    assert (put.method, put.path, put.json) == ("PUT", "networks/N_1/clients/c1/policy",
                                                {"devicePolicy": "Group policy", "groupPolicyId": "101"})
    with pytest.raises(ValueError):
        meraki.update_client_policy("N_1", "c1", "Group policy")
    with pytest.raises(ValueError):
        meraki.update_client_policy("N_1", "c1", "Quarantined")
    assert meraki.search_clients("O_1", "aa:bb:cc:dd:ee:ff").params == {"mac": "aa:bb:cc:dd:ee:ff"}


def test_meraki_block_client_captures_previous_policy():
    router = Router().add("GET", POLICY, json_response(200, {"devicePolicy": "Group policy", "groupPolicyId": "101"}))
    router.add("PUT", POLICY, json_response(200, {"devicePolicy": "Blocked"}))
    adapter = make_adapter("meraki", router)
    request = action_request(ActionType.BLOCK_NETWORK_CLIENT, "meraki", network_id="N_0001")
    outcome = run_authorized(adapter, request)
    assert body_of(router.last()) == {"devicePolicy": "Blocked"}
    assert outcome.rollback_params == {"integration": "meraki", "network_id": "N_0001", "client_id": "k74272e",
                                       "previous_device_policy": "Group policy", "previous_group_policy_id": "101"}


def test_meraki_restore_client_policy_and_verify():
    router = Router().add("GET", POLICY, json_response(200, {"devicePolicy": "Blocked"}),
                          json_response(200, {"devicePolicy": "Group policy", "groupPolicyId": "101"}))
    router.add("PUT", POLICY, json_response(200, {}))
    adapter = make_adapter("meraki", router)
    request = action_request(ActionType.RESTORE_NETWORK_CLIENT, "meraki", network_id="N_0001",
                             previous_device_policy="Group policy", previous_group_policy_id="101")
    assert run_authorized(adapter, request).status is ActionResultStatus.SUCCESS
    assert body_of(router.calls[1]) == {"devicePolicy": "Group policy", "groupPolicyId": "101"}
    assert adapter.verify(request, None).status is VerificationStatus.VERIFIED


def test_meraki_block_ip_inserts_one_tagged_rule_and_never_writes_the_default_rule():
    router = Router().add("GET", L3, json_response(200, {"rules": [EXISTING, DEFAULT]}))
    router.add("PUT", L3, json_response(200, {}))
    adapter = make_adapter("meraki", router)
    request = action_request(ActionType.BLOCK_IP, "meraki", network_id="N_0001")
    outcome = run_authorized(adapter, request)
    written = body_of(router.last())["rules"]
    assert written == [meraki.deny_rule("203.0.113.10/32", rule_tag(request.idempotency_key)), EXISTING]
    assert outcome.rollback_params == {"integration": "meraki", "network_id": "N_0001",
                                       "rule_comment": rule_tag(request.idempotency_key)}


def test_meraki_block_ip_is_idempotent_and_verified():
    request = action_request(ActionType.BLOCK_IP, "meraki", network_id="N_0001")
    tagged = meraki.deny_rule("203.0.113.10/32", rule_tag(request.idempotency_key))
    router = Router().add("GET", L3, json_response(200, {"rules": [tagged, EXISTING, DEFAULT]}))
    adapter = make_adapter("meraki", router)
    assert run_authorized(adapter, request).status is ActionResultStatus.ALREADY_CONTAINED
    assert [c.method for c in router.calls] == ["GET"]
    assert adapter.verify(request, None).status is VerificationStatus.VERIFIED


def test_meraki_unblock_ip_removes_exactly_the_tagged_rule():
    control_key = "XDR-83921:block_ip:203.0.113.10"
    tagged = meraki.deny_rule("203.0.113.10/32", rule_tag(control_key))
    other = meraki.deny_rule("203.0.113.10/32", rule_tag("XDR-00001:block_ip:203.0.113.10"))
    router = Router().add("GET", L3, json_response(200, {"rules": [tagged, other, EXISTING, DEFAULT]}))
    router.add("PUT", L3, json_response(200, {}))
    adapter = make_adapter("meraki", router)
    request = action_request(ActionType.UNBLOCK_IP, "meraki", network_id="N_0001", restores=control_key)
    assert run_authorized(adapter, request).status is ActionResultStatus.SUCCESS
    assert body_of(router.last())["rules"] == [other, EXISTING]


def test_meraki_unblock_ip_absent_rule_is_already_released():
    router = Router().add("GET", L3, json_response(200, {"rules": [EXISTING, DEFAULT]}))
    adapter = make_adapter("meraki", router)
    request = action_request(ActionType.UNBLOCK_IP, "meraki", network_id="N_0001",
                             rule_comment="xdr-response XDR-83921:block_ip:203.0.113.10")
    assert run_authorized(adapter, request).status is ActionResultStatus.ALREADY_CONTAINED
    assert [c.method for c in router.calls] == ["GET"]
