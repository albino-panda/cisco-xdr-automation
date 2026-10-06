"""Defender for Endpoint, Defender for Office 365, Intune and Graph Security adapters."""
from __future__ import annotations

import pytest

from tests.fixtures.factories import FAKE_SHA256
from tests.unit.vendors._helpers import Router, action_request, body_of, json_response, make_adapter, run_authorized
from xdr_response.errors import InvalidTargetError
from xdr_response.integrations.defender_endpoint import builders as mde
from xdr_response.integrations.defender_endpoint.adapter import indicator_type_for
from xdr_response.integrations.defender_o365 import builders as o365
from xdr_response.integrations.microsoft_cloud import builders as mcloud
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    InvestigationQuery,
    Observable,
    ObservableType,
    OperationKind,
    TargetKind,
    VerificationStatus,
)

MACHINE = "0000000000000000000000000000000000001047"
REMEDIATE = "/beta/security/collaboration/analyzedEmails/remediate"
MESSAGE = "msg-0001@example.test"


# -------------------------------------------------------- Defender for Endpoint --
def test_mde_builders_match_documentation():
    iso = mde.isolate(MACHINE, "c", "Selective")
    assert (iso.method, iso.path, iso.json) == ("POST", f"machines/{MACHINE}/isolate",
                                                {"Comment": "c", "IsolationType": "Selective"})
    assert mde.unisolate(MACHINE, "c").json == {"Comment": "c"}
    assert mde.list_machine_actions(MACHINE).params == {"$filter": f"machineId eq '{MACHINE}'"}
    ind = mde.submit_indicator(FAKE_SHA256, "FileSha256", "Block", "t", "d")
    assert ind.json == {"indicatorValue": FAKE_SHA256, "indicatorType": "FileSha256", "action": "Block",
                        "title": "t", "description": "d"}
    assert "expirationTime" not in ind.json
    assert mde.delete_indicator("42").method == "DELETE"
    with pytest.raises(ValueError):
        mde.isolate(MACHINE, "c", "Partial")


@pytest.mark.parametrize(("kind", "value", "expected"), [
    (TargetKind.HASH, "a" * 64, "FileSha256"), (TargetKind.HASH, "a" * 40, "FileSha1"),
    (TargetKind.HASH, "a" * 32, "FileMd5"), (TargetKind.IP, "203.0.113.10", "IpAddress"),
    (TargetKind.DOMAIN, "bad.example.test", "DomainName"), (TargetKind.URL, "https://bad.example.test/", "Url"),
])
def test_mde_indicator_types(kind, value, expected):
    assert indicator_type_for(kind, value) == expected


def test_mde_isolate_records_machine_action_and_verifies_it():
    router = Router().add("POST", f"/api/machines/{MACHINE}/isolate", json_response(201, {"id": "ma-1"}))
    router.add("GET", "/api/machineactions/ma-1", json_response(200, {"id": "ma-1", "status": "Succeeded"}))
    router.add("GET", f"/api/machines/{MACHINE}", json_response(200, {"id": MACHINE, "computerDnsName": "th-lt-1047.corp.example.test"}))
    adapter = make_adapter("defender_endpoint", router)
    request = action_request(ActionType.ISOLATE_ENDPOINT, "defender_endpoint", machine_id=MACHINE)
    outcome = run_authorized(adapter, request)
    assert router.calls[0].method == "GET"  # machine id confirmed to be the approved host first
    assert router.calls[1].url.host == "api.security.microsoft.com"
    assert body_of(router.calls[1]) == {"Comment": f"xdr-response {request.idempotency_key}", "IsolationType": "Full"}
    assert outcome.external_ref == "ma-1"
    assert outcome.rollback_params == {"integration": "defender_endpoint", "machine_id": MACHINE}
    assert adapter.verify(request, outcome).status is VerificationStatus.VERIFIED


def test_mde_pending_machine_action_is_unable_to_verify():
    router = Router().add("POST", f"/api/machines/{MACHINE}/isolate", json_response(201, {"id": "ma-1"}))
    router.add("GET", "/api/machineactions/ma-1", json_response(200, {"status": "Pending"}))
    router.add("GET", f"/api/machines/{MACHINE}", json_response(200, {"id": MACHINE, "computerDnsName": "th-lt-1047.corp.example.test"}))
    adapter = make_adapter("defender_endpoint", router)
    request = action_request(ActionType.ISOLATE_ENDPOINT, "defender_endpoint", machine_id=MACHINE)
    outcome = run_authorized(adapter, request)
    result = adapter.verify(request, outcome)
    assert result.status is VerificationStatus.UNABLE_TO_VERIFY and "Pending" in result.details


def test_mde_repeat_unisolate_maps_to_already_contained():
    router = Router().add("POST", f"/api/machines/{MACHINE}/unisolate",
                          json_response(400, {"error": {"code": "ActiveRequestAlreadyExists",
                                                        "message": "Action is already in progress"}}))
    router.add("GET", f"/api/machines/{MACHINE}", json_response(200, {"id": MACHINE, "computerDnsName": "th-lt-1047.corp.example.test"}))
    adapter = make_adapter("defender_endpoint", router)
    request = action_request(ActionType.RELEASE_ENDPOINT, "defender_endpoint", machine_id=MACHINE)
    assert run_authorized(adapter, request).status is ActionResultStatus.ALREADY_CONTAINED


def test_mde_other_400_is_invalid_target():
    router = Router().add("POST", f"/api/machines/{MACHINE}/isolate",
                          json_response(400, {"error": {"message": "Machine not onboarded"}}))
    router.add("GET", f"/api/machines/{MACHINE}", json_response(200, {"id": MACHINE, "computerDnsName": "th-lt-1047.corp.example.test"}))
    adapter = make_adapter("defender_endpoint", router)
    request = action_request(ActionType.ISOLATE_ENDPOINT, "defender_endpoint", machine_id=MACHINE)
    with pytest.raises(InvalidTargetError, match="not onboarded"):
        run_authorized(adapter, request)


def test_mde_block_hash_submits_indicator_without_vendor_expiry():
    router = Router().add("POST", "/api/indicators", json_response(200, {"id": 42}))
    adapter = make_adapter("defender_endpoint", router)
    request = action_request(ActionType.BLOCK_HASH, "defender_endpoint", expiration_time="2026-02-01T00:00:00Z")
    outcome = run_authorized(adapter, request)
    sent = body_of(router.last())
    assert sent["indicatorValue"] == FAKE_SHA256 and sent["indicatorType"] == "FileSha256"
    assert sent["action"] == "Block" and "expirationTime" not in sent
    assert outcome.rollback_params == {"integration": "defender_endpoint", "indicator_id": "42"}
    assert adapter.verify(request, outcome).status is VerificationStatus.UNABLE_TO_VERIFY


def test_mde_vendor_expiry_only_with_explicit_option():
    router = Router().add("POST", "/api/indicators", json_response(200, {"id": 43}))
    adapter = make_adapter("defender_endpoint", router, options={"allow_vendor_expiry": True})
    request = action_request(ActionType.BLOCK_IP, "defender_endpoint", expiration_time="2026-02-01T00:00:00Z")
    run_authorized(adapter, request)
    assert body_of(router.last())["expirationTime"] == "2026-02-01T00:00:00Z"


@pytest.mark.parametrize(("status", "expected"), [(204, ActionResultStatus.SUCCESS),
                                                  (404, ActionResultStatus.ALREADY_CONTAINED)])
def test_mde_unblock_deletes_indicator_by_id(status, expected):
    router = Router().add("DELETE", "/api/indicators/42", json_response(status))
    adapter = make_adapter("defender_endpoint", router)
    request = action_request(ActionType.UNBLOCK_DOMAIN, "defender_endpoint", indicator_id="42")
    assert run_authorized(adapter, request).status is expected


# ---------------------------------------------------- Defender for Office 365 --
def test_o365_builder_sets_prefer_header_only_for_quarantine():
    emails = [{"networkMessageId": MESSAGE, "recipientEmailAddress": "j.doe@example.com"}]
    req = o365.remediate("moveToQuarantine", emails, display_name="n", description="d")
    assert req.headers == {"Prefer": "include-unknown-enum-members"} and req.kind is OperationKind.STATE_CHANGING
    assert o365.remediate("softDelete", emails, display_name="n", description="d").headers is None
    with pytest.raises(ValueError, match="hardDelete"):
        o365.remediate("hardDelete", emails, display_name="n", description="d")


@pytest.mark.parametrize(("action", "vendor_action"), [
    (ActionType.QUARANTINE_EMAIL, "moveToQuarantine"), (ActionType.DELETE_EMAIL, "softDelete"),
    (ActionType.RELEASE_EMAIL, "moveToInbox"),
])
def test_o365_remediation_requests(action, vendor_action):
    location = {"Location": "https://security.example.test/a"}
    router = Router().add("POST", REMEDIATE, json_response(202, headers=location))
    adapter = make_adapter("defender_o365", router)
    request = action_request(action, "defender_o365", recipient="j.doe@example.com")
    outcome = run_authorized(adapter, request)
    sent = router.last()
    assert sent.url.host == "graph.microsoft.com"
    body = body_of(sent)
    assert body["action"] == vendor_action and body["remediateSendersCopy"] is False
    assert body["analyzedEmails"] == [{"networkMessageId": MESSAGE, "recipientEmailAddress": "j.doe@example.com"}]
    assert ("prefer" in sent.headers) is (vendor_action == "moveToQuarantine")
    assert outcome.external_ref == "https://security.example.test/a"
    assert adapter.verify(request, outcome).status is VerificationStatus.UNABLE_TO_VERIFY


def test_o365_refuses_hard_delete():
    adapter = make_adapter("defender_o365", Router())
    request = action_request(ActionType.DELETE_EMAIL, "defender_o365", recipient="j.doe@example.com",
                             delete_action="hardDelete")
    with pytest.raises(InvalidTargetError, match="delete_action"):
        run_authorized(adapter, request)


# --------------------------------------------------------------------- Intune --
def test_intune_remote_lock():
    router = Router().add("POST", "/v1.0/deviceManagement/managedDevices/md-0001/remoteLock", json_response(204))
    router.add("GET", "/v1.0/deviceManagement/managedDevices/md-0001", json_response(200, {"deviceName": "TH-LT-1047"}))
    adapter = make_adapter("intune", router)
    request = action_request(ActionType.LOCK_DEVICE, "intune", managed_device_id="md-0001")
    outcome = run_authorized(adapter, request)
    assert outcome.status is ActionResultStatus.SUCCESS and outcome.rollback_params == {}
    assert router.last().content == b""
    assert adapter.verify(request, outcome).status is VerificationStatus.UNABLE_TO_VERIFY


def test_intune_enrich_reads_managed_device():
    router = Router().add("GET", "/v1.0/deviceManagement/managedDevices/md-0001",
                          json_response(200, {"deviceName": "TH-LT-1047", "complianceState": "noncompliant"}))
    result = make_adapter("intune", router).enrich(Observable(type=ObservableType.ENDPOINT_ID, value="md-0001"))
    assert result.evidence[0].data["complianceState"] == "noncompliant"


# ------------------------------------------------------------ Graph Security --
def test_hunting_query_builder_and_investigation():
    req = mcloud.run_hunting_query("DeviceEvents | take 1", "P1D")
    assert (req.method, req.path, req.json) == ("POST", "v1.0/security/runHuntingQuery",
                                                {"Query": "DeviceEvents | take 1", "Timespan": "P1D"})
    router = Router().add("POST", "/v1.0/security/runHuntingQuery", json_response(200, {"results": [{"a": 1}]}))
    query = InvestigationQuery(action_type=ActionType.SEARCH_HASH_ENTERPRISE, options={"kql": "DeviceEvents"},
                               subject=Observable(type=ObservableType.SHA256, value=FAKE_SHA256))
    assert make_adapter("microsoft_cloud", router).investigate(query).findings == ({"a": 1},)


def test_alert_investigation_keeps_alerts_mentioning_the_subject():
    alerts = {"value": [{"id": "a1", "evidence": [{"deviceDnsName": "th-lt-1047"}]}, {"id": "a2"}]}
    router = Router().add("GET", "/v1.0/security/alerts_v2", json_response(200, alerts))
    query = InvestigationQuery(action_type=ActionType.INVESTIGATE_ENDPOINT,
                               subject=Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"))
    result = make_adapter("microsoft_cloud", router).investigate(query)
    assert [f["id"] for f in result.findings] == ["a1"]


def test_mde_and_intune_refuse_params_naming_another_device():
    router = Router().add("GET", f"/api/machines/{MACHINE}", json_response(200, {"computerDnsName": "th-dc-02.corp.example.test"}))
    router.add("GET", "/v1.0/deviceManagement/managedDevices/md-0001", json_response(200, {"deviceName": "TH-DC-02"}))
    mde = make_adapter("defender_endpoint", router)
    with pytest.raises(InvalidTargetError, match="not the approved target"):
        run_authorized(mde, action_request(ActionType.ISOLATE_ENDPOINT, "defender_endpoint", machine_id=MACHINE))
    intune = make_adapter("intune", router)
    with pytest.raises(InvalidTargetError, match="not the approved target"):
        run_authorized(intune, action_request(ActionType.LOCK_DEVICE, "intune", managed_device_id="md-0001"))
    assert all(c.method == "GET" for c in router.calls)
