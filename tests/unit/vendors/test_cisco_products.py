"""Secure Endpoint, Secure Email Threat Defense and Secure Malware Analytics adapters."""
from __future__ import annotations

from datetime import timedelta

import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.unit.vendors._helpers import Router, action_request, body_of, json_response, make_adapter, run_authorized
from xdr_response.errors import ApiError, InvalidTargetError
from xdr_response.integrations.secure_email import builders as etd
from xdr_response.integrations.secure_endpoint import builders as se
from xdr_response.integrations.secure_malware_analytics import builders as sma
from xdr_response.models import (
    ActionResultStatus,
    ActionType,
    InvestigationQuery,
    Observable,
    ObservableType,
    OperationKind,
    Verdict,
    VerificationStatus,
)

GUID = "a1b2c3d4-0000-0000-0000-000000000001"
MESSAGE = "msg-0001@example.test"


# ----------------------------------------------------------- Secure Endpoint --
def test_secure_endpoint_isolation_builders():
    put, delete = se.isolate(GUID), se.stop_isolation(GUID)
    assert (put.method, put.path, put.kind) == ("PUT", f"v1/computers/{GUID}/isolation", OperationKind.STATE_CHANGING)
    assert (delete.method, delete.path) == ("DELETE", f"v1/computers/{GUID}/isolation")


def test_secure_endpoint_isolate_and_release_send_documented_calls():
    router = Router().add("PUT", f"/v1/computers/{GUID}/isolation", json_response(200, {"data": {}}))
    router.add("DELETE", f"/v1/computers/{GUID}/isolation", json_response(200, {"data": {}}))
    # the connector GUID is confirmed to be the approved host before every write
    router.add("GET", f"/v1/computers/{GUID}",
               json_response(200, {"data": {"hostname": "TH-LT-1047", "connector_guid": GUID}}))
    adapter = make_adapter("secure_endpoint", router)
    isolate = action_request(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid=GUID)
    outcome = run_authorized(adapter, isolate)
    assert router.last().method == "PUT" and router.last().url.host == "api.amp.cisco.com"
    assert router.calls[0].method == "GET"  # identity lookup before the write
    assert outcome.status is ActionResultStatus.SUCCESS
    assert outcome.rollback_params == {"integration": "secure_endpoint", "connector_guid": GUID}
    release = action_request(ActionType.RELEASE_ENDPOINT, "secure_endpoint", connector_guid=GUID)
    assert run_authorized(adapter, release).rollback_params == {}
    assert router.last().method == "DELETE"
    assert adapter.verify(isolate, outcome).status is VerificationStatus.UNABLE_TO_VERIFY


def test_secure_endpoint_requires_the_approved_connector_guid():
    router = Router()
    adapter = make_adapter("secure_endpoint", router)
    with pytest.raises(InvalidTargetError, match="connector_guid"):
        run_authorized(adapter, action_request(ActionType.ISOLATE_ENDPOINT, "secure_endpoint"))
    assert router.calls == []


def test_secure_endpoint_reads():
    router = Router().add("GET", "/v1/computers", json_response(200, {"data": [
        {"hostname": "th-lt-1047", "connector_guid": GUID}, {"hostname": "other", "connector_guid": "x"}]}))
    router.add("GET", f"/v1/computers/{GUID}/trajectory",
               json_response(200, {"data": {"events": [{"id": 1}, {"id": 2}, {"id": 3}]}}))
    adapter = make_adapter("secure_endpoint", router)
    assert [c["connector_guid"] for c in adapter.find_computers("TH-LT-1047")] == [GUID]
    query = InvestigationQuery(action_type=ActionType.INVESTIGATE_ENDPOINT, limit=2,
                               subject=Observable(type=ObservableType.ENDPOINT_ID, value=GUID))
    assert adapter.investigate(query).findings == ({"id": 1}, {"id": 2})


# -------------------------------------------------------------- Secure Email --
def test_secure_email_move_builder():
    req = etd.move_messages([MESSAGE], "quarantine", "phishing")
    assert (req.method, req.path, req.operation) == ("POST", "v1/messages/move", "move_messages")
    assert req.json == {"ids": [MESSAGE], "folder": "quarantine", "verdict": "phishing"}
    assert etd.move_messages([MESSAGE], "inbox", "phishing").operation == "release_to_inbox"
    with pytest.raises(ValueError):
        etd.move_messages([f"m{i}" for i in range(101)], "quarantine", "spam")
    with pytest.raises(ValueError):
        etd.move_messages([MESSAGE], "deleted", "spam")
    assert etd.base_url_for("de") == "https://api.de.etd.cisco.com"


@pytest.mark.parametrize(("action", "folder"), [
    (ActionType.QUARANTINE_EMAIL, "quarantine"), (ActionType.DELETE_EMAIL, "trash"),
    (ActionType.RELEASE_EMAIL, "inbox"),
])
def test_secure_email_moves_to_the_documented_folder(action, folder):
    router = Router().add("POST", "/v1/messages/move", json_response(200, {"data": [{"queueSuccess": True}]}))
    adapter = make_adapter("secure_email", router)
    outcome = run_authorized(adapter, action_request(action, "secure_email", verdict="phishing"))
    assert body_of(router.last()) == {"ids": [MESSAGE], "folder": folder, "verdict": "phishing"}
    expected_rollback = {"integration": "secure_email", "message_ids": [MESSAGE], "verdict": "phishing"} \
        if action is ActionType.QUARANTINE_EMAIL else {}
    assert outcome.rollback_params == expected_rollback


def test_secure_email_reports_unqueued_messages():
    router = Router().add("POST", "/v1/messages/move",
                          json_response(200, {"data": [{"id": MESSAGE, "queueSuccess": False}]}))
    adapter = make_adapter("secure_email", router)
    with pytest.raises(ApiError, match="not queued"):
        run_authorized(adapter, action_request(ActionType.QUARANTINE_EMAIL, "secure_email", verdict="spam"))


def test_secure_email_verdict_is_mandatory():
    adapter = make_adapter("secure_email", Router())
    with pytest.raises(InvalidTargetError, match="verdict"):
        run_authorized(adapter, action_request(ActionType.QUARANTINE_EMAIL, "secure_email"))


@pytest.mark.parametrize(("body", "expected"), [
    ({"data": [{"messageId": MESSAGE, "actions": [{"action": "move to quarantine"}]}]}, VerificationStatus.VERIFIED),
    ({"data": [{"messageId": MESSAGE, "actions": [{"folder": "inbox"}]}]}, VerificationStatus.NOT_VERIFIED),
    ({"data": [{"actions": [{"folder": "quarantine"}, {"folder": "inbox"}]}]}, VerificationStatus.UNABLE_TO_VERIFY),
    ({"data": []}, VerificationStatus.UNABLE_TO_VERIFY),
])
def test_secure_email_verify_reads_message_status(body, expected):
    router = Router().add("POST", "/v1/messages/status", json_response(200, body))
    adapter = make_adapter("secure_email", router)
    request = action_request(ActionType.QUARANTINE_EMAIL, "secure_email", verdict="phishing")
    result = adapter.verify(request, None)
    assert result.status is expected and result.method == "message_status"
    assert body_of(router.last()) == {"ids": [MESSAGE]}


def test_secure_email_search_passes_the_caller_body():
    router = Router().add("POST", "/v1/messages/search", json_response(200, {"data": [{"id": "m1"}]}))
    adapter = make_adapter("secure_email", router)
    search = {"timestamp": ["2026-01-15T00:00:00Z", "2026-01-15T12:00:00Z"], "subject": "invoice"}
    query = InvestigationQuery(action_type=ActionType.SEARCH_EMAIL_CAMPAIGN, options={"search": search},
                               subject=Observable(type=ObservableType.EMAIL_MESSAGE_ID, value=MESSAGE))
    assert adapter.investigate(query).findings == ({"id": "m1"},)
    assert body_of(router.last()) == search


# --------------------------------------------------- Secure Malware Analytics --
def test_sma_feed_builder_uses_documented_query_parameters():
    req = sma.domain_ioc_feed(FIXED_NOW - timedelta(hours=1), FIXED_NOW)
    assert (req.method, req.path) == ("GET", "api/v2/iocs/feeds/domains")
    assert req.params == {"after": "2026-01-15T11:00:00Z", "before": "2026-01-15T12:00:00Z"}
    assert "api_key" not in req.params  # added by the auth provider, never by builders


def test_sma_enrich_domain_from_feed():
    feed = {"data": {"items": [{"domain": "bad.example.test", "sample": "s1"}, {"domain": "other.example.test"}]}}
    router = Router().add("GET", "/api/v2/iocs/feeds/domains", json_response(200, feed))
    adapter = make_adapter("secure_malware_analytics", router)
    result = adapter.enrich(Observable(type=ObservableType.DOMAIN, value="bad.example.test"))
    assert result.verdict is Verdict.MALICIOUS
    assert dict(router.last().url.params)["after"] == "2026-01-14T12:00:00Z"
    clean = adapter.enrich(Observable(type=ObservableType.DOMAIN, value="fine.example.test"))
    assert clean.verdict is Verdict.UNKNOWN and clean.risk_score == 0


def test_secure_endpoint_refuses_a_connector_guid_of_another_host():
    router = Router().add("GET", f"/v1/computers/{GUID}",
                          json_response(200, {"data": {"hostname": "TH-DC-02", "connector_guid": GUID}}))
    adapter = make_adapter("secure_endpoint", router)
    with pytest.raises(InvalidTargetError, match="not the approved target"):
        run_authorized(adapter, action_request(ActionType.ISOLATE_ENDPOINT, "secure_endpoint", connector_guid=GUID))
    assert [c.method for c in router.calls] == ["GET"]
