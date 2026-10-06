"""Cisco XDR adapter: request builders and native response flow against httpx.MockTransport."""
from __future__ import annotations

import pytest

from tests.unit.vendors._helpers import Router, action_request, body_of, json_response, make_adapter, run_authorized
from xdr_response.errors import ApiError, InvalidTargetError
from xdr_response.integrations.cisco_xdr import NativeResponseAction, builders
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

TRIGGER = "/iroh/iroh-response/respond/trigger/mi-0001/isolate-host"
NATIVE = {"module_instance_id": "mi-0001", "action_id": "isolate-host", "observable_type": "hostname",
          "verify_integration": "defender_endpoint"}
DOMAIN = Observable(type=ObservableType.DOMAIN, value="bad.example.test")


def test_trigger_builder_matches_documented_request():
    req = builders.respond_trigger("mi/0001", "act-1", "hostname", "TH-LT-1047")
    assert (req.method, req.kind, req.operation) == ("POST", OperationKind.STATE_CHANGING, "trigger_response_action")
    assert req.path == "iroh/iroh-response/respond/trigger/mi%2F0001/act-1"  # targets cannot inject path segments
    assert req.params == {"observable_type": "hostname", "observable_value": "TH-LT-1047"}


def test_enrich_and_respond_builders():
    assert builders.deliberate([DOMAIN]).path == "iroh/iroh-enrich/deliberate/observables"
    assert builders.observe([DOMAIN]).json == [{"type": "domain", "value": "bad.example.test"}]
    assert builders.refer([DOMAIN]).path == "iroh/iroh-enrich/refer/observables"
    assert builders.respond_observables([DOMAIN]).operation == "list_response_actions"
    email = Observable(type=ObservableType.EMAIL_ADDRESS, value="j.doe@example.com")
    assert builders.observables_body([email]) == [{"type": "email", "value": "j.doe@example.com"}]


def test_native_isolation_triggers_exactly_the_approved_module_action():
    router = Router().add("POST", TRIGGER, json_response(200, {"data": {"status": "success"}}))
    adapter = make_adapter("cisco_xdr", router)
    request = action_request(ActionType.ISOLATE_ENDPOINT, "cisco_xdr", **NATIVE)
    outcome = run_authorized(adapter, request)
    sent = router.last()
    assert sent.method == "POST" and sent.url.host == "visibility.amp.cisco.com" and sent.url.path == TRIGGER
    assert dict(sent.url.params) == {"observable_type": "hostname", "observable_value": "TH-LT-1047"}
    assert outcome.status is ActionResultStatus.SUCCESS
    assert outcome.external_ref == "mi-0001/isolate-host"
    assert outcome.rollback_params == {"integration": "cisco_xdr", "module_instance_id": "mi-0001",
                                       "observable_type": "hostname", "observable_value": "TH-LT-1047",
                                       "verify_integration": "defender_endpoint"}
    assert len(outcome.api_calls) == 1 and outcome.api_calls[0].kind is OperationKind.STATE_CHANGING


def test_native_restore_has_no_rollback():
    router = Router().add("POST", "/iroh/iroh-response/respond/trigger/mi-0001/unisolate",
                          json_response(200, {"data": {"status": "success"}}))
    adapter = make_adapter("cisco_xdr", router)
    request = action_request(ActionType.RELEASE_ENDPOINT, "cisco_xdr", **{**NATIVE, "action_id": "unisolate"})
    assert run_authorized(adapter, request).rollback_params == {}


def test_native_failure_is_raised_with_vendor_errors():
    router = Router().add("POST", TRIGGER, json_response(200, {"data": {"status": "failure"},
                                                               "errors": [{"message": "module offline"}]}))
    adapter = make_adapter("cisco_xdr", router)
    request = action_request(ActionType.ISOLATE_ENDPOINT, "cisco_xdr", **NATIVE)
    with pytest.raises(ApiError, match="module offline"):
        run_authorized(adapter, request)


def test_native_trigger_needs_approved_module_and_action():
    router = Router()
    adapter = make_adapter("cisco_xdr", router)
    request = action_request(ActionType.BLOCK_DOMAIN, "cisco_xdr", observable_type="domain")
    with pytest.raises(InvalidTargetError, match="module_instance_id"):
        run_authorized(adapter, request)
    assert router.calls == []


def test_list_response_actions_parses_and_filters_modules():
    body = {"data": [
        {"id": "umbrella-block", "title": "Block domain", "module": "Umbrella", "module_instance_id": "mi-u",
         "query-params": {"observable_type": "domain", "observable_value": "bad.example.test"}},
        {"id": "se-block", "title": "Block", "module-name": "Secure Endpoint", "module-instance-id": "mi-s"},
        {"title": "no id: skipped"},
    ]}
    router = Router().add("POST", "/iroh/iroh-response/respond/observables", json_response(200, body))
    adapter = make_adapter("cisco_xdr", router)
    actions = adapter.list_response_actions(DOMAIN)
    assert [a.action_id for a in actions] == ["umbrella-block", "se-block"]
    assert actions[1] == NativeResponseAction(module_instance_id="mi-s", module_name="Secure Endpoint",
                                              action_id="se-block", title="Block", observable_type="domain",
                                              observable_value="bad.example.test")
    assert [a.module_name for a in adapter.list_response_actions(DOMAIN, module="umbrella")] == ["Umbrella"]
    assert body_of(router.last()) == [{"type": "domain", "value": "bad.example.test"}]


def test_enrich_takes_the_worst_module_verdict():
    body = {"data": [
        {"module": "Umbrella", "data": {"verdicts": {"docs": [{"disposition": 2}]}}},
        {"module": "Talos", "data": {"verdicts": {"docs": [{"disposition": 3}]}}},
    ]}
    router = Router().add("POST", "/iroh/iroh-enrich/deliberate/observables", json_response(200, body))
    result = make_adapter("cisco_xdr", router).enrich(DOMAIN)
    assert result.verdict is Verdict.MALICIOUS and result.risk_score == 90
    assert len(result.evidence) == 2 and {e.source for e in result.evidence} == {"cisco_xdr"}


def test_investigate_reports_sightings_per_module():
    body = {"data": [{"module": "Secure Endpoint", "data": {"sightings": {"count": 3, "docs": []}}}]}
    router = Router().add("POST", "/iroh/iroh-enrich/observe/observables", json_response(200, body))
    query = InvestigationQuery(action_type=ActionType.INVESTIGATE_DOMAIN, subject=DOMAIN)
    result = make_adapter("cisco_xdr", router).investigate(query)
    assert result.findings == ({"module": "Secure Endpoint", "sightings": 3},)
    assert len(result.evidence) == 1


def test_incident_reads_and_status_bookkeeping_use_documented_hosts():
    router = Router()
    router.add("GET", "/iroh/private-intel/incident/XDR-83921/summary", json_response(200, {"id": "XDR-83921"}))
    router.add("GET", "/incidents/XDR-83921", json_response(200, {"id": "XDR-83921"}),
               host="conure.us.security.cisco.com")
    router.add("POST", "/ctia/incident/XDR-83921/status", json_response(200, {}), host="intel.amp.cisco.com")
    adapter = make_adapter("cisco_xdr", router)
    assert adapter.get_incident_summary("XDR-83921") == {"id": "XDR-83921"}
    assert adapter.get_incident("XDR-83921") == {"id": "XDR-83921"}
    adapter.update_incident_status("XDR-83921", "Closed")  # BOOKKEEPING: no approval token needed
    status_call = router.last()
    assert status_call.url.host == "intel.amp.cisco.com" and body_of(status_call) == {"status": "Closed"}


def test_list_workflows_uses_regional_automation_host():
    router = Router().add("GET", "/api/v1/workflows", json_response(200, {"data": [{"id": "wf-1"}]}),
                          host="automate.eu.security.cisco.com")
    adapter = make_adapter("cisco_xdr", router, region="eu", base_url=builders.IROH_HOSTS["eu"])
    assert adapter.list_workflows() == [{"id": "wf-1"}]


def test_verify_is_delegated_to_the_product_adapter():
    adapter = make_adapter("cisco_xdr", Router())
    request = action_request(ActionType.ISOLATE_ENDPOINT, "cisco_xdr", **NATIVE)
    result = adapter.verify(request, None)
    assert result.status is VerificationStatus.UNABLE_TO_VERIFY and "defender_endpoint" in result.details
