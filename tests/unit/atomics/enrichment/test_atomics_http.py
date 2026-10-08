"""Enrichment atomics over the real vendor adapters, HTTP mocked with ``httpx.MockTransport``.

Covers the six enrichment sources of Phase 1 (Cisco XDR enrich, Umbrella, Secure Malware Analytics,
VirusTotal, OTX, HIBP): one request per source, nothing sent where the disclosure policy forbids it,
nothing sent to an UNVERIFIED endpoint, and HTTP failures isolated per source. No network.
"""
from __future__ import annotations

from urllib.parse import unquote

import httpx
import pytest

from tests.unit.atomics.enrichment._support import FAKE_SHA256, Lab, lab, lab_disclosure, statuses
from tests.unit.vendors._helpers import Router, json_response, make_adapter
from xdr_response.atomics.enrichment.atomics import (
    enrich_domain,
    enrich_email_address,
    enrich_endpoint,
    enrich_hash,
    enrich_ip,
)
from xdr_response.atomics.records import SourceOutcome
from xdr_response.models import ErrorCode, HealthStatus, Verdict

DOMAIN = "bad.example.test"
PUBLIC_IP = "198.51.100.7"
DELIBERATE = "/iroh/iroh-enrich/deliberate/observables"


def _xdr_verdict(disposition: int) -> dict:
    return {"data": [{"module": "Talos Intelligence", "data": {"verdicts": {"docs": [{"disposition": disposition}]}}}]}


def _install(the_lab: Lab, routers: dict[str, Router], *, public_documentation_ranges: bool = False) -> None:
    """Register one real adapter per router (third parties get the lab's disclosure policy)."""
    for name, router in routers.items():
        adapter = make_adapter(name, router)
        if name in {"virustotal", "alienvault_otx", "hibp"} and public_documentation_ranges:
            adapter.disclosure = lab_disclosure(the_lab.settings)
        the_lab.registry.register(adapter)


def _domain_routers() -> dict[str, Router]:
    return {
        "cisco_xdr": Router().add("POST", DELIBERATE, json_response(200, _xdr_verdict(2))),
        "umbrella": Router().add("GET", f"/investigate/v2/domains/categorization/{DOMAIN}", json_response(
            200, {DOMAIN: {"status": -1, "security_categories": ["Malware"], "content_categories": ["Business"]}})),
        "secure_malware_analytics": Router().add("GET", "/api/v2/iocs/feeds/domains", json_response(
            200, {"data": {"items": [{"domain": DOMAIN}]}})),
        "virustotal": Router().add("GET", f"/api/v3/domains/{DOMAIN}", json_response(
            200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 50}}}})),
        "alienvault_otx": Router().add("GET", f"/api/v1/indicators/domain/{DOMAIN}/general", json_response(
            200, {"pulse_info": {"count": 6}})),
    }


def test_domain_is_enriched_by_every_capable_source_once():
    the_lab = lab()
    routers = _domain_routers()
    _install(the_lab, routers)
    report = enrich_domain(the_lab.context(), DOMAIN)
    assert report.answered == ("cisco_xdr", "secure_malware_analytics", "umbrella", "virustotal", "alienvault_otx")
    assert {name: len(r.calls) for name, r in routers.items()} == dict.fromkeys(routers, 1)
    assert routers["virustotal"].last().url.host == "www.virustotal.com"
    assert report.source_verdicts() == dict.fromkeys(report.answered, "MALICIOUS")
    assert report.categories() == ("Business", "Malware")
    assert all(r.method in {"GET", "POST"} for router in routers.values() for r in router.calls)


def test_private_ip_reaches_cisco_xdr_but_never_public_intel():
    the_lab = lab()
    routers = {"cisco_xdr": Router().add("POST", DELIBERATE, json_response(200, {"data": []})),
               "virustotal": Router(), "alienvault_otx": Router()}
    _install(the_lab, routers)
    report = enrich_ip(the_lab.context(), "10.20.30.40")
    assert statuses(report) == {"cisco_xdr": "empty", "virustotal": "not_queried", "alienvault_otx": "not_queried"}
    assert routers["virustotal"].calls == [] and routers["alienvault_otx"].calls == []


def test_public_ip_reaches_public_intel():
    the_lab = lab()
    routers = {
        "virustotal": Router().add("GET", f"/api/v3/ip_addresses/{PUBLIC_IP}", json_response(
            200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 60}}}})),
        "alienvault_otx": Router().add("GET", f"/api/v1/indicators/IPv4/{PUBLIC_IP}/general", json_response(
            200, {"pulse_info": {"count": 0}})),
    }
    _install(the_lab, routers, public_documentation_ranges=True)
    report = enrich_ip(the_lab.context(public_documentation_ranges=True), PUBLIC_IP)
    assert statuses(report) == {"virustotal": "answered", "alienvault_otx": "empty"}
    assert report.source_verdicts() == {"virustotal": "SUSPICIOUS"}


def test_hostnames_are_never_sent_to_otx_even_though_it_claims_support():
    the_lab = lab()
    routers = {"cisco_xdr": Router().add("POST", DELIBERATE, json_response(200, _xdr_verdict(3))),
               "alienvault_otx": Router()}
    _install(the_lab, routers)
    report = enrich_endpoint(the_lab.context(), "th-lt-1047")
    assert statuses(report) == {"cisco_xdr": "answered", "alienvault_otx": "not_queried"}
    assert routers["alienvault_otx"].calls == []
    assert '"value":"TH-LT-1047"' in routers["cisco_xdr"].last().content.decode()


def test_hash_enrichment_never_touches_the_unverified_sandbox_search():
    the_lab = lab()
    routers = {
        "secure_malware_analytics": Router(),
        "virustotal": Router().add("GET", f"/api/v3/files/{FAKE_SHA256}", json_response(
            200, {"data": {"attributes": {"last_analysis_stats": {"harmless": 70}}}})),
        "alienvault_otx": Router().add("GET", f"/api/v1/indicators/file/{FAKE_SHA256}/general", json_response(
            200, {"pulse_info": {"count": 0}})),
    }
    _install(the_lab, routers)
    report = enrich_hash(the_lab.context(), FAKE_SHA256.upper())
    assert "secure_malware_analytics" not in statuses(report)
    assert routers["secure_malware_analytics"].calls == []
    assert statuses(report) == {"virustotal": "answered", "alienvault_otx": "empty"}
    assert report.source_verdicts() == {"virustotal": "CLEAN"}


def test_email_address_goes_to_hibp_and_cisco_xdr_only():
    the_lab = lab()
    account = "sender@partner.example.net"
    routers = {
        "cisco_xdr": Router().add("POST", DELIBERATE, json_response(200, {"data": []})),
        "hibp": Router(fallback=json_response(200, [{"Name": "ExampleBreach"}])),
        "virustotal": Router(), "alienvault_otx": Router(),
    }
    _install(the_lab, routers)
    report = enrich_email_address(the_lab.context(), account)
    assert statuses(report) == {"cisco_xdr": "empty", "hibp": "answered"}
    assert unquote(routers["hibp"].last().url.path).endswith(f"breachedaccount/{account}")
    assert routers["virustotal"].calls == [] and routers["alienvault_otx"].calls == []
    assert report.source_verdicts() == {"hibp": "SUSPICIOUS"}


def test_internal_email_address_is_withheld_from_hibp():
    the_lab = lab(exclusions={"third_party_lookup": {"user_domains": ["example.com"]}})
    routers = {"hibp": Router()}
    _install(the_lab, routers)
    report = enrich_email_address(the_lab.context(), "jsmith@example.com")
    assert statuses(report) == {"hibp": "not_queried"} and routers["hibp"].calls == []


@pytest.mark.parametrize(("response", "health", "code"), [
    (json_response(500, {"error": "boom"}), HealthStatus.UNAVAILABLE, ErrorCode.UNAVAILABLE),
    (json_response(400, {"error": "bad request"}), HealthStatus.DEGRADED, ErrorCode.INVALID_TARGET),
    (json_response(429, {"error": "slow down"}, {"Retry-After": "30"}), HealthStatus.RATE_LIMITED,
     ErrorCode.RATE_LIMITED),
    (json_response(401, {"error": "bad key"}), HealthStatus.AUTH_FAILED, ErrorCode.AUTH_FAILED),
])
def test_http_failures_of_one_source_are_isolated(response, health, code):
    the_lab = lab()
    routers = _domain_routers()
    routers["virustotal"] = Router().add("GET", f"/api/v3/domains/{DOMAIN}", response)
    _install(the_lab, routers)
    report = enrich_domain(the_lab.context(), DOMAIN)
    failed = {s.integration: s for s in report.sources if s.outcome is SourceOutcome.FAILED}
    assert list(failed) == ["virustotal"]
    assert failed["virustotal"].health is health and failed["virustotal"].error.code is code
    assert len(report.answered) == 4 and report.degraded


def test_transport_timeouts_are_isolated():
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("simulated timeout", request=request)

    the_lab = lab()
    routers = _domain_routers()
    routers["umbrella"] = Router(fallback=timeout)
    _install(the_lab, routers)
    report = enrich_domain(the_lab.context(), DOMAIN)
    status = next(s for s in report.sources if s.integration == "umbrella")
    assert status.outcome is SourceOutcome.FAILED and status.health is HealthStatus.DEGRADED
    assert report.answered == ("cisco_xdr", "secure_malware_analytics", "virustotal", "alienvault_otx")


def test_adapter_side_disclosure_refusal_is_a_failure_and_still_sends_nothing():
    # The context policy allows documentation ranges, the adapter's own (strict) policy does not:
    # defence in depth keeps the request from leaving, and the run reports the refusal.
    the_lab = lab()
    routers = {"virustotal": Router()}
    _install(the_lab, routers)
    report = enrich_ip(the_lab.context(public_documentation_ranges=True), PUBLIC_IP)
    status = report.sources[0]
    assert (status.outcome, status.reason) == (SourceOutcome.FAILED, ErrorCode.NOT_SUPPORTED.value)
    assert routers["virustotal"].calls == [] and report.verdict is Verdict.UNKNOWN
