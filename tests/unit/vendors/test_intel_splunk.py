"""VirusTotal, OTX and HIBP (disclosure-gated enrichment) and the optional Splunk adapter."""
from __future__ import annotations

from urllib.parse import parse_qs

import pytest

from tests.fixtures.factories import FAKE_SHA256
from tests.unit.vendors._helpers import FAKE_SECRETS, Router, body_of, json_response, make_adapter
from xdr_response.config.policy import DisclosurePolicy
from xdr_response.config.schema import ExclusionsConfig
from xdr_response.errors import CapabilityNotSupportedError, IntegrationTimeoutError
from xdr_response.integrations.alienvault_otx import builders as otx
from xdr_response.integrations.hibp import builders as hibp
from xdr_response.integrations.splunk import builders as splunk
from xdr_response.integrations.virustotal import builders as vt
from xdr_response.integrations.virustotal.adapter import score_analysis
from xdr_response.models import ActionType, ErrorCode, InvestigationQuery, Observable, ObservableType, Verdict

PUBLIC_IP = Observable(type=ObservableType.IP, value="203.0.113.10")
PRIVATE_IP = Observable(type=ObservableType.IP, value="10.0.0.5")
INTERNAL = Observable(type=ObservableType.DOMAIN, value="fileserver.corp.example.com")
DOMAIN = Observable(type=ObservableType.DOMAIN, value="bad.example.test")
EMAIL = Observable(type=ObservableType.EMAIL_ADDRESS, value="j.doe@example.com")
LAB_POLICY = DisclosurePolicy(ExclusionsConfig(internal_domains=["corp.example.com"],
                                               third_party_lookup={"user_domains": ["partner.example.net"]}),
                              allow_documentation_ranges=True)


def _intel(name: str, router: Router):
    adapter = make_adapter(name, router)
    adapter.disclosure = LAB_POLICY
    return adapter


# ---------------------------------------------------------------- VirusTotal --
def test_virustotal_builders():
    assert vt.url_id("http://www.example.com/") == "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"  # no '=' padding
    assert vt.file_report(FAKE_SHA256).path == f"files/{FAKE_SHA256}"
    assert vt.domain_report("bad.example.test").path == "domains/bad.example.test"
    assert vt.ip_report("2001:db8::1").path == "ip_addresses/2001:db8::1"
    assert vt.url_report("http://www.example.com/").path == "urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"


@pytest.mark.parametrize(("stats", "verdict"), [
    ({"malicious": 12, "harmless": 50}, Verdict.MALICIOUS), ({"malicious": 1, "undetected": 60}, Verdict.SUSPICIOUS),
    ({"suspicious": 2, "harmless": 60}, Verdict.SUSPICIOUS), ({"harmless": 70}, Verdict.CLEAN), ({}, Verdict.UNKNOWN),
])
def test_virustotal_scoring(stats, verdict):
    assert score_analysis(stats)[0] is verdict


def test_virustotal_enrich_public_ip():
    report = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "harmless": 60}}}}
    router = Router().add("GET", "/api/v3/ip_addresses/203.0.113.10", json_response(200, report))
    result = _intel("virustotal", router).enrich(PUBLIC_IP)
    assert result.verdict is Verdict.MALICIOUS and result.sources == ("virustotal",)
    assert router.last().url.host == "www.virustotal.com"


def test_virustotal_not_found_is_unknown():
    router = Router().add("GET", "/api/v3/domains/bad.example.test", json_response(404, {"error": {}}))
    assert _intel("virustotal", router).enrich(DOMAIN).verdict is Verdict.UNKNOWN


@pytest.mark.parametrize("observable", [PRIVATE_IP, INTERNAL, Observable(type=ObservableType.URL,
                                                                          value="https://intranet.corp.example.com/x")])
def test_virustotal_never_receives_internal_observables(observable):
    router = Router()
    result = _intel("virustotal", router).enrich(observable)
    assert router.calls == []
    assert result.verdict is Verdict.UNKNOWN and result.errors[0].code is ErrorCode.NOT_SUPPORTED


def test_virustotal_default_policy_withholds_documentation_ranges():
    router = Router()
    assert make_adapter("virustotal", router).enrich(PUBLIC_IP).errors  # strict default policy
    assert router.calls == []


# ----------------------------------------------------------------------- OTX --
def test_otx_builder_validates_documented_sections():
    assert otx.indicator("IPv4", "203.0.113.10", "reputation").path == "api/v1/indicators/IPv4/203.0.113.10/reputation"
    with pytest.raises(ValueError):
        otx.indicator("file", FAKE_SHA256, "whois")
    with pytest.raises(ValueError):
        otx.indicator("cve", "CVE-2026-0001")


@pytest.mark.parametrize(("count", "verdict"), [(9, Verdict.MALICIOUS), (2, Verdict.SUSPICIOUS), (0, Verdict.UNKNOWN)])
def test_otx_enrich_uses_pulse_count(count, verdict):
    router = Router().add("GET", "/api/v1/indicators/domain/bad.example.test/general",
                          json_response(200, {"pulse_info": {"count": count}}))
    assert _intel("alienvault_otx", router).enrich(DOMAIN).verdict is verdict


def test_otx_withholds_private_addresses():
    router = Router()
    assert _intel("alienvault_otx", router).enrich(PRIVATE_IP).errors
    with pytest.raises(CapabilityNotSupportedError):
        _intel("alienvault_otx", router).indicator(INTERNAL)
    assert router.calls == []


# ---------------------------------------------------------------------- HIBP --
def test_hibp_builders():
    req = hibp.breached_account("j.doe@example.com")
    assert req.path == "breachedaccount/j.doe%40example.com" and req.params == {"truncateResponse": "false"}
    assert hibp.paste_account("a@example.com").expected == (200, 404)


def test_hibp_enrich_breaches_with_user_agent():
    router = Router().add("GET", "/api/v3/breachedaccount/j.doe@example.com",
                          json_response(200, [{"Name": "ExampleBreach"}, {"Name": "OtherBreach"}]))
    result = _intel("hibp", router).enrich(EMAIL)
    assert result.verdict is Verdict.SUSPICIOUS and "CC BY 4.0" in result.evidence[0].summary
    assert router.last().headers["user-agent"] == "xdr-response-framework"


def test_hibp_no_breach_and_policy():
    router = Router().add("GET", "/api/v3/breachedaccount/j.doe@example.com", json_response(404))
    adapter = _intel("hibp", router)
    assert adapter.enrich(EMAIL).verdict is Verdict.UNKNOWN
    partner = Observable(type=ObservableType.EMAIL_ADDRESS, value="x@partner.example.net")
    assert adapter.enrich(partner).errors and len(router.calls) == 1
    with pytest.raises(CapabilityNotSupportedError):
        adapter.enrich(DOMAIN)


# -------------------------------------------------------------------- Splunk --
def test_splunk_builders():
    job = splunk.create_search_job('index=main "x"', "-1h", "now")
    assert (job.method, job.path) == ("POST", "services/search/jobs")
    assert job.data == {"search": 'search index=main "x"', "earliest_time": "-1h", "latest_time": "now",
                        "output_mode": "json"}
    assert splunk.normalize_spl("| makeresults") == "| makeresults"
    assert splunk.quoted_term_search('a"b') == 'search "a\\"b"'
    assert splunk.get_search_results("1.23").params == {"output_mode": "json"}


def test_splunk_search_polls_until_results_are_ready():
    router = Router().add("POST", "/services/search/jobs", json_response(201, {"sid": "1.23"}))
    router.add("GET", "/services/search/jobs/1.23/results", json_response(204), json_response(200, {"results": [
        {"host": "TH-LT-1047"}]}))
    adapter = make_adapter("splunk", router, base_url="https://splunk.example.test:8089")
    query = InvestigationQuery(action_type=ActionType.SEARCH_HASH_ENTERPRISE,
                               subject=Observable(type=ObservableType.SHA256, value=FAKE_SHA256))
    assert adapter.investigate(query).findings == ({"host": "TH-LT-1047"},)
    assert parse_qs(router.calls[0].content.decode())["search"] == [f'search "{FAKE_SHA256}"']


def test_splunk_search_gives_up_after_configured_polls():
    router = Router().add("POST", "/services/search/jobs", json_response(201, {"sid": "9"}))
    router.add("GET", "/services/search/jobs/9/results", json_response(204))
    adapter = make_adapter("splunk", router, base_url="https://splunk.example.test:8089",
                           options={"poll_attempts": 3})
    with pytest.raises(IntegrationTimeoutError):
        adapter.search("index=main")
    assert len(router.calls) == 4


def test_splunk_forward_audit_is_redacted_bookkeeping():
    rest, hec = Router(), Router().add("POST", "/services/collector/event", json_response(200, {"code": 0}))
    adapter = make_adapter("splunk", rest, base_url="https://splunk.example.test:8089",
                           options={"hec_url": "https://splunk.example.test:8088"})
    from xdr_response.integrations.http import GuardedHttpClient, RetryPolicy

    adapter.hec_http = GuardedHttpClient("splunk", "https://splunk.example.test:8088", transport=hec.transport(),
                                         retry=RetryPolicy(max_retries=0))
    adapter.secret("token")  # secrets read through the provider are registered with the central redactor
    assert adapter.forward_audit({"event_type": "API_CALL", "api_key": "fake-value-123456",
                                  "note": f"token {FAKE_SECRETS['SPLUNK_TOKEN']}"}) is True
    sent = body_of(hec.last())
    assert sent["sourcetype"] == "xdr_response:audit"
    assert sent["event"]["api_key"] == "[REDACTED]"
    assert FAKE_SECRETS["SPLUNK_TOKEN"] not in hec.last().content.decode()
    assert rest.calls == []
