"""Investigation and enterprise search atomics (architecture 14.1.4) over simulated adapters.

Everything runs on a fixed clock with in-memory simulated vendors: no network, no real API.
"""
from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import Any

import pytest

from tests.unit.atomics.investigation._support import (
    FAKE_MD5,
    FAKE_SHA1,
    FAKE_SHA256,
    FIXED_NOW,
    HOST,
    USER,
    Lab,
    lab,
    statuses,
    typed,
)
from xdr_response.atomics.investigation import INVESTIGATION_ATOMICS, INVESTIGATION_SUBJECT_TYPES
from xdr_response.atomics.investigation.atomics import (
    investigate_authentication,
    investigate_endpoint,
    investigate_hash,
    investigate_ip,
    investigate_process,
    investigate_user,
    search_related_endpoints,
)
from xdr_response.atomics.records import (
    DetectionRecord,
    GenericRecord,
    InvestigationBundle,
    RecordKind,
    SourceOutcome,
)
from xdr_response.config.schema import AssetMatch, CriticalAssetClassConfig, CriticalAssetsConfig
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import (
    ActionCategory,
    ActionType,
    CriticalAssetClass,
    ErrorCode,
    ErrorInfo,
    INTEGRATION_NAMES,
    HealthStatus,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    OperationKind,
    get_action_spec,
)

_A = ActionType
_O = ObservableType
DETECTION = {"name": "Ransomware.Generic", "verdict": "MALICIOUS", "severity": "CRITICAL", "endpoint": HOST}

#: A valid subject for every atomic.
SUBJECTS: dict[str, str] = {
    "investigate_user": USER, "investigate_endpoint": HOST, "investigate_ip": "203.0.113.10",
    "investigate_domain": "bad.example.test", "investigate_hash": FAKE_SHA256, "investigate_email": "msg-1",
    "investigate_authentication": USER, "investigate_process": f"{HOST}/4242",
    "investigate_network_connection": "203.0.113.10", "search_hash_enterprise": FAKE_SHA256,
    "search_domain_enterprise": "bad.example.test", "search_ip_enterprise": "198.51.100.7",
    "search_user_activity": USER, "search_email_campaign": "msg-1", "search_related_endpoints": HOST,
    "search_related_users": USER,
}


class RecordingAdapters:
    """Wraps the read-only facade, recording queries and optionally replacing answers."""

    def __init__(self, inner: Any, answers: dict[str, Any] | None = None, simulated: bool | None = None) -> None:
        self.inner = inner
        self.answers = answers or {}
        self.simulated = simulated
        self.queries: list[tuple[str, InvestigationQuery]] = []

    def enabled(self) -> tuple[str, ...]:
        return self.inner.enabled()

    def investigators(self, action_type: ActionType) -> tuple[str, ...]:
        return self.inner.investigators(action_type)

    def is_simulated(self, integration: str) -> bool:
        return self.inner.is_simulated(integration) if self.simulated is None else self.simulated

    def investigate(self, integration: str, query: InvestigationQuery) -> InvestigationResult:
        self.queries.append((integration, query))
        answer = self.answers.get(integration)
        if isinstance(answer, Exception):
            raise answer
        if callable(answer):
            return answer(query)
        return self.inner.investigate(integration, query)


def recording(the_lab: Lab, **kw: Any) -> tuple[Any, RecordingAdapters]:
    ctx = the_lab.context()
    adapters = RecordingAdapters(ctx.adapters, **kw)
    return dataclasses.replace(ctx, adapters=adapters), adapters


# ------------------------------------------------------------------ tables --
def test_tables_name_the_sixteen_investigation_types():
    investigation_types = {a.value for a in ActionType if get_action_spec(a).category is ActionCategory.INVESTIGATION}
    assert set(INVESTIGATION_ATOMICS) == investigation_types and len(INVESTIGATION_ATOMICS) == 16
    assert set(INVESTIGATION_SUBJECT_TYPES) == investigation_types
    assert INVESTIGATION_SUBJECT_TYPES["investigate_user"] == frozenset({_O.USER, _O.EMAIL_ADDRESS})
    assert INVESTIGATION_SUBJECT_TYPES["investigate_process"] == frozenset({_O.PROCESS})
    with pytest.raises(TypeError):
        INVESTIGATION_ATOMICS["investigate_ip"] = investigate_user  # type: ignore[index]


@pytest.mark.parametrize("name", sorted(SUBJECTS))
def test_every_atomic_runs_read_only_and_reports_every_considered_source(name):
    the_lab = lab()
    bundle = INVESTIGATION_ATOMICS[name](the_lab.context(), SUBJECTS[name])
    assert isinstance(bundle, InvestigationBundle)
    assert bundle.atomic == name and bundle.action_type is ActionType(name)
    catalog = set(get_action_spec(ActionType(name)).integrations)
    assert {s.integration for s in bundle.sources} >= catalog
    order = [s.integration for s in bundle.sources]
    assert order == [n for n in INTEGRATION_NAMES if n in order]
    assert the_lab.env.state_changing_calls() == []
    assert all(c.kind is OperationKind.READ and c.operation == "investigate" for c in the_lab.env.calls)
    assert set(bundle.rule_item()) >= {"atomic", "subject_type", "subject", "record_ids", "sources",
                                       "failed_sources", "degraded"}


# ----------------------------------------------------------------- answers --
def test_investigate_endpoint_collects_typed_records_per_source():
    the_lab = lab()
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST,
                typed("detection", only="secure_endpoint", **DETECTION),
                typed("endpoint", only="secure_endpoint", hostname=HOST, connector_guid="guid-1",
                      groups=["Workstations"], isolation_capable=True),
                typed("endpoint", only="defender_endpoint", hostname=HOST, mde_machine_id="mde-1"))
    bundle = investigate_endpoint(the_lab.context(), "th-lt-1047")
    assert bundle.subject == Observable(type=_O.HOSTNAME, value=HOST)
    assert statuses(bundle) == {
        "cisco_xdr": ("not_queried", "not enabled"), "secure_endpoint": ("answered", ""),
        "defender_endpoint": ("answered", ""), "intune": ("empty", ""),
        "microsoft_cloud": ("not_queried", "not enabled"), "splunk": ("not_queried", "not enabled")}
    assert [r.kind for r in bundle.records] == [RecordKind.DETECTION, RecordKind.ENDPOINT, RecordKind.ENDPOINT]
    assert {r.integration for r in bundle.records} == {"secure_endpoint", "defender_endpoint"}
    assert all(r.atomic == "investigate_endpoint" for r in bundle.records)
    assert {s.integration: s.records for s in bundle.sources}["secure_endpoint"] == 2
    assert [r.integration for r in bundle.raw] == ["secure_endpoint", "defender_endpoint", "intune"]
    assert bundle.started_at == bundle.finished_at == FIXED_NOW and not bundle.degraded
    item = bundle.rule_item()
    assert item["connector_guid"] == "guid-1" and item["mde_machine_id"] == "mde-1"
    assert item["detections"][0]["verdict"] == "MALICIOUS" and item["isolation_capable"] is True


def test_query_carries_the_window_limit_and_options():
    the_lab = lab()
    ctx, adapters = recording(the_lab)
    investigate_endpoint(ctx, HOST, options={"spl": "search index=edr"}, limit=25)
    assert [name for name, _ in adapters.queries] == ["secure_endpoint", "defender_endpoint", "intune"]
    query = adapters.queries[0][1]
    assert (query.time_from, query.time_to) == (FIXED_NOW - timedelta(hours=24), FIXED_NOW)
    assert query.limit == 25 and query.options == {"spl": "search index=edr"}
    assert query.action_type is _A.INVESTIGATE_ENDPOINT and query.subject.value == HOST


def test_identical_records_are_kept_once_first_source_wins():
    the_lab = lab()
    finding = typed("detection", only="secure_endpoint", **DETECTION)
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, finding, finding)
    bundle = investigate_endpoint(the_lab.context(), HOST)
    assert len(bundle.records) == 1 and {s.integration: s.records for s in bundle.sources}["secure_endpoint"] == 2


def test_same_fact_from_two_sources_gives_two_records():
    the_lab = lab()
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("detection", **DETECTION))
    bundle = investigate_endpoint(the_lab.context(), HOST)
    assert sorted(r.integration for r in bundle.records) == ["defender_endpoint", "intune", "secure_endpoint"]
    assert len(set(bundle.record_ids())) == 3


def test_runs_are_deterministic():
    def run() -> InvestigationBundle:
        the_lab = lab()
        the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("detection", **DETECTION),
                    typed("endpoint", hostname=HOST, groups=["Workstations"]))
        return investigate_endpoint(the_lab.context(), HOST)
    assert run() == run()


# --------------------------------------------------------- degraded sources --
@pytest.mark.parametrize("kind, health, code", [
    (FaultKind.FAIL, HealthStatus.DEGRADED, ErrorCode.API_ERROR),
    (FaultKind.UNAVAILABLE, HealthStatus.UNAVAILABLE, ErrorCode.UNAVAILABLE),
    (FaultKind.AUTH_FAIL, HealthStatus.AUTH_FAILED, ErrorCode.AUTH_FAILED),
    (FaultKind.RATE_LIMIT, HealthStatus.RATE_LIMITED, ErrorCode.RATE_LIMITED),
    (FaultKind.TIMEOUT, HealthStatus.DEGRADED, ErrorCode.TIMEOUT),
])
def test_a_failing_source_is_reported_and_the_others_still_answer(kind, health, code):
    the_lab = lab()
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("detection", **DETECTION))
    the_lab.env.inject(kind, integration="defender_endpoint", operation="investigate")
    bundle = investigate_endpoint(the_lab.context(), HOST)
    failed = {s.integration: s for s in bundle.sources}["defender_endpoint"]
    assert failed.outcome is SourceOutcome.FAILED and failed.health is health
    assert failed.error is not None and failed.error.code is code and failed.reason == code.value
    assert bundle.degraded and bundle.failed == ("defender_endpoint",)
    assert bundle.answered == ("secure_endpoint", "intune")
    assert {r.integration for r in bundle.records} == {"secure_endpoint", "intune"}
    assert bundle.rule_item()["failed_sources"] == ["defender_endpoint"]


def test_every_source_failing_still_returns_a_bundle():
    the_lab = lab()
    the_lab.env.inject(FaultKind.UNAVAILABLE, operation="investigate", times=None)
    bundle = investigate_endpoint(the_lab.context(), HOST)
    assert bundle.records == () and bundle.failed == ("secure_endpoint", "defender_endpoint", "intune")
    assert bundle.rule_item()["endpoint"] is None


def test_unexpected_exception_is_redacted_and_internal():
    the_lab = lab()
    ctx, _ = recording(the_lab, answers={"intune": RuntimeError("boom token=abcdef0123456789")})
    bundle = investigate_endpoint(ctx, HOST)
    failed = {s.integration: s for s in bundle.sources}["intune"]
    assert failed.outcome is SourceOutcome.FAILED and failed.health is HealthStatus.UNKNOWN
    assert failed.error.code is ErrorCode.INTERNAL and "abcdef0123456789" not in failed.error.message
    assert "RuntimeError" in failed.error.message


def test_result_with_errors_is_failed_but_keeps_its_records():
    the_lab = lab()
    error = ErrorInfo(code=ErrorCode.RATE_LIMITED, message="partial page", integration="intune")

    def partial(query: InvestigationQuery) -> InvestigationResult:
        return InvestigationResult(integration="intune", action_type=query.action_type, subject=query.subject,
                                   findings=(typed("endpoint", hostname=HOST, intune_device_id="int-1"),),
                                   errors=(error,))
    ctx, _ = recording(the_lab, answers={"intune": partial})
    bundle = investigate_endpoint(ctx, HOST)
    failed = {s.integration: s for s in bundle.sources}["intune"]
    assert (failed.outcome, failed.health, failed.error, failed.records) == \
        (SourceOutcome.FAILED, HealthStatus.DEGRADED, error, 1)
    assert [r.integration for r in bundle.records] == ["intune"] and bundle.degraded


def test_invalid_result_object_is_failed():
    the_lab = lab()

    def wrong(query: InvestigationQuery) -> InvestigationResult:
        return InvestigationResult(integration="entra", action_type=query.action_type, subject=query.subject)
    ctx, _ = recording(the_lab, answers={"intune": wrong, "secure_endpoint": lambda q: {"not": "a result"}})
    bundle = investigate_endpoint(ctx, HOST)
    by_name = {s.integration: s for s in bundle.sources}
    for name in ("intune", "secure_endpoint"):
        assert by_name[name].outcome is SourceOutcome.FAILED and by_name[name].error.code is ErrorCode.INTERNAL
    assert by_name["defender_endpoint"].outcome is SourceOutcome.EMPTY


def test_malformed_typed_record_fails_only_its_source():
    the_lab = lab()
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("endpoint", only="intune"),
                typed("detection", only="secure_endpoint", **DETECTION))
    bundle = investigate_endpoint(the_lab.context(), HOST)
    failed = {s.integration: s for s in bundle.sources}["intune"]
    assert failed.outcome is SourceOutcome.FAILED and failed.error.code is ErrorCode.INTERNAL
    assert "invalid typed endpoint record" in failed.error.message
    assert bundle.answered == ("secure_endpoint",) and len(bundle.records) == 1


def test_typed_findings_from_a_non_simulated_source_are_generic():
    the_lab = lab()
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("detection", only="secure_endpoint", **DETECTION))
    ctx, _ = recording(the_lab, simulated=False)
    bundle = investigate_endpoint(ctx, HOST)
    assert [type(r) for r in bundle.records] == [GenericRecord, GenericRecord, GenericRecord]
    assert not any(isinstance(r, DetectionRecord) for r in bundle.records)


# ------------------------------------------------------------------ splunk --
def test_splunk_disabled_is_not_queried_and_never_called():
    the_lab = lab()
    the_lab.add_splunk(enabled=False)
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("detection", **DETECTION))
    bundle = investigate_endpoint(the_lab.context(), HOST)
    splunk = {s.integration: s for s in bundle.sources}["splunk"]
    assert (splunk.outcome, splunk.health, splunk.reason) == \
        (SourceOutcome.NOT_QUERIED, HealthStatus.UNKNOWN, "not enabled")
    assert not bundle.degraded and "splunk" not in {r.integration for r in bundle.records}
    assert all(c.integration != "splunk" for c in the_lab.env.calls)
    assert len(bundle.records) == 3


def test_splunk_enabled_answers_like_any_other_source():
    the_lab = lab()
    the_lab.add_splunk(enabled=True)
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("dns_query", only="splunk", endpoint=HOST,
                                                     domain="bad.example.test", count=14))
    bundle = investigate_endpoint(the_lab.context(), HOST)
    assert statuses(bundle)["splunk"] == ("answered", "")
    assert [r.integration for r in bundle.records] == ["splunk"]
    assert bundle.rule_item()["dns_queries"][0]["count"] == 14


def test_splunk_failing_does_not_block_other_sources():
    the_lab = lab()
    the_lab.add_splunk(enabled=True)
    the_lab.add(_A.INVESTIGATE_ENDPOINT, HOST, typed("detection", only="secure_endpoint", **DETECTION))
    the_lab.env.inject(FaultKind.TIMEOUT, integration="splunk", operation="investigate")
    bundle = investigate_endpoint(the_lab.context(), HOST)
    assert bundle.failed == ("splunk",) and bundle.answered == ("secure_endpoint",)


# --------------------------------------------------------- source selection --
def test_integrations_restrict_the_queried_sources():
    the_lab = lab()
    ctx, adapters = recording(the_lab)
    bundle = investigate_endpoint(ctx, HOST, integrations=["intune", "entra", "meraki", "intune"])
    assert [name for name, _ in adapters.queries] == ["intune"]
    assert statuses(bundle) == {"entra": ("not_supported", "does not serve investigate_endpoint"),
                                "intune": ("empty", ""), "meraki": ("not_queried", "not enabled")}


@pytest.mark.parametrize("integrations", [["nope"], "intune"])
def test_bad_integration_names_are_refused(integrations):
    with pytest.raises(ValueError):
        investigate_endpoint(lab().context(), HOST, integrations=integrations)


# ------------------------------------------------------------------ subjects --
@pytest.mark.parametrize("atomic, value, otype, normalized", [
    (investigate_ip, "203.0.113.10", _O.IP, "203.0.113.10"),
    (investigate_ip, "2001:DB8:0::1", _O.IPV6, "2001:db8::1"),
    (investigate_hash, FAKE_SHA256.upper(), _O.SHA256, FAKE_SHA256),
    (investigate_hash, FAKE_SHA1, _O.SHA1, FAKE_SHA1),
    (investigate_hash, FAKE_MD5, _O.MD5, FAKE_MD5),
    (investigate_user, "JSmith@Example.com", _O.USER, USER),
    (investigate_endpoint, " th-lt-1047 ", _O.HOSTNAME, HOST),
    (investigate_process, "th-lt-1047/4242", _O.PROCESS, f"{HOST}/4242"),
])
def test_string_subjects_get_their_type_and_normalized_value(atomic, value, otype, normalized):
    bundle = atomic(lab().context(), value)
    assert (bundle.subject.type, bundle.subject.value) == (otype, normalized)


def test_observable_subjects_of_an_allowed_type_are_accepted():
    bundle = investigate_user(lab().context(), Observable(type=_O.EMAIL_ADDRESS, value="JSmith@Example.com"))
    assert bundle.subject == Observable(type=_O.EMAIL_ADDRESS, value=USER)
    endpoint_id = search_related_endpoints(lab().context(), Observable(type=_O.ENDPOINT_ID, value="guid-1"))
    assert endpoint_id.subject.value == "guid-1"


@pytest.mark.parametrize("atomic, subject", [
    (investigate_ip, "not-an-ip"),
    (investigate_hash, "abc"),
    (investigate_hash, "zz" * 32),
    (investigate_process, "TH-LT-1047"),
    (investigate_user, "   "),
    (investigate_user, Observable(type=_O.HOSTNAME, value=HOST)),
    (investigate_authentication, Observable(type=_O.EMAIL_ADDRESS, value=USER)),
    (investigate_endpoint, 42),
])
def test_invalid_subjects_raise_value_error(atomic, subject):
    with pytest.raises(ValueError):
        atomic(lab().context(), subject)


@pytest.mark.parametrize("kw", [{"limit": 0}, {"limit": 10001}, {"limit": True}, {"options": ["x"]},
                                {"options": {1: "x"}}])
def test_invalid_arguments_raise_value_error(kw):
    with pytest.raises(ValueError):
        investigate_endpoint(lab().context(), HOST, **kw)


# ---------------------------------------------------------- critical assets --
CRITICAL = CriticalAssetsConfig(classes={
    CriticalAssetClass.DOMAIN_CONTROLLER: CriticalAssetClassConfig(
        display_name="Domain controller", role="AD DS", potential_impact="Authentication outage",
        match=AssetMatch(groups=["Domain Controllers"])),
    CriticalAssetClass.EXECUTIVE_ENDPOINT: CriticalAssetClassConfig(
        display_name="Executive endpoint", role="Executive laptop", potential_impact="Executive disruption",
        match=AssetMatch(hostname_patterns=["EXEC-*"])),
    CriticalAssetClass.PRIVILEGED_ACCOUNT: CriticalAssetClassConfig(
        display_name="Privileged account", role="Tier 0 admin", potential_impact="Admin lockout",
        match=AssetMatch(groups=["Tier0 Admins"])),
})


def test_endpoint_critical_asset_classes_come_from_the_records():
    the_lab = lab(critical_assets=CRITICAL)
    the_lab.add(_A.INVESTIGATE_ENDPOINT, "DC-01",
                typed("endpoint", only="secure_endpoint", hostname="DC-01", groups=["Domain Controllers"]))
    bundle = investigate_endpoint(the_lab.context(), "dc-01")
    assert bundle.critical_asset_classes == (CriticalAssetClass.DOMAIN_CONTROLLER,)
    item = bundle.rule_item()
    assert item["is_critical_asset"] is True and item["critical_asset_classes"] == ["domain_controller"]


def test_endpoint_subject_alone_is_classified_and_nothing_is_skipped():
    the_lab = lab(critical_assets=CRITICAL)
    bundle = investigate_endpoint(the_lab.context(), "exec-lt-01")
    assert bundle.critical_asset_classes == (CriticalAssetClass.EXECUTIVE_ENDPOINT,)
    assert {s.integration: s.outcome for s in bundle.sources}["secure_endpoint"] is SourceOutcome.EMPTY
    assert investigate_endpoint(the_lab.context(), HOST).critical_asset_classes == ()


def test_user_critical_asset_classes_come_from_profile_groups():
    the_lab = lab(critical_assets=CRITICAL)
    the_lab.add(_A.INVESTIGATE_USER, "admin@example.com",
                typed("user_profile", only="entra", user="admin@example.com", groups=["Tier0 Admins"]))
    bundle = investigate_user(the_lab.context(), "admin@example.com")
    assert bundle.critical_asset_classes == (CriticalAssetClass.PRIVILEGED_ACCOUNT,)
    assert bundle.rule_item()["is_critical_asset"] is True


def test_non_entity_atomics_do_not_classify():
    the_lab = lab(critical_assets=CRITICAL)
    assert investigate_ip(the_lab.context(), "203.0.113.10").critical_asset_classes == ()


# ------------------------------------------------------------ rule outputs --
def test_authentication_bundle_counts_from_typed_records():
    the_lab = lab()
    the_lab.add(_A.INVESTIGATE_AUTHENTICATION, USER,
                *[typed("mfa_event", only="entra", user=USER, timestamp=(FIXED_NOW - timedelta(minutes=i)).isoformat(),
                        method="push", result="denied", ip="203.0.113.9", country="NL") for i in range(14)],
                typed("sign_in", only="entra", user=USER, timestamp=FIXED_NOW.isoformat(), ip="203.0.113.9",
                      country="NL", result="success"))
    item = investigate_authentication(the_lab.context(), USER).rule_item()
    assert item["mfa_denied_count"] == 14 and item["success_count"] == 1
    assert item["distinct_ips"] == 1 and item["distinct_countries"] == 1
    assert item["sources"] == ["entra"]
