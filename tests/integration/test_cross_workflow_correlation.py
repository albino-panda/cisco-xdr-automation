"""Cross-workflow and cross-source correlation (Phase 5, section 12 exit criterion).

The workflow runs come from the existing workflow fixtures (``tests/fixtures/workflows``), detected in
dry run through the real lifecycle; a few cases add records built with the real record models to
show one rule at a time. Every link must cite records of each run it names (no invented facts),
confidence may rise only with independent sources, a degraded source never blocks a link, critical
assets are always reported with a visible warning, and correlating never changes state.

Fake lab data only (example.com, *.example, *.test, documentation IPs, fake hashes).
"""
from __future__ import annotations

import copy
import itertools
import json
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.unit.atomics.evidence._factories import at, context, incident, obs, record, result
from tools.simulator.workflow_scenario import WorkflowScenario, WorkflowScenarioRun
from xdr_response import guard
from xdr_response.atomics.correlation import (
    DEFAULT_CROSS_WINDOW,
    SOURCE_FAMILIES,
    BlastRadiusRollup,
    CrossWorkflowCorrelation,
    EntityAliases,
    EntityRef,
    LinkBasis,
    LinkKind,
    RunSnapshot,
    blast_radius,
    correlate,
    correlate_workflows,
    independent_families,
    link_confidence,
    profile_entities,
    rollup_blast_radius,
    source_family,
)
from xdr_response.atomics.correlation.cross_workflow import (
    LINK_CONFIDENCE_BASE,
    LINK_CONFIDENCE_MAX,
    LINK_CONFIDENCE_STEP,
    REPUTATION_ONLY_CONFIDENCE,
    SHARED_IP_ONLY_CAP,
)
from xdr_response.atomics.records import (
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    NetworkConnectionRecord,
    SignInRecord,
)
from xdr_response.config import Settings
from xdr_response.models import ActionType, Severity, TargetKind, Verdict
from xdr_response.models.catalog import INTEGRATION_NAMES
from xdr_response.workflows.discovery import discover_workflows

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "workflows"
CATALOG = discover_workflows()

HOST = "TH-LT-1047"
HOST_FQDN = "TH-LT-1047.CORP.EXAMPLE"
USER = "jsmith@example.com"
C2_DOMAIN = "beacon-gate.test"
C2_IP = "198.51.100.45"
FAKE_HASH = "d4" * 32


def ref(kind: str, value: str) -> EntityRef:
    return EntityRef(kind=TargetKind(kind), value=value)


# ------------------------------------------------------------------------------- fixture runs


def _raw(name: str) -> dict[str, Any]:
    with (FIXTURES / f"{name}.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _play(data: dict[str, Any], name: str) -> WorkflowScenarioRun:
    """Detect one scenario in dry run (the guard allows one runtime at a time: reset around it)."""
    guard._reset_for_test_harness()
    scenario = WorkflowScenario.model_validate({**data, "path": FIXTURES / f"{name}.yaml"})
    run = WorkflowScenarioRun(scenario, live=False, catalog=CATALOG)
    run.detect()
    guard._reset_for_test_harness()
    assert run.workflow_run is not None, f"{name} must run through its workflow"
    return run


@lru_cache(maxsize=None)
def scenario_run(name: str) -> WorkflowScenarioRun:
    return _play(_raw(name), name)


def wf(name: str):
    return scenario_run(name).workflow_run


@lru_cache(maxsize=None)
def takeover_after_click() -> WorkflowScenarioRun:
    """account-takeover/tp-approve-all with the infostealer detection dated after the phishing click.

    The phishing fixture shows the click on TH-LT-1047 at 09:20; here the infostealer on that host is
    detected at 09:40, so the evidence reads phishing -> account takeover -> C2.
    """
    data = copy.deepcopy(_raw("account-takeover/tp-approve-all"))
    for item in data["environment"]["records"]:
        if item["record"]["kind"] == "detection":
            item["record"]["first_seen"] = "2026-01-15T09:40:00Z"
    data["incident"]["incident_id"] = "XDR-ATO-0101"
    return _play(data, "account-takeover/tp-approve-all")


PHISH = "phishing/tp-approve-all"
ATO = "account-takeover/tp-approve-all"
C2 = "c2/tp-approve-all"
C2_CRITICAL = "c2/critical-asset-elevated"
C2_DEGRADED = "c2/degraded-source"
UNRELATED = "account-takeover/degraded-source"


def _story() -> CrossWorkflowCorrelation:
    return correlate_workflows([wf(C2), takeover_after_click().workflow_run, wf(PHISH)])


def _link(result_: CrossWorkflowCorrelation, a: str, b: str):
    found = [link for link in result_.links if set(link.incidents) == {a, b}]
    assert len(found) == 1, f"expected one link between {a} and {b}, got {result_.links}"
    return found[0]


def _snapshot(incident_id: str, workflow_id: str, *records: Any, report=None) -> RunSnapshot:
    results = tuple(result(r, atomic=r.atomic, subject=r.subject) for r in records)
    return RunSnapshot(incident_id=incident_id, workflow_id=workflow_id, results=results,
                       **({"blast_radius": report} if report is not None else {}))


def _with_records(name: str, *records: Any) -> RunSnapshot:
    """The fixture run of ``name`` plus extra records (each in its own atomic result)."""
    run = wf(name)
    extra = tuple(result(r, atomic=r.atomic, subject=r.subject) for r in records)
    return RunSnapshot(incident_id=run.incident_id, workflow_id=run.workflow.id,
                       results=tuple(run.results) + extra, blast_radius=run.blast_radius)


# -------------------------------------------------------------- linking incidents across workflows


def test_phishing_click_then_takeover_then_c2_on_one_host_is_one_chain():
    story = _story()
    assert len(story.groups) == 1
    group = story.groups[0]
    assert group.incidents == ("XDR-PH-0001", "XDR-ATO-0101", "XDR-C2-0001")  # evidence order, not input order
    assert group.workflows == ("phishing", "account-takeover", "c2")
    assert group.chain.startswith("phishing XDR-PH-0001 -> account-takeover XDR-ATO-0101 -> c2 XDR-C2-0001 via ")
    assert ref("ENDPOINT", HOST) in group.shared_entities
    assert len(story.links) == 3  # every pair shares the host
    for link in story.links:
        assert ref("ENDPOINT", HOST) in link.entities
        assert LinkBasis.SHARED_ASSET in link.basis
    assert story.linked_incidents("XDR-PH-0001") == ("XDR-ATO-0101", "XDR-C2-0001")
    takeover_c2 = _link(story, "XDR-ATO-0101", "XDR-C2-0001")
    assert takeover_c2.entities == (ref("ENDPOINT", HOST), ref("USER", USER))
    assert takeover_c2.sequence == ("XDR-ATO-0101", "XDR-C2-0001")


def test_every_link_cites_records_of_each_run_that_mention_the_shared_entity():
    runs = {r.incident_id: r for r in (wf(PHISH), wf(ATO), wf(C2), wf(C2_CRITICAL))}
    story = correlate_workflows(list(runs.values()))
    assert story.links
    for link in story.links:
        for shared in link.shared:
            assert shared.incidents == link.incidents
            for citation in shared.citations:
                run = runs[citation.incident_id]
                assert citation.workflow_id == run.workflow.id
                assert all(rid in run.index for rid in citation.record_ids), "a citation names an unknown record"
                profile = profile_entities(run.results, entities=[shared.entity])
                assert len(profile) == 1
                assert set(citation.record_ids) <= set(profile[0].record_ids), "a cited record does not mention it"
                assert citation.integrations == tuple(sorted({run.index.get(r).integration
                                                              for r in citation.record_ids}))
        for incident_id in link.incidents:
            assert link.record_ids(incident_id)
    json.dumps(story.rule_item())  # rule-expression friendly


def test_the_order_of_the_runs_never_changes_the_result():
    runs = [wf(PHISH), wf(ATO), wf(C2), wf(C2_CRITICAL), wf(UNRELATED)]
    expected = correlate_workflows(runs).model_dump(mode="json")
    for permutation in itertools.islice(itertools.permutations(runs), 1, 12):
        assert correlate_workflows(list(permutation)).model_dump(mode="json") == expected


def test_an_unrelated_incident_stays_on_its_own_and_reports_its_degraded_source():
    story = correlate_workflows([wf(C2), wf(UNRELATED)])
    assert story.links == ()
    assert [g.incidents for g in story.groups] == [("XDR-ATO-0005",), ("XDR-C2-0001",)]
    lone = story.group_of("XDR-ATO-0005")
    assert lone.chain == "account-takeover XDR-ATO-0005"
    assert lone.degraded_sources == ("XDR-ATO-0005: cisco_xdr",)
    summary = {s.incident_id: s for s in story.incidents}
    assert summary["XDR-ATO-0005"].degraded_sources == ("cisco_xdr",)


def test_a_degraded_source_does_not_block_a_link_backed_by_other_records():
    story = correlate_workflows([wf(C2_DEGRADED), wf(ATO)])
    link = _link(story, "XDR-ATO-0001", "XDR-C2-0005")
    assert link.entities == (ref("ENDPOINT", HOST), ref("USER", USER))
    assert "umbrella" not in link.sources
    assert story.groups[0].degraded_sources == ("XDR-C2-0005: umbrella",)


def test_the_same_incident_given_twice_is_used_once():
    story = correlate_workflows([wf(C2), wf(C2), wf(ATO)])
    assert [s.incident_id for s in story.incidents] == ["XDR-ATO-0001", "XDR-C2-0001"]
    assert "XDR-C2-0001: several runs given; the last one is used" in story.notes


def test_two_c2_incidents_share_indicators_and_the_user():
    story = correlate_workflows([wf(C2), wf(C2_CRITICAL)])
    link = _link(story, "XDR-C2-0001", "XDR-C2-0006")
    kinds = {e.kind for e in link.entities}
    assert {TargetKind.DOMAIN, TargetKind.IP, TargetKind.URL, TargetKind.HASH, TargetKind.USER} <= kinds
    assert ref("ENDPOINT", HOST) not in link.entities and ref("ENDPOINT", "PRD-APP-03") not in link.entities
    assert set(link.basis) == {LinkBasis.SHARED_ASSET, LinkBasis.SHARED_INDICATOR}


# ----------------------------------------------------------------- confidence and independent sources


def test_confidence_counts_independent_first_hand_sources_only():
    story = correlate_workflows([wf(PHISH), wf(ATO), wf(C2)])
    host_only = _link(story, "XDR-C2-0001", "XDR-PH-0001")
    # microsoft_cloud relays Defender telemetry (an aggregator) and the enrichments are ratings:
    assert "microsoft_cloud" in host_only.sources
    assert host_only.first_hand_families == ("cisco_secure_endpoint",)
    assert host_only.confidence_score == LINK_CONFIDENCE_BASE
    host_and_user = _link(story, "XDR-ATO-0001", "XDR-C2-0001")
    assert host_and_user.first_hand_families == ("cisco_secure_endpoint", "microsoft_entra")
    assert host_and_user.confidence_score == LINK_CONFIDENCE_BASE + LINK_CONFIDENCE_STEP


def _host_detection(integration: str, host: str, name: str, minutes: int) -> DetectionRecord:
    return record(DetectionRecord, integration=integration, subject=obs("hostname", host), name=name,
                  verdict=Verdict.MALICIOUS, severity=Severity.HIGH, endpoint=host, user=USER,
                  first_seen=at(minutes))


def test_more_records_from_the_same_source_or_an_aggregator_never_raise_confidence():
    base = _link(correlate_workflows([wf(PHISH), wf(C2)]), "XDR-C2-0001", "XDR-PH-0001").confidence_score
    same_source = _with_records(C2, _host_detection("secure_endpoint", HOST, "Second.Detection", 5),
                                _host_detection("secure_endpoint", HOST, "Third.Detection", 6))
    relayed = _with_records(C2, _host_detection("microsoft_cloud", HOST, "Relayed.Alert", 7),
                            _host_detection("cisco_xdr", HOST, "Relayed.Sighting", 8))
    for variant in (same_source, relayed):
        link = _link(correlate_workflows([wf(PHISH), variant]), "XDR-C2-0001", "XDR-PH-0001")
        assert link.confidence_score == base
        assert link.first_hand_families == ("cisco_secure_endpoint",)


def test_an_independent_source_raises_confidence_and_its_host_spelling_is_merged():
    # Defender names the host by its DNS name; it is the same machine as Secure Endpoint's TH-LT-1047.
    defender = _host_detection("defender_endpoint", HOST_FQDN, "Defender.Detection", 10)
    story = correlate_workflows([wf(PHISH), _with_records(C2, defender)])
    link = _link(story, "XDR-C2-0001", "XDR-PH-0001")
    assert link.first_hand_families == ("cisco_secure_endpoint", "microsoft_defender_endpoint")
    assert link.confidence_score == LINK_CONFIDENCE_BASE + LINK_CONFIDENCE_STEP
    shared = {s.entity: s for s in link.shared}[ref("ENDPOINT", HOST)]
    assert shared.aliases == (ref("ENDPOINT", HOST_FQDN),)
    assert defender.record_id in shared.citations[0].record_ids
    assert f"ENDPOINT:{HOST_FQDN} and ENDPOINT:{HOST} are the same entity (merged)" in story.notes
    profile = story.profile(ref("ENDPOINT", HOST_FQDN))
    assert profile is not None and profile.entity == ref("ENDPOINT", HOST)
    assert {"defender_endpoint", "secure_endpoint", "microsoft_cloud"} <= set(profile.integrations)
    assert set(profile.incidents) == {"XDR-C2-0001", "XDR-PH-0001"}


def test_link_confidence_rules():
    assert link_confidence(0) == REPUTATION_ONLY_CONFIDENCE
    assert link_confidence(1) == LINK_CONFIDENCE_BASE
    assert link_confidence(2) == LINK_CONFIDENCE_BASE + LINK_CONFIDENCE_STEP
    assert link_confidence(50) == LINK_CONFIDENCE_MAX < 100
    assert link_confidence(4, ip_only=True) == SHARED_IP_ONLY_CAP
    assert [link_confidence(n) for n in range(6)] == sorted(link_confidence(n) for n in range(6))
    with pytest.raises(ValueError):
        link_confidence(-1)


def _enrichment(integration: str, kind: str, value: str, verdict: Verdict = Verdict.MALICIOUS) -> EnrichmentRecord:
    return record(EnrichmentRecord, integration=integration, atomic="enrich_observable", subject=obs(kind, value),
                  verdict=verdict, risk_score=80 if verdict is Verdict.MALICIOUS else 0, confidence=70)


def test_a_link_backed_only_by_reputation_ratings_stays_low():
    a = _snapshot("XDR-T-0001", "malware", _enrichment("virustotal", "domain", C2_DOMAIN))
    b = _snapshot("XDR-T-0002", "c2", _enrichment("umbrella", "domain", C2_DOMAIN))
    link = _link(correlate_workflows([a, b]), "XDR-T-0001", "XDR-T-0002")
    assert link.first_hand_families == () and link.independent_sources == 0
    assert link.confidence_score == REPUTATION_ONLY_CONFIDENCE
    assert link.note.endswith("(reputation ratings only)")


def _connection(integration: str, host: str, ip: str, minutes: int = 0) -> NetworkConnectionRecord:
    return record(NetworkConnectionRecord, integration=integration, subject=obs("hostname", host), endpoint=host,
                  remote_ip=ip, remote_port=443, direction="outbound", first_seen=at(minutes))


def test_a_link_resting_only_on_shared_ips_is_capped():
    a = _snapshot("XDR-T-0011", "c2", _connection("secure_endpoint", "TH-LT-2001", "203.0.113.60"),
                  _connection("umbrella", "TH-LT-2001", "203.0.113.60"))
    b = _snapshot("XDR-T-0012", "exfiltration", _connection("secure_cloud_analytics", "TH-LT-2002", "203.0.113.60"),
                  _connection("defender_endpoint", "TH-LT-2002", "203.0.113.60"))
    link = _link(correlate_workflows([a, b]), "XDR-T-0011", "XDR-T-0012")
    assert link.entities == (ref("IP", "203.0.113.60"),)
    assert link.independent_sources == 4
    assert link.confidence_score == SHARED_IP_ONLY_CAP
    assert "shared IPs only" in link.note


# ---------------------------------------------------------------------------- what never links


def test_private_addresses_and_ignored_entities_never_link_incidents():
    a = _snapshot("XDR-T-0021", "c2", _connection("secure_endpoint", "TH-LT-2001", "10.20.30.40"),
                  _connection("secure_endpoint", "TH-LT-2001", "203.0.113.70"))
    b = _snapshot("XDR-T-0022", "c2", _connection("secure_endpoint", "TH-LT-2002", "10.20.30.40"),
                  _connection("secure_endpoint", "TH-LT-2002", "203.0.113.70"))
    story = correlate_workflows([a, b])
    assert _link(story, "XDR-T-0021", "XDR-T-0022").entities == (ref("IP", "203.0.113.70"),)
    assert "IP 10.20.30.40 is a private or local address: not used to link incidents" in story.notes
    assert correlate_workflows([a, b], ignore=[ref("IP", "203.0.113.70")]).links == ()


def test_incidents_further_apart_than_the_window_are_not_linked():
    a = _snapshot("XDR-T-0031", "c2", _connection("secure_endpoint", "TH-LT-2001", "203.0.113.80", minutes=0))
    b = _snapshot("XDR-T-0032", "c2", _connection("umbrella", "TH-LT-2002", "203.0.113.80",
                                                 minutes=int(DEFAULT_CROSS_WINDOW / timedelta(minutes=1)) + 60))
    story = correlate_workflows([a, b])
    assert story.links == ()
    assert any("not linked" in note and "XDR-T-0031 and XDR-T-0032" in note for note in story.notes)
    assert len(correlate_workflows([a, b], window=None).links) == 1
    with pytest.raises(ValueError):
        correlate_workflows([a, b], window=timedelta(0))


def test_a_run_without_blast_radius_links_on_what_its_records_mention():
    run = wf(C2)
    bare = RunSnapshot(incident_id="XDR-T-0041", workflow_id="c2", results=tuple(run.results))
    story = correlate_workflows([bare, wf(ATO)])
    assert ref("ENDPOINT", HOST) in _link(story, "XDR-ATO-0001", "XDR-T-0041").entities
    assert any(note.startswith("XDR-T-0041: blast radius is empty") for note in story.notes)


def test_run_snapshot_input_is_validated():
    with pytest.raises(ValueError):
        RunSnapshot(incident_id=" ", workflow_id="c2")
    with pytest.raises(ValueError):
        RunSnapshot(incident_id="XDR-T-0051", workflow_id="c2", results=("not a result",))  # type: ignore[arg-type]
    snap = RunSnapshot.of(wf(C2))
    assert RunSnapshot.of(snap) is snap
    assert (snap.incident_id, snap.workflow_id) == ("XDR-C2-0001", "c2")


# --------------------------------------------------------------------------- blast-radius rollup


def test_rollup_is_the_union_of_the_linked_scopes_and_keeps_every_critical_asset():
    story = correlate_workflows([wf(C2), wf(C2_CRITICAL), wf(ATO)])
    group = story.group_of("XDR-C2-0006")
    rollup = group.blast_radius
    assert set(group.incidents) == {"XDR-ATO-0001", "XDR-C2-0001", "XDR-C2-0006"}
    assert rollup.endpoints == ("PRD-APP-03", HOST)
    assert rollup.users == (USER,)
    assert set(rollup.indicators) >= {C2_DOMAIN, C2_IP, "203.0.113.145"}
    assert ref("USER", USER) in rollup.shared
    (hit,) = [h for h in rollup.critical_assets if h.entity == ref("ENDPOINT", "PRD-APP-03")]
    assert hit.incidents == ("XDR-C2-0006",) and hit.record_ids
    assert any(w.startswith("critical asset ENDPOINT:PRD-APP-03 (production_server)") for w in group.warnings)
    assert rollup.has_critical_asset and rollup.rule_item()["has_critical_asset"] is True
    assert rollup.to_blast_radius().endpoints == rollup.endpoints
    assert [s.incident_id for s in rollup.per_incident] == ["XDR-ATO-0001", "XDR-C2-0001", "XDR-C2-0006"]
    json.dumps(rollup.rule_item())


def test_a_critical_asset_unclassified_in_another_incident_is_flagged():
    run = wf(C2)
    widened = run.blast_radius.model_copy(update={"endpoints": tuple(sorted({*run.blast_radius.endpoints,
                                                                             "PRD-APP-03"}))})
    other = RunSnapshot(incident_id=run.incident_id, workflow_id="c2", results=tuple(run.results),
                        blast_radius=widened)
    rollup = rollup_blast_radius([other, wf(C2_CRITICAL)])
    (hit,) = [h for h in rollup.critical_assets if h.entity == ref("ENDPOINT", "PRD-APP-03")]
    assert hit.in_scope_of == ("XDR-C2-0001", "XDR-C2-0006")
    assert hit.unclassified_in == ("XDR-C2-0001",)
    assert any("not classified as critical in XDR-C2-0001" in w for w in rollup.warnings)


def test_an_ignored_entity_still_counts_in_the_rollup_and_its_critical_asset_is_reported():
    story = correlate_workflows([wf(C2), wf(C2_CRITICAL)], ignore=[ref("USER", USER), ref("DOMAIN", C2_DOMAIN)])
    link = _link(story, "XDR-C2-0001", "XDR-C2-0006")
    assert ref("USER", USER) not in link.entities and ref("DOMAIN", C2_DOMAIN) not in link.entities
    rollup = story.group_of("XDR-C2-0001").blast_radius
    assert USER in rollup.users and C2_DOMAIN in rollup.indicators
    assert [h.entity for h in rollup.critical_assets] == [ref("ENDPOINT", "PRD-APP-03")]


def test_the_union_can_exceed_a_cap_no_single_incident_exceeds():
    runs = [wf(C2), wf(C2_CRITICAL)]
    assert all("endpoints" not in r.blast_radius.exceeds for r in runs)
    strictest = rollup_blast_radius(runs)
    assert strictest.caps == {name: min(r.blast_radius.caps[name] for r in runs) for name in strictest.caps}
    tight = rollup_blast_radius(runs, caps={"endpoints": 1, "users": 1})
    assert tight.exceeds == ("endpoints",)
    assert isinstance(tight, BlastRadiusRollup)


# ------------------------------------------------------------- merging evidence across sources


def test_profiles_merge_every_source_for_an_entity_and_respect_independence():
    story = correlate_workflows([wf(PHISH), wf(ATO), wf(C2), wf(C2_CRITICAL)])
    host = story.profile(ref("ENDPOINT", HOST))
    assert set(host.incidents) == {"XDR-ATO-0001", "XDR-C2-0001", "XDR-PH-0001"}
    assert host.integrations == ("microsoft_cloud", "secure_endpoint")
    assert host.families == ("cisco_secure_endpoint",) and host.independent_sources == 1
    assert host.verdict is Verdict.UNKNOWN  # nobody rated the host itself
    assert host.activity_verdict is Verdict.MALICIOUS  # it is part of malicious activity
    domain = story.profile(ref("DOMAIN", C2_DOMAIN))
    assert domain.families == ("cisco_secure_endpoint", "cisco_umbrella", "virustotal")
    assert domain.verdict is Verdict.MALICIOUS and not domain.contradicted
    user = story.profile(ref("USER", USER))
    assert user.first_hand_sources == 2  # Secure Endpoint and Entra observed the user


def test_profiles_report_a_contradiction_between_independent_ratings():
    profiles = profile_entities([result(_enrichment("virustotal", "domain", "cdn-edge.example"),
                                        _enrichment("umbrella", "domain", "cdn-edge.example", Verdict.CLEAN),
                                        atomic="enrich_observable", subject=obs("domain", "cdn-edge.example"),
                                        action_type=ActionType.ENRICH_DOMAIN)])
    (profile,) = profiles
    assert profile.contradicted and profile.verdict is Verdict.MALICIOUS
    assert profile.first_hand_sources == 0 and all(o.reputation_only for o in profile.observations)


def test_every_integration_has_a_source_family():
    assert set(SOURCE_FAMILIES) == set(INTEGRATION_NAMES)
    assert independent_families(["cisco_xdr", "secure_endpoint"]) == ("cisco_secure_endpoint",)
    assert independent_families(["cisco_xdr", "microsoft_cloud"]) == ("aggregator:cisco_xdr",
                                                                      "aggregator:microsoft_defender_xdr")
    assert source_family("some_future_source") == "some_future_source"


def test_alias_rules_are_conservative():
    aliases = EntityAliases.resolve([
        ref("ENDPOINT", HOST), ref("ENDPOINT", HOST_FQDN),  # merged into the short name
        ref("ENDPOINT", "TH-LT-3000"), ref("ENDPOINT", "TH-LT-3000.CORP.EXAMPLE"),
        ref("ENDPOINT", "TH-LT-3000.LAB.EXAMPLE"),  # two DNS names with one first label: ambiguous
        ref("ENDPOINT", "WEB-01.CORP.EXAMPLE"),  # no short spelling in the evidence: kept
        ref("ENDPOINT", "192.0.2.15"),  # an IP literal is never split
        ref("USER", USER), ref("EMAIL_ADDRESS", USER),  # a mailbox address is its user
        ref("USER", "jsmith"),  # a bare account name is never merged into a UPN
    ])
    assert dict((a.key(), c.key()) for a, c in aliases.items()) == {
        f"EMAIL_ADDRESS:{USER}": f"USER:{USER}",
        f"ENDPOINT:{HOST_FQDN}": f"ENDPOINT:{HOST}",
    }
    assert aliases.canon(ref("ENDPOINT", "TH-LT-3000.LAB.EXAMPLE")) == ref("ENDPOINT", "TH-LT-3000.LAB.EXAMPLE")
    assert aliases.aliases_of(ref("ENDPOINT", HOST_FQDN)) == (ref("ENDPOINT", HOST_FQDN),)
    assert not EntityAliases.resolve([ref("ENDPOINT", HOST)])


# --------------------------------------------- single-run correlation: opt-in alias merge, compatible


def _two_spellings_results():
    se = record(EndpointRecord, hostname=HOST, users=(USER,), connector_guid="guid-1047", observed_at=at(0))
    se_det = _host_detection("secure_endpoint", HOST, "Infostealer.Generic", 1)
    md_det = _host_detection("defender_endpoint", HOST_FQDN, "Defender.Infostealer", 2)
    dns = record(DnsQueryRecord, integration="umbrella", subject=obs("hostname", HOST), endpoint=HOST_FQDN,
                 domain=C2_DOMAIN, first_seen=at(3))
    sign_in = record(SignInRecord, integration="entra", atomic="investigate_authentication", subject=obs("user", USER),
                     user=USER, timestamp=at(4), ip="203.0.113.145", result="success")
    return [result(se, se_det), result(md_det, subject=obs("hostname", HOST_FQDN)),
            result(dns), result(sign_in, atomic="investigate_authentication", subject=obs("user", USER),
                                action_type=ActionType.INVESTIGATE_USER)]


CRITICAL = {"classes": {"domain_controller": {
    "display_name": "Workstation tier 0", "role": "Admin workstation", "potential_impact": "Admin lockout",
    "match": {"hostname_patterns": ["th-lt-*.corp.example"]}}}}


def test_alias_merge_is_opt_in_and_the_default_is_unchanged():
    results = _two_spellings_results()
    ctx = context(incident(obs("hostname", HOST), obs("user", USER), users=(USER,)),
                  Settings(critical_assets=CRITICAL))
    default = correlate(ctx, results)
    assert default == correlate(ctx, results, merge_aliases=False)
    assert [link.kind for link in default.links if link.kind is LinkKind.SAME_USER], "two spellings, two hosts"
    unmerged = blast_radius(ctx, default, results)
    assert set(unmerged.endpoints) == {HOST, HOST_FQDN}
    assert [h.entity for h in unmerged.critical_assets] == [ref("ENDPOINT", HOST_FQDN)]

    merged = correlate(ctx, results, merge_aliases=True)
    assert ref("ENDPOINT", HOST_FQDN) not in merged.entities
    assert not [link for link in merged.links if link.kind is LinkKind.SAME_USER]
    report = blast_radius(ctx, merged, results, merge_aliases=True)
    assert report.endpoints == (HOST,)
    # the policy matches the DNS name only: the host merged under its short spelling is still critical
    assert [h.entity for h in report.critical_assets] == [ref("ENDPOINT", HOST)]


def test_profile_entities_merges_sources_within_one_run():
    profiles = {p.entity: p for p in profile_entities(_two_spellings_results())}
    host = profiles[ref("ENDPOINT", HOST)]
    assert host.aliases == (ref("ENDPOINT", HOST_FQDN),)
    assert host.integrations == ("defender_endpoint", "secure_endpoint", "umbrella")
    assert host.independent_sources == 3 and host.first_hand_sources == 3
    raw = {p.entity for p in profile_entities(_two_spellings_results(), merge_aliases=False)}
    assert ref("ENDPOINT", HOST_FQDN) in raw


def test_email_records_join_the_user_they_were_sent_to():
    message = record(EmailMessageRecord, integration="secure_email", atomic="investigate_email",
                     subject=obs("email_message_id", "<msg-0001@invoice-portal.example>"),
                     message_id="<msg-0001@invoice-portal.example>", sender="billing@invoice-portal.example",
                     recipients=(USER,), received_at=at(0), domains=("invoice-portal.example",))
    a = _snapshot("XDR-T-0061", "phishing", message)
    sign_in = record(SignInRecord, integration="entra", atomic="investigate_authentication", subject=obs("user", USER),
                     user=USER, timestamp=at(30), ip="203.0.113.145", result="success")
    b = _snapshot("XDR-T-0062", "account-takeover", sign_in)
    link = _link(correlate_workflows([a, b]), "XDR-T-0061", "XDR-T-0062")
    assert link.entities == (ref("USER", USER),)
    assert link.first_hand_families == ("cisco_secure_email", "microsoft_entra")
    assert link.sequence == ("XDR-T-0061", "XDR-T-0062")


# ----------------------------------------------------------------------------- read zone / dry run


def test_correlating_runs_changes_nothing_and_needs_no_adapter():
    names = (PHISH, ATO, C2)
    before = [len(scenario_run(n).environment.calls) for n in names]
    correlate_workflows([wf(n) for n in names])
    rollup_blast_radius([wf(n) for n in names])
    for name, count in zip(names, before):
        environment = scenario_run(name).environment
        assert environment.state_changing_calls() == []
        assert len(environment.calls) == count, "correlation must not call an adapter"
        assert scenario_run(name).runtime.registry.list() == []
