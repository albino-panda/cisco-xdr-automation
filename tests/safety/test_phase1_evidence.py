"""Adversarial safety tests, Phase 1 round 1, lens: evidence, scoring and privacy.

Every test asserts the SAFE behaviour required by docs/architecture.md (sections 13 and 14) and
docs/threat-scoring.md, so a failing test is a defect. Fake data only: documentation IPs, example
domains, fake hashes, hosts like TH-LT-1047 and users like jsmith@example.com. Nothing here talks to
a network or a real vendor; the simulated lab adapters record every call they receive.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import HASH, HOST, make_incident, make_lab
from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW
from tests.fixtures.sample_workflows.sample_malware.hooks import HOOKS, SampleMalwareHooks
from xdr_response.atomics.context import AtomicContext, build_context
from xdr_response.atomics.enrichment.atomics import (
    enrich_email_address,
    enrich_hash,
    enrich_ip,
    enrich_url,
    enrich_user,
)
from xdr_response.atomics.evidence import EvidenceBuilder, EvidenceError, RecordIndex, evidence_draft
from xdr_response.atomics.notifications import LifecycleEvent, LifecycleEventKind
from xdr_response.atomics.notifications.render import (
    render_analyst_summary,
    render_incident_note,
    render_soc_notification,
)
from xdr_response.atomics.records import (
    DetectionRecord,
    NetworkConnectionRecord,
    SourceOutcome,
)
from xdr_response.config.schema import ScoringSettings
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import (
    ActionType,
    EvidenceDraft,
    HealthStatus,
    Incident,
    Observable,
    ObservableType,
    RiskBand,
    Severity,
    Verdict,
)
from xdr_response.models.scoring import ScoringContext, ScoringSignal, SignalCategory
from xdr_response.scoring.engine import ScoringEngine
from xdr_response.workflows.definition import InvestigationStep, WorkflowDefinition
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import WorkflowRun

THIRD_PARTY = ("virustotal", "alienvault_otx", "hibp")
NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
SHA = "5e" * 32


# ------------------------------------------------------------------------------------- helpers --
def _lab_context(suite: Mapping[str, Sequence[str]]) -> tuple[Any, AtomicContext]:
    lab = make_lab(suite)
    ctx = build_context(make_incident(), lab.registry, lab.settings, clock=lab.clock, dry_run=True)
    return lab, ctx


def _third_party_targets(lab: Any) -> list[tuple[str, str | None]]:
    return [(c.integration, c.target) for c in lab.environment.calls if c.integration in THIRD_PARTY]


def _signal(integration: str, category: SignalCategory, *, severity: int, confidence: int, record_id: str,
            verdict: Verdict = Verdict.MALICIOUS, origin: str = "framework",
            observable: Observable | None = None) -> ScoringSignal:
    return ScoringSignal(category=category, integration=integration,
                         observable=observable or Observable(type=ObservableType.HOSTNAME, value=HOST),
                         verdict=verdict, severity=severity, confidence=confidence, record_ids=(record_id,),
                         origin=origin)


def _engine() -> ScoringEngine:
    return ScoringEngine(ScoringSettings())


def _variant(**changes: Any) -> WorkflowDefinition:
    return WorkflowDefinition.model_validate({**WORKFLOW.model_dump(), **changes})


def _run(lab: Any, definition: WorkflowDefinition = WORKFLOW, hooks: Any = HOOKS, incident: Incident | None = None
         ) -> WorkflowRun:
    return lab.runner.run(definition, hooks, incident or make_incident(), dry_run=True)


# =========================================================================== 1. evidence cannot be fabricated
def _detection(**changes: Any) -> DetectionRecord:
    data: dict[str, Any] = {
        "integration": "secure_endpoint", "atomic": "investigate_endpoint",
        "subject": Observable(type=ObservableType.HOSTNAME, value=HOST), "detection_id": "det-0001",
        "name": "Sample.Trojan.Generic", "verdict": Verdict.MALICIOUS, "severity": Severity.HIGH,
        "endpoint": HOST, "sha256": SHA, "observed_at": NOW,
    }
    data.update(changes)
    return DetectionRecord(**data)


def test_evidence_cites_only_known_records():
    builder = EvidenceBuilder(RecordIndex(records=[_detection()]))
    with pytest.raises(EvidenceError):
        builder.cite(["rec_" + "0" * 32])
    with pytest.raises(EvidenceError):
        builder.cite([])
    with pytest.raises(EvidenceError):
        builder.cite("rec_not_a_list")  # a bare string is never a list of ids


def test_tampered_or_reattributed_evidence_is_rejected():
    record = _detection()
    builder = EvidenceBuilder(RecordIndex(records=[record]))
    (draft,) = builder.cite([record.record_id])
    builder.verify([draft])
    for change in ({"summary": "secure_endpoint: CRITICAL ransomware confirmed on TH-LT-1047"},
                   {"source": "defender_endpoint"},
                   {"data": {**draft.data, "record_id": "rec_" + "1" * 32}}):
        forged = EvidenceDraft(**{**draft.model_dump(), **change})
        with pytest.raises(EvidenceError):
            builder.verify([forged])
    with pytest.raises(ValueError):
        EvidenceDraft(source="ai", summary="model says ransomware")


def test_record_id_collision_with_different_content_is_rejected():
    record = _detection()
    forged = DetectionRecord.model_construct(**{**dict(record), "severity": Severity.CRITICAL})
    with pytest.raises(EvidenceError):
        RecordIndex(records=[record, forged])


def test_evidence_data_never_carries_secrets_from_record_fields():
    """A signed URL seen in telemetry must not travel into package evidence with its signature/token.

    Evidence drafts become numbered package evidence (persisted, hashed into the evidence snapshot and
    shown to approvers). Free-text record fields are redacted by the record validators, but URL fields
    are copied verbatim into ``EvidenceDraft.data["fields"]``.
    """
    record = NetworkConnectionRecord(
        integration="umbrella", atomic="investigate_domain",
        subject=Observable(type=ObservableType.DOMAIN, value="cdn.example.com"),
        endpoint=HOST, domain="cdn.example.com", direction="outbound", action="allowed",
        verdict=Verdict.MALICIOUS,
        url="https://cdn.example.com/dl?sig=FAKESIGVALUE00001&access_token=FAKETOKENVALUE0002")
    draft = evidence_draft(record)
    text = json.dumps(draft.model_dump(mode="json"))
    assert "FAKESIGVALUE00001" not in text
    assert "FAKETOKENVALUE0002" not in text


def test_contribution_record_ids_come_from_input_signals():
    signals = [
        _signal("secure_endpoint", SignalCategory.ENDPOINT_DETECTION, severity=80, confidence=80, record_id="rec_a"),
        _signal("umbrella", SignalCategory.NETWORK_BEHAVIOUR, severity=70, confidence=60, record_id="rec_b"),
        _signal("virustotal", SignalCategory.REPUTATION, severity=90, confidence=70, record_id="rec_c"),
    ]
    breakdown = _engine().score(signals, context=ScoringContext())
    cited = {rid for s in signals for rid in s.record_ids}
    for contribution in breakdown.contributions:
        assert set(contribution.record_ids) <= cited


# ---------------------------------------------------------------- hook-derived signals (workflow code)
_SPOOFED = ("defender_endpoint", "secure_malware_analytics", "alienvault_otx", "umbrella")


class _SpoofingHooks(SampleMalwareHooks):
    """Derives signals that claim integrations which never produced any cited record."""

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        detection = next(r for r in view.index.records() if str(r.kind) == "detection")
        return [ScoringSignal(category=SignalCategory.CAMPAIGN_ASSOCIATION, integration=name,
                              observable=Observable(type=ObservableType.SHA256, value=HASH),
                              verdict=Verdict.MALICIOUS, severity=60, confidence=60,
                              record_ids=(detection.record_id,), origin=view.origin, note="pattern")
                for name in _SPOOFED]


def test_hook_signals_cannot_claim_a_source_that_produced_none_of_the_cited_records():
    lab = make_lab()
    lab.infected()
    run = _run(lab, hooks=_SpoofingHooks())
    for signal in run.signals:
        sources = {run.index.get(rid).integration for rid in signal.record_ids}
        assert signal.integration in sources, (
            f"hook signal attributed to {signal.integration} but cites only records of {sorted(sources)}")


def test_hook_signals_cannot_inflate_independent_source_confidence():
    honest_lab, spoof_lab = make_lab(), make_lab()
    honest_lab.infected()
    spoof_lab.infected()
    honest = _run(honest_lab)
    spoofed = _run(spoof_lab, hooks=_SpoofingHooks())
    key = (ActionType.BLOCK_HASH, HASH)
    assert spoofed.breakdowns[key].confidence_score <= honest.breakdowns[key].confidence_score, (
        f"confidence rose from {honest.breakdowns[key].confidence_score} to "
        f"{spoofed.breakdowns[key].confidence_score} through sources that never answered: "
        f"{spoofed.breakdowns[key].explain()}")


def test_a_fact_seen_by_two_atomics_does_not_discard_the_second_atomics_evidence():
    """The same vendor detection returned by investigate_hash and search_hash_enterprise.

    Record ids exclude the producing atomic while ``atomic`` is part of the record content, so the two
    copies collide in the RecordIndex and the runner drops the whole second result, including evidence
    that only it holds (here a malicious enterprise prevalence record).
    """
    lab = make_lab()
    detection = {"kind": "detection", "detection_id": "det-shared-01", "name": "Sample.Trojan.Generic",
                 "verdict": "MALICIOUS", "severity": "HIGH", "endpoint": HOST, "sha256": HASH}
    lab.typed("investigate_hash", HASH, "secure_endpoint", **detection)
    lab.typed("search_hash_enterprise", HASH, "secure_endpoint", **detection)
    lab.typed("search_hash_enterprise", HASH, "secure_endpoint", kind="hash_prevalence", sha256=HASH,
              prevalence=3, verdict="MALICIOUS", endpoints=[HOST, "TH-LT-1048", "TH-LT-1049"])
    definition = _variant(
        investigation=[InvestigationStep(id="hash", atomic="investigate_hash").model_dump(),
                       InvestigationStep(id="hash_search", atomic="search_hash_enterprise").model_dump()],
        recommendations=[{**WORKFLOW.recommendations[1].model_dump(),
                          "id": "block_prevalent_hash", "for_each": "results.search_hash_enterprise",
                          "target": "item.sha256", "evidence": "item.record_ids",
                          "rationale": "'malicious hash seen enterprise-wide'"}])
    run = _run(lab, definition, incident=make_incident((ObservableType.SHA256, HASH)))
    atomics = {r.atomic for r in run.results}
    assert "search_hash_enterprise" in atomics, f"second result dropped; notes: {run.notes}"
    assert any(str(r.kind) == "hash_prevalence" for r in run.index.records())
    assert any(p.action_type is ActionType.BLOCK_HASH for p in run.proposals), run.notes


# =================================================================== 2. no single vendor verdict is absolute
def test_reputation_alone_is_capped_and_never_malicious():
    lab, ctx = _lab_context({"virustotal": ("intel",)})
    lab.environment.set_reputation(ObservableType.SHA256, SHA, Verdict.MALICIOUS, risk_score=100, confidence=100,
                                   integrations=["virustotal"])
    report = enrich_hash(ctx, SHA)
    assert report.risk_score <= 50 and report.confidence <= 50
    assert report.verdict is Verdict.SUSPICIOUS


_SINGLE_VENDORS = [
    pytest.param("secure_malware_analytics", ("endpoint",), ObservableType.SHA256, SHA, enrich_hash,
                 id="sandbox-hash"),
    pytest.param("secure_email", ("email",), ObservableType.EMAIL_ADDRESS, "sender@phish.example", enrich_email_address,
                 id="email-gateway-address"),
    pytest.param("entra", ("identity",), ObservableType.USER, "jsmith@example.com", enrich_user,
                 id="identity-user"),
]


@pytest.mark.parametrize(("integration", "families", "otype", "value", "atomic"), _SINGLE_VENDORS)
def test_one_vendor_malicious_enrichment_is_never_an_aggregate_malicious_verdict(integration, families, otype,
                                                                                 value, atomic):
    """14.2.2: "One vendor's MALICIOUS alone is therefore SUSPICIOUS"; 14.1.3: verdict is never one vendor's word."""
    lab, ctx = _lab_context({integration: families})
    lab.environment.set_reputation(otype, value, Verdict.MALICIOUS, risk_score=100, confidence=95,
                                   integrations=[integration])
    report = atomic(ctx, value)
    assert report.answered == (integration,)
    assert report.verdict is not Verdict.MALICIOUS, (
        f"a single {integration} verdict became the aggregate verdict: {report.breakdown.explain()}")


@pytest.mark.parametrize(("integration", "families", "otype", "value", "atomic"), _SINGLE_VENDORS)
def test_one_vendor_verdict_cannot_reach_critical_with_high_confidence(integration, families, otype, value, atomic):
    """threat-scoring 5.4: a single source never reaches CRITICAL unless it is a high-severity behavioural detection."""
    lab, ctx = _lab_context({integration: families})
    lab.environment.set_reputation(otype, value, Verdict.MALICIOUS, risk_score=100, confidence=95,
                                   integrations=[integration])
    report = atomic(ctx, value)
    band = report.breakdown.risk_band
    assert not (band is RiskBand.CRITICAL and report.confidence >= 80), (
        f"one {integration} enrichment verdict alone: {report.breakdown.explain()}")


def test_one_source_cannot_corroborate_itself_into_critical():
    """Three medium (HIGH band) signals from the same EDR on the same host: no high-severity detection."""
    signals = [
        _signal("secure_endpoint", SignalCategory.ENDPOINT_DETECTION, severity=70, confidence=70, record_id="rec_p"),
        _signal("secure_endpoint", SignalCategory.NETWORK_BEHAVIOUR, severity=70, confidence=60, record_id="rec_n"),
        _signal("secure_endpoint", SignalCategory.PERSISTENCE, severity=70, confidence=60, record_id="rec_s"),
    ]
    breakdown = _engine().score(signals, context=ScoringContext())
    assert all(s.severity < 80 for s in signals)  # none is a high-severity detection on its own
    assert breakdown.risk_band is not RiskBand.CRITICAL, (
        f"a single integration reached CRITICAL by corroborating itself: {breakdown.explain()}")


def test_clean_verdict_never_lowers_risk_and_reputation_cap_survives_weight_override():
    base = [_signal("secure_endpoint", SignalCategory.ENDPOINT_DETECTION, severity=80, confidence=80,
                    record_id="rec_d")]
    clean = _signal("virustotal", SignalCategory.REPUTATION, severity=0, confidence=90, record_id="rec_c",
                    verdict=Verdict.CLEAN)
    engine = _engine()
    assert engine.score([*base, clean], context=ScoringContext()).risk_score == \
        engine.score(base, context=ScoringContext()).risk_score
    reputation = [_signal("virustotal", SignalCategory.REPUTATION, severity=100, confidence=100, record_id="rec_r")]
    overridden = engine.score(reputation, context=ScoringContext(), weights={SignalCategory.REPUTATION: 1.0})
    assert overridden.risk_score <= 50 and overridden.confidence_score <= 50


# ======================================================= 3. degraded and failed sources never crash or inflate
def test_every_source_failing_gives_an_empty_report_not_an_exception():
    lab, ctx = _lab_context({"secure_endpoint": ("endpoint",), "virustotal": ("intel",)})
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="secure_endpoint", operation="enrich", times=None)
    lab.environment.inject(FaultKind.RATE_LIMIT, integration="virustotal", operation="enrich", times=None)
    report = enrich_hash(ctx, SHA)
    assert (report.risk_score, report.confidence, report.verdict) == (0, 0, Verdict.UNKNOWN)
    assert {s.integration for s in report.sources if s.outcome is SourceOutcome.FAILED} == {
        "secure_endpoint", "virustotal"}


def test_failed_sources_never_raise_risk_or_confidence():
    signals = [_signal("secure_endpoint", SignalCategory.ENDPOINT_DETECTION, severity=80, confidence=80,
                       record_id="rec_d")]
    engine = _engine()
    clean = engine.score(signals, context=ScoringContext(expected_sources=("secure_endpoint", "virustotal")))
    for health in HealthStatus:
        degraded = engine.score(signals, context=ScoringContext(
            expected_sources=("secure_endpoint", "virustotal"), failed_sources=(("virustotal", health),)))
        assert degraded.risk_score == clean.risk_score
        assert degraded.confidence_score <= clean.confidence_score


def test_one_failed_source_is_penalised_once_whatever_its_error_mix():
    """5.2 step 5: subtract the penalty for each expected *source* that failed (not per error kind)."""
    signals = [_signal("secure_endpoint", SignalCategory.ENDPOINT_DETECTION, severity=80, confidence=80,
                       record_id="rec_d")]
    expected = ("secure_endpoint", "virustotal")
    engine = _engine()
    once = engine.score(signals, context=ScoringContext(
        expected_sources=expected, failed_sources=(("virustotal", HealthStatus.UNAVAILABLE),)))
    twice = engine.score(signals, context=ScoringContext(
        expected_sources=expected,
        failed_sources=(("virustotal", HealthStatus.UNAVAILABLE), ("virustotal", HealthStatus.RATE_LIMITED))))
    assert twice.confidence_score == once.confidence_score, twice.explain()


def test_a_failed_third_party_does_not_block_a_recommendation_backed_by_edr():
    lab = make_lab()
    lab.infected()
    lab.environment.inject(FaultKind.AUTH_FAIL, integration="virustotal", operation="enrich", times=None)
    run = _run(lab)
    assert {(p.action_type, p.target) for p in run.proposals} >= {(ActionType.ISOLATE_ENDPOINT, HOST)}
    assert lab.environment.state_changing_calls() == []


# ================================================================== 4. privacy: nothing internal to public intel
_INTEL_SUITE: Mapping[str, tuple[str, ...]] = {
    "umbrella": ("network",), "virustotal": ("intel",), "alienvault_otx": ("intel",), "hibp": ("intel",),
    "entra": ("identity",),
}


@pytest.mark.parametrize(("atomic", "value"), [
    (enrich_ip, "10.20.30.40"),
    (enrich_ip, "192.168.1.10"),
    (enrich_ip, "100.64.3.4"),             # CGNAT range from config/exclusions.yaml
    (enrich_ip, "fd00::1234"),
    (enrich_ip, "::ffff:10.20.30.40"),
    (enrich_url, "http://intranet/payroll"),
    (enrich_url, "https://fileserver.corp.example.com/share"),
    (enrich_url, "http://10.1.2.3:8080/admin"),
    (enrich_user, "jsmith@example.com"),
])
def test_internal_observables_never_reach_public_intel(atomic, value):
    lab, ctx = _lab_context(_INTEL_SUITE)
    report = atomic(ctx, value)
    assert _third_party_targets(lab) == []
    assert all(s.outcome is SourceOutcome.NOT_QUERIED for s in report.sources if s.integration in THIRD_PARTY)


def test_nat64_embedded_private_ipv4_is_not_disclosed():
    """64:ff9b::/96 (RFC 6052 well-known prefix) embedding 10.0.0.5 is an internal host, not a public IP."""
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_ip(ctx, "64:ff9b::a00:5")
    assert _third_party_targets(lab) == []


@pytest.mark.parametrize("address", [
    "jsmith@example.internal",       # built-in internal suffix "internal" and settings internal_domains
    "jsmith@corp.example.com",       # settings internal_domains / internal_domain_suffixes
    "svc-backup@dc01.local",         # built-in internal suffix "local"
])
def test_internal_mailbox_addresses_are_never_sent_to_hibp(address):
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_email_address(ctx, address)
    assert [t for i, t in _third_party_targets(lab) if i == "hibp"] == [], (
        f"{address} (an internal mailbox) was sent to HIBP")


def test_credentials_embedded_in_a_url_are_never_sent_to_public_intel():
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_url(ctx, "https://jsmith:FakePass-77zq@portal.example.com/login")
    leaked = [(i, t) for i, t in _third_party_targets(lab) if t and "FakePass-77zq" in t]
    assert leaked == [], f"URL userinfo (credentials) disclosed to {sorted({i for i, _ in leaked})}"


def test_public_indicators_still_reach_intel_and_policy_errors_fail_closed():
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_hash(ctx, SHA)  # hashes are not personal or internal data
    assert {i for i, _ in _third_party_targets(lab)} >= {"virustotal", "alienvault_otx"}

    class _Broken:
        def may_disclose(self, observable: Observable, integration: str) -> bool:
            raise RuntimeError("policy unavailable")

    import dataclasses

    lab2, ctx2 = _lab_context(_INTEL_SUITE)
    enrich_hash(dataclasses.replace(ctx2, disclosure=_Broken()), SHA)
    assert _third_party_targets(lab2) == []


# ======================================================== 5. notes and summaries never carry secrets or codes
def _incident() -> Incident:
    return Incident(incident_id="XDR-SEC-0001", title="Sample malware on TH-LT-1047", severity=Severity.HIGH,
                    created_at=NOW - timedelta(hours=1), workflow_id="sample-malware", workflow_version="1.0.0")


_RENDERERS = (render_incident_note, render_soc_notification, render_analyst_summary)


@pytest.mark.parametrize("note", [
    "Secure Endpoint isolation unlock code: 4F7Q2K9X",
    "isolation unlock code 4F7Q2K9X stays with the analyst",
    "UnlockCode=4F7Q2K9X",
    "Device passcode: 4F7Q2K9X",
])
def test_unlock_codes_never_appear_in_notifications(note):
    event = LifecycleEvent(kind=LifecycleEventKind.DETECTION_COMPLETED, at=NOW, incident=_incident(),
                           notes=(note,))
    for render in (render_incident_note, render_analyst_summary):
        draft = render(event)
        assert "4F7Q2K9X" not in draft.body and "4F7Q2K9X" not in draft.title, render.__name__


def test_tokens_and_credentials_in_notes_are_redacted():
    approval_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqc21pdGgifQ.c2lnbmF0dXJlLWZha2U"
    notes = ("vendor said Authorization: Bearer FAKEBEARERTOKEN123456",
             "token=" + approval_like,
             "client_secret: FAKECLIENTSECRET999")
    event = LifecycleEvent(kind=LifecycleEventKind.DETECTION_COMPLETED, at=NOW, incident=_incident(), notes=notes)
    for render in _RENDERERS:
        body = render(event).body
        for secret in ("FAKEBEARERTOKEN123456", approval_like, "FAKECLIENTSECRET999"):
            assert secret not in body, render.__name__


def test_runner_notes_and_summary_carry_no_secrets():
    lab = make_lab()
    lab.infected()
    lab.environment.inject(FaultKind.FAIL, integration="virustotal", operation="enrich", times=None)
    run = _run(lab)
    summary = run.summary()
    text = json.dumps({"notes": list(run.notes), "summary": summary.model_dump(mode="json")})
    for marker in ("Bearer ", "password", "api_key", "unlock"):
        assert marker.lower() not in text.lower()
    assert all(line.startswith("[rec_") for line in summary.evidence)


# ######################################################################################################
# Round 2 (P1, lens: evidence-scoring-privacy). Same rule: every test asserts the SAFE behaviour.
# ######################################################################################################
import dataclasses  # noqa: E402

from xdr_response.atomics.enrichment.atomics import enrich_domain  # noqa: E402
from xdr_response.lifecycle.recommendation import Recommendation  # noqa: E402
from xdr_response.lifecycle.workflow_adapter import (  # noqa: E402
    WorkflowInvestigationReport,
    WorkflowRecommender,
)


# ------------------------------------------------------- R2.1 evidence: forged drafts at the boundary
class _NoFallback:
    """Fallback recommender that proposes nothing (a refused run must never become proposals)."""

    def recommend(self, incident: Incident, investigation: Any) -> Recommendation:
        return Recommendation(incident_id=incident.incident_id, proposals=(), risk_score=0, confidence_score=0,
                              summary="nothing")


def test_workflow_recommender_never_forwards_evidence_that_cites_no_record_of_the_run():
    """The last read-zone boundary before PackageBuilder must check proposal evidence against the run.

    A proposal whose evidence draft names a record id the run never produced (an invented statement
    with a well-formed ``rec_`` id) must not reach the package.
    """
    lab = make_lab()
    lab.infected()
    run = _run(lab)
    assert run.proposals, run.notes
    forged_id = "rec_" + "ab" * 16
    assert forged_id not in run.index
    forged = EvidenceDraft(source="secure_endpoint",
                           summary="secure_endpoint: CRITICAL ransomware confirmed on TH-LT-1047", observed_at=NOW,
                           data={"record_id": forged_id, "kind": "detection", "atomic": "investigate_endpoint",
                                 "fields": {}})
    tampered_proposal = run.proposals[0].model_copy(update={"evidence": (forged,)})
    tampered = dataclasses.replace(run, proposals=(tampered_proposal, *run.proposals[1:]))
    report = WorkflowInvestigationReport(incident_id="XDR-SM-9001", run=tampered)
    try:
        recommendation = WorkflowRecommender(_NoFallback()).recommend(make_incident(), report)
    except (EvidenceError, ValueError):
        return  # refused: safe
    cited = {d.data.get("record_id") for p in recommendation.proposals for d in p.evidence}
    assert forged_id not in cited, "evidence citing a record the run never produced was forwarded to packaging"


# ------------------------------------------- R2.2 hook signals: a vendor verdict laundered as behaviour
class _LaunderingHooks(SampleMalwareHooks):
    """Re-labels VirusTotal's enrichment verdict as a behavioural endpoint detection.

    It cites the VirusTotal enrichment record (so the attribution check passes) plus an unrelated
    Secure Endpoint context record (so "cites only enrichment records" is false).
    """

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        records = view.index.records()
        vt = next(r for r in records if str(r.kind) == "enrichment" and r.integration == "virustotal")
        context = next(r for r in records if str(r.kind) == "endpoint")
        return [ScoringSignal(category=SignalCategory.ENDPOINT_DETECTION, integration="virustotal",
                              observable=Observable(type=ObservableType.SHA256, value=HASH),
                              verdict=Verdict.MALICIOUS, severity=100, confidence=100,
                              record_ids=(vt.record_id, context.record_id), origin=view.origin, note="pattern")]


def _vt_only_lab() -> Any:
    lab = make_lab()
    lab.infected()
    lab.environment.set_reputation(ObservableType.SHA256, HASH, Verdict.MALICIOUS, risk_score=90, confidence=85,
                                   integrations=["virustotal"])
    return lab


def test_hook_signal_attributed_to_an_enrichment_only_source_stays_a_vendor_verdict():
    run = _run(_vt_only_lab(), hooks=_LaunderingHooks())
    for signal in run.signals:
        own = [run.index.get(rid) for rid in signal.record_ids
               if run.index.get(rid).integration == signal.integration]
        if own and all(str(r.kind) == "enrichment" for r in own):
            assert signal.vendor_verdict, (
                f"{signal.integration} only answered an enrichment, yet its hook signal is a behavioural "
                f"{signal.category.value} (vendor_verdict=False)")


def test_one_reputation_verdict_cannot_be_laundered_into_a_critical_block():
    honest = _run(_vt_only_lab())
    laundered = _run(_vt_only_lab(), hooks=_LaunderingHooks())

    def hash_outcomes(run: WorkflowRun) -> list[Any]:
        return [o for o in run.outcomes if o.rule_id == "block_malicious_hash"]

    assert hash_outcomes(honest) and all(o.risk_score <= 50 for o in hash_outcomes(honest))
    for outcome in hash_outcomes(laundered):
        assert not (outcome.risk_score >= 80 and outcome.confidence_score >= 80), (
            f"one VirusTotal verdict became {outcome.status.value} risk {outcome.risk_score} / confidence "
            f"{outcome.confidence_score} through a hook signal")


# ------------------------------------------- R2.3 single-source cap: a negligible second source
def test_a_negligible_second_source_does_not_lift_the_single_vendor_cap():
    """threat-scoring 5.4: one vendor verdict never reaches CRITICAL on its own.

    The sandbox verdict is the only signal that carries weight; VirusTotal adds a SUSPICIOUS rating
    of severity 10 (weighted 6, below the corroboration minimum, so it corroborates nothing).
    """
    sha = Observable(type=ObservableType.SHA256, value=SHA)
    sandbox = ScoringSignal(category=SignalCategory.SANDBOX_VERDICT, integration="secure_malware_analytics",
                            observable=sha, verdict=Verdict.MALICIOUS, severity=100, confidence=95,
                            record_ids=("rec_sandbox",), vendor_verdict=True)
    whisper = ScoringSignal(category=SignalCategory.REPUTATION, integration="virustotal", observable=sha,
                            verdict=Verdict.SUSPICIOUS, severity=10, confidence=10, record_ids=("rec_vt",),
                            vendor_verdict=True)
    alone = _engine().score([sandbox], context=ScoringContext())
    assert alone.risk_band is not RiskBand.CRITICAL
    paired = _engine().score([sandbox, whisper], context=ScoringContext())
    assert not (paired.risk_band is RiskBand.CRITICAL and paired.confidence_score >= 80), (
        f"a sandbox verdict alone reached CRITICAL once a negligible rating was added: {paired.explain()}")


# ------------------------------------------- R2.4 privacy: IP literals in non-canonical spellings
@pytest.mark.parametrize(("atomic", "value"), [
    (enrich_url, "http://10.1.2.3./admin"),      # trailing dot: the URL host is the IPv4 address 10.1.2.3
    (enrich_url, "http://10.0.258/admin"),       # short form of 10.0.1.2
    (enrich_url, "http://0x0a.0.0.1/admin"),     # hex octet: 10.0.0.1
    (enrich_url, "http://10.1.2.03/admin"),      # octal octet: 10.1.2.3
    (enrich_url, "http://127.1/admin"),          # loopback short form
    (enrich_domain, "10.0.258"),                 # numeric "domain" that is an IPv4 literal
    (enrich_domain, "10.1.2.03"),
])
def test_internal_ip_literals_in_any_spelling_never_reach_public_intel(atomic, value):
    lab, ctx = _lab_context(_INTEL_SUITE)
    try:
        atomic(ctx, value)
    except ValueError:
        return  # refused as invalid input: safe
    assert _third_party_targets(lab) == [], f"{value} (an internal address) was disclosed"


@pytest.mark.parametrize("value", [
    "::a00:1",          # IPv4-compatible (::/96) form of 10.0.0.1
    "::ffff:0:a00:1",   # IPv4-translated (RFC 2765 ::ffff:0:0/96) form of 10.0.0.1
    "fec0::1",          # deprecated site-local (RFC 3879): never a public address
])
def test_ipv6_forms_of_internal_addresses_never_reach_public_intel(value):
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_ip(ctx, value)
    assert _third_party_targets(lab) == [], f"{value} was disclosed"


# ------------------------------------------- R2.5 privacy: secrets and personal data inside URLs
_SECRET_URLS = [
    pytest.param("https://app.example.com/callback#access_token=FAKETOKEN00001&state=x", "FAKETOKEN00001",
                 id="fragment-access-token"),
    pytest.param("https://bucket.example.com/f.bin?X-Amz-Credential=FAKECRED%2F20260101&"
                 "X-Amz-Signature=fakesig0123456789abcdef", "fakesig0123456789abcdef", id="s3-presigned"),
    pytest.param("https://storage.example.com/o.bin?X-Goog-Signature=fakegsig0123456789", "fakegsig0123456789",
                 id="gcs-signed"),
]


@pytest.mark.parametrize(("url", "secret"), _SECRET_URLS)
def test_secret_bearing_urls_are_never_sent_to_public_intel(url, secret):
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_url(ctx, url)
    leaked = [i for i, t in _third_party_targets(lab) if t and secret in t]
    assert leaked == [], f"a URL credential was disclosed to {sorted(set(leaked))}"


def test_urls_carrying_a_mailbox_address_are_never_sent_to_public_intel():
    """An email address in a URL query is personal data (and VT/OTX never get email addresses)."""
    lab, ctx = _lab_context(_INTEL_SUITE)
    enrich_url(ctx, "https://portal.example.com/reset?email=jsmith@example.com")
    leaked = [i for i, t in _third_party_targets(lab) if t and "jsmith@example.com" in t]
    assert leaked == [], f"a mailbox address was disclosed to {sorted(set(leaked))}"


@pytest.mark.parametrize(("url", "secret"), _SECRET_URLS[1:])
def test_signed_url_signatures_never_travel_into_evidence(url, secret):
    record = NetworkConnectionRecord(
        integration="umbrella", atomic="investigate_domain",
        subject=Observable(type=ObservableType.DOMAIN, value="bucket.example.com"),
        endpoint=HOST, domain="bucket.example.com", direction="outbound", action="allowed",
        verdict=Verdict.MALICIOUS, url=url)
    text = json.dumps(evidence_draft(record).model_dump(mode="json"))
    assert secret not in text


# ------------------------------------------- R2.6 notes: unlock codes and signed URLs in prose
@pytest.mark.parametrize("note", [
    "Isolation unlock code for TH-LT-1047 is 4F7Q2K9X",
    "unlock code (TH-LT-1047): 4F7Q2K9X",
    "the code to unlock TH-LT-1047 is 4F7Q2K9X",
])
def test_unlock_codes_naming_the_host_never_appear_in_notifications(note):
    event = LifecycleEvent(kind=LifecycleEventKind.DETECTION_COMPLETED, at=NOW, incident=_incident(),
                           notes=(note,))
    for render in _RENDERERS:
        draft = render(event)
        assert "4F7Q2K9X" not in draft.body and "4F7Q2K9X" not in draft.title, render.__name__


def test_signed_url_signatures_never_appear_in_notifications():
    note = ("sample fetched from https://bucket.example.com/f.bin?X-Amz-Credential=FAKECRED%2F20260101&"
            "X-Amz-Signature=fakesig0123456789abcdef")
    event = LifecycleEvent(kind=LifecycleEventKind.DETECTION_COMPLETED, at=NOW, incident=_incident(),
                           notes=(note,))
    for render in _RENDERERS:
        assert "fakesig0123456789abcdef" not in render(event).body, render.__name__
