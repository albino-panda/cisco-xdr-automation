"""WorkflowRunner (architecture 14.3.4): deterministic, read-only, never raises for a source, rule or hook."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import HASH, HOST, make_incident, make_lab
from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW
from tests.fixtures.sample_workflows.sample_malware.hooks import HOOKS, SampleMalwareHooks
from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.evidence import EvidenceBuilder
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import ActionType, HealthStatus, ObservableType, TargetKind, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.definition import WorkflowDefinition
from xdr_response.workflows.hooks import RunView, WorkflowHooks
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun, WorkflowRunner

ISOLATE = f"isolate_endpoint:{HOST}"
BLOCK = f"block_hash:{HASH}"


def _variant(**changes: Any) -> WorkflowDefinition:
    return WorkflowDefinition.model_validate({**WORKFLOW.model_dump(), **changes})


def _rule(index: int = 0, **changes: Any) -> dict[str, Any]:
    return {**WORKFLOW.recommendations[index].model_dump(), **changes}


def _run(lab, definition: WorkflowDefinition = WORKFLOW, hooks: WorkflowHooks | None = HOOKS, *,
         dry_run: bool = True, incident=None) -> WorkflowRun:
    return lab.runner.run(definition, hooks, incident or make_incident(), dry_run=dry_run)


def _selectors(run: WorkflowRun, status: RuleOutcomeStatus) -> set[str]:
    return {o.selector for o in run.outcomes_with(status)}


def test_a_true_positive_proposes_both_actions_with_cited_evidence(lab):
    lab.infected()
    run = _run(lab)
    assert {f"{p.action_type.value}:{p.target}" for p in run.proposals} == {ISOLATE, BLOCK}
    assert _selectors(run, RuleOutcomeStatus.PROPOSED) == {ISOLATE, BLOCK}
    assert run.proposals == tuple(b.proposal for b in run.built if b.proposal)
    builder = EvidenceBuilder(run.index)
    for proposal in run.proposals:
        builder.verify(proposal.evidence)  # every item is exactly a record of this run
        assert proposal.evidence and all(e.data["record_id"] in run.index for e in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
        assert "settings " in proposal.rationale  # breakdown.explain() reaches the package
        assert proposal.params["integration"] == "secure_endpoint"
    isolate = next(p for p in run.proposals if p.action_type is ActionType.ISOLATE_ENDPOINT)
    assert isolate.rationale.startswith(f"malicious detection on {HOST}; risk ")
    assert isolate.asset is not None and isolate.asset.groups == ("Workstations",)
    assert run.risk_score == max(p.risk_score for p in run.proposals)
    assert run.health["secure_endpoint"] is HealthStatus.CONNECTED
    assert (ActionType.BLOCK_HASH, HASH) in run.breakdowns


def test_reads_only_and_never_changes_state(lab):
    lab.infected()
    _run(lab, dry_run=False)
    assert lab.environment.state_changing_calls() == []


def test_runs_are_deterministic_and_dry_run_scores_identically():
    first_lab, second_lab = make_lab(), make_lab(dry_run=False)
    first_lab.infected()
    second_lab.infected()
    first, second = _run(first_lab), _run(second_lab, dry_run=False)
    assert [p.model_dump() for p in first.proposals] == [p.model_dump() for p in second.proposals]
    assert first.outcomes == second.outcomes and first.notes == second.notes
    assert (first.risk_score, first.confidence_score) == (second.risk_score, second.confidence_score)
    assert first.dry_run is True and second.dry_run is False


def test_summary_and_raw_results(lab):
    lab.infected()
    run = _run(lab)
    summary = run.summary()
    assert (summary.workflow_id, summary.workflow_version) == ("sample-malware", "1.0.0")
    assert summary.risk_score == run.risk_score and summary.confidence_score == run.confidence_score
    assert summary.evidence and all(line.startswith("[rec_") for line in summary.evidence)
    assert HOST in summary.blast_radius.endpoints
    assert {r.integration for r in run.raw_enrichments()} == {"secure_endpoint", "virustotal"}
    assert {r.action_type for r in run.raw_investigations()} == {ActionType.INVESTIGATE_ENDPOINT}


def test_earlier_finds_feed_later_default_subjects(lab):
    lab.infected()
    run = _run(lab)  # the incident carries only the hostname; the hash comes from the detection record
    assert [r.subject.value for r in run.results if r.atomic == "enrich_hash"] == [HASH]


def test_a_failed_source_degrades_but_never_blocks(lab):
    lab.infected()
    healthy = _run(lab)
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="virustotal", operation="enrich", times=5)
    degraded = _run(lab)
    assert {f"{p.action_type.value}:{p.target}" for p in degraded.proposals} == {ISOLATE, BLOCK}
    assert degraded.degraded_sources() == ("virustotal",)
    assert degraded.health["virustotal"] is HealthStatus.UNAVAILABLE
    assert any(n.startswith("degraded source: virustotal (UNAVAILABLE)") for n in degraded.notes)
    block = (ActionType.BLOCK_HASH, HASH)
    assert degraded.breakdowns[block].confidence_score < healthy.breakdowns[block].confidence_score
    assert "virustotal (UNAVAILABLE)" in degraded.breakdowns[block].failed_sources


def test_a_disabled_required_integration_is_noted_and_other_evidence_counts():
    lab = make_lab({"secure_endpoint": ("endpoint",)})
    lab.infected()
    definition = _variant(required_integrations=[*(r.model_dump() for r in WORKFLOW.required_integrations),
                                                 {"integration": "entra", "purpose": "identity context"}])
    run = _run(lab, definition)
    assert any("required integration entra is not enabled" in n for n in run.notes)
    assert ISOLATE in _selectors(run, RuleOutcomeStatus.PROPOSED)


def test_benign_proposes_nothing(lab):
    lab.typed("investigate_endpoint", HOST, "secure_endpoint", kind="endpoint", hostname=HOST)
    run = _run(lab)
    assert run.proposals == () and run.outcomes == () and (run.risk_score, run.confidence_score) == (0, 0)


def test_below_threshold_is_listed_never_hidden(lab):
    lab.infected()
    run = _run(lab, _variant(recommendations=[_rule(0, min_risk=100), _rule(1, min_confidence=100)]))
    assert run.proposals == ()
    assert _selectors(run, RuleOutcomeStatus.BELOW_THRESHOLD) == {ISOLATE, BLOCK}
    assert sum("below threshold" in n for n in run.notes) == 2
    assert all(o.risk_score > 0 for o in run.outcomes)


def test_no_evidence_and_unknown_record_ids(lab):
    lab.infected()
    run = _run(lab, _variant(recommendations=[_rule(0, evidence="[]"), _rule(1, evidence="['rec_unknown']")]))
    assert run.proposals == ()
    assert _selectors(run, RuleOutcomeStatus.NO_EVIDENCE) == {ISOLATE, BLOCK}
    unknown = next(o for o in run.outcomes if o.action_type is ActionType.BLOCK_HASH)
    assert "rec_unknown" in unknown.detail


def test_a_rule_error_is_reported_and_other_rules_still_run(lab):
    lab.infected()
    run = _run(lab, _variant(recommendations=[_rule(0, target="item.no_such_field"), _rule(1)]))
    errors = run.outcomes_with(RuleOutcomeStatus.ERROR)
    assert len(errors) == 1 and "field 'no_such_field' is missing" in errors[0].detail
    assert _selectors(run, RuleOutcomeStatus.PROPOSED) == {BLOCK}
    assert any(n.startswith("rule isolate_infected_endpoint error") for n in run.notes)


def test_for_each_must_give_a_list(lab):
    lab.infected()
    run = _run(lab, _variant(recommendations=[_rule(0, for_each="'TH-LT-1047'")]))
    assert run.outcomes[0].status is RuleOutcomeStatus.ERROR and "must give a list" in run.outcomes[0].detail


def test_builder_refusals_become_errors(lab):
    lab.infected()
    run = _run(lab, _variant(recommendations=[_rule(0, params={"note_ratio": "0.5"})]))
    assert run.outcomes[0].status is RuleOutcomeStatus.ERROR and "builder:" in run.outcomes[0].detail


def test_duplicates_merge_evidence_and_keep_the_higher_risk(lab):
    lab.infected()
    second = _rule(0, id="isolate_again", builder=None, min_risk=0,
                   evidence="ids([e for e in item.endpoints])", rationale="'endpoint record'")
    run = _run(lab, _variant(recommendations=[_rule(0), second]))
    assert [p.action_type for p in run.proposals] == [ActionType.ISOLATE_ENDPOINT]
    assert _selectors(run, RuleOutcomeStatus.DUPLICATE) == {ISOLATE}
    proposal = run.proposals[0]
    kinds = {e.data["kind"] for e in proposal.evidence}
    assert kinds == {"detection", "endpoint"}
    assert proposal.risk_score == run.breakdowns[(ActionType.ISOLATE_ENDPOINT, HOST)].risk_score


def test_unrouted_actions_are_reported_for_manual_handling():
    lab = make_lab({"secure_endpoint": ("endpoint",)})
    lab.infected()
    rule = _rule(1, id="disable_user", action=ActionType.DISABLE_USER, builder=None,
                 for_each="results.investigate_endpoint", target="'jsmith@example.com'",
                 evidence="ids(item.detections)", rationale="'user of the infected endpoint'", min_risk=0)
    run = _run(lab, _variant(recommendations=[rule]))
    assert run.proposals == ()
    assert _selectors(run, RuleOutcomeStatus.UNROUTED) == {"disable_user:jsmith@example.com"}
    assert run.built[0].proposal is None and run.built[0].unrouted_reason
    assert any("manual handling required" in n for n in run.notes)
    assert run.summary().unrouted[0].startswith("disable_user jsmith@example.com: ")


def test_allow_listed_targets_are_still_built_and_noted(lab):
    lab.infected(host="TH-DC-01")
    run = _run(lab, incident=make_incident((ObservableType.HOSTNAME, "TH-DC-01")))
    isolate = next(b for b in run.built if b.action_type is ActionType.ISOLATE_ENDPOINT)
    assert isolate.proposal is not None and isolate.excluded_reason
    assert any(n.startswith("allow-listed (shown as excluded") for n in run.notes)


def test_critical_assets_are_noted_with_the_warning(lab):
    lab.infected(host="PRD-DB-07")
    run = _run(lab, incident=make_incident((ObservableType.HOSTNAME, "PRD-DB-07")))
    isolate = next(b for b in run.built if b.action_type is ActionType.ISOLATE_ENDPOINT)
    assert isolate.warnings and "ELEVATED APPROVAL REQUIRED" in isolate.warnings[0].message
    assert any(n.startswith("critical asset: isolate_endpoint PRD-DB-07") for n in run.notes)
    breakdown = run.breakdowns[(ActionType.ISOLATE_ENDPOINT, "PRD-DB-07")]
    assert any(c.category == "critical_asset" for c in breakdown.contributions)


# ----------------------------------------------------------------- steps --
def test_step_conditions_subjects_and_truncation(lab):
    lab.infected()
    steps = [
        {"id": "endpoint", "atomic": "investigate_endpoint"},
        {"id": "skipped", "atomic": "investigate_domain", "when": "len(results.investigate_endpoint) == 0"},
        {"id": "broken", "atomic": "investigate_domain", "subjects": "no_such_name"},
        {"id": "domains", "atomic": "investigate_domain", "max_subjects": 1,
         "subjects": "['one.example', 'two.example', 'one.example']"},
        {"id": "hash_reputation", "atomic": "enrich_hash"},
    ]
    run = _run(lab, _variant(investigation=steps))
    assert any(n == "step skipped skipped: condition is false" for n in run.notes)
    assert any(n.startswith("step broken skipped: subjects failed") for n in run.notes)
    assert any("1 subject(s) not queried (max_subjects 1): two.example" in n for n in run.notes)
    assert [r.subject.value for r in run.results if r.atomic == "investigate_domain"] == ["one.example"]
    assert _selectors(run, RuleOutcomeStatus.PROPOSED) == {ISOLATE, BLOCK}


def test_a_step_without_subjects_is_noted(lab):
    run = _run(lab, incident=make_incident((ObservableType.SHA256, HASH), title="hash only"))
    assert any(n.startswith("step endpoint: no investigate_endpoint subject") for n in run.notes)


def test_an_invalid_subject_value_is_noted_not_raised(lab):
    steps = [{"id": "ips", "atomic": "investigate_ip", "subject_type": "ip", "subjects": "['not-an-ip']"}]
    run = _run(lab, _variant(investigation=steps))
    assert any(n.startswith("step ips: investigate_ip not-an-ip failed") for n in run.notes)


# ----------------------------------------------------------------- hooks --
class _BrokenHooks(WorkflowHooks):
    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        raise RuntimeError("correlate exploded")

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        raise RuntimeError("signals exploded")

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return {"bad": object()}


class _InvalidHooks(WorkflowHooks):
    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        entities = (EntityRef(kind=TargetKind.ENDPOINT, value=HOST), EntityRef(kind=TargetKind.HASH, value=HASH))
        return ["not a link", _link(entities, ("rec_" + "0" * 32,), view.origin),
                _link(entities, view.index.ids()[:1], "workflow:someone-else")]

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        record = view.index.ids()[0]
        return [_signal(record, "framework"), _signal("rec_" + "1" * 32, view.origin)]


class _GoodHooks(SampleMalwareHooks):
    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        assert view.correlation is None and view.blast_radius is None
        entities = (EntityRef(kind=TargetKind.ENDPOINT, value=HOST), EntityRef(kind=TargetKind.HASH, value=HASH))
        return [_link(entities, view.index.ids()[:1], view.origin)]

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        assert view.correlation is not None
        return [_signal(view.index.ids()[0], view.origin)]


def _link(entities: tuple[EntityRef, ...], record_ids: Sequence[str], origin: str) -> CorrelationLink:
    return CorrelationLink.model_validate({"kind": LinkKind.WORKFLOW, "entities": entities,
                                           "record_ids": tuple(record_ids), "note": "hook link", "origin": origin})


def _signal(record_id: str, origin: str) -> ScoringSignal:
    from xdr_response.models import Observable

    return ScoringSignal(category=SignalCategory.LATERAL_MOVEMENT, integration="secure_endpoint",
                         observable=Observable(type=ObservableType.HOSTNAME, value=HOST), verdict=Verdict.MALICIOUS,
                         severity=90, confidence=80, record_ids=(record_id,), origin=origin, note="hook signal")


def test_hook_exceptions_and_non_json_facts_are_noted_and_ignored(lab):
    lab.infected()
    definition = _variant(recommendations=[_rule(0, when="any(d.verdict == 'MALICIOUS' for d in item.detections)"),
                                           _rule(1)])
    run = _run(lab, definition, _BrokenHooks())
    assert any(n.startswith("hook correlate failed: RuntimeError") for n in run.notes)
    assert any(n.startswith("hook derive_signals failed") for n in run.notes)
    assert any(n.startswith("hook facts ignored") for n in run.notes)
    assert _selectors(run, RuleOutcomeStatus.PROPOSED) == {ISOLATE, BLOCK}


def test_invalid_hook_links_and_signals_are_ignored(lab):
    lab.infected()
    run = _run(lab, _variant(recommendations=[_rule(1)]), _InvalidHooks())
    ignored = [n for n in run.notes if n.startswith(("hook link ignored", "hook signal ignored"))]
    assert len(ignored) == 5 and run.signals == ()
    assert all(link.origin == "framework" for link in run.correlation.links)


def test_valid_hook_links_and_signals_are_used(lab):
    lab.infected()
    run = _run(lab, WORKFLOW, _GoodHooks())
    assert len(run.signals) == 1 and run.signals[0].origin == "workflow:sample-malware"
    assert any(link.origin == "workflow:sample-malware" for link in run.correlation.links)
    breakdown = run.breakdowns[(ActionType.ISOLATE_ENDPOINT, HOST)]
    assert any(c.category == SignalCategory.LATERAL_MOVEMENT for c in breakdown.contributions)


def test_facts_reach_rule_expressions(lab):
    lab.infected()
    run = _run(lab, WORKFLOW, None)  # without hooks, facts is {} and the sample rule's `when` fails
    assert ISOLATE not in _selectors(run, RuleOutcomeStatus.PROPOSED)
    assert any("field 'malicious_detections' is missing" in o.detail for o in run.outcomes)


def test_the_runner_only_accepts_the_read_only_facade(lab):
    with pytest.raises(TypeError, match="ReadOnlyAdapters"):
        WorkflowRunner(lab.registry, lab.settings, clock=lab.clock)  # type: ignore[arg-type]


def test_correlation_failures_never_block(lab, monkeypatch):
    import xdr_response.workflows.runner as runner_module

    real = runner_module.correlate

    def flaky(ctx, results, *, extra_links=(), **kwargs):
        if extra_links:
            raise ValueError("bad hook link")
        return real(ctx, results, extra_links=extra_links, **kwargs)

    lab.infected()
    monkeypatch.setattr(runner_module, "correlate", flaky)
    run = _run(lab, WORKFLOW, _GoodHooks())
    assert "hook links ignored: correlation is retried without them" in run.notes
    assert run.correlation.entities and _selectors(run, RuleOutcomeStatus.PROPOSED) == {ISOLATE, BLOCK}

    def broken(*args, **kwargs):
        raise RuntimeError("correlation down")

    monkeypatch.setattr(runner_module, "correlate", broken)
    run = _run(lab)
    assert any(n.startswith("correlation failed: RuntimeError") for n in run.notes)
    assert run.correlation.entities == () and _selectors(run, RuleOutcomeStatus.PROPOSED) == {ISOLATE, BLOCK}


# ------------------------------------------------------------- integration fixes (Phase 1 step 2) --
def test_the_same_read_runs_once_per_run(lab):
    """A second step enriching the same observable reuses the first result (no second fetch)."""
    from xdr_response.workflows.definition import InvestigationStep

    lab.infected()
    steps = (*WORKFLOW.investigation, InvestigationStep(id="hash_reputation_again", atomic="enrich_hash"))
    run = _run(lab, _variant(investigation=steps))
    hashes = [r for r in run.results if r.atomic == "enrich_hash" and r.subject.value == HASH]
    assert len(hashes) == 1
    assert not any("records rejected" in note for note in run.notes)
    assert {f"{p.action_type.value}:{p.target}" for p in run.proposals} == {ISOLATE, BLOCK}


def test_a_source_withheld_by_the_disclosure_policy_does_not_hide_its_real_health(lab):
    """VirusTotal answers for the hash; withholding a private IP from it must not make it UNKNOWN."""
    from xdr_response.atomics.records import SourceOutcome
    from xdr_response.workflows.definition import InvestigationStep

    lab.infected()
    steps = (*WORKFLOW.investigation, InvestigationStep(id="ip_reputation", atomic="enrich_ip"))
    definition = _variant(investigation=steps,
                          input_observables=(ObservableType.HOSTNAME, ObservableType.SHA256, ObservableType.IP))
    incident = make_incident((ObservableType.HOSTNAME, HOST), (ObservableType.IP, "10.20.30.40"))
    run = _run(lab, definition, incident=incident)
    ip_result = next(r for r in run.results if r.atomic == "enrich_ip")
    withheld = next(s for s in ip_result.sources if s.integration == "virustotal")
    assert withheld.outcome is SourceOutcome.NOT_QUERIED and withheld.health is HealthStatus.UNKNOWN
    assert run.health["virustotal"] is HealthStatus.CONNECTED
    assert "virustotal" not in run.degraded_sources()
