"""WorkflowDefinition validators (architecture 14.3.1) and trigger matching."""
from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from tests.fixtures.sample_workflows.lab import make_incident
from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW
from xdr_response.models import ActionType, ObservableType
from xdr_response.workflows import definition as definition_module
from xdr_response.workflows.definition import (
    APPROVAL_LIKE_KEYS,
    TACTICS,
    InvestigationStep,
    MitreMapping,
    RecommendationRule,
    TriggerSpec,
    WorkflowDefinition,
)


def _data(**changes: Any) -> dict[str, Any]:
    data = WORKFLOW.model_dump()
    data.update(changes)
    return data


def _rule(**changes: Any) -> dict[str, Any]:
    rule = WORKFLOW.recommendations[0].model_dump()
    rule.update(changes)
    return rule


def _step(**changes: Any) -> dict[str, Any]:
    step = WORKFLOW.investigation[0].model_dump()
    step.update(changes)
    return step


def _invalid(match: str, **changes: Any) -> None:
    with pytest.raises(ValidationError, match=match):
        WorkflowDefinition.model_validate(_data(**changes))


def test_the_sample_definition_is_valid_and_round_trips():
    again = WorkflowDefinition.model_validate(WORKFLOW.model_dump())
    assert again == WORKFLOW
    assert WORKFLOW.package_name == "sample_malware"
    assert WORKFLOW.attack_ids() == {"T1204", "T1204.002"}
    assert WORKFLOW.expected_sources() == ("secure_endpoint",)
    assert WORKFLOW.integrations() == ("secure_endpoint", "virustotal")
    assert WORKFLOW.mitre[0].tactic_name == "Execution" and WORKFLOW.mitre[0].attack_id == "T1204.002"


def test_tactics_are_the_14_enterprise_tactics_and_approval_keys_cover_config():
    from xdr_response.config.loader import FORBIDDEN_KEYS

    assert len(TACTICS) == 14 and TACTICS["TA0011"] == "Command and Control"
    assert FORBIDDEN_KEYS <= APPROVAL_LIKE_KEYS
    assert {"approval_level", "requires_approval", "approve", "approved"} <= APPROVAL_LIKE_KEYS


@pytest.mark.parametrize("bad_id", ["Sample", "sample_malware", "-sample", "sample--x", ""])
def test_workflow_id_must_be_kebab_case(bad_id):
    _invalid("kebab-case", id=bad_id)


def test_version_must_be_semver():
    _invalid("semantic", version="1.0")


def test_required_lists_must_not_be_empty():
    for name in ("triggers", "input_observables", "required_integrations", "investigation", "recommendations",
                 "mitre", "known_limitations"):
        with pytest.raises(ValidationError):
            WorkflowDefinition.model_validate(_data(**{name: ()}))


def test_duplicate_step_and_rule_ids_are_refused():
    _invalid("duplicate step ids", investigation=[_step(), _step()])
    _invalid("duplicate rule ids", recommendations=[_rule(), _rule()])


def test_integrations_must_be_known_and_disjoint():
    required = WORKFLOW.required_integrations[0].model_dump()
    _invalid("both required and optional", optional_integrations=[required])
    _invalid("unknown integration", required_integrations=[{**required, "integration": "acme_edr"}])


def test_step_integrations_must_be_declared():
    _invalid("not required or optional", investigation=[_step(integrations=("entra",))])


def test_expected_sources_must_be_declared():
    scoring = WORKFLOW.scoring.model_dump()
    _invalid("expected_sources", scoring={**scoring, "expected_sources": ("entra",)})


@pytest.mark.parametrize("expression", ["item.hostname +", "__import__('os')", "open('x')", "item.__class__()",
                                        "(lambda: 1)()", "{k: v for k, v in item}"])
def test_every_expression_is_parsed_at_import_time(expression):
    _invalid("rule target", recommendations=[_rule(target=expression)])


def test_step_expressions_are_parsed():
    _invalid("step when", investigation=[_step(when="eval('1')")])


def test_rule_action_must_be_containment_or_remediation():
    _invalid("only CONTAINMENT or REMEDIATION", recommendations=[_rule(action=ActionType.RELEASE_ENDPOINT,
                                                                          builder=None)])
    _invalid("only CONTAINMENT or REMEDIATION", recommendations=[_rule(action=ActionType.ENRICH_IP, builder=None)])


def test_builder_must_exist_and_build_the_rule_action():
    _invalid("unknown builder", recommendations=[_rule(builder="isolate_everything")])
    _invalid("builds block_hash", recommendations=[_rule(builder="block_hash")])


@pytest.mark.parametrize("key", ["integration", "verify_integration", "restores", "approval_level", "auto_approve",
                                 "api_key", "password"])
def test_reserved_and_secret_params_are_refused(key):
    with pytest.raises(ValidationError, match="reserved|secret|approval"):
        RecommendationRule.model_validate(_rule(params={key: "'x'"}))


def test_rule_mitre_ids_must_be_mapped():
    _invalid("not in the workflow's mitre mappings", recommendations=[_rule(mitre=("T1486",))])


@pytest.mark.parametrize("where", ["options", "nested"])
def test_no_approval_switch_anywhere(where):
    options = {"auto_approve": True} if where == "options" else {"query": {"requires_approval": False}}
    _invalid("cannot carry approval settings", investigation=[_step(options=options)])


def test_every_approval_like_key_is_refused_case_insensitively():
    for key in sorted(APPROVAL_LIKE_KEYS):
        _invalid("cannot carry approval settings", investigation=[_step(options={key.upper(): 1})])


def test_legacy_id_must_be_the_id_or_a_legacy_spec():
    assert WorkflowDefinition.model_validate(_data(legacy_id="malware")).legacy_id == "malware"
    assert WorkflowDefinition.model_validate(_data(legacy_id="sample-malware")).legacy_id == "sample-malware"
    _invalid("legacy spec id", legacy_id="powershell")


def test_mitre_mapping_rules():
    base = WORKFLOW.mitre[0].model_dump()
    with pytest.raises(ValidationError, match="unknown ATT&CK tactic"):
        MitreMapping.model_validate({**base, "tactic": "TA9999"})
    with pytest.raises(ValidationError, match="does not belong"):
        MitreMapping.model_validate({**base, "sub_technique": "T1059.001"})
    with pytest.raises(ValidationError, match="must look like"):
        MitreMapping.model_validate({**base, "technique": "1204"})
    with pytest.raises(ValidationError, match="needs a sub_technique_name"):
        MitreMapping.model_validate({**base, "sub_technique_name": None})
    _invalid("duplicate MITRE mapping ids", mitre=[base, base])


def test_step_subject_rules():
    with pytest.raises(ValidationError, match="unknown read atomic"):
        InvestigationStep(id="x", atomic="isolate_endpoint")
    with pytest.raises(ValidationError, match="subject_type is required"):
        InvestigationStep(id="x", atomic="investigate_endpoint", subjects="['TH-LT-1047']")
    with pytest.raises(ValidationError, match="does not accept"):
        InvestigationStep(id="x", atomic="enrich_hash", subject_type=ObservableType.DOMAIN)
    with pytest.raises(ValidationError, match="investigation atomics only"):
        InvestigationStep(id="x", atomic="enrich_hash", integrations=("virustotal",))
    with pytest.raises(ValidationError, match="snake_case"):
        InvestigationStep(id="Bad-Id", atomic="enrich_hash")
    with pytest.raises(ValidationError):
        InvestigationStep(id="x", atomic="enrich_hash", max_subjects=0)
    with pytest.raises(ValidationError):
        InvestigationStep(id="x", atomic="investigate_endpoint", lookback_hours=721)
    step = InvestigationStep(id="x", atomic="investigate_domain", subjects="['bad.example']")
    assert step.subject_types() == {ObservableType.DOMAIN}


def test_correlation_window_and_weights_are_bounded():
    correlation = WORKFLOW.correlation.model_dump()
    _invalid("less than or equal", correlation={**correlation, "window_minutes": 2000})
    scoring = WORKFLOW.scoring.model_dump()
    _invalid("within 0.0-1.0", scoring={**scoring, "weights": {"reputation": 1.5}})
    _invalid("Input should be", scoring={**scoring, "weights": {"made_up": 0.5}})


def test_the_link_and_signal_enums_are_the_real_step_0_types():
    from xdr_response.atomics.correlation.models import LinkKind
    from xdr_response.models.scoring import SignalCategory

    assert definition_module.LinkKind is LinkKind
    assert definition_module.SignalCategory is SignalCategory
    assert LinkKind.WORKFLOW not in WORKFLOW.correlation.link_kinds


def test_private_mirrors_match_the_atomic_tables():
    from xdr_response.atomics import atomic_subject_types, containment_builders
    from xdr_response.atomics.containment.builders import RESERVED_PARAM_KEYS

    assert dict(definition_module._READ_ATOMIC_SUBJECTS) == dict(atomic_subject_types())
    builders = containment_builders()
    assert set(definition_module._BUILDER_ACTIONS) == set(builders)
    assert definition_module._RESERVED_PARAM_KEYS <= RESERVED_PARAM_KEYS


# ------------------------------------------------------------------ triggers --
def _trigger(**changes: Any) -> TriggerSpec:
    return TriggerSpec.model_validate({"type": "xdr_incident_rule", "description": "test", **changes})


def test_an_automatic_trigger_needs_a_criterion():
    with pytest.raises(ValidationError, match="at least one matching criterion"):
        _trigger()
    assert TriggerSpec(type="manual", description="analyst").matches(make_incident()) is False
    assert TriggerSpec(type="schedule", description="nightly").matches(make_incident()) is False


def test_trigger_criteria_are_and_of_ors():
    incident = make_incident(trigger={"mitre_techniques": ["T1204.002"], "source": "secure_endpoint"})
    assert _trigger(mitre_techniques=("T1204",)).matches(incident)  # sub-technique matches its parent
    assert _trigger(mitre_techniques=("T1204.002", "T1486")).matches(incident)
    assert not _trigger(mitre_techniques=("T1486",)).matches(incident)
    assert _trigger(title_patterns=("*SAMPLE MALWARE*",)).matches(incident)
    assert not _trigger(title_patterns=("phishing*",)).matches(incident)
    assert _trigger(sources=("secure_endpoint",)).matches(incident)
    assert _trigger(sources=("cisco_xdr",)).matches(incident)  # incident.source default
    assert not _trigger(sources=("entra",)).matches(incident)
    assert _trigger(observable_types=(ObservableType.SHA256, ObservableType.HOSTNAME)).matches(incident)
    assert not _trigger(observable_types=(ObservableType.SHA256,)).matches(incident)
    assert not _trigger(title_patterns=("*sample*",), sources=("entra",)).matches(incident)


def test_definition_matches_picks_the_highest_priority_trigger():
    data = _data(triggers=[{"type": "xdr_incident_rule", "description": "low", "title_patterns": ["*"],
                            "priority": 5},
                           {"type": "webhook", "description": "high", "title_patterns": ["*sample*"],
                            "priority": 50}])
    definition = WorkflowDefinition.model_validate(data)
    assert definition.matches(make_incident()).description == "high"
    assert definition.matches(make_incident(title="Other")).description == "low"


# ------------------------------------------------------- hand-off targets (14.10.1) --
def test_handoff_targets_must_be_related_kebab_case_and_unique():
    ok = WorkflowDefinition.model_validate(_data(related_workflows=("account-takeover", "c2"),
                                                 handoff_to=("account-takeover",)))
    assert ok.handoff_to == ("account-takeover",)
    with pytest.raises(ValidationError, match="must also be listed in related_workflows"):
        WorkflowDefinition.model_validate(_data(related_workflows=("c2",), handoff_to=("account-takeover",)))
    with pytest.raises(ValidationError, match="handoff_to ids must be kebab-case"):
        WorkflowDefinition.model_validate(_data(related_workflows=("Account_Takeover",),
                                                handoff_to=("Account_Takeover",)))
    with pytest.raises(ValidationError, match="related_workflows lists ids twice"):
        WorkflowDefinition.model_validate(_data(related_workflows=("c2", "c2")))
