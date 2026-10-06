"""Runtime wiring (guard verifier, dry-run flag, denial hook, durable stores) and orchestrator edge cases."""
from __future__ import annotations

import shutil
from datetime import timedelta
from pathlib import Path

import pytest

from tests.fixtures.factories import FIXED_NOW, make_incident
from tests.fixtures.principals import make_authenticator, make_test_secrets
from tools.simulator.scenario import ScenarioRun, load_scenario
from xdr_response import guard
from xdr_response.audit import AuditTrail, MemoryAuditTrail
from xdr_response.audit.verify import verify_chain
from xdr_response.clock import FixedClock
from xdr_response.config import Settings
from xdr_response.errors import (
    ApprovalRequiredError,
    AuditError,
    DecisionError,
    InvalidTransitionError,
    SecretNotFoundError,
    TokenInvalidError,
)
from xdr_response.lifecycle import bootstrap, build_runtime, in_memory_runtime
from xdr_response.models import (
    ActionRequest,
    AuditEventType,
    DecisionRequest,
    DecisionType,
    IncidentState,
)
from xdr_response.restoration import InMemoryControlRegistry

S = IncidentState
REPO_CONFIG = Path(__file__).resolve().parents[3] / "config"


def _settings(tmp_path: Path, *, dry_run: bool = True) -> Settings:
    return Settings.model_validate({"runtime": {
        "dry_run": dry_run, "audit_path": str(tmp_path / "audit.jsonl"),
        "registry_path": str(tmp_path / "controls.jsonl"), "token_ledger_path": str(tmp_path / "ledger.jsonl")}})


# ------------------------------------------------------------------ runtime --
def test_build_runtime_installs_the_guard_wiring(tmp_path):
    runtime = build_runtime(_settings(tmp_path, dry_run=False), make_test_secrets(),
                            authenticator=make_authenticator(), clock=FixedClock(FIXED_NOW))
    assert guard.get_verifier() is runtime.tokens
    assert guard.is_dry_run() is False and runtime.dry_run is False
    assert runtime.orchestrator is not None and runtime.machine.store is runtime.incident_store
    # the denial hook writes GUARD_DENIED to the audit trail
    from tests.fixtures.factories import make_recommendation

    request = ActionRequest.from_recommendation(make_recommendation())
    with pytest.raises(ApprovalRequiredError):
        guard.require_authorization(request)
    events = [r.event_type for r in runtime.audit.records()]
    assert AuditEventType.GUARD_DENIED in events
    runtime.close()


def test_build_runtime_defaults_to_durable_jsonl_stores(tmp_path):
    runtime = build_runtime(_settings(tmp_path), make_test_secrets(), authenticator=make_authenticator(),
                            clock=FixedClock(FIXED_NOW))
    assert isinstance(runtime.audit, AuditTrail)
    assert guard.is_dry_run() is True  # settings default: dry run
    runtime.orchestrator.open_incident(make_incident())
    assert verify_chain(tmp_path / "audit.jsonl").ok
    assert (tmp_path / "controls.jsonl").parent.is_dir()


def test_build_runtime_refuses_without_a_signing_key(tmp_path):
    from xdr_response.secrets import StaticSecretProvider

    with pytest.raises(SecretNotFoundError):
        build_runtime(_settings(tmp_path), StaticSecretProvider({}), authenticator=make_authenticator(),
                      audit=MemoryAuditTrail(), registry=InMemoryControlRegistry())


def test_bootstrap_loads_config_env_and_secrets(tmp_path):
    config = tmp_path / "config"
    shutil.copytree(REPO_CONFIG, config)
    env = {"DRY_RUN": "false", "APPROVAL_SIGNING_KEY": "f" * 64,
           "XDR_RESPONSE_AUDIT_PATH": str(tmp_path / "var" / "audit.jsonl"),
           "XDR_RESPONSE_REGISTRY_PATH": str(tmp_path / "var" / "controls.jsonl"),
           "XDR_RESPONSE_TOKEN_LEDGER_PATH": str(tmp_path / "var" / "ledger.jsonl")}
    runtime = bootstrap(config, authenticator=make_authenticator(), env=env)
    assert guard.is_dry_run() is False
    assert runtime.settings.integration("splunk").enabled is False
    assert runtime.settings.integration("entra").options["oauth_scope"]
    runtime.orchestrator.open_incident(make_incident())
    assert verify_chain(tmp_path / "var" / "audit.jsonl").ok
    runtime.close()


def test_bootstrap_defaults_to_dry_run(tmp_path):
    config = tmp_path / "config"
    shutil.copytree(REPO_CONFIG, config)
    env = {"APPROVAL_SIGNING_KEY": "e" * 64, "XDR_RESPONSE_AUDIT_PATH": str(tmp_path / "a.jsonl"),
           "XDR_RESPONSE_REGISTRY_PATH": str(tmp_path / "r.jsonl"),
           "XDR_RESPONSE_TOKEN_LEDGER_PATH": str(tmp_path / "l.jsonl")}
    bootstrap(config, authenticator=make_authenticator(), env=env)
    assert guard.is_dry_run() is True


# ------------------------------------------------------------- orchestrator --
def _live(name: str = "ransomware") -> ScenarioRun:
    return ScenarioRun(load_scenario(name), live=True)


def test_open_incident_rules():
    runtime = in_memory_runtime(Settings(), make_test_secrets(), authenticator=make_authenticator(),
                                clock=FixedClock(FIXED_NOW))
    incident = make_incident()
    runtime.orchestrator.open_incident(incident)
    with pytest.raises(ValueError):
        runtime.orchestrator.open_incident(incident)
    with pytest.raises(ValueError):
        runtime.orchestrator.open_incident(make_incident("XDR-2", state=S.CONTAINED))
    assert [r.event_type for r in runtime.audit.records()] == [AuditEventType.INCIDENT_RECEIVED]


def test_nothing_malicious_means_no_package_and_not_started():
    run = _live()
    run.environment.reputations.clear()
    detection = run.detect()
    assert detection.package is None and detection.recommendation.empty
    assert detection.incident.state is S.NOT_STARTED


def test_propose_checks_incident_and_state():
    run = _live()
    package = run.detect().package
    with pytest.raises(ValueError):
        run.orchestrator.propose("XDR-OTHER", package)
    with pytest.raises(InvalidTransitionError):
        run.orchestrator.investigate_and_propose(run.incident_id)  # already AWAITING_APPROVAL


def test_execution_refusal_moves_the_incident_to_containment_failed(monkeypatch):
    run = _live()
    run.detect()

    def refuse(package, token, *, dry_run=False):
        raise TokenInvalidError("signature check failed")

    monkeypatch.setattr(run.runtime.executor, "execute", refuse)
    result = run.decide()
    assert result.incident.state is S.CONTAINMENT_FAILED and result.report is None
    assert "TokenInvalidError" in result.error
    assert run.environment.state_changing_calls() == []


def test_expired_package_cannot_be_approved_and_is_replaced_by_reinvestigation():
    run = _live()
    expired = run.detect().package
    run.advance(minutes=241)
    with pytest.raises(DecisionError):
        run.decide()
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL
    assert run.environment.state_changing_calls() == []
    fresh = run.orchestrator.reinvestigate(run.incident_id, actor="analyst.one@example.com",
                                           reason="package expired")
    assert fresh.package.package_id != expired.package_id and fresh.incident.state is S.AWAITING_APPROVAL
    assert [t.to_state for t in fresh.incident.history][-2:] == [S.NOT_STARTED, S.AWAITING_APPROVAL]
    assert run.decide().incident.state is S.CONTAINED


def test_audit_outage_at_decision_time_issues_no_token_and_executes_nothing():
    run = _live()
    run.detect()
    audit = run.runtime.audit
    original = audit.append

    def failing(event_type, **kwargs):
        if event_type is AuditEventType.DECISION_RECORDED:
            raise AuditError("audit disk full")
        return original(event_type, **kwargs)

    audit.append = failing  # type: ignore[method-assign]
    with pytest.raises(AuditError):
        run.decide()
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_APPROVAL
    assert run.environment.state_changing_calls() == []


def test_release_and_containment_packages_cannot_be_swapped():
    run = _live()
    containment = run.detect().package
    run.decide()
    release = run.propose_release()
    with pytest.raises(DecisionError):
        run.orchestrator.submit_decision(DecisionRequest(package_id=release.package_id,
                                                         decision=DecisionType.APPROVE_ALL),
                                         run.credentials("analyst"))
    with pytest.raises(DecisionError):
        run.orchestrator.submit_release_decision(DecisionRequest(package_id=containment.package_id,
                                                                 decision=DecisionType.APPROVE_ALL),
                                                 run.credentials("analyst"))
    with pytest.raises(DecisionError):
        run.orchestrator.submit_decision(DecisionRequest(package_id="unknown", decision=DecisionType.REJECT,
                                                         comment="x"), run.credentials("analyst"))


def test_release_cannot_be_proposed_before_containment():
    run = _live()
    run.detect()
    with pytest.raises(InvalidTransitionError):
        run.propose_release()


def test_mark_remediation_required_and_dry_run_helper():
    run = _live()
    package = run.detect().package
    report = run.orchestrator.dry_run(package)
    assert report.dry_run and run.orchestrator.report_for(package.package_id) is report
    run.decide()
    incident = run.orchestrator.mark_remediation_required(run.incident_id, actor="analyst.one@example.com",
                                                          reason="reimage TH-LT-1047")
    assert incident.state is S.REMEDIATION_REQUIRED
    run.propose_release()
    assert run.orchestrator.get_incident(run.incident_id).state is S.AWAITING_RELEASE_APPROVAL


def test_retry_needs_an_executed_package_with_failures():
    run = _live()
    run.detect()
    with pytest.raises(DecisionError):
        run.orchestrator.propose_retry(run.incident_id)
    run.decide()
    with pytest.raises(DecisionError):
        run.orchestrator.propose_retry(run.incident_id)  # everything was contained


def test_clock_drives_package_expiry_window():
    run = _live()
    package = run.detect().package
    assert package.expires_at - package.created_at == timedelta(minutes=240)
