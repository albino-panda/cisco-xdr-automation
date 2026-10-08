"""Real vendor adapters + engines together over httpx.MockTransport (no network).

The runtime is the production composition (``build_runtime``): real ``UmbrellaAdapter``,
``EntraAdapter`` and ``VirusTotalAdapter`` with their real ``GuardedHttpClient`` and OAuth2 / API-key
auth providers, the HMAC approval service, the execution guard, verification, the control registry
and restoration. Only the vendor side is fake (``_fake_vendors``).
"""
from __future__ import annotations

from datetime import datetime

import httpx
import pytest

from tests.fixtures.factories import FIXED_NOW
from tests.fixtures.principals import ANALYST_ID, credential, make_authenticator, make_test_secrets
from tests.integration._fake_vendors import FakeGraph, FakeUmbrella, FakeVirusTotal
from xdr_response import guard
from xdr_response.approval import InMemoryTokenUseLedger
from xdr_response.audit import MemoryAuditTrail
from xdr_response.clock import FixedClock
from xdr_response.config import IntegrationConfig, Settings
from xdr_response.errors import ApprovalRequiredError, DryRunViolationError
from xdr_response.lifecycle import build_runtime
from xdr_response.lifecycle.runtime import Runtime
from xdr_response.models import (
    ActionRequest,
    ActionResultStatus,
    ActionType,
    AuditEventType,
    ContainmentOverall,
    ControlStatus,
    DecisionRequest,
    DecisionType,
    ErrorCode,
    HealthStatus,
    Incident,
    IncidentState,
    Observable,
    ObservableType,
    OperationKind,
    ProposedAction,
    RestorationOverall,
    Severity,
    TargetKind,
    Verdict,
)
from xdr_response.restoration import InMemoryControlRegistry

S = IncidentState
DOMAIN = "c2.bad-actor.example"
USER = "jsmith@example.com"
LIST_ID = "1001"
SECRETS = {
    "UMBRELLA_API_KEY": "fake-umbrella-key-0001", "UMBRELLA_API_SECRET": "fake-umbrella-secret-0001",
    "ENTRA_TENANT_ID": "00000000-0000-0000-0000-000000000000", "ENTRA_CLIENT_ID": "fake-entra-client-0001",
    "ENTRA_CLIENT_SECRET": "fake-entra-secret-0001", "VT_API_KEY": "fake-vt-api-key-0001",
}


class Lab:
    """Runtime wired to the fake vendors."""

    def __init__(self, *, dry_run: bool = False, workflows=None) -> None:
        self.clock = FixedClock(FIXED_NOW)
        self.umbrella = FakeUmbrella(key=SECRETS["UMBRELLA_API_KEY"], secret=SECRETS["UMBRELLA_API_SECRET"],
                                     categorization={DOMAIN: -1})
        self.graph = FakeGraph(client_id=SECRETS["ENTRA_CLIENT_ID"], client_secret=SECRETS["ENTRA_CLIENT_SECRET"],
                               clock=self.clock.now)
        self.graph.add_user(USER)
        self.vt = FakeVirusTotal(api_key=SECRETS["VT_API_KEY"], malicious={DOMAIN: 12})
        transports = {"umbrella": self.umbrella.transport(), "entra": self.graph.transport(),
                      "virustotal": self.vt.transport()}
        settings = Settings(
            runtime={"dry_run": dry_run},
            integrations={
                "umbrella": IntegrationConfig(enabled=True, options={"destination_list_id": LIST_ID}),
                "entra": IntegrationConfig(enabled=True,
                                           options={"oauth_scope": "https://graph.example.test/.default"}),
                "virustotal": IntegrationConfig(enabled=True),
            },
        )
        self.audit = MemoryAuditTrail(clock=self.clock)
        self.runtime: Runtime = build_runtime(
            settings, make_test_secrets(**SECRETS), authenticator=make_authenticator(), clock=self.clock,
            audit=self.audit, registry=InMemoryControlRegistry(clock=self.clock), ledger=InMemoryTokenUseLedger(),
            transport_factory=transports.get, sleep=lambda _s: None, workflows=workflows)
        self.orchestrator = self.runtime.orchestrator

    def incident(self, incident_id: str = "XDR-INT-0001") -> Incident:
        return Incident(incident_id=incident_id, title="C2 beacon from finance laptop", severity=Severity.HIGH,
                        created_at=self.clock.now(), workflow_id="c2-beacon", workflow_version="1.0.0",
                        observables=(Observable(type=ObservableType.DOMAIN, value=DOMAIN),
                                     Observable(type=ObservableType.USER, value=USER)),
                        users=(USER,))

    def approve(self, package, decision=DecisionType.APPROVE_ALL, *, release=False, **kw):
        request = DecisionRequest(package_id=package.package_id, decision=decision, **kw)
        submit = self.orchestrator.submit_release_decision if release else self.orchestrator.submit_decision
        return submit(request, [credential(ANALYST_ID)])

    def all_writes(self) -> list[httpx.Request]:
        return self.umbrella.writes() + self.graph.writes() + self.vt.writes()


@pytest.fixture
def lab() -> Lab:
    return Lab()


def test_http_lifecycle_detect_approve_contain_verify_release(lab: Lab):
    detection = lab.orchestrator.handle_detection(lab.incident())
    package = detection.package
    # automatic investigation over real HTTP: Umbrella + VirusTotal say malicious, Entra gives context
    verdicts = {(r.integration, r.type): r.verdict for r in detection.investigation.enrichments}
    assert verdicts[("umbrella", ObservableType.DOMAIN)] is Verdict.MALICIOUS
    assert verdicts[("virustotal", ObservableType.DOMAIN)] is Verdict.MALICIOUS
    assert verdicts[("entra", ObservableType.USER)] is Verdict.UNKNOWN
    assert [(a.action_type, a.target, a.integration) for a in package.actions] == [
        (ActionType.BLOCK_DOMAIN, DOMAIN, "umbrella")]
    assert lab.all_writes() == []  # nothing written before the human decision

    result = lab.approve(package)
    assert result.report.overall is ContainmentOverall.CONTAINED and result.incident.state is S.CONTAINED
    (action,) = result.report.results
    assert action.status is ActionResultStatus.SUCCESS and action.verification.method == "list_destinations"
    assert lab.umbrella.blocked(LIST_ID, DOMAIN)
    add = [r for r in lab.umbrella.writes() if r.method == "POST"]
    assert len(add) == 1 and add[0].url.path == f"/policies/v2/destinationlists/{LIST_ID}/destinations"
    assert lab.umbrella.tokens_issued  # OAuth2 client credentials through integrations/auth.py
    (control,) = lab.runtime.registry.list(incident_id=package.incident_id)
    assert control.rollback_params["destination_list_id"] == LIST_ID and control.rollback_params["destination_id"]

    release = lab.orchestrator.propose_release(package.incident_id)
    restored = lab.approve(release, release=True)
    assert restored.report.overall is RestorationOverall.RESTORED and restored.incident.state is S.RESTORED
    assert not lab.umbrella.blocked(LIST_ID, DOMAIN)
    assert lab.runtime.registry.get(control.control_key).status is ControlStatus.RELEASED
    assert lab.audit.verify().ok


def test_http_api_calls_are_audited_without_tokens_or_keys(lab: Lab):
    package = lab.orchestrator.handle_detection(lab.incident()).package
    lab.approve(package)
    records = [r for r in lab.audit.records() if r.event_type is AuditEventType.API_CALL]
    assert {r.payload["integration"] for r in records} >= {"umbrella", "entra", "virustotal"}
    blob = "\n".join(r.model_dump_json() for r in lab.audit.records())
    for value in (*SECRETS.values(), *lab.umbrella.tokens_issued, *lab.graph.tokens_issued):
        assert value not in blob
    kinds = {r.payload["kind"] for r in records if r.payload["integration"] == "umbrella"}
    assert {"READ", "VERIFY", "STATE_CHANGING"} <= kinds


def test_entra_disable_and_enable_user_over_graph(lab: Lab):
    incident = lab.incident("XDR-INT-0002")
    lab.orchestrator.open_incident(incident)
    evidence = lab.orchestrator.investigate(incident.incident_id).evidence_drafts
    entra_evidence = tuple(e for e in evidence if e.source == "entra")
    proposals = [ProposedAction(action_type=a, target=USER, target_kind=TargetKind.USER,
                                params={"integration": "entra"}, evidence=entra_evidence, risk_score=85,
                                confidence_score=80, rationale="analyst playbook: compromised account")
                 for a in (ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS)]
    package = lab.runtime.packages.build(incident, proposals, risk_score=85, confidence_score=80,
                                         summary="Account compromise")
    lab.orchestrator.propose(incident.incident_id, package)
    result = lab.approve(package)
    assert result.report.overall is ContainmentOverall.CONTAINED
    assert lab.graph.users[USER]["accountEnabled"] is False
    assert {r.verification.status.value for r in result.report.results} == {"VERIFIED"}
    patch = [r for r in lab.graph.writes() if r.method == "PATCH"]
    assert len(patch) == 1 and patch[0].url.path == f"/v1.0/users/{USER}"
    # Graph token request uses form credentials and the configured scope
    token_call = next(r for r in lab.graph.requests if r.url.path.endswith("/oauth2/v2.0/token"))
    assert token_call.url.host == "login.microsoftonline.com"

    release = lab.orchestrator.propose_release(incident.incident_id)
    assert [a.action_type for a in release.actions] == [ActionType.ENABLE_USER]  # revoke is irreversible
    assert lab.approve(release, release=True).incident.state is S.RESTORED
    assert lab.graph.users[USER]["accountEnabled"] is True


def test_failed_enrichment_source_does_not_block_the_recommendation(lab: Lab):
    lab.vt.fail("GET", "/api/v3/", httpx.Response(500))
    detection = lab.orchestrator.handle_detection(lab.incident())
    vt = next(r for r in detection.investigation.enrichments if r.integration == "virustotal")
    assert vt.verdict is Verdict.UNKNOWN and vt.health is HealthStatus.UNAVAILABLE
    assert vt.errors[0].code is ErrorCode.UNAVAILABLE
    assert [a.action_type for a in detection.package.actions] == [ActionType.BLOCK_DOMAIN]


def test_auth_failure_on_the_write_path_fails_closed_and_requires_remediation(lab: Lab):
    package = lab.orchestrator.handle_detection(lab.incident()).package
    lab.umbrella.fail("POST", f"/policies/v2/destinationlists/{LIST_ID}/destinations", httpx.Response(403))
    result = lab.approve(package)
    (action,) = result.report.results
    assert action.status is ActionResultStatus.FAILED and action.error.code is ErrorCode.AUTH_FAILED
    assert result.report.overall is ContainmentOverall.CONTAINMENT_FAILED
    assert result.incident.state is S.REMEDIATION_REQUIRED
    assert lab.runtime.registry.list() == []
    assert any("Requires attention" in line or "block_domain" in line for line in result.report.attention)


def test_unavailable_write_is_not_retried_blindly(lab: Lab):
    package = lab.orchestrator.handle_detection(lab.incident()).package
    path = f"/policies/v2/destinationlists/{LIST_ID}/destinations"
    lab.umbrella.fail("POST", path, httpx.Response(503))  # no Retry-After: a write is never retried
    result = lab.approve(package)
    posts = [r for r in lab.umbrella.requests if r.method == "POST" and r.url.path == path]
    assert len(posts) == 1
    assert result.report.results[0].error.code is ErrorCode.UNAVAILABLE
    assert result.recommended_next_state is S.AWAITING_APPROVAL  # transient: new approval, never automatic


def test_expired_umbrella_token_is_refreshed_before_use(lab: Lab):
    package = lab.orchestrator.handle_detection(lab.incident()).package
    first = len(lab.umbrella.tokens_issued)
    lab.clock.set(datetime(2026, 1, 15, 12, 59, 0, tzinfo=FIXED_NOW.tzinfo))  # inside the refresh margin
    lab.approve(package)
    assert len(lab.umbrella.tokens_issued) == first + 1  # refreshed, never sent stale (Umbrella answers 400)


def test_direct_adapter_call_is_refused_and_sends_nothing(lab: Lab):
    package = lab.orchestrator.handle_detection(lab.incident()).package
    adapter = lab.runtime.adapters.get("umbrella")
    request = ActionRequest.from_recommendation(package.actions[0])
    with pytest.raises(ApprovalRequiredError):
        adapter.block_domain(request)
    with pytest.raises(ApprovalRequiredError):  # the HTTP client checks the guard as well
        adapter.http.post(f"policies/v2/destinationlists/{LIST_ID}/destinations", kind=OperationKind.STATE_CHANGING,
                          operation="add_destinations", json=[{"destination": DOMAIN}])
    assert lab.all_writes() == []
    assert AuditEventType.GUARD_DENIED in {r.event_type for r in lab.audit.records()}


def test_dry_run_with_real_adapters_sends_no_write():
    lab = Lab(dry_run=True)
    detection = lab.orchestrator.handle_detection(lab.incident())
    assert detection.dry_run_report is not None
    assert [r.dry_run_line for r in detection.dry_run_report.results] == [f"Would block: {DOMAIN}"]
    result = lab.approve(detection.package)
    assert result.report.dry_run and result.incident.state is S.AWAITING_APPROVAL
    assert lab.all_writes() == []
    adapter = lab.runtime.adapters.get("umbrella")
    with pytest.raises(DryRunViolationError):
        with guard.authorized(result.outcome.token, ActionRequest.from_recommendation(detection.package.actions[0])):
            pass  # pragma: no cover
    assert adapter.manifest.integration == "umbrella"


def test_health_monitor_reports_per_integration(lab: Lab):
    health = lab.runtime.health.check_all()
    assert health["splunk"].status is HealthStatus.UNKNOWN  # optional, disabled by default
    assert health["umbrella"].status is HealthStatus.CONNECTED
