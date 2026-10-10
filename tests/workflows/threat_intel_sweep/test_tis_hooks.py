"""threat-intel-sweep hooks: indicator ratings and hits, hosts, files, messages, accounts, considerations,
hand-offs and links computed from the run's own records (simulated read-only lab; nothing state-changing
is ever called)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from tests.fixtures.sample_workflows.lab import Lab, make_incident, make_lab
from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.integrations.simulated import FaultKind
from xdr_response.models import Incident, ObservableType, Verdict
from xdr_response.workflows.hooks import RunView
from xdr_response.workflows.runner import RuleOutcomeStatus, WorkflowRun
from xdr_response.workflows.threat_intel_sweep import HOOKS, WORKFLOW
from xdr_response.workflows.threat_intel_sweep.definition import MAX_INDICATORS_PER_TYPE
from xdr_response.workflows.threat_intel_sweep.hooks import indicator_key, ipv4

H = "7e3a91c5" * 8
OTHER_HASH = "4b1d0c3a" * 8
APPROVED_RMM_HASH = "1" * 64  # config/allowlists.yaml approved_rmm (fake)
D = "update-relay.test"
IP = "198.51.100.77"
URL = "https://update-relay.test/dl/invoice-viewer"
SENDER = "billing@invoice-notice.example"
MID = "etd-tis-0001"
HOST = "TH-LT-1047"
OTHER = "TH-LT-2210"
SE = "secure_endpoint"
MC = "microsoft_cloud"
SUITE = {"cisco_xdr": ("intel",), "secure_endpoint": ("endpoint",), "secure_email": ("email",),
         "microsoft_cloud": ("network",), "umbrella": ("network",), "meraki": ("network",),
         "entra": ("identity",), "virustotal": ("intel",)}
_O = ObservableType
_INCIDENTS: dict[str, Incident] = {}


def _lab(suite: dict[str, tuple[str, ...]] | None = None) -> Lab:
    return make_lab(suite or SUITE)


def _rate(lab: Lab, otype: ObservableType, value: str, verdict: Verdict = Verdict.MALICIOUS,
          integrations: tuple[str, ...] = ("cisco_xdr", "virustotal")) -> None:
    lab.environment.set_reputation(otype, value, verdict, risk_score=85 if verdict is Verdict.MALICIOUS else 40,
                                   confidence=80, integrations=list(integrations))


def _endpoint(lab: Lab, host: str = HOST, **extra: Any) -> None:
    fields = {"connector_guid": "00000000-0000-4000-8000-000000001047", "groups": ["Workstations"],
              "users": ["jsmith@example.com"], "isolation_capable": True, "isolation_state": "not_isolated", **extra}
    lab.typed("investigate_endpoint", host, SE, kind="endpoint", hostname=host, **fields)


def _ran(lab: Lab, host: str = HOST, sha: str = H, *, pid: int = 4410, verdict: str = "UNKNOWN") -> None:
    lab.typed("search_hash_enterprise", sha, SE, kind="process_event", event_id=f"evt-{host}-{pid}", endpoint=host,
              timestamp="2026-01-14T09:15:00Z", event_type="process_start", process_name="invoice-viewer.exe",
              pid=pid, sha256=sha, verdict=verdict)


def _downloaded(lab: Lab, host: str = OTHER, sha: str = H) -> None:
    lab.typed("search_hash_enterprise", sha, SE, kind="process_event", event_id=f"dl-{host}", endpoint=host,
              timestamp="2026-01-15T10:40:00Z", event_type="file_create", process_name="browser.exe", sha256=sha)


def _detection(lab: Lab, host: str = HOST, *, status: str = "active", sha: str | None = H,
               name: str = "Sample.Loader.InvoiceViewer") -> None:
    lab.typed("investigate_endpoint", host, SE, kind="detection", detection_id=f"det-{host}-{status}-{name}",
              name=name, verdict="MALICIOUS", severity="HIGH", endpoint=host, status=status, sha256=sha,
              first_seen="2026-01-14T09:16:00Z")


def _dns(lab: Lab, host: str = HOST, domain: str = D, *, ips: list[str] | None = None) -> None:
    lab.typed("search_domain_enterprise", D if domain.endswith(D) else domain, MC, kind="dns_query", endpoint=host,
              domain=domain, query_type="A", response_ips=ips or [], count=3, action="allowed",
              first_seen="2026-01-14T09:14:00Z", last_seen="2026-01-14T09:20:00Z")


def _message(lab: Lab, *, location: str = "inbox", verdict: str = "UNKNOWN", urls: list[str] | None = None,
             domains: list[str] | None = None, sender: str = SENDER, attachments: list[str] | None = None,
             message_id: str = MID, recipients: list[str] | None = None, subject: str = D,
             atomic: str = "search_domain_enterprise") -> None:
    lab.typed(atomic, subject, MC, kind="email_message", message_id=message_id, sender=sender,
              sender_domain=sender.split("@", 1)[1], recipients=recipients or ["jsmith@example.com"],
              recipient_count=len(recipients or ["jsmith@example.com"]), received_at="2026-01-14T09:02:00Z",
              direction="inbound", verdict=verdict, urls=urls if urls is not None else [URL],
              domains=domains if domains is not None else [D], attachment_hashes=attachments or [],
              delivery_location=location)


def _signin(lab: Lab, user: str = "mlopez@example.com", *, result: str = "success", ip: str = IP) -> None:
    lab.typed("search_ip_enterprise", ip, MC, kind="sign_in", sign_in_id=f"si-{user}-{result}", user=user,
              timestamp="2026-01-15T07:42:00Z", ip=ip, country="ZZ", app="Office 365 Exchange Online", result=result)


def _run(lab: Lab, *observables: tuple[ObservableType, str], **extra: Any) -> WorkflowRun:
    incident = make_incident(*observables, workflow_id="threat-intel-sweep",
                             title="IOC sweep: high-confidence indicators", **extra)
    _INCIDENTS[incident.incident_id] = incident
    return lab.runner.run(WORKFLOW, HOOKS, incident, dry_run=True)


def _view(run: WorkflowRun) -> RunView:
    return RunView(workflow=WORKFLOW, incident=_INCIDENTS[run.incident_id], results=run.results,
                   index=run.index, correlation=run.correlation, blast_radius=run.blast_radius)


def _facts(run: WorkflowRun) -> dict[str, Any]:
    facts = dict(HOOKS.facts(_view(run)))
    json.dumps(facts, allow_nan=False)  # the runner requires JSON facts
    return facts


def _indicator(facts: dict[str, Any], kind: str, value: str) -> dict[str, Any]:
    return next(i for i in facts["indicators"] if (i["type"], i["value"]) == (kind, value))


def _host(facts: dict[str, Any], host: str) -> dict[str, Any]:
    return next(h for h in facts["hosts"] if h["hostname"] == host)


def _proposed(run: WorkflowRun) -> set[str]:
    """Recommended actions: proposed, or UNROUTED (the simulated adapters do only what the real ones do,
    so e.g. a process termination or a Secure Endpoint hash block has no executor; it is still recommended)."""
    return ({f"{p.action_type.value}:{p.target}" for p in run.proposals}
            | {o.selector for o in run.outcomes_with(RuleOutcomeStatus.UNROUTED)})


def _considered(run: WorkflowRun) -> dict[str, bool]:
    return {c.subject: c.manual for c in run.considered}


def _handoffs(run: WorkflowRun) -> set[tuple[str, tuple[str, ...]]]:
    return {(h.workflow_id, h.subjects) for h in run.handoffs}


ALL = ((_O.SHA256, H), (_O.DOMAIN, D), (_O.IP, IP), (_O.URL, URL), (_O.EMAIL_ADDRESS, SENDER))


def _world(lab: Lab) -> None:
    for otype, value in ALL[:4]:
        _rate(lab, otype, value, integrations=("cisco_xdr", "umbrella") if otype is _O.IP else ("cisco_xdr",
                                                                                                 "virustotal"))
    _rate(lab, _O.EMAIL_ADDRESS, SENDER, integrations=("cisco_xdr",))
    _endpoint(lab)
    _endpoint(lab, OTHER, connector_guid="00000000-0000-4000-8000-000000002210", users=["akumar@example.com"])
    _ran(lab, verdict="MALICIOUS")
    _downloaded(lab)
    _detection(lab)
    _dns(lab, ips=[IP])
    _message(lab)
    lab.typed("investigate_email", MID, "secure_email", kind="email_message", message_id=MID, sender=SENDER,
              recipients=["jsmith@example.com"], recipient_count=1, verdict="MALICIOUS", urls=[URL], domains=[D],
              delivery_location="inbox")
    _signin(lab)


# ------------------------------------------------------------------ helpers --
@pytest.mark.parametrize("kind, value, expected", [
    ("sha256", H.upper(), H), ("sha256", "abc", None), ("sha256", "z" * 64, None),
    ("domain", "Update-Relay.TEST.", D), ("ip", " 198.51.100.77 ", IP), ("ip", "::ffff:198.51.100.77", IP),
    ("ip", "2001:db8::1", None), ("ip", "not-an-ip", None), ("email_address", "Billing@Invoice-Notice.example", SENDER),
    ("email_address", "no-at-sign", None), ("url", "HTTPS://Update-Relay.test:443/dl/invoice-viewer", URL),
    ("url", "https://user:secret@update-relay.test/dl/invoice-viewer", URL), ("domain", "  ", None),
])
def test_indicator_keys_normalise_each_type(kind, value, expected):
    assert indicator_key(kind, value) == expected


def test_ipv4_handles_mapped_addresses_and_refuses_ipv6():
    assert ipv4("::ffff:192.0.2.5") == "192.0.2.5" and ipv4("2001:db8::5") is None and ipv4(None) is None


# --------------------------------------------------------------- full case --
def test_the_full_sweep_proposes_containment_for_every_affected_asset():
    lab = _lab()
    _world(lab)
    run = _run(lab, *ALL)
    assert _proposed(run) == {
        f"block_hash:{H}", f"block_domain:{D}", f"block_ip:{IP}", f"block_url:{URL}", f"isolate_endpoint:{HOST}",
        f"quarantine_file:{HOST}/{H}", f"quarantine_file:{OTHER}/{H}", f"quarantine_email:{MID}",
        "revoke_sessions:mlopez@example.com"}
    assert _considered(run) == {f"block_sender:{SENDER}": True}  # manual: no VERIFIED sender block
    assert _handoffs(run) == {("malware", (H,)), ("c2", (HOST,)), ("phishing", ("jsmith@example.com",)),
                              ("account-takeover", ("mlopez@example.com",))}
    facts = _facts(run)
    sender = _indicator(facts, "email_address", SENDER)
    assert sender["rated"] and sender["enrichment_verdict"] == "SUSPICIOUS"  # one vendor: rated by the message
    assert "secure_email email_message" in sender["basis"]
    host = _host(facts, HOST)
    assert host["isolate"] and host["executed"] == [H] and host["contacts"] == [D, IP]
    assert host["binaries"] == []  # an active detection stands on its own
    other = _host(facts, OTHER)
    assert not other["isolate"] and other["executed"] == [] and other["contacts"] == []
    message = facts["messages"][0]
    assert message["quarantine"] and message["recipient"] == "jsmith@example.com"
    assert set(message["rated_indicators"]) == {D, URL, SENDER}
    for group in ("indicators", "hosts", "files", "messages", "accounts"):
        for item in facts[group]:
            assert set(item["record_ids"]) <= set(run.index.ids()), group
            assert item["record_ids"] or (group == "hosts" and not item["isolate"]), group
    assert other["record_ids"] == [] and other["hit_record_ids"]  # named by hits, nothing to act on
    # nothing state-changing was called by the read zone
    assert lab.environment.state_changing_calls() == []


def test_every_proposal_cites_real_records_and_carries_separate_scores():
    lab = _lab()
    _world(lab)
    run = _run(lab, *ALL)
    assert run.proposals
    for proposal in run.proposals:
        assert proposal.evidence
        assert all(e.data["record_id"] in run.index for e in proposal.evidence)
        assert type(proposal.risk_score) is int and type(proposal.confidence_score) is int
    assert type(run.risk_score) is int and type(run.confidence_score) is int


# ------------------------------------------------------------------ ratings --
def test_one_vendor_alone_never_rates_an_indicator_and_the_hits_stay_visible():
    lab = _lab()
    _rate(lab, _O.DOMAIN, D, integrations=("cisco_xdr",))
    _endpoint(lab)
    _dns(lab)
    run = _run(lab, (_O.DOMAIN, D))
    assert _proposed(run) == set()
    assert _considered(run) == {f"block_domain:{D}": False}
    reason = run.considered[0].reason
    assert "SUSPICIOUS only" in reason and "1 hit(s)" in reason and HOST in reason


def test_a_clean_rating_contradicts_the_feed_and_proposes_nothing():
    lab = _lab()
    _rate(lab, _O.IP, "198.51.100.20", Verdict.CLEAN, ("cisco_xdr", "umbrella"))
    run = _run(lab, (_O.IP, "198.51.100.20"))
    assert _proposed(run) == set()
    assert _considered(run) == {"block_ip:198.51.100.20": False}
    assert "rated CLEAN by cisco_xdr, umbrella" in run.considered[0].reason
    assert "contradicted" in run.considered[0].reason and "no hit" in run.considered[0].reason


def test_the_security_products_own_verdict_rates_an_indicator_without_enrichment():
    lab = _lab()
    lab.typed("search_hash_enterprise", H, SE, kind="hash_prevalence", sha256=H, verdict="MALICIOUS", prevalence=1,
              endpoints=[OTHER])
    _endpoint(lab, OTHER, users=["akumar@example.com"])
    run = _run(lab, (_O.SHA256, H))
    indicator = _indicator(_facts(run), "sha256", H)
    assert indicator["rated"] and indicator["enrichment_verdict"] == "UNKNOWN"
    assert "secure_endpoint hash_prevalence" in indicator["basis"]
    assert {f"block_hash:{H}", f"quarantine_file:{OTHER}/{H}"} <= _proposed(run)


def test_the_feeds_own_confidence_is_never_evidence():
    lab = _lab()  # no reputation, no record: only the incident claims the indicator is high confidence
    run = _run(lab, (_O.DOMAIN, D), trigger={"source": "threat_intel", "feed_confidence": "high"})
    assert _proposed(run) == set() and run.considered == () and run.handoffs == ()
    assert _indicator(_facts(run), "domain", D)["rated"] is False


def test_an_unrated_indicator_with_hits_is_shown_not_contained():
    lab = _lab()
    _endpoint(lab)
    _dns(lab)
    run = _run(lab, (_O.DOMAIN, D))
    assert _proposed(run) == set()
    assert _considered(run) == {f"block_domain:{D}": False}
    assert run.considered[0].reason.startswith("no source rates it; 1 hit(s)")


def test_a_rated_indicator_without_hits_is_blocked_preventively_only():
    lab = _lab()
    _rate(lab, _O.SHA256, OTHER_HASH)
    _rate(lab, _O.URL, URL)
    run = _run(lab, (_O.SHA256, OTHER_HASH), (_O.URL, URL))
    assert _proposed(run) == {f"block_hash:{OTHER_HASH}", f"block_url:{URL}"}
    assert run.considered == () and run.handoffs == ()
    facts = _facts(run)
    assert _indicator(facts, "sha256", OTHER_HASH)["hit_text"] == "none found in the sweep window (preventive)"
    assert facts["hosts"] == [] and facts["files"] == [] and facts["messages"] == [] and facts["accounts"] == []


# --------------------------------------------------------------- matching --
def test_a_domain_matches_its_subdomains_and_a_url_only_the_same_url():
    lab = _lab()
    _rate(lab, _O.DOMAIN, D, integrations=("cisco_xdr", "umbrella"))
    _rate(lab, _O.URL, URL)
    _endpoint(lab)
    _dns(lab, domain=f"cdn.{D}")
    lab.typed("search_domain_enterprise", D, MC, kind="network_connection", endpoint=OTHER, remote_ip="198.51.100.5",
              remote_port=443, direction="outbound", domain="not-" + D, url="https://update-relay.test/other",
              count=1)
    run = _run(lab, (_O.DOMAIN, D), (_O.URL, URL))
    facts = _facts(run)
    assert _indicator(facts, "domain", D)["endpoints"] == [HOST]
    assert _indicator(facts, "url", URL)["endpoints"] == []  # another path on the host is not the URL
    assert OTHER not in {h["hostname"] for h in facts["hosts"]}


def test_a_dns_answer_that_resolved_to_the_ip_is_a_hit_of_the_ip():
    lab = _lab()
    _rate(lab, _O.IP, IP, integrations=("cisco_xdr", "umbrella"))
    _endpoint(lab)
    lab.typed("search_ip_enterprise", IP, MC, kind="dns_query", endpoint=HOST, domain="some-name.test",
              response_ips=[IP], count=1)
    run = _run(lab, (_O.IP, IP))
    assert _indicator(_facts(run), "ip", IP)["endpoints"] == [HOST]
    assert _handoffs(run) == {("c2", (HOST,))}


# ------------------------------------------------------------------- hosts --
def test_an_endpoint_that_only_reached_a_rated_indicator_is_considered_and_handed_to_c2():
    lab = _lab()
    _rate(lab, _O.DOMAIN, D, integrations=("cisco_xdr", "umbrella"))
    _endpoint(lab)
    _dns(lab)
    run = _run(lab, (_O.DOMAIN, D))
    assert _proposed(run) == {f"block_domain:{D}"}
    assert _considered(run) == {f"isolate_endpoint:{HOST}": False}
    assert "indicator block cuts the path" in run.considered[0].reason
    assert _handoffs(run) == {("c2", (HOST,))}


def test_reaching_a_rated_indicator_with_own_malicious_activity_isolates():
    lab = _lab()
    _rate(lab, _O.DOMAIN, D, integrations=("cisco_xdr", "umbrella"))
    _endpoint(lab)
    _dns(lab)
    _detection(lab, sha=None, name="Sample.Backdoor.Generic")
    run = _run(lab, (_O.DOMAIN, D))
    assert _proposed(run) == {f"block_domain:{D}", f"isolate_endpoint:{HOST}"}
    host = _host(_facts(run), HOST)
    assert "active detection 'Sample.Backdoor.Generic' MALICIOUS" in host["basis"] and host["binaries"] == []


def test_execution_alone_isolates_and_names_the_binaries():
    lab = _lab()
    _rate(lab, _O.SHA256, H)
    _endpoint(lab)
    _ran(lab)
    run = _run(lab, (_O.SHA256, H))
    assert f"isolate_endpoint:{HOST}" in _proposed(run)
    assert _host(_facts(run), HOST)["binaries"] == [H]


def test_a_sanctioned_binary_never_isolates_its_host():
    lab = _lab()
    _rate(lab, _O.SHA256, APPROVED_RMM_HASH)
    _endpoint(lab)
    _ran(lab, sha=APPROVED_RMM_HASH)
    run = _run(lab, (_O.SHA256, APPROVED_RMM_HASH))
    statuses = {o.selector: o.status for o in run.outcomes}
    assert statuses[f"isolate_endpoint:{HOST}"] is RuleOutcomeStatus.ALLOWLISTED
    assert f"isolate_endpoint:{HOST}" in _considered(run)


def test_a_downloaded_file_is_quarantined_without_isolating_the_endpoint():
    lab = _lab()
    _rate(lab, _O.SHA256, H)
    _endpoint(lab, OTHER, users=["akumar@example.com"])
    _downloaded(lab)
    run = _run(lab, (_O.SHA256, H))
    assert _proposed(run) == {f"block_hash:{H}", f"quarantine_file:{OTHER}/{H}"}
    file_fact = _facts(run)["files"][0]
    assert file_fact["executed"] is False and "process_event" in file_fact["basis"]


@pytest.mark.parametrize("remediation", ["resolved_detection", "file_delete"])
def test_a_remediated_or_deleted_file_is_not_quarantined(remediation: str):
    lab = _lab()
    _rate(lab, _O.SHA256, H)
    _endpoint(lab, OTHER, users=["akumar@example.com"])
    _downloaded(lab)
    if remediation == "resolved_detection":
        _detection(lab, OTHER, status="resolved")
    else:
        lab.typed("search_hash_enterprise", H, SE, kind="process_event", event_id="del-2210", endpoint=OTHER,
                  timestamp="2026-01-15T10:45:00Z", event_type="file_delete", process_name="agent.exe", sha256=H)
    run = _run(lab, (_O.SHA256, H))
    assert _proposed(run) == {f"block_hash:{H}"}
    assert _facts(run)["files"] == []


@pytest.mark.parametrize("extra, manual_reason", [
    ({"connector_guid": None}, "neither Secure Endpoint nor Defender manages it"),
    ({"isolation_capable": False}, "agent policy does not allow isolation"),
])
def test_an_endpoint_no_agent_can_isolate_is_a_manual_step(extra: dict[str, Any], manual_reason: str):
    lab = _lab()
    _rate(lab, _O.SHA256, H)
    _endpoint(lab, **extra)
    _ran(lab)
    run = _run(lab, (_O.SHA256, H))
    assert f"isolate_endpoint:{HOST}" not in _proposed(run)
    assert _considered(run)[f"isolate_endpoint:{HOST}"] is True
    assert any(manual_reason in c.reason for c in run.considered)


# ---------------------------------------------------------------- messages --
@pytest.mark.parametrize("location", ["quarantine", "deleted", "failed"])
def test_a_message_that_is_no_longer_delivered_is_not_quarantined(location: str):
    lab = _lab()
    _rate(lab, _O.URL, URL)
    _message(lab, location=location)
    run = _run(lab, (_O.URL, URL))
    assert _proposed(run) == {f"block_url:{URL}"}
    assert run.handoffs == ()


#: Defender XDR hunting (EmailAttachmentInfo rows) answers the hash sweep in these lab cases.
_MAIL_HUNT = {**SUITE, "microsoft_cloud": ("network", "endpoint")}


def test_a_delivered_message_with_unrated_indicators_only_is_considered():
    lab = _lab(_MAIL_HUNT)
    _message(lab, urls=[], domains=[], attachments=[H], subject=H, atomic="search_hash_enterprise")
    run = _run(lab, (_O.SHA256, H))
    assert _proposed(run) == set()
    assert _considered(run) == {f"block_hash:{H}": False, f"quarantine_email:{MID}": False}


def test_an_attachment_hash_rates_the_message_for_quarantine_with_the_recipient_param():
    lab = _lab(_MAIL_HUNT)
    _rate(lab, _O.SHA256, H)
    _message(lab, urls=[], domains=[], attachments=[H], subject=H, atomic="search_hash_enterprise")
    run = _run(lab, (_O.SHA256, H))
    assert _proposed(run) == {f"block_hash:{H}", f"quarantine_email:{MID}"}
    proposal = next(p for p in run.proposals if p.action_type.value == "quarantine_email")
    assert proposal.params["recipient"] == "jsmith@example.com"
    assert _handoffs(run) == {("phishing", ("jsmith@example.com",))}


def test_a_message_to_several_recipients_carries_no_single_recipient():
    lab = _lab()
    _rate(lab, _O.URL, URL)
    _message(lab, recipients=["jsmith@example.com", "akumar@example.com"])
    run = _run(lab, (_O.URL, URL))
    message = _facts(run)["messages"][0]
    assert message["recipient"] == "" and message["recipients"] == ["akumar@example.com", "jsmith@example.com"]


# ---------------------------------------------------------------- accounts --
def test_failed_sign_ins_only_are_considered_and_a_success_is_revoked_and_handed_off():
    lab = _lab()
    _rate(lab, _O.IP, IP, integrations=("cisco_xdr", "umbrella"))
    _signin(lab, "akumar@example.com", result="failure")
    _signin(lab, "mlopez@example.com")
    run = _run(lab, (_O.IP, IP))
    assert _proposed(run) == {f"block_ip:{IP}", "revoke_sessions:mlopez@example.com"}
    assert _considered(run) == {"revoke_sessions:akumar@example.com": False}
    assert _handoffs(run) == {("account-takeover", ("mlopez@example.com",))}


def test_a_privileged_account_that_signed_in_from_the_indicator_gets_a_critical_asset_warning():
    lab = _lab()
    _rate(lab, _O.IP, IP, integrations=("cisco_xdr", "umbrella"))
    _signin(lab, "adm-mlopez@example.com")
    lab.typed("investigate_user", "adm-mlopez@example.com", "entra", kind="user_profile", user="adm-mlopez@example.com",
              privileged=True, roles=["Global Administrator"], account_enabled=True)
    run = _run(lab, (_O.IP, IP))
    built = next(b for b in run.built if b.action_type.value == "revoke_sessions")
    assert built.proposal is not None and built.warnings  # PackageBuilder makes it ELEVATED; never skipped


@pytest.mark.parametrize("group", ["Executives", "Service Accounts", "Domain Admins"])
def test_an_account_in_a_critical_group_gets_a_critical_asset_warning(group: str):
    lab = _lab()
    _rate(lab, _O.IP, IP, integrations=("cisco_xdr", "umbrella"))
    _signin(lab)
    lab.typed("investigate_user", "mlopez@example.com", "entra", kind="user_profile", user="mlopez@example.com",
              groups=[group], account_enabled=True)
    run = _run(lab, (_O.IP, IP))
    account = _facts(run)["accounts"][0]
    assert account["groups"] == [group] and account["indicators"] == [f"block_ip:{IP}"]
    built = next(b for b in run.built if b.action_type.value == "revoke_sessions")
    assert built.proposal is not None and built.warnings


@pytest.mark.parametrize("address", ["192.0.2.53", "192.0.2.5", "10.20.30.40", "100.64.1.9"])
def test_sign_ins_from_an_allowlisted_or_non_public_indicator_are_considered_never_revoked(address: str):
    lab = _lab()
    _rate(lab, _O.IP, address, integrations=("cisco_xdr", "umbrella"))
    _signin(lab, ip=address)
    run = _run(lab, (_O.IP, address))
    assert "revoke_sessions:mlopez@example.com" not in _proposed(run)
    assert _considered(run).get("revoke_sessions:mlopez@example.com") is False
    outcome = next(o for o in run.outcomes if o.rule_id == "revoke_sessions_signed_in_from_indicator")
    assert outcome.status is RuleOutcomeStatus.ALLOWLISTED


def test_one_public_rated_address_keeps_the_revocation_beside_an_allowlisted_one():
    lab = _lab()
    for address in (IP, "192.0.2.53"):
        _rate(lab, _O.IP, address, integrations=("cisco_xdr", "umbrella"))
    _signin(lab, ip="192.0.2.53")
    lab.typed("search_ip_enterprise", IP, MC, kind="sign_in", sign_in_id="si-mlopez-public",
              user="mlopez@example.com", timestamp="2026-01-15T08:42:00Z", ip=IP, country="ZZ",
              app="Office 365 Exchange Online", result="success")
    run = _run(lab, (_O.IP, IP), (_O.IP, "192.0.2.53"))
    assert "revoke_sessions:mlopez@example.com" in _proposed(run)


# ----------------------------------------------------------------- ratings --
def test_a_subdomain_verdict_never_rates_its_clean_parent():
    lab = _lab()
    _rate(lab, _O.DOMAIN, "cloudhost.test", Verdict.CLEAN, integrations=("cisco_xdr", "umbrella", "virustotal"))
    lab.typed("search_domain_enterprise", "cloudhost.test", MC, kind="dns_query", endpoint=HOST,
              domain="bad.cloudhost.test", query_type="A", response_ips=[], count=2, action="allowed",
              verdict="MALICIOUS", first_seen="2026-01-14T09:14:00Z", last_seen="2026-01-14T09:20:00Z")
    run = _run(lab, (_O.DOMAIN, "cloudhost.test"))
    indicator = _indicator(_facts(run), "domain", "cloudhost.test")
    assert not indicator["rated"] and "bad.cloudhost.test" in indicator["basis"]
    assert "block_domain:cloudhost.test" not in _proposed(run)
    assert "block_domain:cloudhost.test" in _considered(run)


@pytest.mark.parametrize("enrichment", [Verdict.CLEAN, None])
def test_a_connection_verdict_never_overrides_a_clean_destination(enrichment: Verdict | None):
    lab = _lab()
    address = "198.51.100.200"
    if enrichment is not None:
        _rate(lab, _O.IP, address, enrichment, integrations=("cisco_xdr", "umbrella", "virustotal"))
    lab.typed("search_ip_enterprise", address, MC, kind="network_connection", endpoint=HOST, remote_ip=address,
              protocol="udp", direction="outbound", process_name="loader.exe", count=1, action="allowed",
              verdict="MALICIOUS", first_seen="2026-01-14T09:15:00Z", last_seen="2026-01-14T09:15:00Z")
    run = _run(lab, (_O.IP, address))
    indicator = _indicator(_facts(run), "ip", address)
    if enrichment is Verdict.CLEAN:
        assert not indicator["rated"] and indicator["contradicted"]
        assert f"block_ip:{address}" not in _proposed(run) and f"block_ip:{address}" in _considered(run)
    else:  # no rating at all: the product's own verdict on the destination still rates it
        assert indicator["rated"] and f"block_ip:{address}" in _proposed(run)


def test_a_process_verdict_never_rates_a_destination_it_reached():
    lab = _lab()
    address = "198.51.100.200"
    lab.typed("search_ip_enterprise", address, MC, kind="process_event", event_id="evt-tis-p-1", endpoint=HOST,
              timestamp="2026-01-14T09:15:00Z", event_type="network_connect", process_name="loader.exe", pid=4410,
              remote_ip=address, verdict="MALICIOUS")
    run = _run(lab, (_O.IP, address))
    assert not _indicator(_facts(run), "ip", address)["rated"]
    assert f"block_ip:{address}" not in _proposed(run)


# --------------------------------------------------------------- degraded --
def test_a_rating_source_outage_leaves_single_vendor_indicators_considered_and_asset_actions_standing():
    lab = _lab()
    _world(lab)
    lab.environment.inject(FaultKind.UNAVAILABLE, integration="cisco_xdr", operation="enrich", times=50)
    run = _run(lab, *ALL)
    assert run.degraded_sources() == ("cisco_xdr",)
    proposed = _proposed(run)
    assert {f"isolate_endpoint:{HOST}", f"quarantine_file:{HOST}/{H}", f"quarantine_email:{MID}"} <= proposed
    assert f"block_domain:{D}" not in proposed  # Umbrella alone: one vendor
    assert _considered(run)[f"block_domain:{D}"] is False


# -------------------------------------------------------------- cap, links --
def test_indicators_over_the_per_type_cap_are_noted_not_dropped_silently():
    lab = _lab()
    domains = [f"relay-{n:02d}.test" for n in range(MAX_INDICATORS_PER_TYPE + 2)]
    run = _run(lab, *((_O.DOMAIN, d) for d in domains))
    notes = [n for n in run.notes if n.startswith("step domain_reputation: 2 subject(s) not queried")]
    assert notes and domains[-1] in notes[0]


def test_indicator_hit_links_tie_each_indicator_to_the_assets_records_name_with_it():
    lab = _lab()
    _world(lab)
    run = _run(lab, *ALL)
    links = HOOKS.correlate(_view(run))
    pairs = {tuple(sorted(e.key() for e in link.entities)) for link in links}
    assert (f"DOMAIN:{D}", f"ENDPOINT:{HOST}") in pairs
    assert (f"IP:{IP}", "USER:mlopez@example.com") in pairs
    assert (f"EMAIL_MESSAGE:{MID}", f"URL:{URL}") in pairs
    for link in links:
        assert link.kind is LinkKind.WORKFLOW and link.origin == "workflow:threat-intel-sweep"
        assert set(link.record_ids) <= set(run.index.ids())
