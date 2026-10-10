"""Cross-workflow consistency of the migrated workflows (architecture 14.10.2).

Routing between overlapping triggers is deterministic and documented, hand-offs are declared once
(``handoff_to``) and listed the same way in ``workflows/README.md``, and every workflow a definition
names exists (a workflow directory, or a new workflow planned in 14.5.1).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from xdr_response.models import Incident, Observable, ObservableType, Severity
from xdr_response.workflows.discovery import discover_workflows

REPO = Path(__file__).resolve().parents[3]
CATALOG = discover_workflows()
#: New workflows of 14.5.1 that do not have a directory yet: none since Phase 5 (14.13.2).
PLANNED_NEW: frozenset[str] = frozenset()
WORKFLOW_DIRS = frozenset(p.parent.name for p in (REPO / "workflows").glob("*/README.md"))
_O = ObservableType
USER = (_O.USER, "jsmith@example.com")
HOST = (_O.HOSTNAME, "TH-LT-1047")
MAILBOX = (_O.EMAIL_ADDRESS, "jsmith@example.com")
MESSAGE = (_O.EMAIL_MESSAGE_ID, "etd-test-0001")
SOURCE_IP = (_O.IP, "203.0.113.200")
DOMAIN = (_O.DOMAIN, "beacon-relay.example")
URL = (_O.URL, "https://shop.example.com/cart/checkout")
SHA256 = (_O.SHA256, "7e3a91c5" * 8)


def _incident(*observables: tuple[ObservableType, str], techniques: tuple[str, ...] = (), title: str = "Alert",
              source: str = "cisco_xdr") -> Incident:
    return Incident(incident_id="XDR-CROSS-0001", title=title, severity=Severity.HIGH,
                    created_at=datetime(2026, 1, 15, 12, tzinfo=timezone.utc), source=source,
                    workflow_id="xdr-generic", workflow_version="0.0.0",
                    observables=tuple(Observable(type=t, value=v) for t, v in observables),
                    trigger={"mitre_techniques": list(techniques)})


# Routing: the entry-vector workflow wins over account-takeover, which it then hands off to.
ROUTES = [
    pytest.param(_incident(HOST, techniques=("T1486",)), "ransomware", id="T1486"),
    pytest.param(_incident(HOST, techniques=("T1486", "T1204.002")), "ransomware", id="ransomware-over-malware"),
    pytest.param(_incident(HOST, techniques=("T1204.002",)), "malware", id="T1204.002"),
    pytest.param(_incident(MESSAGE, MAILBOX, techniques=("T1566.002", "T1204.001")), "phishing", id="T1566"),
    pytest.param(_incident(MESSAGE, USER, techniques=("T1566.002", "T1078.004")), "phishing",
                 id="phishing-over-account-takeover"),
    pytest.param(_incident(USER, techniques=("T1078.004",)), "account-takeover", id="T1078.004"),
    pytest.param(_incident(USER, techniques=("T1621",)), "mfa-fatigue", id="T1621"),
    pytest.param(_incident(USER, techniques=("T1621", "T1078.004", "T1114.003")), "mfa-fatigue",
                 id="mfa-fatigue-over-account-takeover-and-bec"),
    pytest.param(_incident(USER, SOURCE_IP, techniques=("T1110.003",)), "password-spray", id="T1110.003"),
    pytest.param(_incident(USER, SOURCE_IP, techniques=("T1110.003", "T1078.004")), "password-spray",
                 id="password-spray-over-account-takeover"),
    pytest.param(_incident(MAILBOX, techniques=("T1667",)), "mail-bombing", id="T1667"),
    pytest.param(_incident(MAILBOX, techniques=("T1667", "T1656")), "mail-bombing", id="mail-bombing-over-bec"),
    pytest.param(_incident(MAILBOX, source="cisco-xdr-mailbomb-detector"), "mail-bombing", id="detector"),
    pytest.param(_incident(MAILBOX, techniques=("T1534",)), "bec", id="T1534"),
    pytest.param(_incident(MAILBOX, techniques=("T1656",)), "bec", id="T1656-alone"),
    # Phase 3 (14.11.2): a workflow outranks the workflows it hands off to; ransomware still wins.
    pytest.param(_incident(HOST, techniques=("T1059.001",)), "malicious-powershell", id="T1059.001"),
    pytest.param(_incident(HOST, techniques=("T1059.001", "T1547.001")), "malicious-powershell",
                 id="malicious-powershell-over-persistence"),
    pytest.param(_incident(HOST, techniques=("T1059.001", "T1105")), "malicious-powershell",
                 id="malicious-powershell-over-malware"),
    pytest.param(_incident(HOST, techniques=("T1547.001",)), "persistence", id="T1547.001"),
    pytest.param(_incident(HOST, techniques=("T1547.001", "T1204.002")), "persistence", id="persistence-over-malware"),
    pytest.param(_incident(HOST, techniques=("T1003.001",)), "credential-dumping", id="T1003.001"),
    pytest.param(_incident(HOST, techniques=("T1003.001", "T1059.001")), "credential-dumping",
                 id="credential-dumping-over-malicious-powershell"),
    pytest.param(_incident(HOST, USER, techniques=("T1003.001", "T1078.004")), "credential-dumping",
                 id="credential-dumping-over-account-takeover"),
    pytest.param(_incident(HOST, techniques=("T1021.002",)), "lateral-movement", id="T1021.002"),
    pytest.param(_incident(HOST, techniques=("T1021.002", "T1003.001")), "lateral-movement",
                 id="lateral-movement-over-credential-dumping"),
    pytest.param(_incident(HOST, techniques=("T1021.001", "T1486")), "ransomware", id="ransomware-over-lateral-movement"),
    pytest.param(_incident(HOST, techniques=("T1219",)), "unauthorized-rmm", id="T1219"),
    pytest.param(_incident(HOST, techniques=("T1219.002", "T1543.003")), "unauthorized-rmm",
                 id="unauthorized-rmm-over-persistence"),
    pytest.param(_incident(HOST, title="Remote desktop tool detected on TH-LT-1047"), "unauthorized-rmm",
                 id="rmm-title-over-lateral-movement-title"),
    pytest.param(_incident(HOST, title="Remote desktop logon from an unusual workstation"), "lateral-movement",
                 id="lateral-movement-title"),
    # Phase 4 (14.12.2).
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1071.001",)), "c2", id="T1071.001"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1573",)), "c2", id="T1573"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1071.001", "T1204.002")), "c2", id="c2-over-malware"),
    pytest.param(_incident(HOST, DOMAIN, title="Encrypted beaconing from TH-LT-5520 to beacon-relay.example"), "c2",
                 id="encrypted-beacon-title-is-c2-not-ransomware"),
    pytest.param(_incident(HOST, title="Files encrypted on TH-LT-1047"), "ransomware", id="ransomware-encrypted-files"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1059.001", "T1071.001")), "malicious-powershell",
                 id="malicious-powershell-over-c2"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1071.004",)), "dns-tunneling", id="T1071.004"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1071.004", "T1071.001")), "dns-tunneling",
                 id="dns-tunneling-over-c2"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1572", "T1048")), "dns-tunneling",
                 id="dns-tunneling-over-exfiltration"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1567.002",)), "exfiltration", id="T1567.002"),
    pytest.param(_incident(HOST, DOMAIN, techniques=("T1041", "T1071.001")), "exfiltration",
                 id="exfiltration-over-c2"),
    pytest.param(_incident(HOST, USER, techniques=("T1048", "T1078.004")), "exfiltration",
                 id="exfiltration-over-account-takeover"),
    pytest.param(_incident(HOST, techniques=("T1486", "T1567.002")), "ransomware", id="ransomware-double-extortion"),
    pytest.param(_incident(USER, techniques=("T1098.001",)), "cloud-compromise", id="T1098.001"),
    pytest.param(_incident(USER, techniques=("T1528", "T1078.004")), "cloud-compromise",
                 id="cloud-compromise-over-account-takeover"),
    pytest.param(_incident(USER, techniques=("T1078",)), "suspicious-authentication", id="T1078"),
    pytest.param(_incident(USER, title="Suspicious sign-in from an anonymous IP"), "suspicious-authentication",
                 id="suspicious-authentication-title"),
    pytest.param(_incident(USER, techniques=("T1078", "T1078.004")), "account-takeover",
                 id="account-takeover-cloud-account-over-valid-accounts"),
    pytest.param(_incident(USER, title="Risky sign-in for jsmith@example.com"), "account-takeover",
                 id="account-takeover-risky-sign-in-title"),
    pytest.param(_incident(USER, SOURCE_IP, techniques=("T1110.003", "T1078")), "password-spray",
                 id="password-spray-over-suspicious-authentication"),
    pytest.param(_incident(USER, techniques=("T1621", "T1078")), "mfa-fatigue",
                 id="mfa-fatigue-over-suspicious-authentication"),
    pytest.param(_incident(USER, title="Suspicious sign-in followed by an OAuth consent grant"), "cloud-compromise",
                 id="cloud-compromise-title-tie-by-id"),
    pytest.param(_incident(USER, SOURCE_IP, title="Password spray followed by a suspicious login"), "password-spray",
                 id="password-spray-title-tie-by-id"),
    # Phase 5 (14.13.2).
    pytest.param(_incident(HOST, techniques=("T1068",)), "privilege-escalation", id="T1068"),
    pytest.param(_incident(HOST, techniques=("T1548.002",)), "privilege-escalation", id="T1548.002"),
    pytest.param(_incident(USER, techniques=("T1098",)), "privilege-escalation", id="T1098"),
    pytest.param(_incident(USER, techniques=("T1098.007",)), "privilege-escalation", id="T1098.007"),
    pytest.param(_incident(USER, techniques=("T1098.003", "T1098")), "cloud-compromise",
                 id="cloud-compromise-cloud-roles-over-privilege-escalation"),
    pytest.param(_incident(USER, techniques=("T1098", "T1078.004")), "privilege-escalation",
                 id="privilege-escalation-over-account-takeover"),
    pytest.param(_incident(HOST, techniques=("T1003.001", "T1068")), "credential-dumping",
                 id="credential-dumping-over-privilege-escalation"),
    pytest.param(_incident(USER, title="Privileged role assigned to jsmith@example.com"), "privilege-escalation",
                 id="privilege-escalation-title"),
    pytest.param(_incident(HOST, SOURCE_IP, URL, techniques=("T1190",)), "vulnerability-exploitation", id="T1190"),
    pytest.param(_incident(HOST, techniques=("T1203",)), "vulnerability-exploitation", id="T1203"),
    pytest.param(_incident(HOST, SOURCE_IP, URL, techniques=("T1190", "T1595.002")), "vulnerability-exploitation",
                 id="vulnerability-exploitation-over-scanning"),
    pytest.param(_incident(HOST, SOURCE_IP, URL, techniques=("T1190", "T1204.002")), "vulnerability-exploitation",
                 id="vulnerability-exploitation-over-malware"),
    pytest.param(_incident(HOST, SOURCE_IP, title="Exploit attempt against TH-WEB-0401"),
                 "vulnerability-exploitation", id="vulnerability-exploitation-title"),
    pytest.param(_incident(HOST, SOURCE_IP, URL, techniques=("T1190", "T1505.003")), "web-attacks",
                 id="web-shell-to-web-attacks-over-vulnerability-exploitation"),
    pytest.param(_incident(HOST, SOURCE_IP, URL, techniques=("T1595.002",)), "web-attacks", id="T1595.002"),
    pytest.param(_incident(HOST, SOURCE_IP, title="IPS exploit signatures from the scheduled vulnerability scan"),
                 "web-attacks", id="web-attacks-scan-title-over-exploit-title"),
    pytest.param(_incident(SHA256, source="threat_intel"), "threat-intel-sweep", id="threat-intel-webhook"),
    pytest.param(_incident(SHA256, source="threat_intel", techniques=("T1204.002",)), "threat-intel-sweep",
                 id="threat-intel-sweep-over-malware"),
    pytest.param(_incident(HOST, DOMAIN, title="IOC sweep for beacon-relay.example", techniques=("T1071.001",)),
                 "threat-intel-sweep", id="threat-intel-sweep-title-over-c2"),
]


@pytest.mark.parametrize("incident, expected", ROUTES)
def test_overlapping_triggers_route_deterministically(incident: Incident, expected: str):
    workflow = CATALOG.resolve(incident)
    assert workflow is not None and workflow.id == expected


@pytest.mark.parametrize("workflow_id", sorted(CATALOG.ids()))
def test_related_workflows_and_handoff_targets_exist(workflow_id: str):
    definition = CATALOG.get(workflow_id).definition
    unknown = set(definition.related_workflows) - WORKFLOW_DIRS - PLANNED_NEW
    assert not unknown, f"{workflow_id}: unknown related workflows {sorted(unknown)}"
    assert set(definition.handoff_to) <= WORKFLOW_DIRS, "a hand-off target must exist today"


def test_compromised_account_handoffs_converge_on_account_takeover():
    """Every entry-vector workflow that concludes an account is compromised hands off to account-takeover."""
    entry_vectors = {"phishing", "password-spray", "mfa-fatigue", "mail-bombing", "bec"}
    for workflow_id in entry_vectors:
        assert "account-takeover" in CATALOG.get(workflow_id).definition.handoff_to, workflow_id
    assert CATALOG.get("account-takeover").definition.handoff_to == ()


def test_endpoint_workflows_that_find_compromised_accounts_hand_them_to_account_takeover():
    """Phase 3: credential exposure, movement accounts and RMM-host users go to account-takeover (14.11.2)."""
    for workflow_id in ("credential-dumping", "lateral-movement", "unauthorized-rmm"):
        assert "account-takeover" in CATALOG.get(workflow_id).definition.handoff_to, workflow_id


def test_phase4_workflows_that_find_compromised_accounts_hand_them_to_account_takeover():
    """Phase 4: transfer accounts, likely-compromised sign-ins and cloud accounts go to account-takeover (14.12.2)."""
    for workflow_id in ("exfiltration", "suspicious-authentication", "cloud-compromise"):
        assert "account-takeover" in CATALOG.get(workflow_id).definition.handoff_to, workflow_id
    assert CATALOG.get("c2").definition.handoff_to == ("malware",)
    assert CATALOG.get("dns-tunneling").definition.handoff_to == ()


def test_phase5_handoffs():
    """Phase 5 (14.13.2): privileged accounts go to account-takeover; the sweep routes each finding to the
    workflow that starts from it; exploitation hands the host and the payload on; web shells go to malware."""
    assert CATALOG.get("privilege-escalation").definition.handoff_to == ("account-takeover",)
    assert set(CATALOG.get("threat-intel-sweep").definition.handoff_to) == {
        "malware", "c2", "phishing", "account-takeover"}
    assert set(CATALOG.get("vulnerability-exploitation").definition.handoff_to) == {"persistence", "malware"}
    assert CATALOG.get("web-attacks").definition.handoff_to == ("malware",)


#: The entity each hand-off target starts from (14.11.2, 14.13.2): an account, an endpoint hostname, a file
#: hash or a mailbox.
_ACCOUNT = re.compile(r"^[^@\s/]+@[a-z0-9.-]+\.[a-z]+$")
_HOSTNAME = re.compile(r"^[A-Z0-9][A-Z0-9.-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HANDOFF_SUBJECTS = {"account-takeover": _ACCOUNT, "phishing": _ACCOUNT, "malware": _SHA256,
                    "persistence": _HOSTNAME, "unauthorized-rmm": _HOSTNAME, "credential-dumping": _HOSTNAME,
                    "c2": _HOSTNAME}


def test_every_handoff_target_has_a_subject_convention():
    targets = {t for w in CATALOG.ids() for t in CATALOG.get(w).definition.handoff_to}
    assert targets <= set(HANDOFF_SUBJECTS), sorted(targets - set(HANDOFF_SUBJECTS))


def test_scenario_handoff_subjects_are_the_entity_the_target_starts_from():
    import yaml

    bad = []
    for path in sorted((REPO / "tests" / "fixtures" / "workflows").glob("*/*.yaml")):
        expect = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("expect") or {}
        for entry in expect.get("handoffs") or ():
            target, _, subject = entry.partition(":")
            pattern = HANDOFF_SUBJECTS.get(target)
            if pattern is None or not pattern.match(subject):
                bad.append(f"{path.parent.name}/{path.stem}: {entry}")
    assert not bad, bad


def test_every_attack_id_has_one_name_and_one_tactic_set_across_workflows():
    """14.11.2 / 14.12.2: a technique reads the same in every workflow (and in the generated MITRE mapping)."""
    seen: dict[str, tuple[str, frozenset[str], str]] = {}
    problems = []
    for workflow_id in sorted(CATALOG.ids()):
        tactics: dict[str, set[str]] = {}
        names: dict[str, str] = {}
        for m in CATALOG.get(workflow_id).definition.mitre:
            tactics.setdefault(m.attack_id, set()).add(m.tactic)
            names[m.attack_id] = m.sub_technique_name or m.technique_name
            if m.sub_technique:  # the parent's name is part of every sub-technique mapping
                names.setdefault(m.technique, m.technique_name)
                if names[m.technique] != m.technique_name:
                    problems.append(f"{workflow_id}: {m.technique} named {m.technique_name!r} and {names[m.technique]!r}")
        for attack_id, tactic_set in tactics.items():
            current = (names[attack_id], frozenset(tactic_set), workflow_id)
            first = seen.setdefault(attack_id, current)
            if first[:2] != current[:2]:
                problems.append(f"{attack_id}: {first[2]} {first[0]!r} {sorted(first[1])} != "
                                f"{workflow_id} {current[0]!r} {sorted(current[1])}")
    assert not problems, problems


def _top_priority(workflow_id: str) -> int:
    triggers = [t for t in CATALOG.get(workflow_id).definition.triggers if t.type != "manual"]
    return max((t.priority for t in triggers), default=0)


@pytest.mark.parametrize("workflow_id", sorted(CATALOG.ids()))
def test_a_workflow_outranks_the_workflows_it_hands_off_to(workflow_id: str):
    """When both trigger, the workflow that hands off handles the incident, so the hand-off is still made."""
    for target in CATALOG.get(workflow_id).definition.handoff_to:
        if target in CATALOG:
            assert _top_priority(workflow_id) > _top_priority(target), (workflow_id, target)


def test_handoff_graph_has_no_cycle():
    graph = {w: set(CATALOG.get(w).definition.handoff_to) for w in CATALOG.ids()}
    seen: set[str] = set()

    def visit(node: str, path: tuple[str, ...]) -> None:
        assert node not in path, " -> ".join((*path, node))
        if node in seen:
            return
        for nxt in sorted(graph.get(node, ())):
            visit(nxt, (*path, node))
        seen.add(node)

    for workflow_id in sorted(graph):
        visit(workflow_id, ())


def test_the_workflow_index_lists_the_declared_handoffs():
    text = (REPO / "workflows" / "README.md").read_text(encoding="utf-8")
    section = text.split("## Migrated workflows", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in section.splitlines():
        match = re.match(r"\| \[`([a-z0-9-]+)`\]\([^)]*\) \| (\d) \| (.*) \|$", line)
        if match:
            rows[match.group(1)] = set(re.findall(r"`([a-z0-9-]+)`", match.group(3)))
    assert set(rows) == set(CATALOG.ids())
    for workflow_id, listed in rows.items():
        assert listed == set(CATALOG.get(workflow_id).definition.handoff_to), workflow_id
