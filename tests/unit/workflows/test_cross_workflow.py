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
#: New workflows of 14.5.1 that do not have a directory yet (Phases 4 and 5).
PLANNED_NEW = frozenset({"suspicious-authentication", "threat-intel-sweep"})
WORKFLOW_DIRS = frozenset(p.parent.name for p in (REPO / "workflows").glob("*/README.md"))
_O = ObservableType
USER = (_O.USER, "jsmith@example.com")
HOST = (_O.HOSTNAME, "TH-LT-1047")
MAILBOX = (_O.EMAIL_ADDRESS, "jsmith@example.com")
MESSAGE = (_O.EMAIL_MESSAGE_ID, "etd-test-0001")
SOURCE_IP = (_O.IP, "203.0.113.200")


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
