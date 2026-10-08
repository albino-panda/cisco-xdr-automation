"""Lateral-movement workflow definition (Phase 3; replaces the legacy spec ``workflows/lateral-movement``).

The workflow investigates suspected lateral movement (remote desktop, SMB and admin shares, WinRM, WMI,
remote service creation and PsExec-like behaviour, abnormal authentication, unexpected east-west
traffic), determines the source host, the target hosts, the credential, the responsible process and
the blast radius, and *recommends* a containment package: isolate the source, isolate the targets that
show malicious activity of their own, revoke (and, when confirmed compromised, disable) the credential,
and block the transferred tool and the attacker's address. It never executes anything: every action
needs a human approval in the lifecycle orchestrator, and restoration needs a separate human release
approval.

Rules use the facts of :mod:`xdr_response.workflows.lateral_movement.hooks`; every fact maps an entity
to the records it came from, so every recommendation cites real investigation or enrichment records.
"""
from __future__ import annotations

from xdr_response.models import ActionType, ObservableType, Severity
from xdr_response.workflows.definition import (
    CorrelationSpec,
    IntegrationRequirement,
    InvestigationStep,
    MitreMapping,
    RecommendationRule,
    ScoringInputs,
    TriggerSpec,
    WorkflowDefinition,
)

_O = ObservableType
_A = ActionType

#: Remote service ports (keep in step with hooks.LATERAL_PORTS).
_PORTS = "[135, 139, 445, 3389, 5985, 5986]"
#: Peer addresses of remote service connections recorded on the investigated endpoints.
_PEER_IPS = (f"distinct(flatten([[c.remote_ip for c in e.network_connections if c.remote_ip and c.remote_port in "
             f"{_PORTS}] for e in results.investigate_endpoint]))")
#: Hosts an investigate_endpoint item can be isolated through Secure Endpoint (it knows the host, or
#: Defender does not) and whose connector policy does not forbid isolation.
_SE_ROUTE = "item.isolation_capable != False and (item.connector_guid or not item.mde_machine_id)"
_HOST_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip_addresses[0] if item.ip_addresses else None}"
_USER_ASSET = "{'groups': get(item.profile, 'groups', []), 'roles': get(item.profile, 'roles', [])}"
_FLAGGED = "['MALICIOUS', 'SUSPICIOUS']"
_HOST_RATIONALE = "'lateral movement: ' + get(facts.host_summary, item.hostname, item.hostname)"
_LATERAL_IDS = ("T1021.001", "T1021.002", "T1021.006", "T1570", "T1569.002", "T1047")

WORKFLOW = WorkflowDefinition(
    id="lateral-movement",
    version="3.0.0",
    name="Lateral movement",
    description=(
        "Investigates suspected lateral movement (remote desktop, SMB and admin shares, WinRM, WMI, remote "
        "service creation and PsExec-like behaviour, abnormal authentication, unexpected east-west traffic) "
        "across the hosts, peers, accounts, sign-ins, transferred tools and their spread, builds the movement "
        "graph (source host, target hosts, credential, responsible process) and its blast radius, and "
        "recommends a containment package for human approval: isolate the source host, isolate the target "
        "hosts that show malicious activity of their own, revoke the sessions of the credential used (and "
        "disable it when the identity provider or a malicious sign-in confirms it compromised), block the "
        "transferred tool hash and the attacker's address. Targets reached without activity of their own, "
        "sanctioned admin jump hosts and unresolved peers are shown as considered, never silently dropped."),
    phase=3,
    default_severity=Severity.HIGH,
    legacy_id="lateral-movement",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident tagged with a remote-services or lateral tool transfer technique "
                                "(sub-techniques such as remote desktop, SMB admin shares and WinRM match)",
                    mitre_techniques=("T1021", "T1570"), priority=160),
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident whose title names lateral movement, remote logons, remote "
                                "services, admin shares, WinRM, remote desktop, PsExec-like activity or "
                                "east-west traffic",
                    title_patterns=("*lateral movement*", "*remote logon*", "*remote service*", "*admin share*",
                                    "*winrm*", "*remote desktop*", "*psexec*", "*east-west*"),
                    priority=140),
        TriggerSpec(type="manual", description="An analyst starts the workflow for an incident or a host pivot"),
    ),
    input_observables=(_O.HOSTNAME, _O.ENDPOINT_ID, _O.USER, _O.IP, _O.SHA256),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint context, detections, process and network events of the source and target hosts; "
                    "related endpoints and tool prevalence; preferred isolation route",
            atomics=("investigate_endpoint", "search_related_endpoints", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="entra",
            purpose="Profile, risk state, risk detections and sign-ins of the accounts used for the movement; "
                    "session revocation and account disable route",
            atomics=("investigate_user", "investigate_authentication")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Context of Defender-managed devices; Defender isolation route; indicator route for the "
                    "tool hash and the attacker's address",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Microsoft Defender XDR alerts (typed detections with the vendor's ATT&CK techniques) and "
                    "hunting searches for related endpoints, tool prevalence and authentication",
            atomics=("investigate_endpoint", "search_related_endpoints", "search_hash_enterprise",
                     "investigate_user", "investigate_authentication")),
        IntegrationRequirement(
            integration="splunk",
            purpose="Enterprise searches for related endpoints, tool prevalence and authentication",
            atomics=("search_related_endpoints", "search_hash_enterprise", "investigate_authentication")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Hash and IP enrichment, endpoint context and native response actions",
            atomics=("enrich_hash", "enrich_ip", "investigate_endpoint", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="meraki",
            purpose="IP block route at the network edge"),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Second opinion on tool hash and sign-in address reputation (disclosure policy applies)",
            atomics=("enrich_hash", "enrich_ip")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Additional reputation for tool hashes and addresses (disclosure policy applies)",
            atomics=("enrich_hash", "enrich_ip")),
    ),
    investigation=(
        InvestigationStep(id="incident_hosts", atomic="investigate_endpoint"),
        InvestigationStep(
            id="peer_lookup", atomic="search_related_endpoints", subject_type=_O.HOSTNAME,
            subjects=(f"[e.hostname for e in results.investigate_endpoint if e.hostname and any(c.remote_port in "
                      f"{_PORTS} for c in e.network_connections)]")),
        InvestigationStep(
            id="peer_hosts", atomic="investigate_endpoint", subject_type=_O.HOSTNAME,
            subjects=(f"distinct(flatten([[x.hostname for x in r.endpoints if x.hostname and any(ip in {_PEER_IPS} "
                      "for ip in x.ip_addresses)] for r in results.search_related_endpoints]))")),
        InvestigationStep(id="tool_reputation", atomic="enrich_hash"),
        InvestigationStep(
            id="tool_spread", atomic="search_hash_enterprise", subject_type=_O.SHA256,
            subjects=(f"distinct([r.value for r in results.enrich_hash if r.type == 'sha256' and r.verdict in "
                      f"{_FLAGGED}] + get(incident.observables_by_type, 'sha256', []) + flatten([[d.sha256 for d in "
                      "e.detections if d.verdict == 'MALICIOUS' and d.sha256] for e in results.investigate_endpoint]))"),
            lookback_hours=72),
        InvestigationStep(
            id="tool_hosts", atomic="investigate_endpoint", subject_type=_O.HOSTNAME,
            subjects=(f"distinct(flatten([r.endpoints for r in results.search_hash_enterprise if (r.prevalence is "
                      f"None or r.prevalence <= 50) and (r.verdict in {_FLAGGED} or r.sha256 in [e.value for e in "
                      f"results.enrich_hash if e.verdict in {_FLAGGED}])]))")),
        InvestigationStep(
            id="accounts", atomic="investigate_user", subject_type=_O.USER,
            subjects=("distinct([u for u in incident.users + get(incident.observables_by_type, 'user', []) + "
                      "flatten([[c.user for c in e.network_connections] for e in results.investigate_endpoint]) + "
                      "flatten([[d.user for d in e.detections] for e in results.investigate_endpoint]) + "
                      "flatten([[t.user for t in e.trajectory if t.verdict == 'MALICIOUS'] for e in "
                      "results.investigate_endpoint]) if u and '@' in u])")),
        InvestigationStep(
            id="authentication", atomic="investigate_authentication",
            subjects="[u.user for u in results.investigate_user if u.user]"),
        InvestigationStep(
            id="address_reputation", atomic="enrich_ip", subject_type=_O.IP,
            subjects=("distinct([i for i in get(incident.observables_by_type, 'ip', []) + flatten([[s.ip for s in "
                      "a.signins] for a in results.investigate_authentication]) + flatten([[s.ip for s in u.signins] "
                      "for u in results.investigate_user]) if i and ':' not in i])")),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links over the run's records within 60 minutes: the same user on several endpoints, the "
            "same endpoint used by several users, the same tool hash or address on two or more endpoints, "
            "process lineage on one endpoint, and a successful sign-in followed by account activity. The "
            "workflow hooks add the movement graph: one link per source -> destination edge (remote desktop, "
            "SMB, WinRM, RPC/WMI ports on network connection records, peers resolved through the endpoint "
            "records' addresses) with the account that used it, and derive the facts the rules use: "
            "compromised hosts, quiet movement sources, clean targets, admin jump hosts, transferred tools and "
            "the hosts that hold them, movement and compromised accounts, blockable addresses, remote "
            "execution (the responsible process) and unresolved peers."),
        window_minutes=60),
    scoring=ScoringInputs(
        description=(
            "Per target, from the records its rule cites: endpoint detections and vendor-flagged process "
            "events dominate (a vendor category naming lateral movement scores as lateral movement); a "
            "transferred tool's prevalence record counts as an endpoint detection; the hook adds 'lateral "
            "movement source' and 'credential used for lateral movement' (lateral movement, SUSPICIOUS, "
            "severity 80) citing the edge records and the records that confirm the movement; identity risk "
            "and risk detections score as authentication anomalies. Reputation is capped by the engine, a "
            "single source is capped below CRITICAL unless it is a MALICIOUS behavioural detection, and failed "
            "expected sources lower confidence. Default category weights.")),
    recommendations=(
        RecommendationRule(
            id="isolate_compromised_hosts",
            description="Isolate a source or target host with malicious activity of its own (a malicious "
                        "detection or process event, or a transferred tool rated malicious) through Secure Endpoint",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_secure_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.hostname in facts.compromised_hosts and {_SE_ROUTE}",
            target="item.hostname",
            evidence="facts.compromised_hosts[item.hostname]",
            asset=_HOST_ASSET,
            rationale=_HOST_RATIONALE,
            min_risk=60,
            mitre=_LATERAL_IDS,
        ),
        RecommendationRule(
            id="isolate_movement_sources",
            description="Isolate the quiet source of confirmed lateral movement (no malicious activity of its "
                        "own) through Secure Endpoint, so the origin is not left active",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_secure_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.hostname in facts.movement_sources and {_SE_ROUTE}",
            target="item.hostname",
            evidence="facts.movement_sources[item.hostname]",
            asset=_HOST_ASSET,
            rationale=_HOST_RATIONALE,
            min_risk=60,
            mitre=("T1021.001", "T1021.002", "T1021.006"),
        ),
        RecommendationRule(
            id="isolate_defender_hosts",
            description="Isolate a compromised host or movement source managed by Defender for Endpoint (Defender "
                        "route; merged with the Secure Endpoint recommendation when both products manage the host)",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_defender_endpoint",
            for_each="results.investigate_endpoint",
            when=("item.mde_machine_id and item.isolation_capable != False and (item.hostname in "
                  "facts.compromised_hosts or item.hostname in facts.movement_sources)"),
            target="item.hostname",
            evidence=("get(facts.compromised_hosts, item.hostname, []) + "
                      "get(facts.movement_sources, item.hostname, [])"),
            asset=_HOST_ASSET,
            rationale=_HOST_RATIONALE,
            min_risk=60,
            mitre=_LATERAL_IDS,
        ),
        RecommendationRule(
            id="revoke_movement_credentials",
            description="Revoke the sign-in sessions of the account used for confirmed lateral movement, or of an "
                        "account confirmed compromised",
            action=_A.REVOKE_SESSIONS, builder="revoke_entra_sessions",
            for_each="results.investigate_user",
            when="item.user in facts.movement_accounts or item.user in facts.compromised_accounts",
            target="item.user",
            evidence=("get(facts.movement_accounts, item.user, []) + "
                      "get(facts.compromised_accounts, item.user, [])"),
            asset=_USER_ASSET,
            rationale="'lateral movement credential: ' + get(facts.account_summary, item.user, item.user)",
            min_risk=50,
            mitre=("T1078",),
        ),
        RecommendationRule(
            id="disable_compromised_accounts",
            description="Disable a movement account the identity provider rates high risk, confirms compromised or "
                        "reports a risk detection for, or an account that signed in from an address rated malicious",
            action=_A.DISABLE_USER, builder="disable_entra_user",
            for_each="results.investigate_user",
            when="item.user in facts.compromised_accounts",
            target="item.user",
            evidence="facts.compromised_accounts[item.user] + get(facts.movement_accounts, item.user, [])",
            asset=_USER_ASSET,
            rationale="'compromised account: ' + get(facts.account_summary, item.user, item.user)",
            min_risk=60,
            mitre=("T1078",),
        ),
        RecommendationRule(
            id="block_transferred_tool",
            description="Block a transferred tool hash rated malicious (or suspicious and named by a malicious "
                        "detection) seen on 50 endpoints or fewer",
            action=_A.BLOCK_HASH, builder="block_hash",
            for_each="results.enrich_hash",
            when="item.value in facts.blockable_hashes",
            target="item.value",
            evidence="facts.blockable_hashes[item.value]",
            rationale=("'tool transferred between hosts, rated ' + item.verdict + (', prevalence unknown: check '"
                       " + 'before approving' if facts.tool_hashes[item.value].prevalence is None else '')"),
            min_risk=60,
            mitre=("T1570",),
        ),
        RecommendationRule(
            id="block_attacker_address",
            description="Block an address rated malicious or suspicious that a movement account signed in from, an "
                        "edge names or the incident lists",
            action=_A.BLOCK_IP, builder="block_ip",
            for_each="results.enrich_ip",
            when="item.value in facts.blockable_ips",
            target="item.value",
            evidence="facts.blockable_ips[item.value]",
            rationale="'address rated ' + item.verdict + ' used in the authentication behind the movement'",
            min_risk=50,
            mitre=("T1078",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0008", technique="T1021", technique_name="Remote Services",
                     sub_technique="T1021.001", sub_technique_name="Remote Desktop Protocol",
                     rationale="Remote desktop connections (port 3389) between investigated hosts form movement "
                               "edges; the source and compromised targets are isolated."),
        MitreMapping(tactic="TA0008", technique="T1021", technique_name="Remote Services",
                     sub_technique="T1021.002", sub_technique_name="SMB/Windows Admin Shares",
                     rationale="SMB connections (ports 445 and 139) to admin shares between hosts form movement "
                               "edges; tool copies over them are tracked by hash."),
        MitreMapping(tactic="TA0008", technique="T1021", technique_name="Remote Services",
                     sub_technique="T1021.006", sub_technique_name="Windows Remote Management",
                     rationale="WinRM connections (ports 5985 and 5986) and processes started by the WinRM "
                               "provider host on the destination."),
        MitreMapping(tactic="TA0008", technique="T1570", technique_name="Lateral Tool Transfer",
                     rationale="A tool rated malicious present on further hosts (prevalence records): those hosts "
                               "are isolated before the tool raises a detection, and the hash is blocked."),
        MitreMapping(tactic="TA0002", technique="T1569", technique_name="System Services",
                     sub_technique="T1569.002", sub_technique_name="Service Execution",
                     rationale="Remote service creation (PsExec-like behaviour): service events and children of "
                               "the service control manager on a destination reached over SMB."),
        MitreMapping(tactic="TA0002", technique="T1047", technique_name="Windows Management Instrumentation",
                     rationale="Remote WMI execution: processes started by the WMI provider host on a destination "
                               "reached over RPC. No sub-technique exists."),
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     rationale="The credential used for the movement loses its sessions, and is disabled when "
                               "confirmed compromised; abnormal authentication from an address rated malicious is "
                               "blocked. No sub-technique: the records do not show whether the account is a domain, "
                               "local or cloud account."),
    ),
    known_limitations=(
        "Real Secure Endpoint trajectory events and Defender or Splunk hunting rows stay generic records "
        "(docs/integrations.md documents no event fields), so the source -> destination graph is built only from "
        "typed network connection records (simulated sources today). On real tenants hosts are isolated on their "
        "own typed detections (Microsoft Defender XDR alerts) and tool prevalence; a quiet source with no "
        "detection of its own needs the analyst until the event schema is verified.",
        "A peer address is resolved to a host only through the endpoint records of the run; an address two hosts "
        "claim (DHCP reuse) or no investigated host owns is listed as a manual step, not isolated.",
        "Remote WMI and DCOM share the RPC port, so a connection on port 135 is labelled RPC/WMI; WMI is named "
        "only when the destination records a child of the WMI provider host.",
        "Targets reached by confirmed movement without malicious activity of their own, sanctioned admin jump "
        "hosts (recognised by endpoint group or tag names), hosts whose policy forbids isolation and tool hashes "
        "seen on more than 50 endpoints are not recommended; they are listed as considered with their records, and "
        "the analyst contains them by hand if needed.",
        "Revocation ends cloud sessions only: on-premises Active Directory credentials, Kerberos tickets and "
        "local accounts used for the movement are not reset by any VERIFIED write; password resets stay analyst "
        "follow-up.",
        "Remote services and scheduled tasks created on destinations are not removed (remove_persistence has no "
        "VERIFIED write); the persistence workflow or the analyst handles them.",
        "Secure Cloud Analytics east-west alerts are read only as Cisco XDR incidents (its API is UNVERIFIED), so "
        "they trigger the workflow but add no records of their own.",
        "A tenant whose only executor is Cisco XDR native response needs product-pinned builders; such actions "
        "are reported as unrouted and handled manually.",
    ),
    related_workflows=("credential-dumping", "ransomware", "privilege-escalation", "account-takeover", "malware",
                       "persistence"),
    handoff_to=("account-takeover", "credential-dumping"),
)
