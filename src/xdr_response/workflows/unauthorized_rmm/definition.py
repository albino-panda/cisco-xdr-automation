"""Unauthorised remote access tool workflow (Phase 3; replaces ``workflows/unauthorized-rmm/workflow.yaml``).

A remote monitoring and management (RMM) or remote desktop tool (AnyDesk, RustDesk, ScreenConnect,
TeamViewer, Splashtop, Atera, ConnectWise and others) appears on an endpoint. The workflow
investigates the endpoint (execution, installer source, persistence, network destinations of the
tool), the tool's binary (reputation, prevalence and code-signing subject across the estate), the
other endpoints that run it and the users involved. It then RECOMMENDS a containment package:
terminate the running tool, block its binary, block the destinations it talks to and isolate an
endpoint whose remote session shows a hostile operator.

Sanctioned corporate tools are never treated as malicious:

* the workflow never rates a tool itself; a tool is *flagged* only by an endpoint detection, a
  reputation verdict or a malicious process event that cites the tool's records;
* ``allowlists.approved_rmm`` (``approved_rmm_allowlist``) is enforced by the framework on every
  proposal: an approved tool's hashes and domains are moved to the package's excluded targets by
  ``PackageBuilder`` (shown, never executed), and a hash block or process termination of a file
  signed by an approved signer, or of an approved binary, is withheld by the runner as
  ``ALLOWLISTED`` and shown as considered (also when the process event carries no hash and the
  host's records name the same executable), and so is a block of an unrated relay that rests only
  on a sanctioned tool's flag (``RecommendationRule.binaries``);
* fleet-wide blocks (hash, relay domain) are not proposed for a tool seen on more than
  :data:`MAX_FLEET_BLOCK_PREVALENCE` endpoints, which looks like a corporate deployment; a human
  decides.

Like every workflow it only investigates and recommends: it never executes, never approves and
never chooses an approval level. ELEVATED comes from ``PackageBuilder`` (critical assets,
blast-radius caps); execution, verification and restoration happen only in the lifecycle
orchestrator after human approval.
"""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.atomics.correlation.models import LinkKind
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

__all__ = [
    "WORKFLOW",
    "ENDPOINT_SOURCES",
    "MAX_FLEET_BLOCK_PREVALENCE",
    "RMM_PRODUCTS",
    "RMM_KEYWORDS",
    "RMM_TECHNIQUE",
    "REMOTE_ACCESS_CATEGORIES",
]

#: ATT&CK technique of remote access tools; a detection reporting it (or a sub-technique) names an RMM tool.
RMM_TECHNIQUE = "T1219"

#: Known remote access products and the executable names (lower case, ``fnmatch`` patterns) that
#: identify them in process events, hash prevalence and persistence records. Product knowledge only,
#: never an indicator: a match identifies a tool, it never rates it (rating comes from detections and
#: reputation). Tools not listed are identified by an endpoint detection that reports T1219 or names
#: remote access (:data:`RMM_KEYWORDS`).
RMM_PRODUCTS: Mapping[str, tuple[str, ...]] = {
    "AnyDesk": ("anydesk*.exe", "anydesk"),
    "RustDesk": ("rustdesk*.exe", "rustdesk"),
    "ScreenConnect": ("screenconnect*.exe", "connectwisecontrol*.exe"),
    "TeamViewer": ("teamviewer*.exe", "tv_w32.exe", "tv_x64.exe", "teamviewer"),
    "Splashtop": ("splashtop*.exe", "srservice.exe", "srmanager.exe", "strwinclt.exe"),
    "Atera": ("ateraagent*.exe",),
    "ConnectWise Automate": ("ltsvc.exe", "lttray.exe", "ltsvcmon.exe"),
    "NinjaOne": ("ninjarmmagent*.exe",),
    "LogMeIn": ("logmein*.exe", "lmiguardiansvc.exe"),
    "GoTo Resolve": ("gotoresolve*.exe",),
    "BeyondTrust Remote Support": ("bomgar-scc*.exe",),
    "Remote Utilities": ("rutserv.exe", "rfusclient.exe"),
    "MeshCentral": ("meshagent*.exe",),
    "Action1": ("action1_agent*.exe",),
    "DWService": ("dwagent*.exe",),
    "Supremo": ("supremo*.exe",),
    "Chrome Remote Desktop": ("remoting_host.exe",),
    "NetSupport Manager": ("client32.exe",),
    "Tactical RMM": ("tacticalrmm*.exe",),
}

#: Words in a detection name or category that name a remote access tool (lower case).
RMM_KEYWORDS: tuple[str, ...] = ("remote access", "remoteaccess", "remote-access", "remote admin",
                                 "remoteadmin", "remote desktop", "remote monitoring", "rmm")

#: Vendor or DNS categories (lower case substrings) that mark a domain as remote access infrastructure.
REMOTE_ACCESS_CATEGORIES: tuple[str, ...] = ("remote access", "remote-access", "remoteaccess")

#: A tool seen on more endpoints than this looks like a corporate deployment: its hash and relay
#: domains are not proposed for a fleet-wide block (a wrong call would cut IT's own remote support
#: everywhere at once). They are listed as considered with the prevalence record; a human decides.
MAX_FLEET_BLOCK_PREVALENCE = 50

#: Endpoint sources the endpoint and hash steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")

_ENDPOINTS = "results.investigate_endpoint"
_DETECTIONS = f"flatten([r.detections for r in {_ENDPOINTS}])"
_EVENTS = f"flatten([r.trajectory for r in {_ENDPOINTS}])"
_CONNECTIONS = f"flatten([r.network_connections for r in {_ENDPOINTS}])"
_DNS = f"flatten([r.dns_queries for r in {_ENDPOINTS}])"
_PERSISTENCE = f"flatten([r.persistence for r in {_ENDPOINTS}])"

#: Hashes that can name the tool: incident hashes, detection hashes, hashes of processes that talk to
#: the network, persistence items and executed files (in that priority order; the runner keeps the
#: first ``max_subjects`` distinct values).
_HASH_SUBJECTS = (
    "get(incident.observables_by_type, 'sha256', [])"
    f" + [d.sha256 for d in {_DETECTIONS} if d.sha256]"
    f" + [c.sha256 for c in {_CONNECTIONS} if c.sha256]"
    f" + [p.sha256 for p in {_PERSISTENCE} if p.sha256]"
    f" + [e.sha256 for e in {_EVENTS} if e.sha256 and e.event_type in ['process_start', 'file_execute']]"
)
#: Hashes the detection itself names (incident hashes and detection hashes): their prevalence scopes
#: the other endpoints that run the tool.
_CORE_HASHES = (
    "get(incident.observables_by_type, 'sha256', [])"
    f" + [d.sha256 for d in {_DETECTIONS} if d.sha256]"
)
_AFFECTED_SUBJECTS = (
    f"[d.endpoint for d in {_DETECTIONS} if d.endpoint]"
    f" + flatten([r.endpoints for r in results.search_hash_enterprise if r.sha256 in {_CORE_HASHES}"
    f" and r.prevalence != None and r.prevalence <= {MAX_FLEET_BLOCK_PREVALENCE}])"
)
_DOMAIN_SUBJECTS = (
    "get(incident.observables_by_type, 'domain', [])"
    f" + [c.domain for c in {_CONNECTIONS} if c.domain]"
    f" + [e.domain for e in {_EVENTS} if e.domain]"
    f" + [q.domain for q in {_DNS} if q.domain]"
)
_IP_SUBJECTS = (
    "get(incident.observables_by_type, 'ip', [])"
    f" + [c.remote_ip for c in {_CONNECTIONS} if c.remote_ip and c.direction != 'internal']"
    f" + [e.remote_ip for e in {_EVENTS} if e.remote_ip]"
)

_FACT_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'users': item.users}"
_SESSION_RATIONALE = (
    "'remote session of ' + item.tool_list + ' on ' + item.hostname + ' shows an untrusted operator ('"
    " + item.basis + '); peers: ' + item.peer_list"
)
_DESTINATION_RATIONALE = (
    "item.role_text + ' ' + item.value + ' of ' + item.tool_list + ' (' + item.basis + ')'"
)

WORKFLOW = WorkflowDefinition(
    id="unauthorized-rmm",
    version="3.0.0",
    name="Unauthorised remote access tool",
    description=(
        "Handle a remote monitoring and management (RMM) or remote desktop tool on an endpoint: identify "
        "the tool and check it against allowlists.approved_rmm, investigate how it was installed (installer "
        "source), who ran it, where it executed, how it persists and which destinations its sessions reach, "
        "scope the other endpoints that run it, and recommend a containment package (terminate the tool, "
        "block its binary, block its destinations, isolate an endpoint whose session shows a hostile "
        "operator) for human approval. A sanctioned corporate tool is never treated as malicious."
    ),
    phase=3,
    default_severity=Severity.HIGH,
    legacy_id="unauthorized-rmm",
    triggers=(
        TriggerSpec(type="xdr_incident_rule", priority=150,
                    description="Cisco XDR incident whose detection reports remote access tools (T1219 or a "
                                "sub-technique) on an endpoint",
                    mitre_techniques=(RMM_TECHNIQUE,),
                    observable_types=(ObservableType.HOSTNAME, ObservableType.SHA256)),
        TriggerSpec(type="xdr_incident_rule", priority=145,
                    description="Cisco XDR incident titled as a remote access, remote desktop or RMM tool "
                                "detection that names an endpoint",
                    title_patterns=("*remote access tool*", "*remote access software*", "*remote desktop tool*",
                                    "*rmm tool*", "*remote monitoring and management*", "*unapproved rmm*"),
                    observable_types=(ObservableType.HOSTNAME,)),
        TriggerSpec(type="manual",
                    description="An analyst starts the workflow from an incident or an endpoint observable"),
    ),
    input_observables=(ObservableType.HOSTNAME, ObservableType.SHA256, ObservableType.DOMAIN, ObservableType.IP,
                       ObservableType.USER),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint detections, device trajectory (execution, installer source, network sessions), "
                    "persistence, hash prevalence and signer, and the isolation of the endpoint",
            atomics=("investigate_endpoint", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain status and categories of the tool's relay and download domains, and the landing "
                    "product for approved domain blocks",
            atomics=("enrich_domain",)),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, alerts, timeline, prevalence) and isolation or hash "
                    "indicators for the endpoints it manages",
            atomics=("investigate_endpoint", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings for the tool's hash, domains and IPs, and the native "
                    "response actions the router prefers when configured",
            atomics=("investigate_endpoint", "search_hash_enterprise", "enrich_hash", "enrich_domain",
                     "enrich_ip")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the tool's hash and of the public domains and IPs its sessions reach",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) for the session peers and the tool's hash",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip")),
        IntegrationRequirement(
            integration="entra",
            purpose="Profile and risk state of the users who ran the tool or use the endpoint (account "
                    "compromise hand-off)",
            atomics=("investigate_user",)),
        IntegrationRequirement(
            integration="meraki",
            purpose="Landing product for approved blocks of a session peer IP rated malicious or suspicious",
            atomics=()),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="tool_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
        InvestigationStep(id="tool_prevalence", atomic="search_hash_enterprise", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, integrations=ENDPOINT_SOURCES, max_subjects=10),
        InvestigationStep(id="affected_endpoints", atomic="investigate_endpoint", subjects=_AFFECTED_SUBJECTS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="destination_domains", atomic="enrich_domain", subjects=_DOMAIN_SUBJECTS,
                          max_subjects=15),
        InvestigationStep(id="destination_ips", atomic="enrich_ip", subjects=_IP_SUBJECTS,
                          subject_type=ObservableType.IP, max_subjects=15),
        InvestigationStep(id="tool_users", atomic="investigate_user", integrations=("entra",), max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same hash, domain or IP on two or more endpoints or users (one tool or "
            "relay across the estate), the same endpoint or user across sources, and process lineage. "
            "Workflow links (hooks): a remote session (the endpoint, the tool's hash and the peer domain or "
            "IP its process connected to) and the installer origin (the tool's hash written on an endpoint "
            "from a domain or IP). Links within 120 minutes count; they shape the blast radius and the "
            "decision card, never the approval level."),
        link_kinds=(LinkKind.SAME_HASH, LinkKind.SAME_DOMAIN, LinkKind.SAME_IP, LinkKind.SAME_USER,
                    LinkKind.SAME_ENDPOINT, LinkKind.PROCESS_LINEAGE),
        window_minutes=120,
    ),
    scoring=ScoringInputs(
        description=(
            "The workflow never scores a tool by its name. Endpoint detections and malicious or suspicious "
            "process events of the tool dominate (endpoint_detection, weight 1.0); network records with a "
            "verdict count as network behaviour; Umbrella, Cisco XDR, VirusTotal and OTX answers are vendor "
            "reputation, capped by the engine, and one vendor alone is never an aggregate MALICIOUS verdict. "
            "A destination block cites the tool's flagging records with the contact records, so it scores "
            "on the same detection. Secure Endpoint and Umbrella are the expected sources: when one fails, "
            "confidence drops and the run notes it, but other evidence still produces the recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="terminate_rmm_process",
            description="Terminate a running process of a remote access tool that is flagged, or whose remote "
                        "session shows an untrusted operator",
            action=ActionType.TERMINATE_PROCESS,
            builder="terminate_process",
            for_each="[p for p in facts.running if p.flagged or p.untrusted_session]",
            target="item.target",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_FACT_ASSET,
            rationale="'remote access tool ' + item.tool + ' is running on ' + item.endpoint + ' (' + item.basis + ')'",
            min_risk=40,
            mitre=("T1219.002",),
        ),
        RecommendationRule(
            id="block_rmm_binary",
            description=f"Block the binary of a flagged remote access tool fleet-wide when it is seen on "
                        f"{MAX_FLEET_BLOCK_PREVALENCE} endpoints or fewer (or its prevalence is unknown)",
            action=ActionType.BLOCK_HASH,
            builder="block_hash",
            for_each="[t for t in facts.tools if t.flagged and t.sha256 and not t.widespread]",
            target="item.sha256",
            evidence="item.record_ids",
            rationale="'binary of remote access tool ' + item.name + ' (' + item.basis + '), seen on '"
                      " + item.prevalence_text + ' endpoint(s)'",
            min_risk=40,
            mitre=("T1219.002",),
        ),
        RecommendationRule(
            id="block_rmm_destination_domain",
            description="Block a relay or broker domain the sessions of a flagged remote access tool reach, or a "
                        "session or installer domain rated malicious or suspicious",
            action=ActionType.BLOCK_DOMAIN,
            for_each="[d for d in facts.destinations if d.type == 'domain']",
            when="item.rated or (item.session and item.flagged_tool and not item.widespread_tool)",
            target="item.value",
            evidence="item.record_ids",
            # an unrated relay is blocked only because its tool is flagged: when that tool is sanctioned
            # (approved hash or signer) the framework withholds the block (ALLOWLISTED, considered)
            binaries="[] if item.rated else item.flagged_tool_hashes",
            rationale=_DESTINATION_RATIONALE,
            min_risk=40,
            mitre=("T1219.002",),
        ),
        RecommendationRule(
            id="block_rmm_session_peer_ip",
            description="Block a public session peer IP of a remote access tool when the IP itself is rated "
                        "malicious or suspicious (vendor relays are shared and are not blocked by IP)",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="[d for d in facts.destinations if d.type == 'ip']",
            when="item.rated",
            target="item.value",
            evidence="item.record_ids",
            rationale=_DESTINATION_RATIONALE,
            min_risk=40,
            mitre=("T1219.002",),
        ),
        RecommendationRule(
            id="isolate_untrusted_session_secure_endpoint",
            description="Isolate (Secure Endpoint) an endpoint with an active remote session whose operator is "
                        "untrusted: the peer is rated malicious or suspicious, or a detection rates the tool "
                        "malicious; applies to sanctioned tools too",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="[s for s in facts.sessions if s.untrusted and s.isolation_capable != False]",
            when="item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_FACT_ASSET,
            params={"connector_guid": "item.connector_guid"},
            rationale=_SESSION_RATIONALE,
            min_risk=50,
            mitre=("T1219.002",),
        ),
        RecommendationRule(
            id="isolate_untrusted_session_defender_endpoint",
            description="Isolate (Defender for Endpoint) an endpoint with an active remote session whose operator "
                        "is untrusted (a duplicate of the Secure Endpoint proposal is merged)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="[s for s in facts.sessions if s.untrusted and s.isolation_capable != False]",
            when="item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_FACT_ASSET,
            rationale=_SESSION_RATIONALE,
            min_risk=50,
            mitre=("T1219.002",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0011", technique="T1219", technique_name="Remote Access Tools",
                     sub_technique="T1219.002", sub_technique_name="Remote Desktop Software",
                     rationale="The workflow responds to legitimate remote desktop and RMM software used as an "
                               "unsanctioned or hostile command and control channel: it terminates the tool, "
                               "blocks its binary and relay destinations and isolates an endpoint whose remote "
                               "session shows an untrusted operator."),
    ),
    known_limitations=(
        "Hooks and rule expressions cannot read allowlists.approved_rmm: the framework enforces it on the "
        "proposals (an approved tool's hashes and domains are excluded by the package builder; a file signed "
        "by an approved signer or an approved binary is withheld from hash blocks and process termination, and "
        "an unrated relay domain of such a tool is not blocked on the tool's flag alone). "
        "An approved_rmm entry that lists only a name protects nothing; list the tool's hashes, signers and "
        "domains.",
        "Isolation follows the session, not the tool: an endpoint with a session of a sanctioned tool is "
        "isolated when the peer is rated malicious or suspicious or a detection rates the tool malicious. "
        "Whether the remote operator is verified IT staff cannot be read (no RMM console API in "
        "docs/integrations.md); the analyst confirms it with the service desk before approving.",
        "With the real adapters, Secure Endpoint trajectory events and Defender timeline rows have no "
        "documented field schema (docs/integrations.md), so they stay generic records: citable, never "
        "scored. Execution, sessions, installer source and persistence facts come only from typed sources; "
        "until a schema is VERIFIED, termination, isolation and destination blocks are recommended only "
        "where typed records exist.",
        "Terminate process has no VERIFIED vendor endpoint, so with the real adapters it is reported "
        "UNROUTED for manual handling in the endpoint console; only the simulated lab executes it.",
        "Uninstalling the tool and removing its service or other persistence have no VERIFIED write: they "
        "are listed as manual steps, and persistence is handed off to the persistence workflow.",
        "Secure Endpoint hash blocking (file lists) and the isolation-state read are UNVERIFIED: hash blocks "
        "route to the Cisco XDR native action or Defender indicators, and Secure Endpoint isolation verifies "
        "as UNABLE_TO_VERIFY.",
        f"A tool seen on more than {MAX_FLEET_BLOCK_PREVALENCE} endpoints is not proposed for a fleet-wide "
        "hash or relay-domain block; it is listed as considered with its prevalence record and a human "
        "decides.",
        "Session peer IPs are blocked only when rated malicious or suspicious: RMM vendor relays are shared "
        "infrastructure, so an unrated relay is covered by the relay domain block instead.",
        "Tools are identified by known executable names, by detections that report T1219 or name remote "
        "access, and by remote-access DNS categories; a renamed binary of an unlisted product without such a "
        "detection is not identified.",
        "IPv6 session peers are not enriched or blocked by this workflow (IPv4 only).",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a "
        "withheld or failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("mail-bombing", "persistence", "account-takeover", "malware", "c2"),
    handoff_to=("persistence", "account-takeover"),
)
