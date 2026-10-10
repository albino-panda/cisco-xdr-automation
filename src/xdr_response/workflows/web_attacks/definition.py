"""Web application attacks workflow (Phase 5 add-on; replaces ``workflows/web-attacks/workflow.yaml``).

An internet-facing application is attacked: injection or exploit requests, vulnerability scanning,
or a web shell planted on the web server. The detection usually arrives as a Cisco XDR incident (a
WAF, IPS or EDR alert). The workflow investigates the web servers (detections, inbound requests,
the web worker's process and file activity), rates every external source that attacked them
(Cisco XDR, VirusTotal and OTX reputation, the security product's own verdict on the requests),
finds the other servers the same sources reached, and RECOMMENDS a containment package:

* block an attacking source IP that is rated (enrichment MALICIOUS or SUSPICIOUS, or a request the
  security product flagged MALICIOUS);
* block the targeted application URL that was exploited (a flagged or attacker request to it reached
  a server that shows a web shell or a successful exploit), with the edge virtual patch as a manual
  step;
* isolate a web server with a confirmed web shell (an active MALICIOUS web-shell detection).

Scanning or exploit attempts alone never isolate a server: isolation needs a confirmed web shell.
Like every workflow it only investigates and recommends: it never executes, never approves and
never chooses an approval level. ELEVATED comes from ``PackageBuilder`` (critical assets, blast-radius
caps); execution, verification and restoration happen only in the lifecycle orchestrator after human
approval.
"""
from __future__ import annotations

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
    "ATTACK_IDS",
    "AUTHORIZED_SCANNERS_KEY",
    "ENDPOINT_SOURCES",
    "EXPLOIT_TECHNIQUE",
    "HUNT_SOURCES",
    "ISOLATION_MIN_RISK",
    "SCANNING_TECHNIQUE",
    "SOURCE_MIN_RISK",
    "URL_MIN_RISK",
    "WEB_SHELL_KEYWORDS",
    "WEB_SHELL_TECHNIQUE",
]

WEB_SHELL_TECHNIQUE = "T1505.003"
EXPLOIT_TECHNIQUE = "T1190"
SCANNING_TECHNIQUE = "T1595.002"
#: ATT&CK ids of the workflow's technique triggers. ``T1190`` is mapped and answered (source and URL
#: blocks) but is not a trigger: an incident that reports it is routed to the vulnerability-exploitation
#: workflow (priority 135) unless it also reports a web shell (this workflow, priority 145).
ATTACK_IDS: tuple[str, ...] = (SCANNING_TECHNIQUE, WEB_SHELL_TECHNIQUE)

#: Words (lower case) in a detection's name or category that mark it as a web shell detection. A
#: detection confirms a web shell only when it is MALICIOUS, not resolved, and reports
#: :data:`WEB_SHELL_TECHNIQUE` or one of these words.
WEB_SHELL_KEYWORDS: tuple[str, ...] = ("web shell", "webshell", "web-shell")

#: ``incident.trigger`` key a detection source may use to list sanctioned external scanners (legacy
#: ``incident.context.authorized_scanners``). A listed source is never proposed for a block and is
#: shown as considered; the durable way is ``allowlists.never_block.ips`` (excluded visibly).
AUTHORIZED_SCANNERS_KEY = "authorized_scanners"

#: Minimum risk of a source block: the MEDIUM band lower bound (docs/threat-scoring.md section 2). A
#: scanning source rated SUSPICIOUS by vendor reputation alone (capped by the engine) still reaches it;
#: blocks are reversible and always need human approval, and the decision card shows the score.
SOURCE_MIN_RISK = 30

#: Minimum risk of the URL block: the MEDIUM band lower bound (it rests on a compromised server).
URL_MIN_RISK = 30

#: Minimum risk of an isolation: the HIGH band lower bound (an active MALICIOUS web-shell detection).
ISOLATION_MIN_RISK = 60

#: Endpoint sources the server steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")

#: Enterprise search sources for "which other servers did this source reach".
HUNT_SOURCES: tuple[str, ...] = ("cisco_xdr", "defender_endpoint", "microsoft_cloud", "splunk")

_SERVERS = "results.investigate_endpoint"
_CONNECTIONS = f"flatten([r.network_connections for r in {_SERVERS}])"
_DETECTIONS = f"flatten([r.detections for r in {_SERVERS}])"
_EVENTS = f"flatten([r.trajectory for r in {_SERVERS}])"
_SUSPECT = "['MALICIOUS', 'SUSPICIOUS']"

#: IPv4 sources of inbound requests to the investigated servers (incident IPs first; IPv6 not handled).
_SOURCE_SUBJECTS = (
    "distinct([i for i in get(incident.observables_by_type, 'ip', []) if ':' not in i]"
    f" + [c.remote_ip for c in {_CONNECTIONS} if c.remote_ip and ':' not in c.remote_ip"
    " and c.direction == 'inbound'])"
)
#: Sources worth a fleet-wide search: the incident's own and every rated one.
_SIGHTED_SOURCES = (
    "distinct([i for i in get(incident.observables_by_type, 'ip', []) if ':' not in i]"
    f" + [r.value for r in results.enrich_ip if r.verdict in {_SUSPECT}])"
)
#: Other servers the enterprise searches saw receiving requests from those sources.
_RELATED_SERVERS = "distinct(flatten([r.endpoints for r in results.search_ip_enterprise]))"
#: Hashes of web-shell and flagged detections and of flagged file or process events on the servers.
_HASH_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'sha256', [])"
    f" + [d.sha256 for d in {_DETECTIONS} if d.sha256 and d.verdict in {_SUSPECT}]"
    f" + [e.sha256 for e in {_EVENTS} if e.sha256 and e.verdict in {_SUSPECT}])"
)

_SERVER_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'users': item.users}"
_ISOLATE_RATIONALE = (
    "'web server ' + item.hostname + ' has a confirmed web shell (' + item.web_shell_basis + ')'"
    " + item.source_text + '; isolation contains it until the web root is reviewed and cleaned'"
)

WORKFLOW = WorkflowDefinition(
    id="web-attacks",
    version="2.0.0",
    name="Web application attacks",
    description=(
        "Handle injection, exploit, scanning or web shell activity against an internet-facing application: "
        "investigate the web servers' detections, inbound requests and process and file activity, rate every "
        "external source that attacked them, find the other servers the same sources reached, and recommend a "
        "containment package (block the rated attacking sources, block the exploited application URL with the "
        "edge virtual patch as a manual step, isolate a web server with a confirmed web shell) for human "
        "approval. Scanning alone never isolates a server."
    ),
    phase=5,
    default_severity=Severity.MEDIUM,
    legacy_id="web-attacks",
    triggers=(
        TriggerSpec(type="xdr_incident_rule", priority=145,
                    description="Cisco XDR incident whose detection reports a web shell (T1505.003)",
                    mitre_techniques=(WEB_SHELL_TECHNIQUE,)),
        TriggerSpec(type="xdr_incident_rule", priority=125,
                    description="Cisco XDR incident reporting vulnerability scanning (T1595.002) of an exposed "
                                "service by an external source",
                    mitre_techniques=(SCANNING_TECHNIQUE,),
                    observable_types=(ObservableType.IP, ObservableType.URL, ObservableType.HOSTNAME)),
        TriggerSpec(type="xdr_incident_rule", priority=120,
                    description="Cisco XDR incident titled as a web shell, a web injection attack, a web "
                                "vulnerability scan or a WAF alert that names a source IP, a URL or a web server",
                    title_patterns=("*web shell*", "*webshell*", "*sql injection*", "*command injection*",
                                    "*code injection*", "*cross-site scripting*", "*path traversal*",
                                    "*directory traversal*", "*file inclusion*", "*vulnerability scan*",
                                    "*web scan*", "*web application attack*", "*waf rule*", "*waf alert*",
                                    "*web application firewall*"),
                    observable_types=(ObservableType.IP, ObservableType.URL, ObservableType.HOSTNAME)),
        TriggerSpec(type="manual",
                    description="An analyst starts the workflow from an incident, a web server, a source IP or a "
                                "URL observable"),
    ),
    input_observables=(ObservableType.IP, ObservableType.URL, ObservableType.HOSTNAME, ObservableType.SHA256),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Web server detections (web shell, exploit), device trajectory (the web worker's process and "
                    "file activity, inbound requests) and the isolation of a web server with a confirmed web shell",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts of the attacking sources and of the web shell hash (WAF and IPS alerts "
                    "arrive here as incidents), enterprise sightings of the sources, and the native response "
                    "actions",
            atomics=("investigate_endpoint", "enrich_ip", "enrich_hash", "search_ip_enterprise")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second web server source (machine, alerts, timeline, enterprise search) and isolation or "
                    "indicator blocks for the servers it manages",
            atomics=("investigate_endpoint", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the attacking sources and of the web shell hash",
            atomics=("enrich_ip", "enrich_hash")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) of the attacking sources and of the web shell hash",
            atomics=("enrich_ip", "enrich_hash")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts and hunting rows: other servers that received requests from the sources",
            atomics=("search_ip_enterprise",)),
        IntegrationRequirement(
            integration="splunk",
            purpose="WAF, load balancer and web server logs of other servers the sources reached (optional, "
                    "disabled by default; rows stay citable generic records)",
            atomics=("search_ip_enterprise",)),
        IntegrationRequirement(
            integration="meraki",
            purpose="Landing product for approved blocks of an attacking source IP at the MX firewall",
            atomics=()),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Landing product for an approved block of the exploited URL (destination lists)",
            atomics=()),
    ),
    investigation=(
        InvestigationStep(id="web_server_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="source_reputation", atomic="enrich_ip", subjects=_SOURCE_SUBJECTS,
                          subject_type=ObservableType.IP, max_subjects=25),
        InvestigationStep(id="source_sightings", atomic="search_ip_enterprise", subjects=_SIGHTED_SOURCES,
                          subject_type=ObservableType.IP, integrations=HUNT_SOURCES, max_subjects=10),
        InvestigationStep(id="related_servers", atomic="investigate_endpoint", subjects=_RELATED_SERVERS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES, max_subjects=10),
        InvestigationStep(id="web_shell_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same IP, URL or hash on two or more servers (one source attacking a pool), the "
            "same server across sources, and process lineage on the server. Workflow links (hooks): an attack "
            "request (the source IP, the server it reached and the targeted URL) and a web shell (the server and "
            "the hash of the web shell file). Links within 24 hours count, because scans and exploitation are "
            "often hours apart; they shape the clusters, the blast radius and the decision card, never the "
            "approval level."),
        link_kinds=(LinkKind.SAME_IP, LinkKind.SAME_URL, LinkKind.SAME_HASH, LinkKind.SAME_ENDPOINT,
                    LinkKind.PROCESS_LINEAGE),
        window_minutes=1440,
    ),
    scoring=ScoringInputs(
        description=(
            "Web server detections (web shell, exploit) and malicious process or file events dominate "
            "(endpoint_detection, weight 1.0); inbound request records that carry the security product's verdict "
            "count as network behaviour; Cisco XDR, VirusTotal and OTX answers are vendor reputation, capped by "
            "the engine, and one vendor alone is never an aggregate MALICIOUS verdict. A source block cites the "
            "source's requests with its rating; a URL block cites the requests to the URL with the compromise "
            "records of the server they reached; an isolation cites the web shell detections with the server's "
            "flagged activity and the attack requests. Secure Endpoint and Cisco XDR are the expected sources: "
            "when one fails, confidence drops and the run notes it, but other evidence still produces the "
            "recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="block_attacking_source",
            description="Block an external source IPv4 address that attacked the application (the incident names "
                        "it or it sent requests to an investigated server) and is rated MALICIOUS or SUSPICIOUS by "
                        "enrichment or by the security product's verdict on its requests; never a source the "
                        "incident lists as an authorised scanner, never an address an investigated endpoint "
                        "reports as its own",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="facts.sources",
            when="item.rated and not item.authorized",  # an own address is never rated (hooks)
            target="item.ip",
            evidence="item.record_ids",
            rationale="'source ' + item.ip + ' attacked ' + item.server_list + ' (' + item.basis + ')'"
                      " + item.request_text",
            min_risk=SOURCE_MIN_RISK,
            mitre=(EXPLOIT_TECHNIQUE, SCANNING_TECHNIQUE),
        ),
        RecommendationRule(
            id="block_exploited_url",
            description="Block a targeted application URL that was exploited: a flagged request, or a request from "
                        "a rated source, reached a server that shows a confirmed web shell or a successful exploit "
                        "(a URL only the incident names is considered, never blocked); the WAF virtual patch is a "
                        "manual step",
            action=ActionType.BLOCK_URL,
            builder="block_url",
            for_each="facts.urls",
            when="item.exploited",
            target="item.url",
            evidence="item.record_ids",
            include_target_enrichment=False,
            rationale="'application URL ' + item.url + ' was exploited: ' + item.basis",
            min_risk=URL_MIN_RISK,
            mitre=(EXPLOIT_TECHNIQUE,),
        ),
        RecommendationRule(
            id="isolate_web_shell_server_secure_endpoint",
            description="Isolate (Secure Endpoint) a web server with a confirmed web shell (an active MALICIOUS "
                        "web-shell detection); scanning or exploit attempts alone never isolate",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="[s for s in facts.servers if s.isolate and s.isolation_capable != False]",
            when="item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_SERVER_ASSET,
            params={"connector_guid": "item.connector_guid"},
            rationale=_ISOLATE_RATIONALE,
            min_risk=ISOLATION_MIN_RISK,
            mitre=(WEB_SHELL_TECHNIQUE,),
        ),
        RecommendationRule(
            id="isolate_web_shell_server_defender_endpoint",
            description="Isolate (Defender for Endpoint) a web server with a confirmed web shell (a duplicate of "
                        "the Secure Endpoint proposal is merged)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="[s for s in facts.servers if s.isolate and s.isolation_capable != False]",
            when="item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_SERVER_ASSET,
            rationale=_ISOLATE_RATIONALE,
            min_risk=ISOLATION_MIN_RISK,
            mitre=(WEB_SHELL_TECHNIQUE,),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0001", technique="T1190", technique_name="Exploit Public-Facing Application",
                     rationale="The workflow responds to injection and exploit requests against an internet-facing "
                               "application: it blocks the rated attacking sources and the exploited URL, and puts "
                               "the edge virtual patch in front of the analyst as a manual step."),
        MitreMapping(tactic="TA0043", technique="T1595", technique_name="Active Scanning",
                     sub_technique="T1595.002", sub_technique_name="Vulnerability Scanning",
                     rationale="Vulnerability scanning by an external source is answered by blocking the source "
                               "when it is rated; scanning alone never isolates a server or blocks a URL."),
        MitreMapping(tactic="TA0003", technique="T1505", technique_name="Server Software Component",
                     sub_technique="T1505.003", sub_technique_name="Web Shell",
                     rationale="A confirmed web shell on a web server is answered by isolating the server, handing "
                               "the web shell file to the malware workflow and a manual review of the web root."),
    ),
    known_limitations=(
        "There is no WAF, CDN or load balancer integration with a VERIFIED write (the legacy Cloudflare edge is not "
        "a Phase 0 integration): the virtual patch of an exploited URL at the edge is a manual step, and WAF alerts "
        "arrive only as Cisco XDR incidents.",
        "An approved URL block lands on the DNS and web security layer (Umbrella destination lists, Defender "
        "indicators or the Cisco XDR native action): it stops the organisation's own users and managed endpoints "
        "from reaching the path, not internet traffic to the application; an IP block lands on the Meraki MX, "
        "Defender indicators or the native action, so filtering in front of the application stays with the edge "
        "team by hand.",
        "With the real adapters, Secure Endpoint trajectory events, Defender timeline and hunting rows, Cisco XDR "
        "sightings and Splunk WAF rows have no documented field schema, so they stay generic records: citable, "
        "never scored. Inbound requests and their verdicts come only from typed sources; until a schema is "
        "VERIFIED, a source block rests on enrichment and an exploited URL on the incident naming both the URL and "
        "the compromised server.",
        "Vulnerability state (a known-vulnerable endpoint with a pending fix) has no VERIFIED source; the legacy "
        "incident context fields targeted_endpoints, vulnerable and fix_pending are not evidence, so a URL is "
        "blocked only on records that show it was exploited.",
        "Sanctioned external scanners are recognised from allowlists.never_block.ips (excluded visibly) or from "
        "trigger.authorized_scanners set by the detection source (shown as considered); an unlisted scanner rated "
        "SUSPICIOUS is proposed for a block and the analyst can deselect it.",
        "Isolation needs an active MALICIOUS web-shell detection (technique T1505.003 or a web-shell name or "
        "category); a resolved or SUSPICIOUS web-shell detection, or an exploit without a web shell, is shown as "
        "considered and the analyst can isolate by hand.",
        "A web server whose agent policy forbids isolation, or that neither Secure Endpoint nor Defender manages "
        "(an appliance), is a manual step: take it out of the load-balancer pool by hand.",
        "Removing the web shell, reviewing the web root and rotating the application's credentials are manual "
        "steps (no VERIFIED write); the web shell hash is handed off to the malware workflow for scoping, "
        "quarantine and a hash block.",
        "Secure Endpoint's isolation-state read is UNVERIFIED, so a Secure Endpoint isolation verifies as "
        "UNABLE_TO_VERIFY; Defender machine actions are read back.",
        "IPv6 sources are not enriched or blocked by this workflow (IPv4 only).",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a withheld or "
        "failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("malware", "vulnerability-exploitation", "persistence"),
    handoff_to=("malware",),
)
