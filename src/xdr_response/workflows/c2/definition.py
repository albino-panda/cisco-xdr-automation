"""Command and control workflow (Phase 4; replaces ``workflows/c2/workflow.yaml``).

An endpoint talks to attacker infrastructure: a known command-and-control (C2) domain or IP, a
periodic beacon, a suspicious external connection or a malicious DNS lookup. The detection usually
arrives as a Cisco XDR incident (Secure Cloud Analytics, Umbrella, Secure Endpoint or Defender
alerts). The workflow investigates the endpoints (detections, connections, DNS queries, the process
behind the connection), rates every external destination they reached (Umbrella categorisation,
Cisco XDR, VirusTotal and OTX reputation, the security product's own verdict on the contact), finds
the other endpoints that talk to the same infrastructure, and RECOMMENDS a containment package:

* block the C2 domain, IP and URL (a shared hosting or CDN address is never blocked by IP);
* isolate an endpoint that reached a malicious destination and shows malicious activity itself;
* terminate the flagged process that still holds the C2 connection.

The workflow never rates a destination by its traffic pattern alone: a periodic beacon to an unrated
destination is shown as considered, never blocked, because update agents and SaaS heartbeats beacon
too. Like every workflow it only investigates and recommends: it never executes, never approves and
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
    "C2_CATEGORY_KEYWORDS",
    "DESTINATION_MIN_RISK",
    "ENDPOINT_SOURCES",
    "HUNT_SOURCES",
    "MIN_BEACON_CONTACTS",
    "SHARED_INFRASTRUCTURE_KEY",
]

#: ATT&CK ids the automatic trigger matches (each is mapped below; a parent technique is not listed
#: so that, for example, ``T1071.004`` DNS tunnelling stays with the dns-tunneling workflow).
ATTACK_IDS: tuple[str, ...] = ("T1071.001", "T1573", "T1568.002")

#: Vendor or DNS categories (lower case) that mark a destination as command-and-control
#: infrastructure. ``c2`` is matched as a whole word. A SUSPICIOUS destination is blocked only with
#: such a category (newly seen or DGA-looking domains are SUSPICIOUS without one and stay considered).
C2_CATEGORY_KEYWORDS: tuple[str, ...] = ("command and control", "command & control", "command-and-control",
                                         "c2", "botnet")

#: A destination contacted at least this many times by one endpoint (one connection record's
#: ``count``, or the sum over its records) is reported as beacon-like. Context only: periodicity never
#: rates a destination, it only makes an unrated destination visible as considered.
MIN_BEACON_CONTACTS = 5

#: ``incident.trigger`` key a detection source may use to list shared hosting or CDN addresses
#: (legacy ``incident.context.shared_infrastructure_ips``). Such an IP is never proposed for a block.
SHARED_INFRASTRUCTURE_KEY = "shared_infrastructure_ips"

#: Minimum risk of a destination block: the MEDIUM band lower bound (docs/threat-scoring.md section 2).
#: A rated destination with vendor reputation only (capped by the engine) still reaches it; blocks are
#: reversible and always need human approval.
DESTINATION_MIN_RISK = 30

#: Endpoint sources the endpoint steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")

#: Enterprise search sources for "which other endpoints talk to this destination".
HUNT_SOURCES: tuple[str, ...] = ("cisco_xdr", "defender_endpoint", "microsoft_cloud", "splunk")

_ENDPOINTS = "results.investigate_endpoint"
_CONNECTIONS = f"flatten([r.network_connections for r in {_ENDPOINTS}])"
_DNS = f"flatten([r.dns_queries for r in {_ENDPOINTS}])"
_EVENTS = f"flatten([r.trajectory for r in {_ENDPOINTS}])"
_DETECTIONS = f"flatten([r.detections for r in {_ENDPOINTS}])"
_OUTWARD = "['inbound', 'internal']"
_SUSPECT = "['MALICIOUS', 'SUSPICIOUS']"

#: Domains the investigated endpoints reached (incident domains first).
_DOMAIN_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'domain', [])"
    f" + [c.domain for c in {_CONNECTIONS} if c.domain and c.direction not in {_OUTWARD}]"
    f" + [q.domain for q in {_DNS} if q.domain]"
    f" + [e.domain for e in {_EVENTS} if e.domain])"
)
#: IPv4 addresses the investigated endpoints connected to (incident IPs first; IPv6 is not handled).
_IP_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'ip', [])"
    f" + [c.remote_ip for c in {_CONNECTIONS} if c.remote_ip and ':' not in c.remote_ip"
    f" and c.direction not in {_OUTWARD}]"
    f" + [e.remote_ip for e in {_EVENTS} if e.remote_ip and ':' not in e.remote_ip])"
)
_URL_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'url', [])"
    f" + [c.url for c in {_CONNECTIONS} if c.url and c.direction not in {_OUTWARD}])"
)
#: Destinations worth a fleet-wide search: the incident's own and every rated one.
_SIGHTED_DOMAINS = (
    "distinct(get(incident.observables_by_type, 'domain', [])"
    f" + [r.value for r in results.enrich_domain if r.verdict in {_SUSPECT}])"
)
_SIGHTED_IPS = (
    "distinct([i for i in get(incident.observables_by_type, 'ip', []) if ':' not in i]"
    f" + [r.value for r in results.enrich_ip if r.verdict in {_SUSPECT}])"
)
#: Other endpoints the enterprise searches saw talking to those destinations.
_RELATED_ENDPOINTS = (
    "distinct(flatten([r.endpoints for r in results.search_domain_enterprise])"
    " + flatten([r.endpoints for r in results.search_ip_enterprise]))"
)
#: Hashes of the processes behind the connections and of the endpoint detections.
_HASH_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'sha256', [])"
    f" + [c.sha256 for c in {_CONNECTIONS} if c.sha256]"
    f" + [d.sha256 for d in {_DETECTIONS} if d.sha256 and d.verdict in {_SUSPECT}])"
)

_HOST_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'users': item.users}"
_ISOLATE_RATIONALE = (
    "'endpoint ' + item.hostname + ' reached command-and-control infrastructure ' + item.destination_list"
    " + ' and shows malicious activity itself (' + item.basis + ')'"
)
_DESTINATION_RATIONALE = (
    "item.type + ' ' + item.value + ' is command-and-control infrastructure (' + item.basis + '); contacted by '"
    " + item.endpoint_list + item.beacon_text"
)

WORKFLOW = WorkflowDefinition(
    id="c2",
    version="2.0.0",
    name="Command and control",
    description=(
        "Handle an endpoint that talks to attacker infrastructure (known command-and-control domain or IP, "
        "periodic beaconing, a suspicious external connection or a malicious DNS lookup): investigate the "
        "endpoint's detections, connections, DNS queries and the process behind the connection, rate every "
        "external destination it reached, find the other endpoints that talk to the same infrastructure, and "
        "recommend a containment package (block the C2 domain, IP and URL, isolate the endpoints that show "
        "malicious activity, terminate the flagged beaconing process) for human approval."
    ),
    phase=4,
    default_severity=Severity.HIGH,
    legacy_id="c2",
    triggers=(
        TriggerSpec(type="xdr_incident_rule", priority=115,
                    description="Cisco XDR incident whose detection reports web-protocol C2 (T1071.001), an "
                                "encrypted channel (T1573) or domain generation algorithms (T1568.002)",
                    mitre_techniques=ATTACK_IDS),
        TriggerSpec(type="xdr_incident_rule", priority=105,
                    description="Cisco XDR incident titled as beaconing or command-and-control traffic that names "
                                "an endpoint, a domain or an IP",
                    title_patterns=("*beacon*", "*command and control*", "*command-and-control*", "*c2 traffic*",
                                    "*c2 communication*", "*c2 callback*", "*c2 server*", "*c2 domain*",
                                    "*c2 channel*"),
                    observable_types=(ObservableType.HOSTNAME, ObservableType.DOMAIN, ObservableType.IP)),
        TriggerSpec(type="xdr_incident_rule", priority=95,
                    description="Secure Cloud Analytics or Umbrella alert (read as a Cisco XDR incident) about a "
                                "suspicious external connection or a malicious DNS lookup",
                    sources=("secure_cloud_analytics", "Secure Cloud Analytics", "umbrella", "Cisco Umbrella"),
                    title_patterns=("*suspicious external*", "*new external connection*", "*malicious dns*",
                                    "*malicious domain*", "*known malicious*", "*watchlist*", "*threat feed*"),
                    observable_types=(ObservableType.DOMAIN, ObservableType.IP)),
        TriggerSpec(type="manual",
                    description="An analyst starts the workflow from an incident, an endpoint or a destination "
                                "observable"),
    ),
    input_observables=(ObservableType.HOSTNAME, ObservableType.DOMAIN, ObservableType.IP, ObservableType.URL,
                       ObservableType.SHA256),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint detections, device trajectory (connections, DNS lookups, the process behind the "
                    "connection) and the isolation of the endpoint",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain status and security categories (Command and Control, Malware) of the destinations, "
                    "and the landing product for approved domain and URL blocks",
            atomics=("enrich_domain",)),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, alerts, timeline, enterprise search) and isolation or "
                    "indicator blocks for the endpoints it manages",
            atomics=("investigate_endpoint", "search_domain_enterprise", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings of the destinations and hashes (Secure Cloud Analytics "
                    "alerts arrive here as incidents), and the native response actions",
            atomics=("investigate_endpoint", "search_domain_enterprise", "search_ip_enterprise", "enrich_domain",
                     "enrich_ip", "enrich_url", "enrich_hash")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the destinations and of the beaconing process's hash",
            atomics=("enrich_domain", "enrich_ip", "enrich_url", "enrich_hash")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) for the destinations and the beaconing hash",
            atomics=("enrich_domain", "enrich_ip", "enrich_url", "enrich_hash")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts and hunting rows: other endpoints that resolved or connected to the "
                    "destinations",
            atomics=("search_domain_enterprise", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="splunk",
            purpose="Proxy, firewall and DNS logs of other endpoints that reached the destinations (optional, "
                    "disabled by default; rows stay citable generic records)",
            atomics=("search_domain_enterprise", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="meraki",
            purpose="Landing product for approved blocks of a C2 IP at the MX firewall",
            atomics=()),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="domain_reputation", atomic="enrich_domain", subjects=_DOMAIN_SUBJECTS,
                          max_subjects=15),
        InvestigationStep(id="ip_reputation", atomic="enrich_ip", subjects=_IP_SUBJECTS,
                          subject_type=ObservableType.IP, max_subjects=15),
        InvestigationStep(id="url_reputation", atomic="enrich_url", subjects=_URL_SUBJECTS, max_subjects=10),
        InvestigationStep(id="domain_sightings", atomic="search_domain_enterprise", subjects=_SIGHTED_DOMAINS,
                          integrations=HUNT_SOURCES, max_subjects=10),
        InvestigationStep(id="ip_sightings", atomic="search_ip_enterprise", subjects=_SIGHTED_IPS,
                          subject_type=ObservableType.IP, integrations=HUNT_SOURCES, max_subjects=10),
        InvestigationStep(id="related_endpoints", atomic="investigate_endpoint", subjects=_RELATED_ENDPOINTS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="beacon_process_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same domain, IP, URL or hash on two or more endpoints (one C2 server, many "
            "beaconing hosts), the same endpoint across sources, and process lineage. Workflow links (hooks): "
            "a beacon (an endpoint, the destination it reached and, when known, the hash of the process behind "
            "the connection) and a DNS resolution (a domain and the external IPs it resolved to). Links within "
            "24 hours count, because beacons are long-lived; they shape the clusters, the blast radius and the "
            "decision card, never the approval level."),
        link_kinds=(LinkKind.SAME_DOMAIN, LinkKind.SAME_IP, LinkKind.SAME_URL, LinkKind.SAME_HASH,
                    LinkKind.SAME_ENDPOINT, LinkKind.PROCESS_LINEAGE),
        window_minutes=1440,
    ),
    scoring=ScoringInputs(
        description=(
            "The workflow never rates a destination by its traffic pattern: periodicity is context only. "
            "Endpoint detections and malicious process events dominate (endpoint_detection, weight 1.0); "
            "connection and DNS records that carry the security product's verdict count as network behaviour; "
            "Umbrella, Cisco XDR, VirusTotal and OTX answers are vendor reputation, capped by the engine, and "
            "one vendor alone is never an aggregate MALICIOUS verdict. A destination block cites the contact "
            "records with the destination's rating; an isolation cites the endpoint's own detections and "
            "processes with the C2 contact. Secure Endpoint and Umbrella are the expected sources: when one "
            "fails, confidence drops and the run notes it, but other evidence still produces the "
            "recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="block_c2_domain",
            description="Block a domain an investigated endpoint reached (or the incident names) that is rated "
                        "MALICIOUS, or SUSPICIOUS with a command-and-control category",
            action=ActionType.BLOCK_DOMAIN,
            for_each="[d for d in facts.destinations if d.type == 'domain']",
            when="item.rated",
            target="item.value",
            evidence="item.record_ids",
            rationale=_DESTINATION_RATIONALE,
            min_risk=DESTINATION_MIN_RISK,
            mitre=("T1071.001", "T1568.002"),
        ),
        RecommendationRule(
            id="block_c2_ip",
            description="Block a C2 IPv4 address that is rated MALICIOUS (or SUSPICIOUS with a command-and-control "
                        "category) and is not shared hosting or CDN infrastructure",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="[d for d in facts.destinations if d.type == 'ip']",
            when="item.rated and not item.shared",
            target="item.value",
            evidence="item.record_ids",
            rationale=_DESTINATION_RATIONALE,
            min_risk=DESTINATION_MIN_RISK,
            mitre=("T1071.001", "T1573"),
        ),
        RecommendationRule(
            id="block_c2_url",
            description="Block a C2 URL an investigated endpoint reached (or the incident names) that is rated "
                        "MALICIOUS, or SUSPICIOUS with a command-and-control category",
            action=ActionType.BLOCK_URL,
            builder="block_url",
            for_each="[d for d in facts.destinations if d.type == 'url']",
            when="item.rated",
            target="item.value",
            evidence="item.record_ids",
            rationale=_DESTINATION_RATIONALE,
            min_risk=DESTINATION_MIN_RISK,
            mitre=("T1071.001",),
        ),
        RecommendationRule(
            id="isolate_beaconing_endpoint_secure_endpoint",
            description="Isolate (Secure Endpoint) an endpoint that reached a MALICIOUS command-and-control "
                        "destination and shows malicious activity itself (an active malicious detection, or a "
                        "malicious process)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="[h for h in facts.hosts if h.isolate and h.isolation_capable != False]",
            when="item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            binaries="item.binaries",
            params={"connector_guid": "item.connector_guid"},
            rationale=_ISOLATE_RATIONALE,
            min_risk=60,
            mitre=("T1071.001", "T1573"),
        ),
        RecommendationRule(
            id="isolate_beaconing_endpoint_defender_endpoint",
            description="Isolate (Defender for Endpoint) an endpoint that reached a MALICIOUS command-and-control "
                        "destination and shows malicious activity itself (a duplicate of the Secure Endpoint "
                        "proposal is merged)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="[h for h in facts.hosts if h.isolate and h.isolation_capable != False]",
            when="item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            binaries="item.binaries",
            rationale=_ISOLATE_RATIONALE,
            min_risk=60,
            mitre=("T1071.001", "T1573"),
        ),
        RecommendationRule(
            id="terminate_beaconing_process",
            description="Terminate a flagged process (detection, malicious process event or malicious hash) that "
                        "holds a connection to a rated command-and-control destination and has not ended",
            action=ActionType.TERMINATE_PROCESS,
            builder="terminate_process",
            for_each="facts.processes",
            target="item.target",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_HOST_ASSET,
            rationale="'process ' + item.process_name + ' on ' + item.endpoint + ' holds a connection to '"
                      " + item.destination_list + ' (' + item.basis + ')'",
            min_risk=50,
            mitre=("T1071.001", "T1573"),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0011", technique="T1071", technique_name="Application Layer Protocol",
                     sub_technique="T1071.001", sub_technique_name="Web Protocols",
                     rationale="The workflow responds to beaconing and C2 traffic over HTTP(S): it blocks the C2 "
                               "domain, IP and URL, isolates the endpoints that show malicious activity and "
                               "terminates the beaconing process."),
        MitreMapping(tactic="TA0011", technique="T1573", technique_name="Encrypted Channel",
                     rationale="An encrypted C2 channel hides its content, so the workflow acts on the endpoints "
                               "and destinations of the channel: it blocks the C2 IP and isolates the endpoint "
                               "and terminates the process that holds the connection."),
        MitreMapping(tactic="TA0011", technique="T1568", technique_name="Dynamic Resolution",
                     sub_technique="T1568.002", sub_technique_name="Domain Generation Algorithms",
                     rationale="Algorithm-generated domains are often only SUSPICIOUS: the workflow blocks one "
                               "when a source categorises it as command and control, and shows the others as "
                               "considered for a human decision."),
    ),
    known_limitations=(
        "Secure Cloud Analytics has no VERIFIED API (docs/integrations.md section 2.5): its alerts are read only "
        "as Cisco XDR incidents and sightings, and its observations are not queried directly.",
        "With the real adapters, Secure Endpoint trajectory events, Defender timeline and hunting rows, Cisco "
        "XDR sightings and Splunk rows have no documented field schema, so they stay generic records: citable, "
        "never scored. Contacts, the process behind a connection and beacon counts come only from typed "
        "sources; until a schema is VERIFIED, an isolation rests on the endpoint detection and on the incident "
        "naming both the endpoint and the rated destination.",
        "Umbrella security scores, risk scores and DNS activity reports are UNVERIFIED: only the VERIFIED "
        "domain status and categorisation is read. Direct Umbrella IP blocking is UNVERIFIED (conflict in the "
        "vendor pages), so IP blocks land on the Cisco XDR native action, Meraki or Defender indicators.",
        "Terminate process has no VERIFIED vendor endpoint, so with the real adapters it is reported UNROUTED "
        "for manual handling in the endpoint console; only the simulated lab executes it.",
        "Secure Endpoint's isolation-state read is UNVERIFIED, so a Secure Endpoint isolation verifies as "
        "UNABLE_TO_VERIFY; Defender machine actions are read back.",
        "Beaconing is measured from connection counts and first and last seen times (a mean interval), not "
        "from per-connection timestamps; it is context only and never rates a destination, so a beacon to an "
        "unrated destination is shown as considered and a human decides.",
        "Shared hosting and CDN addresses are recognised only when a run record (a DNS answer, or a connection "
        "record naming the domain with the address) shows the address also serving a domain rated CLEAN, or "
        "when the incident source lists it in trigger.shared_infrastructure_ips; an "
        "unrecognised shared address rated MALICIOUS is proposed and the analyst can deselect it.",
        "An endpoint that reached a C2 destination without any malicious detection or process of its own is "
        "not isolated (shown as considered): the destination blocks cut the channel, and the analyst can "
        "isolate it by hand.",
        "An endpoint whose only malicious activity is a hash rating of the process on the C2 connection, where "
        "that binary is sanctioned (allowlists approved tool hash or signer, never_block.hashes), is not "
        "isolated (shown as considered, like the process termination); an active detection or a malicious "
        "process event on the endpoint still stands on its own.",
        "An endpoint whose agent policy forbids isolation, or that neither Secure Endpoint nor Defender manages "
        "(an appliance or kiosk), is listed as a manual step: contain it on the network by hand.",
        "IPv6 destinations are not enriched or blocked by this workflow (IPv4 only); DNS tunnelling "
        "(T1071.004) is handled by the dns-tunneling workflow.",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a "
        "withheld or failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("malware", "dns-tunneling", "exfiltration", "unauthorized-rmm"),
    handoff_to=("malware",),
)
