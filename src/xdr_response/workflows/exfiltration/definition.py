"""Data exfiltration workflow (Phase 4; replaces ``workflows/exfiltration/workflow.yaml``).

An outbound transfer looks like data theft: an unusual upload volume, a new or unrated external
destination, unusual cloud storage, abnormal DNS, an unusual session of the account that drives it,
or a large transfer reported by an endpoint or network source. The workflow investigates the source
endpoint (detections, staging, outbound connections with their volumes, DNS), every destination
(reputation and categories, and how many endpoints of the estate reach it), and the accounts that
drive the transfer (identity risk, sign-ins, anomalies, insider-risk detections). It correlates user,
endpoint, process, destination, volume and authentication, and RECOMMENDS a containment package:

* block the destination domains and public IPs that receive the data;
* isolate a source endpoint while its transfer is still running and shows exfiltration evidence;
* revoke the sessions of, and disable, an account that drives the transfer and is compromised or
  flagged as an insider risk.

Clean, shared (seen from more than :data:`MAX_DESTINATION_ENDPOINTS` endpoints) and internal
destinations are never proposed for a block; they are listed as considered with their records.
Sanctioned services belong in ``allowlists.never_block``: the package builder moves their blocks to
the excluded targets (shown, never executed).

Like every workflow it only investigates and recommends: it never executes, never approves and never
chooses an approval level. ELEVATED comes from ``PackageBuilder`` (critical assets, blast-radius
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
    "ABNORMAL_DNS_LABEL_LENGTH",
    "ABNORMAL_DNS_SUBDOMAINS",
    "CLOUD_STORAGE_CATEGORIES",
    "ENDPOINT_SOURCES",
    "EXFIL_KEYWORDS",
    "EXFIL_TECHNIQUES",
    "HUNT_SOURCES",
    "INSIDER_KEYWORDS",
    "LARGE_TRANSFER_BYTES",
    "MAX_DESTINATION_ENDPOINTS",
    "NEW_DESTINATION_CATEGORIES",
    "NEW_DESTINATION_DAYS",
    "ONGOING_MINUTES",
]

#: Outbound volume (bytes, summed per source endpoint and destination) that counts as a large transfer.
LARGE_TRANSFER_BYTES = 100 * 1024 * 1024

#: A transfer whose last record is at most this many minutes before the incident was created (or
#: later) is still running. Only a running transfer justifies isolating its source endpoint.
ONGOING_MINUTES = 30

#: A destination reached from more endpoints of the estate than this is shared infrastructure (a CDN,
#: a cloud front door, a popular service): it is not proposed for a block; a human decides.
MAX_DESTINATION_ENDPOINTS = 3

#: A destination whose reputation source first saw it at most this many days before the incident is new.
NEW_DESTINATION_DAYS = 30

#: DNS query records with at least this many distinct child labels, or a label at least this long,
#: are abnormal DNS (data carried in queries); the queried domain becomes a destination of the transfer.
ABNORMAL_DNS_SUBDOMAINS = 50
ABNORMAL_DNS_LABEL_LENGTH = 40

#: Vendor or DNS categories (lower-case substrings) that mark a destination as cloud or file storage.
CLOUD_STORAGE_CATEGORIES: tuple[str, ...] = ("online storage", "file storage", "cloud storage", "file sharing",
                                             "file transfer")

#: Vendor or DNS categories (lower-case substrings) that mark a destination as newly seen.
NEW_DESTINATION_CATEGORIES: tuple[str, ...] = ("newly seen", "newly registered")

#: ATT&CK Exfiltration (TA0010) techniques: a detection that reports one (or a sub-technique) is an
#: exfiltration detection. Reported by the vendor, never inferred.
EXFIL_TECHNIQUES: tuple[str, ...] = ("T1011", "T1020", "T1029", "T1030", "T1041", "T1048", "T1052", "T1537",
                                     "T1567")

#: Words in a detection name or category (lower case) that name data exfiltration or data loss.
EXFIL_KEYWORDS: tuple[str, ...] = ("exfil", "data loss", "dataloss", "dlp", "data theft", "data leak",
                                   "large upload", "upload volume", "outbound volume")

#: Words in a detection name or category (lower case) that name an insider-risk alert; such a detection
#: names the account it is about (``DetectionRecord.user``).
INSIDER_KEYWORDS: tuple[str, ...] = ("insider",)

#: Endpoint sources of the endpoint triage (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr", "microsoft_cloud")

#: Enterprise search sources: how many endpoints of the estate reach a destination.
HUNT_SOURCES: tuple[str, ...] = ("cisco_xdr", "defender_endpoint", "microsoft_cloud", "splunk")

_ENDPOINTS = "results.investigate_endpoint"
_CONNECTIONS = f"flatten([r.network_connections for r in {_ENDPOINTS}])"
_DNS = f"flatten([r.dns_queries for r in {_ENDPOINTS}])"
_DETECTIONS = f"flatten([r.detections for r in {_ENDPOINTS}])"

#: Incident domains, domains of outbound connections and domains of abnormal DNS queries.
_DOMAIN_SUBJECTS = (
    "get(incident.observables_by_type, 'domain', [])"
    f" + [c.domain for c in {_CONNECTIONS} if c.domain and c.direction != 'internal']"
    f" + [q.domain for q in {_DNS} if q.domain and ((q.unique_subdomains != None"
    f" and q.unique_subdomains >= {ABNORMAL_DNS_SUBDOMAINS}) or (q.max_label_length != None"
    f" and q.max_label_length >= {ABNORMAL_DNS_LABEL_LENGTH}))]"
)
#: Incident IPv4 addresses and remote IPs of outbound (not internal) connections.
_IP_SUBJECTS = (
    "get(incident.observables_by_type, 'ip', [])"
    f" + [c.remote_ip for c in {_CONNECTIONS} if c.remote_ip and c.direction != 'internal']"
)
#: Incident users, users of the triaged endpoints and of their connections and detections.
_USER_SUBJECTS = (
    "get(incident.observables_by_type, 'user', []) + incident.users"
    f" + flatten([r.users for r in {_ENDPOINTS}])"
    f" + [c.user for c in {_CONNECTIONS} if c.user]"
    f" + [d.user for d in {_DETECTIONS} if d.user]"
)

_SOURCE_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'ips': item.ips, 'users': item.users}"
_ACTOR_ASSET = "{'groups': item.groups, 'roles': item.roles, 'privileged': item.privileged}"
_DESTINATION_RATIONALE = "'exfiltration destination ' + item.value + ' (' + item.basis + ')'"
_SOURCE_RATIONALE = (
    "'ongoing transfer from ' + item.hostname + ' to ' + item.destination_list + ' (' + item.volume_text"
    " + '); exfiltration evidence: ' + item.basis"
)
_ALL_TECHNIQUES = ("T1041", "T1048", "T1567.002")

WORKFLOW = WorkflowDefinition(
    id="exfiltration",
    version="2.0.0",
    name="Data exfiltration",
    description=(
        "Stop large or unusual outbound transfers and preserve evidence for impact assessment: investigate "
        "the source endpoint (detections, staging, outbound connections and their volumes, DNS), every "
        "destination (reputation, categories such as cloud storage, how new it is and how many endpoints of "
        "the estate reach it) and the accounts that drive the transfer (identity risk, sign-ins, anomalies, "
        "insider-risk detections); correlate user, endpoint, process, destination, volume and "
        "authentication; and recommend a containment package (block the destination, isolate a source "
        "endpoint whose transfer is still running, revoke the sessions of and disable a compromised or "
        "insider account) for human approval. Clean, shared and internal destinations are never proposed "
        "for a block."
    ),
    phase=4,
    default_severity=Severity.CRITICAL,
    legacy_id="exfiltration",
    triggers=(
        TriggerSpec(type="xdr_incident_rule", priority=150,
                    description="Cisco XDR incident whose detection reports an exfiltration technique of the MITRE "
                                "mapping (a reported sub-technique matches its parent)",
                    mitre_techniques=("T1041", "T1048", "T1567")),
        TriggerSpec(type="xdr_incident_rule", priority=140,
                    description="Cisco XDR incident titled as data exfiltration, a large or unusual upload or an "
                                "outbound volume anomaly that names an endpoint, a user, a domain or an IP",
                    title_patterns=("*exfiltration*", "*exfil *", "*data theft*", "*data loss*",
                                    "*large outbound transfer*", "*large upload*", "*unusual upload*",
                                    "*outbound volume anomaly*", "*upload to unsanctioned*",
                                    "*upload to personal cloud*", "*data staged and sent*"),
                    observable_types=(ObservableType.HOSTNAME, ObservableType.USER, ObservableType.DOMAIN,
                                      ObservableType.IP)),
        TriggerSpec(type="manual",
                    description="An analyst starts the workflow from an incident, an endpoint, a user or a "
                                "destination observable"),
    ),
    input_observables=(ObservableType.HOSTNAME, ObservableType.USER, ObservableType.DOMAIN, ObservableType.IP),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint detections, staging events, outbound connections with their volumes and DNS of "
                    "the source endpoint, and the isolation of the endpoint",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Status and categories (cloud storage, newly seen) of the destination domains, and the "
                    "landing product for approved domain blocks",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="entra",
            purpose="Profile, risk state, sign-ins and anomalies of the accounts that drive the transfer, and "
                    "the session revocation and account disable",
            atomics=("investigate_user",)),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, alerts, timeline, connections) and isolation or IP and "
                    "domain indicators for the endpoints it manages",
            atomics=("investigate_endpoint", "search_domain_enterprise", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings for the destinations, and the native response actions "
                    "the router prefers when configured",
            atomics=("investigate_endpoint", "enrich_domain", "enrich_ip", "search_domain_enterprise",
                     "search_ip_enterprise")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts of the source endpoint (including data-loss and insider-risk alerts) and "
                    "advanced hunting across the estate: which other endpoints reach a destination",
            atomics=("investigate_endpoint", "search_domain_enterprise", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="splunk",
            purpose="Enterprise search of proxy, firewall and DNS logs for the destinations (optional, disabled "
                    "by default)",
            atomics=("search_domain_enterprise", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the public destination domains and IPs",
            atomics=("enrich_domain", "enrich_ip")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) for the destination domains and IPs",
            atomics=("enrich_domain", "enrich_ip")),
        IntegrationRequirement(
            integration="meraki",
            purpose="Landing product for approved blocks of a destination IP at the MX firewall",
            atomics=()),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="destination_domains", atomic="enrich_domain", subjects=_DOMAIN_SUBJECTS,
                          max_subjects=15),
        InvestigationStep(id="destination_ips", atomic="enrich_ip", subjects=_IP_SUBJECTS,
                          subject_type=ObservableType.IP, max_subjects=15),
        InvestigationStep(id="destination_reach_domains", atomic="search_domain_enterprise",
                          subjects=_DOMAIN_SUBJECTS, integrations=HUNT_SOURCES, max_subjects=10),
        InvestigationStep(id="destination_reach_ips", atomic="search_ip_enterprise", subjects=_IP_SUBJECTS,
                          subject_type=ObservableType.IP, integrations=HUNT_SOURCES, max_subjects=10),
        InvestigationStep(id="transfer_actors", atomic="investigate_user", subjects=_USER_SUBJECTS,
                          subject_type=ObservableType.USER, integrations=("entra",), max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same domain or IP reached from two or more endpoints or users, the same "
            "user on several endpoints and the same endpoint used by several users. Workflow links (hooks): "
            "each transfer (the source endpoint, the account and the destination domain or IP its connection "
            "record names) and staging (an archive written on the source endpoint before a transfer from it "
            "within the window). Links within 180 minutes count; they shape the blast radius and the decision "
            "card, never the approval level."),
        link_kinds=(LinkKind.SAME_DOMAIN, LinkKind.SAME_IP, LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT),
        window_minutes=180,
    ),
    scoring=ScoringInputs(
        description=(
            "Endpoint detections (an exfiltration, data-loss or insider-risk detection, or any malicious "
            "detection on the source) dominate (endpoint_detection, weight 1.0). Network records with a "
            "verdict count as network behaviour; the transfer pattern itself (a large or abnormal upload to "
            "a destination that is not rated clean, or a running transfer from the source) is a workflow "
            "signal of the source that reported the connection records, citing them. Identity risk and "
            "anomalies count as authentication anomalies. Umbrella, Cisco XDR, VirusTotal and OTX answers are "
            "vendor reputation, capped by the engine: one vendor alone is never an aggregate MALICIOUS "
            "verdict. Secure Endpoint, Umbrella and Entra are the expected sources: when one fails, confidence "
            "drops and the run notes it, but other evidence still produces the recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="block_exfil_domain",
            description="Block a destination domain that receives the data: rated malicious or suspicious, or "
                        "unrated (no reputation, not clean) and new, cloud storage, an abnormal DNS channel or a "
                        f"large upload, and reached from {MAX_DESTINATION_ENDPOINTS} endpoints or fewer",
            action=ActionType.BLOCK_DOMAIN,
            for_each="[d for d in facts.destinations if d.type == 'domain' and d.blockable]",
            target="item.value",
            evidence="item.record_ids",
            rationale=_DESTINATION_RATIONALE,
            min_risk=40,
            mitre=_ALL_TECHNIQUES,
        ),
        RecommendationRule(
            id="block_exfil_ip",
            description="Block a public destination IP that receives the data, under the same conditions as a "
                        "domain (internal and shared addresses are never proposed)",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="[d for d in facts.destinations if d.type == 'ip' and d.blockable]",
            target="item.value",
            evidence="item.record_ids",
            rationale=_DESTINATION_RATIONALE,
            min_risk=40,
            mitre=_ALL_TECHNIQUES,
        ),
        RecommendationRule(
            id="isolate_source_secure_endpoint",
            description="Isolate (Secure Endpoint) a source endpoint while its transfer is still running and "
                        "shows exfiltration evidence: a destination rated malicious or suspicious, a malicious or "
                        "exfiltration detection on the endpoint, a compromised account driving the transfer, or "
                        "an insider-risk detection on an account of the endpoint",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="[s for s in facts.sources if s.isolate]",
            when="item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_SOURCE_ASSET,
            params={"connector_guid": "item.connector_guid"},
            rationale=_SOURCE_RATIONALE,
            min_risk=50,
            mitre=_ALL_TECHNIQUES,
        ),
        RecommendationRule(
            id="isolate_source_defender_endpoint",
            description="Isolate (Defender for Endpoint) a source endpoint under the same conditions (a "
                        "duplicate of the Secure Endpoint proposal is merged)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="[s for s in facts.sources if s.isolate]",
            when="item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_SOURCE_ASSET,
            rationale=_SOURCE_RATIONALE,
            min_risk=50,
            mitre=_ALL_TECHNIQUES,
        ),
        RecommendationRule(
            id="revoke_actor_sessions",
            description="Revoke the sign-in sessions of an account that drives the transfer and is compromised "
                        "or named by an insider-risk detection (stolen tokens and open sessions stop working)",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="[a for a in facts.actors if (a.compromised and a.drives) or a.insider]",
            target="item.user",
            evidence="item.record_ids",
            asset=_ACTOR_ASSET,
            rationale="('account ' + item.user + ' drives the transfer (' + item.transfer_text + '): ' if item.drives"
                      " else 'account ' + item.user + ' (no transfer record names it): ') + item.basis",
            min_risk=40,
            mitre=_ALL_TECHNIQUES,
        ),
        RecommendationRule(
            id="disable_compromised_actor",
            description="Disable an account that drives the transfer and is compromised: identity risk high or "
                        "confirmed compromised, risk medium with a sign-in anomaly, or a high-severity anomaly",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="[a for a in facts.actors if a.compromised and a.drives]",
            target="item.user",
            evidence="item.record_ids",
            asset=_ACTOR_ASSET,
            rationale="'compromised account ' + item.user + ' drives the transfer (' + item.transfer_text + '): '"
                      " + item.basis",
            min_risk=50,
            mitre=_ALL_TECHNIQUES,
        ),
        RecommendationRule(
            id="disable_insider_actor",
            description="Disable an account an insider-risk detection names explicitly; the decision never "
                        "spreads to other accounts of the incident (legal and HR review the case)",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="[a for a in facts.actors if a.insider]",
            target="item.user",
            evidence="item.record_ids",
            asset=_ACTOR_ASSET,
            rationale="'insider-risk account ' + item.user + ' (' + item.basis + '); legal and HR review the case'",
            min_risk=50,
            mitre=_ALL_TECHNIQUES,
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0010", technique="T1041", technique_name="Exfiltration Over C2 Channel",
                     rationale="Data sent to a destination that reputation or the source's own analytics rate "
                               "malicious or suspicious: the workflow blocks that destination and isolates a source "
                               "whose transfer is still running."),
        MitreMapping(tactic="TA0010", technique="T1048", technique_name="Exfiltration Over Alternative Protocol",
                     rationale="Large transfers over non-web protocols and data carried in abnormal DNS queries: the "
                               "workflow blocks the receiving domain or IP and isolates the running source."),
        MitreMapping(tactic="TA0010", technique="T1567", technique_name="Exfiltration Over Web Service",
                     sub_technique="T1567.002", sub_technique_name="Exfiltration to Cloud Storage",
                     rationale="Uploads to unsanctioned or unknown cloud or file storage: the workflow blocks the "
                               "storage destination unless it is shared or sanctioned (allow-listed), and revokes "
                               "and disables the account that drives the upload when it is compromised or an "
                               "insider risk."),
    ),
    known_limitations=(
        "The transfer facts (volume, destination, time) come from typed connection and DNS records. With the "
        "real adapters, Secure Endpoint trajectory events, Defender timeline and hunting rows, Splunk rows and "
        "Cisco XDR sightings have no documented field schema (docs/integrations.md), so they stay generic "
        "records: citable, never scored, never a transfer. Until a schema is VERIFIED, blocks of unrated "
        "destinations and isolations are recommended only where typed records exist; rated destinations are "
        "still blocked from their reputation.",
        "Secure Cloud Analytics (Secure Network Analytics) volume alerts have no VERIFIED API: they arrive as "
        "Cisco XDR incidents and are used for routing, never as evidence on their own.",
        f"Whether a transfer is still running is judged from the last record time: at most {ONGOING_MINUTES} "
        "minutes before the incident was created (or later). A source that reports no time, or reports late, "
        "makes a running transfer look finished, so the isolation is listed as considered and the analyst "
        "decides.",
        f"A destination reached from more than {MAX_DESTINATION_ENDPOINTS} endpoints of the estate is treated as "
        "shared infrastructure and never proposed for a block. Without an enterprise search source "
        "(Cisco XDR, Defender, Microsoft Defender XDR hunting or Splunk) the reach is unknown and only the "
        "source endpoints count.",
        "Sanctioned backup, file-transfer and partner services must be listed in allowlists.never_block: hooks "
        "and rule expressions cannot read the allow-lists; the package builder excludes such blocks and shows "
        "them.",
        "The data that left is not classified: no VERIFIED read names the files or data types sent. The impact "
        "assessment (legal and privacy) is a manual step with the cited volume and window.",
        "An insider-risk flag is read only from an endpoint or platform detection that names insider risk and "
        "the account; an incident field alone (for example a legacy context flag) is data, never evidence.",
        "Abnormal DNS is judged from the distinct child labels and label length the source reports; a DNS "
        "tunnel without those fields is handled by the dns-tunneling workflow, not detected here.",
        "Revoking sessions does not affect external (guest) users and may take a few minutes (Microsoft Graph); "
        "it registers no control and cannot be rolled back.",
        "Secure Endpoint isolation verifies as UNABLE_TO_VERIFY (the isolation read is UNVERIFIED); direct "
        "Umbrella IP blocking is UNVERIFIED and never called (IP blocks use Meraki, Defender indicators or the "
        "native action).",
        "IPv6 destinations are not enriched or blocked by this workflow (IPv4 only).",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a withheld "
        "or failed source lowers confidence and is listed as degraded; an unrated destination stays unrated.",
    ),
    related_workflows=("c2", "dns-tunneling", "cloud-compromise", "account-takeover", "ransomware"),
    handoff_to=("account-takeover",),
)
