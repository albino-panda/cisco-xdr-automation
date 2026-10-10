"""Threat-intelligence sweep workflow (Phase 5, new; no legacy spec).

A high-confidence indicator of compromise (IOC) arrives: a file hash (SHA-256), an IPv4 address, a
domain, a URL or a sender email address, alone or as a list (an analyst, a scheduled retro-hunt over
a feed, or a threat-intelligence webhook). The workflow rates every indicator with the enrichment
sources, then sweeps the estate for it: endpoints that saw or ran the file (Secure Endpoint, Defender
for Endpoint, Cisco XDR sightings), endpoints and users that resolved or connected to the domain, IP
or URL (Cisco XDR, Defender XDR hunting, Splunk), messages that carry the indicator (Secure Email
Threat Defense, Defender for Office 365 data through Defender XDR hunting) and accounts that signed in
from the IP. It then RECOMMENDS containment for every affected asset:

* block the rated indicator (hash, domain, IP, URL), even when nothing was hit yet (preventive);
* isolate an endpoint where the file ran, or that reached the indicator and shows malicious activity
  of its own;
* quarantine the file on every endpoint where it is still present;
* quarantine every delivered message that carries a rated indicator;
* revoke the sessions of an account that signed in successfully from a rated IP.

An indicator is acted on only when a source the framework queried rates it (an aggregate MALICIOUS
enrichment verdict, or the security product's own MALICIOUS verdict on a record that names it): the
feed's claim of "high confidence" is incident data, never evidence. Like every workflow it only
investigates and recommends: it never executes, never approves and never chooses an approval level.
ELEVATED comes from ``PackageBuilder`` (critical assets, blast-radius caps); execution, verification
and restoration happen only in the lifecycle orchestrator after human approval.
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
    "BLOCK_MIN_RISK",
    "DELIVERED_LOCATIONS",
    "ENDPOINT_SOURCES",
    "EXECUTION_EVENT_TYPES",
    "HASH_HUNT_SOURCES",
    "IOC_TYPES",
    "ISOLATE_MIN_RISK",
    "MAIL_SOURCES",
    "MAX_INDICATORS_PER_TYPE",
    "NETWORK_HUNT_SOURCES",
    "QUARANTINE_MIN_RISK",
    "REVOKE_MIN_RISK",
    "SENDER_SOURCES",
    "SWEEP_LOOKBACK_HOURS",
    "TRIGGER_PRIORITY",
]

#: Indicator types the sweep accepts. SHA-1 / MD5 and IPv6 are not swept (records carry SHA-256 and
#: the blocks are IPv4 only); they are documented in the known limitations.
IOC_TYPES: tuple[ObservableType, ...] = (ObservableType.SHA256, ObservableType.DOMAIN, ObservableType.IP,
                                         ObservableType.URL, ObservableType.EMAIL_ADDRESS)

#: Indicators of one type swept per run (``max_subjects`` of every reputation and sighting step).
#: Further indicators are listed in the run notes as not queried, never silently dropped: split a
#: larger feed batch into several sweeps.
MAX_INDICATORS_PER_TYPE = 25

#: Retro-hunt window of the sighting, mail and sign-in steps (the framework maximum, 30 days).
SWEEP_LOOKBACK_HOURS = 720

#: Automatic trigger priority: above every workflow the sweep hands off to (c2 115, phishing 110,
#: malware and account-takeover 100), so a sweep incident stays with the sweep and the hand-offs are
#: made (architecture 14.11.2).
TRIGGER_PRIORITY = 120

#: Minimum risk of an indicator block (the MEDIUM band lower bound): reputation alone is capped by the
#: engine, and a block is reversible and always needs human approval.
BLOCK_MIN_RISK = 30
#: Minimum risk of an isolation (a rated file that ran, rated by two vendors, reaches it).
ISOLATE_MIN_RISK = 50
#: Minimum risk of a file or message quarantine.
QUARANTINE_MIN_RISK = 40
#: Minimum risk of a session revocation (a successful sign-in from a rated address).
REVOKE_MIN_RISK = 30

#: Process-event types that prove a file ran (or was loaded) on the endpoint.
EXECUTION_EVENT_TYPES: tuple[str, ...] = ("process_start", "file_execute", "module_load")
#: Message delivery locations that leave the message in a mailbox (``delivered_count`` of 14.1.4).
DELIVERED_LOCATIONS: tuple[str, ...] = ("inbox", "junk")

#: Sources of each sweep (subsets of the required and optional integrations).
HASH_HUNT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr", "microsoft_cloud",
                                      "splunk")
NETWORK_HUNT_SOURCES: tuple[str, ...] = ("cisco_xdr", "defender_endpoint", "microsoft_cloud", "splunk")
SENDER_SOURCES: tuple[str, ...] = ("cisco_xdr", "microsoft_cloud", "splunk")
MAIL_SOURCES: tuple[str, ...] = ("secure_email", "cisco_xdr", "microsoft_cloud", "splunk")
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")

_O = ObservableType
_A = ActionType


def _iocs(kind: str) -> str:
    return f"get(incident.observables_by_type, '{kind}', [])"


#: Domains swept: the domain indicators and the host of every URL indicator (a URL hit is a record
#: whose URL equals the indicator; a host lookup alone never counts as a URL hit).
_DOMAIN_SWEEP = f"distinct({_iocs('domain')} + [domain_of(u) for u in {_iocs('url')} if domain_of(u)])"
#: Endpoints the sweeps found (hash prevalence, detections, process events, DNS and connections).
_HIT_ENDPOINTS = (
    "distinct(flatten([r.endpoints for r in results.search_hash_enterprise])"
    " + flatten([r.endpoints for r in results.search_domain_enterprise])"
    " + flatten([r.endpoints for r in results.search_ip_enterprise]))"
)
#: Accounts that signed in successfully from a swept IP.
_SIGNED_IN = ("distinct([s.user for s in flatten([r.signins for r in results.search_ip_enterprise])"
              " if s.result == 'success' and s.user])")

_HOST_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'ips': item.ips, 'users': item.users}"
#: The identity source's view of an account (groups, roles, privileged flag): an account in a critical
#: group (Executives, Service Accounts, Domain Admins) is ELEVATED with a warning, never STANDARD.
_ACCOUNT_ASSET = "{'groups': item.groups, 'roles': item.roles, 'privileged': item.privileged}"
_ISOLATE_WHEN ="item.isolate and item.isolation_capable != False"
_ISOLATE_RATIONALE = "'endpoint ' + item.hostname + ' is affected by the swept indicators: ' + item.basis"
_BLOCK_RATIONALE = ("'swept indicator ' + item.value + ' is rated ' + item.rating + ' (' + item.basis + '); hits: '"
                    " + item.hit_text")

WORKFLOW = WorkflowDefinition(
    id="threat-intel-sweep",
    version="1.0.0",
    name="Threat intelligence sweep",
    description=(
        "Sweep the estate for high-confidence indicators of compromise (file hash, IP address, domain, URL, "
        "sender email address): rate every indicator with the enrichment sources, find the endpoints that saw "
        "or ran the file or reached the indicator, the messages that carry it and the accounts that signed in "
        "from it, and recommend containment for every affected asset (block the rated indicators, isolate "
        "affected endpoints, quarantine the file and the delivered messages, revoke the sessions of accounts "
        "that signed in from a rated address) for human approval."
    ),
    phase=5,
    default_severity=Severity.HIGH,
    legacy_id=None,
    triggers=(
        TriggerSpec(type="manual",
                    description="An analyst starts a sweep for one indicator or a list of indicators (the incident "
                                "carries them as observables)"),
        TriggerSpec(type="schedule", priority=TRIGGER_PRIORITY,
                    description="Scheduled retro-hunt over a threat-intelligence feed's new high-confidence "
                                "indicators: one incident per batch, at most "
                                f"{MAX_INDICATORS_PER_TYPE} indicators of each type"),
        TriggerSpec(type="webhook", priority=TRIGGER_PRIORITY,
                    description="Threat-intelligence platform webhook (incident id only) for a new high-confidence "
                                "indicator; the incident is re-read through the VERIFIED Cisco XDR APIs",
                    sources=("threat_intel", "threat_intelligence", "threat-intel"),
                    observable_types=IOC_TYPES),
        TriggerSpec(type="xdr_incident_rule", priority=TRIGGER_PRIORITY,
                    description="Cisco XDR incident titled as an indicator sweep, a retro-hunt or a high-confidence "
                                "indicator match that carries the indicators",
                    title_patterns=("*ioc sweep*", "*indicator sweep*", "*threat intel sweep*",
                                    "*threat-intel sweep*", "*threat intelligence sweep*", "*retro hunt*",
                                    "*retro-hunt*", "*retrohunt*", "*high-confidence ioc*", "*high confidence ioc*",
                                    "*high-confidence indicator*", "*high confidence indicator*"),
                    observable_types=IOC_TYPES),
    ),
    input_observables=(*IOC_TYPES, ObservableType.EMAIL_MESSAGE_ID),
    required_integrations=(
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts (private intelligence carries the feed's own verdict) and sightings of every "
                    "indicator across the enabled Cisco modules, and the native response actions",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip", "enrich_url", "enrich_email_address",
                     "search_hash_enterprise", "search_domain_enterprise", "search_ip_enterprise",
                     "investigate_user", "investigate_email", "investigate_endpoint")),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoints that saw or ran the file (computers and device trajectory of the hit endpoints) and "
                    "the isolation of an affected endpoint",
            atomics=("search_hash_enterprise", "investigate_endpoint")),
        IntegrationRequirement(
            integration="secure_email",
            purpose="Secure Email Threat Defense messages that carry an indicator (by message id, and the related "
                    "campaign messages) and their quarantine",
            atomics=("investigate_email", "search_email_campaign")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machines, alerts, enterprise search) and isolation or indicator "
                    "blocks for the endpoints it manages",
            atomics=("search_hash_enterprise", "search_domain_enterprise", "search_ip_enterprise",
                     "investigate_endpoint")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts and advanced hunting: endpoint, DNS, connection, sign-in and Defender for "
                    "Office 365 email rows that name an indicator",
            atomics=("search_hash_enterprise", "search_domain_enterprise", "search_ip_enterprise",
                     "investigate_user", "investigate_email", "search_email_campaign")),
        IntegrationRequirement(
            integration="defender_o365",
            purpose="Alternative executor for quarantining messages (its message search is UNVERIFIED, so no read "
                    "path is used)"),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain status and security categories of the domain indicators, and the landing product for "
                    "approved domain and URL blocks (DNS activity reports are UNVERIFIED)",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="entra",
            purpose="Profile of an account that signed in from a swept IP (privileged accounts are ELEVATED) and "
                    "the revocation of its sessions",
            atomics=("investigate_user",)),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the hash, domain, IP and URL indicators",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip", "enrich_url")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) of the hash, domain, IP and URL indicators",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip", "enrich_url")),
        IntegrationRequirement(
            integration="secure_malware_analytics",
            purpose="Domain IOC feed (VERIFIED); sample search and sandbox reports are UNVERIFIED",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="hibp",
            purpose="Breach exposure of a sender address indicator (context only, under the disclosure policy)",
            atomics=("enrich_email_address",)),
        IntegrationRequirement(
            integration="splunk",
            purpose="Proxy, firewall, DNS, mail and sign-in logs that name an indicator (optional, disabled by "
                    "default; rows stay citable generic records)",
            atomics=("search_hash_enterprise", "search_domain_enterprise", "search_ip_enterprise",
                     "investigate_user", "investigate_email", "search_email_campaign")),
        IntegrationRequirement(
            integration="meraki",
            purpose="Landing product for approved IP blocks at the MX firewall",
            atomics=()),
    ),
    investigation=(
        InvestigationStep(id="hash_reputation", atomic="enrich_hash", subjects=_iocs("sha256"),
                          subject_type=_O.SHA256, max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="domain_reputation", atomic="enrich_domain", subjects=_iocs("domain"),
                          max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="ip_reputation", atomic="enrich_ip", subjects=_iocs("ip"), subject_type=_O.IP,
                          max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="url_reputation", atomic="enrich_url", subjects=_iocs("url"),
                          max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="sender_reputation", atomic="enrich_email_address", subjects=_iocs("email_address"),
                          max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="hash_sightings", atomic="search_hash_enterprise", subjects=_iocs("sha256"),
                          subject_type=_O.SHA256, integrations=HASH_HUNT_SOURCES,
                          lookback_hours=SWEEP_LOOKBACK_HOURS, max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="domain_sightings", atomic="search_domain_enterprise", subjects=_DOMAIN_SWEEP,
                          integrations=NETWORK_HUNT_SOURCES, lookback_hours=SWEEP_LOOKBACK_HOURS,
                          max_subjects=2 * MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="ip_sightings", atomic="search_ip_enterprise", subjects=_iocs("ip"),
                          subject_type=_O.IP, integrations=NETWORK_HUNT_SOURCES,
                          lookback_hours=SWEEP_LOOKBACK_HOURS, max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="sender_activity", atomic="investigate_user", subjects=_iocs("email_address"),
                          subject_type=_O.EMAIL_ADDRESS, integrations=SENDER_SOURCES,
                          lookback_hours=SWEEP_LOOKBACK_HOURS, max_subjects=MAX_INDICATORS_PER_TYPE),
        InvestigationStep(id="messages", atomic="investigate_email", integrations=MAIL_SOURCES,
                          lookback_hours=SWEEP_LOOKBACK_HOURS, max_subjects=50),
        InvestigationStep(id="related_messages", atomic="search_email_campaign",
                          integrations=("secure_email", "microsoft_cloud", "splunk"),
                          lookback_hours=SWEEP_LOOKBACK_HOURS, max_subjects=50),
        InvestigationStep(id="affected_endpoints", atomic="investigate_endpoint", subjects=_HIT_ENDPOINTS,
                          subject_type=_O.HOSTNAME, integrations=ENDPOINT_SOURCES, lookback_hours=168,
                          max_subjects=50),
        InvestigationStep(id="affected_accounts", atomic="investigate_user", subjects=_SIGNED_IN,
                          subject_type=_O.USER, integrations=("entra",), lookback_hours=168),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same hash, domain, IP or URL on two or more endpoints or users (one indicator, "
            "many affected assets), the same endpoint or user across sources, a message that carries an indicator "
            "followed by a click from a recipient (email to click), and campaign messages. Workflow links (hooks): "
            "an indicator hit, tying each swept indicator to the endpoint, account or message a record names "
            "together with it. Links within 24 hours of each other count; they shape the clusters, the blast "
            "radius and the decision card, never the approval level."),
        link_kinds=(LinkKind.SAME_HASH, LinkKind.SAME_DOMAIN, LinkKind.SAME_IP, LinkKind.SAME_URL,
                    LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT, LinkKind.EMAIL_TO_CLICK, LinkKind.CAMPAIGN),
        window_minutes=1440,
    ),
    scoring=ScoringInputs(
        description=(
            "An indicator is rated by the enrichment sources (Cisco XDR, VirusTotal, OTX, Umbrella, Secure Malware "
            "Analytics): vendor reputation, capped by the engine, where one vendor alone is never an aggregate "
            "MALICIOUS verdict; or by the security product's own MALICIOUS verdict on a record that names it (a "
            "detection or prevalence record of the file, a connection or DNS record, a message from the sender). "
            "The feed's confidence is incident data and is never scored. An asset action cites the hit records "
            "(endpoint detections and process events dominate, endpoint_detection weight 1.0; connection and DNS "
            "verdicts are network behaviour; message verdicts are email verdicts) with the indicator's rating "
            "records. Cisco XDR, Secure Endpoint and Secure Email are the expected sources: when one fails, "
            "confidence drops and the run notes it, but the other evidence still produces the recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="block_swept_hash",
            description="Block a rated file hash indicator fleet-wide (preventive when no endpoint saw it yet)",
            action=_A.BLOCK_HASH,
            builder="block_hash",
            for_each="[i for i in facts.indicators if i.type == 'sha256' and i.rated]",
            target="item.value",
            evidence="item.record_ids",
            rationale=_BLOCK_RATIONALE,
            min_risk=BLOCK_MIN_RISK,
            mitre=("T1204.002",),
        ),
        RecommendationRule(
            id="block_swept_domain",
            description="Block a rated domain indicator (preventive when nothing resolved it yet)",
            action=_A.BLOCK_DOMAIN,
            for_each="[i for i in facts.indicators if i.type == 'domain' and i.rated]",
            target="item.value",
            evidence="item.record_ids",
            rationale=_BLOCK_RATIONALE,
            min_risk=BLOCK_MIN_RISK,
        ),
        RecommendationRule(
            id="block_swept_ip",
            description="Block a rated IPv4 address indicator (preventive when nothing reached it yet)",
            action=_A.BLOCK_IP,
            builder="block_ip",
            for_each="[i for i in facts.indicators if i.type == 'ip' and i.rated]",
            target="item.value",
            evidence="item.record_ids",
            rationale=_BLOCK_RATIONALE,
            min_risk=BLOCK_MIN_RISK,
        ),
        RecommendationRule(
            id="block_swept_url",
            description="Block a rated URL indicator (preventive when nothing requested it yet)",
            action=_A.BLOCK_URL,
            builder="block_url",
            for_each="[i for i in facts.indicators if i.type == 'url' and i.rated]",
            target="item.value",
            evidence="item.record_ids",
            rationale=_BLOCK_RATIONALE,
            min_risk=BLOCK_MIN_RISK,
            mitre=("T1566.002",),
        ),
        RecommendationRule(
            id="isolate_affected_endpoint_secure_endpoint",
            description="Isolate (Secure Endpoint) an endpoint where a rated file indicator ran, or that reached a "
                        "rated network indicator and shows malicious activity of its own",
            action=_A.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="facts.hosts",
            when=f"{_ISOLATE_WHEN} and item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            binaries="item.binaries",
            params={"connector_guid": "item.connector_guid"},
            rationale=_ISOLATE_RATIONALE,
            min_risk=ISOLATE_MIN_RISK,
            mitre=("T1204.002",),
        ),
        RecommendationRule(
            id="isolate_affected_endpoint_defender_endpoint",
            description="Isolate (Defender for Endpoint) an affected endpoint (a duplicate of the Secure Endpoint "
                        "proposal is merged)",
            action=_A.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="facts.hosts",
            when=f"{_ISOLATE_WHEN} and item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            binaries="item.binaries",
            rationale=_ISOLATE_RATIONALE,
            min_risk=ISOLATE_MIN_RISK,
            mitre=("T1204.002",),
        ),
        RecommendationRule(
            id="quarantine_swept_file",
            description="Quarantine a rated file indicator on every endpoint where it is still present (not "
                        "remediated by the agent and not deleted)",
            action=_A.QUARANTINE_FILE,
            builder="quarantine_file",
            for_each="facts.files",
            target="item.target",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_HOST_ASSET,
            rationale="'rated file ' + item.sha256 + ' is present on ' + item.endpoint + ' (' + item.basis + ')'",
            min_risk=QUARANTINE_MIN_RISK,
            mitre=("T1204.002",),
        ),
        RecommendationRule(
            id="quarantine_carrier_message",
            description="Quarantine a delivered message that carries a rated indicator (sender, URL, domain or "
                        "attachment hash); never one whose rated indicators are all excluded by the allow-list",
            action=_A.QUARANTINE_EMAIL,
            builder="quarantine_email",
            for_each="[m for m in facts.messages if m.quarantine]",
            target="item.message_id",
            evidence="item.record_ids",
            include_target_enrichment=False,
            params={"recipient": "item.recipient"},  # Defender for Office 365 route; the ETD verdict is config
            indicators="item.block_indicators",  # never on allow-listed indicators alone (14.13.6)
            rationale="'delivered message ' + item.message_id + ' to ' + item.recipient_list + ' carries the rated "
                      "indicator(s) ' + item.indicator_list",
            min_risk=QUARANTINE_MIN_RISK,
            mitre=("T1566.001", "T1566.002"),
        ),
        RecommendationRule(
            id="revoke_sessions_signed_in_from_indicator",
            description="Revoke the sessions of an account that signed in successfully from a rated IP indicator",
            action=_A.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="[a for a in facts.accounts if a.signed_in]",
            target="item.user",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_ACCOUNT_ASSET,
            indicators="item.indicators",
            rationale="'account ' + item.user + ' signed in successfully from the rated indicator(s) ' + item.ip_list",
            min_risk=REVOKE_MIN_RISK,
            mitre=("T1078",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0002", technique="T1204", technique_name="User Execution",
                     sub_technique="T1204.002", sub_technique_name="Malicious File",
                     rationale="A swept file indicator that ran on an endpoint: the workflow isolates the endpoint, "
                               "quarantines the file wherever it is present and blocks its hash."),
        MitreMapping(tactic="TA0001", technique="T1566", technique_name="Phishing",
                     sub_technique="T1566.001", sub_technique_name="Spearphishing Attachment",
                     rationale="A delivered message whose attachment hash is a swept indicator is quarantined."),
        MitreMapping(tactic="TA0001", technique="T1566", technique_name="Phishing",
                     sub_technique="T1566.002", sub_technique_name="Spearphishing Link",
                     rationale="A delivered message that carries a swept URL or domain (or comes from a swept "
                               "sender) is quarantined and the URL is blocked."),
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     rationale="An account that signed in successfully from a swept IP is treated as used by the "
                               "actor behind the indicator: its sessions are revoked and it is handed to "
                               "account-takeover."),
    ),
    known_limitations=(
        "The feed's own confidence is never evidence: an indicator is acted on only when a queried source rates "
        "it (aggregate MALICIOUS, which needs two vendors or a behavioural detection, or a security product's "
        "MALICIOUS verdict on a record naming it). A feed indicator only one vendor rates is shown as considered, "
        "never blocked; a Cisco XDR private-intelligence verdict is one vendor.",
        "Secure Cloud Analytics has no VERIFIED API (docs/integrations.md section 2.5): its alerts reach the sweep "
        "only as Cisco XDR incidents and sightings; its flow records are not searched directly.",
        "Umbrella DNS activity and reporting reads are UNVERIFIED: Umbrella only rates the domain indicators "
        "(VERIFIED categorisation); DNS hits come from Cisco XDR sightings, Defender XDR hunting or Splunk.",
        "Secure Email Threat Defense message search by sender, URL or attachment hash is not usable (the search "
        "body fields are not documented) and Defender for Office 365 message search is UNVERIFIED: messages are "
        "found from message ids the incident carries, from Cisco XDR sightings and from Defender XDR hunting "
        "rows; a carrier message nobody names is not found and the phishing hand-off covers the mailbox review.",
        "With the real adapters, Cisco XDR sightings, Defender XDR hunting rows and Splunk rows have no "
        "documented field schema, so they stay generic records: citable, never scored, and they cannot name an "
        "affected endpoint, account or message. Until a schema is VERIFIED, asset actions rest on typed sources "
        "(Secure Endpoint computers and trajectory of the incident's endpoints, message ids) and the indicator "
        "blocks follow enrichment.",
        "A sender address indicator has no VERIFIED gateway block write: blocking the sender is a manual step "
        "(listed with its records); the delivered messages from it are quarantined after approval.",
        "Quarantine file has no VERIFIED vendor endpoint, so with the real adapters it is reported UNROUTED for "
        "manual handling in the endpoint console; only the simulated lab executes it. Secure Endpoint isolation "
        "verifies as UNABLE_TO_VERIFY (isolation-state read UNVERIFIED).",
        "An endpoint that only resolved or reached a rated network indicator, without the file running and "
        "without malicious activity of its own, is not isolated (shown as considered and handed to c2): the "
        "indicator block cuts the path and the analyst can isolate it by hand. An endpoint that should be "
        "isolated but no agent manages, or whose policy forbids isolation, is a manual step.",
        f"At most {MAX_INDICATORS_PER_TYPE} indicators of each type are swept per run (the extra ones are listed "
        "in the run notes as not queried); split a larger feed batch. Over the blast-radius caps (endpoints, "
        "users, indicators, messages) every action of that kind needs ELEVATED approval.",
        "SHA-1 and MD5 indicators, IPv6 addresses and file-name indicators are not swept (records carry SHA-256 "
        "and the IP blocks are IPv4 only); convert them before the sweep or handle them by hand.",
        "A sweep is retrospective over at most 30 days (720 hours, the framework maximum); older hits are not "
        "found.",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a withheld or "
        "failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("malware", "c2", "phishing", "account-takeover"),
    handoff_to=("malware", "c2", "phishing", "account-takeover"),
)
