"""Ransomware workflow definition (Phase 2; replaces the legacy spec ``workflows/ransomware``).

The workflow investigates suspected ransomware (mass file modification, suspicious encryption,
shadow-copy deletion, known ransomware executables, simultaneous endpoint and network indicators)
and *recommends* a containment package. It never executes anything: every action needs a human
approval in the lifecycle orchestrator, and restoration needs a separate human release approval.

Rules use the facts of :mod:`xdr_response.workflows.ransomware.hooks`; every fact maps an entity to
the records it came from, so every recommendation cites real investigation or enrichment records.
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

#: Hosts an investigate_endpoint item can be isolated through Secure Endpoint (it knows the host, or
#: Defender does not) and whose connector policy does not forbid isolation.
_SE_ROUTE = "item.isolation_capable != False and (item.connector_guid or not item.mde_machine_id)"
_HOST_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip_addresses[0] if item.ip_addresses else None}"
_USER_ASSET = "{'groups': get(item.profile, 'groups', []), 'roles': get(item.profile, 'roles', [])}"
_FLAGGED = "['MALICIOUS', 'SUSPICIOUS']"

WORKFLOW = WorkflowDefinition(
    id="ransomware",
    version="2.0.0",
    name="Ransomware",
    description=(
        "Investigates suspected ransomware (mass file modification, suspicious encryption, shadow-copy "
        "deletion, known ransomware executables, simultaneous endpoint and network indicators) across the "
        "affected hosts, users, processes, hashes, network destinations, DNS, authentication, lateral "
        "movement, related endpoints and email origin, and recommends a containment package for human "
        "approval: isolate the affected hosts (Secure Endpoint, or Defender for Endpoint when configured), "
        "block the payload hash and the malicious destinations, revoke sessions of the accounts on the "
        "affected hosts, disable accounts the identity provider confirms compromised, quarantine the "
        "originating email campaign and scope lateral targets."),
    phase=2,
    default_severity=Severity.CRITICAL,
    legacy_id="ransomware",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident tagged with an impact technique of ransomware (encryption or "
                                "recovery inhibition)",
                    mitre_techniques=("T1486", "T1490"), priority=200),
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident whose title names ransomware, mass file modification, shadow-copy "
                                "deletion or encrypted files",
                    title_patterns=("*ransom*", "*mass file modification*", "*shadow cop*", "*encrypted*"),
                    priority=150),
        TriggerSpec(type="manual", description="An analyst starts the workflow for an incident"),
    ),
    input_observables=(_O.HOSTNAME, _O.ENDPOINT_ID, _O.SHA256, _O.USER, _O.DOMAIN, _O.URL, _O.IP,
                       _O.EMAIL_MESSAGE_ID),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint context, detections and device trajectory of the affected hosts; preferred "
                    "isolation route",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="entra",
            purpose="User profile, risk state, sign-ins and risk detections; session revocation and account "
                    "disable route",
            atomics=("investigate_user", "investigate_authentication")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Context of Defender-managed devices; Defender isolation route when the host is managed "
                    "there; indicator route for hashes, domains, URLs and IPs",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Enterprise hash and domain search, enrichment and native response actions",
            atomics=("enrich_hash", "enrich_domain", "enrich_url", "enrich_ip", "search_hash_enterprise",
                     "search_domain_enterprise", "investigate_endpoint", "investigate_email")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Microsoft Defender XDR alerts (typed detections) and hunting searches for payload "
                    "prevalence, related endpoints and DNS activity",
            atomics=("investigate_endpoint", "search_hash_enterprise", "search_related_endpoints",
                     "search_domain_enterprise", "investigate_user", "investigate_email")),
        IntegrationRequirement(
            integration="splunk",
            purpose="Enterprise searches for payload prevalence, related endpoints, DNS and authentication",
            atomics=("search_hash_enterprise", "search_related_endpoints", "search_domain_enterprise",
                     "investigate_authentication")),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain reputation; domain and URL block route",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="meraki",
            purpose="IP block route at the network edge"),
        IntegrationRequirement(
            integration="secure_email",
            purpose="Originating message and campaign search; quarantine route",
            atomics=("investigate_email", "search_email_campaign")),
        IntegrationRequirement(
            integration="defender_o365",
            purpose="Quarantine route for Microsoft 365 mailboxes"),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Second opinion on hash, domain, URL and IP reputation (disclosure policy applies)",
            atomics=("enrich_hash", "enrich_domain", "enrich_url", "enrich_ip")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Additional reputation for hashes, domains, URLs and IPs (disclosure policy applies)",
            atomics=("enrich_hash", "enrich_domain", "enrich_url", "enrich_ip")),
        IntegrationRequirement(
            integration="secure_malware_analytics",
            purpose="Sandbox-backed domain reputation",
            atomics=("enrich_domain",)),
    ),
    investigation=(
        InvestigationStep(id="affected_endpoints", atomic="investigate_endpoint"),
        InvestigationStep(id="hash_reputation", atomic="enrich_hash"),
        InvestigationStep(
            id="payload_prevalence", atomic="search_hash_enterprise", subject_type=_O.SHA256,
            subjects=("distinct([r.value for r in results.enrich_hash if r.type == 'sha256' and r.verdict in "
                      f"{_FLAGGED}] + get(incident.observables_by_type, 'sha256', []) + flatten([[d.sha256 for d in "
                      "e.detections if d.verdict == 'MALICIOUS' and d.sha256] for e in results.investigate_endpoint])"
                      " + flatten([[t.sha256 for t in e.trajectory if t.verdict == 'MALICIOUS' and t.sha256] for e "
                      "in results.investigate_endpoint]))"),
            lookback_hours=72),
        InvestigationStep(
            id="payload_hosts", atomic="investigate_endpoint", subject_type=_O.HOSTNAME,
            subjects=("distinct(flatten([r.endpoints for r in results.search_hash_enterprise if (r.prevalence is "
                      "None or r.prevalence <= 50) and (r.verdict in " + _FLAGGED + " or r.sha256 in [e.value "
                      "for e in results.enrich_hash if e.verdict in " + _FLAGGED + "] or r.sha256 in "
                      "flatten([[d.sha256 for d in x.detections if d.verdict == 'MALICIOUS'] for x in "
                      "results.investigate_endpoint]))]))")),
        InvestigationStep(
            id="lateral_scope", atomic="search_related_endpoints", subject_type=_O.HOSTNAME,
            subjects=("[e.hostname for e in results.investigate_endpoint if e.hostname and (any(d.verdict == "
                      "'MALICIOUS' for d in e.detections) or any(t.verdict == 'MALICIOUS' for t in e.trajectory))]")),
        InvestigationStep(
            id="lateral_targets", atomic="investigate_endpoint", subject_type=_O.HOSTNAME,
            subjects="distinct(flatten([[x.hostname for x in r.endpoints] for r in results.search_related_endpoints]))"),
        InvestigationStep(
            id="users", atomic="investigate_user", subject_type=_O.USER,
            subjects=("distinct([u for u in incident.users + get(incident.observables_by_type, 'user', []) + "
                      "flatten([e.users for e in results.investigate_endpoint]) + flatten([[d.user for d in "
                      "e.detections] for e in results.investigate_endpoint]) if u and '@' in u])")),
        InvestigationStep(
            id="authentication", atomic="investigate_authentication",
            subjects="[u.user for u in results.investigate_user if u.user]"),
        InvestigationStep(id="email_origin", atomic="investigate_email"),
        InvestigationStep(id="email_campaign", atomic="search_email_campaign"),
        InvestigationStep(id="domain_reputation", atomic="enrich_domain"),
        InvestigationStep(id="url_reputation", atomic="enrich_url"),
        InvestigationStep(
            id="ip_reputation", atomic="enrich_ip", subject_type=_O.IP,
            subjects=("distinct(get(incident.observables_by_type, 'ip', []) + flatten([[c.remote_ip for c in "
                      "e.network_connections if c.remote_ip and ':' not in c.remote_ip and c.direction in "
                      "['outbound', 'unknown']] for e in results.investigate_endpoint]))")),
        InvestigationStep(
            id="domain_scope", atomic="search_domain_enterprise",
            subjects=f"[r.value for r in results.enrich_domain if r.verdict in {_FLAGGED}]"),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links over the run's records within 60 minutes: the same hash, domain, IP or URL on two "
            "or more endpoints or users (payload spread and simultaneous network indicators), the same user on "
            "several endpoints, process lineage on one endpoint, a delivered message followed by a click from "
            "a recipient, and campaign messages. The workflow hooks add the ransomware facts: affected hosts "
            "(own ransomware activity), payload hosts (payload staged without a detection yet), affected and "
            "compromised users, blockable destinations and lateral targets in scope."),
        window_minutes=60),
    scoring=ScoringInputs(
        description=(
            "Per target, from the records its rule cites: endpoint detections and vendor-flagged process "
            "events dominate; the hook adds 'encryption with recovery inhibition' (endpoint detection, "
            "MALICIOUS, severity 90) and 'payload spread' (lateral movement, SUSPICIOUS, severity 70). "
            "Reputation is capped by the engine, a single source is capped below CRITICAL unless it is a "
            "MALICIOUS behavioural detection, and failed expected sources lower confidence. Default category "
            "weights.")),
    recommendations=(
        RecommendationRule(
            id="isolate_affected_hosts",
            description="Isolate an endpoint with ransomware activity of its own (Secure Endpoint route)",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_secure_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.hostname in facts.affected_hosts and {_SE_ROUTE}",
            target="item.hostname",
            evidence="facts.affected_hosts[item.hostname]",
            asset=_HOST_ASSET,
            rationale="'ransomware activity on ' + item.hostname + ': isolation stops local encryption and spread'",
            min_risk=60,
            mitre=("T1486", "T1490"),
        ),
        RecommendationRule(
            id="isolate_payload_hosts",
            description="Isolate an endpoint that holds the spreading payload before it raises a detection of its "
                        "own (Secure Endpoint route)",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_secure_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.hostname in facts.payload_hosts and {_SE_ROUTE}",
            target="item.hostname",
            evidence="facts.payload_hosts[item.hostname]",
            asset=_HOST_ASSET,
            rationale="'ransomware payload staged on ' + item.hostname",
            min_risk=60,
            mitre=("T1570",),
        ),
        RecommendationRule(
            id="isolate_defender_hosts",
            description="Isolate an affected or payload endpoint managed by Defender for Endpoint (Defender route; "
                        "merged with the Secure Endpoint recommendation when both products manage the host)",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_defender_endpoint",
            for_each="results.investigate_endpoint",
            when=("item.mde_machine_id and item.isolation_capable != False and (item.hostname in "
                  "facts.affected_hosts or item.hostname in facts.payload_hosts)"),
            target="item.hostname",
            evidence="get(facts.affected_hosts, item.hostname, []) + get(facts.payload_hosts, item.hostname, [])",
            asset=_HOST_ASSET,
            rationale="'ransomware activity or payload on Defender-managed ' + item.hostname",
            min_risk=60,
            mitre=("T1486", "T1490", "T1570"),
        ),
        RecommendationRule(
            id="block_payload_hash",
            description="Block a payload hash confirmed by reputation and seen on 50 endpoints or fewer",
            action=_A.BLOCK_HASH, builder="block_hash",
            for_each="results.enrich_hash",
            when="item.value in facts.blockable_hashes",
            target="item.value",
            evidence="facts.blockable_hashes[item.value]",
            rationale=("'ransomware payload hash rated ' + item.verdict + (', prevalence unknown: check before '"
                       " + 'approving' if facts.payload_hashes[item.value].prevalence is None else '')"),
            min_risk=60,
            mitre=("T1486",),
        ),
        RecommendationRule(
            id="block_destination_domains",
            description="Block a domain rated malicious or suspicious that an affected host contacted, a malicious "
                        "message carried or the incident lists",
            action=_A.BLOCK_DOMAIN, builder="block_domain_umbrella",
            for_each="results.enrich_domain",
            when="item.value in facts.blockable_domains",
            target="item.value",
            evidence="facts.blockable_domains[item.value]",
            rationale="'ransomware destination domain rated ' + item.verdict",
            min_risk=50,
            mitre=("T1071",),
        ),
        RecommendationRule(
            id="block_destination_urls",
            description="Block a URL rated malicious or suspicious that an affected host contacted, a malicious "
                        "message carried or the incident lists",
            action=_A.BLOCK_URL, builder="block_url",
            for_each="results.enrich_url",
            when="item.value in facts.blockable_urls",
            target="item.value",
            evidence="facts.blockable_urls[item.value]",
            rationale="'ransomware destination URL rated ' + item.verdict",
            min_risk=50,
            mitre=("T1071",),
        ),
        RecommendationRule(
            id="block_destination_ips",
            description="Block an IP address rated malicious or suspicious that an affected host contacted or the "
                        "incident lists",
            action=_A.BLOCK_IP, builder="block_ip",
            for_each="results.enrich_ip",
            when="item.value in facts.blockable_ips",
            target="item.value",
            evidence="facts.blockable_ips[item.value]",
            rationale="'ransomware destination IP rated ' + item.verdict",
            min_risk=50,
            mitre=("T1071",),
        ),
        RecommendationRule(
            id="revoke_affected_user_sessions",
            description="Revoke the sign-in sessions of an account on an affected host or confirmed compromised",
            action=_A.REVOKE_SESSIONS, builder="revoke_entra_sessions",
            for_each="results.investigate_user",
            when="item.user in facts.affected_users or item.user in facts.compromised_users",
            target="item.user",
            evidence="get(facts.affected_users, item.user, []) + get(facts.compromised_users, item.user, [])",
            asset=_USER_ASSET,
            rationale="'account ' + item.user + ' is on an affected host or confirmed compromised'",
            min_risk=60,
            mitre=("T1078",),
        ),
        RecommendationRule(
            id="disable_compromised_users",
            description="Disable an account the identity provider confirms compromised, or rates high risk with at "
                        "least one risk detection",
            action=_A.DISABLE_USER, builder="disable_entra_user",
            for_each="results.investigate_user",
            when="item.user in facts.compromised_users",
            target="item.user",
            evidence="facts.compromised_users[item.user] + get(facts.affected_users, item.user, [])",
            asset=_USER_ASSET,
            rationale="'account ' + item.user + ' confirmed compromised or high risk with risk detections'",
            min_risk=60,
            mitre=("T1078",),
        ),
        RecommendationRule(
            id="quarantine_originating_campaign",
            description="Quarantine delivered messages of the originating email campaign rated malicious",
            action=_A.QUARANTINE_EMAIL, builder="quarantine_email",
            for_each=("flatten([r.messages for r in results.investigate_email]) + flatten([r.messages for r in "
                      "results.search_email_campaign])"),
            when=f"item.verdict in {_FLAGGED} and item.delivery_location in ['inbox', 'junk']",
            target="item.message_id",
            evidence="[item.record_id]",
            include_target_enrichment=False,
            # Defender for Office 365 route needs one recipient; the Secure Email verdict is config (14.10.3)
            params={"recipient": "item.recipients[0] if len(distinct(item.recipients)) == 1 else ''"},
            rationale="'originating message ' + item.message_id + ' rated ' + item.verdict + ' still in a mailbox'",
            min_risk=60,
            mitre=("T1566",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0040", technique="T1486", technique_name="Data Encrypted for Impact",
                     rationale="Mass file modification and encryption by a flagged process on the affected "
                               "hosts; isolation and the payload block stop it."),
        MitreMapping(tactic="TA0040", technique="T1490", technique_name="Inhibit System Recovery",
                     rationale="Vendor-flagged shadow-copy, backup-catalog or boot-recovery tampering on the "
                               "affected hosts; isolation stops further tampering."),
        MitreMapping(tactic="TA0008", technique="T1570", technique_name="Lateral Tool Transfer",
                     rationale="The same low-prevalence payload staged on further endpoints; those hosts are "
                               "isolated before they raise a detection of their own."),
        MitreMapping(tactic="TA0011", technique="T1071", technique_name="Application Layer Protocol",
                     rationale="Affected hosts contacted destinations rated malicious; the domain, URL and IP "
                               "blocks cut that communication. No sub-technique: the records do not show the "
                               "protocol."),
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     rationale="Accounts on the affected hosts, or confirmed compromised by the identity provider, "
                               "lose their sessions or are disabled. No sub-technique: the records do not show "
                               "whether the account is a domain, local or cloud account."),
        MitreMapping(tactic="TA0001", technique="T1566", technique_name="Phishing",
                     rationale="The originating message and its campaign, when the incident carries a message "
                               "id, are quarantined. No sub-technique: attachment and link delivery are both "
                               "covered."),
    ),
    known_limitations=(
        "Real Secure Endpoint trajectory events stay generic records (docs/integrations.md documents no event "
        "fields), so behavioural evidence (mass file modification, recovery inhibition) comes from typed "
        "detections (Microsoft Defender XDR alerts) until the event schema is verified.",
        "A host whose connector policy forbids isolation, a malicious hash seen on more than 50 endpoints and a "
        "hash without a reputation verdict are not recommended; they are listed as considered (run notes and "
        "analyst summary, with their records), and the analyst contains them by hand if needed.",
        "Email origin is investigated only when the incident or a record carries a message id; there is no "
        "search of mailboxes by payload hash.",
        "Lateral targets are scoped (related endpoints are investigated) but isolated only with ransomware "
        "activity or the payload of their own; a file server encrypted remotely over a share is not isolated.",
        "Service Stop (T1489) from the legacy spec is not mapped: no record kind carries service-stop evidence.",
        "A tenant whose only executor is Cisco XDR native response needs product-pinned builders; such "
        "actions are reported as unrouted and handled manually.",
    ),
    related_workflows=("malware", "lateral-movement", "exfiltration", "phishing"),
)
