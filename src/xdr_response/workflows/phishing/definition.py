"""Phishing workflow definition (architecture 14.3.1, 14.5; Phase 2; replaces ``workflows/phishing/workflow.yaml``).

Credential phishing: the workflow investigates the message, its sender and sending infrastructure,
URLs, domains and attachments, the recipients, the recipients who clicked, authentication after the
click and endpoint activity after the click, then *recommends* a containment package: quarantine the
delivered campaign messages, block the phishing URLs, domains and attachment hashes, revoke the
sessions of affected users, disable an account where the evidence justifies it, and isolate an
endpoint that shows malicious activity after the click. Users whose sessions are revoked are handed
off to the account-takeover workflow.

Like every workflow it only investigates and recommends. Every recommendation needs a human
approval (ELEVATED for critical assets and over blast-radius caps, decided by ``PackageBuilder``);
execution, verification and restoration are Phase 0 lifecycle code.
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

__all__ = ["WORKFLOW"]

_O = ObservableType
_A = ActionType

#: Rule items of the two email atomics (the reported message and its campaign).
_MAIL = "results.investigate_email + results.search_email_campaign"
#: Domains the messages and the incident carry (URL hosts, message domains, incident domains).
_CARRIED_DOMAINS = (
    "[lower(x) for x in get(incident.observables_by_type, 'domain', [])]"
    f" + flatten([r.domains for r in {_MAIL}])"
    " + [domain_of(u) for u in get(incident.observables_by_type, 'url', [])"
    f" + flatten([r.urls for r in {_MAIL}])]"
)
_SENDER_DOMAINS = f"[m.sender_domain for m in flatten([r.messages for r in {_MAIL}]) if m.sender_domain]"
#: Users who may have clicked or opened: reported users, click activity, users of the involved endpoints.
_ACTIVE_USERS = (
    "incident.users + get(incident.observables_by_type, 'user', [])"
    " + flatten([r.users for r in results.search_domain_enterprise])"
    " + flatten([r.users for r in results.investigate_endpoint])"
)

WORKFLOW = WorkflowDefinition(
    id="phishing",
    version="1.0.0",
    name="Phishing",
    description=(
        "Triage a reported or detected credential-phishing message: investigate the sender, sending "
        "infrastructure, URLs, domains and attachments, the recipients, who clicked, authentication after "
        "the click and endpoint activity after the click, then recommend a containment package (quarantine "
        "the campaign, block URLs, domains and attachment hashes, revoke affected sessions, disable an "
        "account where justified, isolate a compromised endpoint) for human approval, and hand affected "
        "accounts off to account-takeover."
    ),
    phase=2,
    default_severity=Severity.MEDIUM,
    legacy_id="phishing",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident whose detection reports a phishing technique (T1566 or a sub-technique)",
                    mitre_techniques=("T1566",), priority=110),
        TriggerSpec(type="xdr_incident_rule",
                    description="Secure Email Threat Defense incident about a message (verdict changed after delivery "
                                "or a user-reported phish)",
                    sources=("secure_email", "Secure Email Threat Defense"),
                    observable_types=(_O.EMAIL_MESSAGE_ID,), priority=100),
        TriggerSpec(type="xdr_incident_rule", description="XDR incident titled as phishing that carries a message id",
                    title_patterns=("*phish*",), observable_types=(_O.EMAIL_MESSAGE_ID,), priority=90),
        TriggerSpec(type="manual",
                    description="An analyst starts the workflow from an incident, a pivot menu or a playbook task"),
    ),
    input_observables=(_O.EMAIL_MESSAGE_ID, _O.EMAIL_ADDRESS, _O.URL, _O.DOMAIN, _O.IP, _O.SHA256, _O.USER,
                       _O.HOSTNAME),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_email",
            purpose="Message facts and the campaign search (VERIFIED message search); quarantines delivered copies "
                    "(VERIFIED move) and verifies them (VERIFIED status)",
            atomics=("investigate_email", "search_email_campaign")),
        IntegrationRequirement(
            integration="entra",
            purpose="Recipient profiles, roles and risk, sign-ins after the click (VERIFIED Graph reads); revokes "
                    "sessions and disables accounts (VERIFIED)",
            atomics=("investigate_user", "investigate_authentication", "enrich_email_address")),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain status and categorization (VERIFIED Investigate read); blocks domains and URLs through "
                    "a destination list (VERIFIED)",
            atomics=("enrich_domain",)),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_o365",
            purpose="Quarantines delivered copies through remediate (VERIFIED) when Secure Email is not enabled; "
                    "no VERIFIED read, so it adds no investigation records"),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Second opinion on URL, domain, IP and attachment reputation (public indicators only)",
            atomics=("enrich_url", "enrich_domain", "enrich_ip", "enrich_hash")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Threat-intelligence context on URLs, domains, sending IPs and attachments",
            atomics=("enrich_url", "enrich_domain", "enrich_ip", "enrich_hash")),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint facts, detections and trajectory after the click; isolates an endpoint (VERIFIED)",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Endpoint facts after the click; isolates (VERIFIED) and blocks attachment hashes, URLs and "
                    "domains through indicators (VERIFIED)",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Sightings of the message, domains and attachments (citable generic records); routes approved "
                    "actions natively when native actions are configured",
            atomics=("investigate_email", "search_domain_enterprise", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts and hunting rows about the message, domains, attachments and users "
                    "(citable generic records)",
            atomics=("investigate_email", "search_domain_enterprise", "search_hash_enterprise", "investigate_user")),
    ),
    investigation=(
        InvestigationStep(id="message", atomic="investigate_email"),
        InvestigationStep(id="campaign", atomic="search_email_campaign",
                          subjects="get(incident.observables_by_type, 'email_message_id', [])"),
        InvestigationStep(id="sender_reputation", atomic="enrich_email_address",
                          subjects=f"distinct(get(incident.observables_by_type, 'email_address', [])"
                                   f" + flatten([r.senders for r in {_MAIL}]))",
                          max_subjects=10),
        InvestigationStep(id="url_reputation", atomic="enrich_url",
                          subjects=f"distinct(get(incident.observables_by_type, 'url', [])"
                                   f" + flatten([r.urls for r in {_MAIL}]))"),
        InvestigationStep(id="domain_reputation", atomic="enrich_domain",
                          subjects=f"distinct([d for d in {_CARRIED_DOMAINS} + {_SENDER_DOMAINS} if d])"),
        InvestigationStep(id="sending_infrastructure", atomic="enrich_ip", max_subjects=10),
        InvestigationStep(id="attachment_reputation", atomic="enrich_hash"),
        InvestigationStep(id="click_activity", atomic="search_domain_enterprise",
                          subjects=f"distinct([d for d in {_CARRIED_DOMAINS} if d])"),
        InvestigationStep(id="attachment_activity", atomic="search_hash_enterprise", subject_type=_O.SHA256,
                          subjects=f"distinct([lower(h) for h in get(incident.observables_by_type, 'sha256', [])"
                                   f" + flatten([r.attachment_hashes for r in {_MAIL}])])"),
        InvestigationStep(id="post_click_endpoints", atomic="investigate_endpoint", subject_type=_O.HOSTNAME,
                          subjects="distinct(get(incident.observables_by_type, 'hostname', [])"
                                   " + flatten([r.endpoints for r in results.search_domain_enterprise])"
                                   " + flatten([r.endpoints for r in results.search_hash_enterprise]))"),
        InvestigationStep(id="recipients", atomic="investigate_user", subject_type=_O.USER,
                          subjects=f"distinct([lower(u) for u in {_ACTIVE_USERS}"
                                   f" + flatten([r.recipients for r in {_MAIL}])])",
                          max_subjects=50),
        InvestigationStep(id="authentication_after_click", atomic="investigate_authentication",
                          subjects=f"distinct([lower(u) for u in {_ACTIVE_USERS}])"),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links over a 24-hour window: email_to_click (a recipient's endpoint or account reaches a "
            "domain the message carried after delivery), campaign (messages sharing a campaign id, or a sender "
            "domain and a URL or attachment), sign_in_to_activity, and the shared-indicator, shared-user and "
            "shared-endpoint links. The workflow hooks confirm phishing messages (gateway verdict, a rated "
            "indicator, an endpoint detection of the attachment, or a campaign link to a confirmed message), keep "
            "only clicks that reach a rated URL or domain, and tie each click to the successful sign-ins and risk "
            "detections that follow it and to endpoint detections after it."),
        window_minutes=1440,
    ),
    scoring=ScoringInputs(
        description=(
            "Default weights. Each target is scored from the records its rule cites: the gateway's message "
            "verdict (email_verdict), URL, domain, IP and attachment reputation (reputation, capped by the "
            "engine), endpoint detections, DNS and network clicks with a verdict (network_behaviour), identity "
            "risk detections and profile risk (authentication_anomaly), plus one workflow-derived "
            "authentication_anomaly signal for a successful sign-in after a phishing click (attributed to the "
            "identity source and citing the sign-in and click records). Expected sources are the required "
            "integrations; a failed one lowers confidence and never blocks a recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="quarantine_phishing_message",
            description="Quarantine every delivered copy of a confirmed phishing message (campaign included)",
            action=_A.QUARANTINE_EMAIL, builder="quarantine_email",
            for_each="get(facts, 'phishing_messages', [])",
            when="item.delivered",
            target="item.message_id",
            evidence="item.record_ids",
            params={"recipient": "item.recipient"},  # Defender for Office 365 route; the ETD verdict is config
            rationale="item.reason",
            min_risk=60,
            mitre=("T1566.001", "T1566.002"),
        ),
        RecommendationRule(
            id="block_phishing_url",
            description="Block a phishing URL whose host is not itself rated malicious (the domain stays reachable)",
            action=_A.BLOCK_URL, builder="block_url",
            for_each="get(facts, 'phishing_urls', [])",
            target="item.url",
            evidence="item.record_ids",
            rationale="item.reason",
            min_risk=60,
            mitre=("T1566.002", "T1204.001"),
        ),
        RecommendationRule(
            id="block_phishing_domain",
            description="Block a domain carried by the phishing messages that is rated malicious or suspicious",
            action=_A.BLOCK_DOMAIN, builder="block_domain_umbrella",
            for_each="get(facts, 'phishing_domains', [])",
            target="item.domain",
            evidence="item.record_ids",
            rationale="item.reason",
            min_risk=60,
            mitre=("T1566.002", "T1204.001"),
        ),
        RecommendationRule(
            id="block_malicious_attachment",
            description="Block an attachment hash rated malicious or suspicious, or detected on an endpoint",
            action=_A.BLOCK_HASH, builder="block_hash",
            for_each="get(facts, 'malicious_attachments', [])",
            target="item.sha256",
            evidence="item.record_ids",
            rationale="item.reason",
            min_risk=60,
            mitre=("T1566.001", "T1204.002"),
        ),
        RecommendationRule(
            id="revoke_clicked_user_sessions",
            description="Revoke the sign-in sessions of a recipient who clicked and then signed in or was flagged",
            action=_A.REVOKE_SESSIONS, builder="revoke_entra_sessions",
            for_each="get(facts, 'compromised_users', [])",
            target="item.user",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.reason",
            min_risk=60,
            mitre=("T1566.002", "T1078.004"),
        ),
        RecommendationRule(
            id="disable_compromised_user",
            description="Disable an account whose compromise after the click is confirmed or strongly indicated",
            action=_A.DISABLE_USER, builder="disable_entra_user",
            for_each="get(facts, 'compromised_users', [])",
            when="item.disable_justified",
            target="item.user",
            evidence="item.disable_record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.disable_reason",
            min_risk=70,
            mitre=("T1078.004",),
        ),
        RecommendationRule(
            id="isolate_compromised_endpoint",
            description="Isolate a Secure Endpoint managed endpoint with malicious activity after the click",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_secure_endpoint",
            for_each="get(facts, 'compromised_endpoints', [])",
            when="item.product == 'secure_endpoint'",
            target="item.hostname",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}",
            rationale="item.reason",
            min_risk=60,
            mitre=("T1204.001", "T1204.002"),
        ),
        RecommendationRule(
            id="isolate_compromised_defender_endpoint",
            description="Isolate a Defender for Endpoint managed endpoint with malicious activity after the click",
            action=_A.ISOLATE_ENDPOINT, builder="isolate_defender_endpoint",
            for_each="get(facts, 'compromised_endpoints', [])",
            when="item.product == 'defender_endpoint'",
            target="item.hostname",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}",
            rationale="item.reason",
            min_risk=60,
            mitre=("T1204.001", "T1204.002"),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0001", technique="T1566", technique_name="Phishing",
                     sub_technique="T1566.001", sub_technique_name="Spearphishing Attachment",
                     rationale="The message carries a malicious attachment; the workflow quarantines the message "
                               "and blocks the attachment hash."),
        MitreMapping(tactic="TA0001", technique="T1566", technique_name="Phishing",
                     sub_technique="T1566.002", sub_technique_name="Spearphishing Link",
                     rationale="The message carries a credential-phishing link; the workflow quarantines the "
                               "message and blocks the URL or domain."),
        MitreMapping(tactic="TA0002", technique="T1204", technique_name="User Execution",
                     sub_technique="T1204.001", sub_technique_name="Malicious Link",
                     rationale="A recipient clicked the link (DNS or network record after delivery); the workflow "
                               "blocks the destination and isolates an endpoint with malicious activity after it."),
        MitreMapping(tactic="TA0002", technique="T1204", technique_name="User Execution",
                     sub_technique="T1204.002", sub_technique_name="Malicious File",
                     rationale="A recipient opened the attachment (endpoint detection of its hash); the workflow "
                               "blocks the hash and isolates the endpoint."),
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
                     rationale="A successful Entra sign-in after the click indicates harvested credentials in use; "
                               "the workflow revokes sessions and, where justified, disables the account."),
    ),
    known_limitations=(
        "Click and post-click activity are interpreted only from typed DNS, network, endpoint and detection "
        "records; Cisco XDR sightings, Defender XDR hunting rows and Splunk rows stay generic records "
        "(citable, never scored), so in production a click often has to be confirmed by the analyst.",
        "Defender for Office 365 has no VERIFIED read API: it contributes no message records, and its quarantine "
        "needs the networkMessageId as target and exactly one recipient; a message with several recipients "
        "routed there needs manual handling.",
        "Defender for Office 365 remediation cannot be verified through an API (UNABLE_TO_VERIFY); Secure Email "
        "quarantine is verified through the VERIFIED status call.",
        "Revoking sign-in sessions is not reversible; release only records it, and the account-takeover workflow "
        "owns the follow-up review.",
        "Attachment hash blocking on Secure Endpoint file lists is UNVERIFIED: the block routes to Defender for "
        "Endpoint indicators or a configured Cisco XDR native action, otherwise it is reported unrouted for "
        "manual handling.",
        "Each delivered copy is one quarantine action; a large campaign produces many actions and exceeds the "
        "max_messages cap, which makes them ELEVATED (never dropped).",
        "A compromised internal sender is investigated and reported, but account actions on the sender belong to "
        "the account-takeover workflow (hand-off), not to this package.",
    ),
    related_workflows=("account-takeover", "bec", "malware"),
    handoff_to=("account-takeover",),
)
