"""``mail-bombing``: respond to an email or subscription bombing flood (Phase 2, architecture 14.5).

The flood is treated as concealment. The workflow measures the flood (volume, window, sender
distribution and domains, the targeted mailbox, message characteristics), searches the flood window
for the messages it was meant to bury (password reset or change, security alert, new sign-in or
device, MFA, wire transfer, invoice, banking, DocuSign, Microsoft, account recovery), then checks the
recipient's identity (Entra sign-ins, MFA, risk detections, mailbox and forwarding rules, role
changes) and endpoint telemetry after the flood started.

It only investigates and recommends. The containment package (quarantine the flood, revoke sessions,
disable the account, isolate the endpoint, block malicious domains) is built from record-backed
evidence and goes to a human through the Phase 0 lifecycle; nothing executes before that approval.
Compatible with incidents raised by the separate ``cisco-xdr-mailbomb-detector`` project (its webhook
payload, ``event_type``, ``recipient`` and ``metrics``, is read from ``incident.trigger``).
"""
from __future__ import annotations

from xdr_response.models import ActionType, ObservableType, Severity
from xdr_response.models.scoring import SignalCategory
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
from xdr_response.workflows.mail_bombing.hooks import DETECTOR_SOURCE

#: The targeted mailboxes as user principal names: incident users, email-address and user
#: observables and the detector's ``recipient`` (identity atomics accept ``user`` subjects only).
RECIPIENTS = (
    "distinct([lower(u) for u in incident.users + get(incident.observables_by_type, 'email_address', [])"
    " + get(incident.observables_by_type, 'user', [])"
    " + ([incident.trigger.recipient] if get(incident.trigger, 'recipient') else [])])"
)

#: Domains worth a reputation lookup: incident domains, domains of flood messages that carry a threat
#: verdict, and domains the recipient's endpoints resolved or contacted with a threat verdict.
#: Neutral newsletter senders of the flood are not looked up (no decision depends on them).
DOMAINS = (
    "distinct([lower(d) for d in get(incident.observables_by_type, 'domain', [])"
    " + flatten([flatten([m.domains + ([m.sender_domain] if m.sender_domain else [])"
    " for m in r.messages if m.verdict in ['MALICIOUS', 'SUSPICIOUS']]) for r in results.search_email_campaign])"
    " + flatten([[q.domain for q in r.dns_queries if q.verdict in ['MALICIOUS', 'SUSPICIOUS']]"
    " for r in results.investigate_endpoint])"
    " + flatten([[c.domain for c in r.network_connections if c.domain and c.verdict in ['MALICIOUS', 'SUSPICIOUS']]"
    " for r in results.investigate_endpoint])])"
)

WORKFLOW = WorkflowDefinition(
    id="mail-bombing",
    version="1.0.0",
    name="Mail bombing",
    description=(
        "Respond to an email or subscription bombing flood as concealment: measure the flood, search its "
        "window for the buried security, identity and payment messages, check the recipient's identity and "
        "endpoint for the follow-up, and recommend a containment package (quarantine the flood, revoke "
        "sessions, disable the account, isolate the endpoint, block malicious domains) for human approval."
    ),
    phase=2,
    default_severity=Severity.HIGH,
    legacy_id="mail-bombing",
    triggers=(
        TriggerSpec(type="webhook", priority=200,
                    description="Incident raised by the cisco-xdr-mailbomb-detector project (its webhook payload "
                                "is carried in incident.trigger)",
                    sources=(DETECTOR_SOURCE,)),
        TriggerSpec(type="xdr_incident_rule", priority=150,
                    description="XDR incident tagged with Email Bombing that names a mailbox",
                    mitre_techniques=("T1667",), observable_types=(ObservableType.EMAIL_ADDRESS, ObservableType.USER)),
        TriggerSpec(type="xdr_incident_rule", priority=120,
                    description="XDR incident whose title names an email, mail or subscription bombing",
                    title_patterns=("*email bomb*", "*mail bomb*", "*mail-bomb*", "*subscription bomb*",
                                    "*mail flood*"),
                    observable_types=(ObservableType.EMAIL_ADDRESS, ObservableType.USER)),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or a mailbox"),
    ),
    input_observables=(ObservableType.EMAIL_ADDRESS, ObservableType.USER, ObservableType.EMAIL_MESSAGE_ID,
                       ObservableType.HOSTNAME, ObservableType.DOMAIN),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_email",
            purpose="Flood messages to the recipient (volume, senders, verdicts, subjects) and the buried "
                    "messages of interest; executes the approved quarantine",
            atomics=("search_email_campaign",)),
        IntegrationRequirement(
            integration="entra",
            purpose="Recipient profile, sign-ins, MFA events, risk detections and mailbox rules inside the "
                    "flood window; executes approved session revocation and account disable",
            atomics=("investigate_user", "investigate_authentication", "search_user_activity")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="User and endpoint context and verdicts from the XDR platform",
            atomics=("investigate_user", "investigate_endpoint", "enrich_domain")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts and hunting results about the recipient, the flood and the endpoint",
            atomics=("search_email_campaign", "investigate_user", "investigate_authentication",
                     "search_user_activity", "investigate_endpoint")),
        IntegrationRequirement(
            integration="splunk",
            purpose="Mail gateway and identity logs indexed in the SIEM",
            atomics=("search_email_campaign", "investigate_user", "investigate_authentication",
                     "search_user_activity", "investigate_endpoint")),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Detections and trajectory on the recipient's endpoint after the flood started "
                    "(remote-access tooling pushed by a fake IT-support contact)",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Device facts and alerts on the recipient's endpoint after the flood started",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="intune",
            purpose="Managed-device facts of the recipient's endpoint",
            atomics=("investigate_endpoint",)),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain categorization of lure and flood domains with a threat verdict",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Second opinion on domain reputation (public domains only, disclosure policy applies)",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Third opinion on domain reputation (public domains only, disclosure policy applies)",
            atomics=("enrich_domain",)),
    ),
    investigation=(
        InvestigationStep(id="flood_messages", atomic="search_email_campaign", max_subjects=5),
        InvestigationStep(id="recipient_profile", atomic="investigate_user", subjects=RECIPIENTS,
                          subject_type=ObservableType.USER, max_subjects=5),
        InvestigationStep(id="recipient_sign_ins", atomic="investigate_authentication", subjects=RECIPIENTS,
                          subject_type=ObservableType.USER, max_subjects=5),
        InvestigationStep(id="recipient_activity", atomic="search_user_activity", subjects=RECIPIENTS,
                          subject_type=ObservableType.USER, max_subjects=5),
        InvestigationStep(id="recipient_endpoints", atomic="investigate_endpoint", max_subjects=5),
        InvestigationStep(id="domain_reputation", atomic="enrich_domain", subjects=DOMAINS,
                          subject_type=ObservableType.DOMAIN, max_subjects=25),
    ),
    correlation=CorrelationSpec(
        description=(
            "The flood window comes from the detector metrics (window_start, window_end) or, without them, from "
            "the first and last observed flood message. Framework links tie the recipient to sign-ins followed by "
            "mailbox rules (sign_in_to_activity), flood messages to clicks on their domains (email_to_click) and "
            "messages sharing a sender domain and URL (campaign). The hooks add the concealment view: messages "
            "inside the window whose subject names a credential, security-alert, MFA, payment or lure topic are "
            "buried messages; identity events, takeover indications and endpoint detections at or after the "
            "window start are tied to the flood."),
        window_minutes=240,
    ),
    scoring=ScoringInputs(
        description=(
            "Each target is scored from the records its rule cites. A message of a qualifying flood carries a "
            "campaign_association pattern (severity 70, confidence 80 with detector metrics, 70 without); its own "
            "gateway verdict is an email_verdict signal (a malicious lure scores higher, a neutral one lowers "
            "confidence by contradiction). The recipient carries authentication_anomaly patterns for identity "
            "events inside the flood window (75), buried credential or MFA notifications (60) and takeover "
            "indications (85), next to the vendor risk detections. Endpoint detections and domain reputation "
            "use the framework signals; reputation alone is capped by the engine. Risk and confidence are "
            "separate; a failed expected source lowers confidence and never blocks other evidence."),
        expected_sources=("secure_email", "entra"),
    ),
    recommendations=(
        RecommendationRule(
            id="quarantine_flood_messages",
            description="Quarantine the neutral and graymail messages of a qualifying flood and the malicious "
                        "messages hidden in it; buried messages of interest stay in the mailbox for the analyst",
            action=ActionType.QUARANTINE_EMAIL,
            builder="quarantine_email",
            for_each="facts.flood_messages",
            when="facts.flood.qualifies",
            target="item.message_id",
            evidence="item.record_ids",
            params={"recipient": "item.recipient"},  # Defender for Office 365 route; the ETD verdict is config
            include_target_enrichment=False,
            rationale="'mail flood message (' + item.verdict + ' from ' + (item.sender_domain or 'unknown sender') "
                      "+ '): ' + facts.flood.summary",
            min_risk=30,
            mitre=("T1667",),
        ),
        RecommendationRule(
            id="revoke_sessions_buried_identity_event",
            description="Revoke the recipient's sessions when an identity event (MFA prompt, risky sign-in, risk "
                        "detection, new mailbox rule, credential or security notification) happened inside the "
                        "flood window",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="facts.identity_events",
            target="item.user",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="'identity event(s) inside the mail flood window: ' + facts.flood.summary",
            min_risk=50,
            mitre=("T1621", "T1078.004"),
        ),
        RecommendationRule(
            id="disable_account_on_takeover",
            description="Disable the recipient's account when the flood hid a successful high-risk sign-in, an "
                        "MFA approval after denied prompts or a mailbox rule that hides or forwards mail",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="facts.takeover",
            target="item.user",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="'account takeover indication inside the mail flood window: ' + facts.flood.summary",
            min_risk=60,
            mitre=("T1078.004", "T1564.008"),
        ),
        RecommendationRule(
            id="isolate_recipient_endpoint",
            description="Isolate the recipient's endpoint when it shows a malicious or suspicious detection at "
                        "or after the flood window start (for example remote-access tooling pushed by a fake "
                        "IT-support contact)",
            action=ActionType.ISOLATE_ENDPOINT,
            for_each="facts.endpoint_activity",
            target="item.hostname",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}",
            rationale="'endpoint detection at or after the mail flood started on ' + item.hostname",
            min_risk=60,
            mitre=("T1219",),
        ),
        RecommendationRule(
            id="block_malicious_flood_domain",
            description="Block a domain rated malicious that a flood message carried or the recipient's endpoint "
                        "contacted after the flood started",
            action=ActionType.BLOCK_DOMAIN,
            for_each="facts.malicious_domains",
            target="item.domain",
            evidence="item.record_ids",
            include_target_enrichment=False,
            rationale="'domain rated ' + item.verdict + ' in the mail flood or contacted after it started'",
            min_risk=50,
            mitre=("T1566",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0040", technique="T1667", technique_name="Email Bombing",
                     rationale="The incident is a flood of messages to one mailbox; the workflow quarantines it."),
        MitreMapping(tactic="TA0005", technique="T1656", technique_name="Impersonation",
                     rationale="Mail bombing is the pretext for a fake IT-support contact; the workflow warns and "
                               "checks the identity and endpoint for its outcome."),
        MitreMapping(tactic="TA0006", technique="T1621",
                     technique_name="Multi-Factor Authentication Request Generation",
                     rationale="MFA prompts inside the flood window are the buried events that revoke sessions."),
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
                     rationale="A risky or successful sign-in to the recipient's Entra account during the flood "
                               "means the account may be used by someone else."),
        MitreMapping(tactic="TA0005", technique="T1564", technique_name="Hide Artifacts",
                     sub_technique="T1564.008", sub_technique_name="Email Hiding Rules",
                     rationale="A mailbox rule created during the flood that moves, deletes or forwards mail "
                               "hides the security notifications the flood is burying."),
        MitreMapping(tactic="TA0011", technique="T1219", technique_name="Remote Access Tools",
                     rationale="Remote-access tooling installed after the flood (the fake IT-support follow-up) "
                               "is the endpoint detection that drives isolation."),
        MitreMapping(tactic="TA0001", technique="T1566", technique_name="Phishing",
                     rationale="Lure messages rated malicious hidden in the flood give the domains to block."),
    ),
    known_limitations=(
        "The production flood search is not automatic yet: the Secure Email Threat Defense message search "
        "(VERIFIED) needs a search body with a time range and a recipient, which a static step option cannot "
        "carry, and its message fields are not documented in docs/integrations.md, so messages would only be "
        "generic records. Until the contract change lands, the analyst runs the recipient search in the Secure "
        "Email console (or the detector's ContainBurst workflow) and the quarantine rule proposes nothing "
        "without typed message records.",
        "The flood search needs a seed message id (an email_message_id observable on the incident); detector "
        "incidents carry the recipient and metrics only.",
        "Password resets and changes and MFA method registrations from the Entra directory audit log have no "
        "record kind and the directoryAudits read is not in docs/integrations.md; they are seen only as buried "
        "notification messages, sign-ins, MFA events and risk detections.",
        "Buried messages are recognised by subject keywords only (credential, security alert, MFA, payment, "
        "DocuSign or Microsoft lure); a buried message with another subject stays in the quarantine set and is "
        "listed in the evidence for the approver.",
        "Recipient addresses are used as user principal names; an alias or shared mailbox that differs from "
        "the UPN gets no identity results.",
        "Release from quarantine through Defender for Office 365 is UNVERIFIED; quarantine release is "
        "executed through Secure Email only, and session revocation cannot be undone.",
        "With detector metrics the flood qualification relies on the detector's counts for the whole burst; "
        "the quarantine set is limited to the messages the search returned.",
    ),
    related_workflows=("unauthorized-rmm", "account-takeover", "mfa-fatigue", "phishing"),
    handoff_to=("account-takeover", "unauthorized-rmm", "phishing"),
)
