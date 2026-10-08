"""Business email compromise (``bec``, Phase 2): investigate a mailbox used for fraud and recommend containment.

The workflow investigates the reported messages and the related campaign, the senders and their
domains, the tenant mailboxes involved (profile, mailbox rules, OAuth app consents), their sign-ins
and MFA events, the reputation of the sign-in IPs and the endpoint telemetry of the incident's
hosts. :mod:`xdr_response.workflows.bec.hooks` turns those records into facts (which mailboxes show
compromise or abuse, which messages are fraud, which sender domains impersonate the organisation)
that always carry the record ids they were computed from.

Like every workflow it only **recommends**. Every action below is a ``ProposedAction`` that a human
approves in the Phase 0 lifecycle; ELEVATED approval comes only from ``PackageBuilder`` (critical
assets, ``always_elevated``, blast-radius caps). Removing a malicious inbox rule, revoking an OAuth
consent and blocking a sender at the mail gateway have no VERIFIED write endpoint and no action type:
they are documented manual steps, named in the rationale of the identity actions and in the README.
"""
from __future__ import annotations

from xdr_response.atomics.correlation.models import LinkKind
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

__all__ = ["WORKFLOW", "MANUAL_STEPS"]

#: Steps a human performs outside this framework (no action type and no VERIFIED write endpoint).
MANUAL_STEPS: tuple[str, ...] = (
    "remove the malicious inbox / forwarding rule(s) in the mailbox (no VERIFIED write endpoint)",
    "revoke risky OAuth consent grants of the mailbox (no VERIFIED write endpoint)",
    "block the sender address or domain at the mail gateway (no VERIFIED write endpoint)",
    "reset the password and re-register MFA before re-enabling the account",
    "finance: hold payments to changed bank details until each change is verified by phone with a known contact",
)

_MAIL_SENDERS = ("flatten([r.senders for r in results.investigate_email])"
                 " + flatten([r.senders for r in results.search_email_campaign])")
_MAILBOX_SUBJECTS = ("distinct(incident.users + get(incident.observables_by_type, 'user', [])"
                     " + get(incident.observables_by_type, 'email_address', []) + " + _MAIL_SENDERS + ")")
_IDENTITY_MITRE = ("T1078.004",)

WORKFLOW = WorkflowDefinition(
    id="bec",
    version="1.0.0",
    name="Business email compromise",
    description=(
        "Investigate a mailbox used for payment fraud or impersonation (compromised internal mailbox, "
        "look-alike sender domain, malicious inbox or forwarding rules) and recommend containment: revoke "
        "sessions, disable the account, quarantine the fraudulent messages, block the impersonating domain "
        "and isolate an infected endpoint. Every action needs human approval."
    ),
    phase=2,
    default_severity=Severity.HIGH,
    legacy_id="bec",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident whose ATT&CK techniques name internal spearphishing, an email "
                                "forwarding rule or impersonation",
                    mitre_techniques=("T1534", "T1114.003", "T1656"), priority=110),
        TriggerSpec(type="xdr_incident_rule",
                    description="XDR incident whose title names business email compromise or payment fraud",
                    title_patterns=("*business email compromise*", "BEC *", "* BEC *", "*(BEC)*", "*bank detail*",
                                    "*wire transfer*",
                                    "*payment change*", "*payment request*", "*forwarding rule*", "*inbox rule*"),
                    observable_types=(ObservableType.EMAIL_ADDRESS, ObservableType.EMAIL_MESSAGE_ID,
                                      ObservableType.USER, ObservableType.DOMAIN)),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or a mailbox"),
    ),
    input_observables=(ObservableType.EMAIL_MESSAGE_ID, ObservableType.EMAIL_ADDRESS, ObservableType.USER,
                       ObservableType.DOMAIN, ObservableType.IP, ObservableType.HOSTNAME),
    required_integrations=(
        IntegrationRequirement(integration="entra",
                               purpose="Mailbox account profile, sign-ins and MFA events; revokes sessions and "
                                       "disables the account after approval",
                               atomics=("investigate_user", "investigate_authentication")),
        IntegrationRequirement(integration="secure_email",
                               purpose="Reported and related messages (sender, recipients, verdict, delivery "
                                       "location); quarantines the fraudulent messages after approval",
                               atomics=("investigate_email", "search_email_campaign")),
    ),
    optional_integrations=(
        IntegrationRequirement(integration="umbrella",
                               purpose="Sender-domain reputation; DNS-layer block of the impersonating domain "
                                       "after approval",
                               atomics=("enrich_domain",)),
        IntegrationRequirement(integration="virustotal",
                               purpose="Second opinion on sender-domain and sign-in IP reputation (public "
                                       "values only, disclosure policy)",
                               atomics=("enrich_domain", "enrich_ip")),
        IntegrationRequirement(integration="cisco_xdr",
                               purpose="XDR enrichment and native response actions where configured",
                               atomics=("enrich_domain", "enrich_ip", "enrich_email_address", "investigate_user",
                                        "investigate_email", "investigate_endpoint")),
        IntegrationRequirement(integration="microsoft_cloud",
                               purpose="Defender XDR alerts and hunting rows about the mailboxes and messages "
                                       "(cited as context)",
                               atomics=("investigate_user", "investigate_authentication", "investigate_email",
                                        "search_email_campaign")),
        IntegrationRequirement(integration="defender_o365",
                               purpose="Alternative executor for quarantining messages (no read path used)"),
        IntegrationRequirement(integration="secure_endpoint",
                               purpose="Endpoint telemetry of the incident's hosts; isolates an infected "
                                       "endpoint after approval",
                               atomics=("investigate_endpoint",)),
        IntegrationRequirement(integration="splunk",
                               purpose="SIEM rows about sign-ins, mailbox activity and messages (cited as context)",
                               atomics=("investigate_user", "investigate_authentication", "investigate_email")),
    ),
    investigation=(
        InvestigationStep(id="reported_messages", atomic="investigate_email"),
        InvestigationStep(id="related_messages", atomic="search_email_campaign"),
        InvestigationStep(
            id="sender_addresses", atomic="enrich_email_address",
            subjects=f"distinct(get(incident.observables_by_type, 'email_address', []) + {_MAIL_SENDERS})",
            subject_type=ObservableType.EMAIL_ADDRESS),
        InvestigationStep(
            id="sender_domains", atomic="enrich_domain",
            subjects=("distinct(get(incident.observables_by_type, 'domain', [])"
                      " + [m.sender_domain for m in flatten([r.messages for r in results.investigate_email])]"
                      " + [m.sender_domain for m in flatten([r.messages for r in results.search_email_campaign])])"),
            subject_type=ObservableType.DOMAIN),
        InvestigationStep(id="mailboxes", atomic="investigate_user", subjects=_MAILBOX_SUBJECTS,
                          subject_type=ObservableType.USER, lookback_hours=72),
        InvestigationStep(id="sign_ins", atomic="investigate_authentication", subjects=_MAILBOX_SUBJECTS,
                          subject_type=ObservableType.USER, lookback_hours=72),
        InvestigationStep(
            id="sign_in_ips", atomic="enrich_ip",
            subjects=("distinct(get(incident.observables_by_type, 'ip', [])"
                      " + [s.ip for s in flatten([r.signins for r in results.investigate_authentication])"
                      " if s.result == 'success' and s.ip]"
                      " + [e.ip for e in flatten([r.mfa_events for r in results.investigate_authentication])"
                      " if e.result == 'approved' and e.ip])"),
            subject_type=ObservableType.IP),
        InvestigationStep(id="endpoints", atomic="investigate_endpoint"),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links over the run's records within 4 hours: a successful sign-in followed by a "
            "mailbox rule or OAuth consent for the same user (sign_in_to_activity), messages sharing a "
            "campaign id or sender domain plus URL or attachment (campaign), and indicators shared by "
            "several users or endpoints (same_ip, same_domain, same_user, same_endpoint). The workflow hook "
            "links a tenant mailbox (user) to the same address as a message sender, so the account and the "
            "fraud it sent form one cluster."),
        link_kinds=(LinkKind.SIGN_IN_TO_ACTIVITY, LinkKind.CAMPAIGN, LinkKind.SAME_IP, LinkKind.SAME_DOMAIN,
                    LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT, LinkKind.EMAIL_TO_CLICK),
        window_minutes=240,
    ),
    scoring=ScoringInputs(
        description=(
            "Per target, from the records the rule cites: identity risk (Entra risk state, anomalies, and the "
            "hook signal 'successful sign-in or approved MFA from an IP rated malicious or suspicious'), "
            "mailbox persistence (external forwarding or deleting rules, risky OAuth consents), the mail "
            "gateway's message verdict, the hook signal 'sender domain is a look-alike of an organisation "
            "domain', sign-in IP and domain reputation (capped by the engine) and endpoint detections. "
            "Persistence and email verdicts weigh 0.9 because forwarding rules and gateway verdicts are the "
            "core of BEC. Risk and confidence are separate; a failed source lowers confidence only."),
        weights={SignalCategory.PERSISTENCE: 0.9, SignalCategory.EMAIL_VERDICT: 0.9},
    ),
    recommendations=(
        RecommendationRule(
            id="revoke_compromised_mailbox_sessions",
            description="Revoke the sign-in sessions of a tenant mailbox with compromise or abuse evidence",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="facts.mailboxes",
            when="item.identity_compromise or item.abuse",
            target="item.user",
            evidence="item.profile_record_ids + item.identity_record_ids + item.abuse_record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale=("'mailbox ' + item.user + ' shows ' + item.summary"
                       " + (('; manual step after approval: ' + item.manual_steps) if item.manual_steps else '')"),
            min_risk=40,
            mitre=_IDENTITY_MITRE,
        ),
        RecommendationRule(
            id="disable_abused_mailbox",
            description="Disable a tenant mailbox account with compromise evidence and ongoing abuse "
                        "(malicious mailbox rule, risky OAuth consent or fraud sent)",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="facts.mailboxes",
            when="item.identity_compromise and item.abuse",
            target="item.user",
            evidence="item.profile_record_ids + item.identity_record_ids + item.abuse_record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale=("'compromised mailbox ' + item.user + ' with ongoing abuse: ' + item.summary"
                       " + (('; manual step after approval: ' + item.manual_steps) if item.manual_steps else '')"),
            min_risk=50,
            mitre=("T1078.004", "T1114.003", "T1564.008", "T1534"),
        ),
        RecommendationRule(
            id="quarantine_fraud_messages",
            description="Quarantine a delivered fraudulent message (sent by a compromised mailbox, flagged by "
                        "the mail gateway or sent from a look-alike domain)",
            action=ActionType.QUARANTINE_EMAIL,
            builder="quarantine_email",
            for_each="facts.fraud_messages",
            target="item.message_id",
            evidence="item.record_ids",
            params={"recipient": "item.recipient"},  # Defender for Office 365 route; the ETD verdict is config
            rationale="'message ' + item.message_id + ' from ' + item.sender + ': ' + item.summary",
            min_risk=40,
            mitre=("T1534", "T1656"),
        ),
        RecommendationRule(
            id="block_impersonation_domain",
            description="Block (DNS layer) a sender domain that impersonates the organisation or was flagged "
                        "by the mail gateway, unless its reputation is clean",
            action=ActionType.BLOCK_DOMAIN,
            for_each="facts.impersonation_domains",
            when="get(get(enrichment, 'domain:' + item.domain, {}), 'verdict', 'UNKNOWN') != 'CLEAN'",
            target="item.domain",
            evidence="item.record_ids",
            rationale=("'sender domain ' + item.domain + ': ' + item.summary"
                       " + '; manual step: block the sender domain at the mail gateway as well'"),
            min_risk=40,
            mitre=("T1656",),
        ),
        RecommendationRule(
            id="isolate_infected_endpoint",
            description="Isolate an investigated endpoint with an active malicious detection",
            action=ActionType.ISOLATE_ENDPOINT,
            for_each="results.investigate_endpoint",
            when="any(d.verdict == 'MALICIOUS' and d.status != 'resolved' for d in item.detections)",
            target="item.hostname",
            evidence="ids([d for d in item.detections if d.verdict in ['MALICIOUS', 'SUSPICIOUS']])",
            asset="{'groups': item.groups, 'tags': item.tags, 'ip': item.ip_addresses[0] if item.ip_addresses else None}",
            rationale="'active malicious detection on ' + item.hostname + ' (endpoint telemetry of the incident)'",
            min_risk=60,
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
                     rationale="The fraud is sent from a tenant mailbox whose cloud credentials or session the "
                               "adversary uses; session revocation and account disable respond to it."),
        MitreMapping(tactic="TA0009", technique="T1114", technique_name="Email Collection",
                     sub_technique="T1114.003", sub_technique_name="Email Forwarding Rule",
                     rationale="Mailbox rules forwarding or redirecting mail outside the organisation are "
                               "investigated and count as ongoing abuse of the mailbox."),
        MitreMapping(tactic="TA0005", technique="T1564", technique_name="Hide Artifacts",
                     sub_technique="T1564.008", sub_technique_name="Email Hiding Rules",
                     rationale="Mailbox rules that delete messages hide the victim's replies from the owner; "
                               "they count as ongoing abuse of the mailbox."),
        MitreMapping(tactic="TA0008", technique="T1534", technique_name="Internal Spearphishing",
                     rationale="A compromised internal mailbox sends payment-change or fraud requests to "
                               "colleagues; those messages are quarantined."),
        MitreMapping(tactic="TA0005", technique="T1656", technique_name="Impersonation",
                     rationale="A look-alike or gateway-flagged sender domain impersonates the organisation, an "
                               "executive or a vendor; its messages are quarantined and the domain is blocked."),
    ),
    known_limitations=(
        "No action type and no VERIFIED write endpoint exist for removing a mailbox rule, revoking an OAuth "
        "consent or blocking a sender at the mail gateway: these are manual steps named in the rationale and "
        "the README.",
        "Mailbox rules, OAuth app consents and typed message records come only from sources whose field "
        "schema is documented; with today's real adapters Secure Email message search, Splunk rows and "
        "Defender hunting rows stay generic records (cited, never scored), so the quarantine and domain "
        "rules need typed message records.",
        "Password and MFA-method changes have no record kind yet; they appear only as generic records and "
        "are not scored.",
        "Look-alike detection is a deterministic heuristic over the registrable label (homoglyph digits, "
        "one edit, organisation name as a hyphenated token); it does not handle internationalised (IDN) "
        "domains or public suffixes beyond common two-level ones.",
        "Quarantine through Secure Email takes its move verdict from integrations.secure_email.options."
        "quarantine_verdict and through Defender for Office 365 needs the message's single recipient; without "
        "them the quarantine is reported unrouted for manual handling (the workflow never invents either).",
        "The DNS-layer domain block stops users and endpoints from reaching the domain; it does not stop "
        "inbound mail from it. Free-mail and partner domains must be in allowlists.never_block.domains, "
        "otherwise a gateway-flagged message can lead to a (human-reviewed) block recommendation.",
        "Only the senders, incident users and incident addresses are investigated as mailboxes; recipients "
        "who replied or paid are not investigated automatically.",
    ),
    related_workflows=("account-takeover", "phishing", "mfa-fatigue"),
    handoff_to=("account-takeover",),
)
