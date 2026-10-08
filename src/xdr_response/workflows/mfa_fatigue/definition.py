"""Workflow ``mfa-fatigue`` (Phase 2, new; seeded from ``account-takeover/05-mfa-fatigue-approved``).

An attacker who already holds a user's password requests MFA push prompts repeatedly until the user
approves one, then signs in. The workflow investigates the user, the prompt source IPs, their
location and reputation, the device and endpoint, and the actions taken after the approval, and
RECOMMENDS a containment package: revoke the user's sessions, disable the account when the
compromise went further, isolate a compromised endpoint, and block the prompt source IP.

It only investigates and recommends. Every action needs a human approval; after approval the
lifecycle orchestrator executes, verifies and (with a separate human release approval) restores.
The pattern itself is computed by the pure hooks in :mod:`.hooks`.
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

_USER_ASSET = "{'groups': item.groups, 'roles': item.roles}"

WORKFLOW = WorkflowDefinition(
    id="mfa-fatigue",
    version="1.0.0",
    name="MFA fatigue",
    description=(
        "Respond to MFA fatigue (push bombing): many MFA prompts for one user, most rejected or "
        "unanswered, then one approved and followed by a sign-in. The workflow investigates the user, "
        "the prompt source IPs (location and reputation), the device and endpoint, and what the "
        "session did after the approval, and recommends revoking the sessions, disabling the account "
        "when the compromise went further, isolating a compromised endpoint and blocking the prompt "
        "source IP. A human approves every action."
    ),
    phase=2,
    default_severity=Severity.HIGH,
    triggers=(
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident whose detection reports ATT&CK T1621 (MFA request generation) "
                        "for a user",
            mitre_techniques=("T1621",),
            observable_types=(ObservableType.USER,),
            priority=200,
        ),
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident titled as an MFA fatigue, push bombing or push spam pattern",
            title_patterns=("*mfa fatigue*", "*mfa push*", "*push bombing*", "*push spam*", "*mfa bombing*",
                            "*mfa spam*"),
            priority=200,
        ),
        TriggerSpec(type="manual", description="An analyst runs the workflow for an incident or a user observable"),
    ),
    input_observables=(ObservableType.USER, ObservableType.IP, ObservableType.HOSTNAME),
    required_integrations=(
        IntegrationRequirement(
            integration="entra",
            purpose="Sign-ins, MFA results, user profile and roles, post-authentication activity; executes the "
                    "approved revoke_sessions and disable_user",
            atomics=("investigate_authentication", "investigate_user", "search_user_activity"),
        ),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts on the user, the source IP and the endpoint (alerts_v2)",
            atomics=("investigate_authentication", "investigate_user", "search_user_activity", "investigate_ip",
                     "investigate_endpoint"),
        ),
        IntegrationRequirement(
            integration="splunk",
            purpose="SIEM sign-in and activity rows (cited as generic records, never scored)",
            atomics=("investigate_authentication", "search_user_activity", "investigate_ip"),
        ),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Incident context, IP reputation and sightings; native response route when configured",
            atomics=("enrich_ip", "investigate_user", "investigate_ip", "investigate_endpoint"),
        ),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Third-party IP reputation (public addresses only, disclosure policy)",
            atomics=("enrich_ip",),
        ),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Third-party IP reputation (public addresses only, disclosure policy)",
            atomics=("enrich_ip",),
        ),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint detections and trajectory of the user's device; executes an approved isolation",
            atomics=("investigate_endpoint",),
        ),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Endpoint alerts and timeline of the user's device; executes an approved isolation",
            atomics=("investigate_endpoint",),
        ),
        IntegrationRequirement(
            integration="meraki",
            purpose="Executes an approved block_ip as a tagged MX L3 firewall rule (no read atomic)",
        ),
    ),
    investigation=(
        InvestigationStep(id="authentication", atomic="investigate_authentication", max_subjects=10),
        InvestigationStep(id="user_profile", atomic="investigate_user", max_subjects=10),
        InvestigationStep(id="post_authentication_activity", atomic="search_user_activity", max_subjects=10),
        InvestigationStep(id="source_ip_reputation", atomic="enrich_ip"),
        InvestigationStep(id="source_ip_activity", atomic="investigate_ip"),
        InvestigationStep(id="endpoint", atomic="investigate_endpoint", max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links over the window (same user, same IP, same endpoint, sign-in to activity) plus "
            "workflow links: each user to every IP that sent them rejected or unanswered prompts, and each "
            "compromised user to an endpoint tied to the compromise (used by that user, or with a "
            "malicious detection for that user, or connecting to an MFA prompt source IP)."
        ),
        window_minutes=60,
    ),
    scoring=ScoringInputs(
        description=(
            "Sign-in and MFA records give no framework signal, so the hooks derive authentication-anomaly "
            "signals that cite them: MALICIOUS 85 for a prompt approved after at least 3 rejected or unanswered "
            "prompts within 60 minutes and followed by a successful sign-in (75 without the sign-in record), "
            "SUSPICIOUS 60 for prompts without an approval, MALICIOUS 80 or SUSPICIOUS 60 for the source IP, "
            "and network-behaviour SUSPICIOUS 70 for an endpoint connecting to a prompt source. Vendor "
            "anomalies, risky-user state, post-authentication mailbox rules and role grants, endpoint "
            "detections and IP reputation add their framework signals; the engine applies the caps."
        ),
    ),
    recommendations=(
        RecommendationRule(
            id="revoke_sessions_after_fatigue_approval",
            description="Revoke every sign-in session of a user who approved a prompt after repeated rejected "
                        "or unanswered prompts (the attacker holds a session).",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="get(facts, 'compromised_users', [])",
            target="item.user",
            evidence="item.record_ids",
            asset=_USER_ASSET,
            rationale="item.summary",
            min_risk=60,
            mitre=("T1621", "T1078.004"),
        ),
        RecommendationRule(
            id="disable_compromised_account",
            description="Disable the account of a compromised user when the session went further: "
                        "post-authentication mailbox rules, role grants or app consents, a privileged "
                        "account, an identity-provider high or confirmed risk, or a new attacker sign-in "
                        "after sessions were revoked.",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="[u for u in get(facts, 'compromised_users', []) if len(u.disable_reasons) > 0]",
            target="item.user",
            evidence="item.record_ids + item.disable_record_ids",
            asset=_USER_ASSET,
            rationale="item.summary + '; disable because: ' + item.disable_summary",
            min_risk=60,
            mitre=("T1621", "T1078.004", "T1114.003", "T1098.003"),
        ),
        RecommendationRule(
            id="isolate_compromised_endpoint",
            description="Isolate an endpoint tied to the compromise (used by the compromised user or connecting "
                        "to a prompt source IP) that shows a malicious or suspicious detection, process or "
                        "connection.",
            action=ActionType.ISOLATE_ENDPOINT,
            for_each="get(facts, 'endpoints', [])",
            target="item.hostname",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}",
            rationale="item.summary",
            min_risk=60,
        ),
        RecommendationRule(
            id="block_mfa_prompt_source_ip",
            description="Block a public IP that sent at least 3 rejected or unanswered prompts and that no "
                        "reputation source rates clean.",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="[p for p in get(facts, 'source_ips', []) if p.unsuccessful >= facts.min_unsuccessful_prompts "
                     "and not p.internal]",
            when="get(get(enrichment, item.enrichment_key, {}), 'verdict', 'UNKNOWN') != 'CLEAN'",
            target="item.ip",
            evidence="item.record_ids",
            rationale="item.summary",
            min_risk=60,
            mitre=("T1621",),
        ),
        RecommendationRule(
            id="block_malicious_signin_ip",
            description="Block an IP rated malicious or suspicious from which the compromised user signed in "
                        "after the approved prompt.",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="[r for r in results.enrich_ip if r.verdict in ['MALICIOUS', 'SUSPICIOUS'] "
                     "and r.value in get(facts, 'compromise_signin_ips', [])]",
            target="item.value",
            evidence="get(get(facts, 'signin_ids_by_ip', {}), item.value, [])",
            rationale="'sign-in after the approved MFA prompt came from ' + item.value + ', rated ' + item.verdict",
            min_risk=60,
            mitre=("T1078.004",),
        ),
    ),
    mitre=(
        MitreMapping(
            tactic="TA0006", technique="T1621", technique_name="Multi-Factor Authentication Request Generation",
            rationale="The trigger and the core pattern: repeated MFA prompts until the user approves one.",
        ),
        MitreMapping(
            tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
            sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
            rationale="After the approval the attacker signs in to the cloud identity with the valid account; "
                      "revoking the sessions and blocking the sign-in IP respond to it.",
        ),
        MitreMapping(
            tactic="TA0009", technique="T1114", technique_name="Email Collection",
            sub_technique="T1114.003", sub_technique_name="Email Forwarding Rule",
            rationale="A forwarding or redirect rule created after the approval is investigated and is a reason "
                      "to recommend disabling the account.",
        ),
        MitreMapping(
            tactic="TA0003", technique="T1098", technique_name="Account Manipulation",
            sub_technique="T1098.003", sub_technique_name="Additional Cloud Roles",
            rationale="A directory role granted after the approval is investigated and is a reason to recommend "
                      "disabling the account.",
        ),
    ),
    known_limitations=(
        "The real Entra sign-in normalizer does not map MFA details yet (no MFA event records, mfa_result "
        "unknown) and Entra ID Protection risk detections are not normalized, so with production adapters the "
        "pattern is only found when another source supplies typed MFA records; otherwise nothing is proposed "
        "and the run notes say why.",
        "There is no adapter for a third-party MFA provider (for example Duo); push logs from such a provider "
        "are not investigated.",
        "Thresholds (3 rejected or unanswered prompts within 60 minutes, sign-in from 10 minutes before to "
        "60 minutes after the approval) are fixed in the workflow hooks, not configurable per tenant.",
        "revoke_sessions is not reversible, is not in the Cisco XDR native catalog (direct Entra call only), can "
        "take a few minutes to apply and does not affect external users.",
        "Password reset and MFA re-registration are not proposed; they stay a manual help-desk step after out "
        "of band identity verification.",
        "Post-authentication actions without a timestamp are not attributed to the attacker.",
        "Isolation needs an enabled EDR executor; with only cisco_xdr enabled the isolation is reported as "
        "unrouted for manual handling.",
        "A prompt source IP can be shared infrastructure (mobile carrier NAT, cloud egress); only allow-listed "
        "IPs are excluded automatically, so the analyst reviews the block.",
    ),
    related_workflows=("account-takeover", "password-spray", "suspicious-authentication"),
    handoff_to=("account-takeover",),
)
