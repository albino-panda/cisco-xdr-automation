"""Account takeover (Phase 2): an attacker signs in with valid credentials or a stolen session.

The workflow investigates the account (Entra user profile and session state, sign-ins, MFA activity,
vendor risk detections, post-sign-in cloud activity), the sign-in source IPs (reputation and enterprise
prevalence) and the user's endpoints named by the incident, then *recommends* a containment package:
revoke the account's sessions, disable the account when it is privileged or the attacker came back
after a revocation, isolate a linked endpoint with an active malicious detection, and block the
attacker sign-in IP.

It only investigates and recommends. Every action needs a human approval (ELEVATED for critical
assets, applied by ``PackageBuilder``); execution, verification and release happen in the Phase 0
lifecycle after that approval. The compromise logic lives in :mod:`.hooks` (pure, record-backed facts).
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

__all__ = ["WORKFLOW", "USER_SUBJECTS", "ENDPOINT_SUBJECTS"]

#: Investigated accounts: the incident's users and user observables (normalized, sorted, unique).
USER_SUBJECTS = ("distinct([lower(u) for u in incident.users] + "
                 "[lower(u) for u in get(incident.observables_by_type, 'user', [])])")
#: Investigated endpoints: hostnames the incident names (observables and endpoint assets).
ENDPOINT_SUBJECTS = ("distinct(get(incident.observables_by_type, 'hostname', []) + "
                     "[a.name for a in incident.assets if a.kind == 'ENDPOINT'])")

WORKFLOW = WorkflowDefinition(
    id="account-takeover",
    version="2.0.0",
    name="Account takeover",
    description=(
        "Respond to a sign-in by an attacker using valid credentials or a stolen session: investigate the "
        "account's sign-ins, MFA activity, identity risk and cloud activity, the reputation and enterprise "
        "prevalence of the sign-in source IPs and the user's endpoints, then recommend revoking sessions, "
        "disabling the account, isolating a linked infected endpoint and blocking the attacker IP. Every "
        "action waits for a human approval."
    ),
    phase=2,
    default_severity=Severity.HIGH,
    legacy_id="account-takeover",
    triggers=(
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident whose detections report cloud-account abuse or a stolen web session",
            mitre_techniques=("T1078.004", "T1539"),
            observable_types=(ObservableType.USER,),
            priority=100,
        ),
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident titled as a risky, unfamiliar or impossible-travel sign-in for a user",
            title_patterns=("*risky sign-in*", "*high-risk sign-in*", "*impossible travel*", "*atypical travel*",
                            "*unfamiliar sign-in*", "*account takeover*", "*token replay*"),
            observable_types=(ObservableType.USER,),
            priority=90,
        ),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or a user pivot"),
    ),
    input_observables=(ObservableType.USER, ObservableType.IP, ObservableType.IPV6, ObservableType.HOSTNAME),
    required_integrations=(
        IntegrationRequirement(
            integration="entra",
            purpose="User profile and session state, sign-in logs, MFA and risk context; executes the approved "
                    "session revocation and account disable",
            atomics=("investigate_user", "investigate_authentication", "search_user_activity"),
        ),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Verdicts for the sign-in source IPs and enterprise sightings of those IPs",
            atomics=("enrich_ip", "search_ip_enterprise"),
        ),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts and advanced hunting for sign-ins, user activity and IP prevalence",
            atomics=("investigate_authentication", "search_user_activity", "search_ip_enterprise"),
        ),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Detections and isolation state of the user's endpoints; executes the approved isolation",
            atomics=("investigate_endpoint",),
        ),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Detections of the user's endpoints and IP prevalence; executes approved isolation or IP "
                    "indicator",
            atomics=("investigate_endpoint", "search_ip_enterprise"),
        ),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Second opinion on public sign-in source IPs (never non-public addresses)",
            atomics=("enrich_ip",),
        ),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Second opinion on public sign-in source IPs (never non-public addresses)",
            atomics=("enrich_ip",),
        ),
        IntegrationRequirement(
            integration="meraki",
            purpose="Executes the approved attacker IP block as an MX layer 3 firewall rule (no reads)",
        ),
        IntegrationRequirement(
            integration="splunk",
            purpose="Optional SIEM search for sign-ins, user activity and IP prevalence",
            atomics=("investigate_authentication", "search_user_activity", "search_ip_enterprise"),
        ),
    ),
    investigation=(
        InvestigationStep(id="user_profile", atomic="investigate_user", subjects=USER_SUBJECTS,
                          subject_type=ObservableType.USER),
        InvestigationStep(id="authentication", atomic="investigate_authentication", subjects=USER_SUBJECTS,
                          lookback_hours=72),
        InvestigationStep(id="user_activity", atomic="search_user_activity", subjects=USER_SUBJECTS,
                          lookback_hours=72),
        InvestigationStep(id="ip_reputation", atomic="enrich_ip"),
        InvestigationStep(id="ip_prevalence", atomic="search_ip_enterprise", lookback_hours=168),
        InvestigationStep(id="user_endpoints", atomic="investigate_endpoint", subjects=ENDPOINT_SUBJECTS,
                          subject_type=ObservableType.HOSTNAME),
    ),
    correlation=CorrelationSpec(
        description=(
            "Sign-ins, MFA events and risk detections are grouped per account. A successful sign-in is tied to "
            "the account's later mailbox-rule, role or app-consent activity within the window "
            "(sign_in_to_activity), and users, IPs and endpoints that share records are clustered (same_ip, "
            "same_user, same_endpoint) for the blast radius. The workflow hooks decide, from records only, "
            "which accounts show a compromise indicator, which sign-in IPs are attacker infrastructure and "
            "which are shared (seen from internal endpoints or other accounts), and which incident endpoints "
            "of a compromised account carry an active malicious detection."
        ),
        link_kinds=(LinkKind.SAME_IP, LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT, LinkKind.SIGN_IN_TO_ACTIVITY),
        window_minutes=240,
    ),
    scoring=ScoringInputs(
        description=(
            "Each target is scored from the records its rule cites. Identity-provider risk detections and a "
            "high user risk are authentication anomalies; post-sign-in mailbox rules, privileged role "
            "assignments and flagged app consents are persistence; endpoint detections are endpoint "
            "detections; IP enrichment is reputation (capped at 50, one vendor's word is never MALICIOUS on "
            "its own). The hooks add authentication-anomaly signals computed from cited records: a successful "
            "sign-in from an IP rated malicious or suspicious, an attacker sign-in after the sessions were "
            "revoked, an MFA approval after repeated denials, and a sign-in source IP used against an "
            "investigated account. A failed expected source (entra, cisco_xdr) lowers confidence and never "
            "blocks a recommendation that other evidence supports."
        ),
    ),
    recommendations=(
        RecommendationRule(
            id="revoke_compromised_sessions",
            description="Revoke every sign-in session of an account that shows a compromise indicator",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="get(facts, 'compromised_users', [])",
            target="item.user",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.summary",
            min_risk=50,
            mitre=("T1078.004", "T1539", "T1621"),
        ),
        RecommendationRule(
            id="disable_compromised_account",
            description="Disable a compromised account that is privileged or was used again after its sessions "
                        "were revoked",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="get(facts, 'disable_users', [])",
            target="item.user",
            evidence="item.disable_record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.disable_summary",
            min_risk=60,
            mitre=("T1078.004",),
        ),
        RecommendationRule(
            id="isolate_compromised_user_endpoint",
            description="Isolate an incident endpoint of a compromised account that has an active malicious "
                        "detection",
            action=ActionType.ISOLATE_ENDPOINT,
            for_each="get(facts, 'endpoints', [])",
            target="item.hostname",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}",
            rationale="item.summary",
            min_risk=60,
            mitre=("T1539",),
        ),
        RecommendationRule(
            id="block_attacker_ip",
            description="Block a sign-in source IP that a source rates malicious and that is not shared "
                        "infrastructure",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="get(facts, 'block_ips', [])",
            target="item.ip",
            evidence="item.record_ids",
            rationale="item.summary",
            min_risk=50,
            mitre=("T1078.004",),
        ),
    ),
    mitre=(
        MitreMapping(
            tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
            sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
            rationale="The incident is a sign-in to a cloud identity with valid credentials; the package "
                      "revokes the sessions, disables the account when needed and blocks the source IP.",
        ),
        MitreMapping(
            tactic="TA0006", technique="T1539", technique_name="Steal Web Session Cookie",
            rationale="A replayed session token or an infected endpoint of the account is how a session is "
                      "stolen; revocation invalidates the stolen session and isolation stops the theft.",
        ),
        MitreMapping(
            tactic="TA0006", technique="T1621", technique_name="Multi-Factor Authentication Request Generation",
            rationale="An MFA approval after repeated denied prompts is one of the compromise indicators that "
                      "lead to revocation; prompt floods without an approval belong to the mfa-fatigue workflow.",
        ),
    ),
    known_limitations=(
        "With the real Entra adapter only user properties and sign-in logs are normalized: risk detections, "
        "riskyUser state (UNVERIFIED), MFA method detail, directory roles and group memberships are not mapped, "
        "so on a tenant the indicators come from sign-in risk and IP reputation, and privileged accounts are "
        "recognised through the critical-asset user patterns and groups.",
        "Session revocation is not reversible, can take a few minutes and does not affect external (guest) "
        "users; the password reset and MFA re-registration stay a manual help-desk step.",
        "The shared-infrastructure check needs typed enterprise sightings; hunting rows without a documented "
        "schema (Splunk, runHuntingQuery) stay generic records, so a VPN exit may still be proposed for a block "
        "and the analyst decides.",
        "A non-public sign-in IP (corporate VPN pool) is proposed like any other; list VPN pools in "
        "allowlists.never_block.cidrs so the block is shown as excluded and never executed.",
        "Direct Umbrella IP blocking is UNVERIFIED; IP blocks route to Meraki MX, a Defender for Endpoint "
        "indicator or the native Cisco XDR action, and Secure Endpoint isolation is UNABLE_TO_VERIFY.",
        "Only endpoints the incident names (hostname observables or endpoint assets) are investigated; sign-in "
        "device ids are not resolved to endpoints.",
        "MFA prompt floods without an approval are handled by the mfa-fatigue workflow; mailbox-rule and "
        "app-consent remediation by the bec and cloud-compromise workflows.",
    ),
    related_workflows=("mfa-fatigue", "password-spray", "bec", "cloud-compromise", "suspicious-authentication"),
)
