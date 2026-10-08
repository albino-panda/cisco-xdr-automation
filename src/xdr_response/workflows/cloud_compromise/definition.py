"""Cloud compromise (Phase 4): abuse of cloud identities, application credentials, OAuth consent and roles.

The workflow investigates the accounts an incident names in Microsoft Entra ID and Microsoft Defender XDR
(profile and session state, directory roles, sign-ins and risk detections, then the cloud activity of the
account: directory role assignments, application credentials, OAuth consents and service-principal
changes, and the cloud alerts raised for it), the sign-in source IPs (reputation and enterprise
prevalence), and then *recommends* a containment package:

* revoke the sign-in sessions (and with them the refresh tokens issued to applications) of an account
  that shows a compromise indicator or that consented to a risky OAuth application;
* disable a compromised account that is privileged or was used to plant cloud persistence (a privileged
  role, an application credential, a tenant-wide consent);
* remove a privileged directory role that a compromised account granted, or that a compromised account
  received, during the investigated window (always ELEVATED by the catalog);
* block the attacker sign-in IP.

Application credentials, OAuth permission grants and service principals have no VERIFIED write in
docs/integrations.md: they are reported as **manual steps** with the records that show them, never
executed. The workflow only investigates and recommends; every action needs a human approval and the
Phase 0 lifecycle executes, verifies and (after a separate release approval) restores. The decisions
live in :mod:`.hooks` (pure, record-backed facts).
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

__all__ = ["WORKFLOW", "USER_SUBJECTS"]

#: Investigated accounts: the incident's users and user observables (normalized, sorted, unique).
USER_SUBJECTS = ("distinct([lower(u) for u in incident.users] + "
                 "[lower(u) for u in get(incident.observables_by_type, 'user', [])])")

WORKFLOW = WorkflowDefinition(
    id="cloud-compromise",
    version="2.0.0",
    name="Cloud compromise",
    description=(
        "Respond to the abuse of Microsoft cloud identities, application credentials, OAuth consent and "
        "directory roles: investigate the accounts' Entra profile, sign-ins and risk detections, their cloud "
        "activity (role assignments, new application credentials, OAuth consents, service-principal changes "
        "and Defender XDR cloud alerts) and the sign-in source IPs, then recommend revoking sessions and "
        "tokens, disabling the compromised account, removing an unauthorized privileged role and blocking the "
        "attacker IP. Application credentials, consents and service principals are manual steps. Every "
        "action waits for a human approval."
    ),
    phase=4,
    default_severity=Severity.HIGH,
    legacy_id="cloud-compromise",
    triggers=(
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident whose detections report new cloud credentials or roles, or a stolen "
                        "application access token, for a user",
            mitre_techniques=("T1098.001", "T1098.003", "T1528"),
            observable_types=(ObservableType.USER,),
            priority=130,
        ),
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident titled as an OAuth consent, app registration, service principal, "
                        "application credential or directory role change for a user",
            title_patterns=("*oauth*", "*consent grant*", "*illicit consent*", "*risky consent*",
                            "*app registration*", "*service principal*", "*client secret*",
                            "*application credential*", "*certificate added to app*", "*directory role*"),
            observable_types=(ObservableType.USER,),
            priority=105,
        ),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or a user pivot"),
    ),
    input_observables=(ObservableType.USER, ObservableType.IP, ObservableType.IPV6),
    required_integrations=(
        IntegrationRequirement(
            integration="entra",
            purpose="User profile, directory roles and session state, sign-in logs and risk context; executes "
                    "the approved session revocation, account disable and role-assignment removal",
            atomics=("investigate_user", "investigate_authentication", "search_user_activity"),
        ),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts (alerts_v2) for the accounts' cloud activity: OAuth applications, new "
                    "application credentials, suspicious cloud API activity",
            atomics=("investigate_user", "search_user_activity", "search_ip_enterprise"),
        ),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Verdicts for the sign-in source IPs and enterprise sightings of those IPs",
            atomics=("enrich_ip", "search_ip_enterprise"),
        ),
    ),
    optional_integrations=(
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
            integration="defender_endpoint",
            purpose="IP prevalence on managed endpoints; executes an approved IP block as an indicator",
            atomics=("search_ip_enterprise",),
        ),
        IntegrationRequirement(
            integration="splunk",
            purpose="Optional SIEM search for sign-ins, cloud audit activity and IP prevalence (generic rows)",
            atomics=("investigate_authentication", "search_user_activity", "search_ip_enterprise"),
        ),
    ),
    investigation=(
        InvestigationStep(id="user_profile", atomic="investigate_user", subjects=USER_SUBJECTS,
                          subject_type=ObservableType.USER),
        InvestigationStep(id="authentication", atomic="investigate_authentication", subjects=USER_SUBJECTS,
                          lookback_hours=72),
        InvestigationStep(id="cloud_activity", atomic="search_user_activity", subjects=USER_SUBJECTS,
                          lookback_hours=168),
        InvestigationStep(id="ip_reputation", atomic="enrich_ip"),
        InvestigationStep(id="ip_prevalence", atomic="search_ip_enterprise", lookback_hours=168),
    ),
    correlation=CorrelationSpec(
        description=(
            "Sign-ins, risk detections, cloud alerts, role changes and application records are grouped per "
            "account. A successful sign-in is tied to the account's later role, consent or application "
            "activity within the window (sign_in_to_activity), and accounts and IPs that share records are "
            "clustered (same_ip, same_user) for the blast radius. The workflow hooks decide, from records "
            "only, which accounts show a compromise indicator, which OAuth applications are risky (rated by a "
            "vendor, or credentialed, created or consented by a compromised account), which privileged role "
            "assignments are unauthorized (granted by or to a compromised account), and which sign-in IPs are "
            "attacker infrastructure that no internal endpoint or other account shares."
        ),
        link_kinds=(LinkKind.SAME_IP, LinkKind.SAME_USER, LinkKind.SIGN_IN_TO_ACTIVITY),
        window_minutes=1440,
    ),
    scoring=ScoringInputs(
        description=(
            "Each target is scored from the records its rule cites. Identity-provider risk detections and a "
            "high user risk are authentication anomalies; privileged role assignments and vendor-rated "
            "applications are persistence; Defender XDR cloud alerts are detections; IP enrichment is "
            "reputation (capped at 50; one vendor's word is never MALICIOUS on its own). The hooks add signals "
            "computed from cited records: a successful sign-in from an IP rated malicious or suspicious "
            "(authentication anomaly), and a credential added to, or a consent granted to, an unrated "
            "application by a compromised account (persistence). A failed expected source (entra, "
            "microsoft_cloud, cisco_xdr) lowers confidence and never blocks a recommendation that other "
            "evidence supports. Cloud persistence is this workflow's primary evidence, so the persistence "
            "category weighs 1.0 here (default 0.8); caps and penalties are unchanged."
        ),
        weights={SignalCategory.PERSISTENCE: 1.0},
    ),
    recommendations=(
        RecommendationRule(
            id="revoke_compromised_sessions",
            description="Revoke every sign-in session and refresh token of an account that shows a compromise "
                        "indicator or that consented to a risky OAuth application",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="get(facts, 'revoke_users', [])",
            target="item.user",
            evidence="item.revoke_record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.revoke_summary",
            min_risk=50,
            mitre=("T1078.004", "T1528"),
        ),
        RecommendationRule(
            id="disable_compromised_account",
            description="Disable a compromised account that is privileged or was used to plant cloud persistence "
                        "(a privileged role, an application credential, a tenant-wide consent)",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="get(facts, 'disable_users', [])",
            target="item.user",
            evidence="item.disable_record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.disable_summary",
            min_risk=60,
            mitre=("T1078.004", "T1098.001", "T1098.003"),
        ),
        RecommendationRule(
            id="remove_unauthorized_role",
            description="Remove a privileged directory role assignment granted by, or to, a compromised account "
                        "during the investigated window",
            action=ActionType.REMOVE_PRIVILEGED_ROLE,
            builder="remove_privileged_role",
            for_each="get(facts, 'remove_roles', [])",
            target="item.target",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'roles': item.roles}",
            rationale="item.summary",
            params={"directory_scope_id": "item.directory_scope_id"},
            min_risk=50,
            mitre=("T1098.003",),
        ),
        RecommendationRule(
            id="block_attacker_ip",
            description="Block a sign-in source IP that a source rates malicious (or suspicious and used by a "
                        "high-risk account) and that is not shared infrastructure",
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
            rationale="The incident is the use of a cloud identity with valid credentials; the package revokes "
                      "the sessions, disables the account when needed and blocks the source IP.",
        ),
        MitreMapping(
            tactic="TA0003", technique="T1098", technique_name="Account Manipulation",
            sub_technique="T1098.001", sub_technique_name="Additional Cloud Credentials",
            rationale="A credential added to an application or service principal by a compromised account is "
                      "investigated; the account is disabled and the credential removal is a manual step "
                      "(no VERIFIED write).",
        ),
        MitreMapping(
            tactic="TA0003", technique="T1098", technique_name="Account Manipulation",
            sub_technique="T1098.003", sub_technique_name="Additional Cloud Roles",
            rationale="A privileged directory role granted by or to a compromised account is recommended for "
                      "removal (always ELEVATED) and the granting account for disable.",
        ),
        MitreMapping(
            tactic="TA0006", technique="T1528", technique_name="Steal Application Access Token",
            rationale="A consent to a risky OAuth application hands it the user's tokens; session revocation "
                      "invalidates the refresh tokens issued to applications for the account and the consent "
                      "revocation is a manual step.",
        ),
    ),
    known_limitations=(
        "Application credentials, OAuth permission grants and service principals have no VERIFIED Graph write "
        "in docs/integrations.md (revoke_app_credentials is UNVERIFIED and there is no service-principal or "
        "consent action type), so removing a credential, revoking a consent and disabling a service principal "
        "are manual steps in the run notes and analyst summary, never package actions.",
        "With the real adapters role changes and application records are not normalized: the Entra directory "
        "audit log and the servicePrincipals / oauth2PermissionGrants reads are not in docs/integrations.md, so "
        "on a tenant the cloud-persistence indicators come only from Defender XDR alerts (alerts_v2), sign-in "
        "risk and IP reputation, and role removal and app manual steps need typed records from another source.",
        "Role removal targets '<user>/<roleDefinitionId>'; the real Entra adapter resolves the user's object id "
        "and the assignment of that role (at the scope of the grant when the role change record names it) through "
        "VERIFIED reads before the delete and in verification. When the user holds the role at several scopes and "
        "the record names none, the approved removal fails visibly and the analyst removes the right assignment "
        "by hand.",
        "Session revocation is not reversible, can take a few minutes, does not affect external (guest) users "
        "and does not stop application-only tokens of a service principal: tenant-wide (admin) consents and "
        "service-principal secrets need the manual steps.",
        "Whether a role assignment or an application credential was an approved change cannot be read from a "
        "VERIFIED source (no change-management integration); a privileged grant between accounts with no "
        "compromise indicator is shown as considered, not proposed, and the analyst checks the change record.",
        "Direct Umbrella IP blocking is UNVERIFIED; IP blocks route to Meraki MX, a Defender for Endpoint "
        "indicator or the native Cisco XDR action. A non-public sign-in IP (corporate VPN pool) is excluded only "
        "when allowlists.never_block lists it or it is in a non-public range.",
        "Access to cloud storage and mailboxes by the application or the accounts (data from cloud storage) is "
        "not investigated: no VERIFIED read exists; it is the exfiltration workflow's and the analyst's review.",
    ),
    related_workflows=("account-takeover", "exfiltration", "privilege-escalation", "bec",
                       "suspicious-authentication"),
    handoff_to=("account-takeover",),
)
