"""Password spray workflow (``password-spray``, Phase 2; architecture 14.5).

One source address tries a few common passwords against many accounts: many failed sign-ins, and
sometimes a later success. The workflow investigates the targeted accounts and their sign-in logs,
enriches the spray sources (reputation and internal sightings) and *recommends* a containment
package: block the spray source IP, revoke the sessions of accounts the spray signed in to, and
disable an account whose spray success was followed by suspicious activity. It never executes:
every action needs human approval, then the Phase 0 lifecycle executes, verifies and (after a
separate human release approval) restores.

The pattern logic lives in :mod:`.hooks` (pure functions over the run's typed records); the rules
below only select the hook facts, so every recommendation cites the records it was computed from.
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

__all__ = ["WORKFLOW", "SPRAY_MIN_ACCOUNTS", "FOLLOW_ON_ANOMALIES", "PATTERN_SIGNAL_MIN_ACCOUNTS"]

#: An address the incident does not name is a spray source only when its failed sign-ins hit at least
#: this many distinct targeted accounts (an address the incident names is a source by definition).
SPRAY_MIN_ACCOUNTS = 3

#: A spray source gets a behavioural scoring signal (hooks) from this many failed accounts on.
PATTERN_SIGNAL_MIN_ACCOUNTS = 2

#: Vendor anomaly types that count as suspicious activity after a spray success (disable_user).
#: An unfamiliar location alone does not count: every spray success from an external address has one.
FOLLOW_ON_ANOMALIES: tuple[str, ...] = ("impossible_travel", "mfa_fatigue", "new_device", "token_replay")

# ----------------------------------------------------------------- expressions --
# The comprehension language allows one ``for`` per comprehension, so the sub-expressions are composed here.
_SIGNINS = "flatten([r.signins for r in results.investigate_authentication + results.investigate_user])"
_FAILED = f"[s for s in {_SIGNINS} if s.result == 'failure' and s.ip]"
_PATTERN_IPS = (f"[ip for ip in distinct([s.ip for s in {_FAILED}]) "
                f"if len(distinct([s.user for s in {_FAILED} if s.ip == ip])) >= {SPRAY_MIN_ACCOUNTS}]")
_SOURCES_V4 = (f"distinct([v for v in get(incident.observables_by_type, 'ip', []) + {_PATTERN_IPS} "
               "if ':' not in v])")
_SOURCES_V6 = (f"distinct([v for v in get(incident.observables_by_type, 'ipv6', []) + {_PATTERN_IPS} "
               "if ':' in v])")
_ACCOUNTS = ("distinct([lower(u) for u in get(incident.observables_by_type, 'user', []) + "
             "get(incident.observables_by_type, 'email_address', []) + incident.users])")
_ACCOUNT_ASSET = "{'groups': item.groups, 'roles': item.roles}"

WORKFLOW = WorkflowDefinition(
    id="password-spray",
    version="2.0.0",
    name="Password spray",
    description=(
        "Investigate a password spray (one source address, many targeted accounts, many failed "
        "sign-ins and possibly a later success) and recommend a containment package for human approval: "
        "block the spray source IP, revoke the sessions of every account the spray signed in to, and "
        "disable an account whose spray success was followed by suspicious activity."
    ),
    phase=2,
    default_severity=Severity.MEDIUM,
    legacy_id="password-spray",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident that reports the Password Spraying sub-technique",
                    mitre_techniques=("T1110.003",), priority=110),
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident titled as a password spray that carries a source address",
                    title_patterns=("*password spray*", "*password-spray*", "*password spraying*"),
                    observable_types=(ObservableType.IP, ObservableType.IPV6), priority=105),
        TriggerSpec(type="manual", description="An analyst starts the workflow for an incident or observable"),
    ),
    input_observables=(ObservableType.IP, ObservableType.IPV6, ObservableType.USER, ObservableType.EMAIL_ADDRESS),
    required_integrations=(
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Incident source; verdicts (enrich deliberate) and sightings of the spray source addresses",
            atomics=("enrich_ip", "search_ip_enterprise")),
        IntegrationRequirement(
            integration="entra",
            purpose="Targeted accounts (Get user) and their sign-in logs (List signIns); executes session "
                    "revocation and account disable after approval",
            atomics=("investigate_user", "investigate_authentication")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="virustotal", purpose="Second reputation opinion on public spray sources only "
                                              "(disclosure policy)",
            atomics=("enrich_ip",)),
        IntegrationRequirement(
            integration="alienvault_otx", purpose="Third reputation opinion on public spray sources only "
                                                  "(disclosure policy)",
            atomics=("enrich_ip",)),
        IntegrationRequirement(
            integration="meraki",
            purpose="Executes an approved IP block as one tagged MX L3 firewall rule (no read atomic)"),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Alternative route for an approved IP block (IpAddress indicator; no read atomic)"),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Advanced hunting for internal sightings of a spray source (rows stay generic records)",
            atomics=("search_ip_enterprise",)),
        IntegrationRequirement(
            integration="splunk",
            purpose="Optional SIEM searches for sign-ins and sightings (rows stay generic records)",
            atomics=("investigate_authentication", "search_ip_enterprise")),
    ),
    investigation=(
        InvestigationStep(id="targeted_accounts", atomic="investigate_user", subjects=_ACCOUNTS,
                          subject_type=ObservableType.USER, max_subjects=50),
        InvestigationStep(id="sign_in_history", atomic="investigate_authentication", subjects=_ACCOUNTS,
                          subject_type=ObservableType.USER, max_subjects=50),
        InvestigationStep(id="source_reputation", atomic="enrich_ip", subjects=_SOURCES_V4,
                          subject_type=ObservableType.IP, max_subjects=50),
        InvestigationStep(id="source_reputation_v6", atomic="enrich_ip", subjects=_SOURCES_V6,
                          subject_type=ObservableType.IPV6, max_subjects=50),
        InvestigationStep(id="source_sightings", atomic="search_ip_enterprise", subjects=_SOURCES_V4,
                          subject_type=ObservableType.IP, max_subjects=50),
        InvestigationStep(id="source_sightings_v6", atomic="search_ip_enterprise", subjects=_SOURCES_V6,
                          subject_type=ObservableType.IPV6, max_subjects=50),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links over the typed records: a spray source mentioned by the sign-ins of two or more "
            "accounts becomes a same_ip link (the spray fan-out), and an account seen with several addresses a "
            "same_user link. The workflow hook then derives, per source address, the failed accounts, the "
            "successes and the internal sightings, and per account the successes from a spray source and the "
            "suspicious activity that followed. Window 60 minutes."),
        window_minutes=60,
    ),
    scoring=ScoringInputs(
        description=(
            "Sign-ins carry no score on their own. The hook derives one authentication_anomaly signal per spray "
            "source (failed sign-ins against two or more accounts; stronger with five or more, or when the spray "
            "succeeded) and one per account with a successful sign-in from a spray source, each citing the "
            "sign-in records. Vendor anomalies, a high Entra risk level and IP reputation add the framework "
            "signals; reputation alone is capped by the engine. Risk and confidence are separate scores; a "
            "failed source lowers confidence and never blocks the recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="block_spray_source",
            description="Block a spray source address that is neither shared infrastructure nor an internal endpoint",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="facts.spray_sources",
            when="not item.shared_infrastructure and not item.internal_endpoint",
            target="item.ip",
            evidence="item.record_ids",
            rationale="item.summary",
            min_risk=30,
            mitre=("T1110.003",),
        ),
        RecommendationRule(
            id="revoke_sprayed_sessions",
            description="Revoke the sign-in sessions of an account with a successful sign-in from a spray source",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="facts.compromised_accounts",
            target="item.user",
            evidence="item.record_ids",
            asset=_ACCOUNT_ASSET,
            rationale="item.summary",
            min_risk=50,
            mitre=("T1110.003", "T1078.004"),
        ),
        RecommendationRule(
            id="disable_compromised_account",
            description=("Disable an account whose successful sign-in from a spray source was followed by "
                         "suspicious activity"),
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="[a for a in facts.compromised_accounts if a.follow_on]",
            target="item.user",
            evidence="item.record_ids + item.follow_on_record_ids",
            asset=_ACCOUNT_ASSET,
            rationale="item.follow_on_summary",
            min_risk=60,
            mitre=("T1110.003", "T1078.004"),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0006", technique="T1110", technique_name="Brute Force",
                     sub_technique="T1110.003", sub_technique_name="Password Spraying",
                     rationale="The incident is one source trying passwords against many accounts; the IP block "
                               "responds to it."),
        MitreMapping(tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
                     sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
                     rationale="A successful sign-in from a spray source is the use of a valid Entra ID (cloud) "
                               "account; session revocation and account disable respond to it."),
    ),
    known_limitations=(
        "Targeted accounts must be named by the incident (user or email observables, or incident users); the "
        "sign-in log is queried per account because no VERIFIED read lists Entra sign-ins by source address.",
        "Entra Identity Protection risk detections are not a VERIFIED read: anomaly records come only from "
        "sources with a typed mapping, so in production a follow-on is mostly a high sign-in risk level.",
        "Sightings from Cisco XDR, Microsoft Defender XDR advanced hunting and Splunk stay generic records: "
        "they are citable but cannot mark a source as shared infrastructure until a typed mapping exists.",
        "Shared egress is recognised only from evidence (a clean verdict or internal sightings); an unrated "
        "cloud or partner egress address is still recommended for a block and the analyst decides.",
        "Session revocation is not reversible and the user signs in again; the password reset and MFA "
        "re-registration are manual follow-up steps (reset_password and reset_mfa are UNVERIFIED).",
        "Umbrella IP blocking is UNVERIFIED (conflict in docs/integrations.md); an IP block routes to Meraki, "
        "Defender for Endpoint or a configured Cisco XDR native action, otherwise it is reported unrouted.",
        "An internal spray source (an address of an investigated endpoint) is not blocked at the perimeter; "
        "contain the endpoint through the lateral-movement workflow.",
    ),
    related_workflows=("account-takeover", "mfa-fatigue", "suspicious-authentication", "lateral-movement"),
    handoff_to=("account-takeover",),
)
