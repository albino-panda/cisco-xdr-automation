"""Workflow ``suspicious-authentication`` (Phase 4, new; no legacy spec).

A sign-in that does not look like the account owner: an unusual country, a new or unmanaged device,
an anonymising network (Tor, open proxy, anonymous VPN), travel between countries faster than a person
can move, an hour the account never signs in at, or an account whose credentials appear in breach
data. The workflow investigates the account (Entra profile, sign-ins over a 14-day baseline, vendor
risk detections, post-sign-in cloud activity), the sign-in source IPs (Cisco XDR, VirusTotal and OTX
reputation, enterprise prevalence to recognise a shared corporate egress), credential exposure (HIBP,
only for addresses the disclosure policy allows) and the managed device the incident names (Intune),
then RECOMMENDS a containment package: revoke the account's sessions, disable the account when the
compromise went further, and block the attacker source IP.

It only investigates and recommends. Every action needs a human approval (ELEVATED for critical
assets, applied by ``PackageBuilder``); execution, verification and release happen in the Phase 0
lifecycle after that approval. The indicator logic lives in the pure hooks of :mod:`.hooks`.
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

__all__ = ["WORKFLOW", "USER_SUBJECTS", "EMAIL_SUBJECTS", "MANAGED_DEVICE_SUBJECTS", "TITLE_PATTERNS"]

#: Investigated accounts: the incident's users and user observables (normalized, sorted, unique).
USER_SUBJECTS = ("distinct([lower(u) for u in incident.users] + "
                 "[lower(u) for u in get(incident.observables_by_type, 'user', [])])")
#: Accounts checked for credential exposure: the investigated accounts that are email-shaped plus the
#: incident's email-address observables. The disclosure policy decides which ones HIBP may receive.
EMAIL_SUBJECTS = ("distinct([lower(u) for u in incident.users if '@' in u] + "
                  "[lower(u) for u in get(incident.observables_by_type, 'user', []) if '@' in u] + "
                  "[lower(u) for u in get(incident.observables_by_type, 'email_address', [])])")
#: Managed devices the incident names (Intune managedDevice ids, ``endpoint_id`` observables).
MANAGED_DEVICE_SUBJECTS = "distinct(get(incident.observables_by_type, 'endpoint_id', []))"

#: Title patterns of the automatic title trigger. They deliberately do not repeat the account-takeover
#: title patterns (risky, high-risk, unfamiliar sign-in, impossible or atypical travel, token replay).
TITLE_PATTERNS = (
    "*suspicious sign-in*", "*suspicious sign in*", "*suspicious login*", "*suspicious logon*",
    "*suspicious authentication*", "*unusual sign-in*", "*anomalous sign-in*", "*sign-in anomaly*",
    "*anonymous ip*", "*anonymized ip*", "*anonymizing*", "*tor exit*", "*sign-in from tor*",
    "*unmanaged device*", "*non-compliant device*", "*unregistered device*", "*leaked credential*",
    "*credential exposure*", "*unusual location*", "*new country*", "*abnormal sign-in time*",
    "*sign-in outside business hours*",
)

_USER_ASSET = "{'groups': item.groups, 'roles': item.roles, 'privileged': item.privileged}"

WORKFLOW = WorkflowDefinition(
    id="suspicious-authentication",
    version="1.0.0",
    name="Suspicious authentication",
    description=(
        "Respond to a sign-in that does not look like the account owner: an unusual country, a new or "
        "unmanaged device, Tor or an anonymising proxy or VPN, impossible travel, an abnormal sign-in hour, "
        "or credentials exposed in breach data. The workflow investigates the account's sign-ins against a "
        "14-day baseline, vendor risk detections and post-sign-in activity, the source IPs (reputation and "
        "enterprise prevalence), credential exposure and the managed device, and recommends revoking the "
        "sessions, disabling the account when the compromise went further and blocking the attacker IP. "
        "Every action waits for a human approval."
    ),
    phase=4,
    default_severity=Severity.MEDIUM,
    triggers=(
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident titled as a suspicious, anomalous or anonymised sign-in, a sign-in "
                        "from an unmanaged device or an unusual location, or leaked credentials, for a user",
            title_patterns=TITLE_PATTERNS,
            observable_types=(ObservableType.USER,),
            priority=105,
        ),
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident reporting valid-account use (any sub-technique) for a user; the "
                        "cloud-account and stolen-session detections of account-takeover outrank it",
            mitre_techniques=("T1078",),
            observable_types=(ObservableType.USER,),
            priority=95,
        ),
        TriggerSpec(type="manual", description="An analyst runs the workflow for an incident or a user pivot"),
    ),
    input_observables=(ObservableType.USER, ObservableType.EMAIL_ADDRESS, ObservableType.IP, ObservableType.IPV6,
                       ObservableType.ENDPOINT_ID),
    required_integrations=(
        IntegrationRequirement(
            integration="entra",
            purpose="User profile, roles and session state, sign-in logs (country, device, compliance, risk) and "
                    "post-sign-in activity; executes the approved session revocation and account disable",
            atomics=("investigate_user", "investigate_authentication", "search_user_activity"),
        ),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Verdicts for the sign-in source IPs and the account address, and enterprise sightings of "
                    "those IPs; native response route when configured",
            atomics=("enrich_ip", "enrich_email_address", "search_ip_enterprise"),
        ),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Defender XDR alerts (alerts_v2, including identity-protection alerts) for the account and "
                    "the source IPs",
            atomics=("investigate_user", "investigate_authentication", "search_user_activity",
                     "search_ip_enterprise"),
        ),
        IntegrationRequirement(
            integration="intune",
            purpose="Compliance state and primary user of the managed device the incident names (managedDevice "
                    "by id)",
            atomics=("investigate_endpoint",),
        ),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Enterprise prevalence of the source IPs; executes an approved IP block as a Defender "
                    "indicator",
            atomics=("search_ip_enterprise",),
        ),
        IntegrationRequirement(
            integration="hibp",
            purpose="Credential exposure of the account address in known breaches (only addresses the "
                    "disclosure policy allows; never internal domains)",
            atomics=("enrich_email_address",),
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
    ),
    investigation=(
        InvestigationStep(id="user_profile", atomic="investigate_user", subjects=USER_SUBJECTS,
                          subject_type=ObservableType.USER, max_subjects=10),
        InvestigationStep(id="authentication", atomic="investigate_authentication", subjects=USER_SUBJECTS,
                          lookback_hours=336, max_subjects=10),
        InvestigationStep(id="post_sign_in_activity", atomic="search_user_activity", subjects=USER_SUBJECTS,
                          lookback_hours=72, max_subjects=10),
        InvestigationStep(id="credential_exposure", atomic="enrich_email_address", subjects=EMAIL_SUBJECTS,
                          max_subjects=10),
        InvestigationStep(id="source_ip_reputation", atomic="enrich_ip"),
        InvestigationStep(id="source_ip_prevalence", atomic="search_ip_enterprise", lookback_hours=168),
        InvestigationStep(id="managed_device", atomic="investigate_endpoint", subjects=MANAGED_DEVICE_SUBJECTS,
                          subject_type=ObservableType.ENDPOINT_ID, integrations=("intune",), max_subjects=5),
    ),
    correlation=CorrelationSpec(
        description=(
            "Each account's successful sign-ins in the 24 hours before the incident are compared with its "
            "older successful sign-ins (the baseline, up to 14 days): a country, device or hour the baseline "
            "never shows, two countries within 120 minutes (impossible travel), a source IP rated malicious or "
            "suspicious, an anonymising network (vendor anonymous-IP detection, Tor or proxy categories, "
            "identity-protection alerts), vendor risk detections, identity risk and credential exposure. "
            "Sign-ins from a non-public address or from a shared egress (other accounts sign in from it, or "
            "internal endpoints reach it) never count as unusual geography, travel or time. The hooks link each "
            "account to the source IPs of its suspicious sign-ins (WORKFLOW links); framework links tie a "
            "successful sign-in to later mailbox-rule, role or app-consent activity (sign_in_to_activity) and "
            "cluster users and IPs that share records (same_ip, same_user)."
        ),
        link_kinds=(LinkKind.SAME_IP, LinkKind.SAME_USER, LinkKind.SIGN_IN_TO_ACTIVITY),
        window_minutes=240,
    ),
    scoring=ScoringInputs(
        description=(
            "Each target is scored from the records its rule cites. Vendor risk detections and a high or "
            "confirmed identity risk are authentication anomalies; post-sign-in forwarding rules, privileged "
            "role grants and flagged app consents are persistence; IP and HIBP enrichment are reputation "
            "(vendor verdicts, capped; breach data is SUSPICIOUS at most). The hooks add authentication-anomaly "
            "signals that cite the sign-in records: a successful sign-in from an IP rated malicious (MALICIOUS "
            "80) or suspicious (SUSPICIOUS 65), through an anonymising network (SUSPICIOUS 70), impossible "
            "travel (SUSPICIOUS 75), an unusual country, device or hour (SUSPICIOUS 50, 50 and 40), an attacker "
            "sign-in after the sessions were revoked (MALICIOUS 85), and the source-IP signal for a block. A "
            "failed expected source (entra, cisco_xdr) lowers confidence and never blocks a recommendation that "
            "other evidence supports."
        ),
    ),
    recommendations=(
        RecommendationRule(
            id="revoke_suspicious_sessions",
            description="Revoke every sign-in session of an account whose recent successful sign-in carries "
                        "enough indicators (at least 3 points, 2 of them from the sign-in itself)",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="get(facts, 'compromised_users', [])",
            target="item.user",
            evidence="item.record_ids",
            asset=_USER_ASSET,
            rationale="item.summary",
            min_risk=50,
            mitre=("T1078.004", "T1090.003"),
        ),
        RecommendationRule(
            id="disable_compromised_account",
            description="Disable a likely compromised account that is privileged, was used again after its "
                        "sessions were revoked, is confirmed compromised, or shows post-sign-in persistence "
                        "(forwarding rule, privileged role grant, flagged app consent)",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="get(facts, 'disable_users', [])",
            target="item.user",
            evidence="item.record_ids + item.disable_record_ids",
            asset=_USER_ASSET,
            rationale="item.summary + '; disable because: ' + item.disable_summary",
            min_risk=60,
            mitre=("T1078.004",),
        ),
        RecommendationRule(
            id="block_attacker_source_ip",
            description="Block a public sign-in source IP that a source rates malicious or a HIGH vendor "
                        "anonymous or malicious IP detection names, unless it is shared infrastructure",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="get(facts, 'block_ips', [])",
            target="item.ip",
            evidence="item.record_ids",
            rationale="item.summary",
            min_risk=50,
            mitre=("T1078.004", "T1090.003"),
        ),
    ),
    mitre=(
        MitreMapping(
            tactic="TA0001", technique="T1078", technique_name="Valid Accounts",
            sub_technique="T1078.004", sub_technique_name="Cloud Accounts",
            rationale="The incident is a sign-in to a cloud identity with valid credentials that does not look "
                      "like the owner; the package revokes the sessions, disables the account when needed and "
                      "blocks the source IP.",
        ),
        MitreMapping(
            tactic="TA0011", technique="T1090", technique_name="Proxy",
            sub_technique="T1090.003", sub_technique_name="Multi-hop Proxy",
            rationale="A sign-in through Tor or an anonymising proxy chain hides the attacker's origin; it is "
                      "detected from vendor anonymous-IP detections, reputation categories and alerts, and the "
                      "package blocks the exit IP when a source rates it malicious.",
        ),
    ),
    known_limitations=(
        "The autonomous system (ASN) of a sign-in is not in the normalized sign-in record (the Entra normalizer "
        "does not map it), so unusual ASN is not assessed; unusual geography is country-level only.",
        "Impossible travel is computed from countries and times only (two countries within 120 minutes); no "
        "distance or city coordinates are used, and a VPN exit that is neither shared nor allow-listed can look "
        "like travel. Vendor impossible-travel detections are used as reported.",
        "With the real Entra adapter, risk detections (riskDetections, riskyUser: UNVERIFIED), MFA detail and "
        "directory roles are not normalized; anonymising networks are then recognised only from Defender XDR "
        "alerts, reputation categories and the incident itself, and privileged accounts through the "
        "critical-asset patterns and groups.",
        "The baseline is the account's own successful sign-ins in the investigation lookback (14 days, at most "
        "100 records per source); without at least one older sign-in the country and device are not assessed, "
        "and without three the sign-in hour is not assessed (hours are compared in UTC).",
        "The shared-egress check needs typed enterprise sightings (other accounts' sign-ins or internal "
        "endpoints reaching the IP); Entra sign-ins by IP are not queryable through a VERIFIED filter and "
        "hunting rows stay generic, so list the corporate VPN egress in allowlists.never_block (and the VPN "
        "pool in exclusions.third_party_lookup.cidrs) so that a block of it is excluded and never executed.",
        "Sign-in device ids are Entra device ids and are not resolved to Intune managed devices; Intune is read "
        "only for a managed device id the incident names, and its compliance state is a supporting indicator.",
        "HIBP is queried only for addresses the disclosure policy allows (never internal domains or "
        "third_party_lookup.user_domains); breach data is credential exposure, never a recommendation on its "
        "own, and the password reset it calls for is a manual help-desk step (no VERIFIED write).",
        "Session revocation is not reversible, can take a few minutes and does not affect external (guest) "
        "users; MFA re-registration stays a manual help-desk step.",
        "Direct Umbrella IP blocking is UNVERIFIED; IP blocks route to Meraki MX, a Defender for Endpoint "
        "indicator or the native Cisco XDR action.",
        "Thresholds (24-hour recent window, 3 indicator points, 120-minute travel window, 4-hour hour gap) are "
        "fixed in the workflow hooks, not configurable per tenant.",
    ),
    related_workflows=("account-takeover", "mfa-fatigue", "password-spray", "cloud-compromise"),
    handoff_to=("account-takeover",),
)
