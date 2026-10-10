"""Privilege escalation (Phase 5): an account, a service principal or a process gaining more privilege than expected.

The workflow investigates the originating endpoints the incident names (detections, files and the users
of the device), the accounts involved (the incident's users and the users of those endpoints), their
privilege activity (directory role assignments and activations, privileged group memberships and
high-privilege application permissions: who made each change, to whom, when, with which reference),
then the accounts named by those changes (grantees and actors) and the sign-ins of all of them. It
decides from records only whether each privileged change is normal or anomalous (granted by or to a
compromised account, or self-assigned outside a privileged identity management activation) and
*recommends* a containment package:

* remove an anomalous directory role assignment (always ELEVATED by the catalog);
* revoke the sessions of every account that made or received an anomalous change;
* disable a compromised identity used for the change, a compromised account that elevated itself, and
  an account with no prior sign-in that an anomalous change made privileged (likely attacker-created);
* isolate the originating endpoint where a MALICIOUS detection or file shows the escalation.

An account that received its privilege through an anomalous change is never shielded by that privilege
(a protected group or administrator role): it is proposed with ``privileged: true`` so the
critical-asset policy makes its actions ELEVATED with a visible warning. Privileged group membership,
role assignments without a role definition id and application permissions have no VERIFIED write in
docs/integrations.md: they are **manual steps** with the records that show them. The workflow only
investigates and recommends; every action needs a human approval and the Phase 0 lifecycle executes,
verifies and (after a separate release approval) restores. The decisions live in :mod:`.hooks`.
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

__all__ = ["WORKFLOW", "ENDPOINT_SOURCES", "ACCOUNT_SUBJECTS", "RELATED_SUBJECTS", "ESCALATION_TRIGGER_TECHNIQUES"]

#: Endpoint sources the endpoint step asks (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "microsoft_cloud", "cisco_xdr")

#: Technique trigger: exploitation for privilege escalation, abuse of elevation control (any sub-technique,
#: for example UAC bypass) and account manipulation. Cloud-only sub-techniques of T1098 that
#: cloud-compromise triggers on (T1098.001, T1098.003) route there first (priority 130 over 128).
ESCALATION_TRIGGER_TECHNIQUES: tuple[str, ...] = ("T1068", "T1548", "T1098")

#: Accounts investigated first: the incident's users and user observables, and every directory account
#: (UPN) a record places on an investigated endpoint (logged-on users, detection and process users).
ACCOUNT_SUBJECTS = (
    "distinct([lower(u) for u in incident.users + get(incident.observables_by_type, 'user', [])"
    " + flatten([r.users for r in results.investigate_endpoint])"
    " + [d.user for d in flatten([r.detections for r in results.investigate_endpoint]) if d.user]"
    " + [e.user for e in flatten([r.trajectory for r in results.investigate_endpoint]) if e.user]"
    " if u and '@' in u])"
)
#: Accounts named by the privilege changes found so far (grantees and actors) and the accounts that granted
#: application permissions.
RELATED_SUBJECTS = (
    "distinct([lower(u) for u in flatten([[c.user, c.actor] for c in"
    " flatten([r.role_changes for r in results.search_user_activity])])"
    " + [a.consented_by for a in flatten([r.cloud_apps for r in results.search_user_activity])]"
    " if u and '@' in u])"
)
#: Every account of the run (for the sign-in step).
_ALL_ACCOUNTS = f"distinct({ACCOUNT_SUBJECTS} + {RELATED_SUBJECTS})"
#: Hashes worth a reputation: incident hashes and hashes named by endpoint detections or process events.
_HASH_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'sha256', [])"
    " + [d.sha256 for d in flatten([r.detections for r in results.investigate_endpoint]) if d.sha256]"
    " + [e.sha256 for e in flatten([r.trajectory for r in results.investigate_endpoint]) if e.sha256])"
)

_HOST_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'ips': item.ips, 'users': item.users}"
_USER_ASSET = "{'groups': item.groups, 'roles': item.roles, 'privileged': item.privileged}"
_ISOLATABLE = "item.isolation_capable != False"
_PRIVILEGE_TECHNIQUES = ("T1098", "T1098.003", "T1098.007")
_ENDPOINT_TECHNIQUES = ("T1068", "T1548.002")

WORKFLOW = WorkflowDefinition(
    id="privilege-escalation",
    version="2.0.0",
    name="Privilege escalation",
    description=(
        "Respond to an account, a service principal or a process gaining more privilege than expected: a new "
        "privileged directory role, an unexpected administrator assignment, a privileged group membership "
        "change, a high-privilege permission granted to an application, or an exploit or UAC bypass on an "
        "endpoint. The workflow establishes who made each change, from which device, with which sign-in "
        "context and change reference, and whether it is normal or anomalous, then recommends removing the "
        "unauthorized privilege, revoking the sessions of the accounts involved, disabling the compromised or "
        "attacker-created identity and isolating the originating endpoint. Group membership and application "
        "permission removal are manual steps. Every action waits for a human approval."
    ),
    phase=5,
    default_severity=Severity.HIGH,
    legacy_id="privilege-escalation",
    triggers=(
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident whose detections report exploitation for privilege escalation, abuse of "
                        "an elevation control mechanism (for example a UAC bypass) or account manipulation",
            mitre_techniques=ESCALATION_TRIGGER_TECHNIQUES,
            priority=128,
        ),
        TriggerSpec(
            type="xdr_incident_rule",
            description="Cisco XDR incident titled as a privilege escalation, a privileged role or administrator "
                        "assignment, a privileged group membership change or a UAC bypass, naming a user or endpoint",
            title_patterns=("*privilege escalation*", "*privileged role*", "*admin role assigned*",
                            "*administrator role assigned*", "*role assignment*", "*privileged group*",
                            "*sensitive group*", "*domain admins*", "*enterprise admins*", "*uac bypass*",
                            "*elevation of privilege*", "*local privilege*"),
            observable_types=(ObservableType.USER, ObservableType.HOSTNAME, ObservableType.ENDPOINT_ID),
            priority=104,
        ),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident, a user or an endpoint"),
    ),
    input_observables=(ObservableType.USER, ObservableType.HOSTNAME, ObservableType.ENDPOINT_ID,
                       ObservableType.SHA256),
    required_integrations=(
        IntegrationRequirement(
            integration="entra",
            purpose="Profiles, directory roles, risk state and sign-ins of the accounts involved and their role "
                    "changes; executes the approved session revocation, account disable and role removal",
            atomics=("investigate_user", "search_user_activity", "investigate_authentication"),
        ),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="The originating endpoint: logged-on users, isolation capability, detections and device "
                    "trajectory, and the isolation route",
            atomics=("investigate_endpoint", "enrich_hash"),
        ),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, alerts) and the isolation route for the endpoints it manages",
            atomics=("investigate_endpoint",),
        ),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Microsoft Defender XDR alerts (alerts_v2) about the accounts and the endpoints, for example "
                    "suspicious role or sensitive group changes",
            atomics=("investigate_endpoint", "investigate_user", "search_user_activity"),
        ),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts for the endpoint and its files, and the native response actions the router "
                    "prefers when configured",
            atomics=("investigate_endpoint", "enrich_hash"),
        ),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public file reputation of the exploit or bypass payload hash (disclosure policy applies)",
            atomics=("enrich_hash",),
        ),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent file reputation of the payload hash (disclosure policy applies)",
            atomics=("enrich_hash",),
        ),
        IntegrationRequirement(
            integration="splunk",
            purpose="Optional SIEM search for directory and Windows security events of the accounts (generic rows: "
                    "citable, never scored)",
            atomics=("search_user_activity", "investigate_authentication"),
        ),
    ),
    investigation=(
        InvestigationStep(id="originating_endpoint", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="payload_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
        InvestigationStep(id="account_profile", atomic="investigate_user", subjects=ACCOUNT_SUBJECTS,
                          subject_type=ObservableType.USER),
        InvestigationStep(id="privilege_activity", atomic="search_user_activity", subjects=ACCOUNT_SUBJECTS,
                          lookback_hours=168),
        InvestigationStep(id="related_profile", atomic="investigate_user", subjects=RELATED_SUBJECTS,
                          subject_type=ObservableType.USER),
        InvestigationStep(id="related_activity", atomic="search_user_activity", subjects=RELATED_SUBJECTS,
                          lookback_hours=168),
        InvestigationStep(id="authentication", atomic="investigate_authentication", subjects=_ALL_ACCOUNTS,
                          lookback_hours=72),
    ),
    correlation=CorrelationSpec(
        description=(
            "Role changes, profiles, sign-ins, risk detections and identity alerts are grouped per account, and "
            "detections, process events and logged-on users per endpoint. Framework links tie an account to the "
            "endpoints and records that name it (same_user, same_endpoint) and a successful sign-in to the "
            "account's later privilege change within the window (sign_in_to_activity). The workflow hooks decide, "
            "from records only, which endpoints show the escalation (an active MALICIOUS detection or a file rated "
            "MALICIOUS), which accounts are compromised (identity risk, risky sign-ins, risk detections, identity "
            "alerts, use of an escalated endpoint), and whether each privileged grant is anomalous (made by or to a "
            "compromised account and not before the compromise, or self-assigned outside a privileged identity "
            "activation), normal, pre-existing or unassessed (an identity read failed)."
        ),
        link_kinds=(LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT, LinkKind.SAME_HASH, LinkKind.SIGN_IN_TO_ACTIVITY),
        window_minutes=1440,
    ),
    scoring=ScoringInputs(
        description=(
            "Each target is scored from the records its rule cites. Endpoint detections and malicious process "
            "events are endpoint detections; privileged role changes are persistence (SUSPICIOUS on their own); "
            "identity-provider risk, risky sign-ins and risk detections are authentication anomalies; file "
            "reputation is vendor reputation, capped by the engine (one vendor alone is never an aggregate MALICIOUS "
            "verdict). The hooks add a persistence signal per anomalous grant, cited by its role change records: "
            "MALICIOUS when a compromised account made or received it, SUSPICIOUS when it is only self-assigned. "
            "The account and role actions cite the compromise records that make the change anomalous, so their "
            "risk follows that evidence. Entra and Secure Endpoint are the expected sources: a failed one lowers "
            "confidence and is listed as degraded, and never blocks a recommendation other evidence supports. "
            "Privileged grants are this workflow's primary evidence, so the persistence category weighs 1.0 here "
            "(default 0.8); caps and penalties are unchanged."
        ),
        weights={SignalCategory.PERSISTENCE: 1.0},
    ),
    recommendations=(
        RecommendationRule(
            id="remove_unauthorized_role",
            description="Remove an anomalous privileged directory role assignment that is still in place (granted by "
                        "or to a compromised account, or self-assigned outside a privileged identity activation)",
            action=ActionType.REMOVE_PRIVILEGED_ROLE,
            builder="remove_privileged_role",
            for_each="facts.remove_roles",
            target="item.target",
            evidence="item.record_ids",
            asset="{'groups': item.groups, 'roles': item.roles, 'privileged': True}",
            binaries="item.binaries",
            params={"directory_scope_id": "item.directory_scope_id"},
            rationale="item.summary",
            min_risk=50,
            mitre=("T1098", "T1098.003"),
        ),
        RecommendationRule(
            id="revoke_escalation_sessions",
            description="Revoke every sign-in session of an account that made or received an anomalous privilege "
                        "change, so the new rights cannot be used with an existing token",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="facts.revoke_users",
            target="item.user",
            evidence="item.revoke_record_ids",
            asset=_USER_ASSET,
            binaries="item.revoke_binaries",
            rationale="item.revoke_summary",
            min_risk=50,
            mitre=_PRIVILEGE_TECHNIQUES,
        ),
        RecommendationRule(
            id="disable_escalation_identity",
            description="Disable a compromised identity used for or elevated by an anomalous change, a compromised "
                        "account that elevated itself, or an account with no prior sign-in that an anomalous change "
                        "made privileged",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="facts.disable_users",
            target="item.user",
            evidence="item.disable_record_ids",
            asset=_USER_ASSET,
            binaries="item.disable_binaries",
            rationale="item.disable_summary",
            min_risk=60,
            mitre=_PRIVILEGE_TECHNIQUES,
        ),
        RecommendationRule(
            id="isolate_originating_endpoint_secure_endpoint",
            description="Isolate (Secure Endpoint) the originating endpoint where an active MALICIOUS detection or a "
                        "file rated MALICIOUS shows the escalation",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="facts.isolate_hosts",
            when="item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            binaries="item.binaries",
            params={"connector_guid": "item.connector_guid"},
            rationale="item.summary",
            min_risk=60,
            mitre=_ENDPOINT_TECHNIQUES,
        ),
        RecommendationRule(
            id="isolate_originating_endpoint_defender_endpoint",
            description="Isolate (Defender for Endpoint) the originating endpoint where an active MALICIOUS detection "
                        "or a file rated MALICIOUS shows the escalation (merged with the Secure Endpoint "
                        "recommendation when both products manage the endpoint)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="facts.isolate_hosts",
            when="item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            binaries="item.binaries",
            rationale="item.summary",
            min_risk=60,
            mitre=_ENDPOINT_TECHNIQUES,
        ),
    ),
    mitre=(
        MitreMapping(
            tactic="TA0004", technique="T1068", technique_name="Exploitation for Privilege Escalation",
            rationale="An exploit detection on an endpoint shows a process gaining higher privileges; the "
                      "originating endpoint is isolated and the accounts it was used to change are contained.",
        ),
        MitreMapping(
            tactic="TA0004", technique="T1548", technique_name="Abuse Elevation Control Mechanism",
            sub_technique="T1548.002", sub_technique_name="Bypass User Account Control",
            rationale="A UAC bypass detection on an endpoint is local privilege escalation; the endpoint is "
                      "isolated and its users' privilege changes are assessed.",
        ),
        MitreMapping(
            tactic="TA0003", technique="T1098", technique_name="Account Manipulation",
            rationale="A privileged change to an account that the source reports without a sub-technique (an "
                      "administrator assignment, a new privileged account): the privilege is removed, the "
                      "sessions revoked and the identity disabled when compromised or attacker-created.",
        ),
        MitreMapping(
            tactic="TA0003", technique="T1098", technique_name="Account Manipulation",
            sub_technique="T1098.003", sub_technique_name="Additional Cloud Roles",
            rationale="A privileged Entra directory role or a high-privilege application permission granted by or "
                      "to a compromised account: the role is removed (always ELEVATED) and the application "
                      "permissions are a manual step.",
        ),
        MitreMapping(
            tactic="TA0003", technique="T1098", technique_name="Account Manipulation",
            sub_technique="T1098.007", sub_technique_name="Additional Local or Domain Groups",
            rationale="An account added to a privileged local or domain group (for example Domain Admins): the "
                      "membership removal is a manual step and the account's sessions and identity are contained "
                      "under ELEVATED approval.",
        ),
    ),
    known_limitations=(
        "Privileged group membership (Active Directory or Entra groups), role assignments whose record carries no "
        "role definition id and application (service principal) permissions have no VERIFIED write in "
        "docs/integrations.md: removing them is a manual step in the run notes and analyst summary, never a "
        "package action. Only an Entra directory role assignment is removed by the package.",
        "With the real adapters role and group changes are not normalized: the Entra directory audit log, group "
        "membership reads and the servicePrincipals / oauth2PermissionGrants reads are not in docs/integrations.md, "
        "so on a tenant privilege changes come from typed records of another source; Defender XDR alerts (alerts_v2) "
        "and endpoint detections still feed the compromise assessment and the isolation.",
        "Whether a change was approved cannot be read from a VERIFIED source (no change-management integration). A "
        "change reference the incident reports (trigger.change_reference) is shown as unverified context and never "
        "withholds or creates a recommendation; a privileged grant between accounts with no compromise indicator "
        "that is not self-assigned is shown as considered and the analyst checks the change record.",
        "Account creation is not observed (no VERIFIED source returns it). An account that receives a privilege "
        "through an anomalous change and has no sign-in before the grant (72 hours of sign-ins and the profile's "
        "last sign-in) is treated as created or staged by the attacker and proposed for disable under ELEVATED "
        "approval; an established account keeps only the revocation and the privilege removal.",
        "The originating endpoint is an endpoint the incident names (and the users a record places on it); a "
        "sign-in's device id is not resolved to an endpoint (no atomic), so a privilege change made from an "
        "unnamed device is contained on the identity side only.",
        "Session revocation is not reversible, can take a few minutes, does not reach on-premises Kerberos tickets "
        "or external (guest) users and does not stop application-only tokens of a service principal (the "
        "application permission manual step covers those).",
        "Escalation on an endpoint is recognised from an active MALICIOUS detection or a file whose aggregate "
        "reputation is MALICIOUS; a SUSPICIOUS-only detection is shown as considered, and an endpoint whose "
        "connector policy forbids isolation, or that no endpoint product manages, is contained by hand. When files "
        "rated MALICIOUS are the only basis and every one is sanctioned (allow-listed hash, approved tool hash or "
        "signer), the isolation and the account actions that rest on that endpoint alone (revocation, disable, role "
        "removal) are withheld and shown as considered (rule binaries); the account-takeover hand-off is still "
        "suggested.",
        "Secure Endpoint isolation verifies as UNABLE_TO_VERIFY (its isolation-state read is UNVERIFIED); Defender "
        "for Endpoint isolation verifies through the machine action status.",
    ),
    related_workflows=("account-takeover", "credential-dumping", "persistence", "cloud-compromise"),
    handoff_to=("account-takeover",),
)
