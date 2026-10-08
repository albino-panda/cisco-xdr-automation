"""Credential dumping workflow (Phase 3; replaces the legacy spec ``workflows/credential-dumping``).

Credential material was read on an endpoint: LSASS process memory, the Security Account Manager
(SAM) hive, the Active Directory database (NTDS), or a credential-dumping tool or suspicious access
to credential memory that an endpoint product detected. The workflow investigates the endpoints, the
tool's file reputation and prevalence, the other endpoints that hold the same file, and the accounts
whose credentials were cached or used on an affected endpoint. It then RECOMMENDS a containment
package: isolate the endpoints where credential access is confirmed, revoke the sign-in sessions of
the exposed accounts, disable the exposed accounts where that is justified (privileged, or confirmed
compromised by the identity provider) and block the credential-dumping tool's hash.

Like every workflow it only investigates and recommends. It never executes, never approves and never
chooses an approval level: the lifecycle packages the proposals, ``PackageBuilder`` applies ELEVATED
(a domain controller and other critical assets, privileged accounts, blast-radius caps), a human
approves, and only then does the orchestrator execute, verify and (after a separate human release
approval) restore.

The rules read hook facts (:mod:`.hooks`) computed from the run's own records; every rule's
``evidence`` expression cites record ids of those records only.
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

__all__ = ["WORKFLOW", "MAX_HASH_BLOCK_PREVALENCE", "ENDPOINT_SOURCES", "CREDENTIAL_TECHNIQUES"]

#: A credential-dumping tool hash seen on more endpoints than this is not proposed for a fleet-wide
#: block (a wrong disposition, or a misused system binary, would break that file everywhere); it is
#: listed as considered with its prevalence record so a human decides.
MAX_HASH_BLOCK_PREVALENCE = 10

#: Endpoint sources the endpoint and hash steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "microsoft_cloud", "cisco_xdr")

#: ATT&CK ids this workflow responds to (technique and sub-techniques of OS Credential Dumping).
CREDENTIAL_TECHNIQUES: tuple[str, ...] = ("T1003", "T1003.001", "T1003.002", "T1003.003")

_RESPONDS_TO = CREDENTIAL_TECHNIQUES

#: Hashes worth enriching and scoping: incident hashes, hashes named by endpoint detections and hashes
#: of vendor-flagged process events on the investigated endpoints.
_HASH_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'sha256', [])"
    " + [d.sha256 for d in flatten([r.detections for r in results.investigate_endpoint]) if d.sha256]"
    " + [e.sha256 for e in flatten([r.trajectory for r in results.investigate_endpoint])"
    " if e.sha256 and e.verdict in ['MALICIOUS', 'SUSPICIOUS']])"
)
#: Other endpoints that hold a malicious, rare tool file (hash prevalence) or reported a detection.
_AFFECTED_SUBJECTS = (
    "distinct(flatten([r.endpoints for r in results.search_hash_enterprise"
    f" if (r.prevalence == None or r.prevalence <= {MAX_HASH_BLOCK_PREVALENCE})"
    " and (r.verdict == 'MALICIOUS' or r.sha256 in [e.value for e in results.enrich_hash"
    " if e.verdict == 'MALICIOUS'])])"
    " + [d.endpoint for d in flatten([r.detections for r in results.investigate_endpoint]) if d.endpoint])"
)
#: Accounts placed on an investigated endpoint (logged-on or recent users, detection and process
#: users) plus the incident's users; directory accounts (UPNs) only.
_USER_SUBJECTS = (
    "distinct([lower(u) for u in incident.users + get(incident.observables_by_type, 'user', [])"
    " + flatten([r.users for r in results.investigate_endpoint])"
    " + [d.user for d in flatten([r.detections for r in results.investigate_endpoint]) if d.user]"
    " + [e.user for e in flatten([r.trajectory for r in results.investigate_endpoint]) if e.user]"
    " if u and '@' in u])"
)

_HOST_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}"
_USER_ASSET = "{'groups': item.groups, 'roles': item.roles}"
_ISOLATABLE = "item.isolation_capable != False"

WORKFLOW = WorkflowDefinition(
    id="credential-dumping",
    version="3.0.0",
    name="Credential dumping",
    description=(
        "Respond to credential dumping on an endpoint (LSASS memory access, SAM access, NTDS activity, a "
        "credential-dumping tool detection or suspicious access to credential memory): confirm the access "
        "from endpoint detections, flagged process events and the tool's file reputation, scope the other "
        "endpoints that hold the tool and the accounts whose credentials were exposed, and recommend a "
        "containment package for human approval (isolate the endpoint, revoke the exposed accounts' "
        "sessions, disable an exposed account that is privileged or confirmed compromised, block the tool's "
        "hash). A domain controller is always contained under ELEVATED approval."
    ),
    phase=3,
    default_severity=Severity.CRITICAL,
    legacy_id="credential-dumping",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident whose detections report OS Credential Dumping (T1003 or one of "
                                "its sub-techniques: LSASS memory, SAM, NTDS)",
                    mitre_techniques=("T1003",), priority=150),
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident titled as credential dumping or theft, LSASS access, SAM access "
                                "or directory database (NTDS) access that names an endpoint",
                    title_patterns=("*credential dump*", "*credential theft*", "*lsass*", "*ntds*",
                                    "*security account manager*", "*directory database*"),
                    observable_types=(ObservableType.HOSTNAME, ObservableType.ENDPOINT_ID), priority=120),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or an endpoint"),
    ),
    input_observables=(ObservableType.HOSTNAME, ObservableType.ENDPOINT_ID, ObservableType.SHA256,
                       ObservableType.USER),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint context (logged-on users, groups, isolation capability), detections and device "
                    "trajectory of the affected endpoints, hash prevalence, and the isolation route",
            atomics=("investigate_endpoint", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="entra",
            purpose="Profiles, directory roles and risk state of the exposed accounts; executes the approved "
                    "session revocation and account disable",
            atomics=("investigate_user",)),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, alerts, timeline) and the isolation or hash-indicator route "
                    "for the endpoints it manages",
            atomics=("investigate_endpoint", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="microsoft_cloud",
            purpose="Microsoft Defender XDR alerts (typed detections) and hunting searches for the endpoints, the "
                    "tool's prevalence and the exposed accounts",
            atomics=("investigate_endpoint", "search_hash_enterprise", "investigate_user")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings for the endpoints and the tool hash, and the native response "
                    "actions the router prefers when configured",
            atomics=("investigate_endpoint", "search_hash_enterprise", "enrich_hash")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public file reputation of the tool hash (disclosure policy applies)",
            atomics=("enrich_hash",)),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent file reputation (OTX pulses) of the tool hash (disclosure policy applies)",
            atomics=("enrich_hash",)),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="tool_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
        InvestigationStep(id="tool_prevalence", atomic="search_hash_enterprise", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, integrations=ENDPOINT_SOURCES, max_subjects=10,
                          lookback_hours=72),
        InvestigationStep(id="affected_endpoints", atomic="investigate_endpoint", subjects=_AFFECTED_SUBJECTS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES, max_subjects=10),
        InvestigationStep(id="exposed_accounts", atomic="investigate_user", subjects=_USER_SUBJECTS,
                          subject_type=ObservableType.USER, max_subjects=25),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same tool hash on two or more endpoints or users, the same account on several "
            "endpoints, the same endpoint reported with several accounts, and parent/child process lineage on "
            "one endpoint. Workflow links (hooks, kind workflow): credential exposure, which ties an endpoint "
            "where credential access is confirmed to every account a record places on it (logged-on users, "
            "detection and process users). Links within 120 minutes count; they shape the clusters, the blast "
            "radius and the decision card, never the approval level."),
        link_kinds=(LinkKind.SAME_HASH, LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT, LinkKind.PROCESS_LINEAGE),
        window_minutes=120,
    ),
    scoring=ScoringInputs(
        description=(
            "Each target is scored from the records its rule cites. Endpoint detections and vendor-flagged "
            "process events of credential access are endpoint detections (weight 1.0); a hash prevalence record "
            "marked malicious is an endpoint detection; Entra risk detections and a high user risk are "
            "authentication anomalies; VirusTotal, OTX and Cisco XDR answers are vendor reputation, capped by "
            "the engine, and one vendor alone is never an aggregate MALICIOUS verdict. An account's revocation "
            "and disable cite the endpoint evidence that exposed it, so their risk follows the confirmed "
            "credential access. Secure Endpoint and Entra are the expected sources: a failed one lowers "
            "confidence and is listed as degraded, and never blocks a recommendation other evidence supports."),
    ),
    recommendations=(
        RecommendationRule(
            id="isolate_credential_host_secure_endpoint",
            description="Isolate (Secure Endpoint) an endpoint where credential access is confirmed",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="facts.credential_hosts",
            when=f"item.connector_guid and {_ISOLATABLE}",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            params={"connector_guid": "item.connector_guid"},
            rationale="item.summary",
            min_risk=60,
            mitre=_RESPONDS_TO,
        ),
        RecommendationRule(
            id="isolate_credential_host_defender_endpoint",
            description="Isolate (Defender for Endpoint) an endpoint where credential access is confirmed (merged "
                        "with the Secure Endpoint recommendation when both products manage the endpoint)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="facts.credential_hosts",
            when=f"item.mde_machine_id and {_ISOLATABLE}",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_HOST_ASSET,
            rationale="item.summary",
            min_risk=60,
            mitre=_RESPONDS_TO,
        ),
        RecommendationRule(
            id="revoke_exposed_sessions",
            description="Revoke every sign-in session of an account whose credentials were exposed on an endpoint "
                        "where credential access is confirmed",
            action=ActionType.REVOKE_SESSIONS,
            builder="revoke_entra_sessions",
            for_each="facts.exposed_users",
            target="item.user",
            evidence="item.record_ids",
            asset=_USER_ASSET,
            rationale="item.summary",
            min_risk=50,
            mitre=_RESPONDS_TO,
        ),
        RecommendationRule(
            id="disable_exposed_account",
            description="Disable an exposed account that is privileged or that the identity provider confirms "
                        "compromised",
            action=ActionType.DISABLE_USER,
            builder="disable_entra_user",
            for_each="[u for u in facts.exposed_users if u.disable]",
            target="item.user",
            evidence="item.disable_record_ids",
            asset=_USER_ASSET,
            rationale="item.disable_summary",
            min_risk=60,
            mitre=_RESPONDS_TO,
        ),
        RecommendationRule(
            id="block_credential_tool_hash",
            description=f"Block a credential-dumping tool hash whose file reputation is malicious, seen on "
                        f"{MAX_HASH_BLOCK_PREVALENCE} endpoints or fewer (or with unknown prevalence)",
            action=ActionType.BLOCK_HASH,
            builder="block_hash",
            for_each="[h for h in facts.hashes if h.blockable]",
            target="item.sha256",
            evidence="item.record_ids",
            rationale="item.summary",
            min_risk=50,
            mitre=("T1003",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0006", technique="T1003", technique_name="OS Credential Dumping",
                     rationale="A credential-dumping tool detection or suspicious access to credential memory whose "
                               "records do not show the method; the workflow isolates the endpoint, revokes or "
                               "disables the exposed accounts and blocks the tool's hash."),
        MitreMapping(tactic="TA0006", technique="T1003", technique_name="OS Credential Dumping",
                     sub_technique="T1003.001", sub_technique_name="LSASS Memory",
                     rationale="A detection or flagged process event shows access to LSASS process memory, which "
                               "holds the credentials of the accounts signed in to the endpoint; those accounts "
                               "are treated as exposed."),
        MitreMapping(tactic="TA0006", technique="T1003", technique_name="OS Credential Dumping",
                     sub_technique="T1003.002", sub_technique_name="Security Account Manager",
                     rationale="A detection or flagged process event shows access to the SAM hive (local account "
                               "credentials); the endpoint is isolated and its local credentials are reset by hand."),
        MitreMapping(tactic="TA0006", technique="T1003", technique_name="OS Credential Dumping",
                     sub_technique="T1003.003", sub_technique_name="NTDS",
                     rationale="A detection or flagged process event shows access to the Active Directory database "
                               "on a domain controller: every domain credential is exposed, the domain controller "
                               "is isolated under ELEVATED approval and the domain-wide reset is a manual step."),
    ),
    known_limitations=(
        "Credential access is recognised from vendor-reported ATT&CK ids (T1003 family) and from detection or "
        "process names and categories (LSASS, SAM, NTDS, directory database, credential); a vendor detection "
        "that names none of these is not treated as credential dumping.",
        "With the real adapters, Secure Endpoint trajectory events have no documented field schema "
        "(docs/integrations.md), so they stay generic records: citable, never scored. Confirmation then comes "
        "from typed detections (for example Microsoft Defender XDR alerts) or the tool's file reputation.",
        "Exposed accounts are the directory accounts (UPNs) a record places on an affected endpoint (logged-on "
        "or recent users, detection and process users). Local and down-level accounts and the host's local "
        "administrator credential are covered only by the manual credential-reset step.",
        "Password reset, service-account secret rotation and the domain-wide reset after a domain controller "
        "is affected (including the Kerberos ticket-granting account, twice) have no VERIFIED automated "
        "action; they are manual steps owned by the incident commander and are never in the package.",
        "An account is disabled only when the identity provider shows it privileged (profile flag, a privileged "
        "directory role, a privileged role assigned or activated during the incident, or the privileged-account "
        "policy) or confirms it compromised; when the identity source "
        "fails, the disable is listed as considered and only the revocation is proposed.",
        "Session revocation is not reversible, can take a few minutes and does not reach on-premises Kerberos "
        "tickets or external (guest) users.",
        f"A tool hash seen on more than {MAX_HASH_BLOCK_PREVALENCE} endpoints, a hash named only by a behaviour "
        "detection (often a misused system binary) and a hash rated clean are never blocked; they are listed as "
        "considered with their records.",
        "Secure Endpoint hash blocking and its isolation-state read are UNVERIFIED: hash blocks route to the Cisco "
        "XDR native action or Defender indicators, and Secure Endpoint isolation verifies as UNABLE_TO_VERIFY.",
        "An endpoint known to neither Secure Endpoint (connector GUID) nor Defender (machine id), or whose "
        "connector policy forbids isolation, is not proposed for isolation; it is listed as considered.",
    ),
    related_workflows=("account-takeover", "lateral-movement", "privilege-escalation", "malware"),
    handoff_to=("account-takeover",),
)
