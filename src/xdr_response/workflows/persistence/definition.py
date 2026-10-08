"""Persistence workflow (Phase 3; replaces the legacy spec ``workflows/persistence/workflow.yaml``).

An attacker foothold on an endpoint: a Registry Run key or startup-folder item, a scheduled task, a
new Windows service, a WMI event subscription or a browser extension (where the endpoint source
reports it). The workflow investigates the endpoint (persistence items, detections, trajectory), the
reputation and estate-wide prevalence of every persisted binary, the other endpoints that carry the
same binary and the process tree of the persisted binary. It then RECOMMENDS a containment package:
isolate an endpoint whose persistence is backed by active malicious execution, terminate a running
persisted malicious process and block a malicious persisted binary's hash. Removing the persistence
item itself has no VERIFIED vendor write, so it is a documented **manual step** (hook consideration),
never an automated action.

Like every workflow it only investigates and recommends. It never executes, never approves and never
chooses an approval level: the lifecycle packages the proposals, ``PackageBuilder`` applies ELEVATED
(critical assets, blast-radius caps), a human approves, and only then does the orchestrator execute,
verify and (after a separate human release approval) restore.

The rules read hook facts (``hooks.py``) computed from the run's own records; every rule's
``evidence`` expression cites record ids of those records only.
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

__all__ = ["WORKFLOW", "MAX_HASH_BLOCK_PREVALENCE", "EXECUTION_EVENT_TYPES", "ENDPOINT_SOURCES",
           "ATTACK_IDS", "LOOKBACK_HOURS"]

#: A malicious persisted binary seen on more endpoints than this is not proposed for a fleet-wide hash
#: block (same convention as the malware workflow): a wrong disposition would break a business
#: application everywhere at once. It is listed as considered, with its prevalence record, for a human.
MAX_HASH_BLOCK_PREVALENCE = 10

#: Process-event types that prove a persisted binary ran (or was loaded) on the endpoint.
EXECUTION_EVENT_TYPES: tuple[str, ...] = ("process_start", "file_execute", "module_load")

#: Endpoint sources the investigation steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")

#: Persistence items can be old (a dormant task, a service installed days ago): look back one week.
LOOKBACK_HOURS = 168

#: Sub-techniques this workflow responds to (every rule responds to all of them: the rules act on a
#: persistence item whatever its mechanism).
ATTACK_IDS: tuple[str, ...] = ("T1547.001", "T1053.005", "T1543.003", "T1546.003", "T1176.001")

_ITEMS = "flatten([r.persistence for r in results.investigate_endpoint])"

#: Hashes worth enriching and scoping: incident hashes and the binaries the persistence items launch.
_HASH_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'sha256', [])"
    f" + [p.sha256 for p in {_ITEMS} if p.sha256])"
)
#: Other endpoints that saw a persisted binary not rated clean (a fleet-wide foothold).
_AFFECTED_SUBJECTS = (
    "distinct(flatten([r.endpoints for r in results.search_hash_enterprise if r.verdict != 'CLEAN'"
    " and get(enrichment, 'sha256:' + r.subject, {'verdict': 'UNKNOWN'}).verdict != 'CLEAN']))"
)
#: The process tree of every persisted binary on its endpoint.
_PROCESS_SUBJECTS = f"distinct([p.endpoint + '/' + p.sha256 for p in {_ITEMS} if p.sha256])"

_ENDPOINT_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip_addresses[0] if item.ip_addresses else None}"
_FACT_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}"
_ISOLATE_WHEN = "item.isolation_capable != False and get(facts.isolate, item.hostname, None) != None"
_ISOLATE_EVIDENCE = "get(facts.isolate, item.hostname, {'record_ids': []}).record_ids"
_ISOLATE_RATIONALE = (
    "'persistence on ' + item.hostname + ' is backed by active malicious execution ('"
    " + get(facts.isolate, item.hostname, {'summary': ''}).summary + ')'"
)

WORKFLOW = WorkflowDefinition(
    id="persistence",
    version="2.0.0",
    name="Persistence",
    description=(
        "Handle an attacker foothold on an endpoint (Registry Run key or startup folder item, scheduled "
        "task, new Windows service, WMI event subscription, browser extension where the endpoint source "
        "reports it): investigate the persistence items, the persisted binaries' reputation and prevalence, "
        "the other endpoints that carry them and their process tree, and recommend a containment package "
        "(isolate the endpoint when the persistence is backed by active malicious execution, terminate the "
        "running persisted process, block the malicious persisted binary) for human approval. Removing the "
        "persistence item has no VERIFIED vendor write and is a documented manual step."
    ),
    phase=3,
    default_severity=Severity.MEDIUM,
    legacy_id="persistence",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident whose detection reports a persistence technique (Run key "
                                "or startup folder, scheduled task, Windows service, WMI event subscription, "
                                "browser extension)",
                    mitre_techniques=ATTACK_IDS, priority=120),
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident titled as a new autorun, scheduled task, service, WMI "
                                "subscription, startup item or browser extension that carries an endpoint",
                    title_patterns=("*run key*", "*runonce*", "*autorun*", "*scheduled task*", "*new service*",
                                    "*service install*", "*service created*", "*wmi*subscription*",
                                    "*startup folder*", "*startup item*", "*browser extension*",
                                    "*persistence*"),
                    observable_types=(ObservableType.HOSTNAME,), priority=95),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or an endpoint"),
    ),
    input_observables=(ObservableType.HOSTNAME, ObservableType.SHA256),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint persistence items, detections and trajectory, persisted-binary prevalence and "
                    "the isolation of the endpoint",
            atomics=("investigate_endpoint", "search_hash_enterprise", "investigate_process")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of every persisted binary's hash",
            atomics=("enrich_hash",)),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, detections, timeline) and isolation or hash indicators "
                    "for endpoints it manages",
            atomics=("investigate_endpoint", "search_hash_enterprise", "investigate_process")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) for the persisted binaries",
            atomics=("enrich_hash",)),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings for the endpoint and the hashes, and the native response "
                    "actions",
            atomics=("investigate_endpoint", "search_hash_enterprise", "enrich_hash")),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES,
                          lookback_hours=LOOKBACK_HOURS),
        InvestigationStep(id="persisted_binary_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
        InvestigationStep(id="persisted_binary_prevalence", atomic="search_hash_enterprise",
                          subjects=_HASH_SUBJECTS, subject_type=ObservableType.SHA256,
                          integrations=ENDPOINT_SOURCES, max_subjects=10),
        InvestigationStep(id="affected_endpoints", atomic="investigate_endpoint", subjects=_AFFECTED_SUBJECTS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES,
                          lookback_hours=LOOKBACK_HOURS),
        InvestigationStep(id="persisted_process_tree", atomic="investigate_process", subjects=_PROCESS_SUBJECTS,
                          integrations=("secure_endpoint", "defender_endpoint"), lookback_hours=LOOKBACK_HOURS,
                          max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same hash on two or more endpoints or users (a fleet-wide foothold), the "
            "same endpoint or user across sources, and parent/child process lineage. Workflow links (hooks): "
            "a persistence item tied to the execution events of the binary it launches on the same endpoint. "
            "Links within 120 minutes of each other count; they shape the blast radius and the decision card, "
            "never the approval level."),
        link_kinds=(LinkKind.SAME_HASH, LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT, LinkKind.PROCESS_LINEAGE),
        window_minutes=120,
    ),
    scoring=ScoringInputs(
        description=(
            "Endpoint detections and malicious process events dominate (endpoint_detection, weight 1.0); a "
            "persistence item the endpoint source rates malicious or suspicious is a persistence signal, "
            "weighted 1.0 in this workflow because persistence is what it responds to; hash prevalence marked "
            "malicious counts as endpoint detection; VirusTotal, OTX and Cisco XDR answers are vendor "
            "reputation, capped by the engine, and one vendor alone is never an aggregate MALICIOUS verdict. "
            "Secure Endpoint and VirusTotal are the expected sources: when one fails, confidence drops and "
            "the run notes it, but the other evidence still produces the recommendation."),
        weights={SignalCategory.PERSISTENCE: 1.0},
    ),
    recommendations=(
        RecommendationRule(
            id="isolate_persistence_host_secure_endpoint",
            description="Isolate (Secure Endpoint) an endpoint whose malicious persistence item is backed by "
                        "active malicious execution",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.connector_guid and {_ISOLATE_WHEN}",
            target="item.hostname",
            evidence=_ISOLATE_EVIDENCE,
            asset=_ENDPOINT_ASSET,
            params={"connector_guid": "item.connector_guid"},
            rationale=_ISOLATE_RATIONALE,
            min_risk=60,
            mitre=ATTACK_IDS,
        ),
        RecommendationRule(
            id="isolate_persistence_host_defender_endpoint",
            description="Isolate (Defender for Endpoint) an endpoint whose malicious persistence item is "
                        "backed by active malicious execution",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.mde_machine_id and {_ISOLATE_WHEN}",
            target="item.hostname",
            evidence=_ISOLATE_EVIDENCE,
            asset=_ENDPOINT_ASSET,
            rationale=_ISOLATE_RATIONALE,
            min_risk=60,
            mitre=ATTACK_IDS,
        ),
        RecommendationRule(
            id="terminate_running_persisted_process",
            description="Terminate a running process of a malicious persisted binary",
            action=ActionType.TERMINATE_PROCESS,
            builder="terminate_process",
            for_each="facts.running",
            target="item.target",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_FACT_ASSET,
            rationale="'persisted malicious binary ' + item.process_name + ' is still running on ' + item.endpoint"
                      " + ' (launched by ' + item.launched_by + ')'",
            min_risk=60,
            mitre=ATTACK_IDS,
        ),
        RecommendationRule(
            id="block_malicious_persisted_binary",
            description=f"Block the hash of a malicious persisted binary seen on {MAX_HASH_BLOCK_PREVALENCE} "
                        "endpoints or fewer (or with unknown prevalence)",
            action=ActionType.BLOCK_HASH,
            builder="block_hash",
            for_each="[h for h in facts.hashes if h.malicious]",
            when=f"item.prevalence == None or item.prevalence <= {MAX_HASH_BLOCK_PREVALENCE}",
            target="item.sha256",
            evidence="item.record_ids",
            rationale="'persisted binary rated malicious (' + item.basis + '), launched by ' + item.launched_by"
                      " + ', seen on ' + item.prevalence_text + ' endpoint(s)'",
            min_risk=50,
            mitre=ATTACK_IDS,
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0003", technique="T1547", technique_name="Boot or Logon Autostart Execution",
                     sub_technique="T1547.001", sub_technique_name="Registry Run Keys / Startup Folder",
                     rationale="Run and RunOnce values and startup-folder items reported as persistence items: "
                               "the workflow blocks the malicious binary they launch, isolates the endpoint when "
                               "it is executing, and lists the item's removal as a manual step."),
        MitreMapping(tactic="TA0003", technique="T1053", technique_name="Scheduled Task/Job",
                     sub_technique="T1053.005", sub_technique_name="Scheduled Task",
                     rationale="Scheduled tasks reported as persistence items, including dormant ones that have "
                               "not run yet: the binary is blocked, isolation needs active execution, and deleting "
                               "the task is a manual step."),
        MitreMapping(tactic="TA0003", technique="T1543", technique_name="Create or Modify System Process",
                     sub_technique="T1543.003", sub_technique_name="Windows Service",
                     rationale="New or modified Windows services reported as persistence items, including the "
                               "same service installed on several endpoints: the service binary is blocked, the "
                               "running service process terminated, executing endpoints isolated, and removing "
                               "the service is a manual step."),
        MitreMapping(tactic="TA0003", technique="T1546", technique_name="Event Triggered Execution",
                     sub_technique="T1546.003",
                     sub_technique_name="Windows Management Instrumentation Event Subscription",
                     rationale="WMI event subscriptions reported as persistence items: the consumer's binary is "
                               "blocked and the endpoint isolated when executing; removing the filter, consumer "
                               "and binding is a manual step."),
        MitreMapping(tactic="TA0003", technique="T1176", technique_name="Software Extensions",
                     sub_technique="T1176.001", sub_technique_name="Browser Extensions",
                     rationale="Browser extensions only where the endpoint source reports them as persistence "
                               "items: a malicious extension file hash is blocked and removing the extension is a "
                               "manual step."),
    ),
    known_limitations=(
        "Removing a persistence item (Run value, startup item, scheduled task, service, WMI subscription, "
        "browser extension) has no VERIFIED vendor write in docs/integrations.md and no catalog integration, so "
        "it is never an automated action: every malicious item is listed as a manual step (hook consideration) "
        "with its records, outside the package and outside the decision card's action list.",
        "No VERIFIED vendor read returns persistence items as typed records (Secure Endpoint events and "
        "Defender timeline rows have no documented field schema), so with the real adapters persistence items "
        "stay generic records: citable, never scored. The rules act on typed persistence items (simulated lab "
        "and future normalizers); with the real adapters the hash block still follows enrichment and the "
        "isolation follows typed detections.",
        "Browser extensions are recognised only when the endpoint source reports them as a persistence item: "
        "mechanism browser_extension, or mechanism other with an extension path or name (a source that does "
        "not map the dedicated mechanism); no VERIFIED vendor read maps extensions to typed records yet.",
        "Account creation (legacy mapping T1136) is not handled: no VERIFIED source returns directory or local "
        "account creation as a typed record. Launch agents and cron items are handled like the Windows "
        "mechanisms when reported, but not triggered on or mapped.",
        "Isolation needs active malicious execution on the endpoint (an active MALICIOUS detection or an "
        "execution event of a malicious persisted binary); a dormant malicious item is listed as considered "
        "and its binary is blocked, but the endpoint is not isolated.",
        "A persistence item rated malicious by the endpoint source without a malicious verdict for its binary "
        "never leads to a hash block: the binary may be a legitimate system tool started with malicious "
        "arguments.",
        "Terminate process has no VERIFIED vendor endpoint, so with the real adapters it is reported UNROUTED "
        "for manual handling in the endpoint console; only the simulated lab executes it.",
        "Secure Endpoint hash blocking (file lists) and the isolation-state read are UNVERIFIED: hash blocks "
        "route to the Cisco XDR native action or Defender indicators, and Secure Endpoint isolation verifies "
        "as UNABLE_TO_VERIFY.",
        f"A malicious persisted binary seen on more than {MAX_HASH_BLOCK_PREVALENCE} endpoints is not proposed "
        "for a fleet-wide block; it is listed as considered with its prevalence record and a human decides.",
        "Network indicators the persisted binary contacted are not enriched or blocked here; that is the c2 "
        "workflow's job.",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: a "
        "withheld or failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("malware", "privilege-escalation", "c2"),
)
