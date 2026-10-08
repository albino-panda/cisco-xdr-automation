"""Suspicious PowerShell and LOLBin workflow (Phase 3; replaces ``workflows/malicious-powershell/workflow.yaml``).

An endpoint alert about a script interpreter or a signed Windows system binary used as a proxy
(PowerShell, pwsh, mshta, rundll32, regsvr32, certutil, wmic, wscript, cscript, bitsadmin,
installutil). Running one of these binaries is **not** malicious on its own: administrators,
deployment agents and the operating system use them every day. The workflow therefore investigates
what the run actually did, from the run's own records:

* the vendor's view of the command line and the process (endpoint detections naming the process,
  with the ATT&CK techniques the vendor reported, and the process event's own verdict);
* the parent and child processes (process lineage);
* the network destinations the process contacted and their reputation;
* download activity: files the process wrote (and their origin) and children it started, and the
  reputation and prevalence of those payload hashes;
* the user and the endpoint.

It then RECOMMENDS a containment package: terminate the malicious process, isolate the endpoint
where a malicious payload landed or ran, block the payload hash, and block the malicious download or
command-and-control (C2) destinations (domain, URL, public IP).

Like every workflow it only investigates and recommends. It never executes, never approves and
never chooses an approval level: the lifecycle packages the proposals, ``PackageBuilder`` applies
ELEVATED (critical assets, blast-radius caps), a human approves, and only then does the orchestrator
execute, verify and (after a separate human release approval) restore.

The rules read hook facts (``hooks.py``) computed from the run's records; every rule's ``evidence``
expression cites record ids of those records only.
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

__all__ = ["WORKFLOW", "LOLBINS", "LOLBIN_IMAGES", "MAX_HASH_BLOCK_PREVALENCE", "ENDPOINT_SOURCES",
           "WRITE_EVENT_TYPES", "START_EVENT_TYPES"]

#: The binaries this workflow evaluates (lower-case image names without ``.exe``).
LOLBINS: tuple[str, ...] = ("powershell", "pwsh", "mshta", "rundll32", "regsvr32", "certutil", "wmic",
                            "wscript", "cscript", "bitsadmin", "installutil")

#: The same names as the process-name values a rule expression compares (with and without ``.exe``).
LOLBIN_IMAGES: tuple[str, ...] = tuple(n for name in LOLBINS for n in (name, f"{name}.exe"))

#: A malicious payload hash seen on more endpoints than this is not proposed for a fleet-wide block
#: (a wrong disposition would break a business application everywhere at once); a human decides.
MAX_HASH_BLOCK_PREVALENCE = 10

#: Process-event types that start a process, and that write a file.
START_EVENT_TYPES: tuple[str, ...] = ("process_start", "file_execute")
WRITE_EVENT_TYPES: tuple[str, ...] = ("file_create", "file_modify", "file_rename")

#: Endpoint sources the investigation steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")

_IMAGES = repr(list(LOLBIN_IMAGES))
_STARTS = repr(list(START_EVENT_TYPES))
_WRITES = repr(list(WRITE_EVENT_TYPES))

_TRAJECTORY = "flatten([r.trajectory for r in results.investigate_endpoint])"
_EVENTS = ("flatten([r.trajectory for r in results.investigate_endpoint]"
           " + [r.events for r in results.investigate_process] + [r.children for r in results.investigate_process])")
_CONNECTIONS = ("flatten([r.network_connections for r in results.investigate_endpoint]"
                " + [r.network_connections for r in results.investigate_process])")
_DNS = "flatten([r.dns_queries for r in results.investigate_endpoint])"

#: ``<HOST>/<pid>`` of every LOLBin process start the endpoint triage found.
_PROCESS_SUBJECTS = (
    f"distinct([e.endpoint + '/%d' % e.pid for e in {_TRAJECTORY}"
    f" if e.pid != None and e.event_type in {_STARTS} and lower(e.process_name) in {_IMAGES}])"
)
#: Payload candidates: incident hashes, detection hashes, files written on the endpoint and images of
#: non-LOLBin processes (a LOLBin's own image hash is a system binary, never a payload).
_HASH_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'sha256', [])"
    " + [d.sha256 for d in flatten([r.detections for r in results.investigate_endpoint]) if d.sha256]"
    f" + [e.sha256 for e in {_EVENTS} if e.sha256 and (e.event_type in {_WRITES}"
    f" or (e.event_type in {_STARTS} and lower(e.process_name) not in {_IMAGES}))])"
)
#: Other endpoints where a payload rated MALICIOUS by the endpoint source is present (hash prevalence).
_AFFECTED_SUBJECTS = ("distinct(flatten([r.endpoints for r in results.search_hash_enterprise"
                      " if r.verdict == 'MALICIOUS']))")
_DOMAIN_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'domain', [])"
    f" + [c.domain for c in {_CONNECTIONS} if c.domain]"
    f" + [q.domain for q in {_DNS} if q.domain]"
    f" + [e.domain for e in {_EVENTS} if e.domain])"
)
_IP_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'ip', [])"
    f" + [c.remote_ip for c in {_CONNECTIONS} if c.remote_ip and c.direction != 'inbound']"
    f" + [e.remote_ip for e in {_EVENTS} if e.remote_ip])"
)
_URL_SUBJECTS = (
    "distinct(get(incident.observables_by_type, 'url', [])"
    f" + [c.url for c in {_CONNECTIONS} if c.url])"
)

_ENDPOINT_ASSET = ("{'groups': item.groups, 'tags': item.tags,"
                   " 'ip': item.ip_addresses[0] if item.ip_addresses else None}")
_FACT_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip}"
_ISOLATE_WHEN = "item.isolation_capable != False and get(facts.isolate, item.hostname, None) != None"
_ISOLATE_EVIDENCE = "get(facts.isolate, item.hostname, {'record_ids': []}).record_ids"
_ISOLATE_RATIONALE = "get(facts.isolate, item.hostname, {'summary': ''}).summary"
_NETWORK_WHEN = ("item.enrichment_verdict == 'MALICIOUS' or item.contact_verdict == 'MALICIOUS'"
                 " or (item.enrichment_verdict == 'SUSPICIOUS' and item.payload_confirmed)")
_NETWORK_RATIONALE = ("item.type + ' ' + item.value + ' contacted by ' + item.process_list"
                      " + ' (enrichment ' + item.enrichment_verdict + ', contact ' + item.contact_verdict"
                      " + (', a malicious payload came from it' if item.payload_confirmed else '') + ')'")

WORKFLOW = WorkflowDefinition(
    id="malicious-powershell",
    version="2.0.0",
    name="Suspicious PowerShell",
    description=(
        "Handle an endpoint alert about PowerShell or another script host or signed system binary used "
        "as a proxy (pwsh, mshta, rundll32, regsvr32, certutil, wmic, wscript, cscript, bitsadmin, "
        "installutil). Use of these binaries alone is not malicious: the workflow evaluates the vendor's "
        "detections and reported techniques for the process, its parent and children, the network "
        "destinations it contacted, the files it downloaded and their reputation and prevalence, the user "
        "and the endpoint, and recommends a containment package (terminate the process, isolate the "
        "endpoint, block the payload hash and the malicious download or C2 destinations) for human approval."
    ),
    phase=3,
    default_severity=Severity.MEDIUM,
    legacy_id="malicious-powershell",
    triggers=(
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident whose detection reports PowerShell, obfuscated or encoded "
                                "content, or system binary proxy execution",
                    mitre_techniques=("T1059.001", "T1027", "T1218"), priority=125),
        TriggerSpec(type="xdr_incident_rule",
                    description="Cisco XDR incident titled after PowerShell or one of the evaluated system "
                                "binaries that carries an endpoint",
                    title_patterns=("*powershell*", "*pwsh*", "*mshta*", "*rundll32*", "*regsvr32*",
                                    "*certutil*", "*wmic*", "*wscript*", "*cscript*", "*bitsadmin*",
                                    "*installutil*", "*lolbin*", "*living off the land*"),
                    observable_types=(ObservableType.HOSTNAME,), priority=110),
        TriggerSpec(type="webhook",
                    description="Endpoint product or SIEM webhook (incident id only) for a PowerShell detection; "
                                "the incident is re-read through the VERIFIED Cisco XDR APIs",
                    sources=("secure_endpoint", "defender_endpoint", "splunk"),
                    mitre_techniques=("T1059.001",), priority=100),
        TriggerSpec(type="manual", description="An analyst starts the workflow from an incident or observable"),
    ),
    input_observables=(ObservableType.HOSTNAME, ObservableType.SHA256, ObservableType.DOMAIN, ObservableType.IP,
                       ObservableType.URL, ObservableType.USER),
    required_integrations=(
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint detections, device trajectory (process chain, file writes, connections), hash "
                    "prevalence and the isolation of the endpoint",
            atomics=("investigate_endpoint", "investigate_process", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the payload hashes and of the domains, IPs and URLs the process "
                    "contacted",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip", "enrich_url")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, detections, timeline) and isolation or indicator blocks "
                    "for the endpoints it manages",
            atomics=("investigate_endpoint", "investigate_process", "search_hash_enterprise")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings for every observable, and the native response actions",
            atomics=("investigate_endpoint", "search_hash_enterprise", "enrich_hash", "enrich_domain",
                     "enrich_ip", "enrich_url")),
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain reputation and the landing product for approved domain and URL blocks",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses) for the payload hashes and the destinations",
            atomics=("enrich_hash", "enrich_domain", "enrich_ip", "enrich_url")),
        IntegrationRequirement(
            integration="splunk",
            purpose="Script block and process logging from the SIEM (generic records: citable, never scored)",
            atomics=("investigate_process",)),
        IntegrationRequirement(
            integration="meraki",
            purpose="Landing product for approved public IP blocks (MX layer 3 rules)",
            atomics=()),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="process_tree", atomic="investigate_process", subjects=_PROCESS_SUBJECTS,
                          integrations=("secure_endpoint", "defender_endpoint", "splunk"), max_subjects=10),
        InvestigationStep(id="payload_reputation", atomic="enrich_hash", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, max_subjects=10),
        InvestigationStep(id="payload_prevalence", atomic="search_hash_enterprise", subjects=_HASH_SUBJECTS,
                          subject_type=ObservableType.SHA256, integrations=ENDPOINT_SOURCES, max_subjects=10),
        InvestigationStep(id="affected_endpoints", atomic="investigate_endpoint", subjects=_AFFECTED_SUBJECTS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES, max_subjects=10),
        InvestigationStep(id="domain_reputation", atomic="enrich_domain", subjects=_DOMAIN_SUBJECTS,
                          max_subjects=15),
        InvestigationStep(id="ip_reputation", atomic="enrich_ip", subjects=_IP_SUBJECTS,
                          subject_type=ObservableType.IP, max_subjects=15),
        InvestigationStep(id="url_reputation", atomic="enrich_url", subjects=_URL_SUBJECTS, max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: parent/child process lineage, the same hash, domain, IP or URL on two or more "
            "endpoints or users, and the same endpoint or user across sources. Workflow links (hooks): a "
            "system binary process and each destination it contacted, and a system binary process and each "
            "payload it wrote or started. Links within 120 minutes count; they shape the blast radius and the "
            "decision card, never the approval level."),
        link_kinds=(LinkKind.PROCESS_LINEAGE, LinkKind.SAME_HASH, LinkKind.SAME_DOMAIN, LinkKind.SAME_IP,
                    LinkKind.SAME_URL, LinkKind.SAME_USER, LinkKind.SAME_ENDPOINT),
        window_minutes=120,
    ),
    scoring=ScoringInputs(
        description=(
            "Endpoint detections that name the process or its payload dominate (endpoint_detection, weight "
            "1.0); malicious process events and malicious hash prevalence count as endpoint detection; network "
            "records with a verdict count as network behaviour; VirusTotal, OTX, Cisco XDR and Umbrella answers "
            "are vendor reputation, capped by the engine, and one vendor alone is never an aggregate MALICIOUS "
            "verdict. Running a system binary adds nothing to the score. Secure Endpoint and VirusTotal are the "
            "expected sources: when one fails, confidence drops and the run notes it, but the other evidence "
            "still produces the recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="terminate_malicious_script_process",
            description="Terminate a running system binary process whose activity is malicious (malicious payload, "
                        "vendor detection, or a malicious destination on an endpoint with a malicious detection)",
            action=ActionType.TERMINATE_PROCESS,
            builder="terminate_process",
            for_each="facts.terminate",
            target="item.target",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_FACT_ASSET,
            rationale="item.process + ' is still running on ' + item.endpoint + ': ' + item.basis",
            min_risk=50,
            mitre=("T1059.001", "T1218"),
        ),
        RecommendationRule(
            id="isolate_secure_endpoint",
            description="Isolate (Secure Endpoint) an endpoint where a payload retrieved by a system binary landed, "
                        "or where a malicious detection follows contact with a malicious destination",
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
            mitre=("T1059.001", "T1105"),
        ),
        RecommendationRule(
            id="isolate_defender_endpoint",
            description="Isolate (Defender for Endpoint) an endpoint where a payload retrieved by a system binary "
                        "landed, or where a malicious detection follows contact with a malicious destination",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="results.investigate_endpoint",
            when=f"item.mde_machine_id and {_ISOLATE_WHEN}",
            target="item.hostname",
            evidence=_ISOLATE_EVIDENCE,
            asset=_ENDPOINT_ASSET,
            rationale=_ISOLATE_RATIONALE,
            min_risk=60,
            mitre=("T1059.001", "T1105"),
        ),
        RecommendationRule(
            id="block_payload_hash",
            description=f"Block a malicious payload hash a system binary wrote or started, when it is seen on "
                        f"{MAX_HASH_BLOCK_PREVALENCE} endpoints or fewer (or its prevalence is unknown)",
            action=ActionType.BLOCK_HASH,
            builder="block_hash",
            for_each="facts.payloads",
            when=f"item.prevalence == None or item.prevalence <= {MAX_HASH_BLOCK_PREVALENCE}",
            target="item.sha256",
            evidence="item.record_ids",
            rationale="'payload ' + item.sha256 + ' retrieved by ' + item.process_list + ' rated malicious ('"
                      " + item.basis + '), seen on ' + item.prevalence_text + ' endpoint(s)'",
            min_risk=50,
            mitre=("T1105",),
        ),
        RecommendationRule(
            id="block_c2_domain",
            description="Block a download or C2 domain a system binary process contacted, when it is rated "
                        "malicious, or suspicious while a malicious payload came from it",
            action=ActionType.BLOCK_DOMAIN,
            for_each="[d for d in facts.destinations if d.type == 'domain']",
            when=_NETWORK_WHEN,
            target="item.value",
            evidence="item.record_ids",
            rationale=_NETWORK_RATIONALE,
            min_risk=40,
            mitre=("T1105",),
        ),
        RecommendationRule(
            id="block_c2_url",
            description="Block a download or C2 URL a system binary process contacted, when it is rated malicious",
            action=ActionType.BLOCK_URL,
            builder="block_url",
            for_each="[d for d in facts.destinations if d.type == 'url']",
            when=_NETWORK_WHEN,
            target="item.value",
            evidence="item.record_ids",
            rationale=_NETWORK_RATIONALE,
            min_risk=40,
            mitre=("T1105",),
        ),
        RecommendationRule(
            id="block_c2_ip",
            description="Block a public IP address a system binary process downloaded from or called back to, "
                        "when it is rated malicious",
            action=ActionType.BLOCK_IP,
            builder="block_ip",
            for_each="[d for d in facts.destinations if d.type == 'ip']",
            when=_NETWORK_WHEN,
            target="item.value",
            evidence="item.record_ids",
            rationale=_NETWORK_RATIONALE,
            min_risk=40,
            mitre=("T1105",),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0002", technique="T1059", technique_name="Command and Scripting Interpreter",
                     sub_technique="T1059.001", sub_technique_name="PowerShell",
                     rationale="The workflow's core subject: it evaluates PowerShell (powershell, pwsh) processes "
                               "and terminates a malicious one, isolates the endpoint and blocks its payload."),
        MitreMapping(tactic="TA0002", technique="T1059", technique_name="Command and Scripting Interpreter",
                     rationale="The Windows script hosts (wscript, cscript) are evaluated the same way; the "
                               "script language is not known from the process alone, so only the technique is "
                               "mapped, not a language sub-technique."),
        MitreMapping(tactic="TA0005", technique="T1027", technique_name="Obfuscated Files or Information",
                     rationale="Encoded or obfuscated command content is a trigger: the vendor's detection of it "
                               "is cited as evidence for the process, never treated as malicious on its own."),
        MitreMapping(tactic="TA0005", technique="T1218", technique_name="System Binary Proxy Execution",
                     rationale="Signed system binaries used as a proxy are evaluated by what they ran, wrote and "
                               "contacted, and a malicious one is terminated and contained."),
        MitreMapping(tactic="TA0005", technique="T1218", technique_name="System Binary Proxy Execution",
                     sub_technique="T1218.004", sub_technique_name="InstallUtil",
                     rationale="installutil is one of the evaluated binaries."),
        MitreMapping(tactic="TA0005", technique="T1218", technique_name="System Binary Proxy Execution",
                     sub_technique="T1218.005", sub_technique_name="Mshta",
                     rationale="mshta is one of the evaluated binaries."),
        MitreMapping(tactic="TA0005", technique="T1218", technique_name="System Binary Proxy Execution",
                     sub_technique="T1218.010", sub_technique_name="Regsvr32",
                     rationale="regsvr32 is one of the evaluated binaries."),
        MitreMapping(tactic="TA0005", technique="T1218", technique_name="System Binary Proxy Execution",
                     sub_technique="T1218.011", sub_technique_name="Rundll32",
                     rationale="rundll32 is one of the evaluated binaries."),
        MitreMapping(tactic="TA0002", technique="T1047", technique_name="Windows Management Instrumentation",
                     rationale="wmic process activity on the endpoint is evaluated like the other binaries "
                               "(remote execution on other hosts is the lateral-movement workflow's job)."),
        MitreMapping(tactic="TA0011", technique="T1105", technique_name="Ingress Tool Transfer",
                     rationale="Download activity (PowerShell, certutil, bitsadmin and the proxy binaries writing "
                               "a payload) is traced to its origin; the payload hash and the malicious download "
                               "destination are blocked and the endpoint is isolated."),
    ),
    known_limitations=(
        "The workflow does not parse command lines itself: command-line characteristics (encoded, obfuscated or "
        "hidden content, download behaviour) reach it only as the endpoint vendor's detections, reported "
        "techniques and process verdicts. A command line no vendor flagged is cited as context, never scored.",
        "With the real adapters, Secure Endpoint trajectory events, Defender timeline rows and Splunk rows have "
        "no documented field schema (docs/integrations.md), so they stay generic records: citable, never scored, "
        "and process, file and connection facts come only from typed sources. Until a schema is VERIFIED, "
        "termination, isolation and blocks are recommended only where typed records exist.",
        "A connection is attributed to a system binary process by image name (and image hash when both are "
        "known) on the same endpoint, and by process id when the connection record carries one; a source "
        "that reports no process id for connections makes two concurrent PowerShell processes on one "
        "endpoint share their connections.",
        "Terminate process has no VERIFIED vendor endpoint (Secure Endpoint and Defender pages not read): with "
        "the real adapters it is reported UNROUTED for manual handling in the endpoint console; only the "
        "simulated lab executes it.",
        "Secure Endpoint hash blocking (file lists) and the isolation-state read are UNVERIFIED: hash blocks "
        "route to the Cisco XDR native action or Defender indicators, and Secure Endpoint isolation verifies as "
        "UNABLE_TO_VERIFY.",
        "The payload file itself is not quarantined by this workflow; it hands off to the malware workflow, "
        "which scopes and quarantines it.",
        f"A malicious payload hash seen on more than {MAX_HASH_BLOCK_PREVALENCE} endpoints is not proposed for "
        "a fleet-wide block, and the image hash of a system binary is never blocked; both are listed as "
        "considered with their records.",
        "An endpoint known to neither Secure Endpoint (connector GUID) nor Defender (machine id) is not proposed "
        "for isolation; the analyst isolates it manually.",
        "IPv6 destinations are not blocked by this workflow (public IPv4 only); internal and non-public "
        "addresses are never proposed.",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota "
        "(4 requests per minute): a withheld or failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("malware", "c2", "persistence", "lateral-movement", "credential-dumping"),
    handoff_to=("malware", "persistence"),
)
