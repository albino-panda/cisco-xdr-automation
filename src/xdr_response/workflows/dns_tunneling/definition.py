"""DNS tunneling workflow (Phase 4; replaces ``workflows/dns-tunneling/workflow.yaml``).

Data or command traffic hidden in DNS queries: a client process encodes data into long, random-looking
labels under one parent domain the operator controls and reads the answers (often TXT records) back.
The workflow investigates the parent domain (reputation and the Umbrella "DNS Tunneling VPN"
category, DNS query volume, subdomain variation, label length, label entropy and record types), the
endpoints and processes that issued the queries (including clients found in internal resolver logs
when Umbrella only sees the forwarding resolver), the querying binaries (reputation, prevalence and
code-signing subject) and the transfer pattern. It then RECOMMENDS a containment package: block the
tunnel parent domain once, terminate the querying process and isolate the client endpoint.

Safety properties of the definition (the hooks compute the facts, the framework enforces the rest):

* a parent domain rated CLEAN by reputation is never proposed for a block (a security or VPN product
  that legitimately encodes lookups in DNS looks like a tunnel); it is listed as considered;
* an internal DNS resolver that only forwards client queries (a DNS server process) is never
  isolated; it is listed as considered and the real client is looked up in the resolver logs;
* ``allowlists.approved_dns_tools`` is enforced by the framework on every proposal: an approved tool's
  domains are moved to the package's excluded targets by ``PackageBuilder`` (shown, never executed),
  the termination of an approved binary (by hash or by signer on a prevalence record) is withheld by
  the runner as ``ALLOWLISTED``, and an isolation or an unrated domain block that rests only on
  approved binaries is withheld the same way (``RecommendationRule.binaries``); each is shown as
  considered, never dropped silently.

Like every workflow it only investigates and recommends: it never executes, never approves and never
chooses an approval level. ELEVATED comes from ``PackageBuilder`` (critical assets, blast-radius
caps); execution, verification and restoration happen only in the lifecycle orchestrator after human
approval.
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

__all__ = [
    "WORKFLOW",
    "DNS_SERVER_PROCESSES",
    "DNS_SOURCES",
    "ENDPOINT_SOURCES",
    "MIN_LABEL_ENTROPY",
    "MIN_LONG_LABEL",
    "MIN_PROFILE_INDICATORS",
    "MIN_TUNNEL_QUERIES",
    "MIN_UNIQUE_SUBDOMAINS",
    "TUNNEL_CATEGORY_KEYWORDS",
    "TUNNEL_DETECTION_KEYWORDS",
    "TUNNEL_RECORD_TYPES",
    "TUNNEL_TECHNIQUES",
]

#: ATT&CK ids a detection reports for DNS tunneling (a reported id ties the detection to the tunnel
#: through the querying process; it never rates a domain on its own).
TUNNEL_TECHNIQUES: tuple[str, ...] = ("T1071.004", "T1572")

#: Words (lower case) in a detection name or category that name DNS tunneling.
TUNNEL_DETECTION_KEYWORDS: tuple[str, ...] = ("dns tunnel", "dnstunnel", "dns-tunnel", "dns_tunnel")

#: Vendor DNS categories (lower case substrings) that mark a domain as a DNS tunnel (Umbrella reports
#: "DNS Tunneling VPN").
TUNNEL_CATEGORY_KEYWORDS: tuple[str, ...] = ("dns tunnel",)

#: Behaviour thresholds over the lookback window (the five tunnel indicators). Each is a measured
#: value cited from records; none of them rates a domain on its own.
#: Frequency: queries under one parent domain (the legacy threshold).
MIN_TUNNEL_QUERIES = 1000
#: Subdomain variation: distinct child names under one parent domain.
MIN_UNIQUE_SUBDOMAINS = 200
#: Query length: the longest label (DNS allows 63 characters per label).
MIN_LONG_LABEL = 40
#: Entropy: mean Shannon entropy (bits per character) of the observed child labels of at least 12
#: characters (encoded data looks random).
MIN_LABEL_ENTROPY = 3.5
#: Record types that carry data back to the client.
TUNNEL_RECORD_TYPES: tuple[str, ...] = ("TXT", "NULL")
#: A behaviour profile needs at least this many of the five indicators, one of them volume or
#: subdomain variation.
MIN_PROFILE_INDICATORS = 3

#: Executable names (lower case) of DNS server software. A host whose only queries for a parent come
#: from these processes is a resolver forwarding client queries: it is never isolated.
DNS_SERVER_PROCESSES: tuple[str, ...] = ("dns.exe", "named", "named.exe", "unbound", "unbound.exe", "dnsmasq",
                                         "dnsmasq.exe", "pdns_recursor", "pdns_server", "coredns", "coredns.exe",
                                         "kresd")

#: Endpoint sources the endpoint and hash steps ask (subset of the required and optional integrations).
ENDPOINT_SOURCES: tuple[str, ...] = ("secure_endpoint", "defender_endpoint", "cisco_xdr")
#: DNS activity sources (resolver and DNS security logs) for the enterprise domain search.
DNS_SOURCES: tuple[str, ...] = ("splunk", "cisco_xdr", "defender_endpoint")

_ENDPOINTS = "results.investigate_endpoint"
_DNS_RECORDS = (f"flatten([r.dns_queries for r in {_ENDPOINTS}])"
                " + flatten([r.dns_queries for r in results.search_domain_enterprise])")
#: The tunnel parent domains: the incident's domains (the detection names the parent) and the domains
#: a DNS source reports as an aggregate over subdomains. Never every random child name.
_PARENTS = ("get(incident.observables_by_type, 'domain', [])"
            f" + [q.domain for q in {_DNS_RECORDS} if q.unique_subdomains]")
#: Endpoints the DNS sources name as querying clients (the real client behind a forwarding resolver
#: comes from the resolver's own log), after the incident's endpoints.
_CLIENT_SUBJECTS = ("get(incident.observables_by_type, 'hostname', [])"
                    f" + [q.endpoint for q in {_DNS_RECORDS} if q.endpoint]")
#: Hashes of the processes that issued DNS queries, and of tunneling-related detections.
_QUERYING_HASHES = (
    f"[e.sha256 for e in flatten([r.trajectory for r in {_ENDPOINTS}]) if e.sha256 and e.domain]"
    f" + [d.sha256 for d in flatten([r.detections for r in {_ENDPOINTS}]) if d.sha256]"
)

_FACT_ASSET = "{'groups': item.groups, 'tags': item.tags, 'ip': item.ip, 'users': item.users}"
_CLIENT_RATIONALE = (
    "'tunnel client ' + item.hostname + ': ' + item.process_list + ' queried ' + item.domain_list"
    " + ' (' + item.basis + ')'"
)

WORKFLOW = WorkflowDefinition(
    id="dns-tunneling",
    version="2.0.0",
    name="DNS tunneling",
    description=(
        "Respond to data or command traffic hidden in DNS queries: investigate the tunnel parent domain "
        "(reputation, the DNS tunneling category, query volume and frequency, subdomain variation, label "
        "length and entropy, record types), the endpoints and processes that issued the queries (also behind "
        "an internal resolver), the querying binaries and the transfer pattern, and recommend a containment "
        "package (block the parent domain, terminate the querying process, isolate the client endpoint) for "
        "human approval. Clean-rated domains, forwarding resolvers and approved DNS tools "
        "(allowlists.approved_dns_tools) are never contained; they are shown as considered or excluded."
    ),
    phase=4,
    default_severity=Severity.HIGH,
    legacy_id="dns-tunneling",
    triggers=(
        TriggerSpec(type="xdr_incident_rule", priority=170,
                    description="Cisco XDR incident whose detection reports DNS application-layer traffic or "
                                "protocol tunneling and names a domain or an endpoint",
                    mitre_techniques=TUNNEL_TECHNIQUES,
                    observable_types=(ObservableType.DOMAIN, ObservableType.HOSTNAME)),
        TriggerSpec(type="xdr_incident_rule", priority=165,
                    description="Cisco XDR or Umbrella incident titled as DNS tunneling (for example an Umbrella "
                                "DNS Tunneling VPN category hit) that names a domain or an endpoint",
                    title_patterns=("*dns tunnel*", "*dns-tunnel*", "*tunneling over dns*", "*tunnelling over dns*",
                                    "*dns tunneling vpn*"),
                    observable_types=(ObservableType.DOMAIN, ObservableType.HOSTNAME)),
        TriggerSpec(type="manual",
                    description="An analyst starts the workflow from an incident, a domain or an endpoint "
                                "observable"),
    ),
    input_observables=(ObservableType.DOMAIN, ObservableType.HOSTNAME, ObservableType.IP, ObservableType.SHA256),
    required_integrations=(
        IntegrationRequirement(
            integration="umbrella",
            purpose="Domain status and categories of the tunnel parent domain (DNS Tunneling VPN category), and "
                    "the landing product for approved domain blocks",
            atomics=("enrich_domain",)),
        IntegrationRequirement(
            integration="secure_endpoint",
            purpose="Endpoint record, device trajectory (the process that issued the DNS queries), hash "
                    "prevalence and signer, and the isolation of the client endpoint",
            atomics=("investigate_endpoint", "search_hash_enterprise")),
    ),
    optional_integrations=(
        IntegrationRequirement(
            integration="splunk",
            purpose="Internal resolver and DNS security logs: query volume, subdomain variation, label length, "
                    "record types and the real client behind a forwarding resolver",
            atomics=("search_domain_enterprise",)),
        IntegrationRequirement(
            integration="defender_endpoint",
            purpose="Second endpoint source (machine, alerts, timeline, prevalence), DNS activity rows, and "
                    "isolation or process termination for the endpoints it manages",
            atomics=("investigate_endpoint", "search_hash_enterprise", "search_domain_enterprise")),
        IntegrationRequirement(
            integration="cisco_xdr",
            purpose="Platform verdicts and sightings for the parent domain and the querying binaries, and the "
                    "native response actions the router prefers when configured",
            atomics=("investigate_endpoint", "search_hash_enterprise", "search_domain_enterprise",
                     "enrich_domain", "enrich_hash")),
        IntegrationRequirement(
            integration="virustotal",
            purpose="Public reputation of the parent domain and the querying binaries",
            atomics=("enrich_domain", "enrich_hash")),
        IntegrationRequirement(
            integration="alienvault_otx",
            purpose="Independent reputation (OTX pulses, passive DNS) for the parent domain and the querying "
                    "binaries",
            atomics=("enrich_domain", "enrich_hash")),
    ),
    investigation=(
        InvestigationStep(id="endpoint_triage", atomic="investigate_endpoint", integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="dns_activity", atomic="search_domain_enterprise", subjects=_PARENTS,
                          subject_type=ObservableType.DOMAIN, integrations=DNS_SOURCES, max_subjects=10),
        InvestigationStep(id="tunnel_clients", atomic="investigate_endpoint", subjects=_CLIENT_SUBJECTS,
                          subject_type=ObservableType.HOSTNAME, integrations=ENDPOINT_SOURCES),
        InvestigationStep(id="parent_reputation", atomic="enrich_domain", subjects=_PARENTS,
                          subject_type=ObservableType.DOMAIN, max_subjects=10),
        InvestigationStep(id="querying_binary_reputation", atomic="enrich_hash", subjects=_QUERYING_HASHES,
                          subject_type=ObservableType.SHA256, max_subjects=10),
        InvestigationStep(id="querying_binary_prevalence", atomic="search_hash_enterprise",
                          subjects=_QUERYING_HASHES, subject_type=ObservableType.SHA256,
                          integrations=ENDPOINT_SOURCES, max_subjects=10),
    ),
    correlation=CorrelationSpec(
        description=(
            "Framework links: the same domain, hash or IP on two or more endpoints (one tunnel parent or one "
            "client binary across the estate), the same endpoint or user across sources, and process lineage. "
            "Workflow links (hooks): a tunnel client (the endpoint, the querying binary and the parent domain "
            "its process queried). Child names are grouped under their parent domain, so many random "
            "subdomains give one tunnel and at most one block. Links within 120 minutes count; they shape the "
            "blast radius and the decision card, never the approval level."),
        link_kinds=(LinkKind.SAME_HASH, LinkKind.SAME_DOMAIN, LinkKind.SAME_IP, LinkKind.SAME_USER,
                    LinkKind.SAME_ENDPOINT, LinkKind.PROCESS_LINEAGE),
        window_minutes=120,
    ),
    scoring=ScoringInputs(
        description=(
            "Reputation answers (Umbrella, Cisco XDR, VirusTotal, OTX) are vendor verdicts, capped by the "
            "engine; one vendor alone is never an aggregate MALICIOUS verdict. DNS and network records with a "
            "verdict and malicious or suspicious process events count as behaviour. The tunnel pattern itself "
            "(the DNS tunneling category with high volume, or a behaviour profile of volume, subdomain variation, "
            "long labels, label entropy and data-carrying record types) is a hook-derived network_behaviour "
            "signal (SUSPICIOUS, severity 70) that cites the DNS and process records it was computed from, "
            "attributed to the source of those records; the same pattern scores the client endpoint and the "
            "querying process. Umbrella and Secure Endpoint are the expected sources: when one fails, "
            "confidence drops and the run notes it, but other evidence still produces the recommendation."),
    ),
    recommendations=(
        RecommendationRule(
            id="block_tunnel_parent_domain",
            description="Block the tunnel parent domain once (never each random subdomain) when it is a confirmed "
                        "tunnel: rated malicious, tied to a tunneling detection, in the DNS tunneling category "
                        f"with at least {MIN_TUNNEL_QUERIES} queries, or matching the behaviour profile; never "
                        "when reputation rates it clean",
            action=ActionType.BLOCK_DOMAIN,
            for_each="[t for t in facts.tunnels if t.confirmed]",
            target="item.domain",
            evidence="item.record_ids",
            # an unrated tunnel rests on the behaviour of its clients: when every querying binary is an
            # approved DNS tool (hash or signer), the framework withholds the block (ALLOWLISTED, considered)
            binaries="[] if item.rated else item.client_hashes",
            rationale="'DNS tunnel parent domain ' + item.domain + ' (' + item.basis + '; ' + item.transfer_text + ')'",
            min_risk=40,
            mitre=("T1071.004", "T1572"),
        ),
        RecommendationRule(
            id="terminate_tunnel_process",
            description="Terminate a running process that issued DNS queries under a confirmed tunnel parent "
                        "domain (DNS server processes forwarding client queries are never targeted)",
            action=ActionType.TERMINATE_PROCESS,
            builder="terminate_process",
            for_each="facts.processes",
            target="item.target",
            evidence="item.record_ids",
            include_target_enrichment=False,
            asset=_FACT_ASSET,
            rationale="'process ' + item.process + ' on ' + item.endpoint + ' queried ' + item.domain_list"
                      " + ' (' + item.basis + ')'",
            min_risk=50,
            mitre=("T1071.004", "T1572"),
        ),
        RecommendationRule(
            id="isolate_tunnel_client_secure_endpoint",
            description="Isolate (Secure Endpoint) a client endpoint whose process queried a confirmed tunnel "
                        "parent domain, unless isolation is known to be impossible",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_secure_endpoint",
            for_each="[c for c in facts.clients if c.isolation_capable != False]",
            when="item.connector_guid",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_FACT_ASSET,
            binaries="item.binaries",
            params={"connector_guid": "item.connector_guid"},
            rationale=_CLIENT_RATIONALE,
            min_risk=50,
            mitre=("T1071.004", "T1572"),
        ),
        RecommendationRule(
            id="isolate_tunnel_client_defender_endpoint",
            description="Isolate (Defender for Endpoint) a client endpoint whose process queried a confirmed "
                        "tunnel parent domain (a duplicate of the Secure Endpoint proposal is merged)",
            action=ActionType.ISOLATE_ENDPOINT,
            builder="isolate_defender_endpoint",
            for_each="[c for c in facts.clients if c.isolation_capable != False]",
            when="item.mde_machine_id",
            target="item.hostname",
            evidence="item.record_ids",
            asset=_FACT_ASSET,
            binaries="item.binaries",
            rationale=_CLIENT_RATIONALE,
            min_risk=50,
            mitre=("T1071.004", "T1572"),
        ),
    ),
    mitre=(
        MitreMapping(tactic="TA0011", technique="T1071", technique_name="Application Layer Protocol",
                     sub_technique="T1071.004", sub_technique_name="DNS",
                     rationale="The workflow responds to command or data traffic carried in DNS queries and "
                               "answers: it blocks the parent domain the client queries, terminates the querying "
                               "process and isolates the client endpoint."),
        MitreMapping(tactic="TA0011", technique="T1572", technique_name="Protocol Tunneling",
                     rationale="DNS tunneling encapsulates another protocol or a data stream inside DNS; the "
                               "workflow measures the encapsulation pattern (volume, subdomain variation, label "
                               "length and entropy, record types) and contains the tunnel endpoints."),
    ),
    known_limitations=(
        "Hooks and rule expressions cannot read allowlists.approved_dns_tools: the framework enforces it on the "
        "proposals (an approved tool's domains are excluded by the package builder; the termination of an "
        "approved binary or signer is withheld; an isolation or an unrated domain block that rests only on "
        "approved binaries is withheld). An approved_dns_tools entry that lists only a name protects nothing; "
        "list the tool's hashes, signers and domains.",
        "No DNS activity endpoint is VERIFIED in docs/integrations.md (Umbrella reporting is not listed), and real "
        "Splunk rows, Cisco XDR sightings, Defender hunting rows and Secure Endpoint trajectory events have no "
        "documented field schema, so with the real adapters they stay generic records: citable, never scored. "
        "Query volume, subdomain variation, label length, record types and the querying process come only from "
        "typed sources; until a schema is VERIFIED a real tenant gets a block proposal only when reputation "
        "rates the parent malicious or a typed source reports the pattern.",
        "Label entropy is computed from the child names the records report; a source that reports only an "
        "aggregate (count and unique subdomains) gives no entropy, and entropy is never used alone.",
        "Parent domains are the incident's domains and the domains a DNS source aggregates over subdomains; "
        "other names are grouped by a two-label heuristic (three labels under a known second-level public "
        "suffix). A tunnel under a deeper delegated zone of a shared provider may be grouped too broadly; the "
        "analyst checks the block target before approving, and only enriched parents carry a reputation.",
        "Terminate process has no VERIFIED vendor endpoint, so with the real adapters it is reported UNROUTED "
        "for manual handling in the endpoint console; only the simulated lab executes it.",
        "Removing the tunnel client binary and assessing what data left through the tunnel have no VERIFIED "
        "write or read: both are listed as manual steps.",
        "A host whose only queries come from a DNS server process (dns.exe, named, unbound, dnsmasq and others) "
        "is treated as a forwarding resolver and never isolated; the real client must come from resolver logs "
        "(Splunk). A tunnel client that renames itself to a DNS server process name on a non-resolver host is "
        "shown as a resolver, never silently skipped.",
        "A host named only by DNS logs, with no endpoint record of the querying process, is not isolated "
        "(it may be another forwarder); it is listed as considered for the analyst.",
        "Secure Endpoint isolation verifies as UNABLE_TO_VERIFY (its isolation-state read is UNVERIFIED); "
        "Umbrella destination-list blocks are read back.",
        "Third-party reputation is subject to the disclosure policy and to VirusTotal's public quota: internal "
        "domains are never sent, and a withheld or failed source lowers confidence and is listed as degraded.",
    ),
    related_workflows=("c2", "exfiltration", "malware"),
)
