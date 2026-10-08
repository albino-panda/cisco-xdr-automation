"""Pure hooks of the DNS tunneling workflow (architecture 14.3.3 and 14.10.1).

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters, no
configuration) and derive:

* ``facts`` for the rule expressions:

  - ``tunnels``: one entry per parent domain (child names are grouped under their parent, so many
    random subdomains give one tunnel), with the measured indicators (query volume and rate,
    subdomain variation, longest label, label entropy, data-carrying record types), the DNS tunneling
    category, the reputation and record verdicts, the client and resolver hosts, the transfer pattern
    and whether the parent is a *confirmed* tunnel;
  - ``clients``: endpoints whose (non DNS server) process queried a confirmed tunnel, with the
    querying processes, their binaries and the endpoint identity for isolation;
  - ``processes``: those querying processes that were not seen ending (termination targets).

  Every fact carries the record ids it was computed from, and the rules cite exactly those ids.
* ``derive_signals``: the tunnel pattern as a ``network_behaviour`` signal (SUSPICIOUS) for the
  parent domain, the client endpoint and the querying process, citing the DNS and process records it
  was computed from and attributed to the source of those records;
* ``correlate`` links of kind ``WORKFLOW``: a tunnel client (endpoint, querying binary, parent);
* ``considered`` items (unconfirmed or clean-rated parents, forwarding resolvers, endpoints that
  cannot be isolated or are named only by DNS logs) and manual steps (removing the client binary,
  assessing what left through the tunnel, finding the client behind a resolver).

The hooks never see ``allowlists.approved_dns_tools``: the framework applies it to every proposal
(excluded domains, approved binaries and signers, rule ``binaries``). Nothing here creates a record,
scores a target, chooses an approval level or calls a vendor; a hook that fails is noted and ignored
by the runner.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
)
from xdr_response.models import Observable, ObservableType, TargetKind, Verdict, same_endpoint
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.dns_tunneling.definition import (
    DNS_SERVER_PROCESSES,
    MIN_LABEL_ENTROPY,
    MIN_LONG_LABEL,
    MIN_PROFILE_INDICATORS,
    MIN_TUNNEL_QUERIES,
    MIN_UNIQUE_SUBDOMAINS,
    TUNNEL_CATEGORY_KEYWORDS,
    TUNNEL_DETECTION_KEYWORDS,
    TUNNEL_RECORD_TYPES,
    TUNNEL_TECHNIQUES,
)
from xdr_response.workflows.hooks import Consideration, RunView, WorkflowHooks

__all__ = [
    "DnsTunnelingHooks",
    "HOOKS",
    "PATTERN_SEVERITY",
    "PATTERN_CONFIDENCE",
    "is_dns_server",
    "label_entropy",
    "names_tunnel",
    "parent_of",
    "registrable_domain",
]

#: Severity and confidence of the hook-derived tunnel pattern signal (network_behaviour, SUSPICIOUS).
PATTERN_SEVERITY = 70
PATTERN_CONFIDENCE = 60

_FLAGGING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_VERDICT_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2,
                                        Verdict.MALICIOUS: 3}
#: Second-level labels that act as public suffixes under a two-letter country code (``co.uk``).
_SECOND_LEVEL = frozenset({"ac", "co", "com", "edu", "go", "gob", "gov", "mil", "ne", "net", "or", "org"})
#: Child labels shorter than this are too short for a meaningful entropy.
_ENTROPY_MIN_LENGTH = 12


# ------------------------------------------------------------------ helpers --
def _norm(name: str | None) -> str:
    return (name or "").strip().lower().rstrip(".")


def registrable_domain(name: str | None) -> str:
    """The parent a name is grouped under when no known parent covers it: the last two labels, or the
    last three under a second-level public suffix of a two-letter country code (``x.example.co.uk``)."""
    labels = [label for label in _norm(name).split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parent_of(name: str | None, known: Iterable[str]) -> str | None:
    """The tunnel parent of a queried name: the shortest known parent (incident domain, aggregated or
    enriched domain) that equals or contains it, else :func:`registrable_domain`. None for a name
    without a dot (an internal single-label host)."""
    domain = _norm(name)
    if not domain or "." not in domain:
        return None
    matches = [k for k in (_norm(k) for k in known) if "." in k and (domain == k or domain.endswith("." + k))]
    if matches:
        return min(matches, key=lambda k: (k.count("."), k))
    return registrable_domain(domain)


def _child_labels(name: str, parent: str) -> list[str]:
    """The labels of ``name`` below ``parent`` (``a1.b2.parent`` -> ``["a1", "b2"]``)."""
    if name == parent or not name.endswith("." + parent):
        return []
    return [label for label in name[: -(len(parent) + 1)].split(".") if label]


def label_entropy(label: str) -> float:
    """Shannon entropy of a label in bits per character (0.0 for an empty label)."""
    if not label:
        return 0.0
    counts = Counter(label.lower())
    size = len(label)
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def _base(name: str | None) -> str:
    """Lower-case file name of a process name or path (``C:\\x\\dns.exe`` -> ``dns.exe``)."""
    if not name:
        return ""
    return re.split(r"[\\/]", name.strip())[-1].strip().lower()


def is_dns_server(process_name: str | None) -> bool:
    """True when the process is DNS server software that forwards client queries."""
    return _base(process_name) in DNS_SERVER_PROCESSES


def names_tunnel(text: str | None) -> bool:
    """True when a detection name or category names DNS tunneling."""
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in TUNNEL_DETECTION_KEYWORDS)


def _tunnel_category(categories: Iterable[str]) -> bool:
    return any(c and any(k in c.lower() for k in TUNNEL_CATEGORY_KEYWORDS) for c in categories)


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v], default=Verdict.UNKNOWN)


def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _under(name: str | None, parent: str) -> bool:
    domain = _norm(name)
    return bool(domain) and (domain == parent or domain.endswith("." + parent))


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


def _observable(otype: ObservableType, value: str) -> Observable | None:
    try:
        return Observable(type=otype, value=value)
    except ValueError:
        return None


class _Tunnel:
    """The records and measurements of one parent domain (private helper)."""

    def __init__(self, parent: str) -> None:
        self.parent = parent
        self.dns: list[DnsQueryRecord] = []
        self.events: list[ProcessEventRecord] = []
        self.connections: list[NetworkConnectionRecord] = []
        self.detections: list[DetectionRecord] = []
        self.report: ObservableReport | None = None


class _Facts:
    """One computation of the facts over a run view (private helper of :class:`DnsTunnelingHooks`)."""

    def __init__(self, view: RunView) -> None:
        records = view.index.records()
        self.incident_hosts = {o.value.upper() for o in view.incident.observables
                               if o.type is ObservableType.HOSTNAME}
        self.dns = [r for r in records if isinstance(r, DnsQueryRecord)]
        self.all_events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                                 key=lambda e: (e.timestamp, e.record_id))
        self.query_events = [e for e in self.all_events if e.event_type == "network" and e.domain]
        self.connections = [r for r in records if isinstance(r, NetworkConnectionRecord) and r.domain]
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self._hashed = [r for r in records if isinstance(r, (ProcessEventRecord, DetectionRecord,
                                                              NetworkConnectionRecord, PersistenceItemRecord,
                                                              HashPrevalenceRecord)) and r.sha256]
        self.reports: dict[str, ObservableReport] = {
            r.value.lower(): r for r in view.results
            if isinstance(r, ObservableReport) and r.type is ObservableType.DOMAIN}
        known = {o.value for o in view.incident.observables if o.type is ObservableType.DOMAIN}
        known |= {q.domain for q in self.dns if q.unique_subdomains}
        known |= set(self.reports)
        self.known = {_norm(k) for k in known if "." in _norm(k)}
        self.tunnels = self._group()
        self._measures = {p: self._measure(t) for p, t in self.tunnels.items()}
        self._clients, self._resolvers, self._dns_only = self._hosts()

    # ---------------------------------------------------------------- grouping --
    def _group(self) -> dict[str, _Tunnel]:
        tunnels: dict[str, _Tunnel] = {}

        def entry(name: str | None) -> _Tunnel | None:
            parent = parent_of(name, self.known)
            if parent is None:
                return None
            return tunnels.setdefault(parent, _Tunnel(parent))

        for parent in sorted(self.known):
            entry(parent)
        for q in self.dns:
            t = entry(q.domain)
            if t is not None:
                t.dns.append(q)
        for e in self.query_events:
            t = entry(e.domain)
            if t is not None:
                t.events.append(e)
        for c in self.connections:
            parent = parent_of(c.domain, self.known)
            if parent is not None and parent in tunnels:
                tunnels[parent].connections.append(c)
        for parent, t in tunnels.items():
            t.report = self.reports.get(parent)
            t.detections = self._tunnel_detections(t)
        return dict(sorted(tunnels.items()))

    def _tunnel_detections(self, t: _Tunnel) -> list[DetectionRecord]:
        """Detections that name DNS tunneling (technique or words) and are tied to a process that queried
        the parent on the same endpoint (same SHA-256 or same executable name)."""
        out = []
        for d in self.detections:
            named = (any(str(x).upper().startswith(TUNNEL_TECHNIQUES) for x in d.mitre_techniques)
                     or names_tunnel(d.name) or names_tunnel(d.category))
            if not named or not d.endpoint:
                continue
            for e in t.events:
                if e.endpoint != d.endpoint:
                    continue
                same_hash = bool(d.sha256 and e.sha256 and d.sha256.lower() == e.sha256.lower())
                same_name = bool(_base(d.process_name) and _base(d.process_name) == _base(e.process_name))
                if same_hash or same_name:
                    out.append(d)
                    break
        return out

    # -------------------------------------------------------------- measuring --
    def _measure(self, t: _Tunnel) -> dict[str, Any]:
        names = {_norm(q.domain) for q in t.dns} | {_norm(e.domain) for e in t.events}
        children = sorted({".".join(_child_labels(n, t.parent)) for n in names} - {""})
        labels = sorted({label for child in children for label in child.split(".")})
        long_labels = [label for label in labels if len(label) >= _ENTROPY_MIN_LENGTH]
        entropy = (round(sum(label_entropy(label) for label in long_labels) / len(long_labels), 2)
                   if long_labels else None)
        # One source may report the same queries as a parent aggregate, per endpoint and per child name:
        # per source, the largest of those views counts (never their sum), then the largest source.
        views: dict[tuple[str, str], int] = {}
        for q in t.dns:
            view = ("child" if _norm(q.domain) != t.parent else "endpoint" if q.endpoint else "aggregate")
            views[(q.integration, view)] = views.get((q.integration, view), 0) + q.count
        # a resolver's forwarded queries are its clients' queries seen again: never added to them
        client_events = sum(e.count for e in t.events if not is_dns_server(e.process_name))
        resolver_events = sum(e.count for e in t.events if is_dns_server(e.process_name))
        volume = max([*views.values(), client_events, resolver_events, 0])
        unique = max([*(q.unique_subdomains or 0 for q in t.dns), len(children)])
        longest = max([*(q.max_label_length or 0 for q in t.dns), *(len(label) for label in labels), 0])
        query_types = sorted({q.query_type.upper() for q in t.dns if q.query_type})
        categories = sorted({*(c for q in t.dns for c in q.categories),
                             *(t.report.categories() if t.report is not None else ())})
        indicators = []
        if volume >= MIN_TUNNEL_QUERIES:
            indicators.append("volume")
        if unique >= MIN_UNIQUE_SUBDOMAINS:
            indicators.append("subdomain variation")
        if longest >= MIN_LONG_LABEL:
            indicators.append("long labels")
        if entropy is not None and entropy >= MIN_LABEL_ENTROPY:
            indicators.append("label entropy")
        if set(query_types) & set(TUNNEL_RECORD_TYPES):
            indicators.append("data record types")
        report_verdict = t.report.verdict if t.report is not None else Verdict.UNKNOWN
        record_verdict = _worst([*(q.verdict for q in t.dns), *(e.verdict for e in t.events),
                                 *(c.verdict for c in t.connections)])
        flagged_detections = [d for d in t.detections if d.verdict in _FLAGGING]
        tunnel_category = _tunnel_category(categories)
        clean = report_verdict is Verdict.CLEAN
        malicious = (report_verdict is Verdict.MALICIOUS or record_verdict is Verdict.MALICIOUS
                     or any(d.verdict is Verdict.MALICIOUS for d in flagged_detections))
        rated = report_verdict in _FLAGGING or record_verdict in _FLAGGING or bool(flagged_detections)
        category_volume = tunnel_category and volume >= MIN_TUNNEL_QUERIES
        profile = (len(indicators) >= MIN_PROFILE_INDICATORS
                   and ("volume" in indicators or "subdomain variation" in indicators))
        pattern = category_volume or profile
        confirmed = not clean and (malicious or pattern or bool(flagged_detections))
        rating: list[str] = []
        if report_verdict in _FLAGGING or clean:
            rating.append(f"reputation {report_verdict.value}")
        if record_verdict in _FLAGGING:
            rating.append(f"DNS or process record {record_verdict.value}")
        for d in flagged_detections:
            rating.append(f"detection '{d.name}' {d.verdict.value} on {d.endpoint}")
        if tunnel_category:
            rating.append("category " + ", ".join(c for c in categories if _tunnel_category([c])))
        indicator_text = (f"{len(indicators)} of 5 tunnel indicators"
                          + (f" ({', '.join(indicators)})" if indicators else ""))
        times = [*(x for q in t.dns for x in (q.first_seen, q.last_seen) if x is not None),
                 *(e.timestamp for e in t.events)]
        first, last = (min(times), max(times)) if times else (None, None)
        minutes = int((last - first).total_seconds() // 60) if first is not None and last is not None else 0
        child_lengths = [len(c) for c in children]
        per_query = (round(sum(child_lengths) / len(child_lengths)) if child_lengths else longest)
        upstream = volume * per_query
        transfer = [f"{volume} queries"]
        if minutes >= 1:
            transfer.append(f"over {minutes} min ({round(volume / minutes, 1)} per min)")
        if upstream:
            transfer.append(f"up to about {max(1, round(upstream / 1024))} KB of encoded labels upstream")
        if query_types:
            transfer.append("record types " + ", ".join(query_types))
        support = ([r for r in t.report.records if isinstance(r, EnrichmentRecord) and r.verdict in _FLAGGING]
                   if t.report is not None and report_verdict in _FLAGGING else [])
        aggregate = [q for q in t.dns if q.unique_subdomains or _tunnel_category(q.categories)
                     or q.verdict in _FLAGGING]
        # reputation answers that put the parent in the DNS tunneling category back that claim (14.12.3)
        support += [r for r in (t.report.records if t.report is not None else ())
                    if isinstance(r, EnrichmentRecord) and _tunnel_category(r.categories) and r not in support]
        return {
            "domain": t.parent,
            "confirmed": confirmed,
            "rated": rated,
            "clean": clean,
            "malicious": malicious,
            "pattern": pattern,
            "reputation": report_verdict.value,
            "record_verdict": record_verdict.value,
            "tunnel_category": tunnel_category,
            "categories": categories,
            "volume": volume,
            "unique_subdomains": unique,
            "max_label_length": longest,
            "entropy": entropy,
            "query_types": query_types,
            "indicators": indicators,
            "indicator_count": len(indicators),
            "basis": "; ".join([*rating, indicator_text]),
            "first_seen": first.isoformat() if isinstance(first, datetime) else None,
            "last_seen": last.isoformat() if isinstance(last, datetime) else None,
            "queries_per_minute": round(volume / minutes, 1) if minutes >= 1 else None,
            "upstream_bytes_estimate": upstream,
            "transfer_text": ", ".join(transfer),
            "detections": [d.name for d in flagged_detections],
            # the records that make the parent a tunnel: aggregated or rated DNS records, detections
            # and the reputation answers that rate it (cited by isolations and terminations too)
            "basis_ids": _ids([*aggregate, *flagged_detections, *support]),
            "pattern_ids": _ids([*t.dns, *t.events]),
            "record_ids": _ids([*t.dns, *t.events, *t.connections, *flagged_detections, *support]),
            "all_ids": _ids([*t.dns, *t.events, *t.connections, *t.detections,
                             *(t.report.records if t.report is not None else ())]),
        }

    # ------------------------------------------------------------------ hosts --
    def _hosts(self) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        """``(clients, resolvers, dns_only)`` over the confirmed tunnels."""
        clients: dict[str, dict[str, Any]] = {}
        resolvers: dict[str, dict[str, Any]] = {}
        for parent, t in self.tunnels.items():
            if not self._measures[parent]["confirmed"]:
                continue
            for e in t.events:
                bucket = resolvers if is_dns_server(e.process_name) else clients
                entry = bucket.setdefault(e.endpoint, {"domains": [], "events": []})
                if parent not in entry["domains"]:
                    entry["domains"].append(parent)
                entry["events"].append(e)
        for host in list(resolvers):
            if host in clients:  # a host with a client process is a client, whatever else it runs
                del resolvers[host]
        dns_only: dict[str, dict[str, Any]] = {}
        for parent, t in self.tunnels.items():
            if not self._measures[parent]["confirmed"]:
                continue
            for q in t.dns:
                host = q.endpoint
                if not host or host in clients or host in resolvers:
                    continue
                entry = dns_only.setdefault(host, {"domains": [], "records": []})
                if parent not in entry["domains"]:
                    entry["domains"].append(parent)
                entry["records"].append(q)
        return dict(sorted(clients.items())), dict(sorted(resolvers.items())), dict(sorted(dns_only.items()))

    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        return {
            "groups": list(dict.fromkeys(g for e in mine for g in e.groups)),
            "tags": list(dict.fromkeys(t for e in mine for t in e.tags)),
            "users": list(dict.fromkeys(u for e in mine for u in e.users)),
            "ip": next((a for e in mine for a in e.ip_addresses), None),
        }

    def _identity(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        capable = [e.isolation_capable for e in mine if e.isolation_capable is not None]
        return {
            "connector_guid": next((e.connector_guid for e in mine if e.connector_guid), None),
            "mde_machine_id": next((e.mde_machine_id for e in mine if e.mde_machine_id), None),
            "isolation_capable": True if True in capable else (False if capable else None),
            "endpoint_ids": _ids(mine),
        }

    @staticmethod
    def _binary(e: ProcessEventRecord) -> str:
        """The SHA-256 of a querying process, or ``name:<executable>`` when no hash is known (a value that
        is never a sanctioned binary, so nothing is withheld on a name)."""
        if e.sha256:
            return e.sha256.lower()
        return f"name:{_base(e.process_name) or 'unknown'}"

    def _candidates(self, e: ProcessEventRecord) -> tuple[list[str], list[str]]:
        """``(binaries, record_ids)``: every binary a querying process event may have run (14.12.6).

        The same identification as the runner's ``_process_candidates`` (14.11.6, 14.11.7), so the
        rules' ``binaries`` (isolation, unrated domain block) and the termination agree. An event with a
        SHA-256 is that binary. A hashless event (a DNS query row that names only the process) takes every
        hash the process events of the same host and pid report (process ids are reused: all count) and
        every hash the host's records give for the same executable (process events, detections,
        connections, persistence items, hash prevalence records listing the host) or a connection of the
        same pid. It is identified only when a record names the same executable with a hash, or a
        connection of that pid reports one; otherwise ``name:<executable>`` is added, a value that is
        never sanctioned, so nothing is withheld on a name or on an older binary of a reused pid.
        """
        if e.sha256:
            return [e.sha256.lower()], []
        name = _base(e.process_name) or _base(e.file_path)
        hashes: dict[str, None] = {}
        ids: dict[str, None] = {}
        identified = False
        for record in self._hashed:
            names: tuple[str | None, ...] = ()
            same_pid = False
            if isinstance(record, HashPrevalenceRecord):
                on_host = any(same_endpoint(str(h), e.endpoint) for h in record.endpoints)
                names = (record.file_name,)
            else:
                on_host = bool(record.endpoint) and same_endpoint(str(record.endpoint), e.endpoint)
                if isinstance(record, (ProcessEventRecord, DetectionRecord)):
                    names = (record.process_name, record.file_path)
                elif isinstance(record, NetworkConnectionRecord):
                    names = (record.process_name,)
                else:
                    names = (record.path, record.name)
                if isinstance(record, (ProcessEventRecord, NetworkConnectionRecord)):
                    same_pid = e.pid is not None and record.pid is not None and record.pid == e.pid
            if not on_host:
                continue
            named = bool(name) and name in {_base(n) for n in names}
            if isinstance(record, NetworkConnectionRecord):
                if not (named or same_pid):
                    continue
                identified = True
            elif isinstance(record, ProcessEventRecord):
                if not (named or same_pid):
                    continue
                identified = identified or named
            elif not named:
                continue
            else:
                identified = True
            hashes[str(record.sha256).lower()] = None
            ids[record.record_id] = None
        if not identified:
            hashes[f"name:{name or 'unknown'}"] = None
        return list(hashes), list(ids)

    def _host_dns(self, host: str, domains: Sequence[str]) -> list[DnsQueryRecord]:
        return [q for parent in domains for q in self.tunnels[parent].dns if q.endpoint == host]

    def clients(self) -> list[dict[str, Any]]:
        out = []
        for host, entry in self._clients.items():
            events: list[ProcessEventRecord] = entry["events"]
            domains: list[str] = entry["domains"]
            identity = self._identity(host)
            processes = list(dict.fromkeys(e.process_name or "unknown process" for e in events))
            basis = "; ".join(f"{d}: {self._measures[d]['basis']}" for d in domains)
            resolved = [self._candidates(e) for e in events]
            ids = [*_ids(events), *_ids(self._host_dns(host, domains)),
                   *(i for d in domains for i in self._measures[d]["basis_ids"]), *identity.pop("endpoint_ids"),
                   *(i for _b, found in resolved for i in found)]
            out.append({
                "hostname": host,
                "domains": domains,
                "domain_list": ", ".join(domains),
                "processes": processes,
                "process_list": ", ".join(processes),
                "binaries": list(dict.fromkeys(b for binaries, _i in resolved for b in binaries)),
                "basis": basis,
                "record_ids": list(dict.fromkeys(ids)),
                **identity,
                **self._context(host),
            })
        return out

    def _ended(self, start: ProcessEventRecord) -> bool:
        if start.pid is None:
            return False
        return any(end.event_type == "process_end" and end.endpoint == start.endpoint and end.pid == start.pid
                   and end.timestamp >= start.timestamp for end in self.all_events)

    def processes(self) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for host, entry in self._clients.items():
            for e in entry["events"]:
                if self._ended(e):
                    continue
                ident = str(e.pid) if e.pid is not None else (e.sha256 or "").lower()
                if not ident:
                    continue
                target = f"{host}/{ident}"
                domains = [d for d in entry["domains"] if _under(e.domain, d)]
                found = out.setdefault(target, {
                    "target": target, "endpoint": host, "pid": e.pid,
                    "sha256": e.sha256.lower() if e.sha256 else None,
                    "process": e.process_name or "unknown process", "domains": [], "events": [],
                    **self._context(host)})
                for d in domains:
                    if d not in found["domains"]:
                        found["domains"].append(d)
                found["events"].append(e)
        result = []
        for target in sorted(out):
            found = out[target]
            events = found.pop("events")
            domains = found["domains"]
            found["domain_list"] = ", ".join(domains)
            found["basis"] = "; ".join(f"{d}: {self._measures[d]['basis']}" for d in domains)
            found["record_ids"] = list(dict.fromkeys(
                [*_ids(events), *(i for d in domains for i in self._measures[d]["basis_ids"])]))
            result.append(found)
        return result

    def tunnels_facts(self) -> list[dict[str, Any]]:
        out = []
        for parent, m in self._measures.items():
            relevant = (m["confirmed"] or m["tunnel_category"] or m["indicator_count"] >= 1
                        or m["record_verdict"] in ("MALICIOUS", "SUSPICIOUS") or parent in self.known)
            if not relevant or not m["all_ids"]:
                continue
            clients = [h for h, e in self._clients.items() if parent in e["domains"]]
            resolvers = [h for h, e in self._resolvers.items() if parent in e["domains"]]
            hashes = [b for h in clients for e in self._clients[h]["events"] if _under(e.domain, parent)
                      for b in self._candidates(e)[0]]
            out.append({
                **{k: v for k, v in m.items() if k not in ("all_ids", "pattern_ids")},
                "clients": clients,
                "resolvers": resolvers,
                "dns_only_hosts": [h for h, e in self._dns_only.items() if parent in e["domains"]],
                "client_hashes": list(dict.fromkeys(hashes)),
            })
        return out

    def as_dict(self) -> dict[str, Any]:
        return {"tunnels": self.tunnels_facts(), "clients": self.clients(), "processes": self.processes()}

    # ---------------------------------------------------------------- signals --
    def signals(self, origin: str) -> list[ScoringSignal]:
        out: list[ScoringSignal] = []

        def emit(otype: ObservableType, value: str, records: Sequence[AnyRecord], note: str) -> None:
            observable = _observable(otype, value)
            if observable is None:
                return
            by_source: dict[str, list[str]] = {}
            for record in records:
                by_source.setdefault(record.integration, []).append(record.record_id)
            for integration, ids in sorted(by_source.items()):
                out.append(ScoringSignal(
                    category=SignalCategory.NETWORK_BEHAVIOUR, integration=integration, observable=observable,
                    verdict=Verdict.SUSPICIOUS, severity=PATTERN_SEVERITY, confidence=PATTERN_CONFIDENCE,
                    record_ids=tuple(dict.fromkeys(ids)), origin=origin, note=note))

        for parent, t in self.tunnels.items():
            m = self._measures[parent]
            if m["confirmed"] and m["pattern"]:
                emit(ObservableType.DOMAIN, parent, [*t.dns, *t.events], f"DNS tunnel pattern under {parent}: "
                     f"{m['basis']}")
        for host, entry in self._clients.items():
            emit(ObservableType.HOSTNAME, host, entry["events"],
                 f"{host} queried confirmed DNS tunnel parent(s) {', '.join(entry['domains'])}")
            for e in entry["events"]:
                if self._ended(e):
                    continue
                ident = str(e.pid) if e.pid is not None else (e.sha256 or "").lower()
                if ident:
                    emit(ObservableType.PROCESS, f"{host}/{ident}", [e],
                         f"{e.process_name or 'process'} on {host} queried a confirmed DNS tunnel")
        return out

    # ------------------------------------------------------------------ links --
    def links(self, origin: str) -> list[CorrelationLink]:
        links: dict[str, CorrelationLink] = {}
        for host, entry in self._clients.items():
            for parent in entry["domains"]:
                events = [e for e in entry["events"] if _under(e.domain, parent)]
                by_binary: dict[str, list[ProcessEventRecord]] = {}
                for e in events:
                    by_binary.setdefault(self._binary(e), []).append(e)
                for binary, group in sorted(by_binary.items()):
                    entities = [x for x in (_entity(TargetKind.ENDPOINT, host), _entity(TargetKind.DOMAIN, parent),
                                            _entity(TargetKind.HASH, None if binary.startswith("name:") else binary))
                                if x is not None]
                    if len(entities) < 2:
                        continue
                    times = [e.timestamp for e in group]
                    link = CorrelationLink(
                        kind=LinkKind.WORKFLOW, entities=tuple(entities), record_ids=tuple(_ids(group)),
                        first_seen=min(times), last_seen=max(times),
                        note=f"tunnel client: {group[0].process_name or 'process'} on {host} queried "
                             f"{sum(e.count for e in group)} name(s) under {parent}",
                        origin=origin)
                    links.setdefault(link.link_id, link)
        return [links[k] for k in sorted(links)]

    # ---------------------------------------------------------- consideration --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for parent, m in self._measures.items():
            if m["confirmed"] or not m["all_ids"]:
                continue
            if m["clean"] and (m["tunnel_category"] or m["indicator_count"] >= 1):
                out.append(Consideration(
                    subject=f"block_domain:{parent}",
                    reason=(f"rated CLEAN by reputation although it looks like a tunnel ({m['basis']}): a security, "
                            "VPN or diagnostics product that encodes lookups in DNS looks like a tunnel; not "
                            "blocked, confirm the product and list it in allowlists.approved_dns_tools"),
                    record_ids=tuple(m["all_ids"])))
            elif not m["clean"] and (m["tunnel_category"] or m["indicator_count"] >= 2
                                     or m["reputation"] == "SUSPICIOUS"):
                out.append(Consideration(
                    subject=f"block_domain:{parent}",
                    reason=(f"tunnel indications ({m['basis']}) but not a confirmed tunnel: a block needs a "
                            f"malicious rating, a tunneling detection, the DNS tunneling category with at least "
                            f"{MIN_TUNNEL_QUERIES} queries, or {MIN_PROFILE_INDICATORS} of 5 behaviour indicators "
                            "including volume or subdomain variation; not blocked"),
                    record_ids=tuple(m["all_ids"])))
        for host, entry in self._resolvers.items():
            names = ", ".join(dict.fromkeys(e.process_name or "dns server" for e in entry["events"]))
            out.append(Consideration(
                subject=f"isolate_endpoint:{host}",
                reason=(f"DNS server process ({names}) forwards client queries for {', '.join(entry['domains'])}: a "
                        "forwarding resolver is never isolated (it would take DNS down for the site); the real "
                        "client comes from the resolver's own query log"),
                record_ids=tuple(_ids(entry["events"]))))
        for client in self.clients():
            host = client["hostname"]
            ids = tuple(client["record_ids"])
            if client["isolation_capable"] is False:
                out.append(Consideration(
                    subject=f"isolate_endpoint:{host}",
                    reason=("the endpoint reports that it cannot be isolated (policy or product): not proposed; "
                            "the querying process is terminated when it is still running, handle the host by hand"),
                    record_ids=ids))
            elif not client["connector_guid"] and not client["mde_machine_id"]:
                out.append(Consideration(
                    subject=f"isolate_endpoint:{host}",
                    reason=("no Secure Endpoint connector or Defender machine id is known for the endpoint, so no "
                            "isolation route can be built: isolate it by hand"),
                    record_ids=ids))
        for host, entry in self._dns_only.items():
            out.append(Consideration(
                subject=f"isolate_endpoint:{host}",
                reason=(f"DNS logs show {host} querying {', '.join(entry['domains'])}, but no endpoint record names "
                        "the querying process (the host may be another forwarder): not isolated; review its "
                        "endpoint telemetry"),
                record_ids=tuple(_ids(entry["records"]))))
        out.extend(self._manual_steps())
        return out

    def _manual_steps(self) -> list[Consideration]:
        out: list[Consideration] = []
        for host, entry in self._clients.items():
            processes = ", ".join(dict.fromkeys(e.process_name or "unknown process" for e in entry["events"]))
            out.append(Consideration(
                subject=f"remove tunnel client on {host}",
                reason=(f"no VERIFIED removal write in docs/integrations.md: after the approved containment, find how "
                        f"{processes} was installed and remove it through the endpoint console, unless it is a "
                        "sanctioned DNS tool in allowlists.approved_dns_tools"),
                record_ids=tuple(_ids(entry["events"])), manual=True))
        for parent, t in self.tunnels.items():
            m = self._measures[parent]
            if not m["confirmed"]:
                continue
            ids = tuple(m["pattern_ids"] or m["record_ids"])
            if ids:
                out.append(Consideration(
                    subject=f"assess data sent through {parent}",
                    reason=(f"{m['transfer_text']}: a DNS tunnel carries data out in its query labels; review what "
                            "the client could read in that window (no VERIFIED read measures the payload), unless "
                            "the traffic belongs to a sanctioned DNS tool in allowlists.approved_dns_tools"),
                    record_ids=ids, manual=True))
            has_client = any(parent in e["domains"] for e in (*self._clients.values(), *self._dns_only.values()))
            if not has_client:
                for host, entry in self._resolvers.items():
                    if parent in entry["domains"]:
                        out.append(Consideration(
                            subject=f"find the client behind {host}",
                            reason=(f"only the forwarding resolver {host} is seen querying {parent}: search the "
                                    "resolver's query log (Splunk) for the clients that asked for it and run this "
                                    "workflow for them"),
                            record_ids=tuple(_ids(entry["events"])), manual=True))
        return out


class DnsTunnelingHooks(WorkflowHooks):
    """Facts, tunnel-pattern signals, client links and considerations (pure; no context, no adapters)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _Facts(view).links(view.origin)

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return _Facts(view).signals(view.origin)

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()


HOOKS = DnsTunnelingHooks()
