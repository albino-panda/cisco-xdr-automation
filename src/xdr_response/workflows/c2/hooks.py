"""Pure hooks of the command and control workflow (architecture 14.3.3 and 14.10.1).

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters, no
configuration) and derive:

* ``facts`` for the rule expressions:

  - ``destinations``: every external domain, IPv4 address and URL the investigated endpoints reached
    (connections, DNS queries, process events, enterprise sightings) or the incident names, with its
    rating. A destination is *rated* when the aggregate enrichment or the security product's verdict
    on a contact record is MALICIOUS, or when it is SUSPICIOUS and a source categorises it as command
    and control (:data:`C2_CATEGORY_KEYWORDS`). Beacon-like repeated contact is reported as context and
    never rates a destination. A rated IP is *shared* when a DNS record shows it also serving a domain
    rated CLEAN or a connection record names such a domain with the address (14.12.7), or the incident
    source lists it as shared infrastructure;
  - ``hosts``: every endpoint seen, whether it reached a MALICIOUS destination and whether it shows
    malicious activity itself (an active malicious detection, a malicious process event, or a process
    with a MALICIOUS hash on a C2 connection); only both together make ``isolate`` true. ``binaries``
    lists the hashes the activity rests on when a hash rating is its only basis (the isolation rules'
    ``binaries``: a sanctioned binary never isolates its host, 14.12.7);
  - ``processes``: flagged processes (detection, malicious process event or malicious hash) that hold
    a connection to a rated destination and were not seen ending (``<HOST>/<pid>``).

  Every fact carries the record ids it was computed from, and the rules cite exactly those ids.
* ``correlate`` links of kind ``WORKFLOW``: a beacon (endpoint, destination and, when known, the
  process hash) and a DNS resolution (a domain and the external IPv4 addresses it resolved to);
* ``considered`` items: destinations rated SUSPICIOUS without a C2 category, unrated destinations
  with beacon-like contact, shared infrastructure IPs, endpoints that reached C2 without malicious
  activity of their own, and unflagged processes on a C2 connection; manual steps for endpoints that
  cannot be isolated by an agent;
* ``handoffs`` to ``malware`` for the hashes of flagged beaconing processes.

Nothing here creates a record, scores a target, chooses an approval level or calls a vendor; a hook
that fails is noted and ignored by the runner. Hosts are upper case and domains, URLs and hashes lower
case, as the record normalizers store them.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EndpointRecord,
    EnrichmentRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
)
from xdr_response.models import ObservableType, TargetKind, Verdict
from xdr_response.workflows.c2.definition import (
    C2_CATEGORY_KEYWORDS,
    MIN_BEACON_CONTACTS,
    SHARED_INFRASTRUCTURE_KEY,
)
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = ["C2Hooks", "HOOKS", "is_c2_category", "ipv4"]

_MALICIOUS = Verdict.MALICIOUS
_SUSPICIOUS = Verdict.SUSPICIOUS
_FLAGGING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_VERDICT_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2,
                                        Verdict.MALICIOUS: 3}
_STARTS = frozenset({"process_start", "file_execute"})
_NOT_OUTWARD = frozenset({"inbound", "internal"})
_WORD_KEYWORDS = frozenset({"c2"})
_TYPES: Mapping[str, ObservableType] = {"domain": ObservableType.DOMAIN, "ip": ObservableType.IP,
                                         "url": ObservableType.URL}
_ACTIONS: Mapping[str, str] = {"domain": "block_domain", "ip": "block_ip", "url": "block_url"}
_KINDS: Mapping[str, TargetKind] = {"domain": TargetKind.DOMAIN, "ip": TargetKind.IP, "url": TargetKind.URL}


# ------------------------------------------------------------------ helpers --
def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v], default=Verdict.UNKNOWN)


def _short(sha: str) -> str:
    return sha[:12] + "..."


def is_c2_category(category: str | None) -> bool:
    """True when a vendor or DNS category names command-and-control infrastructure."""
    if not category:
        return False
    lowered = category.lower()
    for keyword in C2_CATEGORY_KEYWORDS:
        if keyword in _WORD_KEYWORDS:
            if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", lowered):
                return True
        elif keyword in lowered:
            return True
    return False


def ipv4(value: str | None) -> str | None:
    """The compressed IPv4 address of ``value`` (any range), else None (IPv6 is not handled)."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return address.compressed if address.version == 4 else None


def _count_of(record: AnyRecord) -> int:
    """The ``count`` of a contact record (1 for kinds without one)."""
    if isinstance(record, (NetworkConnectionRecord, DnsQueryRecord, ProcessEventRecord)):
        return record.count
    return 1


def _span(records: Sequence[AnyRecord]) -> tuple[datetime | None, datetime | None]:
    firsts: list[datetime] = []
    lasts: list[datetime] = []
    for record in records:
        if isinstance(record, (NetworkConnectionRecord, DnsQueryRecord)):
            first = record.first_seen or record.observed_at
            last = record.last_seen or first
        elif isinstance(record, ProcessEventRecord):
            first = last = record.timestamp
        else:
            continue
        if first is not None:
            firsts.append(first)
        if last is not None:
            lasts.append(last)
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


class _Destination:
    """One external destination (a domain, an IPv4 address or a URL) and the records about it."""

    def __init__(self, kind: str, value: str) -> None:
        self.kind = kind
        self.value = value
        self.contacts: list[AnyRecord] = []
        self.in_incident = False

    def add(self, record: AnyRecord) -> None:
        if record.record_id not in {r.record_id for r in self.contacts}:
            self.contacts.append(record)


class _Facts:
    """One computation of the facts over a run view (private helper of :class:`C2Hooks`)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        records = view.index.records()
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.connections = [r for r in records if isinstance(r, NetworkConnectionRecord)]
        self.dns = [r for r in records if isinstance(r, DnsQueryRecord)]
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {
            (r.type, r.value.lower()): r for r in view.results if isinstance(r, ObservableReport)}
        self.incident_hosts = {o.value.strip().upper().rstrip(".") for o in view.incident.observables
                               if o.type is ObservableType.HOSTNAME}
        shared = view.incident.trigger.get(SHARED_INFRASTRUCTURE_KEY) if isinstance(view.incident.trigger,
                                                                                    Mapping) else None
        self.listed_shared = {ipv4(str(v)) for v in (shared if isinstance(shared, list) else []) if ipv4(str(v))}
        self._destinations = self._collect()
        self.destination_facts = [self._destination_fact(d) for d in self._destinations.values()]
        self._by_key = {(d["type"], d["value"]): d for d in self.destination_facts}
        self.host_facts = self._hosts()
        self.process_facts, self.unflagged_processes = self._processes()

    # ------------------------------------------------------------ helpers --
    def _report(self, kind: str, value: str) -> ObservableReport | None:
        return self.reports.get((_TYPES[kind], value.lower()))

    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        return {
            "groups": list(dict.fromkeys(g for e in mine for g in e.groups)),
            "tags": list(dict.fromkeys(t for e in mine for t in e.tags)),
            "ip": next((a for e in mine for a in e.ip_addresses), None),
            "users": list(dict.fromkeys(u for e in mine for u in e.users)),
        }

    # -------------------------------------------------------- destinations --
    def _collect(self) -> dict[tuple[str, str], _Destination]:
        found: dict[tuple[str, str], _Destination] = {}

        def get(kind: str, value: str | None) -> _Destination | None:
            if not value:
                return None
            if kind == "ip":
                value = ipv4(value)
                if value is None:
                    return None
            elif kind == "domain":
                value = value.strip().lower().rstrip(".")
            else:
                value = value.strip()
            if not value:
                return None
            return found.setdefault((kind, value), _Destination(kind, value))

        for observable in self.view.incident.observables:
            kind = {ObservableType.DOMAIN: "domain", ObservableType.IP: "ip",
                    ObservableType.URL: "url"}.get(observable.type)
            if kind is not None:
                destination = get(kind, observable.value)
                if destination is not None:
                    destination.in_incident = True
        for c in self.connections:
            if c.direction in _NOT_OUTWARD:
                continue
            for kind, value in (("domain", c.domain), ("ip", c.remote_ip), ("url", c.url)):
                destination = get(kind, value)
                if destination is not None:
                    destination.add(c)
        for q in self.dns:
            destination = get("domain", q.domain)
            if destination is not None:
                destination.add(q)
        for e in self.events:
            for kind, value in (("domain", e.domain), ("ip", e.remote_ip)):
                destination = get(kind, value)
                if destination is not None:
                    destination.add(e)
        # a rated report the incident did not name and no endpoint record reached is not a destination
        return dict(sorted(found.items()))

    def _categories(self, destination: _Destination) -> tuple[list[str], list[AnyRecord]]:
        """C2 categories of the destination and the records that report them."""
        names: list[str] = []
        records: list[AnyRecord] = []
        report = self._report(destination.kind, destination.value)
        if report is not None:
            for record in report.enrichment_records():
                hits = [c for c in record.categories if is_c2_category(c)]
                if hits:
                    names.extend(hits)
                    records.append(record)
        for record in destination.contacts:
            if isinstance(record, DnsQueryRecord):
                hits = [c for c in record.categories if is_c2_category(c)]
                if hits:
                    names.extend(hits)
                    records.append(record)
        return list(dict.fromkeys(names)), records

    def _destination_fact(self, destination: _Destination) -> dict[str, Any]:
        report = self._report(destination.kind, destination.value)
        enrichment = report.verdict if report is not None else Verdict.UNKNOWN
        contact = _worst(_verdict_of(r) for r in destination.contacts)
        categories, category_records = self._categories(destination)
        support = [r for r in report.enrichment_records() if r.verdict in _FLAGGING] if report is not None else []
        flagged_contacts = [r for r in destination.contacts if _verdict_of(r) in _FLAGGING]
        rating = Verdict.UNKNOWN
        basis: list[str] = []
        if enrichment is _MALICIOUS:
            rating = _MALICIOUS
            basis.append(f"enrichment MALICIOUS ({', '.join(sorted({r.integration for r in support}))})")
        if contact is _MALICIOUS:
            rating = _MALICIOUS
            basis.append("a contact record carries the security product's MALICIOUS verdict")
        suspicious = enrichment is _SUSPICIOUS or contact is _SUSPICIOUS
        if rating is not _MALICIOUS and suspicious and categories:
            rating = _SUSPICIOUS
            basis.append(f"SUSPICIOUS with category {', '.join(categories)}")
        elif categories and rating is _MALICIOUS:
            basis.append(f"category {', '.join(categories)}")
        rated = rating in _FLAGGING
        endpoints = sorted({h for h in (self._endpoint_of(r) for r in destination.contacts) if h})
        beacon = self._beacon(destination)
        shared, shared_ids, shared_reason = self._shared(destination)
        clean_names = self._clean_names(destination)
        rating_ids = _ids([*support, *flagged_contacts, *category_records]) if rated else []
        record_ids = list(dict.fromkeys([*_ids(destination.contacts), *rating_ids]))
        return {
            "type": destination.kind,
            "value": destination.value,
            "rated": rated,
            "rating": rating.value,
            "malicious": rating is _MALICIOUS,
            "basis": "; ".join(basis) or "not rated",
            "enrichment_verdict": enrichment.value,
            "contact_verdict": contact.value,
            "categories": categories,
            "c2_category": bool(categories),
            "in_incident": destination.in_incident,
            "endpoints": endpoints,
            "endpoint_list": ", ".join(endpoints) or "the incident",
            "beacon": beacon["beacon"],
            "beacon_text": beacon["text"],
            "contacts": beacon["contacts"],
            "shared": shared,
            "shared_reason": shared_reason,
            "shared_record_ids": shared_ids,
            "clean_names": clean_names,
            "rating_record_ids": rating_ids,
            "record_ids": record_ids,
        }

    @staticmethod
    def _endpoint_of(record: AnyRecord) -> str | None:
        if isinstance(record, (NetworkConnectionRecord, DnsQueryRecord)):
            return record.endpoint
        if isinstance(record, ProcessEventRecord):
            return record.endpoint
        return None

    def _beacon(self, destination: _Destination) -> dict[str, Any]:
        """Beacon-like repeated contact per endpoint (context only; never a rating)."""
        best: tuple[int, str, str] | None = None
        total = 0
        for host in sorted({h for h in (self._endpoint_of(r) for r in destination.contacts) if h}):
            # one beacon shows up as DNS lookups and connections: count the record kind with most contacts
            by_kind: dict[str, list[AnyRecord]] = {}
            for record in destination.contacts:
                if self._endpoint_of(record) == host:
                    by_kind.setdefault(str(record.kind), []).append(record)
            mine = max(by_kind.values(), key=lambda rs: sum(_count_of(r) for r in rs))
            count = sum(_count_of(r) for r in mine)
            total += count
            first, last = _span(mine)
            interval = ""
            if first is not None and last is not None and count > 1 and last > first:
                seconds = int((last - first).total_seconds() // (count - 1))
                interval = f", about every {seconds} s"
            if best is None or count > best[0]:
                best = (count, host, interval)
        if best is None or best[0] < MIN_BEACON_CONTACTS:
            return {"beacon": False, "text": "", "contacts": total}
        count, host, interval = best
        return {"beacon": True, "contacts": total,
                "text": f"; beacon-like: {count} contacts from {host}{interval}"}

    def _clean_names(self, destination: _Destination) -> list[str]:
        """Domains rated CLEAN that the records tie to an IP or URL destination (its name or resolution)."""
        names: set[str] = set()
        if destination.kind == "url":
            try:
                host = (urlsplit(destination.value).hostname or "").lower()
            except ValueError:
                host = ""
            if host:
                names.add(host)
        elif destination.kind == "ip":
            names |= {c.domain.lower() for c in destination.contacts
                      if isinstance(c, NetworkConnectionRecord) and c.domain}
            names |= {q.domain.lower() for q in self.dns if destination.value in {ipv4(a) for a in q.response_ips}}
        return sorted(n for n in names if (r := self._report("domain", n)) is not None and r.verdict is Verdict.CLEAN)

    def _shared(self, destination: _Destination) -> tuple[bool, list[str], str]:
        """Whether an IP is shared hosting or CDN infrastructure, the records and the reason.

        Shared: a DNS record resolved a domain rated CLEAN to the address, or an outbound connection
        record names a domain rated CLEAN together with the address (14.12.7, the case exfiltration
        calls ``serves_clean``), or the incident source lists it as shared infrastructure.
        """
        if destination.kind != "ip":
            return False, [], ""
        clean_domains: list[str] = []
        records: list[AnyRecord] = []
        tied: list[tuple[str, AnyRecord]] = [
            (q.domain, q) for q in self.dns if q.domain and destination.value in {ipv4(a) for a in q.response_ips}]
        tied += [(c.domain, c) for c in destination.contacts
                 if isinstance(c, NetworkConnectionRecord) and c.domain]
        for name, record in tied:
            report = self._report("domain", name)
            if report is not None and report.verdict is Verdict.CLEAN:
                clean_domains.append(name.lower())
                records.append(record)
                records.extend(report.enrichment_records())
        if clean_domains:
            names = ", ".join(sorted(set(clean_domains)))
            return True, _ids(records), f"the address also serves {names}, rated CLEAN (shared hosting or CDN)"
        if destination.value in self.listed_shared:
            return True, [], "the incident source lists it as shared hosting or CDN infrastructure"
        return False, [], ""

    def destination(self, kind: str, value: str) -> dict[str, Any] | None:
        return self._by_key.get((kind, value))

    # ------------------------------------------------------------- hosts --
    def _c2_contacts(self, host: str) -> list[dict[str, Any]]:
        """MALICIOUS destinations ``host`` reached (a contact record) or the incident ties to it."""
        out = []
        for d in self.destination_facts:
            if not d["malicious"]:
                continue
            if host in d["endpoints"] or (d["in_incident"] and host in self.incident_hosts):
                out.append(d)
        return out

    def _malicious_hashes(self) -> set[str]:
        return {value for (otype, value), report in self.reports.items()
                if otype is ObservableType.SHA256 and report.verdict is _MALICIOUS}

    def _host_activity(self, host: str,
                       c2: Sequence[dict[str, Any]]) -> tuple[list[str], list[AnyRecord], list[str]]:
        """Malicious activity of ``host`` itself: basis texts, the records that show it and the binaries
        the activity rests on (14.12.7).

        An active malicious detection or a malicious process event is the security product's own
        observation and stands on its own (no binaries). When the only activity is "a process with a
        MALICIOUS hash holds the C2 connection", the activity rests on those hashes alone: they are the
        isolation rules' ``binaries``, so the runner withholds the isolation (shown as considered) when
        every one is sanctioned, exactly as it withholds that process's termination.
        """
        basis: list[str] = []
        records: list[AnyRecord] = []
        detections = [d for d in self.detections if d.endpoint == host and d.verdict is _MALICIOUS
                      and d.status != "resolved"]
        for d in detections:
            basis.append(f"active detection '{d.name}' {d.verdict.value}")
            records.append(d)
        bad_events = [e for e in self.events if e.endpoint == host and e.verdict is _MALICIOUS]
        if bad_events:
            basis.append(f"{len(bad_events)} malicious process event(s)")
            records.extend(bad_events)
        malicious_hashes = self._malicious_hashes()
        c2_values = {(d["type"], d["value"]) for d in c2}
        hash_connections = [c for c in self.connections if c.endpoint == host and c.sha256
                            and c.sha256.lower() in malicious_hashes and self._reaches(c, c2_values)]
        if hash_connections:
            shas = sorted({c.sha256.lower() for c in hash_connections if c.sha256})
            basis.append("a process with a MALICIOUS hash holds the C2 connection ("
                         + ", ".join(_short(s) for s in shas) + ")")
            records.extend(hash_connections)
            for sha in shas:
                records.extend(self._hash_support(sha))
        binaries: list[str] = []
        if hash_connections and not detections and not bad_events:
            binaries = sorted({c.sha256.lower() for c in hash_connections if c.sha256})
        return basis, records, binaries

    @staticmethod
    def _reaches(record: AnyRecord, values: set[tuple[str, str]]) -> bool:
        if isinstance(record, NetworkConnectionRecord):
            return any(((k, v) in values) for k, v in (("domain", (record.domain or "").lower()),
                                                       ("ip", ipv4(record.remote_ip) or ""), ("url", record.url or "")))
        if isinstance(record, ProcessEventRecord):
            return any(((k, v) in values) for k, v in (("domain", (record.domain or "").lower()),
                                                       ("ip", ipv4(record.remote_ip) or "")))
        if isinstance(record, DnsQueryRecord):
            return ("domain", record.domain.lower()) in values
        return False

    def _hash_support(self, sha: str) -> list[EnrichmentRecord]:
        report = self.reports.get((ObservableType.SHA256, sha.lower()))
        if report is None or report.verdict is not _MALICIOUS:
            return []
        return [r for r in report.enrichment_records() if r.verdict in _FLAGGING]

    def _hosts(self) -> list[dict[str, Any]]:
        hosts = sorted({e.hostname for e in self.endpoints}
                       | {h for d in self.destination_facts for h in d["endpoints"]})
        out: list[dict[str, Any]] = []
        for host in hosts:
            mine = [e for e in self.endpoints if e.hostname == host]
            c2 = self._c2_contacts(host)
            basis, activity, binaries = self._host_activity(host, c2) if c2 else ([], [], [])
            contact_ids: list[str] = []
            for d in c2:
                own = [r for r in self._destinations[(d["type"], d["value"])].contacts
                       if self._endpoint_of(r) == host]
                contact_ids.extend(_ids(own))
                contact_ids.extend(d["rating_record_ids"])
            tied_by_incident = [d for d in c2 if host not in d["endpoints"]]
            if tied_by_incident:
                basis.append("the incident names the endpoint and " + ", ".join(d["value"] for d in tied_by_incident))
            capable = next((e.isolation_capable for e in mine if e.isolation_capable is not None), None)
            out.append({
                "hostname": host,
                "connector_guid": next((e.connector_guid for e in mine if e.connector_guid), None),
                "mde_machine_id": next((e.mde_machine_id for e in mine if e.mde_machine_id), None),
                "isolation_capable": capable,
                "isolation_state": next((e.isolation_state for e in mine if e.isolation_state != "unknown"),
                                        "unknown"),
                "c2_contact": bool(c2),
                "malicious_activity": bool(activity),
                "binaries": binaries,
                "isolate": bool(c2) and bool(activity),
                "basis": "; ".join(basis) or "no malicious activity on the endpoint",
                "destinations": [d["value"] for d in c2],
                "destination_list": ", ".join(d["value"] for d in c2),
                "record_ids": list(dict.fromkeys([*_ids(activity), *contact_ids])),
                "contact_record_ids": list(dict.fromkeys(contact_ids)),
                **self._context(host),
            })
        return out

    # ---------------------------------------------------------- processes --
    def _ended(self, host: str, pid: int, since: datetime | None) -> bool:
        return any(e.event_type == "process_end" and e.endpoint == host and e.pid == pid
                   and (since is None or e.timestamp >= since) for e in self.events)

    def _processes(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Flagged processes on a rated C2 connection (proposed) and unflagged ones (considered)."""
        rated = {(d["type"], d["value"]) for d in self.destination_facts if d["rated"]}
        malicious = {(d["type"], d["value"]) for d in self.destination_facts if d["malicious"]}
        malicious_hashes = self._malicious_hashes()
        grouped: dict[tuple[str, int], list[AnyRecord]] = {}
        for record in [*self.connections, *self.events]:
            if isinstance(record, NetworkConnectionRecord) and record.direction in _NOT_OUTWARD:
                continue
            host = record.endpoint
            pid = record.pid
            if not host or pid is None or not self._reaches(record, rated):
                continue
            grouped.setdefault((host, pid), []).append(record)
        flagged: list[dict[str, Any]] = []
        unflagged: list[dict[str, Any]] = []
        for (host, pid), contacts in sorted(grouped.items()):
            events = [e for e in self.events if e.endpoint == host and e.pid == pid]
            shas = sorted({(r.sha256 or "").lower() for r in [*contacts, *events]
                           if isinstance(r, (NetworkConnectionRecord, ProcessEventRecord)) and r.sha256})
            names = [n for n in (_name_of(r) for r in [*contacts, *events]) if n]
            name = names[0] if names else f"pid {pid}"
            starts = [e for e in events if e.event_type in _STARTS]
            since = min((e.timestamp for e in starts), default=None)
            basis: list[str] = []
            flag_records: list[AnyRecord] = []
            detections = [d for d in self.detections if d.endpoint == host and d.verdict in _FLAGGING
                          and d.status != "resolved"
                          and (((d.sha256 or "").lower() in shas and d.sha256)
                               or (d.process_name and d.process_name.lower() in {n.lower() for n in names}))]
            for d in detections:
                basis.append(f"detection '{d.name}' {d.verdict.value}")
                flag_records.append(d)
            bad_events = [e for e in events if e.verdict in _FLAGGING]
            if bad_events:
                basis.append(f"{_worst(e.verdict for e in bad_events).value} process event")
                flag_records.extend(bad_events)
            bad_hashes = [s for s in shas if s in malicious_hashes]
            for sha in bad_hashes:
                basis.append(f"hash {_short(sha)} rated MALICIOUS")
                flag_records.extend(self._hash_support(sha))
            reached = sorted({v for k, v in rated if any(self._reaches(r, {(k, v)}) for r in contacts)})
            target = f"{host}/{pid}"
            item = {
                "target": target, "endpoint": host, "pid": pid, "process_name": name,
                "sha256": shas[0] if shas else None, "hashes": shas, "malicious_hashes": bad_hashes,
                "destinations": reached, "destination_list": ", ".join(reached),
                "reaches_malicious": any(self._reaches(r, malicious) for r in contacts),
                "basis": "; ".join(basis), "flag_record_ids": _ids(flag_records),
                "record_ids": list(dict.fromkeys([*_ids(contacts), *_ids(starts), *_ids(flag_records)])),
                **self._context(host),
            }
            if self._ended(host, pid, since):
                continue  # the process already ended: nothing to terminate
            (flagged if basis else unflagged).append(item)
        return flagged, unflagged

    # ------------------------------------------------------- considered --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for d in self.destination_facts:
            subject = f"{_ACTIONS[d['type']]}:{d['value']}"
            if d["rated"] and d["shared"]:
                ids = d["shared_record_ids"] or d["record_ids"]
                if ids:
                    out.append(Consideration(subject=subject, record_ids=tuple(ids), reason=(
                        f"rated {d['rating']} but {d['shared_reason']}: an IP block would cut legitimate "
                        "sites; the C2 domain block cuts the channel; a human decides")))
            elif not d["rated"] and d["record_ids"]:
                if d["enrichment_verdict"] == _SUSPICIOUS.value or d["contact_verdict"] == _SUSPICIOUS.value:
                    out.append(Consideration(subject=subject, record_ids=tuple(d["record_ids"]), reason=(
                        "rated SUSPICIOUS without a command-and-control category (for example newly seen or "
                        "algorithm-looking): not blocked; a human decides")))
                elif d["beacon"] and not d["clean_names"] and Verdict.CLEAN.value not in (
                        d["enrichment_verdict"], d["contact_verdict"]):
                    out.append(Consideration(subject=subject, record_ids=tuple(d["record_ids"]), reason=(
                        f"beacon-like contact ({d['contacts']} contacts) but no source rates the destination: "
                        "periodicity alone never blocks (update agents and SaaS heartbeats beacon too); "
                        "a human decides")))
        for h in self.host_facts:
            subject = f"isolate_endpoint:{h['hostname']}"
            if h["c2_contact"] and not h["isolate"] and h["contact_record_ids"]:
                out.append(Consideration(subject=subject, record_ids=tuple(h["contact_record_ids"]), reason=(
                    f"reached command-and-control infrastructure ({h['destination_list']}) but shows no malicious "
                    "detection or process of its own: not isolated; the destination blocks cut the channel and "
                    "the analyst can isolate it by hand")))
        for p in self.unflagged_processes:
            if p["reaches_malicious"] and p["record_ids"]:
                out.append(Consideration(subject=f"terminate_process:{p['target']}", record_ids=tuple(p["record_ids"]),
                                         reason=(f"{p['process_name']} reached {p['destination_list']} but no "
                                                 "detection, process verdict or hash rating flags the process "
                                                 "itself (it may be a browser or proxy): not terminated")))
        for h in self.host_facts:
            if not h["isolate"] or not h["record_ids"]:
                continue
            subject = f"isolate_endpoint:{h['hostname']}"
            if h["isolation_capable"] is False:
                out.append(Consideration(subject=subject, record_ids=tuple(h["record_ids"]), manual=True, reason=(
                    "the endpoint should be isolated but its agent policy does not allow isolation: contain it "
                    "on the network by hand (for example a Meraki client block or a switch port shutdown)")))
            elif not h["connector_guid"] and not h["mde_machine_id"]:
                out.append(Consideration(subject=subject, record_ids=tuple(h["record_ids"]), manual=True, reason=(
                    "the endpoint should be isolated but neither Secure Endpoint nor Defender manages it: "
                    "contain it on the network by hand")))
        return out

    def handoffs(self) -> list[Handoff]:
        hashes: dict[str, list[str]] = {}
        for p in self.process_facts:
            for sha in p["hashes"]:
                if sha in p["malicious_hashes"] or p["flag_record_ids"]:
                    hashes.setdefault(sha, []).extend(p["flag_record_ids"])
        cited = list(dict.fromkeys(i for ids in hashes.values() for i in ids))
        if not hashes or not cited:
            return []
        return [Handoff(workflow_id="malware", subjects=tuple(sorted(hashes)), record_ids=tuple(cited), reason=(
            "the beaconing process is flagged: scope its file across the estate, quarantine it and block its "
            "hash"))]

    def as_dict(self) -> dict[str, Any]:
        return {
            "destinations": self.destination_facts,
            "hosts": self.host_facts,
            "processes": self.process_facts,
        }


def _verdict_of(record: AnyRecord) -> Verdict:
    """The security product's verdict on a contact record (UNKNOWN for kinds without one)."""
    if isinstance(record, (NetworkConnectionRecord, DnsQueryRecord, ProcessEventRecord)):
        return record.verdict
    return Verdict.UNKNOWN


def _name_of(record: AnyRecord) -> str | None:
    if isinstance(record, (NetworkConnectionRecord, ProcessEventRecord)):
        return record.process_name
    return None


def _links(view: RunView) -> list[CorrelationLink]:
    links: dict[str, CorrelationLink] = {}

    def add(entities: Sequence[EntityRef | None], record: AnyRecord, note: str) -> None:
        refs = [e for e in entities if e is not None]
        if len(refs) < 2:
            return
        link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=tuple(refs), record_ids=(record.record_id,),
                               first_seen=record.observed_at, last_seen=record.observed_at, note=note,
                               origin=view.origin)
        links.setdefault(link.link_id, link)

    for record in view.index.records():
        if isinstance(record, NetworkConnectionRecord):
            if record.direction in _NOT_OUTWARD:
                continue
            host = _entity(TargetKind.ENDPOINT, record.endpoint)
            sha = _entity(TargetKind.HASH, record.sha256)
            for kind, value in ((TargetKind.DOMAIN, record.domain), (TargetKind.IP, ipv4(record.remote_ip)),
                                (TargetKind.URL, record.url)):
                destination = _entity(kind, value)
                if host is not None and destination is not None:
                    add((host, destination, sha), record, f"beacon: {host.value} reached {destination.value}")
        elif isinstance(record, DnsQueryRecord):
            domain = _entity(TargetKind.DOMAIN, record.domain)
            host = _entity(TargetKind.ENDPOINT, record.endpoint)
            if host is not None and domain is not None:
                add((host, domain), record, f"beacon: {host.value} resolved {domain.value}")
            for address in record.response_ips:
                ip = _entity(TargetKind.IP, ipv4(address))
                if domain is not None and ip is not None:
                    add((domain, ip), record, f"resolution: {domain.value} resolved to {ip.value}")
    return [links[k] for k in sorted(links)]


class C2Hooks(WorkflowHooks):
    """Facts, beacon links, considerations and hand-offs of the c2 workflow (pure)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _links(view)

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Facts(view).handoffs()


HOOKS = C2Hooks()
