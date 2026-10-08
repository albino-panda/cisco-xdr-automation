"""Hooks of the ransomware workflow: pure facts and record-backed signals (architecture 14.3.3).

The hooks read the typed records of one run (:class:`RunView`) and turn them into JSON facts the
recommendation rules use, plus two derived scoring signals. They see no context and no adapter, so
they cannot reach a vendor; every fact maps an entity to the ids of the records it was computed
from, and every signal cites those records. Nothing here invents a fact: a host, user, hash or
destination appears in a fact only when a record of this run names it.

Facts (all keys always present):

``affected_hosts``
    ``{HOST: [record ids]}``: endpoints with ransomware activity of their own: a MALICIOUS detection,
    a MALICIOUS process event, execution of an intel-confirmed payload hash, or vendor-flagged
    (SUSPICIOUS or worse) mass file modification together with vendor-flagged recovery inhibition
    on the same host. The host's endpoint records are cited as context.
``payload_hosts``
    ``{HOST: [record ids]}``: endpoints that hold a spreading payload (an intel-confirmed payload hash,
    or a hash a MALICIOUS detection or process event names) seen on at most
    :data:`WIDESPREAD_PREVALENCE` endpoints, even without a detection of their own.
``payload_hashes``
    ``{hash: {"prevalence", "widespread", "record_ids"}}``: hashes whose aggregate reputation is
    MALICIOUS, or SUSPICIOUS and named by a MALICIOUS detection or process event.
``blockable_hashes``
    ``{hash: [record ids]}``: payload hashes that are not widespread (prevalence unknown counts as not
    widespread; the rationale then says so).
``widespread_hashes``
    sorted hashes left to the approver because they are seen on more than
    :data:`WIDESPREAD_PREVALENCE` endpoints (a mis-scored common binary or a fleet-wide event).
``affected_users``
    ``{user: [record ids]}``: accounts (UPNs) that a record places on an affected host.
``compromised_users``
    ``{user: [record ids]}``: accounts the identity provider confirms compromised, or rates high risk
    with at least one risk detection (anomaly).
``blockable_domains`` / ``blockable_urls`` / ``blockable_ips``
    ``{value: [record ids]}``: destinations whose aggregate reputation is MALICIOUS or SUSPICIOUS and
    that an affected or payload host contacted, a malicious delivered message carried, or the incident
    lists.
``lateral_targets``
    ``{HOST: [record ids]}``: endpoints related to an affected host (``search_related_endpoints``)
    without ransomware activity of their own: scoped for the analyst, never isolated on that basis.
``mass_modification_hosts`` / ``recovery_inhibition_hosts``
    sorted hosts with each behaviour (context for the decision card and the tests).

Signals: ``encryption with recovery inhibition`` (endpoint_detection, MALICIOUS, severity 90) for a
host with both behaviours, and ``payload spread`` (lateral_movement, SUSPICIOUS, severity 70) for every
host holding a spreading payload that is on two or more hosts.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnomalyRecord,
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
    UserProfileRecord,
)
from xdr_response.models import Observable, ObservableType, TargetKind, Verdict, normalize_target
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, RunView, WorkflowHooks

__all__ = [
    "WIDESPREAD_PREVALENCE",
    "MASS_FILE_EVENTS",
    "MASS_FILE_EVENT_TYPES",
    "RECOVERY_TOOLS",
    "RECOVERY_DETECTION_WORDS",
    "RansomwareHooks",
    "HOOKS",
]

#: A payload seen on more endpoints than this is left to the approver (legacy prevalence gate).
WIDESPREAD_PREVALENCE = 50
#: Aggregated file events of one process at or above this count are "mass file modification".
MASS_FILE_EVENTS = 100
MASS_FILE_EVENT_TYPES: frozenset[str] = frozenset({"file_modify", "file_rename", "file_delete", "file_create"})
#: Built-in recovery management tools; an event of one counts only when the vendor flagged it.
RECOVERY_TOOLS: frozenset[str] = frozenset({"vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "wmic.exe",
                                            "diskshadow.exe"})
#: Words in a vendor detection name or category that mean recovery inhibition.
RECOVERY_DETECTION_WORDS: tuple[str, ...] = ("shadow cop", "recovery", "backup catalog")

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_HASH_TYPES = frozenset({ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5})
_ORIGIN = "workflow:ransomware"


def _norm(kind: TargetKind, value: str | None) -> str | None:
    """Normalized target value, or None for an empty or unparseable one."""
    if value is None:
        return None
    try:
        return normalize_target(kind, value)
    except ValueError:
        return None


def _host(value: str | None) -> str | None:
    return _norm(TargetKind.ENDPOINT, value)


def _upn(value: str | None) -> str | None:
    """A user principal name (``name@domain``) normalized, else None (local and SYSTEM accounts)."""
    user = _norm(TargetKind.USER, value)
    return user if user and "@" in user and not user.startswith("@") else None


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def _add(table: dict[str, list[str]], key: str | None, ids: Iterable[str]) -> None:
    if not key:
        return
    bucket = table.setdefault(key, [])
    for record_id in ids:
        if record_id not in bucket:
            bucket.append(record_id)


def _sorted_table(table: Mapping[str, list[str]]) -> dict[str, list[str]]:
    return {key: list(table[key]) for key in sorted(table)}


@dataclass
class _Records:
    """The run's records by kind (each record id once, first copy kept)."""

    detections: list[DetectionRecord] = field(default_factory=list)
    events: list[ProcessEventRecord] = field(default_factory=list)
    endpoints: list[EndpointRecord] = field(default_factory=list)
    prevalence: list[HashPrevalenceRecord] = field(default_factory=list)
    connections: list[NetworkConnectionRecord] = field(default_factory=list)
    dns: list[DnsQueryRecord] = field(default_factory=list)
    profiles: list[UserProfileRecord] = field(default_factory=list)
    anomalies: list[AnomalyRecord] = field(default_factory=list)
    messages: list[EmailMessageRecord] = field(default_factory=list)
    related: list[tuple[str, EndpointRecord]] = field(default_factory=list)  # (subject host, related record)

    @classmethod
    def of(cls, view: RunView) -> "_Records":
        out = cls()
        seen: set[str] = set()
        for result in view.results:
            for record in result.records:
                if record.record_id in seen:
                    continue
                seen.add(record.record_id)
                out.add(record)
                if result.atomic == "search_related_endpoints" and isinstance(record, EndpointRecord):
                    subject = _host(result.subject.value)
                    if subject:
                        out.related.append((subject, record))
        return out

    def add(self, record: AnyRecord) -> None:
        if isinstance(record, DetectionRecord):
            self.detections.append(record)
        elif isinstance(record, ProcessEventRecord):
            self.events.append(record)
        elif isinstance(record, EndpointRecord):
            self.endpoints.append(record)
        elif isinstance(record, HashPrevalenceRecord):
            self.prevalence.append(record)
        elif isinstance(record, NetworkConnectionRecord):
            self.connections.append(record)
        elif isinstance(record, DnsQueryRecord):
            self.dns.append(record)
        elif isinstance(record, UserProfileRecord):
            self.profiles.append(record)
        elif isinstance(record, AnomalyRecord):
            self.anomalies.append(record)
        elif isinstance(record, EmailMessageRecord):
            self.messages.append(record)


@dataclass(frozen=True)
class _Report:
    """One enrichment report: normalized value, aggregate verdict, supporting record ids."""

    type: ObservableType
    value: str
    verdict: Verdict
    supporting: tuple[str, ...]  # MALICIOUS / SUSPICIOUS enrichment records


def _reports(view: RunView) -> list[_Report]:
    out: list[_Report] = []
    for result in view.results:
        if not isinstance(result, ObservableReport):
            continue
        supporting = tuple(r.record_id for r in result.records
                           if isinstance(r, EnrichmentRecord) and r.verdict in _FLAGGED)
        out.append(_Report(type=result.type, value=result.value, verdict=result.verdict, supporting=supporting))
    return out


def _is_recovery_detection(record: DetectionRecord) -> bool:
    text = f"{record.name} {record.category or ''}".lower()
    return record.verdict in _FLAGGED and any(word in text for word in RECOVERY_DETECTION_WORDS)


def _is_recovery_event(record: ProcessEventRecord) -> bool:
    return record.verdict in _FLAGGED and _basename(record.process_name or record.file_path) in RECOVERY_TOOLS


def _is_mass_event(record: ProcessEventRecord) -> bool:
    return record.event_type in MASS_FILE_EVENT_TYPES and record.count >= MASS_FILE_EVENTS


class _Analysis:
    """Every fact of one run, computed once (facts and signals share it)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        self.records = _Records.of(view)
        self.reports = _reports(view)
        self.hash_reports = {r.value.lower(): r for r in self.reports if r.type in _HASH_TYPES}
        self._payload_hashes()
        self._spreading()
        self._affected_hosts()
        self._payload_hosts()
        self._users()
        self._destinations()
        self._lateral()

    # ---------------------------------------------------------- hashes --
    def _hash_mentions(self, sha: str, verdicts: frozenset[Verdict]) -> list[str]:
        ids = [d.record_id for d in self.records.detections if d.sha256 == sha and d.verdict in verdicts]
        ids += [e.record_id for e in self.records.events if e.sha256 == sha and e.verdict in verdicts]
        return ids

    def _prevalence(self, sha: str) -> tuple[int | None, list[str]]:
        rows = [p for p in self.records.prevalence if p.sha256 == sha]
        return (max((p.prevalence for p in rows), default=None), [p.record_id for p in rows])

    def _payload_hashes(self) -> None:
        named = {r.sha256 for r in (*self.records.detections, *self.records.events)
                 if r.sha256 and r.verdict is Verdict.MALICIOUS}
        self.payload: dict[str, dict[str, Any]] = {}
        for sha, report in sorted(self.hash_reports.items()):
            confirmed = report.verdict is Verdict.MALICIOUS or (report.verdict is Verdict.SUSPICIOUS and sha in named)
            if not confirmed:
                continue
            prevalence, prevalence_ids = self._prevalence(sha)
            ids = list(dict.fromkeys([*report.supporting, *self._hash_mentions(sha, _FLAGGED), *prevalence_ids]))
            self.payload[sha] = {"prevalence": prevalence,
                                 "widespread": prevalence is not None and prevalence > WIDESPREAD_PREVALENCE,
                                 "record_ids": ids}
        self.blockable = {sha: list(v["record_ids"]) for sha, v in self.payload.items() if not v["widespread"]}
        self.widespread = sorted(sha for sha, v in self.payload.items() if v["widespread"])

    def _spreading(self) -> None:
        """Payload hashes plus hashes a MALICIOUS detection or event names, unless widespread."""
        named = sorted({r.sha256 for r in (*self.records.detections, *self.records.events)
                        if r.sha256 and r.verdict is Verdict.MALICIOUS})
        self.spreading: dict[str, list[str]] = {}
        for sha in sorted({*self.payload, *named}):
            prevalence, prevalence_ids = self._prevalence(sha)
            if prevalence is not None and prevalence > WIDESPREAD_PREVALENCE:
                continue
            report = self.hash_reports.get(sha)
            self.spreading[sha] = list(dict.fromkeys([*(report.supporting if report else ()), *prevalence_ids]))

    # ----------------------------------------------------------- hosts --
    def _affected_hosts(self) -> None:
        table: dict[str, list[str]] = {}
        mass: dict[str, list[str]] = {}
        recovery: dict[str, list[str]] = {}
        payload_shas = set(self.payload)
        for d in self.records.detections:
            host = _host(d.endpoint)
            if d.verdict is Verdict.MALICIOUS:
                _add(table, host, [d.record_id])
            if _is_recovery_detection(d):
                _add(recovery, host, [d.record_id])
        for e in self.records.events:
            host = _host(e.endpoint)
            if e.verdict is Verdict.MALICIOUS:
                _add(table, host, [e.record_id])
            if e.sha256 and e.sha256 in payload_shas and e.event_type in ("process_start", "file_execute"):
                _add(table, host, [e.record_id])
            if _is_mass_event(e) and (e.verdict in _FLAGGED or (e.sha256 or "") in payload_shas):
                _add(mass, host, [e.record_id])
            if _is_recovery_event(e):
                _add(recovery, host, [e.record_id])
        for host in sorted(set(mass) & set(recovery)):
            _add(table, host, [*mass[host], *recovery[host]])
        self.pattern_hosts = {host: [*mass[host], *recovery[host]] for host in sorted(set(mass) & set(recovery))}
        self.mass_hosts = sorted(mass)
        self.recovery_hosts = sorted(recovery)
        for host in list(table):
            _add(table, host, self._endpoint_ids(host))
        self.affected = _sorted_table(table)

    def _endpoint_ids(self, host: str) -> list[str]:
        return [r.record_id for r in self.records.endpoints if _host(r.hostname) == host]

    def _payload_hosts(self) -> None:
        table: dict[str, list[str]] = {}
        self.spread_hosts: dict[str, set[str]] = {}
        for sha, base_ids in self.spreading.items():
            hosts: dict[str, list[str]] = {}
            for p in self.records.prevalence:
                if p.sha256 == sha:
                    for name in p.endpoints:
                        _add(hosts, _host(name), [p.record_id])
            for r in (*self.records.detections, *self.records.events):
                if r.sha256 == sha and r.verdict in _FLAGGED:
                    _add(hosts, _host(r.endpoint), [r.record_id])
            self.spread_hosts[sha] = set(hosts)
            for host, ids in hosts.items():
                _add(table, host, [*ids, *base_ids])
        for host in list(table):
            _add(table, host, self._endpoint_ids(host))
        self.payload_hosts = _sorted_table(table)

    # ----------------------------------------------------------- users --
    def _users(self) -> None:
        affected: dict[str, list[str]] = {}
        for host, ids in self.affected.items():
            users: set[str] = set()
            for d in self.records.detections:
                if _host(d.endpoint) == host and d.record_id in ids:
                    users.add(_upn(d.user) or "")
            for e in self.records.events:
                if _host(e.endpoint) == host and e.record_id in ids:
                    users.add(_upn(e.user) or "")
            for r in self.records.endpoints:
                if _host(r.hostname) == host:
                    users.update(_upn(u) or "" for u in r.users)
            for user in sorted(u for u in users if u):
                _add(affected, user, ids)
        compromised: dict[str, list[str]] = {}
        for profile in self.records.profiles:
            user = _upn(profile.user)
            anomalies = [a.record_id for a in self.records.anomalies if _upn(a.user) == user]
            if profile.risk_state == "confirmed_compromised":
                _add(compromised, user, [profile.record_id, *anomalies])
            elif profile.risk_level == "high" and anomalies:
                _add(compromised, user, [profile.record_id, *anomalies])
        for user in list(affected):
            _add(affected, user, self._profile_ids(user))
        self.affected_users = _sorted_table(affected)
        self.compromised_users = _sorted_table(compromised)

    def _profile_ids(self, user: str) -> list[str]:
        return [p.record_id for p in self.records.profiles if _upn(p.user) == user]

    # ---------------------------------------------------- destinations --
    def _destinations(self) -> None:
        compromised = set(self.affected) | set(self.payload_hosts)
        incident = {(o.type, o.value.strip().lower()) for o in self.view.incident.observables}
        contacts: dict[tuple[ObservableType, str], list[str]] = {}
        host_contacts: dict[tuple[ObservableType, str], list[AnyRecord]] = {}

        def contact(otype: ObservableType, kind: TargetKind, value: str | None, record: AnyRecord) -> None:
            key = _norm(kind, value)
            if not key:
                return
            _add(contacts, (otype, key.lower()), [record.record_id])  # type: ignore[arg-type]
            if not isinstance(record, EmailMessageRecord):
                bucket = host_contacts.setdefault((otype, key.lower()), [])
                if record not in bucket:
                    bucket.append(record)

        for c in self.records.connections:
            if _host(c.endpoint) not in compromised:
                continue
            contact(ObservableType.DOMAIN, TargetKind.DOMAIN, c.domain, c)
            contact(ObservableType.URL, TargetKind.URL, c.url, c)
            if c.direction in ("outbound", "unknown"):
                contact(ObservableType.IPV6 if c.remote_ip and ":" in c.remote_ip else ObservableType.IP,
                        TargetKind.IP, c.remote_ip, c)
        for q in self.records.dns:
            if _host(q.endpoint) in compromised:
                contact(ObservableType.DOMAIN, TargetKind.DOMAIN, q.domain, q)
        for m in self.records.messages:
            if m.verdict in _FLAGGED and m.delivery_location in ("inbox", "junk"):
                for url in m.urls:
                    contact(ObservableType.URL, TargetKind.URL, url, m)
                for domain in m.domains:
                    contact(ObservableType.DOMAIN, TargetKind.DOMAIN, domain, m)
        tables: dict[str, dict[str, list[str]]] = {"domain": {}, "url": {}, "ip": {}}
        self.contacted: list[tuple[Observable, list[AnyRecord]]] = []  # blockable destinations hosts reached
        for report in self.reports:
            if report.verdict not in _FLAGGED or report.type in _HASH_TYPES:
                continue
            group = {ObservableType.DOMAIN: "domain", ObservableType.URL: "url", ObservableType.IP: "ip",
                     ObservableType.IPV6: "ip"}.get(report.type)
            if group is None:
                continue
            key = (report.type, report.value.strip().lower())
            seen = contacts.get(key, [])
            if not seen and key not in incident:
                continue
            _add(tables[group], report.value, [*seen, *report.supporting])
            if host_contacts.get(key):
                self.contacted.append((Observable(type=report.type, value=report.value), host_contacts[key]))
        self.domains = _sorted_table(tables["domain"])
        self.urls = _sorted_table(tables["url"])
        self.ips = _sorted_table(tables["ip"])

    # --------------------------------------------------------- lateral --
    def _lateral(self) -> None:
        table: dict[str, list[str]] = {}
        for subject, record in self.records.related:
            host = _host(record.hostname)
            if subject in self.affected and host and host not in self.affected and host != subject:
                _add(table, host, [record.record_id])
        self.lateral = _sorted_table(table)

    # ----------------------------------------------------------- views --
    def facts(self) -> dict[str, Any]:
        return {
            "affected_hosts": self.affected,
            "payload_hosts": self.payload_hosts,
            "payload_hashes": {sha: dict(v) for sha, v in self.payload.items()},
            "blockable_hashes": self.blockable,
            "widespread_hashes": self.widespread,
            "affected_users": self.affected_users,
            "compromised_users": self.compromised_users,
            "blockable_domains": self.domains,
            "blockable_urls": self.urls,
            "blockable_ips": self.ips,
            "lateral_targets": self.lateral,
            "mass_modification_hosts": self.mass_hosts,
            "recovery_inhibition_hosts": self.recovery_hosts,
        }

    def considered(self) -> list[Consideration]:
        """Hosts whose policy forbids isolation, widespread payload hashes and hashes nobody rates."""
        out: list[Consideration] = []
        for host in sorted({*self.affected, *self.payload_hosts}):
            locked = [r.record_id for r in self.records.endpoints
                      if _host(r.hostname) == host and r.isolation_capable is False]
            if locked:
                ids = [*self.affected.get(host, []), *self.payload_hosts.get(host, []), *locked]
                out.append(Consideration(
                    subject=f"isolate_endpoint:{host}", record_ids=tuple(dict.fromkeys(ids)),
                    reason="the endpoint's policy does not allow isolation: contain it by hand (network or console)"))
        for sha in self.widespread:
            entry = self.payload[sha]
            out.append(Consideration(
                subject=f"block_hash:{sha}", record_ids=tuple(entry["record_ids"]),
                reason=f"payload hash seen on {entry['prevalence']} endpoints (more than {WIDESPREAD_PREVALENCE}): "
                       "not proposed for a fleet-wide block; a human decides"))
        named = {r.sha256 for r in (*self.records.detections, *self.records.events) if r.sha256}
        for sha, report in sorted(self.hash_reports.items()):
            if report.verdict is not Verdict.UNKNOWN or sha not in named:
                continue
            ids = [*self._hash_mentions(sha, frozenset(Verdict)), *self._prevalence(sha)[1]]
            if ids:
                out.append(Consideration(subject=f"block_hash:{sha}", record_ids=tuple(dict.fromkeys(ids)),
                                         reason="no reputation verdict: not blocked"))
        return out

    def signals(self) -> list[ScoringSignal]:
        out: list[ScoringSignal] = []
        by_id = {r.record_id: r for r in (*self.records.detections, *self.records.events,
                                           *self.records.prevalence)}
        for host, ids in self.pattern_hosts.items():
            out.append(self._signal(SignalCategory.ENDPOINT_DETECTION, _host_observable(host), Verdict.MALICIOUS,
                                    90, 80, [by_id[i] for i in ids if i in by_id],
                                    "mass file modification together with recovery inhibition on the same host"))
        for sha, hosts in sorted(self.spread_hosts.items()):
            if len(hosts) < 2:
                continue
            for host in sorted(hosts):
                cited = [by_id[i] for i in self.payload_hosts.get(host, []) if i in by_id
                         and _mentions_hash(by_id[i], sha)]
                if cited:
                    out.append(self._signal(SignalCategory.LATERAL_MOVEMENT, _host_observable(host),
                                            Verdict.SUSPICIOUS, 70, 70, cited,
                                            f"payload {sha[:12]}... present on {len(hosts)} endpoints"))
        for observable, records in self.contacted:
            out.append(self._signal(SignalCategory.NETWORK_BEHAVIOUR, observable, Verdict.SUSPICIOUS, 60, 60,
                                    records, "destination rated malicious or suspicious contacted by an affected "
                                             "or payload host"))
        return out

    @staticmethod
    def _signal(category: SignalCategory, observable: Observable, verdict: Verdict, severity: int,
                confidence: int, cited: Sequence[AnyRecord], note: str) -> ScoringSignal:
        return ScoringSignal(category=category, integration=cited[0].integration,
                             observable=observable, verdict=verdict,
                             severity=severity, confidence=confidence,
                             record_ids=tuple(dict.fromkeys(r.record_id for r in cited)), origin=_ORIGIN,
                             note=note)


def _host_observable(host: str) -> Observable:
    return Observable(type=ObservableType.HOSTNAME, value=host)


def _mentions_hash(record: AnyRecord, sha: str) -> bool:
    if isinstance(record, HashPrevalenceRecord):
        return record.sha256 == sha
    if isinstance(record, (DetectionRecord, ProcessEventRecord)):
        return record.sha256 == sha
    return False


class RansomwareHooks(WorkflowHooks):
    """Facts for the ransomware rules and two record-backed signals (pure; no context)."""

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return _Analysis(view).signals()

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Analysis(view).facts()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Analysis(view).considered()


HOOKS = RansomwareHooks()
