"""Pure hooks of the data exfiltration workflow (architecture 14.3.3 and 14.10.1).

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters, no
configuration) and derive:

* ``facts`` for the rule expressions:

  - ``destinations``: every external domain and public IP that receives data (an outbound connection
    record with a volume, or an abnormal DNS channel), every incident domain and IP, and every
    destination the source endpoints contacted; with the volume, whether the transfer still runs, the
    rating (reputation and the source's own verdict), cloud-storage and newly-seen categories, how many
    endpoints of the estate reach it, and whether a block is justified (``blockable``). An unrated IP
    that serves a domain rated CLEAN (a transfer record names both, or a DNS record resolved the domain
    to it) is that clean service, and no IP that serves one is ever blockable (``serves_clean``, 14.12.6);
  - ``sources``: the endpoints the data leaves from, whether their transfer is still running, the
    exfiltration evidence (a rated destination, a malicious or exfiltration detection, a compromised
    account, an insider-risk detection) and whether an isolation is justified (``isolate``);
  - ``actors``: the accounts tied to the transfers, whether each is compromised (identity risk,
    anomalies) or named by an insider-risk detection, and whether it ``drives`` a transfer: a transfer
    record names the account, or names no account and comes from an endpoint whose records list that
    account as its only user (14.12.7). Only an account that drives a transfer is contained for being
    compromised; another compromised user of a source endpoint is shown as considered, never contained
    for a transfer no record attributes to it.

  Every fact carries the record ids it was computed from, and the rules cite exactly those ids.
* ``derive_signals``: the transfer pattern (a large or abnormal upload to a destination that is not
  rated clean, a running transfer from a source) as a ``network_behaviour`` signal of the source that
  reported the records, citing them;
* ``correlate`` links of kind ``WORKFLOW``: each transfer (endpoint, account, destination) and staging
  (an archive written on the endpoint before a transfer from it);
* ``considered`` items (clean, shared and internal destinations, isolations withheld, accounts that
  could not be assessed) and manual steps (the data impact assessment);
* ``handoffs`` to ``account-takeover`` for a compromised account that drives the transfer.

Nothing here creates a record, scores a target, chooses an approval level or calls a vendor; a hook
that fails is noted and ignored by the runner.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnomalyRecord,
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EndpointRecord,
    EnrichmentRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.config.policy import non_public_network
from xdr_response.models import Observable, ObservableType, Severity, TargetKind, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.exfiltration.definition import (
    ABNORMAL_DNS_LABEL_LENGTH,
    ABNORMAL_DNS_SUBDOMAINS,
    CLOUD_STORAGE_CATEGORIES,
    EXFIL_KEYWORDS,
    EXFIL_TECHNIQUES,
    INSIDER_KEYWORDS,
    LARGE_TRANSFER_BYTES,
    MAX_DESTINATION_ENDPOINTS,
    NEW_DESTINATION_CATEGORIES,
    NEW_DESTINATION_DAYS,
    ONGOING_MINUTES,
)
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks, failed_reads

__all__ = [
    "ExfiltrationHooks",
    "HOOKS",
    "ARCHIVE_EXTENSIONS",
    "format_bytes",
    "is_archive",
    "names_exfiltration",
    "names_insider",
    "public_ipv4",
]

_FLAGGING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_VERDICT_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2,
                                        Verdict.MALICIOUS: 3}
_HIGH = frozenset({Severity.HIGH, Severity.CRITICAL})
_WRITES = frozenset({"file_create", "file_modify", "file_rename"})
_SEARCH_ATOMICS = frozenset({"search_domain_enterprise", "search_ip_enterprise"})
_STAGING_WINDOW = timedelta(minutes=180)
_DOMAIN, _IP = "domain", "ip"
_OTYPES: Mapping[str, ObservableType] = {_DOMAIN: ObservableType.DOMAIN, _IP: ObservableType.IP}
_TKINDS: Mapping[str, TargetKind] = {_DOMAIN: TargetKind.DOMAIN, _IP: TargetKind.IP}

#: File extensions of archives (lower case): an archive written on a source endpoint before a transfer
#: is staging. Product knowledge only; it never rates anything by itself.
ARCHIVE_EXTENSIONS: tuple[str, ...] = (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab")

#: Signal severities of the transfer pattern (``network_behaviour``, verdict SUSPICIOUS).
_LARGE_SEVERITY = 70
_SMALL_SEVERITY = 50
_RUNNING_SEVERITY = 70
_ACTOR_SEVERITY = 60
_PATTERN_CONFIDENCE = 60


# ------------------------------------------------------------------ helpers --
def format_bytes(value: int) -> str:
    """Human-readable volume (binary units, one decimal): ``4831838208`` -> ``"4.5 GiB"``."""
    size = float(max(value, 0))
    for unit in ("bytes", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} bytes"  # pragma: no cover - loop always returns


def public_ipv4(value: str | None) -> str | None:
    """The compressed IPv4 address when ``value`` is a public IPv4 address, else None."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if address.version != 4 or non_public_network(address) is not None:
        return None
    return address.compressed


def _is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _has_keyword(text: str | None, keywords: Iterable[str]) -> bool:
    if not text:
        return False
    lowered = re.sub(r"[\s_\-]+", " ", text.lower())
    return any(k in lowered or k in text.lower() for k in keywords)


def names_exfiltration(detection: DetectionRecord) -> bool:
    """True when a detection reports an exfiltration technique or names exfiltration or data loss."""
    techniques = [str(t).upper() for t in detection.mitre_techniques]
    if any(t == x or t.startswith(x + ".") for t in techniques for x in EXFIL_TECHNIQUES):
        return True
    return _has_keyword(detection.name, EXFIL_KEYWORDS) or _has_keyword(detection.category, EXFIL_KEYWORDS)


def names_insider(detection: DetectionRecord) -> bool:
    """True when a detection names insider risk (and so the account it is about)."""
    return _has_keyword(detection.name, INSIDER_KEYWORDS) or _has_keyword(detection.category, INSIDER_KEYWORDS)


def is_archive(path: str | None) -> bool:
    """True when a file path or name ends with an archive extension."""
    return bool(path) and str(path).strip().lower().endswith(ARCHIVE_EXTENSIONS)


def _volume_text(volume: int, measured: bool) -> str:
    """The volume sent, or a note that only DNS queries carried it (no byte count reported)."""
    return format_bytes(volume) if measured else "an unmeasured volume carried in DNS queries"


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v], default=Verdict.UNKNOWN)


def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _time(record: NetworkConnectionRecord | DnsQueryRecord) -> datetime | None:
    return record.last_seen or record.first_seen or record.observed_at


def _start(record: NetworkConnectionRecord | DnsQueryRecord) -> datetime | None:
    return record.first_seen or record.last_seen or record.observed_at


def _stamp(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value is not None else "an unknown time"


def _abnormal_dns(query: DnsQueryRecord) -> bool:
    return ((query.unique_subdomains is not None and query.unique_subdomains >= ABNORMAL_DNS_SUBDOMAINS)
            or (query.max_label_length is not None and query.max_label_length >= ABNORMAL_DNS_LABEL_LENGTH))


def _any_category(categories: Iterable[str], keywords: Iterable[str]) -> bool:
    keys = tuple(keywords)
    return any(c and any(k in c.lower() for k in keys) for c in categories)


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


class _Destination:
    """One external domain or public IP: the records that reach it (private helper)."""

    def __init__(self, kind: str, value: str) -> None:
        self.kind = kind
        self.value = value
        self.transfers: list[NetworkConnectionRecord] = []
        self.contacts: list[NetworkConnectionRecord] = []
        self.abnormal_dns: list[DnsQueryRecord] = []
        self.dns: list[DnsQueryRecord] = []
        self.incident = False

    def channel_records(self) -> list[NetworkConnectionRecord | DnsQueryRecord]:
        return [*self.transfers, *self.abnormal_dns]

    def add(self, bucket: list[Any], record: Any) -> None:
        if all(r.record_id != record.record_id for r in bucket):
            bucket.append(record)


class _Analysis:
    """One computation of the facts over a run view (private helper of :class:`ExfiltrationHooks`)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        self.origin = view.origin
        records = view.index.records()
        self.connections = [r for r in records if isinstance(r, NetworkConnectionRecord)]
        self.dns = [r for r in records if isinstance(r, DnsQueryRecord)]
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = [r for r in records if isinstance(r, ProcessEventRecord)]
        self.profiles = [r for r in records if isinstance(r, UserProfileRecord)]
        self.anomalies = [r for r in records if isinstance(r, AnomalyRecord)]
        self.signins = [r for r in records if isinstance(r, SignInRecord)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {
            (r.type, r.value.lower()): r for r in view.results if isinstance(r, ObservableReport)}
        self.created = view.incident.created_at
        self.cutoff = self.created - timedelta(minutes=ONGOING_MINUTES)
        self.identity_failed = failed_reads(view, ("investigate_user",))
        self.rating_failed = failed_reads(view, ("enrich_domain", "enrich_ip"))
        self.internal: dict[str, list[NetworkConnectionRecord]] = {}
        self.destinations = self._collect()
        self._dest_facts = {key: self._destination_fact(d) for key, d in self.destinations.items()}
        self.actors = self._actors()
        self._source_facts = self._sources()

    # ------------------------------------------------------------ collection --
    def _collect(self) -> dict[tuple[str, str], _Destination]:
        found: dict[tuple[str, str], _Destination] = {}

        def dest(kind: str, value: str) -> _Destination:
            key = (kind, value.lower())
            return found.setdefault(key, _Destination(kind, value.lower()))

        triaged = {r.record_id for res in self.view.results if res.atomic == "investigate_endpoint"
                   for r in res.records}
        for c in self.connections:
            if c.action == "blocked":
                continue
            outbound = c.direction != "internal"
            moving = (c.bytes_out or 0) > 0
            ip = public_ipv4(c.remote_ip)
            if moving and c.remote_ip and (not outbound or (ip is None and _is_ip(c.remote_ip)
                                                            and non_public_network(c.remote_ip) is not None)):
                self.internal.setdefault(c.remote_ip, []).append(c)
            if not outbound:
                continue
            for kind, value in ((_DOMAIN, c.domain), (_IP, ip)):
                if not value:
                    continue
                if moving:
                    d = dest(kind, value)
                    d.add(d.transfers, c)
                elif c.record_id in triaged:
                    d = dest(kind, value)
                    d.add(d.contacts, c)
        for q in self.dns:
            if not q.domain:
                continue
            if _abnormal_dns(q):
                d = dest(_DOMAIN, q.domain)
                d.add(d.abnormal_dns, q)
        for q in self.dns:
            key = (_DOMAIN, q.domain.lower()) if q.domain else None
            if key is not None and key in found:
                found[key].add(found[key].dns, q)
        for observable in self.view.incident.observables:
            if observable.type is ObservableType.DOMAIN:
                dest(_DOMAIN, observable.value).incident = True
            elif observable.type is ObservableType.IP and public_ipv4(observable.value):
                dest(_IP, public_ipv4(observable.value) or observable.value).incident = True
        return dict(sorted(found.items()))

    def _report(self, kind: str, value: str) -> ObservableReport | None:
        return self.reports.get((_OTYPES[kind], value.lower()))

    def _support(self, kind: str, value: str) -> list[EnrichmentRecord]:
        """Enrichment records rating ``value`` malicious or suspicious when the aggregate is too."""
        report = self._report(kind, value)
        if report is None or report.verdict not in _FLAGGING:
            return []
        return [r for r in report.enrichment_records() if r.verdict in _FLAGGING]

    def _reach(self, kind: str, value: str) -> tuple[set[str], list[str], bool]:
        """(endpoints of the estate that reach the destination, search record ids, search answered)."""
        hosts: set[str] = set()
        ids: list[str] = []
        answered = False
        for result in self.view.results:
            if result.atomic not in _SEARCH_ATOMICS or result.subject.value.lower() != value.lower():
                continue
            if result.subject.type is not _OTYPES[kind]:
                continue
            answered = answered or bool(result.answered)
            for record in result.records:
                if isinstance(record, (NetworkConnectionRecord, DnsQueryRecord)) and record.endpoint:
                    hosts.add(record.endpoint)
                    ids.append(record.record_id)
        return hosts, _unique(ids), answered

    # ----------------------------------------------------------- destinations --
    def _clean_domain(self, name: str) -> list[AnyRecord] | None:
        """The enrichment records rating domain ``name`` CLEAN, or None when it is not rated CLEAN (no CLEAN
        aggregate, or a record of the run that reaches it carries a MALICIOUS or SUSPICIOUS verdict)."""
        report = self._report(_DOMAIN, name)
        if report is None or report.verdict is not Verdict.CLEAN:
            return None
        d = self.destinations.get((_DOMAIN, name.lower()))
        if d is not None and any(r.verdict in _FLAGGING for r in (*d.transfers, *d.contacts, *d.abnormal_dns)):
            return None
        return list(report.enrichment_records())

    def _serves_clean(self, d: _Destination) -> tuple[list[str], list[str]]:
        """``(domains, record_ids)``: the domains rated CLEAN that the run's records tie to IP ``d``.

        A transfer or contact record that names a domain together with the address, or a DNS record that
        resolved a domain to it (14.12.6). Blocking the address would cut that sanctioned service (and
        whatever else shares the address), so such an IP is never blockable and is shown as considered.
        """
        if d.kind != _IP:
            return [], []
        names: dict[str, list[AnyRecord]] = {}
        for c in (*d.transfers, *d.contacts):
            if c.domain:
                names.setdefault(c.domain.lower(), []).append(c)
        for q in self.dns:
            if q.domain and d.value in {public_ipv4(str(a)) for a in q.response_ips}:
                names.setdefault(q.domain.lower(), []).append(q)
        domains: list[str] = []
        ids: list[str] = []
        for name in sorted(names):
            clean = self._clean_domain(name)
            if clean is None:
                continue
            domains.append(name)
            ids.extend([*_ids(names[name]), *_ids(clean)])
        return domains, _unique(ids)

    def _destination_fact(self, d: _Destination) -> dict[str, Any]:
        report = self._report(d.kind, d.value)
        enrichment = report.verdict if report is not None else Verdict.UNKNOWN
        support = self._support(d.kind, d.value)
        reached = [*d.transfers, *d.contacts, *d.abnormal_dns]
        contact = _worst(r.verdict for r in reached)
        flagging_contacts = [r for r in reached if r.verdict in _FLAGGING]
        rated = bool(support) or contact in _FLAGGING
        serves_clean, serves_clean_ids = self._serves_clean(d)
        # an unrated address of a service rated CLEAN is that clean service (14.12.6)
        clean = not rated and (enrichment is Verdict.CLEAN or bool(serves_clean))
        categories = sorted({*(report.categories() if report is not None else ()),
                             *(c for q in d.dns for c in q.categories)})
        cloud = _any_category(categories, CLOUD_STORAGE_CATEGORIES)
        enriched = list(report.enrichment_records()) if report is not None else []
        recent = [r for r in enriched if r.first_seen is not None
                  and timedelta(0) <= self.created - r.first_seen <= timedelta(days=NEW_DESTINATION_DAYS)]
        new = _any_category(categories, NEW_DESTINATION_CATEGORIES) or bool(recent)
        # The enrichment records that report a storage or newly-seen category, or a recent first-seen
        # time, back the "cloud or file storage" / "newly seen" claims and are cited (14.12.3).
        vendor_context = [r for r in enriched if _any_category(r.categories, (*CLOUD_STORAGE_CATEGORIES,
                                                                              *NEW_DESTINATION_CATEGORIES))]
        vendor_context += [r for r in recent if r not in vendor_context]
        volume = sum(c.bytes_out or 0 for c in d.transfers)
        large = volume >= LARGE_TRANSFER_BYTES
        channel = d.channel_records()
        times = [t for t in (_time(r) for r in channel) if t is not None]
        starts = [t for t in (_start(r) for r in channel) if t is not None]
        last = max(times) if times else None
        sources = sorted({r.endpoint for r in channel if r.endpoint})
        users = sorted({c.user for c in d.transfers if c.user})
        reach, reach_ids, searched = self._reach(d.kind, d.value)
        reach |= set(sources)
        prevalence = len(reach)
        shared = prevalence > MAX_DESTINATION_ENDPOINTS
        unrated_suspicious = (not rated and not clean and bool(channel)
                              and (large or new or cloud or bool(d.abnormal_dns)))
        if d.kind == _DOMAIN:
            blockable = rated or (unrated_suspicious and not shared)
        else:
            blockable = (rated or unrated_suspicious) and not shared and not serves_clean
        basis: list[str] = []
        if d.transfers:
            hosts = ", ".join(sorted({c.endpoint or c.user or "an unknown source" for c in d.transfers}))
            basis.append(f"{format_bytes(volume)} uploaded from {hosts}")
        if d.abnormal_dns:
            peak = max((q.unique_subdomains or 0) for q in d.abnormal_dns)
            basis.append(f"abnormal DNS ({peak} distinct subdomains or long labels)")
        if support:
            basis.append(f"rated {enrichment.value} by reputation")
        if contact in _FLAGGING:
            basis.append(f"connection record {contact.value}")
        if not rated:
            failed = self.rating_failed.get(d.value.lower(), ())
            label = ("rated CLEAN" if enrichment is Verdict.CLEAN
                     else "unrated" + (f" (reputation failed: {', '.join(failed)})" if failed
                                       else " (no reputation verdict)"))
            basis.append(label)
        if serves_clean:
            basis.append(f"serves {', '.join(serves_clean)}, rated CLEAN")
        if new:
            basis.append("newly seen")
        if cloud:
            basis.append("cloud or file storage")
        basis.append(f"reached from {prevalence} endpoint(s) of the estate"
                     + ("" if searched else " (enterprise search gave no answer)"))
        categorized = [q for q in d.dns if _any_category(q.categories, (*CLOUD_STORAGE_CATEGORIES,
                                                                        *NEW_DESTINATION_CATEGORIES))]
        record_ids = _unique([*_ids(d.transfers), *_ids(d.abnormal_dns), *(r.record_id for r in support),
                              *_ids(flagging_contacts), *_ids(categorized), *_ids(vendor_context)])
        if not record_ids:
            blockable = False
        return {
            "type": d.kind, "value": d.value, "incident": d.incident,
            "upload": bool(d.transfers), "abnormal_dns": bool(d.abnormal_dns),
            "bytes_out": volume, "volume_text": _volume_text(volume, bool(d.transfers)), "large": large,
            "ongoing": last is not None and last >= self.cutoff,
            "first_seen": _stamp(min(starts) if starts else None), "last_seen": _stamp(last),
            "sources": sources, "users": users,
            "enrichment_verdict": enrichment.value, "contact_verdict": contact.value,
            "rated": rated, "clean": clean, "new": new, "cloud_storage": cloud, "categories": categories,
            "prevalence": prevalence, "shared": shared, "searched": searched,
            "serves_clean": serves_clean, "serves_clean_ids": serves_clean_ids,
            "blockable": blockable, "basis": "; ".join(basis),
            "record_ids": record_ids,
            "rating_ids": _unique([*(r.record_id for r in support), *_ids(flagging_contacts)]),
            "contact_ids": _unique([*_ids(reached), *_ids(d.dns)]),
            "reach_ids": reach_ids,
        }

    def destination_facts(self) -> list[dict[str, Any]]:
        return list(self._dest_facts.values())

    # ----------------------------------------------------------------- actors --
    def _host_users(self, host: str) -> set[str]:
        users = {u for e in self.endpoints if e.hostname == host for u in e.users}
        users |= {d.user for d in self.detections if d.user and d.endpoint == host}
        return users

    def _transfers_of(self, user: str) -> list[NetworkConnectionRecord]:
        """Transfers to an external destination that the account drives: the transfer record names the
        account, or names none and comes from an endpoint whose only user (by its records) is the account.
        A userless transfer from a shared endpoint is attributed to nobody (14.12.7)."""
        out: list[NetworkConnectionRecord] = []
        for d in self.destinations.values():
            for c in d.transfers:
                if c.user == user or (c.user is None and c.endpoint and self._host_users(c.endpoint) == {user}):
                    if all(x.record_id != c.record_id for x in out):
                        out.append(c)
        return out

    def _actors(self) -> dict[str, dict[str, Any]]:
        transfers = [c for d in self.destinations.values() for c in d.transfers]
        sources = {c.endpoint for c in transfers if c.endpoint}
        sources |= {q.endpoint for d in self.destinations.values() for q in d.abnormal_dns if q.endpoint}
        candidates: set[str] = {c.user for c in transfers if c.user}
        for host in sources:
            candidates |= self._host_users(host)
        if transfers or any(d.abnormal_dns for d in self.destinations.values()):
            candidates |= {u.lower() for u in self.view.incident.users}
            candidates |= {o.value.lower() for o in self.view.incident.observables
                           if o.type is ObservableType.USER}
        candidates |= {d.user for d in self.detections if d.user and names_insider(d)}
        out: dict[str, dict[str, Any]] = {}
        for user in sorted(candidates):
            out[user] = self._actor(user)
        return out

    def _actor(self, user: str) -> dict[str, Any]:
        profiles = [p for p in self.profiles if p.user == user]
        anomalies = [a for a in self.anomalies if a.user == user]
        risky_signins = [s for s in self.signins if s.user == user and s.risk_level in ("medium", "high")]
        basis: list[str] = []
        compromise: list[AnyRecord] = []
        confirmed = [p for p in profiles if p.risk_state == "confirmed_compromised"]
        high = [p for p in profiles if p.risk_level == "high"]
        medium = [p for p in profiles if p.risk_level == "medium"]
        severe = [a for a in anomalies if a.severity in _HIGH]
        if confirmed:
            basis.append("identity risk confirmed compromised")
            compromise += confirmed
        if high:
            basis.append("identity risk high")
            compromise += high
        if medium and anomalies:
            basis.append(f"identity risk medium with {len(anomalies)} anomaly(ies)")
            compromise += medium
        if severe:
            basis.append("high-severity anomaly " + ", ".join(sorted({a.anomaly_type for a in severe})))
        compromised = bool(compromise or severe)
        if compromised:
            compromise += anomalies
            compromise += risky_signins
            if anomalies and not severe:
                basis.append("anomalies " + ", ".join(sorted({a.anomaly_type for a in anomalies})))
        insider = [d for d in self.detections if d.user == user and names_insider(d) and d.verdict in _FLAGGING]
        for d in insider:
            basis.append(f"insider-risk detection '{d.name}' {d.verdict.value}")
        transfers = self._transfers_of(user)
        destinations = sorted({v for c in transfers for v in (c.domain, public_ipv4(c.remote_ip)) if v})
        volume = sum(c.bytes_out or 0 for c in transfers)
        transfer_text = (f"{format_bytes(volume)} to {', '.join(destinations)}" if transfers
                         else "no transfer record names the account")
        groups = sorted({g for p in profiles for g in p.groups})
        roles = sorted({r for p in profiles for r in p.roles})
        failed = self.identity_failed.get(user, ())
        return {
            "user": user,
            "compromised": compromised,
            "insider": bool(insider),
            "assessed": bool(profiles) or not failed,
            "identity_failed": list(failed),
            "basis": "; ".join(basis) or "no compromise record and no insider-risk detection",
            "transfer_text": transfer_text,
            "destinations": destinations,
            "groups": groups, "roles": roles, "privileged": any(p.privileged for p in profiles),
            "record_ids": _unique([*_ids(compromise), *_ids(insider), *_ids(transfers)]),
            "compromise_ids": _unique([*_ids(compromise), *_ids(severe)]),
            "insider_ids": _ids(insider),
            "transfer_ids": _ids(transfers),
            "drives": bool(transfers),
        }

    def actor_facts(self) -> list[dict[str, Any]]:
        return [a for a in self.actors.values() if a["compromised"] or a["insider"] or a["transfer_ids"]]

    # ---------------------------------------------------------------- sources --
    def _sources(self) -> dict[str, dict[str, Any]]:
        by_host: dict[str, list[tuple[dict[str, Any], NetworkConnectionRecord | DnsQueryRecord]]] = {}
        for key, d in self.destinations.items():
            fact = self._dest_facts[key]
            for record in d.channel_records():
                if record.endpoint:
                    by_host.setdefault(record.endpoint, []).append((fact, record))
        out: dict[str, dict[str, Any]] = {}
        for host, items in sorted(by_host.items()):
            out[host] = self._source(host, items)
        return out

    def _source(self, host: str, items: list[tuple[dict[str, Any], Any]]) -> dict[str, Any]:
        records = _unique(r.record_id for _, r in items)
        running = [r for _, r in items if (_time(r) is not None and _time(r) >= self.cutoff)]
        times = [t for t in (_time(r) for _, r in items) if t is not None]
        destinations = _unique(f["value"] for f, _ in items)
        non_clean = _unique(f["value"] for f, _ in items if not f["clean"])
        moved = {r.record_id: r for _, r in items if isinstance(r, NetworkConnectionRecord)}
        volume = sum(r.bytes_out or 0 for r in moved.values())
        staging = self._staging(host, list(moved.values()))
        basis: list[str] = []
        basis_ids: list[str] = []
        for fact, _ in items:
            if fact["rated"]:
                text = f"destination {fact['value']} rated " + (
                    fact["enrichment_verdict"] if fact["enrichment_verdict"] in ("MALICIOUS", "SUSPICIOUS")
                    else fact["contact_verdict"])
                if text not in basis:
                    basis.append(text)
                    basis_ids += fact["rating_ids"]
        for d in self.detections:
            if d.endpoint != host or d.status == "resolved":
                continue
            if d.verdict is Verdict.MALICIOUS or (names_exfiltration(d) and d.verdict in _FLAGGING):
                basis.append(f"detection '{d.name}' {d.verdict.value} on {host}")
                basis_ids.append(d.record_id)
        users = sorted(self._host_users(host) | {r.user for _, r in items
                                                 if isinstance(r, NetworkConnectionRecord) and r.user})
        unassessed: list[str] = []
        for user in users:
            actor = self.actors.get(user)
            if actor is None:
                continue
            if actor["compromised"]:
                basis.append(f"account {user} compromised ({actor['basis']})")
                basis_ids += actor["compromise_ids"]
            if actor["insider"]:
                basis.append(f"insider-risk detection names {user}")
                basis_ids += actor["insider_ids"]
            if not actor["assessed"]:
                unassessed.append(f"{user} ({', '.join(actor['identity_failed'])} failed)")
        mine = [e for e in self.endpoints if e.hostname == host]
        capable = [e.isolation_capable for e in mine if e.isolation_capable is not None]
        ips = _unique(a for e in mine for a in e.ip_addresses)
        connector = next((e.connector_guid for e in mine if e.connector_guid), None)
        machine = next((e.mde_machine_id for e in mine if e.mde_machine_id), None)
        isolation_capable = True if True in capable else (False if capable else None)
        ongoing = bool(running)
        exfil = bool(basis)
        routable = isolation_capable is not False and bool(connector or machine)
        return {
            "hostname": host,
            "ongoing": ongoing,
            "last_seen": _stamp(max(times) if times else None),
            "destinations": destinations,
            "destination_list": ", ".join(destinations),
            "non_clean_destinations": non_clean,
            "bytes_out": volume, "volume_text": _volume_text(volume, bool(moved)),
            "exfil": exfil,
            "basis": "; ".join(dict.fromkeys(basis)) or "no exfiltration evidence beyond the transfer",
            "unassessed": unassessed,
            "isolate": ongoing and exfil and routable,
            "routable": routable,
            "connector_guid": connector, "mde_machine_id": machine, "isolation_capable": isolation_capable,
            "groups": _unique(g for e in mine for g in e.groups), "tags": _unique(t for e in mine for t in e.tags),
            "ip": ips[0] if ips else None, "ips": ips[1:], "users": users,
            "staging": bool(staging),
            "record_ids": _unique([*basis_ids, *(r.record_id for r in running), *_ids(staging), *_ids(mine)]),
            "transfer_ids": records,
            "endpoint_ids": _ids(mine),
        }

    def _staging(self, host: str, transfers: Sequence[NetworkConnectionRecord]) -> list[ProcessEventRecord]:
        """Archives written on ``host`` within the staging window before one of its transfers started."""
        out = []
        for event in self.events:
            if event.endpoint != host or event.event_type not in _WRITES or not is_archive(event.file_path):
                continue
            for c in transfers:
                start = _start(c)
                if start is not None and timedelta(0) <= start - event.timestamp <= _STAGING_WINDOW:
                    out.append(event)
                    break
        return out

    def source_facts(self) -> list[dict[str, Any]]:
        return list(self._source_facts.values())

    # ---------------------------------------------------------------- signals --
    def signals(self) -> list[ScoringSignal]:
        out: list[ScoringSignal] = []
        for key, d in self.destinations.items():
            fact = self._dest_facts[key]
            if fact["clean"] or fact["shared"] or not d.channel_records():
                continue
            observable = Observable(type=_OTYPES[d.kind], value=d.value)
            severity = _LARGE_SEVERITY if (fact["large"] or fact["abnormal_dns"]) else _SMALL_SEVERITY
            out += _by_integration(d.channel_records(), observable, severity, self.origin,
                                   f"{fact['volume_text']} sent to {d.value} ({fact['basis']})")
        for host, fact in self._source_facts.items():
            if not fact["ongoing"] or not fact["non_clean_destinations"]:
                continue
            channel = [r for key, d in self.destinations.items() if not self._dest_facts[key]["clean"]
                       for r in d.channel_records() if r.endpoint == host and _time(r) is not None
                       and _time(r) >= self.cutoff]  # type: ignore[operator]
            out += _by_integration(channel, Observable(type=ObservableType.HOSTNAME, value=host), _RUNNING_SEVERITY,
                                   self.origin, f"running transfer from {host} to "
                                   + ", ".join(fact["non_clean_destinations"]))
        for user, actor in self.actors.items():
            transfers = [c for c in self._transfers_of(user)
                         if any(not self._dest_facts[k]["clean"] for k in self._keys_of(c))]
            if not transfers:
                continue
            out += _by_integration(transfers, Observable(type=ObservableType.USER, value=user), _ACTOR_SEVERITY,
                                   self.origin, f"account {user} drives {actor['transfer_text']}")
        return out

    def _keys_of(self, c: NetworkConnectionRecord) -> list[tuple[str, str]]:
        keys = []
        for kind, value in ((_DOMAIN, c.domain), (_IP, public_ipv4(c.remote_ip))):
            if value and (kind, value.lower()) in self._dest_facts:
                keys.append((kind, value.lower()))
        return keys

    # ------------------------------------------------------------------ links --
    def links(self) -> list[CorrelationLink]:
        links: dict[str, CorrelationLink] = {}

        def add(entities: list[EntityRef | None], record_ids: list[str], note: str, at: datetime | None,
                until: datetime | None) -> None:
            unique = {e.key(): e for e in entities if e is not None}
            if len(unique) < 2 or not record_ids:
                return
            if at is not None and until is not None and until < at:
                at, until = until, at  # a source may report its window out of order
            link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=tuple(unique.values()),
                                   record_ids=tuple(record_ids), first_seen=at, last_seen=until, note=note,
                                   origin=self.origin)
            links.setdefault(link.link_id, link)

        for d in self.destinations.values():
            peer = _entity(_TKINDS[d.kind], d.value)
            for c in d.transfers:
                add([_entity(TargetKind.ENDPOINT, c.endpoint), _entity(TargetKind.USER, c.user), peer],
                    [c.record_id], f"transfer: {format_bytes(c.bytes_out or 0)} from {c.endpoint or c.user} to "
                    f"{d.value}", _start(c), _time(c))
            for q in d.abnormal_dns:
                add([_entity(TargetKind.ENDPOINT, q.endpoint), peer], [q.record_id],
                    f"abnormal DNS: {q.endpoint} to {d.value}", _start(q), _time(q))
        for event in self.events:
            if event.event_type not in _WRITES or not is_archive(event.file_path):
                continue
            for d in self.destinations.values():
                for c in d.transfers:
                    start = _start(c)
                    if c.endpoint != event.endpoint or start is None:
                        continue
                    if timedelta(0) <= start - event.timestamp <= _STAGING_WINDOW:
                        add([_entity(TargetKind.ENDPOINT, event.endpoint), _entity(_TKINDS[d.kind], d.value)],
                            [event.record_id, c.record_id],
                            f"staging: archive written on {event.endpoint} before the transfer to {d.value}",
                            event.timestamp, _time(c))
        return [links[k] for k in sorted(links)]

    # ---------------------------------------------------------- consideration --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for fact in self._dest_facts.values():
            action = f"block_{fact['type']}:{fact['value']}"
            ids = tuple(fact["contact_ids"] or fact["record_ids"])
            if not ids or not (fact["upload"] or fact["abnormal_dns"]):
                continue
            if fact["serves_clean"]:
                out.append(Consideration(
                    subject=action,
                    reason=(f"receives {fact['volume_text']} from {', '.join(fact['sources']) or 'the estate'}, but "
                            f"the address serves {', '.join(fact['serves_clean'])}, which reputation rates CLEAN "
                            "(the same transfer or a DNS resolution names it): blocking the address would cut that "
                            "service and whatever else shares the address, so it is not blocked; confirm the "
                            "service is sanctioned and that the upload was expected"),
                    record_ids=tuple(_unique([*ids, *fact["serves_clean_ids"]]))))
            elif fact["clean"]:
                out.append(Consideration(
                    subject=action,
                    reason=(f"receives {fact['volume_text']} from {', '.join(fact['sources']) or 'the estate'}, but "
                            "reputation rates it CLEAN: not blocked; confirm the destination is sanctioned "
                            "(allowlists.never_block) and that the upload was expected"),
                    record_ids=ids))
            elif fact["shared"] and not fact["blockable"] and (fact["rated"] or fact["large"] or fact["new"]
                                                               or fact["cloud_storage"] or fact["abnormal_dns"]):
                out.append(Consideration(
                    subject=action,
                    reason=(f"reached from {fact['prevalence']} endpoints of the estate (more than "
                            f"{MAX_DESTINATION_ENDPOINTS}): shared infrastructure such as a CDN or a popular "
                            "service, so no block is proposed; a human decides"),
                    record_ids=tuple(_unique([*ids, *fact["reach_ids"]]))))
        for ip, records in sorted(self.internal.items()):
            volume = sum(c.bytes_out or 0 for c in records)
            hosts = ", ".join(sorted({c.endpoint for c in records if c.endpoint})) or "the estate"
            out.append(Consideration(
                subject=f"block_ip:{ip}",
                reason=(f"internal address (a relay or proxy inside the organisation) that received "
                        f"{format_bytes(volume)} from {hosts}: never blocked; investigate the relay host and where "
                        "it forwarded the data"),
                record_ids=tuple(_ids(records))))
        for host, fact in self._source_facts.items():
            ids = tuple(_unique([*fact["record_ids"], *fact["transfer_ids"]]))
            subject = f"isolate_endpoint:{host}"
            if fact["exfil"] and not fact["ongoing"]:
                out.append(Consideration(
                    subject=subject,
                    reason=(f"the transfer to {fact['destination_list']} finished (last record "
                            f"{fact['last_seen']}, more than {ONGOING_MINUTES} minutes before the incident): nothing "
                            "left to stop, so the endpoint is not isolated; keep the evidence on it"),
                    record_ids=ids))
            elif fact["exfil"] and fact["ongoing"] and not fact["routable"]:
                out.append(Consideration(
                    subject=subject,
                    reason=("running transfer with exfiltration evidence, but no isolation-capable endpoint record "
                            "(no Secure Endpoint connector or Defender machine id, or isolation not supported): "
                            "isolate or disconnect the endpoint by hand"),
                    record_ids=ids))
            elif fact["ongoing"] and not fact["exfil"] and fact["non_clean_destinations"]:
                reason = (f"running transfer to {', '.join(fact['non_clean_destinations'])}, but no destination "
                          "rating, malicious or exfiltration detection, compromised account or insider-risk "
                          "detection: not isolated (an approved destination block stops the transfer)")
                if fact["unassessed"]:
                    reason += "; account(s) not assessed: " + ", ".join(fact["unassessed"])
                out.append(Consideration(subject=subject, reason=reason, record_ids=ids))
        for user, actor in self.actors.items():
            if actor["compromised"] and not actor["drives"] and not actor["insider"] and actor["compromise_ids"]:
                hosts = sorted(h for h, f in self._source_facts.items() if user in f["users"])
                tie = (f"uses the source endpoint {', '.join(hosts)}" if hosts else "is named by the incident")
                out.append(Consideration(
                    subject=f"disable_user:{user}",
                    reason=(f"the account is compromised ({actor['basis']}) and {tie}, but no transfer record names "
                            "it: the account decisions of this workflow are for an account that drives a transfer, "
                            "so its sessions are not revoked and it is not disabled here; it is handed off to "
                            "account-takeover and a human decides"),
                    record_ids=tuple(actor["compromise_ids"])))
                continue
            if actor["assessed"] or actor["compromised"] or actor["insider"] or not actor["transfer_ids"]:
                continue
            out.append(Consideration(
                subject=f"revoke_sessions:{user}",
                reason=(f"the account drives {actor['transfer_text']} but could not be assessed because "
                        f"{', '.join(actor['identity_failed'])} failed: sessions are not revoked and the account is "
                        "not disabled; check the identity console and decide by hand"),
                record_ids=tuple(actor["transfer_ids"])))
        out.extend(self._manual_steps())
        return out

    def _manual_steps(self) -> list[Consideration]:
        out = []
        for host, fact in self._source_facts.items():
            blockable = [f for f in self._dest_facts.values() if f["blockable"] and host in f["sources"]]
            if not (fact["exfil"] or blockable):
                continue
            out.append(Consideration(
                subject=f"assess data exposure from {host}",
                reason=(f"no VERIFIED read classifies the data sent: legal and privacy assess what was sent "
                        f"({fact['volume_text']}) to {fact['destination_list']} (last record {fact['last_seen']}) "
                        "and decide notification obligations; keep the evidence on the endpoint (no reimage before "
                        "forensic collection and legal sign-off)"),
                record_ids=tuple(fact["transfer_ids"]), manual=True))
        return out

    # --------------------------------------------------------------- handoffs --
    def handoffs(self) -> list[Handoff]:
        compromised = {u: a for u, a in self.actors.items() if a["compromised"] and a["compromise_ids"]}
        if not compromised:
            return []
        return [Handoff(
            workflow_id="account-takeover", subjects=tuple(sorted(compromised)),
            reason=("an account tied to the transfer (named by a transfer record, the incident or a source "
                    "endpoint's records) shows a compromise record (identity risk or anomalies): review its "
                    "sign-ins, mailbox and cloud activity beyond this transfer"),
            record_ids=tuple(_unique(i for u in sorted(compromised) for i in compromised[u]["compromise_ids"])))]

    def as_dict(self) -> dict[str, Any]:
        return {
            "destinations": [{k: v for k, v in f.items() if k not in ("contact_ids", "reach_ids")}
                             for f in self.destination_facts()],
            "sources": [{k: v for k, v in f.items() if k not in ("transfer_ids", "endpoint_ids")}
                        for f in self.source_facts()],
            "actors": [{k: v for k, v in a.items() if k not in ("compromise_ids", "insider_ids", "transfer_ids")}
                       for a in self.actor_facts()],
        }


def _by_integration(records: Sequence[AnyRecord], observable: Observable, severity: int, origin: str,
                    note: str) -> list[ScoringSignal]:
    """One SUSPICIOUS ``network_behaviour`` signal per integration that reported the cited records."""
    by_source: dict[str, list[str]] = {}
    for record in records:
        by_source.setdefault(record.integration, []).append(record.record_id)
    return [ScoringSignal(category=SignalCategory.NETWORK_BEHAVIOUR, integration=integration, observable=observable,
                          verdict=Verdict.SUSPICIOUS, severity=severity, confidence=_PATTERN_CONFIDENCE,
                          record_ids=tuple(_unique(ids)), origin=origin, note=note[:500])
            for integration, ids in sorted(by_source.items())]


class ExfiltrationHooks(WorkflowHooks):
    """Facts, transfer signals, links, considerations and hand-offs (pure; no context, no adapters)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _Analysis(view).links()

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return _Analysis(view).signals()

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Analysis(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Analysis(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Analysis(view).handoffs()


HOOKS = ExfiltrationHooks()
