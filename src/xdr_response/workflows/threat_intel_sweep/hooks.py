"""Pure hooks of the threat-intelligence sweep workflow (architecture 14.3.3 and 14.10.1).

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters, no
configuration) and derive:

* ``facts`` for the rule expressions:

  - ``indicators``: every swept indicator (the incident's SHA-256, domain, IPv4, URL and email address
    observables), its rating and its hits. An indicator is *rated* when its aggregate enrichment
    verdict is MALICIOUS or a record that names it carries the security product's own MALICIOUS
    verdict (a detection, prevalence or process record of the file, a connection or DNS record whose
    destination is exactly the indicator, a message from the sender). A process verdict never rates a
    destination the process reached, a verdict about a subdomain never rates its parent, and a
    record's verdict never overrides a CLEAN enrichment aggregate of a domain, IP or URL (the
    contradiction is shown as considered). The feed's claim of high confidence is incident data and
    never rates anything. A *hit* is a record that names the indicator together with an affected
    asset: an endpoint (detections, prevalence, process events, connections, DNS queries), an account
    (sign-ins, connections) or a message (sender, sender domain, carried URLs, domains and attachment
    hashes). A domain indicator also matches its subdomains; a URL matches only the same URL;
    a DNS answer that resolved to an IP indicator is a hit of that IP;
  - ``hosts``: every endpoint a hit names, whether a rated file indicator ran on it (a process event
    of an execution type with its hash), whether it reached a rated network indicator, and whether it
    shows malicious activity of its own (an active MALICIOUS detection, a MALICIOUS process event).
    ``isolate`` is true when the file ran, or when the endpoint reached a rated indicator and shows
    malicious activity of its own. ``binaries`` lists the hashes the isolation rests on when the
    execution of rated files is its only basis (a sanctioned binary never isolates its host);
  - ``files``: ``<HOST>/<sha256>`` for every endpoint where a rated file indicator is present and was
    neither remediated by the agent (a resolved detection without an active one) nor deleted;
  - ``messages``: every message that carries an indicator; ``quarantine`` is true when it is still
    delivered (inbox or junk, never reported quarantined or deleted) and carries a rated indicator;
  - ``accounts``: accounts a sign-in record ties to a rated IP indicator; ``signed_in`` when one
    sign-in succeeded; the identity source's ``groups``, ``roles`` and ``privileged`` flag (user
    profile records: an account in a critical group is ELEVATED); ``indicators``, the ``block_ip``
    subjects the revocation rests on alone (the runner withholds it when the allow-list excludes every
    one: organisation infrastructure or a non-public address).

  Every fact carries the record ids it was computed from, and the rules cite exactly those ids.
* ``correlate`` links of kind ``WORKFLOW``: an indicator hit (the indicator and the endpoint, account
  or message one record names together with it);
* ``considered`` items: indicators no source rates MALICIOUS (SUSPICIOUS only, CLEAN, CLEAN but
  contradicted by a connection or DNS verdict, or unrated with hits), endpoints that only reached a rated indicator, delivered messages that carry only unrated
  indicators and accounts with failed sign-ins only; manual steps for a rated sender address (no
  VERIFIED gateway block) and for endpoints that should be isolated but no agent can isolate;
* ``handoffs`` to ``malware`` (rated file hashes found on endpoints), ``c2`` (endpoints that reached a
  rated network indicator), ``phishing`` (mailboxes that received a delivered carrier message) and
  ``account-takeover`` (accounts that signed in from a rated IP).

Nothing here creates a record, scores a target, chooses an approval level or calls a vendor; a hook
that fails is noted and ignored by the runner.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import ObservableType, TargetKind, Verdict
from xdr_response.models.canonical import canonical_url, normalize_target
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks, failed_reads
from xdr_response.workflows.threat_intel_sweep.definition import DELIVERED_LOCATIONS, EXECUTION_EVENT_TYPES

__all__ = ["ThreatIntelSweepHooks", "HOOKS", "indicator_key", "ipv4"]

_MALICIOUS = Verdict.MALICIOUS
_FLAGGING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_VERDICT_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2,
                                        Verdict.MALICIOUS: 3}
_EXECUTION = frozenset(EXECUTION_EVENT_TYPES)
_DELIVERED = frozenset(DELIVERED_LOCATIONS)
_REMOVED_LOCATIONS = frozenset({"quarantine", "deleted"})
_O = ObservableType
#: indicator type -> (observable type, entity kind, block action or manual subject prefix)
_TYPES: Mapping[str, tuple[ObservableType, TargetKind, str]] = {
    "sha256": (_O.SHA256, TargetKind.HASH, "block_hash"),
    "domain": (_O.DOMAIN, TargetKind.DOMAIN, "block_domain"),
    "ip": (_O.IP, TargetKind.IP, "block_ip"),
    "url": (_O.URL, TargetKind.URL, "block_url"),
    "email_address": (_O.EMAIL_ADDRESS, TargetKind.EMAIL_ADDRESS, "block_sender"),
}
_NETWORK = frozenset({"domain", "ip", "url"})
#: the indicator actions that are containment actions (``block_sender`` is a manual step, not one)
_BLOCK_ACTIONS = frozenset({"block_hash", "block_domain", "block_ip", "block_url"})
_HEX = frozenset("0123456789abcdef")


# ------------------------------------------------------------------ helpers --
def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v], default=Verdict.UNKNOWN)


def _short(sha: str) -> str:
    return sha[:12] + "..."


def ipv4(value: str | None) -> str | None:
    """The compressed IPv4 address of ``value`` (an IPv4-mapped IPv6 address is unmapped), else None."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        return mapped.compressed if mapped is not None else None
    return address.compressed


def _url_key(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return canonical_url(normalize_target(TargetKind.URL, value))
    except ValueError:
        return None


def indicator_key(kind: str, value: str | None) -> str | None:
    """The comparison spelling of an indicator of ``kind`` (None when it is not a sweepable value)."""
    if not value or not value.strip():
        return None
    text = value.strip()
    if kind == "sha256":
        lowered = text.lower()
        return lowered if len(lowered) == 64 and set(lowered) <= _HEX else None
    if kind == "domain":
        lowered = text.lower().rstrip(".")
        return lowered or None
    if kind == "ip":
        return ipv4(text)
    if kind == "url":
        return _url_key(text)
    if kind == "email_address":
        lowered = text.lower()
        return lowered if "@" in lowered else None
    return None


def _domain_hit(value: str | None, domain: str) -> bool:
    if not value:
        return False
    name = value.strip().lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


class _Indicator:
    """One swept indicator: its type, its normalized value and the hit records that name it."""

    def __init__(self, kind: str, value: str, key: str) -> None:
        self.kind = kind
        self.value = value
        self.key = key
        self.hits: list[tuple[AnyRecord, TargetKind | None, str | None]] = []

    def add(self, record: AnyRecord, asset_kind: TargetKind | None, asset: str | None) -> None:
        self.hits.append((record, asset_kind, asset))

    def records(self) -> list[AnyRecord]:
        seen: dict[str, AnyRecord] = {}
        for record, _kind, _asset in self.hits:
            seen.setdefault(record.record_id, record)
        return list(seen.values())

    def assets(self, kind: TargetKind) -> list[str]:
        return sorted({a for _r, k, a in self.hits if k is kind and a})

    def records_for(self, kind: TargetKind, asset: str) -> list[AnyRecord]:
        return [r for r, k, a in self.hits if k is kind and a == asset]


def _same_name(value: str | None, domain: str) -> bool:
    return bool(value) and str(value).strip().lower().rstrip(".") == domain


def _names_destination(record: NetworkConnectionRecord, indicator: _Indicator) -> bool:
    """True when the connection's destination is the indicator itself (never a subdomain of it)."""
    if indicator.kind == "domain":
        return _same_name(record.domain, indicator.key)
    if indicator.kind == "ip":
        return ipv4(record.remote_ip) == indicator.key
    if indicator.kind == "url":
        return _url_key(record.url) == indicator.key
    return False


def _own_verdict(record: AnyRecord, indicator: _Indicator) -> Verdict:
    """The security product's verdict on a hit record that rates the indicator itself.

    A detection, prevalence or process record rates the file it names (a process verdict is about the
    process image, never a destination the process reached); a connection or DNS record rates the
    destination it names only when that destination is the indicator itself (a verdict about
    ``bad.cloudhost.test`` never rates ``cloudhost.test``); a message verdict rates only its sender (a
    message is rated as a whole, never one URL or attachment inside it).
    """
    if isinstance(record, (DetectionRecord, HashPrevalenceRecord)):
        return record.verdict if indicator.kind == "sha256" else Verdict.UNKNOWN
    if isinstance(record, ProcessEventRecord):
        if indicator.kind == "sha256":
            return record.verdict if (record.sha256 or "").lower() == indicator.key else Verdict.UNKNOWN
        return Verdict.UNKNOWN  # the verdict is about the process, not the destination it reached
    if isinstance(record, NetworkConnectionRecord):
        if indicator.kind == "sha256":
            return Verdict.UNKNOWN  # the verdict is about the connection, not the process image
        return record.verdict if _names_destination(record, indicator) else Verdict.UNKNOWN
    if isinstance(record, DnsQueryRecord):
        return record.verdict if indicator.kind == "domain" and _same_name(record.domain, indicator.key) \
            else Verdict.UNKNOWN
    if isinstance(record, EmailMessageRecord):
        return record.verdict if indicator.kind == "email_address" else Verdict.UNKNOWN
    return Verdict.UNKNOWN


class _Sweep:
    """One computation of the facts over a run view (private helper of :class:`ThreatIntelSweepHooks`)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        records = view.index.records()
        self.records = records
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {}
        for result in view.results:
            if isinstance(result, ObservableReport):
                self.reports[(result.type, result.value.lower())] = result
                if result.type is _O.URL:
                    url = _url_key(result.value)
                    if url is not None:
                        self.reports[(result.type, url)] = result
        self.indicators = self._indicators()
        self._match()
        self.indicator_facts = [self._indicator_fact(i) for i in self.indicators]
        self._by_key = {(d["type"], d["key"]): d for d in self.indicator_facts}
        self.host_facts = self._hosts()
        self.file_facts = self._files()
        self.message_facts = self._messages()
        self.account_facts = self._accounts()

    # -------------------------------------------------------- indicators --
    def _indicators(self) -> list[_Indicator]:
        kinds = {otype: name for name, (otype, _k, _a) in _TYPES.items()}
        found: dict[tuple[str, str], _Indicator] = {}
        for observable in self.view.incident.observables:
            kind = kinds.get(observable.type)
            if kind is None:
                continue
            key = indicator_key(kind, observable.value)
            if key is None:
                continue
            value = key if kind != "url" else normalize_target(TargetKind.URL, observable.value)
            found.setdefault((kind, key), _Indicator(kind, value, key))
        return list(found.values())

    def _of(self, kind: str) -> list[_Indicator]:
        return [i for i in self.indicators if i.kind == kind]

    def _match(self) -> None:
        hashes = {i.key: i for i in self._of("sha256")}
        ips = {i.key: i for i in self._of("ip")}
        urls = {i.key: i for i in self._of("url")}
        senders = {i.key: i for i in self._of("email_address")}
        domains = self._of("domain")

        def by_domain(value: str | None) -> list[_Indicator]:
            return [d for d in domains if _domain_hit(value, d.key)]

        for record in self.records:
            if isinstance(record, DetectionRecord):
                hit = hashes.get((record.sha256 or "").lower())
                if hit is not None:
                    hit.add(record, TargetKind.ENDPOINT if record.endpoint else None, record.endpoint)
            elif isinstance(record, HashPrevalenceRecord):
                hit = hashes.get(record.sha256.lower())
                if hit is not None:
                    if record.endpoints:
                        for host in record.endpoints:
                            hit.add(record, TargetKind.ENDPOINT, host)
                    else:
                        hit.add(record, None, None)
            elif isinstance(record, ProcessEventRecord):
                for sha in {(record.sha256 or "").lower(), (record.parent_sha256 or "").lower()}:
                    if sha in hashes:
                        hashes[sha].add(record, TargetKind.ENDPOINT, record.endpoint)
                for hit in by_domain(record.domain):
                    hit.add(record, TargetKind.ENDPOINT, record.endpoint)
                ip_hit = ips.get(ipv4(record.remote_ip) or "")
                if ip_hit is not None:
                    ip_hit.add(record, TargetKind.ENDPOINT, record.endpoint)
            elif isinstance(record, NetworkConnectionRecord):
                if record.direction == "internal":
                    continue
                asset = (TargetKind.ENDPOINT, record.endpoint) if record.endpoint else (TargetKind.USER, record.user)
                matched: list[_Indicator] = [*by_domain(record.domain)]
                for found in (ips.get(ipv4(record.remote_ip) or ""), urls.get(_url_key(record.url) or ""),
                              hashes.get((record.sha256 or "").lower())):
                    if found is not None:
                        matched.append(found)
                for hit in matched:
                    hit.add(record, asset[0] if asset[1] else None, asset[1])
                    if record.endpoint and record.user:
                        hit.add(record, TargetKind.USER, record.user)
            elif isinstance(record, DnsQueryRecord):
                asset_kind = TargetKind.ENDPOINT if record.endpoint else None
                for hit in by_domain(record.domain):
                    hit.add(record, asset_kind, record.endpoint)
                for address in record.response_ips:
                    ip_hit = ips.get(ipv4(address) or "")
                    if ip_hit is not None:
                        ip_hit.add(record, asset_kind, record.endpoint)
            elif isinstance(record, EmailMessageRecord):
                matched = []
                sender = senders.get((record.sender or "").lower())
                if sender is not None:
                    matched.append(sender)
                for value in (record.sender_domain, *record.domains):
                    matched.extend(by_domain(value))
                for url in record.urls:
                    found = urls.get(_url_key(url) or "")
                    if found is not None:
                        matched.append(found)
                for sha in record.attachment_hashes:
                    found = hashes.get(sha.lower())
                    if found is not None:
                        matched.append(found)
                for hit in dict.fromkeys(matched):
                    hit.add(record, TargetKind.EMAIL_MESSAGE, record.message_id)
            elif isinstance(record, SignInRecord):
                ip_hit = ips.get(ipv4(record.ip) or "")
                if ip_hit is not None:
                    ip_hit.add(record, TargetKind.USER, record.user)

    def _report(self, indicator: _Indicator) -> ObservableReport | None:
        otype = _TYPES[indicator.kind][0]
        return self.reports.get((otype, indicator.key)) or self.reports.get((otype, indicator.value.lower()))

    def _indicator_fact(self, indicator: _Indicator) -> dict[str, Any]:
        report = self._report(indicator)
        enrichment = report.verdict if report is not None else Verdict.UNKNOWN
        enrichment_records = list(report.enrichment_records()) if report is not None else []
        support = [r for r in enrichment_records if r.verdict in _FLAGGING]
        hit_records = indicator.records()
        flagged = [r for r in hit_records if _own_verdict(r, indicator) is _MALICIOUS]
        sighting = _worst(_own_verdict(r, indicator) for r in hit_records)
        clean = sorted({r.integration for r in enrichment_records if r.verdict is Verdict.CLEAN})
        # A destination the enrichment aggregate rates CLEAN is never rated by a record's verdict: the
        # contradiction is shown to a human (considered), never resolved towards a block (14.13.6).
        contradicted = bool(flagged) and enrichment is Verdict.CLEAN and indicator.kind in _NETWORK
        basis: list[str] = []
        if enrichment is _MALICIOUS:
            basis.append(f"enrichment MALICIOUS ({', '.join(sorted({r.integration for r in support}))})")
        sources = ", ".join(sorted({f"{r.integration} {r.kind}" for r in flagged}))
        if flagged and not contradicted:
            basis.append(f"a record naming it carries a MALICIOUS verdict ({sources})")
        if contradicted:
            basis.append(f"rated CLEAN by {', '.join(clean) or 'enrichment'}, contradicted by a MALICIOUS verdict on "
                         f"a record naming it ({sources})")
        rated = enrichment is _MALICIOUS or (bool(flagged) and not contradicted)
        if rated:
            rating = _MALICIOUS
        elif contradicted:
            rating = Verdict.CLEAN
        elif _VERDICT_RANK[enrichment] >= _VERDICT_RANK[sighting]:
            rating = enrichment
        else:
            rating = sighting
        if not basis:
            if rating is Verdict.SUSPICIOUS:
                basis.append("rated SUSPICIOUS only")
            elif rating is Verdict.CLEAN and clean:
                basis.append(f"rated CLEAN by {', '.join(clean)}")
            else:
                basis.append("not rated")
        nested = [r for r in hit_records if indicator.kind == "domain" and not rated
                  and isinstance(r, (DnsQueryRecord, NetworkConnectionRecord)) and r.verdict is _MALICIOUS
                  and _own_verdict(r, indicator) is not _MALICIOUS]
        if nested:
            names = sorted({str(r.domain) for r in nested if r.domain})
            basis.append(f"a record of a name under it ({', '.join(names)}) carries a MALICIOUS verdict: that verdict "
                         "rates the subdomain, not the indicator")
        endpoints = indicator.assets(TargetKind.ENDPOINT)
        users = indicator.assets(TargetKind.USER)
        messages = indicator.assets(TargetKind.EMAIL_MESSAGE)
        parts = []
        if endpoints:
            parts.append(f"{len(endpoints)} endpoint(s) ({', '.join(endpoints)})")
        if users:
            parts.append(f"{len(users)} account(s) ({', '.join(users)})")
        if messages:
            parts.append(f"{len(messages)} message(s)")
        rating_ids = _ids([*support, *flagged]) if rated else []
        return {
            "type": indicator.kind,
            "value": indicator.value,
            "key": indicator.key,
            "rated": rated,
            "rating": rating.value,
            "contradicted": contradicted,
            "basis": "; ".join(basis),
            "enrichment_verdict": enrichment.value,
            "sighting_verdict": sighting.value,
            "endpoints": endpoints,
            "users": users,
            "messages": messages,
            "hit_count": len(endpoints) + len(users) + len(messages),
            "hit_text": ", ".join(parts) or "none found in the sweep window (preventive)",
            "rating_record_ids": rating_ids,
            "hit_record_ids": _ids(hit_records),
            "enrichment_record_ids": _ids(enrichment_records),
            "record_ids": list(dict.fromkeys([*rating_ids, *_ids(hit_records)])),
        }

    def _fact(self, indicator: _Indicator) -> dict[str, Any]:
        return self._by_key[(indicator.kind, indicator.key)]

    def _rated(self, kind: str | None = None) -> list[_Indicator]:
        return [i for i in self.indicators if self._fact(i)["rated"] and (kind is None or i.kind == kind)]

    # ------------------------------------------------------------- hosts --
    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        addresses = list(dict.fromkeys(a for e in mine for a in e.ip_addresses))
        return {
            "groups": list(dict.fromkeys(g for e in mine for g in e.groups)),
            "tags": list(dict.fromkeys(t for e in mine for t in e.tags)),
            "ip": addresses[0] if addresses else None,
            "ips": addresses,
            "users": list(dict.fromkeys(u for e in mine for u in e.users)),
        }

    def _executions(self, host: str, sha: str) -> list[ProcessEventRecord]:
        return [e for e in self.events if e.endpoint == host and (e.sha256 or "").lower() == sha
                and e.event_type in _EXECUTION]

    def _activity(self, host: str) -> tuple[list[str], list[AnyRecord]]:
        basis: list[str] = []
        records: list[AnyRecord] = []
        for d in self.detections:
            if d.endpoint == host and d.verdict is _MALICIOUS and d.status != "resolved":
                basis.append(f"active detection '{d.name}' {d.verdict.value}")
                records.append(d)
        bad = [e for e in self.events if e.endpoint == host and e.verdict is _MALICIOUS]
        if bad:
            basis.append(f"{len(bad)} malicious process event(s)")
            records.extend(bad)
        return basis, records

    def _hosts(self) -> list[dict[str, Any]]:
        hosts = sorted({h for i in self.indicators for h in i.assets(TargetKind.ENDPOINT)})
        out: list[dict[str, Any]] = []
        for host in hosts:
            mine = [e for e in self.endpoints if e.hostname == host]
            executed: list[str] = []
            exec_records: list[AnyRecord] = []
            for indicator in self._rated("sha256"):
                runs = self._executions(host, indicator.key)
                if runs:
                    executed.append(indicator.key)
                    exec_records.extend(runs)
                    exec_records.extend(self.index_records(self._fact(indicator)["rating_record_ids"]))
            contacts: list[str] = []
            contact_records: list[AnyRecord] = []
            for indicator in self._rated():
                if indicator.kind not in _NETWORK:
                    continue
                own = indicator.records_for(TargetKind.ENDPOINT, host)
                if own:
                    contacts.append(indicator.value)
                    contact_records.extend(own)
                    contact_records.extend(self.index_records(self._fact(indicator)["rating_record_ids"]))
            activity_basis, activity = self._activity(host)
            isolate = bool(executed) or (bool(contacts) and bool(activity))
            basis: list[str] = []
            if executed:
                basis.append("rated file(s) ran on it (" + ", ".join(_short(s) for s in executed) + ")")
            if contacts:
                basis.append("it reached rated indicator(s) " + ", ".join(contacts))
            basis.extend(activity_basis)
            binaries = sorted(executed) if executed and not activity else []
            capable = next((e.isolation_capable for e in mine if e.isolation_capable is not None), None)
            out.append({
                "hostname": host,
                "connector_guid": next((e.connector_guid for e in mine if e.connector_guid), None),
                "mde_machine_id": next((e.mde_machine_id for e in mine if e.mde_machine_id), None),
                "isolation_capable": capable,
                "isolation_state": next((e.isolation_state for e in mine if e.isolation_state != "unknown"),
                                        "unknown"),
                "executed": executed,
                "contacts": contacts,
                "contact_list": ", ".join(contacts),
                "malicious_activity": bool(activity),
                "isolate": isolate,
                "binaries": binaries,
                "basis": "; ".join(basis) or "hits of unrated indicators only",
                "record_ids": list(dict.fromkeys([*_ids(exec_records), *_ids(activity), *_ids(contact_records)])),
                "contact_record_ids": _ids(contact_records),
                "hit_record_ids": _ids(r for i in self.indicators for r in i.records_for(TargetKind.ENDPOINT, host)),
                **self._context(host),
            })
        return out

    def index_records(self, record_ids: Sequence[str]) -> list[AnyRecord]:
        return [self.view.index.get(i) for i in record_ids if i in self.view.index]

    # ------------------------------------------------------------- files --
    def _remediated(self, host: str, sha: str) -> bool:
        mine = [d for d in self.detections if d.endpoint == host and (d.sha256 or "").lower() == sha]
        resolved = any(d.status == "resolved" for d in mine) and not any(d.status != "resolved" for d in mine)
        deleted = any(e.endpoint == host and (e.sha256 or "").lower() == sha and e.event_type == "file_delete"
                      for e in self.events)
        return resolved or deleted

    def _files(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for indicator in self._rated("sha256"):
            fact = self._fact(indicator)
            for host in indicator.assets(TargetKind.ENDPOINT):
                if self._remediated(host, indicator.key):
                    continue
                presence = [r for r in indicator.records_for(TargetKind.ENDPOINT, host)
                            if not (isinstance(r, ProcessEventRecord) and (r.sha256 or "").lower() != indicator.key)]
                if not presence:
                    continue  # only a child of the file was seen: presence of the file itself is not shown
                kinds = sorted({str(r.kind) for r in presence})
                ran = bool(self._executions(host, indicator.key))
                out.append({
                    "target": f"{host}/{indicator.key}",
                    "endpoint": host,
                    "sha256": indicator.key,
                    "executed": ran,
                    "basis": ("ran; " if ran else "") + "seen in " + ", ".join(kinds) + " record(s)",
                    "record_ids": list(dict.fromkeys([*_ids(presence), *fact["rating_record_ids"]])),
                    **self._context(host),
                })
        return sorted(out, key=lambda f: f["target"])

    # ---------------------------------------------------------- messages --
    def _messages(self) -> list[dict[str, Any]]:
        grouped: dict[str, list[EmailMessageRecord]] = {}
        carried: dict[str, list[_Indicator]] = {}
        for indicator in self.indicators:
            for record, kind, asset in indicator.hits:
                if kind is TargetKind.EMAIL_MESSAGE and asset and isinstance(record, EmailMessageRecord):
                    bucket = grouped.setdefault(asset, [])
                    if record.record_id not in {r.record_id for r in bucket}:
                        bucket.append(record)
                    if indicator not in carried.setdefault(asset, []):
                        carried[asset].append(indicator)
        out: list[dict[str, Any]] = []
        for message_id in sorted(grouped):
            records = grouped[message_id]
            indicators = carried[message_id]
            rated = [i for i in indicators if self._fact(i)["rated"]]
            locations = {r.delivery_location for r in records}
            delivered = bool(locations & _DELIVERED) and not locations & _REMOVED_LOCATIONS
            recipients = sorted({a for r in records for a in r.recipients})
            count = max((r.recipient_count for r in records), default=0)
            rating_ids = [i for ind in rated for i in self._fact(ind)["rating_record_ids"]]
            # the quarantine rests on these rated indicators alone (the message has no verdict of its
            # own here): when the allow-list excludes the block of every one (the organisation's own
            # domain, a sanctioned service, the approved RMM tool, a never_block hash) the runner
            # withholds it and shows it as considered (14.13.6). A rated sender has no block action
            # (block_sender is a manual step), so it can never be shown to be allow-listed: [] keeps
            # the quarantine proposed.
            block_indicators = ([] if any(_TYPES[i.kind][2] not in _BLOCK_ACTIONS for i in rated)
                                else [f"{_TYPES[i.kind][2]}:{i.value}" for i in rated])
            out.append({
                "message_id": message_id,
                "indicators": [i.value for i in indicators],
                "rated_indicators": [i.value for i in rated],
                "block_indicators": block_indicators,
                "indicator_list": ", ".join(i.value for i in rated) or ", ".join(i.value for i in indicators),
                "delivered": delivered,
                "delivery_locations": sorted(locations),
                "quarantine": delivered and bool(rated),
                "recipients": recipients,
                "recipient": recipients[0] if len(recipients) == 1 and count <= 1 else "",
                "recipient_list": ", ".join(recipients) or "unknown recipients",
                "record_ids": list(dict.fromkeys([*_ids(records), *rating_ids])),
                "message_record_ids": _ids(records),
            })
        return out

    # ---------------------------------------------------------- accounts --
    def _accounts(self) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for indicator in self._rated("ip"):
            fact = self._fact(indicator)
            for user in indicator.assets(TargetKind.USER):
                signins = [r for r in indicator.records_for(TargetKind.USER, user) if isinstance(r, SignInRecord)]
                if not signins:
                    continue
                entry = out.setdefault(user, {"user": user, "ips": [], "signed_in": False, "record_ids": [],
                                              "sign_in_record_ids": []})
                entry["ips"].append(indicator.value)
                entry["signed_in"] = entry["signed_in"] or any(s.result == "success" for s in signins)
                entry["sign_in_record_ids"].extend(_ids(signins))
                entry["record_ids"].extend([*_ids(signins), *fact["rating_record_ids"]])
        profiles = [r for r in self.records if isinstance(r, UserProfileRecord)]
        for entry in out.values():
            entry["ips"] = sorted(set(entry["ips"]))
            entry["ip_list"] = ", ".join(entry["ips"])
            # the revocation rests on these indicators alone: when the allow-list excludes every one
            # (organisation infrastructure, a non-public address) the runner withholds it (14.13.6)
            entry["indicators"] = [f"block_ip:{ip}" for ip in entry["ips"]]
            entry["record_ids"] = list(dict.fromkeys(entry["record_ids"]))
            entry["sign_in_record_ids"] = list(dict.fromkeys(entry["sign_in_record_ids"]))
            mine = [p for p in profiles if str(p.user).lower() == entry["user"].lower()]
            entry["groups"] = list(dict.fromkeys(g for p in mine for g in p.groups))
            entry["roles"] = list(dict.fromkeys(r for p in mine for r in p.roles))
            entry["privileged"] = any(p.privileged for p in mine)
        return [out[u] for u in sorted(out)]

    # ------------------------------------------------------- considered --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for fact in self.indicator_facts:
            action = _TYPES[fact["type"]][2]
            subject = f"{action}:{fact['value']}"
            if fact["rated"]:
                if fact["type"] == "email_address" and fact["record_ids"]:
                    out.append(Consideration(subject=subject, record_ids=tuple(fact["record_ids"]), manual=True,
                                             reason=(
                        "the sender address is rated MALICIOUS but no VERIFIED write blocks a sender: add it to the "
                        "Secure Email Threat Defense or Defender for Office 365 block list by hand (the delivered "
                        "messages from it are in the package)")))
                continue
            ids = fact["record_ids"] or fact["enrichment_record_ids"]
            if fact["contradicted"]:
                ids = list(dict.fromkeys([*fact["record_ids"], *fact["enrichment_record_ids"]]))
            if not ids:
                continue
            hits = f"{fact['hit_count']} hit(s) ({fact['hit_text']})" if fact["hit_count"] else "no hit"
            if fact["contradicted"]:
                reason = (f"{fact['basis']}: the sources disagree, and a destination the reputation sources rate CLEAN "
                          f"is never blocked on a connection verdict; {hits}: no action rests on it alone; a human "
                          "decides")
            elif fact["rating"] == Verdict.SUSPICIOUS.value:
                reason = (f"rated SUSPICIOUS only (one vendor alone is never MALICIOUS); {hits}: the indicator is "
                          "not blocked and no action rests on it alone; a human decides")
            elif fact["rating"] == Verdict.CLEAN.value:
                reason = (f"{fact['basis']}: the feed's claim is contradicted; {hits}: the indicator is not "
                          "blocked and no action rests on it alone; a human decides")
            else:
                reason = (f"no source rates it; {hits}: the indicator is not blocked and no action rests on it "
                          "alone; a human decides")
            out.append(Consideration(subject=subject, record_ids=tuple(ids), reason=reason))
        for h in self.host_facts:
            subject = f"isolate_endpoint:{h['hostname']}"
            if h["contacts"] and not h["isolate"] and h["contact_record_ids"]:
                out.append(Consideration(subject=subject, record_ids=tuple(h["contact_record_ids"]), reason=(
                    f"reached rated indicator(s) {h['contact_list']} but no rated file ran on it and it shows no "
                    "malicious activity of its own: not isolated; the indicator block cuts the path, the c2 "
                    "hand-off reviews the endpoint and the analyst can isolate it by hand")))
            elif h["isolate"] and h["record_ids"]:
                if h["isolation_capable"] is False:
                    out.append(Consideration(subject=subject, record_ids=tuple(h["record_ids"]), manual=True, reason=(
                        "the endpoint should be isolated but its agent policy does not allow isolation: contain it "
                        "on the network by hand (for example a Meraki client block or a switch port shutdown)")))
                elif not h["connector_guid"] and not h["mde_machine_id"]:
                    out.append(Consideration(subject=subject, record_ids=tuple(h["record_ids"]), manual=True, reason=(
                        "the endpoint should be isolated but neither Secure Endpoint nor Defender manages it: "
                        "contain it on the network by hand")))
        for m in self.message_facts:
            if m["delivered"] and not m["quarantine"] and m["message_record_ids"]:
                out.append(Consideration(subject=f"quarantine_email:{m['message_id']}",
                                         record_ids=tuple(m["message_record_ids"]), reason=(
                    f"delivered to {m['recipient_list']} and carries {m['indicator_list']}, which no source rates "
                    "MALICIOUS: not quarantined; a human decides")))
        out += self._unrated_ip_accounts()
        for a in self.account_facts:
            if not a["signed_in"] and a["sign_in_record_ids"]:
                out.append(Consideration(subject=f"revoke_sessions:{a['user']}",
                                         record_ids=tuple(a["sign_in_record_ids"]), reason=(
                    f"only failed sign-ins from the rated indicator(s) {a['ip_list']}: no session to revoke; the "
                    "indicator block stops further attempts")))
        return out

    def _unrated_ip_accounts(self) -> list[Consideration]:
        """Accounts that signed in from an IP indicator left unrated because its enrichment FAILED.

        The revocation rests on a rated IP indicator. When a reputation source failed for the IP and the
        rest do not rate it MALICIOUS, the account's sign-in is still shown (degraded source, owner rule):
        never revoked on a missing rating, never dropped silently.
        """
        failed = {k.lower(): v for k, v in failed_reads(self.view, ("enrich_ip",)).items()}
        listed = {a["user"] for a in self.account_facts}
        out: list[Consideration] = []
        for indicator in self.indicators:
            names = failed.get(indicator.value.lower()) or failed.get(indicator.key)
            if indicator.kind != "ip" or not names or self._fact(indicator)["rated"]:
                continue
            for user in indicator.assets(TargetKind.USER):
                signins = [r for r in indicator.records_for(TargetKind.USER, user)
                           if isinstance(r, SignInRecord) and r.result == "success"]
                if not signins or user in listed:
                    continue
                out.append(Consideration(subject=f"revoke_sessions:{user}", record_ids=tuple(_ids(signins)), reason=(
                    f"signed in successfully from IP indicator {indicator.value}, which is "
                    f"{self._fact(indicator)['basis']}: {', '.join(names)} failed for enrich_ip {indicator.value}, "
                    "so the rating the revocation needs may be missing; not revoked: re-run when the source "
                    "recovers, or decide by hand")))
        return out

    def handoffs(self) -> list[Handoff]:
        out: list[Handoff] = []
        files: dict[str, list[str]] = {}
        for f in self.file_facts:
            files.setdefault(f["sha256"], []).extend(f["record_ids"])
        if files:
            out.append(Handoff(workflow_id="malware", subjects=tuple(sorted(files)),
                               record_ids=tuple(dict.fromkeys(i for ids in files.values() for i in ids)), reason=(
                "a rated file indicator is on endpoints: trace its process tree, origin and connections and scope "
                "it across the estate")))
        contacted = [h for h in self.host_facts if h["contacts"]]
        if contacted:
            out.append(Handoff(workflow_id="c2", subjects=tuple(h["hostname"] for h in contacted),
                               record_ids=tuple(dict.fromkeys(i for h in contacted for i in h["contact_record_ids"])),
                               reason="the endpoint reached a rated network indicator: review its connections, DNS "
                                      "lookups and the process behind them"))
        carriers = [m for m in self.message_facts if m["quarantine"] and m["recipients"]]
        if carriers:
            out.append(Handoff(workflow_id="phishing",
                               subjects=tuple(sorted({r for m in carriers for r in m["recipients"]})),
                               record_ids=tuple(dict.fromkeys(i for m in carriers for i in m["message_record_ids"])),
                               reason="the mailbox received a delivered message carrying a rated indicator: review "
                                      "clicks, replies and the rest of the campaign"))
        accounts = [a for a in self.account_facts if a["signed_in"]]
        if accounts:
            out.append(Handoff(workflow_id="account-takeover", subjects=tuple(a["user"] for a in accounts),
                               record_ids=tuple(dict.fromkeys(i for a in accounts for i in a["sign_in_record_ids"])),
                               reason="the account signed in successfully from a rated indicator: review the account "
                                      "for takeover"))
        return out

    def links(self) -> list[CorrelationLink]:
        links: dict[str, CorrelationLink] = {}
        origin = self.view.origin
        for indicator in self.indicators:
            ioc = _entity(_TYPES[indicator.kind][1], indicator.value)
            if ioc is None:
                continue
            for record, kind, asset in indicator.hits:
                if kind is None:
                    continue
                other = _entity(kind, asset)
                if other is None or other == ioc:
                    continue
                link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=(ioc, other), record_ids=(record.record_id,),
                                       first_seen=record.observed_at, last_seen=record.observed_at,
                                       note=f"indicator hit: {indicator.value} named with {other.value}",
                                       origin=origin)
                links.setdefault(link.link_id, link)
        return [links[k] for k in sorted(links)]

    def as_dict(self) -> dict[str, Any]:
        return {
            "indicators": self.indicator_facts,
            "hosts": self.host_facts,
            "files": self.file_facts,
            "messages": self.message_facts,
            "accounts": self.account_facts,
        }


class ThreatIntelSweepHooks(WorkflowHooks):
    """Facts, indicator-hit links, considerations and hand-offs of the threat-intel-sweep workflow (pure)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _Sweep(view).links()

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Sweep(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Sweep(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Sweep(view).handoffs()


HOOKS = ThreatIntelSweepHooks()
