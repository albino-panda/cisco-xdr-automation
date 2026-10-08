"""Framework correlation rules (architecture section 14.1.5).

Pure functions over atomic results: no adapter calls, no clock, deterministic output order. Every
link cites the records it was computed from and every cited id is in the run's ``RecordIndex``.

Entities a record "mentions" (``_record_entities``) are the assets and indicators it is about: an
endpoint's own IP and MAC addresses, a DNS client address and a connection's local address are
attributes of the asset, not mentions, so they never inflate the indicator scope.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from xdr_response.atomics.correlation.models import (
    FRAMEWORK_ORIGIN,
    CorrelationLink,
    CorrelationResult,
    EntityRef,
    LinkKind,
    TimelineEntry,
)
from xdr_response.atomics.evidence import EvidenceError, RecordIndex, evidence_summary
from xdr_response.atomics.records import (
    AnomalyRecord,
    CloudAppRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    GenericRecord,
    HashPrevalenceRecord,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RecordBase,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models.canonical import normalize_target
from xdr_response.models.enums import ObservableType, TargetKind
from xdr_response.models.observable import Observable

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.context import AtomicContext
    from xdr_response.atomics.records import AtomicResult

__all__ = ["correlate", "build_timeline", "DEFAULT_WINDOW", "FRAMEWORK_LINK_KINDS"]

DEFAULT_WINDOW = timedelta(minutes=60)
FRAMEWORK_LINK_KINDS: tuple[LinkKind, ...] = tuple(k for k in LinkKind if k is not LinkKind.WORKFLOW)

_OBSERVABLE_KINDS: dict[ObservableType, TargetKind] = {
    ObservableType.IP: TargetKind.IP, ObservableType.IPV6: TargetKind.IP,
    ObservableType.DOMAIN: TargetKind.DOMAIN, ObservableType.URL: TargetKind.URL,
    ObservableType.SHA256: TargetKind.HASH, ObservableType.SHA1: TargetKind.HASH, ObservableType.MD5: TargetKind.HASH,
    ObservableType.EMAIL_ADDRESS: TargetKind.EMAIL_ADDRESS, ObservableType.USER: TargetKind.USER,
    ObservableType.HOSTNAME: TargetKind.ENDPOINT, ObservableType.EMAIL_MESSAGE_ID: TargetKind.EMAIL_MESSAGE,
}
_ASSET_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.USER})
_INDICATOR_LINKS: dict[TargetKind, LinkKind] = {
    TargetKind.HASH: LinkKind.SAME_HASH, TargetKind.DOMAIN: LinkKind.SAME_DOMAIN,
    TargetKind.IP: LinkKind.SAME_IP, TargetKind.URL: LinkKind.SAME_URL,
}


# ------------------------------------------------------------------------------------------ entities


def _ref(kind: TargetKind, value: str | None) -> EntityRef | None:
    """An entity for a record field, or ``None`` when the field is empty or not normalizable."""
    if value is None or not str(value).strip():
        return None
    try:
        return EntityRef(kind=kind, value=normalize_target(kind, str(value)))
    except ValueError:
        return None


def _refs(pairs: Iterable[tuple[TargetKind, str | None]]) -> tuple[EntityRef, ...]:
    """Unique entities, in field order."""
    out: dict[str, EntityRef] = {}
    for kind, value in pairs:
        ref = _ref(kind, value)
        if ref is not None:
            out.setdefault(ref.key(), ref)
    return tuple(out.values())


def _observable_entity(observable: Observable) -> EntityRef | None:
    kind = _OBSERVABLE_KINDS.get(observable.type)
    return _ref(kind, observable.value) if kind is not None else None


def _url_host(url: str | None) -> str | None:
    """Host of a URL (``None`` when the URL has none); accepts URLs without a scheme."""
    if not url:
        return None
    text = url.strip()
    host = urlsplit(text if "//" in text else "//" + text).hostname
    return host or None


def _email_entities(r: EmailMessageRecord) -> list[tuple[TargetKind, str | None]]:
    pairs: list[tuple[TargetKind, str | None]] = [(TargetKind.EMAIL_MESSAGE, r.message_id),
                                                 (TargetKind.EMAIL_ADDRESS, r.sender)]
    pairs += [(TargetKind.USER, v) for v in r.recipients]
    pairs += [(TargetKind.URL, v) for v in r.urls]
    pairs += [(TargetKind.DOMAIN, v) for v in r.domains]
    pairs += [(TargetKind.HASH, v) for v in r.attachment_hashes]
    return pairs


def _record_pairs(r: RecordBase) -> list[tuple[TargetKind, str | None]]:  # noqa: C901 - one branch per kind
    """``(kind, raw value)`` pairs a record mentions, per record kind."""
    ep, us, ha, dom, ip = TargetKind.ENDPOINT, TargetKind.USER, TargetKind.HASH, TargetKind.DOMAIN, TargetKind.IP
    if isinstance(r, EndpointRecord):
        return [(ep, r.hostname)] + [(us, u) for u in r.users]
    if isinstance(r, DetectionRecord):
        return [(ep, r.endpoint), (us, r.user), (ha, r.sha256)]
    if isinstance(r, ProcessEventRecord):
        return [(ep, r.endpoint), (us, r.user), (ha, r.sha256), (ha, r.parent_sha256), (ip, r.remote_ip),
                (dom, r.domain)]
    if isinstance(r, NetworkConnectionRecord):
        return [(ep, r.endpoint), (us, r.user), (ip, r.remote_ip), (dom, r.domain), (TargetKind.URL, r.url),
                (ha, r.sha256)]
    if isinstance(r, DnsQueryRecord):
        return [(ep, r.endpoint), (dom, r.domain)]
    if isinstance(r, HashPrevalenceRecord):
        return [(ha, r.sha256)] + [(ep, e) for e in r.endpoints]
    if isinstance(r, PersistenceItemRecord):
        return [(ep, r.endpoint), (us, r.user), (ha, r.sha256)]
    if isinstance(r, UserProfileRecord):
        return [(us, r.user)]
    if isinstance(r, (SignInRecord, MfaEventRecord)):
        return [(us, r.user), (ip, r.ip)]
    if isinstance(r, AnomalyRecord):
        return [(us, r.user), (ep, r.endpoint), (ip, r.ip)]
    if isinstance(r, MailboxRuleRecord):
        addresses = r.forward_to + r.redirect_to + r.forward_as_attachment_to
        return [(us, r.mailbox)] + [(TargetKind.EMAIL_ADDRESS, a) for a in addresses]
    if isinstance(r, RoleChangeRecord):
        return [(us, r.user)]
    if isinstance(r, EmailMessageRecord):
        return _email_entities(r)
    if isinstance(r, CloudAppRecord):
        return [(TargetKind.APPLICATION, r.app_id), (us, r.consented_by)]
    return []


def _record_entities(record: RecordBase) -> tuple[EntityRef, ...]:
    """Every entity a record mentions (enrichment and generic records mention their subject)."""
    if isinstance(record, (EnrichmentRecord, GenericRecord)):
        ref = _observable_entity(record.subject)
        return (ref,) if ref is not None else ()
    return _refs(_record_pairs(record))


@dataclass(frozen=True)
class _Mentions:
    """Which entities each record mentions, and which records mention each entity."""

    by_record: dict[str, tuple[EntityRef, ...]]
    by_entity: dict[str, list[str]]
    entities: dict[str, EntityRef]

    @classmethod
    def build(cls, index: RecordIndex) -> "_Mentions":
        by_record: dict[str, tuple[EntityRef, ...]] = {}
        by_entity: dict[str, list[str]] = defaultdict(list)
        entities: dict[str, EntityRef] = {}
        for record in index.records():
            refs = _record_entities(record)
            by_record[record.record_id] = refs
            for ref in refs:
                entities.setdefault(ref.key(), ref)
                by_entity[ref.key()].append(record.record_id)
        return cls(by_record, dict(by_entity), entities)

    def of_kind(self, record_id: str, kinds: Collection[TargetKind]) -> tuple[EntityRef, ...]:
        return tuple(e for e in self.by_record.get(record_id, ()) if e.kind in kinds)


# ------------------------------------------------------------------------------------------ timeline


def _record_time(record: RecordBase) -> datetime | None:  # noqa: C901 - one branch per kind
    """The time the recorded fact happened (falls back to ``observed_at``)."""
    t: datetime | None = None
    if isinstance(record, (ProcessEventRecord, SignInRecord, MfaEventRecord, RoleChangeRecord)):
        t = record.timestamp
    elif isinstance(record, (NetworkConnectionRecord, DnsQueryRecord, DetectionRecord, AnomalyRecord,
                             HashPrevalenceRecord)):
        t = record.first_seen or record.last_seen
    elif isinstance(record, EmailMessageRecord):
        t = record.received_at
    elif isinstance(record, (PersistenceItemRecord, CloudAppRecord)):
        t = record.created_at
    elif isinstance(record, MailboxRuleRecord):
        t = record.created_at or record.modified_at
    return t or record.observed_at


def build_timeline(results: Sequence[AtomicResult]) -> tuple[TimelineEntry, ...]:
    """Every record with a time, de-duplicated by id, sorted by ``(at, record_id)``."""
    return _timeline(RecordIndex(results))


def _timeline(index: RecordIndex) -> tuple[TimelineEntry, ...]:
    entries = []
    for record in index.records():
        at = _record_time(record)
        if at is not None:
            entries.append(TimelineEntry(at=at, record_id=record.record_id, kind=record.kind,
                                         integration=record.integration, summary=evidence_summary(record)))
    return tuple(sorted(entries, key=lambda e: (e.at, e.record_id)))


# ------------------------------------------------------------------------------------------- helpers


def _span(index: RecordIndex, record_ids: Iterable[str]) -> tuple[datetime | None, datetime | None]:
    times = [t for t in (_record_time(index.get(rid)) for rid in record_ids) if t is not None]
    return (min(times), max(times)) if times else (None, None)


def _link(index: RecordIndex, kind: LinkKind, entities: Iterable[EntityRef], record_ids: Iterable[str],
          note: str) -> CorrelationLink | None:
    """A framework link, or ``None`` when fewer than two distinct entities remain."""
    unique = {e.key(): e for e in entities}
    ids = sorted(set(record_ids))
    if len(unique) < 2 or not ids:
        return None
    first, last = _span(index, ids)
    return CorrelationLink(kind=kind, entities=tuple(unique.values()), record_ids=tuple(ids),
                           first_seen=first, last_seen=last, note=note, origin=FRAMEWORK_ORIGIN)


def _within(start: datetime | None, at: datetime | None, window: timedelta) -> bool:
    return start is not None and at is not None and start <= at <= start + window


# -------------------------------------------------------------------------------------- shared-entity


def _indicator_links(index: RecordIndex, m: _Mentions) -> list[CorrelationLink | None]:
    """same_hash / same_domain / same_ip / same_url: an indicator seen with >= 2 endpoints or users."""
    links: list[CorrelationLink | None] = []
    for key in sorted(m.entities):
        indicator = m.entities[key]
        kind = _INDICATOR_LINKS.get(indicator.kind)
        if kind is None:
            continue
        cited = [rid for rid in m.by_entity[key] if m.of_kind(rid, _ASSET_KINDS)]
        assets = {a.key(): a for rid in cited for a in m.of_kind(rid, _ASSET_KINDS)}
        endpoints = sum(1 for a in assets.values() if a.kind is TargetKind.ENDPOINT)
        users = len(assets) - endpoints
        if endpoints >= 2 or users >= 2:
            note = (f"{indicator.kind.value.lower()} {indicator.value} seen with {endpoints} endpoint(s) "
                    f"and {users} user(s)")
            links.append(_link(index, kind, [indicator, *assets.values()], cited, note))
    return links


def _asset_links(index: RecordIndex, m: _Mentions) -> list[CorrelationLink | None]:
    """same_user (a user with >= 2 endpoints) and same_endpoint (an endpoint with >= 2 users)."""
    links: list[CorrelationLink | None] = []
    rules = ((TargetKind.USER, TargetKind.ENDPOINT, LinkKind.SAME_USER, "user", "endpoint"),
             (TargetKind.ENDPOINT, TargetKind.USER, LinkKind.SAME_ENDPOINT, "endpoint", "user"))
    for kind, other, link_kind, label, other_label in rules:
        for key in sorted(m.entities):
            entity = m.entities[key]
            if entity.kind is not kind:
                continue
            cited = [rid for rid in m.by_entity[key] if m.of_kind(rid, (other,))]
            others = {o.key(): o for rid in cited for o in m.of_kind(rid, (other,))}
            if len(others) >= 2:
                note = f"{label} {entity.value} seen with {len(others)} {other_label}s"
                links.append(_link(index, link_kind, [entity, *others.values()], cited, note))
    return links


# ------------------------------------------------------------------------------------ process lineage


def _process_key(event: ProcessEventRecord) -> str | None:
    if event.pid is not None:
        return f"pid:{event.pid}"
    return f"sha256:{event.sha256}" if event.sha256 else None


def _parent_key(event: ProcessEventRecord, pids: Collection[str], hashes: Collection[str]) -> str | None:
    if event.parent_pid is not None and f"pid:{event.parent_pid}" in pids:
        return f"pid:{event.parent_pid}"
    if event.parent_sha256 and f"sha256:{event.parent_sha256}" in hashes:
        return f"sha256:{event.parent_sha256}"
    return None


def _endpoint_lineage(index: RecordIndex, endpoint: str,
                      events: list[ProcessEventRecord]) -> list[CorrelationLink | None]:
    by_key: dict[str, list[str]] = defaultdict(list)
    for event in events:
        if event.pid is not None:
            by_key[f"pid:{event.pid}"].append(event.record_id)
        if event.sha256:
            by_key[f"sha256:{event.sha256}"].append(event.record_id)
    pids = {k for k in by_key if k.startswith("pid:")}
    hashes = {k for k in by_key if k.startswith("sha256:")}
    pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for event in events:
        child, parent = _process_key(event), _parent_key(event, pids, hashes)
        if child is None or parent is None or child == parent:
            continue
        pairs[(parent, child)].update([event.record_id, *by_key[parent]])
    links: list[CorrelationLink | None] = []
    host = _ref(TargetKind.ENDPOINT, endpoint)
    for (parent, child), ids in sorted(pairs.items()):
        entities = [host, _ref(TargetKind.PROCESS, f"{endpoint}/{parent.split(':', 1)[1]}"),
                    _ref(TargetKind.PROCESS, f"{endpoint}/{child.split(':', 1)[1]}")]
        note = f"on {endpoint} process {child} was started by process {parent}"
        links.append(_link(index, LinkKind.PROCESS_LINEAGE, [e for e in entities if e is not None], ids, note))
    return links


def _lineage_links(index: RecordIndex) -> list[CorrelationLink | None]:
    """process_lineage: events on one endpoint whose parent pid or hash is another event's pid or hash."""
    by_endpoint: dict[str, list[ProcessEventRecord]] = defaultdict(list)
    for record in index.records():
        if isinstance(record, ProcessEventRecord):
            by_endpoint[normalize_target(TargetKind.ENDPOINT, record.endpoint)].append(record)
    links: list[CorrelationLink | None] = []
    for endpoint in sorted(by_endpoint):
        links += _endpoint_lineage(index, endpoint, by_endpoint[endpoint])
    return links


# ------------------------------------------------------------------------------- sign-in to activity


def _activity_user_times(record: RecordBase) -> tuple[list[str], list[datetime]]:
    """Users an activity record belongs to and the times it happened (empty for other records)."""
    if isinstance(record, MailboxRuleRecord):
        return [record.mailbox], [t for t in (record.created_at, record.modified_at) if t is not None]
    if isinstance(record, RoleChangeRecord):
        users = [u for u in (record.user, record.actor) if u]
        return users, [t for t in (record.timestamp,) if t is not None]
    if isinstance(record, CloudAppRecord) and record.consent_type != "unknown" and record.consented_by:
        return [record.consented_by], [t for t in (record.created_at,) if t is not None]
    return [], []


def _activity_entities(record: RecordBase) -> list[EntityRef | None]:
    if isinstance(record, MailboxRuleRecord):
        addresses = record.forward_to + record.redirect_to + record.forward_as_attachment_to
        return [_ref(TargetKind.EMAIL_ADDRESS, a) for a in addresses]
    if isinstance(record, RoleChangeRecord):
        target = record.target
        return [_ref(TargetKind.USER, record.user), _ref(TargetKind.ROLE_ASSIGNMENT, target) if target else None]
    if isinstance(record, CloudAppRecord):
        return [_ref(TargetKind.APPLICATION, record.app_id)]
    return []


def _sign_in_links(index: RecordIndex, window: timedelta) -> list[CorrelationLink | None]:
    """sign_in_to_activity: a successful sign-in followed within the window by a mailbox rule,
    role change or cloud app consent for the same user."""
    sign_ins: dict[str, list[SignInRecord]] = defaultdict(list)
    for record in index.records():
        if isinstance(record, SignInRecord) and record.result == "success":
            sign_ins[normalize_target(TargetKind.USER, record.user)].append(record)
    links: list[CorrelationLink | None] = []
    for record in index.records():
        users, times = _activity_user_times(record)
        for user in sorted({normalize_target(TargetKind.USER, u) for u in users}):
            matched = [s for s in sign_ins.get(user, []) if any(_within(s.timestamp, t, window) for t in times)]
            if not matched:
                continue
            entities = [_ref(TargetKind.USER, user), *(_ref(TargetKind.IP, s.ip) for s in matched),
                        *_activity_entities(record)]
            note = (f"successful sign-in by {user} followed within {_minutes(window)} minutes by "
                    f"{record.kind.value.replace('_', ' ')}")
            links.append(_link(index, LinkKind.SIGN_IN_TO_ACTIVITY, [e for e in entities if e is not None],
                               [record.record_id, *(s.record_id for s in matched)], note))
    return links


def _minutes(window: timedelta) -> int:
    return int(window.total_seconds() // 60)


# ------------------------------------------------------------------------------------- email to click


def _message_domains(message: EmailMessageRecord) -> set[str]:
    hosts = {_url_host(u) for u in message.urls} | set(message.domains)
    return {normalize_target(TargetKind.DOMAIN, h) for h in hosts if h}


def _domain_match(candidate: str | None, domains: Collection[str]) -> str | None:
    """The message domain ``candidate`` equals or is a subdomain of, if any."""
    if not candidate:
        return None
    value = normalize_target(TargetKind.DOMAIN, candidate)
    for domain in sorted(domains):
        if value == domain or value.endswith("." + domain):
            return domain
    return None


def _click_domain(record: RecordBase) -> str | None:
    if isinstance(record, NetworkConnectionRecord):
        return record.domain or _url_host(record.url)
    if isinstance(record, DnsQueryRecord):
        return record.domain
    return None


def _clicker(record: RecordBase) -> list[EntityRef | None]:
    if isinstance(record, NetworkConnectionRecord):
        return [_ref(TargetKind.ENDPOINT, record.endpoint), _ref(TargetKind.USER, record.user)]
    if isinstance(record, DnsQueryRecord):
        return [_ref(TargetKind.ENDPOINT, record.endpoint)]
    return []


def _recipient_assets(message: EmailMessageRecord, m: _Mentions) -> set[str]:
    """Entity keys of the recipients and of every endpoint a record names together with a recipient."""
    users = [r for r in (_ref(TargetKind.USER, v) for v in message.recipients) if r is not None]
    keys = {u.key() for u in users}
    for user in users:
        for rid in m.by_entity.get(user.key(), []):
            keys.update(e.key() for e in m.of_kind(rid, (TargetKind.ENDPOINT,)))
    return keys


def _email_click_links(index: RecordIndex, m: _Mentions, window: timedelta) -> list[CorrelationLink | None]:
    """email_to_click: a message carrying domain D, then a connection or DNS query to D from a
    recipient's endpoint or user after ``received_at``, within the window."""
    clicks = [r for r in index.records() if isinstance(r, (NetworkConnectionRecord, DnsQueryRecord))]
    links: list[CorrelationLink | None] = []
    for message in (r for r in index.records() if isinstance(r, EmailMessageRecord)):
        domains, received = _message_domains(message), message.received_at or message.observed_at
        recipients = _recipient_assets(message, m)
        hits: dict[str, list[RecordBase]] = defaultdict(list)
        for click in clicks:
            domain = _domain_match(_click_domain(click), domains)
            who = [e for e in _clicker(click) if e is not None and e.key() in recipients]
            if domain and who and _within(received, _record_time(click), window):
                hits[domain].append(click)
        for domain in sorted(hits):
            entities = [_ref(TargetKind.EMAIL_MESSAGE, message.message_id), _ref(TargetKind.DOMAIN, domain)]
            entities += [e for c in hits[domain] for e in _clicker(c) if e is not None and e.key() in recipients]
            note = f"message {message.message_id} carried {domain}, contacted by a recipient within the window"
            links.append(_link(index, LinkKind.EMAIL_TO_CLICK, [e for e in entities if e is not None],
                               [message.record_id, *(c.record_id for c in hits[domain])], note))
    return links


# ------------------------------------------------------------------------------------------- campaign


def _campaign_groups(messages: list[EmailMessageRecord]) -> dict[tuple[str, str, str], list[EmailMessageRecord]]:
    groups: dict[tuple[str, str, str], list[EmailMessageRecord]] = defaultdict(list)
    for msg in messages:
        if msg.campaign_id:
            groups[("campaign_id", msg.campaign_id, "")].append(msg)
        sender = (msg.sender_domain or "").strip().lower().rstrip(".")
        if not sender:
            continue
        for url in sorted(set(msg.urls)):
            groups[("url", sender, url)].append(msg)
        for sha in sorted(set(msg.attachment_hashes)):
            groups[("hash", sender, sha)].append(msg)
    return groups


def _campaign_links(index: RecordIndex) -> list[CorrelationLink | None]:
    """campaign: >= 2 messages sharing a campaign_id, or a sender domain and a URL or attachment hash."""
    messages = [r for r in index.records() if isinstance(r, EmailMessageRecord)]
    links: list[CorrelationLink | None] = []
    for (basis, key, shared), group in sorted(_campaign_groups(messages).items()):
        refs = [_ref(TargetKind.EMAIL_MESSAGE, msg.message_id) for msg in group]
        if len({r.key() for r in refs if r is not None}) < 2:
            continue
        if basis == "campaign_id":
            extra, note = [], f"{len(group)} messages share campaign {key}"
        else:
            kind = TargetKind.URL if basis == "url" else TargetKind.HASH
            extra = [_ref(kind, shared)]
            note = f"{len(group)} messages from sender domain {key} share {basis} {shared}"
        entities = [e for e in [*refs, *extra] if e is not None]
        links.append(_link(index, LinkKind.CAMPAIGN, entities, [msg.record_id for msg in group], note))
    return links


# ------------------------------------------------------------------------------------------- clusters


def _clusters(entities: dict[str, EntityRef], links: Sequence[CorrelationLink]) -> tuple[tuple[EntityRef, ...], ...]:
    """Connected components of the link graph; an unlinked entity is a component of its own."""
    parent = {key: key for key in entities}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for link in links:
        keys = [e.key() for e in link.entities]
        for other in keys[1:]:
            a, b = find(keys[0]), find(other)
            if a != b:
                parent[max(a, b)] = min(a, b)
    groups: dict[str, list[EntityRef]] = defaultdict(list)
    for key, ref in entities.items():
        groups[find(key)].append(ref)
    clusters = [tuple(sorted(group, key=EntityRef.sort_key)) for group in groups.values()]
    return tuple(sorted(clusters, key=lambda c: [e.sort_key() for e in c]))


# ------------------------------------------------------------------------------------------ correlate


def _framework_links(index: RecordIndex, m: _Mentions, window: timedelta,
                     kinds: Collection[LinkKind]) -> list[CorrelationLink]:
    candidates: list[CorrelationLink | None] = []
    candidates += _indicator_links(index, m)
    candidates += _asset_links(index, m)
    candidates += _lineage_links(index)
    candidates += _sign_in_links(index, window)
    candidates += _email_click_links(index, m, window)
    candidates += _campaign_links(index)
    return [link for link in candidates if link is not None and link.kind in kinds]


def _check_extra(index: RecordIndex, extra_links: Sequence[CorrelationLink]) -> list[CorrelationLink]:
    for link in extra_links:
        if not isinstance(link, CorrelationLink):
            raise EvidenceError(f"extra links must be CorrelationLink objects, got {type(link).__name__}")
        index.require(link.record_ids)
    return list(extra_links)


def correlate(ctx: AtomicContext, results: Sequence[AtomicResult], *,
              extra_links: Sequence[CorrelationLink] = (), window: timedelta = DEFAULT_WINDOW,
              link_kinds: Collection[LinkKind] = FRAMEWORK_LINK_KINDS) -> CorrelationResult:
    """Entities, framework links (restricted to ``link_kinds``), ``extra_links``, clusters and timeline.

    ``window`` is ``CorrelationSpec.window_minutes``; ``extra_links`` (workflow-hook links) must cite
    records of ``results`` (:class:`EvidenceError` otherwise) and are never filtered by ``link_kinds``.
    """
    if window <= timedelta(0):
        raise ValueError("correlation window must be positive")
    index = RecordIndex(results)
    mentions = _Mentions.build(index)
    found = _framework_links(index, mentions, window, frozenset(link_kinds)) + _check_extra(index, extra_links)
    links = sorted({link.link_id: link for link in found}.values(), key=lambda link: link.link_id)
    entities = dict(mentions.entities)
    for link in links:
        for entity in link.entities:
            entities.setdefault(entity.key(), entity)
    return CorrelationResult(
        incident_id=ctx.incident.incident_id,
        entities=tuple(sorted(entities.values(), key=EntityRef.sort_key)),
        links=tuple(links),
        clusters=_clusters(entities, links),
        timeline=_timeline(index),
    )
