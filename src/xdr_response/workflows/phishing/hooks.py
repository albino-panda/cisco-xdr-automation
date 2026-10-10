"""Hooks of the phishing workflow: pure facts and one derived signal over the run's records.

Read zone (architecture 14.0.1, 14.3.3): the hooks get a :class:`RunView` (records, enrichment
reports, correlation) and nothing else. They hold no context and no adapter, never write, never build
a token or a package and never choose an approval level. Every fact they return carries the record
ids it was computed from, so the recommendation rules cite real investigation and enrichment
records only (the runner refuses unknown ids).

Facts (JSON, consumed by the rules in ``definition.py``):

``phishing_messages``
    Messages confirmed as phishing by the mail gateway's own verdict (MALICIOUS or SUSPICIOUS), by
    a carried indicator (URL, domain or attachment) whose aggregate verdict is MALICIOUS or
    SUSPICIOUS or that an endpoint detected, or by a framework ``campaign`` link to such a message.
``phishing_urls`` / ``phishing_domains`` / ``malicious_attachments``
    Indicators of the confirmed messages (and of the incident) rated MALICIOUS or SUSPICIOUS. A URL
    is listed only when no domain of its host is listed, so a URL is blocked on an otherwise
    legitimate host and a domain block covers the URLs of a malicious domain.
``clicks``
    Recipient clicks: framework ``email_to_click`` links of a confirmed message whose click record
    reaches a listed domain, the host of a listed URL, or a listed URL.
``compromised_users``
    Clicking recipients with a successful sign-in after the click, a risk detection after the
    click, or an at-risk identity; ``disable_justified`` when the identity provider confirmed the
    compromise, or a post-click sign-in comes with a high user risk or a HIGH / CRITICAL risk
    detection.
``compromised_endpoints``
    Endpoints with a MALICIOUS or SUSPICIOUS detection or process event that names a malicious
    attachment, or that happened on a clicking endpoint after the click.

The derived signal: a successful sign-in after a phishing click is an ``authentication_anomaly``
pattern attributed to the identity source of the sign-in and citing the sign-in and click records.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from xdr_response.atomics.correlation.models import LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnomalyRecord,
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
from xdr_response.models import Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Handoff, RunView, WorkflowHooks, failed_reads

__all__ = ["PhishingHooks", "HOOKS", "WORKFLOW_ID", "SUPPORTING", "DELIVERED_LOCATIONS"]

WORKFLOW_ID = "phishing"
ORIGIN = f"workflow:{WORKFLOW_ID}"

#: Verdicts that support a recommendation (the score decides whether it is proposed).
SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
#: Delivery locations where a copy can still be quarantined.
DELIVERED_LOCATIONS = frozenset({"inbox", "junk", "unknown"})
_HIGH_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})
_RISKY_STATES = frozenset({"at_risk", "confirmed_compromised"})
_PRODUCTS = ("secure_endpoint", "defender_endpoint")

#: Reads whose failure can hide a click or its recipient (the message, the click search, the endpoint's
#: users): when one FAILED, an account the incident names is assessed on its identity records instead of
#: being dropped (owner rule: a failed source never blocks what other evidence backs; 14.14.2).
CLICK_TIE_ATOMICS = ("investigate_email", "search_email_campaign", "search_domain_enterprise",
                     "investigate_endpoint", "enrich_domain", "enrich_url")

#: Derived signal: successful sign-in after a phishing click (a pattern, never a vendor verdict).
CLICK_SIGNIN_SEVERITY = 70
CLICK_SIGNIN_CONFIDENCE = 60


# ------------------------------------------------------------------ helpers --
def _domain(value: str | None) -> str:
    return (value or "").strip().lower().rstrip(".")


def _url_key(value: str | None) -> str:
    return (value or "").strip().lower()


def _host(url: str | None) -> str:
    text = (url or "").strip()
    if not text:
        return ""
    try:
        host = urlsplit(text if "//" in text else "//" + text).hostname
    except ValueError:
        return ""
    return _domain(host)


def _parents(domain: str) -> list[str]:
    """The domain and every parent with at least two labels (``a.b.example`` -> itself, ``b.example``)."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] if len(labels) > 1 else [domain]


def _under(domain: str, listed: Iterable[str]) -> str | None:
    """The listed domain ``domain`` equals or is a subdomain of (first in sorted order), if any."""
    for candidate in sorted(listed):
        if domain == candidate or domain.endswith("." + candidate):
            return candidate
    return None


def _user(value: str | None) -> str:
    return (value or "").strip().lower()


def _host_name(value: str | None) -> str:
    return (value or "").strip().upper()


def _record_time(record: AnyRecord) -> datetime | None:
    """When the recorded fact happened (falls back to ``observed_at``)."""
    at: datetime | None = None
    if isinstance(record, (ProcessEventRecord, SignInRecord)):
        at = record.timestamp
    elif isinstance(record, (NetworkConnectionRecord, DnsQueryRecord, DetectionRecord, AnomalyRecord)):
        at = record.first_seen or record.last_seen
    elif isinstance(record, EmailMessageRecord):
        at = record.received_at
    return at or record.observed_at


def _after(at: datetime | None, start: datetime | None) -> bool:
    """True when ``at`` is at or after ``start`` (an unknown click time accepts any known time)."""
    return at is not None and (start is None or at >= start)


def _ids(*groups: Iterable[str]) -> list[str]:
    """Distinct record ids, first-seen order."""
    return list(dict.fromkeys(rid for group in groups for rid in group if rid))


def _earliest(times: Iterable[datetime | None]) -> datetime | None:
    known = [t for t in times if t is not None]
    return min(known) if known else None


def _iso(at: datetime | None) -> str | None:
    return at.isoformat() if at is not None else None


# ----------------------------------------------------------------- the view --
class _Facts:
    """Everything the hooks compute for one run (private; built once per call)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        self.records: tuple[AnyRecord, ...] = view.index.records()
        self.reports = self._reports(view.results)
        self.messages = self._messages()
        self.incident = self._incident_observables()
        self.confirmed = self._confirmed_messages()
        self.domains = self._phishing_domains()
        self.urls = self._phishing_urls()
        self.hashes = self._malicious_hashes()
        self.clicks = self._clicks()
        self.tie_failed = failed_reads(view, CLICK_TIE_ATOMICS)
        self.users = self._compromised_users() + self._unverified_click_users()
        self.endpoints = self._compromised_endpoints()

    # ------------------------------------------------------------ inputs --
    @staticmethod
    def _reports(results: Sequence[Any]) -> dict[tuple[str, str], ObservableReport]:
        """Enrichment reports by ``(observable type, normalized key)``."""
        out: dict[tuple[str, str], ObservableReport] = {}
        for result in results:
            if isinstance(result, ObservableReport):
                key = _url_key(result.value) if result.type is ObservableType.URL else _domain(result.value)
                out.setdefault((result.type.value, key), result)
        return out

    def _messages(self) -> list[EmailMessageRecord]:
        """Email messages, one per message id (first record wins), in index order."""
        seen: dict[str, EmailMessageRecord] = {}
        for record in self.records:
            if isinstance(record, EmailMessageRecord):
                seen.setdefault(record.message_id.strip().lower(), record)
        return list(seen.values())

    def _incident_observables(self) -> dict[ObservableType, list[str]]:
        out: dict[ObservableType, list[str]] = {}
        for observable in self.view.incident.observables:
            out.setdefault(observable.type, []).append(observable.value)
        return out

    def report(self, kind: str, key: str) -> ObservableReport | None:
        return self.reports.get((kind, key))

    def supporting_ids(self, kind: str, key: str) -> list[str]:
        """Ids of the MALICIOUS / SUSPICIOUS enrichment answers about one indicator ([] when not rated so)."""
        report = self.report(kind, key)
        if report is None or report.verdict not in SUPPORTING:
            return []
        return [r.record_id for r in report.records if r.verdict in SUPPORTING]

    def verdict(self, kind: str, key: str) -> Verdict:
        report = self.report(kind, key)
        return report.verdict if report is not None else Verdict.UNKNOWN

    # ---------------------------------------------------------- messages --
    @staticmethod
    def message_hosts(message: EmailMessageRecord) -> list[str]:
        hosts = [_host(u) for u in message.urls] + [_domain(d) for d in message.domains]
        return list(dict.fromkeys(h for h in hosts if h))

    def _detected_hash_ids(self, sha: str) -> list[str]:
        """Endpoint records that rate ``sha`` MALICIOUS or SUSPICIOUS (detections, events, prevalence)."""
        return [r.record_id for r in self.records
                if isinstance(r, (DetectionRecord, ProcessEventRecord, HashPrevalenceRecord))
                and (r.sha256 or "").lower() == sha and r.verdict in SUPPORTING]

    def _indicator_basis(self, message: EmailMessageRecord) -> list[str]:
        ids: list[str] = []
        for url in message.urls:
            ids += self.supporting_ids("url", _url_key(url))
        for host in self.message_hosts(message):
            for parent in _parents(host):
                ids += self.supporting_ids("domain", parent)
        for sha in message.attachment_hashes:
            ids += self.supporting_ids("sha256", sha.lower()) + self._detected_hash_ids(sha.lower())
        return _ids(ids)

    def _confirmed_messages(self) -> dict[str, list[str]]:
        """``{message record id: basis record ids}`` of every confirmed phishing message."""
        confirmed: dict[str, list[str]] = {}
        gateway = {m.record_id for m in self.messages if m.verdict in SUPPORTING}
        for message in self.messages:
            basis = self._indicator_basis(message)
            if message.record_id in gateway or basis:
                confirmed[message.record_id] = _ids([message.record_id], basis)
        message_ids = {m.record_id for m in self.messages}
        correlation = self.view.correlation
        changed = True
        while changed and correlation is not None:  # a campaign link spreads confirmation to its siblings
            changed = False
            for link in correlation.links:
                if link.kind is not LinkKind.CAMPAIGN:
                    continue
                known = [rid for rid in link.record_ids if rid in confirmed]
                if not known:
                    continue
                # cite up to two siblings the gateway itself rated (their verdict is the campaign's evidence)
                rated = [rid for rid in link.record_ids if rid in gateway] or known
                for rid in link.record_ids:
                    if rid not in message_ids:
                        continue
                    siblings = [s for s in rated if s != rid][:2]
                    merged = _ids(confirmed.get(rid, [rid]), siblings)
                    if merged != confirmed.get(rid):
                        confirmed[rid] = merged
                        changed = True
        return confirmed

    def confirmed_messages(self) -> list[EmailMessageRecord]:
        return [m for m in self.messages if m.record_id in self.confirmed]

    def carriers(self, predicate: Any) -> list[str]:
        """Record ids of confirmed messages for which ``predicate(message)`` holds."""
        return [m.record_id for m in self.confirmed_messages() if predicate(m)]

    # -------------------------------------------------------- indicators --
    def _click_records(self) -> list[NetworkConnectionRecord | DnsQueryRecord]:
        return [r for r in self.records if isinstance(r, (NetworkConnectionRecord, DnsQueryRecord))]

    @staticmethod
    def click_domain(record: NetworkConnectionRecord | DnsQueryRecord) -> str:
        if isinstance(record, NetworkConnectionRecord):
            return _domain(record.domain) or _host(record.url)
        return _domain(record.domain)

    def _phishing_domains(self) -> dict[str, dict[str, Any]]:
        candidates: list[str] = []
        for message in self.confirmed_messages():
            candidates += self.message_hosts(message) + [_domain(message.sender_domain)]
        candidates += [_domain(d) for d in self.incident.get(ObservableType.DOMAIN, [])]
        candidates += [_host(u) for u in self.incident.get(ObservableType.URL, [])]
        out: dict[str, dict[str, Any]] = {}
        for domain in dict.fromkeys(c for c in candidates if c):
            supporting = self.supporting_ids("domain", domain)
            if not supporting:
                continue
            carriers = self.carriers(lambda m, d=domain: d in [_domain(m.sender_domain), *(
                p for h in self.message_hosts(m) for p in _parents(h))])
            clicks = [r.record_id for r in self._click_records() if _under(self.click_domain(r), [domain])]
            out[domain] = {"domain": domain, "verdict": self.verdict("domain", domain).value,
                           "record_ids": _ids(supporting, carriers, clicks),
                           "reason": f"domain {domain} rated {self.verdict('domain', domain).value} and carried by "
                                     f"{len(carriers)} phishing message(s); {len(clicks)} click record(s)"}
        return out

    def _phishing_urls(self) -> dict[str, dict[str, Any]]:
        candidates: list[str] = []
        for message in self.confirmed_messages():
            candidates += list(message.urls)
        candidates += list(self.incident.get(ObservableType.URL, []))
        out: dict[str, dict[str, Any]] = {}
        for url in dict.fromkeys(c.strip() for c in candidates if c and c.strip()):
            key = _url_key(url)
            if key in out:
                continue
            supporting = self.supporting_ids("url", key)
            host = _host(url)
            if not supporting or not host or _under(host, self.domains):
                continue  # not rated, or a listed domain block already covers it
            carriers = self.carriers(lambda m, k=key: k in [_url_key(u) for u in m.urls])
            clicks = [r.record_id for r in self._click_records()
                      if isinstance(r, NetworkConnectionRecord) and _url_key(r.url) == key]
            out[key] = {"url": url, "domain": host, "verdict": self.verdict("url", key).value,
                        "record_ids": _ids(supporting, carriers, clicks),
                        "reason": f"URL rated {self.verdict('url', key).value} on host {host}, which is not "
                                  f"itself rated malicious; carried by {len(carriers)} phishing message(s)"}
        return out

    def _malicious_hashes(self) -> dict[str, dict[str, Any]]:
        candidates: list[str] = []
        for message in self.confirmed_messages():
            candidates += [h.lower() for h in message.attachment_hashes]
        candidates += [h.lower() for h in self.incident.get(ObservableType.SHA256, [])]
        out: dict[str, dict[str, Any]] = {}
        for sha in dict.fromkeys(c for c in candidates if len(c) == 64):
            supporting = self.supporting_ids("sha256", sha)
            detected = self._detected_hash_ids(sha)
            if not supporting and not detected:
                continue
            carriers = self.carriers(lambda m, s=sha: s in [h.lower() for h in m.attachment_hashes])
            out[sha] = {"sha256": sha, "verdict": self.verdict("sha256", sha).value,
                        "record_ids": _ids(supporting, detected, carriers),
                        "reason": f"attachment rated {self.verdict('sha256', sha).value}, detected by "
                                  f"{len(detected)} endpoint record(s); carried by {len(carriers)} phishing "
                                  "message(s)"}
        return out

    # ------------------------------------------------------------ clicks --
    def _phishing_click(self, record: NetworkConnectionRecord | DnsQueryRecord) -> bool:
        domain = self.click_domain(record)
        if domain and (_under(domain, self.domains) or domain in {u["domain"] for u in self.urls.values()}):
            return True
        return isinstance(record, NetworkConnectionRecord) and _url_key(record.url) in self.urls

    def _click_rating_ids(self, record: NetworkConnectionRecord | DnsQueryRecord) -> list[str]:
        """The rating records of the listed domain or URL a click reached (why it is a phishing click)."""
        domain = self.click_domain(record)
        ids: list[str] = []
        listed = _under(domain, self.domains) if domain else None
        if listed:
            ids += self.supporting_ids("domain", listed)
        for key, url in self.urls.items():
            if (isinstance(record, NetworkConnectionRecord) and _url_key(record.url) == key) or url["domain"] == domain:
                ids += self.supporting_ids("url", key)
        return _ids(ids)

    def _endpoint_users(self, hostname: str, recipients: set[str]) -> list[tuple[str, str]]:
        """``(user, endpoint record id)`` for recipients an endpoint record names on ``hostname``."""
        pairs: list[tuple[str, str]] = []
        for record in self.records:
            if isinstance(record, EndpointRecord) and _host_name(record.hostname) == hostname:
                pairs += [(_user(u), record.record_id) for u in record.users if _user(u) in recipients]
        return pairs

    def _clicks(self) -> list[dict[str, Any]]:
        correlation = self.view.correlation
        if correlation is None:
            return []
        by_id = {r.record_id: r for r in self.records}
        clicks: dict[tuple[str, str, str], dict[str, Any]] = {}
        for link in correlation.links:
            if link.kind is not LinkKind.EMAIL_TO_CLICK:
                continue
            messages = [by_id[rid] for rid in link.record_ids if rid in self.confirmed
                        and isinstance(by_id.get(rid), EmailMessageRecord)]
            if not messages:
                continue
            message = messages[0]
            recipients = {_user(r) for r in message.recipients}
            for rid in link.record_ids:
                record = by_id.get(rid)
                if not isinstance(record, (NetworkConnectionRecord, DnsQueryRecord)):
                    continue
                if not self._phishing_click(record):
                    continue
                endpoint = _host_name(record.endpoint)
                actors: list[tuple[str, list[str]]] = []
                if isinstance(record, NetworkConnectionRecord) and _user(record.user) in recipients:
                    actors.append((_user(record.user), []))
                if endpoint:
                    actors += [(user, [endpoint_record]) for user, endpoint_record in
                               self._endpoint_users(endpoint, recipients)]
                rating = self._click_rating_ids(record)
                for user, extra in actors:
                    key = (user, endpoint, record.record_id)
                    entry = clicks.setdefault(key, {
                        "user": user, "endpoint": endpoint or None, "domain": self.click_domain(record),
                        "message_id": message.message_id, "at": _iso(_record_time(record)),
                        "record_ids": _ids([message.record_id, record.record_id])})
                    # the click counts because the indicator it reached is rated: cite that rating too
                    entry["record_ids"] = _ids(entry["record_ids"], extra, rating)
        return [clicks[k] for k in sorted(clicks)]

    def click_time(self, *, user: str | None = None, endpoint: str | None = None) -> datetime | None:
        by_id = {r.record_id: r for r in self.records}
        times = [_record_time(by_id[c["record_ids"][1]]) for c in self.clicks
                 if (user is None or c["user"] == user) and (endpoint is None or c["endpoint"] == endpoint)]
        return _earliest(times)

    # ------------------------------------------------------------- users --
    def _compromised_users(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for user in dict.fromkeys(c["user"] for c in self.clicks):
            click_ids = _ids(*(c["record_ids"] for c in self.clicks if c["user"] == user))
            clicked_at = self.click_time(user=user)
            signins = [r for r in self.records if isinstance(r, SignInRecord) and _user(r.user) == user
                       and r.result == "success" and _after(r.timestamp, clicked_at)]
            anomalies = [r for r in self.records if isinstance(r, AnomalyRecord) and _user(r.user) == user
                         and (_record_time(r) is None or _after(_record_time(r), clicked_at))]
            profiles = [r for r in self.records if isinstance(r, UserProfileRecord) and _user(r.user) == user]
            risky = [p for p in profiles if p.risk_level in ("medium", "high") or p.risk_state in _RISKY_STATES]
            if not (signins or anomalies or risky):
                continue
            confirmed = [p for p in profiles if p.risk_state == "confirmed_compromised"]
            high_profile = [p for p in profiles if p.risk_level == "high"]
            high_anomalies = [a for a in anomalies if a.severity in _HIGH_SEVERITIES]
            justified = bool(confirmed) or (bool(signins) and bool(high_profile or high_anomalies))
            revoke_ids = _ids(click_ids, [r.record_id for r in (*signins, *anomalies, *risky)])
            disable_ids = _ids(revoke_ids, [r.record_id for r in (*confirmed, *high_profile)])
            groups = sorted({g for p in profiles for g in p.groups})
            roles = sorted({r for p in profiles for r in p.roles})
            out.append({
                "user": user, "clicked_at": _iso(clicked_at), "groups": groups, "roles": roles,
                "privileged": any(p.privileged for p in profiles),
                "signins_after_click": len(signins), "risk_detections": len(anomalies),
                "record_ids": revoke_ids, "disable_justified": justified, "disable_record_ids": disable_ids,
                "reason": f"{user} clicked a phishing link ({len(click_ids)} click record(s)); "
                          f"{len(signins)} successful sign-in(s) and {len(anomalies)} risk detection(s) after "
                          "the click; hand-off: run account-takeover for this account",
                "disable_reason": (f"{user}: compromise confirmed by the identity provider" if confirmed else
                                   f"{user}: successful sign-in after the click with high user risk or a HIGH "
                                   "risk detection") + "; hand-off: run account-takeover for this account",
            })
        return out

    def _unverified_click_users(self) -> list[dict[str, Any]]:
        """Accounts the incident names whose click could not be checked because a read FAILED.

        The message, the click search or the endpoint's users came back from a failed source, so no
        ``email_to_click`` link ties the account to a click. An account the incident itself names (and
        that is not already a clicking recipient) is then assessed on what survives: its sign-ins, risk
        detections and identity risk, the messages that name it as a recipient and any click record on
        a listed indicator. The reason says the click is unverified and which read failed.
        """
        if not self.tie_failed:
            return []
        known = {c["user"] for c in self.clicks}
        named = [*self.view.incident.users, *self.incident.get(ObservableType.USER, []),
                 *self.incident.get(ObservableType.EMAIL_ADDRESS, [])]
        failed = "; ".join(f"{', '.join(names)} failed for {subject}" for subject, names in self.tie_failed.items())
        out: list[dict[str, Any]] = []
        for user in dict.fromkeys(_user(u) for u in named):
            if not user or "@" not in user or user in known:
                continue
            profiles = [r for r in self.records if isinstance(r, UserProfileRecord) and _user(r.user) == user]
            signins = [r for r in self.records if isinstance(r, SignInRecord) and _user(r.user) == user
                       and r.result == "success"]
            anomalies = [r for r in self.records if isinstance(r, AnomalyRecord) and _user(r.user) == user]
            risky = [p for p in profiles if p.risk_level in ("medium", "high") or p.risk_state in _RISKY_STATES]
            if not (anomalies or risky):
                continue  # a sign-in alone, without a click, is not a compromise indicator
            messages = [m.record_id for m in self.messages if user in {_user(r) for r in m.recipients}]
            clicks = [r.record_id for r in self._click_records() if self._phishing_click(r)]
            confirmed = [p for p in profiles if p.risk_state == "confirmed_compromised"]
            high_profile = [p for p in profiles if p.risk_level == "high"]
            high_anomalies = [a for a in anomalies if a.severity in _HIGH_SEVERITIES]
            justified = bool(confirmed) or (bool(signins) and bool(high_profile or high_anomalies))
            revoke_ids = _ids([r.record_id for r in (*anomalies, *risky, *signins)], messages, clicks)
            disable_ids = _ids(revoke_ids, [r.record_id for r in (*confirmed, *high_profile)])
            tie = (f"the incident names {user}, but its click could not be checked ({failed}); "
                   f"{len(messages)} message record(s) name it as a recipient, {len(clicks)} click record(s) reach a "
                   "listed indicator")
            out.append({
                "user": user, "clicked_at": None, "groups": sorted({g for p in profiles for g in p.groups}),
                "roles": sorted({r for p in profiles for r in p.roles}),
                "privileged": any(p.privileged for p in profiles),
                "signins_after_click": len(signins), "risk_detections": len(anomalies),
                "record_ids": revoke_ids, "disable_justified": justified, "disable_record_ids": disable_ids,
                "click_unverified": True,
                "reason": f"{tie}; {len(signins)} successful sign-in(s), {len(anomalies)} risk detection(s) and "
                          f"{len(risky)} at-risk identity record(s); hand-off: run account-takeover for this account",
                "disable_reason": (f"{user}: compromise confirmed by the identity provider" if confirmed else
                                   f"{user}: successful sign-in with high user risk or a HIGH risk detection")
                                  + f" ({tie}); hand-off: run account-takeover for this account",
            })
        return out

    # --------------------------------------------------------- endpoints --
    def _compromised_endpoints(self) -> list[dict[str, Any]]:
        clicked = {c["endpoint"] for c in self.clicks if c["endpoint"]}
        hits: dict[str, list[AnyRecord]] = {}
        for record in self.records:
            if not isinstance(record, (DetectionRecord, ProcessEventRecord)) or record.verdict not in SUPPORTING:
                continue
            endpoint = _host_name(record.endpoint)
            if not endpoint:
                continue
            attachment = (record.sha256 or "").lower() in self.hashes
            post_click = endpoint in clicked and _after(_record_time(record), self.click_time(endpoint=endpoint))
            if attachment or post_click:
                hits.setdefault(endpoint, []).append(record)
        out: list[dict[str, Any]] = []
        for endpoint in sorted(hits):
            endpoints = [r for r in self.records
                         if isinstance(r, EndpointRecord) and _host_name(r.hostname) == endpoint]
            sources = [r.integration for r in (*endpoints, *hits[endpoint])]
            product = next((p for p in _PRODUCTS if p in sources), _PRODUCTS[0])
            click_ids = _ids(*(c["record_ids"] for c in self.clicks if c["endpoint"] == endpoint))
            carriers = [rid for sha in {(r.sha256 or "").lower() for r in hits[endpoint]} if sha in self.hashes
                        for rid in self.hashes[sha]["record_ids"]]
            ips = [ip for r in endpoints for ip in r.ip_addresses]
            out.append({
                "hostname": endpoint, "product": product,
                "groups": sorted({g for r in endpoints for g in r.groups}),
                "tags": sorted({t for r in endpoints for t in r.tags}), "ip": ips[0] if ips else None,
                "record_ids": _ids([r.record_id for r in hits[endpoint]], click_ids, carriers,
                                   [r.record_id for r in endpoints]),
                "reason": f"{len(hits[endpoint])} malicious or suspicious endpoint record(s) on {endpoint} after a "
                          "phishing click or naming a malicious attachment",
            })
        return out

    # ------------------------------------------------------------ output --
    def as_facts(self) -> dict[str, Any]:
        messages = []
        for message in self.confirmed_messages():
            recipients = sorted({_user(r) for r in message.recipients})
            messages.append({
                "message_id": message.message_id, "sender": message.sender, "recipients": recipients,
                "recipient": recipients[0] if len(recipients) == 1 else "",
                "delivery_location": message.delivery_location,
                "delivered": message.delivery_location in DELIVERED_LOCATIONS,
                "verdict": message.verdict.value, "record_ids": self.confirmed[message.record_id],
                "reason": f"message {message.message_id} from {message.sender or 'unknown sender'} to "
                          f"{message.recipient_count or len(recipients)} recipient(s), {message.delivery_location}; "
                          f"phishing confirmed by {len(self.confirmed[message.record_id])} record(s)",
            })
        return {
            "phishing_messages": messages,
            "phishing_urls": list(self.urls.values()),
            "phishing_domains": list(self.domains.values()),
            "malicious_attachments": list(self.hashes.values()),
            "clicks": self.clicks,
            "compromised_users": self.users,
            "compromised_endpoints": self.endpoints,
            "account_takeover_handoff": [u["user"] for u in self.users],
        }

    def click_signin_signals(self) -> list[ScoringSignal]:
        signals: list[ScoringSignal] = []
        for user in self.users:
            click_ids = _ids(*(c["record_ids"] for c in self.clicks if c["user"] == user["user"]))
            clicked_at = self.click_time(user=user["user"])
            signins = [r for r in self.records if isinstance(r, SignInRecord) and _user(r.user) == user["user"]
                       and r.result == "success" and _after(r.timestamp, clicked_at)]
            for integration in dict.fromkeys(s.integration for s in signins):
                own = [s.record_id for s in signins if s.integration == integration]
                signals.append(ScoringSignal(
                    category=SignalCategory.AUTHENTICATION_ANOMALY, integration=integration,
                    observable=Observable(type=ObservableType.USER, value=user["user"]), verdict=Verdict.SUSPICIOUS,
                    severity=CLICK_SIGNIN_SEVERITY, confidence=CLICK_SIGNIN_CONFIDENCE,
                    record_ids=tuple(_ids(own, click_ids)), origin=ORIGIN,
                    note="successful sign-in after a phishing click"))
        return signals


class PhishingHooks(WorkflowHooks):
    """Pure facts and the click-then-sign-in signal (no context, no adapters, no writes)."""

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return _Facts(view).click_signin_signals()

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_facts()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        """A recipient who signed in or was flagged after clicking: account-takeover reviews the account."""
        return [Handoff(workflow_id="account-takeover", subjects=(user["user"],),
                        reason="signed in or was flagged by the identity provider after clicking a phishing link; "
                               "review the account's activity after the click",
                        record_ids=tuple(user["record_ids"])) for user in _Facts(view).users]


HOOKS = PhishingHooks()

