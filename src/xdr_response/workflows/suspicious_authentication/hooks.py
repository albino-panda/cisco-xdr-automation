"""Pure hooks of the suspicious-authentication workflow (architecture 14.3.3).

The hooks read the run's records (a :class:`RunView`: no context, no adapters) and decide, per
investigated account, whether its recent successful sign-ins look like someone else:

* the **recent** sign-ins are the account's successful sign-ins in the :data:`RECENT_HOURS` before the
  incident (and any sign-in from an IP the incident names); older successful sign-ins are the
  **baseline**;
* each recent sign-in is checked for **indicators**, grouped in families with points (a family counts
  once, with its strongest finding): ``flagged_ip`` (source rated malicious 2, suspicious 1),
  ``anonymizer`` (Tor, proxy or anonymous-IP detection 2, VPN category 1), ``travel`` (two countries
  within :data:`TRAVEL_WINDOW_MINUTES` 2), ``geography`` (a country the baseline never shows 1),
  ``device`` (new, unregistered or non-compliant device 1), ``time`` (an hour at least
  :data:`HOUR_GAP` hours from every baseline hour 1); account-level findings add ``identity_risk``
  (high or confirmed risk 2, medium sign-in risk 1), ``vendor`` (other vendor risk detections) and
  ``exposure`` (breach data or a leaked-credentials detection, 1 and never on its own);
* an account is **likely compromised** when it has a recent successful sign-in, at least
  :data:`INDICATOR_THRESHOLD` points, and at least :data:`SIGN_IN_POINTS_MIN` of them from the sign-in
  itself. Sign-ins from a non-public address or a shared egress (other accounts sign in from it, or
  internal endpoints reach it, and no source flags it) never count as unusual geography, travel or
  time: a corporate VPN exit is not a new country.

From that the hooks compute ``facts`` for the rules (revoke, disable, block), ``derive_signals``
(authentication-anomaly signals that cite the sign-in records), ``correlate`` (account to source-IP
links), ``considered`` (accounts and IPs examined and deliberately not acted on, manual password
resets) and ``handoffs`` (likely compromised accounts to account-takeover).

Nothing here calls a vendor, writes anything, chooses an approval level or invents a fact: every
account, IP and reason comes from a record, and every record id cited is an id of the run (the runner
checks it again). The hooks only *recommend*; a human approves.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    PRIVILEGED_ROLE_NAMES,
    AnomalyRecord,
    CloudAppRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    MailboxRuleRecord,
    NetworkConnectionRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.config.policy import non_public_network
from xdr_response.models import Observable, ObservableType, Severity, TargetKind, Verdict
from xdr_response.models.canonical import normalize_target
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = [
    "SuspiciousAuthenticationHooks",
    "HOOKS",
    "RECENT_HOURS",
    "INDICATOR_THRESHOLD",
    "SIGN_IN_POINTS_MIN",
    "TRAVEL_WINDOW_MINUTES",
    "HOUR_GAP",
    "HOUR_BASELINE_MIN",
    "SHARED_EGRESS_MIN_ACCOUNTS",
    "POST_SIGN_IN_GRACE_MINUTES",
    "SIGN_IN_FAMILIES",
    "assess_users",
    "source_ips",
]

#: Successful sign-ins in this many hours before the incident are the ones assessed.
RECENT_HOURS = 24
#: Indicator points that make an account likely compromised.
INDICATOR_THRESHOLD = 3
#: Of those points, at least this many must come from the sign-in itself (not exposure or identity risk).
SIGN_IN_POINTS_MIN = 2
#: Two successful sign-ins from different countries within this many minutes are impossible travel.
TRAVEL_WINDOW_MINUTES = 120
#: A sign-in hour at least this many hours (UTC, circular) from every baseline hour is abnormal.
HOUR_GAP = 4
#: Baseline sign-ins needed before the hour is assessed.
HOUR_BASELINE_MIN = 3
#: Other accounts signing in from an IP (successfully) that make it a shared egress.
SHARED_EGRESS_MIN_ACCOUNTS = 2
#: Post-sign-in activity this many minutes before the first suspicious sign-in still counts.
POST_SIGN_IN_GRACE_MINUTES = 10

#: Indicator families that describe the sign-in itself.
SIGN_IN_FAMILIES: frozenset[str] = frozenset({"flagged_ip", "anonymizer", "travel", "geography", "device", "time"})
#: Families discounted for a sign-in from a non-public address or a shared egress.
_LOCATION_FAMILIES = frozenset({"travel", "geography", "time"})
_FAMILY_LABELS: Mapping[str, str] = {
    "flagged_ip": "source IP rated malicious or suspicious", "anonymizer": "anonymising network",
    "travel": "impossible travel", "geography": "unusual country", "device": "new or unmanaged device",
    "time": "abnormal sign-in hour", "identity_risk": "identity risk", "vendor": "vendor risk detection",
    "exposure": "credential exposure",
}

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_STRONG = frozenset({Severity.HIGH, Severity.CRITICAL})
_USER_TYPES = frozenset({ObservableType.USER, ObservableType.EMAIL_ADDRESS})
_IP_TYPES = frozenset({ObservableType.IP, ObservableType.IPV6})
_USER_ATOMICS = frozenset({"investigate_user", "investigate_authentication", "search_user_activity"})
_ATTACKER_IP_ANOMALIES = frozenset({"anonymous_ip", "malicious_ip"})
_ANOMALY_FAMILY: Mapping[str, str] = {
    "impossible_travel": "travel", "unfamiliar_location": "geography", "new_device": "device",
    "anonymous_ip": "anonymizer", "malicious_ip": "flagged_ip", "leaked_credentials": "exposure",
}
_NONCOMPLIANT = frozenset({"noncompliant", "non-compliant", "non_compliant"})
#: Vendor categories (enrichment) and identity-alert names that name an anonymising network.
_ANONYMIZER_WORDS = re.compile(r"\btor\b|anonymi[sz]|anonymous|\bproxy\b|proxies|onion")
_VPN_WORDS = re.compile(r"\bvpn\b")
#: Identity-protection alert names (Defender XDR alerts_v2) -> indicator family.
_ALERT_FAMILIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"leaked credential|credential leak|credentials? exposed"), "exposure"),
    (re.compile(r"impossible travel|atypical travel"), "travel"),
    (_ANONYMIZER_WORDS, "anonymizer"),
    (re.compile(r"malicious ip"), "flagged_ip"),
    (re.compile(r"unfamiliar|unusual location|new country"), "geography"),
    (re.compile(r"new device|unmanaged device|unregistered device"), "device"),
)


def _ids(records: Iterable[Any]) -> list[str]:
    """Record ids in first-seen order, without duplicates."""
    return list(dict.fromkeys(r.record_id for r in records))


def _key(value: str | None) -> str:
    return (value or "").strip().lower()


def _ip_key(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return normalize_target(TargetKind.IP, text)
    except ValueError:
        return text.lower()


def _stamp(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ") if value is not None else "unknown time"


def _hour_gap(hour: int, others: Iterable[int]) -> int:
    return min((min(abs(hour - o), 24 - abs(hour - o)) for o in others), default=0)


def _strength(severity: Severity) -> int:
    return 2 if severity in _STRONG else 1


# ------------------------------------------------------------------ collect --
@dataclass
class _User:
    """Everything the run learned about one investigated account (records only)."""

    user: str
    profiles: dict[str, UserProfileRecord] = field(default_factory=dict)
    signins: dict[str, SignInRecord] = field(default_factory=dict)
    anomalies: dict[str, AnomalyRecord] = field(default_factory=dict)
    detections: dict[str, DetectionRecord] = field(default_factory=dict)
    activity: dict[str, MailboxRuleRecord | RoleChangeRecord | CloudAppRecord] = field(default_factory=dict)
    exposure: dict[str, EnrichmentRecord] = field(default_factory=dict)
    devices: dict[str, EndpointRecord] = field(default_factory=dict)

    @property
    def profile(self) -> UserProfileRecord | None:
        return next(iter(self.profiles.values()), None)


@dataclass
class _Ip:
    """Reputation, vendor detections and enterprise prevalence of one sign-in source IP."""

    ip: str
    verdict: Verdict = Verdict.UNKNOWN
    enrichment: dict[str, EnrichmentRecord] = field(default_factory=dict)
    anomalies: dict[str, AnomalyRecord] = field(default_factory=dict)
    prevalence: dict[str, Any] = field(default_factory=dict)

    def flagged_enrichment(self) -> list[EnrichmentRecord]:
        return [r for r in self.enrichment.values() if r.verdict in _FLAGGED]

    def any_malicious(self) -> bool:
        return any(r.verdict is Verdict.MALICIOUS for r in self.enrichment.values())

    def flagged(self) -> bool:
        return bool(self.flagged_enrichment()) or self.verdict in _FLAGGED or bool(self.anomalies)

    def clean(self) -> bool:
        if self.verdict is Verdict.CLEAN:
            return True
        return bool(self.enrichment) and all(r.verdict is Verdict.CLEAN for r in self.enrichment.values())

    def block_worthy(self) -> bool:
        """At least one source rates it MALICIOUS, or a HIGH/CRITICAL vendor attacker-IP detection names it."""
        if self.clean() and not self.anomalies:
            return False
        return self.any_malicious() or any(a.severity in _STRONG for a in self.anomalies.values())

    def anonymizer_records(self) -> tuple[int, list[Any], str]:
        """(points, records, label) for the anonymising-network family from this IP's own records."""
        strong = [a for a in self.anomalies.values() if a.anomaly_type == "anonymous_ip"]
        tor = [r for r in self.enrichment.values()
               if r.verdict is not Verdict.CLEAN and any(_ANONYMIZER_WORDS.search(c.lower()) for c in r.categories)]
        if strong or tor:
            label = "vendor anonymous-IP detection" if strong else "Tor or proxy category"
            return 2, [*strong, *tor], label
        vpn = [r for r in self.enrichment.values()
               if r.verdict is not Verdict.CLEAN and any(_VPN_WORDS.search(c.lower()) for c in r.categories)]
        if vpn:
            return 1, vpn, "VPN category"
        return 0, [], ""

    def non_public(self) -> bool:
        return non_public_network(self.ip) is not None


@dataclass
class _Data:
    """The run's records grouped by investigated account and by IP."""

    users: dict[str, _User] = field(default_factory=dict)
    ips: dict[str, _Ip] = field(default_factory=dict)
    incident_ips: set[str] = field(default_factory=set)
    created_at: datetime | None = None

    def user(self, value: str) -> _User:
        key = _key(value)
        return self.users.setdefault(key, _User(user=key))

    def ip(self, value: str) -> _Ip:
        key = _ip_key(value)
        return self.ips.setdefault(key, _Ip(ip=key))


def _investigated(view: RunView) -> set[str]:
    incident = view.incident
    users = {_key(u) for u in incident.users}
    users |= {_key(o.value) for o in incident.observables if o.type is ObservableType.USER}
    users.discard("")
    return users


def _collect(view: RunView) -> _Data:
    data = _Data(created_at=view.incident.created_at)
    investigated = _investigated(view)
    for user in sorted(investigated):
        data.user(user)
    data.incident_ips = {_ip_key(o.value) for o in view.incident.observables if o.type in _IP_TYPES}
    for result in view.results:
        subject = result.subject
        if result.atomic == "enrich_ip" and subject.type in _IP_TYPES:
            ip = data.ip(subject.value)
            if isinstance(result, ObservableReport):
                ip.verdict = result.verdict
            for record in result.records:
                if isinstance(record, EnrichmentRecord):
                    ip.enrichment.setdefault(record.record_id, record)
        elif result.atomic == "enrich_email_address" and _key(subject.value) in data.users:
            for record in result.records:
                if isinstance(record, EnrichmentRecord) and record.verdict in _FLAGGED:
                    data.users[_key(subject.value)].exposure.setdefault(record.record_id, record)
        elif result.atomic == "search_ip_enterprise" and subject.type in _IP_TYPES:
            ip = data.ip(subject.value)
            for record in result.records:
                ip.prevalence.setdefault(record.record_id, record)
        elif result.atomic == "investigate_endpoint":
            for record in result.records:
                if isinstance(record, EndpointRecord):
                    for user in record.users:
                        if _key(user) in data.users:
                            data.users[_key(user)].devices.setdefault(record.record_id, record)
        elif result.atomic in _USER_ATOMICS and subject.type in _USER_TYPES and _key(subject.value) in data.users:
            for record in result.records:
                _collect_record(data, record, _key(subject.value))
    for user in data.users.values():  # every sign-in source gets an entry (egress and non-public checks)
        for signin in user.signins.values():
            if signin.ip:
                data.ip(signin.ip)
    return data


def _collect_record(data: _Data, record: Any, subject_user: str) -> None:
    def owner(value: str | None) -> _User | None:
        key = _key(value) or subject_user
        return data.users.get(key)

    if isinstance(record, UserProfileRecord):
        target = owner(record.user)
        if target is not None:
            target.profiles.setdefault(record.record_id, record)
    elif isinstance(record, SignInRecord):
        target = owner(record.user)
        if target is not None:
            target.signins.setdefault(record.record_id, record)
    elif isinstance(record, AnomalyRecord):
        target = owner(record.user)
        if target is not None:
            target.anomalies.setdefault(record.record_id, record)
        if record.ip and record.anomaly_type in _ATTACKER_IP_ANOMALIES:
            data.ip(record.ip).anomalies.setdefault(record.record_id, record)
    elif isinstance(record, DetectionRecord):
        target = owner(record.user)
        if target is not None and record.verdict is not Verdict.CLEAN:
            target.detections.setdefault(record.record_id, record)
    elif isinstance(record, MailboxRuleRecord):
        target = owner(record.mailbox)
        if target is not None:
            target.activity.setdefault(record.record_id, record)
    elif isinstance(record, RoleChangeRecord):
        target = owner(record.user)
        if target is not None:
            target.activity.setdefault(record.record_id, record)
    elif isinstance(record, CloudAppRecord):
        target = owner(record.consented_by)
        if target is not None:
            target.activity.setdefault(record.record_id, record)


# --------------------------------------------------------------------- IPs --
@dataclass
class _Egress:
    """Why an IP is shared: the records that show it, and whether it is a trusted (unflagged) egress."""

    shared_ids: list[str]
    other_accounts: list[str]
    endpoints: list[str]
    egress: bool  # non-public, or shared by enough accounts / internal endpoints and flagged by nobody
    reason: str


def _egress(ip: _Ip, investigated: set[str]) -> _Egress:
    accounts: dict[str, list[str]] = {}
    endpoints: dict[str, list[str]] = {}
    for record in ip.prevalence.values():
        if isinstance(record, SignInRecord) and record.result == "success" and _key(record.user) not in investigated:
            accounts.setdefault(_key(record.user), []).append(record.record_id)
        elif isinstance(record, NetworkConnectionRecord) and record.endpoint:
            endpoints.setdefault(record.endpoint, []).append(record.record_id)
        elif isinstance(record, EndpointRecord):
            endpoints.setdefault(record.hostname, []).append(record.record_id)
    shared_ids = list(dict.fromkeys([i for ids in (*accounts.values(), *endpoints.values()) for i in ids]))
    if ip.non_public():
        return _Egress(shared_ids, sorted(accounts), sorted(endpoints), True,
                       f"the non-public address {ip.ip} of the organisation's own network")
    shared = len(accounts) >= SHARED_EGRESS_MIN_ACCOUNTS or bool(endpoints)
    egress = shared and not ip.flagged()
    parts = []
    if accounts:
        parts.append(f"{len(accounts)} other account(s) sign in from it")
    if endpoints:
        parts.append(f"internal endpoint(s) {', '.join(sorted(endpoints))} reach it")
    return _Egress(shared_ids, sorted(accounts), sorted(endpoints), egress,
                   f"the shared egress {ip.ip} (" + "; ".join(parts) + ")" if parts else "")


# ------------------------------------------------------------------- users --
@dataclass
class _Family:
    points: int = 0
    reasons: list[str] = field(default_factory=list)
    record_ids: list[str] = field(default_factory=list)
    signins: list[SignInRecord] = field(default_factory=list)  # sign-ins the family was computed from

    def add(self, points: int, reason: str, records: Iterable[Any], signins: Iterable[SignInRecord] = ()) -> None:
        self.points = max(self.points, points)
        if reason not in self.reasons:
            self.reasons.append(reason)
        for record_id in _ids(records):
            if record_id not in self.record_ids:
                self.record_ids.append(record_id)
        for signin in signins:
            if signin not in self.signins:
                self.signins.append(signin)


@dataclass
class _Assessment:
    """Indicators of one account, with the records behind every one."""

    user: _User
    recent: list[SignInRecord] = field(default_factory=list)
    baseline: list[SignInRecord] = field(default_factory=list)
    families: dict[str, _Family] = field(default_factory=dict)
    discounted: list[str] = field(default_factory=list)
    discounted_ids: list[str] = field(default_factory=list)
    disable_reasons: list[str] = field(default_factory=list)
    disable_ids: list[str] = field(default_factory=list)
    revoked_then_used: list[SignInRecord] = field(default_factory=list)

    def family(self, name: str) -> _Family:
        return self.families.setdefault(name, _Family())

    @property
    def total(self) -> int:
        return sum(f.points for f in self.families.values())

    @property
    def sign_in_points(self) -> int:
        return sum(f.points for n, f in self.families.items() if n in SIGN_IN_FAMILIES)

    @property
    def compromised(self) -> bool:
        return bool(self.recent) and self.total >= INDICATOR_THRESHOLD and self.sign_in_points >= SIGN_IN_POINTS_MIN

    def suspicious_signins(self) -> list[SignInRecord]:
        found = {s.record_id: s for n, f in self.families.items() if n in SIGN_IN_FAMILIES for s in f.signins}
        return sorted(found.values(), key=lambda s: (s.timestamp, s.record_id))

    def record_ids(self) -> list[str]:
        out = _ids(self.suspicious_signins())
        for name in sorted(self.families, key=lambda n: (-self.families[n].points, n)):
            out += [i for i in self.families[name].record_ids if i not in out]
        return out

    def indicators(self) -> list[str]:
        out = []
        for name in sorted(self.families, key=lambda n: (-self.families[n].points, n)):
            fam = self.families[name]
            out.append(f"{_FAMILY_LABELS[name]} ({'; '.join(fam.reasons)}) [{fam.points}]")
        return out


def _split(user: _User, data: _Data) -> tuple[list[SignInRecord], list[SignInRecord]]:
    successes = sorted((s for s in user.signins.values() if s.result == "success"),
                       key=lambda s: (s.timestamp, s.record_id))
    if data.created_at is None:
        return successes, []
    start = data.created_at - timedelta(hours=RECENT_HOURS)
    recent = [s for s in successes if s.timestamp >= start or (s.ip and _ip_key(s.ip) in data.incident_ips)]
    baseline = [s for s in successes if s not in recent]
    return recent, baseline


def _assess(user: _User, data: _Data, egress: Mapping[str, _Egress]) -> _Assessment:
    found = _Assessment(user=user)
    found.recent, found.baseline = _split(user, data)

    def trusted(signin: SignInRecord) -> _Egress | None:
        ip = _ip_key(signin.ip)
        hit = egress.get(ip) if ip else None
        return hit if hit is not None and hit.egress else None

    baseline_out = [s for s in found.baseline if trusted(s) is None]
    countries = sorted({s.country.upper() for s in baseline_out if s.country})
    devices = sorted({s.device_id for s in found.baseline if s.device_id})
    hours = [s.timestamp.hour for s in baseline_out]
    recent_ips = {_ip_key(s.ip) for s in found.recent if s.ip}
    for signin in found.recent:
        _sign_in_indicators(found, signin, data, trusted(signin), countries, devices, hours, baseline_out)
    _travel(found, trusted)
    _account_indicators(found, data, egress, recent_ips)
    if found.compromised:
        _disable_reasons(found)
    return found


def _sign_in_indicators(found: _Assessment, signin: SignInRecord, data: _Data, shared: _Egress | None,
                        countries: Sequence[str], devices: Sequence[str], hours: Sequence[int],
                        baseline: Sequence[SignInRecord]) -> None:
    where = f"{_stamp(signin.timestamp)} from {signin.ip or 'unknown IP'} ({signin.country or 'unknown country'})"
    at = f" at {_stamp(signin.timestamp)}"
    ip = data.ips.get(_ip_key(signin.ip)) if signin.ip else None
    if ip is not None:
        flagged = ip.flagged_enrichment()
        malicious = [r for r in flagged if r.verdict is Verdict.MALICIOUS]
        attacker = [a for a in ip.anomalies.values() if a.anomaly_type == "malicious_ip"]
        if malicious or flagged or attacker:
            points = 2 if (malicious or any(a.severity in _STRONG for a in attacker)) else 1
            rated = ", ".join(sorted(f"{r.integration} {r.verdict.value}" for r in flagged))
            found.family("flagged_ip").add(points, f"{ip.ip} rated " + (rated or "by a vendor detection"),
                                           [signin, *flagged, *attacker], [signin])
        points, records, label = ip.anonymizer_records()
        if points:
            found.family("anonymizer").add(points, f"{label} for {ip.ip}", [signin, *records], [signin])
    if shared is not None:
        if signin.country and countries and signin.country.upper() not in countries:
            found.discounted.append(f"sign-in {where} came through {shared.reason}: its country is not counted "
                                    "as unusual")
            found.discounted_ids += [i for i in [signin.record_id, *shared.shared_ids] if i not in found.discounted_ids]
    else:
        if signin.country and countries and signin.country.upper() not in countries:
            found.family("geography").add(1, f"country {signin.country.upper()}{at} not in the baseline "
                                             f"({', '.join(countries)})", [signin, *baseline], [signin])
        if len(hours) >= HOUR_BASELINE_MIN and _hour_gap(signin.timestamp.hour, hours) >= HOUR_GAP:
            found.family("time").add(1, f"hour {signin.timestamp.hour:02d} UTC{at} is at least {HOUR_GAP} "
                                        "hours from every baseline sign-in hour", [signin, *baseline], [signin])
    if devices and signin.device_id and signin.device_id not in devices:
        found.family("device").add(1, f"new device {signin.device_id}{at}", [signin, *found.baseline], [signin])
    elif devices and not signin.device_id:
        found.family("device").add(1, f"unregistered device{at} (the baseline uses registered devices)",
                                   [signin, *found.baseline], [signin])
    if signin.device_compliant is False:
        found.family("device").add(1, f"device not compliant{at}", [signin], [signin])
    if signin.risk_level in ("high", "medium"):
        found.family("identity_risk").add(2 if signin.risk_level == "high" else 1,
                                          f"sign-in risk {signin.risk_level}{at}", [signin])


def _travel(found: _Assessment, trusted: Any) -> None:
    candidates = [s for s in found.recent if s.country and trusted(s) is None]
    others = [s for s in (*found.baseline, *found.recent) if s.country and trusted(s) is None]
    window = timedelta(minutes=TRAVEL_WINDOW_MINUTES)
    for signin in candidates:
        for other in others:
            if other.record_id == signin.record_id or other.country.upper() == signin.country.upper():
                continue
            if abs(signin.timestamp - other.timestamp) <= window:
                first, second = sorted((signin, other), key=lambda s: (s.timestamp, s.record_id))
                minutes = int((second.timestamp - first.timestamp).total_seconds() // 60)
                found.family("travel").add(
                    2, f"{first.country.upper()} at {_stamp(first.timestamp)} then {second.country.upper()} at "
                       f"{_stamp(second.timestamp)} ({minutes} minutes apart)", [first, second], [signin])


def _recent_record(when: datetime | None, start: datetime | None) -> bool:
    return when is None or start is None or when >= start


def _account_indicators(found: _Assessment, data: _Data, egress: Mapping[str, _Egress], recent_ips: set[str]) -> None:
    user = found.user
    start = data.created_at - timedelta(hours=RECENT_HOURS) if data.created_at is not None else None
    for anomaly in sorted(user.anomalies.values(), key=lambda a: a.record_id):
        if not _recent_record(anomaly.first_seen, start):
            continue
        ip = _ip_key(anomaly.ip) if anomaly.ip else ""
        if ip and ip not in recent_ips:
            continue  # about an attempt that did not succeed (or an older sign-in): not this account's sign-in
        family = _ANOMALY_FAMILY.get(anomaly.anomaly_type, "vendor")
        hit = egress.get(ip) if ip else None
        if family in _LOCATION_FAMILIES and hit is not None and hit.egress:
            found.discounted.append(f"{anomaly.anomaly_type} detection for a sign-in through {hit.reason}: not "
                                    "counted")
            found.discounted_ids += [i for i in [anomaly.record_id, *hit.shared_ids] if i not in found.discounted_ids]
            continue
        points = 2 if family == "anonymizer" else (1 if family == "exposure" else _strength(anomaly.severity))
        signins = [s for s in found.recent if ip and _ip_key(s.ip) == ip]
        found.family(family).add(points, f"vendor {anomaly.anomaly_type} detection ({anomaly.severity.value})",
                                 [*signins, anomaly], signins)
    for detection in sorted(user.detections.values(), key=lambda d: d.record_id):
        if not _recent_record(detection.first_seen or detection.last_seen, start):
            continue
        text = f"{detection.name} {detection.category or ''}".lower()
        family = next((f for pattern, f in _ALERT_FAMILIES if pattern.search(text)), None)
        if family is None or (family in _LOCATION_FAMILIES and not found.recent):
            continue
        points = 1 if family == "exposure" else (2 if family == "anonymizer" else _strength(detection.severity))
        found.family(family).add(points, f"{detection.integration} alert '{detection.name}' "
                                         f"({detection.severity.value})", [detection])
    profile = user.profile
    if profile is not None and (profile.risk_level == "high" or profile.risk_state == "confirmed_compromised"):
        state = "confirmed compromised" if profile.risk_state == "confirmed_compromised" else "high risk"
        found.family("identity_risk").add(2, f"identity provider rates the account {state}", [profile])
    for record in user.exposure.values():
        found.family("exposure").add(1, f"{record.integration} reports the address in breach data", [record])
    for device in user.devices.values():
        if (device.health_state or "").strip().lower() in _NONCOMPLIANT:
            found.family("device").add(1, f"managed device {device.hostname} is not compliant ({device.integration})",
                                       [device])


def _privileged_roles(user: _User) -> tuple[list[str], list[Any], list[str]]:
    """(reason labels, records, granted role names) that make the account privileged."""
    labels: list[str] = []
    records: list[Any] = []
    granted: list[str] = []
    profile = user.profile
    if profile is not None:
        named = [r for r in profile.roles if r.strip().lower() in PRIVILEGED_ROLE_NAMES]
        if named or profile.privileged:
            labels += named or ["marked privileged by the identity provider"]
            records.append(profile)
    for record in sorted(user.activity.values(), key=lambda r: r.record_id):
        if isinstance(record, RoleChangeRecord) and record.privileged and record.change in (
                "assigned", "activated", "eligible_assigned"):
            labels.append(f"{record.role_name} granted")
            granted.append(record.role_name)
            records.append(record)
    return list(dict.fromkeys(labels)), records, list(dict.fromkeys(granted))


def _disable_reasons(found: _Assessment) -> None:
    user = found.user
    profile = user.profile
    suspicious = found.suspicious_signins() or found.recent
    first = suspicious[0].timestamp if suspicious else None

    def reason(text: str, records: Iterable[Any]) -> None:
        found.disable_reasons.append(text)
        found.disable_ids.extend(i for i in _ids(records) if i not in found.disable_ids)

    roles, role_records, _granted = _privileged_roles(user)
    if roles:
        reason("privileged account (" + ", ".join(roles) + ")", role_records)
    if profile is not None and profile.risk_state == "confirmed_compromised":
        reason("the identity provider confirmed the compromise", [profile])
    if profile is not None and profile.sessions_valid_from is not None:
        later = [s for s in suspicious if s.timestamp > profile.sessions_valid_from]
        if later:
            found.revoked_then_used = later
            reason("suspicious sign-in after the sessions were revoked at "
                   f"{_stamp(profile.sessions_valid_from)}", [profile, *later])
    if first is not None:
        floor = first - timedelta(minutes=POST_SIGN_IN_GRACE_MINUTES)
        persisted: list[Any] = []
        for record in sorted(user.activity.values(), key=lambda r: r.record_id):
            if isinstance(record, MailboxRuleRecord) and (record.external_forwarding or record.delete):
                when = record.created_at or record.modified_at
                label = f"mailbox rule '{record.name}'"
            elif isinstance(record, RoleChangeRecord) and record.privileged and record.change in ("assigned",
                                                                                                    "activated"):
                when, label = record.timestamp, f"role {record.role_name} {record.change}"
            elif isinstance(record, CloudAppRecord) and record.verdict in _FLAGGED:
                when = record.credential_added_at or record.created_at
                label = f"app consent {record.display_name or record.app_id}"
            else:
                continue
            if when is not None and when >= floor:
                persisted.append((label, record))
        if persisted:
            reason("post-sign-in persistence: " + ", ".join(label for label, _ in persisted),
                   [record for _, record in persisted])


def _user_fact(found: _Assessment) -> dict[str, Any]:
    user = found.user
    profile = user.profile
    roles, _records, granted = _privileged_roles(user)
    signins = found.suspicious_signins()
    where = "; ".join(f"{_stamp(s.timestamp)} from {s.ip or 'unknown IP'} ({s.country or 'unknown country'})"
                      for s in signins) or "none"
    summary = (f"account {user.user}: suspicious sign-in(s) {where}; indicators: " + "; ".join(found.indicators())
               + f"; {found.total} indicator point(s), {found.sign_in_points} from the sign-in itself "
                 f"(threshold {INDICATOR_THRESHOLD}, {SIGN_IN_POINTS_MIN})")
    return {
        "user": user.user,
        "compromised": found.compromised,
        "points": found.total,
        "sign_in_points": found.sign_in_points,
        "families": {name: fam.points for name, fam in sorted(found.families.items())},
        "indicators": found.indicators(),
        "recent_signins": len(found.recent),
        "baseline_signins": len(found.baseline),
        "summary": summary,
        "record_ids": found.record_ids(),
        "source_ips": sorted({_ip_key(s.ip) for s in signins if s.ip}),
        "discounted": list(found.discounted),
        "discounted_record_ids": list(found.discounted_ids),
        "privileged": bool(roles),
        "groups": list(profile.groups) if profile is not None else [],
        "roles": list(dict.fromkeys([*(profile.roles if profile is not None else ()), *granted])),
        "disable_reasons": list(found.disable_reasons),
        "disable_summary": "; ".join(found.disable_reasons),
        "disable_record_ids": list(found.disable_ids),
        "exposure_record_ids": list(found.families["exposure"].record_ids) if "exposure" in found.families else [],
    }


def assess_users(view: RunView) -> list[dict[str, Any]]:
    """One fact per investigated account (sorted): indicators, points, the verdict and the records."""
    data = _collect(view)
    egress = _egress_map(data, view)
    return [_user_fact(_assess(data.users[u], data, egress)) for u in sorted(data.users)]


def _egress_map(data: _Data, view: RunView) -> dict[str, _Egress]:
    investigated = _investigated(view)
    return {key: _egress(ip, investigated) for key, ip in sorted(data.ips.items()) if key}


# --------------------------------------------------------------- source IPs --
def source_ips(view: RunView, compromised: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Sign-in source IPs of the investigated accounts (recent sign-ins) and the incident's IPs."""
    data = _collect(view)
    egress = _egress_map(data, view)
    compromised = set(compromised)
    attempts: dict[str, list[SignInRecord]] = {}
    for user in data.users.values():
        start = data.created_at - timedelta(hours=RECENT_HOURS) if data.created_at is not None else None
        for signin in user.signins.values():
            key = _ip_key(signin.ip)
            if key and (start is None or signin.timestamp >= start or key in data.incident_ips):
                attempts.setdefault(key, []).append(signin)
    out: list[dict[str, Any]] = []
    for key in sorted(set(attempts) | data.incident_ips | {k for k, ip in data.ips.items() if ip.anomalies}):
        ip = data.ips.get(key) or _Ip(ip=key)
        if not ip.flagged():
            continue
        signins = sorted(attempts.get(key, []), key=lambda s: (s.timestamp, s.record_id))
        hit = egress.get(key) or _Egress([], [], [], ip.non_public(), "")
        users = sorted({_key(s.user) for s in signins})
        successes = sorted({_key(s.user) for s in signins if s.result == "success"})
        record_ids = _ids([*signins, *sorted(ip.anomalies.values(), key=lambda a: a.record_id),
                           *ip.flagged_enrichment()])
        shared = bool(hit.shared_ids) and not ip.non_public()
        out.append({
            "ip": key,
            "verdict": ip.verdict.value,
            "users": users,
            "successful_users": successes,
            "compromised_users": sorted(set(successes) & compromised),
            "named_by_incident": key in data.incident_ips,
            "record_ids": record_ids,
            "non_public": ip.non_public(),
            "shared": shared,
            "shared_record_ids": list(hit.shared_ids),
            "shared_reason": hit.reason,
            "block_worthy": ip.block_worthy(),
            "block_candidate": ip.block_worthy() and not shared and not ip.non_public() and bool(record_ids),
            "summary": (f"IP {key} rated " + (", ".join(sorted(f"{r.integration} {r.verdict.value}"
                                                               for r in ip.flagged_enrichment()))
                                               or f"{ip.verdict.value} (aggregate)")
                        + (", named by a HIGH vendor anonymous or malicious IP detection"
                           if any(a.severity in _STRONG for a in ip.anomalies.values()) else "")
                        + (f"; sign-in attempts against {', '.join(users)}" if users else "; named by the incident")
                        + (f"; successful sign-in of {', '.join(successes)}" if successes else "")),
        })
    return out


# -------------------------------------------------------------------- hooks --
class SuspiciousAuthenticationHooks(WorkflowHooks):
    """Facts, signals, links, considerations and hand-offs for the suspicious-authentication rules."""

    def facts(self, view: RunView) -> Mapping[str, Any]:
        users = assess_users(view)
        compromised = [u for u in users if u["compromised"]]
        ips = source_ips(view, [u["user"] for u in compromised])
        return {
            "users": users,
            "compromised_users": compromised,
            "disable_users": [u for u in compromised if u["disable_reasons"]],
            "ips": ips,
            "block_ips": [i for i in ips if i["block_candidate"]],
            "indicator_threshold": INDICATOR_THRESHOLD,
        }

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        """Each account to the source IPs of its suspicious sign-ins (citing those sign-ins)."""
        data = _collect(view)
        egress = _egress_map(data, view)
        links: list[CorrelationLink] = []
        for name in sorted(data.users):
            found = _assess(data.users[name], data, egress)
            by_ip: dict[str, list[SignInRecord]] = {}
            for signin in found.suspicious_signins():
                if signin.ip:
                    by_ip.setdefault(_ip_key(signin.ip), []).append(signin)
            for ip, signins in sorted(by_ip.items()):
                try:
                    links.append(CorrelationLink(
                        kind=LinkKind.WORKFLOW, origin=view.origin,
                        entities=(EntityRef(kind=TargetKind.USER, value=name), EntityRef(kind=TargetKind.IP, value=ip)),
                        record_ids=tuple(_ids(signins)), first_seen=signins[0].timestamp,
                        last_seen=signins[-1].timestamp,
                        note=f"suspicious sign-in of {name} from {ip}"))
                except ValueError:
                    continue
        return links

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        data = _collect(view)
        egress = _egress_map(data, view)
        origin = view.origin
        signals: list[ScoringSignal] = []
        compromised: list[str] = []
        for name in sorted(data.users):
            found = _assess(data.users[name], data, egress)
            if not found.compromised:
                continue
            compromised.append(name)
            signals += _user_signals(found, Observable(type=ObservableType.USER, value=name), data, origin)
        for fact in source_ips(view, compromised):
            if fact["block_candidate"]:
                signals += _ip_signals(fact, data, origin)
        return signals

    def considered(self, view: RunView) -> Sequence[Consideration]:
        facts = self.facts(view)
        items: list[Consideration] = []
        for user in facts["users"]:
            if user["compromised"]:
                items.append(Consideration(
                    subject=f"password-reset:{user['user']}", manual=True,
                    reason="reset the password and re-register MFA after out-of-band identity verification (no "
                           "VERIFIED automated write; not in the package)",
                    record_ids=tuple(user["record_ids"])))
                continue
            reasons: list[str] = []
            if user["points"]:
                why = ("no successful sign-in in the recent window" if not user["recent_signins"] else
                       f"{user['points']} indicator point(s), {user['sign_in_points']} from the sign-in itself, "
                       f"below the threshold of {INDICATOR_THRESHOLD} ({SIGN_IN_POINTS_MIN} from the sign-in)")
                reasons.append("indicators " + "; ".join(user["indicators"]) + f": {why}")
            reasons += user["discounted"]
            record_ids = list(dict.fromkeys([*user["record_ids"], *user["discounted_record_ids"]]))
            if reasons and record_ids:
                items.append(Consideration(subject=f"revoke_sessions:{user['user']}",
                                           reason="; ".join(reasons) + ": not proposed, the analyst reviews",
                                           record_ids=tuple(record_ids)))
            if user["exposure_record_ids"]:
                items.append(Consideration(
                    subject=f"password-reset:{user['user']}", manual=True,
                    reason="the address appears in breach data: confirm the password was changed after the breach "
                           "and is not reused (manual help-desk step; credential exposure alone is never contained)",
                    record_ids=tuple(user["exposure_record_ids"])))
        for ip in facts["ips"]:
            if not ip["block_worthy"] or ip["block_candidate"]:
                continue
            if ip["non_public"]:
                reason = "rated malicious but a non-public address of the organisation's own network: not blocked"
            elif ip["shared"]:
                reason = f"rated malicious but it is {ip['shared_reason'] or 'shared infrastructure'}: not blocked"
            else:
                continue
            record_ids = list(dict.fromkeys([*ip["record_ids"], *ip["shared_record_ids"]]))
            if record_ids:
                items.append(Consideration(subject=f"block_ip:{ip['ip']}", reason=reason,
                                           record_ids=tuple(record_ids)))
        return items

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        compromised = self.facts(view)["compromised_users"]
        if not compromised:
            return ()
        record_ids = list(dict.fromkeys(i for u in compromised for i in u["record_ids"]))
        return (Handoff(workflow_id="account-takeover", subjects=tuple(u["user"] for u in compromised),
                        reason="suspicious sign-in concluded as a likely compromise: review the account's wider "
                               "activity, MFA methods and app consents",
                        record_ids=tuple(record_ids)),)


def _by_integration(records: Iterable[Any]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for record in records:
        out.setdefault(record.integration, []).append(record)
    return out


def _signal(origin: str, integration: str, subject: Observable, verdict: Verdict, severity: int, confidence: int,
            records: Sequence[Any], note: str) -> ScoringSignal:
    return ScoringSignal(category=SignalCategory.AUTHENTICATION_ANOMALY, integration=integration,
                         observable=subject, verdict=verdict, severity=severity, confidence=confidence,
                         record_ids=tuple(_ids(records)), origin=origin, note=note)


#: family -> (verdict, severity, confidence, note) of the hook signal over the family's sign-ins.
_FAMILY_SIGNALS: Mapping[str, tuple[Verdict, int, int, str]] = {
    "anonymizer": (Verdict.SUSPICIOUS, 70, 70, "successful sign-in through an anonymising network"),
    "travel": (Verdict.SUSPICIOUS, 75, 65, "impossible travel between successful sign-ins"),
    "geography": (Verdict.SUSPICIOUS, 50, 60, "successful sign-in from a country the baseline never shows"),
    "device": (Verdict.SUSPICIOUS, 50, 60, "successful sign-in from a new, unregistered or non-compliant device"),
    "time": (Verdict.SUSPICIOUS, 40, 50, "successful sign-in at an hour the baseline never shows"),
}


def _user_signals(found: _Assessment, subject: Observable, data: _Data, origin: str) -> list[ScoringSignal]:
    out: list[ScoringSignal] = []
    flagged = found.families.get("flagged_ip")
    if flagged is not None and flagged.signins:
        malicious = flagged.points >= 2
        for integration, signins in sorted(_by_integration(flagged.signins).items()):
            out.append(_signal(origin, integration, subject, Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS,
                               80 if malicious else 65, 75 if malicious else 65, signins,
                               "successful sign-in from an IP rated " + ("malicious" if malicious else "suspicious")))
    for name, (verdict, severity, confidence, note) in _FAMILY_SIGNALS.items():
        family = found.families.get(name)
        if family is None or not family.signins:
            continue
        cited: list[SignInRecord] = list(family.signins)
        if name == "travel":
            ids = set(family.record_ids)
            cited = [s for s in (*found.baseline, *found.recent) if s.record_id in ids]
        for integration, signins in sorted(_by_integration(cited).items()):
            out.append(_signal(origin, integration, subject, verdict, severity, confidence, signins, note))
    profile = found.user.profile
    if found.revoked_then_used and profile is not None:
        out.append(_signal(origin, profile.integration, subject, Verdict.MALICIOUS, 85, 80,
                           [profile, *found.revoked_then_used], "suspicious sign-in after the sessions were revoked"))
    return out


def _ip_signals(fact: Mapping[str, Any], data: _Data, origin: str) -> list[ScoringSignal]:
    key = fact["ip"]
    subject = Observable(type=ObservableType.IPV6 if ":" in key else ObservableType.IP, value=key)
    ip = data.ips.get(key)
    signins = [s for u in data.users.values() for s in u.signins.values() if _ip_key(s.ip) == key]
    if not signins or ip is None:
        return []
    compromised = bool(fact["compromised_users"])
    malicious = compromised and ip.any_malicious()
    out: list[ScoringSignal] = []
    for integration, records in sorted(_by_integration(signins).items()):
        out.append(_signal(origin, integration, subject, Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS,
                           80 if malicious else (70 if compromised else 60), 70, records,
                           "sign-in source of an investigated account"
                           + (" with a successful sign-in of a likely compromised account" if compromised else "")))
    return out


HOOKS = SuspiciousAuthenticationHooks()
