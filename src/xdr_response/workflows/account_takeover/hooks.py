"""Pure hooks of the account-takeover workflow (architecture 14.3.3).

The hooks read the run's records (a :class:`RunView`: no context, no adapters) and compute:

* ``facts``: JSON values for the recommendation rules: which investigated users show a compromise
  indicator (and the record ids that prove it), which of them also need their account disabled, which
  sign-in source IPs are attacker infrastructure worth blocking (and which are shared and are not),
  and which of the users' endpoints carry an active malicious detection (citing the detection and
  the account's compromise records; when the identity reads of the account failed, the endpoint is
  still listed on its detection alone, with a rationale that says the account could not be assessed);
* ``derive_signals``: authentication-anomaly patterns computed from cited records (a successful
  sign-in from an IP that enrichment rates malicious or suspicious, an attacker sign-in after the
  sessions were revoked, an MFA approval after repeated denials, a sign-in source IP used against an
  investigated account).

Nothing here calls a vendor, writes anything, chooses an approval level or invents a fact: every
user, IP and endpoint in the facts comes from a record, and every record id a fact or a signal cites
is an id of the run (the runner checks it again). The hooks only *recommend*; the human approves.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    PRIVILEGED_ROLE_NAMES,
    AnomalyRecord,
    CloudAppRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    InvestigationBundle,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, RunView, WorkflowHooks, failed_reads

__all__ = [
    "AccountTakeoverHooks",
    "HOOKS",
    "ATTACKER_ANOMALIES",
    "ATTACKER_IP_ANOMALIES",
    "MFA_DENIALS_BEFORE_APPROVAL",
    "STRONG_SEVERITIES",
]

#: Vendor risk detections that name attacker infrastructure for the IP they carry.
ATTACKER_IP_ANOMALIES: frozenset[str] = frozenset({"anonymous_ip", "malicious_ip"})
#: Vendor risk detection types that indicate a takeover when HIGH or CRITICAL and a sign-in succeeded.
ATTACKER_ANOMALIES: frozenset[str] = frozenset({
    "impossible_travel", "unfamiliar_location", "new_device", "anonymous_ip", "malicious_ip",
    "mfa_fatigue", "token_replay", "leaked_credentials", "atypical_volume", "other",
})
STRONG_SEVERITIES: frozenset[Severity] = frozenset({Severity.HIGH, Severity.CRITICAL})
#: Denied or fraud-reported MFA prompts before an approval that make the approval suspicious.
MFA_DENIALS_BEFORE_APPROVAL = 3

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_USER_TYPES = frozenset({ObservableType.USER, ObservableType.EMAIL_ADDRESS})
_IP_TYPES = frozenset({ObservableType.IP, ObservableType.IPV6})
_USER_ATOMICS = frozenset({"investigate_user", "investigate_authentication", "search_user_activity",
                           "search_related_users"})


def _ids(records: Iterable[Any]) -> list[str]:
    """Record ids in first-seen order, without duplicates."""
    return list(dict.fromkeys(r.record_id for r in records))


def _key(value: str | None) -> str:
    return (value or "").strip().lower()


@dataclass
class _User:
    """Everything the run learned about one investigated user (records only)."""

    user: str
    profiles: dict[str, UserProfileRecord] = field(default_factory=dict)
    signins: dict[str, SignInRecord] = field(default_factory=dict)
    anomalies: dict[str, AnomalyRecord] = field(default_factory=dict)
    mfa: dict[str, MfaEventRecord] = field(default_factory=dict)
    activity: dict[str, MailboxRuleRecord | RoleChangeRecord | CloudAppRecord] = field(default_factory=dict)

    @property
    def profile(self) -> UserProfileRecord | None:
        return next(iter(self.profiles.values()), None)


@dataclass
class _Ip:
    """Reputation and enterprise prevalence of one sign-in source IP."""

    ip: str
    report: ObservableReport | None = None
    prevalence: list[InvestigationBundle] = field(default_factory=list)
    anomalies: dict[str, AnomalyRecord] = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        return self.report.verdict if self.report is not None else Verdict.UNKNOWN

    def flagged_enrichment(self) -> list[EnrichmentRecord]:
        """Enrichment answers rating the IP MALICIOUS or SUSPICIOUS (vendor verdicts, cited as such)."""
        if self.report is None:
            return []
        return [r for r in self.report.enrichment_records() if r.verdict in _FLAGGED]

    def any_malicious(self) -> bool:
        return any(r.verdict is Verdict.MALICIOUS for r in self.flagged_enrichment())

    def flagged(self) -> bool:
        """Rated MALICIOUS or SUSPICIOUS by enrichment, or named by a vendor attacker-IP detection."""
        return self.verdict in _FLAGGED or bool(self.flagged_enrichment()) or bool(self.anomalies)

    def block_worthy(self) -> bool:
        """At least one source rates it MALICIOUS, or a HIGH/CRITICAL vendor attacker-IP detection names it."""
        if self.verdict is Verdict.CLEAN and not self.anomalies:
            return False
        return self.any_malicious() or any(a.severity in STRONG_SEVERITIES for a in self.anomalies.values())


@dataclass
class _View:
    """The run's records grouped by user, IP and endpoint."""

    users: dict[str, _User] = field(default_factory=dict)
    ips: dict[str, _Ip] = field(default_factory=dict)
    endpoints: dict[str, list[EndpointRecord]] = field(default_factory=dict)
    detections: dict[str, dict[str, DetectionRecord]] = field(default_factory=dict)

    def user(self, value: str) -> _User:
        key = _key(value)
        return self.users.setdefault(key, _User(user=key))

    def ip(self, value: str) -> _Ip:
        key = _key(value)
        return self.ips.setdefault(key, _Ip(ip=key))


def _collect(view: RunView) -> _View:
    out = _View()
    for result in view.results:
        if isinstance(result, ObservableReport):
            if result.subject.type in _IP_TYPES:
                out.ip(result.subject.value).report = result
            continue
        if not isinstance(result, InvestigationBundle):
            continue
        if result.atomic == "search_ip_enterprise" and result.subject.type in _IP_TYPES:
            out.ip(result.subject.value).prevalence.append(result)
            continue
        subject_user = result.subject.value if (result.atomic in _USER_ATOMICS
                                                and result.subject.type in _USER_TYPES) else None
        for record in result.records:
            _collect_record(out, record, subject_user)
    return out


def _collect_record(out: _View, record: Any, subject_user: str | None) -> None:
    if isinstance(record, UserProfileRecord):
        out.user(record.user).profiles.setdefault(record.record_id, record)
    elif isinstance(record, SignInRecord):
        out.user(record.user).signins.setdefault(record.record_id, record)
    elif isinstance(record, AnomalyRecord):
        owner = record.user or subject_user
        if owner:
            out.user(owner).anomalies.setdefault(record.record_id, record)
        if record.ip and record.anomaly_type in ATTACKER_IP_ANOMALIES:
            out.ip(record.ip).anomalies.setdefault(record.record_id, record)
    elif isinstance(record, MfaEventRecord):
        out.user(record.user).mfa.setdefault(record.record_id, record)
    elif isinstance(record, MailboxRuleRecord):
        out.user(record.mailbox).activity.setdefault(record.record_id, record)
    elif isinstance(record, RoleChangeRecord):
        out.user(record.user).activity.setdefault(record.record_id, record)
    elif isinstance(record, CloudAppRecord):
        owner = record.consented_by or subject_user
        if owner:
            out.user(owner).activity.setdefault(record.record_id, record)
    elif isinstance(record, EndpointRecord):
        out.endpoints.setdefault(_key(record.hostname).upper(), []).append(record)
    elif isinstance(record, DetectionRecord) and record.endpoint:
        out.detections.setdefault(_key(record.endpoint).upper(), {}).setdefault(record.record_id, record)


# ------------------------------------------------------------------ users --
@dataclass
class _Assessment:
    """Why one user looks compromised, with the records behind every reason."""

    user: _User
    indicators: list[str] = field(default_factory=list)
    record_ids: list[str] = field(default_factory=list)
    attacker_signins: list[SignInRecord] = field(default_factory=list)  # successes from flagged IPs
    attacker_ips: list[str] = field(default_factory=list)
    revoked_then_used: list[SignInRecord] = field(default_factory=list)
    mfa_pattern: list[MfaEventRecord] = field(default_factory=list)
    privileged_roles: list[str] = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        return bool(self.indicators)

    def cite(self, records: Iterable[Any]) -> None:
        for record_id in _ids(records):
            if record_id not in self.record_ids:
                self.record_ids.append(record_id)


def _successes(user: _User) -> list[SignInRecord]:
    return sorted((s for s in user.signins.values() if s.result == "success"),
                  key=lambda s: (s.timestamp, s.record_id))


def _privileged_roles(user: _User) -> list[str]:
    roles: list[str] = []
    profile = user.profile
    if profile is not None:
        roles += [r for r in profile.roles if r.strip().lower() in PRIVILEGED_ROLE_NAMES]
    for record in user.activity.values():
        if isinstance(record, RoleChangeRecord) and record.privileged and record.change in ("assigned", "activated"):
            roles.append(record.role_name)
    return list(dict.fromkeys(roles))


def _assess(user: _User, ips: Mapping[str, _Ip]) -> _Assessment:
    found = _Assessment(user=user, privileged_roles=_privileged_roles(user))
    successes = _successes(user)
    profile = user.profile
    if profile is not None and (profile.risk_level == "high" or profile.risk_state == "confirmed_compromised"):
        state = "confirmed compromised" if profile.risk_state == "confirmed_compromised" else "high risk"
        found.indicators.append(f"identity provider rates the user {state}")
        found.cite([profile])
    for signin in successes:
        source = ips.get(_key(signin.ip)) if signin.ip else None
        if source is not None and source.flagged():
            found.attacker_signins.append(signin)
            if source.ip not in found.attacker_ips:
                found.attacker_ips.append(source.ip)
    if found.attacker_signins:
        found.indicators.append("successful sign-in from an IP rated malicious or suspicious ("
                                + ", ".join(found.attacker_ips) + ")")
        found.cite(found.attacker_signins)
        for ip in found.attacker_ips:
            found.cite(ips[ip].flagged_enrichment())
            found.cite(ips[ip].anomalies.values())
    risky = [s for s in successes if s.risk_level == "high"]
    if risky:
        found.indicators.append("successful sign-in rated high risk by the identity provider")
        found.cite(risky)
    strong = [a for a in user.anomalies.values()
              if a.anomaly_type in ATTACKER_ANOMALIES and a.severity in STRONG_SEVERITIES]
    if strong and successes:
        found.indicators.append("HIGH or CRITICAL risk detection ("
                                + ", ".join(sorted({a.anomaly_type for a in strong})) + ") with a successful sign-in")
        found.cite(strong)
        found.cite(successes[-1:])
    replay = [a for a in user.anomalies.values() if a.anomaly_type == "token_replay"]
    if replay:
        found.indicators.append("session token replay detected")
        found.cite(replay)
    _assess_mfa(found, successes)
    if found.compromised:
        _assess_revocation(found)
        found.cite(a for a in user.anomalies.values() if a.severity is not Severity.INFO)
        found.cite(_post_compromise_activity(user))
        if profile is not None:
            found.cite([profile])
    return found


def _assess_mfa(found: _Assessment, successes: Sequence[SignInRecord]) -> None:
    user = found.user
    events = sorted(user.mfa.values(), key=lambda m: (m.timestamp, m.record_id))
    denied = [m for m in events if m.result in ("denied", "fraud_reported")]
    approved = [m for m in events if m.result == "approved"]
    fatigue = [a for a in user.anomalies.values() if a.anomaly_type == "mfa_fatigue"]
    approved_after = [m for m in approved if sum(1 for d in denied if d.timestamp <= m.timestamp)
                      >= MFA_DENIALS_BEFORE_APPROVAL]
    if approved_after or (fatigue and successes):
        found.mfa_pattern = [*denied, *approved_after]
        found.indicators.append("MFA approved after repeated denied prompts" if approved_after
                                else "MFA fatigue detection followed by a successful sign-in")
        found.cite(fatigue)
        found.cite(found.mfa_pattern)
        found.cite(successes[-1:])


def _assess_revocation(found: _Assessment) -> None:
    """An attacker sign-in after the sessions were last revoked: the attacker holds working credentials."""
    profile = found.user.profile
    if profile is None or profile.sessions_valid_from is None:
        return
    later = [s for s in found.attacker_signins if s.timestamp > profile.sessions_valid_from]
    if later:
        found.revoked_then_used = later
        found.cite([profile, *later])


def _post_compromise_activity(user: _User) -> list[Any]:
    """Cloud activity of the account that matters after a takeover (cited as context, never alone)."""
    out: list[Any] = []
    for record in user.activity.values():
        if isinstance(record, MailboxRuleRecord) and (record.external_forwarding or record.delete):
            out.append(record)
        elif isinstance(record, RoleChangeRecord) and record.privileged and record.change in ("assigned", "activated"):
            out.append(record)
        elif isinstance(record, CloudAppRecord) and record.verdict in _FLAGGED:
            out.append(record)
    return out


def _user_fact(found: _Assessment) -> dict[str, Any]:
    user = found.user
    profile = user.profile
    disable_reasons: list[str] = []
    disable_ids: list[str] = []
    if found.compromised and found.privileged_roles:
        disable_reasons.append("privileged account (" + ", ".join(found.privileged_roles) + ")")
        disable_ids += found.record_ids
    if found.revoked_then_used:
        disable_reasons.append("attacker sign-in after the sessions were revoked")
        disable_ids += [r for r in found.record_ids if r not in disable_ids]
    groups = list(profile.groups) if profile is not None else []
    roles = list(dict.fromkeys([*(profile.roles if profile is not None else ()), *found.privileged_roles]))
    summary = (f"account {user.user}: " + "; ".join(found.indicators)) if found.indicators else ""
    return {
        "user": user.user,
        "compromised": found.compromised,
        "indicators": list(found.indicators),
        "summary": summary,
        "record_ids": list(found.record_ids),
        "attacker_ips": list(found.attacker_ips),
        "privileged": bool(found.privileged_roles) or bool(profile is not None and profile.privileged),
        "privileged_roles": list(found.privileged_roles),
        "groups": groups,
        "roles": roles,
        "disable_reasons": disable_reasons,
        "disable_summary": (f"account {user.user}: " + "; ".join(disable_reasons)) if disable_reasons else "",
        "disable_record_ids": disable_ids,
    }


# -------------------------------------------------------------------- IPs --
def _shared(ip: _Ip, investigated: set[str]) -> list[str]:
    """Record ids showing the IP is shared: seen from internal endpoints, or used by other accounts."""
    shown: list[str] = []
    for bundle in ip.prevalence:
        for record in bundle.records:
            if isinstance(record, NetworkConnectionRecord) and (record.endpoint or record.user):
                if record.endpoint or _key(record.user) not in investigated:
                    shown.append(record.record_id)
            elif isinstance(record, EndpointRecord):
                shown.append(record.record_id)
            elif isinstance(record, SignInRecord) and _key(record.user) not in investigated:
                shown.append(record.record_id)
    return list(dict.fromkeys(shown))


def _ip_facts(data: _View, compromised: set[str]) -> list[dict[str, Any]]:
    investigated = set(data.users)
    out: list[dict[str, Any]] = []
    for key in sorted(data.ips):
        ip = data.ips[key]
        signins = [s for u in data.users.values() for s in u.signins.values() if _key(s.ip) == key]
        mfa = [m for u in data.users.values() for m in u.mfa.values() if _key(m.ip) == key]
        if not signins and not mfa and not ip.anomalies:
            continue  # an IP no investigated account used is not an account-takeover source
        if not ip.flagged():
            continue
        users = sorted({s.user for s in signins} | {m.user for m in mfa})
        successes = [s for s in signins if s.result == "success" and s.user in compromised]
        record_ids = _ids([*sorted(signins, key=lambda s: (s.timestamp, s.record_id)),
                           *sorted(mfa, key=lambda m: (m.timestamp, m.record_id)), *ip.anomalies.values()])
        shared_ids = _shared(ip, investigated)
        shared = bool(shared_ids)
        out.append({
            "ip": key,
            "verdict": ip.verdict.value,
            "users": users,
            "compromised_users": sorted({s.user for s in successes}),
            "record_ids": record_ids,
            "shared": shared,
            "shared_record_ids": shared_ids,
            "block_worthy": ip.block_worthy(),
            "block_candidate": ip.block_worthy() and not shared,
            "summary": (f"IP {key} rated {ip.verdict.value}"
                        + (", named by a vendor attacker-IP detection" if ip.anomalies else "")
                        + f"; used against {', '.join(users)}"
                        + (f"; successful sign-in of compromised account(s) {', '.join(sorted({s.user for s in successes}))}"
                           if successes else "")),
        })
    return out


# --------------------------------------------------------------- endpoints --
def _endpoint_facts(data: _View, compromise_ids: Mapping[str, Sequence[str]],
                    unassessed: Mapping[str, Sequence[str]] | None = None) -> list[dict[str, Any]]:
    """Incident endpoints with an active MALICIOUS detection that this workflow recommends isolating.

    ``compromise_ids`` maps each compromised account to the record ids that prove its compromise. An
    endpoint of a compromised account cites its detection and endpoint records *and* those compromise
    records, so the "of compromised account" claim in the rationale is backed by numbered evidence.

    ``unassessed`` maps accounts whose identity reads lost a source (and that no surviving record
    shows compromised) to the failed integrations. An endpoint of such an account (or one that names
    no account while some account is unassessed) with an active MALICIOUS detection is still
    recommended on the detection alone, and the rationale says the account link could not be
    assessed: a failed identity source never silently drops an isolation another source backs.
    """
    compromised = set(compromise_ids)
    unassessed = dict(unassessed or {})
    out: list[dict[str, Any]] = []
    for host in sorted(set(data.endpoints) | set(data.detections)):
        records = data.endpoints.get(host, [])
        active = [d for d in data.detections.get(host, {}).values()
                  if d.verdict is Verdict.MALICIOUS and d.status != "resolved"]
        if not active:
            continue
        users = {_key(u) for r in records for u in r.users} | {_key(d.user) for d in active if d.user}
        users.discard("")
        linked = sorted(users & compromised)
        detections = ", ".join(sorted({d.name for d in active}))
        ips = [ip for r in records for ip in r.ip_addresses]
        fact = {
            "hostname": host,
            "groups": sorted({g for r in records for g in r.groups}),
            "tags": sorted({t for r in records for t in r.tags}),
            "ip": ips[0] if ips else None,
        }
        if linked:
            cited = _ids([*active, *records])
            for user in linked:
                cited += [i for i in compromise_ids[user] if i not in cited]
            out.append({**fact, "users": linked, "record_ids": cited, "identity_assessed": True,
                        "summary": (f"endpoint {host} of compromised account(s) {', '.join(linked)} has active "
                                    f"malicious detection(s) {detections}")})
            continue
        pending = sorted(users & set(unassessed)) if users else sorted(unassessed)
        if not pending:
            continue  # every account of the endpoint was assessed and none is compromised
        failed = sorted({name for user in pending for name in unassessed[user]})
        out.append({**fact, "users": pending, "record_ids": _ids([*active, *records]), "identity_assessed": False,
                    "summary": (f"endpoint {host} named by the incident has active malicious detection(s) "
                                f"{detections}; the compromise of account(s) {', '.join(pending)} could not be "
                                f"assessed because {', '.join(failed)} failed, so this isolation rests on the "
                                f"endpoint detection alone")})
    return out


# ------------------------------------------------------------------ hooks --
class AccountTakeoverHooks(WorkflowHooks):
    """Facts and derived authentication signals for the account-takeover rules."""

    def facts(self, view: RunView) -> Mapping[str, Any]:
        data = _collect(view)
        assessments = [_assess(data.users[u], data.ips) for u in sorted(data.users)]
        users = [_user_fact(a) for a in assessments]
        compromised = {u["user"] for u in users if u["compromised"]}
        ips = _ip_facts(data, compromised)
        compromise_ids = {u["user"]: u["record_ids"] for u in users if u["compromised"]}
        unassessed = {_key(subject): failed for subject, failed in failed_reads(view, _USER_ATOMICS).items()
                      if _key(subject) not in compromised}
        return {
            "users": users,
            "compromised_users": [u for u in users if u["compromised"]],
            "disable_users": [u for u in users if u["compromised"] and u["disable_reasons"]],
            "ips": ips,
            "block_ips": [i for i in ips if i["block_candidate"]],
            "shared_ips": [i["ip"] for i in ips if i["shared"]],
            "endpoints": _endpoint_facts(data, compromise_ids, unassessed),
        }

    def considered(self, view: RunView) -> Sequence[Consideration]:
        """Attacker-rated sign-in IPs not blocked because they are shared infrastructure, and rated IPs
        that no sign-in ties to an account because the identity reads failed (degraded source)."""
        ips = self.facts(view)["ips"]
        out = [Consideration(subject=f"block_ip:{i['ip']}",
                             reason=f"rated {i['verdict']} but shared (seen from internal endpoints or used by "
                                    "other accounts): not blocked",
                             record_ids=tuple(dict.fromkeys([*i["record_ids"], *i["shared_record_ids"]])))
               for i in ips if i["shared"] and i["block_worthy"]]
        failed = failed_reads(view, _USER_ATOMICS)
        if not failed:
            return out
        data = _collect(view)
        listed = {i["ip"] for i in ips}
        names = sorted({n for v in failed.values() for n in v})
        for key in sorted(data.ips):
            ip = data.ips[key]
            cited = _ids([*ip.flagged_enrichment(), *ip.anomalies.values()])
            if key in listed or not ip.block_worthy() or not cited:
                continue
            out.append(Consideration(
                subject=f"block_ip:{key}",
                reason=(f"rated {ip.verdict.value}, but no sign-in record of an investigated account ties it to the "
                        f"takeover: {', '.join(names)} failed for the identity reads of {', '.join(failed)}; not "
                        "blocked (re-run when the source recovers, or decide by hand)"),
                record_ids=tuple(cited)))
        return out

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        data = _collect(view)
        origin = view.origin
        signals: list[ScoringSignal] = []
        compromised: set[str] = set()
        for name in sorted(data.users):
            found = _assess(data.users[name], data.ips)
            if not found.compromised:
                continue
            compromised.add(name)
            subject = Observable(type=ObservableType.USER, value=name)
            signals += _user_signals(found, subject, data.ips, origin)
        for fact in _ip_facts(data, compromised):
            if not fact["block_candidate"]:
                continue
            signals += _ip_signals(fact, data, origin)
        return signals


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


def _user_signals(found: _Assessment, subject: Observable, ips: Mapping[str, _Ip],
                  origin: str) -> list[ScoringSignal]:
    out: list[ScoringSignal] = []
    if found.attacker_signins:
        sources = [ips[ip] for ip in found.attacker_ips]
        malicious = any(s.verdict is Verdict.MALICIOUS for s in sources)
        enrichment = [r for s in sources for r in s.flagged_enrichment()]
        for integration, signins in sorted(_by_integration(found.attacker_signins).items()):
            out.append(_signal(origin, integration, subject, Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS,
                               80 if malicious else 70, 75 if malicious else 65, [*signins, *enrichment],
                               "successful sign-in from an IP rated " + ("malicious" if malicious else "suspicious")))
    profile = found.user.profile
    if found.revoked_then_used and profile is not None:
        out.append(_signal(origin, profile.integration, subject, Verdict.MALICIOUS, 85, 80,
                           [profile, *found.revoked_then_used],
                           "attacker sign-in after the sessions were revoked"))
    if found.mfa_pattern:
        for integration, events in sorted(_by_integration(found.mfa_pattern).items()):
            out.append(_signal(origin, integration, subject, Verdict.SUSPICIOUS, 70, 70, events,
                               "MFA approved after repeated denied prompts"))
    return out


def _ip_signals(fact: Mapping[str, Any], data: _View, origin: str) -> list[ScoringSignal]:
    key = fact["ip"]
    subject = Observable(type=ObservableType.IPV6 if ":" in key else ObservableType.IP, value=key)
    ip = data.ips[key]
    signins = [s for u in data.users.values() for s in u.signins.values() if _key(s.ip) == key]
    if not signins:
        return []
    compromised_success = bool(fact["compromised_users"])
    malicious = compromised_success and ip.verdict is Verdict.MALICIOUS
    out: list[ScoringSignal] = []
    for integration, records in sorted(_by_integration(signins).items()):
        out.append(_signal(origin, integration, subject, Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS,
                           80 if malicious else (70 if compromised_success else 60), 70,
                           [*records, *ip.flagged_enrichment()],
                           "sign-in source of an investigated account"
                           + (" with a successful compromised sign-in" if compromised_success else "")))
    return out


HOOKS = AccountTakeoverHooks()
