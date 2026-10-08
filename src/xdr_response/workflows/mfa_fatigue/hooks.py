"""Hooks of the ``mfa-fatigue`` workflow (architecture 14.3.3): pure pattern analysis over records.

The hooks see only the run's records (no context, no adapters). They compute the MFA fatigue
pattern and expose it three ways, always citing the records it was computed from:

* ``facts()``: JSON values the recommendation rules read (compromised users, prompt source IPs,
  tied endpoints, rationale text);
* ``derive_signals()``: authentication-anomaly and network-behaviour signals about the user, the
  source IPs and tied endpoints (sign-in and MFA records produce no framework signal, 14.2.3);
* ``correlate()``: ``WORKFLOW`` links between a user and the IPs that prompted them, and between a
  compromised user and a tied endpoint.

Pattern (per user, thresholds below):

1. unsuccessful prompts: MFA events with result ``denied``, ``fraud_reported`` or ``timeout`` (or, only
   when a user has no MFA event record at all, sign-ins whose ``mfa_result`` is ``denied`` or
   ``timeout``);
2. an approval: the first MFA event with result ``approved`` (or sign-in with ``mfa_result``
   ``satisfied`` under the same fallback) preceded by at least :data:`MIN_UNSUCCESSFUL_PROMPTS`
   unsuccessful prompts within :data:`PROMPT_WINDOW`;
3. the suspicious login: successful sign-ins of that user from :data:`SIGN_IN_LEAD` before the
   approval to :data:`SIGN_IN_WINDOW` after it.

A user with step 2 is ``approved_after_prompts`` (compromised); with step 1 only (at least the
threshold, no qualifying approval) ``prompts_only``. Nothing here decides an approval level, builds
an action or calls a vendor: the rules turn facts into ``ProposedAction``s and a human approves.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.records import PRIVILEGED_ROLE_NAMES
from xdr_response.models import Observable, ObservableType, TargetKind, Verdict
from xdr_response.models.canonical import normalize_target
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Handoff, RunView, WorkflowHooks, failed_reads

__all__ = [
    "MIN_UNSUCCESSFUL_PROMPTS",
    "PROMPT_WINDOW",
    "SIGN_IN_LEAD",
    "SIGN_IN_WINDOW",
    "MAX_PROMPT_EVIDENCE",
    "MfaFatigueHooks",
    "HOOKS",
    "analyze",
]

#: Unsuccessful prompts (denied, fraud reported or timed out) needed before an approval counts.
MIN_UNSUCCESSFUL_PROMPTS = 3
#: Window before the approval in which the unsuccessful prompts must fall.
PROMPT_WINDOW = timedelta(minutes=60)
#: A successful sign-in may be logged slightly before the MFA approval it completed.
SIGN_IN_LEAD = timedelta(minutes=10)
#: Successful sign-ins up to this long after the approval are the suspicious login.
SIGN_IN_WINDOW = timedelta(minutes=60)
#: At most this many prompt records are cited per finding (the newest ones before the approval).
MAX_PROMPT_EVIDENCE = 20

_UNSUCCESSFUL_EVENT = frozenset({"denied", "fraud_reported", "timeout"})
_UNSUCCESSFUL_SIGN_IN = frozenset({"denied", "timeout"})
_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_GRANTING_ROLE_CHANGES = frozenset({"assigned", "activated", "eligible_assigned"})
#: Non-public ranges never proposed for an IP block (the documentation ranges stay blockable lab data).
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"))
_MIN_TIME = datetime.min.replace(tzinfo=timezone.utc)
#: Identity reads whose failure leaves a user's MFA activity unassessed.
_IDENTITY_ATOMICS = ("investigate_authentication", "investigate_user", "search_user_activity")


# ------------------------------------------------------------------ helpers --
def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _kind(record: Any) -> str:
    return str(record.kind)


_TIMESTAMPED = frozenset({"mfa_event", "sign_in", "process_event"})


def _when(record: Any) -> datetime:
    """The time a record describes (``_MIN_TIME`` when unknown, so it sorts first)."""
    kind = _kind(record)
    if kind in _TIMESTAMPED:
        return record.timestamp
    if kind == "anomaly":
        return record.first_seen or record.observed_at or _MIN_TIME
    return record.observed_at or _MIN_TIME


def _sorted(records: Iterable[Any]) -> list[Any]:
    return sorted(records, key=lambda r: (_when(r), r.record_id))


def _ids(records: Iterable[Any]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _norm(kind: TargetKind, value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    try:
        return normalize_target(kind, str(value))
    except ValueError:
        return None


def _is_internal(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True  # never propose a block for a value that is not an address
    # An IPv4-mapped spelling (``::ffff:10.0.0.5``) is the IPv4 host it carries.
    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    candidates = [address, *([mapped] if mapped is not None else [])]
    return any(candidate in network for candidate in candidates
               for network in _INTERNAL_NETWORKS if network.version == candidate.version)


def _ip_type(ip: str) -> ObservableType:
    return ObservableType.IPV6 if ":" in ip else ObservableType.IP


def _main_integration(records: Sequence[Any]) -> str:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.integration] = counts.get(record.integration, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


# ----------------------------------------------------------------- analysis --
@dataclass
class _User:
    user: str
    prompts: list[Any] = field(default_factory=list)  # unsuccessful prompt records, time order
    approvals: list[Any] = field(default_factory=list)
    sign_ins: list[Any] = field(default_factory=list)
    anomalies: list[Any] = field(default_factory=list)
    profiles: list[Any] = field(default_factory=list)
    approval: Any = None
    window_prompts: list[Any] = field(default_factory=list)
    login: list[Any] = field(default_factory=list)
    post_auth: list[tuple[Any, str]] = field(default_factory=list)  # (record, description)
    disable_reasons: list[str] = field(default_factory=list)
    disable_records: list[Any] = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        return self.approval is not None

    @property
    def pattern(self) -> str:
        if self.approval is not None:
            return "approved_after_prompts"
        if len(self.prompts) >= MIN_UNSUCCESSFUL_PROMPTS:
            return "prompts_only"
        return "none"

    def evidence(self) -> list[Any]:
        prompts = self.window_prompts if self.approval is not None else self.prompts
        cited = prompts[-MAX_PROMPT_EVIDENCE:]
        return [*cited, *([self.approval] if self.approval is not None else []), *self.login, *self.anomalies]

    def source_ips(self) -> list[str]:
        prompts = self.window_prompts if self.approval is not None else self.prompts
        return sorted({r.ip for r in prompts if r.ip})

    def login_ips(self) -> list[str]:
        return sorted({r.ip for r in self.login if r.ip})


@dataclass
class Analysis:
    """The pattern over one run's records (pure; no context)."""

    users: dict[str, _User]
    ips: dict[str, dict[str, Any]]
    endpoints: dict[str, dict[str, Any]]


def _user_entry(users: dict[str, _User], value: str | None) -> _User | None:
    user = _norm(TargetKind.USER, value)
    if user is None:
        return None
    return users.setdefault(user, _User(user=user))


def _collect(records: Sequence[Any]) -> dict[str, _User]:
    users: dict[str, _User] = {}
    events: dict[str, list[Any]] = {}
    sign_ins: dict[str, list[Any]] = {}
    for record in records:
        kind = _kind(record)
        if kind == "mfa_event":
            entry = _user_entry(users, record.user)
            if entry is not None:
                events.setdefault(entry.user, []).append(record)
        elif kind == "sign_in":
            entry = _user_entry(users, record.user)
            if entry is not None:
                sign_ins.setdefault(entry.user, []).append(record)
        elif kind == "anomaly" and record.anomaly_type == "mfa_fatigue":
            entry = _user_entry(users, record.user)
            if entry is not None:
                entry.anomalies.append(record)
        elif kind == "user_profile":
            entry = _user_entry(users, record.user)
            if entry is not None:
                entry.profiles.append(record)
    for user, entry in users.items():
        user_events = _sorted(events.get(user, []))
        user_sign_ins = _sorted(sign_ins.get(user, []))
        entry.sign_ins = user_sign_ins
        entry.anomalies = _sorted(entry.anomalies)
        if user_events:
            entry.prompts = [r for r in user_events if r.result in _UNSUCCESSFUL_EVENT]
            entry.approvals = [r for r in user_events if r.result == "approved"]
        else:  # fallback: MFA results carried by sign-in records (never both, so nothing is counted twice)
            entry.prompts = [r for r in user_sign_ins if r.mfa_result in _UNSUCCESSFUL_SIGN_IN]
            entry.approvals = [r for r in user_sign_ins if r.mfa_result == "satisfied" and r.result == "success"]
    return users


def _find_approval(entry: _User) -> None:
    for approval in entry.approvals:
        at = _when(approval)
        window = [p for p in entry.prompts if at - PROMPT_WINDOW <= _when(p) <= at]
        if len(window) >= MIN_UNSUCCESSFUL_PROMPTS:
            entry.approval = approval
            entry.window_prompts = window
            entry.login = [s for s in entry.sign_ins if s.result == "success"
                           and at - SIGN_IN_LEAD <= _when(s) <= at + SIGN_IN_WINDOW]
            return


def _post_auth(entry: _User, records: Sequence[Any]) -> None:
    """Persistence-like actions of the user after the approved prompt (known timestamps only)."""
    since = _when(entry.approval) - SIGN_IN_LEAD
    for record in records:
        kind = _kind(record)
        if kind == "mailbox_rule" and _norm(TargetKind.USER, record.mailbox) == entry.user:
            changed = record.modified_at or record.created_at
            risky = record.external_forwarding or record.delete or record.forward_to or record.redirect_to \
                or record.forward_as_attachment_to
            if changed is not None and changed >= since and risky:
                what = "forwards externally" if record.external_forwarding else (
                    "deletes messages" if record.delete else "forwards or redirects messages")
                entry.post_auth.append((record, f"mailbox rule '{record.name}' created or changed at "
                                                f"{_iso(changed)} {what}"))
        elif kind == "role_change" and _norm(TargetKind.USER, record.user) == entry.user:
            if record.timestamp is not None and record.timestamp >= since and record.change in _GRANTING_ROLE_CHANGES:
                entry.post_auth.append((record, f"role {record.role_name} {record.change} at {_iso(record.timestamp)}"))
        elif kind == "cloud_app" and _norm(TargetKind.USER, record.consented_by) == entry.user:
            when = record.created_at or record.credential_added_at
            if when is not None and when >= since:
                entry.post_auth.append((record, f"application {record.display_name or record.app_id} consented "
                                                f"at {_iso(when)}"))


def _disable_reasons(entry: _User) -> None:
    if entry.post_auth:
        entry.disable_reasons.append("post-authentication activity: " + "; ".join(d for _, d in entry.post_auth))
        entry.disable_records.extend(r for r, _ in entry.post_auth)
    for profile in entry.profiles:
        roles = sorted(r for r in profile.roles if r.lower() in PRIVILEGED_ROLE_NAMES)
        if profile.privileged or roles:
            text = ", ".join(roles) if roles else "the identity provider marks it privileged"
            entry.disable_reasons.append(f"privileged account ({text})")
            entry.disable_records.append(profile)
        if profile.risk_state == "confirmed_compromised" or profile.risk_level == "high":
            entry.disable_reasons.append(f"identity provider risk {profile.risk_level}, state {profile.risk_state}")
            entry.disable_records.append(profile)
        revoked_at = profile.sessions_valid_from
        if revoked_at is not None and revoked_at > _when(entry.approval):
            again = [s for s in entry.sign_ins if s.result == "success" and _when(s) > revoked_at
                     and s.ip in set(entry.source_ips()) | set(entry.login_ips())]
            if again:
                entry.disable_reasons.append(f"attacker sign-in again after sessions were revoked at "
                                             f"{_iso(revoked_at)}")
                entry.disable_records.extend([profile, *again])


def _user_summary(entry: _User) -> str:
    prompts = entry.window_prompts if entry.approval is not None else entry.prompts
    sources = ", ".join(entry.source_ips()) or "an unknown IP"
    text = (f"MFA fatigue against {entry.user}: {_plural(len(prompts), 'rejected or unanswered prompt')} "
            f"from {sources}")
    if entry.approval is None:
        return text + ", no prompt approved"
    text += f", then a prompt approved at {_iso(_when(entry.approval))}"
    if entry.login:
        text += f" and a successful sign-in from {', '.join(entry.login_ips()) or 'an unknown IP'}"
    else:
        text += " (no successful sign-in record in the window)"
    return text


def _ips(users: Mapping[str, _User]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in users.values():
        if entry.pattern == "none":
            continue
        prompts = entry.window_prompts if entry.approval is not None else entry.prompts
        for record in [*prompts, *([entry.approval] if entry.approval is not None else []), *entry.login]:
            ip = _norm(TargetKind.IP, record.ip)
            if ip is None:
                continue
            item = out.setdefault(ip, {"ip": ip, "unsuccessful": 0, "approved": False, "login": False,
                                       "users": [], "records": [], "compromise": False})
            if record in prompts:
                item["unsuccessful"] += 1
            if record is entry.approval:
                item["approved"] = True
            if record in entry.login:
                item["login"] = True
            if entry.user not in item["users"]:
                item["users"].append(entry.user)
            item["records"].append(record)
            item["compromise"] = item["compromise"] or entry.compromised
    return out


def _endpoints(records: Sequence[Any], compromised: set[str], attacker_ips: Mapping[str, Sequence[str]],
               unassessed: Mapping[str, Sequence[str]] | None = None) -> dict[str, dict[str, Any]]:
    """Endpoints tied to a compromised user or an attacker IP that show malicious activity.

    ``attacker_ips`` maps each prompt source IP of a compromise to the compromised users it targeted;
    every endpoint remembers which compromised users it is tied to (``linked``), so its facts can cite
    the compromise records. ``unassessed`` maps users whose identity reads lost a source (and that no
    surviving record shows compromised) to the failed integrations: an endpoint of such a user (or one
    that names no user) with an active MALICIOUS detection is kept on the detection alone
    (``fallback``), so an identity outage never silently drops the isolation.
    """
    unassessed = dict(unassessed or {})
    if not compromised and not unassessed:
        return {}
    found: dict[str, dict[str, Any]] = {}

    def entry(host: str | None) -> dict[str, Any] | None:
        name = _norm(TargetKind.ENDPOINT, host)
        if name is None:
            return None
        return found.setdefault(name, {"hostname": name, "tied": [], "bad": [], "reasons": [], "connections": [],
                                       "groups": [], "tags": [], "ip": None, "linked": [], "users": [],
                                       "active": []})

    def link(item: dict[str, Any], users: Iterable[str | None]) -> None:
        for user in users:
            if user and user not in item["linked"]:
                item["linked"].append(user)

    for record in records:
        kind = _kind(record)
        if kind == "endpoint":
            item = entry(record.hostname)
            if item is None:
                continue
            item["groups"] = sorted(set(item["groups"]) | set(record.groups))
            item["tags"] = sorted(set(item["tags"]) | set(record.tags))
            item["ip"] = item["ip"] or (record.ip_addresses[0] if record.ip_addresses else None)
            users = {u for u in (_norm(TargetKind.USER, u) for u in record.users) if u}
            item["users"] = sorted(set(item["users"]) | users)
            if users & compromised:
                item["tied"].append(record)
                item["reasons"].append("used by " + ", ".join(sorted(users & compromised)))
                link(item, sorted(users & compromised))
        elif kind in ("detection", "process_event"):
            item = entry(record.endpoint)
            if item is None or record.verdict not in _SUPPORTING:
                continue
            item["bad"].append(record)
            label = record.name if kind == "detection" else (record.process_name or "process")
            item["reasons"].append(f"{record.verdict.value} {kind.replace('_', ' ')} {label}")
            user = _norm(TargetKind.USER, record.user)
            if user:
                item["users"] = sorted(set(item["users"]) | {user})
            if kind == "detection" and record.verdict is Verdict.MALICIOUS and record.status != "resolved":
                item["active"].append(record)
            if user in compromised:
                item["tied"].append(record)
                link(item, [user])
        elif kind == "network_connection":
            item = entry(record.endpoint)
            remote = _norm(TargetKind.IP, record.remote_ip)
            if item is None or remote is None or remote not in attacker_ips:
                continue
            item["tied"].append(record)
            item["bad"].append(record)
            item["connections"].append(record)
            item["reasons"].append(f"connection to MFA prompt source {remote}")
            link(item, attacker_ips[remote])
    out: dict[str, dict[str, Any]] = {}
    for host, item in sorted(found.items()):
        if item["tied"] and item["bad"]:
            out[host] = item
            continue
        if not item["active"] or set(item["users"]) & compromised:
            continue
        pending = sorted(set(item["users"]) & set(unassessed)) if item["users"] else sorted(unassessed)
        if pending:
            item["fallback"] = {"users": pending,
                                "failed": sorted({name for user in pending for name in unassessed[user]})}
            out[host] = item
    return out


def analyze(view: RunView) -> Analysis:
    """The MFA fatigue pattern of one run (deterministic)."""
    records = sorted(view.index.records(), key=lambda r: r.record_id)  # input order never matters
    users = _collect(records)
    for entry in users.values():
        _find_approval(entry)
        if entry.compromised:
            _post_auth(entry, records)
            _disable_reasons(entry)
    ips = _ips(users)
    compromised = {u for u, e in users.items() if e.compromised}
    attacker_ips = {ip: [u for u in item["users"] if u in compromised]
                    for ip, item in ips.items() if item["compromise"]}
    unassessed: dict[str, list[str]] = {}
    for subject, failed in failed_reads(view, _IDENTITY_ATOMICS).items():
        user = _norm(TargetKind.USER, subject)
        if user is not None and user not in compromised:
            unassessed[user] = sorted(set(unassessed.get(user, [])) | set(failed))
    endpoints = _endpoints(records, compromised, attacker_ips, unassessed)
    return Analysis(users=dict(sorted(users.items())), ips=dict(sorted(ips.items())), endpoints=endpoints)


# -------------------------------------------------------------------- facts --
def _user_fact(entry: _User) -> dict[str, Any]:
    groups = sorted({g for p in entry.profiles for g in p.groups})
    # Roles granted after the approval count too: the account now holds them, so the critical-asset
    # policy sees them (never weaker than the account's current rights).
    granted = {r.role_name for r, _ in entry.post_auth if _kind(r) == "role_change"}
    roles = sorted({r for p in entry.profiles for r in p.roles} | granted)
    disable_ids = _ids(entry.disable_records)
    return {
        "user": entry.user,
        "pattern": entry.pattern,
        "compromised": entry.compromised,
        "unsuccessful_prompts": len(entry.window_prompts if entry.compromised else entry.prompts),
        "approved_at": _iso(_when(entry.approval)) if entry.approval is not None else None,
        "source_ips": entry.source_ips(),
        "login_ips": entry.login_ips(),
        "record_ids": _ids(entry.evidence()),
        "groups": groups,
        "roles": roles,
        "summary": _user_summary(entry),
        "disable_reasons": list(dict.fromkeys(entry.disable_reasons)),
        "disable_record_ids": disable_ids,
        "disable_summary": "; ".join(dict.fromkeys(entry.disable_reasons)),
    }


def _ip_fact(item: Mapping[str, Any]) -> dict[str, Any]:
    ip = item["ip"]
    users = ", ".join(item["users"])
    text = (f"{ip} sent {_plural(item['unsuccessful'], 'rejected or unanswered MFA prompt')} to {users}")
    if item["approved"]:
        text += "; a prompt from it was approved"
    if item["login"]:
        text += "; a successful sign-in followed from it"
    return {
        "ip": ip,
        "unsuccessful": item["unsuccessful"],
        "approved": item["approved"],
        "login": item["login"],
        "compromise": item["compromise"],
        "users": list(item["users"]),
        "internal": _is_internal(ip),
        "enrichment_key": f"{_ip_type(ip).value}:{ip}",
        "record_ids": _ids(item["records"]),
        "summary": text,
    }


def _endpoint_fact(item: Mapping[str, Any], users: Mapping[str, _User]) -> dict[str, Any]:
    """Isolation facts of one endpoint. A tied endpoint cites its own records *and* the compromise
    records (prompts, approval, sign-in, anomaly) of every compromised user it is tied to, so the
    "tied to the MFA fatigue compromise" claim is backed by numbered evidence."""
    base = {"hostname": item["hostname"], "groups": list(item["groups"]), "tags": list(item["tags"]),
            "ip": item["ip"]}
    fallback = item.get("fallback")
    if fallback is not None:
        names = ", ".join(sorted({d.name for d in item["active"]}))
        return {**base, "users": list(fallback["users"]), "identity_assessed": False,
                "record_ids": _ids(item["active"]),
                "summary": (f"endpoint {item['hostname']} named by the incident has active malicious detection(s) "
                            f"{names}; the MFA activity of {', '.join(fallback['users'])} could not be assessed "
                            f"because {', '.join(fallback['failed'])} failed, so this isolation rests on the "
                            "endpoint detection alone")}
    reasons = list(dict.fromkeys(item["reasons"]))
    linked = [u for u in item["linked"] if u in users]
    compromise = [r for u in linked for r in users[u].evidence()]
    return {
        **base,
        "users": linked,
        "identity_assessed": True,
        "record_ids": _ids([*item["bad"], *item["tied"], *compromise]),
        "summary": (f"endpoint {item['hostname']} tied to the MFA fatigue compromise"
                    + (f" of {', '.join(linked)}" if linked else "") + ": " + "; ".join(reasons)),
    }


def facts_of(analysis: Analysis) -> dict[str, Any]:
    users = [_user_fact(e) for e in analysis.users.values() if e.pattern != "none"]
    signin_ids: dict[str, list[str]] = {}
    for entry in analysis.users.values():
        for record in entry.login:
            ip = _norm(TargetKind.IP, record.ip)
            if ip is not None:
                signin_ids.setdefault(ip, [])
                signin_ids[ip] = list(dict.fromkeys([*signin_ids[ip], record.record_id,
                                                     *([entry.approval.record_id] if entry.approval else [])]))
    return {
        "min_unsuccessful_prompts": MIN_UNSUCCESSFUL_PROMPTS,
        "users": users,
        "compromised_users": [u for u in users if u["compromised"]],
        "source_ips": [_ip_fact(item) for item in analysis.ips.values()],
        "compromise_signin_ips": sorted(signin_ids),
        "signin_ids_by_ip": dict(sorted(signin_ids.items())),
        "endpoints": [_endpoint_fact(item, analysis.users) for item in analysis.endpoints.values()],
    }


# ------------------------------------------------------------------ signals --
def _signal(view: RunView, observable: Observable, records: Sequence[Any], *, category: SignalCategory,
            verdict: Verdict, severity: int, confidence: int, note: str) -> ScoringSignal | None:
    if not records:
        return None
    return ScoringSignal(category=category, integration=_main_integration(records), observable=observable,
                         verdict=verdict, severity=severity, confidence=confidence,
                         record_ids=tuple(_ids(records)), origin=view.origin, note=note[:300])


def signals_of(view: RunView, analysis: Analysis) -> list[ScoringSignal]:
    out: list[ScoringSignal | None] = []
    for entry in analysis.users.values():
        observable = Observable(type=ObservableType.USER, value=entry.user)
        if entry.compromised:
            records = [*entry.window_prompts[-MAX_PROMPT_EVIDENCE:], entry.approval, *entry.login]
            out.append(_signal(view, observable, records, category=SignalCategory.AUTHENTICATION_ANOMALY,
                               verdict=Verdict.MALICIOUS, severity=85 if entry.login else 75, confidence=75,
                               note="MFA prompt approved after repeated rejected or unanswered prompts"))
        elif entry.pattern == "prompts_only":
            out.append(_signal(view, observable, entry.prompts[-MAX_PROMPT_EVIDENCE:],
                               category=SignalCategory.AUTHENTICATION_ANOMALY, verdict=Verdict.SUSPICIOUS,
                               severity=60, confidence=70, note="repeated rejected or unanswered MFA prompts"))
    for ip, item in analysis.ips.items():
        observable = Observable(type=_ip_type(ip), value=ip)
        if item["compromise"]:
            out.append(_signal(view, observable, item["records"], category=SignalCategory.AUTHENTICATION_ANOMALY,
                               verdict=Verdict.MALICIOUS, severity=80, confidence=70,
                               note="source of an MFA fatigue sequence that ended in an approval"))
        elif item["unsuccessful"] >= MIN_UNSUCCESSFUL_PROMPTS:
            out.append(_signal(view, observable, item["records"], category=SignalCategory.AUTHENTICATION_ANOMALY,
                               verdict=Verdict.SUSPICIOUS, severity=60, confidence=70,
                               note="source of repeated rejected or unanswered MFA prompts"))
    for host, item in analysis.endpoints.items():
        if item["connections"]:
            out.append(_signal(view, Observable(type=ObservableType.HOSTNAME, value=host), item["connections"],
                               category=SignalCategory.NETWORK_BEHAVIOUR, verdict=Verdict.SUSPICIOUS,
                               severity=70, confidence=60, note="connection to an MFA prompt source"))
    return [s for s in out if s is not None]


# -------------------------------------------------------------------- links --
def _entity(kind: TargetKind, value: str) -> EntityRef:
    return EntityRef(kind=kind, value=normalize_target(kind, value))


def links_of(view: RunView, analysis: Analysis) -> list[CorrelationLink]:
    links: list[CorrelationLink] = []
    for entry in analysis.users.values():
        if entry.pattern == "none":
            continue
        prompts = entry.window_prompts if entry.compromised else entry.prompts
        for ip in entry.source_ips():
            cited = [r for r in [*prompts, *([entry.approval] if entry.approval else []), *entry.login]
                     if r.ip == ip]
            times = [_when(r) for r in cited if _when(r) != _MIN_TIME]
            links.append(CorrelationLink(
                kind=LinkKind.WORKFLOW, entities=(_entity(TargetKind.USER, entry.user), _entity(TargetKind.IP, ip)),
                record_ids=tuple(sorted(_ids(cited))), first_seen=min(times) if times else None,
                last_seen=max(times) if times else None, origin=view.origin,
                note=f"MFA prompts from {ip} to {entry.user} ({entry.pattern})"))
    compromised = [e for e in analysis.users.values() if e.compromised]
    for host, item in analysis.endpoints.items():
        if item.get("fallback") is not None:
            continue  # kept on its detection alone: no record ties it to a compromise
        for entry in compromised:
            if item["linked"] and entry.user not in item["linked"]:
                continue
            links.append(CorrelationLink(
                kind=LinkKind.WORKFLOW,
                entities=(_entity(TargetKind.USER, entry.user), _entity(TargetKind.ENDPOINT, host)),
                record_ids=tuple(sorted(_ids([*item["tied"], *item["bad"]]))), origin=view.origin,
                note=f"endpoint {host} tied to the MFA fatigue compromise of {entry.user}"))
    return links


class MfaFatigueHooks(WorkflowHooks):
    """Pattern facts, signals and links of the MFA fatigue workflow (pure, read-only)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return links_of(view, analyze(view))

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return signals_of(view, analyze(view))

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return facts_of(analyze(view))

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        """An approved fatigue prompt means the password is known: account-takeover reviews the account."""
        return [Handoff(workflow_id="account-takeover", subjects=(user["user"],),
                        reason="approved an MFA prompt after repeated rejected or unanswered prompts, so the "
                               "password is known to someone else; review the account's activity after the approval",
                        record_ids=tuple(user["record_ids"]))
                for user in facts_of(analyze(view))["compromised_users"]]


HOOKS = MfaFatigueHooks()
