"""Hooks of the password spray workflow: pure pattern logic over the run's typed records.

The hooks see a read-only :class:`RunView` (no context, no adapters). They compute

* ``facts["spray_sources"]``: one item per spray source address (the addresses the incident names,
  plus any address whose failed sign-ins hit at least ``SPRAY_MIN_ACCOUNTS`` targeted accounts) with
  its failed accounts, successes, reputation, internal sightings and the record ids that back it;
* ``facts["compromised_accounts"]``: one item per account with a successful sign-in from a spray
  source, with the suspicious activity that followed (``FOLLOW_ON_ANOMALIES``, a high Entra risk
  level) and the record ids that back it;
* behavioural ``authentication_anomaly`` signals for the spray pattern and for each spray success,
  each attributed to the integration whose sign-in records it cites.

Nothing here invents a fact: every item and signal cites records of the run, and a value that is
not in a record stays out. Workflow rules only select these facts; ``PackageBuilder`` and a human
decide everything after that.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from xdr_response.atomics.records import (
    AnomalyRecord,
    DnsQueryRecord,
    EndpointRecord,
    EnrichmentRecord,
    NetworkConnectionRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Observable, ObservableType, TargetKind, Verdict
from xdr_response.models.canonical import normalize_target
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks
from xdr_response.workflows.password_spray.definition import (
    FOLLOW_ON_ANOMALIES,
    PATTERN_SIGNAL_MIN_ACCOUNTS,
    SPRAY_MIN_ACCOUNTS,
)

__all__ = ["PasswordSprayHooks", "HOOKS", "spray_sources", "compromised_accounts"]

_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
#: Signal severities (0-100) of the derived authentication_anomaly signals.
_PATTERN_SEVERITY = 60          # failed sign-ins against PATTERN_SIGNAL_MIN_ACCOUNTS or more accounts
_WIDE_PATTERN_SEVERITY = 70     # ... against WIDE_PATTERN_ACCOUNTS or more accounts
_SUCCESS_SEVERITY = 80          # the spray succeeded from this address
_ACCOUNT_SEVERITY = 75          # an account signed in successfully from a spray source
_SIGNAL_CONFIDENCE = 70
WIDE_PATTERN_ACCOUNTS = 5


# ------------------------------------------------------------------ helpers --
def _ip(value: object) -> str | None:
    """Canonical address text (``normalize_target``: compressed, IPv4-mapped IPv6 unmapped, so
    ``::ffff:192.0.2.5`` and ``192.0.2.5`` are one source), or None when ``value`` is not an IP."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return normalize_target(TargetKind.IP, value.strip())
    except ValueError:
        return None


def _user(value: object) -> str | None:
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _records(view: RunView) -> list[Any]:
    """Every record of the run once (first copy wins), sorted by record id (input order never matters)."""
    seen: dict[str, Any] = {}
    for result in view.results:
        for record in result.records:
            seen.setdefault(record.record_id, record)
    return [seen[key] for key in sorted(seen)]


def _sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted({v for v in values if v})


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


@dataclass
class _Source:
    """Facts about one spray source address (private accumulator)."""

    ip: str
    named_by_incident: bool
    failed_users: set[str] = field(default_factory=set)
    success_users: set[str] = field(default_factory=set)
    signin_ids: list[str] = field(default_factory=list)
    failure_count: int = 0
    success_count: int = 0
    enrichment: list[EnrichmentRecord] = field(default_factory=list)
    sighting_endpoints: set[str] = field(default_factory=set)
    sighting_ids: list[str] = field(default_factory=list)
    internal_endpoint: str | None = None
    internal_ids: list[str] = field(default_factory=list)


# ------------------------------------------------------------- pattern logic --
def _incident_ips(view: RunView) -> list[str]:
    out: list[str] = []
    for observable in view.incident.observables:
        if observable.type in (ObservableType.IP, ObservableType.IPV6):
            ip = _ip(observable.value)
            if ip and ip not in out:
                out.append(ip)
    return out


def _sign_ins(records: Sequence[Any]) -> list[SignInRecord]:
    """Sign-in records in time order (record id breaks ties)."""
    return sorted((r for r in records if isinstance(r, SignInRecord)), key=lambda r: (r.timestamp, r.record_id))


def _collect_sources(view: RunView, records: Sequence[Any]) -> dict[str, _Source]:
    """Spray sources keyed by address: incident addresses plus wide failure patterns."""
    sign_ins = _sign_ins(records)
    failed_accounts: dict[str, set[str]] = {}
    for record in sign_ins:
        ip, user = _ip(record.ip), _user(record.user)
        if ip and user and record.result == "failure":
            failed_accounts.setdefault(ip, set()).add(user)
    named = _incident_ips(view)
    candidates = list(named) + sorted(ip for ip, users in failed_accounts.items()
                                      if ip not in named and len(users) >= SPRAY_MIN_ACCOUNTS)
    sources = {ip: _Source(ip=ip, named_by_incident=ip in named) for ip in candidates}
    for record in sign_ins:
        source = sources.get(_ip(record.ip) or "")
        user = _user(record.user)
        if source is None or user is None:
            continue
        if record.result == "failure":
            source.failed_users.add(user)
            source.failure_count += 1
            source.signin_ids.append(record.record_id)
        elif record.result == "success":
            source.success_users.add(user)
            source.success_count += 1
            source.signin_ids.append(record.record_id)
    for record in records:
        _attach_context(sources, record)
    return sources


def _attach_context(sources: Mapping[str, _Source], record: Any) -> None:
    """Reputation, internal sightings and internal-endpoint ownership of the spray sources."""
    if isinstance(record, EnrichmentRecord):
        if record.subject.type in (ObservableType.IP, ObservableType.IPV6):
            source = sources.get(_ip(record.subject.value) or "")
            if source is not None:
                source.enrichment.append(record)
        return
    if isinstance(record, (NetworkConnectionRecord, DnsQueryRecord)):
        remote = (record.remote_ip,) if isinstance(record, NetworkConnectionRecord) else record.response_ips
        for value in remote:
            source = sources.get(_ip(value) or "")
            if source is not None and record.endpoint:
                source.sighting_endpoints.add(record.endpoint)
                source.sighting_ids.append(record.record_id)
        return
    if isinstance(record, EndpointRecord):
        for value in record.ip_addresses:
            source = sources.get(_ip(value) or "")
            if source is not None:
                source.internal_endpoint = source.internal_endpoint or record.hostname
                source.internal_ids.append(record.record_id)


def _source_item(source: _Source) -> dict[str, Any]:
    verdicts = {r.integration: r.verdict.value for r in source.enrichment}
    supporting = [r.record_id for r in source.enrichment if r.verdict in _SUPPORTING]
    clean = sorted(r.integration for r in source.enrichment if r.verdict is Verdict.CLEAN)
    shared_reasons: list[str] = []
    if clean and not supporting:
        shared_reasons.append("rated CLEAN by " + ", ".join(clean))
    if source.sighting_endpoints:
        shared_reasons.append(f"{_plural(len(source.sighting_endpoints), 'internal endpoint')} talk to it")
    record_ids = list(dict.fromkeys([*source.signin_ids, *supporting]))
    reputation = ", ".join(f"{k} {v}" for k, v in sorted(verdicts.items())) or "no answer"
    summary = (f"spray source {source.ip}: {_plural(source.failure_count, 'failed sign-in')} against "
               f"{_plural(len(source.failed_users), 'account')}, {_plural(source.success_count, 'successful sign-in')}"
               f"; reputation: {reputation}")
    if not source.named_by_incident:
        summary += f"; not named by the incident (failed sign-ins against {SPRAY_MIN_ACCOUNTS}+ accounts)"
    return {
        "ip": source.ip,
        "named_by_incident": source.named_by_incident,
        "failed_accounts": sorted(source.failed_users),
        "success_accounts": sorted(source.success_users),
        "failure_count": source.failure_count,
        "success_count": source.success_count,
        "verdicts": verdicts,
        "internal_sightings": len(source.sighting_endpoints),
        "sighting_endpoints": sorted(source.sighting_endpoints),
        "sighting_record_ids": list(dict.fromkeys(source.sighting_ids)),
        "shared_infrastructure": bool(shared_reasons),
        "shared_reasons": shared_reasons,
        "internal_endpoint": source.internal_endpoint,
        "internal_record_ids": list(dict.fromkeys(source.internal_ids)),
        "record_ids": record_ids,
        "summary": summary,
    }


def spray_sources(view: RunView) -> list[dict[str, Any]]:
    """The ``facts["spray_sources"]`` items (incident addresses first, then wide patterns)."""
    return [_source_item(s) for s in _collect_sources(view, _records(view)).values()]


def _follow_on(user: str, records: Sequence[Any], success: Sequence[SignInRecord]) -> tuple[list[str], list[str]]:
    """(record ids, reasons) of suspicious activity on ``user`` that marks the spray success as abused."""
    ids: list[str] = []
    reasons: list[str] = []
    for record in records:
        if isinstance(record, AnomalyRecord) and _user(record.user) == user \
                and record.anomaly_type in FOLLOW_ON_ANOMALIES:
            ids.append(record.record_id)
            reasons.append(f"{record.anomaly_type} anomaly ({record.integration})")
        elif isinstance(record, UserProfileRecord) and _user(record.user) == user \
                and (record.risk_level == "high" or record.risk_state == "confirmed_compromised"):
            ids.append(record.record_id)
            reasons.append(f"account risk {record.risk_level}/{record.risk_state} ({record.integration})")
    for record in success:
        if record.risk_level == "high":
            ids.append(record.record_id)
            reasons.append(f"high-risk successful sign-in from {record.ip} ({record.integration})")
    return list(dict.fromkeys(ids)), list(dict.fromkeys(reasons))


def compromised_accounts(view: RunView) -> list[dict[str, Any]]:
    """The ``facts["compromised_accounts"]`` items: accounts the spray signed in to."""
    records = _records(view)
    sources = _collect_sources(view, records)
    sign_ins = _sign_ins(records)
    accounts: dict[str, dict[str, list[SignInRecord]]] = {}
    for record in sign_ins:
        user, ip = _user(record.user), _ip(record.ip)
        if user is None or ip not in sources:
            continue
        bucket = accounts.setdefault(user, {"success": [], "failure": []})
        if record.result in bucket:
            bucket[record.result].append(record)
    items: list[dict[str, Any]] = []
    for user in sorted(accounts):
        success = accounts[user]["success"]
        if not success:
            continue  # failed attempts alone never revoke or disable an account
        failure = accounts[user]["failure"]
        groups: list[str] = []
        roles: list[str] = []
        profile_ids: list[str] = []
        for record in records:
            if isinstance(record, UserProfileRecord) and _user(record.user) == user:
                groups.extend(record.groups)
                roles.extend(record.roles)
                profile_ids.append(record.record_id)
        follow_ids, reasons = _follow_on(user, records, success)
        success_ips = _sorted_unique(_ip(r.ip) or "" for r in success)
        summary = (f"{user}: {_plural(len(success), 'successful sign-in')} from spray source(s) "
                   f"{', '.join(success_ips)} after {_plural(len(failure), 'failed sign-in')} from spray sources")
        items.append({
            "user": user,
            "success_ips": success_ips,
            "success_count": len(success),
            "failure_count": len(failure),
            "groups": _sorted_unique(groups),
            "roles": _sorted_unique(roles),
            "profile_record_ids": profile_ids,
            "record_ids": list(dict.fromkeys(r.record_id for r in (*success, *failure))),
            "follow_on": bool(follow_ids),
            "follow_on_reasons": reasons,
            "follow_on_record_ids": follow_ids,
            "follow_on_summary": (summary + "; followed by " + "; ".join(reasons)) if reasons else summary,
            "summary": summary,
        })
    return items


# ------------------------------------------------------------------- signals --
def _by_integration(records: Iterable[SignInRecord]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for record in records:
        out.setdefault(record.integration, []).append(record.record_id)
    return out


def _observable(ip: str) -> Observable:
    return Observable(type=ObservableType.IPV6 if ":" in ip else ObservableType.IP, value=ip)


class PasswordSprayHooks(WorkflowHooks):
    """Spray-pattern facts and behavioural signals (pure; cites only records of the run)."""

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return {"spray_sources": spray_sources(view), "compromised_accounts": compromised_accounts(view)}

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        records = _records(view)
        sources = _collect_sources(view, records)
        sign_ins = _sign_ins(records)
        signals: list[ScoringSignal] = []
        for ip, source in sources.items():
            accounts = len(source.failed_users)
            if accounts < PATTERN_SIGNAL_MIN_ACCOUNTS and not (source.success_users and source.failed_users):
                continue  # one account failing from an address is not a spray pattern
            severity = _PATTERN_SEVERITY if accounts < WIDE_PATTERN_ACCOUNTS else _WIDE_PATTERN_SEVERITY
            if source.success_users:
                severity = _SUCCESS_SEVERITY
            cited = [r for r in sign_ins if _ip(r.ip) == ip and r.result in ("failure", "success")]
            note = (f"password spray from {ip}: failed sign-ins against {_plural(accounts, 'account')}, "
                    f"{_plural(len(source.success_users), 'account')} signed in")
            for integration, ids in sorted(_by_integration(cited).items()):
                signals.append(ScoringSignal(
                    category=SignalCategory.AUTHENTICATION_ANOMALY, integration=integration,
                    observable=_observable(ip), verdict=Verdict.SUSPICIOUS, severity=severity,
                    confidence=_SIGNAL_CONFIDENCE, record_ids=tuple(ids), origin=view.origin, note=note))
        for account in compromised_accounts(view):
            cited = [r for r in sign_ins if r.record_id in set(account["record_ids"])]
            note = f"successful sign-in from a spray source for {account['user']}"
            for integration, ids in sorted(_by_integration(cited).items()):
                signals.append(ScoringSignal(
                    category=SignalCategory.AUTHENTICATION_ANOMALY, integration=integration,
                    observable=Observable(type=ObservableType.USER, value=account["user"]),
                    verdict=Verdict.SUSPICIOUS, severity=_ACCOUNT_SEVERITY, confidence=_SIGNAL_CONFIDENCE,
                    record_ids=tuple(ids), origin=view.origin, note=note))
        return signals

    def considered(self, view: RunView) -> Sequence[Consideration]:
        """Spray sources deliberately not blocked (shared infrastructure or an internal endpoint)."""
        out: list[Consideration] = []
        for item in spray_sources(view):
            reasons = list(item["shared_reasons"])
            if item["internal_endpoint"]:
                reasons.append(f"it is the address of internal endpoint {item['internal_endpoint']}")
            if not reasons:
                continue
            cited = tuple(dict.fromkeys([*item["record_ids"], *item["sighting_record_ids"],
                                         *item["internal_record_ids"]]))
            if cited:
                out.append(Consideration(subject=f"block_ip:{item['ip']}", record_ids=cited,
                                         reason="spray source not blocked: " + "; ".join(reasons)))
        return out

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        """Accounts the spray signed in to: account-takeover reviews what happened after the sign-in."""
        return [Handoff(workflow_id="account-takeover", subjects=(account["user"],),
                        reason="signed in successfully from a password spray source; review the account's "
                               "activity after the sign-in",
                        record_ids=tuple(account["record_ids"])) for account in compromised_accounts(view)]


HOOKS = PasswordSprayHooks()
