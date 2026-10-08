"""Pure hooks of the cloud-compromise workflow (architecture 14.3.3).

The hooks read the run's records (a :class:`RunView`: no context, no adapters) and compute:

* ``facts`` for the recommendation rules:

  - ``users``: every investigated account with its compromise indicators (identity-provider risk,
    successful sign-ins from IPs rated malicious or suspicious, high-risk sign-ins, strong risk
    detections, token replay, Defender XDR cloud alerts), whether it is privileged, and the cloud
    persistence it planted (privileged roles granted, application credentials added, tenant-wide
    consents to risky applications);
  - ``revoke_users``: compromised accounts and accounts that consented (user consent) to a risky OAuth
    application; ``disable_users``: accounts with a *strong* compromise indicator that are privileged
    or planted cloud persistence;
  - ``remove_roles``: privileged directory role assignments granted by or to a compromised account and
    not removed since (target ``<user>/<roleDefinitionId>``). A grant dated more than
    :data:`PRE_COMPROMISE_GRACE` before every dated compromise record of that account predates the
    compromise and is considered, not proposed (14.12.7);
  - ``apps``: risky applications (rated by a vendor, or credentialed, created or consented by a
    compromised account);
  - ``block_ips``: sign-in source IPs rated malicious (or suspicious and used by a high-risk account)
    that are not shared infrastructure.

* ``considered``: withheld actions (a shared attacker IP, a privileged grant between accounts with no
  compromise indicator, an admin consent by an uncompromised administrator, an uncompromised account
  that added a credential) and **manual steps** for application credentials, OAuth consents and service
  principals, which have no VERIFIED write.
* ``handoffs``: compromised accounts to ``account-takeover`` for the broader account review.
* ``derive_signals``: signals computed from cited records only.

Nothing here calls a vendor, writes anything, chooses an approval level or invents a fact: every
account, application, role and IP in the facts comes from a record, and every record id a fact,
signal, consideration or hand-off cites is an id of the run (the runner checks it again).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
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
    NetworkConnectionRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = [
    "CloudCompromiseHooks",
    "HOOKS",
    "ATTACKER_ANOMALIES",
    "ATTACKER_IP_ANOMALIES",
    "GRANTED_CHANGES",
    "HIGH_RISK_PERMISSIONS",
    "PRE_COMPROMISE_GRACE",
    "STRONG_SEVERITIES",
]

#: Vendor risk detections that name attacker infrastructure for the IP they carry.
ATTACKER_IP_ANOMALIES: frozenset[str] = frozenset({"anonymous_ip", "malicious_ip"})
#: Vendor risk detection types that indicate a compromise when HIGH or CRITICAL and a sign-in succeeded.
ATTACKER_ANOMALIES: frozenset[str] = frozenset({
    "impossible_travel", "unfamiliar_location", "new_device", "anonymous_ip", "malicious_ip",
    "token_replay", "leaked_credentials", "atypical_volume", "other",
})
STRONG_SEVERITIES: frozenset[Severity] = frozenset({Severity.HIGH, Severity.CRITICAL})
#: Role changes that give the account the role (a later ``removed`` change undoes them).
GRANTED_CHANGES: frozenset[str] = frozenset({"assigned", "activated", "eligible_assigned"})
#: A privileged grant made more than this long before the earliest dated compromise record of the
#: account that ties it to the incident (its actor, or its grantee) predates the compromise: it is a
#: pre-existing assignment the incident did not create, shown as considered and never proposed for
#: removal (14.12.7). The grace is the correlation window (``sign_in_to_activity``, 1440 minutes): a
#: risk detection or alert can be dated a little after the activity it is about.
PRE_COMPROMISE_GRACE = timedelta(hours=24)
#: OAuth permissions (lower case) that give an application broad read or write access to tenant data.
HIGH_RISK_PERMISSIONS: frozenset[str] = frozenset({
    "mail.read", "mail.readwrite", "mail.send", "mailboxsettings.readwrite", "files.read.all",
    "files.readwrite.all", "sites.read.all", "sites.readwrite.all", "directory.readwrite.all",
    "application.readwrite.all", "approleassignment.readwrite.all", "rolemanagement.readwrite.directory",
    "user.readwrite.all", "full_access_as_app", "full_access_as_user", "offline_access",
})

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_USER_TYPES = frozenset({ObservableType.USER, ObservableType.EMAIL_ADDRESS})
_IP_TYPES = frozenset({ObservableType.IP, ObservableType.IPV6})
_USER_ATOMICS = frozenset({"investigate_user", "investigate_authentication", "search_user_activity",
                           "search_related_users"})
_REVOCATION_NOTE = "revocation also invalidates the refresh tokens issued to applications for the account"


def _ids(records: Iterable[Any]) -> list[str]:
    """Record ids in first-seen order, without duplicates."""
    return list(dict.fromkeys(r.record_id for r in records))


def _key(value: str | None) -> str:
    return (value or "").strip().lower()


def _merge_ids(*groups: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(i for group in groups for i in group))


# ------------------------------------------------------------------ records --
@dataclass
class _User:
    """Everything the run learned about one account (records only)."""

    user: str
    profiles: dict[str, UserProfileRecord] = field(default_factory=dict)
    signins: dict[str, SignInRecord] = field(default_factory=dict)
    anomalies: dict[str, AnomalyRecord] = field(default_factory=dict)
    alerts: dict[str, DetectionRecord] = field(default_factory=dict)

    @property
    def profile(self) -> UserProfileRecord | None:
        return next(iter(self.profiles.values()), None)


@dataclass
class _App:
    """One application (``app_id``) and the accounts whose activity shows it."""

    app_id: str
    records: dict[str, CloudAppRecord] = field(default_factory=dict)
    owners: dict[str, list[CloudAppRecord]] = field(default_factory=dict)  # account -> its records of the app

    @property
    def name(self) -> str:
        names = [r.display_name for r in self.records.values() if r.display_name]
        return names[0] if names else self.app_id

    def flagged(self) -> list[CloudAppRecord]:
        return [r for r in self.records.values() if r.verdict in _FLAGGED]

    def unverified(self) -> bool:
        return any(r.publisher_verified is False for r in self.records.values())

    def risky_permissions(self) -> list[str]:
        perms = {p for r in self.records.values() for p in r.permissions if p.strip().lower() in HIGH_RISK_PERMISSIONS}
        return sorted(perms, key=str.lower)

    def credentialed(self) -> list[CloudAppRecord]:
        return [r for r in self.records.values() if r.credential_added_at is not None]


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
        if self.report is None:
            return []
        return [r for r in self.report.enrichment_records() if r.verdict in _FLAGGED]

    def any_malicious(self) -> bool:
        return any(r.verdict is Verdict.MALICIOUS for r in self.flagged_enrichment())

    def flagged(self) -> bool:
        return self.verdict in _FLAGGED or bool(self.flagged_enrichment()) or bool(self.anomalies)

    def strong(self) -> bool:
        """At least one source rates it MALICIOUS, or a HIGH/CRITICAL vendor attacker-IP detection names it."""
        if self.verdict is Verdict.CLEAN and not self.anomalies:
            return False
        return self.any_malicious() or any(a.severity in STRONG_SEVERITIES for a in self.anomalies.values())


@dataclass
class _Data:
    users: dict[str, _User] = field(default_factory=dict)
    ips: dict[str, _Ip] = field(default_factory=dict)
    apps: dict[str, _App] = field(default_factory=dict)
    roles: dict[str, RoleChangeRecord] = field(default_factory=dict)

    def user(self, value: str) -> _User:
        key = _key(value)
        return self.users.setdefault(key, _User(user=key))

    def ip(self, value: str) -> _Ip:
        key = _key(value)
        return self.ips.setdefault(key, _Ip(ip=key))


def _collect(view: RunView) -> _Data:
    out = _Data()
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
        subject_user = (_key(result.subject.value) if result.atomic in _USER_ATOMICS
                        and result.subject.type in _USER_TYPES else None)
        if subject_user:
            out.user(subject_user)
        for record in result.records:
            _collect_record(out, record, subject_user)
    return out


def _collect_record(out: _Data, record: Any, subject_user: str | None) -> None:
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
    elif isinstance(record, DetectionRecord) and record.endpoint is None:
        owner = record.user or subject_user  # a cloud alert (no endpoint) about the account
        if owner:
            out.user(owner).alerts.setdefault(record.record_id, record)
    elif isinstance(record, RoleChangeRecord):
        out.roles.setdefault(record.record_id, record)
    elif isinstance(record, CloudAppRecord):
        app = out.apps.setdefault(record.app_id, _App(app_id=record.app_id))
        app.records.setdefault(record.record_id, record)
        owner = _key(record.consented_by) or subject_user
        if owner:
            mine = app.owners.setdefault(owner, [])
            if record not in mine:
                mine.append(record)


# ------------------------------------------------------------- assessment --
@dataclass
class _Assessment:
    """Why one account looks compromised, with the records behind every reason."""

    user: _User
    indicators: list[str] = field(default_factory=list)
    strong: bool = False
    record_ids: list[str] = field(default_factory=list)
    attacker_signins: list[SignInRecord] = field(default_factory=list)
    attacker_ips: list[str] = field(default_factory=list)
    #: Dated records behind the indicators (sign-ins, risk detections, alerts); a profile rating has no date.
    dated: list[tuple[datetime, str]] = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        return bool(self.indicators)

    @property
    def since(self) -> tuple[datetime, str] | None:
        """``(time, record_id)`` of the earliest dated record behind an indicator, else ``None``."""
        return min(self.dated) if self.dated else None

    def add(self, text: str, records: Iterable[Any], *, strong: bool) -> None:
        records = list(records)
        self.indicators.append(text)
        self.strong = self.strong or strong
        self.cite(records)
        for record in records:
            when = _event_time(record)
            if when is not None:
                self.dated.append((when, record.record_id))

    def cite(self, records: Iterable[Any]) -> None:
        for record_id in _ids(records):
            if record_id not in self.record_ids:
                self.record_ids.append(record_id)


def _event_time(record: Any) -> datetime | None:
    """When the activity a compromise record reports happened (never the collection time)."""
    if isinstance(record, SignInRecord):
        return record.timestamp
    if isinstance(record, (AnomalyRecord, DetectionRecord)):
        return record.first_seen or record.last_seen
    return None


def _successes(user: _User) -> list[SignInRecord]:
    return sorted((s for s in user.signins.values() if s.result == "success"),
                  key=lambda s: (s.timestamp, s.record_id))


def _assess(user: _User, ips: Mapping[str, _Ip]) -> _Assessment:
    found = _Assessment(user=user)
    successes = _successes(user)
    profile = user.profile
    if profile is not None and (profile.risk_level == "high" or profile.risk_state == "confirmed_compromised"):
        state = "confirmed compromised" if profile.risk_state == "confirmed_compromised" else "high risk"
        found.add(f"identity provider rates the account {state}", [profile], strong=True)
    for signin in successes:
        source = ips.get(_key(signin.ip)) if signin.ip else None
        if source is not None and source.flagged():
            found.attacker_signins.append(signin)
            if source.ip not in found.attacker_ips:
                found.attacker_ips.append(source.ip)
    if found.attacker_signins:
        sources = [ips[ip] for ip in found.attacker_ips]
        strong = any(s.strong() for s in sources)
        found.add("successful sign-in from an IP rated " + ("malicious" if strong else "suspicious")
                  + " (" + ", ".join(found.attacker_ips) + ")", found.attacker_signins, strong=strong)
        for source in sources:
            found.cite(source.flagged_enrichment())
            found.cite(source.anomalies.values())
    risky = [s for s in successes if s.risk_level == "high"]
    if risky:
        found.add("successful sign-in rated high risk by the identity provider", risky, strong=True)
    strong_anomalies = [a for a in user.anomalies.values()
                        if a.anomaly_type in ATTACKER_ANOMALIES and a.severity in STRONG_SEVERITIES]
    if strong_anomalies and successes:
        found.add("HIGH or CRITICAL risk detection (" + ", ".join(sorted({a.anomaly_type for a in strong_anomalies}))
                  + ") with a successful sign-in", [*strong_anomalies, *successes[-1:]], strong=True)
    replay = [a for a in user.anomalies.values() if a.anomaly_type == "token_replay"]
    if replay:
        found.add("session token replay detected", replay, strong=True)
    if (profile is not None and profile.risk_level == "medium" and user.anomalies
            and not found.compromised):
        found.add("identity provider rates the account medium risk with risk detections ("
                  + ", ".join(sorted({a.anomaly_type for a in user.anomalies.values()})) + ")",
                  [profile, *user.anomalies.values()], strong=False)
    _assess_alerts(found, user)
    if found.compromised:
        found.cite(a for a in user.anomalies.values() if a.severity is not Severity.INFO)
        if profile is not None:
            found.cite([profile])
    return found


def _assess_alerts(found: _Assessment, user: _User) -> None:
    """Defender XDR cloud alerts about the account (no endpoint): active and rated, or unclassified HIGH."""
    active = [d for d in user.alerts.values() if d.status != "resolved"]
    malicious = [d for d in active if d.verdict is Verdict.MALICIOUS]
    if malicious:
        found.add("cloud alert rated malicious (" + ", ".join(sorted({d.name for d in malicious})) + ")",
                  malicious, strong=True)
    suspicious = [d for d in active if d.verdict is Verdict.SUSPICIOUS and d.severity in STRONG_SEVERITIES]
    if suspicious:
        found.add("unresolved HIGH cloud alert (" + ", ".join(sorted({d.name for d in suspicious})) + ")",
                  suspicious, strong=False)


def _privileged_roles(user: _User, roles: Iterable[RoleChangeRecord]) -> list[str]:
    out: list[str] = []
    profile = user.profile
    if profile is not None:
        out += [r for r in profile.roles if r.strip().lower() in PRIVILEGED_ROLE_NAMES]
    out += [r.role_name for r in roles if _key(r.user) == user.user and r.privileged and r.change in GRANTED_CHANGES]
    return list(dict.fromkeys(out))


# ------------------------------------------------------------------- apps --
def _app_risk(app: _App, compromised: set[str]) -> tuple[list[str], list[str]]:
    """Reasons an application is risky, and the record ids that show them (both empty when it is not)."""
    reasons: list[str] = []
    ids: list[str] = []
    flagged = app.flagged()
    if flagged:
        verdicts = sorted({r.verdict.value for r in flagged})
        reasons.append("rated " + " / ".join(verdicts) + " by " + ", ".join(sorted({r.integration for r in flagged})))
        ids += _ids(flagged)
    for owner in sorted(app.owners):
        if owner not in compromised:
            continue
        mine = app.owners[owner]
        added = [r for r in mine if r.credential_added_at is not None]
        if added:
            reasons.append(f"credential added by compromised account {owner}")
            ids += _ids(added)
        created = [r for r in mine if r.created_at is not None and r.credential_added_at is None
                   and r.consent_type == "unknown"]
        if created:
            reasons.append(f"registered or changed by compromised account {owner}")
            ids += _ids(created)
        consents = [r for r in mine if r.consent_type != "unknown" and r.publisher_verified is not True]
        if consents:
            reasons.append(f"consent granted by compromised account {owner} to an unverified publisher")
            ids += _ids(consents)
    return reasons, list(dict.fromkeys(ids))


def _app_fact(app: _App, compromised: set[str]) -> dict[str, Any]:
    reasons, ids = _app_risk(app, compromised)
    consents = {owner: [r for r in records if r.consent_type != "unknown"] for owner, records in app.owners.items()}
    user_consents = sorted(o for o, rs in consents.items() if any(r.consent_type == "user" for r in rs))
    admin_consents = sorted(o for o, rs in consents.items() if any(r.consent_type == "admin" for r in rs))
    credential_actors = sorted(o for o, rs in app.owners.items() if any(r.credential_added_at for r in rs))
    return {
        "app_id": app.app_id,
        "name": app.name,
        "risky": bool(reasons),
        "reasons": reasons,
        "record_ids": ids or _ids(app.records.values()),
        "all_record_ids": _ids(app.records.values()),
        "unverified": app.unverified(),
        "risky_permissions": app.risky_permissions(),
        "credentialed": bool(app.credentialed()),
        "consented": bool(user_consents or admin_consents),
        "user_consents": user_consents,
        "admin_consents": admin_consents,
        "credential_actors": credential_actors,
    }


def _owner_records(app: _App, owner: str, *, consent: str | None = None, credential: bool = False) -> list[str]:
    records = app.owners.get(owner, [])
    if consent is not None:
        records = [r for r in records if r.consent_type == consent]
    if credential:
        records = [r for r in records if r.credential_added_at is not None]
    return _ids(records)


# ------------------------------------------------------------------ roles --
def _still_granted(change: RoleChangeRecord, roles: Iterable[RoleChangeRecord]) -> bool:
    """False when a later ``removed`` change of the same account and role undoes the grant."""
    for other in roles:
        if other.change != "removed" or _key(other.user) != _key(change.user):
            continue
        if other.role_name.strip().lower() != change.role_name.strip().lower():
            continue
        if change.timestamp is None or other.timestamp is None or other.timestamp >= change.timestamp:
            return False
    return True


def _role_facts(data: _Data, assessed: Mapping[str, _Assessment]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(role removals to recommend, privileged grants considered and not recommended)."""
    remove: list[dict[str, Any]] = []
    withheld: list[dict[str, Any]] = []
    roles = sorted(data.roles.values(), key=lambda r: (_key(r.user), r.role_name.lower(), str(r.timestamp),
                                                       r.record_id))
    seen: set[str] = set()
    for change in roles:
        if not (change.privileged and change.change in GRANTED_CHANGES and _still_granted(change, roles)):
            continue
        grantee, actor = _key(change.user), _key(change.actor)
        grantee_found = assessed.get(grantee)
        actor_found = assessed.get(actor) if actor else None
        why: list[str] = []
        ids = [change.record_id]
        before: list[str] = []
        if actor_found is not None and actor_found.compromised:
            ids += actor_found.record_ids
            if _predates(change, actor_found):
                before.append(_predates_text(actor, actor_found))
            else:
                why.append(f"granted by compromised account {actor}")
                if grantee == actor:
                    why.append(f"self-assigned by compromised account {grantee}")
        if grantee_found is not None and grantee_found.compromised and grantee != actor:
            ids += grantee_found.record_ids
            if _predates(change, grantee_found):
                before.append(_predates_text(grantee, grantee_found))
            else:
                why.append(f"received by compromised account {grantee}")
        if why:
            before = []  # tied to the incident through an account: proposed, and only that is claimed
        subject = change.target or f"{grantee}/{change.role_name}"
        profile = data.users[grantee].profile if grantee in data.users else None
        fact = {
            "target": change.target,
            "subject": subject,
            "user": grantee,
            "role_name": change.role_name,
            # The scope the grant was made at, so the adapter removes exactly that assignment ("" = the
            # role's only assignment; several scopes are refused by the adapter, 14.12.3).
            "directory_scope_id": change.directory_scope_id or "",
            "actor": actor or None,
            "record_ids": _merge_ids(ids),
            "groups": list(profile.groups) if profile is not None else [],
            "roles": list(dict.fromkeys([change.role_name, *(profile.roles if profile is not None else ())])),
            "summary": (f"privileged role {change.role_name} assigned to {grantee}"
                        + (f" by {actor}" if actor else "") + ": " + "; ".join(why)) if why else "",
            # Why a grant tied to a compromised account is still not proposed: it predates the compromise.
            "predates": "; ".join(before),
        }
        if subject in seen:
            continue
        seen.add(subject)
        (remove if why else withheld).append(fact)
    return remove, withheld


def _predates(change: RoleChangeRecord, found: _Assessment) -> bool:
    """True when the grant is dated more than :data:`PRE_COMPROMISE_GRACE` before the account's earliest
    dated compromise record (14.12.7). An undated grant, or an account whose compromise has no dated
    record (a profile rating only), cannot be placed before the compromise: False (nothing is withheld on
    a guess)."""
    since = found.since
    if change.timestamp is None or since is None:
        return False
    return change.timestamp < since[0] - PRE_COMPROMISE_GRACE


def _predates_text(account: str, found: _Assessment) -> str:
    since = found.since
    when = since[0].isoformat() if since is not None else "unknown"
    return f"made before the earliest compromise record of {account} ({when})"


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


def _high_risk(user: _User) -> bool:
    profile = user.profile
    return profile is not None and (profile.risk_level == "high" or profile.risk_state == "confirmed_compromised")


def _ip_facts(data: _Data, compromised: set[str]) -> list[dict[str, Any]]:
    investigated = set(data.users)
    out: list[dict[str, Any]] = []
    for key in sorted(data.ips):
        ip = data.ips[key]
        signins = sorted((s for u in data.users.values() for s in u.signins.values() if _key(s.ip) == key),
                         key=lambda s: (s.timestamp, s.record_id))
        if not signins and not ip.anomalies:
            continue  # an IP no investigated account used is not a cloud-compromise source
        if not ip.flagged():
            continue
        users = sorted({s.user for s in signins})
        successes = [s for s in signins if s.result == "success"]
        high_risk_success = [s for s in successes if _high_risk(data.users[_key(s.user)])]
        worthy = ip.strong() or (ip.verdict in _FLAGGED and bool(high_risk_success))
        shared_ids = _shared(ip, investigated)
        record_ids = _ids([*signins, *ip.anomalies.values()])
        compromised_users = sorted({s.user for s in successes if _key(s.user) in compromised})
        out.append({
            "ip": key,
            "verdict": ip.verdict.value,
            "users": users,
            "compromised_users": compromised_users,
            "record_ids": record_ids,
            "shared": bool(shared_ids),
            "shared_record_ids": shared_ids,
            "block_worthy": worthy,
            "block_candidate": worthy and not shared_ids,
            "summary": (f"sign-in source IP {key} rated {ip.verdict.value}"
                        + (", named by a vendor attacker-IP detection" if ip.anomalies else "")
                        + f"; used against {', '.join(users) or 'an investigated account'}"
                        + (f"; successful sign-in of compromised account(s) {', '.join(compromised_users)}"
                           if compromised_users else "")),
        })
    return out


# ------------------------------------------------------------------ facts --
def _user_fact(found: _Assessment, data: _Data, apps: Mapping[str, dict[str, Any]],
               app_objs: Mapping[str, _App]) -> dict[str, Any]:
    user = found.user
    profile = user.profile
    privileged_roles = _privileged_roles(user, data.roles.values())
    privileged = bool(privileged_roles) or bool(profile is not None and profile.privileged)
    revoke_reasons = list(found.indicators)
    revoke_ids = list(found.record_ids)
    consented = [a for a in apps.values() if a["risky"] and user.user in a["user_consents"]]
    for app in consented:
        revoke_reasons.append(f"consented to risky OAuth application '{app['name']}' ({'; '.join(app['reasons'])})")
        revoke_ids = _merge_ids(revoke_ids, _owner_records(app_objs[app["app_id"]], user.user, consent="user"),
                                app["record_ids"])
    if consented and profile is not None:
        revoke_ids = _merge_ids(revoke_ids, [profile.record_id])
    # Persistence this account planted while compromised.
    planted: list[str] = []
    planted_ids: list[str] = []
    for change in sorted(data.roles.values(), key=lambda r: r.record_id):
        if (_key(change.actor) == user.user and change.privileged and change.change in GRANTED_CHANGES
                and _key(change.user) != user.user):
            planted.append(f"granted privileged role {change.role_name} to {_key(change.user)}")
            planted_ids.append(change.record_id)
    for app_id in sorted(app_objs):
        obj = app_objs[app_id]
        fact = apps[app_id]
        cred = _owner_records(obj, user.user, credential=True)
        if cred:
            planted.append(f"added a credential to application '{fact['name']}'")
            planted_ids += cred
        if fact["risky"] and user.user in fact["admin_consents"]:
            planted.append(f"granted tenant-wide consent to risky application '{fact['name']}'")
            planted_ids += _owner_records(obj, user.user, consent="admin")
    disable_reasons: list[str] = []
    disable_ids: list[str] = []
    if found.compromised and found.strong:
        if privileged:
            disable_reasons.append("privileged account (" + ", ".join(privileged_roles or ["privileged"]) + ")")
        disable_reasons += planted
        if disable_reasons:
            disable_ids = _merge_ids(found.record_ids, planted_ids)
    groups = list(profile.groups) if profile is not None else []
    roles = list(dict.fromkeys([*(profile.roles if profile is not None else ()), *privileged_roles]))
    return {
        "user": user.user,
        "compromised": found.compromised,
        "strong": found.strong,
        "indicators": list(found.indicators),
        "summary": (f"account {user.user}: " + "; ".join(found.indicators)) if found.indicators else "",
        "record_ids": list(found.record_ids),
        "attacker_ips": list(found.attacker_ips),
        "privileged": privileged,
        "privileged_roles": privileged_roles,
        "groups": groups,
        "roles": roles,
        "planted": planted,
        "planted_record_ids": list(dict.fromkeys(planted_ids)),
        "revoke": bool(revoke_reasons),
        "revoke_summary": (f"account {user.user}: " + "; ".join(revoke_reasons) + f" ({_REVOCATION_NOTE})")
        if revoke_reasons else "",
        "revoke_record_ids": revoke_ids,
        "disable_reasons": disable_reasons,
        "disable_summary": (f"account {user.user}: " + "; ".join(disable_reasons) + " while compromised ("
                            + "; ".join(found.indicators) + ")") if disable_reasons else "",
        "disable_record_ids": disable_ids,
    }


@dataclass
class _Facts:
    data: _Data
    assessed: dict[str, _Assessment]
    users: list[dict[str, Any]]
    apps: dict[str, dict[str, Any]]
    remove_roles: list[dict[str, Any]]
    withheld_roles: list[dict[str, Any]]
    ips: list[dict[str, Any]]


def _facts(view: RunView) -> _Facts:
    data = _collect(view)
    assessed = {name: _assess(data.users[name], data.ips) for name in sorted(data.users)}
    compromised = {name for name, found in assessed.items() if found.compromised}
    apps = {app_id: _app_fact(data.apps[app_id], compromised) for app_id in sorted(data.apps)}
    users = [_user_fact(assessed[name], data, apps, data.apps) for name in sorted(assessed)]
    remove_roles, withheld_roles = _role_facts(data, assessed)
    return _Facts(data=data, assessed=assessed, users=users, apps=apps, remove_roles=remove_roles,
                  withheld_roles=withheld_roles, ips=_ip_facts(data, compromised))


# ------------------------------------------------------------------ hooks --
class CloudCompromiseHooks(WorkflowHooks):
    """Facts, considered items, manual steps, hand-offs and derived signals for the cloud-compromise rules."""

    def facts(self, view: RunView) -> Mapping[str, Any]:
        found = _facts(view)
        return {
            "users": found.users,
            "compromised_users": [u for u in found.users if u["compromised"]],
            "revoke_users": [u for u in found.users if u["revoke"]],
            "disable_users": [u for u in found.users if u["disable_reasons"]],
            "remove_roles": [r for r in found.remove_roles if r["target"]],
            "apps": list(found.apps.values()),
            "risky_apps": [a for a in found.apps.values() if a["risky"]],
            "ips": found.ips,
            "block_ips": [i for i in found.ips if i["block_candidate"]],
            "shared_ips": [i["ip"] for i in found.ips if i["shared"]],
        }

    def considered(self, view: RunView) -> Sequence[Consideration]:
        found = _facts(view)
        out: list[Consideration] = []
        for app in found.apps.values():
            if app["risky"]:
                out += _app_manual_steps(app)
        out += _app_considerations(found)
        for role in found.remove_roles:
            if not role["target"]:
                out.append(Consideration(
                    subject=f"remove-role:{role['subject']}",
                    reason=(f"{role['summary']}; the role change record carries no role definition id, so the "
                            "assignment is not a package action: remove it in the Entra admin center"),
                    record_ids=tuple(role["record_ids"]), manual=True))
        for role in found.withheld_roles:
            assigned = (f"privileged role {role['role_name']} assigned to {role['user']}"
                        + (f" by {role['actor']}" if role["actor"] else ""))
            if role["predates"]:
                reason = (assigned + f" {role['predates']}: a pre-existing assignment this incident did not "
                          "create and no record ties to the attacker; not proposed (review it with the account)")
            else:
                reason = (assigned + " during the investigated window; neither account shows a compromise "
                          "indicator: not proposed (check the change record)")
            out.append(Consideration(subject=f"remove_privileged_role:{role['subject']}", reason=reason,
                                     record_ids=tuple(role["record_ids"])))
        for ip in found.ips:
            if ip["shared"] and ip["block_worthy"]:
                out.append(Consideration(
                    subject=f"block_ip:{ip['ip']}",
                    reason=(f"rated {ip['verdict']} but shared (seen from internal endpoints or used by other "
                            "accounts): not blocked"),
                    record_ids=tuple(_merge_ids(ip["record_ids"], ip["shared_record_ids"]))))
        return out

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        found = _facts(view)
        compromised = [u for u in found.users if u["compromised"]]
        if not compromised:
            return ()
        return [Handoff(
            workflow_id="account-takeover",
            subjects=tuple(u["user"] for u in compromised),
            reason=("cloud identity compromise: review the accounts' mailbox rules, sign-ins and endpoints "
                    "beyond the cloud activity covered here"),
            record_ids=tuple(_merge_ids(*(u["record_ids"] for u in compromised))),
        )]

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        found = _facts(view)
        origin = view.origin
        signals: list[ScoringSignal] = []
        compromised = {name for name, a in found.assessed.items() if a.compromised}
        for name in sorted(found.assessed):
            assessment = found.assessed[name]
            if not assessment.compromised:
                continue
            subject = Observable(type=ObservableType.USER, value=name)
            signals += _signin_signals(assessment, subject, found.data.ips, origin)
            signals += _planted_signals(name, subject, found.data, compromised, origin)
        for ip in found.ips:
            if ip["block_candidate"]:
                signals += _ip_signals(ip, found.data, origin)
        return signals


def _app_manual_steps(app: Mapping[str, Any]) -> list[Consideration]:
    """Manual steps for a risky application: no VERIFIED write exists for any of them."""
    name = app["name"]
    why = "; ".join(app["reasons"])
    ids = tuple(app["all_record_ids"])
    steps: list[Consideration] = []
    if app["credentialed"]:
        steps.append(Consideration(
            subject=f"remove-app-credentials:{app['app_id']}",
            reason=(f"application '{name}' ({why}): remove the client secrets and certificates added during the "
                    "investigated window in the Entra admin center (no VERIFIED write; not in the package)"),
            record_ids=ids, manual=True))
    if app["consented"]:
        steps.append(Consideration(
            subject=f"revoke-oauth-consent:{app['app_id']}",
            reason=(f"application '{name}' ({why}): revoke its delegated permission grants and app role "
                    "assignments in the Entra admin center (no VERIFIED write; not in the package)"),
            record_ids=ids, manual=True))
    steps.append(Consideration(
        subject=f"disable-service-principal:{app['app_id']}",
        reason=(f"application '{name}' ({why}): disable its service principal unless it is a sanctioned "
                "application, and review its sign-ins and data access (no VERIFIED write; not in the package)"),
        record_ids=ids, manual=True))
    return steps


def _app_considerations(found: _Facts) -> list[Consideration]:
    """Account actions deliberately not proposed for application activity of uncompromised accounts."""
    out: list[Consideration] = []
    users = {u["user"]: u for u in found.users}
    for app_id in sorted(found.apps):
        app = found.apps[app_id]
        obj = found.data.apps[app_id]
        if not app["risky"]:
            continue
        for admin in app["admin_consents"]:
            user = users.get(admin)
            if user is not None and user["compromised"]:
                continue
            out.append(Consideration(
                subject=f"revoke_sessions:{admin}",
                reason=(f"granted tenant-wide consent to risky application '{app['name']}' but shows no compromise "
                        "indicator; revoking the administrator's sessions would not stop the application's own "
                        "tokens: not proposed (see the consent manual step)"),
                record_ids=tuple(_owner_records(obj, admin, consent="admin"))))
        for actor in app["credential_actors"]:
            user = users.get(actor)
            if user is not None and user["compromised"]:
                continue
            out.append(Consideration(
                subject=f"disable_user:{actor}",
                reason=(f"added a credential to risky application '{app['name']}' but shows no compromise "
                        "indicator: not disabled (confirm the change with the account owner)"),
                record_ids=tuple(_owner_records(obj, actor, credential=True))))
    return out


def _by_integration(records: Iterable[Any]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for record in records:
        out.setdefault(record.integration, []).append(record)
    return out


def _signal(origin: str, category: SignalCategory, integration: str, subject: Observable, verdict: Verdict,
            severity: int, confidence: int, records: Sequence[Any], note: str) -> ScoringSignal:
    return ScoringSignal(category=category, integration=integration, observable=subject, verdict=verdict,
                         severity=severity, confidence=confidence, record_ids=tuple(_ids(records)), origin=origin,
                         note=note)


def _signin_signals(found: _Assessment, subject: Observable, ips: Mapping[str, _Ip],
                    origin: str) -> list[ScoringSignal]:
    if not found.attacker_signins:
        return []
    sources = [ips[ip] for ip in found.attacker_ips]
    malicious = any(s.verdict is Verdict.MALICIOUS or s.any_malicious() for s in sources)
    enrichment = [r for s in sources for r in s.flagged_enrichment()]
    out: list[ScoringSignal] = []
    for integration, signins in sorted(_by_integration(found.attacker_signins).items()):
        out.append(_signal(origin, SignalCategory.AUTHENTICATION_ANOMALY, integration, subject,
                           Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS, 80 if malicious else 70,
                           75 if malicious else 65, [*signins, *enrichment],
                           "successful sign-in from an IP rated " + ("malicious" if malicious else "suspicious")))
    return out


def _planted_signals(name: str, subject: Observable, data: _Data, compromised: set[str],
                     origin: str) -> list[ScoringSignal]:
    """Credentials added to, or consents granted to, unrated applications by a compromised account."""
    records: list[CloudAppRecord] = []
    for app in data.apps.values():
        for record in app.owners.get(name, []):
            if record.verdict in _FLAGGED:
                continue  # the record already scores on its own verdict
            if record.credential_added_at is not None or (record.consent_type != "unknown"
                                                          and record.publisher_verified is not True):
                records.append(record)
    out: list[ScoringSignal] = []
    for integration, mine in sorted(_by_integration(records).items()):
        out.append(_signal(origin, SignalCategory.PERSISTENCE, integration, subject, Verdict.SUSPICIOUS, 70, 65,
                           mine, "application credential or consent added by a compromised account"))
    return out


def _ip_signals(fact: Mapping[str, Any], data: _Data, origin: str) -> list[ScoringSignal]:
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
        out.append(_signal(origin, SignalCategory.AUTHENTICATION_ANOMALY, integration, subject,
                           Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS,
                           80 if malicious else (70 if compromised_success else 60), 70,
                           [*records, *ip.flagged_enrichment()],
                           "sign-in source of an investigated account"
                           + (" with a successful compromised sign-in" if compromised_success else "")))
    return out


HOOKS = CloudCompromiseHooks()
