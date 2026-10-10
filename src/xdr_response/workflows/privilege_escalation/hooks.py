"""Pure hooks of the privilege-escalation workflow (architecture 14.3.3).

The hooks read the run's records (a :class:`RunView`: no context, no adapters) and compute:

* ``facts`` for the recommendation rules:

  - ``changes``: every privileged grant the run found (a directory role, a privileged group membership
    or a high-privilege application permission), with **who** made it (``actor``), who received it,
    when, the source's reference, a change reference the incident reports (unverified), and whether it
    is ``anomalous`` (granted by or to a compromised account, or self-assigned outside a privileged
    identity management activation), ``normal`` (neither account shows a compromise indicator) or
    ``unassessed`` (an identity read of an involved account failed);
  - ``remove_roles``: anomalous directory-role grants still in place that carry a role definition id
    (target ``<user>/<roleDefinitionId>``, always ELEVATED by the catalog);
  - ``revoke_users``: the accounts that made or received an anomalous change;
  - ``disable_users``: a compromised identity (strong indicator) that made or received an anomalous
    change, a compromised account that elevated itself, and an account with no sign-in before it
    received a privilege through an anomalous change (likely created or staged by the attacker);
  - ``isolate_hosts``: investigated endpoints (the originating devices) with an active MALICIOUS
    detection, or a file whose aggregate reputation is MALICIOUS, that can be isolated.

  Every host, change, application and account fact carries the ``binaries`` its action rests on
  alone (``binaries``, ``revoke_binaries``, ``disable_binaries``): the SHA-256 of the rated files when
  they are the endpoint's only basis and every reason of the action goes back to that endpoint
  (use of it by the actor or grantee), else ``[]``. The rules pass them to the runner, which
  withholds the action as sanctioned when every hash is an allow-listed or approved tool's binary
  (14.11.6): an approved RMM tool that two vendors call riskware never isolates its host and never
  spreads "compromised" to its user and the accounts that user changed.

  An account that received a privilege through an anomalous change is passed to the package with
  ``privileged: true``: its own new privilege (a protected group, an administrator role) never
  shields it; the critical-asset policy makes its actions ELEVATED with a warning instead.

* ``considered``: withheld actions (a normal or pre-existing grant, an unassessed change, an involved
  account that is not disabled, a host that cannot be isolated or whose detection is only suspicious)
  and **manual steps** for the writes that have no VERIFIED endpoint (privileged group membership,
  a role assignment without a role definition id, application permissions).
* ``handoffs``: compromised accounts to ``account-takeover`` for the broader account review.
* ``derive_signals``: signals computed from cited records only.

Nothing here calls a vendor, writes anything, chooses an approval level or invents a fact: every
account, change, application and endpoint in the facts comes from a record, and every record id a fact,
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
    InvestigationBundle,
    ProcessEventRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks, failed_reads

__all__ = [
    "PrivilegeEscalationHooks",
    "HOOKS",
    "ATTACKER_ANOMALIES",
    "ESCALATION_MARKERS",
    "ESCALATION_TECHNIQUES",
    "GRANTED_CHANGES",
    "HIGH_PRIVILEGE_PERMISSIONS",
    "IDENTITY_ATOMICS",
    "PRE_COMPROMISE_GRACE",
    "PRIVILEGED_GROUP_NAMES",
    "SELF_ASSIGNED_CHANGES",
    "STRONG_SEVERITIES",
]

#: Vendor risk detection types that indicate a compromise when HIGH or CRITICAL and a sign-in succeeded.
ATTACKER_ANOMALIES: frozenset[str] = frozenset({
    "impossible_travel", "unfamiliar_location", "new_device", "anonymous_ip", "malicious_ip",
    "token_replay", "leaked_credentials", "atypical_volume", "other",
})
STRONG_SEVERITIES: frozenset[Severity] = frozenset({Severity.HIGH, Severity.CRITICAL})
#: Role changes that give the account the role or membership (a later ``removed`` change undoes them).
GRANTED_CHANGES: frozenset[str] = frozenset({"assigned", "activated", "eligible_assigned"})
#: Grants an account cannot normally make to itself. ``activated`` is a privileged identity management
#: activation of an eligible role, made by the account itself by design: never "self-assigned".
SELF_ASSIGNED_CHANGES: frozenset[str] = frozenset({"assigned", "eligible_assigned"})
#: Lower-case names of on-premises Active Directory and directory groups that grant administrator rights.
#: A role change record naming one of them (without a role definition id) is a privileged group membership.
PRIVILEGED_GROUP_NAMES: frozenset[str] = frozenset({
    "domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
    "backup operators", "server operators", "print operators", "dnsadmins", "group policy creator owners",
    "key admins", "enterprise key admins", "global administrators",
})
#: Application (service principal) permissions, lower case, that let an application grant itself or others
#: administrator rights or change the directory.
HIGH_PRIVILEGE_PERMISSIONS: frozenset[str] = frozenset({
    "rolemanagement.readwrite.directory", "approleassignment.readwrite.all", "directory.readwrite.all",
    "application.readwrite.all", "user.readwrite.all", "group.readwrite.all", "groupmember.readwrite.all",
    "privilegedaccess.readwrite.azuread", "policy.readwrite.conditionalaccess", "domain.readwrite.all",
    "full_access_as_app",
})
#: ATT&CK ids (prefixes) a vendor reports for escalation on an endpoint.
ESCALATION_TECHNIQUES: tuple[str, ...] = ("T1068", "T1548", "T1134")
#: Words in a detection name or category that report escalation on an endpoint.
ESCALATION_MARKERS: tuple[str, ...] = (
    "privilege escalation", "elevation of privilege", "uac bypass", "bypass user account control",
    "exploit", "token manipulation", "local privilege",
)
#: A grant made more than this long before the earliest dated compromise record of the account that ties it
#: to the incident predates the compromise: a pre-existing assignment, considered and never proposed.
PRE_COMPROMISE_GRACE = timedelta(hours=24)
#: Identity reads whose failure leaves an account unassessed.
IDENTITY_ATOMICS: tuple[str, ...] = ("investigate_user", "investigate_authentication", "search_user_activity")

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_USER_TYPES = frozenset({ObservableType.USER, ObservableType.EMAIL_ADDRESS})
_HASH_TYPES = frozenset({ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5})
_ENDPOINT_ATOMICS = frozenset({"investigate_endpoint"})
_REVOCATION_NOTE = "a revocation ends the sessions that could use the new rights with an existing token"


def _ids(records: Iterable[Any]) -> list[str]:
    """Record ids in first-seen order, without duplicates."""
    return list(dict.fromkeys(r.record_id for r in records))


def _merge_ids(*groups: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(i for group in groups for i in group))


def _key(value: str | None) -> str:
    return (value or "").strip().lower()


def _host(value: str | None) -> str:
    return (value or "").strip().rstrip(".").upper()


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


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
class _Host:
    """One investigated endpoint and the records the run holds for it."""

    hostname: str
    endpoints: dict[str, EndpointRecord] = field(default_factory=dict)
    detections: dict[str, DetectionRecord] = field(default_factory=dict)
    events: dict[str, ProcessEventRecord] = field(default_factory=dict)

    def first(self) -> EndpointRecord | None:
        return next(iter(self.endpoints.values()), None)

    def value(self, name: str) -> Any:
        for record in self.endpoints.values():
            found = record.model_dump(mode="json").get(name)
            if found not in (None, (), [], "unknown"):
                return found
        return None

    def users(self) -> list[str]:
        out = [_key(u) for e in self.endpoints.values() for u in e.users]
        out += [_key(d.user) for d in self.detections.values() if d.user]
        out += [_key(e.user) for e in self.events.values() if e.user]
        return [u for u in dict.fromkeys(out) if u and "@" in u]


@dataclass
class _Change:
    """One privileged grant (de-duplicated across the subjects that reported it)."""

    record: RoleChangeRecord
    records: list[RoleChangeRecord] = field(default_factory=list)

    @property
    def user(self) -> str:
        return _key(self.record.user)

    @property
    def actor(self) -> str:
        return _key(self.record.actor)

    @property
    def kind(self) -> str:
        if self.record.role_definition_id:
            return "directory_role"
        if self.record.role_name.strip().lower() in PRIVILEGED_GROUP_NAMES:
            return "group"
        return "role"

    @property
    def self_assigned(self) -> bool:
        return bool(self.actor) and self.actor == self.user and self.record.change in SELF_ASSIGNED_CHANGES

    @property
    def subject(self) -> str:
        return self.record.target or f"{self.user}/{self.record.role_name}"


@dataclass
class _Data:
    users: dict[str, _User] = field(default_factory=dict)
    hosts: dict[str, _Host] = field(default_factory=dict)
    roles: dict[str, RoleChangeRecord] = field(default_factory=dict)
    apps: dict[str, list[tuple[CloudAppRecord, str | None]]] = field(default_factory=dict)
    hashes: dict[str, ObservableReport] = field(default_factory=dict)

    def user(self, value: str) -> _User:
        key = _key(value)
        return self.users.setdefault(key, _User(user=key))

    def host(self, value: str) -> _Host:
        key = _host(value)
        return self.hosts.setdefault(key, _Host(hostname=key))


def _collect(view: RunView) -> _Data:
    out = _Data()
    for result in view.results:
        if isinstance(result, ObservableReport):
            if result.subject.type in _HASH_TYPES:
                out.hashes[result.subject.value.lower()] = result
            continue
        if not isinstance(result, InvestigationBundle):
            continue
        if result.atomic in _ENDPOINT_ATOMICS:
            endpoints = [r for r in result.records if isinstance(r, EndpointRecord)]
            if endpoints:
                name = endpoints[0].hostname
            elif result.subject.type is ObservableType.HOSTNAME:
                name = result.subject.value
            else:
                name = ""
            for record in result.records:
                _collect_host_record(out, name, record)
            continue
        subject_user = _key(result.subject.value) if result.subject.type in _USER_TYPES else None
        if subject_user and result.atomic in IDENTITY_ATOMICS:
            out.user(subject_user)
        for record in result.records:
            _collect_user_record(out, record, subject_user)
    return out


def _collect_host_record(out: _Data, name: str, record: Any) -> None:
    """Endpoint records belong to the bundle's host; detections and events to the endpoint they name."""
    if isinstance(record, EndpointRecord) and name:
        out.host(name).endpoints.setdefault(record.record_id, record)
    elif isinstance(record, DetectionRecord) and (record.endpoint or name):
        out.host(record.endpoint or name).detections.setdefault(record.record_id, record)
    elif isinstance(record, ProcessEventRecord):
        out.host(record.endpoint).events.setdefault(record.record_id, record)


def _collect_user_record(out: _Data, record: Any, subject_user: str | None) -> None:
    if isinstance(record, UserProfileRecord):
        out.user(record.user).profiles.setdefault(record.record_id, record)
    elif isinstance(record, SignInRecord):
        out.user(record.user).signins.setdefault(record.record_id, record)
    elif isinstance(record, AnomalyRecord):
        owner = record.user or subject_user
        if owner:
            out.user(owner).anomalies.setdefault(record.record_id, record)
    elif isinstance(record, DetectionRecord) and record.endpoint is None:
        owner = record.user or subject_user  # an identity or cloud alert about the account
        if owner:
            out.user(owner).alerts.setdefault(record.record_id, record)
    elif isinstance(record, RoleChangeRecord):
        out.roles.setdefault(record.record_id, record)
    elif isinstance(record, CloudAppRecord):
        out.apps.setdefault(record.app_id, []).append((record, _key(record.consented_by) or subject_user))


# ------------------------------------------------------------------- hosts --
def _escalation(detection: DetectionRecord) -> bool:
    """True when the vendor reports escalation on the endpoint (technique, name or category)."""
    if any(t.upper().startswith(ESCALATION_TECHNIQUES) for t in detection.mitre_techniques):
        return True
    text = " ".join((detection.name, detection.category or "")).lower().replace("-", " ")
    return any(marker in text for marker in ESCALATION_MARKERS)


@dataclass
class _HostFinding:
    host: _Host
    basis: list[str] = field(default_factory=list)  # why the host is compromised
    record_ids: list[str] = field(default_factory=list)
    escalation: bool = False
    suspicious_only: list[DetectionRecord] = field(default_factory=list)
    since: datetime | None = None
    #: SHA-256 of the rated files when they are the only basis (no active MALICIOUS detection): the
    #: compromise rests on those binaries alone, so a sanctioned one never isolates the host or
    #: contains its users (``RecommendationRule.binaries``, 14.11.6).
    binaries: list[str] = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        return bool(self.basis)


def _assess_host(host: _Host, hashes: Mapping[str, ObservableReport]) -> _HostFinding:
    found = _HostFinding(host=host)
    active = [d for d in host.detections.values() if d.status != "resolved"]
    malicious = sorted((d for d in active if d.verdict is Verdict.MALICIOUS), key=lambda d: d.record_id)
    dated: list[datetime] = []
    if malicious:
        found.basis.append("active MALICIOUS detection (" + ", ".join(sorted({d.name for d in malicious})) + ")")
        found.record_ids += _ids(malicious)
        found.escalation = any(_escalation(d) for d in malicious)
        dated += [d.first_seen or d.last_seen for d in malicious if d.first_seen or d.last_seen]
    rated = _malicious_files(host, hashes)
    if rated:
        names = sorted(rated)
        found.basis.append("file rated MALICIOUS on the endpoint (" + ", ".join(n[:12] for n in names) + ")")
        for sha in names:
            report = hashes[sha]
            found.record_ids += [r.record_id for r in report.enrichment_records() if r.verdict in _FLAGGED]
            found.record_ids += rated[sha]
    if rated and not malicious:
        found.binaries = sorted(rated)
    if not found.basis:
        found.suspicious_only = sorted((d for d in active if d.verdict is Verdict.SUSPICIOUS),
                                       key=lambda d: d.record_id)
        found.escalation = any(_escalation(d) for d in found.suspicious_only)
    else:
        found.record_ids = _merge_ids(found.record_ids, _ids(host.endpoints.values()))
    found.since = min(dated) if dated else None
    return found


def _malicious_files(host: _Host, hashes: Mapping[str, ObservableReport]) -> dict[str, list[str]]:
    """SHA-256 of files the host's own records name whose aggregate reputation is MALICIOUS -> those records."""
    out: dict[str, list[str]] = {}
    for record in [*host.detections.values(), *host.events.values()]:
        sha = (record.sha256 or "").lower()
        report = hashes.get(sha)
        if sha and report is not None and report.verdict is Verdict.MALICIOUS:
            out.setdefault(sha, []).append(record.record_id)
    return out


def _host_fact(found: _HostFinding, failed: Mapping[str, tuple[str, ...]]) -> dict[str, Any]:
    host = found.host
    first = host.first()
    capable = host.value("isolation_capable")
    ips = list(dict.fromkeys(ip for e in host.endpoints.values() for ip in e.ip_addresses))
    what = "privilege escalation" if found.escalation else "malicious activity"
    return {
        "hostname": host.hostname,
        "connector_guid": host.value("connector_guid"),
        "mde_machine_id": host.value("mde_machine_id"),
        "isolation_capable": capable,
        "isolation_state": host.value("isolation_state") or "unknown",
        "groups": list(first.groups) if first is not None else [],
        "tags": list(first.tags) if first is not None else [],
        "ip": ips[0] if ips else None,
        "ips": ips,
        "users": host.users(),
        "compromised": found.compromised,
        "escalation": found.escalation,
        "basis": list(found.basis),
        "record_ids": list(found.record_ids),
        "failed_sources": list(failed.get(host.hostname, ())),
        "isolate": found.compromised and capable is not False,
        "binaries": list(found.binaries),
        "summary": (f"originating endpoint {host.hostname}: {what}: " + "; ".join(found.basis)
                    + (f"; used by {', '.join(host.users())}" if host.users() else "")) if found.basis else "",
    }


# ------------------------------------------------------------- accounts --
@dataclass
class _Assessment:
    """Why one account looks compromised, with the records behind every reason."""

    user: _User
    indicators: list[str] = field(default_factory=list)
    strong: bool = False
    record_ids: list[str] = field(default_factory=list)
    dated: list[datetime] = field(default_factory=list)
    #: per indicator, the binaries it rests on alone ([] when it stands on its own)
    binary_sets: list[list[str]] = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        return bool(self.indicators)

    @property
    def binaries(self) -> list[str]:
        """The binaries the whole compromise rests on (every indicator is the use of an endpoint whose only
        basis is rated files), else [] (one indicator stands on its own)."""
        return _rests_on(self.binary_sets)

    @property
    def since(self) -> datetime | None:
        return min(self.dated) if self.dated else None

    def add(self, text: str, records: Iterable[Any], *, strong: bool, when: Iterable[datetime | None] = (),
            binaries: Iterable[str] = ()) -> None:
        records = list(records)
        self.indicators.append(text)
        self.binary_sets.append(list(binaries))
        self.strong = self.strong or strong
        self.cite(records)
        self.dated += [w for w in when if w is not None]

    def cite(self, records: Iterable[Any]) -> None:
        self.record_ids = _merge_ids(self.record_ids, _ids(records))


def _successes(user: _User) -> list[SignInRecord]:
    return sorted((s for s in user.signins.values() if s.result == "success"), key=lambda s: (s.timestamp, s.record_id))


def _assess(user: _User, hosts: Sequence[_HostFinding]) -> _Assessment:
    found = _Assessment(user=user)
    successes = _successes(user)
    profile = user.profile
    if profile is not None and (profile.risk_level == "high" or profile.risk_state == "confirmed_compromised"):
        state = "confirmed compromised" if profile.risk_state == "confirmed_compromised" else "high risk"
        found.add(f"identity provider rates the account {state}", [profile], strong=True)
    risky = [s for s in successes if s.risk_level == "high"]
    if risky:
        found.add("successful sign-in rated high risk by the identity provider", risky, strong=True,
                  when=[s.timestamp for s in risky])
    strong_anomalies = [a for a in user.anomalies.values()
                        if a.anomaly_type in ATTACKER_ANOMALIES and a.severity in STRONG_SEVERITIES]
    if strong_anomalies and successes:
        found.add("HIGH or CRITICAL risk detection (" + ", ".join(sorted({a.anomaly_type for a in strong_anomalies}))
                  + ") with a successful sign-in", [*strong_anomalies, *successes[-1:]], strong=True,
                  when=[a.first_seen or a.last_seen for a in strong_anomalies])
    replay = [a for a in user.anomalies.values() if a.anomaly_type == "token_replay"]
    if replay:
        found.add("session token replay detected", replay, strong=True, when=[a.first_seen for a in replay])
    if profile is not None and profile.risk_level == "medium" and user.anomalies and not found.compromised:
        found.add("identity provider rates the account medium risk with risk detections ("
                  + ", ".join(sorted({a.anomaly_type for a in user.anomalies.values()})) + ")",
                  [profile, *user.anomalies.values()], strong=False,
                  when=[a.first_seen or a.last_seen for a in user.anomalies.values()])
    active = [d for d in user.alerts.values() if d.status != "resolved"]
    malicious = [d for d in active if d.verdict is Verdict.MALICIOUS]
    if malicious:
        found.add("identity alert rated malicious (" + ", ".join(sorted({d.name for d in malicious})) + ")",
                  malicious, strong=True, when=[d.first_seen or d.last_seen for d in malicious])
    suspicious = [d for d in active if d.verdict is Verdict.SUSPICIOUS and d.severity in STRONG_SEVERITIES]
    if suspicious:
        found.add("unresolved HIGH identity alert (" + ", ".join(sorted({d.name for d in suspicious})) + ")",
                  suspicious, strong=False, when=[d.first_seen or d.last_seen for d in suspicious])
    for host in hosts:
        if host.compromised and user.user in host.host.users():
            found.add(f"uses endpoint {host.host.hostname} where {'; '.join(host.basis)}", _host_records(host),
                      strong=False, when=[host.since], binaries=host.binaries)
    if found.compromised:
        found.cite(a for a in user.anomalies.values() if a.severity is not Severity.INFO)
        if profile is not None:
            found.cite([profile])
    return found


def _rests_on(sets: Iterable[Sequence[str]]) -> list[str]:
    """Union of the binaries several reasons rest on, or [] when there is no reason or one reason stands on
    its own (an empty set): an action is withheld as sanctioned only when every reason is a binary."""
    groups = [list(s) for s in sets]
    if not groups or any(not g for g in groups):
        return []
    return sorted({h for g in groups for h in g})


def _host_records(host: _HostFinding) -> list[Any]:
    wanted = set(host.record_ids)
    records = [*host.host.detections.values(), *host.host.events.values(), *host.host.endpoints.values()]
    return [r for r in records if r.record_id in wanted]


def _privileged_now(user: _User, changes: Iterable[_Change]) -> tuple[bool, list[str]]:
    """(the account holds or received a privilege, the privileged role and group names)."""
    names: list[str] = []
    profile = user.profile
    if profile is not None:
        names += [r for r in profile.roles if r.strip().lower() in PRIVILEGED_ROLE_NAMES]
        names += [g for g in profile.groups if g.strip().lower() in PRIVILEGED_GROUP_NAMES]
    names += [c.record.role_name for c in changes if c.user == user.user]
    names = list(dict.fromkeys(names))
    return bool(names) or bool(profile is not None and profile.privileged), names


# ------------------------------------------------------------------ changes --
def _privileged_change(record: RoleChangeRecord) -> bool:
    return record.change in GRANTED_CHANGES and (
        record.privileged or record.role_name.strip().lower() in PRIVILEGED_GROUP_NAMES)


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


def _changes(data: _Data) -> list[_Change]:
    """Privileged grants still in place, one per (account, role, change, time), in a stable order."""
    roles = list(data.roles.values())
    out: dict[tuple[str, str, str, str | None], _Change] = {}
    for record in sorted(roles, key=lambda r: (_key(r.user), r.role_name.lower(), str(r.timestamp), r.record_id)):
        if not (_privileged_change(record) and _still_granted(record, roles)):
            continue
        key = (_key(record.user), record.role_name.strip().lower(), record.change, _iso(record.timestamp))
        change = out.setdefault(key, _Change(record=record))
        change.records.append(record)
        if change.record.role_definition_id is None and record.role_definition_id:
            change.record = record
    return list(out.values())


def _predates(when: datetime | None, found: _Assessment) -> bool:
    """True when ``when`` is more than :data:`PRE_COMPROMISE_GRACE` before the account's earliest dated
    compromise record. Undated grants or undated compromises are never placed before it (nothing is
    withheld on a guess)."""
    since = found.since
    return when is not None and since is not None and when < since - PRE_COMPROMISE_GRACE


def _change_reference(view: RunView) -> str:
    """A change reference the incident reports (``trigger.change_reference``); shown, never trusted."""
    value = view.incident.trigger.get("change_reference")
    return value.strip()[:100] if isinstance(value, str) else ""


def _endpoint_unassessed(view: RunView, assessed: Mapping[str, _Assessment],
                         failed_endpoint: Mapping[str, tuple[str, ...]]) -> dict[str, str]:
    """Accounts the incident names whose endpoint compromise could not be checked (degraded source).

    When an endpoint read FAILED, the users of that endpoint are unknown and its detections are missing,
    so an account the incident itself names (incident users and user observables) cannot be cleared of
    "uses an escalated endpoint". Maps each such account without a compromise indicator of its own to
    ``"<host> (<integrations>)"`` text. Empty when no endpoint read failed.
    """
    if not failed_endpoint:
        return {}
    named = [*view.incident.users, *(o.value for o in view.incident.observables if o.type in _USER_TYPES)]
    where = "; ".join(f"{host} ({', '.join(names)})" for host, names in sorted(failed_endpoint.items()))
    out: dict[str, str] = {}
    for account in dict.fromkeys(_key(n) for n in named):
        found = assessed.get(account)
        if account and "@" in account and not (found is not None and found.compromised):
            out[account] = where
    return out


def _assess_change(change: _Change, assessed: Mapping[str, _Assessment],
                   failed: Mapping[str, tuple[str, ...]], reference: str, data: _Data,
                   endpoint_unassessed: Mapping[str, str] | None = None) -> dict[str, Any]:
    record = change.record
    grantee, actor = change.user, change.actor
    why: list[str] = []
    why_binaries: list[list[str]] = []
    before: list[str] = []
    ids = _ids(change.records)
    actor_found = assessed.get(actor) if actor else None
    grantee_found = assessed.get(grantee)
    if actor_found is not None and actor_found.compromised:
        ids = _merge_ids(ids, actor_found.record_ids)
        if _predates(record.timestamp, actor_found):
            before.append(f"made before the earliest compromise record of {actor}")
        else:
            why.append(f"granted by compromised account {actor} (" + "; ".join(actor_found.indicators) + ")")
            why_binaries.append(actor_found.binaries)
    if grantee_found is not None and grantee_found.compromised and grantee != actor:
        ids = _merge_ids(ids, grantee_found.record_ids)
        if _predates(record.timestamp, grantee_found):
            before.append(f"made before the earliest compromise record of {grantee}")
        else:
            why.append(f"received by compromised account {grantee} (" + "; ".join(grantee_found.indicators) + ")")
            why_binaries.append(grantee_found.binaries)
    if change.self_assigned:
        why.insert(0, f"self-assigned by {grantee} (change '{record.change}', not a privileged identity "
                      "management activation)")
        why_binaries.insert(0, [])  # a self-assigned grant stands on its own
    if why:
        before = []  # tied to the incident: proposed, and only that is claimed
    unassessed = sorted({name for account in (grantee, actor) if account for name in failed.get(account, ())})
    degraded = ""
    pending = [a for a in dict.fromkeys((actor, grantee)) if a and a in (endpoint_unassessed or {})]
    if not why and not before and not unassessed and pending:
        # Owner rule: a failed endpoint source never blocks what the identity evidence backs. The incident
        # names the account, its endpoint could not be read, so the grant is suspicious (not confirmed):
        # the rules evaluate it on the role change records and the human decides.
        degraded = (f"the endpoint read failed for {endpoint_unassessed[pending[0]]}, so the escalation the incident "
                    f"reports for {', '.join(pending)} could not be checked: the grant is treated as suspicious, not "
                    "confirmed")
        why.append(f"made by or to {', '.join(pending)}, named by the incident: {degraded}")
        why_binaries.append([])
    status = "anomalous" if why else ("pre-existing" if before else ("unassessed" if unassessed else "normal"))
    what = {"directory_role": "privileged role", "group": "privileged group", "role": "privileged role"}[change.kind]
    profile = data.users[grantee].profile if grantee in data.users else None
    described = (f"{what} {record.role_name} {'activated by' if record.change == 'activated' else 'granted to'} "
                 f"{grantee}" + (f" by {actor}" if actor and record.change != "activated" else "")
                 + (f" at {_iso(record.timestamp)}" if record.timestamp else ""))
    return {
        "subject": change.subject,
        "kind": change.kind,
        "target": record.target if change.kind == "directory_role" else None,
        "user": grantee,
        "actor": actor or None,
        "role_name": record.role_name,
        "role_definition_id": record.role_definition_id,
        "directory_scope_id": record.directory_scope_id or "",
        "change": record.change,
        "timestamp": _iso(record.timestamp),
        "self_assigned": change.self_assigned,
        "source_reference": next((r.reference for r in change.records if r.reference), None),
        "change_reference": reference or None,
        "status": status,
        "anomalous": status == "anomalous",
        "reasons": why,
        "binaries": _rests_on(why_binaries) if why else [],
        "predates": "; ".join(before),
        "failed_sources": unassessed,
        "degraded": degraded,
        "record_ids": _merge_ids(ids),
        "groups": list(profile.groups) if profile is not None else [],
        "roles": list(dict.fromkeys([record.role_name, *(profile.roles if profile is not None else ())])),
        "description": described,
        "summary": (described + ": " + "; ".join(why)) if why else "",
    }


def _app_changes(data: _Data, assessed: Mapping[str, _Assessment]) -> list[dict[str, Any]]:
    """High-privilege permissions granted to an application (service principal), one fact per app."""
    out: list[dict[str, Any]] = []
    for app_id in sorted(data.apps):
        entries = data.apps[app_id]
        granted = [(r, owner) for r, owner in entries if r.consent_type != "unknown"
                   and {p.strip().lower() for p in r.permissions} & HIGH_PRIVILEGE_PERMISSIONS]
        if not granted:
            continue
        records = [r for r, _ in granted]
        actors = sorted({owner for _, owner in granted if owner})
        perms = sorted({p for r in records for p in r.permissions if p.strip().lower() in HIGH_PRIVILEGE_PERMISSIONS},
                       key=str.lower)
        name = next((r.display_name for r in records if r.display_name), app_id)
        why: list[str] = []
        why_binaries: list[list[str]] = []
        ids = _ids(records)
        flagged = [r for r, _ in entries if r.verdict in _FLAGGED]
        if flagged:
            why.append("application rated " + "/".join(sorted({r.verdict.value for r in flagged})))
            why_binaries.append([])
            ids = _merge_ids(ids, _ids(flagged))
        for actor in actors:
            found = assessed.get(actor)
            if found is not None and found.compromised:
                why.append(f"granted by compromised account {actor} (" + "; ".join(found.indicators) + ")")
                why_binaries.append(found.binaries)
                ids = _merge_ids(ids, found.record_ids)
        out.append({
            "app_id": app_id,
            "name": name,
            "permissions": perms,
            "actors": actors,
            "anomalous": bool(why),
            "reasons": why,
            "binaries": _rests_on(why_binaries) if why else [],
            "record_ids": ids,
            "summary": (f"high-privilege permissions ({', '.join(perms)}) granted to application '{name}'"
                        + (f" by {', '.join(actors)}" if actors else "") + (": " + "; ".join(why) if why else "")),
        })
    return out


# ------------------------------------------------------------- decisions --
def _prior_activity(user: _User, before: datetime | None) -> list[SignInRecord]:
    """Sign-ins of the account dated before ``before`` (any sign-in when the grant is undated)."""
    return [s for s in user.signins.values() if before is None or s.timestamp < before]


def _account_fact(name: str, data: _Data, found: _Assessment, changes: Sequence[dict[str, Any]],
                  apps: Sequence[dict[str, Any]], failed: Mapping[str, tuple[str, ...]],
                  privileged_changes: Sequence[_Change]) -> dict[str, Any]:
    user = data.users.get(name) or _User(user=name)
    profile = user.profile
    received = [c for c in changes if c["anomalous"] and c["user"] == name]
    made = [c for c in changes if c["anomalous"] and c["actor"] == name and c["user"] != name]
    granted_apps = [a for a in apps if a["anomalous"] and name in a["actors"]]
    privileged, names = _privileged_now(user, privileged_changes)
    reasons: list[str] = []
    ids: list[str] = []
    for change in received:
        reasons.append(f"received {change['description']} through an anomalous change")
        ids = _merge_ids(ids, change["record_ids"])
    for change in made:
        reasons.append(f"made an anomalous change: {change['description']}")
        ids = _merge_ids(ids, change["record_ids"])
    for app in granted_apps:
        reasons.append(f"granted {app['summary']}")
        ids = _merge_ids(ids, app["record_ids"])
    involved = bool(reasons)
    if involved:
        ids = _merge_ids(ids, found.record_ids, [profile.record_id] if profile is not None else [])
    # Disable: a compromised identity used for (or elevated by) the change, a compromised account that
    # elevated itself, or an account with no prior sign-in that an anomalous change made privileged.
    revoke_binaries = _rests_on([c["binaries"] for c in (*received, *made, *granted_apps)])
    disable: list[str] = []
    disable_binaries: list[str] = []
    disable_ids: list[str] = []
    held: str = ""
    if involved and found.compromised and found.strong:
        disable.append("compromised identity (" + "; ".join(found.indicators) + ")")
        disable_ids = list(ids)
    self_elevated = [c for c in received if c["self_assigned"]]
    if self_elevated and found.compromised and not disable:
        disable.append("compromised account elevated itself (" + "; ".join(found.indicators) + ")")
        disable_ids = list(ids)
        disable_binaries = found.binaries
    staged = [c for c in received if not c["self_assigned"]]
    if staged and not disable:
        assessed_ok = name not in failed and profile is not None
        times = [datetime.fromisoformat(c["timestamp"]) for c in staged if c["timestamp"]]
        earliest = min(times) if len(times) == len(staged) else None
        prior = _prior_activity(user, earliest)
        last = profile.last_sign_in if profile is not None else None
        if assessed_ok and not prior and (last is None or (earliest is not None and last >= earliest)):
            disable.append("no sign-in before it received the privilege (likely created or staged by the attacker)")
            disable_binaries = _rests_on([c["binaries"] for c in staged])
            disable_ids = _merge_ids(ids, [profile.record_id] if profile is not None else [])
        elif not assessed_ok:
            held = ("its identity reads failed (" + ", ".join(failed.get(name, ())) + "), so whether it is a new "
                    "account cannot be assessed") if name in failed else "no profile record was returned"
        else:
            held = "an established account (it signed in before the grant)"
            disable_ids = _merge_ids(ids, _ids(prior[:3]))
    if involved and not disable and not held:
        held = ("no strong compromise indicator" if found.compromised else "no compromise indicator of its own")
        degraded = [c["degraded"] for c in (*received, *made) if c.get("degraded")]
        if degraded:
            held += f" ({degraded[0]})"
    elevated_by_change = bool(received)
    return {
        "user": name,
        "compromised": found.compromised,
        "strong": found.strong,
        "indicators": list(found.indicators),
        "indicator_record_ids": list(found.record_ids),
        "privileged": privileged,
        "privileged_names": names,
        "elevated_by_change": elevated_by_change,
        "groups": list(profile.groups) if profile is not None else [],
        "roles": list(dict.fromkeys([*(profile.roles if profile is not None else ()),
                                     *[c["role_name"] for c in received if c["kind"] != "group"]])),
        "involved": involved,
        "revoke": involved,
        "revoke_record_ids": ids,
        "revoke_binaries": revoke_binaries if involved else [],
        "revoke_summary": (f"account {name}: " + "; ".join(reasons)
                           + (f"; compromise indicators: {'; '.join(found.indicators)}" if found.indicators else "")
                           + (f"; the privilege it holds came from this change, so it is ELEVATED, never shielded"
                              if elevated_by_change else "") + f" ({_REVOCATION_NOTE})") if involved else "",
        "disable": bool(disable),
        "disable_reasons": disable,
        "disable_record_ids": disable_ids if disable else [],
        "disable_binaries": disable_binaries if disable else [],
        "disable_summary": (f"account {name}: " + "; ".join(disable) + "; " + "; ".join(reasons)
                            + ("; remove the privilege it received before re-enabling it" if elevated_by_change
                               else "")) if disable else "",
        "held": held if involved and not disable else "",
        "held_record_ids": disable_ids or ids,
    }


@dataclass
class _Facts:
    data: _Data
    hosts: list[dict[str, Any]]
    host_findings: dict[str, _HostFinding]
    assessed: dict[str, _Assessment]
    changes: list[dict[str, Any]]
    apps: list[dict[str, Any]]
    accounts: list[dict[str, Any]]
    failed_identity: dict[str, tuple[str, ...]]
    failed_endpoint: dict[str, tuple[str, ...]]


def _facts(view: RunView) -> _Facts:
    data = _collect(view)
    failed_identity = failed_reads(view, IDENTITY_ATOMICS)
    failed_endpoint = failed_reads(view, _ENDPOINT_ATOMICS)
    findings = {name: _assess_host(data.hosts[name], data.hashes) for name in sorted(data.hosts)}
    hosts = [_host_fact(findings[name], failed_endpoint) for name in sorted(findings)]
    privileged_changes = _changes(data)
    for change in privileged_changes:
        for account in (change.user, change.actor):
            if account:
                data.user(account)
    for entries in data.apps.values():
        for _, owner in entries:
            if owner:
                data.user(owner)
    assessed = {name: _assess(data.users[name], list(findings.values())) for name in sorted(data.users)}
    reference = _change_reference(view)
    pending = _endpoint_unassessed(view, assessed, failed_endpoint)
    changes = [_assess_change(c, assessed, failed_identity, reference, data, pending) for c in privileged_changes]
    apps = _app_changes(data, assessed)
    accounts = [_account_fact(name, data, assessed[name], changes, apps, failed_identity, privileged_changes)
                for name in sorted(assessed)]
    return _Facts(data=data, hosts=hosts, host_findings=findings, assessed=assessed, changes=changes, apps=apps,
                  accounts=accounts, failed_identity=failed_identity, failed_endpoint=failed_endpoint)


# ------------------------------------------------------------------- hooks --
class PrivilegeEscalationHooks(WorkflowHooks):
    """Facts, considered items, manual steps, hand-offs and derived signals for the privilege-escalation rules."""

    def facts(self, view: RunView) -> Mapping[str, Any]:
        found = _facts(view)
        return {
            "hosts": found.hosts,
            "isolate_hosts": [h for h in found.hosts if h["isolate"]],
            "changes": found.changes,
            "anomalous_changes": [c for c in found.changes if c["anomalous"]],
            "remove_roles": [c for c in found.changes if c["anomalous"] and c["target"]],
            "apps": found.apps,
            "accounts": found.accounts,
            "compromised_users": [a["user"] for a in found.accounts if a["compromised"]],
            "revoke_users": [a for a in found.accounts if a["revoke"]],
            "disable_users": [a for a in found.accounts if a["disable"]],
        }

    def considered(self, view: RunView) -> Sequence[Consideration]:
        found = _facts(view)
        out: list[Consideration] = []
        out += _change_considerations(found)
        out += _app_considerations(found)
        out += _account_considerations(found)
        out += _host_considerations(found)
        return out

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        found = _facts(view)
        compromised = [a for a in found.accounts if a["compromised"]]
        if not compromised:
            return ()
        return [Handoff(
            workflow_id="account-takeover",
            subjects=tuple(a["user"] for a in compromised),
            reason=("account compromise behind a privilege escalation: review the accounts' sign-ins, mailbox "
                    "rules and other activity beyond the privilege changes covered here"),
            record_ids=tuple(_merge_ids(*(a["indicator_record_ids"] for a in compromised))),
        )]

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        found = _facts(view)
        origin = view.origin
        index: dict[str, Any] = {r.record_id: r for r in found.data.roles.values()}
        signals: list[ScoringSignal] = []
        for change in found.changes:
            if not change["anomalous"]:
                continue
            records = [index[i] for i in change["record_ids"] if i in index]
            if not records:
                continue
            compromised = any(r.startswith(("granted by compromised", "received by compromised"))
                              for r in change["reasons"])
            verdict = Verdict.MALICIOUS if compromised else Verdict.SUSPICIOUS
            if compromised:
                severity, note = 80, "tied to a compromised account"
            elif change["self_assigned"]:
                severity, note = 70, "self-assigned outside a privileged identity activation"
            else:  # degraded endpoint source: suspicious, never more (14.14.2)
                severity, note = 60, "made by or to an incident account whose endpoint read failed"
            accounts = [a for a in (change["user"], change["actor"]) if a]
            for account in dict.fromkeys(accounts):
                subject = Observable(type=ObservableType.USER, value=account)
                for integration, mine in sorted(_by_integration(records).items()):
                    signals.append(ScoringSignal(
                        category=SignalCategory.PERSISTENCE, integration=integration, observable=subject,
                        verdict=verdict, severity=severity, confidence=70 if compromised or
                        change["self_assigned"] else 60,
                        record_ids=tuple(_ids(mine)), origin=origin, note="privileged grant " + note))
        return signals


def _by_integration(records: Iterable[Any]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for record in records:
        out.setdefault(record.integration, []).append(record)
    return out


def _change_considerations(found: _Facts) -> list[Consideration]:
    out: list[Consideration] = []
    for change in found.changes:
        ref = (f"; change reference {change['change_reference']} reported by the incident (not verified)"
               if change["change_reference"] else "; no change reference is readable from a VERIFIED source")
        ids = tuple(change["record_ids"])
        if change["anomalous"]:
            if change["kind"] == "group":
                out.append(Consideration(
                    subject=f"remove-group-membership:{change['user']}/{change['role_name']}",
                    reason=(f"{change['summary']}: remove the membership in the directory (no VERIFIED write; not in "
                            "the package); do it before re-enabling the account"),
                    record_ids=ids, manual=True))
            elif not change["target"]:
                out.append(Consideration(
                    subject=f"remove-role-assignment:{change['subject']}",
                    reason=(f"{change['summary']}: the record carries no role definition id, so the assignment is "
                            "not a package action: remove it in the Entra admin center"),
                    record_ids=ids, manual=True))
            continue
        if change["status"] == "pre-existing":
            reason = (f"{change['description']} {change['predates']}: a pre-existing assignment this incident did "
                      "not create; not proposed (review it with the account)")
        elif change["status"] == "unassessed":
            reason = (f"{change['description']}: an identity read of the accounts failed "
                      f"({', '.join(change['failed_sources'])}), so the change could not be assessed; not proposed "
                      "(check it by hand)")
        else:
            reason = (f"{change['description']}: neither account shows a compromise indicator and it is not "
                      "self-assigned: a normal change, not proposed" + ref)
        subject = (f"remove_privileged_role:{change['target']}" if change["target"]
                   else f"remove-privilege:{change['subject']}")
        out.append(Consideration(subject=subject, reason=reason, record_ids=ids))
    return out


def _app_considerations(found: _Facts) -> list[Consideration]:
    out: list[Consideration] = []
    for app in found.apps:
        ids = tuple(app["record_ids"])
        if app["anomalous"]:
            out.append(Consideration(
                subject=f"revoke-app-permissions:{app['app_id']}",
                reason=(f"{app['summary']}: remove the application's high-privilege permission grants and app role "
                        "assignments, and disable its service principal unless it is sanctioned, in the Entra admin "
                        "center (no VERIFIED write; not in the package)"),
                record_ids=ids, manual=True))
        else:
            out.append(Consideration(
                subject=f"revoke-app-permissions:{app['app_id']}",
                reason=(f"{app['summary']}: no compromise indicator and no vendor rating: a normal change, not "
                        "proposed (check the change record)"),
                record_ids=ids))
    return out


def _account_considerations(found: _Facts) -> list[Consideration]:
    out: list[Consideration] = []
    for account in found.accounts:
        if not account["held"]:
            continue
        out.append(Consideration(
            subject=f"disable_user:{account['user']}",
            reason=(f"involved in an anomalous privilege change but {account['held']}: only the session revocation "
                    "(and the privilege removal) is proposed; the approver decides on disabling it"),
            record_ids=tuple(account["held_record_ids"])))
    return out


def _host_considerations(found: _Facts) -> list[Consideration]:
    out: list[Consideration] = []
    for host in found.hosts:
        name = host["hostname"]
        finding = found.host_findings[name]
        if host["compromised"] and host["isolation_capable"] is False:
            out.append(Consideration(
                subject=f"isolate_endpoint:{name}",
                reason=(f"{host['summary']}; the endpoint cannot be isolated by its connector policy: contain it by "
                        "hand (network or physical isolation)"),
                record_ids=tuple(host["record_ids"])))
        elif host["compromised"] and not (host["connector_guid"] or host["mde_machine_id"]):
            out.append(Consideration(
                subject=f"isolate_endpoint:{name}",
                reason=f"{host['summary']}; no endpoint product manages it (no connector or machine id): contain it "
                       "by hand",
                record_ids=tuple(host["record_ids"])))
        elif not host["compromised"] and finding.suspicious_only:
            out.append(Consideration(
                subject=f"isolate_endpoint:{name}",
                reason=("active SUSPICIOUS detection only (" + ", ".join(sorted({d.name for d in
                                                                                  finding.suspicious_only}))
                        + "): not isolated without a MALICIOUS verdict (the analyst decides)"),
                record_ids=tuple(_ids([*finding.suspicious_only, *finding.host.endpoints.values()]))))
    return out


HOOKS = PrivilegeEscalationHooks()
