"""Hooks of the lateral-movement workflow: pure facts, movement links and record-backed signals.

The hooks read the typed records of one run (:class:`RunView`: no context, no adapters, so they cannot
reach a vendor) and build the **movement graph**: which host reached which other host over a remote
service (RDP, SMB / admin shares, WinRM, RPC / WMI), as which account, from which process. Every fact
maps an entity to the ids of the records it was computed from, every link and signal cites those
records, and nothing is invented: a host, account, tool or address appears in a fact only when a record
of this run names it.

Movement edges come from network connection records (and ``network`` process events) on a remote
service port (:data:`LATERAL_PORTS`). The peer address is resolved to a host through the endpoint
records of the run (their ``ip_addresses``); an address two hosts claim stays unresolved. An
unresolved peer counts only on an ``internal`` connection or a non-public address (an outbound remote
desktop session to the internet is not lateral movement).

Facts (all keys always present):

``compromised_hosts``
    ``{HOST: [record ids]}``: hosts with malicious activity of their own: a MALICIOUS detection, a
    MALICIOUS process event, or a confirmed transferred tool (``tool_hosts``). The host's endpoint
    records are cited as context.
``movement_sources``
    ``{HOST: [record ids]}``: hosts with no malicious activity of their own that originated a
    *confirmed* movement edge (one end compromised, or a connection the vendor rates MALICIOUS). They
    are the quiet sources a responder must not leave active. Sanctioned admin jump hosts
    (:data:`JUMP_HOST_MARKERS`) are not listed here; they are considered instead.
``clean_targets``
    ``{HOST: [record ids]}``: destinations of a confirmed edge without malicious activity of their own:
    in the blast radius, scoped for the analyst, never isolated on that basis.
``jump_hosts``
    sorted quiet sources the endpoint records mark as admin jump hosts.
``tool_hashes`` / ``blockable_hashes`` / ``widespread_hashes`` / ``tool_hosts``
    transferred tools: hashes rated MALICIOUS (or SUSPICIOUS and named by a MALICIOUS detection or
    process event) with their prevalence; the ones seen on at most :data:`WIDESPREAD_PREVALENCE`
    endpoints are blockable, and the hosts that hold them are compromised (lateral tool transfer).
``movement_accounts``
    ``{user: [record ids]}``: accounts (UPNs) a confirmed edge or a malicious record of a compromised
    host names: the credential used for the movement.
``compromised_accounts``
    ``{user: [record ids]}``: movement accounts the identity provider confirms compromised, rates
    high risk or reports a risk detection for, and any investigated account with a sign-in from an
    address rated MALICIOUS (abnormal authentication).
``blockable_ips``
    ``{ip: [record ids]}``: addresses rated MALICIOUS or SUSPICIOUS that an investigated account
    signed in from, an edge names or the incident lists.
``edges``
    the movement graph: ``[{source, destination, protocol, port, users, processes, confirmed,
    suspicious, record_ids}]`` (an unresolved end is its IP address).
``remote_execution``
    ``{HOST: [{process, via, record_id}]}``: remote execution recorded on a host (a service started
    by the service control manager, a child of the WMI or WinRM provider host): the responsible
    process on the destination side.
``unresolved_peers``
    ``{ip: [record ids]}``: ends of confirmed edges no endpoint record of the run resolves.
``host_summary`` / ``account_summary``
    one deterministic sentence per host and account for the rationale (role, protocol, account,
    process, own activity).
``movement_confirmed``
    whether any edge is confirmed.

Signals: ``lateral movement source`` (lateral_movement, SUSPICIOUS, severity 80) for every movement
source and ``credential used for lateral movement`` (same values) for every movement account, each
citing the edge records and the records that confirm the movement.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnomalyRecord,
    AnyRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.config.policy import non_public_network
from xdr_response.models import Observable, ObservableType, TargetKind, Verdict, normalize_target
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = [
    "LATERAL_PORTS",
    "REMOTE_EXECUTION_PARENTS",
    "JUMP_HOST_MARKERS",
    "WIDESPREAD_PREVALENCE",
    "LateralMovementHooks",
    "HOOKS",
]

#: Remote service ports and the protocol a connection to them carries.
LATERAL_PORTS: Mapping[int, str] = {
    135: "RPC/WMI", 139: "SMB", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM",
}
#: Parent processes that mark a process as remotely executed on its host (lower-case base names).
REMOTE_EXECUTION_PARENTS: Mapping[str, str] = {
    "services.exe": "remote service", "wmiprvse.exe": "WMI", "wsmprovhost.exe": "WinRM",
}
#: Words in an endpoint group or tag that mark a sanctioned admin jump host.
JUMP_HOST_MARKERS: tuple[str, ...] = ("jump host", "jump-host", "jumphost", "bastion",
                                      "privileged access workstation")
#: A tool seen on more endpoints than this is left to the approver (fleet-wide binary).
WIDESPREAD_PREVALENCE = 50

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_HASH_TYPES = frozenset({ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5})
_IP_TYPES = frozenset({ObservableType.IP, ObservableType.IPV6})
_ORIGIN = "workflow:lateral-movement"
_CREDENTIAL_WORDS = ("credentialaccess", "credentialtheft", "credentialdumping")


# ------------------------------------------------------------------ helpers --
def _norm(kind: TargetKind, value: str | None) -> str | None:
    """Normalized target value, or None for an empty or unparseable one."""
    if value is None or not str(value).strip():
        return None
    try:
        return normalize_target(kind, value)
    except ValueError:
        return None


def _host(value: str | None) -> str | None:
    return _norm(TargetKind.ENDPOINT, value)


def _ip(value: str | None) -> str | None:
    return _norm(TargetKind.IP, value)


def _upn(value: str | None) -> str | None:
    """A user principal name (``name@domain``) normalized, else None (local and SYSTEM accounts)."""
    user = _norm(TargetKind.USER, value)
    return user if user and "@" in user and not user.startswith("@") else None


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def _add(table: dict[str, list[str]], key: str | None, ids: Iterable[str]) -> None:
    if not key:
        return
    bucket = table.setdefault(key, [])
    for record_id in ids:
        if record_id not in bucket:
            bucket.append(record_id)


def _unique(ids: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(ids))


def _sorted_table(table: Mapping[str, list[str]]) -> dict[str, list[str]]:
    return {key: list(table[key]) for key in sorted(table)}


def _short(sha: str) -> str:
    return sha[:12] + "..."


@dataclass
class _Records:
    """The run's records by kind (each record id once, first copy kept)."""

    detections: list[DetectionRecord] = field(default_factory=list)
    events: list[ProcessEventRecord] = field(default_factory=list)
    endpoints: list[EndpointRecord] = field(default_factory=list)
    prevalence: list[HashPrevalenceRecord] = field(default_factory=list)
    connections: list[NetworkConnectionRecord] = field(default_factory=list)
    profiles: list[UserProfileRecord] = field(default_factory=list)
    anomalies: list[AnomalyRecord] = field(default_factory=list)
    sign_ins: list[SignInRecord] = field(default_factory=list)

    @classmethod
    def of(cls, view: RunView) -> "_Records":
        out = cls()
        seen: set[str] = set()
        for result in view.results:
            for record in result.records:
                if record.record_id in seen:
                    continue
                seen.add(record.record_id)
                out.add(record)
        return out

    def add(self, record: AnyRecord) -> None:
        if isinstance(record, DetectionRecord):
            self.detections.append(record)
        elif isinstance(record, ProcessEventRecord):
            self.events.append(record)
        elif isinstance(record, EndpointRecord):
            self.endpoints.append(record)
        elif isinstance(record, HashPrevalenceRecord):
            self.prevalence.append(record)
        elif isinstance(record, NetworkConnectionRecord):
            self.connections.append(record)
        elif isinstance(record, UserProfileRecord):
            self.profiles.append(record)
        elif isinstance(record, AnomalyRecord):
            self.anomalies.append(record)
        elif isinstance(record, SignInRecord):
            self.sign_ins.append(record)


@dataclass(frozen=True)
class _Report:
    """One enrichment report: normalized value, aggregate verdict, supporting record ids."""

    type: ObservableType
    value: str
    verdict: Verdict
    supporting: tuple[str, ...]  # MALICIOUS / SUSPICIOUS enrichment records


def _reports(view: RunView) -> list[_Report]:
    out: list[_Report] = []
    for result in view.results:
        if not isinstance(result, ObservableReport):
            continue
        supporting = tuple(r.record_id for r in result.records
                           if isinstance(r, EnrichmentRecord) and r.verdict in _FLAGGED)
        out.append(_Report(type=result.type, value=result.value, verdict=result.verdict, supporting=supporting))
    return out


@dataclass
class _Edge:
    """One movement edge: ``source`` reached ``destination`` over ``protocol``."""

    source: str                      # host name, or the IP address when unresolved
    destination: str
    protocol: str
    port: int
    source_resolved: bool
    destination_resolved: bool
    records: list[AnyRecord] = field(default_factory=list)
    users: dict[str, list[str]] = field(default_factory=dict)       # user -> record ids naming it
    processes: list[str] = field(default_factory=list)              # source-side process names
    confirmed: bool = False
    suspicious: bool = False

    @property
    def record_ids(self) -> list[str]:
        return _unique(r.record_id for r in self.records)

    def verdicts(self) -> set[Verdict]:
        out: set[Verdict] = set()
        for record in self.records:
            if isinstance(record, (NetworkConnectionRecord, ProcessEventRecord)):
                out.add(record.verdict)
        return out

    def times(self) -> list[datetime]:
        out: list[datetime] = []
        for record in self.records:
            if isinstance(record, NetworkConnectionRecord):
                out.extend(t for t in (record.first_seen, record.last_seen) if t is not None)
            elif isinstance(record, ProcessEventRecord):
                out.append(record.timestamp)
            if record.observed_at is not None:
                out.append(record.observed_at)
        return sorted(out)

    def as_fact(self) -> dict[str, Any]:
        return {"source": self.source, "destination": self.destination, "protocol": self.protocol,
                "port": self.port, "users": sorted(self.users), "processes": list(self.processes),
                "confirmed": self.confirmed, "suspicious": self.suspicious, "record_ids": self.record_ids}

    def label(self) -> str:
        users = ", ".join(sorted(self.users)) or "an unrecorded account"
        process = f", process {', '.join(self.processes)}" if self.processes else ""
        return f"{self.source} -> {self.destination} over {self.protocol} as {users}{process}"


# ----------------------------------------------------------------- analysis --
class _Analysis:
    """Every fact of one run, computed once (facts, links, signals and considerations share it)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        self.records = _Records.of(view)
        self.reports = _reports(view)
        self.hash_reports = {r.value.lower(): r for r in self.reports if r.type in _HASH_TYPES}
        self.ip_reports = {r.value.lower(): r for r in self.reports if r.type in _IP_TYPES}
        self._ip_map()
        self._tools()
        self._compromised()
        self._edges()
        self._classify()
        self._remote_execution()
        self._accounts()
        self._ips()
        self._summaries()

    # ------------------------------------------------------------ hosts --
    def _endpoint_ids(self, host: str) -> list[str]:
        return [r.record_id for r in self.records.endpoints if _host(r.hostname) == host]

    def _ip_map(self) -> None:
        owners: dict[str, set[str]] = {}
        for record in self.records.endpoints:
            host = _host(record.hostname)
            for address in record.ip_addresses:
                ip = _ip(address)
                if host and ip:
                    owners.setdefault(ip, set()).add(host)
        self.ip_hosts = {ip: next(iter(hosts)) for ip, hosts in owners.items() if len(hosts) == 1}

    def _is_jump_host(self, host: str) -> bool:
        for record in self.records.endpoints:
            if _host(record.hostname) != host:
                continue
            labels = " | ".join((*record.groups, *record.tags)).lower()
            if any(marker in labels for marker in JUMP_HOST_MARKERS):
                return True
        return False

    def _jump_ids(self, host: str) -> list[str]:
        return [r.record_id for r in self.records.endpoints if _host(r.hostname) == host
                and any(m in " | ".join((*r.groups, *r.tags)).lower() for m in JUMP_HOST_MARKERS)]

    # ------------------------------------------------------------ tools --
    def _prevalence(self, sha: str) -> tuple[int | None, list[str]]:
        rows = [p for p in self.records.prevalence if p.sha256 == sha]
        return (max((p.prevalence for p in rows), default=None), [p.record_id for p in rows])

    def _hash_mentions(self, sha: str, verdicts: frozenset[Verdict]) -> list[str]:
        ids = [d.record_id for d in self.records.detections if d.sha256 == sha and d.verdict in verdicts]
        ids += [e.record_id for e in self.records.events if e.sha256 == sha and e.verdict in verdicts]
        return ids

    def _tools(self) -> None:
        self.named_malicious = {r.sha256 for r in (*self.records.detections, *self.records.events)
                                if r.sha256 and r.verdict is Verdict.MALICIOUS}
        self.tools: dict[str, dict[str, Any]] = {}
        for sha, report in sorted(self.hash_reports.items()):
            confirmed = report.verdict is Verdict.MALICIOUS or (
                report.verdict is Verdict.SUSPICIOUS and sha in self.named_malicious)
            if not confirmed:
                continue
            prevalence, prevalence_ids = self._prevalence(sha)
            ids = _unique([*report.supporting, *self._hash_mentions(sha, _FLAGGED), *prevalence_ids])
            self.tools[sha] = {"prevalence": prevalence,
                               "widespread": prevalence is not None and prevalence > WIDESPREAD_PREVALENCE,
                               "record_ids": ids}
        self.blockable = {sha: list(v["record_ids"]) for sha, v in self.tools.items() if not v["widespread"]}
        self.widespread = sorted(sha for sha, v in self.tools.items() if v["widespread"])
        table: dict[str, list[str]] = {}
        for sha in sorted(self.blockable):
            supporting = self.hash_reports[sha].supporting
            for p in self.records.prevalence:
                if p.sha256 == sha:
                    for name in p.endpoints:
                        _add(table, _host(name), [p.record_id, *supporting])
            for r in (*self.records.detections, *self.records.events):
                if r.sha256 == sha and r.verdict in _FLAGGED:
                    _add(table, _host(r.endpoint), [r.record_id, *supporting])
        self.tool_hosts = _sorted_table(table)

    # ------------------------------------------------------ compromised --
    def _compromised(self) -> None:
        table: dict[str, list[str]] = {}
        self.own_activity: dict[str, list[str]] = {}
        for d in self.records.detections:
            if d.verdict is Verdict.MALICIOUS:
                host = _host(d.endpoint)
                _add(table, host, [d.record_id])
                if host:
                    self.own_activity.setdefault(host, []).append(f"detection '{d.name}'")
        for e in self.records.events:
            if e.verdict is Verdict.MALICIOUS:
                host = _host(e.endpoint)
                _add(table, host, [e.record_id])
                if host:
                    self.own_activity.setdefault(host, []).append(
                        f"malicious {e.event_type} {e.process_name or 'process'}")
        for host, ids in self.tool_hosts.items():
            _add(table, host, ids)
            self.own_activity.setdefault(host, []).append("holds a transferred tool rated malicious")
        for host in list(table):
            _add(table, host, self._endpoint_ids(host))
        self.compromised = _sorted_table(table)

    def _activity_ids(self, host: str) -> list[str]:
        """The records that make ``host`` compromised, without its endpoint context records."""
        context = set(self._endpoint_ids(host))
        return [i for i in self.compromised.get(host, []) if i not in context]

    # ------------------------------------------------------------ edges --
    def _edge_ends(self, host: str, address: str, inbound: bool, internal: bool
                   ) -> tuple[str, str, bool, bool] | None:
        peer = self.ip_hosts.get(address)
        if peer == host:
            return None
        if peer is None and not (internal or non_public_network(address) is not None):
            return None
        peer_end = peer or address
        if inbound:
            return peer_end, host, peer is not None, True
        return host, peer_end, True, peer is not None

    def _edges(self) -> None:
        edges: dict[tuple[str, str, str], _Edge] = {}

        def add(record: AnyRecord, host: str | None, address: str | None, port: int | None, *,
                inbound: bool, internal: bool, user: str | None, process: str | None) -> None:
            protocol = LATERAL_PORTS.get(port or -1)
            ip = _ip(address)
            if protocol is None or not host or not ip or port is None:
                return
            ends = self._edge_ends(host, ip, inbound, internal)
            if ends is None:
                return
            source, destination, source_resolved, destination_resolved = ends
            edge = edges.setdefault((source, destination, protocol), _Edge(
                source=source, destination=destination, protocol=protocol, port=port,
                source_resolved=source_resolved, destination_resolved=destination_resolved))
            if record not in edge.records:
                edge.records.append(record)
            upn = _upn(user)
            if upn:
                _add(edge.users, upn, [record.record_id])
            name = _basename(process)
            if name and not inbound and name not in edge.processes:
                edge.processes.append(name)

        for c in self.records.connections:
            add(c, _host(c.endpoint), c.remote_ip, c.remote_port, inbound=c.direction == "inbound",
                internal=c.direction == "internal", user=c.user, process=c.process_name)
        for e in self.records.events:
            if e.event_type == "network":
                add(e, _host(e.endpoint), e.remote_ip, e.remote_port, inbound=False, internal=False,
                    user=e.user, process=e.process_name)
        self.edges = [edges[key] for key in sorted(edges)]

    def _classify(self) -> None:
        compromised = set(self.compromised)
        sources: dict[str, list[str]] = {}
        clean: dict[str, list[str]] = {}
        unresolved: dict[str, list[str]] = {}
        suspicious: dict[str, list[str]] = {}
        jump: dict[str, list[str]] = {}
        self.source_edges: dict[str, list[_Edge]] = {}
        for edge in self.edges:
            verdicts = edge.verdicts()
            ends = [end for end, resolved in ((edge.source, edge.source_resolved),
                                              (edge.destination, edge.destination_resolved))
                    if resolved and end in compromised]
            edge.confirmed = bool(ends) or Verdict.MALICIOUS in verdicts
            edge.suspicious = not edge.confirmed and Verdict.SUSPICIOUS in verdicts
            if edge.suspicious and edge.source_resolved and edge.source not in compromised:
                _add(suspicious, edge.source, [*edge.record_ids, *self._endpoint_ids(edge.source)])
            if not edge.confirmed:
                continue
            confirming = _unique(i for end in ends for i in self._activity_ids(end))
            for end, resolved in ((edge.source, edge.source_resolved), (edge.destination, edge.destination_resolved)):
                if not resolved:
                    _add(unresolved, end, edge.record_ids)
            if edge.source_resolved and edge.source not in compromised:
                if self._is_jump_host(edge.source):
                    _add(jump, edge.source, [*edge.record_ids, *self._jump_ids(edge.source), *confirming])
                else:
                    _add(sources, edge.source, [*edge.record_ids, *confirming, *self._endpoint_ids(edge.source)])
                    self.source_edges.setdefault(edge.source, []).append(edge)
            if edge.destination_resolved and edge.destination not in compromised:
                _add(clean, edge.destination, [*edge.record_ids, *self._endpoint_ids(edge.destination)])
        self.movement_sources = _sorted_table(sources)
        self.clean_targets = _sorted_table({h: v for h, v in clean.items() if h not in sources})
        self.unresolved = _sorted_table(unresolved)
        self.suspicious_sources = _sorted_table({h: v for h, v in suspicious.items()
                                                 if h not in sources and h not in jump})
        self.jump = _sorted_table(jump)
        self.confirmed = any(edge.confirmed for edge in self.edges)

    def _remote_execution(self) -> None:
        table: dict[str, list[dict[str, Any]]] = {}
        for e in self.records.events:
            host = _host(e.endpoint)
            via = REMOTE_EXECUTION_PARENTS.get(_basename(e.parent_process_name))
            if e.event_type == "service" and via is None:
                via = "remote service"
            if not host or via is None:
                continue
            table.setdefault(host, []).append({"process": _basename(e.process_name or e.file_path) or "unknown",
                                               "via": via, "record_id": e.record_id})
        self.remote_execution = {host: table[host] for host in sorted(table)}

    # --------------------------------------------------------- accounts --
    def _profile_ids(self, user: str) -> list[str]:
        return [p.record_id for p in self.records.profiles if _upn(p.user) == user]

    def _accounts(self) -> None:
        movement: dict[str, list[str]] = {}
        self.account_edges: dict[str, list[_Edge]] = {}
        compromised_hosts = set(self.compromised)
        for edge in self.edges:
            if not edge.confirmed:
                continue
            confirming = _unique(i for end in (edge.source, edge.destination) if end in compromised_hosts
                                 for i in self._activity_ids(end))
            for user, ids in edge.users.items():
                _add(movement, user, [*ids, *confirming])
                self.account_edges.setdefault(user, []).append(edge)
        for record in (*self.records.detections, *self.records.events):
            host = _host(record.endpoint)
            if record.verdict is Verdict.MALICIOUS and host in compromised_hosts:
                _add(movement, _upn(record.user), [record.record_id])
        for user in list(movement):
            _add(movement, user, self._profile_ids(user))
        self.movement_accounts = _sorted_table(movement)

        compromised: dict[str, list[str]] = {}
        self.account_reasons: dict[str, list[str]] = {}
        for user, ids in self.movement_accounts.items():
            profiles = [p for p in self.records.profiles if _upn(p.user) == user]
            anomalies = [a.record_id for a in self.records.anomalies if _upn(a.user) == user]
            risky = [p.record_id for p in profiles
                     if p.risk_state == "confirmed_compromised" or p.risk_level == "high"]
            if risky or anomalies:
                _add(compromised, user, [*ids, *risky, *anomalies])
                self.account_reasons.setdefault(user, []).append(
                    "identity provider rates it high risk or reports a risk detection")
        for sign_in in self.records.sign_ins:
            user = _upn(sign_in.user)
            report = self.ip_reports.get((_ip(sign_in.ip) or "").lower())
            if user and sign_in.result == "success" and report and report.verdict is Verdict.MALICIOUS:
                _add(compromised, user, [sign_in.record_id, *report.supporting, *self._profile_ids(user)])
                self.account_reasons.setdefault(user, []).append(
                    f"successful sign-in from {report.value}, rated MALICIOUS")
        self.compromised_accounts = _sorted_table(compromised)

    # -------------------------------------------------------------- ips --
    def _ips(self) -> None:
        contacts: dict[str, list[str]] = {}
        for sign_in in self.records.sign_ins:
            _add(contacts, _ip(sign_in.ip), [sign_in.record_id])
        for edge in self.edges:
            for end, resolved in ((edge.source, edge.source_resolved), (edge.destination, edge.destination_resolved)):
                if not resolved:
                    _add(contacts, end, edge.record_ids)
        incident = {_ip(o.value) for o in self.view.incident.observables if o.type in _IP_TYPES}
        table: dict[str, list[str]] = {}
        self.ip_contacts: dict[str, list[str]] = {}  # blockable address -> sign-in / edge records naming it
        for key, report in sorted(self.ip_reports.items()):
            if report.verdict not in _FLAGGED or not report.supporting:
                continue
            ip = _ip(report.value)
            if ip is None or ip in self.ip_hosts:
                continue  # an address an investigated host owns is contained by isolation, not a block
            seen = contacts.get(ip, [])
            if not seen and ip not in incident:
                continue
            _add(table, report.value, [*seen, *report.supporting])
            if seen:
                self.ip_contacts[report.value] = seen
        self.blockable_ips = _sorted_table(table)

    # -------------------------------------------------------- summaries --
    def _summaries(self) -> None:
        summary: dict[str, str] = {}
        hosts = sorted({*self.compromised, *self.movement_sources})
        for host in hosts:
            parts: list[str] = []
            out_edges = [e for e in self.edges if e.confirmed and e.source == host]
            in_edges = [e for e in self.edges if e.confirmed and e.destination == host]
            if out_edges:
                parts.append("source of " + "; ".join(e.label() for e in out_edges))
            if in_edges:
                parts.append("reached by " + "; ".join(e.label() for e in in_edges))
            executed = self.remote_execution.get(host, [])
            if executed:
                parts.append("remote execution: " + ", ".join(
                    sorted({f"{x['process']} via {x['via']}" for x in executed})))
            activity = self.own_activity.get(host, [])
            if activity:
                parts.append("own malicious activity: " + ", ".join(dict.fromkeys(activity)))
            elif host in self.movement_sources:
                parts.append("no malicious activity of its own: isolated as the origin of confirmed movement")
            summary[host] = f"{host}: " + "; ".join(parts or ["involved in the movement"])
        self.host_summary = summary
        accounts: dict[str, str] = {}
        for user in sorted({*self.movement_accounts, *self.compromised_accounts}):
            parts = []
            edges = self.account_edges.get(user, [])
            if edges:
                parts.append("used for " + "; ".join(f"{e.source} -> {e.destination} over {e.protocol}"
                                                      for e in edges))
            elif user in self.movement_accounts:
                parts.append("named by malicious activity on a compromised host")
            parts.extend(dict.fromkeys(self.account_reasons.get(user, [])))
            accounts[user] = f"{user}: " + "; ".join(parts)
        self.account_summary = accounts

    # ------------------------------------------------------------ views --
    def facts(self) -> dict[str, Any]:
        return {
            "compromised_hosts": self.compromised,
            "movement_sources": self.movement_sources,
            "clean_targets": self.clean_targets,
            "jump_hosts": sorted(self.jump),
            "tool_hashes": {sha: dict(v) for sha, v in self.tools.items()},
            "blockable_hashes": self.blockable,
            "widespread_hashes": self.widespread,
            "tool_hosts": self.tool_hosts,
            "movement_accounts": self.movement_accounts,
            "compromised_accounts": self.compromised_accounts,
            "blockable_ips": self.blockable_ips,
            "edges": [edge.as_fact() for edge in self.edges],
            "remote_execution": self.remote_execution,
            "unresolved_peers": self.unresolved,
            "host_summary": self.host_summary,
            "account_summary": self.account_summary,
            "movement_confirmed": self.confirmed,
        }

    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for host, ids in self.clean_targets.items():
            reached = [e for e in self.edges if e.confirmed and e.destination == host]
            how = "; ".join(e.label() for e in reached)
            out.append(Consideration(
                subject=f"isolate_endpoint:{host}", record_ids=tuple(ids),
                reason=f"reached by confirmed lateral movement ({how}) but no malicious activity of its own: "
                       "in the blast radius, not isolated; review it and isolate by hand if activity appears"))
        for host, ids in self.jump.items():
            out.append(Consideration(
                subject=f"isolate_endpoint:{host}", record_ids=tuple(ids),
                reason="sanctioned admin jump host that originated the movement but has no malicious activity "
                       "of its own: not isolated (isolation cuts administration of every server it manages); "
                       "the movement account is revoked instead; review the jump host session by hand"))
        for host, ids in self.suspicious_sources.items():
            out.append(Consideration(
                subject=f"isolate_endpoint:{host}", record_ids=tuple(ids),
                reason="east-west remote service traffic rated SUSPICIOUS, but no host involved shows malicious "
                       "activity: movement not confirmed, not isolated"))
        for host in sorted({*self.compromised, *self.movement_sources}):
            locked = [r.record_id for r in self.records.endpoints
                      if _host(r.hostname) == host and r.isolation_capable is False]
            if locked:
                ids = [*self.compromised.get(host, []), *self.movement_sources.get(host, []), *locked]
                out.append(Consideration(
                    subject=f"isolate_endpoint:{host}", record_ids=tuple(_unique(ids)),
                    reason="the endpoint's policy does not allow isolation: contain it by hand (network or console)"))
        for sha in self.widespread:
            entry = self.tools[sha]
            out.append(Consideration(
                subject=f"block_hash:{sha}", record_ids=tuple(entry["record_ids"]),
                reason=f"tool hash seen on {entry['prevalence']} endpoints (more than {WIDESPREAD_PREVALENCE}): "
                       "not proposed for a fleet-wide block; a human decides"))
        for sha in sorted(self.named_malicious):
            report = self.hash_reports.get(sha)
            if report is not None and report.verdict is not Verdict.UNKNOWN:
                continue
            ids = [*self._hash_mentions(sha, frozenset(Verdict)), *self._prevalence(sha)[1]]
            if ids:
                out.append(Consideration(subject=f"block_hash:{sha}", record_ids=tuple(_unique(ids)),
                                         reason="named by a malicious detection but without a reputation "
                                                "verdict: not blocked"))
        for address, ids in self.unresolved.items():
            out.append(Consideration(
                subject=f"lateral peer {address}", record_ids=tuple(ids), manual=True,
                reason="an end of confirmed lateral movement that no investigated endpoint owns: identify the "
                       "host behind this address, investigate it and contain it by hand if needed"))
        return out

    def handoffs(self) -> list[Handoff]:
        out: list[Handoff] = []
        if self.compromised_accounts:
            ids = _unique(i for user in self.compromised_accounts for i in self.compromised_accounts[user])
            out.append(Handoff(
                workflow_id="account-takeover", subjects=tuple(self.compromised_accounts), record_ids=tuple(ids),
                reason="account used for or tied to lateral movement is compromised: review its sign-ins, MFA "
                       "and cloud activity beyond the endpoints"))
        dumped: dict[str, list[str]] = {}
        for d in self.records.detections:
            host = _host(d.endpoint)
            if host not in self.compromised or d.verdict not in _FLAGGED:
                continue
            category = "".join(ch for ch in (d.category or "").lower() if ch.isalnum())
            if any(t == "T1003" or t.startswith("T1003.") for t in d.mitre_techniques) or any(
                    word in category for word in _CREDENTIAL_WORDS):
                _add(dumped, host, [d.record_id])
        if dumped:
            out.append(Handoff(
                workflow_id="credential-dumping", subjects=tuple(sorted(dumped)),
                record_ids=tuple(_unique(i for host in sorted(dumped) for i in dumped[host])),
                reason="credential access reported on a host of the movement: scope the exposed credentials"))
        return out

    def links(self) -> list[CorrelationLink]:
        out: dict[str, CorrelationLink] = {}
        for edge in self.edges:
            if not (edge.source_resolved and edge.destination_resolved):
                continue
            entities = [EntityRef(kind=TargetKind.ENDPOINT, value=edge.source),
                        EntityRef(kind=TargetKind.ENDPOINT, value=edge.destination)]
            entities += [EntityRef(kind=TargetKind.USER, value=u) for u in sorted(edge.users)]
            times = edge.times()
            link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=tuple(entities),
                                   record_ids=tuple(sorted(edge.record_ids)),
                                   first_seen=times[0] if times else None, last_seen=times[-1] if times else None,
                                   note=f"lateral movement: {edge.label()}", origin=_ORIGIN)
            out.setdefault(link.link_id, link)
        return [out[key] for key in sorted(out)]

    def signals(self) -> list[ScoringSignal]:
        by_id = {r.record_id: r for r in self.view.index.records()}
        out: list[ScoringSignal] = []
        for host, ids in self.movement_sources.items():
            cited = [by_id[i] for i in ids if i in by_id]
            edges = self.source_edges.get(host, [])
            first = next((r for e in edges for r in e.records), None)
            if first is None or not cited:
                continue
            out.append(_signal(Observable(type=ObservableType.HOSTNAME, value=host), first.integration, cited,
                               "origin of confirmed lateral movement: "
                               + "; ".join(e.label() for e in edges)))
        for user in self.movement_accounts:
            edges = self.account_edges.get(user, [])
            first = next((r for e in edges for r in e.records), None)
            if first is None:
                continue
            cited = [by_id[i] for i in self.movement_accounts[user] if i in by_id]
            out.append(_signal(Observable(type=ObservableType.USER, value=user), first.integration, cited,
                               "credential used for confirmed lateral movement: "
                               + "; ".join(f"{e.source} -> {e.destination} over {e.protocol}" for e in edges)))
        for address, ids in sorted(self.ip_contacts.items()):
            cited = [by_id[i] for i in ids if i in by_id]
            if not cited:
                continue
            sign_in = any(isinstance(r, SignInRecord) for r in cited)
            otype = ObservableType.IPV6 if ":" in address else ObservableType.IP
            out.append(_signal(Observable(type=otype, value=address), cited[0].integration, cited,
                               "address rated malicious or suspicious used by "
                               + ("a sign-in of an investigated account" if sign_in else "an end of the movement"),
                               category=(SignalCategory.AUTHENTICATION_ANOMALY if sign_in
                                         else SignalCategory.LATERAL_MOVEMENT), severity=70, confidence=70))
        return out


def _signal(observable: Observable, integration: str, cited: Sequence[AnyRecord], note: str, *,
            category: SignalCategory = SignalCategory.LATERAL_MOVEMENT, severity: int = 80,
            confidence: int = 75) -> ScoringSignal:
    return ScoringSignal(category=category, integration=integration, observable=observable,
                         verdict=Verdict.SUSPICIOUS, severity=severity, confidence=confidence,
                         record_ids=tuple(_unique(r.record_id for r in cited)), origin=_ORIGIN, note=note[:500])


class LateralMovementHooks(WorkflowHooks):
    """Movement graph facts, links, signals, considerations and hand-offs (pure; no context)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _Analysis(view).links()

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return _Analysis(view).signals()

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Analysis(view).facts()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Analysis(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Analysis(view).handoffs()


HOOKS = LateralMovementHooks()
