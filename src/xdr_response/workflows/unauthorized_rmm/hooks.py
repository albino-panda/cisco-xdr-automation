"""Pure hooks of the unauthorised remote access tool workflow (architecture 14.3.3 and 14.10.1).

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters, no
configuration) and derive:

* ``facts`` for the rule expressions:

  - ``tools``: every remote access tool identified on the investigated endpoints (by a known
    executable name, a detection reporting T1219 or naming remote access, or a prevalence or
    persistence record of such a binary), whether something *flags* it (an endpoint detection, a
    malicious or suspicious process event, a reputation verdict) and how widespread it is;
  - ``running``: processes of those tools that started and were not seen ending;
  - ``sessions``: endpoints with an active session of a tool to a peer outside the organisation, and
    whether the operator is untrusted (the peer is rated malicious or suspicious, the connection
    record carries such a verdict, or a detection rates the tool malicious on that endpoint);
  - ``destinations``: the domains and public IPs the tools' sessions reach and the installer
    sources the binaries were written from, with their ratings.

  Every fact carries the record ids it was computed from, and the rules cite exactly those ids.
* ``correlate`` links of kind ``WORKFLOW``: a remote session (endpoint, tool hash, peer) and the
  installer origin (endpoint, tool hash, download domain or IP);
* ``considered`` items (tools nothing flags, isolations withheld, fleet-wide blocks withheld for a
  widespread tool, unrated peers and installer sources) and manual steps (uninstalling the tool);
* ``handoffs`` to ``persistence`` (the tool persists as a service or task) and ``account-takeover``
  (a user tied to the tool shows a compromise record).

The hooks never rate a tool by its name and never see ``allowlists.approved_rmm``: the framework
applies it to every proposal (excluded targets, approved signers and binaries). Nothing here creates a
record, scores a target, chooses an approval level or calls a vendor; a hook that fails is noted and
ignored by the runner.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from fnmatch import fnmatchcase
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnomalyRecord,
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    UserProfileRecord,
)
from xdr_response.models import ObservableType, Severity, TargetKind, Verdict
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks, failed_reads
from xdr_response.workflows.unauthorized_rmm.definition import (
    MAX_FLEET_BLOCK_PREVALENCE,
    REMOTE_ACCESS_CATEGORIES,
    RMM_KEYWORDS,
    RMM_PRODUCTS,
    RMM_TECHNIQUE,
)

__all__ = ["UnauthorizedRmmHooks", "HOOKS", "INTERNAL_NETWORKS", "product_of", "public_ipv4", "names_rmm"]

_MALICIOUS = Verdict.MALICIOUS
_FLAGGING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_VERDICT_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2,
                                        Verdict.MALICIOUS: 3}
_STARTS = frozenset({"process_start", "file_execute"})
_WRITES = frozenset({"file_create", "file_modify", "file_rename"})
_HIGH = frozenset({Severity.HIGH, Severity.CRITICAL})
_WORD_KEYWORDS = frozenset({"rmm"})

#: Never a session peer outside the organisation: private, loopback, link-local, shared (CGNAT),
#: multicast, reserved, unique-local. (The package builder also excludes these from any IP block.)
INTERNAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                      "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4",
                                      "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10"))


# ------------------------------------------------------------------ helpers --
def _short(sha: str) -> str:
    return sha[:12] + "..."


def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v], default=Verdict.UNKNOWN)


def _base(name: str | None) -> str:
    """Lower-case file name of a process name or path (``C:\\x\\AnyDesk.exe`` -> ``anydesk.exe``)."""
    if not name:
        return ""
    return re.split(r"[\\/]", name.strip())[-1].strip().lower()


def product_of(name: str | None) -> str | None:
    """The remote access product whose executable name matches ``name`` (a process name or a path)."""
    base = _base(name)
    if not base:
        return None
    for product, patterns in RMM_PRODUCTS.items():
        if any(fnmatchcase(base, pattern) for pattern in patterns):
            return product
    return None


def names_rmm(text: str | None) -> bool:
    """True when a detection name or category names a remote access tool (:data:`RMM_KEYWORDS`)."""
    if not text:
        return False
    lowered = text.lower()
    for keyword in RMM_KEYWORDS:
        if keyword in _WORD_KEYWORDS:
            if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", lowered):
                return True
        elif keyword in lowered:
            return True
    return False


def _remote_access_category(categories: Iterable[str]) -> bool:
    return any(c and any(k in c.lower() for k in REMOTE_ACCESS_CATEGORIES) for c in categories)


def public_ipv4(value: str | None) -> str | None:
    """The compressed IPv4 address when ``value`` is a public (non-internal) IPv4 address, else None."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if address.version != 4 or any(address in network for network in INTERNAL_NETWORKS):
        return None
    return address.compressed


def _internal_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(address.version == n.version and address in n for n in INTERNAL_NETWORKS)


def _detection_names_rmm(d: DetectionRecord) -> bool:
    return (any(str(t).upper().startswith(RMM_TECHNIQUE) for t in d.mitre_techniques)
            or names_rmm(d.name) or names_rmm(d.category)
            or product_of(d.process_name) is not None or product_of(d.file_path) is not None)


def _event_time(record: NetworkConnectionRecord | ProcessEventRecord) -> Any:
    if isinstance(record, ProcessEventRecord):
        return record.timestamp
    return record.last_seen or record.first_seen or record.observed_at


class _Tool:
    """One remote access binary (by SHA-256, or by executable name when no hash is known)."""

    def __init__(self, key: str, sha256: str | None) -> None:
        self.key = key
        self.sha256 = sha256
        self.names: set[str] = set()
        self.products: list[str] = []
        self.labels: list[str] = []

    def add_name(self, name: str | None) -> None:
        base = _base(name)
        if base:
            self.names.add(base)
            product = product_of(base)
            if product and product not in self.products:
                self.products.append(product)

    def add_label(self, label: str | None) -> None:
        if label and label not in self.labels:
            self.labels.append(label)

    @property
    def name(self) -> str:
        if self.products:
            return self.products[0]
        if self.names:
            return sorted(self.names)[0]
        if self.labels:
            return self.labels[0]
        return _short(self.sha256) if self.sha256 else "unknown tool"


class _Facts:
    """One computation of the facts over a run view (private helper of :class:`UnauthorizedRmmHooks`)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        records = view.index.records()
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.connections = [r for r in records if isinstance(r, NetworkConnectionRecord)]
        self.dns = [r for r in records if isinstance(r, DnsQueryRecord)]
        self.prevalence = [r for r in records if isinstance(r, HashPrevalenceRecord)]
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.persistence = [r for r in records if isinstance(r, PersistenceItemRecord)]
        self.profiles = [r for r in records if isinstance(r, UserProfileRecord)]
        self.anomalies = [r for r in records if isinstance(r, AnomalyRecord)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {
            (r.type, r.value.lower()): r for r in view.results if isinstance(r, ObservableReport)}
        self.tools = self._identify()
        self._tool_facts = {key: self._tool_fact(tool) for key, tool in self.tools.items()}
        self._sessions = self._compute_sessions()

    # -------------------------------------------------------- identification --
    def _identify(self) -> dict[str, _Tool]:
        tools: dict[str, _Tool] = {}

        def by_sha(sha: str) -> _Tool:
            sha = sha.lower()
            return tools.setdefault(sha, _Tool(sha, sha))

        for d in self.detections:
            if _detection_names_rmm(d) and d.sha256:
                tool = by_sha(d.sha256)
                tool.add_name(d.process_name)
                tool.add_name(d.file_path)
                tool.add_label(d.name)
        for e in self.events:
            if e.sha256 and (product_of(e.process_name) or product_of(e.file_path)):
                tool = by_sha(e.sha256)
                tool.add_name(e.process_name if product_of(e.process_name) else e.file_path)
        for c in self.connections:
            if c.sha256 and product_of(c.process_name):
                by_sha(c.sha256).add_name(c.process_name)
        for p in self.prevalence:
            if product_of(p.file_name):
                by_sha(p.sha256).add_name(p.file_name)
        for item in self.persistence:
            if item.sha256 and (product_of(item.path) or product_of(item.name)):
                by_sha(item.sha256).add_name(item.path if product_of(item.path) else item.name)
        # executable names of tools known by hash also name the same tool in records without a hash
        for tool in list(tools.values()):
            for e in self.events:
                if e.sha256 and e.sha256.lower() == tool.sha256:
                    tool.add_name(e.process_name)
            for p in self.prevalence:
                if p.sha256.lower() == tool.sha256:
                    tool.add_name(p.file_name)
        known = {n for t in tools.values() for n in t.names}

        def by_name(name: str | None) -> None:
            base = _base(name)
            if base and base not in known:
                tool = tools.setdefault(f"name:{base}", _Tool(f"name:{base}", None))
                tool.add_name(base)

        for d in self.detections:
            if _detection_names_rmm(d) and not d.sha256 and (d.process_name or d.file_path):
                by_name(d.process_name or d.file_path)
                tool = tools.get(f"name:{_base(d.process_name or d.file_path)}")
                if tool is not None:
                    tool.add_label(d.name)
        for e in self.events:
            if not e.sha256 and product_of(e.process_name):
                by_name(e.process_name)
        for c in self.connections:
            if not c.sha256 and product_of(c.process_name):
                by_name(c.process_name)
        return dict(sorted(tools.items()))

    def _is_tool(self, tool: _Tool, sha: str | None, name: str | None) -> bool:
        if tool.sha256 and sha and sha.lower() == tool.sha256:
            return True
        if sha and tool.sha256 and sha.lower() != tool.sha256:
            return False
        return bool(_base(name)) and _base(name) in tool.names

    def _tool_events(self, tool: _Tool) -> list[ProcessEventRecord]:
        return [e for e in self.events if self._is_tool(tool, e.sha256, e.process_name or e.file_path)]

    def _tool_detections(self, tool: _Tool) -> list[DetectionRecord]:
        out = []
        for d in self.detections:
            if tool.sha256 and d.sha256:
                if d.sha256.lower() == tool.sha256:
                    out.append(d)
            elif _detection_names_rmm(d) and self._is_tool(tool, None, d.process_name or d.file_path):
                out.append(d)
        return out

    def _tool_connections(self, tool: _Tool) -> list[NetworkConnectionRecord]:
        return [c for c in self.connections if self._is_tool(tool, c.sha256, c.process_name)]

    def _tool_persistence(self, tool: _Tool) -> list[PersistenceItemRecord]:
        return [p for p in self.persistence
                if self._is_tool(tool, p.sha256, p.path) or self._is_tool(tool, p.sha256, p.name)]

    def _report(self, otype: ObservableType, value: str) -> ObservableReport | None:
        return self.reports.get((otype, value.lower()))

    def _support(self, otype: ObservableType, value: str) -> list[EnrichmentRecord]:
        """Enrichment records rating ``value`` malicious or suspicious when the aggregate is too."""
        report = self._report(otype, value)
        if report is None or report.verdict not in _FLAGGING:
            return []
        return [r for r in report.records if isinstance(r, EnrichmentRecord) and r.verdict in _FLAGGING]

    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        groups = list(dict.fromkeys(g for e in mine for g in e.groups))
        tags = list(dict.fromkeys(t for e in mine for t in e.tags))
        users = list(dict.fromkeys(u for e in mine for u in e.users))
        ip = next((a for e in mine for a in e.ip_addresses), None)
        return {"groups": groups, "tags": tags, "ip": ip, "users": users}

    # ------------------------------------------------------------------ tools --
    def _tool_fact(self, tool: _Tool) -> dict[str, Any]:
        detections = self._tool_detections(tool)
        events = self._tool_events(tool)
        prevalence = [p for p in self.prevalence if tool.sha256 and p.sha256.lower() == tool.sha256]
        bad_detections = [d for d in detections if d.verdict in _FLAGGING]
        bad_events = [e for e in events if e.verdict in _FLAGGING]
        bad_prevalence = [p for p in prevalence if p.verdict in _FLAGGING]
        report = self._report(ObservableType.SHA256, tool.sha256) if tool.sha256 else None
        reputation = report.verdict if report is not None else Verdict.UNKNOWN
        support = self._support(ObservableType.SHA256, tool.sha256) if tool.sha256 else []
        basis: list[str] = []
        for d in bad_detections:
            basis.append(f"endpoint detection '{d.name}' {d.verdict.value} on {d.endpoint or 'an endpoint'}")
        if bad_events:
            basis.append(f"{_worst(e.verdict for e in bad_events).value} process events")
        if bad_prevalence:
            basis.append(f"prevalence record {_worst(p.verdict for p in bad_prevalence).value}")
        if support:
            basis.append(f"reputation {reputation.value}")
        count = max((p.prevalence for p in prevalence), default=None)
        hosts = sorted({e.endpoint for e in events} | {d.endpoint for d in detections if d.endpoint}
                       | {c.endpoint for c in self._tool_connections(tool) if c.endpoint}
                       | {p.endpoint for p in self._tool_persistence(tool)})
        flagging = [*bad_detections, *bad_events, *bad_prevalence]
        malicious_hosts = sorted({d.endpoint for d in bad_detections if d.verdict is _MALICIOUS and d.endpoint}
                                 | {e.endpoint for e in bad_events if e.verdict is _MALICIOUS})
        signers = sorted({p.signer for p in prevalence if p.signer})
        return {
            "key": tool.key,
            "name": tool.name,
            "sha256": tool.sha256,
            "executables": sorted(tool.names),
            "signers": signers,
            "flagged": bool(basis),
            "basis": "; ".join(basis) or "not flagged by any detection or reputation source",
            "reputation": reputation.value,
            "prevalence": count,
            "prevalence_text": str(count) if count is not None else "an unknown number of",
            "widespread": count is not None and count > MAX_FLEET_BLOCK_PREVALENCE,
            "endpoints": hosts,
            "malicious_endpoints": malicious_hosts,
            "flagging_ids": _ids(flagging) + [r.record_id for r in support],
            "record_ids": list(dict.fromkeys([*_ids(flagging), *_ids(prevalence), *(r.record_id for r in support)])),
            "all_ids": list(dict.fromkeys([*_ids(detections), *_ids(events), *_ids(prevalence),
                                           *_ids(self._tool_persistence(tool)), *_ids(self._tool_connections(tool))])),
        }

    # -------------------------------------------------------------- processes --
    def _ended(self, start: ProcessEventRecord, tool: _Tool) -> bool:
        for end in self.events:
            if end.event_type != "process_end" or end.endpoint != start.endpoint or end.timestamp < start.timestamp:
                continue
            if start.pid is not None and end.pid == start.pid:
                return True
            if start.pid is None and self._is_tool(tool, end.sha256, end.process_name):
                return True
        return False

    def _running(self) -> dict[tuple[str, str], list[ProcessEventRecord]]:
        """``(tool key, host) -> start events still running``."""
        out: dict[tuple[str, str], list[ProcessEventRecord]] = {}
        for key, tool in self.tools.items():
            for start in self._tool_events(tool):
                if start.event_type in _STARTS and not self._ended(start, tool):
                    out.setdefault((key, start.endpoint), []).append(start)
        return out

    def _started(self, key: str, host: str) -> bool:
        tool = self.tools[key]
        return any(e.endpoint == host and e.event_type in _STARTS for e in self._tool_events(tool))

    # --------------------------------------------------------------- sessions --
    @staticmethod
    def _peer(c: NetworkConnectionRecord) -> tuple[str | None, str | None, bool]:
        """(peer domain, public peer IPv4, external) of a connection: a peer inside the organisation
        (internal direction or a non-public remote address) is not an external session."""
        if c.direction == "internal" or _internal_ip(c.remote_ip):
            return c.domain, None, False
        ip = public_ipv4(c.remote_ip)
        return c.domain, ip, bool(c.domain) or ip is not None

    def _compute_sessions(self) -> dict[str, dict[str, Any]]:
        running = self._running()
        hosts: dict[str, dict[str, Any]] = {}
        for key, tool in self.tools.items():
            fact = self._tool_facts[key]
            for c in self._tool_connections(tool):
                if not c.endpoint or c.action == "blocked":
                    continue
                domain, ip, external = self._peer(c)
                if not external:
                    continue
                if self._started(key, c.endpoint) and not running.get((key, c.endpoint)):
                    continue  # every process of the tool on this endpoint ended: no active session
                entry = hosts.setdefault(c.endpoint, {"tools": [], "tool_keys": [], "peers": [], "basis": [],
                                                      "session_ids": [], "basis_ids": []})
                if fact["name"] not in entry["tools"]:
                    entry["tools"].append(fact["name"])
                if key not in entry["tool_keys"]:
                    entry["tool_keys"].append(key)
                for peer in (domain, ip):
                    if peer and peer not in entry["peers"]:
                        entry["peers"].append(peer)
                entry["session_ids"].append(c.record_id)
                if c.verdict in _FLAGGING:
                    entry["basis"].append(f"connection to {domain or ip} {c.verdict.value}")
                    entry["basis_ids"].append(c.record_id)
                for otype, value in ((ObservableType.DOMAIN, domain), (ObservableType.IP, ip)):
                    support = self._support(otype, value) if value else []
                    if support:
                        verdict = self._report(otype, value).verdict  # type: ignore[union-attr]
                        entry["basis"].append(f"peer {value} rated {verdict.value}")
                        entry["basis_ids"].extend(r.record_id for r in support)
        for host, entry in hosts.items():
            for key in entry["tool_keys"]:
                tool = self.tools[key]
                bad = [d for d in self._tool_detections(tool) if d.endpoint == host and d.verdict is _MALICIOUS]
                bad += [e for e in self._tool_events(tool) if e.endpoint == host and e.verdict is _MALICIOUS]
                for record in bad:
                    label = record.name if isinstance(record, DetectionRecord) else (record.process_name or "process")
                    entry["basis"].append(f"'{label}' rates {self.tools[key].name} MALICIOUS on {host}")
                    entry["basis_ids"].append(record.record_id)
        return dict(sorted(hosts.items()))

    def _flagging_on(self, key: str, host: str) -> list[AnyRecord]:
        """Detections and process events on ``host`` that rate tool ``key`` malicious or suspicious."""
        tool = self.tools[key]
        return [*(d for d in self._tool_detections(tool) if d.endpoint == host and d.verdict in _FLAGGING),
                *(e for e in self._tool_events(tool) if e.endpoint == host and e.verdict in _FLAGGING)]

    def _endpoint_identity(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        capable = [e.isolation_capable for e in mine if e.isolation_capable is not None]
        return {
            "connector_guid": next((e.connector_guid for e in mine if e.connector_guid), None),
            "mde_machine_id": next((e.mde_machine_id for e in mine if e.mde_machine_id), None),
            "isolation_capable": True if True in capable else (False if capable else None),
            "endpoint_ids": _ids(mine),
        }

    def sessions(self) -> list[dict[str, Any]]:
        running = self._running()
        out = []
        for host, entry in self._sessions.items():
            starts = [s for key in entry["tool_keys"] for s in running.get((key, host), [])]
            identity = self._endpoint_identity(host)
            basis = list(dict.fromkeys(entry["basis"]))
            # the records that flag the tool back the claim: first those on this endpoint, then the tool's
            # other flagging records (the same binary flagged on another endpoint or by reputation)
            flagging = [r for key in entry["tool_keys"] for r in self._flagging_on(key, host)]
            tool_flagging = [i for key in entry["tool_keys"] for i in self._tool_facts[key]["flagging_ids"]]
            ids = [*entry["basis_ids"], *_ids(flagging), *tool_flagging, *entry["session_ids"], *_ids(starts),
                   *identity.pop("endpoint_ids")]
            out.append({
                "hostname": host,
                "tools": entry["tools"],
                "tool_list": ", ".join(entry["tools"]),
                "peers": entry["peers"],
                "peer_list": ", ".join(entry["peers"]) or "unknown",
                "untrusted": bool(basis),
                "basis": "; ".join(basis) or "no untrusted-operator evidence",
                "record_ids": list(dict.fromkeys(ids)),
                **identity,
                **self._context(host),
            })
        return out

    def running(self) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        untrusted = {s["hostname"] for s in self.sessions() if s["untrusted"]}
        for (key, host), starts in sorted(self._running().items()):
            fact = self._tool_facts[key]
            session_untrusted = host in untrusted and key in self._sessions.get(host, {}).get("tool_keys", [])
            basis = fact["basis"] if fact["flagged"] else "untrusted remote session"
            if fact["flagged"] and session_untrusted:
                basis += "; untrusted remote session"
            for start in starts:
                ident = str(start.pid) if start.pid is not None else (start.sha256 or "").lower()
                if not ident:
                    continue
                target = f"{host}/{ident}"
                ids = [start.record_id, *[i for i in fact["flagging_ids"]]]
                if session_untrusted:
                    ids += self._sessions[host]["basis_ids"]
                entry = out.setdefault(target, {
                    "target": target, "endpoint": host, "pid": start.pid, "sha256": fact["sha256"],
                    "tool": fact["name"], "flagged": fact["flagged"], "untrusted_session": session_untrusted,
                    "basis": basis, "record_ids": [], **self._context(host)})
                entry["record_ids"] = list(dict.fromkeys([*entry["record_ids"], *ids]))
        return [out[k] for k in sorted(out)]

    # ----------------------------------------------------------- destinations --
    def destinations(self) -> list[dict[str, Any]]:
        found: dict[tuple[str, str], dict[str, Any]] = {}

        def add(kind: str, value: str | None, record: AnyRecord, key: str, role: str, host: str | None,
                verdict: Verdict) -> None:
            if not value:
                return
            entry = found.setdefault((kind, value.lower()), {"records": [], "tools": [], "roles": set(),
                                                             "endpoints": set(), "verdicts": []})
            entry["records"].append(record)
            if key not in entry["tools"]:
                entry["tools"].append(key)
            entry["roles"].add(role)
            if host:
                entry["endpoints"].add(host)
            entry["verdicts"].append(verdict)

        for key, tool in self.tools.items():
            hosts = set(self._tool_facts[key]["endpoints"])
            for c in self._tool_connections(tool):
                domain, ip, external = self._peer(c)
                if not external:
                    continue
                add("domain", domain, c, key, "session", c.endpoint, c.verdict)
                add("ip", ip, c, key, "session", c.endpoint, c.verdict)
            for e in self._tool_events(tool):
                if e.event_type == "network":
                    add("domain", e.domain, e, key, "session", e.endpoint, e.verdict)
                    add("ip", public_ipv4(e.remote_ip), e, key, "session", e.endpoint, e.verdict)
                elif e.event_type in _WRITES:
                    add("domain", e.domain, e, key, "installer", e.endpoint, Verdict.UNKNOWN)
                    add("ip", public_ipv4(e.remote_ip), e, key, "installer", e.endpoint, Verdict.UNKNOWN)
            for q in self.dns:
                if q.endpoint not in hosts or not q.domain:
                    continue
                report = self._report(ObservableType.DOMAIN, q.domain)
                categories = [*q.categories, *(report.categories() if report is not None else ())]
                if _remote_access_category(categories):
                    add("domain", q.domain, q, key, "session", q.endpoint, q.verdict)
        otypes = {"domain": ObservableType.DOMAIN, "ip": ObservableType.IP}
        out = []
        for (kind, value), entry in sorted(found.items()):
            facts = [self._tool_facts[k] for k in entry["tools"]]
            report = self._report(otypes[kind], value)
            enrichment = report.verdict if report is not None else Verdict.UNKNOWN
            contact = _worst(entry["verdicts"])
            support = self._support(otypes[kind], value)
            rated = bool(support) or contact in _FLAGGING
            flagged = [f for f in facts if f["flagged"]]
            roles = entry["roles"]
            role_text = ("session destination and installer source" if roles == {"session", "installer"}
                         else "session destination (relay or peer)" if "session" in roles else "installer source")
            basis = []
            if flagged:
                basis.append("tool flagged: " + "; ".join(f["basis"] for f in flagged))
            if support:
                basis.append(f"rated {enrichment.value} by reputation")
            if contact in _FLAGGING:
                basis.append(f"contact record {contact.value}")
            ids = [*_ids(entry["records"]), *(i for f in flagged for i in f["flagging_ids"]),
                   *(r.record_id for r in support)]
            out.append({
                "type": kind, "value": value, "session": "session" in roles, "installer": "installer" in roles,
                "role_text": role_text, "tools": [f["name"] for f in facts],
                "tool_list": ", ".join(dict.fromkeys(f["name"] for f in facts)),
                "endpoints": sorted(entry["endpoints"]), "flagged_tool": bool(flagged),
                # the flagged tools' binaries (a tool known only by name gives its key, never a hash):
                # the framework withholds a block that rests only on sanctioned binaries
                "flagged_tool_hashes": [f["sha256"] or f["key"] for f in flagged],
                "widespread_tool": any(f["widespread"] for f in facts),
                "enrichment_verdict": enrichment.value, "contact_verdict": contact.value, "rated": rated,
                "basis": "; ".join(basis) or "not rated",
                "record_ids": list(dict.fromkeys(ids)),
                "contact_ids": _ids(entry["records"]),
            })
        return out

    # ---------------------------------------------------------- consideration --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        sessions = self.sessions()
        untrusted_tools = {k for h, e in self._sessions.items() for k in e["tool_keys"]
                           if any(s["hostname"] == h and s["untrusted"] for s in sessions)}
        for key, fact in self._tool_facts.items():
            if not fact["all_ids"]:
                continue
            if not fact["flagged"] and key not in untrusted_tools:
                hosts = ", ".join(fact["endpoints"]) or "the estate"
                out.append(Consideration(
                    subject=f"rmm_tool:{fact['name']}",
                    reason=(f"remote access tool {fact['name']}"
                            f"{' (' + _short(fact['sha256']) + ')' if fact['sha256'] else ''} seen on {hosts}: no "
                            "endpoint detection, reputation verdict or untrusted session flags it, so nothing is "
                            "proposed; confirm it is sanctioned in allowlists.approved_rmm"),
                    record_ids=tuple(fact["all_ids"])))
            elif fact["flagged"] and fact["widespread"] and fact["sha256"]:
                out.append(Consideration(
                    subject=f"block_hash:{fact['sha256']}",
                    reason=(f"remote access tool {fact['name']} is seen on {fact['prevalence']} endpoints (more than "
                            f"{MAX_FLEET_BLOCK_PREVALENCE}): it looks like a corporate deployment, so no fleet-wide "
                            "block is proposed; a human decides"),
                    record_ids=tuple(fact["record_ids"] or fact["all_ids"])))
        flagged_names = {fact["name"] for fact in self._tool_facts.values() if fact["flagged"]}
        rating_failed = {k.lower(): v for k, v in failed_reads(self.view, ("enrich_ip", "enrich_domain")).items()}
        for session in sessions:
            # an unflagged tool's session is covered by its rmm_tool item; a flagged one's withheld isolation is shown
            if not session["untrusted"] and flagged_names.intersection(session["tools"]):
                unrated = [f"{', '.join(rating_failed[p.lower()])} failed for the rating of {p}"
                           for p in session["peers"] if p.lower() in rating_failed]
                out.append(Consideration(
                    subject=f"isolate_endpoint:{session['hostname']}",
                    reason=(f"active session of {session['tool_list']} to {session['peer_list']}, but no peer is "
                            "rated malicious or suspicious and no detection rates the tool malicious: not isolated "
                            "(terminating a flagged tool ends the session); verify the operator with the service "
                            "desk" + (f"; degraded: {'; '.join(unrated)}, so a peer rating may be missing"
                                      if unrated else "")),
                    record_ids=tuple(session["record_ids"])))
        for dest in self.destinations():
            if dest["rated"]:
                continue
            ids = tuple(dest["contact_ids"])
            if dest["type"] == "ip" and dest["session"] and dest["flagged_tool"]:
                out.append(Consideration(
                    subject=f"block_ip:{dest['value']}",
                    reason=(f"session peer of {dest['tool_list']} without a malicious or suspicious rating: RMM "
                            "vendor relays are shared infrastructure, so the IP is not blocked (the relay domain "
                            "block covers it)"),
                    record_ids=ids))
            elif dest["type"] == "domain" and dest["flagged_tool"] and dest["widespread_tool"] and dest["session"]:
                out.append(Consideration(
                    subject=f"block_domain:{dest['value']}",
                    reason=(f"relay of {dest['tool_list']}, a tool seen on more than {MAX_FLEET_BLOCK_PREVALENCE} "
                            "endpoints: no fleet-wide domain block is proposed; a human decides"),
                    record_ids=ids))
            elif dest["type"] == "domain" and dest["installer"] and not dest["session"] and dest["flagged_tool"]:
                out.append(Consideration(
                    subject=f"block_domain:{dest['value']}",
                    reason=(f"installer source of {dest['tool_list']}, not rated malicious or suspicious (often the "
                            "vendor's own download site): not blocked; review the download"),
                    record_ids=ids))
        out.extend(self._manual_steps(untrusted_tools))
        return out

    def _manual_steps(self, untrusted_tools: set[str]) -> list[Consideration]:
        out = []
        for key, fact in self._tool_facts.items():
            if not (fact["flagged"] or key in untrusted_tools):
                continue
            for host in fact["endpoints"]:
                tool = self.tools[key]
                ids = _ids([*(e for e in self._tool_events(tool) if e.endpoint == host),
                            *(d for d in self._tool_detections(tool) if d.endpoint == host),
                            *(p for p in self._tool_persistence(tool) if p.endpoint == host),
                            *(c for c in self._tool_connections(tool) if c.endpoint == host)])
                if not ids:
                    continue
                out.append(Consideration(
                    subject=f"uninstall {fact['name']} on {host}",
                    reason=("no VERIFIED uninstall or application-removal write in docs/integrations.md: after the "
                            "approved containment, uninstall the tool (and its service) through the endpoint "
                            "management console unless it is sanctioned in allowlists.approved_rmm (then review "
                            "its configuration and operator accounts instead), and confirm with the user how the "
                            "remote contact started"),
                    record_ids=tuple(ids), manual=True))
        return out

    # --------------------------------------------------------------- handoffs --
    def handoffs(self) -> list[Handoff]:
        out: list[Handoff] = []
        sessions = self.sessions()
        untrusted_hosts = {s["hostname"] for s in sessions if s["untrusted"]}
        in_scope = {key for key, fact in self._tool_facts.items()
                    if fact["flagged"] or any(h in untrusted_hosts for h in fact["endpoints"])}
        items = [p for key in sorted(in_scope) for p in self._tool_persistence(self.tools[key])]
        if items:
            hosts = tuple(sorted({p.endpoint for p in items}))
            listed = ", ".join(sorted({f"{p.mechanism} '{p.name}' on {p.endpoint}" for p in items}))
            out.append(Handoff(workflow_id="persistence", subjects=hosts,
                               reason=f"the remote access tool persists ({listed}); removing persistence has no "
                                      "VERIFIED write and needs the persistence review",
                               record_ids=tuple(_ids(items))))
        hosts = {h for key in in_scope for h in self._tool_facts[key]["endpoints"]}
        users = {u for e in self.endpoints if e.hostname in hosts for u in e.users}
        users |= {d.user for d in self.detections if d.user and d.endpoint in hosts}
        users |= {e.user for e in self.events if e.user and e.endpoint in hosts}
        compromised: dict[str, list[AnyRecord]] = {}
        for profile in self.profiles:
            if profile.user in users and (profile.risk_state == "confirmed_compromised" or profile.risk_level == "high"):
                compromised.setdefault(profile.user, []).append(profile)
        for anomaly in self.anomalies:
            if anomaly.user in users and anomaly.severity in _HIGH:
                compromised.setdefault(anomaly.user, []).append(anomaly)
        if compromised:
            out.append(Handoff(workflow_id="account-takeover", subjects=tuple(sorted(compromised)),
                               reason="a user of an endpoint with the remote access tool shows a compromise record "
                                      "(high or confirmed identity risk, or a high-severity anomaly)",
                               record_ids=tuple(_ids(r for user in sorted(compromised) for r in compromised[user]))))
        return out

    def as_dict(self) -> dict[str, Any]:
        tools = []
        for fact in self._tool_facts.values():
            tools.append({k: v for k, v in fact.items() if k not in ("all_ids",)})
        return {
            "tools": tools,
            "running": self.running(),
            "sessions": self.sessions(),
            "destinations": [{k: v for k, v in d.items() if k != "contact_ids"} for d in self.destinations()],
        }

    # ------------------------------------------------------------------ links --
    def links(self, origin: str) -> list[CorrelationLink]:
        links: dict[str, CorrelationLink] = {}
        for key, tool in self.tools.items():
            if not tool.sha256:
                continue
            sha = _entity(TargetKind.HASH, tool.sha256)
            records: list[tuple[AnyRecord, str]] = [(c, "remote session") for c in self._tool_connections(tool)]
            records += [(e, "installer origin" if e.event_type in _WRITES else "remote session")
                        for e in self._tool_events(tool) if e.event_type in _WRITES or e.event_type == "network"]
            for record, label in records:
                host = _entity(TargetKind.ENDPOINT, _record_endpoint(record))
                domain = _entity(TargetKind.DOMAIN, record.domain)  # type: ignore[union-attr]
                ip = _entity(TargetKind.IP, public_ipv4(record.remote_ip))  # type: ignore[union-attr]
                peer = domain or ip
                if host is None or sha is None or peer is None:
                    continue
                link = CorrelationLink(
                    kind=LinkKind.WORKFLOW, entities=(host, sha, peer), record_ids=(record.record_id,),
                    first_seen=record.observed_at, last_seen=record.observed_at,
                    note=f"{label}: {self._tool_facts[key]['name']} ({_short(tool.sha256)}) on {host.value} "
                         f"and {peer.value}",
                    origin=origin)
                links.setdefault(link.link_id, link)
        return [links[k] for k in sorted(links)]


def _record_endpoint(record: AnyRecord) -> str | None:
    """The endpoint of a connection or process event record (typed access, no reflection)."""
    if isinstance(record, (NetworkConnectionRecord, ProcessEventRecord)):
        return record.endpoint
    return None


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


class UnauthorizedRmmHooks(WorkflowHooks):
    """Facts, session links, considerations and hand-offs (pure; no context, no adapters)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _Facts(view).links(view.origin)

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Facts(view).handoffs()


HOOKS = UnauthorizedRmmHooks()
