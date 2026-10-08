"""Pure hooks of the Suspicious PowerShell workflow (architecture 14.3.3): facts, links, considered items.

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters) and
derive, per run of an evaluated system binary (PowerShell, pwsh, mshta, rundll32, regsvr32,
certutil, wmic, wscript, cscript, bitsadmin, installutil) on an investigated endpoint:

* what the vendor says about it (detections naming the process, its image or its payload, with the
  vendor-reported techniques, and the process event's own verdict);
* what it wrote or started (payload hashes) and whether a payload is malicious;
* which destinations it contacted (domain, URL, public IPv4) and their reputation;
* whether it is still running.

Using one of these binaries is never malicious on its own. A run is **malicious** only when one of
these holds: it wrote or started a malicious payload; the vendor rates the process (or a detection
naming it) MALICIOUS; or it contacted a malicious destination on an endpoint that has an active
malicious detection. Everything else is reported as considered, with the records that were checked.

Every fact carries the record ids it was computed from, and the rules cite exactly those ids. Nothing
here creates a record, scores a target, chooses an approval level or calls a vendor; a hook that
fails is noted and ignored by the runner. Hosts are upper case and hashes, domains and URLs lower
case, as the record normalizers store them.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnyRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
)
from xdr_response.config.policy import host_ip, non_public_network
from xdr_response.models import ObservableType, TargetKind, Verdict
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks
from xdr_response.workflows.malicious_powershell.definition import (
    LOLBINS,
    MAX_HASH_BLOCK_PREVALENCE,
    START_EVENT_TYPES,
    WRITE_EVENT_TYPES,
)

__all__ = ["MaliciousPowershellHooks", "HOOKS", "destinations_of", "lolbin_name", "public_ipv4", "url_destination"]

_MALICIOUS = Verdict.MALICIOUS
_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}
_STARTS = frozenset(START_EVENT_TYPES)
_WRITES = frozenset(WRITE_EVENT_TYPES)
_LOLBINS = frozenset(LOLBINS)
_OTYPES: Mapping[str, ObservableType] = {"domain": ObservableType.DOMAIN, "url": ObservableType.URL,
                                         "ip": ObservableType.IP}


def lolbin_name(process_name: str | None) -> str | None:
    """The evaluated binary a process name denotes (``"powershell"``), or None.

    Only the image name counts (path and ``.exe`` removed, case ignored): ``C:/x/PowerShell.EXE`` is
    ``powershell``; ``powershell_helper.exe`` is not.
    """
    if not process_name:
        return None
    base = process_name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base if base in _LOLBINS else None


def public_ipv4(value: str | None) -> str | None:
    """The compressed IPv4 address when ``value`` is a public (non-internal) IPv4 address, else None."""
    if not value:
        return None
    ip = host_ip(value.strip())
    if ip is None or ip.version != 4 or non_public_network(ip) is not None:
        return None
    return ip.compressed


def url_destination(url: str) -> str:
    """The destination a URL names, without its userinfo (14.11.7).

    A ``user:password@`` part is a credential, never part of the destination: it must not reach a
    basis text, a rationale, a notification or a block target. The rest of the URL is unchanged.
    """
    value = url.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if "@" not in parts.netloc:
        return value
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[1], parts.path, parts.query, parts.fragment))


def destinations_of(record: AnyRecord) -> list[tuple[str, str]]:
    """``(kind, value)`` destinations a process event or connection names: domain, URL (without
    userinfo), public IPv4."""
    out: list[tuple[str, str]] = []
    if not isinstance(record, (ProcessEventRecord, NetworkConnectionRecord)):
        return out
    if record.domain:
        out.append(("domain", record.domain.lower()))
    if isinstance(record, NetworkConnectionRecord) and record.url:
        out.append(("url", url_destination(record.url)))
    ip = public_ipv4(record.remote_ip)
    if ip:
        out.append(("ip", ip))
    return out


def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _short(sha: str) -> str:
    return sha[:12] + "..."


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _RANK[v], default=Verdict.UNKNOWN)


@dataclass
class _Run:
    """One run of an evaluated binary on one endpoint (private to the hooks)."""

    start: ProcessEventRecord
    name: str
    host: str
    pid: int | None
    own: list[ProcessEventRecord] = field(default_factory=list)       # events of the same process
    writes: list[ProcessEventRecord] = field(default_factory=list)    # files it wrote (with a hash)
    children: list[ProcessEventRecord] = field(default_factory=list)  # processes it started
    contacts: list[AnyRecord] = field(default_factory=list)           # its network activity
    detections: list[DetectionRecord] = field(default_factory=list)   # vendor detections naming it
    ended: bool = False

    @property
    def target(self) -> str:
        return f"{self.host}/{self.pid}" if self.pid is not None else f"{self.host}/{self.name}"

    @property
    def label(self) -> str:
        return f"{self.name} (pid {self.pid}) on {self.host}" if self.pid is not None else f"{self.name} on {self.host}"


class _Facts:
    """One computation of the facts over a run view (private helper of the hooks)."""

    def __init__(self, view: RunView) -> None:
        records = view.index.records()
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.prevalence = [r for r in records if isinstance(r, HashPrevalenceRecord)]
        self.connections = [r for r in records if isinstance(r, NetworkConnectionRecord)]
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.persistence = [r for r in records if isinstance(r, PersistenceItemRecord)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {
            (r.type, r.value.lower()): r for r in view.results if isinstance(r, ObservableReport)}
        # Image hashes of the evaluated binaries: system binaries, never payloads, never blocked.
        self.images = {e.sha256.lower() for e in self.events
                       if e.sha256 and e.event_type in _STARTS and lolbin_name(e.process_name)}
        self.runs = self._runs()

    # ------------------------------------------------------------ helpers --
    def _report(self, otype: ObservableType, value: str) -> ObservableReport | None:
        return self.reports.get((otype, value.lower()))

    def _enrichment_verdict(self, otype: ObservableType, value: str) -> Verdict:
        report = self._report(otype, value)
        return report.verdict if report is not None else Verdict.UNKNOWN

    def _support(self, otype: ObservableType, value: str) -> list[str]:
        """Enrichment records rating ``value`` malicious or suspicious, when the aggregate is supporting."""
        report = self._report(otype, value)
        if report is None or report.verdict not in _SUPPORTING:
            return []
        return _ids(r for r in report.records if isinstance(r, EnrichmentRecord) and r.verdict in _SUPPORTING)

    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        return {"groups": list(dict.fromkeys(g for e in mine for g in e.groups)),
                "tags": list(dict.fromkeys(t for e in mine for t in e.tags)),
                "ip": next((a for e in mine for a in e.ip_addresses), None)}

    # --------------------------------------------------------------- runs --
    def _runs(self) -> list[_Run]:
        runs: dict[tuple[str, str], _Run] = {}
        for event in self.events:
            name = lolbin_name(event.process_name)
            if name is None or event.event_type not in _STARTS:
                continue
            key = (event.endpoint, str(event.pid) if event.pid is not None else name)
            if key not in runs:
                runs[key] = _Run(start=event, name=name, host=event.endpoint, pid=event.pid)
        out = [runs[k] for k in sorted(runs)]
        for run in out:
            self._fill(run)
        return out

    def _same_process(self, run: _Run, event: ProcessEventRecord) -> bool:
        if event.endpoint != run.host or event.record_id == run.start.record_id:
            return False
        if run.pid is not None:
            return event.pid == run.pid
        return event.pid is None and lolbin_name(event.process_name) == run.name

    def _fill(self, run: _Run) -> None:
        image = (run.start.sha256 or "").lower() or None
        for event in self.events:
            if event.timestamp < run.start.timestamp:
                continue
            if self._same_process(run, event):
                run.own.append(event)
                if event.event_type in _WRITES and event.sha256:
                    run.writes.append(event)
                if event.event_type == "process_end":
                    run.ended = True
                if event.domain or public_ipv4(event.remote_ip):
                    run.contacts.append(event)
            elif (run.pid is not None and event.endpoint == run.host and event.parent_pid == run.pid
                  and event.event_type in _STARTS):
                run.children.append(event)
        for connection in self.connections:
            if connection.endpoint != run.host or connection.direction in ("inbound", "internal"):
                continue
            if lolbin_name(connection.process_name) != run.name:
                continue
            if image and connection.sha256 and connection.sha256.lower() != image:
                continue
            if run.pid is not None and connection.pid is not None and connection.pid != run.pid:
                continue  # another instance of the same binary on this host (14.11.3)
            run.contacts.append(connection)
        payloads = set(self._payload_hashes(run))
        for detection in self.detections:
            if detection.endpoint != run.host or detection.verdict not in _SUPPORTING:
                continue
            if detection.status == "resolved":
                continue
            sha = (detection.sha256 or "").lower()
            if (lolbin_name(detection.process_name) == run.name or (image and sha == image)
                    or (sha and sha in payloads)):
                run.detections.append(detection)

    def _payload_hashes(self, run: _Run) -> list[str]:
        shas = [e.sha256.lower() for e in run.writes if e.sha256]
        shas += [c.sha256.lower() for c in run.children if c.sha256 and not lolbin_name(c.process_name)]
        return [s for s in dict.fromkeys(shas) if s not in self.images]

    # ------------------------------------------------------------- hashes --
    def _hash_records(self, sha: str) -> tuple[list[AnyRecord], list[str]]:
        """``(malicious records, basis)`` for a payload hash (detections, telemetry, enrichment)."""
        bad: list[AnyRecord] = [d for d in self.detections if (d.sha256 or "").lower() == sha and d.verdict is _MALICIOUS]
        basis = ["endpoint detection"] if bad else []
        telemetry: list[AnyRecord] = [p for p in self.prevalence if p.sha256.lower() == sha and p.verdict is _MALICIOUS]
        telemetry += [e for e in self.events if (e.sha256 or "").lower() == sha and e.verdict is _MALICIOUS]
        if telemetry:
            basis.append("endpoint telemetry")
        if self._enrichment_verdict(ObservableType.SHA256, sha) is _MALICIOUS:
            basis.append("enrichment")
        return [*bad, *telemetry], basis

    def _payload_malicious(self, sha: str) -> bool:
        return bool(self._hash_records(sha)[1])

    def _payload_ids(self, run: _Run, sha: str) -> list[str]:
        events = [e for e in [*run.writes, *run.children] if (e.sha256 or "").lower() == sha]
        bad, _basis = self._hash_records(sha)
        prevalence = [p for p in self.prevalence if p.sha256.lower() == sha]
        return list(dict.fromkeys([*_ids(events), *_ids(bad), *_ids(prevalence),
                                   *self._support(ObservableType.SHA256, sha)]))

    # ------------------------------------------------------- destinations --
    def _malicious_destinations(self, run: _Run) -> list[tuple[str, str, AnyRecord]]:
        found = []
        for record in run.contacts:
            for kind, value in destinations_of(record):
                contact = record.verdict if isinstance(record, NetworkConnectionRecord) else Verdict.UNKNOWN
                if contact is _MALICIOUS or self._enrichment_verdict(_OTYPES[kind], value) is _MALICIOUS:
                    found.append((kind, value, record))
        return found

    # ------------------------------------------------------------- verdict --
    def _assess(self, run: _Run) -> dict[str, Any]:
        payloads = [s for s in self._payload_hashes(run) if self._payload_malicious(s)]
        vendor = [d for d in run.detections if d.verdict is _MALICIOUS]
        own_verdict = run.start.verdict is _MALICIOUS
        destinations = self._malicious_destinations(run)
        host_detected = any(d.endpoint == run.host and d.verdict is _MALICIOUS and d.status != "resolved"
                            for d in self.detections)
        basis: list[str] = []
        ids: list[str] = [run.start.record_id]
        if payloads:
            basis.append("retrieved or started malicious payload " + ", ".join(_short(s) for s in payloads))
            for sha in payloads:
                ids += self._payload_ids(run, sha)
        if vendor or own_verdict:
            techniques = sorted({t for d in vendor for t in d.mitre_techniques})
            text = "the endpoint vendor rates the process malicious"
            basis.append(text + (f" (reported techniques {', '.join(techniques)})" if techniques else ""))
            ids += _ids(vendor)
        if destinations and host_detected:
            basis.append("contacted malicious destination " + ", ".join(sorted({v for _k, v, _r in destinations}))
                         + " on an endpoint with an active malicious detection")
            ids += _ids(r for _k, _v, r in destinations)
            for kind, value, _record in destinations:
                ids += self._support(_OTYPES[kind], value)
            ids += _ids(d for d in self.detections
                        if d.endpoint == run.host and d.verdict is _MALICIOUS and d.status != "resolved")
        return {"malicious": bool(basis), "basis": "; ".join(basis), "payloads": payloads,
                "record_ids": list(dict.fromkeys(ids)), "destinations": destinations,
                "host_detected": host_detected}

    # -------------------------------------------------------------- facts --
    def terminate(self) -> list[dict[str, Any]]:
        out = []
        for run in self.runs:
            verdict = self._assess(run)
            if not verdict["malicious"] or run.ended or run.pid is None:
                continue
            out.append({"target": run.target, "endpoint": run.host, "pid": run.pid, "process": run.name,
                        "basis": verdict["basis"], "record_ids": verdict["record_ids"], **self._context(run.host)})
        return out

    def isolate(self) -> dict[str, dict[str, Any]]:
        """Endpoints to isolate: a malicious payload of a malicious run landed there (the run's endpoint
        or an endpoint the payload's prevalence names), or a malicious detection there follows contact
        with a malicious destination."""
        hosts: dict[str, dict[str, Any]] = {}

        def add(host: str, reason: str, ids: Iterable[str]) -> None:
            entry = hosts.setdefault(host, {"reasons": [], "record_ids": []})
            if reason not in entry["reasons"]:
                entry["reasons"].append(reason)
            entry["record_ids"] = list(dict.fromkeys([*entry["record_ids"], *ids]))

        for run in self.runs:
            verdict = self._assess(run)
            for sha in verdict["payloads"]:
                ids = self._payload_ids(run, sha)
                add(run.host, f"malicious payload {_short(sha)} retrieved by {run.label}", ids)
                for record in self.prevalence:
                    if record.sha256.lower() != sha:
                        continue
                    for host in record.endpoints:
                        if host != run.host:
                            add(host, f"malicious payload {_short(sha)} retrieved by {run.label} is present "
                                      f"(hash prevalence)", [record.record_id, *ids])
            if verdict["destinations"] and verdict["host_detected"]:
                detections = [d for d in self.detections if d.endpoint == run.host and d.verdict is _MALICIOUS
                              and d.status != "resolved"]
                ids = [*_ids(detections), run.start.record_id, *_ids(r for _k, _v, r in verdict["destinations"])]
                for kind, value, _record in verdict["destinations"]:
                    ids += self._support(_OTYPES[kind], value)
                values = ", ".join(sorted({v for _k, v, _r in verdict["destinations"]}))
                add(run.host, f"malicious detection after {run.label} contacted malicious destination {values}", ids)
        return {host: {"summary": "; ".join(entry["reasons"]), "record_ids": entry["record_ids"],
                       **self._context(host)} for host, entry in sorted(hosts.items())}

    def payloads(self) -> list[dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for run in self.runs:
            verdict = self._assess(run)
            for sha in verdict["payloads"]:
                entry = found.setdefault(sha, {"sha256": sha, "processes": [], "record_ids": []})
                entry["processes"].append(run.label)
                entry["record_ids"] = list(dict.fromkeys([*entry["record_ids"], *self._payload_ids(run, sha)]))
        out = []
        for sha in sorted(found):
            entry = found[sha]
            count = max((p.prevalence for p in self.prevalence if p.sha256.lower() == sha), default=None)
            out.append({**entry, "process_list": ", ".join(dict.fromkeys(entry["processes"])),
                        "basis": ", ".join(self._hash_records(sha)[1]), "prevalence": count,
                        "prevalence_text": str(count) if count is not None else "an unknown number of",
                        "widespread": count is not None and count > MAX_HASH_BLOCK_PREVALENCE})
        return out

    def destinations(self) -> list[dict[str, Any]]:
        """Every destination an evaluated process contacted, with its verdicts and the contact records."""
        found: dict[tuple[str, str], dict[str, Any]] = {}
        for run in self.runs:
            malicious_payloads = self._assess(run)["payloads"]
            for record in run.contacts:
                for kind, value in destinations_of(record):
                    entry = found.setdefault((kind, value), {"records": [], "verdicts": [], "processes": [],
                                                             "support": []})
                    entry["records"].append(record)
                    entry["verdicts"].append(record.verdict if isinstance(record, NetworkConnectionRecord)
                                             else Verdict.UNKNOWN)
                    entry["processes"].append(run.label)
                    # A malicious payload came from it: the run wrote the payload with this origin,
                    # or the run that contacted it retrieved a malicious payload.
                    for sha in malicious_payloads:
                        entry["support"] += self._payload_ids(run, sha)
        out = []
        for (kind, value), entry in sorted(found.items()):
            enrichment = self._enrichment_verdict(_OTYPES[kind], value)
            support = list(dict.fromkeys(entry["support"]))
            confirmed = bool(support)
            ids = _ids(entry["records"])
            if confirmed and enrichment is Verdict.SUSPICIOUS:
                ids = list(dict.fromkeys([*ids, *support]))
            out.append({"type": kind, "value": value, "enrichment_verdict": enrichment.value,
                        "contact_verdict": _worst(entry["verdicts"]).value, "payload_confirmed": confirmed,
                        "process_list": ", ".join(dict.fromkeys(entry["processes"])), "record_ids": ids})
        return out

    def as_dict(self) -> dict[str, Any]:
        runs = []
        for run in self.runs:
            verdict = self._assess(run)
            runs.append({"target": run.target, "process": run.name, "endpoint": run.host, "pid": run.pid,
                         "parent": run.start.parent_process_name, "user": run.start.user,
                         "malicious": verdict["malicious"], "basis": verdict["basis"], "ended": run.ended,
                         "payloads": verdict["payloads"], "record_ids": verdict["record_ids"]})
        return {"runs": runs, "terminate": self.terminate(), "isolate": self.isolate(),
                "payloads": self.payloads(), "destinations": self.destinations()}

    # -------------------------------------------------- considered, hand-offs --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for run in self.runs:
            verdict = self._assess(run)
            if verdict["malicious"]:
                if run.ended:
                    out.append(Consideration(
                        subject=f"terminate_process:{run.target}",
                        reason=f"{run.label} is malicious but already ended: nothing to terminate",
                        record_ids=tuple(_ids([run.start, *[e for e in run.own if e.event_type == 'process_end']]))))
                continue
            checked = _ids([run.start, *run.contacts, *run.writes, *run.children, *run.detections])
            bad = self._malicious_destinations(run)
            if bad:
                reason = (f"{run.label} contacted a malicious destination, but no malicious payload landed and the "
                          "endpoint has no active malicious detection: the destination block is proposed, the "
                          "process is not terminated and the endpoint is not isolated")
            else:
                parent = run.start.parent_process_name or "an unknown parent"
                suspicious = [d for d in run.detections if d.verdict is Verdict.SUSPICIOUS]
                flagged = ""
                if suspicious:
                    techniques = sorted({t for d in suspicious for t in d.mitre_techniques})
                    flagged = (" The vendor's SUSPICIOUS detection" + (f" (reported techniques {', '.join(techniques)})"
                                                                         if techniques else "")
                               + " is a characteristic, not proof.")
                reason = (f"{run.label} (parent {parent}) shows no malicious corroboration: no malicious vendor "
                          "detection, no malicious payload, no malicious destination." + flagged
                          + " Use of a system binary alone is not malicious: not proposed")
            out.append(Consideration(subject=f"terminate_process:{run.target}", reason=reason,
                                     record_ids=tuple(checked)))
        for payload in self.payloads():
            if payload["widespread"]:
                out.append(Consideration(
                    subject=f"block_hash:{payload['sha256']}",
                    reason=(f"malicious payload seen on {payload['prevalence']} endpoints (more than "
                            f"{MAX_HASH_BLOCK_PREVALENCE}): not proposed for a fleet-wide block; a human decides"),
                    record_ids=tuple(payload["record_ids"])))
        for sha in sorted(self.images):
            flagged = [d for d in self.detections if (d.sha256 or "").lower() == sha and d.verdict in _SUPPORTING]
            rated = self._enrichment_verdict(ObservableType.SHA256, sha) in _SUPPORTING
            if not flagged and not rated:
                continue
            starts = [e for e in self.events if (e.sha256 or "").lower() == sha and e.event_type in _STARTS]
            names = ", ".join(sorted({lolbin_name(e.process_name) or "" for e in starts}))
            ids = _ids([*flagged, *starts]) + self._support(ObservableType.SHA256, sha)
            out.append(Consideration(
                subject=f"block_hash:{sha}",
                reason=(f"image hash of the system binary {names}: blocking it would break legitimate use of the "
                        "binary across the estate, so it is never proposed; the process and its payloads are "
                        "handled instead"),
                record_ids=tuple(dict.fromkeys(ids))))
        return out

    def handoffs(self) -> list[Handoff]:
        out: list[Handoff] = []
        payloads = self.payloads()
        if payloads:
            out.append(Handoff(
                workflow_id="malware",
                subjects=tuple(p["sha256"] for p in payloads),
                reason="a system binary retrieved a malicious payload: the malware workflow scopes the file "
                       "across the estate and quarantines it (this workflow blocks the hash only)",
                record_ids=tuple(dict.fromkeys(i for p in payloads for i in p["record_ids"]))))
        affected = {run.host for run in self.runs if self._assess(run)["malicious"]}
        payload_shas = {p["sha256"] for p in payloads}
        items = [p for p in self.persistence if p.endpoint in affected
                 and (p.verdict in _SUPPORTING or (p.sha256 or "").lower() in payload_shas)]
        if items:
            listed = ", ".join(sorted({f"{p.mechanism} '{p.name}' on {p.endpoint}" for p in items}))
            out.append(Handoff(
                workflow_id="persistence",
                subjects=tuple(sorted({p.endpoint for p in items})),
                reason=f"a malicious or suspicious persistence item ({listed}) exists on an endpoint where a "
                       "system binary ran malicious activity: the persistence workflow reviews it",
                record_ids=tuple(_ids(items))))
        return out


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


def _links(view: RunView, facts: _Facts) -> list[CorrelationLink]:
    links: dict[str, CorrelationLink] = {}

    def add(entities: Sequence[EntityRef | None], record: AnyRecord, note: str) -> None:
        present = [e for e in entities if e is not None]
        if len({(e.kind, e.value) for e in present}) < 2:
            return
        link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=tuple(present), record_ids=(record.record_id,),
                               first_seen=record.observed_at, last_seen=record.observed_at, note=note,
                               origin=view.origin)
        links.setdefault(link.link_id, link)

    for run in facts.runs:
        host = _entity(TargetKind.ENDPOINT, run.host)
        for record in run.contacts:
            for kind, value in destinations_of(record):
                target_kind = {"domain": TargetKind.DOMAIN, "url": TargetKind.URL, "ip": TargetKind.IP}[kind]
                add([host, _entity(target_kind, value)], record, f"{run.label} contacted {value}")
        for event in [*run.writes, *run.children]:
            sha = (event.sha256 or "").lower()
            if sha and sha not in facts.images:
                add([host, _entity(TargetKind.HASH, sha)], event, f"{run.label} wrote or started {_short(sha)}")
    return [links[k] for k in sorted(links)]


class MaliciousPowershellHooks(WorkflowHooks):
    """Facts, links, considered items and hand-offs of the Suspicious PowerShell workflow (pure)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _links(view, _Facts(view))

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Facts(view).handoffs()


HOOKS = MaliciousPowershellHooks()
