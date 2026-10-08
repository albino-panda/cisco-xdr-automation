"""Pure hooks of the persistence workflow (architecture 14.3.3): facts, links and manual steps.

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters) and
derive:

* ``facts`` for the rule expressions: which persisted binaries are malicious and how widespread
  (``hashes``), which persistence items are malicious (``items``), which endpoints carry a malicious
  persistence item backed by active malicious execution (``isolate``) and which persisted malicious
  processes are still running (``running``). Every fact carries the record ids it was computed from,
  and the rules cite exactly those ids as evidence;
* ``correlate`` links of kind ``WORKFLOW``: a persistence item tied to the binary it launches on its
  endpoint and to that binary's execution events there;
* ``considered`` items: the **manual removal step** of every malicious persistence item (no VERIFIED
  vendor write removes persistence, 14.10.1), items not rated malicious (left for review), endpoints
  whose malicious persistence is dormant (not isolated) and malicious binaries too widespread for a
  fleet-wide block.

Nothing here creates a record, scores a target, chooses an approval level or calls a vendor: a hook
that fails is noted and ignored by the runner. Hosts are upper case and hashes lower case, as the
record normalizers store them.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnyRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    InvestigationBundle,
    PersistenceItemRecord,
    ProcessEventRecord,
)
from xdr_response.models import ObservableType, TargetKind, Verdict, same_endpoint
from xdr_response.workflows.hooks import Consideration, RunView, WorkflowHooks
from xdr_response.workflows.persistence.definition import EXECUTION_EVENT_TYPES, MAX_HASH_BLOCK_PREVALENCE

__all__ = ["PersistenceHooks", "HOOKS", "is_browser_extension", "mechanism_label", "removal_step"]

_MALICIOUS = Verdict.MALICIOUS
_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_EXECUTION = frozenset(EXECUTION_EVENT_TYPES)
_STARTS = frozenset({"process_start", "file_execute"})

_LABELS: Mapping[str, str] = {
    "run_key": "Run key value", "startup_folder": "startup folder item", "scheduled_task": "scheduled task",
    "service": "Windows service", "wmi_subscription": "WMI event subscription", "launch_agent": "launch agent",
    "cron": "cron job", "browser_extension": "browser extension", "other": "persistence item",
}
_REMOVAL: Mapping[str, str] = {
    "run_key": "delete the Run or RunOnce registry value",
    "startup_folder": "delete the startup folder item",
    "scheduled_task": "disable, then delete the scheduled task",
    "service": "stop and disable the service, then delete it",
    "wmi_subscription": "remove the WMI event filter, consumer and binding",
    "launch_agent": "unload and delete the launch agent",
    "cron": "delete the cron entry",
    "browser_extension": "remove the browser extension and block it by browser policy",
    "other": "remove the persistence item",
}
_EXTENSION_MARKERS = ("\\extensions\\", "/extensions/", ".crx", ".xpi")


def is_browser_extension(item: PersistenceItemRecord) -> bool:
    """A ``browser_extension`` item, or a mechanism ``other`` item whose path or name shows a browser extension
    (sources that do not map the dedicated mechanism, 14.11.3)."""
    if item.mechanism == "browser_extension":
        return True
    if item.mechanism != "other":
        return False
    text = f"{item.path or ''} {item.name}".lower()
    return "browser extension" in text or any(marker in text for marker in _EXTENSION_MARKERS)


def mechanism_label(item: PersistenceItemRecord) -> str:
    """Human label of the item's mechanism (``browser extension`` for a recognised extension)."""
    return "browser extension" if is_browser_extension(item) else _LABELS[item.mechanism]


def removal_step(item: PersistenceItemRecord) -> str:
    """The manual removal step for the item's mechanism (defensive guidance only)."""
    if is_browser_extension(item):
        return "remove the browser extension and block it by browser policy"
    return _REMOVAL[item.mechanism]


def _short(sha: str) -> str:
    return sha[:12] + "..."


def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _sha(value: str | None) -> str:
    return (value or "").lower()


class _Facts:
    """One computation of the facts over a run view (private helper of :class:`PersistenceHooks`)."""

    def __init__(self, view: RunView) -> None:
        records = view.index.records()
        self.items = sorted((r for r in records if isinstance(r, PersistenceItemRecord)),
                            key=lambda r: (r.endpoint, r.item_id))
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.prevalence = [r for r in records if isinstance(r, HashPrevalenceRecord)]
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {
            (r.type, r.value.lower()): r for r in view.results if isinstance(r, ObservableReport)}
        self.critical: dict[str, list[str]] = {}
        for result in view.results:
            if isinstance(result, InvestigationBundle) and result.atomic == "investigate_endpoint":
                classes = [str(c) for c in result.critical_asset_classes]
                if classes:
                    host = result.subject.value.upper()
                    self.critical[host] = sorted({*self.critical.get(host, []), *classes})
        incident_hashes = [o.value.lower() for o in view.incident.observables if o.type is ObservableType.SHA256]
        candidates = list(dict.fromkeys([*(_sha(i.sha256) for i in self.items if i.sha256), *incident_hashes]))
        self.hashes = {sha: self._hash(sha) for sha in sorted(candidates)}
        self.malicious = {sha for sha, h in self.hashes.items() if h["malicious"]}

    # ------------------------------------------------------------ helpers --
    def _report(self, otype: ObservableType, value: str) -> ObservableReport | None:
        return self.reports.get((otype, value.lower()))

    def _support(self, sha: str) -> list[EnrichmentRecord]:
        """Enrichment records rating ``sha`` malicious or suspicious, when the aggregate is MALICIOUS."""
        report = self._report(ObservableType.SHA256, sha)
        if report is None or report.verdict is not _MALICIOUS:
            return []
        return [r for r in report.records if isinstance(r, EnrichmentRecord) and r.verdict in _SUPPORTING]

    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if same_endpoint(e.hostname, host)]
        groups = list(dict.fromkeys(g for e in mine for g in e.groups))
        tags = list(dict.fromkeys(t for e in mine for t in e.tags))
        ip = next((a for e in mine for a in e.ip_addresses), None)
        return {"groups": groups, "tags": tags, "ip": ip}

    def _items_launching(self, sha: str, host: str | None = None) -> list[PersistenceItemRecord]:
        return [i for i in self.items if _sha(i.sha256) == sha and (host is None or same_endpoint(i.endpoint, host))]

    @staticmethod
    def _describe(items: Sequence[PersistenceItemRecord]) -> str:
        return "; ".join(f"{mechanism_label(i)} '{i.name}' on {i.endpoint}" for i in items)

    def _remediated(self, host: str, sha: str) -> bool:
        """The agent remediated ``sha`` on ``host``: it has detections there and every one is resolved."""
        found = [d for d in self.detections if d.endpoint and same_endpoint(d.endpoint, host) and _sha(d.sha256) == sha]
        return bool(found) and all(d.status == "resolved" for d in found)

    # -------------------------------------------------------------- hashes --
    def _hash(self, sha: str) -> dict[str, Any]:
        bad_detections = [d for d in self.detections if _sha(d.sha256) == sha and d.verdict is _MALICIOUS]
        prevalence = [p for p in self.prevalence if p.sha256.lower() == sha]
        bad_prevalence = [p for p in prevalence if p.verdict is _MALICIOUS]
        bad_events = [e for e in self.events if _sha(e.sha256) == sha and e.verdict is _MALICIOUS]
        report = self._report(ObservableType.SHA256, sha)
        enrichment_verdict = report.verdict if report is not None else Verdict.UNKNOWN
        clean = (enrichment_verdict is Verdict.CLEAN or any(p.verdict is Verdict.CLEAN for p in prevalence))
        basis = []
        if bad_detections:
            basis.append("endpoint detection")
        if bad_prevalence or bad_events:
            basis.append("endpoint telemetry")
        if enrichment_verdict is _MALICIOUS:
            basis.append("enrichment")
        items = self._items_launching(sha)
        count = max((p.prevalence for p in prevalence), default=None)
        return {
            "sha256": sha,
            "malicious": bool(basis),
            "clean": clean and not basis,
            "basis": ", ".join(basis) or "not malicious",
            "enrichment_verdict": enrichment_verdict.value,
            "persisted": bool(items),
            "launched_by": self._describe(items) or "no reported persistence item (incident observable)",
            "prevalence": count,
            "prevalence_text": str(count) if count is not None else "an unknown number of",
            "widespread": count is not None and count > MAX_HASH_BLOCK_PREVALENCE,
            "endpoints": sorted({h for p in prevalence for h in p.endpoints}
                                | {d.endpoint for d in bad_detections if d.endpoint}),
            "record_ids": _ids([*items, *bad_detections, *bad_events, *prevalence, *self._support(sha)]),
        }

    # --------------------------------------------------------------- items --
    def _item(self, item: PersistenceItemRecord) -> dict[str, Any]:
        sha = _sha(item.sha256)
        hash_fact = self.hashes.get(sha) if sha else None
        malicious = item.verdict is _MALICIOUS or bool(hash_fact and hash_fact["malicious"])
        basis = []
        if item.verdict is _MALICIOUS:
            basis.append("item rated malicious by the endpoint source")
        if hash_fact and hash_fact["malicious"]:
            basis.append(f"binary {_short(sha)} malicious ({hash_fact['basis']})")
        suspicious_hash = bool(hash_fact) and hash_fact["enrichment_verdict"] == Verdict.SUSPICIOUS.value
        suspicious_detection = bool(sha) and any(
            _sha(d.sha256) == sha and d.verdict is Verdict.SUSPICIOUS for d in self.detections)
        clean = (item.verdict is Verdict.CLEAN or bool(hash_fact and hash_fact["clean"])) and not malicious
        ids = [item.record_id]
        if hash_fact and (hash_fact["malicious"] or suspicious_hash):
            ids += hash_fact["record_ids"]
        return {
            "target": item.target, "endpoint": item.endpoint, "item_id": item.item_id,
            "mechanism": item.mechanism, "label": mechanism_label(item), "name": item.name,
            "sha256": sha or None, "malicious": malicious,
            "suspicious": not malicious and (item.verdict is Verdict.SUSPICIOUS or suspicious_hash
                                             or suspicious_detection),
            "clean": clean, "basis": "; ".join(basis) or "not rated malicious",
            "record_ids": list(dict.fromkeys(ids)),
        }

    def items_facts(self) -> list[dict[str, Any]]:
        return [self._item(i) for i in self.items]

    # ----------------------------------------------------------- endpoints --
    def _execution(self, host: str) -> tuple[list[DetectionRecord], list[ProcessEventRecord]]:
        """Active malicious detections and executions of malicious persisted binaries on ``host``."""
        persisted_here = {_sha(i.sha256) for i in self.items if i.sha256 and same_endpoint(i.endpoint, host)}
        detections = [d for d in self.detections if d.endpoint and same_endpoint(d.endpoint, host)
                      and d.verdict is _MALICIOUS and d.status != "resolved"]
        events = [e for e in self.events if same_endpoint(e.endpoint, host) and e.event_type in _EXECUTION
                  and _sha(e.sha256) in persisted_here
                  and (_sha(e.sha256) in self.malicious or e.verdict is _MALICIOUS)
                  and not self._remediated(host, _sha(e.sha256))]
        return detections, events

    def _hosts(self) -> list[str]:
        hosts: list[str] = []
        for item in self.items:
            if not any(same_endpoint(item.endpoint, h) for h in hosts):
                hosts.append(item.endpoint)
        return hosts

    def _malicious_items(self, host: str) -> list[PersistenceItemRecord]:
        return [i for i in self.items if same_endpoint(i.endpoint, host) and self._item(i)["malicious"]]

    def isolate(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for host in self._hosts():
            items = self._malicious_items(host)
            if not items:
                continue
            detections, events = self._execution(host)
            if not detections and not events:
                continue
            support = [i for item in items for i in self._item(item)["record_ids"]]
            ids = [*_ids(items), *_ids(detections), *_ids(events), *support]
            parts = [self._describe(items)]
            if detections:
                parts.append("active detection " + ", ".join(sorted({f"'{d.name}'" for d in detections})))
            if events:
                parts.append("persisted binary executed " + ", ".join(
                    sorted({f"{_short(_sha(e.sha256))} {e.event_type}" for e in events})))
            entry = {"record_ids": list(dict.fromkeys(ids)), "summary": "; ".join(parts), **self._context(host)}
            for endpoint in self.endpoints:  # rule items carry the endpoint record's own spelling
                if same_endpoint(endpoint.hostname, host):
                    out.setdefault(endpoint.hostname, entry)
            out.setdefault(host, entry)
        return out

    def dormant(self) -> list[Consideration]:
        out = []
        for host in self._hosts():
            items = self._malicious_items(host)
            if not items:
                continue
            detections, events = self._execution(host)
            if detections or events:
                continue
            ids = _ids(items) + [i for item in items for i in self._item(item)["record_ids"]]
            out.append(Consideration(
                subject=f"isolate_endpoint:{host}",
                reason=("malicious persistence is dormant (no active malicious detection and no execution of "
                        "the persisted binary): isolation not proposed; the binary block and the manual "
                        "removal still apply"),
                record_ids=tuple(dict.fromkeys(ids))))
        return out

    # ----------------------------------------------------------- processes --
    def _ended(self, start: ProcessEventRecord) -> bool:
        for end in self.events:
            if end.event_type != "process_end" or not same_endpoint(end.endpoint, start.endpoint):
                continue
            if end.timestamp < start.timestamp:
                continue
            if start.pid is not None and end.pid == start.pid:
                return True
            if start.pid is None and start.sha256 and _sha(end.sha256) == _sha(start.sha256):
                return True
        return False

    def running(self) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for start in self.events:
            sha = _sha(start.sha256)
            if start.event_type not in _STARTS or sha not in self.malicious:
                continue
            items = self._items_launching(sha, start.endpoint)
            if not items or self._remediated(start.endpoint, sha) or self._ended(start):
                continue
            ident = str(start.pid) if start.pid is not None else sha
            target = f"{start.endpoint}/{ident}"
            entry = out.setdefault(target, {
                "target": target, "endpoint": start.endpoint, "sha256": sha, "pid": start.pid,
                "process_name": start.process_name or _short(sha), "launched_by": self._describe(items),
                "record_ids": [], **self._context(start.endpoint)})
            detections = [d for d in self.detections if d.endpoint and same_endpoint(d.endpoint, start.endpoint)
                          and _sha(d.sha256) == sha and d.verdict is not Verdict.CLEAN]
            ids = [start.record_id, *_ids(items), *_ids(detections), *_ids(self._support(sha))]
            entry["record_ids"] = list(dict.fromkeys([*entry["record_ids"], *ids]))
        return [out[k] for k in sorted(out)]

    # ------------------------------------------------------- considerations --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for item in self.items:
            fact = self._item(item)
            host = item.endpoint.upper()
            if fact["malicious"]:
                critical = self.critical.get(host)
                note = (f"; the endpoint is a critical asset ({', '.join(critical)}): coordinate the removal with "
                        "the asset owner") if critical else ""
                out.append(Consideration(
                    subject=f"remove_persistence:{item.target}",
                    reason=(f"no VERIFIED vendor write removes persistence: {removal_step(item)} "
                            f"('{item.name}') on {item.endpoint} by hand, then re-scan after a reboot and record "
                            f"who removed it and when ({fact['basis']}){note}"),
                    record_ids=tuple(fact["record_ids"]), manual=True))
            elif not fact["clean"]:
                rating = "rated suspicious" if fact["suspicious"] else "not rated by any source"
                out.append(Consideration(
                    subject=f"remove_persistence:{item.target}",
                    reason=(f"{fact['label']} '{item.name}' is {rating}: no containment proposed; an analyst "
                            "reviews the item and its binary"),
                    record_ids=tuple(fact["record_ids"])))
        out += self.dormant()
        for sha, h in self.hashes.items():
            if h["malicious"] and h["widespread"]:
                out.append(Consideration(
                    subject=f"block_hash:{sha}",
                    reason=(f"malicious persisted binary seen on {h['prevalence']} endpoints (more than "
                            f"{MAX_HASH_BLOCK_PREVALENCE}): not proposed for a fleet-wide block; a human decides"),
                    record_ids=tuple(h["record_ids"])))
            elif not h["persisted"] and not h["malicious"] and not h["clean"] and h["record_ids"]:
                out.append(Consideration(
                    subject=f"block_hash:{sha}",
                    reason="no malicious verdict for this incident hash and no persistence item launches it: not "
                           "blocked; an analyst reviews it",
                    record_ids=tuple(h["record_ids"])))
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "hashes": list(self.hashes.values()),
            "items": self.items_facts(),
            "isolate": self.isolate(),
            "running": self.running(),
        }


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


def _item_links(view: RunView) -> list[CorrelationLink]:
    records = view.index.records()
    items = [r for r in records if isinstance(r, PersistenceItemRecord) and r.sha256]
    events = [r for r in records if isinstance(r, ProcessEventRecord) and r.event_type in _EXECUTION]
    links: dict[str, CorrelationLink] = {}
    for item in items:
        host = _entity(TargetKind.ENDPOINT, item.endpoint)
        sha = _entity(TargetKind.HASH, item.sha256)
        if host is None or sha is None:
            continue
        runs = [e for e in events if same_endpoint(e.endpoint, item.endpoint) and _sha(e.sha256) == sha.value]
        times = [t for t in (item.created_at, *(e.timestamp for e in runs)) if t is not None]
        link = CorrelationLink(
            kind=LinkKind.WORKFLOW, entities=(host, sha),
            record_ids=tuple(sorted({item.record_id, *(e.record_id for e in runs)})),
            first_seen=min(times) if times else None, last_seen=max(times) if times else None,
            note=(f"persistence: {mechanism_label(item)} '{item.name}' on {host.value} launches "
                  f"{_short(sha.value)} ({len(runs)} execution event(s))"),
            origin=view.origin)
        links.setdefault(link.link_id, link)
    return [links[k] for k in sorted(links)]


class PersistenceHooks(WorkflowHooks):
    """Facts, item links and manual steps of the persistence workflow (pure; no context, no adapters)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _item_links(view)

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()


HOOKS = PersistenceHooks()
