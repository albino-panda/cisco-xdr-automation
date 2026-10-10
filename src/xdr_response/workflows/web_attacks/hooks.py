"""Pure hooks of the web application attacks workflow (architecture 14.3.3 and 14.10.1).

The hooks read the run's own records (a read-only :class:`RunView`: no context, no adapters, no
configuration) and derive:

* ``facts`` for the rule expressions:

  - ``sources``: every external IPv4 source the incident names or that sent an inbound request to an
    investigated server, with its rating. A source is *rated* when the aggregate enrichment is
    MALICIOUS or SUSPICIOUS, or when the security product flagged one of its requests MALICIOUS. A
    source the incident lists in ``trigger.authorized_scanners`` is *authorized* (never proposed,
    shown as considered);
  - ``servers``: every web server seen, whether it has a *confirmed web shell* (an active MALICIOUS
    detection reporting T1505.003 or a web-shell name or category) and whether it shows a successful
    *exploit* (an active MALICIOUS detection reporting T1190 or an exploit category). Only a confirmed
    web shell makes ``isolate`` true: scanning or exploit attempts alone never isolate;
  - ``urls``: every targeted application URL (inbound requests, incident URLs). A URL is *exploited*
    when a flagged request, or a request from a rated source, that was not blocked reached a server
    that shows a confirmed web shell or a successful exploit, or when the incident names both the URL
    and such a server and a request record to that server mentions the URL. A URL only the incident
    names (no record mentions it) is never exploited, even when the incident also names such a
    server: it is shown as considered (the observable list is not evidence).

  Every fact carries the record ids it was computed from, and the rules cite exactly those ids.
* ``correlate`` links of kind ``WORKFLOW``: an attack request (the source IP, the server it reached and
  the targeted URL) and a web shell (the server and the hash of the web shell file);
* ``considered`` items: rated sources listed as authorised scanners, sources whose requests are only
  flagged SUSPICIOUS, servers with an exploit or an unconfirmed web shell (not isolated), URLs probed
  by flagged requests without any sign of success and URLs only the incident names next to a
  compromised server (no record mentions them); manual steps for the edge virtual patch of every
  exploited URL, the web root review of every web-shell server and a web-shell server that no agent
  can isolate;
* ``handoffs`` to ``malware`` for the hashes of confirmed web shell files.

Nothing here creates a record, scores a target, chooses an approval level or calls a vendor; a hook
that fails is noted and ignored by the runner. Hosts are upper case and hashes lower case, as the
record normalizers store them.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnyRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
)
from xdr_response.models import ObservableType, TargetKind, Verdict
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks
from xdr_response.workflows.web_attacks.definition import (
    AUTHORIZED_SCANNERS_KEY,
    EXPLOIT_TECHNIQUE,
    WEB_SHELL_KEYWORDS,
    WEB_SHELL_TECHNIQUE,
)

__all__ = ["WebAttacksHooks", "HOOKS", "ipv4", "is_exploit_detection", "is_web_shell_detection"]

_MALICIOUS = Verdict.MALICIOUS
_SUSPICIOUS = Verdict.SUSPICIOUS
_FLAGGING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_VERDICT_RANK: Mapping[Verdict, int] = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2,
                                        Verdict.MALICIOUS: 3}


# ------------------------------------------------------------------ helpers --
def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _worst(verdicts: Iterable[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: _VERDICT_RANK[v], default=Verdict.UNKNOWN)


def _short(sha: str) -> str:
    return sha[:12] + "..."


def ipv4(value: str | None) -> str | None:
    """The compressed IPv4 address of ``value`` (any range), else None (IPv6 is not handled)."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return address.compressed if address.version == 4 else None


def _techniques(record: DetectionRecord) -> set[str]:
    return {t.strip().upper() for t in record.mitre_techniques}


def is_web_shell_detection(record: DetectionRecord) -> bool:
    """True when a detection reports a web shell (technique T1505.003, or a web-shell name or category)."""
    if WEB_SHELL_TECHNIQUE in _techniques(record):
        return True
    text = f"{record.name} {record.category or ''}".lower()
    return any(keyword in text for keyword in WEB_SHELL_KEYWORDS)


def is_exploit_detection(record: DetectionRecord) -> bool:
    """True when a detection reports exploitation of the application (T1190, or an exploit category)."""
    return EXPLOIT_TECHNIQUE in _techniques(record) or "exploit" in (record.category or "").lower()


def _active_malicious(record: DetectionRecord) -> bool:
    return record.verdict is _MALICIOUS and record.status != "resolved"


def _entity(kind: TargetKind, value: str | None) -> EntityRef | None:
    if not value:
        return None
    try:
        return EntityRef(kind=kind, value=value)
    except ValueError:
        return None


def _url(value: str | None) -> str | None:
    text = (value or "").strip()
    return text or None


class _Facts:
    """One computation of the facts over a run view (private helper of :class:`WebAttacksHooks`)."""

    def __init__(self, view: RunView) -> None:
        self.view = view
        records = view.index.records()
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        #: inbound requests to a server from an IPv4 source (the attack traffic the workflow judges)
        self.requests = [r for r in records if isinstance(r, NetworkConnectionRecord) and r.direction == "inbound"
                         and r.endpoint and ipv4(r.remote_ip)]
        self.reports: dict[tuple[ObservableType, str], ObservableReport] = {
            (r.type, r.value.lower()): r for r in view.results if isinstance(r, ObservableReport)}
        incident = view.incident
        self.incident_hosts = {o.value.strip().upper().rstrip(".") for o in incident.observables
                               if o.type is ObservableType.HOSTNAME}
        self.incident_ips = [ip for ip in (ipv4(o.value) for o in incident.observables
                                           if o.type is ObservableType.IP) if ip]
        self.incident_urls = [u for u in (_url(o.value) for o in incident.observables
                                          if o.type is ObservableType.URL) if u]
        listed = incident.trigger.get(AUTHORIZED_SCANNERS_KEY) if isinstance(incident.trigger, Mapping) else None
        self.authorized = {ip for ip in (ipv4(str(v)) for v in (listed if isinstance(listed, list) else [])) if ip}
        #: addresses an investigated endpoint record reports as its own: never an attacking source (a
        #: health check or hairpin through the WAF, or a proxy that loses the client address); shown as
        #: considered, never blocked (the vulnerability-exploitation contract, 14.13)
        self.own_ips = {a for e in self.endpoints for a in (ipv4(i) for i in e.ip_addresses) if a}
        self.source_facts = self._sources()
        self.rated_ips = {s["ip"] for s in self.source_facts if s["rated"]}
        self._server_state = {host: self._server_state_of(host) for host in self._server_names()}
        self.server_facts = [self._server_fact(host) for host in sorted(self._server_state)]
        self.url_facts = self._urls()

    # ------------------------------------------------------------ helpers --
    def _context(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if e.hostname == host]
        return {
            "groups": list(dict.fromkeys(g for e in mine for g in e.groups)),
            "tags": list(dict.fromkeys(t for e in mine for t in e.tags)),
            "ip": next((a for e in mine for a in e.ip_addresses), None),
            "users": list(dict.fromkeys(u for e in mine for u in e.users)),
        }

    def _flagging_enrichment(self, otype: ObservableType, value: str) -> list[EnrichmentRecord]:
        report = self.reports.get((otype, value.lower()))
        if report is None or report.verdict not in _FLAGGING:
            return []
        return [r for r in report.enrichment_records() if r.verdict in _FLAGGING]

    # ----------------------------------------------------------- sources --
    def _sources(self) -> list[dict[str, Any]]:
        values = list(dict.fromkeys([*self.incident_ips, *(ipv4(r.remote_ip) for r in self.requests)]))
        out: list[dict[str, Any]] = []
        for ip in sorted(v for v in values if v):
            report = self.reports.get((ObservableType.IP, ip))
            enrichment = report.verdict if report is not None else Verdict.UNKNOWN
            requests = [r for r in self.requests if ipv4(r.remote_ip) == ip]
            malicious_requests = [r for r in requests if r.verdict is _MALICIOUS]
            suspicious_requests = [r for r in requests if r.verdict is _SUSPICIOUS]
            support = self._flagging_enrichment(ObservableType.IP, ip)
            basis: list[str] = []
            if enrichment in _FLAGGING:
                names = ", ".join(sorted({r.integration for r in support})) or "enrichment"
                basis.append(f"enrichment {enrichment.value} ({names})")
            if malicious_requests:
                basis.append(f"the security product flagged {len(malicious_requests)} of its request record(s) "
                             "MALICIOUS")
            own = ip in self.own_ips
            rated = not own and (enrichment in _FLAGGING or bool(malicious_requests))
            rating = _MALICIOUS if (enrichment is _MALICIOUS or malicious_requests) else (
                _SUSPICIOUS if enrichment is _SUSPICIOUS else Verdict.UNKNOWN)
            servers = sorted({r.endpoint for r in requests if r.endpoint})
            total = sum(r.count for r in requests)
            flagged = sum(r.count for r in requests if r.verdict in _FLAGGING)
            urls = sorted({u for u in (_url(r.url) for r in requests) if u})
            request_text = ""
            if requests:
                request_text = f"; {total} request(s), {flagged} flagged by the security product"
                if urls:
                    request_text += " (" + ", ".join(urls[:5]) + (", ..." if len(urls) > 5 else "") + ")"
            rating_ids = _ids([*support, *malicious_requests]) if rated else []
            out.append({
                "ip": ip,
                "rated": rated,
                "rating": rating.value,
                "basis": "; ".join(basis) or "not rated",
                "enrichment_verdict": enrichment.value,
                "request_verdict": _worst(r.verdict for r in requests).value,
                "authorized": ip in self.authorized,
                "own": own,
                "own_hosts": sorted({e.hostname for e in self.endpoints
                                     if any(ipv4(a) == ip for a in e.ip_addresses)}) if own else [],
                "own_record_ids": _ids([e for e in self.endpoints
                                        if any(ipv4(a) == ip for a in e.ip_addresses)]) if own else [],
                "flagged_request_ids": _ids([*malicious_requests, *suspicious_requests]),
                "in_incident": ip in self.incident_ips,
                "servers": servers,
                "server_list": ", ".join(servers) or "the application named by the incident",
                "urls": urls,
                "requests": total,
                "flagged_requests": flagged,
                "request_text": request_text,
                "suspicious_request_ids": _ids(suspicious_requests),
                "rating_record_ids": rating_ids,
                "record_ids": list(dict.fromkeys([*_ids(requests), *rating_ids])),
            })
        return out

    # ----------------------------------------------------------- servers --
    def _server_names(self) -> set[str]:
        names = {e.hostname for e in self.endpoints}
        names |= {r.endpoint for r in self.requests if r.endpoint}
        names |= {d.endpoint for d in self.detections if d.endpoint and (is_web_shell_detection(d)
                                                                          or is_exploit_detection(d))}
        return names

    def _server_state_of(self, host: str) -> dict[str, Any]:
        mine = [d for d in self.detections if d.endpoint == host]
        web_shell = [d for d in mine if is_web_shell_detection(d)]
        confirmed = [d for d in web_shell if _active_malicious(d)]
        unconfirmed = [d for d in web_shell if d not in confirmed and d.verdict in _FLAGGING]
        exploits = [d for d in mine if d not in web_shell and is_exploit_detection(d) and _active_malicious(d)]
        flagged_events = [e for e in self.events if e.endpoint == host and e.verdict in _FLAGGING]
        attack_requests = [r for r in self.requests if r.endpoint == host
                           and (r.verdict in _FLAGGING or ipv4(r.remote_ip) in self.rated_ips)]
        compromise: list[str] = []
        if confirmed:
            compromise.append("a confirmed web shell (" + ", ".join(f"'{d.name}'" for d in confirmed) + ")")
        if exploits:
            compromise.append("a successful exploit (" + ", ".join(f"'{d.name}'" for d in exploits) + ")")
        return {"confirmed": confirmed, "unconfirmed": unconfirmed, "exploits": exploits,
                "flagged_events": flagged_events, "attack_requests": attack_requests,
                "compromise_records": [*confirmed, *exploits], "compromise_basis": " and ".join(compromise)}

    def _server_fact(self, host: str) -> dict[str, Any]:
        state = self._server_state[host]
        mine = [e for e in self.endpoints if e.hostname == host]
        confirmed: list[DetectionRecord] = state["confirmed"]
        flagged_events: list[ProcessEventRecord] = state["flagged_events"]
        attack_requests: list[NetworkConnectionRecord] = state["attack_requests"]
        basis = [f"active {d.verdict.value} detection '{d.name}'" for d in confirmed]
        if confirmed and flagged_events:
            basis.append(f"{len(flagged_events)} flagged process or file event(s)")
        attackers = sorted({ip for ip in (ipv4(r.remote_ip) for r in attack_requests) if ip in self.rated_ips})
        source_text = "; attacked by " + ", ".join(attackers) if attackers else ""
        hashes = sorted({d.sha256.lower() for d in confirmed if d.sha256})
        record_ids = _ids([*confirmed, *flagged_events, *attack_requests]) if confirmed else []
        capable = next((e.isolation_capable for e in mine if e.isolation_capable is not None), None)
        return {
            "hostname": host,
            "connector_guid": next((e.connector_guid for e in mine if e.connector_guid), None),
            "mde_machine_id": next((e.mde_machine_id for e in mine if e.mde_machine_id), None),
            "isolation_capable": capable,
            "isolation_state": next((e.isolation_state for e in mine if e.isolation_state != "unknown"), "unknown"),
            "web_shell": bool(confirmed),
            "exploited": bool(state["exploits"]),
            "compromised": bool(state["compromise_records"]),
            "isolate": bool(confirmed),
            "web_shell_basis": "; ".join(basis) or "no confirmed web shell",
            "compromise_basis": state["compromise_basis"] or "no sign of compromise",
            "web_shell_hashes": hashes,
            "attackers": attackers,
            "source_text": source_text,
            "in_incident": host in self.incident_hosts,
            "record_ids": record_ids,
            "compromise_record_ids": _ids(state["compromise_records"]),
            **self._context(host),
        }

    # -------------------------------------------------------------- urls --
    def _urls(self) -> list[dict[str, Any]]:
        values = list(dict.fromkeys([*self.incident_urls, *(u for u in (_url(r.url) for r in self.requests) if u)]))
        compromised = {h: s for h, s in self._server_state.items() if s["compromise_records"]}
        out: list[dict[str, Any]] = []
        for url in sorted(values):
            requests = [r for r in self.requests if _url(r.url) == url]
            flagged = [r for r in requests if r.verdict in _FLAGGING]
            attack = [r for r in requests if r.verdict in _FLAGGING or ipv4(r.remote_ip) in self.rated_ips]
            basis: list[str] = []
            cited: list[AnyRecord] = []
            servers: list[str] = []
            named: list[str] = []
            named_records: list[AnyRecord] = []
            for host, state in sorted(compromised.items()):
                hits = [r for r in attack if r.endpoint == host and r.action != "blocked"]
                if hits:
                    basis.append(f"{len(hits)} flagged or attacker request record(s) reached {host}, which shows "
                                 f"{state['compromise_basis']}")
                elif url in self.incident_urls and host in self.incident_hosts:
                    # The incident's observable list is not evidence on its own: the URL counts only when a
                    # request record to that server mentions it (a URL no record mentions is considered).
                    hits = [r for r in requests if r.endpoint == host]
                    if not hits:
                        named.append(host)
                        named_records.extend(state["compromise_records"])
                        continue
                    basis.append(f"the incident names the URL and {host}, which shows {state['compromise_basis']}, "
                                 f"and {len(hits)} request record(s) to it reached the server")
                else:
                    continue
                servers.append(host)
                cited.extend(hits)
                cited.extend(state["compromise_records"])
            exploited = bool(servers)
            out.append({
                "url": url,
                "exploited": exploited,
                "basis": "; ".join(basis) or "no sign of successful exploitation",
                "servers": servers,
                "server_list": ", ".join(servers),
                "in_incident": url in self.incident_urls,
                "requests": sum(r.count for r in requests),
                "flagged_requests": sum(r.count for r in flagged),
                "flagged_record_ids": _ids(flagged),
                "named_servers": [] if exploited else named,
                "named_record_ids": [] if exploited else _ids(named_records),
                "record_ids": _ids([*attack, *cited]) if exploited else [],
            })
        return out

    # ------------------------------------------------------- considered --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for s in self.source_facts:
            subject = f"block_ip:{s['ip']}"
            if s["own"]:
                records = tuple(dict.fromkeys([*s["own_record_ids"], *s["flagged_request_ids"],
                                               *_ids(self._flagging_enrichment(ObservableType.IP, s["ip"]))]))
                if s["flagged_request_ids"] or s["enrichment_verdict"] in {v.value for v in _FLAGGING}:
                    out.append(Consideration(subject=subject, record_ids=records, reason=(
                        f"the address is one {', '.join(s['own_hosts'])} reports as its own (a health check, a "
                        "hairpin through the WAF or a proxy that loses the client address): never treated as an "
                        "attacking source and not blocked; a human decides")))
            elif s["rated"] and s["authorized"] and s["record_ids"]:
                out.append(Consideration(subject=subject, record_ids=tuple(s["record_ids"]), reason=(
                    f"rated {s['rating']} but the incident source lists it as an authorised scanner: not blocked; "
                    "list it in allowlists.never_block.ips to make this durable; a human decides")))
            elif not s["rated"] and s["suspicious_request_ids"]:
                out.append(Consideration(subject=subject, record_ids=tuple(s["suspicious_request_ids"]), reason=(
                    "its requests are flagged SUSPICIOUS only and no source rates the address: not blocked; "
                    "a human decides")))
        for h in self.server_facts:
            if h["isolate"]:
                continue
            state = self._server_state[h["hostname"]]
            reasons: list[str] = []
            records: list[AnyRecord] = []
            if state["exploits"]:
                reasons.append(f"shows {state['compromise_basis']} but no confirmed web shell")
                records.extend(state["exploits"])
            if state["unconfirmed"]:
                reasons.append("a web-shell detection that is " + ", ".join(sorted(
                    {"resolved" if d.status == "resolved" else d.verdict.value for d in state["unconfirmed"]}))
                    + " only")
                records.extend(state["unconfirmed"])
            if reasons and records:
                out.append(Consideration(subject=f"isolate_endpoint:{h['hostname']}", record_ids=tuple(_ids(records)),
                                         reason=("; ".join(reasons) + ": not isolated (isolation needs an active "
                                                 "MALICIOUS web-shell detection; scanning or exploit attempts "
                                                 "alone never isolate); the analyst can isolate it by hand")))
        for u in self.url_facts:
            if not u["exploited"] and not u["flagged_record_ids"] and u["named_record_ids"]:
                out.append(Consideration(subject=f"block_url:{u['url']}", record_ids=tuple(u["named_record_ids"]),
                                         reason=(f"the incident names the URL and {', '.join(u['named_servers'])}, "
                                                 "which shows a compromise, but no request, WAF or IPS record "
                                                 "mentions the URL: not blocked (the incident's list is not "
                                                 "evidence that this path was exploited); check the server's web "
                                                 "logs and block or virtually patch it by hand if they show it")))
            if not u["exploited"] and u["flagged_record_ids"]:
                out.append(Consideration(subject=f"block_url:{u['url']}", record_ids=tuple(u["flagged_record_ids"]),
                                         reason=(f"probed by {u['flagged_requests']} flagged request(s) but no server "
                                                 "they reached shows a web shell or a successful exploit: not "
                                                 "blocked; if the application is known to be vulnerable, apply a "
                                                 "WAF rule or deploy the fix")))
        out.extend(self._manual_steps())
        return out

    def _manual_steps(self) -> list[Consideration]:
        out: list[Consideration] = []
        for u in self.url_facts:
            if u["exploited"] and u["record_ids"]:
                out.append(Consideration(subject=f"waf-virtual-patch:{u['url']}", record_ids=tuple(u["record_ids"]),
                                         manual=True, reason=(
                    "apply a virtual patch for the exploited URL at the WAF, CDN or load balancer in front of the "
                    "application by hand (no VERIFIED edge integration) and deploy the application fix; the "
                    "proposed URL block covers only the DNS and web security layer")))
        for h in self.server_facts:
            if not h["isolate"] or not h["record_ids"]:
                continue
            host = h["hostname"]
            out.append(Consideration(subject=f"review-web-root:{host}", record_ids=tuple(h["compromise_record_ids"]),
                                     manual=True, reason=(
                "after evidence capture, review the web root and the server logs, remove the web shell and any "
                "other dropped file, and rotate the application's credentials (no VERIFIED write); isolation "
                "contains the server but does not clean it")))
            if h["isolation_capable"] is False:
                out.append(Consideration(subject=f"isolate_endpoint:{host}", record_ids=tuple(h["record_ids"]),
                                         manual=True, reason=(
                    "the server has a confirmed web shell but its agent policy does not allow isolation: take it "
                    "out of the load-balancer pool and contain it on the network by hand")))
            elif not h["connector_guid"] and not h["mde_machine_id"]:
                out.append(Consideration(subject=f"isolate_endpoint:{host}", record_ids=tuple(h["record_ids"]),
                                         manual=True, reason=(
                    "the server has a confirmed web shell but neither Secure Endpoint nor Defender manages it: take "
                    "it out of the load-balancer pool and contain it on the network by hand")))
        return out

    def handoffs(self) -> list[Handoff]:
        hashes: dict[str, list[str]] = {}
        for host, state in sorted(self._server_state.items()):
            for d in state["confirmed"]:
                if d.sha256:
                    hashes.setdefault(d.sha256.lower(), []).append(d.record_id)
        cited = list(dict.fromkeys(i for ids in hashes.values() for i in ids))
        if not hashes or not cited:
            return []
        return [Handoff(workflow_id="malware", subjects=tuple(sorted(hashes)), record_ids=tuple(cited), reason=(
            "the web shell file is confirmed: scope it across the estate, quarantine it and block its hash"))]

    def as_dict(self) -> dict[str, Any]:
        return {"sources": self.source_facts, "servers": self.server_facts, "urls": self.url_facts}


def _links(view: RunView) -> list[CorrelationLink]:
    links: dict[str, CorrelationLink] = {}

    def add(entities: Sequence[EntityRef | None], record: AnyRecord, note: str) -> None:
        refs = list({(e.kind, e.value): e for e in entities if e is not None}.values())
        if len(refs) < 2:
            return
        link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=tuple(refs), record_ids=(record.record_id,),
                               first_seen=record.observed_at, last_seen=record.observed_at, note=note,
                               origin=view.origin)
        links.setdefault(link.link_id, link)

    for record in view.index.records():
        if isinstance(record, NetworkConnectionRecord) and record.direction == "inbound":
            source = _entity(TargetKind.IP, ipv4(record.remote_ip))
            server = _entity(TargetKind.ENDPOINT, record.endpoint)
            url = _entity(TargetKind.URL, _url(record.url))
            if source is not None and server is not None:
                add((source, server, url), record, f"attack request: {source.value} reached {server.value}")
        elif isinstance(record, DetectionRecord) and is_web_shell_detection(record):
            server = _entity(TargetKind.ENDPOINT, record.endpoint)
            sha = _entity(TargetKind.HASH, record.sha256)
            if server is not None and sha is not None:
                add((server, sha), record, f"web shell: {server.value} holds {_short(sha.value)}")
    return [links[k] for k in sorted(links)]


class WebAttacksHooks(WorkflowHooks):
    """Facts, attack links, considerations and hand-offs of the web-attacks workflow (pure)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _links(view)

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Facts(view).handoffs()


HOOKS = WebAttacksHooks()
