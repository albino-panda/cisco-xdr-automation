"""Pure hooks of the credential-dumping workflow (architecture 14.3.3 and 14.10.1).

The hooks read the typed records of one run (a read-only :class:`RunView`: no context, no adapters)
and derive, from those records only:

``facts`` (all keys always present, JSON):

``credential_hosts``
    endpoints where credential access is **confirmed**: a MALICIOUS detection or a MALICIOUS process
    event that is credential-related (:func:`credential_behaviours`), or a credential-dumping tool file
    whose file reputation is malicious (aggregate enrichment MALICIOUS, or a hash prevalence record
    MALICIOUS) seen on the endpoint. Each entry carries the endpoint's routing ids and asset context,
    the behaviours, whether it is a domain controller, the exposed accounts and the record ids that
    prove the access (plus the endpoint records as context).
``exposed_users``
    directory accounts (UPNs) a record places on a confirmed endpoint (endpoint users, detection and
    process users). Each entry says whether a disable is justified: the account is privileged
    (profile flag, a privileged directory role, a privileged role the identity source reports
    assigned, activated or made eligible during the incident, or the privileged-account policy) or the identity
    provider confirms it compromised (risk state, or high risk with a risk detection).
``hashes``
    candidate tool hashes (incident hashes, hashes named by credential-related detections or flagged
    process events, prevalence and enrichment subjects) with their file verdict, prevalence and
    whether a fleet-wide block is proposed (``blockable``).

``considered``: unconfirmed credential activity, endpoints that cannot be isolated, hashes that are not
blocked, disables that cannot be assessed (identity source failed), and the **manual steps**
(credential reset per confirmed endpoint; the domain-wide reset after a domain controller is affected).

``handoffs``: the exposed accounts to ``account-takeover`` (review their sign-ins and cloud activity
for use of the stolen credentials). A hand-off never starts anything.

``correlate``: one ``WORKFLOW`` link per confirmed endpoint and the accounts a record places on it.

Nothing here creates a record, scores a target, chooses an approval level or calls a vendor.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    PRIVILEGED_ROLE_NAMES,
    AnomalyRecord,
    AnyRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    HashPrevalenceRecord,
    InvestigationBundle,
    ProcessEventRecord,
    RoleChangeRecord,
    UserProfileRecord,
)
from xdr_response.models import CriticalAssetClass, ObservableType, TargetKind, Verdict, normalize_target
from xdr_response.workflows.credential_dumping.definition import MAX_HASH_BLOCK_PREVALENCE
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks, failed_reads

__all__ = [
    "LSASS",
    "SAM",
    "NTDS",
    "CREDENTIAL_DUMPING",
    "credential_behaviours",
    "CredentialDumpingHooks",
    "HOOKS",
]

#: Behaviour labels (as they appear in facts, rationales and notes).
LSASS = "LSASS memory access"
SAM = "SAM access"
NTDS = "NTDS (directory database) access"
CREDENTIAL_DUMPING = "credential dumping"
_LABEL_ORDER = (LSASS, SAM, NTDS, CREDENTIAL_DUMPING)

_SAM_PHRASES = ("security account manager", "sam hive", "sam database", "sam registry")
_NTDS_PHRASES = ("ntds", "directory database")
_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_HANDOFF = "account-takeover"


def _tokens(text: str) -> set[str]:
    cleaned = "".join(ch if ch.isalnum() else " " for ch in text)
    return set(cleaned.split())


def credential_behaviours(texts: Iterable[str | None], techniques: Iterable[str] = ()) -> tuple[str, ...]:
    """Credential-access behaviours named by vendor text and vendor-reported ATT&CK ids (ordered labels).

    ``T1003.001`` or "lsass": LSASS; ``T1003.002``, "security account manager" or the word "sam": SAM;
    ``T1003.003``, "ntds" or "directory database": NTDS; any other ``T1003`` id or the word stem
    "credential": generic credential dumping (only when no specific behaviour is named). Pure text
    matching on what the vendor reported; nothing is inferred beyond it.
    """
    blob = " ".join(t.lower() for t in texts if t)
    words = _tokens(blob)
    ids = {t.strip().upper() for t in techniques if t}
    labels: set[str] = set()
    if "T1003.001" in ids or "lsass" in blob:
        labels.add(LSASS)
    if "T1003.002" in ids or "sam" in words or any(p in blob for p in _SAM_PHRASES):
        labels.add(SAM)
    if "T1003.003" in ids or any(p in blob for p in _NTDS_PHRASES):
        labels.add(NTDS)
    if not labels and (any(i == "T1003" or i.startswith("T1003.") for i in ids) or "credential" in blob):
        labels.add(CREDENTIAL_DUMPING)
    return tuple(label for label in _LABEL_ORDER if label in labels)


def _norm(kind: TargetKind, value: str | None) -> str | None:
    if not value:
        return None
    try:
        return normalize_target(kind, value)
    except ValueError:
        return None


def _upn(value: str | None) -> str | None:
    user = _norm(TargetKind.USER, value)
    return user if user and "@" in user and not user.startswith("@") and not user.endswith("@") else None


def _ids(records: Iterable[AnyRecord]) -> list[str]:
    return list(dict.fromkeys(r.record_id for r in records))


def _union(*lists: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(i for ids in lists for i in ids))


def _short(sha: str) -> str:
    return sha[:12] + "..."


def _detection_behaviours(record: DetectionRecord) -> tuple[str, ...]:
    return credential_behaviours((record.name, record.category, record.process_name, record.file_path),
                                 record.mitre_techniques)


def _event_behaviours(record: ProcessEventRecord) -> tuple[str, ...]:
    return credential_behaviours((record.process_name, record.file_path, record.command_line,
                                  record.parent_process_name))


class _Facts:
    """One computation of the facts over a run view (private helper of :class:`CredentialDumpingHooks`)."""

    def __init__(self, view: RunView) -> None:
        records = view.index.records()
        self.detections = [r for r in records if isinstance(r, DetectionRecord)]
        self.events = sorted((r for r in records if isinstance(r, ProcessEventRecord)),
                             key=lambda e: (e.timestamp, e.record_id))
        self.endpoints = [r for r in records if isinstance(r, EndpointRecord)]
        self.prevalence = [r for r in records if isinstance(r, HashPrevalenceRecord)]
        self.profiles = [r for r in records if isinstance(r, UserProfileRecord)]
        #: privileged roles the account gained (assigned, activated, made eligible): the profile can
        #: predate them (14.11.7).
        self.role_grants = [r for r in records if isinstance(r, RoleChangeRecord) and r.privileged
                            and r.change in ("assigned", "activated", "eligible_assigned")]
        self.anomalies = [r for r in records if isinstance(r, AnomalyRecord)]
        self.reports: dict[str, ObservableReport] = {
            r.value.lower(): r for r in view.results
            if isinstance(r, ObservableReport) and r.type is ObservableType.SHA256}
        self.host_classes: dict[str, set[CriticalAssetClass]] = {}
        self.user_classes: dict[str, set[CriticalAssetClass]] = {}
        for result in view.results:
            if not isinstance(result, InvestigationBundle):
                continue
            if result.atomic == "investigate_endpoint":
                host = _norm(TargetKind.ENDPOINT, result.subject.value)
                if host:
                    self.host_classes.setdefault(host, set()).update(result.critical_asset_classes)
            elif result.atomic == "investigate_user":
                user = _upn(result.subject.value)
                if user:
                    self.user_classes.setdefault(user, set()).update(result.critical_asset_classes)
        self.identity_failures = failed_reads(view, ("investigate_user",))
        incident_hashes = [o.value for o in view.incident.observables if o.type is ObservableType.SHA256]
        self.cred_detections = [(d, _detection_behaviours(d)) for d in self.detections]
        self.cred_detections = [(d, b) for d, b in self.cred_detections if b]
        self.cred_events = [(e, _event_behaviours(e)) for e in self.events]
        self.cred_events = [(e, b) for e, b in self.cred_events if b]
        self.hashes = self._hashes(incident_hashes)
        self.by_sha = {h["sha256"]: h for h in self.hashes}
        self.hosts = self._hosts()
        self.users = self._users()

    # -------------------------------------------------------------- hashes --
    def _report_support(self, sha: str) -> list[EnrichmentRecord]:
        report = self.reports.get(sha)
        if report is None or report.verdict is not Verdict.MALICIOUS:
            return []
        return [r for r in report.records if isinstance(r, EnrichmentRecord) and r.verdict in _SUPPORTING]

    def _hashes(self, incident_hashes: Sequence[str]) -> list[dict[str, Any]]:
        candidates: list[str] = []
        values = [*incident_hashes, *(d.sha256 for d, _ in self.cred_detections),
                  *(e.sha256 for e, _ in self.cred_events if e.verdict in _SUPPORTING),
                  *(p.sha256 for p in self.prevalence), *self.reports]
        for value in values:
            sha = _norm(TargetKind.HASH, value)
            if sha and len(sha) == 64 and sha not in candidates:
                candidates.append(sha)
        return [self._hash(sha) for sha in sorted(candidates)]

    def _hash(self, sha: str) -> dict[str, Any]:
        report = self.reports.get(sha)
        enrichment = report.verdict if report is not None else Verdict.UNKNOWN
        prevalence = [p for p in self.prevalence if p.sha256.lower() == sha]
        bad_prevalence = [p for p in prevalence if p.verdict is Verdict.MALICIOUS]
        naming_dets = [d for d, _ in self.cred_detections if (d.sha256 or "").lower() == sha]
        naming_events = [e for e, _ in self.cred_events if (e.sha256 or "").lower() == sha]
        file_malicious = enrichment is Verdict.MALICIOUS or bool(bad_prevalence)
        count = max((p.prevalence for p in prevalence), default=None)
        widespread = count is not None and count > MAX_HASH_BLOCK_PREVALENCE
        seen = {h for p in prevalence for h in (_norm(TargetKind.ENDPOINT, e) for e in p.endpoints) if h}
        named = ({h for h in (_norm(TargetKind.ENDPOINT, d.endpoint) for d in naming_dets) if h}
                 | {h for h in (_norm(TargetKind.ENDPOINT, e.endpoint) for e in naming_events) if h})
        # A widespread file confirms access only where a credential-related record names it on the endpoint.
        hosts = sorted(named | (set() if widespread else seen))
        blockable = file_malicious and enrichment is not Verdict.CLEAN and not widespread
        basis = []
        if enrichment is Verdict.MALICIOUS:
            basis.append("file reputation MALICIOUS")
        if bad_prevalence:
            basis.append("endpoint file disposition MALICIOUS")
        prevalence_text = str(count) if count is not None else "an unknown number of"
        record_ids = _union(_ids(bad_prevalence or prevalence), _ids(self._report_support(sha)),
                            _ids(d for d in naming_dets if d.verdict in _SUPPORTING),
                            _ids(e for e in naming_events if e.verdict in _SUPPORTING))
        context_ids = _union(record_ids, _ids(prevalence), _ids(naming_dets), _ids(naming_events),
                             _ids(r for r in (report.records if report is not None else ())
                                  if isinstance(r, EnrichmentRecord)))
        return {
            "sha256": sha,
            "file_malicious": file_malicious,
            "enrichment_verdict": enrichment.value,
            "prevalence": count,
            "prevalence_text": prevalence_text,
            "widespread": widespread,
            "blockable": blockable,
            "hosts": hosts,
            "named_by_behaviour": bool(naming_dets or naming_events),
            "summary": (f"credential-dumping tool hash {_short(sha)} ({', '.join(basis) or 'not malicious'}), "
                        f"seen on {prevalence_text} endpoint(s)"),
            "record_ids": record_ids,
            "context_ids": context_ids,
        }

    # ---------------------------------------------------------------- hosts --
    def _host_names(self) -> list[str]:
        names: set[str] = set()
        for value in [*(e.hostname for e in self.endpoints), *(d.endpoint for d, _ in self.cred_detections),
                      *(e.endpoint for e, _ in self.cred_events),
                      *(h for x in self.hashes if x["file_malicious"] for h in x["hosts"])]:
            host = _norm(TargetKind.ENDPOINT, value)
            if host:
                names.add(host)
        return sorted(names)

    def _hosts(self) -> list[dict[str, Any]]:
        return [self._host(host) for host in self._host_names()]

    def _host(self, host: str) -> dict[str, Any]:
        mine = [e for e in self.endpoints if _norm(TargetKind.ENDPOINT, e.hostname) == host]
        dets = [(d, b) for d, b in self.cred_detections if _norm(TargetKind.ENDPOINT, d.endpoint) == host]
        events = [(e, b) for e, b in self.cred_events if _norm(TargetKind.ENDPOINT, e.endpoint) == host]
        bad_dets = [(d, b) for d, b in dets if d.verdict is Verdict.MALICIOUS]
        bad_events = [(e, b) for e, b in events if e.verdict is Verdict.MALICIOUS]
        files = [h for h in self.hashes if h["file_malicious"] and host in h["hosts"]]
        behaviours: set[str] = {label for _, b in (*bad_dets, *bad_events) for label in b}
        for file in files:
            behaviours.update(label for d, b in self.cred_detections if (d.sha256 or "").lower() == file["sha256"]
                              for label in b)
            behaviours.update(label for e, b in self.cred_events if (e.sha256 or "").lower() == file["sha256"]
                              for label in b)
        confirmed = bool(bad_dets or bad_events or files)
        if confirmed:  # the other (not CLEAN) credential activity on a confirmed endpoint names the behaviour too
            behaviours.update(label for d, b in dets if d.verdict is not Verdict.CLEAN for label in b)
            behaviours.update(label for e, b in events if e.verdict is not Verdict.CLEAN for label in b)
        if files and not behaviours:
            behaviours.add(CREDENTIAL_DUMPING)
        classes = self.host_classes.get(host, set())
        ordered = [label for label in _LABEL_ORDER if label in behaviours]
        domain_controller = CriticalAssetClass.DOMAIN_CONTROLLER in classes or NTDS in behaviours
        basis = []
        if bad_dets:
            basis.append("MALICIOUS detection " + ", ".join(f"'{d.name}'" for d, _ in bad_dets[:3]))
        if bad_events:
            basis.append("MALICIOUS process event " + ", ".join(sorted({e.process_name or 'unknown process'
                                                                         for e, _ in bad_events})))
        if files:
            basis.append("malicious tool file " + ", ".join(_short(f["sha256"]) for f in files) + " on the endpoint")
        # Evidence: the proof of access first, then context (other credential activity, endpoint records).
        file_shas = {f["sha256"] for f in files}
        file_records = [r for r in (*self.detections, *self.events)
                        if _norm(TargetKind.ENDPOINT, r.endpoint) == host and (r.sha256 or "").lower() in file_shas
                        and r.verdict is not Verdict.CLEAN]
        proof = _union(_ids(d for d, _ in bad_dets), _ids(e for e, _ in bad_events),
                       *(f["record_ids"] for f in files), _ids(file_records))
        context = _union(_ids(d for d, _ in dets if d.verdict is not Verdict.CLEAN),
                         _ids(e for e, _ in events if e.verdict in _SUPPORTING), _ids(mine))
        users = self._placements(host, mine)
        groups = list(dict.fromkeys(g for e in mine for g in e.groups))
        tags = list(dict.fromkeys(t for e in mine for t in e.tags))
        ip = next((a for e in mine for a in e.ip_addresses), None)
        capable = None if not mine or all(e.isolation_capable is None for e in mine) else \
            all(e.isolation_capable is not False for e in mine)
        dc_note = "; domain controller: every domain credential is exposed" if domain_controller else ""
        return {
            "hostname": host,
            "confirmed": confirmed,
            "connector_guid": next((e.connector_guid for e in mine if e.connector_guid), None),
            "mde_machine_id": next((e.mde_machine_id for e in mine if e.mde_machine_id), None),
            "isolation_capable": capable,
            "groups": groups,
            "tags": tags,
            "ip": ip,
            "behaviours": ordered,
            "domain_controller": domain_controller,
            "users": sorted(users),
            "summary": (f"credential access confirmed on {host}: {', '.join(ordered) or CREDENTIAL_DUMPING} "
                        f"({'; '.join(basis)}){dc_note}"),
            "record_ids": _union(proof, context) if confirmed else [],
            "placements": {user: ids for user, ids in sorted(users.items())},
            "activity_ids": _union(_ids(d for d, _ in dets), _ids(e for e, _ in events)),
            "activity_verdicts": sorted({str(d.verdict.value) for d, _ in dets} | {str(e.verdict.value) for e, _ in events}),
        }

    def _placements(self, host: str, mine: Sequence[EndpointRecord]) -> dict[str, list[str]]:
        """Accounts a record places on ``host`` -> the ids of those records."""
        out: dict[str, list[str]] = {}
        for record in mine:
            for value in record.users:
                user = _upn(value)
                if user:
                    out.setdefault(user, [])
                    out[user] = _union(out[user], [record.record_id])
        for record in [*self.detections, *self.events]:
            if _norm(TargetKind.ENDPOINT, record.endpoint) != host:
                continue
            user = _upn(record.user)
            if user:
                out.setdefault(user, [])
                out[user] = _union(out[user], [record.record_id])
        return out

    # ---------------------------------------------------------------- users --
    def _users(self) -> list[dict[str, Any]]:
        exposure: dict[str, dict[str, Any]] = {}
        for host in self.hosts:
            if not host["confirmed"]:
                continue
            for user, ids in host["placements"].items():
                entry = exposure.setdefault(user, {"hosts": [], "record_ids": [], "behaviours": []})
                entry["hosts"].append(host["hostname"])
                entry["record_ids"] = _union(entry["record_ids"], host["record_ids"], ids)
                entry["behaviours"] = _union(entry["behaviours"], host["behaviours"])
        return [self._user(user, exposure[user]) for user in sorted(exposure)]

    def _user(self, user: str, exposure: Mapping[str, Any]) -> dict[str, Any]:
        profiles = [p for p in self.profiles if _upn(p.user) == user]
        anomalies = [a for a in self.anomalies if _upn(a.user) == user]
        roles = list(dict.fromkeys(r for p in profiles for r in p.roles))
        groups = list(dict.fromkeys(g for p in profiles for g in p.groups))
        privileged_roles = [r for r in roles if r.strip().lower() in PRIVILEGED_ROLE_NAMES]
        policy_privileged = CriticalAssetClass.PRIVILEGED_ACCOUNT in self.user_classes.get(user, set())
        flagged = any(p.privileged for p in profiles)
        grants = [g for g in self.role_grants if _upn(g.user) == user]
        granted_roles = list(dict.fromkeys(g.role_name for g in grants))
        privileged = flagged or bool(privileged_roles) or bool(grants) or policy_privileged
        confirmed = any(p.risk_state == "confirmed_compromised" for p in profiles)
        high_risk = any(p.risk_level == "high" for p in profiles) and bool(anomalies)
        compromised = confirmed or high_risk
        failed = self.identity_failures.get(user, ())
        assessed = bool(profiles) or not failed
        hosts = ", ".join(exposure["hosts"])
        behaviours = ", ".join(exposure["behaviours"]) or CREDENTIAL_DUMPING
        reasons = []
        if privileged:
            if privileged_roles:
                reasons.append("privileged (directory roles: " + ", ".join(privileged_roles) + ")")
            elif flagged:
                reasons.append("privileged (identity provider: " + ", ".join(roles or groups or ["flagged"]) + ")")
            elif grants:
                reasons.append("privileged (role granted during the incident: " + ", ".join(granted_roles) + ")")
            else:
                reasons.append("privileged (privileged-account policy)")
        if confirmed:
            reasons.append("confirmed compromised by the identity provider")
        elif high_risk:
            reasons.append("high user risk with a risk detection")
        disable = privileged or compromised
        summary = (f"credentials of {user} were exposed on {hosts} where credential access is confirmed "
                   f"({behaviours}): revoking the sessions forces a new sign-in")
        if not assessed:
            summary += f"; account state not assessed ({', '.join(failed)} failed), disable not proposed"
        elif not disable:
            summary += "; not disabled: not privileged and not confirmed compromised"
        profile_ids = _ids([*profiles, *grants])
        anomaly_ids = _ids(anomalies) if compromised else []
        return {
            "user": user,
            "hosts": list(exposure["hosts"]),
            "groups": groups,
            "roles": roles,
            "privileged": privileged,
            "compromised": compromised,
            "assessed": assessed,
            "failed_sources": list(failed),
            "disable": disable,
            "summary": summary,
            "disable_summary": (f"account {user} is {' and '.join(reasons)} and its credentials were exposed on "
                                f"{hosts} ({behaviours})") if disable else "",
            "record_ids": list(exposure["record_ids"]),
            "disable_record_ids": _union(exposure["record_ids"], profile_ids, anomaly_ids),
        }

    # -------------------------------------------------------- considerations --
    def considered(self) -> list[Consideration]:
        out: list[Consideration] = []
        for host in self.hosts:
            name = host["hostname"]
            if not host["confirmed"]:
                if not host["activity_ids"]:
                    continue
                verdicts = host["activity_verdicts"]
                if verdicts == [Verdict.CLEAN.value]:
                    reason = (f"credential-related activity on {name} is rated CLEAN by the endpoint product (for "
                              "example an approved security agent): not contained")
                else:
                    reason = (f"credential-related activity on {name} (verdicts {', '.join(verdicts)}) is not "
                              "confirmed: no MALICIOUS detection or process event and no malicious tool file; not "
                              "isolated, an analyst reviews it")
                out.append(Consideration(subject=f"isolate_endpoint:{name}", reason=reason,
                                         record_ids=tuple(host["activity_ids"])))
                continue
            if host["isolation_capable"] is False:
                out.append(Consideration(subject=f"isolate_endpoint:{name}",
                                         reason=f"credential access confirmed on {name} but its connector policy "
                                                "forbids isolation: contain it by hand",
                                         record_ids=tuple(host["record_ids"])))
            elif not host["connector_guid"] and not host["mde_machine_id"]:
                out.append(Consideration(subject=f"isolate_endpoint:{name}",
                                         reason=f"credential access confirmed on {name} but neither Secure Endpoint "
                                                "nor Defender for Endpoint knows the endpoint: isolate it by hand",
                                         record_ids=tuple(host["record_ids"])))
        for h in self.hashes:
            if h["blockable"] or not h["context_ids"]:
                continue
            if h["file_malicious"] and h["widespread"]:
                reason = (f"tool hash rated malicious but seen on {h['prevalence']} endpoints (more than "
                          f"{MAX_HASH_BLOCK_PREVALENCE}): not proposed for a fleet-wide block; a human decides")
            elif h["file_malicious"]:
                reason = ("the endpoint product rates the file malicious but its reputation is CLEAN: conflicting "
                          "verdicts, not blocked; a human decides")
            elif h["enrichment_verdict"] == Verdict.CLEAN.value:
                reason = "file reputation CLEAN (for example a legitimate system binary): not blocked"
            elif h["named_by_behaviour"]:
                reason = ("named only by a behaviour detection; the file itself has no malicious reputation (it may "
                          "be a misused system binary): not blocked")
            else:
                reason = "no file reputation verdict and no malicious detection: not blocked"
            out.append(Consideration(subject=f"block_hash:{h['sha256']}", reason=reason,
                                     record_ids=tuple(h["context_ids"])))
        for user in self.users:
            if not user["assessed"]:
                out.append(Consideration(
                    subject=f"disable_user:{user['user']}",
                    reason=(f"identity source {', '.join(user['failed_sources'])} failed: whether the exposed account "
                            "is privileged or compromised is unknown, so the disable is not proposed (the session "
                            "revocation is); review the account by hand"),
                    record_ids=tuple(user["record_ids"])))
        out.extend(self.manual_steps())
        return out

    def manual_steps(self) -> list[Consideration]:
        out: list[Consideration] = []
        for host in self.hosts:
            if not host["confirmed"]:
                continue
            name = host["hostname"]
            if host["domain_controller"]:
                out.append(Consideration(
                    subject=f"domain-credential-reset:{name}", manual=True, record_ids=tuple(host["record_ids"]),
                    reason=(f"the domain credential store was exposed on {name}: treat every domain account as "
                            "compromised; the incident commander owns the domain-wide credential reset (privileged "
                            "and service accounts first, the Kerberos ticket-granting account twice) and rebuilds "
                            "the domain controller before release; nothing of this is automated")))
            else:
                out.append(Consideration(
                    subject=f"credential-reset:{name}", manual=True, record_ids=tuple(host["record_ids"]),
                    reason=(f"reset the credentials of every account exposed on {name} (privileged and service "
                            "accounts first), rotate the endpoint's local administrator credential and service "
                            "secrets, review MFA methods, and rebuild the endpoint before release; credential reset "
                            "has no VERIFIED automated action")))
        return out

    def handoffs(self) -> list[Handoff]:
        if not self.users:
            return []
        hosts = sorted({h for u in self.users for h in u["hosts"]})
        ids = _union(*(u["record_ids"] for u in self.users))
        return [Handoff(workflow_id=_HANDOFF, subjects=tuple(u["user"] for u in self.users), record_ids=tuple(ids),
                        reason=(f"credentials of these accounts were exposed on {', '.join(hosts)} where credential "
                                "access is confirmed: review their sign-ins, MFA and cloud activity for use of the "
                                "stolen credentials"))]

    def as_dict(self) -> dict[str, Any]:
        credential_hosts = []
        for host in self.hosts:
            if host["confirmed"]:
                credential_hosts.append({k: v for k, v in host.items()
                                         if k not in ("placements", "activity_ids", "activity_verdicts")})
        return {
            "credential_hosts": credential_hosts,
            "exposed_users": self.users,
            "hashes": [{k: v for k, v in h.items() if k != "context_ids"} for h in self.hashes],
            "domain_controllers": sorted(h["hostname"] for h in credential_hosts if h["domain_controller"]),
        }


def _exposure_links(view: RunView, facts: _Facts) -> list[CorrelationLink]:
    links: dict[str, CorrelationLink] = {}
    for host in facts.hosts:
        if not host["confirmed"] or not host["placements"]:
            continue
        entities = [EntityRef(kind=TargetKind.ENDPOINT, value=host["hostname"])]
        entities += [EntityRef(kind=TargetKind.USER, value=u) for u in host["placements"]]
        ids = _union(*host["placements"].values())
        link = CorrelationLink(kind=LinkKind.WORKFLOW, entities=tuple(entities), record_ids=tuple(sorted(ids)),
                               note=(f"credential exposure: {len(host['placements'])} account(s) placed on "
                                     f"{host['hostname']}"),
                               origin=view.origin)
        links.setdefault(link.link_id, link)
    return [links[k] for k in sorted(links)]


class CredentialDumpingHooks(WorkflowHooks):
    """Facts, considerations, hand-offs and exposure links of the credential-dumping workflow (pure)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _exposure_links(view, _Facts(view))

    def facts(self, view: RunView) -> Mapping[str, Any]:
        return _Facts(view).as_dict()

    def considered(self, view: RunView) -> Sequence[Consideration]:
        return _Facts(view).considered()

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        return _Facts(view).handoffs()


HOOKS = CredentialDumpingHooks()
