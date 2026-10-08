"""Pure hooks of the ``bec`` workflow (architecture 14.3.3).

The hooks read only the run's records (a :class:`RunView`: no context, no adapters) and compute:

* ``facts`` for the recommendation rules: which tenant mailboxes show identity compromise or mailbox
  abuse, which delivered messages are fraud, which sender domains impersonate the organisation. Every
  fact carries the record ids it was computed from, so each recommendation cites real records;
* ``derive_signals``: patterns no single record's signal expresses, each citing the records it was
  computed from and attributed to the source of those records: "successful sign-in or approved MFA from
  an IP rated malicious or suspicious", "the user reported an MFA prompt as fraud", "unverified OAuth
  app consented with mailbox access" and "sender domain is a look-alike of an organisation domain";
* ``correlate``: one link per tenant mailbox that also appears as the sender of investigated messages.

Nothing here decides an approval level, skips a critical asset or calls a vendor. The look-alike test is
a deterministic heuristic (homoglyph digits, one edit, the organisation name as a hyphenated token, the
same name under another suffix) and is shown as such in every note.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from xdr_response.atomics.correlation.models import CorrelationLink, EntityRef, LinkKind
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.models import Observable, ObservableType, Severity, TargetKind, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = ["BecHooks", "HOOKS", "is_lookalike", "registrable_label", "skeleton"]

_FLAGGED = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_OUT_OF_MAILBOX = frozenset({"quarantine", "deleted", "failed"})
_SEVERE = frozenset({Severity.HIGH, Severity.CRITICAL})
#: OAuth permissions that give an application access to a mailbox (lower case).
_MAIL_PERMISSIONS = frozenset({
    "mail.read", "mail.readwrite", "mail.send", "mail.read.shared", "mail.readwrite.shared", "mail.send.shared",
    "mailboxsettings.readwrite", "full_access_as_app", "eas.accessasuser.all", "ews.accessasuser.all",
})
_SECOND_LEVEL = frozenset({"co", "com", "org", "net", "ac", "gov", "edu"})
_GLYPHS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "4": "a", "5": "s", "7": "t",
                         "8": "b", "@": "a", "$": "s"})
_SUMMARY_CHARS = 400
_SIGN_IN_SEVERITY = {Verdict.MALICIOUS: 80, Verdict.SUSPICIOUS: 60}
_LOOKALIKE_SEVERITY = 70
_CONSENT_SEVERITY = 60
_FRAUD_REPORT_SEVERITY = 70


# ------------------------------------------------------------- look-alike --
def registrable_label(domain: str) -> str:
    """The label before the public suffix (``examp1e`` of ``pay.examp1e.test``; ``co.uk``-style aware)."""
    labels = [label for label in domain.strip().lower().rstrip(".").split(".") if label]
    if len(labels) < 2:
        return labels[0] if labels else ""
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2]


def skeleton(label: str) -> str:
    """Homoglyph skeleton of a label: digits and look-alike characters folded, ``rn`` -> ``m``, ``vv`` -> ``w``."""
    return label.lower().replace("rn", "m").replace("vv", "w").translate(_GLYPHS)


def _edit_distance(first: str, second: str) -> int:
    previous = list(range(len(second) + 1))
    for i, a in enumerate(first, start=1):
        current = [i]
        for j, b in enumerate(second, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a != b)))
        previous = current
    return previous[-1]


def _within(domain: str, parent: str) -> bool:
    return domain == parent or domain.endswith("." + parent)


def is_lookalike(domain: str, org_domain: str) -> bool:
    """True when ``domain`` imitates ``org_domain`` without being it or one of its subdomains."""
    candidate, org = domain.strip().lower().rstrip("."), org_domain.strip().lower().rstrip(".")
    if not candidate or not org or _within(candidate, org):
        return False
    name, org_name = registrable_label(candidate), registrable_label(org)
    if len(org_name) < 4 or not name:
        return False
    if name == org_name or skeleton(name) == skeleton(org_name):
        return True  # same name under another suffix, or homoglyphs of it
    if len(org_name) >= 5 and _edit_distance(name, org_name) == 1:
        return True
    return org_name in name.split("-")


def _lookalike_of(domain: str | None, org_domains: Sequence[str]) -> str | None:
    if not domain:
        return None
    return next((org for org in org_domains if is_lookalike(domain, org)), None)


# ------------------------------------------------------------ record view --
def _lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _domain_of(address: str | None) -> str:
    text = _lower(address)
    return text.rpartition("@")[2] if "@" in text else ""


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _clip(text: str) -> str:
    return text if len(text) <= _SUMMARY_CHARS else text[:_SUMMARY_CHARS - 3] + "..."


@dataclass
class _Mailbox:
    user: str
    profile_ids: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    identity_reasons: list[str] = field(default_factory=list)
    identity_ids: list[str] = field(default_factory=list)
    risky_access_ids: list[str] = field(default_factory=list)  # sign-in / MFA pattern (hook signal)
    risky_access_integration: str | None = None
    risky_access_verdict: Verdict = Verdict.SUSPICIOUS
    abuse_reasons: list[str] = field(default_factory=list)
    abuse_ids: list[str] = field(default_factory=list)
    persistence: bool = False  # malicious rule or risky OAuth consent
    unrated_apps: list[Any] = field(default_factory=list)  # risky consents without a vendor verdict (hook signal)
    fraud_reports: list[Any] = field(default_factory=list)  # MFA prompts the user reported as fraud (hook signal)
    manual: list[str] = field(default_factory=list)
    manual_steps: list[tuple[str, str, str]] = field(default_factory=list)  # (subject, step, record id)

    @property
    def compromised(self) -> bool:
        return bool(self.identity_reasons) or self.persistence

    def fact(self) -> dict[str, Any]:
        reasons = [*self.identity_reasons, *self.abuse_reasons]
        return {
            "user": self.user,
            "identity_compromise": bool(self.identity_reasons),
            "abuse": bool(self.abuse_reasons),
            "identity_reasons": list(self.identity_reasons),
            "abuse_reasons": list(self.abuse_reasons),
            "profile_record_ids": _unique(self.profile_ids),
            "identity_record_ids": _unique(self.identity_ids),
            "abuse_record_ids": _unique(self.abuse_ids),
            "groups": _unique(self.groups),
            "roles": _unique(self.roles),
            "summary": _clip("; ".join(reasons) if reasons else "no compromise evidence"),
            "manual_steps": _clip("; ".join(_unique(self.manual))),
        }


@dataclass
class _Message:
    message_id: str
    record_ids: list[str]
    sender: str
    sender_domain: str
    integration: str
    verdict: Verdict
    in_mailbox: bool
    direction: str
    recipients: list[str]


class _Analysis:
    """Everything the three hooks need, computed once per call from the run's records."""

    def __init__(self, view: RunView) -> None:
        self.records: dict[str, Any] = {}
        self.ip_reports: dict[str, ObservableReport] = {}
        for result in view.results:
            if isinstance(result, ObservableReport) and result.subject.type in (ObservableType.IP, ObservableType.IPV6):
                self.ip_reports.setdefault(_lower(result.subject.value), result)
            for record in result.records:
                self.records.setdefault(record.record_id, record)
        self.messages = self._messages()
        self.mailboxes = self._mailboxes()
        self.org_domains = self._org_domains(view)
        self._mark_fraud_senders()

    # -- records --
    def of(self, kind: str) -> list[Any]:
        return [r for r in self.records.values() if str(r.kind) == kind]

    def _messages(self) -> dict[str, _Message]:
        out: dict[str, _Message] = {}
        for record in self.of("email_message"):
            known = out.get(record.message_id)
            if known is not None:
                known.record_ids.append(record.record_id)
                if record.verdict is Verdict.MALICIOUS or (record.verdict is Verdict.SUSPICIOUS
                                                           and known.verdict not in _FLAGGED):
                    known.verdict = record.verdict
                continue
            sender = _lower(record.sender)
            out[record.message_id] = _Message(
                message_id=record.message_id, record_ids=[record.record_id], sender=sender,
                sender_domain=_lower(record.sender_domain) or _domain_of(sender), integration=record.integration,
                verdict=record.verdict, in_mailbox=record.delivery_location not in _OUT_OF_MAILBOX,
                direction=record.direction, recipients=[_lower(r) for r in record.recipients])
        return dict(sorted(out.items()))

    def _mailboxes(self) -> dict[str, _Mailbox]:
        boxes: dict[str, _Mailbox] = {}
        for profile in self.of("user_profile"):
            box = boxes.setdefault(_lower(profile.user), _Mailbox(user=_lower(profile.user)))
            box.profile_ids.append(profile.record_id)
            box.groups.extend(profile.groups)
            box.roles.extend(profile.roles)
            if profile.risk_state == "confirmed_compromised":
                box.identity_reasons.append("Entra risk state confirmed compromised")
                box.identity_ids.append(profile.record_id)
            elif profile.risk_level == "high":
                box.identity_reasons.append("Entra user risk high")
                box.identity_ids.append(profile.record_id)
        for user, box in sorted(boxes.items()):
            self._identity(user, box)
            self._persistence(user, box)
        return dict(sorted(boxes.items()))

    def _risky_ip(self, ip: str | None) -> tuple[Verdict, list[str]] | None:
        report = self.ip_reports.get(_lower(ip))
        if report is None or report.verdict not in _FLAGGED:
            return None
        ids = [r.record_id for r in report.records if str(r.kind) == "enrichment" and r.verdict in _FLAGGED]
        return (report.verdict, ids) if ids else None

    def _risky_access(self, box: _Mailbox, record: Any, what: str) -> None:
        risky = self._risky_ip(record.ip)
        if risky is None:
            return
        verdict, enrichment_ids = risky
        box.identity_reasons.append(f"{what} from {record.ip} rated {verdict.value}")
        box.identity_ids.extend([record.record_id, *enrichment_ids])
        box.risky_access_ids.extend([record.record_id, *enrichment_ids])
        box.risky_access_integration = box.risky_access_integration or record.integration
        if verdict is Verdict.MALICIOUS:
            box.risky_access_verdict = Verdict.MALICIOUS

    def _identity(self, user: str, box: _Mailbox) -> None:
        for sign_in in sorted(self.of("sign_in"), key=lambda r: (r.timestamp, r.record_id)):
            if _lower(sign_in.user) == user and sign_in.result == "success":
                self._risky_access(box, sign_in, "successful sign-in")
        for event in sorted(self.of("mfa_event"), key=lambda r: (r.timestamp, r.record_id)):
            if _lower(event.user) != user:
                continue
            if event.result == "fraud_reported":
                box.identity_reasons.append(f"user reported an MFA prompt as fraud ({event.method})")
                box.identity_ids.append(event.record_id)
                box.fraud_reports.append(event)
            elif event.result == "approved":
                self._risky_access(box, event, "approved MFA prompt")
        for anomaly in sorted(self.of("anomaly"), key=lambda r: r.record_id):
            if _lower(anomaly.user) == user and Severity(anomaly.severity) in _SEVERE:
                box.identity_reasons.append(f"{anomaly.anomaly_type} anomaly ({Severity(anomaly.severity).value})")
                box.identity_ids.append(anomaly.record_id)

    def _persistence(self, user: str, box: _Mailbox) -> None:
        for rule in sorted(self.of("mailbox_rule"), key=lambda r: (r.rule_id, r.record_id)):
            if _lower(rule.mailbox) != user or rule.enabled is False:
                continue
            if rule.external_forwarding:
                targets = ", ".join(_unique([*rule.forward_to, *rule.redirect_to, *rule.forward_as_attachment_to]))
                box.abuse_reasons.append(f"mailbox rule '{rule.name}' forwards mail outside the organisation "
                                         f"({targets})")
            elif rule.delete:
                box.abuse_reasons.append(f"mailbox rule '{rule.name}' deletes messages")
            else:
                continue
            box.abuse_ids.append(rule.record_id)
            box.persistence = True
            box.manual.append(f"remove mailbox rule '{rule.name}' (id {rule.rule_id}) from {user}")
            box.manual_steps.append((f"mailbox rule {rule.rule_id} of {user}",
                                     f"remove mailbox rule '{rule.name}' in the mail console (no verified "
                                     "automated action exists)", rule.record_id))
        for app in sorted(self.of("cloud_app"), key=lambda r: (r.app_id, r.record_id)):
            if _lower(app.consented_by) != user and not (app.consented_by is None and _lower(app.subject.value) == user):
                continue
            mail_access = sorted(p for p in app.permissions if p.lower() in _MAIL_PERMISSIONS)
            if app.verdict in _FLAGGED or (mail_access and app.publisher_verified is False):
                name = app.display_name or app.app_id
                box.abuse_reasons.append(f"OAuth app '{name}' consented with mailbox access"
                                         + (f" ({', '.join(mail_access)})" if mail_access else ""))
                box.abuse_ids.append(app.record_id)
                box.persistence = True
                if app.verdict is Verdict.UNKNOWN:
                    box.unrated_apps.append(app)
                box.manual.append(f"revoke the OAuth consent of '{name}' for {user}")
                box.manual_steps.append((f"OAuth consent {app.app_id} of {user}",
                                         f"revoke the OAuth consent of '{name}' in the identity console (no "
                                         "verified automated action exists)", app.record_id))

    def _mark_fraud_senders(self) -> None:
        for message in self.messages.values():
            box = self.mailboxes.get(message.sender)
            if box is not None and message.verdict in _FLAGGED:
                box.abuse_reasons.append(f"sent message {message.message_id} flagged {message.verdict.value} by the "
                                         "mail gateway")
                box.abuse_ids.extend(message.record_ids)

    def _org_domains(self, view: RunView) -> list[str]:
        domains = [_domain_of(user) for user in self.mailboxes]
        domains += [_domain_of(user) for user in view.incident.users]
        domains += [_domain_of(o.value) for o in view.incident.observables if o.type is ObservableType.USER]
        domains += [_domain_of(r) for m in self.messages.values() if m.direction == "inbound" for r in m.recipients]
        return sorted(set(d for d in domains if d))

    # -- facts --
    def fraud_messages(self) -> list[dict[str, Any]]:
        out = []
        for message in self.messages.values():
            if not message.in_mailbox:
                continue
            reasons: list[str] = []
            ids = list(message.record_ids)
            box = self.mailboxes.get(message.sender)
            if box is not None and box.compromised:
                reasons.append(f"sent by mailbox {box.user} with compromise evidence")
                ids += [*box.identity_ids, *box.abuse_ids]
            if message.verdict in _FLAGGED:
                reasons.append(f"flagged {message.verdict.value} by the mail gateway")
            lookalike = None if box is not None else _lookalike_of(message.sender_domain, self.org_domains)
            if lookalike is not None:
                reasons.append(f"sender domain {message.sender_domain} looks like {lookalike} (heuristic)")
            if not reasons:
                continue
            out.append({"message_id": message.message_id, "sender": message.sender or "unknown sender",
                        "recipient": message.recipients[0] if len(set(message.recipients)) == 1 else "",
                        "sender_domain": message.sender_domain, "record_ids": _unique(ids),
                        "summary": _clip("; ".join(reasons))})
        return out

    def impersonation_domains(self) -> list[dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for message in self.messages.values():
            if not message.sender_domain or message.sender in self.mailboxes:
                continue  # a tenant mailbox's own domain is handled by the identity actions, never blocked
            lookalike = _lookalike_of(message.sender_domain, self.org_domains)
            flagged = message.verdict in _FLAGGED
            if lookalike is None and not flagged:
                continue
            entry = found.setdefault(message.sender_domain, {
                "domain": message.sender_domain, "lookalike_of": lookalike, "gateway_flagged": False,
                "record_ids": [], "messages": 0})
            entry["gateway_flagged"] = entry["gateway_flagged"] or flagged
            entry["record_ids"] = _unique([*entry["record_ids"], *message.record_ids])
            entry["messages"] += 1
        out = []
        for domain, entry in sorted(found.items()):
            parts = []
            if entry["lookalike_of"]:
                parts.append(f"looks like organisation domain {entry['lookalike_of']} (heuristic)")
            if entry["gateway_flagged"]:
                parts.append("sent messages flagged by the mail gateway")
            parts.append(f"{entry['messages']} investigated message(s)")
            out.append({**entry, "summary": _clip("; ".join(parts))})
        return out

    # -- signals --
    def signals(self, origin: str) -> list[ScoringSignal]:
        out: list[ScoringSignal] = []
        for box in self.mailboxes.values():
            for app in box.unrated_apps:
                out.append(_signal(SignalCategory.PERSISTENCE, app.integration,
                                   Observable(type=ObservableType.USER, value=box.user), _CONSENT_SEVERITY, 60,
                                   (app.record_id,), origin,
                                   f"unverified OAuth app '{app.display_name or app.app_id}' consented with "
                                   "mailbox access"))
            for event in box.fraud_reports:
                out.append(_signal(SignalCategory.AUTHENTICATION_ANOMALY, event.integration,
                                   Observable(type=ObservableType.USER, value=box.user), _FRAUD_REPORT_SEVERITY, 70,
                                   (event.record_id,), origin,
                                   "the user reported an MFA prompt as fraud: someone else holds the password"))
            if not box.risky_access_ids or box.risky_access_integration is None:
                continue
            ids = tuple(_unique(box.risky_access_ids))
            severity = _SIGN_IN_SEVERITY[box.risky_access_verdict]
            note = "successful sign-in or approved MFA from an IP rated " + box.risky_access_verdict.value.lower()
            out.append(_signal(SignalCategory.AUTHENTICATION_ANOMALY, box.risky_access_integration,
                               Observable(type=ObservableType.USER, value=box.user), severity, 70, ids, origin, note))
            for message in self.messages.values():
                if message.sender == box.user:
                    out.append(_signal(SignalCategory.AUTHENTICATION_ANOMALY, box.risky_access_integration,
                                       Observable(type=ObservableType.EMAIL_MESSAGE_ID, value=message.message_id),
                                       severity, 70, (*ids, *message.record_ids), origin,
                                       f"sent by {box.user}: {note}"))
        by_domain: dict[str, list[_Message]] = {}
        for message in self.messages.values():
            if message.sender not in self.mailboxes and _lookalike_of(message.sender_domain, self.org_domains):
                by_domain.setdefault(message.sender_domain, []).append(message)
        for domain, messages in sorted(by_domain.items()):
            org = _lookalike_of(domain, self.org_domains)
            note = f"sender domain {domain} looks like organisation domain {org} (workflow heuristic)"
            for integration in sorted({m.integration for m in messages}):
                ids = tuple(_unique(i for m in messages if m.integration == integration for i in m.record_ids))
                out.append(_signal(SignalCategory.EMAIL_VERDICT, integration,
                                   Observable(type=ObservableType.DOMAIN, value=domain), _LOOKALIKE_SEVERITY, 60,
                                   ids, origin, note))
            for message in messages:
                out.append(_signal(SignalCategory.EMAIL_VERDICT, message.integration,
                                   Observable(type=ObservableType.EMAIL_MESSAGE_ID, value=message.message_id),
                                   _LOOKALIKE_SEVERITY, 60, tuple(message.record_ids), origin, note))
        return out

    # -- links --
    def links(self, origin: str) -> list[CorrelationLink]:
        out: list[CorrelationLink] = []
        for box in self.mailboxes.values():
            sent = [m for m in self.messages.values() if m.sender == box.user]
            if not sent or not box.profile_ids:
                continue
            ids = tuple(sorted(set([*box.profile_ids, *(i for m in sent for i in m.record_ids)])))
            out.append(CorrelationLink(
                kind=LinkKind.WORKFLOW, origin=origin, record_ids=ids,
                entities=(EntityRef(kind=TargetKind.USER, value=box.user),
                          EntityRef(kind=TargetKind.EMAIL_ADDRESS, value=box.user)),
                note=f"tenant mailbox {box.user} is the sender of {len(sent)} investigated message(s)"))
        return out


def _signal(category: SignalCategory, integration: str, observable: Observable, severity: int, confidence: int,
            record_ids: Sequence[str], origin: str, note: str) -> ScoringSignal:
    return ScoringSignal(category=category, integration=integration, observable=observable,
                         verdict=Verdict.SUSPICIOUS, severity=severity, confidence=confidence,
                         record_ids=tuple(_unique(record_ids)), origin=origin, note=note)


class BecHooks(WorkflowHooks):
    """Facts, signals and links of the BEC workflow (pure functions of the run's records)."""

    def correlate(self, view: RunView) -> Sequence[CorrelationLink]:
        return _Analysis(view).links(view.origin)

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        return _Analysis(view).signals(view.origin)

    def facts(self, view: RunView) -> Mapping[str, Any]:
        analysis = _Analysis(view)
        return {
            "org_domains": analysis.org_domains,
            "mailboxes": [box.fact() for box in analysis.mailboxes.values()],
            "fraud_messages": analysis.fraud_messages(),
            "impersonation_domains": analysis.impersonation_domains(),
        }

    def considered(self, view: RunView) -> Sequence[Consideration]:
        """Manual steps: mailbox rule removal and OAuth consent revocation have no VERIFIED write."""
        return [Consideration(subject=subject, reason=step, record_ids=(record_id,), manual=True)
                for box in _Analysis(view).mailboxes.values() for subject, step, record_id in box.manual_steps]

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        """Identity compromise behind the mailbox abuse: account-takeover reviews the account."""
        return [Handoff(workflow_id="account-takeover", subjects=(box.user,),
                        reason="identity compromise behind the business email compromise ("
                               + "; ".join(_unique(box.identity_reasons)) + "); review the account",
                        record_ids=tuple(_unique(box.identity_ids)))
                for box in _Analysis(view).mailboxes.values() if box.identity_reasons and box.identity_ids]


HOOKS = BecHooks()
