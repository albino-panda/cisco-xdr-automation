"""Hooks of the ``mail-bombing`` workflow: pure facts and record-backed signals (architecture 14.3.3).

A mail bomb (email or subscription bombing) is treated as **concealment**: the flood exists to bury
something the recipient must not notice (a password reset or change, a security alert, a new sign-in
or device, an MFA prompt, a payment or invoice request, a lure) and is often followed by a fake IT
support contact that pushes remote-access tooling. These hooks turn the typed records of one run into:

* ``facts()``: the flood (window, volume, sender diversity, message characteristics, qualification),
  the flood messages that may be quarantined, the buried messages of interest that are kept out of the
  quarantine, identity events and account-takeover indications inside the flood window, endpoint
  activity after the flood started and malicious domains seen in the flood;
* ``derive_signals()``: two computed patterns, each citing the records it was computed from
  (``campaign_association`` for a message that belongs to a qualifying flood; ``authentication_anomaly``
  for identity events and takeover indications inside the flood window).

Read zone (14.0.1): no context, no adapters, no state change, no approval decision. The hooks never
invent a fact: every list they return names the ids of records produced by the run. The detector
metrics in ``incident.trigger`` (from the separate ``cisco-xdr-mailbomb-detector`` project) only gate
the flood qualification, as in the legacy plan rule; they are never evidence.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import (
    AnomalyRecord,
    AnyRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    ProcessEventRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Observable, ObservableType, Severity, Verdict
from xdr_response.models.scoring import ScoringSignal, SignalCategory
from xdr_response.workflows.hooks import Consideration, Handoff, RunView, WorkflowHooks

__all__ = [
    "WORKFLOW_ID",
    "DETECTOR_SOURCE",
    "DETECTOR_EVENT_TYPE",
    "FLOOD_MIN_SENDER_DOMAINS",
    "FLOOD_MIN_CLEAN_RATIO_PCT",
    "FLOOD_MIN_MESSAGES",
    "BURIED_KEYWORDS",
    "IDENTITY_CATEGORIES",
    "MailBombingHooks",
    "HOOKS",
    "classify_subject",
]

WORKFLOW_ID = "mail-bombing"
ORIGIN = f"workflow:{WORKFLOW_ID}"

#: The separate detector project that raises mail-bomb incidents, and its webhook event type.
DETECTOR_SOURCE = "cisco-xdr-mailbomb-detector"
DETECTOR_EVENT_TYPE = "mailbomb.detection"

#: Flood qualification (the legacy ``quarantine_burst_messages`` rule): real sender diversity (the
#: detector's medium floor) and at least half of the burst neutral or graymail. Spam and malicious
#: storms are left to Secure Email policies and the phishing workflow.
FLOOD_MIN_SENDER_DOMAINS = 10
FLOOD_MIN_CLEAN_RATIO_PCT = 50
#: Without detector metrics the flood is judged on the observed messages only.
FLOOD_MIN_MESSAGES = 10

#: Subject keywords of the messages a flood is meant to bury (case-insensitive substrings, matched on
#: the subject with hyphens, underscores and runs of whitespace folded to one space, so "sign-in
#: code", "sign in code" and "Sign_In  Code" are one phrase). A security notice is any subject about
#: the account's password, a one-time / verification / sign-in code or a change of the second
#: factor: when in doubt the message is kept for the analyst, never quarantined with the flood.
BURIED_KEYWORDS: Mapping[str, tuple[str, ...]] = {
    "credential": ("password reset", "reset your password", "password changed", "password was changed",
                   "password change", "password", "passcode", "passphrase", "passkey", "account recovery",
                   "recover your account", "recovery code", "recovery email", "recovery phone", "reset code",
                   "reset link", "account locked", "account was locked", "account has been locked",
                   "unlock your account", "account suspended"),
    "security_alert": ("security alert", "security notice", "security notification", "security warning",
                       "security info", "security information", "security settings", "new sign in", "new login",
                       "new log in", "new device", "unusual sign in", "unusual login", "unusual activity",
                       "sign in attempt", "login attempt", "log in attempt", "suspicious activity",
                       "suspicious sign in", "unrecognized sign in", "unrecognised sign in"),
    "mfa": ("mfa", "multi factor", "multifactor", "two factor", "2fa", "two step", "2 step", "2sv",
            "verification code", "verification link", "security code", "security key", "sign in code",
            "signin code", "login code", "log in code", "access code", "auth code", "authentication",
            "authenticator", "one time", "onetime", "single use code", "confirmation code", "otp", "totp"),
    "financial": ("wire transfer", "invoice", "banking", "bank account", "payment"),
    "lure": ("docusign", "microsoft"),
}
#: Keywords so short they are matched as whole words only ("otp" must not match "hotpot").
_WHOLE_WORD_KEYWORDS = frozenset({"mfa", "2fa", "2sv", "otp", "totp"})
_FOLD = re.compile(r"[\s_\-\u2010-\u2015]+")
#: Buried-message categories that stand for an identity event of the recipient.
IDENTITY_CATEGORIES = frozenset({"credential", "security_alert", "mfa"})

_SUPPORTING = frozenset({Verdict.MALICIOUS, Verdict.SUSPICIOUS})
_CLEAN_VERDICTS = frozenset({Verdict.CLEAN, Verdict.UNKNOWN})
_THREAT_TYPES = frozenset({"spam", "phish", "phishing", "malware", "bec", "scam"})
_HIGH_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})
#: Role changes that leave the account holding the role (counted in the critical-asset context).
_GRANTING_ROLE_CHANGES = frozenset({"assigned", "activated", "eligible_assigned"})
_SIGNAL_CITATION_CAP = 25  # a flood signal cites its message and at most this many flood records

# Computed-pattern signals (severity = impact if true, confidence = strength of the pattern).
_FLOOD_SEVERITY, _FLOOD_CONFIDENCE = 70, 80
_FLOOD_CONFIDENCE_OBSERVED_ONLY = 70
_IDENTITY_SEVERITY, _IDENTITY_CONFIDENCE = 75, 75
_NOTIFICATION_SEVERITY, _NOTIFICATION_CONFIDENCE = 60, 60
_TAKEOVER_SEVERITY, _TAKEOVER_CONFIDENCE = 85, 80


# ------------------------------------------------------------------ helpers --
def _fold(text: str) -> str:
    return _FOLD.sub(" ", text.lower()).strip()


def _keyword_in(word: str, text: str) -> bool:
    folded = _fold(word)
    if folded in _WHOLE_WORD_KEYWORDS:
        return re.search(rf"(?<![a-z0-9]){re.escape(folded)}(?![a-z0-9])", text) is not None
    return folded in text


def classify_subject(subject_line: str | None) -> tuple[str, ...]:
    """Buried-message categories whose keywords appear in a subject line (sorted, may be empty)."""
    text = _fold(subject_line or "")
    if not text:
        return ()
    return tuple(sorted(c for c, words in BURIED_KEYWORDS.items() if any(_keyword_in(w, text) for w in words)))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _lower(values: Iterable[Any]) -> list[str]:
    return [str(v).strip().lower() for v in values if isinstance(v, str) and v.strip()]


def _detector_payload(trigger: Mapping[str, Any]) -> Mapping[str, Any]:
    """The detector webhook payload: ``trigger["detector"]``, a legacy replay context, or the trigger."""
    for key in ("detector", "legacy_context"):
        nested = trigger.get(key)
        if isinstance(nested, Mapping) and (nested.get("event_type") or nested.get("metrics")):
            return nested
    return trigger


def _record_time(record: AnyRecord) -> datetime | None:
    """When the fact happened (kind-specific time, else ``observed_at``)."""
    if isinstance(record, EmailMessageRecord):
        when = record.received_at
    elif isinstance(record, (SignInRecord, MfaEventRecord, ProcessEventRecord)):
        when = record.timestamp
    elif isinstance(record, (AnomalyRecord, DetectionRecord, DnsQueryRecord, NetworkConnectionRecord)):
        when = record.first_seen or record.last_seen
    elif isinstance(record, MailboxRuleRecord):
        when = record.created_at or record.modified_at
    elif isinstance(record, RoleChangeRecord):
        when = record.timestamp
    else:
        when = None
    return when or record.observed_at


def _at_or_after(record: AnyRecord, start: datetime | None) -> bool:
    if start is None:
        return False
    when = _record_time(record)
    return when is not None and when >= start


def _sender_domain(message: EmailMessageRecord) -> str | None:
    if message.sender_domain:
        return message.sender_domain
    if message.sender and "@" in message.sender:
        return message.sender.rsplit("@", 1)[1].lower().rstrip(".") or None
    return None


def _is_bulk(message: EmailMessageRecord) -> bool:
    """Neutral or graymail: no threat verdict and no threat type other than graymail / bulk."""
    types = {t.lower() for t in message.threat_types}
    return message.verdict in _CLEAN_VERDICTS and not (types & _THREAT_TYPES)


def _sorted_ids(ids: Iterable[str]) -> list[str]:
    return sorted(set(ids))


# ------------------------------------------------------------------ analysis --
class _Analysis:
    """Everything the facts and signals are computed from (pure, deterministic)."""

    def __init__(self, view: RunView) -> None:
        self.records: tuple[AnyRecord, ...] = view.index.records()
        self.reports = tuple(r for r in view.results if isinstance(r, ObservableReport))
        trigger = view.incident.trigger if isinstance(view.incident.trigger, Mapping) else {}
        self.detector = _detector_payload(trigger)
        self.recipients = self._recipients(view)
        self.messages = sorted((r for r in self.records if isinstance(r, EmailMessageRecord)
                                and set(_lower(r.recipients)) & set(self.recipients)
                                and r.direction in ("inbound", "unknown")),
                               key=lambda m: (_iso(m.received_at) or "", m.message_id))
        metrics = self.detector.get("metrics")
        self.metrics: Mapping[str, Any] = metrics if isinstance(metrics, Mapping) else {}
        self.window_start, self.window_end = self._window()
        self.flood = [m for m in self.messages if self._in_flood_window(m)]
        self.buried = {m.record_id: classify_subject(m.subject_line) for m in self.flood}
        self.quarantinable = [m for m in self.flood
                              if (_is_bulk(m) and not self.buried[m.record_id]) or m.verdict is Verdict.MALICIOUS]
        self.qualifies, self.reason = self._qualification()

    # ------------------------------------------------------------ inputs --
    def _recipients(self, view: RunView) -> list[str]:
        incident = view.incident
        found = _lower(incident.users)
        found += _lower(o.value for o in incident.observables
                        if o.type in (ObservableType.EMAIL_ADDRESS, ObservableType.USER))
        recipient = self.detector.get("recipient")
        if isinstance(recipient, str):
            found += _lower([recipient])
        return list(dict.fromkeys(found))

    def _window(self) -> tuple[datetime | None, datetime | None]:
        start = _parse_time(self.metrics.get("window_start"))
        end = _parse_time(self.metrics.get("window_end"))
        if start is not None:
            return start, end
        times = [m.received_at for m in self.messages if m.received_at is not None]
        if len(self.messages) >= FLOOD_MIN_MESSAGES and times:
            return min(times), max(times)
        return None, None

    def _in_flood_window(self, message: EmailMessageRecord) -> bool:
        if self.window_start is None:
            return False
        when = message.received_at
        if when is None:
            return True  # the flood search returned it without a time: part of the searched flood
        return when >= self.window_start and (self.window_end is None or when <= self.window_end)

    # ------------------------------------------------------- qualification --
    def observed(self) -> dict[str, int]:
        domains = {d for d in (_sender_domain(m) for m in self.flood) if d}
        bulk = sum(1 for m in self.flood if _is_bulk(m))
        return {"messages": len(self.flood), "sender_domains": len(domains), "bulk": bulk,
                "spam": sum(1 for m in self.flood if "spam" in {t.lower() for t in m.threat_types}),
                "malicious": sum(1 for m in self.flood if m.verdict is Verdict.MALICIOUS)}

    def detector_numbers(self) -> dict[str, int] | None:
        total = _int(self.metrics.get("total_messages"))
        domains = _int(self.metrics.get("unique_sender_domains"))
        if total is None or domains is None or total <= 0:
            return None
        clean = (_int(self.metrics.get("neutral_count")) or 0) + (_int(self.metrics.get("graymail_count")) or 0)
        return {"total_messages": total, "unique_sender_domains": domains, "clean_messages": clean,
                "clean_ratio_pct": (clean * 100) // total}

    def _qualification(self) -> tuple[bool, str]:
        if self.window_start is None:
            return False, "no flood window: no detector metrics and too few messages to the recipient"
        numbers = self.detector_numbers()
        if numbers is not None:
            domains, ratio = numbers["unique_sender_domains"], numbers["clean_ratio_pct"]
            basis = (f"detector: {numbers['total_messages']} messages from {domains} sender domains, "
                     f"{ratio}% neutral or graymail")
        else:
            seen = self.observed()
            domains = seen["sender_domains"]
            ratio = (seen["bulk"] * 100) // seen["messages"] if seen["messages"] else 0
            if seen["messages"] < FLOOD_MIN_MESSAGES:
                return False, f"observed: {seen['messages']} messages (< {FLOOD_MIN_MESSAGES})"
            basis = f"observed: {seen['messages']} messages from {domains} sender domains, {ratio}% neutral or graymail"
        if domains < FLOOD_MIN_SENDER_DOMAINS:
            return False, f"{basis}: fewer than {FLOOD_MIN_SENDER_DOMAINS} sender domains (not a subscription bomb)"
        if ratio < FLOOD_MIN_CLEAN_RATIO_PCT:
            return False, f"{basis}: below {FLOOD_MIN_CLEAN_RATIO_PCT}% neutral or graymail (spam or malicious storm)"
        return True, basis

    # ------------------------------------------------------------ identity --
    def _user_records(self, user: str) -> list[AnyRecord]:
        out: list[AnyRecord] = []
        for record in self.records:
            if isinstance(record, (SignInRecord, MfaEventRecord, RoleChangeRecord)) and record.user == user:
                out.append(record)
            elif isinstance(record, AnomalyRecord) and record.user == user:
                out.append(record)
            elif isinstance(record, MailboxRuleRecord) and record.mailbox == user:
                out.append(record)
        return out

    @staticmethod
    def _is_identity_event(record: AnyRecord) -> bool:
        if isinstance(record, (MfaEventRecord, AnomalyRecord)):
            return True
        if isinstance(record, SignInRecord):
            return (record.risk_level in ("medium", "high") or record.device_compliant is False
                    or record.conditional_access == "failure")
        if isinstance(record, MailboxRuleRecord):
            return True
        if isinstance(record, RoleChangeRecord):
            return record.privileged and record.change in ("assigned", "activated", "eligible_assigned")
        return False

    def identity_records(self, user: str) -> list[AnyRecord]:
        """Identity-provider records of ``user`` at or after the flood window start."""
        return [r for r in self._user_records(user) if _at_or_after(r, self.window_start)
                and self._is_identity_event(r)]

    def notification_records(self, user: str) -> list[EmailMessageRecord]:
        """Buried credential, security-alert or MFA notifications to ``user`` inside the flood."""
        return [m for m in self.flood if user in _lower(m.recipients)
                and set(self.buried[m.record_id]) & IDENTITY_CATEGORIES]

    def takeover_records(self, user: str) -> tuple[list[AnyRecord], list[str]]:
        """Records that indicate the account is in someone else's hands, and why."""
        events = self.identity_records(user)
        cited: list[AnyRecord] = []
        reasons: list[str] = []
        high_anomalies = [r for r in events if isinstance(r, AnomalyRecord) and r.severity in _HIGH_SEVERITIES]
        for record in events:
            if isinstance(record, SignInRecord) and record.result == "success" and (
                    record.risk_level == "high" or high_anomalies):
                cited.append(record)
                reasons.append("successful high-risk sign-in inside the flood window")
            elif isinstance(record, MailboxRuleRecord) and (
                    record.external_forwarding or record.delete or record.mark_as_read or record.move_to_folder):
                cited.append(record)
                reasons.append(f"mailbox rule '{record.name}' that hides or forwards mail created inside the flood window")
        mfa = sorted((r for r in events if isinstance(r, MfaEventRecord)), key=lambda r: (r.timestamp, r.record_id))
        denied = [r for r in mfa if r.result in ("denied", "fraud_reported", "timeout")]
        approved_after = [r for r in mfa if r.result == "approved" and denied and r.timestamp >= denied[0].timestamp]
        if approved_after:
            cited += [*denied, *approved_after]
            reasons.append("MFA prompt approved after denied prompts inside the flood window")
        profiles = [r for r in self.records if isinstance(r, UserProfileRecord) and r.user == user
                    and r.risk_state == "confirmed_compromised"]
        if cited and profiles:
            cited += profiles
            reasons.append("identity provider marks the user confirmed compromised")
        if cited:
            cited += high_anomalies
        return list({r.record_id: r for r in cited}.values()), list(dict.fromkeys(reasons))

    def user_asset(self, user: str) -> dict[str, list[str]]:
        """Groups and directory roles of ``user`` for the critical-asset policy.

        Roles granted by a role change the workflow found (``assigned``, ``activated``,
        ``eligible_assigned``) count too, whenever they happened: the account holds them now, so an
        account made Global Administrator during the incident is classified critical (ELEVATED with
        a warning), never weaker than its current rights.
        """
        groups: set[str] = set()
        roles: set[str] = set()
        for record in self.records:
            if isinstance(record, UserProfileRecord) and record.user == user:
                groups.update(record.groups)
                roles.update(record.roles)
            elif (isinstance(record, RoleChangeRecord) and record.user == user
                  and record.change in _GRANTING_ROLE_CHANGES and record.role_name):
                roles.add(record.role_name)
        return {"groups": sorted(groups), "roles": sorted(roles)}

    # ------------------------------------------------------------ endpoint --
    def endpoint_activity(self) -> list[dict[str, Any]]:
        if self.window_start is None:
            return []
        hosts: dict[str, dict[str, Any]] = {}
        for record in self.records:
            if isinstance(record, EndpointRecord):
                entry = hosts.setdefault(record.hostname, {"ids": set(), "groups": set(), "tags": set(), "ip": None})
                entry["groups"].update(record.groups)
                entry["tags"].update(record.tags)
                if entry["ip"] is None and record.ip_addresses:
                    entry["ip"] = record.ip_addresses[0]
        for record in self.records:
            host = None
            if isinstance(record, DetectionRecord) and record.verdict in _SUPPORTING:
                host = record.endpoint
            elif isinstance(record, ProcessEventRecord) and record.verdict in _SUPPORTING:
                host = record.endpoint
            if host and _at_or_after(record, self.window_start):
                hosts.setdefault(host, {"ids": set(), "groups": set(), "tags": set(), "ip": None})["ids"].add(
                    record.record_id)
        return [{"hostname": host, "record_ids": _sorted_ids(entry["ids"]), "groups": sorted(entry["groups"]),
                 "tags": sorted(entry["tags"]), "ip": entry["ip"]}
                for host, entry in sorted(hosts.items()) if entry["ids"]]

    # ------------------------------------------------------------- domains --
    def _post_flood_traffic(self, domain: str) -> list[AnyRecord]:
        out: list[AnyRecord] = []
        for record in self.records:
            if isinstance(record, (DnsQueryRecord, NetworkConnectionRecord)) and record.domain and (
                    record.domain == domain or record.domain.endswith("." + domain)) \
                    and _at_or_after(record, self.window_start):
                out.append(record)
        return out

    def _flood_messages_with(self, domain: str) -> list[EmailMessageRecord]:
        return [m for m in self.flood if m.verdict in _SUPPORTING and (
            _sender_domain(m) == domain or domain in m.domains)]

    def malicious_domains(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for report in sorted(self.reports, key=lambda r: r.value):
            if report.type is not ObservableType.DOMAIN or report.verdict not in _SUPPORTING:
                continue
            domain = report.value
            vendors = [r for r in report.records if isinstance(r, EnrichmentRecord) and r.verdict in _SUPPORTING]
            messages = self._flood_messages_with(domain)
            traffic = self._post_flood_traffic(domain)
            if report.verdict is Verdict.SUSPICIOUS and not (messages or traffic):
                continue  # one vendor's word alone is not enough to block
            if not (self.qualifies or traffic):
                continue  # a spam or phishing storm is the phishing workflow's job
            ids = [r.record_id for r in (*vendors, *messages, *traffic)]
            if ids:
                out.append({"domain": domain, "verdict": report.verdict.value, "record_ids": _sorted_ids(ids),
                            "flood_messages": len(messages), "endpoint_events": len(traffic)})
        return out


# --------------------------------------------------------------------- hooks --
class MailBombingHooks(WorkflowHooks):
    """Flood facts and record-backed patterns for the ``mail-bombing`` rules."""

    def facts(self, view: RunView) -> Mapping[str, Any]:
        a = _Analysis(view)
        observed = a.observed()
        detector = a.detector_numbers()
        buried = [{"message_id": m.message_id, "record_id": m.record_id, "categories": list(a.buried[m.record_id]),
                   "verdict": m.verdict.value, "sender_domain": _sender_domain(m)}
                  for m in a.flood if a.buried[m.record_id]]
        kept_out = [b for b in buried if b["verdict"] != Verdict.MALICIOUS.value]
        flood_messages = [{"message_id": m.message_id, "record_ids": [m.record_id], "verdict": m.verdict.value,
                           "recipient": _lower(m.recipients)[0] if len(set(_lower(m.recipients))) == 1 else "",
                           "sender_domain": _sender_domain(m)} for m in a.quarantinable] if a.qualifies else []
        identity: list[dict[str, Any]] = []
        takeover: list[dict[str, Any]] = []
        for user in a.recipients:
            events = a.identity_records(user)
            notes = a.notification_records(user)
            asset = a.user_asset(user)
            if events or notes:
                kinds = sorted({str(r.kind) for r in events} | ({"buried_notification"} if notes else set()))
                identity.append({"user": user, "record_ids": _sorted_ids(r.record_id for r in (*events, *notes)),
                                 "kinds": kinds, **asset})
            cited, reasons = a.takeover_records(user)
            if cited:
                takeover.append({"user": user, "record_ids": _sorted_ids(r.record_id for r in cited),
                                 "reasons": reasons, **asset})
        summary = (f"flood window {_iso(a.window_start) or 'unknown'} to {_iso(a.window_end) or 'unknown'}; "
                   f"{a.reason}; {observed['messages']} message(s) observed to the recipient, "
                   f"{len(flood_messages)} proposed for quarantine, {len(kept_out)} buried message(s) of interest "
                   "kept out of the quarantine for the analyst")
        return {
            "recipients": a.recipients,
            "flood": {
                "detector": detector is not None,
                "detector_event": str(a.detector.get("event_type") or ""),
                "window_start": _iso(a.window_start),
                "window_end": _iso(a.window_end),
                "observed": observed,
                "detector_metrics": detector,
                "qualifies": a.qualifies,
                "reason": a.reason,
                "summary": summary,
            },
            "flood_messages": flood_messages,
            "buried_messages": buried,
            "identity_events": identity,
            "takeover": takeover,
            "endpoint_activity": a.endpoint_activity(),
            "malicious_domains": a.malicious_domains(),
        }

    def derive_signals(self, view: RunView) -> Sequence[ScoringSignal]:
        a = _Analysis(view)
        signals: list[ScoringSignal] = []
        if a.qualifies:
            flood_ids = sorted(m.record_id for m in a.flood)
            confidence = _FLOOD_CONFIDENCE if a.detector_numbers() is not None else _FLOOD_CONFIDENCE_OBSERVED_ONLY
            for message in a.quarantinable:
                others = [i for i in flood_ids if i != message.record_id][:_SIGNAL_CITATION_CAP]
                signals.append(ScoringSignal(
                    category=SignalCategory.CAMPAIGN_ASSOCIATION, integration=message.integration,
                    observable=Observable(type=ObservableType.EMAIL_MESSAGE_ID, value=message.message_id),
                    verdict=Verdict.SUSPICIOUS, severity=_FLOOD_SEVERITY, confidence=confidence,
                    record_ids=(message.record_id, *others), origin=ORIGIN,
                    note=f"message of a qualifying mail flood ({a.reason})"))
        for user in a.recipients:
            observable = Observable(type=ObservableType.USER, value=user)
            signals += self._by_integration(
                a.identity_records(user), observable, SignalCategory.AUTHENTICATION_ANOMALY,
                _IDENTITY_SEVERITY, _IDENTITY_CONFIDENCE, "identity event inside the mail flood window")
            signals += self._by_integration(
                a.notification_records(user), observable, SignalCategory.AUTHENTICATION_ANOMALY,
                _NOTIFICATION_SEVERITY, _NOTIFICATION_CONFIDENCE,
                "credential, security or MFA notification buried in the mail flood")
            cited, _ = a.takeover_records(user)
            signals += self._by_integration(
                cited, observable, SignalCategory.AUTHENTICATION_ANOMALY, _TAKEOVER_SEVERITY, _TAKEOVER_CONFIDENCE,
                "account takeover indication inside the mail flood window")
        return signals

    @staticmethod
    def _by_integration(records: Sequence[AnyRecord], observable: Observable, category: SignalCategory,
                        severity: int, confidence: int, note: str) -> list[ScoringSignal]:
        """One signal per source, citing only that source's records (attribution rule, 14.9.6)."""
        by_source: dict[str, list[str]] = {}
        for record in records:
            by_source.setdefault(record.integration, []).append(record.record_id)
        return [ScoringSignal(category=category, integration=integration, observable=observable,
                              verdict=Verdict.SUSPICIOUS, severity=severity, confidence=confidence,
                              record_ids=tuple(_sorted_ids(ids)), origin=ORIGIN, note=note)
                for integration, ids in sorted(by_source.items())]

    def considered(self, view: RunView) -> Sequence[Consideration]:
        """Buried messages of interest deliberately kept out of the flood quarantine."""
        a = _Analysis(view)
        if not a.qualifies:
            return []
        return [Consideration(subject=f"quarantine_email:{m.message_id}", record_ids=(m.record_id,),
                              reason=f"buried {', '.join(a.buried[m.record_id])} message ({m.verdict.value}) kept "
                                     "in the mailbox for the analyst to review")
                for m in a.flood if a.buried[m.record_id] and m.verdict is not Verdict.MALICIOUS]

    def handoffs(self, view: RunView) -> Sequence[Handoff]:
        """Takeover indications, endpoint activity after the flood, or a malicious storm that is not a bomb."""
        a = _Analysis(view)
        out: list[Handoff] = []
        for user in a.recipients:
            cited, reasons = a.takeover_records(user)
            if cited:
                out.append(Handoff(workflow_id="account-takeover", subjects=(user,),
                                   reason="account takeover indications inside the flood window ("
                                          + "; ".join(reasons) + "); review the account",
                                   record_ids=tuple(_sorted_ids(r.record_id for r in cited))))
        for host in a.endpoint_activity():
            out.append(Handoff(workflow_id="unauthorized-rmm", subjects=(host["hostname"],),
                               reason="malicious or suspicious endpoint activity after the flood (the fake help-desk "
                                      "follow-up pattern); check the endpoint for a remote access tool",
                               record_ids=tuple(host["record_ids"])))
        malicious = [m for m in a.flood if m.verdict is Verdict.MALICIOUS]
        if not a.qualifies and malicious:
            out.append(Handoff(workflow_id="phishing", subjects=tuple(a.recipients),
                               reason=f"not a subscription bomb ({a.reason}); {len(malicious)} malicious message(s) "
                                      "in the storm are phishing-workflow work",
                               record_ids=tuple(_sorted_ids(m.record_id for m in malicious))))
        return out


HOOKS = MailBombingHooks()
