"""Evidence builder (architecture section 14.1.6).

The only way the read zone produces :class:`EvidenceDraft` objects. Every draft is derived from a
normalized record that an atomic returned (and that therefore came from an integration), cited by
its ``record_id``; there is no API that takes free text, a score or an AI statement and turns it into
evidence. Derived statements (correlation, scores, thresholds) belong in the rationale, never here.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from xdr_response.atomics.records import (
    AnomalyRecord,
    CloudAppRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    GenericRecord,
    HashPrevalenceRecord,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RecordBase,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.logs.redaction import get_redactor
from xdr_response.models.canonical import canonical_json
from xdr_response.models.evidence import EvidenceDraft

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.records import AnyRecord, AtomicResult

__all__ = [
    "EvidenceError",
    "RecordIndex",
    "evidence_summary",
    "evidence_draft",
    "EvidenceBuilder",
    "SUMMARY_MAX_CHARS",
]

SUMMARY_MAX_CHARS = 300
_UNKNOWN = "unknown"
_HASH_LENGTHS = frozenset({32, 40, 64})
_HEX = frozenset("0123456789abcdefABCDEF")
_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)
_GENERIC_ATTRIBUTES = 3
_GENERIC_VALUE_CHARS = 60


class EvidenceError(ValueError):
    """Evidence would cite a record that does not exist, nothing at all, or a tampered draft."""


# --------------------------------------------------------------------------------------------- index


def _same_fact(existing: RecordBase, record: RecordBase) -> bool:
    """The same vendor fact returned by two atomics: equal content except the producing ``atomic``.

    The record id excludes the atomic (one fact, one id), so the second copy is the same record;
    the first copy is kept and the second atomic's other records are never discarded.
    """
    if type(existing) is not type(record) or existing.atomic == record.atomic:
        return False
    return existing.model_copy(update={"atomic": record.atomic}) == record


class RecordIndex:
    """All records of one run, by ``record_id``.

    The same id with different content, a non-record object, or an anomaly whose
    ``related_record_ids`` do not resolve inside the index raise :class:`EvidenceError`. The same
    fact seen by two atomics (content equal except ``atomic``) is one record: the first copy is kept.
    ``ids()`` keeps first-seen order (results in the given order, then ``records``).
    """

    def __init__(self, results: Iterable[AtomicResult] = (), *, records: Iterable[AnyRecord] = ()) -> None:
        self._records: dict[str, RecordBase] = {}
        for result in results:
            self._add_all(result.records)
        self._add_all(records)
        self._check_related()

    def _add_all(self, records: Iterable[Any]) -> None:
        for record in records:
            self._add(record)

    def _add(self, record: Any) -> None:
        if not isinstance(record, RecordBase):
            raise EvidenceError(f"only normalized records can be indexed, got {type(record).__name__}")
        existing = self._records.get(record.record_id)
        if existing is None:
            self._records[record.record_id] = record
        elif existing != record and not _same_fact(existing, record):
            raise EvidenceError(f"record id {record.record_id} is used by two records with different content")

    def _check_related(self) -> None:
        for record in self._records.values():
            if isinstance(record, AnomalyRecord):
                missing = [rid for rid in record.related_record_ids if rid not in self._records]
                if missing:
                    raise EvidenceError(f"anomaly {record.record_id} relates to unknown record ids {missing}")

    def get(self, record_id: str) -> AnyRecord:
        """The record with this id (``KeyError`` when unknown)."""
        return self._records[record_id]  # type: ignore[return-value]

    def require(self, record_ids: Iterable[str]) -> tuple[AnyRecord, ...]:
        """The records with these ids, in the given order; :class:`EvidenceError` names unknown ids."""
        ids = _id_list(record_ids)
        missing = [rid for rid in ids if rid not in self._records]
        if missing:
            raise EvidenceError(f"unknown record ids {missing}: evidence may only cite records of this run")
        return tuple(self._records[rid] for rid in ids)  # type: ignore[misc]

    def ids(self) -> tuple[str, ...]:
        return tuple(self._records)

    def records(self) -> tuple[AnyRecord, ...]:
        """Every record, in ``ids()`` order."""
        return tuple(self._records.values())  # type: ignore[arg-type]

    def __contains__(self, record_id: object) -> bool:
        return isinstance(record_id, str) and record_id in self._records

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        return f"RecordIndex({len(self._records)} records)"


def _id_list(record_ids: Iterable[str]) -> list[str]:
    """Validate an iterable of record ids (a bare string is a caller bug, not a list of characters)."""
    if isinstance(record_ids, (str, bytes)):
        raise EvidenceError("record ids must be given as a list, not a single string")
    ids = list(record_ids)
    bad = [rid for rid in ids if not isinstance(rid, str) or not rid]
    if bad:
        raise EvidenceError(f"record ids must be non-empty strings, got {bad!r}")
    return ids


# ------------------------------------------------------------------------------------------- summary


def _is_hash(value: str) -> bool:
    return len(value) in _HASH_LENGTHS and set(value) <= _HEX


def _fmt(value: Any) -> str:
    """Template value: ``unknown`` for ``None``, enum values, compact UTC times, shortened hashes."""
    if value is None:
        return _UNKNOWN
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value.value) if isinstance(value, Enum) else str(value)
    return text[:12] + "..." if _is_hash(text) else text


def _first(*values: Any) -> Any:
    """First value that is not ``None`` or empty (``None`` when all are)."""
    return next((v for v in values if v not in (None, "")), None)


def _enrichment(r: EnrichmentRecord) -> str:
    return (f"{r.integration} rates {_fmt(r.subject.value)} {_fmt(r.verdict)} "
            f"(risk {r.risk_score}, confidence {r.confidence})")


def _endpoint(r: EndpointRecord) -> str:
    return f"{r.integration}: endpoint {_fmt(r.hostname)} ({_fmt(r.os)}), isolation {_fmt(r.isolation_state)}"


def _detection(r: DetectionRecord) -> str:
    return (f"{r.integration}: {_fmt(r.severity)} detection '{_fmt(r.name)}' ({_fmt(r.verdict)}) "
            f"on {_fmt(r.endpoint)}")


def _process_event(r: ProcessEventRecord) -> str:
    return (f"{r.integration}: {_fmt(r.event_type)} {_fmt(r.process_name)} on {_fmt(r.endpoint)} "
            f"at {_fmt(r.timestamp)} (x{r.count})")


def _network_connection(r: NetworkConnectionRecord) -> str:
    return (f"{r.integration}: {_fmt(_first(r.endpoint, r.user))} {_fmt(r.direction)} to "
            f"{_fmt(_first(r.domain, r.remote_ip))}:{_fmt(r.remote_port)} ({_fmt(r.action)})")


def _dns_query(r: DnsQueryRecord) -> str:
    return (f"{r.integration}: {_fmt(_first(r.endpoint, r.client_ip))} queried {_fmt(r.domain)} "
            f"x{r.count} ({_fmt(r.action)})")


def _hash_prevalence(r: HashPrevalenceRecord) -> str:
    return f"{r.integration}: {_fmt(r.sha256)} seen on {r.prevalence} endpoint(s), {_fmt(r.verdict)}"


def _persistence_item(r: PersistenceItemRecord) -> str:
    return f"{r.integration}: {_fmt(r.mechanism)} '{_fmt(r.name)}' on {_fmt(r.endpoint)}"


def _user_profile(r: UserProfileRecord) -> str:
    return (f"{r.integration}: user {_fmt(r.user)}, risk {_fmt(r.risk_level)}, "
            f"enabled {_fmt(r.account_enabled)}, privileged {_fmt(r.privileged)}")


def _sign_in(r: SignInRecord) -> str:
    return (f"{r.integration}: sign-in {_fmt(r.result)} for {_fmt(r.user)} from {_fmt(r.ip)} "
            f"({_fmt(r.country)}) to {_fmt(r.app)} at {_fmt(r.timestamp)}, MFA {_fmt(r.mfa_result)}")


def _anomaly(r: AnomalyRecord) -> str:
    return (f"{r.integration}: {_fmt(r.anomaly_type)} ({_fmt(r.severity)}) "
            f"for {_fmt(_first(r.user, r.endpoint))}")


def _mfa_event(r: MfaEventRecord) -> str:
    return f"{r.integration}: MFA {_fmt(r.method)} {_fmt(r.result)} for {_fmt(r.user)} at {_fmt(r.timestamp)}"


def _mailbox_rule(r: MailboxRuleRecord) -> str:
    text = f"{r.integration}: mailbox rule '{_fmt(r.name)}' on {_fmt(r.mailbox)}"
    return text + ", forwards externally" if r.external_forwarding else text


def _role_change(r: RoleChangeRecord) -> str:
    return (f"{r.integration}: role {_fmt(r.role_name)} {_fmt(r.change)} for {_fmt(r.user)} "
            f"by {_fmt(r.actor)}")


def _email_message(r: EmailMessageRecord) -> str:
    return (f"{r.integration}: message {_fmt(r.message_id)} from {_fmt(r.sender)} to "
            f"{r.recipient_count} recipient(s), {_fmt(r.verdict)}, {_fmt(r.delivery_location)}")


def _cloud_app(r: CloudAppRecord) -> str:
    return (f"{r.integration}: app {_fmt(r.display_name)} ({_fmt(r.app_id)}), "
            f"consent {_fmt(r.consent_type)}, {len(r.permissions)} permission(s)")


def _attribute_value(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        text = canonical_json(value, allow_floats=True).decode("utf-8")
    else:
        text = _fmt(value)
    return text if len(text) <= _GENERIC_VALUE_CHARS else text[: _GENERIC_VALUE_CHARS - 3] + "..."


def _generic(r: GenericRecord) -> str:
    text = f"{r.integration}: {_fmt(r.name)}"
    keys = sorted(r.attributes)[:_GENERIC_ATTRIBUTES]
    if not keys:
        return text
    return text + " (" + ", ".join(f"{k}={_attribute_value(r.attributes[k])}" for k in keys) + ")"


_TEMPLATES: Mapping[type, Any] = {
    EnrichmentRecord: _enrichment,
    EndpointRecord: _endpoint,
    DetectionRecord: _detection,
    ProcessEventRecord: _process_event,
    NetworkConnectionRecord: _network_connection,
    DnsQueryRecord: _dns_query,
    HashPrevalenceRecord: _hash_prevalence,
    PersistenceItemRecord: _persistence_item,
    UserProfileRecord: _user_profile,
    SignInRecord: _sign_in,
    AnomalyRecord: _anomaly,
    MfaEventRecord: _mfa_event,
    MailboxRuleRecord: _mailbox_rule,
    RoleChangeRecord: _role_change,
    EmailMessageRecord: _email_message,
    CloudAppRecord: _cloud_app,
    GenericRecord: _generic,
}


def evidence_summary(record: AnyRecord) -> str:
    """Deterministic one-line summary of a record (template per kind), redacted, at most 300 chars."""
    template = _TEMPLATES.get(type(record))
    if template is None:
        raise EvidenceError(f"no evidence template for {type(record).__name__}")
    text = get_redactor().redact_text(template(record))
    return text if len(text) <= SUMMARY_MAX_CHARS else text[: SUMMARY_MAX_CHARS - 3] + "..."


def _json_fields(record: RecordBase) -> dict[str, Any]:
    """``record.evidence_fields()`` in JSON mode, so drafts compare equal after any round trip."""
    loaded: dict[str, Any] = json.loads(canonical_json(record.evidence_fields(), allow_floats=True))
    return loaded


def evidence_draft(record: AnyRecord) -> EvidenceDraft:
    """The one draft a record yields; ``data["record_id"]`` maps it back to the record."""
    if not isinstance(record, RecordBase):
        raise EvidenceError(f"evidence can only be built from a normalized record, got {type(record).__name__}")
    return EvidenceDraft(
        source=record.integration,
        summary=evidence_summary(record),
        observed_at=record.observed_at,
        reference=record.reference,
        data={"record_id": record.record_id, "kind": record.kind.value, "atomic": record.atomic,
              "fields": _json_fields(record)},
    )


# ------------------------------------------------------------------------------------------- builder


def _draft_dict(draft: EvidenceDraft) -> dict[str, Any]:
    """The ``EvidenceDraft`` fields of a draft or of numbered package ``Evidence``."""
    return draft.model_dump(mode="python", include=set(EvidenceDraft.model_fields))


class EvidenceBuilder:
    """Cites records of one :class:`RecordIndex` as evidence drafts, and checks drafts against it."""

    def __init__(self, index: RecordIndex) -> None:
        if not isinstance(index, RecordIndex):
            raise TypeError("EvidenceBuilder needs a RecordIndex")
        self._index = index

    @property
    def index(self) -> RecordIndex:
        return self._index

    def cite(self, record_ids: Iterable[str]) -> tuple[EvidenceDraft, ...]:
        """Drafts for these records: at least one id, all known, duplicates removed,
        ordered by ``(observed_at or min, record_id)``."""
        ids = list(dict.fromkeys(_id_list(record_ids)))
        if not ids:
            raise EvidenceError("evidence must cite at least one record")
        records = self._index.require(ids)
        ordered = sorted(records, key=lambda r: (r.observed_at or _MIN_DT, r.record_id))
        return tuple(evidence_draft(r) for r in ordered)

    def verify(self, drafts: Iterable[EvidenceDraft]) -> None:
        """Every draft (or numbered ``Evidence``) must equal ``evidence_draft`` of its record exactly."""
        for draft in drafts:
            if not isinstance(draft, EvidenceDraft):
                raise EvidenceError(f"not an evidence draft: {type(draft).__name__}")
            record_id = draft.data.get("record_id")
            if not isinstance(record_id, str) or record_id not in self._index:
                raise EvidenceError(f"evidence {draft.summary!r} does not cite a record of this run")
            expected = evidence_draft(self._index.get(record_id))
            if _draft_dict(draft) != _draft_dict(expected):
                raise EvidenceError(f"evidence for record {record_id} does not match the record")

    @staticmethod
    def record_ids(drafts: Iterable[EvidenceDraft]) -> tuple[str, ...]:
        """Cited record ids in draft order, duplicates removed; a draft without one raises."""
        ids: list[str] = []
        for draft in drafts:
            record_id = draft.data.get("record_id") if isinstance(draft, EvidenceDraft) else None
            if not isinstance(record_id, str) or not record_id:
                raise EvidenceError("evidence draft without a record_id")
            ids.append(record_id)
        return tuple(dict.fromkeys(ids))
