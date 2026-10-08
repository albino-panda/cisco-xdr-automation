"""Normalized investigation records (architecture section 14.1.2).

Every fact a read atomic learns is a typed, frozen **record** with a deterministic ``record_id``.
Evidence (14.1.6), scoring signals (14.2) and correlation links (14.1.5) refer to records by id
only. Records are created by the investigation normalizers, the enrichment atomics and, for legacy
replay, ``plan_bridge``; the framework never synthesizes a record from a computation.

This is a layer-0 model module: it imports only Phase 0 models, canonical helpers and the redactor.

Field rules applied by validators:

* free text (``command_line``, ``subject_line``, ``detail``, ``conditions``, ``failure_reason`` and
  ``GenericRecord.attributes``) is redacted and capped (1024 / 200 / 500 characters, 4 KiB);
* entity values are normalized for their kind (hostnames upper case, users and email addresses
  lower case, domains lower case without trailing dot, IPs compressed, hashes lower case);
* ``evidence_fields()`` (what evidence drafts copy) redacts every string on the way out (URL
  userinfo and secret query values, ``key=value`` secrets), so record URLs never carry signatures
  into package evidence;
* ``reference`` must not need redaction; ``integration`` must be a known integration name;
* ``record_id`` must equal :func:`make_record_id` over the record's natural key. It may be omitted
  when constructing a record, in which case it is computed (the result is identical).
"""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, ClassVar, Literal, Union

from pydantic import (
    AfterValidator,
    AwareDatetime,
    Field,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)

from xdr_response.logs.redaction import REDACTED, get_redactor
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionCategory,
    ActionType,
    CriticalAssetClass,
    EnrichmentResult,
    ErrorInfo,
    HealthStatus,
    InvestigationResult,
    Observable,
    ObservableType,
    Severity,
    TargetKind,
    Verdict,
    get_action_spec,
)
from xdr_response.models._base import FrozenModel, JsonDict, Score
from xdr_response.models.canonical import canonical_json, normalize_target, sha256_hex

__all__ = [
    "Level",
    "RecordKind",
    "make_record_id",
    "RecordBase",
    "EnrichmentRecord",
    "EndpointRecord",
    "DetectionRecord",
    "ProcessEventRecord",
    "NetworkConnectionRecord",
    "DnsQueryRecord",
    "HashPrevalenceRecord",
    "PersistenceItemRecord",
    "UserProfileRecord",
    "SignInRecord",
    "AnomalyRecord",
    "MfaEventRecord",
    "MailboxRuleRecord",
    "RoleChangeRecord",
    "EmailMessageRecord",
    "CloudAppRecord",
    "GenericRecord",
    "AnyRecord",
    "RECORD_TYPES",
    "PRIVILEGED_ROLE_NAMES",
    "SourceOutcome",
    "SourceStatus",
    "AtomicResult",
    "InvestigationBundle",
]

Level = Literal["none", "low", "medium", "high", "unknown"]


class RecordKind(StrEnum):
    ENRICHMENT = "enrichment"
    ENDPOINT = "endpoint"
    DETECTION = "detection"
    PROCESS_EVENT = "process_event"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    HASH_PREVALENCE = "hash_prevalence"
    PERSISTENCE_ITEM = "persistence_item"
    USER_PROFILE = "user_profile"
    SIGN_IN = "sign_in"
    ANOMALY = "anomaly"
    MFA_EVENT = "mfa_event"
    MAILBOX_RULE = "mailbox_rule"
    ROLE_CHANGE = "role_change"
    EMAIL_MESSAGE = "email_message"
    CLOUD_APP = "cloud_app"
    GENERIC = "generic"


#: Lower-case Entra directory role names treated as privileged.
PRIVILEGED_ROLE_NAMES: frozenset[str] = frozenset({
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
    "security administrator",
    "exchange administrator",
    "sharepoint administrator",
    "user administrator",
    "authentication administrator",
    "application administrator",
    "cloud application administrator",
    "conditional access administrator",
    "hybrid identity administrator",
    "intune administrator",
})

_AUTO_ID = "rec_auto"
_TRIAL_CONTEXT = "xdr_record_id_trial"
_ATTRIBUTES_MAX_BYTES = 4096
_RECIPIENTS_MAX = 100
_HASH_LENGTHS: Mapping[ObservableType, int] = MappingProxyType(
    {ObservableType.SHA256: 64, ObservableType.SHA1: 40, ObservableType.MD5: 32})
_HEX = frozenset("0123456789abcdef")
_DATETIME = TypeAdapter(AwareDatetime)


# --------------------------------------------------------------- record ids --
def make_record_id(integration: str, kind: RecordKind, subject: Observable,
                   natural_key: Mapping[str, object]) -> str:
    """Deterministic id: ``"rec_" + sha256_hex(canonical_json({...}, allow_floats=True))[:32]``."""
    payload = {"i": integration, "k": RecordKind(kind).value, "t": subject.type.value,
               "v": subject.value.strip().lower(), "n": dict(natural_key)}
    return "rec_" + sha256_hex(canonical_json(payload, allow_floats=True))[:32]


# ----------------------------------------------------- subject normalization --
def _normalize_hash(value: str, otype: ObservableType) -> str:
    v = value.strip().lower()
    expected = _HASH_LENGTHS[otype]
    if len(v) != expected or not set(v) <= _HEX:
        raise ValueError(f"invalid {otype.value} value: expected {expected} hexadecimal characters")
    return v


def _normalize_process(value: str) -> str:
    endpoint, sep, ident = value.strip().partition("/")
    if not sep or not endpoint.strip() or not ident.strip():
        raise ValueError("process subject must be '<ENDPOINT>/<sha256 or pid>'")
    return f"{endpoint.strip().upper()}/{ident.strip().lower()}"


def _normalize_ip(value: str, otype: ObservableType) -> str:
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"invalid {otype.value} value: {value!r}") from exc
    if otype is ObservableType.IPV6 and parsed.version != 6:
        raise ValueError(f"invalid ipv6 value: {value!r}")
    return parsed.compressed


def _normalize_domain(value: str) -> str:
    v = normalize_target(TargetKind.DOMAIN, value)
    if any(ch.isspace() for ch in v) or "/" in v or "@" in v:
        raise ValueError(f"invalid domain value: {value!r}")
    return v


def _normalize_email(value: str) -> str:
    v = normalize_target(TargetKind.EMAIL_ADDRESS, value)
    local, sep, domain = v.partition("@")
    if not sep or not local or not domain or any(ch.isspace() for ch in v):
        raise ValueError(f"invalid email address value: {value!r}")
    return v


_SUBJECT_NORMALIZERS: Mapping[ObservableType, Callable[[str], str]] = MappingProxyType({
    ObservableType.IP: lambda v: _normalize_ip(v, ObservableType.IP),
    ObservableType.IPV6: lambda v: _normalize_ip(v, ObservableType.IPV6),
    ObservableType.DOMAIN: _normalize_domain,
    ObservableType.URL: lambda v: v.strip(),
    ObservableType.SHA256: lambda v: _normalize_hash(v, ObservableType.SHA256),
    ObservableType.SHA1: lambda v: _normalize_hash(v, ObservableType.SHA1),
    ObservableType.MD5: lambda v: _normalize_hash(v, ObservableType.MD5),
    ObservableType.EMAIL_ADDRESS: _normalize_email,
    ObservableType.USER: lambda v: normalize_target(TargetKind.USER, v),
    ObservableType.HOSTNAME: lambda v: normalize_target(TargetKind.ENDPOINT, v),
    ObservableType.ENDPOINT_ID: lambda v: v.strip(),
    ObservableType.MAC_ADDRESS: lambda v: v.strip().lower(),
    ObservableType.EMAIL_MESSAGE_ID: lambda v: v.strip(),
    ObservableType.PROCESS: _normalize_process,
    ObservableType.FILE_PATH: lambda v: v.strip(),
})


def _normalize_observable(observable: Observable) -> Observable:
    """The observable with its value normalized for its type (``ValueError`` when unparseable)."""
    value = _SUBJECT_NORMALIZERS[observable.type](observable.value)
    if value == observable.value:
        return observable
    return observable.model_copy(update={"value": value})


# ------------------------------------------------------ field value helpers --
def _redact_cap(limit: int) -> AfterValidator:
    def check(value: str) -> str:
        return get_redactor().redact_text(value)[:limit]
    return AfterValidator(check)


def _entity(kind: TargetKind) -> AfterValidator:
    def check(value: str) -> str:
        return normalize_target(kind, value)
    return AfterValidator(check)


def _lower(value: str) -> str:
    v = value.strip().lower()
    if not v:
        raise ValueError("value must not be empty")
    return v


_Text = Annotated[str, _redact_cap(500)]
def _redact_command_line(value: str) -> str:
    return get_redactor().redact_command_line(value)[:1024]


_CommandLine = Annotated[str, AfterValidator(_redact_command_line)]
_SubjectLine = Annotated[str, _redact_cap(200)]
_Host = Annotated[str, _entity(TargetKind.ENDPOINT)]
_User = Annotated[str, _entity(TargetKind.USER)]
_Email = Annotated[str, _entity(TargetKind.EMAIL_ADDRESS)]
_Domain = Annotated[str, _entity(TargetKind.DOMAIN)]
_Ip = Annotated[str, _entity(TargetKind.IP)]
_Hash = Annotated[str, _entity(TargetKind.HASH)]
_Mac = Annotated[str, AfterValidator(_lower)]
_Count = Annotated[int, Field(ge=1)]
_NonNegative = Annotated[int, Field(ge=0)]
_Port = Annotated[int, Field(ge=0, le=65535)]


def _cap_attributes(value: Mapping[str, Any]) -> dict[str, Any]:
    """Redacted attributes, replaced by a truncated preview when larger than 4 KiB."""
    redacted = get_redactor().redact(dict(value))
    encoded = json.dumps(redacted, default=str, ensure_ascii=False, sort_keys=True)
    size = len(encoded.encode("utf-8"))
    if size <= _ATTRIBUTES_MAX_BYTES:
        return json.loads(encoded)
    preview = encoded.encode("utf-8")[: _ATTRIBUTES_MAX_BYTES - 256].decode("utf-8", errors="ignore")
    return {"_truncated": True, "_original_bytes": size, "preview": preview}


# ------------------------------------------------------------------- records --
def _expected_record_id(record: "RecordBase") -> str:
    """:func:`make_record_id` over a record's integration, kind, subject and natural key."""
    return make_record_id(record.integration, record.kind, record.subject, record.natural_key())


class RecordBase(FrozenModel):
    """Common fields of every record. Subclasses fix ``kind`` and define the natural key."""

    kind: RecordKind
    record_id: str
    integration: str
    atomic: str = Field(min_length=1)
    subject: Observable
    observed_at: AwareDatetime | None = None
    reference: str | None = None

    _NATURAL_KEY: ClassVar[tuple[str, ...]] = ()
    _EVIDENCE_FIELDS: ClassVar[tuple[str, ...]] = ()

    @model_validator(mode="before")
    @classmethod
    def _fill_record_id(cls, data: Any) -> Any:
        """Compute an omitted ``record_id`` from a trial validation of the same data."""
        if not isinstance(data, Mapping) or data.get("record_id") is not None:
            return data
        trial = cls.model_validate({**data, "record_id": _AUTO_ID}, context={_TRIAL_CONTEXT: True})
        return {**data, "record_id": _expected_record_id(trial)}

    @model_validator(mode="after")
    def _check_record_id(self, info: ValidationInfo) -> "RecordBase":
        if isinstance(info.context, Mapping) and info.context.get(_TRIAL_CONTEXT):
            return self
        expected = _expected_record_id(self)
        if self.record_id != expected:
            raise ValueError(f"record_id {self.record_id!r} does not match the record content "
                             f"(expected {expected!r})")
        return self


    @field_validator("integration")
    @classmethod
    def _known_integration(cls, value: str) -> str:
        if value not in INTEGRATION_NAMES:
            raise ValueError(f"record integration {value!r} must be one of INTEGRATION_NAMES")
        return value

    @field_validator("subject")
    @classmethod
    def _normalized_subject(cls, value: Observable) -> Observable:
        return _normalize_observable(value)

    @field_validator("reference")
    @classmethod
    def _clean_reference(cls, value: str | None) -> str | None:
        if value is not None and get_redactor().redact_text(value) != value:
            raise ValueError("reference must not contain secrets (redact it before building the record)")
        return value

    def natural_key(self) -> dict[str, object]:
        """The fields that identify this fact within its integration and subject (14.1.2 table)."""
        return _pick(self, self._NATURAL_KEY)

    def rule_item(self) -> dict[str, Any]:
        """``model_dump(mode="json")``: every field present (``None`` when unknown)."""
        return self.model_dump(mode="json")

    def evidence_fields(self) -> dict[str, Any]:
        """The fields copied into ``EvidenceDraft.data["fields"]`` (14.1.2 table), JSON-ready.

        Every string value is redacted on the way out (URL userinfo and sensitive query values
        such as ``sig=`` / ``access_token=``, ``key=value`` secrets, bearer credentials), so a signed
        URL seen in telemetry never travels into package evidence with its signature.
        """
        dumped = self.model_dump(mode="json", include=set(self._EVIDENCE_FIELDS))
        return {name: _redact_evidence_value(dumped[name]) for name in self._EVIDENCE_FIELDS}


def _redact_evidence_value(value: Any) -> Any:
    """A JSON value with every string redacted (URLs by ``redact_url``) and sensitive keys masked."""
    redactor = get_redactor()
    if isinstance(value, str):
        if "://" in value and not any(ch.isspace() for ch in value.strip()):
            return redactor.redact_url(value)
        return redactor.redact_text(value)
    if isinstance(value, Mapping):
        return {k: (REDACTED if isinstance(k, str) and redactor.is_sensitive_key(k) and v is not None
                    else _redact_evidence_value(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_evidence_value(v) for v in value]
    return value


def _pick(record: RecordBase, names: tuple[str, ...]) -> dict[str, object]:
    """``{name: value}`` for ``names`` (python values, in the given order)."""
    dumped = record.model_dump(mode="python", include=set(names))
    return {name: dumped[name] for name in names}


def _id_or(record: RecordBase, id_field: str, fallback: tuple[str, ...]) -> dict[str, object]:
    """``{"id": <id>}`` when the source gave an id, else the fallback fields."""
    value = _pick(record, (id_field,))[id_field]
    if value:
        return {"id": value}
    return _pick(record, fallback)


class EnrichmentRecord(RecordBase):
    """One source's answer about one observable (from an ``EnrichmentResult``)."""

    kind: Literal[RecordKind.ENRICHMENT] = RecordKind.ENRICHMENT
    verdict: Verdict
    risk_score: Score
    confidence: Score
    categories: tuple[str, ...] = ()
    first_seen: AwareDatetime | None = None
    detail: _Text = ""

    _EVIDENCE_FIELDS = ("verdict", "risk_score", "confidence", "categories")


class EndpointRecord(RecordBase):
    kind: Literal[RecordKind.ENDPOINT] = RecordKind.ENDPOINT
    hostname: _Host
    connector_guid: str | None = None
    mde_machine_id: str | None = None
    intune_device_id: str | None = None
    os: str | None = None
    ip_addresses: tuple[_Ip, ...] = ()
    mac_addresses: tuple[_Mac, ...] = ()
    users: tuple[_User, ...] = ()
    groups: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    isolation_capable: bool | None = None
    isolation_state: Literal["isolated", "not_isolated", "pending", "unknown"] = "unknown"
    health_state: str | None = None
    risk_level: Level = "unknown"
    last_seen: AwareDatetime | None = None

    _EVIDENCE_FIELDS = ("hostname", "os", "isolation_state", "groups", "tags")

    def natural_key(self) -> dict[str, object]:
        return {"hostname": self.hostname,
                "id": self.connector_guid or self.mde_machine_id or self.intune_device_id}


class DetectionRecord(RecordBase):
    kind: Literal[RecordKind.DETECTION] = RecordKind.DETECTION
    detection_id: str | None = None
    name: str = Field(min_length=1)
    verdict: Verdict
    severity: Severity
    category: str | None = None
    endpoint: _Host | None = None
    user: _User | None = None
    sha256: _Hash | None = None
    file_path: str | None = None
    process_name: str | None = None
    mitre_techniques: tuple[str, ...] = ()
    status: Literal["active", "resolved", "unknown"] = "unknown"
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

    _EVIDENCE_FIELDS = ("name", "verdict", "severity", "category", "endpoint", "user", "sha256",
                        "mitre_techniques")

    def natural_key(self) -> dict[str, object]:
        return _id_or(self, "detection_id", ("name", "endpoint", "sha256", "first_seen"))


class ProcessEventRecord(RecordBase):
    """Trajectory / device timeline entry. ``command_line`` is data only, never executed."""

    kind: Literal[RecordKind.PROCESS_EVENT] = RecordKind.PROCESS_EVENT
    event_id: str | None = None
    endpoint: _Host
    timestamp: AwareDatetime
    event_type: Literal["process_start", "process_end", "file_create", "file_modify", "file_execute",
                        "file_delete", "file_rename", "network", "registry", "module_load", "service",
                        "scheduled_task", "other"]
    process_name: str | None = None
    pid: _NonNegative | None = None
    sha256: _Hash | None = None
    parent_process_name: str | None = None
    parent_pid: _NonNegative | None = None
    parent_sha256: _Hash | None = None
    file_path: str | None = None
    command_line: _CommandLine | None = None
    user: _User | None = None
    verdict: Verdict = Verdict.UNKNOWN
    remote_ip: _Ip | None = None
    remote_port: _Port | None = None
    domain: _Domain | None = None
    count: _Count = 1

    _EVIDENCE_FIELDS = ("endpoint", "timestamp", "event_type", "process_name", "parent_process_name",
                        "sha256", "command_line", "verdict", "count")

    def natural_key(self) -> dict[str, object]:
        return _id_or(self, "event_id", ("endpoint", "timestamp", "event_type", "pid", "sha256"))


class NetworkConnectionRecord(RecordBase):
    kind: Literal[RecordKind.NETWORK_CONNECTION] = RecordKind.NETWORK_CONNECTION
    endpoint: _Host | None = None
    user: _User | None = None
    local_ip: _Ip | None = None
    remote_ip: _Ip | None = None
    remote_port: _Port | None = None
    protocol: Literal["tcp", "udp", "icmp", "other", "unknown"] = "unknown"
    direction: Literal["outbound", "inbound", "internal", "unknown"] = "unknown"
    domain: _Domain | None = None
    url: str | None = None
    process_name: str | None = None
    pid: _NonNegative | None = None  # process that owns the connection, when the source reports it (14.11.3)
    sha256: _Hash | None = None
    bytes_out: _NonNegative | None = None
    bytes_in: _NonNegative | None = None
    count: _Count = 1
    action: Literal["allowed", "blocked", "unknown"] = "unknown"
    verdict: Verdict = Verdict.UNKNOWN
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

    _NATURAL_KEY = ("endpoint", "remote_ip", "remote_port", "domain", "first_seen")
    _EVIDENCE_FIELDS = ("endpoint", "user", "remote_ip", "remote_port", "domain", "url", "direction",
                        "action", "verdict", "bytes_out", "count")


class DnsQueryRecord(RecordBase):
    kind: Literal[RecordKind.DNS_QUERY] = RecordKind.DNS_QUERY
    endpoint: _Host | None = None
    client_ip: _Ip | None = None
    domain: _Domain
    query_type: str | None = None
    response_ips: tuple[_Ip, ...] = ()
    count: _Count = 1
    unique_subdomains: _NonNegative | None = None
    max_label_length: _NonNegative | None = None
    categories: tuple[str, ...] = ()
    action: Literal["allowed", "blocked", "unknown"] = "unknown"
    verdict: Verdict = Verdict.UNKNOWN
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

    _NATURAL_KEY = ("endpoint", "client_ip", "domain", "query_type", "first_seen")
    _EVIDENCE_FIELDS = ("endpoint", "domain", "query_type", "count", "unique_subdomains", "action",
                        "verdict")


class HashPrevalenceRecord(RecordBase):
    """Enterprise prevalence of a file hash (legacy enrich-hash prevalence / hosts)."""

    kind: Literal[RecordKind.HASH_PREVALENCE] = RecordKind.HASH_PREVALENCE
    sha256: _Hash
    file_name: str | None = None
    verdict: Verdict = Verdict.UNKNOWN
    prevalence: _NonNegative
    endpoints: tuple[_Host, ...] = ()
    truncated: bool = False
    signer: str | None = None
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None

    _NATURAL_KEY = ("sha256",)
    _EVIDENCE_FIELDS = ("sha256", "file_name", "verdict", "prevalence", "endpoints")


class PersistenceItemRecord(RecordBase):
    kind: Literal[RecordKind.PERSISTENCE_ITEM] = RecordKind.PERSISTENCE_ITEM
    endpoint: _Host
    item_id: str = Field(min_length=1)
    mechanism: Literal["run_key", "scheduled_task", "service", "wmi_subscription", "startup_folder",
                       "launch_agent", "cron", "browser_extension", "other"]
    name: str
    path: str | None = None
    sha256: _Hash | None = None
    command_line: _CommandLine | None = None
    user: _User | None = None
    created_at: AwareDatetime | None = None
    verdict: Verdict = Verdict.UNKNOWN

    _NATURAL_KEY = ("endpoint", "item_id")
    _EVIDENCE_FIELDS = ("endpoint", "mechanism", "name", "path", "sha256", "command_line", "verdict")

    @property
    def target(self) -> str:
        """``PERSISTENCE_ITEM`` target value (13.3): ``"<ENDPOINT>/<item_id>"``."""
        return f"{self.endpoint}/{self.item_id}"


def _privileged_from_roles(data: Any, roles_key: str) -> Any:
    """Before-validator body: mark ``privileged`` when a role is in :data:`PRIVILEGED_ROLE_NAMES`."""
    if not isinstance(data, Mapping):
        return data
    raw = data.get(roles_key)
    roles = [raw] if isinstance(raw, str) else list(raw or ())
    if any(isinstance(r, str) and r.strip().lower() in PRIVILEGED_ROLE_NAMES for r in roles):
        return {**data, "privileged": True}
    return data


class UserProfileRecord(RecordBase):
    kind: Literal[RecordKind.USER_PROFILE] = RecordKind.USER_PROFILE
    user: _User
    object_id: str | None = None
    display_name: str | None = None
    department: str | None = None
    job_title: str | None = None
    manager: str | None = None
    groups: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    privileged: bool = False
    account_enabled: bool | None = None
    risk_level: Level = "unknown"
    risk_state: Literal["at_risk", "confirmed_compromised", "remediated", "dismissed", "none",
                        "unknown"] = "unknown"
    mfa_registered: bool | None = None
    last_sign_in: AwareDatetime | None = None
    sessions_valid_from: AwareDatetime | None = None

    _NATURAL_KEY = ("user",)
    _EVIDENCE_FIELDS = ("user", "risk_level", "risk_state", "account_enabled", "privileged", "roles")

    @model_validator(mode="before")
    @classmethod
    def _privileged_roles(cls, data: Any) -> Any:
        return _privileged_from_roles(data, "roles")


class SignInRecord(RecordBase):
    kind: Literal[RecordKind.SIGN_IN] = RecordKind.SIGN_IN
    sign_in_id: str | None = None
    user: _User
    timestamp: AwareDatetime
    ip: _Ip | None = None
    country: str | None = None
    city: str | None = None
    app: str | None = None
    client_app: str | None = None
    device_id: str | None = None
    device_compliant: bool | None = None
    result: Literal["success", "failure", "interrupted", "unknown"]
    failure_reason: _Text | None = None
    mfa_required: bool | None = None
    mfa_result: Literal["satisfied", "denied", "timeout", "not_required", "unknown"] = "unknown"
    conditional_access: Literal["success", "failure", "not_applied", "unknown"] = "unknown"
    risk_level: Level = "unknown"
    authentication_method: str | None = None

    _EVIDENCE_FIELDS = ("user", "timestamp", "ip", "country", "app", "result", "mfa_result", "risk_level")

    def natural_key(self) -> dict[str, object]:
        return _id_or(self, "sign_in_id", ("user", "timestamp", "ip"))


class AnomalyRecord(RecordBase):
    """A vendor risk detection (never a framework inference)."""

    kind: Literal[RecordKind.ANOMALY] = RecordKind.ANOMALY
    anomaly_id: str | None = None
    anomaly_type: Literal["impossible_travel", "unfamiliar_location", "new_device", "anonymous_ip",
                          "malicious_ip", "mfa_fatigue", "password_spray", "brute_force", "token_replay",
                          "atypical_volume", "leaked_credentials", "other"]
    severity: Severity
    user: _User | None = None
    endpoint: _Host | None = None
    ip: _Ip | None = None
    detail: _Text = ""
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    related_record_ids: tuple[str, ...] = ()

    _EVIDENCE_FIELDS = ("anomaly_type", "severity", "user", "endpoint", "ip", "detail")

    def natural_key(self) -> dict[str, object]:
        return _id_or(self, "anomaly_id", ("anomaly_type", "user", "endpoint", "first_seen"))


class MfaEventRecord(RecordBase):
    kind: Literal[RecordKind.MFA_EVENT] = RecordKind.MFA_EVENT
    user: _User
    timestamp: AwareDatetime
    method: Literal["push", "sms", "voice", "totp", "fido2", "windows_hello", "other", "unknown"] = "unknown"
    result: Literal["approved", "denied", "timeout", "fraud_reported", "unknown"]
    ip: _Ip | None = None
    country: str | None = None
    app: str | None = None
    device: str | None = None

    _NATURAL_KEY = ("user", "timestamp", "method")
    _EVIDENCE_FIELDS = ("user", "timestamp", "method", "result", "ip", "country")


class MailboxRuleRecord(RecordBase):
    kind: Literal[RecordKind.MAILBOX_RULE] = RecordKind.MAILBOX_RULE
    mailbox: _Email
    rule_id: str = Field(min_length=1)
    name: str
    enabled: bool | None = None
    forward_to: tuple[_Email, ...] = ()
    redirect_to: tuple[_Email, ...] = ()
    forward_as_attachment_to: tuple[_Email, ...] = ()
    move_to_folder: str | None = None
    delete: bool = False
    mark_as_read: bool = False
    external_forwarding: bool = False
    conditions: tuple[_Text, ...] = ()
    created_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    created_by: _User | None = None

    _NATURAL_KEY = ("mailbox", "rule_id")
    _EVIDENCE_FIELDS = ("mailbox", "name", "enabled", "forward_to", "redirect_to", "external_forwarding",
                        "delete")


class RoleChangeRecord(RecordBase):
    kind: Literal[RecordKind.ROLE_CHANGE] = RecordKind.ROLE_CHANGE
    user: _User
    role_name: str = Field(min_length=1)
    role_definition_id: str | None = None
    directory_scope_id: str | None = None
    change: Literal["assigned", "removed", "eligible_assigned", "activated", "unknown"]
    privileged: bool = False
    actor: _User | None = None
    timestamp: AwareDatetime | None = None

    _NATURAL_KEY = ("user", "role_name", "change", "timestamp")
    _EVIDENCE_FIELDS = ("user", "role_name", "change", "privileged", "actor", "timestamp")

    @model_validator(mode="before")
    @classmethod
    def _privileged_role(cls, data: Any) -> Any:
        return _privileged_from_roles(data, "role_name")

    @property
    def target(self) -> str | None:
        """``ROLE_ASSIGNMENT`` target ``"<user>/<role_definition_id>"``, or ``None`` without a role id."""
        return f"{self.user}/{self.role_definition_id}" if self.role_definition_id else None


class EmailMessageRecord(RecordBase):
    kind: Literal[RecordKind.EMAIL_MESSAGE] = RecordKind.EMAIL_MESSAGE
    message_id: str = Field(min_length=1)
    internet_message_id: str | None = None
    network_message_id: str | None = None
    sender: _Email | None = None
    sender_domain: _Domain | None = None
    recipients: tuple[_Email, ...] = ()
    recipient_count: _NonNegative = 0
    subject_line: _SubjectLine | None = None
    received_at: AwareDatetime | None = None
    direction: Literal["inbound", "outbound", "internal", "unknown"] = "unknown"
    verdict: Verdict = Verdict.UNKNOWN
    threat_types: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    domains: tuple[_Domain, ...] = ()
    attachment_hashes: tuple[_Hash, ...] = ()
    attachment_names: tuple[str, ...] = ()
    delivery_location: Literal["inbox", "junk", "quarantine", "deleted", "failed", "unknown"] = "unknown"
    campaign_id: str | None = None
    spf: Literal["pass", "fail", "none", "unknown"] = "unknown"
    dkim: Literal["pass", "fail", "none", "unknown"] = "unknown"
    dmarc: Literal["pass", "fail", "none", "unknown"] = "unknown"

    _NATURAL_KEY = ("message_id",)
    _EVIDENCE_FIELDS = ("message_id", "sender", "recipient_count", "verdict", "threat_types",
                        "delivery_location", "campaign_id")

    @model_validator(mode="before")
    @classmethod
    def _cap_recipients(cls, data: Any) -> Any:
        """Keep at most 100 recipients; ``recipient_count`` stays the true count."""
        if not isinstance(data, Mapping) or data.get("recipients") is None:
            return data
        recipients = list(data["recipients"])
        count = data.get("recipient_count") or 0
        true_count = max(count if isinstance(count, int) and not isinstance(count, bool) else 0,
                         len(recipients))
        return {**data, "recipients": recipients[:_RECIPIENTS_MAX], "recipient_count": true_count}


class CloudAppRecord(RecordBase):
    """OAuth application / service principal facts."""

    kind: Literal[RecordKind.CLOUD_APP] = RecordKind.CLOUD_APP
    app_id: str = Field(min_length=1)
    display_name: str | None = None
    publisher_verified: bool | None = None
    permissions: tuple[str, ...] = ()
    consent_type: Literal["admin", "user", "unknown"] = "unknown"
    consented_by: _User | None = None
    credential_added_at: AwareDatetime | None = None
    created_at: AwareDatetime | None = None
    verdict: Verdict = Verdict.UNKNOWN

    _NATURAL_KEY = ("app_id",)
    _EVIDENCE_FIELDS = ("app_id", "display_name", "consent_type", "permissions", "publisher_verified")


class GenericRecord(RecordBase):
    """A finding no normalizer understands, and legacy replay data. Citable, never a scoring signal."""

    kind: Literal[RecordKind.GENERIC] = RecordKind.GENERIC
    name: str = Field(min_length=1)
    attributes: JsonDict = {}

    _NATURAL_KEY = ("name", "attributes")
    _EVIDENCE_FIELDS = ("name", "attributes")

    @field_validator("attributes")
    @classmethod
    def _redacted_attributes(cls, value: JsonDict) -> JsonDict:
        return _cap_attributes(value)


AnyRecord = Annotated[
    Union[EnrichmentRecord, EndpointRecord, DetectionRecord, ProcessEventRecord, NetworkConnectionRecord,
          DnsQueryRecord, HashPrevalenceRecord, PersistenceItemRecord, UserProfileRecord, SignInRecord,
          AnomalyRecord, MfaEventRecord, MailboxRuleRecord, RoleChangeRecord, EmailMessageRecord,
          CloudAppRecord, GenericRecord],
    Field(discriminator="kind"),
]

RECORD_TYPES: Mapping[RecordKind, type[RecordBase]] = MappingProxyType({
    RecordKind.ENRICHMENT: EnrichmentRecord,
    RecordKind.ENDPOINT: EndpointRecord,
    RecordKind.DETECTION: DetectionRecord,
    RecordKind.PROCESS_EVENT: ProcessEventRecord,
    RecordKind.NETWORK_CONNECTION: NetworkConnectionRecord,
    RecordKind.DNS_QUERY: DnsQueryRecord,
    RecordKind.HASH_PREVALENCE: HashPrevalenceRecord,
    RecordKind.PERSISTENCE_ITEM: PersistenceItemRecord,
    RecordKind.USER_PROFILE: UserProfileRecord,
    RecordKind.SIGN_IN: SignInRecord,
    RecordKind.ANOMALY: AnomalyRecord,
    RecordKind.MFA_EVENT: MfaEventRecord,
    RecordKind.MAILBOX_RULE: MailboxRuleRecord,
    RecordKind.ROLE_CHANGE: RoleChangeRecord,
    RecordKind.EMAIL_MESSAGE: EmailMessageRecord,
    RecordKind.CLOUD_APP: CloudAppRecord,
    RecordKind.GENERIC: GenericRecord,
})


# ------------------------------------------------------------------- sources --
class SourceOutcome(StrEnum):
    ANSWERED = "answered"
    EMPTY = "empty"
    FAILED = "failed"
    NOT_QUERIED = "not_queried"
    NOT_SUPPORTED = "not_supported"


class SourceStatus(FrozenModel):
    """What one integration contributed to a read atomic."""

    integration: str
    outcome: SourceOutcome
    health: HealthStatus
    reason: str = ""
    error: ErrorInfo | None = None
    records: _NonNegative = 0

    @field_validator("integration")
    @classmethod
    def _known_integration(cls, value: str) -> str:
        if value not in INTEGRATION_NAMES:
            raise ValueError(f"source integration {value!r} must be one of INTEGRATION_NAMES")
        return value


# ------------------------------------------------------------ atomic results --
_READ_CATEGORIES = frozenset({ActionCategory.ENRICHMENT, ActionCategory.INVESTIGATION})


class AtomicResult(FrozenModel):
    """Base of every read-atomic result: records plus one source status per integration considered."""

    atomic: str = Field(min_length=1)
    action_type: ActionType
    subject: Observable
    records: tuple[AnyRecord, ...] = ()
    sources: tuple[SourceStatus, ...] = ()
    raw: tuple[EnrichmentResult | InvestigationResult, ...] = Field(default=(), repr=False)
    started_at: AwareDatetime
    finished_at: AwareDatetime

    @field_validator("subject")
    @classmethod
    def _normalized_subject(cls, value: Observable) -> Observable:
        return _normalize_observable(value)

    @model_validator(mode="after")
    def _consistent(self) -> "AtomicResult":
        if get_action_spec(self.action_type).category not in _READ_CATEGORIES:
            raise ValueError("an atomic result needs an ENRICHMENT or INVESTIGATION action type")
        ids = [r.record_id for r in self.records]
        if len(ids) != len(set(ids)):
            raise ValueError("record ids must be unique within an atomic result")
        foreign = sorted({r.atomic for r in self.records if r.atomic != self.atomic})
        if foreign:
            raise ValueError(f"records produced by another atomic: {foreign}")
        names = [s.integration for s in self.sources]
        if len(names) != len(set(names)):
            raise ValueError("one source status per integration")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not be before started_at")
        return self

    @property
    def degraded(self) -> bool:
        """True when any source FAILED."""
        return any(s.outcome is SourceOutcome.FAILED for s in self.sources)

    @property
    def answered(self) -> tuple[str, ...]:
        return tuple(s.integration for s in self.sources if s.outcome is SourceOutcome.ANSWERED)

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(s.integration for s in self.sources if s.outcome is SourceOutcome.FAILED)

    def of(self, kind: RecordKind) -> tuple[AnyRecord, ...]:
        """Records of one kind, in result order."""
        k = RecordKind(kind)
        return tuple(r for r in self.records if r.kind is k)

    def record_ids(self) -> tuple[str, ...]:
        return tuple(r.record_id for r in self.records)

    def rule_item(self) -> dict[str, Any]:
        """The common keys of every read-atomic item (14.1.4); subclasses add their own."""
        return {
            "atomic": self.atomic,
            "subject_type": self.subject.type.value,
            "subject": self.subject.value,
            "record_ids": list(self.record_ids()),
            "sources": list(self.answered),
            "failed_sources": list(self.failed),
            "degraded": self.degraded,
        }


class InvestigationBundle(AtomicResult):
    """Result of every ``investigate_*`` and ``search_*`` atomic.

    ``critical_asset_classes`` is filled by the atomic from ``ctx.critical_assets.classify`` with an
    asset built from the bundle's own records. It only informs rules and the decision card; it never
    causes a skip and never chooses an approval level (``PackageBuilder`` does).
    """

    critical_asset_classes: tuple[CriticalAssetClass, ...] = ()

    def rule_item(self) -> dict[str, Any]:
        """Common keys plus the keys of the atomic's family (14.1.4 table); every key always present."""
        item = super().rule_item()
        builder = _RULE_ITEM_BUILDERS.get(self.action_type)
        if builder is not None:
            item.update(builder(self))
        return item


# --------------------------------------------------------- rule-item helpers --
_VERDICT_RANK: Mapping[Verdict, int] = MappingProxyType(
    {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3})


def _items(records: Iterable[RecordBase]) -> list[dict[str, Any]]:
    return [r.rule_item() for r in records]


def _distinct(values: Iterable[str | None]) -> list[str]:
    """Distinct non-empty values, first-seen order."""
    out: list[str] = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def _first(values: Iterable[Any]) -> Any:
    return next((v for v in values if v is not None), None)


def _dt_json(value: datetime | None) -> str | None:
    return None if value is None else _DATETIME.dump_python(value, mode="json")


def _by_time(records: Iterable[ProcessEventRecord]) -> list[ProcessEventRecord]:
    return sorted(records, key=lambda r: (r.timestamp, r.record_id))


def _critical(bundle: InvestigationBundle) -> dict[str, Any]:
    classes = [c.value for c in bundle.critical_asset_classes]
    return {"is_critical_asset": bool(classes), "critical_asset_classes": classes}


def _endpoint_item(b: InvestigationBundle) -> dict[str, Any]:
    endpoints: tuple[EndpointRecord, ...] = b.of(RecordKind.ENDPOINT)  # type: ignore[assignment]
    first = endpoints[0] if endpoints else None
    subject_host = b.subject.value if b.subject.type is ObservableType.HOSTNAME else None
    return {
        "hostname": first.hostname if first else subject_host,
        "endpoint": first.rule_item() if first else None,
        "endpoints": _items(endpoints),
        "connector_guid": _first(e.connector_guid for e in endpoints),
        "mde_machine_id": _first(e.mde_machine_id for e in endpoints),
        "intune_device_id": _first(e.intune_device_id for e in endpoints),
        "ip_addresses": _distinct(ip for e in endpoints for ip in e.ip_addresses),
        "users": _distinct(u for e in endpoints for u in e.users),
        "groups": _distinct(g for e in endpoints for g in e.groups),
        "tags": _distinct(t for e in endpoints for t in e.tags),
        "isolation_capable": _first(e.isolation_capable for e in endpoints),
        "isolation_state": _first(e.isolation_state for e in endpoints if e.isolation_state != "unknown")
        or "unknown",
        "detections": _items(b.of(RecordKind.DETECTION)),
        "trajectory": _items(_by_time(b.of(RecordKind.PROCESS_EVENT))),  # type: ignore[arg-type]
        "network_connections": _items(b.of(RecordKind.NETWORK_CONNECTION)),
        "dns_queries": _items(b.of(RecordKind.DNS_QUERY)),
        "persistence": _items(b.of(RecordKind.PERSISTENCE_ITEM)),
        **_critical(b),
    }


def _user_item(b: InvestigationBundle) -> dict[str, Any]:
    profiles: tuple[UserProfileRecord, ...] = b.of(RecordKind.USER_PROFILE)  # type: ignore[assignment]
    first = profiles[0] if profiles else None
    subject_user = b.subject.value if b.subject.type in (ObservableType.USER, ObservableType.EMAIL_ADDRESS) \
        else None
    return {
        "user": first.user if first else subject_user,
        "profile": first.rule_item() if first else None,
        "users": _items(profiles),
        "risk_level": first.risk_level if first else None,
        "risk_state": first.risk_state if first else None,
        "is_privileged": any(p.privileged for p in profiles) if profiles else None,
        "account_enabled": first.account_enabled if first else None,
        "signins": _items(b.of(RecordKind.SIGN_IN)),
        "anomalies": _items(b.of(RecordKind.ANOMALY)),
        "mfa_events": _items(b.of(RecordKind.MFA_EVENT)),
        "mailbox_rules": _items(b.of(RecordKind.MAILBOX_RULE)),
        "role_changes": _items(b.of(RecordKind.ROLE_CHANGE)),
        "cloud_apps": _items(b.of(RecordKind.CLOUD_APP)),
        **_critical(b),
    }


def _authentication_item(b: InvestigationBundle) -> dict[str, Any]:
    signins: tuple[SignInRecord, ...] = b.of(RecordKind.SIGN_IN)  # type: ignore[assignment]
    mfa: tuple[MfaEventRecord, ...] = b.of(RecordKind.MFA_EVENT)  # type: ignore[assignment]
    located = [*signins, *mfa]
    return {
        "user": b.subject.value,
        "signins": _items(signins),
        "mfa_events": _items(mfa),
        "anomalies": _items(b.of(RecordKind.ANOMALY)),
        "success_count": sum(1 for s in signins if s.result == "success"),
        "failure_count": sum(1 for s in signins if s.result == "failure"),
        "mfa_denied_count": sum(1 for m in mfa if m.result in ("denied", "fraud_reported")),
        "mfa_approved_count": sum(1 for m in mfa if m.result == "approved"),
        "distinct_ips": len(_distinct(r.ip for r in located)),
        "distinct_countries": len(_distinct(r.country for r in located)),
    }


def _activity_hosts_users(b: InvestigationBundle) -> tuple[list[str], list[str]]:
    net: tuple[NetworkConnectionRecord, ...] = b.of(RecordKind.NETWORK_CONNECTION)  # type: ignore[assignment]
    dns: tuple[DnsQueryRecord, ...] = b.of(RecordKind.DNS_QUERY)  # type: ignore[assignment]
    hosts = _distinct([*(n.endpoint for n in net), *(d.endpoint for d in dns),
                       *(e.hostname for e in b.of(RecordKind.ENDPOINT))])  # type: ignore[union-attr]
    users = _distinct([*(n.user for n in net), *(s.user for s in b.of(RecordKind.SIGN_IN))])  # type: ignore[union-attr]
    return sorted(hosts), sorted(users)


def _ip_item(b: InvestigationBundle) -> dict[str, Any]:
    hosts, users = _activity_hosts_users(b)
    return {
        "ip": b.subject.value,
        "network_connections": _items(b.of(RecordKind.NETWORK_CONNECTION)),
        "dns_queries": _items(b.of(RecordKind.DNS_QUERY)),
        "signins": _items(b.of(RecordKind.SIGN_IN)),
        "endpoints": hosts,
        "users": users,
    }


def _domain_item(b: InvestigationBundle) -> dict[str, Any]:
    hosts, users = _activity_hosts_users(b)
    dns: tuple[DnsQueryRecord, ...] = b.of(RecordKind.DNS_QUERY)  # type: ignore[assignment]
    net: tuple[NetworkConnectionRecord, ...] = b.of(RecordKind.NETWORK_CONNECTION)  # type: ignore[assignment]
    seen = [r.first_seen for r in (*dns, *net) if r.first_seen is not None]
    return {
        "domain": b.subject.value,
        "dns_queries": _items(dns),
        "network_connections": _items(net),
        "endpoints": hosts,
        "users": users,
        "query_count": sum(d.count for d in dns),
        "first_seen": _dt_json(min(seen)) if seen else None,
    }


def _hash_item(b: InvestigationBundle) -> dict[str, Any]:
    prevalence: tuple[HashPrevalenceRecord, ...] = b.of(RecordKind.HASH_PREVALENCE)  # type: ignore[assignment]
    detections: tuple[DetectionRecord, ...] = b.of(RecordKind.DETECTION)  # type: ignore[assignment]
    events: tuple[ProcessEventRecord, ...] = b.of(RecordKind.PROCESS_EVENT)  # type: ignore[assignment]
    subject_sha = b.subject.value if b.subject.type is ObservableType.SHA256 else None
    sha256 = subject_sha or _first([*(p.sha256 for p in prevalence), *(d.sha256 for d in detections)])
    verdicts = [r.verdict for r in (*prevalence, *detections, *events)]
    worst = max(verdicts, key=lambda v: _VERDICT_RANK[v]) if verdicts else None
    hosts = _distinct([*(h for p in prevalence for h in p.endpoints), *(d.endpoint for d in detections),
                       *(e.endpoint for e in events)])
    names = _distinct([*(p.file_name for p in prevalence),
                       *(e.process_name for e in events if sha256 and e.sha256 == sha256),
                       *(d.process_name for d in detections if sha256 and d.sha256 == sha256)])
    return {
        "sha256": sha256,
        "prevalence": max((p.prevalence for p in prevalence), default=None),
        "endpoints": sorted(hosts),
        "verdict": worst.value if worst is not None else None,
        "detections": _items(detections),
        "process_events": _items(_by_time(events)),
        "file_names": sorted(names),
    }


def _email_item(b: InvestigationBundle) -> dict[str, Any]:
    messages: tuple[EmailMessageRecord, ...] = b.of(RecordKind.EMAIL_MESSAGE)  # type: ignore[assignment]
    return {
        "message_id": b.subject.value,
        "messages": _items(messages),
        "recipients": sorted(_distinct(r for m in messages for r in m.recipients)),
        "senders": sorted(_distinct(m.sender for m in messages)),
        "urls": sorted(_distinct(u for m in messages for u in m.urls)),
        "domains": sorted(_distinct(d for m in messages for d in m.domains)),
        "attachment_hashes": sorted(_distinct(h for m in messages for h in m.attachment_hashes)),
        "campaign_ids": sorted(_distinct(m.campaign_id for m in messages)),
        "delivered_count": sum(1 for m in messages if m.delivery_location in ("inbox", "junk")),
    }


def _process_item(b: InvestigationBundle) -> dict[str, Any]:
    endpoint, _, ident = b.subject.value.partition("/")
    events = _by_time(b.of(RecordKind.PROCESS_EVENT))  # type: ignore[arg-type]
    pid = int(ident) if ident.isdigit() else None
    sha = None if pid is not None else ident

    def is_child(e: ProcessEventRecord) -> bool:
        return (pid is not None and e.parent_pid == pid) or (sha is not None and e.parent_sha256 == sha)

    return {
        "process": b.subject.value,
        "endpoint": endpoint or None,
        "events": _items(events),
        "network_connections": _items(b.of(RecordKind.NETWORK_CONNECTION)),
        "children": _items(e for e in events if is_child(e)),
    }


_A = ActionType
_RULE_ITEM_BUILDERS: Mapping[ActionType, Callable[[InvestigationBundle], dict[str, Any]]] = MappingProxyType({
    _A.INVESTIGATE_ENDPOINT: _endpoint_item,
    _A.SEARCH_RELATED_ENDPOINTS: _endpoint_item,
    _A.INVESTIGATE_USER: _user_item,
    _A.SEARCH_RELATED_USERS: _user_item,
    _A.SEARCH_USER_ACTIVITY: _user_item,
    _A.INVESTIGATE_AUTHENTICATION: _authentication_item,
    _A.INVESTIGATE_IP: _ip_item,
    _A.INVESTIGATE_NETWORK_CONNECTION: _ip_item,
    _A.SEARCH_IP_ENTERPRISE: _ip_item,
    _A.INVESTIGATE_DOMAIN: _domain_item,
    _A.SEARCH_DOMAIN_ENTERPRISE: _domain_item,
    _A.INVESTIGATE_HASH: _hash_item,
    _A.SEARCH_HASH_ENTERPRISE: _hash_item,
    _A.INVESTIGATE_EMAIL: _email_item,
    _A.SEARCH_EMAIL_CAMPAIGN: _email_item,
    _A.INVESTIGATE_PROCESS: _process_item,
})
