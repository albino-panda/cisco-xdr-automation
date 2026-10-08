"""Investigation and enterprise search atomics (architecture 14.1.4).

Every atomic is a read: it asks each enabled integration that serves its INVESTIGATION action type
(through the read-only facade ``ctx.adapters``), normalizes the findings into typed records and
returns an :class:`InvestigationBundle`. Atomics never call a state-changing method, never build a
token or an action package, never enter a guard context and never write audit records.

Read atomics never raise because of a source: an exception or a result carrying ``errors`` becomes
a ``FAILED`` :class:`SourceStatus` and the other sources still answer, so a degraded source never
blocks a recommendation backed by other evidence. They raise ``ValueError`` only for invalid caller
input (an unparseable or wrong-typed subject, an unknown integration name, a bad limit).

Signature of every atomic::

    (ctx: AtomicContext, subject: str | Observable, *, options: Mapping[str, Any] | None = None,
     integrations: Sequence[str] = (), limit: int = 100) -> InvestigationBundle
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from xdr_response.atomics.investigation.normalize import NormalizeContext, normalize
from xdr_response.atomics.records import (
    AnyRecord,
    EndpointRecord,
    InvestigationBundle,
    SourceOutcome,
    SourceStatus,
    UserProfileRecord,
    _normalize_observable,
)
from xdr_response.errors import IntegrationError
from xdr_response.integrations.health import classify_exception
from xdr_response.logs.redaction import get_redactor
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionCategory,
    ActionType,
    Asset,
    CriticalAssetClass,
    ErrorCode,
    ErrorInfo,
    HealthStatus,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    TargetKind,
    get_action_spec,
)

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.context import AtomicContext

__all__ = [
    "InvestigationAtomic",
    "investigate_user",
    "investigate_endpoint",
    "investigate_ip",
    "investigate_domain",
    "investigate_hash",
    "investigate_email",
    "investigate_authentication",
    "investigate_process",
    "investigate_network_connection",
    "search_hash_enterprise",
    "search_domain_enterprise",
    "search_ip_enterprise",
    "search_user_activity",
    "search_email_campaign",
    "search_related_endpoints",
    "search_related_users",
    "INVESTIGATION_ATOMICS",
    "INVESTIGATION_SUBJECT_TYPES",
]

InvestigationAtomic = Callable[..., InvestigationBundle]

_O = ObservableType
_A = ActionType
_USERS = frozenset({_O.USER})
_HOSTS = frozenset({_O.HOSTNAME, _O.ENDPOINT_ID})
_IPS = frozenset({_O.IP, _O.IPV6})
_HASHES = frozenset({_O.SHA256, _O.SHA1, _O.MD5})
_MESSAGES = frozenset({_O.EMAIL_MESSAGE_ID})
_DOMAINS = frozenset({_O.DOMAIN})

INVESTIGATION_SUBJECT_TYPES: Mapping[str, frozenset[ObservableType]] = MappingProxyType({
    _A.INVESTIGATE_USER.value: frozenset({_O.USER, _O.EMAIL_ADDRESS}),
    _A.INVESTIGATE_ENDPOINT.value: _HOSTS,
    _A.INVESTIGATE_IP.value: _IPS,
    _A.INVESTIGATE_DOMAIN.value: _DOMAINS,
    _A.INVESTIGATE_HASH.value: _HASHES,
    _A.INVESTIGATE_EMAIL.value: _MESSAGES,
    _A.INVESTIGATE_AUTHENTICATION.value: _USERS,
    _A.INVESTIGATE_PROCESS.value: frozenset({_O.PROCESS}),
    _A.INVESTIGATE_NETWORK_CONNECTION.value: _IPS,
    _A.SEARCH_HASH_ENTERPRISE.value: _HASHES,
    _A.SEARCH_DOMAIN_ENTERPRISE.value: _DOMAINS,
    _A.SEARCH_IP_ENTERPRISE.value: _IPS,
    _A.SEARCH_USER_ACTIVITY.value: _USERS,
    _A.SEARCH_EMAIL_CAMPAIGN.value: _MESSAGES,
    _A.SEARCH_RELATED_ENDPOINTS.value: _HOSTS,
    _A.SEARCH_RELATED_USERS.value: _USERS,
})

_HASH_TYPES_BY_LENGTH: Mapping[int, ObservableType] = MappingProxyType({64: _O.SHA256, 40: _O.SHA1, 32: _O.MD5})
_ENDPOINT_FAMILY = frozenset({_A.INVESTIGATE_ENDPOINT, _A.SEARCH_RELATED_ENDPOINTS})
_USER_FAMILY = frozenset({_A.INVESTIGATE_USER, _A.SEARCH_RELATED_USERS, _A.SEARCH_USER_ACTIVITY})
_MAX_LIMIT = 10000
_ERROR_CHARS = 500


# ------------------------------------------------------------------ subject --
def _default_type(allowed: frozenset[ObservableType], value: str) -> ObservableType:
    """Observable type for a plain string subject."""
    if allowed == _IPS:
        try:
            return _O.IPV6 if ipaddress.ip_address(value.strip()).version == 6 else _O.IP
        except ValueError as exc:
            raise ValueError(f"invalid IP subject: {value!r}") from exc
    if allowed == _HASHES:
        found = _HASH_TYPES_BY_LENGTH.get(len(value.strip()))
        if found is None:
            raise ValueError("hash subject must be 32 (md5), 40 (sha1) or 64 (sha256) hexadecimal characters")
        return found
    for preferred in (_O.USER, _O.HOSTNAME):
        if preferred in allowed:
            return preferred
    (only,) = tuple(allowed)
    return only


def _subject(atomic: str, subject: str | Observable) -> Observable:
    """The normalized subject observable (``ValueError`` for wrong type or unparseable value)."""
    allowed = INVESTIGATION_SUBJECT_TYPES[atomic]
    if isinstance(subject, Observable):
        observable = subject
    elif isinstance(subject, str) and subject.strip():
        observable = Observable(type=_default_type(allowed, subject), value=subject)
    else:
        raise ValueError(f"{atomic} needs a non-empty string or an Observable subject")
    if observable.type not in allowed:
        names = sorted(t.value for t in allowed)
        raise ValueError(f"{atomic} does not accept {observable.type.value} subjects (allowed: {names})")
    return _normalize_observable(observable)


# --------------------------------------------------------------- arguments --
def _check_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {_MAX_LIMIT}")
    return limit


def _check_options(options: Mapping[str, Any] | None) -> dict[str, Any]:
    if options is None:
        return {}
    if not isinstance(options, Mapping) or not all(isinstance(k, str) for k in options):
        raise ValueError("options must be a mapping with string keys")
    return dict(options)


def _ordered(names: Iterable[str]) -> tuple[str, ...]:
    """Distinct names in ``INTEGRATION_NAMES`` order."""
    wanted = set(names)
    return tuple(n for n in INTEGRATION_NAMES if n in wanted)


def _considered(action_type: ActionType, investigators: tuple[str, ...],
                integrations: Sequence[str]) -> tuple[str, ...]:
    """Integrations reported on: the requested ones, else the catalog's plus any investigator."""
    if isinstance(integrations, str):
        raise ValueError("integrations must be a sequence of integration names, not a string")
    unknown = sorted({n for n in integrations if n not in INTEGRATION_NAMES})
    if unknown:
        raise ValueError(f"unknown integrations {unknown}")
    if integrations:
        return _ordered(integrations)
    return _ordered((*get_action_spec(action_type).integrations, *investigators))


# ------------------------------------------------------------------ sources --
def _error_info(integration: str, exc: Exception) -> ErrorInfo:
    """Redacted :class:`ErrorInfo` for any exception raised by a source."""
    if isinstance(exc, IntegrationError):
        return exc.to_error_info()
    message = get_redactor().redact_text(f"{type(exc).__name__}: {exc}")[:_ERROR_CHARS]
    return ErrorInfo(code=ErrorCode.INTERNAL, message=message, integration=integration)


def _skipped(integration: str, enabled: tuple[str, ...], action_type: ActionType) -> SourceStatus:
    """Status of an integration that is not asked: disabled (not queried) or not serving the type."""
    if integration not in enabled:
        return SourceStatus(integration=integration, outcome=SourceOutcome.NOT_QUERIED,
                            health=HealthStatus.UNKNOWN, reason="not enabled")
    return SourceStatus(integration=integration, outcome=SourceOutcome.NOT_SUPPORTED, health=HealthStatus.UNKNOWN,
                        reason=f"does not serve {action_type.value}")


def _failed(integration: str, health: HealthStatus, error: ErrorInfo, records: int = 0) -> SourceStatus:
    return SourceStatus(integration=integration, outcome=SourceOutcome.FAILED, health=health,
                        reason=error.code.value, error=error, records=records)


def _query_source(ctx: "AtomicContext", integration: str, query: InvestigationQuery,
                  atomic: str) -> tuple[SourceStatus, InvestigationResult | None, list[AnyRecord]]:
    """Ask one integration and normalize its answer. Never raises."""
    try:
        result = ctx.adapters.investigate(integration, query)
    except Exception as exc:  # noqa: BLE001 - a failing source never stops the atomic
        return _failed(integration, classify_exception(exc), _error_info(integration, exc)), None, []
    if not isinstance(result, InvestigationResult) or result.integration != integration:
        error = ErrorInfo(code=ErrorCode.INTERNAL, message="adapter returned an invalid investigation result",
                          integration=integration)
        return _failed(integration, HealthStatus.UNKNOWN, error), None, []
    try:
        records = normalize(integration, result, _normalize_context(ctx, integration, atomic, query.subject))
    except Exception as exc:  # noqa: BLE001 - malformed lab data or a normalizer bug: report, continue
        error = _error_info(integration, exc)
        return _failed(integration, result.health, error.model_copy(update={"code": ErrorCode.INTERNAL})), \
            result, []
    return _status_of(integration, result, len(records)), result, records


def _normalize_context(ctx: "AtomicContext", integration: str, atomic: str, subject: Observable) -> NormalizeContext:
    try:
        typed_allowed = bool(ctx.adapters.is_simulated(integration))
    except Exception:  # noqa: BLE001 - unknown means "not simulated": typed records refused
        typed_allowed = False
    return NormalizeContext(atomic=atomic, subject=subject, typed_allowed=typed_allowed,
                            internal_domains=tuple(ctx.settings.exclusions.internal_domains))


def _status_of(integration: str, result: InvestigationResult, produced: int) -> SourceStatus:
    """FAILED when the result carries errors (records kept), EMPTY without records, else ANSWERED."""
    if result.errors:
        health = result.health if result.health is not HealthStatus.CONNECTED else HealthStatus.DEGRADED
        return _failed(integration, health, result.errors[0], produced)
    outcome = SourceOutcome.ANSWERED if produced else SourceOutcome.EMPTY
    return SourceStatus(integration=integration, outcome=outcome, health=result.health, records=produced)


def _dedupe(records: Iterable[AnyRecord], seen: set[str]) -> list[AnyRecord]:
    """Records whose id was not seen yet (first wins); updates ``seen``."""
    kept: list[AnyRecord] = []
    for record in records:
        if record.record_id not in seen:
            seen.add(record.record_id)
            kept.append(record)
    return kept


# ------------------------------------------------------------ critical assets --
def _endpoint_assets(subject: Observable, records: Sequence[AnyRecord]) -> list[Asset]:
    endpoints = [r for r in records if isinstance(r, EndpointRecord)]
    assets = [Asset(name=e.hostname, kind=TargetKind.ENDPOINT, groups=e.groups, tags=e.tags,
                    ip=e.ip_addresses[0] if e.ip_addresses else None) for e in endpoints]
    if not assets or subject.type is ObservableType.HOSTNAME:
        assets.append(Asset(name=subject.value, kind=TargetKind.ENDPOINT))
    return assets


def _user_assets(subject: Observable, records: Sequence[AnyRecord]) -> list[Asset]:
    profiles = [r for r in records if isinstance(r, UserProfileRecord)]
    assets = [Asset(name=p.user, kind=TargetKind.USER, groups=p.groups, roles=p.roles) for p in profiles]
    assets.append(Asset(name=subject.value, kind=TargetKind.USER))
    return assets


def _critical_classes(ctx: "AtomicContext", action_type: ActionType, subject: Observable,
                      records: Sequence[AnyRecord]) -> tuple[CriticalAssetClass, ...]:
    """Critical-asset classes of the investigated endpoints / users (informational, never a skip)."""
    if action_type in _ENDPOINT_FAMILY:
        assets = _endpoint_assets(subject, records)
    elif action_type in _USER_FAMILY:
        assets = _user_assets(subject, records)
    else:
        return ()
    found: set[CriticalAssetClass] = set()
    for asset in assets:
        found.update(ctx.critical_assets.classify(asset.name, asset.kind, asset))
    return tuple(c for c in CriticalAssetClass if c in found)


# ------------------------------------------------------------------ runner --
def _investigate(ctx: "AtomicContext", action_type: ActionType, subject: str | Observable, *,
                 options: Mapping[str, Any] | None, integrations: Sequence[str], limit: int) -> InvestigationBundle:
    """Shared body of every investigation and enterprise search atomic."""
    atomic = action_type.value
    if get_action_spec(action_type).category is not ActionCategory.INVESTIGATION:
        raise ValueError(f"{atomic} is not an investigation action type")  # pragma: no cover - table guard
    observable = _subject(atomic, subject)
    query_options = _check_options(options)
    started = ctx.now()
    time_from, time_to = ctx.window()
    query = InvestigationQuery(action_type=action_type, subject=observable, time_from=time_from,
                               time_to=time_to, limit=_check_limit(limit), options=query_options)
    investigators = tuple(ctx.adapters.investigators(action_type))
    enabled = tuple(ctx.adapters.enabled())
    sources: list[SourceStatus] = []
    raw: list[InvestigationResult] = []
    records: list[AnyRecord] = []
    seen: set[str] = set()
    for integration in _considered(action_type, investigators, integrations):
        if integration not in investigators:
            sources.append(_skipped(integration, enabled, action_type))
            continue
        status, result, found = _query_source(ctx, integration, query, atomic)
        sources.append(status)
        if result is not None:
            raw.append(result)
        records.extend(_dedupe(found, seen))
    return InvestigationBundle(
        atomic=atomic, action_type=action_type, subject=observable, records=tuple(records),
        sources=tuple(sources), raw=tuple(raw), started_at=started, finished_at=ctx.now(),
        critical_asset_classes=_critical_classes(ctx, action_type, observable, records),
    )


# ----------------------------------------------------------------- atomics --
def investigate_user(ctx: "AtomicContext", subject: str | Observable, *, options: Mapping[str, Any] | None = None,
                     integrations: Sequence[str] = (), limit: int = 100) -> InvestigationBundle:
    """Profile, risk, roles and recent identity activity of a user (subject: user or email_address)."""
    return _investigate(ctx, _A.INVESTIGATE_USER, subject, options=options, integrations=integrations, limit=limit)


def investigate_endpoint(ctx: "AtomicContext", subject: str | Observable, *,
                         options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                         limit: int = 100) -> InvestigationBundle:
    """Device facts, detections, trajectory and connections of an endpoint (hostname or endpoint_id)."""
    return _investigate(ctx, _A.INVESTIGATE_ENDPOINT, subject, options=options, integrations=integrations,
                        limit=limit)


def investigate_ip(ctx: "AtomicContext", subject: str | Observable, *, options: Mapping[str, Any] | None = None,
                   integrations: Sequence[str] = (), limit: int = 100) -> InvestigationBundle:
    """Connections, DNS answers and sign-ins involving an IP address (ip or ipv6)."""
    return _investigate(ctx, _A.INVESTIGATE_IP, subject, options=options, integrations=integrations, limit=limit)


def investigate_domain(ctx: "AtomicContext", subject: str | Observable, *,
                       options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                       limit: int = 100) -> InvestigationBundle:
    """DNS queries and connections to a domain."""
    return _investigate(ctx, _A.INVESTIGATE_DOMAIN, subject, options=options, integrations=integrations,
                        limit=limit)


def investigate_hash(ctx: "AtomicContext", subject: str | Observable, *, options: Mapping[str, Any] | None = None,
                     integrations: Sequence[str] = (), limit: int = 100) -> InvestigationBundle:
    """Prevalence, detections and executions of a file hash (sha256, sha1 or md5)."""
    return _investigate(ctx, _A.INVESTIGATE_HASH, subject, options=options, integrations=integrations, limit=limit)


def investigate_email(ctx: "AtomicContext", subject: str | Observable, *, options: Mapping[str, Any] | None = None,
                      integrations: Sequence[str] = (), limit: int = 100) -> InvestigationBundle:
    """Facts about one email message (email_message_id)."""
    return _investigate(ctx, _A.INVESTIGATE_EMAIL, subject, options=options, integrations=integrations,
                        limit=limit)


def investigate_authentication(ctx: "AtomicContext", subject: str | Observable, *,
                               options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                               limit: int = 100) -> InvestigationBundle:
    """Sign-ins, MFA events and risk detections of a user."""
    return _investigate(ctx, _A.INVESTIGATE_AUTHENTICATION, subject, options=options, integrations=integrations,
                        limit=limit)


def investigate_process(ctx: "AtomicContext", subject: str | Observable, *,
                        options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                        limit: int = 100) -> InvestigationBundle:
    """Events, children and connections of a process (``"<ENDPOINT>/<sha256 or pid>"``)."""
    return _investigate(ctx, _A.INVESTIGATE_PROCESS, subject, options=options, integrations=integrations,
                        limit=limit)


def investigate_network_connection(ctx: "AtomicContext", subject: str | Observable, *,
                                   options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                                   limit: int = 100) -> InvestigationBundle:
    """Network connections to or from an IP address (ip or ipv6)."""
    return _investigate(ctx, _A.INVESTIGATE_NETWORK_CONNECTION, subject, options=options,
                        integrations=integrations, limit=limit)


def search_hash_enterprise(ctx: "AtomicContext", subject: str | Observable, *,
                           options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                           limit: int = 100) -> InvestigationBundle:
    """Every endpoint and event that saw a file hash."""
    return _investigate(ctx, _A.SEARCH_HASH_ENTERPRISE, subject, options=options, integrations=integrations,
                        limit=limit)


def search_domain_enterprise(ctx: "AtomicContext", subject: str | Observable, *,
                             options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                             limit: int = 100) -> InvestigationBundle:
    """Every endpoint and user that resolved or contacted a domain."""
    return _investigate(ctx, _A.SEARCH_DOMAIN_ENTERPRISE, subject, options=options, integrations=integrations,
                        limit=limit)


def search_ip_enterprise(ctx: "AtomicContext", subject: str | Observable, *,
                         options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                         limit: int = 100) -> InvestigationBundle:
    """Every endpoint and user that communicated with an IP address."""
    return _investigate(ctx, _A.SEARCH_IP_ENTERPRISE, subject, options=options, integrations=integrations,
                        limit=limit)


def search_user_activity(ctx: "AtomicContext", subject: str | Observable, *,
                         options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                         limit: int = 100) -> InvestigationBundle:
    """Recent activity of a user across identity, mail and cloud sources."""
    return _investigate(ctx, _A.SEARCH_USER_ACTIVITY, subject, options=options, integrations=integrations,
                        limit=limit)


def search_email_campaign(ctx: "AtomicContext", subject: str | Observable, *,
                          options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                          limit: int = 100) -> InvestigationBundle:
    """Messages related to one message (same campaign, sender, URL or attachment)."""
    return _investigate(ctx, _A.SEARCH_EMAIL_CAMPAIGN, subject, options=options, integrations=integrations,
                        limit=limit)


def search_related_endpoints(ctx: "AtomicContext", subject: str | Observable, *,
                             options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                             limit: int = 100) -> InvestigationBundle:
    """Endpoints related to an endpoint (shared users, indicators or groups)."""
    return _investigate(ctx, _A.SEARCH_RELATED_ENDPOINTS, subject, options=options, integrations=integrations,
                        limit=limit)


def search_related_users(ctx: "AtomicContext", subject: str | Observable, *,
                         options: Mapping[str, Any] | None = None, integrations: Sequence[str] = (),
                         limit: int = 100) -> InvestigationBundle:
    """Users related to a user (shared devices, sign-in sources or mail activity)."""
    return _investigate(ctx, _A.SEARCH_RELATED_USERS, subject, options=options, integrations=integrations,
                        limit=limit)


INVESTIGATION_ATOMICS: Mapping[str, InvestigationAtomic] = MappingProxyType({
    fn.__name__: fn for fn in (
        investigate_user, investigate_endpoint, investigate_ip, investigate_domain, investigate_hash,
        investigate_email, investigate_authentication, investigate_process, investigate_network_connection,
        search_hash_enterprise, search_domain_enterprise, search_ip_enterprise, search_user_activity,
        search_email_campaign, search_related_endpoints, search_related_users,
    )
})
