"""The seven enrichment atomics (architecture 14.1.3).

Each atomic takes an :class:`AtomicContext` and a subject (``str`` or :class:`Observable`) and
returns an :class:`ObservableReport`. Deterministic steps:

1. build and normalize the subject (``ValueError`` for invalid caller input, the only exception an
   atomic raises);
2. ask every enricher of the subject's type through ``ctx.adapters`` (third-party sources the
   disclosure policy refuses are ``NOT_QUERIED`` and never called; failures become ``FAILED``);
3. score the answering sources' records with the scoring engine (critical-asset classes, expected,
   failed and not-queried sources in the context);
4. take risk, confidence and the aggregate verdict from the engine.

No source ever blocks the report: with every source failed the report has risk 0, confidence 0,
verdict ``UNKNOWN`` and lists the failures. Atomics only read: they call ``ctx.adapters.enrich``
and nothing else.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from xdr_response.atomics.context import AtomicContext
from xdr_response.atomics.enrichment._scoring import score_observable, scoring_context
from xdr_response.atomics.enrichment._sources import query_sources
from xdr_response.atomics.enrichment._subjects import build_subject
from xdr_response.atomics.enrichment.models import ObservableReport
from xdr_response.atomics.records import EnrichmentRecord
from xdr_response.models import ActionType, Observable, ObservableType

__all__ = [
    "enrich_ip",
    "enrich_domain",
    "enrich_url",
    "enrich_hash",
    "enrich_email_address",
    "enrich_user",
    "enrich_endpoint",
    "enrich",
    "ENRICHMENT_ATOMICS",
    "ENRICHMENT_SUBJECT_TYPES",
]

_O = ObservableType


@dataclass(frozen=True)
class _AtomicSpec:
    """Name, catalog action type, accepted subject types and the type a plain string gets."""

    name: str
    action_type: ActionType
    accepted: frozenset[ObservableType]
    default: ObservableType


_SPECS: Mapping[str, _AtomicSpec] = MappingProxyType({spec.name: spec for spec in (
    _AtomicSpec("enrich_ip", ActionType.ENRICH_IP, frozenset({_O.IP, _O.IPV6}), _O.IP),
    _AtomicSpec("enrich_domain", ActionType.ENRICH_DOMAIN, frozenset({_O.DOMAIN}), _O.DOMAIN),
    _AtomicSpec("enrich_url", ActionType.ENRICH_URL, frozenset({_O.URL}), _O.URL),
    _AtomicSpec("enrich_hash", ActionType.ENRICH_HASH, frozenset({_O.SHA256, _O.SHA1, _O.MD5}), _O.SHA256),
    _AtomicSpec("enrich_email_address", ActionType.ENRICH_EMAIL_ADDRESS, frozenset({_O.EMAIL_ADDRESS}),
                _O.EMAIL_ADDRESS),
    _AtomicSpec("enrich_user", ActionType.ENRICH_USER, frozenset({_O.USER}), _O.USER),
    _AtomicSpec("enrich_endpoint", ActionType.ENRICH_ENDPOINT, frozenset({_O.HOSTNAME, _O.ENDPOINT_ID}),
                _O.HOSTNAME),
)})

#: Accepted subject observable types per enrichment atomic name.
ENRICHMENT_SUBJECT_TYPES: Mapping[str, frozenset[ObservableType]] = MappingProxyType(
    {name: spec.accepted for name, spec in _SPECS.items()})

_ATOMIC_FOR_TYPE: Mapping[ObservableType, str] = MappingProxyType(
    {t: name for name, spec in _SPECS.items() for t in spec.accepted})


def _run(spec: _AtomicSpec, ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Steps 1 to 4 of 14.1.3 for one atomic."""
    subject = build_subject(value, spec.accepted, spec.default)
    started_at = ctx.now()
    answers = query_sources(ctx, spec.name, subject, ctx.adapters.enrichers(subject.type))
    records = tuple(a.record for a in answers if isinstance(a.record, EnrichmentRecord))
    breakdown, verdict = score_observable(ctx, records, scoring_context(ctx, spec.action_type, subject, answers))
    return ObservableReport(
        atomic=spec.name,
        action_type=spec.action_type,
        subject=subject,
        records=records,
        sources=tuple(a.status for a in answers),
        raw=tuple(a.raw for a in answers if a.raw is not None),
        started_at=started_at,
        finished_at=ctx.now(),
        type=subject.type,
        value=subject.value,
        risk_score=breakdown.risk_score,
        confidence=breakdown.confidence_score,
        verdict=verdict,
        breakdown=breakdown,
    )


def enrich_ip(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich an IPv4 or IPv6 address (a string picks ``ip`` or ``ipv6`` by version)."""
    return _run(_SPECS["enrich_ip"], ctx, value)


def enrich_domain(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich a domain (lower case, no trailing dot, IDN as punycode)."""
    return _run(_SPECS["enrich_domain"], ctx, value)


def enrich_url(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich a URL (stripped; scheme http, https, ftp or ftps, or none; a host is required)."""
    return _run(_SPECS["enrich_url"], ctx, value)


def enrich_hash(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich a file hash (a string picks sha256 / sha1 / md5 by length)."""
    return _run(_SPECS["enrich_hash"], ctx, value)


def enrich_email_address(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich an email address (never sent to public intel except HIBP when the policy allows)."""
    return _run(_SPECS["enrich_email_address"], ctx, value)


def enrich_user(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich a user account (internal sources only; never disclosed to third parties)."""
    return _run(_SPECS["enrich_user"], ctx, value)


def enrich_endpoint(ctx: AtomicContext, value: str | Observable) -> ObservableReport:
    """Enrich an endpoint by hostname (a string) or ``endpoint_id`` (internal sources only)."""
    return _run(_SPECS["enrich_endpoint"], ctx, value)


#: The seven enrichment atomics by name (name == catalog ``ActionType`` value).
ENRICHMENT_ATOMICS: Mapping[str, Callable[[AtomicContext, Observable], ObservableReport]] = MappingProxyType({
    "enrich_ip": enrich_ip,
    "enrich_domain": enrich_domain,
    "enrich_url": enrich_url,
    "enrich_hash": enrich_hash,
    "enrich_email_address": enrich_email_address,
    "enrich_user": enrich_user,
    "enrich_endpoint": enrich_endpoint,
})


def enrich(ctx: AtomicContext, observable: Observable) -> ObservableReport:
    """Dispatch by observable type to the matching enrichment atomic (``ValueError`` when none)."""
    if not isinstance(observable, Observable):
        raise ValueError("enrich needs an Observable")
    name = _ATOMIC_FOR_TYPE.get(observable.type)
    if name is None:
        raise ValueError(f"no enrichment atomic accepts {observable.type.value} observables")
    return ENRICHMENT_ATOMICS[name](ctx, observable)
