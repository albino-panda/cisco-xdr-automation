"""Native-first routing of containment recommendations (architecture 4.2 and 14.1.7).

:func:`choose_route` decides which integration *would* execute an action once a human has approved
it. It only reads: the names of enabled executors (``ReadOnlyAdapters.executors``) and the Cisco XDR
``respond/observables`` listing (``ReadOnlyAdapters.native_response_actions``, a READ operation).
It never holds an adapter, never calls a state-changing method and never decides an approval level.

Order (deterministic):

1. ``candidates = ctx.adapters.executors(action_type)``. With ``product`` given, only ``cisco_xdr``
   (native, landing on that product) and ``product`` itself are eligible; the router never
   silently switches product.
2. Native first: when ``cisco_xdr`` is eligible and the operator configured
   ``integrations.cisco_xdr.options.native_actions[<action>][<landing product>]`` as
   ``{"module": ..., "action_id": ...}``, the listing for the target must offer exactly one module
   instance with that action id. Missing configuration, no match, several matches or a read
   error are recorded in ``considered`` and routing falls through. Action ids are copied by the
   operator from the tenant listing; the router never guesses them.
3. Direct: ``product`` when eligible, else the first non-``cisco_xdr`` candidate.
4. Nothing: ``integration=None`` with reason ``"no enabled adapter has a VERIFIED write for <action>"``.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from xdr_response.atomics.containment.models import RouteDecision
from xdr_response.models.canonical import normalize_target
from xdr_response.models.catalog import INTEGRATION_NAMES, ActionSpec, ActionType, get_action_spec
from xdr_response.models.enums import ApprovalPurpose, ObservableType, TargetKind
from xdr_response.models.observable import Observable

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.context import AtomicContext
    from xdr_response.config import Settings

__all__ = ["NATIVE_OBSERVABLE_TYPES", "choose_route"]

NATIVE = "cisco_xdr"

#: Target kind -> Cisco XDR (CTIM) observable type of a native action. IP targets use ``ipv6`` for
#: IPv6 addresses and hashes use ``sha1`` / ``md5`` by length (see :func:`_native_observable`).
NATIVE_OBSERVABLE_TYPES: Mapping[TargetKind, str] = MappingProxyType({
    TargetKind.ENDPOINT: "hostname",
    TargetKind.DOMAIN: "domain",
    TargetKind.URL: "url",
    TargetKind.IP: "ip",
    TargetKind.HASH: "sha256",
    TargetKind.USER: "user",
    TargetKind.EMAIL_MESSAGE: "email_messageid",
})

_CTIM_TO_OBSERVABLE: Mapping[str, ObservableType] = MappingProxyType({
    "hostname": ObservableType.HOSTNAME, "domain": ObservableType.DOMAIN, "url": ObservableType.URL,
    "ip": ObservableType.IP, "ipv6": ObservableType.IPV6, "sha256": ObservableType.SHA256,
    "sha1": ObservableType.SHA1, "md5": ObservableType.MD5, "user": ObservableType.USER,
    "email_messageid": ObservableType.EMAIL_MESSAGE_ID,
})

_HASH_TYPES: Mapping[int, str] = MappingProxyType({64: "sha256", 40: "sha1", 32: "md5"})
_HEX = re.compile(r"[0-9a-f]+")
_PID = re.compile(r"[0-9]+")
_ENDPOINT_COMPOSITES = frozenset({TargetKind.PROCESS, TargetKind.FILE, TargetKind.PERSISTENCE_ITEM})
_COMPOSITES = _ENDPOINT_COMPOSITES | {TargetKind.ROLE_ASSIGNMENT, TargetKind.NETWORK_CLIENT}
_NO_SPACE_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.DOMAIN, TargetKind.URL, TargetKind.USER,
                             TargetKind.HASH, TargetKind.EMAIL_ADDRESS})


# --------------------------------------------------------------- targets --
def _containment_spec(action_type: ActionType | str) -> ActionSpec:
    """Catalog spec of a CONTAINMENT / REMEDIATION type; ValueError for anything else."""
    spec = get_action_spec(action_type)
    if spec.purpose is not ApprovalPurpose.CONTAINMENT:
        raise ValueError(f"{spec.action_type.value} is not a containment or remediation action type; "
                         "restoration is only ever built by the RestorationPlanner")
    return spec


def _hash_value(value: str, *, sha256_only: bool = False) -> str:
    """Lower-case hex hash; ValueError unless md5 / sha1 / sha256 (sha256 only when asked)."""
    v = value.strip().lower()
    lengths = (64,) if sha256_only else tuple(_HASH_TYPES)
    if len(v) not in lengths or not _HEX.fullmatch(v):
        raise ValueError(f"invalid hash target: {value!r}")
    return v


def _composite(kind: TargetKind, value: str) -> str:
    """Normalize ``<left>/<right>`` composite targets (architecture 13.3)."""
    left, sep, right = value.partition("/")
    left, right = left.strip(), right.strip()
    if not sep or not left or not right:
        raise ValueError(f"{kind.value} target must be '<left>/<right>', got {value!r}")
    if kind in _ENDPOINT_COMPOSITES:
        left = normalize_target(TargetKind.ENDPOINT, left)
        if any(c.isspace() for c in left):
            raise ValueError(f"invalid endpoint in {kind.value} target: {value!r}")
    if kind is TargetKind.FILE:
        right = _hash_value(right, sha256_only=True)
    elif kind is TargetKind.PROCESS:
        right = right if _PID.fullmatch(right) else _hash_value(right, sha256_only=True)
    elif kind is TargetKind.ROLE_ASSIGNMENT:
        left = normalize_target(TargetKind.USER, left)
    return f"{left}/{right}"


def _normalize_containment_target(kind: TargetKind, value: str) -> str:
    """Normalize ``value`` for ``kind``; ValueError when it cannot be a target of that kind."""
    base = normalize_target(kind, value)
    if kind in _COMPOSITES:
        return _composite(kind, base)
    if kind in _NO_SPACE_KINDS and any(c.isspace() for c in base):
        raise ValueError(f"invalid {kind.value} target: {value!r}")
    if kind is TargetKind.HASH:
        return _hash_value(base)
    if kind in (TargetKind.ENDPOINT, TargetKind.DOMAIN) and any(c in base for c in "/@:"):
        raise ValueError(f"invalid {kind.value} target: {value!r}")
    if kind is TargetKind.URL and "." not in base and "://" not in base:
        raise ValueError(f"invalid URL target: {value!r}")
    return base


# ---------------------------------------------------------------- native --
def _native_observable(kind: TargetKind, target: str) -> tuple[str, Observable] | None:
    """(CTIM observable type, Observable to list native actions for), or None for other kinds."""
    ctim = NATIVE_OBSERVABLE_TYPES.get(kind)
    if ctim is None:
        return None
    if kind is TargetKind.IP and ipaddress.ip_address(target).version == 6:
        ctim = "ipv6"
    elif kind is TargetKind.HASH:
        ctim = _HASH_TYPES[len(target)]
    return ctim, Observable(type=_CTIM_TO_OBSERVABLE[ctim], value=target)


def _native_config(settings: "Settings", action_type: ActionType, landing: str) -> tuple[str, str] | str:
    """``(module, action_id)`` configured for this action on ``landing``, or the reason there is none."""
    options = settings.integration(NATIVE).options
    table = options.get("native_actions") if isinstance(options, Mapping) else None
    per_action = table.get(action_type.value) if isinstance(table, Mapping) else None
    entry = per_action.get(landing) if isinstance(per_action, Mapping) else None
    if entry is None:
        return f"{NATIVE}: no configured native action for {landing}"
    module = entry.get("module") if isinstance(entry, Mapping) else None
    action_id = entry.get("action_id") if isinstance(entry, Mapping) else None
    if not isinstance(module, str) or not module.strip() or not isinstance(action_id, str) or not action_id.strip():
        return f"{NATIVE}: invalid native action configuration for {landing} (needs module and action_id)"
    return module.strip(), action_id.strip()


def _module_instances(listing: Sequence[Any], action_id: str) -> tuple[str, ...]:
    """Distinct module instance ids offering ``action_id`` (sorted, deterministic)."""
    found = {a.module_instance_id for a in listing
             if a.action_id == action_id and isinstance(a.module_instance_id, str) and a.module_instance_id}
    return tuple(sorted(found))


def _native_route(ctx: "AtomicContext", spec: ActionSpec, target: str, landing: str | None,
                  considered: list[str]) -> RouteDecision | None:
    """Step 2: the native Cisco XDR route, or None (with the reason appended to ``considered``)."""
    if landing is None:
        considered.append(f"{NATIVE}: no product to land a native {spec.action_type.value} on")
        return None
    observable = _native_observable(spec.target_kind, target)
    if observable is None:
        considered.append(f"{NATIVE}: no native observable type for {spec.target_kind.value}")
        return None
    config = _native_config(ctx.settings, spec.action_type, landing)
    if isinstance(config, str):
        considered.append(config)
        return None
    module, action_id = config
    ctim, subject = observable
    try:
        listing = tuple(ctx.adapters.native_response_actions(subject, module=module))
    except Exception as exc:  # noqa: BLE001 - a failed read is recorded and routing falls back
        considered.append(f"{NATIVE}: native action listing failed ({type(exc).__name__})")
        return None
    instances = _module_instances(listing, action_id)
    if len(instances) != 1:
        problem = "not offered" if not instances else f"ambiguous ({len(instances)} module instances)"
        considered.append(f"{NATIVE}: native action {action_id} for {landing} {problem}")
        return None
    params = {"integration": NATIVE, "module_instance_id": instances[0], "action_id": action_id,
              "observable_type": ctim, "observable_value": target, "verify_integration": landing}
    considered.append(f"{NATIVE}: native action {action_id} via module {module}, verified through {landing}")
    return RouteDecision(action_type=spec.action_type, integration=NATIVE, native=True, product=landing,
                         params=params, considered=tuple(considered))


# ---------------------------------------------------------------- routing --
def _check_product(spec: ActionSpec, product: str | None) -> None:
    """ValueError when ``product`` cannot execute ``spec`` according to the catalog."""
    if product is None:
        return
    if product not in INTEGRATION_NAMES or product == NATIVE or product not in spec.integrations:
        raise ValueError(f"product {product!r} cannot execute {spec.action_type.value} "
                         f"(catalog integrations: {list(spec.integrations)}; cisco_xdr is only a native path)")


def _eligible(spec: ActionSpec, candidates: Sequence[str], product: str | None,
              considered: list[str]) -> tuple[str, ...]:
    """Step 1: the candidates allowed for this route (product pinning), with notes."""
    if product is None:
        return tuple(candidates)
    if product not in candidates:
        considered.append(f"{product}: not enabled or no VERIFIED write for {spec.action_type.value}")
    for name in candidates:
        if name not in (NATIVE, product):
            considered.append(f"{name}: not eligible (pinned to {product})")
    return tuple(c for c in candidates if c in (NATIVE, product))


def _direct(product: str | None, eligible: Sequence[str]) -> str | None:
    """Step 3: ``product`` when eligible, else the first non-native candidate (catalog order)."""
    if product is not None:
        return product if product in eligible else None
    return next((c for c in eligible if c != NATIVE), None)


def choose_route(ctx: "AtomicContext", action_type: ActionType, target: str, *,
                 product: str | None = None) -> RouteDecision:
    """Choose the integration that would execute ``action_type`` on ``target`` after approval.

    Deterministic, read-only (see the module docstring). Raises ValueError for a non-containment
    action type, a target that cannot be normalized or a product the catalog does not list.
    """
    spec = _containment_spec(action_type)
    target = _normalize_containment_target(spec.target_kind, target)
    _check_product(spec, product)
    considered: list[str] = []
    eligible = _eligible(spec, ctx.adapters.executors(spec.action_type), product, considered)
    landing = product or next((c for c in eligible if c != NATIVE), None)
    if NATIVE in eligible:
        native = _native_route(ctx, spec, target, landing, considered)
        if native is not None:
            return native
    elif NATIVE in spec.integrations:
        considered.append(f"{NATIVE}: not an enabled executor for {spec.action_type.value}")
    direct = _direct(product, eligible)
    if direct is not None:
        considered.append(f"{direct}: direct {spec.action_type.value}")
        return RouteDecision(action_type=spec.action_type, integration=direct, product=direct,
                             params={"integration": direct}, considered=tuple(considered))
    return RouteDecision(action_type=spec.action_type, integration=None, product=product,
                         considered=tuple(considered),
                         reason=f"no enabled adapter has a VERIFIED write for {spec.action_type.value}")
