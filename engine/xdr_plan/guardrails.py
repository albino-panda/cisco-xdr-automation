"""Guardrail checks applied to every containment action before it is planned.

Each check returns ``None`` when the action may proceed unchanged, otherwise a
marker:

- ``"skipped_allowlisted"`` / ``"skipped_internal"``: the target is excluded
  by the allow-list (an allow-listed indicator is never blocked);
- ``"elevated:protected"`` (``ELEVATED_PROTECTED``): the target is a protected
  (critical) asset. The action stays planned and needs ELEVATED human
  approval (architecture 14.4.1 C3). A protected asset is never silently
  dropped from the plan.

Approval can never be disabled or automated by a guardrails file:
``LEGACY_FORBIDDEN_KEYS`` mirrors ``xdr_response.config.loader.FORBIDDEN_KEYS``
and ``find_forbidden_keys`` reports any of them at any depth.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from fnmatch import fnmatch
from typing import Any

from .expr import _domain_of

HOST_FIELDS = ("host", "hostname", "connector_guid", "ip")
USER_FIELDS = ("user", "upn", "email")

ELEVATED_PROTECTED = "elevated:protected"
"""Marker returned by ``host_protected`` / ``user_protected`` for a protected asset."""

LEGACY_FORBIDDEN_KEYS = frozenset({"auto_approve", "skip_approval", "bypass_approval", "approval_required"})
"""Keys refused anywhere in guardrails, specs and scenarios (equal to the runtime's FORBIDDEN_KEYS)."""

_DOC_RANGES = tuple(ipaddress.ip_network(n) for n in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))

Check = Callable[[str, Any, dict], "str | None"]


def find_forbidden_keys(data: Any, path: str = "") -> list[str]:
    """Return the dotted path of every ``LEGACY_FORBIDDEN_KEYS`` key in ``data``, at any depth."""
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).strip().lower() in LEGACY_FORBIDDEN_KEYS:
                found.append(here)
            found += find_forbidden_keys(value, here)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            found += find_forbidden_keys(value, f"{path}[{index}]")
    return found


def _as_network(pattern: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def _as_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _values(item: Any, target: str, fields: tuple[str, ...]) -> list[str]:
    vals = [str(target)]
    if isinstance(item, dict):
        vals += [str(item[f]) for f in fields if item.get(f)]
    return vals


def _host_matches(value: str, pattern: Any) -> bool:
    """True when a host value matches a protected pattern (CIDR or glob)."""
    net = _as_network(str(pattern))
    if net is not None:
        ip = _as_ip(value)
        return ip is not None and ip.version == net.version and ip in net
    return fnmatch(value.lower(), str(pattern).lower())


def host_protected(target: str, item: Any, g: dict) -> str | None:
    """``ELEVATED_PROTECTED`` when the host is protected (flag, name, GUID or CIDR), else ``None``."""
    if isinstance(item, dict) and item.get("is_protected"):
        return ELEVATED_PROTECTED
    patterns = (g.get("protected") or {}).get("hosts") or []
    for value in _values(item, target, HOST_FIELDS):
        if any(_host_matches(value, pattern) for pattern in patterns):
            return ELEVATED_PROTECTED
    return None


def _user_groups(item: Any) -> set[str]:
    if isinstance(item, dict) and isinstance(item.get("profile"), dict):
        return {str(x).lower() for x in item["profile"].get("groups", []) or []}
    return set()


def user_protected(target: str, item: Any, g: dict) -> str | None:
    """``ELEVATED_PROTECTED`` when the user is protected (flag, name or group), else ``None``."""
    if isinstance(item, dict) and item.get("is_protected"):
        return ELEVATED_PROTECTED
    protected = g.get("protected") or {}
    for value in _values(item, target, USER_FIELDS):
        if any(fnmatch(value.lower(), str(p).lower()) for p in protected.get("users", []) or []):
            return ELEVATED_PROTECTED
    if _user_groups(item) & {str(x).lower() for x in protected.get("groups", []) or []}:
        return ELEVATED_PROTECTED
    return None


def _domain_in(domain: str, patterns: list[Any]) -> bool:
    domain = domain.lower().rstrip(".")
    for pattern in patterns:
        pattern = str(pattern).lower()
        if fnmatch(domain, pattern) or domain == pattern or domain.endswith("." + pattern.lstrip("*.")):
            return True
    return False


def domain_allowlisted(domain: str, g: dict) -> bool:
    """True when ``domain`` or a parent domain is in ``allowlist.domains``."""
    return _domain_in(domain, (g.get("allowlist") or {}).get("domains", []) or [])


def url_block_allowed(domain: str, g: dict) -> bool:
    """True when URL blocks on ``domain`` are allowed despite the domain allow-list."""
    return _domain_in(domain, (g.get("allowlist") or {}).get("url_block_allowed_domains", []) or [])


def domain_check(target: str, item: Any, g: dict) -> str | None:
    """Allow-listed domains are never blocked."""
    return "skipped_allowlisted" if domain_allowlisted(target, g) else None


def url_check(target: str, item: Any, g: dict) -> str | None:
    """A URL on an allow-listed domain is skipped unless the domain allows URL blocks (per-action allow-list)."""
    domain = _domain_of(target)
    if domain_allowlisted(domain, g) and not url_block_allowed(domain, g):
        return "skipped_allowlisted"
    return None


def ip_check(target: str, item: Any, g: dict) -> str | None:
    """Internal, allow-listed or non-routable addresses are never blocked."""
    ip = _as_ip(target)
    if ip is None:
        raise ValueError(f"block-ip target is not an IP address: {target!r}")
    if isinstance(item, dict) and item.get("is_internal"):
        return "skipped_internal"
    for pattern in (g.get("allowlist") or {}).get("ip_ranges", []) or []:
        net = _as_network(str(pattern))
        if net is not None and ip.version == net.version and ip in net:
            return "skipped_internal"
    # Documentation ranges (RFC 5737 / 3849) stand in for public IPs in scenarios.
    if any(ip in n for n in _DOC_RANGES if n.version == ip.version):
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "skipped_internal"
    return None


def hash_check(target: str, item: Any, g: dict) -> str | None:
    """Allow-listed hashes are never blocked."""
    allowed = {str(h).lower() for h in (g.get("allowlist") or {}).get("hashes", []) or []}
    return "skipped_allowlisted" if target.lower() in allowed else None


def no_check(target: str, item: Any, g: dict) -> str | None:
    """Atomics without a target-level guardrail."""
    return None


CHECKS: dict[str, Check] = {
    "isolate-endpoint": host_protected,
    "disable-user": user_protected,
    "revoke-session": user_protected,
    "block-domain": domain_check,
    "block-url": url_check,
    "block-ip": ip_check,
    "block-hash": hash_check,
    "quarantine-email": no_check,
}

# Blast-radius cap applied to planned actions of each atomic.
CAPS = {
    "isolate-endpoint": "max_hosts_isolated",
    "disable-user": "max_users_disabled",
    "block-domain": "max_indicators_blocked",
    "block-url": "max_indicators_blocked",
    "block-ip": "max_indicators_blocked",
    "block-hash": "max_indicators_blocked",
}
