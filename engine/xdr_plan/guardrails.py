"""Guardrail checks applied to every containment action before it is planned.

Each check returns ``None`` when the action may proceed, otherwise a status:
``skipped_protected``, ``skipped_allowlisted`` or ``skipped_internal``.
"""
from __future__ import annotations

import ipaddress
from fnmatch import fnmatch
from typing import Any

from .expr import _domain_of

HOST_FIELDS = ("host", "hostname", "connector_guid", "ip")
USER_FIELDS = ("user", "upn", "email")


def _as_network(pattern: str):
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def _as_ip(value: Any):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _values(item: Any, target: str, fields: tuple[str, ...]) -> list[str]:
    vals = [str(target)]
    if isinstance(item, dict):
        vals += [str(item[f]) for f in fields if item.get(f)]
    return vals


def host_protected(target: str, item: Any, g: dict) -> str | None:
    if isinstance(item, dict) and item.get("is_protected"):
        return "skipped_protected"
    for value in _values(item, target, HOST_FIELDS):
        ip = _as_ip(value)
        for pattern in g.get("protected", {}).get("hosts", []) or []:
            net = _as_network(pattern)
            if net is not None:
                if ip is not None and ip in net:
                    return "skipped_protected"
            elif fnmatch(value.lower(), str(pattern).lower()):
                return "skipped_protected"
    return None


def user_protected(target: str, item: Any, g: dict) -> str | None:
    if isinstance(item, dict) and item.get("is_protected"):
        return "skipped_protected"
    protected = g.get("protected", {})
    for value in _values(item, target, USER_FIELDS):
        for pattern in protected.get("users", []) or []:
            if fnmatch(value.lower(), str(pattern).lower()):
                return "skipped_protected"
    groups = set()
    if isinstance(item, dict) and isinstance(item.get("profile"), dict):
        groups = {str(x).lower() for x in item["profile"].get("groups", []) or []}
    if groups & {str(x).lower() for x in protected.get("groups", []) or []}:
        return "skipped_protected"
    return None


def domain_allowlisted(domain: str, g: dict) -> bool:
    domain = domain.lower().rstrip(".")
    for pattern in g.get("allowlist", {}).get("domains", []) or []:
        pattern = str(pattern).lower()
        if fnmatch(domain, pattern) or domain == pattern or domain.endswith("." + pattern.lstrip("*.")):
            return True
    return False


def domain_check(target: str, item: Any, g: dict) -> str | None:
    return "skipped_allowlisted" if domain_allowlisted(target, g) else None


def url_check(target: str, item: Any, g: dict) -> str | None:
    return "skipped_allowlisted" if domain_allowlisted(_domain_of(target), g) else None


def ip_check(target: str, item: Any, g: dict) -> str | None:
    ip = _as_ip(target)
    if ip is None:
        raise ValueError(f"block-ip target is not an IP address: {target!r}")
    if isinstance(item, dict) and item.get("is_internal"):
        return "skipped_internal"
    for pattern in g.get("allowlist", {}).get("ip_ranges", []) or []:
        net = _as_network(str(pattern))
        if net is not None and ip in net:
            return "skipped_internal"
    # Documentation ranges (RFC 5737 / 3849) stand in for public IPs in scenarios.
    doc_ranges = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    if any(ip in n for n in doc_ranges if n.version == ip.version):
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "skipped_internal"
    return None


def hash_check(target: str, item: Any, g: dict) -> str | None:
    allowed = {str(h).lower() for h in g.get("allowlist", {}).get("hashes", []) or []}
    return "skipped_allowlisted" if target.lower() in allowed else None


CHECKS = {
    "isolate-endpoint": host_protected,
    "disable-user": user_protected,
    "revoke-session": user_protected,
    "block-domain": domain_check,
    "block-url": url_check,
    "block-ip": ip_check,
    "block-hash": hash_check,
    "quarantine-email": lambda target, item, g: None,
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
