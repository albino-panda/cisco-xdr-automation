"""Deterministic config-driven policies: allow-lists and third-party disclosure."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from xdr_response.config.schema import AllowlistsConfig, ExclusionsConfig
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import ApprovalPurpose, ObservableType, TargetKind
from xdr_response.models.observable import Observable

__all__ = ["AllowlistPolicy", "DisclosurePolicy", "THIRD_PARTY_INTEGRATIONS", "DOCUMENTATION_NETWORKS"]

#: Integrations that send observables outside the organization.
THIRD_PARTY_INTEGRATIONS = frozenset({"virustotal", "alienvault_otx", "hibp"})

#: RFC 5737 / RFC 3849 documentation ranges (only treated as public with allow_documentation_ranges).
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

_BUILTIN_INTERNAL_SUFFIXES = ("local", "localhost", "internal", "lan", "home.arpa", "intranet", "corp")


def _domain_matches(domain: str, candidates: list[str] | tuple[str, ...]) -> str | None:
    d = domain.lower().rstrip(".")
    for c in candidates:
        c = c.lower().strip().rstrip(".").lstrip("*").lstrip(".")
        if c and (d == c or d.endswith("." + c)):
            return c
    return None


def _split_composite(target: str) -> tuple[str, str]:
    endpoint, _, rest = target.partition("/")
    return endpoint, rest


class AllowlistPolicy:
    """Decides whether a containment target is allow-listed (never blocked, shown as excluded)."""

    def __init__(self, config: AllowlistsConfig) -> None:
        nb = config.never_block
        self._domains = tuple(nb.get("domains", []))
        self._urls = frozenset(u.strip() for u in nb.get("urls", []))
        self._ips = frozenset(ipaddress.ip_address(i) for i in nb.get("ips", []))
        self._cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in nb.get("cidrs", []))
        self._hashes = frozenset(h.lower() for h in nb.get("hashes", []))
        self._users = frozenset(u.lower() for u in nb.get("users", []))
        self._endpoints = frozenset(e.upper() for e in nb.get("endpoints", []))
        self._url_ok = tuple(config.url_block_allowed_domains)
        self._tools: list[tuple[str, str, dict]] = [
            ("approved_rmm", t["name"], t) for t in config.approved_rmm
        ] + [("approved_dns_tools", t["name"], t) for t in config.approved_dns_tools]

    def _tool_hash(self, h: str) -> str | None:
        for section, name, tool in self._tools:
            if h.lower() in {x.lower() for x in tool.get("hashes", []) or []}:
                return f"allowlists.{section}: {name}"
        return None

    def _tool_domain(self, domain: str) -> str | None:
        for section, name, tool in self._tools:
            if _domain_matches(domain, tool.get("domains", []) or []):
                return f"allowlists.{section}: {name}"
        return None

    def _domain_reason(self, domain: str) -> str | None:
        hit = _domain_matches(domain, self._domains)
        if hit:
            return f"allowlists.never_block.domains: {hit}"
        return self._tool_domain(domain)

    def excluded_reason(self, action_type: ActionType, target: str, target_kind: TargetKind) -> str | None:
        """Reason string when the target is allow-listed for this containment action, else None.

        Only containment/remediation actions are checked; restoration (unblock/release) never is.
        """
        spec = get_action_spec(action_type)
        if spec.purpose is not ApprovalPurpose.CONTAINMENT:
            return None
        kind = TargetKind(target_kind)
        t = target.strip()
        if kind is TargetKind.DOMAIN:
            return self._domain_reason(t)
        if kind is TargetKind.URL:
            if t in self._urls:
                return f"allowlists.never_block.urls: {t}"
            host = (urlsplit(t if "://" in t else f"//{t}").hostname or "").lower()
            if not host:
                return None
            reason = self._domain_reason(host)
            if reason and _domain_matches(host, self._url_ok):
                return None  # URL-level blocks allowed on owned domains
            return reason
        if kind is TargetKind.IP:
            try:
                ip = ipaddress.ip_address(t)
            except ValueError:
                return None
            if ip in self._ips:
                return f"allowlists.never_block.ips: {t}"
            for net in self._cidrs:
                if ip.version == net.version and ip in net:
                    return f"allowlists.never_block.cidrs: {net}"
            return None
        if kind is TargetKind.HASH:
            if t.lower() in self._hashes:
                return f"allowlists.never_block.hashes: {t.lower()}"
            return self._tool_hash(t)
        if kind is TargetKind.USER:
            if t.lower() in self._users:
                return f"allowlists.never_block.users: {t.lower()}"
            return None
        if kind is TargetKind.ENDPOINT:
            if t.upper() in self._endpoints:
                return f"allowlists.never_block.endpoints: {t.upper()}"
            return None
        if kind in (TargetKind.FILE, TargetKind.PROCESS):
            endpoint, rest = _split_composite(t)
            if endpoint.upper() in self._endpoints:
                return f"allowlists.never_block.endpoints: {endpoint.upper()}"
            if rest and rest.lower() in self._hashes:
                return f"allowlists.never_block.hashes: {rest.lower()}"
            return self._tool_hash(rest) if rest else None
        return None


class DisclosurePolicy:
    """Decides whether an observable may be sent to a third-party lookup service.

    Restrictions apply to :data:`THIRD_PARTY_INTEGRATIONS` (VirusTotal, OTX, HIBP); internal tools
    (Cisco, Microsoft, Splunk) may always receive observables. Non-public IPs, internal domains,
    hostnames, endpoint ids, processes, file paths, MAC addresses, message ids and user names are
    never disclosed. HIBP only ever receives email addresses. ``allow_documentation_ranges`` treats
    the RFC 5737/3849 documentation ranges as public (tests and lab only).
    """

    _NEVER = frozenset({
        ObservableType.HOSTNAME, ObservableType.ENDPOINT_ID, ObservableType.PROCESS,
        ObservableType.FILE_PATH, ObservableType.EMAIL_MESSAGE_ID, ObservableType.MAC_ADDRESS,
        ObservableType.USER,
    })

    def __init__(self, config: ExclusionsConfig, *, allow_documentation_ranges: bool = False) -> None:
        tpl = config.third_party_lookup
        self._suffixes = tuple(tpl.get("internal_domain_suffixes", [])) + _BUILTIN_INTERNAL_SUFFIXES
        self._internal = tuple(config.internal_domains)
        self._cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in tpl.get("cidrs", []))
        self._user_domains = tuple(tpl.get("user_domains", []))
        self._hostnames = frozenset(h.lower().rstrip(".") for h in tpl.get("hostnames", []))
        self._allow_doc = allow_documentation_ranges

    def _domain_ok(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        if not d or "." not in d:
            return False  # single-label names are internal hostnames
        if d in self._hostnames:
            return False
        if _domain_matches(d, self._internal) or _domain_matches(d, self._suffixes):
            return False
        return True

    def _ip_ok(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        for net in self._cidrs:
            if ip.version == net.version and ip in net:
                return False
        if self._allow_doc and any(ip.version == n.version and ip in n for n in DOCUMENTATION_NETWORKS):
            return True
        return ip.is_global and not ip.is_multicast

    def may_disclose(self, observable: Observable, integration: str) -> bool:
        if integration not in THIRD_PARTY_INTEGRATIONS:
            return True
        t, v = observable.type, observable.value.strip()
        if integration == "hibp":
            if t is not ObservableType.EMAIL_ADDRESS:
                return False
            domain = v.rpartition("@")[2]
            return bool(domain) and not _domain_matches(domain, self._user_domains)
        if t in self._NEVER or t is ObservableType.EMAIL_ADDRESS:
            return False
        if t in (ObservableType.IP, ObservableType.IPV6):
            return self._ip_ok(v)
        if t is ObservableType.DOMAIN:
            return self._domain_ok(v)
        if t is ObservableType.URL:
            try:
                host = urlsplit(v if "://" in v else f"//{v}").hostname or ""
            except ValueError:
                return False
            try:
                ipaddress.ip_address(host)
                return self._ip_ok(host)
            except ValueError:
                return self._domain_ok(host)
        if t in (ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5):
            return True
        return False
