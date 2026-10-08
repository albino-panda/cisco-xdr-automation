"""Deterministic config-driven policies: allow-lists and third-party disclosure."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, unquote_plus, urlsplit

from xdr_response.config.schema import AllowlistsConfig, ExclusionsConfig
from xdr_response.logs.redaction import get_redactor
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import ApprovalPurpose, ObservableType, TargetKind
from xdr_response.models.canonical import canonical_url, endpoint_names
from xdr_response.models.observable import Observable

__all__ = ["AllowlistPolicy", "DisclosurePolicy", "THIRD_PARTY_INTEGRATIONS", "DOCUMENTATION_NETWORKS",
           "NON_PUBLIC_NETWORKS", "embedded_ipv4", "ends_in_number", "host_ip", "non_public_network",
           "parse_ipv4_literal"]

#: Integrations that send observables outside the organization.
THIRD_PARTY_INTEGRATIONS = frozenset({"virustotal", "alienvault_otx", "hibp"})

#: RFC 5737 / RFC 3849 documentation ranges (only treated as public with allow_documentation_ranges).
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

_BUILTIN_INTERNAL_SUFFIXES = ("local", "localhost", "internal", "lan", "home.arpa", "intranet", "corp")

#: Address ranges that are always the organisation's own (or nobody's) network, never edge-blockable
#: attacker infrastructure: RFC 1918 private, carrier-grade NAT (RFC 6598, VPN pools), loopback,
#: link-local, "this network", multicast and reserved, IPv6 unspecified, loopback, unique local,
#: link-local, site-local and multicast. The RFC 5737 / 3849 documentation ranges are deliberately
#: absent (lab and test data use them as public addresses).
NON_PUBLIC_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10",
        "ff00::/8"))

#: RFC 6052 NAT64 well-known prefix and RFC 8215 local-use prefix (the stdlib registry counts the
#: first as global).
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
#: RFC 4291 deprecated IPv4-compatible addresses (``::a.b.c.d``) and RFC 2765 IPv4-translated
#: addresses (``::ffff:0:a.b.c.d``).
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")
_IPV4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")
_HEX_LABEL = re.compile(r"0[xX][0-9a-fA-F]*")
_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_PARAM_KEY = re.compile(r"(?:^|[?&;#/])([^=&;#?/]+)=")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def embedded_ipv4(ip: IPAddress) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses carried inside an IPv6 address.

    IPv4-mapped (``::ffff:a.b.c.d``), IPv4-translated (``::ffff:0:a.b.c.d``), IPv4-compatible
    (``::a.b.c.d``), NAT64 (``64:ff9b::/96`` and the local-use ``64:ff9b:1::/48``, low 32 bits),
    6to4 and Teredo (both the server and the client address).
    """
    if ip.version != 6:
        return []
    assert isinstance(ip, ipaddress.IPv6Address)
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip in _IPV4_TRANSLATED or ip in _IPV4_COMPATIBLE or any(ip in n for n in _NAT64):
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)
    return list(dict.fromkeys(found))


_embedded_ipv4 = embedded_ipv4  # pre-round-2 name


def ends_in_number(host: str) -> bool:
    """True when the last label of ``host`` (one trailing dot ignored) is numeric or ``0x`` hex.

    Browsers and resolvers (WHATWG URL host parsing, ``inet_aton``) read such a host as an IPv4
    address, never as a domain name: ``10.0.258``, ``0x0a.0.0.1``, ``10.1.2.03``, ``127.1``.
    """
    labels = host.strip().split(".")
    if len(labels) > 1 and labels[-1] == "":
        labels.pop()
    last = labels[-1] if labels else ""
    return bool(last) and last.isascii() and (last.isdigit() or bool(_HEX_LABEL.fullmatch(last)))


def parse_ipv4_literal(host: str) -> ipaddress.IPv4Address | None:
    """The IPv4 address a lenient parser reads from ``host`` (WHATWG IPv4 parser), else None.

    Accepts one trailing dot, one to four parts, decimal, octal (leading ``0``) and hex (``0x``)
    parts, and a last part that fills the remaining bytes (``10.0.258`` is ``10.0.1.2``).
    """
    parts = host.strip().split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if not 1 <= len(parts) <= 4:
        return None
    numbers: list[int] = []
    for part in parts:
        if not part or not part.isascii():
            return None
        try:
            if part[:2].lower() == "0x":
                numbers.append(int(part[2:], 16) if part[2:] else 0)
            elif len(part) > 1 and part.startswith("0"):
                numbers.append(int(part[1:], 8))
            elif part.isdigit():
                numbers.append(int(part))
            else:
                return None
        except ValueError:
            return None
    *head, last = numbers
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(numbers)):
        return None
    value = last
    for index, n in enumerate(head):
        value += n << (8 * (3 - index))
    return ipaddress.IPv4Address(value)


def host_ip(host: str) -> IPAddress | None:
    """The IP address ``host`` denotes (strict IPv4 / IPv6, or a lenient IPv4 literal), else None."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    return parse_ipv4_literal(h) if ends_in_number(h) else None


def non_public_network(value: str | IPAddress,
                       extra: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
                       ) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The non-public network (:data:`NON_PUBLIC_NETWORKS`, then ``extra``) containing ``value`` or an
    IPv4 address it carries (IPv4-mapped, NAT64, 6to4, Teredo ...), else None (also for a non-IP)."""
    if isinstance(value, str):
        ip = host_ip(value)
        if ip is None:
            return None
    else:
        ip = value
    for candidate in (ip, *embedded_ipv4(ip)):
        for net in (*NON_PUBLIC_NETWORKS, *extra):
            if candidate.version == net.version and candidate in net:
                return net
    return None


def _domain_matches(domain: str, candidates: list[str] | tuple[str, ...]) -> str | None:
    d = domain.lower().rstrip(".")
    for c in candidates:
        c = c.lower().strip().rstrip(".").lstrip("*").lstrip(".")
        if c and (d == c or d.endswith("." + c)):
            return c
    return None


def _signer_key(signer: object) -> str:
    return " ".join(str(signer).split()).casefold() if isinstance(signer, str) else ""


def _split_composite(target: str) -> tuple[str, str]:
    endpoint, _, rest = target.partition("/")
    return endpoint, rest


class AllowlistPolicy:
    """Decides whether a containment target is allow-listed (never blocked, shown as excluded).

    Besides ``never_block`` and the approved tools, the organisation's own network is never blocked:
    an IP target (or a URL whose host is an IP) in a non-public range (:data:`NON_PUBLIC_NETWORKS`,
    plus ``exclusions.third_party_lookup.cidrs`` such as the VPN pool) and a domain target (or URL
    host) under the configured ``exclusions.internal_domains`` / ``internal_domain_suffixes`` /
    ``hostnames``, a built-in internal suffix (``local``, ``internal``, ...) or a single-label name
    are excluded with the reason (``url_block_allowed_domains`` lifts only the ``never_block.domains``
    reason of a URL host, never the internal-domain or approved-tool reason, 14.12.6). Endpoint names match by host identity (a listed short name also
    covers the FQDN with that first label, a listed FQDN its short name, a trailing dot is
    ignored); URLs match in their canonical spelling
    (:func:`~xdr_response.models.canonical.canonical_url`: case of scheme and host, default port,
    trailing dot on the host).
    """

    def __init__(self, config: AllowlistsConfig, *, exclusions: ExclusionsConfig | None = None) -> None:
        nb = config.never_block
        self._domains = tuple(nb.get("domains", []))
        self._urls = frozenset(canonical_url(u) for u in nb.get("urls", []) if u.strip())
        tpl = exclusions.third_party_lookup if exclusions is not None else {}
        self._internal_domains = tuple(exclusions.internal_domains) if exclusions is not None else ()
        self._internal_suffixes = tuple(tpl.get("internal_domain_suffixes", [])) + _BUILTIN_INTERNAL_SUFFIXES
        self._internal_hosts = frozenset(h.strip().lower().rstrip(".") for h in tpl.get("hostnames", []))
        self._own_cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in tpl.get("cidrs", []))
        listed = [ipaddress.ip_address(i) for i in nb.get("ips", [])]
        # An allow-listed IPv4-mapped spelling also lists the IPv4 address it denotes.
        self._ips = frozenset([*listed, *(i.ipv4_mapped for i in listed
                                          if isinstance(i, ipaddress.IPv6Address) and i.ipv4_mapped is not None)])
        self._cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in nb.get("cidrs", []))
        self._hashes = frozenset(h.lower() for h in nb.get("hashes", []))
        self._users = frozenset(u.lower() for u in nb.get("users", []))
        self._endpoints = frozenset(endpoint_names(e)[0] for e in nb.get("endpoints", []) if e.strip())
        self._url_ok = tuple(config.url_block_allowed_domains)
        self._tools: list[tuple[str, str, dict]] = [
            ("approved_rmm", t["name"], t) for t in config.approved_rmm
        ] + [("approved_dns_tools", t["name"], t) for t in config.approved_dns_tools]

    def _endpoint_reason(self, host: str) -> str | None:
        """Reason when ``host`` is a listed endpoint: the same name, a listed short name of a reported
        FQDN, or a reported short name of a listed FQDN (a trailing dot ignored)."""
        full, short = endpoint_names(host)
        if not full:
            return None
        if full in self._endpoints:
            return f"allowlists.never_block.endpoints: {full}"
        if short is not None and short in self._endpoints:
            return f"allowlists.never_block.endpoints: {short} (reported as {full})"
        if short is None:
            for listed in sorted(self._endpoints):
                if endpoint_names(listed)[1] == full:
                    return f"allowlists.never_block.endpoints: {listed} (reported as {full})"
        return None

    def hash_reason(self, sha: str) -> str | None:
        """Reason when a file hash is in ``never_block.hashes`` or belongs to an approved tool, else None."""
        h = sha.strip().lower()
        if not h:
            return None
        if h in self._hashes:
            return f"allowlists.never_block.hashes: {h}"
        return self._tool_hash(h)

    def _ip_reason(self, ip: IPAddress) -> str | None:
        # The address itself and every IPv4 address it carries (IPv4-mapped / translated /
        # compatible, NAT64, 6to4, Teredo): ``::ffff:192.0.2.5`` is the allow-listed 192.0.2.5.
        # The same expansion as DisclosurePolicy, so the two policies agree on what is internal.
        listed = self._listed_ip_reason(ip)
        if listed:
            return listed
        net = non_public_network(ip, self._own_cidrs)
        if net is not None:
            return (f"non-public address {ip.compressed} ({net}): the organisation's own network (private, "
                    "loopback, link-local, carrier-grade NAT / VPN pool or exclusions cidrs), never blocked as "
                    "attacker infrastructure")
        return None

    def address_reason(self, address: str) -> str | None:
        """Reason when an address a host holds is allow-listed infrastructure, else None (14.11.7).

        Only ``never_block.ips`` and ``never_block.cidrs`` count (the address itself and every IPv4
        address it embeds), never the built-in non-public ranges: a workstation's private address is
        not infrastructure. Used by the package builder for actions that take a host off the network
        (isolation): the host carries the listed address, so the action is ELEVATED with a warning.
        """
        try:
            ip = ipaddress.ip_address(str(address).strip())
        except ValueError:
            return None
        return self._listed_ip_reason(ip)

    def _listed_ip_reason(self, ip: IPAddress) -> str | None:
        """``never_block.ips`` / ``never_block.cidrs`` match of the address or an IPv4 address it embeds."""
        for candidate in (ip, *embedded_ipv4(ip)):
            if candidate in self._ips:
                return f"allowlists.never_block.ips: {candidate.compressed}"
            for net in self._cidrs:
                if candidate.version == net.version and candidate in net:
                    return f"allowlists.never_block.cidrs: {net}"
        return None

    def _internal_domain_reason(self, domain: str) -> str | None:
        d = domain.strip().lower().rstrip(".")
        if not d:
            return None
        if d in self._internal_hosts:
            return f"exclusions.third_party_lookup.hostnames: {d} (the organisation's own host)"
        hit = _domain_matches(d, self._internal_domains)
        if hit:
            return f"exclusions.internal_domains: {hit} (the organisation's internal domain)"
        hit = _domain_matches(d, self._internal_suffixes)
        if hit:
            return f"internal domain suffix {hit} (the organisation's internal names are never blocked)"
        if "." not in d:
            return f"single-label name {d} (an internal host name, never blocked)"
        return None

    def _tool_hash(self, h: str) -> str | None:
        for section, name, tool in self._tools:
            if h.lower() in {x.lower() for x in tool.get("hashes", []) or []}:
                return f"allowlists.{section}: {name}"
        return None

    def signer_reason(self, signer: str | None) -> str | None:
        """Reason string when ``signer`` (a code-signing subject a vendor record reports for a file) is a
        signer of an approved tool (``approved_rmm`` / ``approved_dns_tools`` ``signers``), else None.

        Matching ignores case and runs of whitespace; it is exact otherwise (no substring match, so
        "Example RMM Vendor Inc. Clone" is not the approved signer).
        """
        wanted = _signer_key(signer)
        if not wanted:
            return None
        for section, name, tool in self._tools:
            if wanted in {_signer_key(x) for x in tool.get("signers", []) or []}:
                return f"allowlists.{section}: {name} (signer {' '.join(str(signer).split())})"
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
        return self._tool_domain(domain) or self._internal_domain_reason(domain)

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
            if canonical_url(t) in self._urls:
                return f"allowlists.never_block.urls: {t}"
            try:
                host = (urlsplit(t if "://" in t else f"//{t}").hostname or "").lower().rstrip(".")
            except ValueError:
                return None
            if not host:
                return None
            ip = host_ip(host)
            if ip is not None:
                return self._ip_reason(ip)
            if _domain_matches(host, self._url_ok):
                # URL-level blocks are allowed on owned public domains: the exception lifts only the
                # never_block.domains reason. An approved tool's domain and an internal host (an
                # exclusions.internal_domains sub-zone of the owned domain, an internal suffix, a
                # listed host name) stay excluded.
                return self._tool_domain(host) or self._internal_domain_reason(host)
            return self._domain_reason(host)
        if kind is TargetKind.IP:
            try:
                ip = ipaddress.ip_address(t)
            except ValueError:
                return None
            return self._ip_reason(ip)
        if kind is TargetKind.HASH:
            return self.hash_reason(t)
        if kind is TargetKind.USER:
            if t.lower() in self._users:
                return f"allowlists.never_block.users: {t.lower()}"
            return None
        if kind is TargetKind.ENDPOINT:
            return self._endpoint_reason(t)
        if kind in (TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM):
            endpoint, rest = _split_composite(t)
            reason = self._endpoint_reason(endpoint)
            if reason or kind is TargetKind.PERSISTENCE_ITEM:
                return reason
            return self.hash_reason(rest) if rest else None
        return None


class DisclosurePolicy:
    """Decides whether an observable may be sent to a third-party lookup service.

    Restrictions apply to :data:`THIRD_PARTY_INTEGRATIONS` (VirusTotal, OTX, HIBP); internal tools
    (Cisco, Microsoft, Splunk) may always receive observables. Non-public IPs, internal domains,
    hostnames, endpoint ids, processes, file paths, MAC addresses, message ids and user names are
    never disclosed. An IPv6 address that embeds an IPv4 address (IPv4-mapped, IPv4-translated,
    IPv4-compatible, NAT64, 6to4, Teredo) is judged by the embedded address too; deprecated
    site-local ``fec0::/10`` is never public. A host or domain whose last label is numeric or ``0x``
    hex is an IPv4 literal in any spelling (``10.0.258``, ``0x0a.0.0.1``, ``10.1.2.03``, ``127.1``,
    trailing dot) and is judged by the address it denotes. A URL carrying credentials (userinfo),
    a sensitive query or fragment parameter (``sig``, ``token``, ``access_token``,
    ``X-Amz-Signature``, ...) or an email address anywhere in its path, query or fragment is never
    disclosed. HIBP
    only ever receives email addresses, never of an internal domain (``internal_domains``,
    internal suffixes) nor of ``user_domains``. ``allow_documentation_ranges`` treats
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
        if ends_in_number(domain):
            # A numeric (or 0x hex) last label is an IPv4 literal to every resolver, never a domain
            # name: judge it by the address it denotes, refuse it when it denotes none.
            literal = parse_ipv4_literal(domain)
            return literal is not None and self._ip_ok(str(literal))
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
        embedded = embedded_ipv4(ip)
        if embedded:
            # An IPv6 form that carries an IPv4 address is judged by the IPv4 address it carries
            # (an internal 10.x host behind NAT64 is still internal), and the IPv6 form itself.
            if not all(self._ip_ok(str(v4)) for v4 in embedded):
                return False
        return self._single_ip_ok(ip)

    def _single_ip_ok(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        for net in self._cidrs:
            if ip.version == net.version and ip in net:
                return False
        if self._allow_doc and any(ip.version == n.version and ip in n for n in DOCUMENTATION_NETWORKS):
            return True
        if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
            return False  # deprecated site-local fec0::/10 (RFC 3879): the registry calls it global
        return ip.is_global and not ip.is_multicast

    @staticmethod
    def _url_carries_no_secret(netloc: str, query: str, fragment: str = "") -> bool:
        """False for a URL with userinfo (``user:pass@``) or a sensitive parameter key.

        Query and fragment parameters are both checked (an OAuth implicit-flow redirect carries
        ``#access_token=...``), with ``&``, ``;`` and ``/`` as separators, so signed-URL keys such as
        ``X-Amz-Signature``, ``X-Amz-Credential`` and ``X-Goog-Signature`` refuse the URL too.
        """
        if "@" in netloc:
            return False
        redactor = get_redactor()
        for text in (query, fragment):
            if not text:
                continue
            for raw in (text, unquote(text)):
                for match in _PARAM_KEY.finditer(raw):
                    key = unquote_plus(match.group(1)).strip()
                    if key and redactor.is_sensitive_key(key):
                        return False
        return True

    @staticmethod
    def _url_carries_no_mailbox(path: str, query: str, fragment: str) -> bool:
        """False when the path, query or fragment holds an email address (personal data)."""
        for text in (path, query, fragment):
            if text and (_EMAIL_IN_TEXT.search(text) or _EMAIL_IN_TEXT.search(unquote_plus(text))):
                return False
        return True

    def may_disclose(self, observable: Observable, integration: str) -> bool:
        if integration not in THIRD_PARTY_INTEGRATIONS:
            return True
        t, v = observable.type, observable.value.strip()
        if integration == "hibp":
            if t is not ObservableType.EMAIL_ADDRESS:
                return False
            domain = v.rpartition("@")[2]
            # Internal mailboxes (internal_domains, internal suffixes, single-label domains) are
            # never disclosed, exactly as for VirusTotal / OTX; user_domains are refused on top.
            return (bool(domain) and self._domain_ok(domain)
                    and not _domain_matches(domain, self._user_domains))
        if t in self._NEVER or t is ObservableType.EMAIL_ADDRESS:
            return False
        if t in (ObservableType.IP, ObservableType.IPV6):
            return self._ip_ok(v)
        if t is ObservableType.DOMAIN:
            return self._domain_ok(v)
        if t is ObservableType.URL:
            try:
                parts = urlsplit(v if "://" in v else f"//{v}")
                host = parts.hostname or ""
            except ValueError:
                return False
            if not self._url_carries_no_secret(parts.netloc, parts.query, parts.fragment):
                return False
            if not self._url_carries_no_mailbox(parts.path, parts.query, parts.fragment):
                return False
            ip = host_ip(host)
            if ip is not None:
                return self._ip_ok(str(ip))
            if ends_in_number(host):
                return False  # an IPv4-looking host no parser accepts: never guess
            return self._domain_ok(host)
        if t in (ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5):
            return True
        return False
