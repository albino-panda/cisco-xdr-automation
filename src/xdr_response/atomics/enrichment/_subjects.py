"""Subject parsing and normalization for the enrichment atomics (architecture 14.1.3 step 1).

Every enrichment atomic first turns its caller input (a ``str`` or an :class:`Observable`) into one
normalized :class:`Observable`. Invalid input is a caller bug and raises ``ValueError``; the message
names the expected kind but never echoes the value (it may be personal data).

Normalization follows :func:`xdr_response.models.normalize_target` for the matching target kind
(hostnames upper case, users, email addresses, domains and hashes lower case, IPs compressed) so
record ids, correlation entities and containment targets agree on the same spelling.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from urllib.parse import urlsplit

from xdr_response.config.policy import ends_in_number
from xdr_response.models import ObservableType, Observable

__all__ = ["HASH_TYPES_BY_LENGTH", "build_subject", "normalize_value"]

_O = ObservableType

#: Hex digest length -> hash observable type (``enrich_hash`` picks the type by length).
HASH_TYPES_BY_LENGTH: Mapping[int, ObservableType] = MappingProxyType({64: _O.SHA256, 40: _O.SHA1, 32: _O.MD5})

_MAX_LENGTH: Mapping[ObservableType, int] = MappingProxyType({
    _O.URL: 4096, _O.DOMAIN: 253, _O.HOSTNAME: 255, _O.ENDPOINT_ID: 256, _O.USER: 256, _O.EMAIL_ADDRESS: 320,
})
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_WHITESPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
_HOST_FORBIDDEN = frozenset("/\\@:")
_URL_SCHEMES = frozenset({"http", "https", "ftp", "ftps"})


def _invalid(kind: str) -> ValueError:
    return ValueError(f"invalid {kind} value for enrichment")


def _check_length(observable_type: ObservableType, value: str) -> None:
    limit = _MAX_LENGTH.get(observable_type)
    if limit is not None and len(value) > limit:
        raise ValueError(f"{observable_type.value} value longer than {limit} characters")


def _no_whitespace(value: str, kind: str) -> str:
    if not value or _WHITESPACE_RE.search(value):
        raise _invalid(kind)
    return value


def _ascii_domain(value: str) -> str:
    """Lower-case ASCII (punycode) form of a domain name, without a trailing dot."""
    v = value.strip().lower().rstrip(".")
    if not v.isascii():
        try:
            v = v.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise _invalid("domain") from exc
    return v


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _domain(value: str) -> str:
    v = _ascii_domain(value)
    _check_length(_O.DOMAIN, v)
    # A numeric (or 0x hex) last label makes every resolver read the name as an IPv4 literal
    # (10.0.258, 10.1.2.03, 0x0a.0.0.1): it is never a domain, whatever the spelling.
    if not _DOMAIN_RE.match(v) or _is_ip(v) or ends_in_number(v):
        raise _invalid("domain")
    return v


def _ip(value: str, expected: ObservableType) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise _invalid("IP address") from exc
    actual = _O.IP if ip.version == 4 else _O.IPV6
    if actual is not expected:
        raise ValueError(f"value is an IPv{ip.version} address, not {expected.value}")
    return ip.compressed


def _hash(value: str, expected: ObservableType) -> str:
    v = value.strip().lower()
    if not _HEX_RE.match(v) or HASH_TYPES_BY_LENGTH.get(len(v)) is not expected:
        raise _invalid(expected.value)
    return v


def _url(value: str) -> str:
    v = _no_whitespace(value.strip(), "URL")
    _check_length(_O.URL, v)
    try:
        parts = urlsplit(v if "://" in v else f"//{v}")
        host = parts.hostname or ""
        _ = parts.port  # a non-numeric "port" (for example "javascript:...") raises ValueError
    except ValueError as exc:
        raise _invalid("URL") from exc
    if parts.scheme and parts.scheme.lower() not in _URL_SCHEMES:
        raise _invalid("URL")
    if not host or not (_is_ip(host) or _DOMAIN_RE.match(_ascii_domain(host))):
        raise _invalid("URL")
    return v


def _email(value: str) -> str:
    v = _no_whitespace(value.strip().lower(), "email address")
    _check_length(_O.EMAIL_ADDRESS, v)
    local, at, domain = v.rpartition("@")
    if not at or not local or "@" in local or "." not in domain:
        raise _invalid("email address")
    return f"{local}@{_domain(domain)}"


def _user(value: str) -> str:
    v = _no_whitespace(value.strip().lower(), "user")
    _check_length(_O.USER, v)
    return v


def _hostname(value: str) -> str:
    v = _no_whitespace(value.strip().rstrip(".").upper(), "hostname")
    _check_length(_O.HOSTNAME, v)
    if _HOST_FORBIDDEN & set(v):
        raise _invalid("hostname")
    return v


def _endpoint_id(value: str) -> str:
    v = _no_whitespace(value.strip(), "endpoint id")
    _check_length(_O.ENDPOINT_ID, v)
    return v


_NORMALIZERS: Mapping[ObservableType, Callable[[str], str]] = MappingProxyType({
    _O.IP: lambda v: _ip(v, _O.IP),
    _O.IPV6: lambda v: _ip(v, _O.IPV6),
    _O.DOMAIN: _domain,
    _O.URL: _url,
    _O.SHA256: lambda v: _hash(v, _O.SHA256),
    _O.SHA1: lambda v: _hash(v, _O.SHA1),
    _O.MD5: lambda v: _hash(v, _O.MD5),
    _O.EMAIL_ADDRESS: _email,
    _O.USER: _user,
    _O.HOSTNAME: _hostname,
    _O.ENDPOINT_ID: _endpoint_id,
})


def normalize_value(observable_type: ObservableType, value: str) -> str:
    """Normalized ``value`` for ``observable_type``; ``ValueError`` when invalid or unsupported."""
    if not isinstance(value, str):
        raise ValueError("observable value must be a string")
    normalizer = _NORMALIZERS.get(ObservableType(observable_type))
    if normalizer is None:
        raise ValueError(f"no enrichment atomic accepts {ObservableType(observable_type).value} observables")
    return normalizer(value)


def _type_for_text(value: str, accepted: frozenset[ObservableType], default: ObservableType) -> ObservableType:
    """Observable type for a plain string given to an atomic accepting ``accepted`` types."""
    v = value.strip()
    if default in (_O.IP, _O.IPV6):
        try:
            return _O.IP if ipaddress.ip_address(v).version == 4 else _O.IPV6
        except ValueError as exc:
            raise _invalid("IP address") from exc
    if default in HASH_TYPES_BY_LENGTH.values():
        picked = HASH_TYPES_BY_LENGTH.get(len(v))
        if picked is None or picked not in accepted:
            raise ValueError("hash length must be 64 (sha256), 40 (sha1) or 32 (md5) hex characters")
        return picked
    return default


def build_subject(value: str | Observable, accepted: frozenset[ObservableType],
                  default: ObservableType) -> Observable:
    """The normalized subject :class:`Observable` of one atomic call.

    A ``str`` gets ``default`` (IPs pick ``ip``/``ipv6`` by version, hashes pick sha256 / sha1 /
    md5 by length); an :class:`Observable` must have one of the ``accepted`` types. The result never
    carries the caller's ``source`` so the same observable always yields the same subject.
    """
    if isinstance(value, Observable):
        observable_type, raw = value.type, value.value
        if observable_type not in accepted:
            names = ", ".join(sorted(t.value for t in accepted))
            raise ValueError(f"{observable_type.value} observables are not accepted here (expected {names})")
    elif isinstance(value, str):
        if not value.strip():
            raise ValueError("observable value must not be empty")
        observable_type, raw = _type_for_text(value, accepted, default), value
    else:
        raise ValueError("subject must be a str or an Observable")
    return Observable(type=observable_type, value=normalize_value(observable_type, raw))
