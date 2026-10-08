"""Subject building and normalization (architecture 14.1.3 step 1)."""
from __future__ import annotations

import pytest

from tests.unit.atomics.enrichment._support import FAKE_MD5, FAKE_SHA1, FAKE_SHA256
from xdr_response.atomics.enrichment._subjects import build_subject, normalize_value
from xdr_response.models import Observable, ObservableType

_O = ObservableType
IP_TYPES = frozenset({_O.IP, _O.IPV6})
HASH_TYPES = frozenset({_O.SHA256, _O.SHA1, _O.MD5})
ENDPOINT_TYPES = frozenset({_O.HOSTNAME, _O.ENDPOINT_ID})


@pytest.mark.parametrize(("otype", "raw", "expected"), [
    (_O.IP, " 203.0.113.10 ", "203.0.113.10"),
    (_O.IPV6, "2001:DB8:0:0::1", "2001:db8::1"),
    (_O.DOMAIN, "Bad.Example.TEST.", "bad.example.test"),
    (_O.DOMAIN, "bücher.example", "xn--bcher-kva.example"),
    (_O.URL, "  https://Bad.Example.test/Path?q=1 ", "https://Bad.Example.test/Path?q=1"),
    (_O.URL, "bad.example.test/landing", "bad.example.test/landing"),
    (_O.SHA256, FAKE_SHA256.upper(), FAKE_SHA256),
    (_O.SHA1, FAKE_SHA1, FAKE_SHA1),
    (_O.MD5, FAKE_MD5.upper(), FAKE_MD5),
    (_O.EMAIL_ADDRESS, "JSmith@Example.COM", "jsmith@example.com"),
    (_O.USER, "JSmith@Example.com", "jsmith@example.com"),
    (_O.HOSTNAME, "th-lt-1047", "TH-LT-1047"),
    (_O.ENDPOINT_ID, " 0f1e2d3c-aaaa-bbbb-cccc-000000000001 ", "0f1e2d3c-aaaa-bbbb-cccc-000000000001"),
])
def test_values_are_normalized_per_type(otype, raw, expected):
    assert normalize_value(otype, raw) == expected


@pytest.mark.parametrize(("otype", "raw"), [
    (_O.IP, "999.0.0.1"), (_O.IP, "2001:db8::1"), (_O.IPV6, "203.0.113.10"), (_O.IP, "not-an-ip"),
    (_O.DOMAIN, "bad example.test"), (_O.DOMAIN, "bad.example.test/path"), (_O.DOMAIN, "203.0.113.10"),
    (_O.DOMAIN, "-bad.example.test"), (_O.DOMAIN, "a" * 64 + ".example.test"), (_O.DOMAIN, "*.example.test"),
    (_O.URL, "javascript:alert(1)"), (_O.URL, "https://"), (_O.URL, "https://bad example.test/"),
    (_O.URL, "https://" + "a" * 5000 + ".example.test/"),
    (_O.SHA256, FAKE_SHA1), (_O.SHA256, "z" * 64), (_O.MD5, FAKE_SHA256),
    (_O.EMAIL_ADDRESS, "jsmith"), (_O.EMAIL_ADDRESS, "@example.com"), (_O.EMAIL_ADDRESS, "jsmith@example"),
    (_O.EMAIL_ADDRESS, "j smith@example.com"),
    (_O.USER, "j smith"), (_O.USER, "\x00jsmith"),
    (_O.HOSTNAME, "TH-LT 1047"), (_O.HOSTNAME, "TH-LT-1047/C$"), (_O.ENDPOINT_ID, "id with space"),
])
def test_invalid_values_raise_value_error(otype, raw):
    with pytest.raises(ValueError):
        normalize_value(otype, raw)


def test_error_messages_never_echo_the_value():
    with pytest.raises(ValueError) as info:
        normalize_value(_O.EMAIL_ADDRESS, "private person@example.com")
    assert "private" not in str(info.value)


@pytest.mark.parametrize("otype", [_O.MAC_ADDRESS, _O.EMAIL_MESSAGE_ID, _O.PROCESS, _O.FILE_PATH])
def test_types_without_an_enrichment_atomic_are_refused(otype):
    with pytest.raises(ValueError, match="no enrichment atomic"):
        normalize_value(otype, "x")


def test_non_string_values_are_refused():
    with pytest.raises(ValueError):
        normalize_value(_O.DOMAIN, 42)  # type: ignore[arg-type]


@pytest.mark.parametrize(("raw", "otype"), [("203.0.113.10", _O.IP), ("2001:db8::1", _O.IPV6)])
def test_ip_strings_pick_the_type_by_version(raw, otype):
    assert build_subject(raw, IP_TYPES, _O.IP).type is otype


@pytest.mark.parametrize(("raw", "otype"), [(FAKE_SHA256, _O.SHA256), (FAKE_SHA1, _O.SHA1), (FAKE_MD5, _O.MD5)])
def test_hash_strings_pick_the_type_by_length(raw, otype):
    subject = build_subject(f" {raw.upper()} ", HASH_TYPES, _O.SHA256)
    assert (subject.type, subject.value) == (otype, raw)


def test_hash_strings_of_another_length_are_refused():
    with pytest.raises(ValueError, match="hash length"):
        build_subject("ab" * 10, HASH_TYPES, _O.SHA256)


def test_endpoint_strings_are_hostnames():
    assert build_subject("th-lt-1047", ENDPOINT_TYPES, _O.HOSTNAME) == Observable(type=_O.HOSTNAME,
                                                                                 value="TH-LT-1047")


def test_observables_keep_their_type_and_lose_their_source():
    observable = Observable(type=_O.ENDPOINT_ID, value="mde-0001", source="defender_endpoint")
    assert build_subject(observable, ENDPOINT_TYPES, _O.HOSTNAME) == Observable(type=_O.ENDPOINT_ID,
                                                                                 value="mde-0001")


def test_observables_of_an_unaccepted_type_are_refused():
    with pytest.raises(ValueError, match="not accepted"):
        build_subject(Observable(type=_O.DOMAIN, value="bad.example.test"), IP_TYPES, _O.IP)


def test_observable_value_must_match_its_declared_hash_type():
    with pytest.raises(ValueError):
        build_subject(Observable(type=_O.SHA1, value=FAKE_SHA256), HASH_TYPES, _O.SHA256)


@pytest.mark.parametrize("bad", ["", "   ", None, 7])
def test_empty_or_non_string_subjects_are_refused(bad):
    with pytest.raises(ValueError):
        build_subject(bad, IP_TYPES, _O.IP)  # type: ignore[arg-type]
