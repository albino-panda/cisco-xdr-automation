"""Central redaction used by both logging and the audit trail.

Nothing that looks like a secret (registered secret values, bearer/basic credentials, JWT-shaped
strings, approval tokens, values under sensitive keys) leaves the process through a log line or an
audit record.

Text redaction (:meth:`Redactor.redact_text`) applies, in order: registered secret values, JWTs,
encoded approval tokens (``base64url(claims).key_id.signature`` for every legal key id),
``<scheme> <credential>`` with a case-insensitive scheme (Bearer, Basic, Splunk, ApiKey; RFC 7235),
and every ``key=value`` / ``key: value`` pair whose key is sensitive by :data:`SENSITIVE_KEY_PATTERN`,
with optional single or double quotes around the key and the value. The last rule covers JSON text
(``"access_token":"..."``), Python dict reprs (``'password': '...'``), headers echoed in vendor
error bodies and URL query strings inside free text (``?key=...``, ``&sig=...``), so text and
:meth:`Redactor.redact_url` agree on which query parameters are secret. Two more forms common in
vendor error bodies are covered: escaped JSON pairs inside a JSON string
(a backslash before every quote of a ``"password": "..."`` pair) and XML elements of sensitive
keys (``<sessionKey>...</sessionKey>``).

Registered secrets are also matched in their JSON-escaped forms (backslash-u unicode escapes
under the default ``ensure_ascii`` and backslash-escaped slashes), because vendors echo
credentials inside JSON.
:meth:`Redactor.redact_body` parses JSON bodies (recursively decoding string values that are JSON
themselves) and redacts the structure before the text rules run.
"""
from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from enum import Enum
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from pydantic import BaseModel, SecretBytes, SecretStr

__all__ = ["REDACTED", "SENSITIVE_KEY_PATTERN", "Redactor", "get_redactor", "normalize_key"]

REDACTED = "[REDACTED]"

#: Matched (``fullmatch``, case-insensitive) against keys normalized by :func:`normalize_key`
#: (camelCase -> snake_case). Exact-only terms: authorization, proxy-authorization, cookie,
#: set-cookie, key, session, credential(s), signature, sig (Azure SAS URL signature). Suffix terms
#: (also "<prefix>_<term>" or "<prefix>-<term>"): password, passwd, passphrase, secret,
#: client_secret, secret_key, token, access_token, refresh_token, id_token, session_token,
#: session_key / sessionKey (Splunk), session_id, signing_key (APPROVAL_SIGNING_KEY),
#: recovery_key / recovery_password (BitLocker), secret_access_key, api_key / apikey / api-key
#: (covers x-apikey, x-api-key, hibp-api-key, x-otx-api-key, x-cisco-meraki-api-key), private_key,
#: approval_token, unlock_code. "idempotency_key", "control_key", "token_id", "params_hash" are NOT
#: sensitive.
SENSITIVE_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie|key|session|credentials?|signature|sig"
    r"|(?:.*[-_.])?(?:password|passwd|passphrase|secret|client[-_]secret|secret[-_]key|token"
    r"|access[-_]token|refresh[-_]token|id[-_]token|session[-_]token|session[-_]?(?:key|id)"
    r"|signing[-_]key|recovery[-_](?:key|password)|secret[-_]access[-_]key|api[-_]?key|private[-_]key"
    r"|approval[-_]token|unlock[-_]code))",
    re.IGNORECASE,
)

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
#: ``<scheme> <credential>``: the scheme is case-insensitive (RFC 7235: ``basic``, ``BASIC``, ...).
_BEARER = re.compile(
    r"(?i)\b(bearer|basic|splunk|apikey)\s+([A-Za-z0-9._~+/=\-]{8,})"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")
#: Encoded approval token ``base64url(canonical claims).key_id.signature`` for every legal key id
#: (``[A-Za-z0-9_-]{1,64}``) and the 64 hex HMAC signature.
_APPROVAL_TOKEN = re.compile(r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{1,64}\.[0-9a-fA-F]{64}(?![0-9A-Za-z])")
#: ``key = value`` / ``key: value`` with optional quotes around the key and the value (JSON text,
#: Python dict reprs, headers, query strings). The value is replaced only when the key is sensitive.
#: Only the key and separator are consumed; the value is captured in a lookahead so that a value
#: of a non-sensitive key (for example a URL after "https:") is still scanned for nested pairs.
_KV = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?P<kq>["']?)(?P<key>[A-Za-z][A-Za-z0-9_.\-]{0,63})(?P=kq)\s*[=:]\s*"""
    r"""(?=(?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s&,;"'}\])]+))"""
)
#: ``\"key\": \"value\"`` (a JSON document serialized into a JSON string value).
_KV_ESCAPED = re.compile(
    r"""\\+["'](?P<key>[A-Za-z][A-Za-z0-9_.\-]{0,63})\\+["']\s*[=:]\s*\\+["'](?P<value>(?:(?!\\+["']).)*)\\+["']"""
)
#: ``<key attr="...">value</key>`` (XML bodies, for example Splunk's ``<sessionKey>``).
_XML_ELEMENT = re.compile(
    r"<(?P<tag>(?:[A-Za-z_][\w.\-]*:)?(?P<local>[A-Za-z_][\w.\-]{0,63}))(?P<attrs>\s[^<>]*)?>"
    r"(?P<value>[^<]*)</(?P=tag)\s*>"
)
#: Bare values after an authorization key that are only the auth scheme (the credential after the
#: scheme is handled by ``_BEARER``).
_AUTH_SCHEMES = frozenset({"bearer", "basic", "splunk", "apikey", "token", "digest", "negotiate"})
_MIN_SECRET_LEN = 6


def normalize_key(key: str) -> str:
    """camelCase -> snake_case, stripped, lower-cased."""
    return _CAMEL.sub("_", str(key).strip()).lower()


class Redactor:
    def __init__(self, extra_keys: Iterable[str] = ()) -> None:
        self._extra = {normalize_key(k) for k in extra_keys}
        self._secrets: set[str] = set()
        self._lock = threading.Lock()
        self._secret_re: re.Pattern[str] | None = None

    # ---------------------------------------------------------------- setup --
    def register_secret(self, value: str) -> None:
        """Remember a secret value so it is scrubbed from any text. Values < 6 chars are ignored.

        The JSON-escaped forms of the value are registered too (``ensure_ascii`` unicode escapes,
        backslash-escaped slashes and both), so a credential a vendor echoes inside a JSON error body
        is still recognised.
        """
        if not isinstance(value, str) or len(value) < _MIN_SECRET_LEN:
            return
        variants = {value}
        for ascii_only in (True, False):
            escaped = json.dumps(value, ensure_ascii=ascii_only)[1:-1]
            variants.add(escaped)
            variants.add(escaped.replace("/", "\\/"))
        with self._lock:
            if variants <= self._secrets:
                return
            self._secrets.update(v for v in variants if len(v) >= _MIN_SECRET_LEN)
            ordered = sorted(self._secrets, key=len, reverse=True)
            self._secret_re = re.compile("|".join(re.escape(s) for s in ordered))

    def is_sensitive_key(self, key: str) -> bool:
        if not isinstance(key, str):
            return False
        nk = normalize_key(key)
        return bool(SENSITIVE_KEY_PATTERN.fullmatch(nk)) or nk in self._extra

    # ------------------------------------------------------------ redaction --
    def redact(self, value: Any) -> Any:
        """Deep-copied, redacted version of ``value``."""
        return self._redact(value, 0)

    def _redact(self, value: Any, depth: int) -> Any:
        if depth > 64:
            return REDACTED
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if _is_secret_object(value):
            return REDACTED
        if isinstance(value, Enum):
            return value
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, (bytes, bytearray)):
            return REDACTED
        if isinstance(value, (datetime, date)):
            return value
        if isinstance(value, BaseModel):
            return self._redact(value.model_dump(mode="json"), depth + 1)
        if isinstance(value, Mapping):
            out: dict[Any, Any] = {}
            for k, v in value.items():
                if isinstance(k, str) and self.is_sensitive_key(k) and v is not None:
                    out[k] = REDACTED
                else:
                    out[k] = self._redact(v, depth + 1)
            return out
        if isinstance(value, tuple):
            return tuple(self._redact(v, depth + 1) for v in value)
        if isinstance(value, list):
            return [self._redact(v, depth + 1) for v in value]
        if isinstance(value, (set, frozenset)):
            return [self._redact(v, depth + 1) for v in value]
        # unknown object: never trust its str() blindly
        return self.redact_text(repr(value))

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        if not text:
            return text
        pattern = self._secret_re
        if pattern is not None:
            text = pattern.sub(REDACTED, text)
        text = _JWT.sub(REDACTED, text)
        text = _APPROVAL_TOKEN.sub(REDACTED, text)
        text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
        text = _KV_ESCAPED.sub(self._escaped_pair, text)
        text = _XML_ELEMENT.sub(self._xml_element, text)
        return self._redact_pairs(text)

    def _escaped_pair(self, match: re.Match[str]) -> str:
        if not self.is_sensitive_key(match.group("key")) or match.group("value").startswith("[REDACTED"):
            return match.group(0)
        start, end = match.span("value")
        whole_start = match.start()
        return match.group(0)[: start - whole_start] + REDACTED + match.group(0)[end - whole_start:]

    def _xml_element(self, match: re.Match[str]) -> str:
        if not self.is_sensitive_key(match.group("local")) or not match.group("value").strip():
            return match.group(0)
        start, end = match.span("value")
        whole_start = match.start()
        return match.group(0)[: start - whole_start] + REDACTED + match.group(0)[end - whole_start:]

    def redact_body(self, text: str) -> str:
        """Redact a vendor response body: structured JSON redaction first, then the text rules.

        A JSON body is parsed, string values that are JSON documents themselves are decoded
        (recursively), sensitive keys are replaced at every level, and the result is serialized
        again before :meth:`redact_text` runs. Non-JSON bodies (XML, HTML, text) go to the text
        rules directly.
        """
        if not isinstance(text, str):
            text = str(text)
        stripped = text.strip()
        if stripped[:1] in ("{", "["):
            try:
                parsed = json.loads(stripped)
            except ValueError:
                parsed = None
            if parsed is not None:
                decoded = _decode_nested_json(parsed, 0)
                text = json.dumps(self.redact(decoded), ensure_ascii=False, default=str)
        return self.redact_text(text)

    def _redact_pairs(self, text: str) -> str:
        """Replace the value of every sensitive ``key=value`` / ``"key": "value"`` pair in ``text``."""
        spans: list[tuple[int, int, str]] = []
        last_end = -1
        for match in _KV.finditer(text):
            start, end = match.span("value")
            if start < last_end or not self.is_sensitive_key(match.group("key")):
                continue
            value = match.group("value")
            if value[0] in "\"'":
                replacement = f"{value[0]}{REDACTED}{value[0]}"
            elif value.startswith("[REDACTED"):
                continue
            elif value.lower() in _AUTH_SCHEMES and "authorization" in normalize_key(match.group("key")):
                continue  # "Authorization: Bearer [REDACTED]": the credential is handled by _BEARER
            else:
                replacement = REDACTED
            spans.append((start, end, replacement))
            last_end = end
        if not spans:
            return text
        out: list[str] = []
        cursor = 0
        for start, end, replacement in spans:
            out.append(text[cursor:start])
            out.append(replacement)
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    def redact_url(self, url: str) -> str:
        """Remove userinfo and replace values of sensitive query keys."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return self.redact_text(url)
        netloc = parts.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        query = parts.query
        if query:
            pairs = []
            for pair in query.split("&"):
                if not pair:
                    continue
                k, sep, v = pair.partition("=")
                if self.is_sensitive_key(unquote_plus(k)):
                    pairs.append(f"{k}={REDACTED}")
                else:
                    pairs.append(f"{k}{sep}{v}")
            query = "&".join(pairs)
        rebuilt = urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
        return self.redact_text(rebuilt)

    def redact_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        return {
            str(k): (REDACTED if self.is_sensitive_key(str(k)) else self.redact_text(str(v)))
            for k, v in headers.items()
        }


def _decode_nested_json(value: Any, depth: int) -> Any:
    """Decode string values that are JSON documents (or end with one) into structures."""
    if depth > 16:
        return value
    if isinstance(value, dict):
        return {k: _decode_nested_json(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_nested_json(v, depth + 1) for v in value]
    if isinstance(value, str):
        candidate = value.strip()
        for start in (0, *(i for i, ch in enumerate(candidate) if ch in "{[" and i > 0)):
            chunk = candidate[start:]
            if chunk[:1] not in ("{", "["):
                continue
            try:
                inner = json.loads(chunk)
            except ValueError:
                continue
            if isinstance(inner, (dict, list)):
                decoded = _decode_nested_json(inner, depth + 1)
                return decoded if start == 0 else {"text": candidate[:start], "json": decoded}
            break
    return value


def _is_secret_object(value: Any) -> bool:
    if isinstance(value, (SecretStr, SecretBytes)):
        return True
    # SecretValue lives in xdr_response.secrets (higher layer); detect it structurally
    return type(value).__name__ == "SecretValue" and hasattr(value, "reveal")


_DEFAULT: Redactor | None = None
_DEFAULT_LOCK = threading.Lock()


def get_redactor() -> Redactor:
    """Process-wide default redactor (secret providers register values here)."""
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = Redactor()
    return _DEFAULT
