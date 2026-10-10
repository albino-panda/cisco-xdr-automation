"""Central redaction used by both logging and the audit trail.

Nothing that looks like a secret (registered secret values, bearer/basic credentials, JWT-shaped
strings, approval tokens, values under sensitive keys) leaves the process through a log line or an
audit record.

Text redaction (:meth:`Redactor.redact_text`) applies, in order: registered secret values, JWTs,
encoded approval tokens (``base64url(claims).key_id.signature`` for every legal key id),
``<scheme> <credential>`` with a case-insensitive scheme (Bearer, Basic, Splunk, ApiKey; RFC 7235),
every ``key=value`` / ``key: value`` pair whose key is sensitive by :data:`SENSITIVE_KEY_PATTERN`,
and unlock codes or passcodes phrased in prose (``isolation unlock code: X``, ``unlock code X``,
``unlock code for TH-LT-1047 is X``, ``the code to unlock TH-LT-1047 is X``), with optional single or double quotes around the key and the value. The last rule covers JSON text
(``"access_token":"..."``), Python dict reprs (``'password': '...'``), headers echoed in vendor
error bodies and URL query strings inside free text (``?key=...``, ``&sig=...``), so text and
:meth:`Redactor.redact_url` agree on which query parameters are secret. Two more forms common in
vendor error bodies are covered: escaped JSON pairs inside a JSON string
(a backslash before every quote of a ``"password": "..."`` pair) and XML elements of sensitive
keys (``<sessionKey>...</sessionKey>``).

One-time, verification, security, sign-in, reset and recovery codes are credentials in prose too
(``Your verification code is 482913``, ``Password reset code: 482913``, ``482913 is your sign-in
code``), and so is a password stated in prose (``Your new password is X``, ``temporary password
X``, ``password is X`` when X looks like a credential) unless the word after it is an ordinary
status word (``password is expiring``). Security notices quote them in subject lines, which reach
records and the audit trail.

Registered secrets are also matched in their JSON-escaped forms (backslash-u unicode escapes
under the default ``ensure_ascii`` and backslash-escaped slashes), because vendors echo
credentials inside JSON.
:meth:`Redactor.redact_body` parses JSON bodies (recursively decoding string values that are JSON
themselves) and redacts the structure before the text rules run.

Command-line flags whose name is a sensitive key are redacted when the value is a separate
argument too (``tool.exe --password VALUE``, ``-token VALUE``), not only in the ``--key=value``
form. :meth:`Redactor.redact_command_line` (used for recorded process command lines) adds the
forms that are credentials only by command-line convention: ``-p VALUE`` (the conventional
password flag of database clients) and ``-u user:password`` / ``--user user:password`` (the
password part of a basic-auth pair). Archive, transfer and database tools add more forms (14.12.7):
an attached password (``7z a -pVALUE``, ``rar a -hpVALUE``, ``mysqldump -pVALUE``; always for a
known archive or database tool, otherwise when the value looks like a credential and is not a
path or a ``name:value`` / ``name=value`` parameter), ``-P VALUE`` of the zip family and
``-pw VALUE`` / ``-pwd VALUE`` / ``-pass VALUE`` (PuTTY ``pscp`` / ``plink`` / ``psftp``, OpenSSL).
Connection-string keys (``AccountKey=``, ``SharedAccessKey=``) and environment passwords
(``set PGPASSWORD=VALUE``, ``MYSQL_PWD=VALUE``) are sensitive keys in every text.

Every text (not only command lines, 14.11.7) gets the password in URL userinfo
(``https://user:password@host``) and the forms in which Windows and PowerShell administrative
commands carry passwords, because a service ImagePath, a task action, a detection title, a script
block or an untyped vendor attribute quotes the command with its arguments: ``/name:VALUE`` switches whose name is a password
(``cmdkey /pass:X``, ``/pw:X``, ``/pwd:X``, ``wmic /password:X``), ``/rp X`` (schtasks run-as
password), ``/p X`` after a ``/u USER`` (schtasks and similar), the plain-text literal of
``ConvertTo-SecureString 'X' -AsPlainText`` / ``-String X`` (a ``$variable`` is kept), and the
positional password of ``net use [device] \\\\host\\share X`` and ``net user NAME X`` (the ``*``
prompt is kept).
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

__all__ = ["COMMAND_LINE_KEY_PATTERN", "REDACTED", "SENSITIVE_KEY_PATTERN", "Redactor", "get_redactor", "normalize_key"]

REDACTED = "[REDACTED]"

#: Matched (``fullmatch``, case-insensitive) against keys normalized by :func:`normalize_key`
#: (camelCase -> snake_case). Exact-only terms: authorization, proxy-authorization, cookie,
#: set-cookie, key, session, credential(s), sig (Azure SAS URL signature), pass / pwd / pw (the
#: common names of a password parameter in web forms and URL query strings: ``?pass=``, ``&pwd=``;
#: P5 round 2). Header-style credential
#: parameters "x-<vendor>-credential(s)" (S3 pre-signed X-Amz-Credential, GCS X-Goog-Credential).
#: Suffix terms (also "<prefix>_<term>" or "<prefix>-<term>"): signature (X-Amz-Signature,
#: X-Goog-Signature), password, passwd, passphrase, secret,
#: client_secret, secret_key, token, access_token, refresh_token, id_token, session_token,
#: session_key / sessionKey (Splunk), session_id, signing_key (APPROVAL_SIGNING_KEY),
#: recovery_key / recovery_password (BitLocker), secret_access_key, api_key / apikey / api-key
#: (covers x-apikey, x-api-key, hibp-api-key, x-otx-api-key, x-cisco-meraki-api-key), private_key,
#: approval_token, unlock_code, passcode / pass_code, account_key / shared_access_key /
#: storage_key / storage_account_key (Azure connection strings ``AccountKey=``,
#: ``SharedAccessKey=``, 14.12.7). A password word glued to a prefix is sensitive too (environment
#: variables ``PGPASSWORD``, ``DBPASSWORD``, ``MYSQL_PWD``). "idempotency_key", "control_key",
#: "token_id", "params_hash" are NOT sensitive.
SENSITIVE_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"(?:authorization|proxy[-_]authorization|cookie|set[-_]cookie|key|session|credentials?|signature|sig"
    r"|pass|pwd|pw"
    r"|x[-_][a-z0-9]+[-_]credentials?"
    r"|[a-z0-9]*(?:password|passwd)|mysql[-_]pwd"
    r"|(?:.*[-_.])?(?:password|passwd|passphrase|secret|client[-_]secret|secret[-_]key|token|signature"
    r"|access[-_]token|refresh[-_]token|id[-_]token|session[-_]token|session[-_]?(?:key|id)"
    r"|signing[-_]key|recovery[-_](?:key|password)|secret[-_]access[-_]key|api[-_]?key|private[-_]key"
    r"|account[-_]?key|shared[-_]?access[-_]?key|storage[-_]?(?:account[-_]?)?key"
    r"|approval[-_]token|unlock[-_]code|pass[-_]?code))",
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
#: Mapping keys (normalized by :func:`normalize_key`) whose string value is a process command line:
#: :meth:`Redactor.redact` applies :meth:`Redactor.redact_command_line` to it, so a raw vendor
#: finding or a typed lab record quoted in an audit payload gets the same treatment as the record's
#: own ``command_line`` field (``command_line``, ``commandLine``, ``ProcessCommandLine``,
#: ``InitiatingProcessCommandLine``, ``cmdline``, ``cmd_line``).
COMMAND_LINE_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"(?:.*[-_.])?(?:command[-_]?line|cmd[-_]?line|commandline)", re.IGNORECASE)
#: ``key = value`` / ``key: value`` with optional quotes around the key and the value (JSON text,
#: Python dict reprs, headers, query strings). The value is replaced only when the key is sensitive.
#: Only the key and separator are consumed; the value is captured in a lookahead so that a value
#: of a non-sensitive key (for example a URL after "https:") is still scanned for nested pairs.
#: A command-line flag prefix (``-key=value``, ``--key=value``) is accepted before the key, so
#: ``tool.exe --password=...`` in a recorded command line is redacted too.
_KV = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?:-{1,2}(?=[A-Za-z]))?(?P<kq>["']?)(?P<key>[A-Za-z][A-Za-z0-9_.\-]{0,63})(?P=kq)\s*[=:]\s*"""
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
#: ``--key VALUE`` / ``-key VALUE``: a command-line flag whose value is the next argument. The value
#: is replaced only when the flag name is a sensitive key; a following flag (``-x``) is not a value.
_FLAG_ARG = re.compile(
    r"""(?<![A-Za-z0-9_.\-])-{1,2}(?P<key>[A-Za-z][A-Za-z0-9_.\-]{0,63})[ \t]+"""
    r"""(?P<value>"[^"]*"|'[^']*'|(?!-)[^\s"']+)"""
)
#: Command lines only: ``-p VALUE`` (conventional password flag, for example database clients).
_CMD_P_FLAG = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?P<flag>-p[ \t]+)(?P<value>"[^"]*"|'[^']*'|(?!-)[^\s"']+)"""
)
#: Command lines only: an attached password ``-pVALUE`` / ``-hpVALUE`` (7-Zip, RAR, MySQL clients).
_CMD_P_ATTACHED = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?P<flag>-h?p)(?P<value>"[^"]*"|'[^']*'|[^\s"'\-][^\s"']*)"""
)
#: Tools whose attached ``-p`` / ``-hp`` is always the password (archive and database clients).
_CMD_P_ATTACHED_TOOLS = re.compile(
    r"""(?i)(?:^|[\s"'\\/&|;(])(?:7z|7za|7zr|7zg|7zz|7-zip|rar|winrar|unrar|mysql|mysqldump|mysqladmin|mysqlimport"""
    r"""|mysqlcheck|mysqlshow|mysqlpump|mysqlsh|mariadb|mariadb-dump|mariadb-admin)(?:\.exe)?(?=$|[\s"'&|;)])"""
)
#: Command lines only: ``-P VALUE`` of the zip family (``zip -P X``, ``unzip -P X``).
_CMD_UPPER_P_FLAG = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?P<flag>-P[ \t]+)(?P<value>"[^"]*"|'[^']*'|(?!-)[^\s"']+)"""
)
_CMD_ZIP_TOOLS = re.compile(
    r"""(?i)(?:^|[\s"'\\/&|;(])(?:zip|unzip|zipcloak|funzip|pkzip|pkzipc|pkunzip|wzzip|wzunzip)(?:\.exe)?"""
    r"""(?=$|[\s"'&|;)])"""
)
#: Command lines only: password flags that are not sensitive keys in general text: ``-pw VALUE``
#: (PuTTY ``pscp`` / ``plink`` / ``psftp``), ``-pwd VALUE``, ``-pass VALUE`` / ``-passin`` /
#: ``-passout`` (OpenSSL), also with ``=`` or ``:`` before the value.
_CMD_PW_FLAG = re.compile(
    r"""(?i)(?<![A-Za-z0-9_.\-])(?P<flag>-{1,2}(?:pw|pwd|pass|passin|passout)(?:[ \t]+|[=:]))"""
    r"""(?P<value>"[^"]*"|'[^']*'|(?!-)[^\s"']+)"""
)
#: Command lines only: ``-u user:password`` / ``--user user:password`` / ``--user=user:password``.
_CMD_USER_PAIR = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?P<flag>(?:-u|--user|--proxy-user)(?:[ \t]+|=))(?P<q>["']?)"""
    r"""(?P<user>[^\s:"'@]+):(?P<value>[^\s"']+)(?P=q)"""
)
#: Any text: Windows ``/name:VALUE`` / ``/name=VALUE`` switches whose name is a password
#: (``cmdkey /pass:X``, ``wmic /password:X``, ``/pw:X``, ``/pwd:X``) or any sensitive key. The
#: switch starts an argument (after whitespace, a quote or at the start), never inside a path.
_CMD_SLASH_SWITCH = re.compile(
    r"""(?<![^\s"'])/(?P<key>[A-Za-z][A-Za-z0-9_\-]{0,31})[:=]"""
    r"""(?P<value>"[^"]*"|'[^']*'|[^\s"']+)"""
)
_CMD_SLASH_PASSWORD_NAMES = frozenset({"pass", "pw", "pwd", "passwd", "password", "rp", "runpassword"})
#: Any text: ``/rp VALUE`` (schtasks run-as password) and ``/p VALUE`` (the password of a
#: preceding ``/u USER``, schtasks and similar) with the value as the next argument; another switch
#: is not a value.
_CMD_SLASH_ARG = re.compile(
    r"""(?i)(?<![^\s"'])(?P<flag>/(?P<name>rp|p)[ \t]+)(?P<value>"[^"]*"|'[^']*'|(?![/-])[^\s"']+)"""
)
_CMD_SLASH_USER = re.compile(r"""(?i)(?<![^\s"'])/u[ \t]+\S""")
#: Any text: PowerShell ``ConvertTo-SecureString 'X' -AsPlainText`` and
#: ``ConvertTo-SecureString -String X``: the plain-text password literal (a ``$variable`` or a
#: sub-expression is kept).
_SECURESTRING = re.compile(
    r"""(?i)\bConvertTo-SecureString\b(?P<pre>(?:[ \t]+-(?:AsPlainText|Force)\b)*[ \t]+(?:-String[ \t]+)?)"""
    r"""(?P<value>'(?:''|[^'])*'|"(?:`.|[^"`])*"|(?![-$(])[^\s;|)'"]+)"""
)
#: Any text: ``net use [device] \\host\share PASSWORD /user:...`` and
#: ``net user NAME PASSWORD``: positional passwords of the ``net`` command (``*`` prompts, kept).
_NET_COMMAND = re.compile(
    r"""(?i)(?<![A-Za-z0-9_.\-])net1?(?:\.exe)?["']?[ \t]+(?P<verb>use|user)\b(?P<rest>[^;&|\r\n]*)"""
)
_NET_TOKEN = re.compile(r"""\S+""")
_NET_DEVICE = re.compile(r"""(?i)^(?:[A-Z]:|\*|LPT\d:|COM\d:)$""")
#: Any text: ``scheme://user:password@host``.
_URL_USERINFO = re.compile(r"(?P<head>[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]+:)(?P<value>[^\s/@]+)(?=@)")
#: Bare values after an authorization key that are only the auth scheme (the credential after the
#: scheme is handled by ``_BEARER``).
_AUTH_SCHEMES = frozenset({"bearer", "basic", "splunk", "apikey", "token", "digest", "negotiate"})
_MIN_SECRET_LEN = 6
#: Labels of one-time and verification codes in prose (security notices, sign-in mails).
_ONE_TIME_LABELS = (
    r"(?:verification|security|sign[\s_-]?in|log[\s_-]?in|logon|one[\s_-]?time|reset|recovery|confirmation"
    r"|2fa|mfa|otp|backup|single[\s_-]?use)[\s_-]*code|one[\s_-]?time[\s_-]*(?:password|pass[\s_-]?word|pin)"
)
#: Short or generic labels, recognised only right before the value (never across other words).
_SHORT_CODE_LABELS = r"(?:access|auth|authentication|account|device|pairing)[\s_-]*code|otp|totp|pin"
#: An unlock code, passcode or one-time code phrased in prose ("isolation unlock code: X", "unlock
#: code X", "Device passcode X", "Your verification code is X"): the key=value rule only sees the
#: last word before the separator. The value must look like a code (a digit, or all upper case) so
#: ordinary words are left alone.
_CODE_PROSE = re.compile(
    r"(?i)\b(?P<label>unlock[\s_-]*code|pass[\s_-]?code|isolation[\s_-]*code|" + _ONE_TIME_LABELS + "|"
    + _SHORT_CODE_LABELS + r")(?![A-Za-z0-9])"
    r"(?P<sep>\s*(?:[:=]|\bis\b)?\s*)"
    r"(?P<q>[\"']?)(?P<value>[A-Za-z0-9][A-Za-z0-9-]{3,63})(?P=q)(?![A-Za-z0-9])"
)
#: The same with words between the label and the value, which then needs an explicit separator
#: (``:`` / ``=`` / ``is``): "unlock code for TH-LT-1047 is X", "unlock code (TH-LT-1047): X",
#: "the code to unlock TH-LT-1047 is X". The words in between stay on one line (at most 80 chars).
_CODE_PROSE_LOOSE = re.compile(
    r"(?i)\b(?P<label>unlock[\s_-]*code|pass[\s_-]?code|isolation[\s_-]*code|code\s+to\s+unlock|"
    + _ONE_TIME_LABELS + r")(?![A-Za-z0-9])"
    r"(?P<sep>[^\r\n:=]{0,80}?(?:\s*[:=]\s*|\s+is\s+))"
    r"(?P<q>[\"']?)(?P<value>[A-Za-z0-9][A-Za-z0-9-]{3,63})(?P=q)(?![A-Za-z0-9])"
)

#: The code first: "482913 is your verification code", "G-482913 is your sign-in code".
_CODE_FIRST = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<value>(?:[A-Z]{1,3}-)?\d[A-Za-z0-9-]{3,15})(?P<rest>\s+is\s+your\b[^\r\n]{0,60}?"
    r"\b(?:code|passcode|password|pin|otp))\b"
)
#: A password stated in prose: "new password is X", "temporary password: X", "password is X" and,
#: after a qualifier only, "new password X". The value is kept when it is an ordinary status word.
_PASSWORD_PROSE = re.compile(
    r"(?i)\b(?P<label>(?P<qual>(?:new|temporary|temp|initial|default|one[\s_-]?time|generated|reset)[\s_-]+)?"
    r"pass[\s_-]?word)(?P<sep>\s+is\s+|\s*[:=]\s*|[ \t]+)(?P<q>[\"']?)(?P<value>[^\s\"'<>]{3,128})(?P=q)"
)
_PASSWORD_STATUS_WORDS = frozenset({
    "a", "about", "already", "an", "and", "at", "being", "been", "by", "change", "changed", "compromised",
    "due", "empty", "expire", "expired", "expires", "expiring", "for", "from", "going", "has", "have",
    "in", "incorrect", "invalid", "is", "locked", "missing", "must", "needed", "never", "no", "not", "now",
    "of", "old", "on", "or", "out", "policy", "ready", "request", "requested", "required", "reset", "set",
    "should", "soon", "still", "strong", "successfully", "the", "this", "to", "too", "unchanged", "updated",
    "valid", "was", "weak", "will", "with", "wrong", "you", "your", "manager",
})


def _looks_like_credential(value: str) -> bool:
    """A digit, a symbol or upper case after the first letter: never an ordinary prose word."""
    bare = value.rstrip(".,;:!?")
    return any(ch.isdigit() for ch in bare) or not bare.isalpha() or bare[1:] != bare[1:].lower()


def _password_prose(match: re.Match[str]) -> str:
    """Redact a password stated in prose.

    ``password: X`` / ``password = X`` and ``new password is X`` (a qualifier and ``is``): the value
    unless it is a status word. ``password is X`` (no qualifier) and ``new password X`` (no
    separator): only a value that looks like a credential, so "the password is known" and "new
    password manager" stay readable.
    """
    value = match.group("value")
    if value.startswith("[REDACTED") or value.lower().rstrip(".,;:!?") in _PASSWORD_STATUS_WORDS:
        return match.group(0)
    sep = match.group("sep")
    word = sep.strip().lower()
    qualified = bool(match.group("qual"))
    if word == "is" and not qualified and not _looks_like_credential(value):
        return match.group(0)
    if not word and not (qualified and _looks_like_credential(value)):
        return match.group(0)
    q = match.group("q")
    return f"{match.group('label')}{sep}{q}{REDACTED}{q}"


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
                elif isinstance(k, str) and isinstance(v, str) and _is_command_line_key(k):
                    out[k] = self.redact_command_line(v)
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
        text = self._redact_pairs(text)
        text = _FLAG_ARG.sub(self._flag_arg, text)
        text = _CODE_PROSE.sub(_code_prose, text)
        text = _CODE_PROSE_LOOSE.sub(_code_prose, text)
        text = _CODE_FIRST.sub(_code_first, text)
        text = _PASSWORD_PROSE.sub(_password_prose, text)
        return self._redact_embedded_command_forms(text)

    def _redact_embedded_command_forms(self, text: str) -> str:
        """Credential forms of administrative commands that are unambiguous in any text (14.11.7):
        URL userinfo passwords, Windows ``/pass:X`` style switches, ``/rp X`` and ``/u USER /p X``,
        PowerShell ``ConvertTo-SecureString`` literals and the positional passwords of ``net use``
        and ``net user``. A service ImagePath, a scheduled task action, a detection title, a script
        block or an untyped vendor attribute quotes a command with its arguments just as a
        ``command_line`` field does, so these rules are part of :meth:`redact_text`."""
        text = _URL_USERINFO.sub(_replace_value, text)
        text = _CMD_SLASH_SWITCH.sub(self._slash_switch, text)
        has_slash_user = bool(_CMD_SLASH_USER.search(text))
        text = _CMD_SLASH_ARG.sub(
            lambda m: _replace_value(m) if m.group("name").lower() == "rp" or has_slash_user else m.group(0), text)
        text = _SECURESTRING.sub(_replace_value, text)
        return _NET_COMMAND.sub(_net_command, text)

    def redact_command_line(self, text: str) -> str:
        """:meth:`redact_text` (which already covers URL userinfo passwords, Windows ``/pass:X``
        style switches, ``/rp X`` and ``/u USER /p X``, PowerShell ``ConvertTo-SecureString``
        literals and the positional passwords of ``net use`` and ``net user``) plus the forms that
        are credentials only by command-line convention: ``-p VALUE``, ``-u user:password``,
        ``-pw`` / ``-pwd`` / ``-pass VALUE``, ``-P VALUE`` of the zip family and an attached
        ``-pVALUE`` / ``-hpVALUE`` (14.12.7)."""
        text = self.redact_text(text)
        if not text:
            return text
        text = _CMD_P_FLAG.sub(_replace_value, text)
        text = _CMD_PW_FLAG.sub(_replace_value, text)
        if _CMD_ZIP_TOOLS.search(text):
            text = _CMD_UPPER_P_FLAG.sub(_replace_value, text)
        known_tool = bool(_CMD_P_ATTACHED_TOOLS.search(text))
        text = _CMD_P_ATTACHED.sub(lambda m: _attached_password(m, known_tool), text)
        return _CMD_USER_PAIR.sub(
            lambda m: m.group(0) if m.group("value").startswith("[REDACTED")
            else f"{m.group('flag')}{m.group('q')}{m.group('user')}:{REDACTED}{m.group('q')}", text)

    def _slash_switch(self, match: re.Match[str]) -> str:
        key = match.group("key")
        if key.lower() not in _CMD_SLASH_PASSWORD_NAMES and not self.is_sensitive_key(key):
            return match.group(0)
        return _replace_value(match)

    def _flag_arg(self, match: re.Match[str]) -> str:
        if not self.is_sensitive_key(match.group("key")):
            return match.group(0)
        return _replace_value(match)

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
        """Remove userinfo and replace values of sensitive query and fragment keys.

        The fragment is treated like a query (an OAuth implicit-flow redirect carries
        ``#access_token=...``).
        """
        try:
            parts = urlsplit(url)
        except ValueError:
            return self.redact_text(url)
        netloc = parts.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        rebuilt = urlunsplit((parts.scheme, netloc, parts.path, self._redact_query(parts.query),
                              self._redact_query(parts.fragment)))
        return self.redact_text(rebuilt)

    def _redact_query(self, query: str) -> str:
        """``k=v&k2=v2`` with the values of sensitive keys replaced (empty pairs dropped)."""
        if not query:
            return query
        pairs = []
        for pair in query.split("&"):
            if not pair:
                continue
            k, sep, v = pair.partition("=")
            if self.is_sensitive_key(unquote_plus(k)):
                pairs.append(f"{k}={REDACTED}")
            else:
                pairs.append(f"{k}{sep}{v}")
        return "&".join(pairs)

    def redact_headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        return {
            str(k): (REDACTED if self.is_sensitive_key(str(k)) else self.redact_text(str(v)))
            for k, v in headers.items()
        }


def _replace_value(match: re.Match[str]) -> str:
    """``match`` with its ``value`` group replaced by :data:`REDACTED` (quotes kept)."""
    value = match.group("value")
    if value.strip("\"'").startswith("[REDACTED"):
        return match.group(0)
    replacement = f"{value[0]}{REDACTED}{value[0]}" if value[:1] in ("\"", "'") else REDACTED
    start, end = match.span("value")
    whole_start = match.start()
    return match.group(0)[: start - whole_start] + replacement + match.group(0)[end - whole_start:]


def _attached_password(match: re.Match[str], known_tool: bool) -> str:
    """``-pVALUE`` / ``-hpVALUE``: always the password for a known archive or database tool;
    otherwise only a value that looks like a credential and is not a path or a ``name:value`` /
    ``name=value`` parameter (``-pthread``, ``-print``, ``-priority:high`` are kept)."""
    value = match.group("value")
    if value.strip("\"'").startswith("[REDACTED"):
        return match.group(0)
    if not known_tool:
        bare = value.strip("\"'")
        if not bare or any(ch in bare for ch in ":=/\\") or not _looks_like_credential(bare):
            return match.group(0)
    return _replace_value(match)


def _net_command(match: re.Match[str]) -> str:
    """Redact the positional password of ``net use`` (after the share) and ``net user`` (after the
    account name). Switches (``/user:...``), the device name and the ``*`` prompt are kept."""
    rest = match.group("rest")
    verb = match.group("verb").lower()
    positional = 0
    seen_share = False
    spans: list[tuple[int, int]] = []
    for token in _NET_TOKEN.finditer(rest):
        value = token.group(0)
        if value.startswith("/") or value.startswith("[REDACTED"):
            continue
        if verb == "use":
            if not seen_share:
                if value.lstrip("\"'").startswith("\\\\"):
                    seen_share = True
                elif not _NET_DEVICE.match(value):
                    break  # not the documented form: leave the rest alone
                continue
            if value != "*":
                spans.append(_token_span(token))
            break  # only the first argument after the share is the password
        else:
            positional += 1
            if positional == 2:
                if value != "*":
                    spans.append(_token_span(token))
                break
    if not spans:
        return match.group(0)
    out, cursor = [], 0
    for start, end in spans:
        out.append(rest[cursor:start])
        out.append(REDACTED)
        cursor = end
    out.append(rest[cursor:])
    head = match.group(0)[: match.start("rest") - match.start()]
    return head + "".join(out)


def _is_command_line_key(key: str) -> bool:
    return bool(COMMAND_LINE_KEY_PATTERN.fullmatch(normalize_key(key)))


def _token_span(token: re.Match[str]) -> tuple[int, int]:
    """The span of a command-line token without a closing quote that belongs to an outer string."""
    start, end = token.span()
    value = token.group(0)
    if value[-1:] in ("\"", "'") and value.count(value[-1]) % 2 == 1:
        end -= 1
    return start, end


def _code_prose(match: re.Match[str]) -> str:
    value = match.group("value")
    if not (any(ch.isdigit() for ch in value) or (value.isupper() and value.isalpha())):
        return match.group(0)
    q = match.group("q")
    return f"{match.group('label')}{match.group('sep')}{q}{REDACTED}{q}"


def _code_first(match: re.Match[str]) -> str:
    if not any(ch.isdigit() for ch in match.group("value")):
        return match.group(0)
    return f"{REDACTED}{match.group('rest')}"


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
