"""Secret providers. Secret values only come from the environment, mounted files or a vault.

A :class:`SecretValue` never reveals itself through ``repr``, ``str``, ``format``, logging,
pickling or JSON serialization; callers must use :meth:`SecretValue.reveal` explicitly at the point
of use (for example when building an ``Authorization`` header). Every provider registers each value
it returns with the redactor so the value is scrubbed from logs and audit records.
"""
from __future__ import annotations

import hmac
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from xdr_response.errors import SecretNotFoundError
from xdr_response.logs.redaction import Redactor, get_redactor

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.interfaces import SecretProvider

__all__ = [
    "SecretValue",
    "EnvSecretProvider",
    "FileSecretProvider",
    "StaticSecretProvider",
    "ChainSecretProvider",
    "default_secret_provider",
    "SECRET_NAME_RE",
]

SECRET_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_MASK = "***"


class SecretValue:
    __slots__ = ("_value", "name")

    def __init__(self, name: str, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("secret value must be a string")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        return self._value

    def __setattr__(self, key: str, value: Any) -> None:
        raise AttributeError("SecretValue is immutable")

    def __repr__(self) -> str:
        return f"SecretValue(name={self.name!r}, value='{_MASK}')"

    def __str__(self) -> str:
        return _MASK

    def __format__(self, format_spec: str) -> str:
        return _MASK

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self) -> Any:
        raise TypeError("SecretValue cannot be pickled or serialized")

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise TypeError("SecretValue cannot be pickled or serialized")

    def __copy__(self) -> "SecretValue":
        return self

    def __deepcopy__(self, memo: Any) -> "SecretValue":
        return self

    def __getstate__(self) -> Any:
        raise TypeError("SecretValue cannot be pickled or serialized")


def _check_name(name: str) -> str:
    if not isinstance(name, str) or not SECRET_NAME_RE.match(name):
        raise ValueError(f"invalid secret name {name!r}: must match {SECRET_NAME_RE.pattern}")
    return name


class _BaseProvider:
    def __init__(self, *, redactor: Redactor | None = None) -> None:
        self._redactor = redactor

    def _lookup(self, name: str) -> str | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _wrap(self, name: str, value: str | None) -> SecretValue | None:
        if value is None or value == "":
            return None
        (self._redactor or get_redactor()).register_secret(value)
        return SecretValue(name, value)

    def get(self, name: str) -> SecretValue:
        _check_name(name)
        secret = self._wrap(name, self._lookup(name))
        if secret is None:
            raise SecretNotFoundError(name)
        return secret

    def get_optional(self, name: str) -> SecretValue | None:
        _check_name(name)
        return self._wrap(name, self._lookup(name))

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class EnvSecretProvider(_BaseProvider):
    """Reads secrets from environment variables (``os.environ`` by default, read live)."""

    def __init__(self, environ: Mapping[str, str] | None = None, *, redactor: Redactor | None = None) -> None:
        super().__init__(redactor=redactor)
        self._environ = environ

    def _lookup(self, name: str) -> str | None:
        env = os.environ if self._environ is None else self._environ
        return env.get(name)


class FileSecretProvider(_BaseProvider):
    """Reads secrets mounted as files: ``<directory>/<NAME>`` (Docker/Kubernetes secrets).

    The trailing newline is stripped. Names are validated so a name can never escape the directory.
    """

    def __init__(self, directory: Path | str, *, redactor: Redactor | None = None) -> None:
        super().__init__(redactor=redactor)
        self._dir = Path(directory)

    def _lookup(self, name: str) -> str | None:
        path = self._dir / name
        try:
            if not path.is_file():
                return None
            return path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError:
            return None

    def __repr__(self) -> str:
        return f"FileSecretProvider({str(self._dir)!r})"


class StaticSecretProvider(_BaseProvider):
    """In-memory secrets for tests and the lab only."""

    def __init__(self, values: Mapping[str, str], *, redactor: Redactor | None = None) -> None:
        super().__init__(redactor=redactor)
        for name in values:
            _check_name(name)
        self._values = dict(values)

    def _lookup(self, name: str) -> str | None:
        return self._values.get(name)

    def __repr__(self) -> str:
        return f"StaticSecretProvider(names={sorted(self._values)!r})"


class ChainSecretProvider:
    """Tries each provider in order; the first non-empty value wins."""

    def __init__(self, *providers: "SecretProvider") -> None:
        if not providers:
            raise ValueError("ChainSecretProvider needs at least one provider")
        self._providers = providers

    def get(self, name: str) -> SecretValue:
        secret = self.get_optional(name)
        if secret is None:
            raise SecretNotFoundError(name)
        return secret

    def get_optional(self, name: str) -> SecretValue | None:
        _check_name(name)
        for p in self._providers:
            secret = p.get_optional(name)
            if secret is not None:
                return secret
        return None

    def __repr__(self) -> str:
        return f"ChainSecretProvider({', '.join(repr(p) for p in self._providers)})"


def default_secret_provider(
    environ: Mapping[str, str] | None = None, *, mount_dir: Path | str | None = None
) -> "SecretProvider":
    """Environment first, then mounted files (``XDR_RESPONSE_SECRETS_DIR`` or ``mount_dir``)."""
    env = os.environ if environ is None else environ
    directory = mount_dir or env.get("XDR_RESPONSE_SECRETS_DIR")
    if directory:
        return ChainSecretProvider(EnvSecretProvider(environ), FileSecretProvider(directory))
    return EnvSecretProvider(environ)
