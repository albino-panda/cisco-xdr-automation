"""Secret access. Values come from the environment, mounted files or a vault; never from code or config."""
from __future__ import annotations

from xdr_response.secrets.provider import (
    SECRET_NAME_RE,
    ChainSecretProvider,
    EnvSecretProvider,
    FileSecretProvider,
    SecretValue,
    StaticSecretProvider,
    default_secret_provider,
)

__all__ = [
    "SECRET_NAME_RE",
    "SecretValue",
    "EnvSecretProvider",
    "FileSecretProvider",
    "StaticSecretProvider",
    "ChainSecretProvider",
    "default_secret_provider",
]
