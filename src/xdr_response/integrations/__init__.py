"""Integration adapters (architecture section 13.13).

``base`` (adapter ABC, manifests) is imported eagerly. The HTTP client, auth providers, registry
and health monitor are resolved lazily on first attribute access so that importing this package
never pulls in every adapter (and never fails because an optional module is absent).
"""
from __future__ import annotations

import importlib
from typing import Any

from xdr_response.integrations.base import (
    STATE_CHANGING_ACTION_NAMES,
    CapabilityManifest,
    HealthStatus,
    IntegrationAdapter,
    OperationSpec,
)
from xdr_response.models.catalog import INTEGRATION_NAMES

_LAZY = {
    "GuardedHttpClient": "xdr_response.integrations.http",
    "RetryPolicy": "xdr_response.integrations.http",
    "RateLimiter": "xdr_response.integrations.http",
    "HttpResult": "xdr_response.integrations.http",
    "AuthProvider": "xdr_response.integrations.auth",
    "OAuth2ClientCredentials": "xdr_response.integrations.auth",
    "ApiKeyHeader": "xdr_response.integrations.auth",
    "ApiKeyQuery": "xdr_response.integrations.auth",
    "BasicAuth": "xdr_response.integrations.auth",
    "ADAPTER_PATHS": "xdr_response.integrations.registry",
    "AdapterRegistry": "xdr_response.integrations.registry",
    "load_adapter_class": "xdr_response.integrations.registry",
    "HealthMonitor": "xdr_response.integrations.health",
    "classify_exception": "xdr_response.integrations.health",
}

__all__ = [
    "INTEGRATION_NAMES",
    "STATE_CHANGING_ACTION_NAMES",
    "CapabilityManifest",
    "HealthStatus",
    "IntegrationAdapter",
    "OperationSpec",
    *_LAZY,
]


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
