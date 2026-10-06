"""Microsoft identity platform and Graph helpers shared by entra, defender_endpoint, defender_o365,
intune and microsoft_cloud (docs/integrations.md sections 2.8 to 2.12).

Token endpoint (VERIFIED): ``POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` with
``grant_type=client_credentials``. Source:
https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp

The Graph scope string (``https://graph.microsoft.com/.default``) is marked UNVERIFIED in
docs/integrations.md 2.8, so Graph adapters take it from ``options.oauth_scope`` and refuse to build
auth without it. The Defender for Endpoint scope is VERIFIED and is a constant in that adapter.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from xdr_response.errors import ConfigError
from xdr_response.integrations._adapter_support import segment
from xdr_response.integrations.base import OperationSpec
from xdr_response.models import EndpointStatus, OperationKind

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.integrations.auth import AuthProvider
    from xdr_response.integrations.base import IntegrationAdapter

__all__ = [
    "GRAPH_BASE_URL",
    "TOKEN_URL_TEMPLATE",
    "TOKEN_SOURCE",
    "GRAPH_SECRET_NAMES",
    "token_url",
    "token_operation",
    "graph_scope",
    "microsoft_auth",
    "odata_string",
]

GRAPH_BASE_URL = "https://graph.microsoft.com"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
TOKEN_SOURCE = "https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp"
GRAPH_SECRET_NAMES: Mapping[str, str] = {
    "tenant_id": "ENTRA_TENANT_ID",
    "client_id": "ENTRA_CLIENT_ID",
    "client_secret": "ENTRA_CLIENT_SECRET",
}


def token_url(tenant: str) -> str:
    """The VERIFIED client-credentials token URL for ``tenant``."""
    return TOKEN_URL_TEMPLATE.format(tenant=segment(tenant))


def token_operation() -> OperationSpec:
    """Manifest row for the identity-platform token endpoint."""
    return OperationSpec(name="token", kind=OperationKind.READ, status=EndpointStatus.VERIFIED,
                         method="POST", path=TOKEN_URL_TEMPLATE, source=TOKEN_SOURCE)


def graph_scope(adapter: "IntegrationAdapter") -> str:
    """The Graph OAuth scope from ``options.oauth_scope`` (the string itself is UNVERIFIED)."""
    scope = adapter.config.options.get("oauth_scope")
    if not isinstance(scope, str) or not scope:
        raise ConfigError(
            f"{adapter.name}: options.oauth_scope is required; the Graph scope string is UNVERIFIED "
            "in docs/integrations.md section 2.8"
        )
    return scope


def microsoft_auth(adapter: "IntegrationAdapter", *, scope: str) -> "AuthProvider":
    """Client-credentials auth against the identity platform (credentials in the form body)."""
    from xdr_response.integrations.auth import OAuth2ClientCredentials

    tenant = adapter.secret("tenant_id").reveal()
    return OAuth2ClientCredentials(
        token_url=token_url(tenant), client_id=adapter.secret("client_id"),
        client_secret=adapter.secret("client_secret"), scope=scope, basic_auth=False,
        transport=adapter.transport, clock=adapter.clock,
    )


def odata_string(value: str) -> str:
    """OData string literal: single-quoted with embedded quotes doubled."""
    return "'" + str(value).replace("'", "''") + "'"
