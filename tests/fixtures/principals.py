"""Test principals, credentials and secrets (architecture section 13.20). Fake values only.

``make_authenticator`` imports ``xdr_response.approval`` lazily so that this module can be imported
by tests of components that do not depend on the approval package.
"""
from __future__ import annotations

import secrets as _stdlib_secrets
from typing import TYPE_CHECKING

from pydantic import SecretStr

from xdr_response.models import ApproverCredential, PrincipalKind
from xdr_response.secrets import StaticSecretProvider

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.approval.authenticator import InMemoryApproverAuthenticator

__all__ = [
    "ANALYST_ID",
    "ELEVATED_ID",
    "SERVICE_ID",
    "AUTOMATION_ID",
    "AI_ID",
    "STANDARD_ROLE",
    "ELEVATED_ROLE",
    "PRINCIPALS",
    "TEST_SIGNING_KEY_NAME",
    "make_authenticator",
    "credential",
    "make_test_secrets",
]

ANALYST_ID = "analyst.one@example.com"
ELEVATED_ID = "lead.two@example.com"
SERVICE_ID = "svc-soar@example.com"
AUTOMATION_ID = "automation-runner@example.com"
AI_ID = "ai-assistant@example.com"

STANDARD_ROLE = "xdr-approver"
ELEVATED_ROLE = "xdr-elevated-approver"

# principal_id -> (display_name, kind, roles). Non-human principals hold every role on purpose:
# roles must never let a SERVICE, AUTOMATION or AI principal approve.
PRINCIPALS: dict[str, tuple[str, PrincipalKind, frozenset[str]]] = {
    ANALYST_ID: ("Analyst One", PrincipalKind.HUMAN, frozenset({STANDARD_ROLE})),
    ELEVATED_ID: ("Lead Two", PrincipalKind.HUMAN, frozenset({STANDARD_ROLE, ELEVATED_ROLE})),
    SERVICE_ID: ("SOAR service", PrincipalKind.SERVICE, frozenset({STANDARD_ROLE, ELEVATED_ROLE})),
    AUTOMATION_ID: ("Automation runner", PrincipalKind.AUTOMATION, frozenset({STANDARD_ROLE, ELEVATED_ROLE})),
    AI_ID: ("AI assistant", PrincipalKind.AI, frozenset({STANDARD_ROLE, ELEVATED_ROLE})),
}

_TEST_CREDENTIAL_SECRETS = {pid: f"test-credential-{i}-not-a-real-secret" for i, pid in enumerate(PRINCIPALS)}

TEST_SIGNING_KEY_NAME = "APPROVAL_SIGNING_KEY"


def make_authenticator() -> "InMemoryApproverAuthenticator":
    """Authenticator with a human analyst, an elevated human, a service, an automation and an AI."""
    from xdr_response.approval.authenticator import InMemoryApproverAuthenticator

    auth = InMemoryApproverAuthenticator()
    for pid, (display, kind, roles) in PRINCIPALS.items():
        auth.add_principal(pid, display_name=display, kind=kind, roles=roles,
                           secret=_TEST_CREDENTIAL_SECRETS[pid])
    return auth


def credential(principal_id: str) -> ApproverCredential:
    """The valid static credential of a test principal."""
    return ApproverCredential(principal_id=principal_id, scheme="static",
                              secret=SecretStr(_TEST_CREDENTIAL_SECRETS[principal_id]))


def make_test_secrets(**extra: str) -> StaticSecretProvider:
    """Secrets with a random 32-byte (64 hex chars) signing key per call, plus ``extra`` NAME=value."""
    values = {TEST_SIGNING_KEY_NAME: _stdlib_secrets.token_hex(32)}
    values.update(extra)
    return StaticSecretProvider(values)
