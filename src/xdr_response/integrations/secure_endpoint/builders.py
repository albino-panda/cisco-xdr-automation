"""Pure request builders for Cisco Secure Endpoint (docs/integrations.md section 2.2).

Base URL: ``https://api.amp.cisco.com`` (or the EU / APJC host), VERIFIED on
https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html
"""
from __future__ import annotations

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.models import OperationKind

__all__ = ["HOSTS", "list_computers", "get_computer", "get_trajectory", "list_audit_logs",
           "isolate", "stop_isolation"]

HOSTS = {
    "us": "https://api.amp.cisco.com",
    "eu": "https://api.eu.amp.cisco.com",
    "apjc": "https://api.apjc.amp.cisco.com",
}


def list_computers() -> ApiRequest:
    """``GET /v1/computers``."""
    return ApiRequest(operation="list_computers", method="GET", path="v1/computers")


def get_computer(connector_guid: str) -> ApiRequest:
    """``GET /v1/computers/{connector_guid}``. Source: secure-endpoint/whats-new."""
    return ApiRequest(operation="get_computer", method="GET", path=f"v1/computers/{segment(connector_guid)}")


def get_trajectory(connector_guid: str) -> ApiRequest:
    """``GET /v1/computers/{connector_guid}/trajectory``. Source: secure-endpoint/whats-new."""
    return ApiRequest(operation="get_trajectory", method="GET",
                      path=f"v1/computers/{segment(connector_guid)}/trajectory")


def list_audit_logs() -> ApiRequest:
    """``GET /v1/audit_logs``. Source: secure-endpoint/whats-new."""
    return ApiRequest(operation="list_audit_logs", method="GET", path="v1/audit_logs")


def isolate(connector_guid: str) -> ApiRequest:
    """``PUT /v1/computers/{connector_guid}/isolation`` (STATE_CHANGING). Source: 222226 tech note."""
    return ApiRequest(operation="isolate", method="PUT", kind=OperationKind.STATE_CHANGING,
                      path=f"v1/computers/{segment(connector_guid)}/isolation")


def stop_isolation(connector_guid: str) -> ApiRequest:
    """``DELETE /v1/computers/{connector_guid}/isolation`` (STATE_CHANGING). Source: 222226 tech note."""
    return ApiRequest(operation="stop_isolation", method="DELETE", kind=OperationKind.STATE_CHANGING,
                      path=f"v1/computers/{segment(connector_guid)}/isolation")
