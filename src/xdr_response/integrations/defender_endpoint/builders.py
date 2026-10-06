"""Pure request builders for Microsoft Defender for Endpoint (docs/integrations.md section 2.9).

Base ``https://api.security.microsoft.com/api``; paths below are relative to it (``machines/...``
resolves to ``/api/machines/...``).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.integrations._graph import odata_string
from xdr_response.models import OperationKind

__all__ = ["BASE_URL", "SCOPE", "ISOLATION_TYPES", "INDICATOR_TYPES", "INDICATOR_ACTIONS", "get_machine",
           "isolate", "unisolate", "get_machine_action", "list_machine_actions", "submit_indicator",
           "delete_indicator"]

BASE_URL = "https://api.security.microsoft.com/api"
#: VERIFIED: https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp
SCOPE = "https://api.securitycenter.microsoft.com/.default"
ISOLATION_TYPES = ("Full", "Selective", "UnManagedDevice")
INDICATOR_TYPES = ("FileSha1", "FileMd5", "CertificateThumbprint", "FileSha256", "IpAddress", "DomainName", "Url")
INDICATOR_ACTIONS = ("Alert", "Warn", "Block", "Audit", "BlockAndRemediate", "AlertAndBlock", "Allowed")

_SC = OperationKind.STATE_CHANGING
_V = OperationKind.VERIFY


def get_machine(machine: str) -> ApiRequest:
    """``GET /api/machines/{id}`` (device ID or computer name). Source: get-machine-by-id."""
    return ApiRequest(operation="get_machine", method="GET", path=f"machines/{segment(machine)}")


def isolate(machine_id: str, comment: str, isolation_type: str = "Full") -> ApiRequest:
    """``POST /api/machines/{id}/isolate`` (201 MachineAction; 400 when already in progress)."""
    if isolation_type not in ISOLATION_TYPES:
        raise ValueError(f"IsolationType must be one of {ISOLATION_TYPES}")
    return ApiRequest(operation="isolate", method="POST", path=f"machines/{segment(machine_id)}/isolate", kind=_SC,
                      json={"Comment": comment, "IsolationType": isolation_type}, expected=(200, 201, 400))


def unisolate(machine_id: str, comment: str) -> ApiRequest:
    """``POST /api/machines/{id}/unisolate`` (201; a repeat returns 400 "Action is already in progress")."""
    return ApiRequest(operation="unisolate", method="POST", path=f"machines/{segment(machine_id)}/unisolate",
                      kind=_SC, json={"Comment": comment}, expected=(200, 201, 400))


def get_machine_action(action_id: str) -> ApiRequest:
    """``GET /api/machineactions/{id}`` (VERIFY). Source: get-machineaction-object."""
    return ApiRequest(operation="get_machine_action", method="GET", path=f"machineactions/{segment(action_id)}",
                      kind=_V)


def list_machine_actions(machine_id: str | None = None) -> ApiRequest:
    """``GET /api/machineactions`` with an optional ``$filter=machineId eq '..'``."""
    params = {"$filter": f"machineId eq {odata_string(machine_id)}"} if machine_id else None
    return ApiRequest(operation="list_machine_actions", method="GET", path="machineactions", params=params, kind=_V)


def submit_indicator(value: str, indicator_type: str, action: str, title: str, description: str,
                     expiration_time: str | None = None) -> ApiRequest:
    """``POST /api/indicators`` ("submits or updates", idempotent by value). Source: post-ti-indicator."""
    if indicator_type not in INDICATOR_TYPES:
        raise ValueError(f"indicatorType must be one of {INDICATOR_TYPES}")
    if action not in INDICATOR_ACTIONS:
        raise ValueError(f"action must be one of {INDICATOR_ACTIONS}")
    body: dict[str, Any] = {"indicatorValue": value, "indicatorType": indicator_type, "action": action,
                            "title": title, "description": description}
    if expiration_time:
        body["expirationTime"] = expiration_time
    return ApiRequest(operation="submit_indicator", method="POST", path="indicators", kind=_SC, json=body)


def delete_indicator(indicator_id: str) -> ApiRequest:
    """``DELETE /api/indicators/{id}`` (204; 404 if absent). Source: delete-ti-indicator-by-id."""
    return ApiRequest(operation="delete_indicator", method="DELETE", path=f"indicators/{segment(indicator_id)}",
                      kind=_SC, expected=(200, 204, 404))


def machine_action_status(body: Mapping[str, Any]) -> str:
    """The ``status`` of a MachineAction entity ('' when absent)."""
    status = body.get("status")
    return status if isinstance(status, str) else ""
