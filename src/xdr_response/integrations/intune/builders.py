"""Pure request builders for Microsoft Intune via Graph v1.0 (docs/integrations.md section 2.11)."""
from __future__ import annotations

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.models import OperationKind

__all__ = ["get_managed_device", "remote_lock"]


def _device(managed_device_id: str) -> str:
    return f"v1.0/deviceManagement/managedDevices/{segment(managed_device_id)}"


def get_managed_device(managed_device_id: str, *, kind: OperationKind = OperationKind.READ) -> ApiRequest:
    """``GET /deviceManagement/managedDevices/{managedDeviceId}``. Source: intune-devices-manageddevice-get."""
    return ApiRequest(operation="get_managed_device", method="GET", path=_device(managed_device_id), kind=kind)


def remote_lock(managed_device_id: str) -> ApiRequest:
    """``POST .../{managedDeviceId}/remoteLock`` (STATE_CHANGING, 204).

    Source: intune-devices-manageddevice-remotelock
    """
    return ApiRequest(operation="remote_lock", method="POST", path=f"{_device(managed_device_id)}/remoteLock",
                      kind=OperationKind.STATE_CHANGING, expected=(200, 204))
