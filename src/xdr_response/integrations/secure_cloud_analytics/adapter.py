"""Cisco Secure Cloud Analytics adapter (docs/integrations.md section 2.5).

Every operation raises :class:`UnverifiedEndpointError`; health is always UNKNOWN. Secure Cloud
Analytics alerts reach the framework as Cisco XDR incidents (read through ``cisco_xdr``).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar, NoReturn

from xdr_response.integrations._adapter_support import VendorAdapter
from xdr_response.integrations.secure_cloud_analytics.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import HealthStatus, IntegrationHealth

__all__ = ["SecureCloudAnalyticsAdapter"]


class SecureCloudAnalyticsAdapter(VendorAdapter):
    """Placeholder adapter: no VERIFIED endpoint exists yet."""

    name: ClassVar[str] = "secure_cloud_analytics"
    manifest = MANIFEST
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def health_check(self) -> IntegrationHealth:
        """Always UNKNOWN (no VERIFIED endpoint to probe)."""
        if not self.enabled:
            return self.disabled_health()
        return IntegrationHealth(integration=self.name, status=HealthStatus.UNKNOWN, checked_at=self.clock.now(),
                                 detail="no VERIFIED endpoint (docs/integrations.md 2.5); read alerts via cisco_xdr")

    def list_alerts(self) -> NoReturn:
        """UNVERIFIED."""
        self._unverified("list_alerts")

    def list_observations(self) -> NoReturn:
        """UNVERIFIED."""
        self._unverified("list_observations")

    def get_device(self, device_id: str) -> NoReturn:
        """UNVERIFIED."""
        self._unverified("get_device")
