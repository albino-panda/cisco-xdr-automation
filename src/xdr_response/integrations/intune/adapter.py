"""Microsoft Intune adapter via Graph v1.0 (docs/integrations.md section 2.11).

``lock_device`` sends ``remoteLock`` to ``params.managed_device_id`` (no API undo was read, so it is
not reversible). Verification would read ``deviceActionResults``, but the lock ``actionName`` string
was not read, so it is UNABLE_TO_VERIFY. Retire, wipe, sync and app removal are UNVERIFIED.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import VendorAdapter, body_dict
from xdr_response.integrations._graph import GRAPH_BASE_URL, graph_scope, microsoft_auth
from xdr_response.integrations.intune import builders
from xdr_response.integrations.intune.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    EnrichmentResult,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    Verdict,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["IntuneAdapter"]

_DEVICE_FIELDS = ("deviceName", "complianceState", "lastSyncDateTime", "operatingSystem")


class IntuneAdapter(VendorAdapter):
    """Intune: managed device reads and remote lock."""

    name: ClassVar[str] = "intune"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = GRAPH_BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """Client credentials at the identity platform with ``options.oauth_scope``."""
        return microsoft_auth(self, scope=graph_scope(self))

    def get_managed_device(self, managed_device_id: str) -> dict[str, Any]:
        """One managed device (includes ``deviceActionResults`` and ``complianceState``)."""
        return body_dict(self._send(builders.get_managed_device(managed_device_id)).body)

    def retire_device(self, managed_device_id: str) -> NoReturn:
        """UNVERIFIED (and out of scope for automated containment)."""
        self._unverified("retire_wipe")

    def wipe_device(self, managed_device_id: str) -> NoReturn:
        """UNVERIFIED (and out of scope for automated containment)."""
        self._unverified("retire_wipe")

    def sync_device(self, managed_device_id: str) -> NoReturn:
        """UNVERIFIED."""
        self._unverified("sync_scan")

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Compliance context for a managed device ID (no reputation verdict)."""
        if observable.type is not ObservableType.ENDPOINT_ID:
            raise CapabilityNotSupportedError(f"intune cannot enrich {observable.type.value}", integration=self.name)
        device = body_dict(self._send(builders.get_managed_device(observable.value)).body)
        evidence = [self._evidence(f"Intune device {device.get('deviceName', observable.value)}: "
                                   f"complianceState={device.get('complianceState')}", reference=observable.value,
                                   data={k: device[k] for k in _DEVICE_FIELDS if k in device})] if device else []
        return self._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=50 if device else 0,
                                evidence=evidence)

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """``investigate_endpoint`` for a managed device ID."""
        if query.subject.type is not ObservableType.ENDPOINT_ID:
            raise CapabilityNotSupportedError(f"intune cannot investigate {query.subject.type.value}",
                                              integration=self.name)
        result = self._send(builders.get_managed_device(query.subject.value))
        device = body_dict(result.body)
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=(device,) if device else (), api_calls=self._calls([result]))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """UNABLE_TO_VERIFY: the remoteLock ``actionName`` in ``deviceActionResults`` was not read."""
        return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none",
                                  details="intune remoteLock actionName is UNVERIFIED")

    @state_changing
    def lock_device(self, request: ActionRequest) -> ActionOutcome:
        """Remote-lock the approved managed device."""
        device_id = str(self._param(request, "managed_device_id"))
        lookup = self._send(builders.get_managed_device(device_id))
        self._require_identity(request, device_id, body_dict(lookup.body), ("deviceName",),
                               what="managed device")
        result = self._send(builders.remote_lock(device_id))
        return self._outcome(ActionResultStatus.SUCCESS, results=[lookup, result], external_ref=device_id,
                             message=f"remote lock sent to {request.target}")

    @state_changing
    def remove_application(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED."""
        self._unverified("remove_application")
