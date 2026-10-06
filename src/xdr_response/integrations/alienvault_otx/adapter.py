"""LevelBlue (AlienVault) OTX adapter (docs/integrations.md section 2.14). Read-only enrichment.

Observables pass the disclosure policy first. The ``general`` section's pulse count drives the
verdict: OTX pulses are community threat reports, so absence of pulses is UNKNOWN, never CLEAN.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.integrations._adapter_support import ApiRequest, ThirdPartyLookupMixin, VendorAdapter, body_dict
from xdr_response.integrations.alienvault_otx import builders
from xdr_response.integrations.alienvault_otx.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import EnrichmentResult, Observable, ObservableType, Verdict

__all__ = ["AlienVaultOtxAdapter", "OTX_KINDS"]

#: Framework observable type -> OTX indicator type.
OTX_KINDS: Mapping[ObservableType, str] = {
    ObservableType.IP: "IPv4", ObservableType.IPV6: "IPv6", ObservableType.DOMAIN: "domain",
    ObservableType.HOSTNAME: "hostname", ObservableType.SHA256: "file", ObservableType.SHA1: "file",
    ObservableType.MD5: "file", ObservableType.URL: "url",
}


class AlienVaultOtxAdapter(ThirdPartyLookupMixin, VendorAdapter):
    """OTX: indicator details for IPs, domains, hostnames, files and URLs."""

    name: ClassVar[str] = "alienvault_otx"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """``X-OTX-API-KEY`` header."""
        from xdr_response.integrations.auth import ApiKeyHeader

        return ApiKeyHeader(builders.API_KEY_HEADER, self.secret("api_key"))

    def _health_probe(self) -> ApiRequest | None:
        return builders.indicator("domain", "example.com", "general")

    def indicator(self, observable: Observable, section: str = "general") -> dict[str, Any]:
        """Raw indicator details (disclosure-checked)."""
        kind = self._kind(observable)
        if not self.disclosure.may_disclose(observable, self.name):
            raise CapabilityNotSupportedError(f"{observable.type.value} withheld by the disclosure policy",
                                              integration=self.name)
        return body_dict(self._send(builders.indicator(kind, observable.value, section)).body)

    def _kind(self, observable: Observable) -> str:
        kind = OTX_KINDS.get(observable.type)
        if kind is None:
            raise CapabilityNotSupportedError(f"alienvault_otx cannot enrich {observable.type.value}",
                                              integration=self.name)
        return kind

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Pulse count from the ``general`` section."""
        kind = self._kind(observable)
        if not self.disclosure.may_disclose(observable, self.name):
            return self._withheld(observable)
        result = self._send(builders.indicator(kind, observable.value, "general"))
        pulses = body_dict(body_dict(result.body).get("pulse_info")).get("count")
        count = pulses if isinstance(pulses, int) and pulses > 0 else 0
        if count >= 5:
            verdict, risk = Verdict.MALICIOUS, 80
        elif count >= 1:
            verdict, risk = Verdict.SUSPICIOUS, 50
        else:
            verdict, risk = Verdict.UNKNOWN, 0
        evidence = [self._evidence(f"OTX: {observable.value} appears in {count} pulse(s)",
                                   data={"pulse_count": count})] if count else []
        return self._enrichment(observable, verdict, risk=risk, confidence=60 if count else 30, evidence=evidence)
