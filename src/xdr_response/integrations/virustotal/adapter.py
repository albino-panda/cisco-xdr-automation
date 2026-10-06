"""VirusTotal API v3 adapter (docs/integrations.md section 2.13). Read-only enrichment.

Every IoC queried is added to the VirusTotal dataset, so observables pass the
:class:`~xdr_response.config.policy.DisclosurePolicy` first (public hashes, external domains, IPs and
URLs only); withheld observables return UNKNOWN without any HTTP call. The public API is
non-commercial only and limited to 4 requests/min and 500/day.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.integrations._adapter_support import ApiRequest, ThirdPartyLookupMixin, VendorAdapter, body_dict
from xdr_response.integrations.virustotal import builders
from xdr_response.integrations.virustotal.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import EnrichmentResult, Observable, ObservableType, Verdict

__all__ = ["VirusTotalAdapter", "score_analysis"]

_HASHES = frozenset({ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5})


def score_analysis(stats: Mapping[str, Any]) -> tuple[Verdict, int, int]:
    """(verdict, risk, confidence) from ``last_analysis_stats``."""
    def count(key: str) -> int:
        value = stats.get(key)
        return value if isinstance(value, int) and value > 0 else 0

    malicious, suspicious = count("malicious"), count("suspicious")
    total = malicious + suspicious + count("harmless") + count("undetected")
    if total == 0:
        return Verdict.UNKNOWN, 0, 0
    confidence = 80 if total >= 10 else 40
    if malicious >= 5:
        return Verdict.MALICIOUS, 90, confidence
    if malicious >= 1:
        return Verdict.SUSPICIOUS, 60, confidence
    if suspicious >= 1:
        return Verdict.SUSPICIOUS, 40, confidence
    return Verdict.CLEAN, 5, confidence


class VirusTotalAdapter(ThirdPartyLookupMixin, VendorAdapter):
    """VirusTotal: file, domain, IP and URL reports."""

    name: ClassVar[str] = "virustotal"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """``x-apikey`` header."""
        from xdr_response.integrations.auth import ApiKeyHeader

        return ApiKeyHeader("x-apikey", self.secret("api_key"))

    def _request_for(self, observable: Observable) -> ApiRequest:
        if observable.type in _HASHES:
            return builders.file_report(observable.value.lower())
        if observable.type is ObservableType.DOMAIN:
            return builders.domain_report(observable.value.lower().rstrip("."))
        if observable.type in (ObservableType.IP, ObservableType.IPV6):
            return builders.ip_report(observable.value)
        if observable.type is ObservableType.URL:
            return builders.url_report(observable.value)
        raise CapabilityNotSupportedError(f"virustotal cannot enrich {observable.type.value}", integration=self.name)

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Report for an allowed observable; 404 means VirusTotal has no record (UNKNOWN)."""
        request = self._request_for(observable)
        if not self.disclosure.may_disclose(observable, self.name):
            return self._withheld(observable)
        result = self._send(request)
        if result.status_code == 404:
            return self._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=0)
        attributes = body_dict(body_dict(body_dict(result.body).get("data")).get("attributes"))
        stats = body_dict(attributes.get("last_analysis_stats"))
        verdict, risk, confidence = score_analysis(stats)
        evidence = [self._evidence(f"VirusTotal: {stats.get('malicious', 0)} malicious, "
                                   f"{stats.get('suspicious', 0)} suspicious detections for {observable.value}",
                                   data={"last_analysis_stats": dict(stats)})] if stats else []
        return self._enrichment(observable, verdict, risk=risk, confidence=confidence, evidence=evidence)
