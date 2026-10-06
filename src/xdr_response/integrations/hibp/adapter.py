"""Have I Been Pwned v3 adapter (docs/integrations.md section 2.15). Read-only enrichment.

Only the investigated account is ever sent (never bulk lists), and only when the disclosure policy
allows it (email addresses outside ``user_domains``). Breaches mean credential exposure, which is
reported as SUSPICIOUS (not MALICIOUS). Pwned Passwords is never used.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.integrations._adapter_support import ApiRequest, ThirdPartyLookupMixin, VendorAdapter, body_list
from xdr_response.integrations.hibp import builders
from xdr_response.integrations.hibp.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import EnrichmentResult, Observable, ObservableType, Verdict

__all__ = ["HibpAdapter", "ATTRIBUTION", "DEFAULT_USER_AGENT"]

ATTRIBUTION = "Breach data: Have I Been Pwned (haveibeenpwned.com), CC BY 4.0"
DEFAULT_USER_AGENT = "xdr-response-framework"


class HibpAdapter(ThirdPartyLookupMixin, VendorAdapter):
    """HIBP: breaches and pastes for one account."""

    name: ClassVar[str] = "hibp"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """``hibp-api-key`` header."""
        from xdr_response.integrations.auth import ApiKeyHeader

        return ApiKeyHeader("hibp-api-key", self.secret("api_key"))

    def default_headers(self) -> Mapping[str, str]:
        """The user-agent is mandatory (requests without one get 403)."""
        return {"user-agent": str(self._option("user_agent") or DEFAULT_USER_AGENT)}

    def _health_probe(self) -> ApiRequest | None:
        return builders.all_breaches()

    def _check(self, observable: Observable) -> None:
        if observable.type is not ObservableType.EMAIL_ADDRESS:
            raise CapabilityNotSupportedError(f"hibp only accepts email addresses, not {observable.type.value}",
                                              integration=self.name)

    def pastes(self, observable: Observable) -> list[Any]:
        """Pastes for one allowed account (empty when none)."""
        self._check(observable)
        if not self.disclosure.may_disclose(observable, self.name):
            raise CapabilityNotSupportedError("account withheld by the disclosure policy", integration=self.name)
        result = self._send(builders.paste_account(observable.value))
        return [] if result.status_code == 404 else body_list(result.body)

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Breaches of one account: none -> UNKNOWN; any -> SUSPICIOUS (credential exposure)."""
        self._check(observable)
        if not self.disclosure.may_disclose(observable, self.name):
            return self._withheld(observable)
        result = self._send(builders.breached_account(observable.value))
        breaches = [] if result.status_code == 404 else [b for b in body_list(result.body) if isinstance(b, dict)]
        if not breaches:
            return self._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=80)
        names = sorted(str(b.get("Name", "unknown")) for b in breaches)
        evidence = [self._evidence(f"{observable.value} appears in {len(breaches)} known breach(es). {ATTRIBUTION}",
                                   data={"breaches": names[:50]})]
        return self._enrichment(observable, Verdict.SUSPICIOUS, risk=min(80, 20 + 10 * len(breaches)),
                                confidence=90, evidence=evidence)
