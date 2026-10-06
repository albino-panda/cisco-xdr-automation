"""Capability manifest for Have I Been Pwned v3 (docs/integrations.md section 2.15)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V = EndpointStatus.VERIFIED
_R = OperationKind.READ

SRC_API = "https://haveibeenpwned.com/API/v3"

REQUIRED_SECRETS: Mapping[str, str] = {"api_key": "HIBP_API_KEY"}
CONFIG_OPTIONS: Mapping[str, str] = {
    "user_agent": "Mandatory user-agent sent on every request (default: xdr-response-framework)",
}
HEALTH_PROBE = "all_breaches"

MANIFEST = CapabilityManifest(
    integration="hibp",
    display_name="Have I Been Pwned",
    read_actions=frozenset({A.ENRICH_EMAIL_ADDRESS}),
    enrichment_types=frozenset({ObservableType.EMAIL_ADDRESS}),
    operations=(
        OperationSpec(name="breached_account", kind=_R, status=_V, method="GET", path="/breachedaccount/{account}",
                      source=SRC_API, action_types=(A.ENRICH_EMAIL_ADDRESS,)),
        OperationSpec(name="paste_account", kind=_R, status=_V, method="GET", path="/pasteaccount/{account}",
                      source=SRC_API),
        OperationSpec(name="all_breaches", kind=_R, status=_V, method="GET", path="/breaches", source=SRC_API),
        # VERIFIED but never used: this framework never handles passwords. No method sends it.
        OperationSpec(name="pwned_passwords_range", kind=_R, status=_V, method="GET",
                      path="https://api.pwnedpasswords.com/range/{first5sha1}", source=SRC_API),
    ),
    rate_limit_note="Depends on the subscription; 429 carries retry-after in seconds. Attribution (CC BY 4.0) "
                    "is required when breach data is shown.",
)
