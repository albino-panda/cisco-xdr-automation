"""Capability manifest for VirusTotal API v3 (docs/integrations.md section 2.13)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V, _NA = EndpointStatus.VERIFIED, EndpointStatus.NOT_APPLICABLE
_R = OperationKind.READ

_DOCS = "https://docs.virustotal.com/reference/"

REQUIRED_SECRETS: Mapping[str, str] = {"api_key": "VT_API_KEY"}
CONFIG_OPTIONS: Mapping[str, str] = {}
#: Every call counts against the public quota (4/min, 500/day), so no health probe is sent.
HEALTH_PROBE = None

MANIFEST = CapabilityManifest(
    integration="virustotal",
    display_name="VirusTotal",
    read_actions=frozenset({A.ENRICH_HASH, A.ENRICH_DOMAIN, A.ENRICH_IP, A.ENRICH_URL}),
    enrichment_types=frozenset({ObservableType.SHA256, ObservableType.SHA1, ObservableType.MD5,
                                ObservableType.DOMAIN, ObservableType.IP, ObservableType.IPV6, ObservableType.URL}),
    operations=(
        OperationSpec(name="file_report", kind=_R, status=_V, method="GET", path="/files/{id}",
                      source=_DOCS + "file-info", action_types=(A.ENRICH_HASH,)),
        OperationSpec(name="domain_report", kind=_R, status=_V, method="GET", path="/domains/{domain}",
                      source=_DOCS + "domain-info", action_types=(A.ENRICH_DOMAIN,)),
        OperationSpec(name="ip_report", kind=_R, status=_V, method="GET", path="/ip_addresses/{ip}",
                      source=_DOCS + "ip-info", action_types=(A.ENRICH_IP,)),
        OperationSpec(name="url_report", kind=_R, status=_V, method="GET", path="/urls/{id}",
                      source=_DOCS + "url-info", action_types=(A.ENRICH_URL,)),
        OperationSpec(name="state_changing_ops", kind=OperationKind.STATE_CHANGING, status=_NA),
    ),
    rate_limit_note="Public API: 4 requests/min and 500/day, non-commercial use only; 429 QuotaExceededError.",
)
