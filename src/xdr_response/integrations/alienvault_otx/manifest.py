"""Capability manifest for LevelBlue (AlienVault) OTX (docs/integrations.md section 2.14)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, ObservableType, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE", "SECTIONS"]

_V = EndpointStatus.VERIFIED
_R = OperationKind.READ

SRC_API = "https://otx.alienvault.com/assets/static/external_api.html"
#: The API key header name is VERIFIED from the vendor's official SDK source.
SRC_SDK = "https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py"

#: Indicator type (path segment) -> documented sections.
SECTIONS: Mapping[str, tuple[str, ...]] = {
    "IPv4": ("general", "reputation", "geo", "malware", "url_list", "passive_dns", "http_scans"),
    "IPv6": ("general", "reputation", "geo", "malware", "url_list", "passive_dns"),
    "domain": ("general", "geo", "malware", "url_list", "passive_dns", "whois", "http_scans"),
    "hostname": ("general", "geo", "malware", "url_list", "passive_dns", "http_scans"),
    "file": ("general", "analysis"),
    "url": ("general", "url_list"),
}

REQUIRED_SECRETS: Mapping[str, str] = {"api_key": "OTX_API_KEY"}
CONFIG_OPTIONS: Mapping[str, str] = {}
HEALTH_PROBE = "indicators_domain"

_ACTIONS: Mapping[str, tuple[A, ...]] = {
    "IPv4": (A.ENRICH_IP,), "IPv6": (A.ENRICH_IP,), "domain": (A.ENRICH_DOMAIN,), "hostname": (A.ENRICH_DOMAIN,),
    "file": (A.ENRICH_HASH,), "url": (A.ENRICH_URL,),
}

MANIFEST = CapabilityManifest(
    integration="alienvault_otx",
    display_name="LevelBlue OTX (AlienVault)",
    read_actions=frozenset({A.ENRICH_IP, A.ENRICH_DOMAIN, A.ENRICH_HASH, A.ENRICH_URL}),
    enrichment_types=frozenset({ObservableType.IP, ObservableType.IPV6, ObservableType.DOMAIN,
                                ObservableType.HOSTNAME, ObservableType.SHA256, ObservableType.SHA1,
                                ObservableType.MD5, ObservableType.URL}),
    operations=tuple(
        OperationSpec(name=f"indicators_{kind.lower()}", kind=_R, status=_V, method="GET",
                      path=f"/api/v1/indicators/{kind}/{{value}}/{{section}}", source=SRC_API,
                      action_types=_ACTIONS[kind])
        for kind in SECTIONS
    ),
    rate_limit_note="Not documented: honor 429 and back off.",
)
