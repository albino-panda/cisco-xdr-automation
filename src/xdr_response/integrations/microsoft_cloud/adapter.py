"""Microsoft Defender XDR / Graph Security adapter (docs/integrations.md section 2.12). Read-only.

Investigations run a caller-supplied KQL query (``query.options["kql"]``, optional
``options["timespan"]``) through ``runHuntingQuery``; the hunting table names are not part of the
VERIFIED documentation, so the adapter never composes KQL itself. Without a query it lists
``alerts_v2`` since ``query.time_from`` and keeps the alerts that mention the subject value.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.integrations._adapter_support import ApiRequest, VendorAdapter, body_dict, body_list
from xdr_response.integrations._graph import GRAPH_BASE_URL, graph_scope, microsoft_auth
from xdr_response.integrations.microsoft_cloud import builders
from xdr_response.integrations.microsoft_cloud.manifest import INVESTIGATIONS, MANIFEST, REQUIRED_SECRETS
from xdr_response.models import InvestigationQuery, InvestigationResult

__all__ = ["MicrosoftCloudAdapter"]


def _mentions(item: Any, value: str) -> bool:
    try:
        return value.lower() in json.dumps(item, ensure_ascii=False, default=str).lower()
    except (TypeError, ValueError):
        return False


class MicrosoftCloudAdapter(VendorAdapter):
    """Cross-product Microsoft 365 Defender context: alerts and advanced hunting."""

    name: ClassVar[str] = "microsoft_cloud"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = GRAPH_BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """Client credentials at the identity platform with ``options.oauth_scope``."""
        return microsoft_auth(self, scope=graph_scope(self))

    def _health_probe(self) -> ApiRequest | None:
        return builders.list_alerts()

    def list_alerts(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        """Alerts (``alerts_v2``), optionally since a time."""
        result = self._send(builders.list_alerts(since=since))
        return [a for a in body_list(result.body, "value") if isinstance(a, dict)]

    def run_hunting_query(self, query: str, timespan: str | None = None) -> dict[str, Any]:
        """Advanced hunting (KQL); returns the raw response body."""
        return body_dict(self._send(builders.run_hunting_query(query, timespan)).body)

    def list_incidents(self) -> NoReturn:
        """UNVERIFIED."""
        self._unverified("list_incidents")

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """KQL from ``options["kql"]`` when given, else alerts that mention the subject."""
        if query.action_type not in INVESTIGATIONS:
            raise CapabilityNotSupportedError(f"microsoft_cloud cannot run {query.action_type.value}",
                                              integration=self.name)
        kql = query.options.get("kql")
        if isinstance(kql, str) and kql.strip():
            result = self._send(builders.run_hunting_query(kql, query.options.get("timespan")))
            rows = body_list(result.body, "results")
        else:
            result = self._send(builders.list_alerts(since=query.time_from))
            rows = [a for a in body_list(result.body, "value") if _mentions(a, query.subject.value)]
        findings = tuple(r for r in rows if isinstance(r, dict))[: query.limit]
        evidence = (self._evidence(f"{len(findings)} Microsoft Defender record(s) for {query.subject.value}"),) \
            if findings else ()
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=findings, evidence=evidence, api_calls=self._calls([result]))
