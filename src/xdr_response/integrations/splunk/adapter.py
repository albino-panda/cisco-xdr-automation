"""Splunk adapter: optional, disabled by default, never a hard dependency (docs/integrations.md 2.16).

* Search (READ): create a job (``POST /services/search/jobs``), then poll its results with the
  injected ``sleep``. Auth is a REST session key sent as ``Authorization: Splunk <key>`` (default) or
  HTTP Basic (``options.auth_mode: basic``); Splunk bearer tokens are UNVERIFIED and refused.
* Audit forwarding (BOOKKEEPING): ``POST {hec_url}/services/collector/event`` with
  ``Authorization: Splunk <hec_token>`` through a second guarded client. Events are passed through
  the central redactor before sending. HEC writes are not containment and need no approval.
"""
from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.clock import utc
from xdr_response.errors import ApiError, ConfigError, IntegrationTimeoutError
from xdr_response.integrations._adapter_support import ApiRequest, VendorAdapter, body_dict, body_list
from xdr_response.integrations.splunk import builders
from xdr_response.integrations.splunk.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import InvestigationQuery, InvestigationResult

__all__ = ["SplunkAdapter"]

_DEFAULT_SOURCETYPE = "xdr_response:audit"


class SplunkAdapter(VendorAdapter):
    """Splunk: search jobs for investigation and HEC audit forwarding."""

    name: ClassVar[str] = "splunk"
    manifest = MANIFEST
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._hec_http: Any = None

    # ------------------------------------------------------------- plumbing --
    def build_auth(self) -> Any:
        """Session key (``Authorization: Splunk <key>``) or HTTP Basic; bearer tokens are UNVERIFIED."""
        mode = str(self._option("auth_mode", "session_key"))
        if mode == "bearer":
            self._unverified("auth_bearer_token")
        if mode not in ("basic", "session_key"):
            raise ConfigError(f"splunk: unknown options.auth_mode {mode!r}")
        from xdr_response.integrations.auth import ApiKeyHeader, BasicAuth

        if mode == "basic":
            return BasicAuth(self.secret("username"), self.secret("password"))
        return ApiKeyHeader("Authorization", self.secret("token"), prefix="Splunk ")

    def _build_hec_client(self) -> Any:
        from xdr_response.integrations.auth import ApiKeyHeader
        from xdr_response.integrations.http import GuardedHttpClient, RateLimiter, RetryPolicy

        hec_url = self._option("hec_url")
        if not hec_url:
            raise ConfigError("splunk: options.hec_url is required for audit forwarding")
        cfg = self.config
        return GuardedHttpClient(
            self.name, str(hec_url), timeout=cfg.timeout_seconds,
            retry=RetryPolicy(max_retries=cfg.max_retries, backoff_base=cfg.backoff_base_seconds,
                              backoff_max=cfg.backoff_max_seconds),
            rate_limiter=RateLimiter(cfg.rate_limit_per_minute, clock=self.clock, sleep=self.sleep),
            auth=ApiKeyHeader("Authorization", self.secret("hec_token"), prefix="Splunk "),
            transport=self.transport, clock=self.clock, sleep=self.sleep, audit=self.audit,
            manifest=self.manifest,
        )

    @property
    def hec_http(self) -> Any:
        """Guarded client for the HTTP Event Collector, built on first use (manifest-checked)."""
        if self._hec_http is None:
            self._hec_http = self._bind_manifest(self._build_hec_client())
        return self._hec_http

    @hec_http.setter
    def hec_http(self, client: Any) -> None:
        self._hec_http = self._bind_manifest(client)

    def close(self) -> None:
        super().close()
        if self._hec_http is not None:
            self._hec_http.close()

    def _health_probe(self) -> ApiRequest | None:
        return builders.create_search_job("| makeresults", "-1m", "now")

    def _pause(self, seconds: float) -> None:
        (self.sleep or time.sleep)(seconds)

    # --------------------------------------------------------------- search --
    def search(self, spl: str, earliest_time: str = "-24h", latest_time: str = "now",
               limit: int = 100) -> list[dict[str, Any]]:
        """Run a search job and return up to ``limit`` result rows."""
        job = self._send(builders.create_search_job(spl, earliest_time, latest_time))
        sid = body_dict(job.body).get("sid")
        if not sid:
            raise ApiError("splunk: search job returned no sid", integration=self.name, http_status=job.status_code)
        attempts = int(self._option("poll_attempts", 10))
        interval = float(self._option("poll_interval_seconds", 1.0))
        for attempt in range(attempts):
            result = self._send(builders.get_search_results(str(sid)))
            if result.status_code != 204:
                rows = [r for r in body_list(result.body, "results") if isinstance(r, dict)]
                return rows[:limit]
            if attempt + 1 < attempts:
                self._pause(interval)
        raise IntegrationTimeoutError(f"splunk: results for job {sid} not ready after {attempts} polls",
                                      integration=self.name)

    def export(self, spl: str) -> NoReturn:
        """Streaming export: UNVERIFIED (search snippet only)."""
        self._unverified("export")

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """SPL from ``options.spl`` (query or config), else a quoted term search on the subject."""
        spl = query.options.get("spl") or self._option("spl") or builders.quoted_term_search(query.subject.value)
        earliest = utc(query.time_from).strftime("%Y-%m-%dT%H:%M:%S") if query.time_from else "-24h"
        latest = utc(query.time_to).strftime("%Y-%m-%dT%H:%M:%S") if query.time_to else "now"
        rows = self.search(str(spl), earliest, latest, limit=query.limit)
        evidence = (self._evidence(f"{len(rows)} Splunk event(s) for {query.subject.value}"),) if rows else ()
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=tuple(rows), evidence=evidence)

    # ---------------------------------------------------------- bookkeeping --
    def forward_audit(self, event: Mapping[str, Any]) -> bool:
        """Send one redacted audit event to HEC. Returns False (nothing sent) when Splunk is disabled."""
        if not self.enabled:
            return False
        from xdr_response.logs.redaction import get_redactor

        redacted = get_redactor().redact(dict(event))
        sourcetype = str(self._option("hec_sourcetype", _DEFAULT_SOURCETYPE))
        self._send(builders.hec_event(redacted, sourcetype), client=self.hec_http)
        return True
