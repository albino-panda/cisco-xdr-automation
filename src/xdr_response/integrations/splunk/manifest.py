"""Capability manifest for Splunk (optional, disabled by default; docs/integrations.md section 2.16)."""
from __future__ import annotations

from collections.abc import Mapping

from xdr_response.integrations.base import CapabilityManifest, OperationSpec
from xdr_response.models import ActionType as A
from xdr_response.models import EndpointStatus, OperationKind

__all__ = ["MANIFEST", "REQUIRED_SECRETS", "CONFIG_OPTIONS", "HEALTH_PROBE"]

_V, _U = EndpointStatus.VERIFIED, EndpointStatus.UNVERIFIED
_R, _BK = OperationKind.READ, OperationKind.BOOKKEEPING

SRC_SEARCH = ("https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/9.4/"
              "rest-api-tutorials/creating-searches-using-the-rest-api")
SRC_HEC = ("https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/"
           "get-data-with-http-event-collector/http-event-collector-examples")

_SEARCHES = (A.SEARCH_HASH_ENTERPRISE, A.SEARCH_DOMAIN_ENTERPRISE, A.SEARCH_IP_ENTERPRISE, A.SEARCH_USER_ACTIVITY,
             A.SEARCH_RELATED_ENDPOINTS, A.SEARCH_RELATED_USERS, A.INVESTIGATE_AUTHENTICATION,
             A.INVESTIGATE_NETWORK_CONNECTION)

#: ``token`` is the REST session key (``Authorization: Splunk <key>``); ``hec_token`` is for HEC.
#: With ``options.auth_mode: basic`` the logical secrets ``username`` / ``password`` are used instead.
REQUIRED_SECRETS: Mapping[str, str] = {"token": "SPLUNK_TOKEN", "hec_token": "SPLUNK_HEC_TOKEN"}
CONFIG_OPTIONS: Mapping[str, str] = {
    "auth_mode": "session_key (default, VERIFIED header format), basic (VERIFIED) or bearer (UNVERIFIED: raises)",
    "hec_url": "HTTP Event Collector base URL, for example https://splunk.example.test:8088",
    "hec_sourcetype": "Sourcetype of forwarded audit events (default xdr_response:audit)",
    "spl": "Default SPL for investigations (otherwise a quoted term search on the subject)",
    "poll_attempts": "Result polls before giving up (default 10)",
    "poll_interval_seconds": "Seconds between result polls (default 1)",
}
HEALTH_PROBE = "create_search_job"  # only when enabled; '| makeresults'

MANIFEST = CapabilityManifest(
    integration="splunk",
    display_name="Splunk (optional)",
    optional=True,
    enabled_by_default=False,
    read_actions=frozenset(_SEARCHES),
    operations=(
        OperationSpec(name="create_search_job", kind=_R, status=_V, method="POST", path="/services/search/jobs",
                      source=SRC_SEARCH, action_types=_SEARCHES),
        OperationSpec(name="get_search_results", kind=_R, status=_V, method="GET",
                      path="/services/search/jobs/{sid}/results", source=SRC_SEARCH),
        OperationSpec(name="auth_login", kind=_R, status=_V, method="POST", path="/services/auth/login",
                      source=SRC_SEARCH),
        OperationSpec(name="auth_bearer_token", kind=_R, status=_U),
        OperationSpec(name="export", kind=_R, status=_U, method="GET", path="/services/search/v2/jobs/export"),
        OperationSpec(name="forward_audit", kind=_BK, status=_V, method="POST",
                      path="https://{host}:8088/services/collector/event", source=SRC_HEC),
    ),
    rate_limit_note="Not documented on the pages read.",
)
