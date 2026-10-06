"""Pure request builders for Cisco XDR (docs/integrations.md section 2.1). No I/O here.

Hosts (VERIFIED, https://developer.cisco.com/docs/cisco-xdr/getting-started/): the IROH platform
host is the adapter base URL; the full incident view, the Global Intelligence status update and
the Automation API use the absolute hosts below.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.models import Observable, ObservableType, OperationKind

__all__ = [
    "IROH_HOSTS", "AUTOMATION_HOSTS", "CONURE_URL", "GLOBAL_INTEL_URL", "CTIM_TYPES",
    "ctim_type", "observables_body", "deliberate", "observe", "refer", "respond_observables",
    "respond_trigger", "incident_summary", "incident_full", "update_incident_status", "list_workflows",
]

IROH_HOSTS: Mapping[str, str] = {
    "us": "https://visibility.amp.cisco.com",
    "eu": "https://visibility.eu.amp.cisco.com",
    "apjc": "https://visibility.apjc.amp.cisco.com",
}
AUTOMATION_HOSTS: Mapping[str, str] = {
    "us": "https://automate.us.security.cisco.com",
    "eu": "https://automate.eu.security.cisco.com",
    "apjc": "https://automate.apjc.security.cisco.com",
}
#: Only the US host of the full incident view is documented.
CONURE_URL = "https://conure.us.security.cisco.com"
#: The status update is documented on the Global Intelligence host only.
GLOBAL_INTEL_URL = "https://intel.amp.cisco.com"

#: Framework observable type -> XDR (CTIM) observable type.
CTIM_TYPES: Mapping[ObservableType, str] = {
    ObservableType.IP: "ip", ObservableType.IPV6: "ipv6", ObservableType.DOMAIN: "domain",
    ObservableType.URL: "url", ObservableType.SHA256: "sha256", ObservableType.SHA1: "sha1",
    ObservableType.MD5: "md5", ObservableType.EMAIL_ADDRESS: "email", ObservableType.USER: "user",
    ObservableType.HOSTNAME: "hostname", ObservableType.MAC_ADDRESS: "mac_address",
    ObservableType.EMAIL_MESSAGE_ID: "email_messageid", ObservableType.FILE_PATH: "file_path",
}


def ctim_type(observable_type: ObservableType) -> str:
    """XDR observable type for ``observable_type`` (KeyError when XDR has none)."""
    return CTIM_TYPES[observable_type]


def observables_body(observables: Iterable[Observable]) -> list[dict[str, str]]:
    """The ``[{"type": ..., "value": ...}]`` body shared by the enrich and respond APIs."""
    return [{"type": ctim_type(o.type), "value": o.value} for o in observables]


def _enrich(operation: str, verb: str, observables: Iterable[Observable]) -> ApiRequest:
    return ApiRequest(operation=operation, method="POST", path=f"iroh/iroh-enrich/{verb}/observables",
                      json=observables_body(observables))


def deliberate(observables: Iterable[Observable]) -> ApiRequest:
    """``POST /iroh/iroh-enrich/deliberate/observables`` (verdicts). Source: enrich-api-guide."""
    return _enrich("deliberate_observables", "deliberate", observables)


def observe(observables: Iterable[Observable]) -> ApiRequest:
    """``POST /iroh/iroh-enrich/observe/observables`` (sightings). Source: enrich-api-guide."""
    return _enrich("observe_observables", "observe", observables)


def refer(observables: Iterable[Observable]) -> ApiRequest:
    """``POST /iroh/iroh-enrich/refer/observables`` (pivot references). Source: enrich-api-guide."""
    return _enrich("refer_observables", "refer", observables)


def respond_observables(observables: Iterable[Observable]) -> ApiRequest:
    """``POST /iroh/iroh-response/respond/observables``. Source: response-api-guide."""
    return ApiRequest(operation="list_response_actions", method="POST",
                      path="iroh/iroh-response/respond/observables", json=observables_body(observables))


def respond_trigger(module_instance_id: str, action_id: str, observable_type: str,
                    observable_value: str) -> ApiRequest:
    """``POST /iroh/iroh-response/respond/trigger/{module-instance-id}/{action-id}`` (STATE_CHANGING).

    Source: https://developer.cisco.com/docs/cisco-xdr/trigger-an-action/
    """
    return ApiRequest(
        operation="trigger_response_action", method="POST", kind=OperationKind.STATE_CHANGING,
        path=f"iroh/iroh-response/respond/trigger/{segment(module_instance_id)}/{segment(action_id)}",
        params={"observable_type": observable_type, "observable_value": observable_value},
    )


def incident_summary(incident_id: str) -> ApiRequest:
    """``GET /iroh/private-intel/incident/{incident_id}/summary``. Source: incident-management-api-guide."""
    return ApiRequest(operation="get_incident_summary", method="GET",
                      path=f"iroh/private-intel/incident/{segment(incident_id)}/summary")


def incident_full(incident_id: str) -> ApiRequest:
    """``GET https://conure.us.security.cisco.com/incidents/{incident-id}``. Source: full-summary page."""
    return ApiRequest(operation="get_incident_full", method="GET",
                      path=f"{CONURE_URL}/incidents/{segment(incident_id)}")


def update_incident_status(incident_id: str, status: str) -> ApiRequest:
    """``POST https://intel.amp.cisco.com/ctia/incident/{id}/status`` (BOOKKEEPING).

    Source: global-intelligence-api-incident-update-an-incident-status
    """
    return ApiRequest(operation="update_incident_status", method="POST", kind=OperationKind.BOOKKEEPING,
                      path=f"{GLOBAL_INTEL_URL}/ctia/incident/{segment(incident_id)}/status",
                      json={"status": status})


def list_workflows(automation_base_url: str) -> ApiRequest:
    """``GET {automation}/api/v1/workflows``. Source: automation-api-guide."""
    return ApiRequest(operation="list_workflows", method="GET",
                      path=f"{automation_base_url.rstrip('/')}/api/v1/workflows")
