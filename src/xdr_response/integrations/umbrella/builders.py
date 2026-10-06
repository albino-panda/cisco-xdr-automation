"""Pure request builders for Cisco Umbrella (docs/integrations.md section 2.6). Base ``https://api.umbrella.com``."""
from __future__ import annotations

from collections.abc import Sequence

from xdr_response.integrations._adapter_support import ApiRequest, segment
from xdr_response.integrations.umbrella.manifest import MAX_DESTINATIONS_PER_CALL
from xdr_response.models import OperationKind

__all__ = ["BASE_URL", "TOKEN_URL", "domain_categorization", "list_destination_lists", "list_destinations",
           "add_destinations", "remove_destinations"]

BASE_URL = "https://api.umbrella.com"
#: Source: https://developer.cisco.com/docs/cloud-security/umbrella-api-getting-started/
TOKEN_URL = "https://api.umbrella.com/auth/v2/token"


def _destinations_path(list_id: str | int) -> str:
    return f"policies/v2/destinationlists/{segment(list_id)}/destinations"


def domain_categorization(domain: str) -> ApiRequest:
    """``GET /investigate/v2/domains/categorization/{domain}`` (status -1 malicious, 0 undetermined, 1 safe)."""
    return ApiRequest(operation="domain_categorization", method="GET",
                      path=f"investigate/v2/domains/categorization/{segment(domain)}")


def list_destination_lists() -> ApiRequest:
    """``GET /policies/v2/destinationlists``. Source: destination-lists overview."""
    return ApiRequest(operation="list_destination_lists", method="GET", path="policies/v2/destinationlists")


def list_destinations(list_id: str | int) -> ApiRequest:
    """``GET /policies/v2/destinationlists/{destinationListId}/destinations`` (VERIFY / idempotency read)."""
    return ApiRequest(operation="list_destinations", method="GET", path=_destinations_path(list_id),
                      kind=OperationKind.VERIFY)


def add_destinations(list_id: str | int, destinations: Sequence[str], comment: str) -> ApiRequest:
    """``POST .../destinations`` with ``[{"destination", "comment"}]`` (STATE_CHANGING, at most 500)."""
    if not destinations or len(destinations) > MAX_DESTINATIONS_PER_CALL:
        raise ValueError(f"between 1 and {MAX_DESTINATIONS_PER_CALL} destinations are required")
    return ApiRequest(operation="add_destinations", method="POST", path=_destinations_path(list_id),
                      kind=OperationKind.STATE_CHANGING,
                      json=[{"destination": d, "comment": comment} for d in destinations])


def remove_destinations(list_id: str | int, destination_ids: Sequence[int]) -> ApiRequest:
    """``DELETE .../destinations/remove`` with integer destination IDs (STATE_CHANGING, at most 500)."""
    if not destination_ids or len(destination_ids) > MAX_DESTINATIONS_PER_CALL:
        raise ValueError(f"between 1 and {MAX_DESTINATIONS_PER_CALL} destination ids are required")
    return ApiRequest(operation="remove_destinations", method="DELETE",
                      path=f"{_destinations_path(list_id)}/remove", kind=OperationKind.STATE_CHANGING,
                      json=[int(i) for i in destination_ids])
