"""Cisco Umbrella adapter (docs/integrations.md section 2.6).

Auth: OAuth2 client credentials at ``https://api.umbrella.com/auth/v2/token`` with HTTP Basic
``key:secret`` (VERIFIED). Blocking adds the domain or URL to a block destination list; the
destination ID returned by the list read is recorded in ``rollback_params`` because removal takes
IDs, not values. Every write is preceded by a read of the list (idempotency) and verified by the
same read. Direct IPv4 blocking is UNVERIFIED / CONFLICT and raises.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import CapabilityNotSupportedError, InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import (
    ApiRequest,
    HttpResultLike,
    VendorAdapter,
    body_dict,
    body_list,
)
from xdr_response.integrations.umbrella import builders
from xdr_response.integrations.umbrella.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    EnrichmentResult,
    Observable,
    ObservableType,
    TargetState,
    TargetStateCheck,
    Verdict,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["UmbrellaAdapter"]

_BLOCK = frozenset({ActionType.BLOCK_DOMAIN, ActionType.BLOCK_URL})
_UNBLOCK = frozenset({ActionType.UNBLOCK_DOMAIN, ActionType.UNBLOCK_URL})
#: Categorization status -> (verdict, risk, confidence).
_STATUS: Mapping[int, tuple[Verdict, int, int]] = {
    -1: (Verdict.MALICIOUS, 90, 80), 0: (Verdict.UNKNOWN, 0, 30), 1: (Verdict.CLEAN, 5, 70),
}


def _match(destination: Any, value: str) -> bool:
    return isinstance(destination, Mapping) and str(destination.get("destination", "")).lower() == value.lower()


class UmbrellaAdapter(VendorAdapter):
    """Umbrella: domain categorization, destination-list block and unblock."""

    name: ClassVar[str] = "umbrella"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """OAuth2 client credentials with HTTP Basic ``key:secret``."""
        from xdr_response.integrations.auth import OAuth2ClientCredentials

        return OAuth2ClientCredentials(token_url=builders.TOKEN_URL, client_id=self.secret("api_key"),
                                       client_secret=self.secret("api_secret"), basic_auth=True,
                                       transport=self.transport, clock=self.clock)

    def _health_probe(self) -> ApiRequest | None:
        return builders.list_destination_lists()

    # ---------------------------------------------------------------- reads --
    def list_destination_lists(self) -> list[Any]:
        """All destination lists of the organization."""
        return body_list(self._send(builders.list_destination_lists()).body)

    def list_destinations(self, list_id: str | int) -> list[Any]:
        """Destinations in one list (first page)."""
        return body_list(self._send(builders.list_destinations(list_id)).body)

    def security_scores(self, domain: str) -> NoReturn:
        """UNVERIFIED (search snippet only)."""
        self._unverified("security_scores")

    def risk_score(self, domain: str) -> NoReturn:
        """UNVERIFIED (search snippet only)."""
        self._unverified("risk_score")

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Domain status and categories from Umbrella Investigate."""
        if observable.type is not ObservableType.DOMAIN:
            raise CapabilityNotSupportedError(f"umbrella cannot enrich {observable.type.value}", integration=self.name)
        result = self._send(builders.domain_categorization(observable.value))
        body = body_dict(result.body)
        entry = body_dict(body.get(observable.value) or body.get(observable.value.lower()))
        status = entry.get("status")
        verdict, risk, confidence = _STATUS.get(status if isinstance(status, int) else 0, _STATUS[0])
        evidence = [self._evidence(f"Umbrella status {status} for {observable.value}",
                                   data={"status": status,
                                         "security_categories": entry.get("security_categories", []),
                                         "content_categories": entry.get("content_categories", [])})] \
            if entry else []
        return self._enrichment(observable, verdict, risk=risk, confidence=confidence if entry else 0,
                                evidence=evidence)

    # ------------------------------------------------------------ list state --
    def _list_id(self, request: ActionRequest) -> str:
        list_id = request.params.get("destination_list_id") or self._option("destination_list_id")
        if not list_id:
            raise InvalidTargetError("umbrella: params.destination_list_id (or options.destination_list_id) "
                                     "is required", integration=self.name)
        return str(list_id)

    def _find(self, list_id: str, value: str) -> tuple[str | None, HttpResultLike]:
        """(destination ID or None, read result) for ``value`` in ``list_id``."""
        result = self._send(builders.list_destinations(list_id))
        for destination in body_list(result.body):
            if _match(destination, value):
                found = destination.get("id")
                return (str(found) if found is not None else ""), result
        return None, result

    def current_state(self, request: ActionRequest) -> TargetStateCheck:
        """Read the destination list: present means blocked."""
        if request.action_type not in _BLOCK | _UNBLOCK:
            return super().current_state(request)
        found, result = self._find(self._list_id(request), request.target)
        desired = (found is not None) == (request.action_type in _BLOCK)
        return TargetStateCheck(state=TargetState.IN_DESIRED_STATE if desired else TargetState.NOT_IN_DESIRED_STATE,
                                detail=f"{request.target} {'in' if found is not None else 'not in'} list",
                                api_calls=self._calls([result]))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Re-read the destination list (VERIFIED read)."""
        if request.action_type not in _BLOCK | _UNBLOCK:
            return super().verify(request, outcome)
        found, result = self._find(self._list_id(request), request.target)
        ok = (found is not None) == (request.action_type in _BLOCK)
        return self._verification(request, VerificationStatus.VERIFIED if ok else VerificationStatus.NOT_VERIFIED,
                                  method="list_destinations", results=[result],
                                  details=f"{request.target} {'present' if found is not None else 'absent'}")

    # --------------------------------------------------------------- writes --
    def _block(self, request: ActionRequest) -> ActionOutcome:
        list_id = self._list_id(request)
        found, before = self._find(list_id, request.target)
        if found is not None:
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before], external_ref=found or None,
                                 message=f"{request.target} already in list {list_id}",
                                 rollback={"destination_list_id": list_id, "destination_id": found or None})
        added = self._send(builders.add_destinations(list_id, [request.target],
                                                     f"xdr-response {request.idempotency_key}"))
        found, after = self._find(list_id, request.target)
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, added, after], external_ref=found or None,
                             message=f"{request.target} added to list {list_id}",
                             rollback={"destination_list_id": list_id, "destination_id": found or None})

    def _unblock(self, request: ActionRequest) -> ActionOutcome:
        list_id = str(self._param(request, "destination_list_id"))
        destination_id = request.params.get("destination_id")
        results: list[HttpResultLike] = []
        if not destination_id:
            found, lookup = self._find(list_id, request.target)
            results.append(lookup)
            if found is None:
                return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=results,
                                     message=f"{request.target} not in list {list_id}")
            destination_id = found
        try:
            ids = [int(destination_id)]
        except (TypeError, ValueError):
            raise InvalidTargetError(f"umbrella: destination id {destination_id!r} is not an integer",
                                     integration=self.name) from None
        results.append(self._send(builders.remove_destinations(list_id, ids)))
        return self._outcome(ActionResultStatus.SUCCESS, results=results, external_ref=str(ids[0]),
                             message=f"{request.target} removed from list {list_id}")

    @state_changing
    def block_domain(self, request: ActionRequest) -> ActionOutcome:
        """Add the domain to the approved block destination list."""
        return self._block(request)

    @state_changing
    def block_url(self, request: ActionRequest) -> ActionOutcome:
        """Add the URL to the approved block destination list."""
        return self._block(request)

    @state_changing
    def unblock_domain(self, request: ActionRequest) -> ActionOutcome:
        """Remove the domain (by destination ID) from the list."""
        return self._unblock(request)

    @state_changing
    def unblock_url(self, request: ActionRequest) -> ActionOutcome:
        """Remove the URL (by destination ID) from the list."""
        return self._unblock(request)

    @state_changing
    def block_ip(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED / CONFLICT (section 2.6): use the XDR native action or Meraki."""
        self._unverified("block_ip")

    @state_changing
    def unblock_ip(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED / CONFLICT (section 2.6)."""
        self._unverified("unblock_ip")
