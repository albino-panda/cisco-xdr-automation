"""Cisco Secure Endpoint adapter (docs/integrations.md section 2.2).

Auth: HTTP Basic ``client_id:api_key`` (VERIFIED, https://developer.cisco.com/docs/secure-endpoint/overview/).
Isolation is implemented directly (PUT / DELETE ``/v1/computers/{guid}/isolation``); the connector
GUID must be in ``params["connector_guid"]`` so the analyst approves the exact device. The
isolation-state GET is UNVERIFIED, so ``current_state`` is UNKNOWN and ``verify`` is
UNABLE_TO_VERIFY. Hash blocking should use the Cisco XDR native action; the file-list endpoints are
UNVERIFIED and raise.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import CapabilityNotSupportedError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import ApiRequest, VendorAdapter, body_dict, body_list
from xdr_response.integrations.secure_endpoint import builders
from xdr_response.integrations.secure_endpoint.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    EnrichmentResult,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    ObservableType,
    Verdict,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["SecureEndpointAdapter"]


class SecureEndpointAdapter(VendorAdapter):
    """Secure Endpoint: computer lookups, trajectory, audit logs, isolation."""

    name: ClassVar[str] = "secure_endpoint"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.HOSTS["us"]
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """HTTP Basic with the client ID and API key."""
        from xdr_response.integrations.auth import BasicAuth

        return BasicAuth(self.secret("client_id"), self.secret("api_key"))

    def _health_probe(self) -> ApiRequest | None:
        return builders.list_computers()

    # ---------------------------------------------------------------- reads --
    def list_computers(self) -> list[dict[str, Any]]:
        """All computers visible to the API client (single page)."""
        return [c for c in body_list(self._send(builders.list_computers()).body) if isinstance(c, dict)]

    def find_computers(self, hostname: str) -> list[dict[str, Any]]:
        """Computers whose ``hostname`` equals ``hostname`` (case-insensitive, filtered client-side)."""
        wanted = hostname.strip().lower()
        return [c for c in self.list_computers() if str(c.get("hostname", "")).lower() == wanted]

    def get_computer(self, connector_guid: str) -> dict[str, Any]:
        """One computer by connector GUID."""
        return body_dict(body_dict(self._send(builders.get_computer(connector_guid)).body).get("data"))

    def list_audit_logs(self) -> list[Any]:
        """Console audit log entries."""
        return body_list(self._send(builders.list_audit_logs()).body)

    def get_isolation(self, connector_guid: str) -> NoReturn:
        """Isolation status GET: UNVERIFIED (JavaScript-rendered docs page)."""
        self._unverified("get_isolation")

    def list_events(self) -> NoReturn:
        """Events API: UNVERIFIED."""
        self._unverified("list_events")

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Context for a connector GUID (no reputation verdict)."""
        if observable.type is not ObservableType.ENDPOINT_ID:
            raise CapabilityNotSupportedError(f"secure_endpoint cannot enrich {observable.type.value}",
                                              integration=self.name)
        result = self._send(builders.get_computer(observable.value))
        data = body_dict(body_dict(result.body).get("data"))
        evidence = [self._evidence(f"Secure Endpoint computer {data.get('hostname', observable.value)}",
                                   reference=observable.value,
                                   data={k: data[k] for k in ("hostname", "operating_system", "active")
                                         if k in data})]
        return self._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=50 if data else 0,
                                evidence=evidence if data else ())

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """Device trajectory for a connector GUID (``investigate_endpoint``)."""
        if query.action_type is not ActionType.INVESTIGATE_ENDPOINT or \
                query.subject.type is not ObservableType.ENDPOINT_ID:
            raise CapabilityNotSupportedError(f"secure_endpoint cannot run {query.action_type.value} on "
                                              f"{query.subject.type.value}", integration=self.name)
        result = self._send(builders.get_trajectory(query.subject.value))
        events = body_list(body_dict(body_dict(result.body).get("data")), "events")[: query.limit]
        evidence = [self._evidence(f"{len(events)} trajectory event(s) for {query.subject.value}",
                                   reference=query.subject.value)] if events else []
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=tuple(e for e in events if isinstance(e, dict)),
                                   evidence=tuple(evidence), api_calls=self._calls([result]))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """UNABLE_TO_VERIFY: the isolation GET is UNVERIFIED (docs/integrations.md section 3)."""
        return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none",
                                  details="secure_endpoint isolation status GET is UNVERIFIED")

    # --------------------------------------------------------------- writes --
    def _approved_guid(self, request: ActionRequest) -> tuple[str, Any]:
        """The connector GUID from params, confirmed (VERIFIED computer GET) to be the approved host."""
        guid = str(self._param(request, "connector_guid"))
        lookup = self._send(builders.get_computer(guid))
        computer = body_dict(body_dict(lookup.body).get("data"))
        self._require_identity(request, guid, computer, ("hostname",), what="computer")
        return guid, lookup

    @state_changing
    def isolate_endpoint(self, request: ActionRequest) -> ActionOutcome:
        """Start isolation of the approved connector GUID (confirmed to be the approved host first)."""
        guid, lookup = self._approved_guid(request)
        result = self._send(builders.isolate(guid))
        return self._outcome(ActionResultStatus.SUCCESS, results=[lookup, result], external_ref=guid,
                             message=f"isolation requested for {request.target}",
                             rollback={"connector_guid": guid})

    @state_changing
    def release_endpoint(self, request: ActionRequest) -> ActionOutcome:
        """Stop isolation of the approved connector GUID (confirmed to be the approved host first)."""
        guid, lookup = self._approved_guid(request)
        result = self._send(builders.stop_isolation(guid))
        return self._outcome(ActionResultStatus.SUCCESS, results=[lookup, result], external_ref=guid,
                             message=f"isolation stopped for {request.target}")

    @state_changing
    def block_hash(self, request: ActionRequest) -> ActionOutcome:
        """File-list block: UNVERIFIED (use the Cisco XDR native Block File Hashes action)."""
        self._unverified("block_hash")

    @state_changing
    def unblock_hash(self, request: ActionRequest) -> ActionOutcome:
        """File-list unblock: UNVERIFIED."""
        self._unverified("unblock_hash")

    @state_changing
    def terminate_process(self, request: ActionRequest) -> ActionOutcome:
        """No endpoint read: UNVERIFIED."""
        self._unverified("terminate_process")

    @state_changing
    def quarantine_file(self, request: ActionRequest) -> ActionOutcome:
        """No endpoint read: UNVERIFIED."""
        self._unverified("quarantine_file")

    @state_changing
    def restore_file(self, request: ActionRequest) -> ActionOutcome:
        """No endpoint read: UNVERIFIED."""
        self._unverified("restore_file")
