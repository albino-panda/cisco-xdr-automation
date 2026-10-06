"""Microsoft Defender for Endpoint adapter (docs/integrations.md section 2.9).

Auth: client credentials with scope ``https://api.securitycenter.microsoft.com/.default`` (VERIFIED).
Isolation returns a MachineAction whose ID is the ``external_ref``; verification reads it back
(``Succeeded`` -> VERIFIED; the full status enum was not read, so anything else is UNABLE_TO_VERIFY).
A repeat isolate/unisolate returns 400 "Action is already in progress", mapped to ALREADY_CONTAINED.
Indicators (hash / IP / domain / URL) are submitted with ``POST /api/indicators`` and removed by ID;
the indicator GET is UNVERIFIED, so indicator verification is UNABLE_TO_VERIFY. Vendor-side expiry is
off by default (an automatic expiry would be a release without human release approval).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import CapabilityNotSupportedError, InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import ApiRequest, HttpResultLike, VendorAdapter, body_dict
from xdr_response.integrations._graph import microsoft_auth
from xdr_response.integrations.defender_endpoint import builders
from xdr_response.integrations.defender_endpoint.manifest import MANIFEST, REQUIRED_SECRETS
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
    TargetKind,
    Verdict,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["DefenderEndpointAdapter", "indicator_type_for"]

_ALREADY_IN_PROGRESS = "already in progress"
_ISOLATION_TYPES = frozenset({ActionType.ISOLATE_ENDPOINT, ActionType.RELEASE_ENDPOINT})
_RISK: Mapping[str, tuple[Verdict, int]] = {"High": (Verdict.SUSPICIOUS, 70), "Medium": (Verdict.SUSPICIOUS, 50)}
_HASH_TYPES = {64: "FileSha256", 40: "FileSha1", 32: "FileMd5"}


def indicator_type_for(target_kind: TargetKind, value: str) -> str:
    """MDE ``indicatorType`` for a target (no CIDR support)."""
    if target_kind is TargetKind.HASH:
        try:
            return _HASH_TYPES[len(value)]
        except KeyError:
            raise ValueError(f"unsupported hash length {len(value)}") from None
    mapping = {TargetKind.IP: "IpAddress", TargetKind.DOMAIN: "DomainName", TargetKind.URL: "Url"}
    if target_kind not in mapping:
        raise ValueError(f"no indicator type for {target_kind.value}")
    return mapping[target_kind]


def _error_text(result: HttpResultLike) -> str:
    error = body_dict(body_dict(result.body).get("error"))
    return str(error.get("message") or getattr(result, "text", "") or "")


class DefenderEndpointAdapter(VendorAdapter):
    """Defender for Endpoint: machines, isolation, machine actions, indicators."""

    name: ClassVar[str] = "defender_endpoint"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """Client credentials with the VERIFIED legacy Defender audience."""
        return microsoft_auth(self, scope=builders.SCOPE)

    def _health_probe(self) -> ApiRequest | None:
        return builders.list_machine_actions()

    # ---------------------------------------------------------------- reads --
    def get_machine(self, machine: str) -> dict[str, Any]:
        """One machine by device ID or computer name."""
        return body_dict(self._send(builders.get_machine(machine)).body)

    def get_machine_action(self, action_id: str) -> dict[str, Any]:
        """One MachineAction (status of isolate / unisolate)."""
        return body_dict(self._send(builders.get_machine_action(action_id)).body)

    def list_indicators(self) -> NoReturn:
        """Indicator list/get: UNVERIFIED."""
        self._unverified("list_indicators")

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Machine context; MDE ``riskScore`` High/Medium becomes SUSPICIOUS."""
        if observable.type not in (ObservableType.ENDPOINT_ID, ObservableType.HOSTNAME):
            raise CapabilityNotSupportedError(f"defender_endpoint cannot enrich {observable.type.value}",
                                              integration=self.name)
        machine = body_dict(self._send(builders.get_machine(observable.value)).body)
        verdict, risk = _RISK.get(str(machine.get("riskScore")), (Verdict.UNKNOWN, 0))
        fields = ("computerDnsName", "healthStatus", "riskScore", "exposureLevel")
        evidence = [self._evidence(f"MDE machine {machine.get('computerDnsName', observable.value)}: "
                                   f"riskScore={machine.get('riskScore')}", reference=machine.get("id"),
                                   data={k: machine[k] for k in fields if k in machine})] if machine else []
        return self._enrichment(observable, verdict, risk=risk, confidence=60 if machine else 0, evidence=evidence)

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """``investigate_endpoint``: the machine entity."""
        if query.action_type is not ActionType.INVESTIGATE_ENDPOINT:
            raise CapabilityNotSupportedError(f"defender_endpoint cannot run {query.action_type.value}",
                                              integration=self.name)
        result = self._send(builders.get_machine(query.subject.value))
        machine = body_dict(result.body)
        evidence = (self._evidence(f"MDE machine record for {query.subject.value}", reference=machine.get("id")),) \
            if machine else ()
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=(machine,) if machine else (), evidence=evidence,
                                   api_calls=self._calls([result]))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Isolation: read the MachineAction. Indicators: UNABLE_TO_VERIFY (indicator GET UNVERIFIED)."""
        if request.action_type not in _ISOLATION_TYPES:
            return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none",
                                      details="defender_endpoint indicator GET is UNVERIFIED")
        if outcome is None or not outcome.external_ref:
            return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none",
                                      details="no MachineAction id to read back")
        result = self._send(builders.get_machine_action(outcome.external_ref))
        status = builders.machine_action_status(body_dict(result.body))
        verified = VerificationStatus.VERIFIED if status == "Succeeded" else VerificationStatus.UNABLE_TO_VERIFY
        return self._verification(request, verified, method="get_machine_action", results=[result],
                                  details=f"MachineAction status {status or 'missing'}")

    # ------------------------------------------------------------ isolation --
    def _isolation(self, request: ActionRequest, req: ApiRequest, machine_id: str, *,
                   rollback: Mapping[str, Any] | None) -> ActionOutcome:
        result = self._send(req)
        if result.status_code == 400:
            text = _error_text(result)
            if _ALREADY_IN_PROGRESS in text.lower():
                return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[result], rollback=rollback,
                                     message=f"{req.operation} already in progress for {request.target}")
            raise InvalidTargetError(f"defender_endpoint.{req.operation}: HTTP 400: {text[:200]}",
                                     integration=self.name, http_status=400)
        action_id = body_dict(result.body).get("id")
        return self._outcome(ActionResultStatus.SUCCESS, results=[result], rollback=rollback,
                             external_ref=str(action_id) if action_id else None,
                             message=f"{req.operation} requested for {request.target} ({machine_id})")

    def _machine_id(self, request: ActionRequest) -> str:
        """``params.machine_id`` (confirmed to be the approved host) or the approved target itself."""
        machine_id = str(request.params.get("machine_id") or request.target)
        if machine_id.strip().lower() != request.target.strip().lower():
            machine = body_dict(self._send(builders.get_machine(machine_id)).body)
            self._require_identity(request, machine_id, machine, ("computerDnsName",), what="machine")
        return machine_id

    @state_changing
    def isolate_endpoint(self, request: ActionRequest) -> ActionOutcome:
        """Isolate the machine (``params.isolation_type`` Full by default)."""
        machine_id = self._machine_id(request)
        req = builders.isolate(machine_id, f"xdr-response {request.idempotency_key}",
                               str(request.params.get("isolation_type") or "Full"))
        return self._isolation(request, req, machine_id, rollback={"machine_id": machine_id})

    @state_changing
    def release_endpoint(self, request: ActionRequest) -> ActionOutcome:
        """Release the machine from isolation."""
        machine_id = self._machine_id(request)
        req = builders.unisolate(machine_id, f"xdr-response {request.idempotency_key}")
        return self._isolation(request, req, machine_id, rollback=None)

    # ----------------------------------------------------------- indicators --
    def _block(self, request: ActionRequest) -> ActionOutcome:
        try:
            indicator_type = indicator_type_for(request.target_kind, request.target)
        except ValueError as exc:
            raise InvalidTargetError(f"defender_endpoint: {exc}", integration=self.name) from None
        expiration = None
        if self._option("allow_vendor_expiry", False) is True and request.params.get("expiration_time"):
            expiration = str(request.params["expiration_time"])
        req = builders.submit_indicator(
            request.target, indicator_type, str(request.params.get("indicator_action") or "Block"),
            title=f"xdr-response {request.incident_id}",
            description=f"Approved containment {request.idempotency_key}", expiration_time=expiration,
        )
        result = self._send(req)
        indicator_id = body_dict(result.body).get("id")
        message = f"indicator {indicator_type} submitted for {request.target}"
        if indicator_id is None:
            message += " (no indicator id returned: release must look it up)"
        return self._outcome(ActionResultStatus.SUCCESS, results=[result], message=message,
                             external_ref=str(indicator_id) if indicator_id is not None else None,
                             rollback={"indicator_id": str(indicator_id) if indicator_id is not None else None})

    def _unblock(self, request: ActionRequest) -> ActionOutcome:
        indicator_id = str(self._param(request, "indicator_id"))
        result = self._send(builders.delete_indicator(indicator_id))
        if result.status_code == 404:
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[result],
                                 message=f"indicator {indicator_id} already absent")
        return self._outcome(ActionResultStatus.SUCCESS, results=[result], external_ref=indicator_id,
                             message=f"indicator {indicator_id} removed")

    @state_changing
    def block_hash(self, request: ActionRequest) -> ActionOutcome:
        return self._block(request)

    @state_changing
    def block_ip(self, request: ActionRequest) -> ActionOutcome:
        return self._block(request)

    @state_changing
    def block_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._block(request)

    @state_changing
    def block_url(self, request: ActionRequest) -> ActionOutcome:
        return self._block(request)

    @state_changing
    def unblock_hash(self, request: ActionRequest) -> ActionOutcome:
        return self._unblock(request)

    @state_changing
    def unblock_ip(self, request: ActionRequest) -> ActionOutcome:
        return self._unblock(request)

    @state_changing
    def unblock_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._unblock(request)

    @state_changing
    def unblock_url(self, request: ActionRequest) -> ActionOutcome:
        return self._unblock(request)

    # ------------------------------------------------------------ unverified --
    @state_changing
    def terminate_process(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED."""
        self._unverified("terminate_process")

    @state_changing
    def quarantine_file(self, request: ActionRequest) -> ActionOutcome:
        """Stop and quarantine file: UNVERIFIED."""
        self._unverified("quarantine_file")

    @state_changing
    def restore_file(self, request: ActionRequest) -> ActionOutcome:
        """UNVERIFIED."""
        self._unverified("restore_file")

    @state_changing
    def remove_application(self, request: ActionRequest) -> ActionOutcome:
        """Restrict app execution / removal: UNVERIFIED."""
        self._unverified("remove_application")
