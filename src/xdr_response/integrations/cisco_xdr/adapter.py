"""Cisco XDR platform adapter (docs/integrations.md sections 1.4, 1.6 and 2.1; architecture 4.2).

Native-first execution: at plan time :meth:`CiscoXdrAdapter.list_response_actions` (READ) finds the
module action for an observable; its ``module_instance_id`` and ``action_id`` go into the
recommendation params, which the approval token hashes. At execution time every native action type
dispatches to a ``@state_changing`` method that calls ``respond/trigger``. The trigger reports only
``success`` / ``failure``, so verification is delegated to ``params["verify_integration"]`` by the
verification engine and this adapter's own ``verify`` returns UNABLE_TO_VERIFY.

An XDR approval task never authorizes anything: the approval-task APIs are UNVERIFIED and raise.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, ClassVar, NoReturn

from xdr_response.errors import ApiError, CapabilityNotSupportedError, InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import (
    ApiRequest,
    HttpResultLike,
    VendorAdapter,
    body_dict,
    body_list,
)
from xdr_response.integrations.cisco_xdr import builders
from xdr_response.integrations.cisco_xdr.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    EnrichmentResult,
    EvidenceDraft,
    FrozenModel,
    InvestigationQuery,
    InvestigationResult,
    Observable,
    TargetKind,
    Verdict,
    VerificationResult,
    VerificationStatus,
    get_action_spec,
)

__all__ = ["CiscoXdrAdapter", "NativeResponseAction"]

#: XDR disposition number -> framework verdict (1 Clean, 2 Malicious, 3 Suspicious, 4 Common, 5 Unknown).
_DISPOSITIONS: Mapping[int, Verdict] = {
    1: Verdict.CLEAN, 2: Verdict.MALICIOUS, 3: Verdict.SUSPICIOUS, 4: Verdict.CLEAN, 5: Verdict.UNKNOWN,
}
_VERDICT_RANK = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}

#: XDR (CTIM) observable types a native action may name for each approved target kind. The trigger
#: always acts on the approved ``target`` itself; params can only choose among these types.
_OBSERVABLE_TYPES_FOR: Mapping[TargetKind, frozenset[str]] = {
    TargetKind.ENDPOINT: frozenset({"hostname"}),
    TargetKind.DOMAIN: frozenset({"domain"}),
    TargetKind.URL: frozenset({"url"}),
    TargetKind.IP: frozenset({"ip", "ipv6"}),
    TargetKind.HASH: frozenset({"sha256", "sha1", "md5"}),
    TargetKind.USER: frozenset({"user", "email"}),
    TargetKind.EMAIL_ADDRESS: frozenset({"email"}),
    TargetKind.EMAIL_MESSAGE: frozenset({"email_messageid"}),
}
_VERDICT_RISK = {Verdict.UNKNOWN: 0, Verdict.CLEAN: 5, Verdict.SUSPICIOUS: 60, Verdict.MALICIOUS: 90}


class NativeResponseAction(FrozenModel):
    """One response action a configured XDR module offers for an observable."""

    module_instance_id: str
    module_name: str
    action_id: str
    title: str
    observable_type: str
    observable_value: str


def _first_str(item: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _parse_response_actions(body: Any, observable: Observable) -> list[NativeResponseAction]:
    """Tolerant parse of ``respond/observables``: entries without action or instance id are skipped."""
    actions: list[NativeResponseAction] = []
    for item in body_list(body):
        if not isinstance(item, Mapping):
            continue
        action_id = _first_str(item, "id")
        instance = _first_str(item, "module_instance_id", "module-instance-id")
        if not action_id or not instance:
            continue
        query = item.get("query-params") if isinstance(item.get("query-params"), Mapping) else {}
        actions.append(NativeResponseAction(
            module_instance_id=instance,
            module_name=_first_str(item, "module", "module-name", "module_name"),
            action_id=action_id,
            title=_first_str(item, "title") or action_id,
            observable_type=_first_str(query, "observable_type") or builders.ctim_type(observable.type),
            observable_value=_first_str(query, "observable_value") or observable.value,
        ))
    return actions


def _module_verdicts(body: Any) -> list[tuple[str, Verdict]]:
    """(module, verdict) pairs from a ``deliberate/observables`` response."""
    found: list[tuple[str, Verdict]] = []
    for module in body_list(body):
        if not isinstance(module, Mapping):
            continue
        verdicts = body_dict(body_dict(module.get("data")).get("verdicts"))
        for doc in verdicts.get("docs") or []:
            if isinstance(doc, Mapping):
                verdict = _DISPOSITIONS.get(doc.get("disposition"), Verdict.UNKNOWN)  # type: ignore[arg-type]
                found.append((_first_str(module, "module") or "unknown module", verdict))
    return found


class CiscoXdrAdapter(VendorAdapter):
    """Cisco XDR: enrichment, incidents, Automation reads and native response actions."""

    name: ClassVar[str] = "cisco_xdr"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.IROH_HOSTS["us"]
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    # ------------------------------------------------------------- plumbing --
    def build_auth(self) -> Any:
        """OAuth2 client credentials, HTTP Basic, ``{iroh}/iroh/oauth2/token`` (VERIFIED)."""
        from xdr_response.integrations.auth import OAuth2ClientCredentials

        return OAuth2ClientCredentials(
            token_url=f"{self.base_url.rstrip('/')}/iroh/oauth2/token",
            client_id=self.secret("client_id"), client_secret=self.secret("client_secret"),
            basic_auth=True, transport=self.transport, clock=self.clock,
        )

    @property
    def automation_base_url(self) -> str:
        """Automation API host: ``options.automation_base_url`` or the documented regional host."""
        configured = self._option("automation_base_url")
        if configured:
            return str(configured)
        return builders.AUTOMATION_HOSTS.get((self.config.region or "us").lower(), builders.AUTOMATION_HOSTS["us"])

    def _health_probe(self) -> ApiRequest | None:
        return builders.list_workflows(self.automation_base_url)

    # ---------------------------------------------------------------- reads --
    def _observable_supported(self, observable: Observable) -> None:
        if observable.type not in builders.CTIM_TYPES:
            raise CapabilityNotSupportedError(f"cisco_xdr has no observable type for {observable.type.value}",
                                              integration=self.name)

    def enrich(self, observable: Observable) -> EnrichmentResult:
        """Verdicts from every enabled XDR module (``deliberate/observables``)."""
        self._observable_supported(observable)
        result = self._send(builders.deliberate([observable]))
        verdicts = _module_verdicts(result.body)
        if not verdicts:
            return self._enrichment(observable, Verdict.UNKNOWN, risk=0, confidence=0)
        worst = max((v for _, v in verdicts), key=_VERDICT_RANK.__getitem__)
        evidence = [self._evidence(f"XDR module {m} verdict for {observable.value}: {v.value}",
                                   data={"module": m, "verdict": v.value}) for m, v in verdicts]
        confidence = min(90, 50 + 10 * len(verdicts))
        return self._enrichment(observable, worst, risk=_VERDICT_RISK[worst], confidence=confidence,
                                evidence=evidence)

    def investigate(self, query: InvestigationQuery) -> InvestigationResult:
        """Sightings for the subject observable across modules (``observe/observables``)."""
        self._observable_supported(query.subject)
        result = self._send(builders.observe([query.subject]))
        findings: list[dict[str, Any]] = []
        evidence: list[EvidenceDraft] = []
        for module in body_list(result.body):
            if not isinstance(module, Mapping):
                continue
            sightings = body_dict(body_dict(module.get("data")).get("sightings"))
            count = sightings.get("count") if isinstance(sightings.get("count"), int) else 0
            name = _first_str(module, "module") or "unknown module"
            findings.append({"module": name, "sightings": count})
            if count:
                evidence.append(self._evidence(f"{count} sighting(s) of {query.subject.value} in {name}",
                                               data={"module": name, "sightings": count}))
        return InvestigationResult(integration=self.name, action_type=query.action_type, subject=query.subject,
                                   findings=tuple(findings), evidence=tuple(evidence),
                                   api_calls=self._calls([result]))

    def refer(self, observable: Observable) -> list[dict[str, Any]]:
        """Pivot references for an observable (``refer/observables``)."""
        self._observable_supported(observable)
        return [r for r in body_list(self._send(builders.refer([observable])).body) if isinstance(r, dict)]

    def list_response_actions(self, observable: Observable, *, module: str | None = None
                              ) -> list[NativeResponseAction]:
        """Native response actions for ``observable`` (READ), optionally filtered by module name."""
        self._observable_supported(observable)
        actions = _parse_response_actions(self._send(builders.respond_observables([observable])).body,
                                          observable)
        if module:
            actions = [a for a in actions if module.lower() in a.module_name.lower()]
        return actions

    def get_incident_summary(self, incident_id: str) -> dict[str, Any]:
        """Incident summary (Private Intelligence)."""
        return body_dict(self._send(builders.incident_summary(incident_id)).body)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Full incident view. Only the US host is documented; other regions are UNVERIFIED."""
        if (self.config.region or "us").lower() != "us":
            self._unverified("get_incident_full")
        return body_dict(self._send(builders.incident_full(incident_id)).body)

    def list_workflows(self) -> list[Any]:
        """Automation workflows (read-only)."""
        return body_list(self._send(builders.list_workflows(self.automation_base_url)).body)

    # ------------------------------------------------------------ bookkeeping --
    def update_incident_status(self, incident_id: str, status: str) -> HttpResultLike:
        """Set the XDR incident status (Global Intelligence host; BOOKKEEPING, not approval-gated)."""
        return self._send(builders.update_incident_status(incident_id, status))

    def update_incident_status_private_intel(self, incident_id: str, status: str) -> NoReturn:
        """Private Intelligence host variant: the host substitution is an inference (UNVERIFIED)."""
        self._unverified("update_incident_status_private_intel")

    def add_incident_note(self, incident_id: str, note: str) -> NoReturn:
        """Worklog note: the path was not shown on the page read (UNVERIFIED)."""
        self._unverified("add_incident_note")

    def search_incidents(self, **criteria: Any) -> NoReturn:
        """Incident search: UNVERIFIED."""
        self._unverified("search_incidents")

    def inspect(self, text: str) -> NoReturn:
        """Free-text observable extraction: UNVERIFIED."""
        self._unverified("inspect")

    def run_workflow(self, workflow_id: str, inputs: Mapping[str, Any] | None = None) -> NoReturn:
        """Run an Automation workflow via API: UNVERIFIED (and never an approval path)."""
        self._unverified("run_workflow")

    def list_approval_tasks(self) -> NoReturn:
        """Approval-task APIs: UNVERIFIED. XDR tasks are a UI surface, never an authorization."""
        self._unverified("approval_tasks")

    def respond_to_approval_task(self, task_id: str, decision: str) -> NoReturn:
        """Approval-task APIs: UNVERIFIED. XDR tasks are a UI surface, never an authorization."""
        self._unverified("approval_tasks")

    # --------------------------------------------------------------- verify --
    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """UNABLE_TO_VERIFY: ``respond/trigger`` reports only success/failure (section 2.1)."""
        delegate = request.params.get("verify_integration")
        detail = ("native trigger reports only success/failure; verify through "
                  f"{delegate}" if delegate else "native trigger reports only success/failure; no "
                  "params.verify_integration given")
        return self._verification(request, VerificationStatus.UNABLE_TO_VERIFY, method="none", details=detail)

    # ------------------------------------------------------- native trigger --
    def _approved_observable(self, request: ActionRequest) -> tuple[str, str]:
        """``(observable_type, observable_value)`` of the approved target, never another object.

        Params come from proposals (untrusted workflow data) while critical-asset evaluation and the
        decision card see only ``target``: a params-supplied value must equal the target and the type
        must fit the target kind, otherwise the trigger is refused before anything is sent.
        """
        observable_type = str(self._param(request, "observable_type"))
        allowed = _OBSERVABLE_TYPES_FOR.get(request.target_kind, frozenset())
        if observable_type not in allowed:
            raise InvalidTargetError(
                f"cisco_xdr: observable_type {observable_type!r} does not fit the approved "
                f"{request.target_kind.value} target (allowed: {sorted(allowed)})", integration=self.name)
        supplied = request.params.get("observable_value")
        if supplied not in (None, "") and str(supplied) != request.target:
            raise InvalidTargetError(
                "cisco_xdr: params.observable_value differs from the approved target; the native "
                f"action may only act on {request.target}", integration=self.name)
        return observable_type, request.target

    def _trigger(self, request: ActionRequest) -> ActionOutcome:
        """Trigger the approved module action; ``params`` name the exact module and action."""
        instance = str(self._param(request, "module_instance_id"))
        action_id = str(self._param(request, "action_id"))
        observable_type, observable_value = self._approved_observable(request)
        result = self._send(builders.respond_trigger(instance, action_id, observable_type, observable_value))
        body = body_dict(result.body)
        status = body_dict(body.get("data")).get("status")
        if status != "success":
            raise ApiError(f"cisco_xdr native action {action_id} reported {status or 'no status'}: "
                           f"{_error_text(body.get('errors'))}", integration=self.name,
                           http_status=result.status_code)
        rollback = None
        if get_action_spec(request.action_type).reversible:
            rollback = {"module_instance_id": instance, "observable_type": observable_type,
                        "observable_value": observable_value}
            if request.params.get("verify_integration"):
                rollback["verify_integration"] = request.params["verify_integration"]
        return self._outcome(ActionResultStatus.SUCCESS, results=[result], external_ref=f"{instance}/{action_id}",
                             message=f"native action {action_id} succeeded for {observable_value}",
                             rollback=rollback)

    @state_changing
    def isolate_endpoint(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def block_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def block_url(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def block_ip(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def block_hash(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def disable_user(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def quarantine_email(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def delete_email(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def release_endpoint(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def unblock_domain(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def unblock_url(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def unblock_ip(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def unblock_hash(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def enable_user(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)

    @state_changing
    def release_email(self, request: ActionRequest) -> ActionOutcome:
        return self._trigger(request)


def _error_text(errors: Any, limit: int = 3) -> str:
    if not isinstance(errors, Iterable) or isinstance(errors, (str, bytes, Mapping)):
        return "no error details"
    parts = [str(e.get("message") or e.get("error") or e) if isinstance(e, Mapping) else str(e)
             for e in list(errors)[:limit]]
    return "; ".join(parts) or "no error details"
