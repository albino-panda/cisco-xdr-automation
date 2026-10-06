"""Release package planning (architecture sections 8.2 and 13.17).

:class:`RestorationPlanner` turns registry entries that are still in force into a
:class:`ReleasePackage` for a human release approval. It never reads vendor state and never
invents a control: every release action restores exactly one registry entry of the same incident,
named by its ``control_key`` (no wildcards, no tenant-wide release).

A release action is ``ELEVATED`` (with an explicit warning, never a silent block) when:

* the control was created under ELEVATED approval, or the rollback type is always elevated;
* the target is a critical asset *now* (``config/critical-assets.yaml`` is evaluated at release
  time, so a control recorded STANDARD before the asset was classified still needs elevation);
* the target is critical by name pattern, or by the group / tag / IP context of the incident's
  asset record (``incident.assets``), evaluated at release time;
* another incident depends on the same effective control: it holds its own registered control on
  the same target, or its approved containment of the target found it ALREADY_CONTAINED (no control
  of its own). The warning names that incident, because releasing lifts its containment too.

:func:`required_release_level` is the single rule (registry level, catalog, critical assets with
asset context, dependent incidents); the restoration engine re-applies exactly the same rule at
execution time so a release package cannot carry a lower level than the policy demands.

Provenance: a registry entry is only treated as "created by automation" when its approval token
was actually consumed for that control key (the token-use ledger records every authorized write)
and the execution record, when one exists, is a SUCCESS of that package. Entries without that
provenance (for example a manual block registered by hand) are never auto-selected for release;
when named explicitly they are shown with an explicit warning, and the engine refuses to release
them.

``outstanding`` reports every control that may still be in force, including ``RELEASE_PENDING``
(a release that crashed between the registry update and the vendor call).
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import timedelta
from typing import Any, Protocol

from xdr_response.clock import Clock, SystemClock
from xdr_response.config.schema import Settings
from xdr_response.errors import RegistryError
from xdr_response.interfaces import ControlRegistry
from xdr_response.models import (
    ActionResultStatus,
    ApprovalLevel,
    Asset,
    ControlStatus,
    CriticalAssetWarning,
    Evidence,
    EvidenceDraft,
    Incident,
    RecommendedAction,
    ReleasePackage,
    TargetKind,
    TemporaryControl,
    evidence_snapshot_hash,
    format_datetime,
    get_action_spec,
    make_idempotency_key,
    number_evidence,
)
from xdr_response.restoration.registry import RELEASABLE_STATUSES

__all__ = ["RestorationPlanner", "RELEASE_RISK_SCORE", "RELEASE_CONFIDENCE_SCORE", "REGISTRY_SOURCE",
           "required_release_level", "release_params", "dependent_incidents", "incident_asset",
           "IN_FORCE_STATUSES", "ProvenanceCheck", "control_provenance"]

#: Statuses of a control that may still be in force at the vendor (reported on close and review).
IN_FORCE_STATUSES = frozenset({*RELEASABLE_STATUSES, ControlStatus.RELEASE_PENDING})
#: Returns why a registry entry has no automation provenance, or None when it does.
ProvenanceCheck = Callable[[TemporaryControl], "str | None"]


class CriticalAssetEvaluator(Protocol):
    """The part of ``approval.CriticalAssetPolicy`` the planner and engine use."""

    def evaluate(self, action_type: Any, target: str, target_kind: Any,
                 asset: Any = None) -> list[CriticalAssetWarning]:
        ...


def release_params(control: TemporaryControl) -> dict[str, Any]:
    """The only params a release of ``control`` may carry: the recorded rollback params plus ``restores``."""
    return {**control.rollback_params, "restores": control.control_key}


_ENDPOINT_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM})
_USER_KINDS = frozenset({TargetKind.USER, TargetKind.ROLE_ASSIGNMENT, TargetKind.EMAIL_ADDRESS})


def incident_asset(incident: Incident | None, target: str, kind: TargetKind) -> Asset | None:
    """The asset record of ``incident`` that describes ``target`` (endpoint or user part), if any."""
    if incident is None:
        return None
    name = target.partition("/")[0] if kind not in (TargetKind.URL, TargetKind.ENDPOINT, TargetKind.USER) else target
    wanted = (TargetKind.ENDPOINT if kind in _ENDPOINT_KINDS
              else TargetKind.USER if kind in _USER_KINDS else kind)
    for asset in incident.assets:
        if asset.kind is wanted and asset.name.lower() == name.lower():
            return asset
    return None


def critical_release_warnings(control: TemporaryControl, critical_assets: CriticalAssetEvaluator | None,
                              asset: Asset | None = None) -> list[CriticalAssetWarning]:
    """Critical-asset warnings for releasing ``control`` under the current configuration.

    ``asset`` (from the incident's asset records) lets group, tag and IP rules match too.
    """
    if critical_assets is None:
        return []
    spec = get_action_spec(control.rollback_action_type)
    return list(critical_assets.evaluate(control.rollback_action_type, control.target, spec.target_kind, asset))


def dependent_incidents(control: TemporaryControl, registry: ControlRegistry, executions: Any = None) -> list[str]:
    """Other incidents that hold the same effective control on the same target."""
    found: set[str] = set()
    for other in registry.list():
        if (other.incident_id != control.incident_id and other.action_type is control.action_type
                and other.target == control.target and other.status in RELEASABLE_STATUSES):
            found.add(other.incident_id)
    records: list[Any] = []
    if executions is not None:
        try:
            records = list(executions.list())
        except Exception:  # noqa: BLE001 - advisory: a failing store never hides the registry check
            records = []
    for record in records:
        result = getattr(record, "result", None)
        if (result is not None and record.incident_id != control.incident_id
                and result.action_type is control.action_type and result.target == control.target
                and result.status in (ActionResultStatus.SUCCESS, ActionResultStatus.ALREADY_CONTAINED)):
            found.add(record.incident_id)
    return sorted(found)


def control_provenance(tokens: Any, executions: Any = None) -> ProvenanceCheck:
    """Provenance rule: the control's token was consumed for exactly its control key.

    The token-use ledger records every write the execution guard authorized, so an entry for a
    control the automation never created (a manual block registered by hand, invented ids, or ids
    borrowed from a genuine control of another key) has no matching ledger entry. When an execution
    record of the control's package exists it must have succeeded and registered the control.
    """
    def check(control: TemporaryControl) -> str | None:
        was_used = getattr(tokens, "was_used", None)
        if not callable(was_used):
            return "the token-use ledger cannot be consulted"
        if not was_used(control.token_id, control.control_key):
            return (f"approval token {control.token_id} never authorized {control.control_key} "
                    f"(package {control.package_id})")
        if executions is not None:
            try:
                record = executions.get(control.package_id, control.control_key)
            except Exception:  # noqa: BLE001 - the ledger check above still holds
                record = None
            result = getattr(record, "result", None)
            if result is not None and not result.control_registered and                     result.status is not ActionResultStatus.SUCCESS:
                return f"the recorded execution of {control.control_key} ended {result.status.value}"
        return None

    return check


def required_release_level(control: TemporaryControl,
                           critical_assets: CriticalAssetEvaluator | None = None, *,
                           asset: Asset | None = None,
                           dependents: Sequence[str] = ()) -> ApprovalLevel:
    """Minimum approval level for releasing ``control``.

    ELEVATED for an ELEVATED registry record, an always-elevated rollback type, a critical asset
    (name pattern, or group / tag / IP of ``asset``) and when other incidents depend on the control.
    """
    spec = get_action_spec(control.rollback_action_type)
    if (control.approval_level is ApprovalLevel.ELEVATED or spec.always_elevated or dependents
            or critical_release_warnings(control, critical_assets, asset)):
        return ApprovalLevel.ELEVATED
    return ApprovalLevel.STANDARD

#: Evidence source for release actions (allowed by ``models.evidence``).
REGISTRY_SOURCE = "temporary_control_registry"
#: A release restores a state recorded by automation; no threat scoring is applied to it.
RELEASE_RISK_SCORE = 0
#: The registry entry is first-hand evidence that the control exists and was created by automation.
RELEASE_CONFIDENCE_SCORE = 100


def _control_evidence(control: TemporaryControl) -> EvidenceDraft:
    """Evidence draft describing who created ``control`` and under which approval."""
    return EvidenceDraft(
        source=REGISTRY_SOURCE,
        summary=(
            f"Temporary control {control.action_type.value} on {control.target} was created by "
            f"automation for incident {control.incident_id} via {control.integration} "
            f"(containment package {control.package_id}, approval token {control.token_id}); "
            f"status {control.status.value}"
        ),
        observed_at=control.created_at,
        reference=control.control_key,
        data={
            "control_key": control.control_key,
            "action_type": control.action_type.value,
            "integration": control.integration,
            "workflow_id": control.workflow_id,
            "workflow_version": control.workflow_version,
            "package_id": control.package_id,
            "token_id": control.token_id,
            "decision_id": control.decision_id,
            "created_at": format_datetime(control.created_at),
            "external_ref": control.external_ref,
            "status": control.status.value,
        },
    )


def _dependent_warning(control: TemporaryControl, incident_id: str) -> CriticalAssetWarning:
    """Warning that releasing ``control`` also lifts a containment another incident relies on."""
    rollback = control.rollback_action_type
    return CriticalAssetWarning(
        asset=control.target,
        asset_class=None,
        role=f"also contained for incident {incident_id}",
        action_type=rollback,
        potential_impact=(
            f"releasing {control.target} also lifts the containment that incident {incident_id} "
            "approved (same target and control); coordinate with that incident before approving"
        ),
        message=(
            f"WARNING: ELEVATED APPROVAL REQUIRED - {rollback.value} on {control.target} also removes "
            f"the containment incident {incident_id} depends on"
        ),
    )


def _provenance_warning(control: TemporaryControl, problem: str) -> CriticalAssetWarning:
    """Warning for a registry entry that cannot be tied to an approved, executed automation action."""
    rollback = control.rollback_action_type
    return CriticalAssetWarning(
        asset=control.target, asset_class=None, role="automation provenance NOT confirmed",
        action_type=rollback,
        potential_impact=(f"{problem}; this may be a manual control that automation never created. "
                          "The restoration engine refuses to release it"),
        message=(f"WARNING: ELEVATED APPROVAL REQUIRED - {rollback.value} on {control.target}: "
                 f"control {control.control_key} has no confirmed automation provenance"),
    )


def _elevated_warning(control: TemporaryControl) -> CriticalAssetWarning:
    """Explicit warning shown on the release checklist for an ELEVATED release."""
    rollback = control.rollback_action_type
    return CriticalAssetWarning(
        asset=control.target,
        asset_class=None,
        role="control created under ELEVATED approval or privileged rollback",
        action_type=rollback,
        potential_impact=(
            f"{get_action_spec(rollback).description} for {control.target}; "
            "restores access that was removed during containment"
        ),
        message=(
            f"WARNING: ELEVATED APPROVAL REQUIRED - {rollback.value} on {control.target} "
            f"(control {control.control_key})"
        ),
    )


class RestorationPlanner:
    """Builds release packages from the temporary control registry. Implements contract 13.17."""

    def __init__(self, registry: ControlRegistry, settings: Settings, *, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None,
                 critical_assets: CriticalAssetEvaluator | None = None,
                 executions: Any = None, provenance: ProvenanceCheck | None = None) -> None:
        self._registry = registry
        #: Returns why a registry entry has no automation provenance (None: provenance confirmed).
        self._provenance = provenance
        self._settings = settings
        self._clock: Clock = clock or SystemClock()
        self._new_id: Callable[[], str] = id_factory or (lambda: uuid.uuid4().hex)
        self._critical_assets = critical_assets
        # ExecutionStateStore (list()) used to find other incidents relying on the same control
        self._executions = executions

    def outstanding(self, incident_id: str) -> list[TemporaryControl]:
        """Controls of ``incident_id`` that may still be in force (shown when an incident is closed).

        Includes ``RELEASE_PENDING``: a release that died between the registry update and the
        vendor call leaves the control in force, and it must never disappear from every view.
        """
        return [c for c in self._registry.list(incident_id=incident_id) if c.status in IN_FORCE_STATUSES]

    def provenance_problem(self, control: TemporaryControl) -> str | None:
        """Why ``control`` cannot be tied to an approved automation action (None: it can)."""
        if self._provenance is None:
            return None
        try:
            return self._provenance(control)
        except Exception as exc:  # noqa: BLE001 - fail closed
            return f"provenance could not be checked ({type(exc).__name__})"

    def build_release_package(self, incident: Incident, control_keys: Sequence[str] | None = None, *,
                              requested_by: str = "automation:restoration_planner") -> ReleasePackage:
        """Release package for all controls of ``incident`` in force, or exactly ``control_keys``.

        Raises :class:`RegistryError` for an unknown key, a key of another incident, a control that
        is not in force (``RELEASE_PENDING`` or ``RELEASED``), duplicate keys, or when nothing is
        left to release.
        """
        controls = self._select(incident.incident_id, control_keys)
        drafts = [_control_evidence(c) for c in controls]
        evidence = number_evidence(drafts)
        by_ref = {e.reference: e for e in evidence}
        actions = tuple(self._release_action(c, by_ref[c.control_key], incident) for c in controls)
        created_at = self._clock.now()
        ttl = timedelta(minutes=self._settings.thresholds.approval.package_ttl_minutes)
        return ReleasePackage(
            package_id=self._new_id(),
            incident_id=incident.incident_id,
            workflow_id=incident.workflow_id,
            workflow_version=incident.workflow_version,
            created_at=created_at,
            expires_at=created_at + ttl,
            requested_by=requested_by,
            severity=incident.severity,
            risk_score=RELEASE_RISK_SCORE,
            confidence_score=RELEASE_CONFIDENCE_SCORE,
            summary=self._summary(incident.incident_id, actions),
            endpoints=tuple(sorted({a.target for a in actions if a.target_kind is TargetKind.ENDPOINT})),
            users=tuple(sorted({a.target for a in actions if a.target_kind is TargetKind.USER})),
            evidence=evidence,
            evidence_snapshot_hash=evidence_snapshot_hash(evidence),
            actions=actions,
            control_keys=tuple(c.control_key for c in controls),
        )

    # internals --------------------------------------------------------------
    def _select(self, incident_id: str, control_keys: Sequence[str] | None) -> list[TemporaryControl]:
        if control_keys is None:
            # automatic selection: releasable controls with confirmed automation provenance only
            controls = [c for c in self._registry.list(incident_id=incident_id)
                        if c.status in RELEASABLE_STATUSES and self.provenance_problem(c) is None]
        else:
            if isinstance(control_keys, str):
                raise TypeError("control_keys must be a sequence of keys, not a string")
            if len(set(control_keys)) != len(control_keys):
                raise RegistryError("duplicate control keys in release request")
            controls = [self._releasable(incident_id, key) for key in control_keys]
        if not controls:
            raise RegistryError(f"incident {incident_id} has no temporary controls in force to release")
        return controls

    def _releasable(self, incident_id: str, control_key: str) -> TemporaryControl:
        control = self._registry.get(control_key)
        if control is None:
            raise RegistryError(f"unknown control key: {control_key} (only registered controls can be released)")
        if control.incident_id != incident_id:
            raise RegistryError(f"control {control_key} belongs to another incident")
        if control.status not in RELEASABLE_STATUSES:
            raise RegistryError(f"control {control_key} is {control.status.value}, not ACTIVE")
        return control

    def _dependent_incidents(self, control: TemporaryControl) -> list[str]:
        """Other incidents that hold the same effective control on the same target."""
        return dependent_incidents(control, self._registry, self._executions)

    def _release_action(self, control: TemporaryControl, evidence: Evidence,
                        incident: Incident | None = None) -> RecommendedAction:
        rollback = control.rollback_action_type
        spec = get_action_spec(rollback)
        warnings: list[CriticalAssetWarning] = []
        if control.approval_level is ApprovalLevel.ELEVATED or spec.always_elevated:
            warnings.append(_elevated_warning(control))
        asset = incident_asset(incident, control.target, control.target_kind)
        warnings.extend(critical_release_warnings(control, self._critical_assets, asset))
        warnings.extend(_dependent_warning(control, other) for other in self._dependent_incidents(control))
        problem = self.provenance_problem(control)
        if problem is not None:
            warnings.append(_provenance_warning(control, problem))
        elevated = bool(warnings)
        params = release_params(control)
        return RecommendedAction(
            incident_id=control.incident_id,
            idempotency_key=make_idempotency_key(control.incident_id, rollback, control.target),
            action_type=rollback,
            target=control.target,
            target_kind=spec.target_kind,
            params=params,
            evidence=(evidence,),
            risk_score=RELEASE_RISK_SCORE,
            confidence_score=RELEASE_CONFIDENCE_SCORE,
            approval_level=ApprovalLevel.ELEVATED if elevated else ApprovalLevel.STANDARD,
            warnings=tuple(warnings),
            rationale=(
                f"Release temporary control {control.control_key} created by automation "
                f"(evidence #{evidence.number})"
            ),
        )

    @staticmethod
    def _summary(incident_id: str, actions: Sequence[RecommendedAction]) -> str:
        lines = ", ".join(f"{a.action_type.value} {a.target}" for a in actions)
        return f"Release {len(actions)} temporary control(s) of incident {incident_id}: {lines}"
