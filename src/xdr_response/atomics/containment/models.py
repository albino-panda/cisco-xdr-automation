"""Containment recommendation models (architecture 14.1.7, layer 0 model module).

A :class:`BuiltRecommendation` is *data*: the action a workflow rule recommends, the integration
chosen for it (native Cisco XDR first) and the preview of what the approval policy will say. It
never carries an approval level, a token or an idempotency key: numbering, approval levels and
packages stay with ``PackageBuilder``, and a human approves the package before anything runs.
"""
from __future__ import annotations

from pydantic import model_validator

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.catalog import ActionType, get_action_spec
from xdr_response.models.enums import ApprovalPurpose
from xdr_response.models.recommendation import CriticalAssetWarning, ProposedAction

__all__ = ["RouteDecision", "BuiltRecommendation"]


def _require_containment(action_type: ActionType) -> None:
    """ValueError unless ``action_type`` is a CONTAINMENT or REMEDIATION catalog type."""
    if get_action_spec(action_type).purpose is not ApprovalPurpose.CONTAINMENT:
        raise ValueError(f"{ActionType(action_type).value} is not a containment or remediation action type")


class RouteDecision(FrozenModel):
    """Which integration would execute an action after approval, and why."""

    action_type: ActionType
    integration: str | None                      # None: no execution path today
    native: bool = False                         # executed through cisco_xdr respond/trigger
    product: str | None = None                   # product the action lands on (verify_integration when native)
    params: JsonDict = {}                        # routing params: integration and, when native, module_instance_id,
                                                 # action_id, observable_type, observable_value, verify_integration
    considered: tuple[str, ...] = ()             # e.g. "cisco_xdr: no configured native action for secure_endpoint"
    reason: str = ""                             # why integration is None

    @model_validator(mode="after")
    def _consistent(self) -> "RouteDecision":
        _require_containment(self.action_type)
        if self.integration is None:
            if self.native or self.params:
                raise ValueError("an unrouted decision has no native flag and no params")
            if not self.reason:
                raise ValueError("an unrouted decision must say why (reason)")
            return self
        if self.params.get("integration") != self.integration:
            raise ValueError('params["integration"] must equal the routed integration')
        if self.native and (self.integration != "cisco_xdr" or not self.params.get("verify_integration")):
            raise ValueError("a native route runs on cisco_xdr and names its verify_integration")
        return self


class BuiltRecommendation(FrozenModel):
    """A containment recommendation: a :class:`ProposedAction` plus routing and policy previews.

    ``warnings`` and ``excluded_reason`` are previews only. ``PackageBuilder`` re-evaluates both,
    decides the approval level (critical assets and ``always_elevated`` make it ELEVATED) and moves
    allow-listed targets to ``excluded_targets`` where they stay visible.
    """

    action_type: ActionType
    target: str                                  # normalized
    proposal: ProposedAction | None              # None when unrouted
    route: RouteDecision
    warnings: tuple[CriticalAssetWarning, ...] = ()   # preview from CriticalAssetPolicy.evaluate; PackageBuilder decides
    excluded_reason: str | None = None           # AllowlistPolicy preview; the proposal is still built and
                                                 # PackageBuilder moves it to excluded_targets (shown, never dropped)
    unrouted_reason: str | None = None           # set exactly when proposal is None

    @model_validator(mode="after")
    def _consistent(self) -> "BuiltRecommendation":
        _require_containment(self.action_type)
        if self.route.action_type is not self.action_type:
            raise ValueError("route.action_type must equal action_type")
        if (self.proposal is None) != (self.unrouted_reason is not None):
            raise ValueError("unrouted_reason must be set exactly when proposal is None")
        if self.proposal is None:
            if self.route.integration is not None:
                raise ValueError("a routed recommendation must carry its proposal")
        else:
            self._check_proposal(self.proposal)
        if any(w.action_type is not self.action_type for w in self.warnings):
            raise ValueError("every warning must name this recommendation's action type")
        return self

    def _check_proposal(self, proposal: ProposedAction) -> None:
        if proposal.action_type is not self.action_type or proposal.target != self.target:
            raise ValueError("proposal action type and target must match the recommendation")
        if self.route.integration is None or proposal.params.get("integration") != self.route.integration:
            raise ValueError('proposal params["integration"] must equal the routed integration')

    # ------------------------------------------------------- read-only views --
    @property
    def routed(self) -> bool:
        """True when an enabled adapter can execute the action after approval."""
        return self.proposal is not None

    @property
    def reversible(self) -> bool:
        """True when the catalog defines a rollback (release needs its own human approval)."""
        return get_action_spec(self.action_type).reversible

    @property
    def rollback_action_type(self) -> ActionType | None:
        """The catalog rollback action type, or None when the action is not reversible."""
        return get_action_spec(self.action_type).rollback_action_type

    @property
    def elevation_expected(self) -> bool:
        """Preview: the package builder will require ELEVATED approval (warnings or ``always_elevated``).

        Informational only; the approval level is decided by ``PackageBuilder`` and can only go up.
        """
        return bool(self.warnings) or get_action_spec(self.action_type).always_elevated
