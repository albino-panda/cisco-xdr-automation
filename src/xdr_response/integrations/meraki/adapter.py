"""Cisco Meraki adapter (docs/integrations.md section 2.7).

Auth: ``Authorization: Bearer <API_KEY>`` (VERIFIED). Two controls:

* **Client policy** (block_network_client / restore_network_client): the previous ``devicePolicy``
  (and ``groupPolicyId``) is read before the change and returned in ``rollback_params`` so the
  release restores exactly that policy.
* **MX L3 firewall** (block_ip / unblock_ip): the PUT replaces the whole rule set, so the adapter
  reads the rules, inserts or removes exactly one rule whose comment carries the idempotency key,
  writes them back and verifies. Writes are serialized per network with a lock (concurrent writers
  could otherwise lose rules). The implicit "Default rule" returned by the GET is never written back.
"""
from __future__ import annotations

import ipaddress
import threading
from collections.abc import Mapping
from typing import Any, ClassVar

from xdr_response.errors import ConfigError, InvalidTargetError
from xdr_response.guard import state_changing
from xdr_response.integrations._adapter_support import ApiRequest, HttpResultLike, VendorAdapter, body_dict, body_list
from xdr_response.integrations.meraki import builders
from xdr_response.integrations.meraki.manifest import MANIFEST, REQUIRED_SECRETS
from xdr_response.models import (
    ActionOutcome,
    ActionRequest,
    ActionResultStatus,
    ActionType,
    TargetState,
    TargetStateCheck,
    VerificationResult,
    VerificationStatus,
)

__all__ = ["MerakiAdapter", "rule_tag"]

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()
_POLICY_TYPES = frozenset({ActionType.BLOCK_NETWORK_CLIENT, ActionType.RESTORE_NETWORK_CLIENT})
_L3_TYPES = frozenset({ActionType.BLOCK_IP, ActionType.UNBLOCK_IP})


def _network_lock(network_id: str) -> threading.Lock:
    """One lock per Meraki network for the read-modify-write of L3 rules."""
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(network_id, threading.Lock())


def rule_tag(control_key: str) -> str:
    """Comment that marks the L3 rule created for ``control_key`` (the containment idempotency key)."""
    return f"xdr-response {control_key}"


def _cidr(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    return f"{address.compressed}/{address.max_prefixlen}"


def _rules(body: Any) -> list[dict[str, Any]]:
    """Rules from a GET, without the implicit default rule (never written back)."""
    return [dict(r) for r in body_list(body, "rules")
            if isinstance(r, Mapping) and r.get("comment") != builders.DEFAULT_RULE_COMMENT]


class MerakiAdapter(VendorAdapter):
    """Meraki: client policy and MX L3 firewall controls."""

    name: ClassVar[str] = "meraki"
    manifest = MANIFEST
    default_base_url: ClassVar[str | None] = builders.BASE_URL
    secret_names: ClassVar[Mapping[str, str]] = REQUIRED_SECRETS

    def build_auth(self) -> Any:
        """``Authorization: Bearer <API_KEY>``."""
        from xdr_response.integrations.auth import ApiKeyHeader

        return ApiKeyHeader("Authorization", self.secret("api_key"), prefix="Bearer ")

    def _health_probe(self) -> ApiRequest | None:
        network = self._option("health_network_id")
        return builders.get_l3_rules(str(network)) if network else None

    # ---------------------------------------------------------------- reads --
    def search_client(self, mac: str) -> dict[str, Any]:
        """Find a client by MAC across the configured organization."""
        organization = self._option("organization_id")
        if not organization:
            raise ConfigError("meraki: options.organization_id is required for client search")
        return body_dict(self._send(builders.search_clients(str(organization), mac)).body)

    def _client_ref(self, request: ActionRequest) -> tuple[str, str]:
        """``(network_id, client_id)`` of the approved target; params can never name another client."""
        target_network, sep, target_client = request.target.partition("/")
        if not sep:
            target_network, target_client = "", request.target
        network_id = str(request.params.get("network_id") or target_network or self._param(request, "network_id"))
        client_id = str(request.params.get("client_id") or target_client)
        if client_id.strip().lower() != target_client.strip().lower():
            raise InvalidTargetError(
                f"meraki: params.client_id {client_id!r} is not the approved target {request.target!r}; "
                "refusing to act on another client", integration=self.name)
        if target_network and network_id.strip().lower() != target_network.strip().lower():
            raise InvalidTargetError(
                f"meraki: params.network_id {network_id!r} is not the network of the approved target "
                f"{request.target!r}", integration=self.name)
        return network_id, client_id

    def _policy(self, network_id: str, client_id: str) -> tuple[dict[str, Any], HttpResultLike]:
        result = self._send(builders.get_client_policy(network_id, client_id))
        return body_dict(result.body), result

    def _l3_tag(self, request: ActionRequest) -> str:
        if request.action_type is ActionType.BLOCK_IP:
            return rule_tag(request.idempotency_key)
        explicit = request.params.get("rule_comment")
        if explicit:
            return str(explicit)
        return rule_tag(str(self._param(request, "restores")))

    def _rule_present(self, request: ActionRequest) -> tuple[bool, HttpResultLike]:
        result = self._send(builders.get_l3_rules(str(self._param(request, "network_id"))))
        tag = self._l3_tag(request)
        return any(r.get("comment") == tag for r in _rules(result.body)), result

    def _in_desired_state(self, request: ActionRequest) -> tuple[bool, str, HttpResultLike]:
        if request.action_type in _L3_TYPES:
            present, result = self._rule_present(request)
            desired = present == (request.action_type is ActionType.BLOCK_IP)
            return desired, f"tagged rule {'present' if present else 'absent'}", result
        policy, result = self._policy(*self._client_ref(request))
        current = policy.get("devicePolicy")
        wanted = "Blocked" if request.action_type is ActionType.BLOCK_NETWORK_CLIENT else \
            request.params.get("previous_device_policy")
        return current == wanted, f"devicePolicy is {current!r}", result

    def current_state(self, request: ActionRequest) -> TargetStateCheck:
        """Read the client policy or the L3 rules."""
        if request.action_type not in _POLICY_TYPES | _L3_TYPES:
            return super().current_state(request)
        desired, detail, result = self._in_desired_state(request)
        return TargetStateCheck(state=TargetState.IN_DESIRED_STATE if desired else TargetState.NOT_IN_DESIRED_STATE,
                                detail=detail, api_calls=self._calls([result]))

    def verify(self, request: ActionRequest, outcome: ActionOutcome | None) -> VerificationResult:
        """Re-read the client policy or the L3 rules (both VERIFIED reads)."""
        if request.action_type not in _POLICY_TYPES | _L3_TYPES:
            return super().verify(request, outcome)
        desired, detail, result = self._in_desired_state(request)
        method = "get_l3_rules" if request.action_type in _L3_TYPES else "get_client_policy"
        return self._verification(request, VerificationStatus.VERIFIED if desired else VerificationStatus.NOT_VERIFIED,
                                  method=method, details=detail, results=[result])

    # ------------------------------------------------------- client policy --
    @state_changing
    def block_network_client(self, request: ActionRequest) -> ActionOutcome:
        """Set ``devicePolicy`` to ``Blocked`` after capturing the previous policy."""
        network_id, client_id = self._client_ref(request)
        policy, before = self._policy(network_id, client_id)
        rollback = {"network_id": network_id, "client_id": client_id,
                    "previous_device_policy": policy.get("devicePolicy") or "Normal",
                    "previous_group_policy_id": policy.get("groupPolicyId")}
        if policy.get("devicePolicy") == "Blocked":
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before], rollback=rollback,
                                 message=f"client {client_id} already blocked")
        changed = self._send(builders.update_client_policy(network_id, client_id, "Blocked"))
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, changed], rollback=rollback,
                             external_ref=client_id, message=f"client {client_id} blocked")

    @state_changing
    def restore_network_client(self, request: ActionRequest) -> ActionOutcome:
        """Restore the policy captured before the block."""
        network_id, client_id = self._client_ref(request)
        previous = str(self._param(request, "previous_device_policy"))
        group = request.params.get("previous_group_policy_id")
        policy, before = self._policy(network_id, client_id)
        if policy.get("devicePolicy") == previous:
            return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before],
                                 message=f"client {client_id} already {previous}")
        changed = self._send(builders.update_client_policy(network_id, client_id, previous,
                                                           str(group) if group else None))
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, changed], external_ref=client_id,
                             message=f"client {client_id} restored to {previous}")

    # ------------------------------------------------------------ L3 rules --
    @state_changing
    def block_ip(self, request: ActionRequest) -> ActionOutcome:
        """Insert one tagged deny rule at the top of the MX L3 rule set."""
        network_id = str(self._param(request, "network_id"))
        tag = rule_tag(request.idempotency_key)
        rollback = {"network_id": network_id, "rule_comment": tag}
        with _network_lock(network_id):
            before = self._send(builders.get_l3_rules(network_id))
            rules = _rules(before.body)
            if any(r.get("comment") == tag for r in rules):
                return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before], rollback=rollback,
                                     message=f"rule for {request.target} already present")
            new_rules = [builders.deny_rule(_cidr(request.target), tag), *rules]
            written = self._send(builders.update_l3_rules(network_id, new_rules))
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, written], rollback=rollback,
                             external_ref=tag, message=f"deny rule for {request.target} added")

    @state_changing
    def unblock_ip(self, request: ActionRequest) -> ActionOutcome:
        """Remove exactly the rule tagged for the original control."""
        network_id = str(self._param(request, "network_id"))
        tag = self._l3_tag(request)
        with _network_lock(network_id):
            before = self._send(builders.get_l3_rules(network_id))
            rules = _rules(before.body)
            kept = [r for r in rules if r.get("comment") != tag]
            if len(kept) == len(rules):
                return self._outcome(ActionResultStatus.ALREADY_CONTAINED, results=[before],
                                     message=f"no rule tagged {tag!r}")
            written = self._send(builders.update_l3_rules(network_id, kept))
        return self._outcome(ActionResultStatus.SUCCESS, results=[before, written], external_ref=tag,
                             message=f"deny rule for {request.target} removed")
