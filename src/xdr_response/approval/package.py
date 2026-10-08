"""Containment package builder (architecture section 5.2).

Turns proposed actions into a :class:`ContainmentPackage` the analyst approves. Rules, applied
deterministically in this order:

1. refuse read-only and restoration action types (read-only work never needs a package; release
   actions belong in a release package);
2. normalize targets, compute idempotency keys, merge duplicates (higher risk score wins, evidence
   is merged);
3. move allow-listed targets to ``excluded_targets`` with the reason (shown, never dropped silently);
4. critical-asset matches set ``ELEVATED`` with a warning (never blocked). The incident's asset
   context is always evaluated; asset context carried by a proposal (untrusted workflow data) is
   merged into it (union of groups, tags, roles) and can never replace or shrink it;
5. ``always_elevated`` action types set ``ELEVATED``;
6. blast radius above the ``thresholds.yaml`` caps sets ``ELEVATED`` with a warning on every action
   of the capped kind (nothing is removed); an action that takes a host off the network
   (``isolate_endpoint``, ``block_network_client``) on a host whose asset context holds an address
   in ``never_block.ips`` / ``never_block.cidrs`` sets ``ELEVATED`` with a warning (14.11.7: the
   isolation cuts allow-listed infrastructure off the network; shown, never silent or blocked);
7. number the evidence, compute the evidence snapshot hash, set ``expires_at = now + package_ttl``.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from xdr_response.approval.critical_assets import WARNING_PREFIX, CriticalAssetPolicy, find_incident_asset
from xdr_response.clock import Clock, SystemClock
from xdr_response.config import AllowlistPolicy, BlastRadiusSettings, Settings
from xdr_response.models import (
    ActionType,
    ApprovalLevel,
    ApprovalPurpose,
    Asset,
    BlastRadius,
    ContainmentPackage,
    CriticalAssetWarning,
    Evidence,
    EvidenceDraft,
    ExcludedTarget,
    Incident,
    ProposedAction,
    RecommendedAction,
    TargetKind,
    asset_addresses,
    canonical_json,
    evidence_snapshot_hash,
    get_action_spec,
    make_idempotency_key,
    merge_asset_context,
    normalize_target,
    number_evidence,
)

__all__ = ["PackageBuilder", "DEFAULT_REQUESTER", "INFRASTRUCTURE_ADDRESS_ROLE"]

DEFAULT_REQUESTER = "automation:package_builder"
#: ``CriticalAssetWarning.role`` of the warning on an isolation of a host that holds an allow-listed
#: infrastructure address (``never_block.ips`` / ``never_block.cidrs``).
INFRASTRUCTURE_ADDRESS_ROLE = "allow-listed infrastructure address"
#: Actions that take a host off the network: every address the host holds goes with it.
_NETWORK_CUTTING = frozenset({ActionType.ISOLATE_ENDPOINT, ActionType.BLOCK_NETWORK_CLIENT})

_ENDPOINT_KINDS = frozenset({TargetKind.ENDPOINT, TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM})
_USER_KINDS = frozenset({TargetKind.USER, TargetKind.ROLE_ASSIGNMENT})
_INDICATOR_KINDS = frozenset({TargetKind.DOMAIN, TargetKind.URL, TargetKind.IP, TargetKind.HASH})
_COMPOSITE_KINDS = frozenset({TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM,
                              TargetKind.ROLE_ASSIGNMENT})


@dataclass
class _Draft:
    """A proposal after normalization and duplicate merging."""

    key: str
    target: str
    proposal: ProposedAction
    evidence: list[EvidenceDraft] = field(default_factory=list)
    asset: Asset | None = None


def _evidence_key(item: EvidenceDraft) -> bytes:
    """Content identity of an evidence item, ignoring its number."""
    return canonical_json({name: getattr(item, name) for name in EvidenceDraft.model_fields}, allow_floats=True)


def _subject(target: str, kind: TargetKind) -> str:
    """Endpoint or user part of a composite target (``ENDPOINT/hash``, ``user/roleId``)."""
    return target.partition("/")[0] if kind in _COMPOSITE_KINDS else target


def _blast_group(kind: TargetKind) -> str | None:
    if kind in _ENDPOINT_KINDS:
        return "endpoints"
    if kind in _USER_KINDS:
        return "users"
    if kind in _INDICATOR_KINDS:
        return "indicators"
    if kind is TargetKind.EMAIL_MESSAGE:
        return "messages"
    return None


def _union_assets(primary: Asset | None, extra: Asset | None) -> Asset | None:
    """Union of two asset contexts: groups, tags, roles, users and addresses of both, ``privileged``
    when either says so; ``primary`` wins for name and first IP (:func:`merge_asset_context`)."""
    if primary is None or extra is None:
        return primary or extra
    return merge_asset_context(primary, extra)


def _as_proposal(action: RecommendedAction) -> ProposedAction:
    """Minimal proposal view of a package action (used for the blast-radius recount)."""
    drafts = tuple(EvidenceDraft(**e.model_dump(exclude={"number"})) for e in action.evidence)
    return ProposedAction(action_type=action.action_type, target=action.target, target_kind=action.target_kind,
                          params=dict(action.params), evidence=drafts, risk_score=action.risk_score,
                          confidence_score=action.confidence_score, rationale=action.rationale or "policy check")


def _check_proposal(proposal: ProposedAction) -> None:
    spec = get_action_spec(proposal.action_type)
    if not spec.state_changing:
        raise ValueError(f"{spec.action_type.value} is read-only and never needs an approval package")
    if spec.purpose is not ApprovalPurpose.CONTAINMENT:
        raise ValueError(f"{spec.action_type.value} is a restoration action; it belongs in a release package")
    if TargetKind(proposal.target_kind) is not spec.target_kind:
        raise ValueError(f"{spec.action_type.value} targets {spec.target_kind.value}, "
                         f"not {TargetKind(proposal.target_kind).value}")


class PackageBuilder:
    """Builds containment packages. Pure and deterministic given the clock and id factory."""

    def __init__(self, settings: Settings, *, critical_assets: CriticalAssetPolicy,
                 allowlists: AllowlistPolicy, clock: Clock | None = None,
                 id_factory: Callable[[], str] | None = None) -> None:
        self._ttl = timedelta(minutes=settings.thresholds.approval.package_ttl_minutes)
        self._caps: BlastRadiusSettings = settings.thresholds.blast_radius
        self._critical = critical_assets
        self._allowlists = allowlists
        self._clock = clock or SystemClock()
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)

    def build(self, incident: Incident, proposals: Sequence[ProposedAction], *,
              risk_score: int, confidence_score: int, summary: str,
              extra_evidence: Sequence[EvidenceDraft] = (), dry_run: bool = False,
              requested_by: str = DEFAULT_REQUESTER) -> ContainmentPackage:
        """Build the package for ``incident``.

        Raises ValueError for read-only or restoration proposals, and when no action remains
        after allow-list exclusion (the caller keeps the incident in ``NOT_STARTED``).
        """
        drafts = self._merge(incident, proposals)
        included, excluded = self._split_allowlisted(drafts)
        if not included:
            raise ValueError("no containment action remains after allow-list exclusion")
        blast = self._blast_radius(included)
        blast_warnings = self._blast_warnings(blast, included)
        evidence = number_evidence([d for draft in included for d in draft.evidence] + list(extra_evidence))
        by_content = {_evidence_key(e): e for e in evidence}
        actions = tuple(
            self._recommend(incident.incident_id, d, by_content, blast_warnings.get(d.key, []))
            for d in included
        )
        now = self._clock.now()
        return ContainmentPackage(
            package_id=self._id_factory(), incident_id=incident.incident_id,
            workflow_id=incident.workflow_id, workflow_version=incident.workflow_version,
            created_at=now, expires_at=now + self._ttl, requested_by=requested_by,
            severity=incident.severity, risk_score=risk_score, confidence_score=confidence_score,
            summary=summary, endpoints=blast.endpoints, users=blast.users, evidence=evidence,
            evidence_snapshot_hash=evidence_snapshot_hash(evidence), actions=actions,
            excluded_targets=tuple(excluded), blast_radius=blast, dry_run=dry_run,
        )

    def policy_violations(self, package: ContainmentPackage, incident: Incident | None = None) -> list[str]:
        """Actions of ``package`` marked below the approval level the policy requires.

        Re-runs rules 4-6 (critical assets with the incident's asset context, ``always_elevated``
        and the blast-radius caps) on a package, whoever built it. Used at proposal and decision
        time so a hand-built or tampered package can never lower ``ELEVATED`` to ``STANDARD``.
        """
        if not isinstance(package, ContainmentPackage):
            return []
        blast = package.blast_radius
        counts = {"endpoints": len(blast.endpoints), "users": len(blast.users),
                  "indicators": len(blast.indicators), "messages": blast.messages}
        caps = {"endpoints": self._caps.max_endpoints, "users": self._caps.max_users,
                "indicators": self._caps.max_indicators, "messages": self._caps.max_messages}
        recomputed = self._blast_radius([_Draft(key=a.idempotency_key, target=a.target,
                                                proposal=_as_proposal(a)) for a in package.actions])
        counts = {"endpoints": max(counts["endpoints"], len(recomputed.endpoints)),
                  "users": max(counts["users"], len(recomputed.users)),
                  "indicators": max(counts["indicators"], len(recomputed.indicators)),
                  "messages": max(counts["messages"], recomputed.messages)}
        problems: list[str] = []
        for action in package.actions:
            if action.approval_level is ApprovalLevel.ELEVATED:
                continue
            kind = TargetKind(action.target_kind)
            asset = self._incident_asset(incident, action.target, kind) if incident is not None else None
            reasons = [w.message for w in self._critical.evaluate(action.action_type, action.target, kind, asset)]
            reasons += [w.message for w in self._infrastructure_warnings(action.action_type, action.target, asset)]
            if get_action_spec(action.action_type).always_elevated:
                reasons.append(f"{action.action_type.value} is always ELEVATED")
            group = _blast_group(kind)
            if group is not None and counts[group] > caps[group]:
                reasons.append(f"{counts[group]} {group} exceed the blast-radius cap of {caps[group]}")
            if reasons:
                problems.append(f"{action.idempotency_key} is STANDARD but requires ELEVATED ({reasons[0]})")
        return problems

    # ------------------------------------------------------------- rules 1-3 --
    def _merge(self, incident: Incident, proposals: Sequence[ProposedAction]) -> list[_Draft]:
        merged: dict[str, _Draft] = {}
        for proposal in proposals:
            _check_proposal(proposal)
            target = normalize_target(proposal.target_kind, proposal.target)
            key = make_idempotency_key(incident.incident_id, proposal.action_type, target)
            # The incident's asset context (re-read from XDR) is always evaluated. Proposal-supplied
            # context (workflow data, untrusted) can only add groups / tags / roles, never remove them.
            asset = _union_assets(self._incident_asset(incident, target, TargetKind(proposal.target_kind)),
                                  proposal.asset)
            existing = merged.get(key)
            if existing is None:
                merged[key] = _Draft(key=key, target=target, proposal=proposal,
                                     evidence=list(proposal.evidence), asset=asset)
                continue
            existing.evidence.extend(proposal.evidence)
            existing.asset = _union_assets(existing.asset, asset)
            if proposal.risk_score > existing.proposal.risk_score:
                existing.proposal = proposal
        return list(merged.values())

    @staticmethod
    def _incident_asset(incident: Incident, target: str, kind: TargetKind) -> Asset | None:
        """The incident's asset record for the target: by name, or by ``ip`` for an IP-named endpoint."""
        wanted = TargetKind.ENDPOINT if kind in _ENDPOINT_KINDS else TargetKind.USER if kind in _USER_KINDS else kind
        return find_incident_asset(incident.assets, _subject(target, kind), wanted)

    def _split_allowlisted(self, drafts: list[_Draft]) -> tuple[list[_Draft], list[ExcludedTarget]]:
        included: list[_Draft] = []
        excluded: list[ExcludedTarget] = []
        for d in drafts:
            p = d.proposal
            reason = self._allowlists.excluded_reason(p.action_type, d.target, TargetKind(p.target_kind))
            if reason:
                excluded.append(ExcludedTarget(action_type=p.action_type, target=d.target, reason=reason))
            else:
                included.append(d)
        return included, excluded

    # ------------------------------------------------------------------ rule 6 --
    @staticmethod
    def _blast_radius(drafts: list[_Draft]) -> BlastRadius:
        groups: dict[str, set[str]] = {"endpoints": set(), "users": set(), "indicators": set(), "messages": set()}
        for d in drafts:
            kind = TargetKind(d.proposal.target_kind)
            group = _blast_group(kind)
            if group is not None:
                groups[group].add(_subject(d.target, kind) if group in ("endpoints", "users") else d.target)
        return BlastRadius(
            endpoints=tuple(sorted(groups["endpoints"])), users=tuple(sorted(groups["users"])),
            indicators=tuple(sorted(groups["indicators"])), messages=len(groups["messages"]),
        )

    def _blast_warnings(self, blast: BlastRadius, drafts: list[_Draft]) -> dict[str, list[CriticalAssetWarning]]:
        counts = {"endpoints": len(blast.endpoints), "users": len(blast.users),
                  "indicators": len(blast.indicators), "messages": blast.messages}
        caps = {"endpoints": self._caps.max_endpoints, "users": self._caps.max_users,
                "indicators": self._caps.max_indicators, "messages": self._caps.max_messages}
        out: dict[str, list[CriticalAssetWarning]] = {}
        for d in drafts:
            group = _blast_group(TargetKind(d.proposal.target_kind))
            if group is None or counts[group] <= caps[group]:
                continue
            impact = (f"{counts[group]} {group} affected exceeds the blast-radius cap of {caps[group]} "
                      f"(thresholds.yaml blast_radius.max_{group})")
            out.setdefault(d.key, []).append(CriticalAssetWarning(
                asset=d.target, asset_class=None, role="blast radius", action_type=d.proposal.action_type,
                potential_impact=impact,
                message=f"{WARNING_PREFIX} - {d.proposal.action_type.value} on {d.target}: {impact}",
            ))
        return out

    def _infrastructure_warnings(self, action_type: ActionType, target: str,
                                 asset: Asset | None) -> list[CriticalAssetWarning]:
        """One warning per allow-listed infrastructure address of a host an action takes off the
        network. ``AllowlistPolicy.excluded_reason`` sees only the host name; the addresses come from
        the asset context (the incident's asset and the addresses the run's endpoint records report).
        The action stays proposed (the host may be the compromised one) but needs ELEVATED approval."""
        if action_type not in _NETWORK_CUTTING:
            return []
        out: list[CriticalAssetWarning] = []
        for address in asset_addresses(asset):
            reason = self._allowlists.address_reason(address)
            if not reason:
                continue
            impact = (f"{target} holds allow-listed infrastructure address {address} ({reason}); "
                      f"{action_type.value} cuts that address off the network")
            out.append(CriticalAssetWarning(
                asset=target, asset_class=None, role=INFRASTRUCTURE_ADDRESS_ROLE, action_type=action_type,
                potential_impact=impact, message=f"{WARNING_PREFIX} - {action_type.value} on {target}: {impact}"))
        return out

    # -------------------------------------------------------------- rules 4,5,7 --
    def _recommend(self, incident_id: str, d: _Draft, by_content: dict[bytes, Evidence],
                   blast_warnings: list[CriticalAssetWarning]) -> RecommendedAction:
        p = d.proposal
        spec = get_action_spec(p.action_type)
        kind = TargetKind(p.target_kind)
        warnings = (self._critical.evaluate(p.action_type, d.target, kind, d.asset)
                    + self._infrastructure_warnings(p.action_type, d.target, d.asset) + blast_warnings)
        level = ApprovalLevel.ELEVATED if warnings or spec.always_elevated else ApprovalLevel.STANDARD
        numbers = {by_content[_evidence_key(e)].number: by_content[_evidence_key(e)] for e in d.evidence}
        return RecommendedAction(
            incident_id=incident_id, idempotency_key=d.key, action_type=spec.action_type, target=d.target,
            target_kind=kind, params=dict(p.params), evidence=tuple(numbers[n] for n in sorted(numbers)),
            risk_score=p.risk_score, confidence_score=p.confidence_score, approval_level=level,
            warnings=tuple(warnings), rationale=p.rationale,
        )
