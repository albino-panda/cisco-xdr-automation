"""Critical-asset classification (``config/critical-assets.yaml``).

A containment action on a critical asset is never blocked silently: the package builder marks it
``ELEVATED`` and attaches a :class:`CriticalAssetWarning` naming the asset, its class and role, the
action and the potential impact. Matching is deterministic: exact names and ``fnmatch`` patterns are
case-insensitive, groups and tags are compared case-insensitively, IPs are matched against CIDRs.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from xdr_response.config import AssetMatch, CriticalAssetClassConfig, CriticalAssetsConfig
from xdr_response.models import ActionType, Asset, CriticalAssetClass, CriticalAssetWarning, TargetKind

__all__ = ["CriticalAssetPolicy", "WARNING_PREFIX", "format_warning"]

WARNING_PREFIX = "WARNING: ELEVATED APPROVAL REQUIRED"

_ENDPOINT_COMPOSITES = frozenset({TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM})
_USER_KINDS = frozenset({TargetKind.USER, TargetKind.EMAIL_ADDRESS})


@dataclass
class _Subject:
    """What a target and its optional asset context say about the thing being acted on."""

    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = field(default_factory=list)
    groups: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)


def _add_ip(subject: _Subject, value: str | None) -> None:
    if not value:
        return
    try:
        subject.ips.append(ipaddress.ip_address(value.strip()))
    except ValueError:
        return


def _add_name(subject: _Subject, value: str, kind: TargetKind) -> None:
    v = value.strip()
    if not v:
        return
    if kind is TargetKind.ENDPOINT:
        subject.hosts.add(v.lower())
    elif kind in _ENDPOINT_COMPOSITES:
        subject.hosts.add(v.partition("/")[0].lower())
    elif kind in _USER_KINDS:
        subject.users.add(v.lower())
    elif kind is TargetKind.ROLE_ASSIGNMENT:
        subject.users.add(v.partition("/")[0].lower())
    elif kind is TargetKind.IP:
        _add_ip(subject, v)


def _subject(target: str, target_kind: TargetKind, asset: Asset | None) -> _Subject:
    subject = _Subject()
    _add_name(subject, target, TargetKind(target_kind))
    if asset is not None:
        _add_name(subject, asset.name, asset.kind)
        _add_ip(subject, asset.ip)
        subject.groups.update(g.lower() for g in asset.groups)
        subject.tags.update(t.lower() for t in asset.tags)
    return subject


def _names_match(values: set[str], exact: list[str], patterns: list[str]) -> bool:
    exact_l = {e.lower() for e in exact}
    pats = [p.lower() for p in patterns]
    return any(v in exact_l or any(fnmatchcase(v, p) for p in pats) for v in values)


def _matches(match: AssetMatch, subject: _Subject) -> bool:
    if _names_match(subject.hosts, match.hostnames, match.hostname_patterns):
        return True
    if _names_match(subject.users, match.users, match.user_patterns):
        return True
    if subject.groups & {g.lower() for g in match.groups} or subject.tags & {t.lower() for t in match.tags}:
        return True
    networks = [ipaddress.ip_network(c, strict=False) for c in match.ip_cidrs]
    return any(ip.version == n.version and ip in n for ip in subject.ips for n in networks)


def format_warning(action_type: ActionType, target: str, display_name: str, role: str,
                   potential_impact: str) -> str:
    """Decision-card text for a critical-asset warning."""
    return (f"{WARNING_PREFIX} - {ActionType(action_type).value} on {display_name} {target} "
            f"(role: {role}). Potential impact: {potential_impact}")


class CriticalAssetPolicy:
    """Classifies targets into critical-asset classes and builds the matching warnings."""

    def __init__(self, config: CriticalAssetsConfig) -> None:
        # Iterate in enum declaration order so results are deterministic regardless of YAML order.
        self._classes: list[tuple[CriticalAssetClass, CriticalAssetClassConfig]] = [
            (cls, config.classes[cls]) for cls in CriticalAssetClass if cls in config.classes
        ]

    def classify(self, target: str, target_kind: TargetKind,
                 asset: Asset | None = None) -> list[CriticalAssetClass]:
        """Every critical-asset class the target (and its optional asset context) belongs to."""
        subject = _subject(target, target_kind, asset)
        return [cls for cls, cfg in self._classes if _matches(cfg.match, subject)]

    def evaluate(self, action_type: ActionType, target: str, target_kind: TargetKind,
                 asset: Asset | None = None) -> list[CriticalAssetWarning]:
        """One warning per matching class; an empty list means no elevated approval is needed."""
        configs = dict(self._classes)
        warnings: list[CriticalAssetWarning] = []
        for cls in self.classify(target, target_kind, asset):
            cfg = configs[cls]
            warnings.append(CriticalAssetWarning(
                asset=target, asset_class=cls, role=cfg.role, action_type=ActionType(action_type),
                potential_impact=cfg.potential_impact,
                message=format_warning(action_type, target, cfg.display_name, cfg.role, cfg.potential_impact),
            ))
        return warnings
