"""Entity aliases: one canonical spelling for an entity that sources name differently (Phase 5).

Sources name the same thing in different ways: Defender reports a host by its DNS name
(``TH-LT-1047.CORP.EXAMPLE``) where Secure Endpoint, Umbrella and the incident use the short name
(``TH-LT-1047``); a mailbox appears as an ``EMAIL_ADDRESS`` in mail records and as a ``USER`` in
identity records. Without merging, one host counts as two endpoints and a user "seen with two
endpoints" can be a single machine.

The rules are deliberately conservative (a wrong merge would link unrelated evidence):

* an ``ENDPOINT`` written as a DNS name merges into the short host name when the short name is
  itself an entity of the same evidence and exactly one DNS name has that first label (two DNS
  names with the same first label are ambiguous and nothing merges);
* an ``EMAIL_ADDRESS`` merges into the ``USER`` with exactly the same (normalized) value.

Bare account names (``jsmith``, ``CORP\\jsmith``) are never merged into a user principal name: a
local account and a directory account can share a name. IP literals are never host names.

Pure and deterministic: the same entities always resolve the same way, whatever their order.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping

from xdr_response.atomics.correlation.models import EntityRef
from xdr_response.models.canonical import endpoint_names
from xdr_response.models.enums import TargetKind

__all__ = ["EntityAliases"]


def _short_name(value: str) -> str | None:
    """First DNS label of an endpoint written as a DNS name (``None`` for short names and IPs).

    The same host identity as :func:`~xdr_response.models.canonical.same_endpoint`, which allow-lists
    and the critical-asset policy already use.
    """
    return endpoint_names(value)[1]


class EntityAliases:
    """Canonical spelling per entity key; entities without an alias map to themselves."""

    def __init__(self, mapping: Mapping[str, EntityRef] | None = None) -> None:
        self._canonical: dict[str, EntityRef] = dict(mapping or {})
        merged: dict[str, dict[str, EntityRef]] = defaultdict(dict)
        for alias_key, canonical in self._canonical.items():
            kind, _, value = alias_key.partition(":")
            merged[canonical.key()][alias_key] = EntityRef(kind=TargetKind(kind), value=value)
        self._aliases = {key: tuple(sorted(refs.values(), key=EntityRef.sort_key)) for key, refs in merged.items()}

    @classmethod
    def resolve(cls, entities: Iterable[EntityRef]) -> "EntityAliases":
        """The aliases among ``entities`` (see the module rules)."""
        unique = {e.key(): e for e in entities}
        mapping: dict[str, EntityRef] = {}
        endpoints = {e.value for e in unique.values() if e.kind is TargetKind.ENDPOINT}
        by_short: dict[str, set[str]] = defaultdict(set)
        for value in endpoints:
            short = _short_name(value)
            if short is not None:
                by_short[short].add(value)
        for short, names in by_short.items():
            if len(names) == 1 and short in endpoints:
                (name,) = names
                mapping[f"{TargetKind.ENDPOINT.value}:{name}"] = EntityRef(kind=TargetKind.ENDPOINT, value=short)
        users = {e.value for e in unique.values() if e.kind is TargetKind.USER}
        for entity in unique.values():
            if entity.kind is TargetKind.EMAIL_ADDRESS and entity.value in users:
                mapping[entity.key()] = EntityRef(kind=TargetKind.USER, value=entity.value)
        return cls(mapping)

    def canon(self, entity: EntityRef) -> EntityRef:
        """The canonical spelling of ``entity`` (``entity`` itself when it has no alias)."""
        return self._canonical.get(entity.key(), entity)

    def aliases_of(self, entity: EntityRef) -> tuple[EntityRef, ...]:
        """Other spellings merged into the canonical ``entity``, sorted (``()`` when none)."""
        return self._aliases.get(self.canon(entity).key(), ())

    def items(self) -> tuple[tuple[EntityRef, EntityRef], ...]:
        """``(alias, canonical)`` pairs, sorted by alias."""
        pairs = [(alias, self._canonical[alias.key()]) for refs in self._aliases.values() for alias in refs]
        return tuple(sorted(pairs, key=lambda pair: pair[0].sort_key()))

    def __len__(self) -> int:
        return len(self._canonical)

    def __bool__(self) -> bool:
        return bool(self._canonical)
