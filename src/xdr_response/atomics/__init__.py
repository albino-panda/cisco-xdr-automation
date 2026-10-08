"""Atomic library (architecture 14.1): read atomics, correlation, evidence, routing, notifications.

This package composes the name tables of the keys that own the atomics (14.1.9). The tables are
built lazily on first use (function-local imports, no ``importlib``), so importing
``xdr_response.atomics`` or one of its model modules never pulls in every atomic. No key edits
another key's table; the framework only composes them.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from functools import cache
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from xdr_response.models import ObservableType

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.atomics.containment.models import BuiltRecommendation
    from xdr_response.atomics.records import AtomicResult

__all__ = ["read_atomics", "atomic_subject_types", "containment_builders"]


def _merge(first: Mapping[str, Any], second: Mapping[str, Any], what: str) -> Mapping[str, Any]:
    clash = sorted(set(first) & set(second))
    if clash:
        raise RuntimeError(f"{what} name collision between atomic tables: {clash}")
    return MappingProxyType({**first, **second})


@cache
def read_atomics() -> Mapping[str, Callable[..., "AtomicResult"]]:
    """``ENRICHMENT_ATOMICS | INVESTIGATION_ATOMICS`` (23 names; names never collide)."""
    from xdr_response.atomics.enrichment.atomics import ENRICHMENT_ATOMICS
    from xdr_response.atomics.investigation.atomics import INVESTIGATION_ATOMICS

    return _merge(ENRICHMENT_ATOMICS, INVESTIGATION_ATOMICS, "read atomic")


@cache
def atomic_subject_types() -> Mapping[str, frozenset[ObservableType]]:
    """Accepted subject observable types per read atomic name."""
    from xdr_response.atomics.enrichment.atomics import ENRICHMENT_SUBJECT_TYPES
    from xdr_response.atomics.investigation.atomics import INVESTIGATION_SUBJECT_TYPES

    return _merge(ENRICHMENT_SUBJECT_TYPES, INVESTIGATION_SUBJECT_TYPES, "subject type")


@cache
def containment_builders() -> Mapping[str, Callable[..., "BuiltRecommendation"]]:
    """``CONTAINMENT_BUILDERS``: the 15 named containment recommendation builders."""
    from xdr_response.atomics.containment.builders import CONTAINMENT_BUILDERS

    return MappingProxyType(dict(CONTAINMENT_BUILDERS))
