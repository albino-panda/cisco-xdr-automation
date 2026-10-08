"""``engine/xdr_plan/expr.py`` is a re-export shim of the canonical evaluator (architecture 14.3.2, 14.4.1)."""
from __future__ import annotations

import pytest

from xdr_plan import expr as legacy
from xdr_response.workflows import expr as canonical


@pytest.mark.parametrize("name", ["ExprError", "FUNCTIONS", "parse", "evaluate", "_domain_of", "SEVERITIES"])
def test_names_are_the_canonical_objects(name):
    assert getattr(legacy, name) is getattr(canonical, name)


def test_legacy_rules_still_evaluate_with_phase_1_helpers():
    env = {"item": {"ip": "203.0.113.9", "hosts": [["a"], ["b", "a"]]}}
    assert legacy.evaluate("in_cidr(item.ip, '203.0.113.0/24')", env) is True
    assert legacy.evaluate("distinct(flatten(item.hosts))", env) == ["a", "b"]
    with pytest.raises(legacy.ExprError):
        legacy.evaluate("item.__class__", env)
