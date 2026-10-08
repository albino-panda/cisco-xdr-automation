"""The canonical rule-expression evaluator (architecture 14.3.2)."""
from __future__ import annotations

import ast

import pytest

from xdr_response.workflows import expr
from xdr_response.workflows.expr import FUNCTIONS, ExprError, evaluate, names_used, parse


def test_the_legacy_whitelist_is_kept_and_extended():
    legacy = {"any", "all", "len", "min", "max", "sum", "sorted", "lower", "get", "domain_of", "severity_at_least",
              "startswith", "endswith"}
    assert legacy | {"ids", "flatten", "distinct", "within_minutes", "in_cidr"} == set(FUNCTIONS)


@pytest.mark.parametrize("src", [
    "__import__('os')", "item.__class__", "open('x')", "(lambda: 1)()", "[x for x in y for z in x]",
    "{k: 1 for k in y}", "{**item}", "f'{item}'", "get(item, 'a', default=1)", "item.keys()", "(x := 1)",
    "exec('1')", "getattr(item, 'a')",
])
def test_unsafe_expressions_are_rejected(src):
    with pytest.raises(ExprError):
        evaluate(src, {"item": {"a": 1}, "y": [[1]]})


def test_attribute_access_reads_dict_keys_only():
    assert evaluate("item.a.b", {"item": {"a": {"b": 3}}}) == 3
    with pytest.raises(ExprError, match="field 'c' is missing"):
        evaluate("item.c", {"item": {"a": 1}})
    with pytest.raises(ExprError, match="cannot read .real"):
        evaluate("item.a.real", {"item": {"a": 1}})


def test_legacy_helpers():
    env = {"item": {"url": "https://Bad.Example/x", "sev": "high"}}
    assert evaluate("domain_of(item.url)", env) == "bad.example"
    assert evaluate("severity_at_least(item.sev, 'medium')", env) is True
    assert evaluate("get(item, 'missing', 3)", env) == 3
    with pytest.raises(ExprError, match="unknown severity"):
        evaluate("severity_at_least('extreme', 'low')", env)
    assert isinstance(parse("item.a if item.b else item.c"), ast.expr)


def test_ids_reads_record_ids_from_items():
    detections = [{"record_id": "rec_1"}, {"record_id": "rec_2"}, {"record_id": "rec_1"}]
    bundles = [{"record_ids": ["rec_3", "rec_4"]}, {"record_ids": []}]
    assert evaluate("ids(d)", {"d": detections}) == ["rec_1", "rec_2"]
    assert evaluate("ids(b)", {"b": bundles}) == ["rec_3", "rec_4"]
    assert evaluate("ids(b[0])", {"b": bundles}) == ["rec_3", "rec_4"]
    assert evaluate("ids(['rec_5', [{'record_id': 'rec_6'}]])", {}) == ["rec_5", "rec_6"]
    assert evaluate("ids(None)", {}) == []
    with pytest.raises(ExprError, match="cannot read record ids"):
        evaluate("ids([1])", {})


def test_flatten_and_distinct():
    assert evaluate("flatten([[1, 2], [3], 4])", {}) == [1, 2, 3, 4]
    assert evaluate("distinct(['b', 'a', 'b', None])", {}) == ["a", "b"]
    assert evaluate("distinct(flatten(x))", {"x": [["h2", "h1"], ["h1"]]}) == ["h1", "h2"]


def test_within_minutes():
    env = {"a": "2026-01-15T12:00:00Z", "b": "2026-01-15T12:45:00+00:00", "c": None}
    assert evaluate("within_minutes(a, b, 60)", env) is True
    assert evaluate("within_minutes(b, a, 30)", env) is False
    assert evaluate("within_minutes(a, c, 60)", env) is False
    with pytest.raises(ExprError, match="not an ISO timestamp"):
        evaluate("within_minutes(a, 'yesterday', 5)", env)


def test_in_cidr():
    assert evaluate("in_cidr('198.51.100.7', '198.51.100.0/24')", {}) is True
    assert evaluate("in_cidr('203.0.113.9', '198.51.100.0/24')", {}) is False
    assert evaluate("in_cidr(None, '198.51.100.0/24')", {}) is False
    assert evaluate("in_cidr('not-an-ip', '198.51.100.0/24')", {}) is False
    assert evaluate("in_cidr('2001:db8::1', '2001:db8::/32')", {}) is True
    with pytest.raises(ExprError, match="invalid CIDR"):
        evaluate("in_cidr('198.51.100.7', 'nope')", {})


def test_dict_literals_with_string_keys():
    assert evaluate("{'groups': item.g, 'ip': None}", {"item": {"g": ["Workstations"]}}) == {
        "groups": ["Workstations"], "ip": None}
    with pytest.raises(ExprError, match="dict keys must be strings"):
        evaluate("{1: 2}", {})


def test_errors_carry_the_expression_and_helper_failures_are_wrapped():
    with pytest.raises(ExprError, match="in 'len\\(5\\)'"):
        evaluate("len(5)", {})
    with pytest.raises(ExprError, match="division by zero"):
        evaluate("1 / 0", {})
    with pytest.raises(ExprError, match="unknown name 'nope'"):
        evaluate("nope", {})


def test_names_used_lists_free_names_only():
    assert names_used("any(d.verdict == 'MALICIOUS' for d in item.detections) and facts.n > 0") == {"item", "facts"}
    assert names_used("ids(results.investigate_endpoint)") == {"results"}


def test_the_evaluator_uses_no_reflection():
    source = expr.__loader__.get_source(expr.__name__)  # type: ignore[union-attr]
    tree = ast.parse(source)
    called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not called & {"getattr", "setattr", "eval", "exec", "compile", "__import__", "vars", "globals"}
