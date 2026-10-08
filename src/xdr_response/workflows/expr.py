"""Safe expression evaluator for workflow rules (canonical copy of ``engine/xdr_plan/expr.py``, 14.3.2).

Rules and investigation steps are short Python-like expressions such as::

    item.verdict == 'MALICIOUS' and not item.is_critical_asset
    any(s.result == 'success' for s in item.signins)
    ids(results.investigate_endpoint)

Only a small whitelist of syntax and helper functions is allowed. There is no access to builtins,
imports, attributes of Python objects (dict keys only) or assignment, so a definition can never
execute arbitrary code. The evaluator dispatches through a fixed table (no reflection).

Phase 1 additions to ``FUNCTIONS``: ``ids``, ``flatten``, ``distinct``, ``within_minutes`` and
``in_cidr``; dict literals with string keys (for a rule's ``asset`` mapping). ``engine/xdr_plan/expr.py`` becomes a re-export shim of this module (14.4).
"""
from __future__ import annotations

import ast
import ipaddress
import operator
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

__all__ = ["SEVERITIES", "ExprError", "FUNCTIONS", "parse", "evaluate", "names_used"]

SEVERITIES = ["info", "low", "medium", "high", "critical"]


class ExprError(ValueError):
    """Raised for invalid syntax, unknown names or missing fields."""


# ------------------------------------------------------------------ helpers --
def _severity_at_least(value: str, threshold: str) -> bool:
    try:
        return SEVERITIES.index(str(value).lower()) >= SEVERITIES.index(str(threshold).lower())
    except ValueError as exc:
        raise ExprError(f"unknown severity in severity_at_least({value!r}, {threshold!r})") from exc


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return default


def _domain_of(url: str) -> str:
    host = urlsplit(url if "://" in url else "http://" + url).hostname
    return (host or "").lower()


def _lower(value: Any) -> str:
    return str(value).lower()


def _as_items(items: Any) -> list[Any]:
    if items is None:
        return []
    if isinstance(items, (dict, str)):
        return [items]
    if isinstance(items, Iterable):
        return list(items)
    raise ExprError(f"expected a list, got {type(items).__name__}")


def _ids(items: Any) -> list[str]:
    """Record ids of rule items: ``item["record_id"]`` or each item's ``record_ids``, flattened."""
    out: list[str] = []
    for item in _as_items(items):
        if isinstance(item, str):
            found: list[Any] = [item]
        elif isinstance(item, dict) and isinstance(item.get("record_id"), str):
            found = [item["record_id"]]
        elif isinstance(item, dict):
            found = list(item.get("record_ids") or ())
        elif isinstance(item, (list, tuple)):
            found = _ids(item)
        else:
            raise ExprError(f"ids() cannot read record ids from {type(item).__name__}")
        out.extend(str(i) for i in found if i)
    return list(dict.fromkeys(out))


def _flatten(lists: Any) -> list[Any]:
    """One level of flattening; non-list elements are kept as they are."""
    out: list[Any] = []
    for value in _as_items(lists):
        if isinstance(value, (list, tuple)):
            out.extend(value)
        else:
            out.append(value)
    return out


def _distinct(values: Any) -> list[Any]:
    """Sorted unique values (``None`` removed)."""
    unique = {v for v in _as_items(values) if v is not None}
    try:
        return sorted(unique)
    except TypeError:
        return sorted(unique, key=str)


def _timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ExprError(f"not an ISO timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _within_minutes(t1: Any, t2: Any, n: Any) -> bool:
    """True when both timestamps are known and at most ``n`` minutes apart."""
    first, second = _timestamp(t1), _timestamp(t2)
    if first is None or second is None:
        return False
    return abs((first - second).total_seconds()) <= float(n) * 60


def _in_cidr(ip: Any, cidr: Any) -> bool:
    """True when ``ip`` is inside ``cidr``; an empty or invalid address is never inside."""
    try:
        network = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError as exc:
        raise ExprError(f"invalid CIDR {cidr!r}") from exc
    if ip is None or ip == "":
        return False
    try:
        return ipaddress.ip_address(str(ip).strip()) in network
    except ValueError:
        return False


FUNCTIONS: dict[str, Any] = {
    "any": any,
    "all": all,
    "len": len,
    "min": min,
    "max": max,
    "sum": sum,
    "sorted": sorted,
    "lower": _lower,
    "get": _get,
    "domain_of": _domain_of,
    "severity_at_least": _severity_at_least,
    "startswith": lambda s, prefix: str(s).startswith(prefix),
    "endswith": lambda s, suffix: str(s).endswith(suffix),
    # Phase 1 (14.3.2)
    "ids": _ids,
    "flatten": _flatten,
    "distinct": _distinct,
    "within_minutes": _within_minutes,
    "in_cidr": _in_cidr,
}

_COMPARE: Mapping[type, Callable[[Any, Any], Any]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

_BINARY: Mapping[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}

_FORBIDDEN_NODES = (ast.Lambda, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom, ast.DictComp,
                    ast.SetComp, ast.Starred, ast.JoinedStr)


def parse(src: str) -> ast.expr:
    """Parse and statically check an expression. Raises :class:`ExprError`."""
    if not isinstance(src, str) or not src.strip():
        raise ExprError(f"expression must be a non-empty string, got {src!r}")
    try:
        tree = ast.parse(src.strip(), mode="eval")
    except SyntaxError as exc:
        raise ExprError(f"syntax error in {src!r}: {exc.msg}") from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in FUNCTIONS:
                raise ExprError(f"only these functions are allowed: {sorted(FUNCTIONS)} (in {src!r})")
            if node.keywords:
                raise ExprError(f"keyword arguments are not allowed (in {src!r})")
        if isinstance(node, _FORBIDDEN_NODES):
            raise ExprError(f"{type(node).__name__} is not allowed (in {src!r})")
    return tree.body


def names_used(src: str) -> frozenset[str]:
    """Free names an expression reads (function names and comprehension variables excluded)."""
    tree = parse(src)
    bound = {g.target.id for node in ast.walk(tree) if isinstance(node, (ast.ListComp, ast.GeneratorExp))
             for g in node.generators if isinstance(g.target, ast.Name)}
    called = {node.func.id for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    return frozenset(node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
                     and isinstance(node.ctx, ast.Load) and node.id not in bound and node.id not in called)


def evaluate(src: str, names: Mapping[str, Any]) -> Any:
    """Evaluate ``src`` with the given names (dicts, lists and scalars only)."""
    return _Evaluator(src).visit(parse(src), dict(names))


class _Evaluator:
    def __init__(self, src: str) -> None:
        self.src = src
        self._dispatch: dict[type, Callable[[Any, dict[str, Any]], Any]] = {
            ast.Constant: self.v_constant, ast.Name: self.v_name, ast.Attribute: self.v_attribute,
            ast.Subscript: self.v_subscript, ast.BoolOp: self.v_boolop, ast.UnaryOp: self.v_unaryop,
            ast.BinOp: self.v_binop, ast.Compare: self.v_compare, ast.IfExp: self.v_ifexp,
            ast.List: self.v_list, ast.Tuple: self.v_tuple, ast.Dict: self.v_dict, ast.Call: self.v_call,
            ast.GeneratorExp: self.v_comprehension, ast.ListComp: self.v_comprehension,
        }

    def fail(self, msg: str) -> ExprError:
        return ExprError(f"{msg} (in {self.src!r})")

    def visit(self, node: ast.AST, env: dict[str, Any]) -> Any:
        method = self._dispatch.get(type(node))
        if method is None:
            raise self.fail(f"{type(node).__name__} is not allowed")
        return method(node, env)

    def v_constant(self, node: ast.Constant, env: dict[str, Any]) -> Any:
        return node.value

    def v_name(self, node: ast.Name, env: dict[str, Any]) -> Any:
        if node.id in env:
            return env[node.id]
        if node.id in FUNCTIONS:
            return FUNCTIONS[node.id]
        raise self.fail(f"unknown name {node.id!r}; available: {sorted(env)}")

    def v_attribute(self, node: ast.Attribute, env: dict[str, Any]) -> Any:
        obj = self.visit(node.value, env)
        if isinstance(obj, dict):
            if node.attr in obj:
                return obj[node.attr]
            raise self.fail(f"field {node.attr!r} is missing; present fields: {sorted(obj)}. "
                            f"Use get(x, '{node.attr}') for optional fields")
        raise self.fail(f"cannot read .{node.attr} from {type(obj).__name__}")

    def v_subscript(self, node: ast.Subscript, env: dict[str, Any]) -> Any:
        obj = self.visit(node.value, env)
        key = self.visit(node.slice, env)
        if not isinstance(obj, (dict, list, tuple, str)):
            raise self.fail(f"cannot index {type(obj).__name__}")
        try:
            return obj[key]
        except (KeyError, IndexError, TypeError) as exc:
            raise self.fail(f"cannot index with {key!r}: {exc}") from exc

    def v_boolop(self, node: ast.BoolOp, env: dict[str, Any]) -> Any:
        if isinstance(node.op, ast.And):
            result: Any = True
            for value in node.values:
                result = self.visit(value, env)
                if not result:
                    return result
            return result
        result = False
        for value in node.values:
            result = self.visit(value, env)
            if result:
                return result
        return result

    def v_unaryop(self, node: ast.UnaryOp, env: dict[str, Any]) -> Any:
        value = self.visit(node.operand, env)
        if isinstance(node.op, ast.Not):
            return not value
        if isinstance(node.op, ast.USub):
            return -value
        raise self.fail(f"operator {type(node.op).__name__} is not allowed")

    def v_binop(self, node: ast.BinOp, env: dict[str, Any]) -> Any:
        op = _BINARY.get(type(node.op))
        if op is None:
            raise self.fail(f"operator {type(node.op).__name__} is not allowed")
        try:
            return op(self.visit(node.left, env), self.visit(node.right, env))
        except (TypeError, ZeroDivisionError) as exc:
            raise self.fail(str(exc)) from exc

    def v_compare(self, node: ast.Compare, env: dict[str, Any]) -> Any:
        left = self.visit(node.left, env)
        for op_node, comparator in zip(node.ops, node.comparators):
            right = self.visit(comparator, env)
            try:
                ok = _COMPARE[type(op_node)](left, right)
            except TypeError as exc:
                raise self.fail(str(exc)) from exc
            if not ok:
                return False
            left = right
        return True

    def v_ifexp(self, node: ast.IfExp, env: dict[str, Any]) -> Any:
        return self.visit(node.body, env) if self.visit(node.test, env) else self.visit(node.orelse, env)

    def v_list(self, node: ast.List, env: dict[str, Any]) -> Any:
        return [self.visit(e, env) for e in node.elts]

    def v_tuple(self, node: ast.Tuple, env: dict[str, Any]) -> Any:
        return tuple(self.visit(e, env) for e in node.elts)

    def v_dict(self, node: ast.Dict, env: dict[str, Any]) -> Any:
        out: dict[Any, Any] = {}
        for key, value in zip(node.keys, node.values):
            if key is None:  # {**x} unpacking
                raise self.fail("dict unpacking is not allowed")
            name = self.visit(key, env)
            if not isinstance(name, str):
                raise self.fail(f"dict keys must be strings, got {type(name).__name__}")
            out[name] = self.visit(value, env)
        return out

    def v_call(self, node: ast.Call, env: dict[str, Any]) -> Any:
        assert isinstance(node.func, ast.Name)  # validated in parse()
        func = FUNCTIONS[node.func.id]
        args = [self.visit(a, env) for a in node.args]
        try:
            return func(*args)
        except ExprError as exc:
            raise self.fail(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - surface helper errors with context
            raise self.fail(f"{node.func.id}() failed: {exc}") from exc

    def v_comprehension(self, node: ast.ListComp | ast.GeneratorExp, env: dict[str, Any]) -> Any:
        if len(node.generators) != 1:
            raise self.fail("only one 'for' clause is allowed in a comprehension")
        gen = node.generators[0]
        if not isinstance(gen.target, ast.Name):
            raise self.fail("comprehension target must be a single name")
        out = []
        for value in self.visit(gen.iter, env) or []:
            local = {**env, gen.target.id: value}
            if all(self.visit(cond, local) for cond in gen.ifs):
                out.append(self.visit(node.elt, local))
        return out
