"""Safe expression evaluator for workflow plan rules.

Rules in ``workflow.yaml`` are short Python-like expressions such as::

    item.verdict == 'malicious' and not item.is_internal
    any(s.result == 'success' for s in item.signins)

Only a small whitelist of syntax and helper functions is allowed. There is no
access to builtins, imports, attributes of Python objects or assignment, so a
rule file can never execute arbitrary code.
"""
from __future__ import annotations

import ast
import operator
from typing import Any
from urllib.parse import urlsplit

SEVERITIES = ["info", "low", "medium", "high", "critical"]


class ExprError(ValueError):
    """Raised for invalid syntax, unknown names or missing fields."""


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
}

_COMPARE = {
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

_BINARY = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}


def parse(src: str) -> ast.expr:
    """Parse and statically check an expression. Raises ExprError."""
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
        if isinstance(node, (ast.Lambda, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom,
                             ast.DictComp, ast.SetComp, ast.Starred, ast.JoinedStr)):
            raise ExprError(f"{type(node).__name__} is not allowed (in {src!r})")
    return tree.body


def evaluate(src: str, names: dict[str, Any]) -> Any:
    return _Evaluator(src).visit(parse(src), names)


class _Evaluator:
    def __init__(self, src: str) -> None:
        self.src = src

    def fail(self, msg: str) -> ExprError:
        return ExprError(f"{msg} (in {self.src!r})")

    def visit(self, node: ast.AST, env: dict[str, Any]) -> Any:
        method = getattr(self, "v_" + type(node).__name__, None)
        if method is None:
            raise self.fail(f"{type(node).__name__} is not allowed")
        return method(node, env)

    def v_Constant(self, node: ast.Constant, env):
        return node.value

    def v_Name(self, node: ast.Name, env):
        if node.id in env:
            return env[node.id]
        if node.id in FUNCTIONS:
            return FUNCTIONS[node.id]
        raise self.fail(f"unknown name {node.id!r}; available: {sorted(env)}")

    def v_Attribute(self, node: ast.Attribute, env):
        obj = self.visit(node.value, env)
        if isinstance(obj, dict):
            if node.attr in obj:
                return obj[node.attr]
            raise self.fail(f"field {node.attr!r} is missing; present fields: {sorted(obj)}. "
                            f"Use get(x, '{node.attr}') for optional fields")
        raise self.fail(f"cannot read .{node.attr} from {type(obj).__name__}")

    def v_Subscript(self, node: ast.Subscript, env):
        obj = self.visit(node.value, env)
        key = self.visit(node.slice, env)
        try:
            return obj[key]
        except (KeyError, IndexError, TypeError) as exc:
            raise self.fail(f"cannot index with {key!r}: {exc}") from exc

    def v_BoolOp(self, node: ast.BoolOp, env):
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

    def v_UnaryOp(self, node: ast.UnaryOp, env):
        value = self.visit(node.operand, env)
        if isinstance(node.op, ast.Not):
            return not value
        if isinstance(node.op, ast.USub):
            return -value
        raise self.fail(f"operator {type(node.op).__name__} is not allowed")

    def v_BinOp(self, node: ast.BinOp, env):
        op = _BINARY.get(type(node.op))
        if op is None:
            raise self.fail(f"operator {type(node.op).__name__} is not allowed")
        try:
            return op(self.visit(node.left, env), self.visit(node.right, env))
        except TypeError as exc:
            raise self.fail(str(exc)) from exc

    def v_Compare(self, node: ast.Compare, env):
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

    def v_IfExp(self, node: ast.IfExp, env):
        return self.visit(node.body, env) if self.visit(node.test, env) else self.visit(node.orelse, env)

    def v_List(self, node: ast.List, env):
        return [self.visit(e, env) for e in node.elts]

    def v_Tuple(self, node: ast.Tuple, env):
        return tuple(self.visit(e, env) for e in node.elts)

    def v_Call(self, node: ast.Call, env):
        func = FUNCTIONS[node.func.id]  # validated in parse()
        args = [self.visit(a, env) for a in node.args]
        try:
            return func(*args)
        except ExprError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface helper errors with context
            raise self.fail(f"{node.func.id}() failed: {exc}") from exc

    def _comprehension(self, node, env):
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

    v_GeneratorExp = _comprehension
    v_ListComp = _comprehension
