"""The notifications package obeys the read-zone rules of section 14.0.1 (local AST check).

The authoritative lint is ``tests/safety/test_read_zone.py`` (owner workflow-framework); this test
keeps the notifications key honest on its own.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import xdr_response.atomics.notifications as package

PACKAGE_DIR = Path(package.__file__).parent
FILES = sorted(PACKAGE_DIR.glob("*.py"))

FORBIDDEN_MODULES = (
    "xdr_response.guard", "xdr_response.approval.tokens", "xdr_response.approval.engine",
    "xdr_response.approval.authenticator", "xdr_response.approval.ledger", "xdr_response.approval.package",
    "xdr_response.approval._quorum", "xdr_response.execution", "xdr_response.restoration",
    "xdr_response.dryrun", "xdr_response.verification", "xdr_response.integrations", "xdr_response.lifecycle",
    "xdr_response.audit", "httpx", "socket", "subprocess", "importlib",
)
FORBIDDEN_CALLS = {"getattr", "setattr", "delattr", "vars", "globals", "__import__", "eval", "exec",
                   "compile", "open"}
FORBIDDEN_CONSTRUCTORS = {
    "ApprovalToken", "ApprovalTokenClaims", "TokenActionGrant", "ApproverClaim", "AnalystDecision",
    "DecisionRequest", "ApproverCredential", "AuthenticatedPrincipal", "RecommendedAction", "ActionPackage",
    "ContainmentPackage", "ReleasePackage", "ActionRequest", "ActionBinding", "AuditRecord",
}
STATE_CHANGING_CALLS = {"execute", "isolate_endpoint", "block_domain", "disable_user", "revoke_sessions",
                        "add_incident_note", "submit_decision", "submit_release_decision"}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_package_has_the_contract_files() -> None:
    assert {p.name for p in FILES} == {"__init__.py", "models.py", "render.py", "sinks.py", "service.py"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_forbidden_imports(path: Path) -> None:
    modules: list[str] = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(a.name for a in node.names)
    bad = [m for m in modules if any(m == f or m.startswith(f + ".") for f in FORBIDDEN_MODULES)]
    assert not bad


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_forbidden_calls_or_constructors(path: Path) -> None:
    for node in ast.walk(_tree(path)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        builtin = isinstance(func, ast.Name)  # re.compile() is fine, compile() is not
        allowed_open = path.name == "sinks.py" and name == "open"
        assert not builtin or name not in FORBIDDEN_CALLS or allowed_open, f"{path.name}: {name}()"
        assert name not in FORBIDDEN_CONSTRUCTORS, f"{path.name}: constructs {name}"
        assert name not in STATE_CHANGING_CALLS, f"{path.name}: calls {name}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_private_attribute_of_another_object(path: Path) -> None:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
            owner = node.value
            assert isinstance(owner, ast.Name) and owner.id in {"self", "cls"}, f"{path.name}: .{node.attr}"
