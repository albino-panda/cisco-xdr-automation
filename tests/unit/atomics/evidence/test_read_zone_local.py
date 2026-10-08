"""Local read-zone guard for the correlation-evidence modules (14.0.1).

The full lint lives in tests/safety/test_read_zone.py (workflow-framework); this keeps the
correlation-evidence key honest on its own files: no write-zone imports, no dynamic attribute or
code access, no I/O, and no construction of approval or execution objects.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[4] / "src" / "xdr_response" / "atomics"
FILES = [SRC / "evidence.py", *sorted((SRC / "correlation").glob("*.py"))]

FORBIDDEN_MODULES = (
    "xdr_response.guard", "xdr_response.approval.tokens", "xdr_response.approval.engine",
    "xdr_response.approval.authenticator", "xdr_response.approval.ledger", "xdr_response.approval.package",
    "xdr_response.approval._quorum", "xdr_response.execution", "xdr_response.restoration",
    "xdr_response.dryrun", "xdr_response.verification", "xdr_response.integrations", "httpx", "importlib",
    "subprocess", "socket",
)
FORBIDDEN_NAMES = {"getattr", "setattr", "delattr", "hasattr", "vars", "globals", "__import__", "eval", "exec",
                   "compile", "open"}
FORBIDDEN_CLASSES = {"ApprovalToken", "ApprovalTokenClaims", "TokenActionGrant", "ApproverClaim", "AnalystDecision",
                     "DecisionRequest", "ApproverCredential", "AuthenticatedPrincipal", "RecommendedAction",
                     "ActionPackage", "ContainmentPackage", "ReleasePackage", "ActionRequest", "ActionBinding",
                     "ProposedAction"}


def _imports(tree: ast.AST) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names += [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
    return names


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_module_stays_in_the_read_zone(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert [m for m in _imports(tree) if m.startswith(FORBIDDEN_MODULES)] == []
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert names & FORBIDDEN_NAMES == set()
    assert names & FORBIDDEN_CLASSES == set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
            assert isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"}, ast.unparse(node)


def test_all_owned_modules_are_checked():
    assert {p.name for p in FILES} >= {"evidence.py", "__init__.py", "models.py", "correlate.py", "blast_radius.py"}
