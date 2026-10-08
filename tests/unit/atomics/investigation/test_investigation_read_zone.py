"""Local read-zone check (architecture 14.0.1) for the investigation key's own modules.

The authoritative lint is ``tests/safety/test_read_zone.py`` (workflow-framework); this keeps the
investigation modules honest on their own: no forbidden imports, no reflective builtins, no access
to another object's private attributes, no state-changing method calls, no token construction.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from xdr_response.models import ActionType, is_state_changing

SRC = Path(__file__).resolve().parents[4] / "src" / "xdr_response" / "atomics"
FILES = sorted([SRC / "records.py", *(SRC / "investigation").rglob("*.py")])

FORBIDDEN_MODULES = (
    "xdr_response.guard", "xdr_response.approval.tokens", "xdr_response.approval.engine",
    "xdr_response.approval.authenticator", "xdr_response.approval.ledger", "xdr_response.approval.package",
    "xdr_response.approval._quorum", "xdr_response.execution", "xdr_response.restoration", "xdr_response.dryrun",
    "xdr_response.verification", "xdr_response.integrations.http", "xdr_response.integrations.auth",
    "xdr_response.integrations.registry", "xdr_response.integrations.simulated", "httpx",
    "xdr_response.audit",
)
VENDOR_PACKAGES = ("cisco_xdr", "secure_endpoint", "secure_email", "secure_malware_analytics",
                   "secure_cloud_analytics", "umbrella", "meraki", "entra", "defender_endpoint", "defender_o365",
                   "intune", "microsoft_cloud", "virustotal", "alienvault_otx", "hibp", "splunk")
FORBIDDEN_NAMES = {"getattr", "setattr", "delattr", "vars", "globals", "__import__", "importlib", "eval", "exec",
                   "compile", "open", "subprocess", "socket"}
FORBIDDEN_CONSTRUCTORS = {"ApprovalToken", "ApprovalTokenClaims", "TokenActionGrant", "ApproverClaim",
                          "AnalystDecision", "DecisionRequest", "ApproverCredential", "AuthenticatedPrincipal",
                          "RecommendedAction", "ActionPackage", "ContainmentPackage", "ReleasePackage",
                          "ActionRequest", "ActionBinding"}
STATE_CHANGING_METHODS = {a.value for a in ActionType if is_state_changing(a)} | {"execute"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
            names.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def test_files_are_found():
    assert len(FILES) >= 12


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_forbidden_imports(path):
    for name in _imported(_tree(path)):
        assert not name.startswith(FORBIDDEN_MODULES), f"{path.name} imports {name}"
        for vendor in VENDOR_PACKAGES:
            assert not name.startswith(f"xdr_response.integrations.{vendor}"), f"{path.name} imports {name}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_reflection_private_access_or_writes(path):
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Name):
            assert node.id not in FORBIDDEN_NAMES, f"{path.name}:{node.lineno} uses {node.id}"
            assert node.id not in FORBIDDEN_CONSTRUCTORS, f"{path.name}:{node.lineno} names {node.id}"
        if isinstance(node, ast.Attribute):
            owner = node.value.id if isinstance(node.value, ast.Name) else None
            if node.attr.startswith("_") and not node.attr.startswith("__"):
                assert owner in ("self", "cls"), f"{path.name}:{node.lineno} reads private .{node.attr}"
            assert node.attr not in STATE_CHANGING_METHODS, f"{path.name}:{node.lineno} calls .{node.attr}"
            assert node.attr not in {"system"} or owner != "os"
