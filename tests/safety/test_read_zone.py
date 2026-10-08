"""The read zone (architecture 14.0.1): investigation and recommendation code can never change state.

Three layers are tested:

1. an AST lint over every read-zone file (``xdr_response.scoring``, ``xdr_response.atomics``,
   ``xdr_response.workflows`` including every workflow package, ``lifecycle/plan_bridge.py``,
   ``lifecycle/workflow_adapter.py`` and the tests-only sample workflow) for the rules of 14.0.1;
2. a runtime check: every workflow scenario detects (investigates and recommends) with zero
   state-changing operations and zero guard denials (the full per-scenario assertions run in
   ``tests/simulation/test_workflow_scenarios.py``);
3. the Phase 0 guard itself: a state-changing adapter call outside an authorized context fails closed.

Imports inside ``if TYPE_CHECKING:`` blocks are type-only and not executed, so they are not checked.
"""
from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE, SAMPLE_SCENARIO_DIR
from tests.fixtures.sample_workflows.lab import HOST, make_lab
from tools.simulator.workflow_scenario import WorkflowScenarioRun, discover_workflow_scenarios, load_workflow_scenario
from xdr_response.errors import ApprovalRequiredError
from xdr_response.models import ActionRequest, ActionType, AuditEventType, TargetKind, get_action_spec
from xdr_response.workflows.discovery import discover_workflows

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "xdr_response"

SAMPLE_ROOT = REPO / "tests" / "fixtures" / "sample_workflows"
#: The sample workflow *packages* are read zone; the lab harness next to them is test code.
READ_ZONE_DIRS = (SRC / "scoring", SRC / "atomics", SRC / "workflows",
                  *(d for d in sorted(SAMPLE_ROOT.iterdir()) if (d / "__init__.py").is_file()))
READ_ZONE_FILES = (SRC / "lifecycle" / "plan_bridge.py", SRC / "lifecycle" / "workflow_adapter.py")

FORBIDDEN_MODULES = (
    "xdr_response.guard", "xdr_response.execution", "xdr_response.restoration", "xdr_response.dryrun",
    "xdr_response.verification", "xdr_response.approval.tokens", "xdr_response.approval.engine",
    "xdr_response.approval.authenticator", "xdr_response.approval.ledger", "xdr_response.approval.package",
    "xdr_response.approval._quorum", "xdr_response.integrations.http", "xdr_response.integrations.auth",
    "xdr_response.integrations.registry", "xdr_response.integrations.simulated", "xdr_response.audit",
    "httpx", "importlib", "subprocess", "socket",
)
VENDOR_PACKAGES = frozenset({
    "cisco_xdr", "secure_endpoint", "secure_email", "secure_malware_analytics", "secure_cloud_analytics", "umbrella",
    "meraki", "entra", "defender_endpoint", "defender_o365", "intune", "microsoft_cloud", "virustotal",
    "alienvault_otx", "hibp", "splunk",
})
#: (path relative to the repository, forbidden module prefix) pairs allowed by 14.0.1.
ALLOWED_IMPORTS = frozenset({
    ("src/xdr_response/atomics/context.py", "xdr_response.integrations.registry"),
    ("src/xdr_response/atomics/context.py", "xdr_response.integrations.simulated"),
    ("src/xdr_response/lifecycle/workflow_adapter.py", "xdr_response.audit"),
    # discovery imports the workflow packages it finds (documented exception, 14.3.5 as built)
    ("src/xdr_response/workflows/discovery.py", "importlib"),
})
FORBIDDEN_CONSTRUCTORS = frozenset({
    "ApprovalToken", "ApprovalTokenClaims", "TokenActionGrant", "ApproverClaim", "AnalystDecision", "DecisionRequest",
    "ApproverCredential", "AuthenticatedPrincipal", "RecommendedAction", "ActionPackage", "ContainmentPackage",
    "ReleasePackage", "ActionRequest", "ActionBinding",
})
FORBIDDEN_CALLS = frozenset({"getattr", "setattr", "delattr", "vars", "globals", "__import__", "eval", "exec",
                             "compile", "open"})
ALLOWED_CALLS = frozenset({("src/xdr_response/atomics/notifications/sinks.py", "open")})
STATE_CHANGING_METHODS = frozenset({"execute"} | {a.value for a in ActionType if get_action_spec(a).state_changing})
BUILDER_MODULE = "src/xdr_response/atomics/containment/builders.py"


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}"


def read_zone_files() -> list[Path]:
    files = [p for d in READ_ZONE_DIRS if d.is_dir() for p in d.rglob("*.py")]
    files += [p for p in READ_ZONE_FILES if p.is_file()]
    return sorted(set(files))


def _relative(path: Path) -> str:
    return path.resolve().relative_to(REPO).as_posix()


def _type_checking_lines(tree: ast.AST) -> set[int]:
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test):
            for child in node.body:
                lines.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
    return lines


def _imported_modules(node: ast.AST) -> Iterator[str]:
    if isinstance(node, ast.Import):
        yield from (alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        yield node.module
        yield from (f"{node.module}.{alias.name}" for alias in node.names)


def _import_violations(rel: str, node: ast.AST) -> Iterator[Violation]:
    for module in _imported_modules(node):
        parts = module.split(".")
        if parts[:2] == ["xdr_response", "integrations"] and len(parts) > 2 and parts[2] in VENDOR_PACKAGES:
            yield Violation(rel, node.lineno, f"imports the vendor module {module}")
        for forbidden in FORBIDDEN_MODULES:
            if (module == forbidden or module.startswith(forbidden + ".")) and (rel, forbidden) not in ALLOWED_IMPORTS:
                yield Violation(rel, node.lineno, f"imports {module}")


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _call_violations(rel: str, node: ast.Call) -> Iterator[Violation]:
    name = _call_name(node)
    if name in FORBIDDEN_CONSTRUCTORS:
        yield Violation(rel, node.lineno, f"constructs {name} (output type is ProposedAction only)")
    if isinstance(node.func, ast.Name) and name in FORBIDDEN_CALLS and (rel, name) not in ALLOWED_CALLS:
        yield Violation(rel, node.lineno, f"calls {name}()")
    if isinstance(node.func, ast.Attribute) and name in STATE_CHANGING_METHODS and rel != BUILDER_MODULE:
        yield Violation(rel, node.lineno, f"calls the state-changing method .{name}()")
    if isinstance(node.func, ast.Attribute) and name == "system":
        yield Violation(rel, node.lineno, "calls os.system")


def _private_violation(rel: str, node: ast.Attribute) -> Violation | None:
    attr = node.attr
    if not attr.startswith("_") or (attr.startswith("__") and attr.endswith("__")):
        return None
    if isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"):
        return None
    return Violation(rel, node.lineno, f"reads the private attribute .{attr} of another object")


def lint(path: Path, rel: str | None = None) -> list[Violation]:
    """Violations of the read-zone rules in one file (``rel`` defaults to the repository path)."""
    rel = rel if rel is not None else _relative(path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    type_only = _type_checking_lines(tree)
    found: list[Violation] = []
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) in type_only:
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            found.extend(_import_violations(rel, node))
        elif isinstance(node, ast.Call):
            found.extend(_call_violations(rel, node))
        elif isinstance(node, ast.Attribute):
            violation = _private_violation(rel, node)
            if violation is not None:
                found.append(violation)
    return found


def test_the_read_zone_is_not_empty():
    names = {_relative(p) for p in read_zone_files()}
    assert "src/xdr_response/workflows/runner.py" in names
    assert "src/xdr_response/atomics/context.py" in names
    assert "src/xdr_response/lifecycle/workflow_adapter.py" in names
    assert "tests/fixtures/sample_workflows/sample_malware/hooks.py" in names


@pytest.mark.parametrize("path", read_zone_files(), ids=_relative)
def test_read_zone_file_obeys_the_rules(path: Path):
    violations = lint(path)
    assert not violations, "\n".join(str(v) for v in violations)


BAD_SOURCE = """import httpx
from xdr_response.guard import authorized
from xdr_response.integrations.entra import adapter
from xdr_response.execution import ActionRunner
def f(adapter, other):
    adapter.execute(1)
    adapter.isolate_endpoint(1)
    getattr(other, 'x')
    other._secret
    ApprovalToken(x=1)
    eval('1')
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from xdr_response.guard import authorized
"""


def test_the_lint_catches_each_rule(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text(BAD_SOURCE, encoding="utf-8")
    found = {(v.line, v.rule) for v in lint(bad, rel="bad.py")}
    assert {line for line, _ in found} == {1, 2, 3, 4, 6, 7, 8, 9, 10, 11}  # line 14 is type-only
    assert (6, "calls the state-changing method .execute()") in found
    assert (7, "calls the state-changing method .isolate_endpoint()") in found
    assert (9, "reads the private attribute ._secret of another object") in found
    assert (10, "constructs ApprovalToken (output type is ProposedAction only)") in found
    assert (3, "imports the vendor module xdr_response.integrations.entra") in found


SAMPLE = discover_workflows(SAMPLE_PACKAGE)
SCENARIOS = [p for paths in discover_workflow_scenarios(SAMPLE_SCENARIO_DIR, catalog=SAMPLE).values() for p in paths]
PRODUCTION = discover_workflows()
SCENARIOS_PRODUCTION = [p for paths in discover_workflow_scenarios(catalog=PRODUCTION).values() for p in paths]


@pytest.mark.parametrize("catalog, path", [*((SAMPLE, p) for p in SCENARIOS),
                                           *((PRODUCTION, p) for p in SCENARIOS_PRODUCTION)],
                         ids=lambda v: v.stem if isinstance(v, Path) else "")
@pytest.mark.parametrize("live", [False, True], ids=["dry_run", "live"])
def test_detection_never_changes_state(catalog, path: Path, live: bool):
    run = WorkflowScenarioRun(load_workflow_scenario(path), live=live, catalog=catalog)
    run.detect()
    assert run.environment.state_changing_calls() == []
    events = {r.event_type for r in run.runtime.audit.records(run.incident_id)}
    assert AuditEventType.GUARD_DENIED not in events and AuditEventType.ACTION_STARTED not in events


def test_a_state_changing_call_outside_an_authorized_context_fails_closed():
    lab = make_lab(dry_run=False)
    adapter = lab.registry.get("secure_endpoint")
    request = ActionRequest(incident_id="XDR-SM-9001", idempotency_key=f"XDR-SM-9001:isolate_endpoint:{HOST}",
                            action_type=ActionType.ISOLATE_ENDPOINT, target=HOST, target_kind=TargetKind.ENDPOINT,
                            params={"integration": "secure_endpoint"})
    with pytest.raises(ApprovalRequiredError):
        adapter.execute(request)
    assert lab.environment.state_changing_calls() == []
