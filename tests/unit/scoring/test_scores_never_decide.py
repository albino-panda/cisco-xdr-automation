"""What scores never do (architecture 14.2.5, docs/threat-scoring.md section 8).

Scores never approve, skip approval, execute or change ``approval_level``; critical assets are
always ELEVATED with a visible warning whatever the score; the scoring code stays in the read zone.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.fixtures.factories import FIXED_NOW, make_incident
from tests.unit.scoring._support import CAT, DC, ctx, engine, sig, worked_example_signals
from xdr_response.approval import CriticalAssetPolicy, PackageBuilder
from xdr_response.clock import FixedClock
from xdr_response.config import AllowlistPolicy, load_settings
from xdr_response.models import ActionType, ApprovalLevel, EvidenceDraft, ProposedAction, get_action_spec
from xdr_response.models.enums import HealthStatus, Verdict

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src" / "xdr_response"
SCORING_FILES = [SRC / "scoring" / "engine.py", SRC / "scoring" / "signals.py", SRC / "scoring" / "verdict.py",
                 SRC / "scoring" / "__init__.py", SRC / "models" / "scoring.py"]

# critical-asset fixtures of config/critical_assets.example.yaml, plus a non-critical control
TARGETS = [
    (ActionType.ISOLATE_ENDPOINT, "DC-01", "secure_endpoint"),
    (ActionType.ISOLATE_ENDPOINT, "PRD-WEB-01", "secure_endpoint"),
    (ActionType.DISABLE_USER, "svc-backup@example.com", "entra"),
    (ActionType.DISABLE_USER, "ceo@example.com", "entra"),
    (ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", "secure_endpoint"),
]


def _score_pairs() -> list[tuple[int, int]]:
    e = engine()
    breakdowns = [
        e.score([], context=ctx()),
        e.score([sig(CAT.REPUTATION, "virustotal", 90, 80)], context=ctx()),
        e.score(worked_example_signals(), context=ctx(critical=[DC])),
        e.score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 95, 10)],
                context=ctx(failed=[("virustotal", HealthStatus.UNAVAILABLE)])),
        e.score([sig(CAT.ENDPOINT_DETECTION, "secure_endpoint", 100, 100),
                 sig(CAT.REPUTATION, "umbrella", 0, 100, verdict=Verdict.CLEAN)], context=ctx()),
    ]
    return sorted({(b.risk_score, b.confidence_score) for b in breakdowns} | {(0, 0), (100, 100), (100, 0), (0, 100)})


@pytest.fixture(scope="module")
def builder() -> PackageBuilder:
    settings = load_settings(ROOT / "config", env={})
    return PackageBuilder(settings, critical_assets=CriticalAssetPolicy(settings.critical_assets),
                          allowlists=AllowlistPolicy(settings.allowlists), clock=FixedClock(FIXED_NOW),
                          id_factory=lambda: "pkg-score")


def _package(builder: PackageBuilder, action_type: ActionType, target: str, integration: str, risk: int,
             confidence: int):
    spec = get_action_spec(action_type)
    proposal = ProposedAction(action_type=action_type, target=target, target_kind=spec.target_kind,
                              params={"integration": integration},
                              evidence=(EvidenceDraft(source=integration, summary="EDR alert (fake)",
                                                      observed_at=FIXED_NOW),),
                              risk_score=risk, confidence_score=confidence, rationale="test")
    return builder.build(make_incident(), [proposal], risk_score=risk, confidence_score=confidence, summary="test")


@pytest.mark.parametrize("action_type,target,integration", TARGETS)
def test_no_score_changes_approval_level_or_warnings(builder, action_type, target, integration):
    outcomes = set()
    for risk, confidence in _score_pairs():
        [action] = _package(builder, action_type, target, integration, risk, confidence).actions
        outcomes.add((action.approval_level, tuple(w.message for w in action.warnings)))
    assert len(outcomes) == 1, outcomes
    [(level, warnings)] = outcomes
    if target == "TH-LT-1047":
        assert level is ApprovalLevel.STANDARD and warnings == ()
    else:
        assert level is ApprovalLevel.ELEVATED and warnings
        assert all(w.startswith("WARNING: ELEVATED APPROVAL REQUIRED") for w in warnings)


def test_a_low_score_never_hides_a_critical_asset_action(builder):
    pkg = _package(builder, ActionType.ISOLATE_ENDPOINT, "DC-01", "secure_endpoint", 0, 0)
    assert len(pkg.actions) == 1 and pkg.actions[0].approval_level is ApprovalLevel.ELEVATED


# ------------------------------------------------------------- read zone --
_FORBIDDEN_MODULES = (
    "xdr_response.guard", "xdr_response.approval", "xdr_response.execution", "xdr_response.restoration",
    "xdr_response.dryrun", "xdr_response.verification", "xdr_response.integrations", "xdr_response.lifecycle",
    "xdr_response.audit", "httpx", "subprocess", "socket", "importlib",
)
_FORBIDDEN_CALLS = {"getattr", "setattr", "delattr", "vars", "globals", "__import__", "eval", "exec", "compile",
                    "open"}


@pytest.mark.parametrize("path", SCORING_FILES, ids=lambda p: p.name)
def test_scoring_code_stays_in_the_read_zone(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            assert not name.startswith(_FORBIDDEN_MODULES), f"{path.name} imports {name}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in _FORBIDDEN_CALLS, f"{path.name} calls {node.func.id}"
        if isinstance(node, ast.Attribute) and node.attr in ("execute", "approve", "issue", "submit_decision"):
            pytest.fail(f"{path.name} references .{node.attr}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
            assert isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"), (
                f"{path.name} reads private attribute .{node.attr}")


def test_scoring_models_have_no_approval_or_execution_fields():
    from xdr_response.models.scoring import Contribution, ScoreBreakdown, ScoringContext, ScoringSignal

    for model in (ScoringSignal, ScoringContext, Contribution, ScoreBreakdown):
        for field in model.model_fields:
            assert "approv" not in field and "execut" not in field and "token" not in field, (model, field)
