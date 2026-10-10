"""Repository-wide checks that no spec text asserts a weaker rule than the runtime (architecture 14.4, 14.7.1 item 2).

The legacy plan engine (``engine/xdr_plan``), its specs and its tests were retired at the end of Phase 5
(14.4.3, 14.13.1). These checks keep the agent and forbidden-key rules without ``xdr_plan`` and pin the
retirement itself.
"""
from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from xdr_response.config.loader import FORBIDDEN_KEYS
from xdr_response.workflows.discovery import discover_workflows

ROOT = Path(__file__).resolve().parents[3]
SPEC_TEXT = sorted(
    p for p in [*ROOT.glob("workflows/**/*.md"), *ROOT.glob("atomic/**/*"), *ROOT.glob("integrations/**/*.md"),
                *ROOT.glob(".claude/agents/wf-*.md")]
    if p.is_file()
)
SPEC_YAML = sorted(
    p for p in [*ROOT.glob("config/**/*.yaml"), *ROOT.glob("docs/**/*.yaml"), *ROOT.glob("workflows/**/*.yaml"),
                *ROOT.glob("tests/fixtures/workflows/**/*.yaml")]
    if p.is_file()
)
RENAMES = {"powershell": "malicious-powershell", "rmm": "unauthorized-rmm"}
# 14.4.3 / 14.13.1: deleted at the end of Phase 5.
RETIRED_PATHS = (
    "engine",
    "src/xdr_response/lifecycle/plan_bridge.py",
    "tools/simulator/legacy_replay.py",
    "tests/simulation/test_legacy_replay.py",
    "tests/unit/lifecycle/test_plan_bridge.py",
    "tests/test_workflows.py",
    "tests/test_engine.py",
    "tests/unit/legacy/test_legacy_expr_shim.py",
    "tests/unit/legacy/test_legacy_guardrails.py",
    "tests/unit/legacy/test_legacy_planner.py",
    "tests/unit/legacy/test_legacy_repo.py",
    "tests/unit/legacy/test_legacy_validate.py",
    "docs/deployment/guardrails.example.yaml",
)


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _forbidden_keys(node: Any, path: str = "") -> Iterator[str]:
    """Every key of ``FORBIDDEN_KEYS`` at any depth (same normalisation as the config loader)."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).strip().lower() in FORBIDDEN_KEYS:
                yield here
            yield from _forbidden_keys(value, here)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _forbidden_keys(value, f"{path}[{i}]")


def test_forbidden_key_helper_matches_the_loader():
    assert list(_forbidden_keys({"a": [{"Auto_Approve ": True}], "skip_approval": 1})) == [
        "a[0].Auto_Approve ", "skip_approval"]
    assert {"auto_approve", "skip_approval", "bypass_approval", "approval_required"} <= FORBIDDEN_KEYS


@pytest.mark.parametrize("path", SPEC_YAML, ids=_rel)
def test_no_forbidden_keys_in_config_docs_or_workflow_scenarios(path):
    assert list(_forbidden_keys(yaml.safe_load(path.read_text(encoding="utf-8")))) == []


@pytest.mark.parametrize("path", RETIRED_PATHS)
def test_retired_legacy_paths_are_gone(path):
    assert not (ROOT / path).exists()


def test_no_legacy_spec_or_atomic_spec_remains():
    assert list(ROOT.glob("workflows/*/workflow.yaml")) == []
    assert list(ROOT.glob("workflows/*/scenarios")) == []
    assert list(ROOT.glob("atomic/*/atomic.yaml")) == []
    assert [p.name for p in (ROOT / "atomic").iterdir()] == ["README.md"]


@pytest.mark.parametrize("word", ["skipped_protected", "skipped_limit", "{plan.unlock_codes}"])
def test_removed_statuses_and_placeholders_are_gone(word):
    offenders = [_rel(p) for p in SPEC_TEXT if word in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_no_auto_approval_wording_left():
    pattern = re.compile(r"eligible for auto-approval|auto-approved (in|for)|auto_approve\.", re.IGNORECASE)
    offenders = [_rel(p) for p in SPEC_TEXT if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_no_spec_text_says_session_revocation_skips_approval():
    pattern = re.compile(r"requires_approval:\s*false", re.IGNORECASE)
    offenders = [_rel(p) for p in [*SPEC_TEXT, *SPEC_YAML] if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


@pytest.mark.parametrize("old, new", sorted(RENAMES.items()))
def test_renamed_workflows(old, new):
    assert not (ROOT / "workflows" / old).exists()
    assert not (ROOT / ".claude" / "agents" / f"wf-{old}.md").exists()
    definition = discover_workflows().get(new).definition
    assert definition.id == new and definition.legacy_id == new
    assert (ROOT / "workflows" / new / "README.md").is_file()
    agent = (ROOT / ".claude" / "agents" / f"wf-{new}.md").read_text(encoding="utf-8")
    assert f"name: wf-{new}\n" in agent and f"workflows/{new}/" in agent
    assert f"workflows/{old}/" not in agent


def test_no_reference_to_old_workflow_ids():
    old_refs = re.compile(r"^- (powershell|rmm)$|workflows/(powershell|rmm)/|`wf-(powershell|rmm)`", re.MULTILINE)
    offenders = [_rel(p) for p in SPEC_TEXT if old_refs.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


@pytest.mark.parametrize("wid", sorted(discover_workflows().ids()))
def test_agents_follow_the_phase_2_to_5_model(wid):
    agent = " ".join((ROOT / ".claude" / "agents" / f"wf-{wid}.md").read_text(encoding="utf-8").split())
    snake = wid.replace("-", "_")
    for needle in (f"src/xdr_response/workflows/{snake}/definition.py", f"tests/fixtures/workflows/{wid}/",
                   f"tests/workflows/{snake}/", "check_workflow_readmes.py --workflow", "ELEVATED",
                   "never constructs approval tokens"):
        assert needle in agent, needle
