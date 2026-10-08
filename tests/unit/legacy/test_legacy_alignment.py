"""Repository-wide checks that no legacy file asserts a weaker rule than the runtime (architecture 14.4, 14.7.1 item 2)."""
from __future__ import annotations

import io
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import yaml

from xdr_plan import repo
from xdr_plan.cli import main as xdr_plan_main
from xdr_plan.guardrails import find_forbidden_keys
from xdr_plan.validate import copies_unlock_code

ROOT = repo.ROOT
LEGACY_TEXT = sorted(
    [*ROOT.glob("workflows/**/*.yaml"), *ROOT.glob("workflows/**/*.md"), *ROOT.glob("atomic/**/*"),
     *ROOT.glob(".claude/agents/wf-*.md"), ROOT / "docs" / "deployment" / "guardrails.example.yaml",
     ROOT / "engine" / "README.md"],
)
LEGACY_TEXT = [p for p in LEGACY_TEXT if p.is_file()]
SPEC_YAML = [p for p in LEGACY_TEXT if p.suffix == ".yaml"]
RENAMES = {"powershell": "malicious-powershell", "rmm": "unauthorized-rmm"}


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_xdr_plan_check_passes():
    out = io.StringIO()
    with redirect_stdout(out):
        code = xdr_plan_main(["check"])
    assert code == 0, out.getvalue()
    assert "[PASS] repository (atomics, guardrails)" in out.getvalue()


@pytest.mark.parametrize("path", SPEC_YAML, ids=_rel)
def test_no_forbidden_keys_in_specs_scenarios_or_guardrails(path):
    assert find_forbidden_keys(yaml.safe_load(path.read_text(encoding="utf-8"))) == []


def test_no_file_asserts_requires_approval_false_for_containment():
    containment = {a for a, s in repo.atomics().items() if s.get("category") == "containment"}
    offenders = []
    for path in SPEC_YAML:
        text = path.read_text(encoding="utf-8")
        if "requires_approval: false" not in text:
            continue
        is_read_atomic = path.name == "atomic.yaml" and path.parent.name not in containment
        if not is_read_atomic:
            offenders.append(_rel(path))
    assert offenders == []


@pytest.mark.parametrize("word", ["skipped_protected", "skipped_limit", "{plan.unlock_codes}"])
def test_removed_statuses_and_placeholders_are_gone(word):
    # engine/README.md documents the checks that refuse these words, so it is the one exception
    offenders = [_rel(p) for p in LEGACY_TEXT
                 if p != ROOT / "engine" / "README.md" and word in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_no_auto_approval_wording_left():
    pattern = re.compile(r"eligible for auto-approval|auto-approved (in|for)|auto_approve\.", re.IGNORECASE)
    offenders = [_rel(p) for p in LEGACY_TEXT if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


@pytest.mark.parametrize("wid", repo.workflow_ids())
def test_templates_never_copy_unlock_codes(wid):
    templates = repo.load_workflow(wid)["templates"]
    assert [k for k, v in templates.items() if copies_unlock_code(str(v))] == []


@pytest.mark.parametrize("old, new", sorted(RENAMES.items()))
def test_renamed_workflows(old, new):
    assert not (ROOT / "workflows" / old).exists()
    assert not (ROOT / ".claude" / "agents" / f"wf-{old}.md").exists()
    if new in repo.workflow_ids():  # legacy spec not migrated yet
        assert repo.load_workflow(new)["id"] == new
    else:  # migrated (14.5.1): the legacy spec is deleted and the framework definition carries the id
        from xdr_response.workflows.discovery import discover_workflows

        definition = discover_workflows().get(new).definition
        assert definition.id == new and definition.legacy_id == new
        assert (ROOT / "workflows" / new / "README.md").is_file()
    agent = (ROOT / ".claude" / "agents" / f"wf-{new}.md").read_text(encoding="utf-8")
    assert f"name: wf-{new}\n" in agent and f"workflows/{new}/" in agent
    assert f"workflows/{old}/" not in agent


def test_no_reference_to_old_workflow_ids():
    old_refs = re.compile(r"^- (powershell|rmm)$|workflows/(powershell|rmm)/|`wf-(powershell|rmm)`", re.MULTILINE)
    offenders = [_rel(p) for p in LEGACY_TEXT if old_refs.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


@pytest.mark.parametrize("wid", repo.workflow_ids())
def test_agents_follow_the_phase_2_to_5_model(wid):
    agent = (ROOT / ".claude" / "agents" / f"wf-{wid}.md").read_text(encoding="utf-8")
    snake = wid.replace("-", "_")
    for needle in (f"src/xdr_response/workflows/{snake}/definition.py", f"tests/fixtures/workflows/{wid}/",
                   f"tests/workflows/{snake}/", "check_workflow_readmes.py --workflow", "ELEVATED",
                   "never constructs approval tokens"):
        assert needle in agent, needle
