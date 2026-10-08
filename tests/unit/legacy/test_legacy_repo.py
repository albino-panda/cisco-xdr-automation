"""``xdr_plan.repo`` discovery after the Phase 1 renames (architecture 14.4.2)."""
from __future__ import annotations

from pathlib import Path

import pytest

from xdr_plan import repo


@pytest.fixture
def fake_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for wid, files in {
        "legacy-one": ("README.md", "workflow.yaml"),
        "migrated-two": ("README.md",),
        "stray": ("notes.txt",),
    }.items():
        (tmp_path / "workflows" / wid).mkdir(parents=True)
        for name in files:
            (tmp_path / "workflows" / wid / name).write_text("id: x\n", encoding="utf-8")
    monkeypatch.setattr(repo, "ROOT", tmp_path)
    return tmp_path


def test_workflow_ids_only_list_dirs_with_a_legacy_spec(fake_root):
    assert repo.workflow_ids() == ["legacy-one"]


def test_workflow_dirs_list_every_dir_with_a_readme(fake_root):
    assert repo.workflow_dirs() == ["legacy-one", "migrated-two"]


def test_check_forbidden_names_the_source():
    with pytest.raises(ValueError, match=r"my.yaml: forbidden key\(s\) \['a.bypass_approval'\]"):
        repo.check_forbidden({"a": {"bypass_approval": True}}, "my.yaml")
    repo.check_forbidden({"a": {"approval_level": "ELEVATED"}}, "ok.yaml")


def test_example_guardrails_load_without_auto_approve():
    g = repo.load_guardrails()
    assert "auto_approve" not in g
    assert g["allowlist"]["url_block_allowed_domains"] == []
