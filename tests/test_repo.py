"""Repository-wide consistency checks."""
from __future__ import annotations

import re

import pytest
import yaml

from xdr_plan import repo

ROOT = repo.ROOT
INTEGRATIONS = {p.name for p in (ROOT / "integrations").iterdir() if p.is_dir()}


def test_all_yaml_parses():
    for path in ROOT.rglob("*.yaml"):
        if ".venv" in path.parts:
            continue
        yaml.safe_load(path.read_text(encoding="utf-8"))


def test_relative_markdown_links_resolve():
    link = re.compile(r"\]\((<[^>]+>|[^)\s]+)\)")
    broken = []
    for md in ROOT.rglob("*.md"):
        if ".venv" in md.parts or ".pytest_cache" in md.parts:
            continue
        for m in link.finditer(md.read_text(encoding="utf-8")):
            target = m.group(1).strip("<>")
            if target.startswith(("http", "#", "mailto:")):
                continue
            if not (md.parent / target.split("#")[0]).resolve().exists():
                broken.append(f"{md.relative_to(ROOT)} -> {target}")
    assert not broken, "\n".join(broken)


@pytest.mark.parametrize("atomic_id", sorted(repo.atomics()))
def test_atomic_references(atomic_id):
    spec = repo.atomics()[atomic_id]
    assert spec["id"] == atomic_id
    assert set(spec["integrations"]) <= INTEGRATIONS
    assert set(spec["used_by"]) <= set(repo.workflow_dirs())


def test_workflow_ids_are_workflow_dirs():
    """Every legacy spec lives in a workflow directory; migrated ones keep only their README."""
    assert set(repo.workflow_ids()) <= set(repo.workflow_dirs())


@pytest.mark.parametrize("workflow_id", repo.workflow_ids())
def test_workflow_references(workflow_id):
    spec = repo.load_workflow(workflow_id)
    assert spec["id"] == workflow_id
    for step in spec["steps"]:
        if "atomic" in step:
            assert step["atomic"] in repo.atomics(), step
    assert set(spec["integrations"]) <= INTEGRATIONS
    assert set(spec["related_workflows"]) <= set(repo.workflow_dirs())


def test_mitre_mapping_in_sync():
    from tools.validation import generate_workflow_docs

    assert generate_workflow_docs.check(ROOT) == []
    mapping = repo.load_yaml(ROOT / "docs" / "mitre-mapping" / "mitre-mapping.yaml")
    assert mapping["schema_version"] == 2
    from_doc = {(t["id"], w) for t in mapping["techniques"] for w in t["workflows"]}
    from_specs = {(t["id"], wid) for wid in repo.workflow_ids() for t in repo.load_workflow(wid)["mitre_attack"]}
    assert from_specs <= from_doc


def test_one_agent_per_workflow():
    agents = {}
    for path in (ROOT / ".claude" / "agents").glob("*.md"):
        front = yaml.safe_load(path.read_text(encoding="utf-8").split("---")[1])
        assert front["name"] == path.stem
        agents[path.stem] = front
    assert set(agents) == {f"wf-{w}" for w in repo.workflow_dirs()}
