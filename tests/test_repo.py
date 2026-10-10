"""Repository-wide consistency checks (YAML parse, links, MITRE generator, agents, atomic table)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".venv", ".git", ".pytest_cache", "__pycache__", "node_modules"}


def _files(pattern: str) -> list[Path]:
    return sorted(p for p in ROOT.rglob(pattern) if not SKIP_PARTS.intersection(p.parts))


def workflow_dirs() -> list[str]:
    """Every workflow id: directories under ``workflows/`` that hold a ``README.md``."""
    return sorted(p.parent.name for p in (ROOT / "workflows").glob("*/README.md"))


def test_all_yaml_parses():
    for path in _files("*.yaml"):
        yaml.safe_load(path.read_text(encoding="utf-8"))


def test_relative_markdown_links_resolve():
    link = re.compile(r"\]\((<[^>]+>|[^)\s]+)\)")
    broken = []
    for md in _files("*.md"):
        for m in link.finditer(md.read_text(encoding="utf-8")):
            target = m.group(1).strip("<>")
            if target.startswith(("http", "#", "mailto:")):
                continue
            if not (md.parent / target.split("#")[0]).resolve().exists():
                broken.append(f"{md.relative_to(ROOT)} -> {target}")
    assert not broken, "\n".join(broken)


def test_workflow_dirs_are_the_discovered_workflows():
    from xdr_response.workflows.discovery import discover_workflows

    assert set(workflow_dirs()) == set(discover_workflows().ids())


def test_mitre_mapping_in_sync():
    from tools.validation import generate_workflow_docs

    assert generate_workflow_docs.check(ROOT) == []
    mapping = yaml.safe_load((ROOT / "docs" / "mitre-mapping" / "mitre-mapping.yaml").read_text(encoding="utf-8"))
    assert mapping["schema_version"] == 2
    mapped = {w for t in mapping["techniques"] for w in t["workflows"]}
    assert mapped <= set(workflow_dirs())


def test_one_agent_per_workflow():
    agents = {}
    for path in (ROOT / ".claude" / "agents").glob("*.md"):
        front = yaml.safe_load(path.read_text(encoding="utf-8").split("---")[1])
        assert front["name"] == path.stem
        agents[path.stem] = front
    assert set(agents) == {f"wf-{w}" for w in workflow_dirs()}


def test_catalog_spec_refs_resolve_to_the_atomic_table():
    """14.13.1: ``spec_ref`` values ``atomic/<name>`` resolve to a row of ``atomic/README.md``."""
    from xdr_response.models.catalog import ActionType, get_action_spec

    table = (ROOT / "atomic" / "README.md").read_text(encoding="utf-8")
    rows = dict(re.findall(r"^\| `(atomic/[a-z-]+)` \| `([a-z_]+)` \|", table, re.MULTILINE))
    refs = {get_action_spec(a).spec_ref: a.value for a in ActionType if get_action_spec(a).spec_ref}
    assert refs == rows


def test_integration_docs_link_the_atomic_table():
    for readme in (ROOT / "integrations").glob("*/README.md"):
        links = re.findall(r"\]\((\.\./\.\./atomic/[^)]*)\)", readme.read_text(encoding="utf-8"))
        assert links and set(links) == {"../../atomic/README.md"}, readme


# Paths deleted at the end of Phase 5 (docs/architecture.md 14.4.3). Only the design history
# (docs/architecture.md, CHANGELOG.md) and the tests that pin the retirement may still name them.
RETIRED_REFERENCES = re.compile(
    r"xdr_plan|plan_bridge|legacy_replay|test_legacy_replay|tests/test_workflows\.py|tests/test_engine\.py"
    r"|guardrails\.example\.yaml|engine/README\.md|PYTHONPATH=engine|atomic/[a-z-]+/(atomic\.yaml|README\.md)"
    r"|--legacy\b"
)
HISTORY = {"docs/architecture.md", "CHANGELOG.md", "tests/test_repo.py", "tests/unit/legacy/test_legacy_alignment.py",
           "tests/unit/legacy/test_generate_workflow_docs.py", "tests/unit/workflows/test_framework_clis.py"}


def test_nothing_references_retired_legacy_paths():
    offenders = []
    for path in [*_files("*.md"), *_files("*.py"), *_files("*.yaml"), *_files("*.yml"), *_files("*.toml"),
                 ROOT / ".gitignore"]:
        rel = path.relative_to(ROOT).as_posix()
        if rel in HISTORY or not path.is_file():
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if RETIRED_REFERENCES.search(line):
                offenders.append(f"{rel}:{n}: {line.strip()[:120]}")
    assert offenders == [], "\n".join(offenders)
