"""``tools/validation/generate_workflow_docs.py`` (architecture 14.5.5)."""
from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tools.validation import generate_workflow_docs as gen


def mitre(tactic, tactic_name, technique, technique_name, sub=None, sub_name=None):
    return SimpleNamespace(tactic=tactic, tactic_name=tactic_name, technique=technique, technique_name=technique_name,
                           sub_technique=sub, sub_technique_name=sub_name, attack_id=sub or technique)


def definition(**overrides):
    """A stand-in with the ``WorkflowDefinition`` attributes the generator reads."""
    base = dict(
        id="ransomware", name="Ransomware", phase=2, default_severity=SimpleNamespace(value="CRITICAL"),
        legacy_id="ransomware",
        mitre=(mitre("TA0040", "Impact", "T1486", "Data Encrypted for Impact"),
               mitre("TA0040", "Impact", "T1490", "Inhibit System Recovery")),
        recommendations=(SimpleNamespace(action=SimpleNamespace(value="isolate_endpoint")),
                         SimpleNamespace(action=SimpleNamespace(value="block_hash")),
                         SimpleNamespace(action=SimpleNamespace(value="isolate_endpoint"))),
        required_integrations=(SimpleNamespace(integration="secure_endpoint"),),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def credential_dumping():
    return definition(
        id="credential-dumping", name="Credential dumping", phase=3, legacy_id="credential-dumping",
        mitre=(mitre("TA0006", "Credential Access", "T1003", "OS Credential Dumping", "T1003.002",
                     "Security Account Manager"),
               mitre("TA0006", "Credential Access", "T1003", "OS Credential Dumping", "T1003.001", "LSASS Memory")),
        recommendations=(SimpleNamespace(action=SimpleNamespace(value="isolate_endpoint")),
                         SimpleNamespace(action=SimpleNamespace(value="revoke_sessions"))),
    )


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "tests" / "fixtures" / "workflows" / "ransomware").mkdir(parents=True)
    for name in ("tp-approve-all.yaml", "dry-run.yaml"):
        (tmp_path / "tests" / "fixtures" / "workflows" / "ransomware" / name).write_text("schema: 1\n", encoding="utf-8")
    (tmp_path / "tests" / "fixtures" / "workflows" / "credential-dumping").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "workflows" / "credential-dumping" / "01.yaml").write_text(
        "name: x\n", encoding="utf-8")
    return tmp_path


def test_every_definition_becomes_a_migrated_entry(root):
    entries = gen.collect(root, [definition(), credential_dumping()])
    assert [(e.id, e.status, e.phase, e.scenarios) for e in entries] == [
        ("credential-dumping", "migrated", 3, 1), ("ransomware", "migrated", 2, 2)]
    ransomware = entries[1]
    assert ransomware.severity == "critical"
    assert ransomware.actions == ("isolate_endpoint", "block_hash")  # de-duplicated, ordered
    assert ransomware.integrations == ("secure_endpoint",)


def test_the_legacy_spec_source_is_retired():
    """14.4.3: the generator reads only workflow definitions (no ``xdr_plan``, no ``workflow.yaml``)."""
    assert not hasattr(gen, "legacy_entry") and not hasattr(gen, "load_legacy_specs")
    source = Path(gen.__file__).read_text(encoding="utf-8")
    assert "from xdr_plan" not in source and "import xdr_plan" not in source and '"engine"' not in source


def test_mitre_yaml_schema_2_sorted_with_tactics(root):
    text = gen.render_mitre_yaml(gen.collect(root, [definition(), credential_dumping()]))
    assert text.startswith(gen.YAML_HEADER + "\n")
    data = yaml.safe_load(text)
    assert data["schema_version"] == 2
    assert [t["id"] for t in data["techniques"]] == ["T1003.001", "T1003.002", "T1486", "T1490"]
    t1486 = data["techniques"][2]
    assert t1486 == {"id": "T1486", "name": "Data Encrypted for Impact",
                     "tactics": [{"id": "TA0040", "name": "Impact"}], "workflows": ["ransomware"]}
    assert data["techniques"][0]["name"] == "LSASS Memory"
    assert data["techniques"][0]["tactics"] == [{"id": "TA0006", "name": "Credential Access"}]


def test_technique_ids_sort_numerically():
    entry = gen.WorkflowEntry("x", "X", 2, "migrated", "high",
                              tuple(gen.TechniqueRef(t, t) for t in ("T1566.002", "T1110.003", "T1566", "T1021.006")),
                              (), (), 0)
    assert [t.id for t in gen.techniques([entry])] == ["T1021.006", "T1110.003", "T1566", "T1566.002"]


def test_sub_technique_names_and_shared_techniques(root):
    d = definition(id="malware", legacy_id=None, mitre=(
        mitre("TA0002", "Execution", "T1204", "User Execution", "T1204.002", "Malicious File"),
        mitre("TA0001", "Initial Access", "T1204", "User Execution", "T1204.002", "Malicious File"),
    ))
    techs = {t.id: t for t in gen.techniques(gen.collect(root, [d]))}
    assert techs["T1204.002"].name == "Malicious File"
    assert techs["T1204.002"].tactics == {"TA0001": "Initial Access", "TA0002": "Execution"}


def test_readmes_link_every_workflow_and_mark_generated(root):
    files = gen.render_all(gen.collect(root, [definition(), credential_dumping()]))
    mitre_md = files[gen.MITRE_README]
    index_md = files[gen.WORKFLOWS_README]
    for text in (mitre_md, index_md):
        assert text.startswith(gen.MD_HEADER + "\n")
    assert "| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | TA0006 Credential Access |" in mitre_md
    assert "| TA0040 Impact | [`ransomware`](../../workflows/ransomware/README.md) |" in mitre_md
    assert ("| [`ransomware`](../../workflows/ransomware/README.md) | 2 | migrated | critical | T1486, T1490 | "
            "`isolate_endpoint`, `block_hash` | `secure_endpoint` | 2 | - |") in index_md
    assert "| Scenarios | Hands off to |" in index_md


def test_hand_off_targets_are_listed(root):
    index_md = gen.render_workflows_readme(gen.collect(root, [definition(handoff_to=("account-takeover",))]))
    assert index_md.rstrip().endswith("| 2 | `account-takeover` |")


def test_output_is_deterministic(root):
    a = gen.render_all(gen.collect(root, [definition(), credential_dumping()]))
    b = gen.render_all(gen.collect(root, [credential_dumping(), definition()]))
    assert a == b


def test_check_and_write(root):
    files = gen.render_all(gen.collect(root, [credential_dumping()]))
    assert sorted(gen.stale_files(root, files)) == sorted(
        f"{p.as_posix()}: missing; run python {gen.GENERATOR} --write" for p in files)
    assert sorted(gen.write_files(root, files)) == sorted(files)
    assert gen.stale_files(root, files) == []
    assert gen.write_files(root, files) == []  # nothing rewritten when up to date
    (root / gen.MITRE_README).write_text("hand edit\n", encoding="utf-8")
    assert gen.stale_files(root, files) == [f"docs/mitre-mapping/README.md: out of date; run python {gen.GENERATOR} --write"]


def test_crlf_checkout_is_not_stale(root):
    files = gen.render_all(gen.collect(root, [credential_dumping()]))
    gen.write_files(root, files)
    path = root / gen.WORKFLOWS_README
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert gen.stale_files(root, files) == []


def test_load_catalog_is_empty_without_the_framework(monkeypatch):
    monkeypatch.setitem(sys.modules, "xdr_response.workflows.discovery", None)
    assert gen.load_catalog() == []


def test_load_catalog_reads_discovered_definitions(monkeypatch):
    d1, d2 = definition(id="a-flow"), definition(id="b-flow")
    catalog = SimpleNamespace(ids=lambda: ("a-flow", "b-flow"),
                              get=lambda wid: SimpleNamespace(definition={"a-flow": d1, "b-flow": d2}[wid]))
    fake = types.ModuleType("xdr_response.workflows.discovery")
    fake.discover_workflows = lambda package: catalog
    monkeypatch.setitem(sys.modules, "xdr_response.workflows.discovery", fake)
    if "xdr_response.workflows" not in sys.modules:
        monkeypatch.setitem(sys.modules, "xdr_response.workflows", types.ModuleType("xdr_response.workflows"))
    assert gen.load_catalog() == [d1, d2]


def test_phases_cover_the_14_5_1_table():
    assert len(gen.PHASES) == 22
    assert {w for w, p in gen.PHASES.items() if p == 3} == {
        "malicious-powershell", "credential-dumping", "lateral-movement", "persistence", "unauthorized-rmm"}


def test_main_requires_a_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        gen.main([])
    assert exc.value.code == 2


def test_repository_docs_are_up_to_date():
    assert gen.check() == []
    assert gen.main(["--check"]) == 0
