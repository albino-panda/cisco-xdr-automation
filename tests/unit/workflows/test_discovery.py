"""Workflow discovery and routing (architecture 14.3.5)."""
from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE
from tests.fixtures.sample_workflows.lab import make_incident
from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW
from tests.fixtures.sample_workflows.sample_malware.hooks import SampleMalwareHooks
from xdr_response.workflows.discovery import (
    DiscoveredWorkflow,
    WorkflowCatalog,
    WorkflowDiscoveryError,
    discover_workflows,
    not_migrated,
)

_COUNTER = itertools.count()
_IMPORT = "from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW as _BASE\n"


def _root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workflows: dict[str, str]) -> str:
    """A throw-away root package with one sub-package per entry (unique name per test)."""
    name = f"wf_discovery_{next(_COUNTER)}_{tmp_path.name.replace('-', '_')}"
    package = tmp_path / name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "notes.py").write_text("X = 1\n", encoding="utf-8")  # a plain module is not a workflow
    (package / "_private").mkdir()
    (package / "_private" / "__init__.py").write_text("raise RuntimeError('never imported')\n", encoding="utf-8")
    for sub, body in workflows.items():
        (package / sub).mkdir()
        (package / sub / "__init__.py").write_text(body, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    return name


def _variant(workflow_id: str) -> str:
    return _IMPORT + f"WORKFLOW = _BASE.model_copy(update={{'id': {workflow_id!r}}})\n"


def test_the_sample_package_is_discovered(sample_catalog):
    assert sample_catalog.ids() == ("sample-malware",)
    found = sample_catalog.get("sample-malware")
    assert found.definition == WORKFLOW and found.id == "sample-malware"
    assert isinstance(found.hooks, SampleMalwareHooks)
    assert found.module == f"{SAMPLE_PACKAGE}.sample_malware"
    assert "sample-malware" in sample_catalog and len(sample_catalog) == 1
    with pytest.raises(KeyError):
        sample_catalog.get("ransomware")


def test_the_production_package_discovers_without_errors():
    assert isinstance(discover_workflows(), WorkflowCatalog)


def test_sub_packages_are_workflows_and_sorted(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch, {"zeta_flow": _variant("zeta-flow"), "alpha_flow": _variant("alpha-flow")})
    catalog = discover_workflows(root)
    assert catalog.ids() == ("alpha-flow", "zeta-flow")
    assert catalog.get("alpha-flow").hooks is None


@pytest.mark.parametrize("body, match", [
    ("X = 1\n", "does not export WORKFLOW"),
    ("WORKFLOW = {'id': 'x'}\n", "not a WorkflowDefinition"),
    ("raise ImportError('boom')\n", "cannot be imported: ImportError: boom"),
    (_IMPORT + "WORKFLOW = _BASE.model_copy(update={'version': 'one'})\n", "invalid definition"),
    (_IMPORT + "WORKFLOW = _BASE\n", "package name must be 'sample_malware'"),
    (_variant("broken-flow") + "HOOKS = object()\n", "HOOKS must be a WorkflowHooks"),
])
def test_a_broken_workflow_fails_loudly(tmp_path, monkeypatch, body, match):
    root = _root(tmp_path, monkeypatch, {"broken_flow": body})
    with pytest.raises(WorkflowDiscoveryError, match=match) as info:
        discover_workflows(root)
    assert f"{root}.broken_flow" in str(info.value) or "package name" in str(info.value)


def test_unknown_or_module_roots_fail_loudly():
    with pytest.raises(WorkflowDiscoveryError, match="cannot be imported"):
        discover_workflows("tests.fixtures.no_such_package")
    with pytest.raises(WorkflowDiscoveryError, match="is a module, not a package"):
        discover_workflows("tests.fixtures.factories")


def test_duplicate_ids_are_refused():
    entry = DiscoveredWorkflow(definition=WORKFLOW, hooks=None, module="a")
    with pytest.raises(WorkflowDiscoveryError, match="duplicate workflow id"):
        WorkflowCatalog([entry, DiscoveredWorkflow(definition=WORKFLOW, hooks=None, module="b")])
    with pytest.raises(WorkflowDiscoveryError, match="DiscoveredWorkflow"):
        WorkflowCatalog([WORKFLOW])  # type: ignore[list-item]


def test_resolve_prefers_the_incident_workflow_id(sample_catalog):
    incident = make_incident(workflow_id="sample-malware", title="Unrelated title")
    assert sample_catalog.resolve(incident).id == "sample-malware"


def test_resolve_by_trigger_and_none(sample_catalog):
    assert sample_catalog.resolve(make_incident(workflow_id="xdr-generic")).id == "sample-malware"
    assert sample_catalog.resolve(make_incident(workflow_id="xdr-generic", title="Phishing reported")) is None


def test_a_legacy_workflow_not_migrated_takes_the_generic_path(sample_catalog):
    incident = make_incident(workflow_id="ransomware")  # the title would match the sample trigger
    assert not_migrated("ransomware", sample_catalog)
    assert not not_migrated("sample-malware", sample_catalog)
    assert sample_catalog.resolve(incident) is None


def test_priority_then_id_breaks_ties():
    low = WORKFLOW.model_copy(update={"id": "b-flow"})
    tie = WORKFLOW.model_copy(update={"id": "a-flow"})
    catalog = WorkflowCatalog([DiscoveredWorkflow(low, None, "x.b"), DiscoveredWorkflow(tie, None, "x.a")])
    assert catalog.resolve(make_incident(workflow_id="xdr-generic")).id == "a-flow"
    high_trigger = WORKFLOW.triggers[0].model_copy(update={"priority": 500})
    high = WORKFLOW.model_copy(update={"id": "c-flow", "triggers": (high_trigger,)})
    catalog = WorkflowCatalog([*(DiscoveredWorkflow(d, None, "x") for d in (low, tie)),
                               DiscoveredWorkflow(high, None, "x.c")])
    assert catalog.resolve(make_incident(workflow_id="xdr-generic")).id == "c-flow"


def test_assign_sets_workflow_id_and_version(sample_catalog):
    incident = make_incident(workflow_id="xdr-generic")
    assigned = sample_catalog.assign(incident)
    assert (assigned.workflow_id, assigned.workflow_version) == ("sample-malware", "1.0.0")
    assert sample_catalog.assign(assigned) is assigned
    other = make_incident(workflow_id="xdr-generic", title="Phishing reported")
    assert sample_catalog.assign(other) is other
