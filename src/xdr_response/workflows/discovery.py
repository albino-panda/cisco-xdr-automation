"""Workflow discovery and routing (architecture 14.3.5). There is no shared registry file.

Every sub-*package* of ``xdr_response.workflows`` whose name does not start with ``_`` is a
workflow. It must export ``WORKFLOW`` (a :class:`WorkflowDefinition`) and may export ``HOOKS`` (a
:class:`WorkflowHooks` instance); its package name equals ``WORKFLOW.id`` with ``-`` replaced by
``_``. Import or validation errors raise :class:`WorkflowDiscoveryError` naming the package: a broken
workflow fails loudly, it is never skipped.

Read-zone note (14.0.1): this module is the one documented exception to the "no ``importlib``"
rule, because importing the discovered packages is its whole job. It imports workflow packages
only (never an adapter) and runs no workflow code besides their module bodies.
"""
from __future__ import annotations

import pkgutil
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import import_module
from types import MappingProxyType, ModuleType

from pydantic import ValidationError

from xdr_response.models import Incident
from xdr_response.workflows.definition import _LEGACY_IDS, WorkflowDefinition
from xdr_response.workflows.hooks import WorkflowHooks

__all__ = ["WorkflowDiscoveryError", "DiscoveredWorkflow", "WorkflowCatalog", "discover_workflows",
           "DEFAULT_PACKAGE"]

DEFAULT_PACKAGE = "xdr_response.workflows"


class WorkflowDiscoveryError(RuntimeError):
    """A workflow package could not be imported or does not export a valid definition."""


@dataclass(frozen=True)
class DiscoveredWorkflow:
    """A validated workflow definition, its optional hooks and the module it came from."""

    definition: WorkflowDefinition
    hooks: WorkflowHooks | None
    module: str  # e.g. "xdr_response.workflows.ransomware"

    @property
    def id(self) -> str:
        return self.definition.id


class WorkflowCatalog:
    """Immutable set of discovered workflows, keyed by workflow id."""

    def __init__(self, workflows: Iterable[DiscoveredWorkflow]) -> None:
        by_id: dict[str, DiscoveredWorkflow] = {}
        for workflow in workflows:
            if not isinstance(workflow, DiscoveredWorkflow):
                raise WorkflowDiscoveryError(f"catalog entries must be DiscoveredWorkflow, got {type(workflow).__name__}")
            if workflow.id in by_id:
                raise WorkflowDiscoveryError(
                    f"duplicate workflow id {workflow.id!r} in {by_id[workflow.id].module} and {workflow.module}")
            by_id[workflow.id] = workflow
        self._by_id = MappingProxyType(dict(sorted(by_id.items())))

    def __repr__(self) -> str:
        return f"WorkflowCatalog({list(self._by_id)})"

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, workflow_id: object) -> bool:
        return workflow_id in self._by_id

    def ids(self) -> tuple[str, ...]:
        """Workflow ids, sorted."""
        return tuple(self._by_id)

    def get(self, workflow_id: str) -> DiscoveredWorkflow:
        """The workflow with this id (``KeyError`` when unknown)."""
        return self._by_id[workflow_id]

    def resolve(self, incident: Incident) -> DiscoveredWorkflow | None:
        """The workflow that handles ``incident``.

        1. ``incident.workflow_id`` is a catalog id: that workflow.
        2. ``incident.workflow_id`` names a legacy spec that is not migrated yet: ``None`` (the
           Phase 0 generic path handles it).
        3. Otherwise the matching automatic triggers: highest priority, then id; ``None`` when
           nothing matches.
        """
        if incident.workflow_id in self._by_id:
            return self._by_id[incident.workflow_id]
        if not_migrated(incident.workflow_id, self):
            return None
        best: tuple[int, str] | None = None
        for workflow_id, workflow in self._by_id.items():
            trigger = workflow.definition.matches(incident)
            if trigger is None:
                continue
            rank = (-trigger.priority, workflow_id)
            if best is None or rank < best:
                best = rank
        return self._by_id[best[1]] if best is not None else None

    def assign(self, incident: Incident) -> Incident:
        """Copy of ``incident`` with ``workflow_id`` / ``workflow_version`` of :meth:`resolve`."""
        workflow = self.resolve(incident)
        if workflow is None:
            return incident
        definition = workflow.definition
        if incident.workflow_id == definition.id and incident.workflow_version == definition.version:
            return incident
        return incident.model_copy(update={"workflow_id": definition.id, "workflow_version": definition.version})


def not_migrated(workflow_id: str, catalog: WorkflowCatalog) -> bool:
    """True when ``workflow_id`` names a legacy spec (14.5.1) that has no definition in ``catalog``."""
    return workflow_id in _LEGACY_IDS and workflow_id not in catalog


def discover_workflows(package: str = DEFAULT_PACKAGE) -> WorkflowCatalog:
    """Import every workflow sub-package of ``package`` and build the catalog (sorted by name)."""
    try:
        root = import_module(package)
    except Exception as exc:  # noqa: BLE001 - reported with the package name
        raise WorkflowDiscoveryError(f"workflow root package {package!r} cannot be imported: "
                                     f"{type(exc).__name__}: {exc}") from exc
    try:
        search_path = root.__path__
    except AttributeError:
        raise WorkflowDiscoveryError(f"{package!r} is a module, not a package") from None
    names = sorted(info.name for info in pkgutil.iter_modules(search_path)
                   if info.ispkg and not info.name.startswith("_"))
    return WorkflowCatalog(_load(f"{package}.{name}", name) for name in names)


def _load(module_name: str, package_name: str) -> DiscoveredWorkflow:
    try:
        module = import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - a broken workflow fails loudly, never skipped
        raise WorkflowDiscoveryError(f"workflow package {module_name} cannot be imported: "
                                     f"{type(exc).__name__}: {exc}") from exc
    definition = _definition(module, module_name)
    if definition.package_name != package_name:
        raise WorkflowDiscoveryError(f"workflow package {module_name}: package name must be "
                                     f"{definition.package_name!r} for workflow id {definition.id!r}")
    return DiscoveredWorkflow(definition=definition, hooks=_hooks(module, module_name), module=module_name)


def _definition(module: ModuleType, module_name: str) -> WorkflowDefinition:
    try:
        definition = module.WORKFLOW
    except AttributeError:
        raise WorkflowDiscoveryError(f"workflow package {module_name} does not export WORKFLOW") from None
    if not isinstance(definition, WorkflowDefinition):
        raise WorkflowDiscoveryError(f"workflow package {module_name}: WORKFLOW is a "
                                     f"{type(definition).__name__}, not a WorkflowDefinition")
    try:  # re-validate: a definition built with model_construct() would skip every validator
        return WorkflowDefinition.model_validate(definition.model_dump())
    except ValidationError as exc:
        raise WorkflowDiscoveryError(f"workflow package {module_name}: invalid definition: {exc}") from exc


def _hooks(module: ModuleType, module_name: str) -> WorkflowHooks | None:
    try:
        hooks = module.HOOKS
    except AttributeError:
        return None
    if hooks is not None and not isinstance(hooks, WorkflowHooks):
        raise WorkflowDiscoveryError(f"workflow package {module_name}: HOOKS must be a WorkflowHooks "
                                     f"instance, got {type(hooks).__name__}")
    return hooks
