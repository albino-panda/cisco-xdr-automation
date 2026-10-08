"""Workflow framework (architecture 14.3).

Framework modules are plain modules (``definition``, ``expr``, ``hooks``, ``runner``,
``discovery``); every sub-*package* whose name does not start with ``_`` is a workflow, found by
:func:`xdr_response.workflows.discovery.discover_workflows`. Adding a workflow is adding a
directory: no file lists workflows.

Workflows only investigate and recommend. They never call a state-changing adapter method, never
construct approval tokens and never enter a guard context; execution happens only through the
lifecycle orchestrator after a human approved the package.

This package re-exports only the light layer 0 names (definition, expression language, hooks); the
runner and discovery are imported from their modules.
"""
from __future__ import annotations

from xdr_response.workflows.definition import (
    APPROVAL_LIKE_KEYS,
    SEMVER_RE,
    TACTICS,
    WORKFLOW_ID_RE,
    CorrelationSpec,
    IntegrationRequirement,
    InvestigationStep,
    MitreMapping,
    RecommendationRule,
    ScoringInputs,
    TriggerSpec,
    WorkflowDefinition,
)
from xdr_response.workflows.expr import ExprError
from xdr_response.workflows.hooks import RunView, WorkflowHooks

__all__ = [
    "APPROVAL_LIKE_KEYS",
    "SEMVER_RE",
    "TACTICS",
    "WORKFLOW_ID_RE",
    "CorrelationSpec",
    "ExprError",
    "IntegrationRequirement",
    "InvestigationStep",
    "MitreMapping",
    "RecommendationRule",
    "RunView",
    "ScoringInputs",
    "TriggerSpec",
    "WorkflowDefinition",
    "WorkflowHooks",
]
