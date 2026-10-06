"""Dry-run system: simulate packages without ever reaching a state-changing call."""
from __future__ import annotations

from xdr_response.dryrun.simulator import (
    DRY_RUN_ACTOR,
    DRY_RUN_FOOTER,
    DRY_RUN_HEADER,
    DryRunSimulator,
    dry_run_line,
    dry_run_lines,
    render_dry_run,
    simulate_and_render,
)
from xdr_response.dryrun.switch import (
    DRY_RUN_ENV_VAR,
    apply_global_dry_run,
    dry_run_scope,
    is_dry_run,
    resolve_dry_run,
)

__all__ = [
    "DRY_RUN_ACTOR",
    "DRY_RUN_ENV_VAR",
    "DRY_RUN_FOOTER",
    "DRY_RUN_HEADER",
    "DryRunSimulator",
    "apply_global_dry_run",
    "dry_run_line",
    "dry_run_lines",
    "dry_run_scope",
    "is_dry_run",
    "render_dry_run",
    "resolve_dry_run",
    "simulate_and_render",
]
