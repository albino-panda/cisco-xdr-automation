"""Re-export shim of the canonical rule evaluator ``xdr_response.workflows.expr`` (architecture 14.3.2, 14.4.1).

There is one rule language: the legacy plan engine evaluates ``workflow.yaml`` rules with the same
safe evaluator the workflow framework uses (AST whitelist, no builtins, dict-only attribute access).
``ExprError``, ``FUNCTIONS``, ``parse``, ``evaluate`` and ``_domain_of`` keep their legacy names.

``PYTHONPATH=engine python -m xdr_plan check`` still works from a checkout without installation:
when ``xdr_response`` is not importable, the repository's ``src`` directory is added to the path.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _ensure_src_on_path() -> None:
    """Make ``xdr_response`` importable from a plain checkout (``engine`` on the path, ``src`` not)."""
    try:
        import xdr_response  # noqa: F401, PLC0415
    except ModuleNotFoundError:
        src = Path(__file__).resolve().parents[2] / "src"
        if src.is_dir() and str(src) not in sys.path:
            sys.path.insert(0, str(src))


_ensure_src_on_path()

from xdr_response.workflows.expr import *  # noqa: E402, F403
from xdr_response.workflows.expr import (  # noqa: E402
    FUNCTIONS,
    SEVERITIES,
    ExprError,
    _domain_of,
    evaluate,
    parse,
)

__all__ = ["SEVERITIES", "ExprError", "FUNCTIONS", "parse", "evaluate", "_domain_of"]
