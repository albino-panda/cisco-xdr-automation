#!/usr/bin/env python3
"""Cross-check every adapter manifest against docs/integrations.md (architecture 13.2, 13.7).

Usage:
    python tools/validation/check_endpoints.py
    python tools/validation/check_endpoints.py --list            # print every operation
    python tools/validation/check_endpoints.py --integration entra

For every integration of ``INTEGRATION_NAMES`` the adapter class is loaded (no instance, no network)
and each manifest operation is checked: a VERIFIED operation needs an HTTP method and a source
that appears in ``docs/integrations.md``; an UNVERIFIED operation cites no source (calling it raises
the documented unverified error, so it is never implemented); every action type the manifest
claims to support is served by a VERIFIED state-changing operation. The same rules run in CI as
``tests/unit/vendors/test_vendor_contracts.py``.

Exit codes: 0 consistent, 1 problems (one line each), 2 usage error. Read-only.
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT / "src") not in sys.path:  # run from a checkout without install
    sys.path.insert(0, str(_ROOT / "src"))

from xdr_response.integrations.base import CapabilityManifest  # noqa: E402
from xdr_response.integrations.registry import load_adapter_class  # noqa: E402
from xdr_response.models import INTEGRATION_NAMES, EndpointStatus, OperationKind  # noqa: E402

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2
DOCS = _ROOT / "docs" / "integrations.md"


def check_manifest(manifest: CapabilityManifest, docs: str) -> list[str]:
    """Problems of one manifest against the integrations document (empty list: consistent)."""
    name = manifest.integration
    problems: list[str] = []
    for op in manifest.operations:
        if op.status is EndpointStatus.VERIFIED:
            if not op.method:
                problems.append(f"{name}.{op.name}: VERIFIED operation without an HTTP method")
            if not op.source or op.source not in docs:
                problems.append(f"{name}.{op.name}: source {op.source!r} is not listed in docs/integrations.md")
        elif op.source is not None:
            problems.append(f"{name}.{op.name}: only VERIFIED operations cite sources")
    for action in sorted(manifest.supported_actions, key=lambda a: a.value):
        served = any(op.status is EndpointStatus.VERIFIED and op.kind is OperationKind.STATE_CHANGING
                     and action in op.action_types for op in manifest.operations)
        if not served:
            problems.append(f"{name}: supports {action.value} without a VERIFIED state-changing operation")
    return problems


def describe(manifest: CapabilityManifest) -> list[str]:
    """One line per operation: integration, status, kind, method, path."""
    return [f"{manifest.integration:<26} {op.status.value:<10} {op.kind.value:<14} {op.method or '-':<6} "
            f"{op.path or '-'}  ({op.name})" for op in manifest.operations]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="check_endpoints", description=__doc__.split("\n\n")[0])
    parser.add_argument("--integration", choices=list(INTEGRATION_NAMES), help="check one integration")
    parser.add_argument("--list", action="store_true", help="print every operation")
    parser.add_argument("--docs", type=Path, default=DOCS, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    out = out or sys.stdout
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_OK
    try:
        docs = args.docs.read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"check_endpoints: cannot read {args.docs}: {exc}\n")
        return EXIT_USAGE
    problems: list[str] = []
    names = (args.integration,) if args.integration else INTEGRATION_NAMES
    for name in names:
        try:
            manifest = load_adapter_class(name).manifest
        except (ImportError, TypeError, KeyError) as exc:
            problems.append(f"{name}: adapter cannot be loaded: {type(exc).__name__}: {exc}")
            continue
        if args.list:
            out.write("\n".join(describe(manifest)) + "\n")
        problems += check_manifest(manifest, docs)
    for problem in problems:
        out.write(problem + "\n")
    if not problems:
        out.write(f"{len(names)} manifest(s) consistent with {args.docs.name}\n")
    return EXIT_PROBLEMS if problems else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["check_manifest", "describe", "main", "EXIT_OK", "EXIT_PROBLEMS", "EXIT_USAGE"]
