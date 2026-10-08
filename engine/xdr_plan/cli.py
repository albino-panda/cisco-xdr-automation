"""Command line: check workflows and show the plan a scenario produces.

    python -m xdr_plan check [workflow ...]     # repository checks + validate spec + run scenarios (all when none given)
    python -m xdr_plan plan <workflow> <scenario.yaml>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import repo
from .planner import PlanError, build_plan
from .validate import check_repository, check_workflow, load_scenario


def _report(name: str, errors: list[str]) -> bool:
    """Print one PASS/FAIL block; return True when it failed."""
    print(f"[{'PASS' if not errors else 'FAIL'}] {name}")
    for err in errors:
        print(f"    - {err}")
    return bool(errors)


def cmd_check(ids: list[str]) -> int:
    """Run the repository-wide lifecycle checks, then every requested workflow."""
    failed = _report("repository (atomics, guardrails)", check_repository())
    for wid in ids or repo.workflow_ids():
        failed = _report(wid, check_workflow(wid)) or failed
    return 1 if failed else 0


def cmd_plan(wid: str, scenario: str) -> int:
    """Print the plan one scenario produces (recommendation only; nothing is executed)."""
    s = load_scenario(Path(scenario))
    try:
        plan = build_plan(wid, s.get("incident") or {}, s.get("results") or {}, repo.load_guardrails(s.get("guardrails")))
    except (PlanError, ValueError) as exc:
        print(f"plan error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(plan.as_dict(), indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="xdr_plan")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_check = sub.add_parser("check", help="validate workflows and run their scenarios")
    p_check.add_argument("workflows", nargs="*")
    p_plan = sub.add_parser("plan", help="print the plan for one scenario")
    p_plan.add_argument("workflow")
    p_plan.add_argument("scenario")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args.workflows)
    return cmd_plan(args.workflow, args.scenario)


if __name__ == "__main__":
    raise SystemExit(main())
