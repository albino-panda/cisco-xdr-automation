#!/usr/bin/env python3
"""Run a fixture incident end to end against the simulated adapter environment.

Usage:
    python tools/simulator/simulate.py --list
    python tools/simulator/simulate.py ransomware                 # dry run (default)
    python tools/simulator/simulate.py ransomware --live          # simulated-live execution
    python tools/simulator/simulate.py phishing --live --decision APPROVE_ALL --approver analyst
    python tools/simulator/simulate.py tests/fixtures/incidents/account_takeover.yaml --live --check

What it prints, in order: the analyst decision card, the containment result (the ``DRY RUN`` block
in dry-run mode), the release package checklist and the restoration result (simulated-live only),
and the audit-chain verification.

Nothing leaves the process: adapters are :mod:`xdr_response.integrations.simulated` (no HTTP),
the audit trail, control registry and token ledger are in memory, and lab approvers get random
credentials per run. ``--live`` still goes through the real approval engine (HMAC tokens for
HUMAN principals only) and the execution guard; it only changes the in-memory simulated vendor
state. ``--audit-out`` writes the hash-chained audit records as JSONL for inspection with
``tools/validation/verify_audit_chain.py``.

Exit codes: 0 completed (and expectations met with ``--check``), 1 expectations not met,
2 usage error.
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

_ROOT = Path(__file__).resolve().parents[2]
for _path in (_ROOT / "src", _ROOT):  # run from a checkout without install
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from tools.simulator.scenario import LAB_PRINCIPALS, ScenarioRun, list_scenarios, load_scenario  # noqa: E402
from xdr_response.audit.hashing import encode_record_line  # noqa: E402
from xdr_response.dryrun import render_dry_run  # noqa: E402
from xdr_response.errors import RegistryError, XdrResponseError  # noqa: E402
from xdr_response.models import DecisionType  # noqa: E402
from xdr_response.reporting import (  # noqa: E402
    render_containment_report,
    render_decision_card,
    render_release_checklist,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="simulate", description=__doc__.split("\n\n")[0])
    parser.add_argument("scenario", nargs="?", help="scenario name (tests/fixtures/incidents) or YAML path")
    parser.add_argument("--list", action="store_true", help="list bundled scenarios and exit")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="simulated-live execution (default: dry run)")
    mode.add_argument("--dry-run", action="store_true", help="dry run (default)")
    parser.add_argument("--decision", choices=[d.value for d in DecisionType],
                        help="override the scenario's analyst decision")
    parser.add_argument("--approver", action="append", choices=sorted(LAB_PRINCIPALS),
                        help="approver alias; repeatable (default: the scenario's approvers)")
    parser.add_argument("--no-release", action="store_true", help="stop after containment")
    parser.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    parser.add_argument("--check", action="store_true", help="compare the run with the scenario's expect block")
    parser.add_argument("--audit-out", type=Path, default=None, help="write the audit records as JSONL")
    return parser


def _section(out: TextIO, title: str, body: str) -> None:
    out.write(f"\n=== {title} ===\n{body.rstrip()}\n")


def _check(run: ScenarioRun) -> list[str]:
    """Differences between the run and ``scenario.expect`` (empty list: all met)."""
    expect = run.scenario.expect
    problems: list[str] = []
    package = run.detection.package if run.detection else None
    if package is None:
        return ["no containment package was proposed"]
    if "actions" in expect:
        wanted = set(run.keys(package, expect["actions"]))
        if wanted != set(package.keys):
            problems.append(f"package actions {sorted(package.keys)} != expected {sorted(wanted)}")
    if "elevated" in expect:
        elevated = {a.idempotency_key for a in package.actions if a.approval_level.value == "ELEVATED"}
        wanted = set(run.keys(package, expect["elevated"]))
        if elevated != wanted:
            problems.append(f"elevated {sorted(elevated)} != expected {sorted(wanted)}")
    if run.live and run.decision is not None and "containment" in expect:
        overall = run.decision.report.overall.value if run.decision.report and run.decision.report.overall else None
        if overall != expect["containment"]:
            problems.append(f"containment {overall} != expected {expect['containment']}")
    if run.live and "controls" in expect:
        count = len(run.runtime.registry.list(incident_id=run.incident_id))
        if count != int(expect["controls"]):
            problems.append(f"{count} temporary controls != expected {expect['controls']}")
    if run.live and run.release_result is not None and "restoration" in expect:
        report = run.release_result.report
        overall = report.overall.value if report is not None and report.overall is not None else None
        if overall != expect["restoration"]:
            problems.append(f"restoration {overall} != expected {expect['restoration']}")
    return problems


def run_cli(args: argparse.Namespace, out: TextIO) -> int:
    scenario = load_scenario(args.scenario)
    run = ScenarioRun(scenario, live=bool(args.live))
    fmt = args.format
    mode = "SIMULATED LIVE" if run.live else "DRY RUN"
    out.write(f"Scenario {scenario.name} ({mode}): {scenario.description.strip()}\n")

    detection = run.detect()
    for note in detection.notes:
        out.write(f"note: {note}\n")
    if detection.package is None:
        out.write("No containment package proposed: nothing met the recommendation rules.\n")
        return EXIT_OK
    _section(out, "Analyst decision card",
             render_decision_card(detection.package, incident_title=scenario.incident.title, fmt=fmt))

    spec = dict(scenario.analyst)
    if args.decision:
        spec["decision"] = args.decision
    decision = run.decide(spec, approvers=args.approver)
    out.write(f"\nDecision {decision.outcome.decision.decision.value} by "
              f"{decision.outcome.decision.analyst_identity}; incident now {decision.incident.state.value}\n")
    if decision.report is not None:
        title = "Containment result (dry run)" if decision.report.dry_run else "Containment result"
        body = render_dry_run(decision.report) if decision.report.dry_run and fmt == "text" else \
            render_containment_report(decision.report, fmt=fmt)
        _section(out, title, body)

    if run.live and not args.no_release and decision.report is not None:
        try:
            release = run.propose_release()
        except RegistryError as exc:
            _section(out, "Release package", f"No release package: {exc}")
        else:
            _section(out, "Release package", render_release_checklist(release, incident_title=scenario.incident.title,
                                                                      fmt=fmt))
            result = run.decide_release(approvers=args.approver)
            out.write(f"\nRelease {result.outcome.decision.decision.value}; incident now "
                      f"{result.incident.state.value}\n")
            if result.report is not None:
                _section(out, "Restoration result", render_containment_report(result.report, fmt=fmt))
    elif not run.live:
        _section(out, "Release package",
                 "None: a dry run creates no temporary controls, so there is nothing to release.")

    verification = run.runtime.audit.verify()  # type: ignore[attr-defined]
    _section(out, "Audit trail", f"{verification.records} records, chain {'intact' if verification.ok else 'BROKEN'}"
                                 f", head {verification.head_hash[:16]}")
    if run.live:
        calls = run.environment.state_changing_calls()
        out.write(f"Simulated vendor state changes: {len(calls)}\n")
    else:
        out.write("Simulated vendor state changes: 0 (dry run)\n")
    if args.audit_out is not None:
        args.audit_out.parent.mkdir(parents=True, exist_ok=True)
        with args.audit_out.open("wb") as handle:
            for record in run.runtime.audit.records():
                handle.write(encode_record_line(record))  # the canonical stored line encoding
        out.write(f"Audit records written to {args.audit_out}\n")
    if args.check:
        problems = _check(run)
        for problem in problems:
            out.write(f"EXPECTATION FAILED: {problem}\n")
        if problems:
            return EXIT_FAILED
        out.write("All scenario expectations met.\n")
    return EXIT_OK


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    out = out or sys.stdout
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_OK
    if args.list:
        out.write("\n".join(list_scenarios()) + "\n")
        return EXIT_OK
    if not args.scenario:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    try:
        return run_cli(args, out)
    except (FileNotFoundError, ValueError, KeyError) as exc:
        sys.stderr.write(f"simulate: {type(exc).__name__}: {exc}\n")
        return EXIT_USAGE
    except XdrResponseError as exc:
        sys.stderr.write(f"simulate: refused: {type(exc).__name__}: {exc}\n")
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main", "run_cli", "EXIT_OK", "EXIT_FAILED", "EXIT_USAGE"]
