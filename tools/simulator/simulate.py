#!/usr/bin/env python3
"""Run a fixture incident end to end against the simulated adapter environment.

Usage:
    python tools/simulator/simulate.py --list
    python tools/simulator/simulate.py ransomware                 # dry run (default)
    python tools/simulator/simulate.py ransomware --live          # simulated-live execution
    python tools/simulator/simulate.py phishing --live --decision APPROVE_ALL --approver analyst
    python tools/simulator/simulate.py tests/fixtures/incidents/account_takeover.yaml --live --check
    python tools/simulator/simulate.py --list-workflows
    python tools/simulator/simulate.py --workflow ransomware --scenario tp-approve-all --live --check
    python tools/simulator/simulate.py --legacy web-attacks                   # every legacy scenario
    python tools/simulator/simulate.py --legacy web-attacks 01-confirmed-web-shell --check

Workflow scenarios (``tests/fixtures/workflows/<workflow id>/*.yaml``, architecture 14.5.2) run
through the workflow framework: the incident is routed to its workflow, investigated with typed
records served by the simulated adapters, and recommended; the analyst decision and the release
are played from the scenario. Without ``--scenario`` every scenario of the workflow runs. With
``--check`` the scenario's ``expect`` block and the implicit safety assertions (14.5.3) are checked.

Legacy scenarios (``workflows/<id>/scenarios/*.yaml``, architecture 14.3.8) replay in dry run only:
the legacy plan is built, bridged to proposals (``plan_bridge``) and run through the runtime up to
the package and its DRY RUN block; ``--check`` compares with the scenario's ``expect`` block.

The execution guard allows one runtime per process (its verifier slot is sealed), so when several
scenarios are selected each one runs in its own child process.

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
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

_ROOT = Path(__file__).resolve().parents[2]
for _path in (_ROOT / "engine", _ROOT / "src", _ROOT):  # run from a checkout without install
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from tools.simulator.scenario import LAB_PRINCIPALS, ScenarioRun, list_scenarios, load_scenario  # noqa: E402
from tools.simulator.workflow_scenario import (  # noqa: E402
    WORKFLOW_SCENARIO_DIR,
    WorkflowScenarioRun,
    discover_workflow_scenarios,
    load_workflow_scenario,
)
from xdr_response.workflows.discovery import DEFAULT_PACKAGE, WorkflowCatalog, discover_workflows  # noqa: E402
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
    parser.add_argument("--list-workflows", action="store_true", help="list workflows and their scenarios")
    parser.add_argument("--workflow", help="run the scenarios of this workflow (tests/fixtures/workflows/<id>)")
    parser.add_argument("--scenario", dest="workflow_scenario", help="with --workflow: one scenario name")
    parser.add_argument("--legacy", metavar="WORKFLOW",
                        help="replay legacy scenarios of workflows/<WORKFLOW> in dry run (positional: one scenario)")
    parser.add_argument("--package", default=DEFAULT_PACKAGE, help=argparse.SUPPRESS)
    parser.add_argument("--scenario-root", type=Path, default=WORKFLOW_SCENARIO_DIR, help=argparse.SUPPRESS)
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


def _list_workflows(catalog: WorkflowCatalog, root: Path, out: TextIO) -> int:
    scenarios = discover_workflow_scenarios(root, catalog=catalog)
    if not catalog.ids():
        out.write("No workflows discovered yet.\n")
    for workflow_id in catalog.ids():
        names = ", ".join(p.stem for p in scenarios.get(workflow_id, [])) or "(no scenarios)"
        out.write(f"{workflow_id} {catalog.get(workflow_id).definition.version}: {names}\n")
    return EXIT_OK


def _workflow_paths(args: argparse.Namespace, catalog: WorkflowCatalog) -> list[Path]:
    if args.workflow not in catalog.ids():
        raise KeyError(f"unknown workflow {args.workflow!r} (known: {list(catalog.ids())})")
    paths = discover_workflow_scenarios(args.scenario_root, catalog=catalog).get(args.workflow, [])
    if args.workflow_scenario:
        paths = [p for p in paths if p.stem == args.workflow_scenario]
        if not paths:
            raise FileNotFoundError(f"no scenario {args.workflow_scenario!r} for workflow {args.workflow}")
    return paths


def _print_workflow_run(run: WorkflowScenarioRun, out: TextIO, fmt: str) -> None:
    detection = run.detection
    assert detection is not None
    workflow_run = run.workflow_run
    if workflow_run is not None:
        out.write(f"workflow {workflow_run.workflow.id} {workflow_run.workflow.version}: risk "
                  f"{workflow_run.risk_score}, confidence {workflow_run.confidence_score}\n")
        for outcome in workflow_run.outcomes:
            out.write(f"rule {outcome.rule_id}: {outcome.status.value} {outcome.selector}\n")
    for note in detection.notes:
        out.write(f"note: {note}\n")
    if detection.package is None:
        out.write("No containment package proposed.\n")
        return
    _section(out, "Analyst decision card",
             render_decision_card(detection.package, incident_title=run.scenario.incident.title, fmt=fmt))
    if detection.dry_run_report is not None and fmt == "text":
        _section(out, "Containment preview (dry run)", render_dry_run(detection.dry_run_report))
    if run.decision is not None:
        out.write(f"\nDecision {run.decision.outcome.decision.decision.value}; incident now "
                  f"{run.decision.incident.state.value}\n")
        if run.decision.report is not None and not run.decision.report.dry_run:
            _section(out, "Containment result", render_containment_report(run.decision.report, fmt=fmt))
    if run.release_result is not None and run.release_result.report is not None:
        _section(out, "Restoration result", render_containment_report(run.release_result.report, fmt=fmt))


def run_workflow_cli(args: argparse.Namespace, out: TextIO) -> int:
    """Run workflow scenarios (dry run unless ``--live``); ``--check`` asserts expectations."""
    catalog = discover_workflows(args.package)
    paths = _workflow_paths(args, catalog)
    if len(paths) > 1:
        return _run_isolated([_workflow_argv(args, path.stem) for path in paths], out)
    failed = False
    for path in paths:
        scenario = load_workflow_scenario(path)
        if bool(args.live) not in scenario.modes():
            out.write(f"Scenario {scenario.name}: skipped (mode {scenario.mode})\n")
            continue
        run = WorkflowScenarioRun(scenario, live=bool(args.live), catalog=catalog).play()
        mode = "SIMULATED LIVE" if args.live else "DRY RUN"
        out.write(f"\nScenario {args.workflow}/{scenario.name} ({mode}): {scenario.description.strip()}\n")
        _print_workflow_run(run, out, args.format)
        changes = len(run.environment.state_changing_calls())
        out.write(f"Simulated vendor state changes: {changes}\n")
        if args.check:
            problems = run.check() + run.implicit_problems()
            for problem in problems:
                out.write(f"EXPECTATION FAILED: {problem}\n")
            failed = failed or bool(problems)
            if not problems:
                out.write("All scenario expectations met.\n")
    return EXIT_FAILED if failed else EXIT_OK


def _workflow_argv(args: argparse.Namespace, scenario: str) -> list[str]:
    argv = ["--workflow", args.workflow, "--scenario", scenario, "--format", args.format,
            "--package", args.package, "--scenario-root", str(args.scenario_root)]
    return argv + (["--live"] if args.live else []) + (["--check"] if args.check else [])


def _run_isolated(argvs: Sequence[Sequence[str]], out: TextIO) -> int:
    """Run each argument list in its own child process (one runtime per process, see the guard)."""
    worst = EXIT_OK
    for argv in argvs:
        done = subprocess.run([sys.executable, str(Path(__file__).resolve()), *argv], capture_output=True,
                              text=True, encoding="utf-8", cwd=str(_ROOT), check=False)
        out.write(done.stdout)
        if done.stderr:
            sys.stderr.write(done.stderr)
        worst = max(worst, done.returncode)
    return worst


def run_legacy_cli(args: argparse.Namespace, out: TextIO) -> int:
    """Replay legacy scenarios in dry run (``--legacy <workflow> [<scenario>]``)."""
    from tools.simulator.legacy_replay import replay_legacy_scenario
    from xdr_plan import repo

    if args.legacy not in repo.workflow_ids():
        raise KeyError(f"unknown legacy workflow {args.legacy!r} (known: {repo.workflow_ids()})")
    paths = repo.scenario_paths(args.legacy)
    if args.scenario:
        paths = [p for p in paths if args.scenario in (p.stem, p.name)]
        if not paths:
            raise FileNotFoundError(f"no legacy scenario {args.scenario!r} for workflow {args.legacy}")
    if len(paths) > 1:
        return _run_isolated([["--legacy", args.legacy, p.stem, "--format", args.format]
                              + (["--check"] if args.check else []) for p in paths], out)
    replay = replay_legacy_scenario(args.legacy, paths[0])
    out.write(f"\nLegacy scenario {args.legacy}/{paths[0].stem} (DRY RUN replay): "
              f"{replay.run.scenario.description.strip()}\n")
    for action in replay.bridge.actions:
        level = "elevated" if action.elevated else "standard"
        out.write(f"legacy rule {action.rule}: {action.legacy_atomic} {action.legacy_target} {action.status} "
                  f"({level}) -> {action.action_type.value} {action.target}"
                  + (f" [{action.note}]" if action.note else "") + "\n")
    for note in replay.detection.notes:
        out.write(f"note: {note}\n")
    package = replay.package
    if package is None:
        out.write("No containment package proposed.\n")
    else:
        _section(out, "Analyst decision card",
                 render_decision_card(package, incident_title=replay.run.scenario.incident.title, fmt=args.format))
        if args.format == "text":
            _section(out, "Containment preview (dry run)", replay.dry_run_text())
    out.write(f"Simulated vendor state changes: {len(replay.run.environment.state_changing_calls())}\n")
    if args.check:
        for problem in replay.mismatches:
            out.write(f"EXPECTATION FAILED: {problem}\n")
        if replay.mismatches:
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
    if not args.scenario and not args.workflow and not args.list_workflows and not args.legacy:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    try:
        if args.list_workflows:
            return _list_workflows(discover_workflows(args.package), args.scenario_root, out)
        if args.legacy:
            return run_legacy_cli(args, out)
        if args.workflow:
            return run_workflow_cli(args, out)
        return run_cli(args, out)
    except (FileNotFoundError, ValueError, KeyError) as exc:
        sys.stderr.write(f"simulate: {type(exc).__name__}: {exc}\n")
        return EXIT_USAGE
    except XdrResponseError as exc:
        sys.stderr.write(f"simulate: refused: {type(exc).__name__}: {exc}\n")
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main", "run_cli", "run_workflow_cli", "run_legacy_cli", "EXIT_OK", "EXIT_FAILED", "EXIT_USAGE"]
