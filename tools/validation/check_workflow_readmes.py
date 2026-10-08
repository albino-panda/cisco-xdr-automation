#!/usr/bin/env python3
"""Check the README of every discovered workflow against its definition (architecture 14.5.4).

Usage:
    python tools/validation/check_workflow_readmes.py
    python tools/validation/check_workflow_readmes.py --workflow ransomware

For every workflow found by ``discover_workflows()`` (legacy READMEs of unmigrated workflows are not
checked) ``workflows/<X>/README.md`` must:

* start with ``# <WORKFLOW.name>`` and have exactly the 17 ``##`` headings of 14.5.4, in order, each
  with at least one non-empty line (``###`` sub-headings are free);
* name exactly the definition's integrations (backticked) under "Required integrations" and
  "Optional integrations";
* name every tactic, technique and sub-technique id of the definition, and no other ATT&CK id,
  under "MITRE mapping";
* state under "Approval requirements" that every action needs human approval and when ELEVATED
  applies;
* name ``tests/fixtures/workflows/<X>/`` and ``tests/workflows/<x_snake>/`` under "Testing
  instructions";
* list at least as many bullets under "Known limitations" as the definition has;
* contain no ``auto_approve``, no ``unlock_code``, no secret-like literal and no IP address outside
  the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32);

and the workflow's scenarios must meet the minimum set (``check_coverage``, 14.5.3).

Exit codes: 0 all good, 1 problems (one line per problem), 2 usage error. Read-only.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

_ROOT = Path(__file__).resolve().parents[2]
for _path in (_ROOT / "src", _ROOT):  # run from a checkout without install
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from tools.simulator.workflow_scenario import (  # noqa: E402
    WORKFLOW_SCENARIO_DIR,
    check_coverage,
    load_workflow_scenario,
)
from xdr_response.logs.redaction import Redactor  # noqa: E402
from xdr_response.models import INTEGRATION_NAMES  # noqa: E402
from xdr_response.workflows.definition import WorkflowDefinition  # noqa: E402
from xdr_response.workflows.discovery import (  # noqa: E402
    DEFAULT_PACKAGE,
    DiscoveredWorkflow,
    WorkflowDiscoveryError,
    discover_workflows,
)

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2

README_ROOT = _ROOT / "workflows"

#: The 17 ``##`` headings of 14.5.4, in order.
SECTIONS: tuple[str, ...] = (
    "Purpose", "Trigger", "Required integrations", "Optional integrations", "Input data",
    "Investigation steps", "Correlation logic", "Risk calculation", "Containment recommendations",
    "Approval requirements", "Containment execution", "Verification", "Rollback", "Failure handling",
    "MITRE mapping", "Testing instructions", "Known limitations",
)

_ATTACK_ID = re.compile(r"\b(TA\d{4}|T\d{4}(?:\.\d{3})?)\b")
_BACKTICKED = re.compile(r"`([^`\n]+)`")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}|(?:[0-9A-Fa-f]{1,4}:)+:[0-9A-Fa-f:]*)"
                   r"(?:/\d{1,3})?(?![\w:])")
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
_DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in
                      ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_FORBIDDEN_WORDS = ("auto_approve", "unlock_code")
_REDACTOR = Redactor()


# ------------------------------------------------------------------ parsing --
def split_sections(text: str) -> tuple[str | None, list[tuple[str, list[str]]]]:
    """``(H1 title, [(H2 heading, body lines)])``; text before the first H2 is ignored."""
    title: str | None = None
    sections: list[tuple[str, list[str]]] = []
    in_code = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
        if not in_code and line.startswith("# ") and title is None and not sections:
            title = line[2:].strip()
        elif not in_code and line.startswith("## "):
            sections.append((line[3:].strip(), []))
        elif sections:
            sections[-1][1].append(line)
    return title, sections


def _body(lines: Sequence[str]) -> str:
    return "\n".join(lines)


def _has_content(lines: Sequence[str]) -> bool:
    return any(line.strip() and not line.lstrip().startswith("#") for line in lines)


# ------------------------------------------------------------------- checks --
def _check_structure(definition: WorkflowDefinition, title: str | None,
                     sections: list[tuple[str, list[str]]]) -> list[str]:
    problems: list[str] = []
    if title != definition.name:
        problems.append(f"H1 is {title!r}, expected {definition.name!r}")
    headings = [h for h, _ in sections]
    if headings != list(SECTIONS):
        problems.append(f"## headings {headings} != the 17 required headings {list(SECTIONS)} (exact order)")
    for heading, lines in sections:
        if not _has_content(lines):
            problems.append(f"section {heading!r} is empty")
    return problems


def _integrations_in(lines: Sequence[str]) -> set[str]:
    return {m for m in _BACKTICKED.findall(_body(lines)) if m in INTEGRATION_NAMES}


def _check_integrations(definition: WorkflowDefinition, by_name: dict[str, list[str]]) -> list[str]:
    problems: list[str] = []
    for heading, requirements in (("Required integrations", definition.required_integrations),
                                  ("Optional integrations", definition.optional_integrations)):
        wanted = {r.integration for r in requirements}
        named = _integrations_in(by_name.get(heading, []))
        if named != wanted:
            problems.append(f"{heading!r} names {sorted(named)}, the definition has {sorted(wanted)} (backticked)")
    return problems


def _check_mitre(definition: WorkflowDefinition, by_name: dict[str, list[str]]) -> list[str]:
    wanted = {m.tactic for m in definition.mitre} | set(definition.attack_ids())
    named = set(_ATTACK_ID.findall(_body(by_name.get("MITRE mapping", []))))
    problems = []
    if wanted - named:
        problems.append(f"'MITRE mapping' does not name {sorted(wanted - named)}")
    if named - wanted:
        problems.append(f"'MITRE mapping' names ATT&CK ids not in the definition: {sorted(named - wanted)}")
    return problems


def _check_approval(by_name: dict[str, list[str]]) -> list[str]:
    text = _body(by_name.get("Approval requirements", []))
    problems = []
    if "human approval" not in text.lower():
        problems.append("'Approval requirements' must state that every action needs human approval")
    if "ELEVATED" not in text:
        problems.append("'Approval requirements' must state when ELEVATED approval applies")
    return problems


def _check_testing(definition: WorkflowDefinition, by_name: dict[str, list[str]]) -> list[str]:
    text = _body(by_name.get("Testing instructions", []))
    return [f"'Testing instructions' must name {path}" for path in
            (f"tests/fixtures/workflows/{definition.id}/", f"tests/workflows/{definition.package_name}/")
            if path not in text]


def _check_limitations(definition: WorkflowDefinition, by_name: dict[str, list[str]]) -> list[str]:
    bullets = sum(1 for line in by_name.get("Known limitations", []) if _BULLET.match(line))
    if bullets < len(definition.known_limitations):
        return [f"'Known limitations' has {bullets} bullet(s), the definition has {len(definition.known_limitations)}"]
    return []


def _is_documentation_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True  # not an address (version numbers and the like)
    return any(address in network for network in _DOC_NETWORKS)


def check_text_hygiene(text: str) -> list[str]:
    """Forbidden words, secret-like literals and non-documentation IP addresses."""
    problems = [f"must not contain {word!r}" for word in _FORBIDDEN_WORDS if word in text.lower()]
    for number, line in enumerate(text.splitlines(), start=1):
        if _REDACTOR.redact_text(line) != line:
            problems.append(f"line {number}: secret-like literal")
        for match in (*_IPV4.findall(line), *_IPV6.findall(line)):
            if not _is_documentation_ip(match):
                problems.append(f"line {number}: IP address {match} is outside the documentation ranges")
    return problems


def check_readme(definition: WorkflowDefinition, text: str) -> list[str]:
    """Problems of one README text against its definition (empty list: valid)."""
    title, sections = split_sections(text)
    by_name: dict[str, list[str]] = {}
    for heading, lines in sections:
        by_name.setdefault(heading, lines)
    problems = _check_structure(definition, title, sections)
    problems += _check_integrations(definition, by_name)
    problems += _check_mitre(definition, by_name)
    problems += _check_approval(by_name)
    problems += _check_testing(definition, by_name)
    problems += _check_limitations(definition, by_name)
    problems += check_text_hygiene(text)
    return problems


def check_workflow(workflow: DiscoveredWorkflow, *, readme_root: Path = README_ROOT,
                   scenario_root: Path = WORKFLOW_SCENARIO_DIR) -> list[str]:
    """README and scenario-coverage problems of one discovered workflow, prefixed with its id."""
    definition = workflow.definition
    readme = readme_root / definition.id / "README.md"
    if not readme.is_file():
        problems = [f"{readme.as_posix()} is missing"]
    else:
        problems = check_readme(definition, readme.read_text(encoding="utf-8"))
    problems += _coverage(definition, scenario_root)
    return [f"{definition.id}: {p}" for p in problems]


def _coverage(definition: WorkflowDefinition, scenario_root: Path) -> list[str]:
    directory = scenario_root / definition.id
    scenarios = []
    problems: list[str] = []
    for path in sorted(directory.glob("*.yaml")) if directory.is_dir() else ():
        try:
            scenarios.append(load_workflow_scenario(path))
        except (ValueError, OSError) as exc:
            problems.append(f"scenario {path.name}: {exc}")
    return problems + [p.removeprefix(f"{definition.id}: ") for p in
                       check_coverage(definition.id, scenarios, definition)]


# ---------------------------------------------------------------------- CLI --
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="check_workflow_readmes", description=__doc__.split("\n\n")[0])
    parser.add_argument("--workflow", help="check only this workflow id")
    parser.add_argument("--package", default=DEFAULT_PACKAGE, help=argparse.SUPPRESS)
    parser.add_argument("--readme-root", type=Path, default=README_ROOT, help=argparse.SUPPRESS)
    parser.add_argument("--scenario-root", type=Path, default=WORKFLOW_SCENARIO_DIR, help=argparse.SUPPRESS)
    return parser


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    out = out or sys.stdout
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_OK
    try:
        catalog = discover_workflows(args.package)
    except WorkflowDiscoveryError as exc:
        out.write(f"discovery: {exc}\n")
        return EXIT_PROBLEMS
    ids = catalog.ids()
    if args.workflow is not None and args.workflow not in ids:
        sys.stderr.write(f"check_workflow_readmes: unknown workflow {args.workflow!r} (known: {list(ids)})\n")
        return EXIT_USAGE
    problems: list[str] = []
    for workflow_id in ids if args.workflow is None else (args.workflow,):
        problems += check_workflow(catalog.get(workflow_id), readme_root=args.readme_root,
                                   scenario_root=args.scenario_root)
    for problem in problems:
        out.write(problem + "\n")
    if not problems:
        out.write(f"{len(ids) if args.workflow is None else 1} workflow README(s) OK\n")
    return EXIT_PROBLEMS if problems else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["SECTIONS", "check_readme", "check_text_hygiene", "check_workflow", "main", "split_sections",
           "EXIT_OK", "EXIT_PROBLEMS", "EXIT_USAGE"]
