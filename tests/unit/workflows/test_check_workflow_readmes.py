"""tools/validation/check_workflow_readmes.py (architecture 14.5.4)."""
from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest

from tests.fixtures.sample_workflows import SAMPLE_PACKAGE, SAMPLE_SCENARIO_DIR
from tests.fixtures.sample_workflows.sample_malware.definition import WORKFLOW
from tools.validation import check_workflow_readmes as checker

README_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "sample_workflows" / "readmes"
README = (README_ROOT / "sample-malware" / "README.md").read_text(encoding="utf-8")


def _cli(*args: str, readme_root: Path = README_ROOT, scenario_root: Path = SAMPLE_SCENARIO_DIR) -> tuple[int, str]:
    out = io.StringIO()
    code = checker.main(["--package", SAMPLE_PACKAGE, "--readme-root", str(readme_root),
                         "--scenario-root", str(scenario_root), *args], out=out)
    return code, out.getvalue()


def test_the_sample_readme_passes():
    assert checker.check_readme(WORKFLOW, README) == []
    assert _cli() == (checker.EXIT_OK, "1 workflow README(s) OK\n")
    assert _cli("--workflow", "sample-malware")[0] == checker.EXIT_OK


def test_an_unknown_workflow_is_a_usage_error():
    assert _cli("--workflow", "ransomware")[0] == checker.EXIT_USAGE


def test_the_production_catalog_check_runs():
    assert checker.main([], out=io.StringIO()) in (checker.EXIT_OK, checker.EXIT_PROBLEMS)


def test_the_17_headings_in_order():
    assert len(checker.SECTIONS) == 17
    swapped = README.replace("## Purpose", "## TEMP").replace("## Trigger", "## Purpose").replace("## TEMP",
                                                                                                    "## Trigger")
    assert any("exact order" in p for p in checker.check_readme(WORKFLOW, swapped))
    missing = README.replace("## Rollback\n", "")
    assert any("exact order" in p for p in checker.check_readme(WORKFLOW, missing))


def test_h1_and_empty_sections():
    assert "H1 is 'Other', expected 'Sample endpoint malware'" in checker.check_readme(
        WORKFLOW, README.replace("# Sample endpoint malware", "# Other", 1))
    empty = README.replace("Every executed action is verified automatically by reading the target state back.",
                           "### Notes")
    assert "section 'Verification' is empty" in checker.check_readme(WORKFLOW, empty)


def test_integrations_must_match_the_definition():
    problems = checker.check_readme(WORKFLOW, README.replace("- `virustotal`:", "- `alienvault_otx`:"))
    assert any("'Optional integrations' names ['alienvault_otx']" in p for p in problems)
    problems = checker.check_readme(WORKFLOW, README.replace("- `secure_endpoint`:", "- secure_endpoint:"))
    assert any("'Required integrations' names []" in p for p in problems)


def test_mitre_ids_must_match_exactly():
    problems = checker.check_readme(WORKFLOW, README.replace("T1204.002 Malicious File", "Malicious File"))
    assert any("does not name ['T1204.002']" in p for p in problems)
    problems = checker.check_readme(WORKFLOW, README.replace("| TA0002 Execution |", "| TA0002 Execution, T1486 |"))
    assert any("not in the definition: ['T1486']" in p for p in problems)


def test_approval_testing_and_limitations_sections():
    problems = checker.check_readme(WORKFLOW, README.replace("needs human approval", "is reviewed"))
    assert any("needs human approval" in p for p in problems)
    problems = checker.check_readme(WORKFLOW, README.replace("ELEVATED approval (a lead", "Extra approval (a lead"))
    assert any("ELEVATED" in p for p in problems)
    problems = checker.check_readme(WORKFLOW, README.replace("`tests/workflows/sample_malware/`", "the unit tests"))
    assert "'Testing instructions' must name tests/workflows/sample_malware/" in problems
    problems = checker.check_readme(WORKFLOW, README.replace("- Only Secure Endpoint", "Only Secure Endpoint"))
    assert any("'Known limitations' has 1 bullet(s)" in p for p in problems)


@pytest.mark.parametrize("line, match", [
    ("Set auto_approve for low risk.", "'auto_approve'"),
    ("Paste the unlock_code here.", "'unlock_code'"),
    ("Use api_key=abcd1234efgh5678 for the lab.", "secret-like literal"),
    ("Authorization: Bearer abcdefghijklmnop", "secret-like literal"),
    ("The C2 server is 10.20.30.40.", "IP address 10.20.30.40"),
    ("Blocks 8.8.8.8/32 too.", "IP address 8.8.8.8"),
])
def test_hygiene_rules(line, match):
    problems = checker.check_text_hygiene(line)
    assert any(match in p for p in problems), problems


def test_documentation_addresses_and_versions_are_fine():
    text = "Lab hosts 192.0.2.10, 198.51.100.7, 203.0.113.9/32 and 2001:db8::1; version 1.0.0; at 12:30:00."
    assert checker.check_text_hygiene(text) == []


def test_a_missing_readme_and_coverage_gaps_are_reported(tmp_path):
    code, out = _cli(readme_root=tmp_path)
    assert code == checker.EXIT_PROBLEMS and "sample-malware/README.md is missing" in out
    scenarios = tmp_path / "scenarios"
    shutil.copytree(SAMPLE_SCENARIO_DIR, scenarios)
    (scenarios / "sample-malware" / "tp-reject.yaml").unlink()
    code, out = _cli(scenario_root=scenarios)
    assert code == checker.EXIT_PROBLEMS and "sample-malware: missing scenario tp-reject.yaml" in out
    (scenarios / "sample-malware" / "broken.yaml").write_text("schema: 1\nname: other\n", encoding="utf-8")
    code, out = _cli(scenario_root=scenarios)
    assert "sample-malware: scenario broken.yaml:" in out
