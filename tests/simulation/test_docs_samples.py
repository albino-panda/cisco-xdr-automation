"""docs/samples/*.md show real simulator output: each output block matches a fresh simulator run.

A sample marks its output block with ``<!-- simulate: <simulate.py arguments> -->`` on the line
above a fenced ``text`` block. The simulator is deterministic (fixed clock, fixed ids), so the block
must equal the run's stdout. Each run is a child process: the execution guard allows one runtime per
process.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "docs" / "samples"
SIMULATE = ROOT / "tools" / "simulator" / "simulate.py"
BLOCK = re.compile(r"<!-- simulate: (?P<args>[^\n]+?) -->\n```text\n(?P<body>.*?)\n```", re.DOTALL)


def _blocks() -> list[tuple[str, str, str]]:
    found = []
    for md in sorted(SAMPLES.glob("*.md")):
        for m in BLOCK.finditer(md.read_text(encoding="utf-8")):
            found.append((md.name, m.group("args"), m.group("body")))
    return found


def test_three_samples_with_output_blocks():
    names = {name for name, _, _ in _blocks()}
    assert len(names) >= 3, names


def test_samples_cover_release_parity_degraded_source_and_more_investigation():
    """The sample set shows a restoration table, the production outcome of the simulated adapters (they
    do only what the real ones support and verify: UNROUTED and UNABLE_TO_VERIFY results, architecture
    14.14.3), the owner rule on a degraded source and a REQUEST_MORE_INVESTIGATION decision. No sample
    shows a lab-only capability: there is none."""
    blocks = {name: (args, body) for name, args, body in _blocks()}
    bodies = "\n".join(body for _, body in blocks.values())
    assert "=== Restoration result ===" in bodies
    assert "UNROUTED" in bodies and "UNABLE_TO_VERIFY" in bodies
    assert "degraded source" in bodies
    assert "REQUEST_MORE_INVESTIGATION" in bodies
    for name, (args, body) in blocks.items():
        assert "Lab-only capability" not in body, name
        assert "via secure_endpoint  verification VERIFIED" not in body, (
            f"{name}: the real Secure Endpoint adapter cannot read anything back")


@pytest.mark.parametrize(("sample", "args", "body"), [pytest.param(*b, id=b[0]) for b in _blocks()])
def test_sample_matches_the_simulator(sample: str, args: str, body: str):
    argv = shlex.split(args)
    assert "--workflow" in argv and "--scenario" in argv, f"{sample}: a sample names one workflow scenario"
    proc = subprocess.run([sys.executable, str(SIMULATE), *argv], capture_output=True, text=True, encoding="utf-8",
                          cwd=str(ROOT), timeout=300)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert proc.stdout.strip("\n") == body, (
        f"{sample} is out of date: run `python tools/simulator/simulate.py {args}` and paste its output")
