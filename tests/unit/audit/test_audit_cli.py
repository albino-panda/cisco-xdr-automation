"""tools/validation/verify_audit_chain.py: reports the first broken record, exit codes 0/1/2."""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "tools" / "validation" / "verify_audit_chain.py"


def _load_cli():
    spec = importlib.util.spec_from_file_location("verify_audit_chain_under_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load_cli()


def _run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = cli.main(list(argv), out=out)
    return code, out.getvalue()


@pytest.fixture
def chain(make_trail, fill, audit_path) -> Path:
    fill(make_trail(), 5)
    return audit_path


def test_intact_chain_exits_zero(chain):
    code, out = _run(str(chain))
    assert code == cli.EXIT_OK
    assert out.startswith("OK:") and "5 records" in out


def test_broken_chain_reports_first_bad_record(chain):
    lines = chain.read_bytes().splitlines(keepends=True)
    lines[3] = lines[3].replace(b'"index":3', b'"index":8')
    chain.write_bytes(b"".join(lines))
    code, out = _run(str(chain))
    assert code == cli.EXIT_BROKEN
    assert "BROKEN" in out and "seq 3 (line 4)" in out and "3 records verified" in out


def test_json_output(chain):
    code, out = _run(str(chain), "--json")
    data = json.loads(out)
    assert code == 0 and data["ok"] is True and data["records"] == 5


def test_anchor_detects_truncation(chain):
    lines = chain.read_bytes().splitlines(keepends=True)
    head = json.loads(lines[-1])["hash"]
    chain.write_bytes(b"".join(lines[:3]))
    assert _run(str(chain))[0] == cli.EXIT_OK
    code, out = _run(str(chain), "--anchor", f"4:{head}")
    assert code == cli.EXIT_BROKEN and "truncated" in out


def test_anchor_file(chain, tmp_path, make_trail):
    anchor = make_trail().anchor()
    anchor_file = tmp_path / "anchors.json"
    anchor_file.write_text(json.dumps([anchor.model_dump()]), encoding="utf-8")
    assert _run(str(chain), "--anchor-file", str(anchor_file))[0] == cli.EXIT_OK
    anchor_file.write_text(json.dumps({"seq": anchor.seq, "hash": "0" * 64}), encoding="utf-8")
    assert _run(str(chain), "--anchor-file", str(anchor_file))[0] == cli.EXIT_BROKEN


@pytest.mark.parametrize("argv", [["--anchor", "bad"], ["--anchor", "1:xyz"]])
def test_invalid_anchor_is_usage_error(chain, argv):
    code, out = _run(str(chain), *argv)
    assert code == cli.EXIT_USAGE and "invalid anchor" in out


def test_missing_anchor_file_is_usage_error(chain, tmp_path):
    code, _ = _run(str(chain), "--anchor-file", str(tmp_path / "none.json"))
    assert code == cli.EXIT_USAGE


def test_missing_audit_file_is_usage_error(tmp_path):
    code, out = _run(str(tmp_path / "missing.jsonl"))
    assert code == cli.EXIT_USAGE and "not found" in out


def test_cli_never_modifies_the_file(chain):
    before = chain.read_bytes()
    _run(str(chain))
    _run(str(chain), "--json")
    assert chain.read_bytes() == before


def test_script_runs_standalone(chain):
    proc = subprocess.run([sys.executable, str(SCRIPT), str(chain)], capture_output=True, text=True,
                          cwd=str(REPO_ROOT), timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("OK:")
