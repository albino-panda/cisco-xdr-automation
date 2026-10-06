#!/usr/bin/env python3
"""Verify the hash chain of an xdr_response audit trail (JSONL).

Usage:
    python tools/validation/verify_audit_chain.py var/audit/audit.jsonl
    python tools/validation/verify_audit_chain.py audit.jsonl --anchor 41:<64 hex> --json
    python tools/validation/verify_audit_chain.py audit.jsonl --anchor-file anchors.json

Anchors are ``(seq, hash)`` checkpoints exported to an external system (``AuditTrail.anchor()``).
Without an anchor the verifier detects edited, deleted, inserted and reordered records and a
partially written last line; with one it also detects truncation of the tail and a fully rewritten
chain.

Exit codes: 0 chain intact, 1 chain broken (the first broken record is reported), 2 usage error or
unreadable input. The tool only reads files; it never modifies the audit trail.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

_REPO_SRC = Path(__file__).resolve().parents[2] / "src"
if _REPO_SRC.is_dir() and str(_REPO_SRC) not in sys.path:  # run from a checkout without install
    sys.path.insert(0, str(_REPO_SRC))

from xdr_response.audit.verify import AuditAnchor, verify_chain  # noqa: E402
from xdr_response.models.audit import ChainVerification  # noqa: E402

EXIT_OK = 0
EXIT_BROKEN = 1
EXIT_USAGE = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_audit_chain",
        description="Verify the SHA-256 hash chain of an xdr_response JSONL audit trail.")
    parser.add_argument("path", type=Path, help="audit JSONL file")
    parser.add_argument("--anchor", action="append", default=[], metavar="SEQ:HASH",
                        help="externally recorded checkpoint; repeatable")
    parser.add_argument("--anchor-file", type=Path, default=None,
                        help='JSON file with {"seq": n, "hash": "..."} or a list of them')
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    return parser


def load_anchors(texts: Sequence[str], anchor_file: Path | None) -> list[AuditAnchor]:
    """Parse ``--anchor`` values and an optional anchor file. ``ValueError`` on bad input."""
    anchors = [AuditAnchor.parse(text) for text in texts]
    if anchor_file is not None:
        try:
            data = json.loads(anchor_file.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"cannot read anchor file: {type(exc).__name__}") from None
        items = data if isinstance(data, list) else [data]
        anchors.extend(AuditAnchor.model_validate(item) for item in items)
    return anchors


def render(result: ChainVerification, path: Path) -> str:
    """Human-readable one-line verdict."""
    if result.ok:
        return f"OK: {path} - {result.records} records, head {result.head_hash}"
    where = f"seq {result.first_bad_seq}" if result.first_bad_seq is not None else "file"
    line = f" (line {result.first_bad_seq + 1})" if result.first_bad_seq is not None else ""
    return (f"BROKEN: {path} - first bad record at {where}{line}: {result.reason}; "
            f"{result.records} records verified before it, last good hash {result.head_hash}")


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """CLI entry point; returns the exit code."""
    stream = out or sys.stdout
    args = _parser().parse_args(argv)
    try:
        anchors = load_anchors(args.anchor, args.anchor_file)
    except ValueError as exc:
        print(f"ERROR: invalid anchor: {str(exc).splitlines()[0]}", file=stream)
        return EXIT_USAGE
    if not args.path.is_file():
        print(f"ERROR: audit file not found: {args.path}", file=stream)
        return EXIT_USAGE
    result = verify_chain(args.path, anchors=anchors)
    if args.json:
        print(result.model_dump_json(), file=stream)
    else:
        print(render(result, args.path), file=stream)
    return EXIT_OK if result.ok else EXIT_BROKEN


if __name__ == "__main__":
    raise SystemExit(main())
