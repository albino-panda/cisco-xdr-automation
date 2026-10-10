#!/usr/bin/env python3
"""Forward a verified xdr_response audit trail to Splunk HEC (architecture 14.14.4).

Usage:
    python tools/deployment/forward_audit.py var/audit/audit.jsonl --checkpoint var/audit/splunk.checkpoint
    python tools/deployment/forward_audit.py var/audit/audit.jsonl --checkpoint cp.json --config-dir config --limit 500

Run it from a scheduler next to the runtime, never inside the response path. It verifies the whole
hash chain first and forwards nothing when the chain is broken; then it sends every record after the
checkpoint, in order, through ``SplunkAdapter.forward_audit`` (``POST {hec_url}/services/collector/event``,
VERIFIED in docs/integrations.md, a bookkeeping write that redacts each event again) and stops at the
first failure. The checkpoint file holds the last forwarded ``seq``; the next run resumes after it.

Splunk must be enabled in ``config/integrations.yaml`` with ``options.hec_url``; the HEC token comes
from the secret provider (environment or ``XDR_RESPONSE_SECRETS_DIR``), never from the command line.
The audit file is only read.

Exit codes: 0 everything after the checkpoint was forwarded, 1 the run stopped early (broken chain,
collector failure, Splunk disabled, limit reached), 2 usage or configuration error.
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

_ROOT = Path(__file__).resolve().parents[2]
for _path in (_ROOT / "src", _ROOT):  # run from a checkout without install
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from xdr_response.audit.forwarding import forward_audit_file, read_checkpoint, write_checkpoint  # noqa: E402

EXIT_OK = 0
EXIT_STOPPED = 1
EXIT_USAGE = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forward_audit", description=__doc__.split("\n\n")[0])
    parser.add_argument("path", type=Path, help="audit JSONL file (read only)")
    parser.add_argument("--checkpoint", type=Path, required=True, help="checkpoint file (last forwarded seq)")
    parser.add_argument("--config-dir", type=Path, default=Path("config"), help="configuration directory")
    parser.add_argument("--limit", type=int, default=None, help="at most this many records in one run")
    return parser


def splunk_sender(config_dir: Path) -> Callable[[Mapping[str, Any]], bool]:
    """``SplunkAdapter.forward_audit`` of the configured Splunk integration."""
    from xdr_response.config.loader import load_settings
    from xdr_response.integrations.registry import load_adapter_class
    from xdr_response.secrets.provider import default_secret_provider

    settings = load_settings(config_dir)
    adapter = load_adapter_class("splunk")(settings.integrations["splunk"], default_secret_provider())
    return adapter.forward_audit


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None,
         sender: Callable[[Mapping[str, Any]], bool] | None = None) -> int:
    """CLI entry point; ``sender`` replaces the configured Splunk adapter (tests)."""
    stream = out or sys.stdout
    args = _parser().parse_args(argv)
    if not args.path.is_file():
        print(f"ERROR: audit file not found: {args.path}", file=stream)
        return EXIT_USAGE
    try:
        after = read_checkpoint(args.checkpoint)
        send = sender or splunk_sender(args.config_dir)
    except Exception as exc:  # noqa: BLE001 - configuration problems are reported, never a traceback
        print(f"ERROR: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}", file=stream)
        return EXIT_USAGE
    result = forward_audit_file(args.path, send, after_seq=after, limit=args.limit)
    if result.last_seq != after:
        write_checkpoint(args.checkpoint, result.last_seq)
    print(f"forwarded {result.sent} record(s); checkpoint seq {result.last_seq}"
          + (f"; stopped: {result.stopped}" if result.stopped else ""), file=stream)
    return EXIT_OK if not result.stopped else EXIT_STOPPED


if __name__ == "__main__":
    raise SystemExit(main())
