#!/usr/bin/env python3
"""Validate the configuration directory (architecture 13.2, 13.11) without starting anything.

Usage:
    python tools/validation/validate_config.py
    python tools/validation/validate_config.py --config-dir config --use-env

Loads every file of ``config/`` with the production loader (``extra="forbid"`` everywhere, approval
bypass keys such as ``auto_approve`` refused at any depth, secrets by NAME only) and prints a short
summary: dry-run flag, environment, enabled integrations, critical-asset classes, allow-list sizes
and scoring bands. Environment overrides (``DRY_RUN`` ...) apply only with ``--use-env``.

Exit codes: 0 valid, 1 invalid (the loader's message is printed), 2 usage error. Read-only: it never
reads a secret value, opens a network connection or writes a file.
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

from xdr_response.config import Settings, load_settings  # noqa: E402
from xdr_response.errors import ConfigError  # noqa: E402

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2


def summarize(settings: Settings) -> list[str]:
    """Human-readable summary lines of a loaded configuration (no secret values exist in it)."""
    enabled = [name for name, cfg in settings.integrations.items() if cfg.enabled]
    never_block = {k: len(v) for k, v in sorted(settings.allowlists.never_block.items())}
    return [
        f"runtime: dry_run={settings.runtime.dry_run} environment={settings.runtime.environment}",
        f"integrations enabled: {', '.join(enabled) or 'none'}",
        f"critical-asset classes: {', '.join(c.value for c in settings.critical_assets.classes) or 'none'}",
        f"never_block entries: {never_block or 'none'}",
        f"scoring bands: {settings.thresholds.scoring.bands}",
        f"blast radius caps: {settings.thresholds.blast_radius.model_dump()}",
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="validate_config", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config-dir", type=Path, default=_ROOT / "config", help="configuration directory")
    parser.add_argument("--use-env", action="store_true", help="apply DRY_RUN and XDR_RESPONSE_* overrides")
    return parser


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    out = out or sys.stdout
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_OK
    try:
        settings = load_settings(args.config_dir, env=None if args.use_env else {})
    except ConfigError as exc:
        out.write(f"INVALID: {exc}\n")
        return EXIT_INVALID
    out.write(f"{args.config_dir.as_posix()}: valid\n")
    for line in summarize(settings):
        out.write(f"  {line}\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main", "summarize", "EXIT_OK", "EXIT_INVALID", "EXIT_USAGE"]
