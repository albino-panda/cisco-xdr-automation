"""Global dry-run switch: resolve ``DRY_RUN`` from config and environment, and lock the guard.

Resolution (first match wins, fail safe):

1. ``force=True`` (a per-run request): dry run. A per-run request can only switch dry run ON.
2. The ``DRY_RUN`` environment variable, exactly ``true`` or ``false`` (case-insensitive);
   any other value is a :class:`~xdr_response.errors.ConfigError`.
3. ``settings.runtime.dry_run`` (the example config ships ``dry_run: true``).
4. No settings at all: dry run (the guard default).

:func:`dry_run_scope` also *locks* the guard for its duration: it sets the global flag and enters
:func:`xdr_response.guard.dry_run`, whose per-run flag cannot be cleared by a later
``guard.configure(dry_run=False)``. Inside the scope every state-changing path raises
:class:`~xdr_response.errors.DryRunViolationError`, even with a valid approval token.
"""
from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from xdr_response import guard
from xdr_response.clock import Clock
from xdr_response.config.loader import parse_bool
from xdr_response.config.schema import Settings

__all__ = ["DRY_RUN_ENV_VAR", "resolve_dry_run", "apply_global_dry_run", "dry_run_scope", "is_dry_run"]

DRY_RUN_ENV_VAR = "DRY_RUN"


def resolve_dry_run(settings: Settings | None = None, *, env: Mapping[str, str] | None = None,
                    force: bool = False) -> bool:
    """Return the effective dry-run flag (see the module docstring for the precedence)."""
    if force:
        return True
    environ = os.environ if env is None else env
    raw = environ.get(DRY_RUN_ENV_VAR)
    if raw is not None:
        return parse_bool(DRY_RUN_ENV_VAR, raw)
    if settings is None:
        return True
    return bool(settings.runtime.dry_run)


def apply_global_dry_run(settings: Settings | None = None, *, env: Mapping[str, str] | None = None,
                         force: bool = False, clock: Clock | None = None) -> bool:
    """Resolve the flag and set the guard's global dry-run switch to it. Returns the flag."""
    effective = resolve_dry_run(settings, env=env, force=force)
    guard.configure(dry_run=effective, clock=clock)
    return effective


@contextmanager
def dry_run_scope(settings: Settings | None = None, *, env: Mapping[str, str] | None = None,
                  force: bool = False) -> Iterator[bool]:
    """Resolve the flag; when it is on, lock the guard in dry run for the enclosed block.

    Yields the effective flag. When the resolved flag is off the guard is left unchanged (this
    scope never switches dry run off; only the runtime builder does that from settings).
    """
    if not resolve_dry_run(settings, env=env, force=force):
        yield guard.is_dry_run()
        return
    guard.configure(dry_run=True)
    with guard.dry_run():
        yield True


def is_dry_run() -> bool:
    """True when the guard is in dry run (global switch or an active per-run scope)."""
    return guard.is_dry_run()
