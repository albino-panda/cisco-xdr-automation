"""Execution guard: the central, deterministic safety primitive (architecture sections 5.7 and 13.10).

* A ``ContextVar`` holds the current :class:`AuthorizationContext`; it is only set by
  :func:`authorized` after the registered :class:`TokenVerifier` verified the approval token for
  exactly this action and consumed its single use.
* Every state-changing adapter method is wrapped by :func:`state_changing`, which re-verifies the
  token and checks the binding before the method body runs, even when the method is called directly.
* Dry run is ON by default (fail closed) until :func:`configure` turns it off. :func:`dry_run`
  can only switch it on for a run, never off. While dry run is active every state-changing path
  raises :class:`DryRunViolationError`, even with a valid token.
* One authorization authorizes exactly one guarded call: the first (outermost) ``@state_changing``
  call consumes it and nested guarded calls made by that call (``execute`` dispatching to the
  method named after the action) ride along. The decorated method's name must be the approved
  action type (or ``execute``), so an approval for action A can never drive the write method B.
* An authorization never outlives its ``with`` block: leaving :func:`authorized` closes the
  context, so a copy of the context captured inside the block (``contextvars.copy_context()``, a
  thread pool, an asyncio task) is refused afterwards.
* The verifier slot is sealed by the first registration: afterwards only that identical
  instance (same signing key, same single-use ledger) can be registered again. Another object,
  even of the same class (another key, an empty ledger), is refused. :func:`unregister_verifier`
  and :func:`reset_for_tests` empty the slot but keep the seal, so the guard then fails closed
  for good (every state-changing call is refused) and can never be re-opened for another
  verifier. Only the test harness (:func:`_reset_for_test_harness`, private, never called by
  production code) removes the seal between tests.
* A ``STATE_CHANGING`` HTTP request is accepted only while the authorization's single use is in
  flight: inside the ``@state_changing`` call that consumed it, or as one raw logical request
  (:func:`write_window`) that itself consumes the single use and must carry the approved
  target. The in-flight state lives in the context state shared by every copy of the context,
  so a copy captured during the call loses the authority as soon as the call returns; nothing
  in the ``with authorized(...)`` block can write a second time, or to another target, before
  or after the guarded call.

The guard never imports the approval package: the verifier is injected with
:func:`register_verifier` by the runtime builder.
"""
from __future__ import annotations

import functools
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from xdr_response.clock import Clock, SystemClock
from xdr_response.errors import (
    ActionMethodMismatchError,
    ApprovalRequiredError,
    DryRunViolationError,
    TokenInvalidError,
    TokenMismatchError,
)
from xdr_response.interfaces import TokenVerifier
from xdr_response.models import (
    ActionBinding,
    ActionRequest,
    ApprovalPurpose,
    ApprovalToken,
    TokenActionGrant,
    is_state_changing,
    purpose_for,
)

__all__ = [
    "AuthorizationContext",
    "register_verifier",
    "unregister_verifier",
    "get_verifier",
    "configure",
    "is_dry_run",
    "dry_run",
    "authorized",
    "current",
    "check_token",
    "require_authorization",
    "require_active_authorization",
    "write_window",
    "state_changing",
    "is_state_changing_method",
    "set_denial_hook",
    "reset_for_tests",
    "STATE_CHANGING_ATTR",
]

F = TypeVar("F", bound=Callable[..., Any])
DenialHook = Callable[[str, "ActionRequest | None", Exception], None]

STATE_CHANGING_ATTR = "__xdr_state_changing__"
#: The only decorated method name that may run any approved action type (it dispatches by type).
_DISPATCH_METHOD = "execute"


class _ContextState:
    """Mutable, thread-safe life-cycle flags shared by every copy of one authorization context."""

    __slots__ = ("_lock", "closed", "consumed", "in_flight", "raw")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.closed = False
        self.consumed = False
        #: Guarded calls of this authorization currently running (nested calls ride along).
        self.in_flight = 0
        #: True while the single use is held by one raw (non-decorated) HTTP write, see write_window().
        self.raw = False

    def close(self) -> None:
        with self._lock:
            self.closed = True

    def consume(self) -> bool:
        """Mark the single guarded call as used. False when it was already used or the context closed."""
        with self._lock:
            if self.closed or self.consumed:
                return False
            self.consumed = True
            return True

    def enter_call(self) -> bool:
        """Start a guarded call. The outermost call consumes the single use; nested calls ride along.

        False when the context is closed, or when no call is in flight and the use was consumed.
        """
        with self._lock:
            if self.closed or self.raw:
                return False
            if self.in_flight == 0:
                if self.consumed:
                    return False
                self.consumed = True
            self.in_flight += 1
            return True

    def enter_raw(self) -> bool:
        """Claim the single use for one raw HTTP write made outside any guarded call."""
        with self._lock:
            if self.closed or self.consumed or self.in_flight:
                return False
            self.consumed = True
            self.raw = True
            self.in_flight = 1
            return True

    def exit_call(self) -> None:
        with self._lock:
            self.in_flight = max(0, self.in_flight - 1)
            if self.in_flight == 0:
                self.raw = False

    @property
    def call_running(self) -> bool:
        with self._lock:
            return self.in_flight > 0 and not self.closed


@dataclass(frozen=True)
class AuthorizationContext:
    token: ApprovalToken
    request: ActionRequest
    binding: ActionBinding
    purpose: ApprovalPurpose
    grant: TokenActionGrant
    entered_at: datetime
    # Created by authorized(); a hand-built context gets its own state but still needs a valid token.
    state: _ContextState = field(default_factory=_ContextState, compare=False, repr=False)

    @property
    def closed(self) -> bool:
        return self.state.closed

    @property
    def consumed(self) -> bool:
        return self.state.consumed


_lock = threading.RLock()
_verifier: TokenVerifier | None = None
#: The first verifier ever registered in this process; only this identical object may be registered again.
_sealed_verifier: TokenVerifier | None = None
_global_dry_run: bool = True
_clock: Clock = SystemClock()
_denial_hook: DenialHook | None = None

_ctx: ContextVar[AuthorizationContext | None] = ContextVar("xdr_response_authorization", default=None)
_dry_ctx: ContextVar[bool] = ContextVar("xdr_response_dry_run", default=False)


# ------------------------------------------------------------ configuration --
def register_verifier(verifier: TokenVerifier) -> None:
    """Install the token verifier (done once by the runtime builder).

    The first registration seals the slot: afterwards only that identical instance can be
    registered again (re-registering it is a no-op). Any other object, including another
    instance of the same class with another signing key or an empty single-use ledger, raises
    :class:`ApprovalRequiredError`. Emptying the slot (:func:`unregister_verifier`,
    :func:`reset_for_tests`) keeps the seal, so it fails closed instead of re-opening the slot.
    """
    global _verifier, _sealed_verifier
    if not isinstance(verifier, TokenVerifier):
        raise TypeError("verifier must implement TokenVerifier (verify, mark_used)")
    with _lock:
        sealed = _sealed_verifier
        if sealed is not None and verifier is not sealed:
            raise _deny("verifier replacement refused", None, ApprovalRequiredError(
                f"the approval verifier is sealed (a {type(sealed).__name__} was registered first); "
                f"it cannot be replaced by another {type(verifier).__name__} instance"))
        _sealed_verifier = verifier
        _verifier = verifier


def unregister_verifier() -> None:
    """Empty the verifier slot. The seal stays: the guard fails closed until the sealed verifier returns."""
    global _verifier
    with _lock:
        _verifier = None


def get_verifier() -> TokenVerifier | None:
    return _verifier


def configure(*, dry_run: bool, clock: Clock | None = None) -> None:
    """Set the global dry-run flag (default True until called) and the guard clock."""
    global _global_dry_run, _clock
    if not isinstance(dry_run, bool):
        raise TypeError("dry_run must be a bool")
    with _lock:
        _global_dry_run = dry_run
        if clock is not None:
            _clock = clock


def is_dry_run() -> bool:
    """True when the global flag or the per-run context flag is set."""
    return _global_dry_run or _dry_ctx.get()


@contextmanager
def dry_run() -> Iterator[None]:
    """Enable dry run for the enclosed block. It can never switch dry run off."""
    token = _dry_ctx.set(True)
    try:
        yield
    finally:
        _dry_ctx.reset(token)


def set_denial_hook(hook: DenialHook | None) -> None:
    """Optional callback (for example audit GUARD_DENIED) invoked before every denial is raised."""
    global _denial_hook
    with _lock:
        _denial_hook = hook


def reset_for_tests() -> None:
    """Return to the fail-closed defaults without ever re-opening the verifier slot.

    Empties the verifier slot (the seal stays, so only the originally registered verifier can be
    registered again), clears the denial hook, switches global dry run back on and clears the
    context variables of the calling context. It only tightens: it can never enable a verifier
    swap or switch dry run off.
    """
    global _verifier, _global_dry_run, _clock, _denial_hook
    with _lock:
        _verifier = None
        _global_dry_run = True
        _clock = SystemClock()
        _denial_hook = None
    _ctx.set(None)
    _dry_ctx.set(False)


def _reset_for_test_harness() -> None:
    """Test harness only (tests/conftest.py): full reset including the verifier seal.

    Private and never called by production code: a production process registers its verifier
    once (build_runtime) and keeps the seal for its whole life.
    """
    global _sealed_verifier
    reset_for_tests()
    with _lock:
        _sealed_verifier = None


# ------------------------------------------------------------------ denials --
def _deny(reason: str, request: ActionRequest | None, exc: Exception) -> Exception:
    hook = _denial_hook
    if hook is not None:
        try:
            hook(reason, request, exc)
        except Exception:  # noqa: BLE001 - a failing hook must never turn a denial into an allow
            pass
    return exc


def _verify(verifier: TokenVerifier, token: ApprovalToken, purpose: ApprovalPurpose,
            binding: ActionBinding, request: ActionRequest) -> TokenActionGrant:
    """Call the verifier and re-check its answer (defense in depth). Fails closed on anything odd."""
    try:
        grant = verifier.verify(token, purpose=purpose, binding=binding)
    except ApprovalRequiredError as exc:
        raise _deny(f"token verification failed: {type(exc).__name__}", request, exc) from None
    except Exception as exc:  # noqa: BLE001 - unexpected verifier error: fail closed
        err = TokenInvalidError(f"token verification error: {type(exc).__name__}")
        raise _deny("token verification error", request, err) from exc
    if not isinstance(grant, TokenActionGrant):
        raise _deny("verifier returned no grant", request,
                    TokenInvalidError("verifier returned no grant"))
    if (grant.idempotency_key != binding.idempotency_key or grant.action_type != binding.action_type
            or grant.target != binding.target or grant.params_hash != binding.params_hash):
        raise _deny("grant does not match action", request,
                    TokenMismatchError("grant does not match the action binding"))
    if token.claims.purpose != purpose:
        raise _deny("purpose mismatch", request,
                    TokenMismatchError(f"token purpose {token.claims.purpose.value} does not "
                                       f"authorize a {purpose.value} action"))
    if token.claims.incident_id != binding.incident_id:
        raise _deny("incident mismatch", request, TokenMismatchError("token incident mismatch"))
    return grant


# --------------------------------------------------------------- authorized --
@contextmanager
def authorized(token: ApprovalToken, action: ActionRequest) -> Iterator[AuthorizationContext]:
    """Enter an authorization context for exactly one approved action.

    Order: verifier registered; not dry run; no active context; purpose from the catalog;
    verifier.verify; verifier.mark_used (single use); set the context var; reset on exit.
    """
    if not isinstance(action, ActionRequest):
        raise TypeError("action must be an ActionRequest")
    verifier = _verifier
    if verifier is None:
        raise _deny("no verifier registered", action,
                    ApprovalRequiredError("no approval verifier registered: state-changing actions are refused"))
    if is_dry_run():
        raise _deny("dry run active", action,
                    DryRunViolationError("dry run is active: state-changing actions are refused"))
    if _ctx.get() is not None:
        raise _deny("nested authorization", action, ApprovalRequiredError("nested authorization"))
    if not isinstance(token, ApprovalToken):
        raise _deny("no approval token", action, ApprovalRequiredError("an approval token is required"))
    try:
        purpose = purpose_for(action.action_type)
    except (ValueError, KeyError) as exc:
        raise _deny("action is not state-changing", action, ValueError(str(exc))) from None
    binding = ActionBinding.from_request(action)
    grant = _verify(verifier, token, purpose, binding, action)
    try:
        verifier.mark_used(token, action.idempotency_key)
    except ApprovalRequiredError as exc:
        raise _deny(f"token use rejected: {type(exc).__name__}", action, exc) from None
    except Exception as exc:  # noqa: BLE001 - ledger failure: fail closed
        err = TokenInvalidError(f"token use could not be recorded: {type(exc).__name__}")
        raise _deny("token ledger error", action, err) from exc
    context = AuthorizationContext(
        token=token, request=action, binding=binding, purpose=purpose, grant=grant,
        entered_at=_clock.now(),
    )
    reset_token = _ctx.set(context)
    try:
        yield context
    finally:
        context.state.close()  # copies of this context captured inside the block lose the authority
        _ctx.reset(reset_token)


def current() -> AuthorizationContext | None:
    return _ctx.get()


def check_token(token: ApprovalToken, action: ActionRequest) -> TokenActionGrant:
    """Pre-flight: verify ``token`` for ``action`` with the registered verifier WITHOUT consuming it.

    Used by the execution pipeline before it claims an action, so a forged or foreign token can
    never occupy (poison) the execution slot of the genuinely approved action.
    """
    if not isinstance(action, ActionRequest):
        raise TypeError("action must be an ActionRequest")
    verifier = _verifier
    if verifier is None:
        raise _deny("no verifier registered", action,
                    ApprovalRequiredError("no approval verifier registered: state-changing actions are refused"))
    if not isinstance(token, ApprovalToken):
        raise _deny("no approval token", action, ApprovalRequiredError("an approval token is required"))
    try:
        purpose = purpose_for(action.action_type)
    except (ValueError, KeyError) as exc:
        raise _deny("action is not state-changing", action, ValueError(str(exc))) from None
    return _verify(verifier, token, purpose, ActionBinding.from_request(action), action)


def _active_or_deny(request: ActionRequest | None) -> AuthorizationContext:
    if is_dry_run():
        raise _deny("dry run active", request,
                    DryRunViolationError("dry run is active: state-changing actions are refused"))
    context = _ctx.get()
    if context is None:
        raise _deny("no authorization context", request,
                    ApprovalRequiredError("state-changing call outside an approved authorization context"))
    if context.state.closed:
        raise _deny("authorization context closed", request, ApprovalRequiredError(
            "the authorization context has ended; its authority cannot be reused"))
    return context


def _reverify(context: AuthorizationContext, request: ActionRequest | None) -> None:
    verifier = _verifier
    if verifier is None:
        raise _deny("no verifier registered", request,
                    ApprovalRequiredError("no approval verifier registered"))
    _verify(verifier, context.token, context.purpose, context.binding, request or context.request)


def require_authorization(request: ActionRequest, *, integration: str | None = None) -> AuthorizationContext:
    """Require an active context that authorizes exactly ``request`` (and ``integration``)."""
    if not isinstance(request, ActionRequest):
        raise TypeError("request must be an ActionRequest")
    context = _active_or_deny(request)
    if ActionBinding.from_request(request) != context.binding:
        raise _deny("binding mismatch", request,
                    TokenMismatchError("the call does not match the authorized action"))
    if integration is not None and request.params.get("integration") != integration:
        raise _deny("integration mismatch", request,
                    TokenMismatchError(f"action is approved for integration "
                                       f"{request.params.get('integration')!r}, not {integration!r}"))
    _reverify(context, request)
    return context


def require_active_authorization(integration: str) -> AuthorizationContext:
    """Used by the HTTP client before every STATE_CHANGING request attempt.

    Allowed only inside an open context for ``integration`` and only while the ``@state_changing``
    call that consumed the authorization is running. Before that call (for example in the
    read-only state pre-check), after it returned, and from a copy of the context that outlived
    the call, every write is refused: one approval authorizes the writes of one guarded call.
    """
    context = _active_or_deny(None)
    if context.request.params.get("integration") != integration:
        raise _deny("integration mismatch", context.request,
                    TokenMismatchError(f"authorized action targets integration "
                                       f"{context.request.params.get('integration')!r}, not {integration!r}"))
    if not context.state.call_running:
        raise _deny("write outside the guarded call", context.request, ApprovalRequiredError(
            "state-changing requests are only allowed while the approved @state_changing call runs; "
            "one approval authorizes one write"))
    _reverify(context, context.request)
    return context


@contextmanager
def write_window(integration: str, carries_target: Callable[[ActionRequest], bool],
                 action_types: tuple[Any, ...] = ()) -> Iterator[AuthorizationContext]:
    """Hold the authorization for one logical STATE_CHANGING HTTP request (all its attempts).

    * Inside the running ``@state_changing`` call: allowed (the decorator checked the binding).
    * Outside it (a raw client write in the ``authorized`` block): allowed only once, only when
      the request carries the approved target (``carries_target``) and, when the manifest row
      names action types, only for the approved action type. The raw write consumes the single
      use, so no guarded call and no further write can follow under the same approval.
    """
    context = _active_or_deny(None)
    if context.request.params.get("integration") != integration:
        raise _deny("integration mismatch", context.request,
                    TokenMismatchError(f"authorized action targets integration "
                                       f"{context.request.params.get('integration')!r}, not {integration!r}"))
    if context.state.call_running and not context.state.raw:
        yield context  # every attempt re-verifies through require_active_authorization
        return
    if action_types and context.request.action_type not in action_types:
        raise _deny("write operation does not serve the approved action", context.request,
                    TokenMismatchError(f"this write operation does not serve "
                                       f"{context.request.action_type.value}"))
    try:
        carries = bool(carries_target(context.request))
    except Exception:  # noqa: BLE001 - fail closed
        carries = False
    if not carries:
        raise _deny("write not bound to the approved target", context.request, TokenMismatchError(
            f"a state-changing request outside the guarded call must carry the approved target "
            f"{context.request.target!r}"))
    if not context.state.enter_raw():
        raise _deny("authorization already used", context.request, ApprovalRequiredError(
            "this authorization was already used; one approval authorizes one write"))
    try:
        yield context  # every attempt re-verifies through require_active_authorization
    finally:
        context.state.exit_call()


# ---------------------------------------------------------------- decorator --
def state_changing(fn: F) -> F:
    """Guard an adapter method ``(self, request: ActionRequest, /, *args, **kwargs)``."""

    method_name = getattr(fn, "__name__", "")

    @functools.wraps(fn)
    def wrapper(self: Any, request: Any, /, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(request, ActionRequest):
            raise TypeError(f"{fn.__qualname__} requires an ActionRequest as first argument")
        if not is_state_changing(request.action_type):
            raise ValueError(
                f"{fn.__qualname__} called with non-state-changing action {request.action_type.value}"
            )
        if method_name not in (request.action_type.value, _DISPATCH_METHOD):
            raise _deny("method does not match the approved action", request, ActionMethodMismatchError(
                f"{fn.__qualname__} cannot run under an approval for {request.action_type.value}"))
        context = require_authorization(request, integration=getattr(self, "name", None))
        if not context.state.enter_call():
            raise _deny("authorization already used", request, ApprovalRequiredError(
                "this authorization was already used for a state-changing call; "
                "one approval authorizes one write"))
        try:
            return fn(self, request, *args, **kwargs)
        finally:
            context.state.exit_call()

    setattr(wrapper, STATE_CHANGING_ATTR, True)
    return wrapper  # type: ignore[return-value]


def is_state_changing_method(obj: object) -> bool:
    return getattr(obj, STATE_CHANGING_ATTR, False) is True

