"""Runtime composition (architecture section 13.19): one place that wires every component.

:func:`build_runtime` connects config, secrets, the audit sink, the adapter registry, the approval
token service and engine, the package builder, the control registry, the execution, verification and
restoration engines, the dry-run simulator, the state machine and the orchestrator. It also installs
the deterministic safety wiring in the process-wide execution guard:

* ``guard.register_verifier(tokens)``: every ``@state_changing`` adapter call re-verifies its
  approval token with the HMAC token service (no verifier registered means every call is refused).
  The first registration seals the guard's verifier slot;
* ``guard.configure(dry_run=settings.runtime.dry_run)`` (dry run is the default);
* ``guard.set_denial_hook(...)``: every guard refusal is written to the audit trail
  (``GUARD_DENIED``).

The guard is process-global and its verifier slot is sealed by the first registration, so one
process runs one runtime: a second ``build_runtime`` in the same process is refused
(``ApprovalRequiredError``) instead of replacing the verifier.

Only the :class:`ApprovalEngine` holds the token service's one-time issuing capability. The
executor, the restoration engine and the state machine receive a verify-only
:class:`~xdr_response.approval.tokens.TokenVerifierView`; they can check tokens but never mint one.

:func:`bootstrap` is the entry point for a deployment: it loads ``config/`` (``DRY_RUN`` from the
environment wins), reads secrets from the environment or mounted files, and opens the durable JSONL
audit trail, control registry and token ledger at the configured paths.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from xdr_response import guard
from xdr_response.approval import (
    ApprovalEngine,
    ApprovalTokenService,
    CriticalAssetPolicy,
    InMemoryTokenUseLedger,
    JsonlTokenUseLedger,
    PackageBuilder,
)
from xdr_response.audit import AuditTrail
from xdr_response.audit.events import AuditRecorder
from xdr_response.audit.keys import AUDIT_CHAIN_KEY_NAME
from xdr_response.clock import Clock, SystemClock
from xdr_response.config import Settings, load_settings
from xdr_response.config.policy import AllowlistPolicy
from xdr_response.dryrun import DryRunSimulator
from xdr_response.execution import ActionRunner, ContainmentExecutor
from xdr_response.execution.state_store import ExecutionStateStore
from xdr_response.integrations.health import HealthMonitor
from xdr_response.integrations.registry import AdapterRegistry
from xdr_response.interfaces import (
    ApproverAuthenticator,
    AuditSink,
    ControlRegistry,
    IncidentStore,
    PackageStore,
    SecretProvider,
    TokenUseLedger,
)
from xdr_response.lifecycle.investigation import InvestigationService
from xdr_response.lifecycle.machine import IncidentStateMachine
from xdr_response.lifecycle.recommendation import Recommender, RuleBasedRecommender
from xdr_response.models import ActionPackage
from xdr_response.restoration.planner import control_provenance
from xdr_response.lifecycle.store import InMemoryIncidentStore, InMemoryPackageStore
from xdr_response.restoration import (
    JsonlControlRegistry,
    RestorationEngine,
    RestorationPlanner,
    control_from_result,
)
from xdr_response.secrets import default_secret_provider
from xdr_response.verification import VerificationEngine

if TYPE_CHECKING:  # pragma: no cover
    from xdr_response.lifecycle.observers import LifecycleObserver
    from xdr_response.lifecycle.orchestrator import ResponseOrchestrator
    from xdr_response.workflows.discovery import WorkflowCatalog

#: Default notification outbox of :func:`bootstrap` (env ``XDR_RESPONSE_NOTIFICATIONS_PATH`` wins).
DEFAULT_NOTIFICATIONS_PATH = Path("var/notifications/outbox.jsonl")
NOTIFICATIONS_PATH_ENV = "XDR_RESPONSE_NOTIFICATIONS_PATH"

__all__ = ["Runtime", "build_runtime", "bootstrap", "in_memory_runtime"]


@dataclass
class Runtime:
    """Every wired component of one process (contract fields first, then additions)."""

    settings: Settings
    clock: Clock
    secrets: SecretProvider
    audit: AuditSink
    adapters: AdapterRegistry
    tokens: ApprovalTokenService
    approval: ApprovalEngine
    packages: PackageBuilder
    registry: ControlRegistry
    executor: ContainmentExecutor
    restoration: RestorationEngine
    planner: RestorationPlanner
    simulator: DryRunSimulator
    machine: IncidentStateMachine
    orchestrator: "ResponseOrchestrator"
    # additions (section 13.22)
    verification: VerificationEngine
    runner: ActionRunner
    investigator: InvestigationService
    recommender: Recommender
    health: HealthMonitor
    incident_store: IncidentStore
    package_store: PackageStore
    recorder: AuditRecorder
    # Phase 1 additions (section 14.3.6)
    workflows: "WorkflowCatalog | None" = None
    observers: "tuple[LifecycleObserver, ...]" = ()

    @property
    def dry_run(self) -> bool:
        """True while the process-wide guard refuses every state-changing call."""
        return guard.is_dry_run()

    def close(self) -> None:
        """Close adapter HTTP clients. Never touches the registry or the audit trail."""
        self.adapters.close()


def build_runtime(settings: Settings, secrets: SecretProvider, *, authenticator: ApproverAuthenticator,
                  clock: Clock | None = None, audit: AuditSink | None = None,
                  registry: ControlRegistry | None = None, ledger: TokenUseLedger | None = None,
                  transport_factory: Callable[[str], httpx.BaseTransport | None] | None = None,
                  incident_store: IncidentStore | None = None,
                  package_store: PackageStore | None = None,
                  sleep: Callable[[float], None] | None = None,
                  execution_state_store: ExecutionStateStore | None = None,
                  recommender: Recommender | None = None,
                  investigator: InvestigationService | None = None,
                  id_factory: Callable[[], str] | None = None,
                  max_concurrency: int = 1,
                  integration_concurrency: Mapping[str, int] | None = None,
                  workflows: "WorkflowCatalog | None" = None,
                  observers: "Sequence[LifecycleObserver]" = ()) -> Runtime:
    """Wire every component and install the guard verifier, dry-run flag and denial hook.

    Defaults: durable JSONL audit trail, control registry and token ledger at the
    ``settings.runtime`` paths; in-memory incident and package stores; the rule-based recommender.

    With a workflow catalog (section 14.3.6) the investigator is a ``WorkflowInvestigator``
    (read-only ``WorkflowRunner`` with the Phase 0 ``InvestigationService`` as fallback) and the
    recommender a ``WorkflowRecommender`` (fallback ``RuleBasedRecommender``); explicit
    ``investigator=`` / ``recommender=`` arguments still win. Without a catalog everything behaves
    exactly as in Phase 0. ``observers`` receive lifecycle events (bookkeeping only).
    """
    from xdr_response.lifecycle.orchestrator import ResponseOrchestrator

    if not isinstance(settings, Settings):
        raise TypeError("settings must be a Settings instance")
    clock = clock or SystemClock()
    audit = audit if audit is not None else AuditTrail(
        settings.runtime.audit_path, clock=clock, chain_key=secrets.get_optional(AUDIT_CHAIN_KEY_NAME))
    registry = registry if registry is not None else JsonlControlRegistry(settings.runtime.registry_path,
                                                                         clock=clock)
    ledger = ledger if ledger is not None else JsonlTokenUseLedger(settings.runtime.token_ledger_path,
                                                                   clock=clock)
    incident_store = incident_store if incident_store is not None else InMemoryIncidentStore()
    package_store = package_store if package_store is not None else InMemoryPackageStore()
    recorder = AuditRecorder(audit)

    adapters = AdapterRegistry(settings, secrets, clock=clock, audit=audit,
                               transport_factory=transport_factory, sleep=sleep)
    approval_settings = settings.thresholds.approval
    tokens = ApprovalTokenService(secrets, approval_settings, ledger=ledger, clock=clock, id_factory=id_factory)
    packages = PackageBuilder(settings, critical_assets=CriticalAssetPolicy(settings.critical_assets),
                              allowlists=AllowlistPolicy(settings.allowlists, exclusions=settings.exclusions),
                              clock=clock, id_factory=id_factory)

    def level_policy(package: ActionPackage) -> list[str]:
        try:
            incident = incident_store.get(package.incident_id)
        except KeyError:
            incident = None
        return packages.policy_violations(package, incident)  # type: ignore[arg-type]

    # The engine binds the token service's one-time issuing capability: nothing else can mint tokens.
    approval = ApprovalEngine(approval_settings, authenticator=authenticator, tokens=tokens, audit=audit,
                              clock=clock, id_factory=id_factory, level_policy=level_policy)
    #: Verify-only facade for automation components (they can check tokens, never issue or revoke).
    verify_only = tokens.view()
    verification = VerificationEngine(adapters, settings.thresholds.verification, clock=clock, sleep=sleep)
    runner = ActionRunner(adapters, verification, registry=registry, audit=audit, clock=clock,
                          state_store=execution_state_store,
                          review_after_hours=settings.thresholds.temporary_controls.review_after_hours,
                          control_factory=control_from_result)
    simulator = DryRunSimulator(audit=audit, clock=clock, id_factory=id_factory)
    executor = ContainmentExecutor(runner, verify_only, settings, audit=audit, simulator=simulator, clock=clock,
                                   max_concurrency=max_concurrency,
                                   integration_concurrency=integration_concurrency, id_factory=id_factory)
    critical_assets = CriticalAssetPolicy(settings.critical_assets)
    provenance = control_provenance(verify_only, runner.state_store)
    restoration = RestorationEngine(runner, registry, verify_only, settings, audit=audit, simulator=simulator,
                                    clock=clock, id_factory=id_factory, critical_assets=critical_assets,
                                    executions=runner.state_store, provenance=provenance,
                                    incidents=incident_store)
    planner = RestorationPlanner(registry, settings, clock=clock, id_factory=id_factory,
                                 critical_assets=critical_assets, executions=runner.state_store,
                                 provenance=provenance)
    machine = IncidentStateMachine(incident_store, audit, clock, tokens=verify_only)
    if investigator is None:
        investigator = InvestigationService(adapters, audit=audit, clock=clock)
        if workflows is not None:
            investigator = _workflow_investigator(workflows, investigator, adapters, settings, audit, clock)
    if recommender is None:
        recommender = RuleBasedRecommender(adapters)
        if workflows is not None:
            from xdr_response.lifecycle.workflow_adapter import WorkflowRecommender

            recommender = WorkflowRecommender(recommender)
    health = HealthMonitor(adapters, audit=audit)

    # ---- deterministic safety wiring of the process-wide execution guard ----
    # The verifier slot is sealed by the first registration: one runtime per process. A second
    # build_runtime in the same process is refused here, before it can touch the dry-run flag.
    guard.register_verifier(tokens)
    guard.configure(dry_run=settings.runtime.dry_run, clock=clock)
    guard.set_denial_hook(recorder.guard_denial_hook())

    runtime = Runtime(
        settings=settings, clock=clock, secrets=secrets, audit=audit, adapters=adapters, tokens=tokens,
        approval=approval, packages=packages, registry=registry, executor=executor,
        restoration=restoration, planner=planner, simulator=simulator, machine=machine,
        orchestrator=None,  # type: ignore[arg-type] - set right below
        verification=verification, runner=runner, investigator=investigator, recommender=recommender,
        health=health, incident_store=incident_store, package_store=package_store, recorder=recorder,
        workflows=workflows, observers=_observers(observers),
    )
    runtime.orchestrator = ResponseOrchestrator(runtime, incidents=incident_store, packages=package_store)
    return runtime


def bootstrap(config_dir: Path | str = "config", *, authenticator: ApproverAuthenticator,
              env: Mapping[str, str] | None = None, secrets: SecretProvider | None = None,
              clock: Clock | None = None,
              transport_factory: Callable[[str], httpx.BaseTransport | None] | None = None,
              workflows: bool = True, notifications_path: Path | str | None = None) -> Runtime:
    """Load configuration and secrets and build a durable runtime (deployment entry point).

    ``DRY_RUN`` in ``env`` (default: the process environment) overrides ``runtime.dry_run``.
    Secrets come from the environment, then from ``XDR_RESPONSE_SECRETS_DIR`` mounted files.
    ``workflows=True`` discovers the workflow catalog (a broken workflow fails loudly). The
    notification outbox is ``notifications_path``, else ``XDR_RESPONSE_NOTIFICATIONS_PATH``, else
    ``var/notifications/outbox.jsonl`` (rendered text only; nothing is posted to a vendor).
    """
    from xdr_response.atomics.notifications.service import NotificationService
    from xdr_response.atomics.notifications.sinks import JsonlNotificationSink
    from xdr_response.workflows.discovery import discover_workflows

    environment = os.environ if env is None else env
    settings = load_settings(config_dir, env=env)
    provider = secrets if secrets is not None else default_secret_provider(env)
    outbox = notifications_path or environment.get(NOTIFICATIONS_PATH_ENV) or DEFAULT_NOTIFICATIONS_PATH
    notifications = NotificationService([JsonlNotificationSink(outbox, clock=clock)], clock=clock)
    return build_runtime(settings, provider, authenticator=authenticator, clock=clock,
                         transport_factory=transport_factory,
                         workflows=discover_workflows() if workflows else None, observers=(notifications,))


def _workflow_investigator(catalog: "WorkflowCatalog", fallback: InvestigationService, adapters: AdapterRegistry,
                           settings: Settings, audit: AuditSink, clock: Clock) -> InvestigationService:
    """``WorkflowInvestigator`` over a read-only facade (its dry-run check matches the orchestrator's)."""
    from xdr_response.atomics.context import ReadOnlyAdapters
    from xdr_response.lifecycle.workflow_adapter import WorkflowInvestigator
    from xdr_response.workflows.runner import WorkflowRunner

    runner = WorkflowRunner(ReadOnlyAdapters(adapters), settings, clock=clock)
    investigator = WorkflowInvestigator(catalog, runner, fallback, audit=audit,
                                        dry_run=lambda: guard.is_dry_run() or bool(settings.runtime.dry_run))
    return investigator  # type: ignore[return-value] - same run() contract as InvestigationService


def _observers(observers: "Sequence[LifecycleObserver]") -> "tuple[LifecycleObserver, ...]":
    from xdr_response.lifecycle.observers import LifecycleObserver

    out = tuple(observers)
    for observer in out:
        if not isinstance(observer, LifecycleObserver):
            raise TypeError(f"observer {type(observer).__name__} has no on_event(event) method")
    return out


def in_memory_runtime(settings: Settings, secrets: SecretProvider, *, authenticator: ApproverAuthenticator,
                      clock: Clock | None = None, **kwargs: object) -> Runtime:
    """A runtime with in-memory audit, registry and ledger (tests, lab and the simulator)."""
    from xdr_response.audit import MemoryAuditTrail
    from xdr_response.restoration import InMemoryControlRegistry

    clock = clock or SystemClock()
    audit = kwargs.pop("audit", None)
    registry = kwargs.pop("registry", None)
    ledger = kwargs.pop("ledger", None)
    return build_runtime(settings, secrets, authenticator=authenticator, clock=clock,
                         audit=audit if audit is not None else MemoryAuditTrail(clock=clock),  # type: ignore[arg-type]
                         registry=registry if registry is not None else InMemoryControlRegistry(clock=clock),  # type: ignore[arg-type]
                         ledger=ledger if ledger is not None else InMemoryTokenUseLedger(),  # type: ignore[arg-type]
                         **kwargs)  # type: ignore[arg-type]
