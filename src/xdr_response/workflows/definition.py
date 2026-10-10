"""Declarative workflow definition (architecture 14.3.1; layer 0 model module).

A workflow is a validated :class:`WorkflowDefinition` (plus optional pure hooks) in its own package
under ``xdr_response.workflows``. A definition only describes what to investigate and which
containment to *recommend*; it carries no vendor code, no approval switch and no execution path.
Every validator runs at import time and raises ``ValueError`` (pydantic ``ValidationError``):

* unique step and rule ids; required and optional integrations disjoint and known; step
  ``integrations`` within them;
* every expression parses with :func:`xdr_response.workflows.expr.parse` (syntax and function
  whitelist);
* a rule's ``action`` is a CONTAINMENT or REMEDIATION catalog type and its ``builder`` (when given)
  builds exactly that type; rule ``params`` never use a reserved or secret-like key;
* rule ``mitre`` ids appear in the definition's ``mitre`` mappings;
* no key in :data:`APPROVAL_LIKE_KEYS` anywhere in the definition (walk of ``model_dump``), so a
  workflow cannot carry an approval switch;
* ``legacy_id`` is the workflow id or one of the legacy spec ids of 14.5.

The builder table and the read-atomic subject types are mirrored here as private constants because
this layer 0 module may not import the atomics (14.0.2); ``tests/unit/workflows`` cross-checks them
against ``xdr_response.atomics`` once those tables exist.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from fnmatch import fnmatchcase
from types import MappingProxyType
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from xdr_response.config.loader import FORBIDDEN_KEYS
from xdr_response.logs.redaction import Redactor
from xdr_response.models import (
    INTEGRATION_NAMES,
    ActionCategory,
    ActionType,
    FrozenModel,
    Incident,
    JsonDict,
    ObservableType,
    Severity,
    get_action_spec,
)
from xdr_response.workflows.expr import ExprError, parse

from xdr_response.atomics.correlation.models import LinkKind  # layer 0 model module (14.0.2)
from xdr_response.models.scoring import SignalCategory  # layer 0 model module (14.2.1)

__all__ = [
    "WORKFLOW_ID_RE",
    "SEMVER_RE",
    "TACTICS",
    "APPROVAL_LIKE_KEYS",
    "TriggerSpec",
    "IntegrationRequirement",
    "InvestigationStep",
    "CorrelationSpec",
    "ScoringInputs",
    "RecommendationRule",
    "MitreMapping",
    "WorkflowDefinition",
]

WORKFLOW_ID_RE = r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"  # kebab-case == workflows/<id>/
SEMVER_RE = r"^\d+\.\d+\.\d+$"

#: ATT&CK Enterprise tactic ids -> names.
TACTICS: Mapping[str, str] = MappingProxyType({
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
})

#: Keys a definition may never carry anywhere: a workflow cannot hold an approval switch.
APPROVAL_LIKE_KEYS: frozenset[str] = frozenset(FORBIDDEN_KEYS) | frozenset(
    {"approval_level", "requires_approval", "approve", "approved"})

_ID_RE = re.compile(WORKFLOW_ID_RE)
_SEMVER_RE = re.compile(SEMVER_RE)
_SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}$")
_SUB_TECHNIQUE_RE = re.compile(r"^T\d{4}\.\d{3}$")
_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_KEY_CHECKER = Redactor()  # is_sensitive_key only (no registered values)

_O = ObservableType
_HASH_TYPES = frozenset({_O.SHA256, _O.SHA1, _O.MD5})
_IP_TYPES = frozenset({_O.IP, _O.IPV6})
_HOST_TYPES = frozenset({_O.HOSTNAME, _O.ENDPOINT_ID})

#: Read atomics (14.1.3, 14.1.4) -> accepted subject types. Mirrors ``atomic_subject_types()``.
_READ_ATOMIC_SUBJECTS: Mapping[str, frozenset[ObservableType]] = MappingProxyType({
    "enrich_ip": _IP_TYPES,
    "enrich_domain": frozenset({_O.DOMAIN}),
    "enrich_url": frozenset({_O.URL}),
    "enrich_hash": _HASH_TYPES,
    "enrich_email_address": frozenset({_O.EMAIL_ADDRESS}),
    "enrich_user": frozenset({_O.USER}),
    "enrich_endpoint": _HOST_TYPES,
    "investigate_user": frozenset({_O.USER, _O.EMAIL_ADDRESS}),
    "investigate_endpoint": _HOST_TYPES,
    "investigate_ip": _IP_TYPES,
    "investigate_domain": frozenset({_O.DOMAIN}),
    "investigate_hash": _HASH_TYPES,
    "investigate_email": frozenset({_O.EMAIL_MESSAGE_ID}),
    "investigate_authentication": frozenset({_O.USER}),
    "investigate_process": frozenset({_O.PROCESS}),
    "investigate_network_connection": _IP_TYPES,
    "search_hash_enterprise": _HASH_TYPES,
    "search_domain_enterprise": frozenset({_O.DOMAIN}),
    "search_ip_enterprise": _IP_TYPES,
    "search_user_activity": frozenset({_O.USER}),
    "search_email_campaign": frozenset({_O.EMAIL_MESSAGE_ID}),
    "search_related_endpoints": _HOST_TYPES,
    "search_related_users": frozenset({_O.USER}),
})

_A = ActionType
#: Named containment builders (14.1.7) -> the action type they build. Mirrors ``CONTAINMENT_BUILDERS``.
_BUILDER_ACTIONS: Mapping[str, ActionType] = MappingProxyType({
    "isolate_secure_endpoint": _A.ISOLATE_ENDPOINT,
    "isolate_defender_endpoint": _A.ISOLATE_ENDPOINT,
    "block_domain_umbrella": _A.BLOCK_DOMAIN,
    "block_url": _A.BLOCK_URL,
    "block_ip": _A.BLOCK_IP,
    "block_hash": _A.BLOCK_HASH,
    "revoke_entra_sessions": _A.REVOKE_SESSIONS,
    "disable_entra_user": _A.DISABLE_USER,
    "quarantine_email": _A.QUARANTINE_EMAIL,
    "delete_malicious_email": _A.DELETE_EMAIL,
    "intune_device_action": _A.LOCK_DEVICE,
    "terminate_process": _A.TERMINATE_PROCESS,
    "quarantine_file": _A.QUARANTINE_FILE,
    "remove_persistence": _A.REMOVE_PERSISTENCE,
    "remove_privileged_role": _A.REMOVE_PRIVILEGED_ROLE,
})

#: Mirrors ``atomics.containment.builders.RESERVED_PARAM_KEYS`` (14.1.7).
_RESERVED_PARAM_KEYS: frozenset[str] = frozenset(
    {"integration", "verify_integration", "restores", "module_instance_id", "action_id", "observable_type",
     "observable_value", "approval_level"}) | frozenset(FORBIDDEN_KEYS)

#: Legacy spec ids of 14.5.1 a definition may replace.
_LEGACY_IDS: frozenset[str] = frozenset({
    "ransomware", "phishing", "account-takeover", "mail-bombing", "malware", "password-spray", "bec",
    "malicious-powershell", "credential-dumping", "lateral-movement", "persistence", "unauthorized-rmm",
    "c2", "dns-tunneling", "exfiltration", "cloud-compromise", "privilege-escalation",
    "vulnerability-exploitation", "web-attacks",
})

_EXECUTABLE = frozenset({ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION})
_AUTOMATIC_TRIGGERS = frozenset({"xdr_incident_rule", "webhook"})


# ------------------------------------------------------------------ helpers --
def _check_expr(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    try:
        parse(value)
    except ExprError as exc:
        raise ValueError(f"{field}: {exc}") from None
    return value


def _check_snake(value: str, what: str) -> str:
    if not _SNAKE_RE.match(value):
        raise ValueError(f"{what} {value!r} must be snake_case")
    return value


def _check_integration(name: str) -> str:
    if name not in INTEGRATION_NAMES:
        raise ValueError(f"unknown integration {name!r}; known: {list(INTEGRATION_NAMES)}")
    return name


def _non_empty(value: str, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{what} must not be empty")
    return value


def _approval_like_paths(node: Any, path: str = "") -> list[str]:
    """Every ``model_dump`` path whose key is approval-like (any depth, case-insensitive)."""
    found: list[str] = []
    if isinstance(node, Mapping):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).strip().lower() in APPROVAL_LIKE_KEYS:
                found.append(here)
            found.extend(_approval_like_paths(value, here))
    elif isinstance(node, (list, tuple, set, frozenset)):
        for index, value in enumerate(node):
            found.extend(_approval_like_paths(value, f"{path}[{index}]"))
    return found


def _duplicates(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    dupes: list[str] = []
    for value in values:
        if value in seen and value not in dupes:
            dupes.append(value)
        seen.add(value)
    return dupes


def _trigger_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(v) for v in value if v is not None]
    return [str(value)]


# ------------------------------------------------------------------- models --
class TriggerSpec(FrozenModel):
    """When a workflow handles an incident automatically (``manual`` / ``schedule`` never match)."""

    type: Literal["xdr_incident_rule", "webhook", "schedule", "manual"]
    description: str
    mitre_techniques: tuple[str, ...] = ()  # match incident.trigger["mitre_techniques"]
    title_patterns: tuple[str, ...] = ()  # fnmatch, case-insensitive, on incident.title
    sources: tuple[str, ...] = ()  # incident.source or incident.trigger["source"]
    observable_types: tuple[ObservableType, ...] = ()  # the incident must carry at least one
    priority: int = 100  # higher wins when several workflows match

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        return _non_empty(value, "trigger description")

    @field_validator("mitre_techniques")
    @classmethod
    def _techniques(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        bad = [v for v in value if not _ATTACK_ID_RE.match(v)]
        if bad:
            raise ValueError(f"invalid ATT&CK technique ids {bad}")
        return value

    @model_validator(mode="after")
    def _criteria(self) -> "TriggerSpec":
        if self.type in _AUTOMATIC_TRIGGERS and not (self.mitre_techniques or self.title_patterns
                                                     or self.sources or self.observable_types):
            raise ValueError(f"an automatic {self.type!r} trigger needs at least one matching criterion")
        return self

    def matches(self, incident: Incident) -> bool:
        """Every non-empty criterion must hold (AND); within a criterion any value may match (OR)."""
        if self.type not in _AUTOMATIC_TRIGGERS:
            return False
        checks = (self._match_mitre, self._match_title, self._match_source, self._match_observables)
        return all(check(incident) for check in checks)

    def _match_mitre(self, incident: Incident) -> bool:
        if not self.mitre_techniques:
            return True
        reported = {t.strip().upper() for t in _trigger_values(incident.trigger.get("mitre_techniques"))}
        # a reported sub-technique (T1486.001) matches its listed parent technique (T1486)
        return any(t in reported or any(r.startswith(t + ".") for r in reported) for t in self.mitre_techniques)

    def _match_title(self, incident: Incident) -> bool:
        if not self.title_patterns:
            return True
        title = incident.title.lower()
        return any(fnmatchcase(title, pattern.lower()) for pattern in self.title_patterns)

    def _match_source(self, incident: Incident) -> bool:
        if not self.sources:
            return True
        seen = {incident.source.lower(), *(s.lower() for s in _trigger_values(incident.trigger.get("source")))}
        return any(source.lower() in seen for source in self.sources)

    def _match_observables(self, incident: Incident) -> bool:
        if not self.observable_types:
            return True
        carried = {o.type for o in incident.observables}
        return any(t in carried for t in self.observable_types)


class IntegrationRequirement(FrozenModel):
    """An integration the workflow reads from, and why (README source)."""

    integration: str  # INTEGRATION_NAMES member
    purpose: str  # one line for the README
    atomics: tuple[str, ...] = ()  # read atomics that use it

    @field_validator("integration")
    @classmethod
    def _known(cls, value: str) -> str:
        return _check_integration(value)

    @field_validator("purpose")
    @classmethod
    def _purpose(cls, value: str) -> str:
        return _non_empty(value, "integration purpose")

    @field_validator("atomics")
    @classmethod
    def _atomics(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = [a for a in value if a not in _READ_ATOMIC_SUBJECTS]
        if unknown:
            raise ValueError(f"unknown read atomics {unknown}")
        return value


class InvestigationStep(FrozenModel):
    """One read atomic the runner calls, with its subjects and condition."""

    id: str  # snake_case, unique in the workflow
    atomic: str  # a read_atomics() name (14.1.9)
    subjects: str | None = None  # expression -> list[str]; default: incident observables + earlier finds
    subject_type: ObservableType | None = None  # required with `subjects` when the atomic accepts several
    when: str | None = None  # expression -> bool; step skipped (noted) when false
    integrations: tuple[str, ...] = ()  # restrict sources; subset of required + optional integrations
    options: JsonDict = {}  # passed to the atomic (adapter query options)
    lookback_hours: int | None = Field(default=None, ge=1, le=720)  # default 24
    max_subjects: int = Field(default=25, ge=1, le=200)  # further subjects are noted, not queried

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        return _check_snake(value, "step id")

    @field_validator("atomic")
    @classmethod
    def _atomic(cls, value: str) -> str:
        if value not in _READ_ATOMIC_SUBJECTS:
            raise ValueError(f"unknown read atomic {value!r}; known: {sorted(_READ_ATOMIC_SUBJECTS)}")
        return value

    @field_validator("subjects", "when")
    @classmethod
    def _expressions(cls, value: str | None, info: Any) -> str | None:
        return _check_expr(value, f"step {info.field_name}")

    @field_validator("integrations")
    @classmethod
    def _integrations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            _check_integration(name)
        return value

    @model_validator(mode="after")
    def _subject_type(self) -> "InvestigationStep":
        accepted = self.subject_types()
        if self.subject_type is not None and self.subject_type not in accepted:
            raise ValueError(f"step {self.id}: {self.atomic} does not accept {self.subject_type.value} subjects")
        if self.subjects is not None and self.subject_type is None and len(accepted) > 1:
            raise ValueError(f"step {self.id}: subject_type is required with subjects because {self.atomic} "
                             f"accepts {sorted(t.value for t in accepted)}")
        if self.atomic.startswith("enrich_") and (self.integrations or self.options):
            raise ValueError(f"step {self.id}: enrichment atomics ask every enricher (disclosure policy "
                             "applies); integrations and options are for investigation atomics only")
        return self

    def subject_types(self) -> frozenset[ObservableType]:
        """Observable types the step's atomic accepts."""
        return _READ_ATOMIC_SUBJECTS[self.atomic]


class CorrelationSpec(FrozenModel):
    """Which framework link rules the run applies (README "Correlation logic")."""

    description: str
    link_kinds: tuple[LinkKind, ...] = tuple(k for k in LinkKind if k is not LinkKind.WORKFLOW)
    window_minutes: int = Field(default=60, ge=1, le=1440)

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        return _non_empty(value, "correlation description")


class ScoringInputs(FrozenModel):
    """Workflow scoring inputs (README "Risk calculation"); caps and penalties are not overridable."""

    description: str
    weights: Mapping[SignalCategory, float] = {}  # category weight overrides, 0.0-1.0
    expected_sources: tuple[str, ...] = ()  # default: the required integrations

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        return _non_empty(value, "scoring description")

    @field_validator("weights")
    @classmethod
    def _weights(cls, value: Mapping[SignalCategory, float]) -> Mapping[SignalCategory, float]:
        bad = {str(k): v for k, v in value.items() if not 0.0 <= float(v) <= 1.0}
        if bad:
            raise ValueError(f"category weights must be within 0.0-1.0: {bad}")
        return value

    @field_validator("expected_sources")
    @classmethod
    def _sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            _check_integration(name)
        return value


class RecommendationRule(FrozenModel):
    """A containment the workflow may recommend; the human decides (never the rule)."""

    id: str  # snake_case, unique in the workflow
    description: str
    action: ActionType  # CONTAINMENT or REMEDIATION catalog type
    builder: str | None = None  # a CONTAINMENT_BUILDERS name whose action type == action
    for_each: str  # expression -> list
    when: str | None = None  # expression -> bool
    target: str  # expression -> str (normalized by the builder)
    evidence: str  # expression -> list[str] of record ids (>= 1 at run time)
    include_target_enrichment: bool = True
    #: expression -> {"groups", "tags", "roles", "ip", "ips", "users", "privileged"} (optional keys)
    asset: str | None = None
    #: expression -> list of SHA-256 values: the binaries whose behaviour alone the recommendation
    #: rests on (a relay block because the tool is flagged). When every one is sanctioned (allow-listed
    #: or approved-tool hash, approved signer on a prevalence record) the runner withholds the action as
    #: ALLOWLISTED and shows it as considered. ``[]`` (or None) when the target stands on its own.
    binaries: str | None = None
    #: expression -> list of ``"<block action>:<target>"`` entries: the indicators whose meeting alone
    #: the recommendation rests on (an account revoked because it signed in from a rated IP). When the
    #: allow-list excludes the block of every one (``never_block``, approved tools, non-public
    #: addresses, internal domains) the runner withholds the action as ALLOWLISTED and shows it as
    #: considered. ``[]`` (or None) when the target stands on its own.
    indicators: str | None = None
    params: Mapping[str, str] = {}  # param name -> expression; reserved keys refused; no floats
    rationale: str  # expression -> str
    min_risk: int = Field(default=0, ge=0, le=100)  # below: "considered, not proposed" note
    min_confidence: int = Field(default=0, ge=0, le=100)
    mitre: tuple[str, ...] = ()  # technique / sub-technique ids this rule responds to

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        return _check_snake(value, "rule id")

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        return _non_empty(value, "rule description")

    @field_validator("action")
    @classmethod
    def _action(cls, value: ActionType) -> ActionType:
        category = get_action_spec(value).category
        if category not in _EXECUTABLE:
            raise ValueError(f"rule action {value.value} is {category.value}; only CONTAINMENT or REMEDIATION "
                             "types can be recommended (restoration is only built by RestorationPlanner)")
        return value

    @field_validator("for_each", "when", "target", "evidence", "asset", "binaries", "indicators", "rationale")
    @classmethod
    def _expressions(cls, value: str | None, info: Any) -> str | None:
        return _check_expr(value, f"rule {info.field_name}")

    @field_validator("params")
    @classmethod
    def _params(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        for key, expression in value.items():
            if key in _RESERVED_PARAM_KEYS or key.lower() in APPROVAL_LIKE_KEYS:
                raise ValueError(f"param {key!r} is reserved (routing and approval are not workflow inputs)")
            if _KEY_CHECKER.is_sensitive_key(key):
                raise ValueError(f"param {key!r} looks like a secret; secrets are never workflow inputs")
            _check_expr(expression, f"rule param {key}")
        return value

    @field_validator("mitre")
    @classmethod
    def _mitre(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        bad = [v for v in value if not _ATTACK_ID_RE.match(v)]
        if bad:
            raise ValueError(f"invalid ATT&CK ids {bad}")
        return value

    @model_validator(mode="after")
    def _builder(self) -> "RecommendationRule":
        if self.builder is None:
            return self
        built = _BUILDER_ACTIONS.get(self.builder)
        if built is None:
            raise ValueError(f"rule {self.id}: unknown builder {self.builder!r}; known: {sorted(_BUILDER_ACTIONS)}")
        if built is not self.action:
            raise ValueError(f"rule {self.id}: builder {self.builder} builds {built.value}, not {self.action.value}")
        return self


class MitreMapping(FrozenModel):
    """One ATT&CK technique the workflow responds to ("no forced mappings")."""

    tactic: str  # key of TACTICS
    technique: str  # r"^T\d{4}$"
    technique_name: str
    sub_technique: str | None = None  # r"^T\d{4}\.\d{3}$", must start with technique
    sub_technique_name: str | None = None
    rationale: str  # why this workflow responds to it

    @field_validator("tactic")
    @classmethod
    def _tactic(cls, value: str) -> str:
        if value not in TACTICS:
            raise ValueError(f"unknown ATT&CK tactic {value!r}; known: {sorted(TACTICS)}")
        return value

    @field_validator("technique")
    @classmethod
    def _technique(cls, value: str) -> str:
        if not _TECHNIQUE_RE.match(value):
            raise ValueError(f"technique {value!r} must look like T1234")
        return value

    @field_validator("technique_name", "rationale")
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        return _non_empty(value, info.field_name)

    @model_validator(mode="after")
    def _sub(self) -> "MitreMapping":
        if self.sub_technique is None:
            if self.sub_technique_name is not None:
                raise ValueError("sub_technique_name needs a sub_technique")
            return self
        if not _SUB_TECHNIQUE_RE.match(self.sub_technique):
            raise ValueError(f"sub-technique {self.sub_technique!r} must look like T1234.001")
        if not self.sub_technique.startswith(self.technique + "."):
            raise ValueError(f"sub-technique {self.sub_technique} does not belong to {self.technique}")
        if not (self.sub_technique_name or "").strip():
            raise ValueError(f"sub-technique {self.sub_technique} needs a sub_technique_name")
        return self

    @property
    def tactic_name(self) -> str:
        """Display name of the tactic."""
        return TACTICS[self.tactic]

    @property
    def attack_id(self) -> str:
        """The sub-technique id when present, else the technique id."""
        return self.sub_technique or self.technique


class WorkflowDefinition(FrozenModel):
    """A complete, validated workflow (see module docstring for the validators)."""

    id: str  # WORKFLOW_ID_RE
    version: str  # SEMVER_RE; bound into packages and tokens (workflow_version)
    name: str
    description: str  # README "Purpose" source
    phase: Literal[2, 3, 4, 5]
    default_severity: Severity
    legacy_id: str | None = None  # workflows/<legacy_id>/workflow.yaml this definition replaces
    triggers: tuple[TriggerSpec, ...] = Field(min_length=1)
    input_observables: tuple[ObservableType, ...] = Field(min_length=1)  # README "Input data"
    required_integrations: tuple[IntegrationRequirement, ...] = Field(min_length=1)
    optional_integrations: tuple[IntegrationRequirement, ...] = ()
    investigation: tuple[InvestigationStep, ...] = Field(min_length=1)
    correlation: CorrelationSpec
    scoring: ScoringInputs
    recommendations: tuple[RecommendationRule, ...] = Field(min_length=1)
    mitre: tuple[MitreMapping, ...] = Field(min_length=1)
    known_limitations: tuple[str, ...] = Field(min_length=1)
    related_workflows: tuple[str, ...] = ()
    #: Workflows this one may hand off to (hook ``handoffs``, 14.10.1); a subset of related_workflows.
    handoff_to: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(f"workflow id {value!r} must be kebab-case ({WORKFLOW_ID_RE})")
        return value

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not _SEMVER_RE.match(value):
            raise ValueError(f"version {value!r} must be semantic (MAJOR.MINOR.PATCH)")
        return value

    @field_validator("name", "description")
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        return _non_empty(value, info.field_name)

    @field_validator("known_limitations")
    @classmethod
    def _limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _non_empty(item, "known limitation")
        return value

    @field_validator("related_workflows", "handoff_to")
    @classmethod
    def _related(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        bad = [v for v in value if not _ID_RE.match(v)]
        if bad:
            raise ValueError(f"{info.field_name} ids must be kebab-case: {bad}")
        dupes = _duplicates(list(value))
        if dupes:
            raise ValueError(f"{info.field_name} lists ids twice: {dupes}")
        return value

    @model_validator(mode="after")
    def _cross_checks(self) -> "WorkflowDefinition":
        self._check_ids()
        self._check_integrations()
        self._check_rule_mitre()
        self._check_legacy_id()
        paths = _approval_like_paths(self.model_dump(mode="json"))
        if paths:
            raise ValueError(f"a workflow definition cannot carry approval settings: {paths}")
        return self

    def _check_ids(self) -> None:
        for what, ids in (("step", [s.id for s in self.investigation]),
                          ("rule", [r.id for r in self.recommendations]),
                          ("MITRE mapping", [m.attack_id for m in self.mitre])):
            dupes = _duplicates(ids)
            if dupes:
                raise ValueError(f"duplicate {what} ids: {dupes}")
        if self.id in self.related_workflows:
            raise ValueError("a workflow cannot list itself in related_workflows")
        outside = [w for w in self.handoff_to if w not in self.related_workflows]
        if outside:
            raise ValueError(f"handoff_to {outside} must also be listed in related_workflows")

    def _check_integrations(self) -> None:
        required = [r.integration for r in self.required_integrations]
        optional = [r.integration for r in self.optional_integrations]
        dupes = _duplicates(required + optional)
        if dupes:
            raise ValueError(f"integrations listed twice or both required and optional: {dupes}")
        known = set(required) | set(optional)
        for step in self.investigation:
            outside = sorted(set(step.integrations) - known)
            if outside:
                raise ValueError(f"step {step.id}: integrations {outside} are not required or optional")
        outside = sorted(set(self.scoring.expected_sources) - known)
        if outside:
            raise ValueError(f"scoring.expected_sources {outside} are not required or optional integrations")

    def _check_rule_mitre(self) -> None:
        mapped = self.attack_ids()
        for rule in self.recommendations:
            missing = [m for m in rule.mitre if m not in mapped]
            if missing:
                raise ValueError(f"rule {rule.id}: ATT&CK ids {missing} are not in the workflow's mitre mappings")

    def _check_legacy_id(self) -> None:
        if self.legacy_id is not None and self.legacy_id != self.id and self.legacy_id not in _LEGACY_IDS:
            raise ValueError(f"legacy_id {self.legacy_id!r} is neither the workflow id nor a legacy spec id")

    # ------------------------------------------------------------ helpers --
    def attack_ids(self) -> frozenset[str]:
        """Every technique and sub-technique id of the mappings."""
        return frozenset({m.technique for m in self.mitre} | {m.sub_technique for m in self.mitre
                                                               if m.sub_technique})

    def integrations(self) -> tuple[str, ...]:
        """Required then optional integration names, in definition order."""
        return tuple(r.integration for r in (*self.required_integrations, *self.optional_integrations))

    def expected_sources(self) -> tuple[str, ...]:
        """``scoring.expected_sources`` or, by default, the required integrations."""
        return self.scoring.expected_sources or tuple(r.integration for r in self.required_integrations)

    def matches(self, incident: Incident) -> TriggerSpec | None:
        """The highest-priority automatic trigger matching ``incident`` (None when none matches)."""
        hits = [t for t in self.triggers if t.matches(incident)]
        return max(hits, key=lambda t: t.priority) if hits else None

    @property
    def package_name(self) -> str:
        """Python package name of the workflow (``id`` with ``-`` replaced by ``_``)."""
        return self.id.replace("-", "_")
