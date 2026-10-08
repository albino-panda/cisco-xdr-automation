"""Data models (architecture sections 13.3, 13.5, 13.6). Re-exports every public name."""
from __future__ import annotations

from xdr_response.models._base import FrozenModel, JsonDict
from xdr_response.models.action import (
    ActionOutcome,
    ActionRequest,
    ActionResult,
    ApiCallSummary,
    ContainmentReport,
    ErrorInfo,
    RestorationReport,
    TargetStateCheck,
)
from xdr_response.models.approval import (
    TOKEN_ISSUANCE_CONTEXT,
    TOKEN_SIGNING_CONTEXT,
    ActionBinding,
    AnalystDecision,
    ApprovalOutcome,
    ApprovalToken,
    ApprovalTokenClaims,
    ApproverClaim,
    ApproverCredential,
    AuthenticatedPrincipal,
    DecisionRequest,
    TokenActionGrant,
)
from xdr_response.models.audit import GENESIS_HASH, AuditRecord, ChainVerification
from xdr_response.models.canonical import (
    canonical_json,
    canonical_url,
    endpoint_names,
    format_datetime,
    make_idempotency_key,
    normalize_target,
    params_hash,
    same_endpoint,
    sha256_hex,
)
from xdr_response.models.catalog import (
    ACTION_CATALOG,
    BOOKKEEPING_OPERATIONS,
    INTEGRATION_NAMES,
    ActionSpec,
    ActionType,
    get_action_spec,
    is_state_changing,
    purpose_for,
    rollback_for,
)
from xdr_response.models.enums import (
    ActionCategory,
    ActionResultStatus,
    ApprovalLevel,
    ApprovalPurpose,
    AuditEventType,
    ContainmentOverall,
    ControlStatus,
    CriticalAssetClass,
    DecisionType,
    EndpointStatus,
    ErrorCode,
    HealthStatus,
    IncidentState,
    ObservableType,
    OperationKind,
    PrincipalKind,
    RestorationOverall,
    RiskBand,
    Severity,
    SkipReason,
    TargetKind,
    TargetState,
    Verdict,
    VerificationStatus,
)
from xdr_response.models.evidence import (
    ALLOWED_NON_INTEGRATION_SOURCES,
    Evidence,
    EvidenceDraft,
    evidence_snapshot_hash,
    number_evidence,
)
from xdr_response.models.health import IntegrationHealth
from xdr_response.models.incident import Asset, Incident, StateTransition, asset_addresses, merge_asset_context
from xdr_response.models.investigation import InvestigationQuery, InvestigationResult
from xdr_response.models.observable import EnrichmentResult, Observable
from xdr_response.models.recommendation import (
    ActionPackage,
    BlastRadius,
    ContainmentPackage,
    CriticalAssetWarning,
    ExcludedTarget,
    ProposedAction,
    RecommendedAction,
    ReleasePackage,
    risk_band,
)
from xdr_response.models.restoration import TemporaryControl
from xdr_response.models.states import (
    ALLOWED_TRANSITIONS,
    OUTCOME_ACTOR,
    OUTCOME_STATES,
    REPORT_REQUIRED,
    TOKEN_REQUIRED,
    can_transition,
)
from xdr_response.models.verification import VerificationResult

__all__ = [
    # base
    "FrozenModel", "JsonDict",
    # enums
    "IncidentState", "ApprovalLevel", "DecisionType", "PrincipalKind", "ApprovalPurpose",
    "ActionResultStatus", "SkipReason", "ContainmentOverall", "RestorationOverall",
    "VerificationStatus", "HealthStatus", "OperationKind", "EndpointStatus", "ActionCategory",
    "TargetKind", "ObservableType", "Verdict", "RiskBand", "Severity", "CriticalAssetClass",
    "ControlStatus", "TargetState", "ErrorCode", "AuditEventType",
    # canonical
    "canonical_json", "sha256_hex", "params_hash", "normalize_target", "make_idempotency_key",
    "format_datetime", "endpoint_names", "same_endpoint", "canonical_url",
    # catalog
    "ActionType", "ActionSpec", "ACTION_CATALOG", "BOOKKEEPING_OPERATIONS", "INTEGRATION_NAMES",
    "get_action_spec", "is_state_changing", "purpose_for", "rollback_for",
    # observable / evidence
    "Observable", "EnrichmentResult", "ALLOWED_NON_INTEGRATION_SOURCES", "EvidenceDraft", "Evidence",
    "number_evidence", "evidence_snapshot_hash",
    # incident
    "Asset", "StateTransition", "Incident", "asset_addresses", "merge_asset_context",
    # recommendation
    "risk_band", "CriticalAssetWarning", "ExcludedTarget", "BlastRadius", "ProposedAction",
    "RecommendedAction", "ActionPackage", "ContainmentPackage", "ReleasePackage",
    # approval
    "ApproverCredential", "AuthenticatedPrincipal", "DecisionRequest", "AnalystDecision",
    "TokenActionGrant", "ApproverClaim", "ApprovalTokenClaims", "ApprovalToken",
    "TOKEN_SIGNING_CONTEXT", "TOKEN_ISSUANCE_CONTEXT", "ActionBinding", "ApprovalOutcome",
    # action
    "ErrorInfo", "ApiCallSummary", "ActionRequest", "TargetStateCheck", "ActionOutcome",
    "ActionResult", "ContainmentReport", "RestorationReport",
    # verification / restoration / audit / health / investigation
    "VerificationResult", "TemporaryControl", "GENESIS_HASH", "AuditRecord", "ChainVerification",
    "IntegrationHealth", "InvestigationQuery", "InvestigationResult",
    # lifecycle table
    "ALLOWED_TRANSITIONS", "TOKEN_REQUIRED", "can_transition", "REPORT_REQUIRED", "OUTCOME_ACTOR",
    "OUTCOME_STATES",
]
