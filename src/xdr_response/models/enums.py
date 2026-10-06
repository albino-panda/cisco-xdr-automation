"""Shared enumerations (architecture section 13.3). This module imports nothing from the package."""
from __future__ import annotations

from enum import StrEnum

__all__ = [
    "IncidentState",
    "ApprovalLevel",
    "DecisionType",
    "PrincipalKind",
    "ApprovalPurpose",
    "ActionResultStatus",
    "SkipReason",
    "ContainmentOverall",
    "RestorationOverall",
    "VerificationStatus",
    "HealthStatus",
    "OperationKind",
    "EndpointStatus",
    "ActionCategory",
    "TargetKind",
    "ObservableType",
    "Verdict",
    "RiskBand",
    "Severity",
    "CriticalAssetClass",
    "ControlStatus",
    "TargetState",
    "ErrorCode",
    "AuditEventType",
]


class IncidentState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    CONTAINMENT_RUNNING = "CONTAINMENT_RUNNING"
    CONTAINED = "CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"
    REMEDIATION_REQUIRED = "REMEDIATION_REQUIRED"
    AWAITING_RELEASE_APPROVAL = "AWAITING_RELEASE_APPROVAL"
    RESTORATION_RUNNING = "RESTORATION_RUNNING"
    RESTORED = "RESTORED"
    CLOSED = "CLOSED"


class ApprovalLevel(StrEnum):
    STANDARD = "STANDARD"
    ELEVATED = "ELEVATED"


class DecisionType(StrEnum):
    APPROVE_ALL = "APPROVE_ALL"
    APPROVE_SELECTED = "APPROVE_SELECTED"
    REJECT = "REJECT"
    REQUEST_MORE_INVESTIGATION = "REQUEST_MORE_INVESTIGATION"


class PrincipalKind(StrEnum):
    HUMAN = "HUMAN"
    SERVICE = "SERVICE"
    AUTOMATION = "AUTOMATION"
    AI = "AI"


class ApprovalPurpose(StrEnum):
    CONTAINMENT = "containment"
    RELEASE = "release"


class ActionResultStatus(StrEnum):
    SUCCESS = "SUCCESS"
    ALREADY_CONTAINED = "ALREADY_CONTAINED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    DRY_RUN = "DRY_RUN"


class SkipReason(StrEnum):
    REJECTED_BY_ANALYST = "REJECTED_BY_ANALYST"
    NO_CAPABLE_ADAPTER = "NO_CAPABLE_ADAPTER"
    INTEGRATION_DISABLED = "INTEGRATION_DISABLED"
    CONTROL_NOT_ACTIVE = "CONTROL_NOT_ACTIVE"


class ContainmentOverall(StrEnum):  # values equal IncidentState names
    CONTAINED = "CONTAINED"
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"


class RestorationOverall(StrEnum):
    RESTORED = "RESTORED"  # -> IncidentState.RESTORED
    PARTIALLY_RESTORED = "PARTIALLY_RESTORED"  # -> IncidentState.AWAITING_RELEASE_APPROVAL
    RESTORATION_FAILED = "RESTORATION_FAILED"  # -> IncidentState.AWAITING_RELEASE_APPROVAL


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"


class HealthStatus(StrEnum):
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    UNKNOWN = "UNKNOWN"


class OperationKind(StrEnum):
    READ = "READ"  # enrichment, investigation, token endpoints, search POSTs
    VERIFY = "VERIFY"  # read-back of a target's state
    BOOKKEEPING = "BOOKKEEPING"  # notes, incident status, tickets, notifications, audit forwarding
    STATE_CHANGING = "STATE_CHANGING"  # approval-gated; guard required


class EndpointStatus(StrEnum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ActionCategory(StrEnum):
    ENRICHMENT = "ENRICHMENT"
    INVESTIGATION = "INVESTIGATION"
    BOOKKEEPING = "BOOKKEEPING"
    CONTAINMENT = "CONTAINMENT"
    REMEDIATION = "REMEDIATION"
    RESTORATION = "RESTORATION"


class TargetKind(StrEnum):
    ENDPOINT = "ENDPOINT"
    USER = "USER"
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    HASH = "HASH"
    EMAIL_MESSAGE = "EMAIL_MESSAGE"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PROCESS = "PROCESS"
    FILE = "FILE"
    PERSISTENCE_ITEM = "PERSISTENCE_ITEM"
    ROLE_ASSIGNMENT = "ROLE_ASSIGNMENT"
    NETWORK_CLIENT = "NETWORK_CLIENT"
    APPLICATION = "APPLICATION"
    CREDENTIAL = "CREDENTIAL"
    INCIDENT = "INCIDENT"


class ObservableType(StrEnum):
    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL_ADDRESS = "email_address"
    USER = "user"
    HOSTNAME = "hostname"
    ENDPOINT_ID = "endpoint_id"
    MAC_ADDRESS = "mac_address"
    EMAIL_MESSAGE_ID = "email_message_id"
    PROCESS = "process"
    FILE_PATH = "file_path"


class Verdict(StrEnum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class RiskBand(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CriticalAssetClass(StrEnum):
    DOMAIN_CONTROLLER = "domain_controller"
    IDENTITY_INFRASTRUCTURE = "identity_infrastructure"
    EXECUTIVE_ENDPOINT = "executive_endpoint"
    PRODUCTION_SERVER = "production_server"
    HYPERVISOR = "hypervisor"
    NETWORK_INFRASTRUCTURE = "network_infrastructure"
    SECURITY_INFRASTRUCTURE = "security_infrastructure"
    SERVICE_ACCOUNT = "service_account"
    PRIVILEGED_ACCOUNT = "privileged_account"
    AUTOMATION_ACCOUNT = "automation_account"


class ControlStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RELEASE_PENDING = "RELEASE_PENDING"
    RELEASED = "RELEASED"
    RELEASE_FAILED = "RELEASE_FAILED"


class TargetState(StrEnum):
    IN_DESIRED_STATE = "IN_DESIRED_STATE"
    NOT_IN_DESIRED_STATE = "NOT_IN_DESIRED_STATE"
    UNKNOWN = "UNKNOWN"


class ErrorCode(StrEnum):
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILED = "AUTH_FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID_TARGET = "INVALID_TARGET"
    API_ERROR = "API_ERROR"
    UNVERIFIED_ENDPOINT = "UNVERIFIED_ENDPOINT"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    DRY_RUN = "DRY_RUN"
    NO_CAPABLE_ADAPTER = "NO_CAPABLE_ADAPTER"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    INTERNAL = "INTERNAL"


class AuditEventType(StrEnum):
    INCIDENT_RECEIVED = "INCIDENT_RECEIVED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    ENRICHMENT_RESULT = "ENRICHMENT_RESULT"
    PACKAGE_PROPOSED = "PACKAGE_PROPOSED"
    DECISION_RECORDED = "DECISION_RECORDED"
    TOKEN_ISSUED = "TOKEN_ISSUED"  # token_id and claims hash only
    APPROVAL_DENIED = "APPROVAL_DENIED"
    GUARD_DENIED = "GUARD_DENIED"
    STATE_TRANSITION = "STATE_TRANSITION"
    ACTION_STARTED = "ACTION_STARTED"
    API_CALL = "API_CALL"  # redacted ApiCallSummary
    ACTION_RESULT = "ACTION_RESULT"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"
    CONTROL_REGISTERED = "CONTROL_REGISTERED"
    CONTAINMENT_COMPLETED = "CONTAINMENT_COMPLETED"
    RELEASE_PACKAGE_PROPOSED = "RELEASE_PACKAGE_PROPOSED"
    RESTORATION_RESULT = "RESTORATION_RESULT"
    RESTORATION_COMPLETED = "RESTORATION_COMPLETED"
    DRY_RUN_SIMULATION = "DRY_RUN_SIMULATION"
    HEALTH_CHECK = "HEALTH_CHECK"
    ERROR = "ERROR"
