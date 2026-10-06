"""Action catalog (architecture section 13.6): the single source of truth for what is state-changing.

The approval purpose of an action is always derived from this catalog, never from caller input.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from pydantic import model_validator

from xdr_response.models._base import FrozenModel
from xdr_response.models.enums import ActionCategory, ApprovalPurpose, TargetKind

__all__ = [
    "ActionType",
    "ActionSpec",
    "ACTION_CATALOG",
    "BOOKKEEPING_OPERATIONS",
    "INTEGRATION_NAMES",
    "STATE_CHANGING_CATEGORIES",
    "get_action_spec",
    "is_state_changing",
    "purpose_for",
    "rollback_for",
]

#: Every integration the framework knows (re-exported by ``xdr_response.config.schema``).
INTEGRATION_NAMES: tuple[str, ...] = (
    "cisco_xdr", "secure_endpoint", "secure_email", "secure_malware_analytics",
    "secure_cloud_analytics", "umbrella", "meraki", "entra", "defender_endpoint",
    "defender_o365", "intune", "microsoft_cloud", "virustotal", "alienvault_otx", "hibp", "splunk",
)

STATE_CHANGING_CATEGORIES = frozenset(
    {ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION, ActionCategory.RESTORATION}
)

BOOKKEEPING_OPERATIONS: frozenset[str] = frozenset(
    {"add_incident_note", "update_incident_status", "create_ticket", "notify_soc", "forward_audit"}
)


class ActionType(StrEnum):
    # containment
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    BLOCK_IP = "block_ip"
    BLOCK_HASH = "block_hash"
    DISABLE_USER = "disable_user"
    REVOKE_SESSIONS = "revoke_sessions"
    CONFIRM_USER_COMPROMISED = "confirm_user_compromised"
    QUARANTINE_EMAIL = "quarantine_email"
    BLOCK_NETWORK_CLIENT = "block_network_client"
    LOCK_DEVICE = "lock_device"
    REMOVE_PRIVILEGED_ROLE = "remove_privileged_role"
    # remediation
    DELETE_EMAIL = "delete_email"
    TERMINATE_PROCESS = "terminate_process"
    QUARANTINE_FILE = "quarantine_file"
    REMOVE_PERSISTENCE = "remove_persistence"
    RESET_PASSWORD = "reset_password"
    RESET_MFA = "reset_mfa"
    REVOKE_APP_CREDENTIALS = "revoke_app_credentials"
    REMOVE_APPLICATION = "remove_application"
    # restoration
    RELEASE_ENDPOINT = "release_endpoint"
    UNBLOCK_DOMAIN = "unblock_domain"
    UNBLOCK_URL = "unblock_url"
    UNBLOCK_IP = "unblock_ip"
    UNBLOCK_HASH = "unblock_hash"
    ENABLE_USER = "enable_user"
    RELEASE_EMAIL = "release_email"
    RESTORE_NETWORK_CLIENT = "restore_network_client"
    RESTORE_PRIVILEGED_ROLE = "restore_privileged_role"
    RESTORE_FILE = "restore_file"
    # enrichment
    ENRICH_IP = "enrich_ip"
    ENRICH_DOMAIN = "enrich_domain"
    ENRICH_URL = "enrich_url"
    ENRICH_HASH = "enrich_hash"
    ENRICH_EMAIL_ADDRESS = "enrich_email_address"
    ENRICH_USER = "enrich_user"
    ENRICH_ENDPOINT = "enrich_endpoint"
    # investigation
    INVESTIGATE_USER = "investigate_user"
    INVESTIGATE_ENDPOINT = "investigate_endpoint"
    INVESTIGATE_IP = "investigate_ip"
    INVESTIGATE_DOMAIN = "investigate_domain"
    INVESTIGATE_HASH = "investigate_hash"
    INVESTIGATE_EMAIL = "investigate_email"
    INVESTIGATE_AUTHENTICATION = "investigate_authentication"
    INVESTIGATE_PROCESS = "investigate_process"
    INVESTIGATE_NETWORK_CONNECTION = "investigate_network_connection"
    SEARCH_HASH_ENTERPRISE = "search_hash_enterprise"
    SEARCH_DOMAIN_ENTERPRISE = "search_domain_enterprise"
    SEARCH_IP_ENTERPRISE = "search_ip_enterprise"
    SEARCH_USER_ACTIVITY = "search_user_activity"
    SEARCH_EMAIL_CAMPAIGN = "search_email_campaign"
    SEARCH_RELATED_ENDPOINTS = "search_related_endpoints"
    SEARCH_RELATED_USERS = "search_related_users"
    # bookkeeping
    ADD_INCIDENT_NOTE = "add_incident_note"
    UPDATE_INCIDENT_STATUS = "update_incident_status"
    CREATE_TICKET = "create_ticket"
    NOTIFY_SOC = "notify_soc"


class ActionSpec(FrozenModel):
    action_type: ActionType
    category: ActionCategory
    state_changing: bool
    reversible: bool
    rollback_action_type: ActionType | None
    target_kind: TargetKind
    purpose: ApprovalPurpose | None
    always_elevated: bool = False
    creates_control: bool = False
    integrations: tuple[str, ...]
    dry_run_verb: str
    description: str
    spec_ref: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "ActionSpec":
        sc = self.category in STATE_CHANGING_CATEGORIES
        if self.state_changing != sc:
            raise ValueError("state_changing must be true exactly for CONTAINMENT/REMEDIATION/RESTORATION")
        expected_purpose = (
            ApprovalPurpose.CONTAINMENT
            if self.category in (ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION)
            else ApprovalPurpose.RELEASE if self.category is ActionCategory.RESTORATION else None
        )
        if self.purpose != expected_purpose:
            raise ValueError(f"purpose for {self.category} must be {expected_purpose}")
        if self.reversible != (self.rollback_action_type is not None):
            raise ValueError("reversible must be true exactly when a rollback action type is set")
        if self.creates_control and not (self.reversible and self.purpose is ApprovalPurpose.CONTAINMENT):
            raise ValueError("only reversible containment/remediation actions create controls")
        unknown = [i for i in self.integrations if i not in INTEGRATION_NAMES]
        if unknown:
            raise ValueError(f"unknown integrations: {unknown}")
        if self.state_changing and not self.dry_run_verb:
            raise ValueError("state-changing actions need a dry_run_verb")
        return self


_C, _R, _X = ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION, ActionCategory.RESTORATION
_E, _I, _B = ActionCategory.ENRICHMENT, ActionCategory.INVESTIGATION, ActionCategory.BOOKKEEPING
_T = TargetKind
_A = ActionType

_EDR = ("cisco_xdr", "defender_endpoint", "secure_endpoint")
_DNS = ("cisco_xdr", "umbrella", "defender_endpoint")
_NET = ("cisco_xdr", "meraki", "defender_endpoint")
_MAIL = ("cisco_xdr", "secure_email", "defender_o365")
_IDP = ("cisco_xdr", "entra")

# (type, category, rollback, target kind, always_elevated, integrations, verb, description, spec_ref)
_WRITE_ROWS: tuple[tuple, ...] = (
    (_A.ISOLATE_ENDPOINT, _C, _A.RELEASE_ENDPOINT, _T.ENDPOINT, False, _EDR, "Would isolate",
     "Network-isolate an endpoint", "atomic/isolate-endpoint"),
    (_A.BLOCK_DOMAIN, _C, _A.UNBLOCK_DOMAIN, _T.DOMAIN, False, _DNS, "Would block",
     "Block a domain", "atomic/block-domain"),
    (_A.BLOCK_URL, _C, _A.UNBLOCK_URL, _T.URL, False, _DNS, "Would block",
     "Block a URL", "atomic/block-url"),
    (_A.BLOCK_IP, _C, _A.UNBLOCK_IP, _T.IP, False, _NET, "Would block",
     "Block an IP address", "atomic/block-ip"),
    (_A.BLOCK_HASH, _C, _A.UNBLOCK_HASH, _T.HASH, False, _EDR, "Would block",
     "Block a file hash", "atomic/block-hash"),
    (_A.DISABLE_USER, _C, _A.ENABLE_USER, _T.USER, False, _IDP, "Would disable user",
     "Disable a user account", "atomic/disable-user"),
    (_A.REVOKE_SESSIONS, _C, None, _T.USER, False, ("entra",), "Would revoke sessions",
     "Revoke all sign-in sessions of a user", "atomic/revoke-session"),
    (_A.CONFIRM_USER_COMPROMISED, _C, None, _T.USER, False, ("entra",), "Would mark compromised",
     "Confirm a user as compromised in Entra ID Protection", None),
    (_A.QUARANTINE_EMAIL, _C, _A.RELEASE_EMAIL, _T.EMAIL_MESSAGE, False, _MAIL, "Would quarantine email",
     "Quarantine an email message", "atomic/quarantine-email"),
    (_A.BLOCK_NETWORK_CLIENT, _C, _A.RESTORE_NETWORK_CLIENT, _T.NETWORK_CLIENT, False, ("meraki",),
     "Would block network client", "Block a network client via Meraki group policy", None),
    (_A.LOCK_DEVICE, _C, None, _T.ENDPOINT, False, ("intune",), "Would lock device",
     "Remote-lock a managed device", None),
    (_A.REMOVE_PRIVILEGED_ROLE, _C, _A.RESTORE_PRIVILEGED_ROLE, _T.ROLE_ASSIGNMENT, True, ("entra",),
     "Would remove role", "Remove a privileged directory role assignment", None),
    (_A.DELETE_EMAIL, _R, None, _T.EMAIL_MESSAGE, False, ("cisco_xdr", "defender_o365", "secure_email"),
     "Would delete email", "Delete an email message", None),
    (_A.TERMINATE_PROCESS, _R, None, _T.PROCESS, False, ("defender_endpoint", "secure_endpoint"),
     "Would terminate process", "Terminate a process on an endpoint", None),
    (_A.QUARANTINE_FILE, _R, _A.RESTORE_FILE, _T.FILE, False, ("defender_endpoint", "secure_endpoint"),
     "Would quarantine file", "Quarantine a file on an endpoint", None),
    (_A.REMOVE_PERSISTENCE, _R, None, _T.PERSISTENCE_ITEM, False, (), "Would remove persistence",
     "Remove a persistence mechanism (no verified integration)", None),
    (_A.RESET_PASSWORD, _R, None, _T.USER, False, ("entra",), "Would reset password",
     "Reset a user's password", None),
    (_A.RESET_MFA, _R, None, _T.USER, False, ("entra",), "Would reset MFA",
     "Reset a user's MFA registrations", None),
    (_A.REVOKE_APP_CREDENTIALS, _R, None, _T.CREDENTIAL, False, ("entra",), "Would revoke credentials",
     "Revoke application credentials", None),
    (_A.REMOVE_APPLICATION, _R, None, _T.APPLICATION, False, ("intune", "defender_endpoint"),
     "Would remove application", "Remove an application from managed devices", None),
    # restoration
    (_A.RELEASE_ENDPOINT, _X, None, _T.ENDPOINT, False, _EDR, "Would release endpoint",
     "Release an endpoint from isolation", None),
    (_A.UNBLOCK_DOMAIN, _X, None, _T.DOMAIN, False, _DNS, "Would unblock",
     "Remove a temporary domain block", None),
    (_A.UNBLOCK_URL, _X, None, _T.URL, False, _DNS, "Would unblock",
     "Remove a temporary URL block", None),
    (_A.UNBLOCK_IP, _X, None, _T.IP, False, _NET, "Would unblock",
     "Remove a temporary IP block", None),
    (_A.UNBLOCK_HASH, _X, None, _T.HASH, False, _EDR, "Would unblock",
     "Remove a temporary hash block", None),
    (_A.ENABLE_USER, _X, None, _T.USER, False, _IDP, "Would re-enable user",
     "Re-enable a disabled user account", None),
    (_A.RELEASE_EMAIL, _X, None, _T.EMAIL_MESSAGE, False, _MAIL, "Would release email",
     "Release an email message from quarantine", None),
    (_A.RESTORE_NETWORK_CLIENT, _X, None, _T.NETWORK_CLIENT, False, ("meraki",),
     "Would restore network client", "Restore a network client's previous policy", None),
    (_A.RESTORE_PRIVILEGED_ROLE, _X, None, _T.ROLE_ASSIGNMENT, True, ("entra",), "Would restore role",
     "Restore a removed privileged role assignment", None),
    (_A.RESTORE_FILE, _X, None, _T.FILE, False, ("defender_endpoint", "secure_endpoint"),
     "Would restore file", "Restore a quarantined file", None),
)

_INTEL = ("cisco_xdr", "virustotal", "alienvault_otx")
_HUNT = ("cisco_xdr", "defender_endpoint", "microsoft_cloud", "splunk")

# (type, category, target kind, integrations, description, spec_ref)
_READ_ROWS: tuple[tuple, ...] = (
    (_A.ENRICH_IP, _E, _T.IP, _INTEL, "Enrich an IP address", "atomic/enrich-ip"),
    (_A.ENRICH_DOMAIN, _E, _T.DOMAIN, _INTEL + ("umbrella", "secure_malware_analytics"),
     "Enrich a domain", "atomic/enrich-domain"),
    (_A.ENRICH_URL, _E, _T.URL, _INTEL, "Enrich a URL", None),
    (_A.ENRICH_HASH, _E, _T.HASH, _INTEL + ("secure_malware_analytics",), "Enrich a file hash",
     "atomic/enrich-hash"),
    (_A.ENRICH_EMAIL_ADDRESS, _E, _T.EMAIL_ADDRESS, ("cisco_xdr", "hibp"), "Enrich an email address", None),
    (_A.ENRICH_USER, _E, _T.USER, ("cisco_xdr", "entra"), "Enrich a user", None),
    (_A.ENRICH_ENDPOINT, _E, _T.ENDPOINT, ("cisco_xdr", "defender_endpoint", "secure_endpoint", "intune"),
     "Enrich an endpoint", None),
    (_A.INVESTIGATE_USER, _I, _T.USER, ("cisco_xdr", "entra", "microsoft_cloud", "splunk"),
     "Investigate a user", "atomic/investigate-user"),
    (_A.INVESTIGATE_ENDPOINT, _I, _T.ENDPOINT,
     ("cisco_xdr", "secure_endpoint", "defender_endpoint", "intune", "microsoft_cloud", "splunk"),
     "Investigate an endpoint", "atomic/investigate-host"),
    (_A.INVESTIGATE_IP, _I, _T.IP, ("cisco_xdr", "microsoft_cloud", "splunk"), "Investigate an IP", None),
    (_A.INVESTIGATE_DOMAIN, _I, _T.DOMAIN, ("cisco_xdr", "microsoft_cloud", "splunk"),
     "Investigate a domain", None),
    (_A.INVESTIGATE_HASH, _I, _T.HASH,
     ("cisco_xdr", "secure_endpoint", "defender_endpoint", "microsoft_cloud", "splunk"),
     "Investigate a file hash", None),
    (_A.INVESTIGATE_EMAIL, _I, _T.EMAIL_MESSAGE, ("cisco_xdr", "secure_email", "microsoft_cloud", "splunk"),
     "Investigate an email message", None),
    (_A.INVESTIGATE_AUTHENTICATION, _I, _T.USER, ("entra", "microsoft_cloud", "splunk"),
     "Investigate authentication activity", None),
    (_A.INVESTIGATE_PROCESS, _I, _T.PROCESS, ("secure_endpoint", "defender_endpoint", "microsoft_cloud", "splunk"),
     "Investigate a process", None),
    (_A.INVESTIGATE_NETWORK_CONNECTION, _I, _T.IP, _HUNT, "Investigate network connections", None),
    (_A.SEARCH_HASH_ENTERPRISE, _I, _T.HASH,
     ("cisco_xdr", "secure_endpoint", "defender_endpoint", "microsoft_cloud", "splunk"),
     "Search the enterprise for a hash", None),
    (_A.SEARCH_DOMAIN_ENTERPRISE, _I, _T.DOMAIN, _HUNT, "Search the enterprise for a domain", None),
    (_A.SEARCH_IP_ENTERPRISE, _I, _T.IP, _HUNT, "Search the enterprise for an IP", None),
    (_A.SEARCH_USER_ACTIVITY, _I, _T.USER, ("entra", "microsoft_cloud", "splunk"), "Search user activity", None),
    (_A.SEARCH_EMAIL_CAMPAIGN, _I, _T.EMAIL_MESSAGE, ("secure_email", "microsoft_cloud", "splunk"),
     "Search for related campaign messages", None),
    (_A.SEARCH_RELATED_ENDPOINTS, _I, _T.ENDPOINT,
     ("cisco_xdr", "secure_endpoint", "defender_endpoint", "splunk"), "Search related endpoints", None),
    (_A.SEARCH_RELATED_USERS, _I, _T.USER, ("cisco_xdr", "entra", "splunk"), "Search related users", None),
    (_A.ADD_INCIDENT_NOTE, _B, _T.INCIDENT, ("cisco_xdr",), "Add a note to the incident", None),
    (_A.UPDATE_INCIDENT_STATUS, _B, _T.INCIDENT, ("cisco_xdr",), "Update the incident status", None),
    (_A.CREATE_TICKET, _B, _T.INCIDENT, ("cisco_xdr",), "Create a ticket", "atomic/create-ticket"),
    (_A.NOTIFY_SOC, _B, _T.INCIDENT, ("cisco_xdr",), "Notify the SOC", "atomic/notify-soc"),
)


def _build() -> Mapping[ActionType, ActionSpec]:
    specs: dict[ActionType, ActionSpec] = {}
    for at, cat, rb, tk, elevated, integ, verb, desc, ref in _WRITE_ROWS:
        purpose = ApprovalPurpose.RELEASE if cat is _X else ApprovalPurpose.CONTAINMENT
        specs[at] = ActionSpec(
            action_type=at, category=cat, state_changing=True, reversible=rb is not None,
            rollback_action_type=rb, target_kind=tk, purpose=purpose, always_elevated=elevated,
            creates_control=(rb is not None and cat is not _X), integrations=integ,
            dry_run_verb=verb, description=desc, spec_ref=ref,
        )
    for at, cat, tk, integ, desc, ref in _READ_ROWS:
        specs[at] = ActionSpec(
            action_type=at, category=cat, state_changing=False, reversible=False,
            rollback_action_type=None, target_kind=tk, purpose=None, integrations=integ,
            dry_run_verb="", description=desc, spec_ref=ref,
        )
    missing = set(ActionType) - set(specs)
    if missing:  # pragma: no cover - guarded by unit tests
        raise RuntimeError(f"catalog incomplete: {sorted(missing)}")
    return MappingProxyType(specs)


ACTION_CATALOG: Mapping[ActionType, ActionSpec] = _build()


def get_action_spec(action_type: ActionType | str) -> ActionSpec:
    """Spec for an action type. Unknown values raise KeyError."""
    try:
        at = ActionType(action_type)
    except ValueError as exc:
        raise KeyError(f"unknown action type: {action_type!r}") from exc
    return ACTION_CATALOG[at]


def is_state_changing(action_type: ActionType | str) -> bool:
    return get_action_spec(action_type).state_changing


def purpose_for(action_type: ActionType | str) -> ApprovalPurpose:
    spec = get_action_spec(action_type)
    if spec.purpose is None:
        raise ValueError(f"{spec.action_type.value} is not state-changing and has no approval purpose")
    return spec.purpose


def rollback_for(action_type: ActionType | str) -> ActionType | None:
    return get_action_spec(action_type).rollback_action_type
