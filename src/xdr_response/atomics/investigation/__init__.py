"""Investigation and enterprise search atomics (architecture 14.1.4).

Read-only: every atomic reaches the adapters only through ``AtomicContext.adapters``
(``ReadOnlyAdapters``) and returns an :class:`~xdr_response.atomics.records.InvestigationBundle`.
"""
from __future__ import annotations

from xdr_response.atomics.investigation.atomics import (
    INVESTIGATION_ATOMICS,
    INVESTIGATION_SUBJECT_TYPES,
    InvestigationAtomic,
    investigate_authentication,
    investigate_domain,
    investigate_email,
    investigate_endpoint,
    investigate_hash,
    investigate_ip,
    investigate_network_connection,
    investigate_process,
    investigate_user,
    search_domain_enterprise,
    search_email_campaign,
    search_hash_enterprise,
    search_ip_enterprise,
    search_related_endpoints,
    search_related_users,
    search_user_activity,
)
from xdr_response.atomics.investigation.normalize import (
    NORMALIZERS,
    TYPED_RECORD_KEY,
    NormalizeContext,
    Normalizer,
    normalize,
)

__all__ = [
    "INVESTIGATION_ATOMICS",
    "INVESTIGATION_SUBJECT_TYPES",
    "InvestigationAtomic",
    "investigate_authentication",
    "investigate_domain",
    "investigate_email",
    "investigate_endpoint",
    "investigate_hash",
    "investigate_ip",
    "investigate_network_connection",
    "investigate_process",
    "investigate_user",
    "search_domain_enterprise",
    "search_email_campaign",
    "search_hash_enterprise",
    "search_ip_enterprise",
    "search_related_endpoints",
    "search_related_users",
    "search_user_activity",
    "NORMALIZERS",
    "TYPED_RECORD_KEY",
    "NormalizeContext",
    "Normalizer",
    "normalize",
]
