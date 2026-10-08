"""Every record kind has a deterministic, capped evidence summary and a verifiable draft (14.1.6)."""
from __future__ import annotations

import pytest

from xdr_response.atomics.evidence import SUMMARY_MAX_CHARS, EvidenceBuilder, RecordIndex, evidence_summary
from xdr_response.atomics.records import (
    RECORD_TYPES,
    AnomalyRecord,
    CloudAppRecord,
    DetectionRecord,
    DnsQueryRecord,
    EmailMessageRecord,
    EndpointRecord,
    EnrichmentRecord,
    GenericRecord,
    HashPrevalenceRecord,
    MailboxRuleRecord,
    MfaEventRecord,
    NetworkConnectionRecord,
    PersistenceItemRecord,
    ProcessEventRecord,
    RoleChangeRecord,
    SignInRecord,
    UserProfileRecord,
)
from xdr_response.models import Severity, Verdict

from tests.unit.atomics.evidence._factories import EVIL_DOMAIN, EVIL_IP, HASH_A, HOST_1, USER_1, at, obs, record

MINIMAL = {
    EnrichmentRecord: ({"integration": "umbrella", "atomic": "enrich_domain", "subject": obs("domain", EVIL_DOMAIN)},
                       {"verdict": Verdict.SUSPICIOUS, "risk_score": 60, "confidence": 70},
                       "umbrella rates login-portal.example SUSPICIOUS (risk 60, confidence 70)"),
    EndpointRecord: ({}, {"hostname": HOST_1}, "secure_endpoint: endpoint TH-LT-1047 (unknown), isolation unknown"),
    DetectionRecord: ({}, {"name": "Trojan.Fake", "verdict": Verdict.MALICIOUS, "severity": Severity.CRITICAL},
                      "secure_endpoint: CRITICAL detection 'Trojan.Fake' (MALICIOUS) on unknown"),
    ProcessEventRecord: ({}, {"endpoint": HOST_1, "timestamp": at(2), "event_type": "file_rename", "count": 1204},
                         "secure_endpoint: file_rename unknown on TH-LT-1047 at 2026-10-08T09:02:00Z (x1204)"),
    NetworkConnectionRecord: ({}, {"user": USER_1, "remote_ip": EVIL_IP, "remote_port": 443,
                                   "direction": "outbound", "action": "blocked"},
                              "secure_endpoint: jsmith@example.com outbound to 203.0.113.10:443 (blocked)"),
    DnsQueryRecord: ({}, {"client_ip": "192.0.2.15", "domain": EVIL_DOMAIN, "count": 14},
                     "secure_endpoint: 192.0.2.15 queried login-portal.example x14 (unknown)"),
    HashPrevalenceRecord: ({}, {"sha256": HASH_A, "prevalence": 3, "verdict": Verdict.MALICIOUS},
                           f"secure_endpoint: {HASH_A[:12]}... seen on 3 endpoint(s), MALICIOUS"),
    PersistenceItemRecord: ({}, {"endpoint": HOST_1, "item_id": "task-7", "mechanism": "scheduled_task",
                                 "name": "Updater"},
                            "secure_endpoint: scheduled_task 'Updater' on TH-LT-1047"),
    UserProfileRecord: ({"integration": "entra"}, {"user": USER_1, "risk_level": "high", "account_enabled": True},
                        "entra: user jsmith@example.com, risk high, enabled true, privileged false"),
    SignInRecord: ({"integration": "entra"}, {"user": USER_1, "timestamp": at(0), "result": "failure"},
                   "entra: sign-in failure for jsmith@example.com from unknown (unknown) to unknown at "
                   "2026-10-08T09:00:00Z, MFA unknown"),
    AnomalyRecord: ({"integration": "entra"}, {"anomaly_type": "mfa_fatigue", "severity": Severity.HIGH,
                                               "user": USER_1},
                    "entra: mfa_fatigue (HIGH) for jsmith@example.com"),
    MfaEventRecord: ({"integration": "entra"}, {"user": USER_1, "timestamp": at(1), "method": "push",
                                                "result": "denied"},
                     "entra: MFA push denied for jsmith@example.com at 2026-10-08T09:01:00Z"),
    MailboxRuleRecord: ({"integration": "microsoft_cloud"},
                        {"mailbox": USER_1, "rule_id": "r1", "name": "fwd", "forward_to": ("x@external.example",),
                         "external_forwarding": True},
                        "microsoft_cloud: mailbox rule 'fwd' on jsmith@example.com, forwards externally"),
    RoleChangeRecord: ({"integration": "entra"}, {"user": USER_1, "role_name": "Security Reader",
                                                  "change": "assigned"},
                       "entra: role Security Reader assigned for jsmith@example.com by unknown"),
    EmailMessageRecord: ({"integration": "secure_email"},
                         {"message_id": "msg-9@sender.example", "sender": "a@sender.example", "recipient_count": 4,
                          "verdict": Verdict.MALICIOUS, "delivery_location": "inbox"},
                         "secure_email: message msg-9@sender.example from a@sender.example to 4 recipient(s), "
                         "MALICIOUS, inbox"),
    CloudAppRecord: ({"integration": "entra"}, {"app_id": "app-1", "display_name": "Mail Helper",
                                                "consent_type": "user", "permissions": ("Mail.Read", "offline")},
                     "entra: app Mail Helper (app-1), consent user, 2 permission(s)"),
    GenericRecord: ({"integration": "splunk"}, {"name": "splunk:search_user_activity"},
                    "splunk: splunk:search_user_activity"),
}


def test_every_record_type_has_a_case():
    assert set(MINIMAL) == set(RECORD_TYPES.values())


@pytest.mark.parametrize("cls", list(MINIMAL), ids=lambda c: c.__name__)
def test_summary_template_and_draft_roundtrip(cls):
    base, fields, expected = MINIMAL[cls]
    rec = record(cls, **base, **fields)
    text = evidence_summary(rec)
    assert text == expected
    assert len(text) <= SUMMARY_MAX_CHARS
    assert evidence_summary(rec) == text  # deterministic
    builder = EvidenceBuilder(RecordIndex(records=[rec]))
    drafts = builder.cite([rec.record_id])
    builder.verify(drafts)
    assert drafts[0].source == rec.integration
