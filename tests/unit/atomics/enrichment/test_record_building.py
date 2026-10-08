"""Building an EnrichmentRecord from one source's EnrichmentResult (only reported facts are copied)."""
from __future__ import annotations

from datetime import datetime, timezone

from tests.unit.atomics.enrichment._support import FIXED_NOW
from xdr_response.atomics.enrichment._records import build_record, categories_of, first_seen_of
from xdr_response.models import EnrichmentResult, EvidenceDraft, Observable, ObservableType, Verdict

SUBJECT = Observable(type=ObservableType.DOMAIN, value="bad.example.test")


def _draft(summary: str = "rated malicious", *, reference: str | None = None, **data: object) -> EvidenceDraft:
    return EvidenceDraft(source="umbrella", summary=summary, observed_at=FIXED_NOW, reference=reference, data=data)


def _result(*evidence: EvidenceDraft, verdict: Verdict = Verdict.MALICIOUS) -> EnrichmentResult:
    return EnrichmentResult(type=SUBJECT.type, value=SUBJECT.value, risk_score=90, confidence=80,
                            sources=("umbrella",), verdict=verdict, integration="umbrella", evidence=evidence)


def test_categories_are_distinct_strings_in_first_seen_order_and_capped():
    drafts = [_draft(categories=["Malware", "Phishing"], security_categories=["Malware", 3, "", None]),
              _draft(content_categories=[f"Category {i}" for i in range(40)])]
    found = categories_of(drafts)
    assert found[:3] == ("Malware", "Phishing", "Category 0") and len(found) == 20


def test_categories_ignore_non_list_values():
    assert categories_of([_draft(categories="Malware"), _draft(categories={"a": 1})]) == ()


def test_first_seen_takes_the_earliest_aware_timestamp_only():
    drafts = [_draft(first_seen="2026-01-12T00:00:00Z"), _draft(first_seen="2026-01-10T00:00:00+00:00"),
              _draft(first_seen="2026-01-01T00:00:00"), _draft(first_seen="yesterday"), _draft(first_seen=5)]
    assert first_seen_of(drafts) == datetime(2026, 1, 10, tzinfo=timezone.utc)
    assert first_seen_of([_draft()]) is None


def test_record_copies_only_what_the_source_reported():
    record = build_record("enrich_domain", SUBJECT, "umbrella",
                          _result(_draft("Umbrella status -1", reference="umbrella:domain:bad.example.test")))
    assert (record.verdict, record.risk_score, record.confidence) == (Verdict.MALICIOUS, 90, 80)
    assert record.detail == "Umbrella status -1" and record.reference == "umbrella:domain:bad.example.test"
    assert record.observed_at == FIXED_NOW and record.categories == () and record.first_seen is None


def test_record_without_evidence_has_no_detail_time_or_reference():
    record = build_record("enrich_domain", SUBJECT, "umbrella", _result(verdict=Verdict.CLEAN))
    assert (record.detail, record.observed_at, record.reference) == ("", None, None)


def test_references_that_would_need_redaction_are_dropped():
    secret_ref = "https://console.example.test/x?api_key=fake-secret-value-123"
    record = build_record("enrich_domain", SUBJECT, "umbrella", _result(_draft(reference=secret_ref)))
    assert record.reference is None


def test_detail_is_redacted():
    record = build_record("enrich_domain", SUBJECT, "umbrella",
                          _result(_draft("lookup ok, password=fake-secret-value-123")))
    assert "fake-secret-value-123" not in record.detail
