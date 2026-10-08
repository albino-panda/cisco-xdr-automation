"""Evidence builder (architecture 14.1.6): evidence cites known records only, deterministically."""
from __future__ import annotations

import pytest

from xdr_response.atomics.evidence import (
    SUMMARY_MAX_CHARS,
    EvidenceBuilder,
    EvidenceError,
    RecordIndex,
    evidence_draft,
    evidence_summary,
)
from xdr_response.atomics.records import (
    AnomalyRecord,
    DetectionRecord,
    EndpointRecord,
    EnrichmentRecord,
    GenericRecord,
    SignInRecord,
)
from xdr_response.models import Evidence, EvidenceDraft, Severity, Verdict, number_evidence

from tests.unit.atomics.evidence._factories import HASH_A, HOST_1, USER_1, at, obs, record, result


def _detection(name: str = "Ransomware.Generic", minutes: int = 0, **extra):
    return record(DetectionRecord, name=name, verdict=Verdict.MALICIOUS, severity=Severity.HIGH,
                  endpoint=HOST_1, sha256=HASH_A, detection_id=f"det-{name}-{minutes}",
                  observed_at=at(minutes), **extra)


def _endpoint(**extra):
    return record(EndpointRecord, hostname=HOST_1, os="Windows 11", isolation_state="not_isolated",
                  connector_guid="00000000-0000-4000-8000-000000000001", observed_at=at(1), **extra)


def _sign_in(minutes: int = 0):
    return record(SignInRecord, integration="entra", atomic="investigate_user", subject=obs("user", USER_1),
                  user=USER_1, timestamp=at(minutes), ip="198.51.100.7", country="NL", app="Office 365",
                  result="success", mfa_result="satisfied", sign_in_id=f"si-{minutes}")


# ----------------------------------------------------------------------------------------- RecordIndex


def test_index_collects_results_and_extra_records_in_first_seen_order():
    det, ep, si = _detection(), _endpoint(), _sign_in()
    index = RecordIndex([result(det, ep)], records=[si])
    assert index.ids() == (det.record_id, ep.record_id, si.record_id)
    assert len(index) == 3
    assert det.record_id in index and "rec_unknown" not in index and 42 not in index
    assert index.get(ep.record_id) is ep


def test_index_accepts_identical_duplicates_once():
    det = _detection()
    index = RecordIndex([result(det), result(det)], records=[det])
    assert index.ids() == (det.record_id,)


def test_index_rejects_same_id_with_different_content():
    det = _detection()
    tampered = det.model_copy(update={"name": "Benign.Tool"})  # same record_id, other content
    with pytest.raises(EvidenceError, match="different content"):
        RecordIndex(records=[det, tampered])


def test_index_rejects_objects_that_are_not_records():
    with pytest.raises(EvidenceError, match="only normalized records"):
        RecordIndex(records=[{"record_id": "rec_x", "summary": "made up"}])


def test_index_requires_anomaly_related_ids_to_resolve():
    si = _sign_in()
    anomaly = record(AnomalyRecord, integration="entra", atomic="investigate_user", subject=obs("user", USER_1),
                     anomaly_type="impossible_travel", severity=Severity.HIGH, user=USER_1,
                     anomaly_id="an-1", related_record_ids=(si.record_id,))
    assert len(RecordIndex(records=[si, anomaly])) == 2
    with pytest.raises(EvidenceError, match="unknown record ids"):
        RecordIndex(records=[anomaly])


def test_require_names_unknown_ids_and_get_raises_key_error():
    det = _detection()
    index = RecordIndex(records=[det])
    assert index.require([det.record_id]) == (det,)
    with pytest.raises(EvidenceError, match="rec_missing"):
        index.require([det.record_id, "rec_missing"])
    with pytest.raises(KeyError):
        index.get("rec_missing")


# ----------------------------------------------------------------------------------------- cite


def test_cite_builds_one_draft_per_known_record_ordered_and_deduplicated():
    late, early = _detection("Late", minutes=30), _detection("Early", minutes=5)
    builder = EvidenceBuilder(RecordIndex(records=[late, early]))
    drafts = builder.cite([late.record_id, early.record_id, late.record_id])
    assert [d.data["record_id"] for d in drafts] == [early.record_id, late.record_id]
    assert drafts == builder.cite([early.record_id, late.record_id])  # deterministic


def test_cite_orders_records_without_time_first_then_by_id():
    timed = _detection(minutes=5)
    untimed_a = record(GenericRecord, name="secure_endpoint:investigate_endpoint", attributes={"k": "a"})
    untimed_b = record(GenericRecord, name="secure_endpoint:investigate_endpoint", attributes={"k": "b"})
    builder = EvidenceBuilder(RecordIndex(records=[timed, untimed_a, untimed_b]))
    drafts = builder.cite([timed.record_id, untimed_b.record_id, untimed_a.record_id])
    expected_untimed = sorted([untimed_a.record_id, untimed_b.record_id])
    assert [d.data["record_id"] for d in drafts] == [*expected_untimed, timed.record_id]


@pytest.mark.parametrize("ids", [[], ()])
def test_cite_refuses_empty_evidence(ids):
    with pytest.raises(EvidenceError, match="at least one record"):
        EvidenceBuilder(RecordIndex(records=[_detection()])).cite(ids)


def test_cite_refuses_unknown_ids_so_evidence_cannot_be_invented():
    det = _detection()
    builder = EvidenceBuilder(RecordIndex(records=[det]))
    with pytest.raises(EvidenceError, match="unknown record ids"):
        builder.cite([det.record_id, "rec_" + "0" * 32])


def test_cite_refuses_a_bare_string_and_non_string_ids():
    det = _detection()
    builder = EvidenceBuilder(RecordIndex(records=[det]))
    with pytest.raises(EvidenceError, match="not a single string"):
        builder.cite(det.record_id)
    with pytest.raises(EvidenceError, match="non-empty strings"):
        builder.cite([det.record_id, None])  # type: ignore[list-item]


def test_builder_requires_a_record_index():
    with pytest.raises(TypeError):
        EvidenceBuilder([_detection()])  # type: ignore[arg-type]


# ----------------------------------------------------------------------------------------- drafts


def test_draft_carries_source_record_id_and_evidence_fields():
    det = _detection(reference="det-console-ref-1")
    draft = evidence_draft(det)
    assert draft.source == "secure_endpoint"
    assert draft.observed_at == det.observed_at
    assert draft.reference == "det-console-ref-1"
    assert draft.data["record_id"] == det.record_id
    assert draft.data["kind"] == "detection"
    assert draft.data["atomic"] == "investigate_endpoint"
    fields = draft.data["fields"]
    assert fields["name"] == "Ransomware.Generic"
    assert fields["verdict"] == "MALICIOUS" and fields["severity"] == "HIGH"
    assert fields["endpoint"] == HOST_1 and fields["sha256"] == HASH_A
    assert draft.audit_ref is None


def test_draft_fields_are_json_mode():
    si = _sign_in(minutes=3)
    fields = evidence_draft(si).data["fields"]
    assert isinstance(fields["timestamp"], str) and fields["timestamp"].endswith("Z")
    assert evidence_draft(si) == evidence_draft(si)


def test_draft_refuses_non_records():
    with pytest.raises(EvidenceError):
        evidence_draft({"record_id": "rec_x"})  # type: ignore[arg-type]


# ----------------------------------------------------------------------------------------- summaries


def test_summary_templates_for_common_kinds():
    assert evidence_summary(_detection()) == (
        "secure_endpoint: HIGH detection 'Ransomware.Generic' (MALICIOUS) on TH-LT-1047")
    assert evidence_summary(_endpoint()) == (
        "secure_endpoint: endpoint TH-LT-1047 (Windows 11), isolation not_isolated")
    assert evidence_summary(_sign_in(minutes=5)) == (
        "entra: sign-in success for jsmith@example.com from 198.51.100.7 (NL) to Office 365 at "
        "2026-10-08T09:05:00Z, MFA satisfied")


def test_summary_shortens_hashes_and_writes_unknown_for_missing_values():
    enrichment = record(EnrichmentRecord, integration="virustotal", atomic="enrich_hash",
                        subject=obs("sha256", HASH_A), verdict=Verdict.MALICIOUS, risk_score=90, confidence=80)
    assert evidence_summary(enrichment) == (
        f"virustotal rates {HASH_A[:12]}... MALICIOUS (risk 90, confidence 80)")
    bare = record(DetectionRecord, name="Generic", verdict=Verdict.SUSPICIOUS, severity=Severity.LOW,
                  detection_id="det-bare")
    assert evidence_summary(bare) == "secure_endpoint: LOW detection 'Generic' (SUSPICIOUS) on unknown"


def test_generic_summary_lists_three_sorted_attributes():
    rec = record(GenericRecord, name="splunk:investigate_endpoint",
                 attributes={"zeta": 1, "alpha": "x", "beta": True, "gamma": None})
    assert evidence_summary(rec) == "secure_endpoint: splunk:investigate_endpoint (alpha=x, beta=true, gamma=unknown)"


def test_summary_is_capped_and_redacted():
    long_name = "Trojan." + "X" * 400
    rec = _detection(name=long_name)
    text = evidence_summary(rec)
    assert len(text) == SUMMARY_MAX_CHARS and text.endswith("...")
    secret = record(GenericRecord, name="splunk:search", attributes={"note": "password=hunter2-fake"})
    assert "hunter2" not in evidence_summary(secret)


# ----------------------------------------------------------------------------------------- verify


def test_verify_accepts_cited_drafts_and_numbered_package_evidence():
    det, ep = _detection(), _endpoint()
    builder = EvidenceBuilder(RecordIndex(records=[det, ep]))
    drafts = builder.cite([det.record_id, ep.record_id])
    builder.verify(drafts)
    numbered = number_evidence(drafts)
    assert all(isinstance(e, Evidence) for e in numbered)
    builder.verify(numbered)
    roundtrip = [EvidenceDraft.model_validate_json(d.model_dump_json()) for d in drafts]
    builder.verify(roundtrip)


def test_verify_rejects_edited_summary_fields_and_unknown_records():
    det = _detection()
    builder = EvidenceBuilder(RecordIndex(records=[det]))
    (draft,) = builder.cite([det.record_id])
    with pytest.raises(EvidenceError, match="does not match"):
        builder.verify([draft.model_copy(update={"summary": "analyst-free text claim"})])
    edited = {**draft.data, "fields": {**draft.data["fields"], "verdict": "CLEAN"}}
    with pytest.raises(EvidenceError, match="does not match"):
        builder.verify([draft.model_copy(update={"data": edited})])
    with pytest.raises(EvidenceError, match="does not cite a record"):
        builder.verify([EvidenceDraft(source="secure_endpoint", summary="made up", data={})])
    with pytest.raises(EvidenceError, match="does not cite a record"):
        builder.verify([draft.model_copy(update={"data": {**draft.data, "record_id": "rec_other"}})])


def test_record_ids_maps_drafts_back_to_records():
    det, ep = _detection(), _endpoint()
    drafts = EvidenceBuilder(RecordIndex(records=[det, ep])).cite([ep.record_id, det.record_id])
    assert EvidenceBuilder.record_ids([*drafts, drafts[0]]) == tuple(d.data["record_id"] for d in drafts)
    with pytest.raises(EvidenceError):
        EvidenceBuilder.record_ids([EvidenceDraft(source="analyst", summary="note")])
