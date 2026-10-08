"""Correlation models (architecture 14.1.5): normalization, link ids, invariants."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from xdr_response.atomics.correlation import (
    BlastRadiusReport,
    CorrelationLink,
    CorrelationResult,
    CriticalAssetHit,
    EntityRef,
    LinkKind,
)
from xdr_response.models import BlastRadius, CriticalAssetClass, TargetKind
from xdr_response.models.canonical import canonical_json, sha256_hex

HOST = EntityRef(kind=TargetKind.ENDPOINT, value="th-lt-1047")
USER = EntityRef(kind=TargetKind.USER, value="JSmith@Example.com")
DOMAIN = EntityRef(kind=TargetKind.DOMAIN, value="Login-Portal.example.")


def _link(**overrides):
    data = {"kind": LinkKind.SAME_DOMAIN, "entities": [USER, DOMAIN, HOST], "record_ids": ["rec_b", "rec_a", "rec_b"],
            "note": "domain seen with 1 endpoint(s) and 1 user(s)"}
    return CorrelationLink(**{**data, **overrides})


def test_entity_ref_normalizes_value_for_its_kind():
    assert HOST.value == "TH-LT-1047"
    assert USER.value == "jsmith@example.com"
    assert DOMAIN.value == "login-portal.example"
    assert EntityRef(kind=TargetKind.IP, value=" 2001:db8:0:0::1 ").value == "2001:db8::1"
    assert HOST.key() == "ENDPOINT:TH-LT-1047"
    with pytest.raises(ValidationError):
        EntityRef(kind=TargetKind.IP, value="not-an-ip")


def test_link_sorts_entities_and_ids_and_derives_link_id():
    link = _link()
    assert link.entities == (DOMAIN, HOST, USER)
    assert link.record_ids == ("rec_a", "rec_b")
    expected = "lnk_" + sha256_hex(canonical_json([LinkKind.SAME_DOMAIN, list(link.entities), ["rec_a", "rec_b"]]))[:24]
    assert link.link_id == expected
    assert _link(entities=[HOST, DOMAIN, USER]).link_id == link.link_id
    assert _link(link_id=expected).link_id == expected


def test_link_rejects_wrong_id_too_few_entities_and_no_records():
    with pytest.raises(ValidationError, match="link_id"):
        _link(link_id="lnk_" + "0" * 24)
    with pytest.raises(ValidationError):
        _link(entities=[HOST, HOST])
    with pytest.raises(ValidationError):
        _link(record_ids=[])


def test_link_origin_and_kind_must_agree():
    assert _link(kind=LinkKind.WORKFLOW, origin="workflow:wf_test").origin == "workflow:wf_test"
    with pytest.raises(ValidationError):
        _link(kind=LinkKind.WORKFLOW)  # framework origin cannot claim a workflow link
    with pytest.raises(ValidationError):
        _link(origin="workflow:wf_test")  # a hook cannot pass off a framework link kind
    with pytest.raises(ValidationError):
        _link(kind=LinkKind.WORKFLOW, origin="ai")
    with pytest.raises(ValidationError):
        _link(kind=LinkKind.WORKFLOW, origin="workflow:")


def test_correlation_result_invariants_and_queries():
    link = _link()
    other = EntityRef(kind=TargetKind.HASH, value="a" * 64)
    result = CorrelationResult(incident_id="inc-1", entities=(DOMAIN, HOST, other, USER), links=(link,),
                               clusters=((DOMAIN, HOST, USER), (other,)))
    assert result.related(HOST) == (DOMAIN, USER)
    assert result.related(other) == ()
    assert result.links_for(USER) == (link,)
    assert result.links_for(other) == ()
    item = result.rule_item()
    assert set(item) == {"entities", "links", "clusters", "related"}
    assert item["related"]["ENDPOINT:TH-LT-1047"] == [{"kind": "DOMAIN", "value": "login-portal.example"},
                                                      {"kind": "USER", "value": "jsmith@example.com"}]
    assert item["links"][0]["link_id"] == link.link_id


def test_correlation_result_rejects_inconsistent_structures():
    link = _link()
    with pytest.raises(ValidationError, match="sorted"):
        CorrelationResult(incident_id="i", entities=(USER, HOST), clusters=((HOST,), (USER,)))
    with pytest.raises(ValidationError, match="link entity"):
        CorrelationResult(incident_id="i", entities=(DOMAIN, HOST), links=(link,), clusters=((DOMAIN, HOST),))
    with pytest.raises(ValidationError, match="partition"):
        CorrelationResult(incident_id="i", entities=(DOMAIN, HOST, USER), links=(link,), clusters=((DOMAIN, HOST),))


def test_blast_radius_report_validation_and_conversion():
    hit = CriticalAssetHit(entity=HOST, classes=(CriticalAssetClass.DOMAIN_CONTROLLER,), record_ids=("rec_a",))
    report = BlastRadiusReport(endpoints=("TH-LT-1047",), users=("jsmith@example.com",),
                               indicators=("login-portal.example",), messages=2, critical_assets=(hit,),
                               caps={"endpoints": 0, "users": 3, "indicators": 50, "messages": 500},
                               exceeds=("endpoints",), record_ids=("rec_a",))
    assert report.to_blast_radius() == BlastRadius(endpoints=("TH-LT-1047",), users=("jsmith@example.com",),
                                                   indicators=("login-portal.example",), messages=2)
    item = report.rule_item()
    assert item["endpoint_count"] == 1 and item["has_critical_asset"] is True
    assert item["critical_asset_classes"] == ["domain_controller"]
    with pytest.raises(ValidationError):
        BlastRadiusReport(caps={"hosts": 1})
    with pytest.raises(ValidationError):
        BlastRadiusReport(exceeds=("hosts",))
    with pytest.raises(ValidationError):
        BlastRadiusReport(endpoints=("B", "A"))
    with pytest.raises(ValidationError):
        CriticalAssetHit(entity=HOST, classes=())
