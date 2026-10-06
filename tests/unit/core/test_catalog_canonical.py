"""Action catalog invariants and canonical JSON / hashing / normalization."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from xdr_response.models import (
    ACTION_CATALOG,
    BOOKKEEPING_OPERATIONS,
    INTEGRATION_NAMES,
    ActionCategory,
    ActionType,
    ApprovalPurpose,
    IncidentState,
    TargetKind,
    canonical_json,
    get_action_spec,
    is_state_changing,
    make_idempotency_key,
    normalize_target,
    params_hash,
    purpose_for,
    rollback_for,
    sha256_hex,
)

STATE_CHANGING = {ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION, ActionCategory.RESTORATION}


# ------------------------------------------------------------------ catalog --
def test_catalog_has_one_entry_per_action_type():
    assert set(ACTION_CATALOG) == set(ActionType)
    for at, spec in ACTION_CATALOG.items():
        assert spec.action_type is at
        assert at.value == at.name.lower()


def test_catalog_is_read_only():
    with pytest.raises(TypeError):
        ACTION_CATALOG[ActionType.ISOLATE_ENDPOINT] = ACTION_CATALOG[ActionType.BLOCK_IP]  # type: ignore[index]


def test_state_changing_exactly_for_write_categories():
    for spec in ACTION_CATALOG.values():
        assert spec.state_changing == (spec.category in STATE_CHANGING), spec.action_type


def test_purposes_follow_category():
    for spec in ACTION_CATALOG.values():
        if spec.category in (ActionCategory.CONTAINMENT, ActionCategory.REMEDIATION):
            assert spec.purpose is ApprovalPurpose.CONTAINMENT
        elif spec.category is ActionCategory.RESTORATION:
            assert spec.purpose is ApprovalPurpose.RELEASE
        else:
            assert spec.purpose is None
            assert spec.dry_run_verb == ""


def test_reversible_actions_roll_back_to_restoration_of_same_target_kind():
    for spec in ACTION_CATALOG.values():
        if spec.reversible:
            rb = get_action_spec(spec.rollback_action_type)
            assert rb.category is ActionCategory.RESTORATION
            assert rb.target_kind is spec.target_kind
            assert spec.creates_control is True
        else:
            assert spec.rollback_action_type is None
            assert spec.creates_control is False


def test_every_restoration_type_is_a_rollback():
    rollbacks = {s.rollback_action_type for s in ACTION_CATALOG.values() if s.rollback_action_type}
    for spec in ACTION_CATALOG.values():
        if spec.category is ActionCategory.RESTORATION:
            assert spec.action_type in rollbacks
            assert spec.reversible is False and spec.creates_control is False


def test_read_and_bookkeeping_types_never_state_changing():
    for spec in ACTION_CATALOG.values():
        if spec.category in (ActionCategory.ENRICHMENT, ActionCategory.INVESTIGATION, ActionCategory.BOOKKEEPING):
            assert not is_state_changing(spec.action_type)
    assert BOOKKEEPING_OPERATIONS == {
        "add_incident_note", "update_incident_status", "create_ticket", "notify_soc", "forward_audit"
    }


def test_privileged_role_actions_always_elevated():
    elevated = {s.action_type for s in ACTION_CATALOG.values() if s.always_elevated}
    assert elevated == {ActionType.REMOVE_PRIVILEGED_ROLE, ActionType.RESTORE_PRIVILEGED_ROLE}


def test_catalog_rows_from_contract():
    iso = get_action_spec("isolate_endpoint")
    assert iso.integrations == ("cisco_xdr", "defender_endpoint", "secure_endpoint")
    assert iso.dry_run_verb == "Would isolate" and iso.spec_ref == "atomic/isolate-endpoint"
    assert rollback_for(ActionType.BLOCK_DOMAIN) is ActionType.UNBLOCK_DOMAIN
    assert rollback_for(ActionType.REVOKE_SESSIONS) is None
    assert get_action_spec(ActionType.REMOVE_PERSISTENCE).integrations == ()
    assert get_action_spec(ActionType.DELETE_EMAIL).integrations[0] == "cisco_xdr"
    for spec in ACTION_CATALOG.values():
        assert set(spec.integrations) <= set(INTEGRATION_NAMES)


def test_lookup_errors():
    with pytest.raises(KeyError):
        get_action_spec("format_c_drive")
    with pytest.raises(ValueError):
        purpose_for(ActionType.ENRICH_IP)
    assert purpose_for("release_endpoint") is ApprovalPurpose.RELEASE
    assert purpose_for(ActionType.DELETE_EMAIL) is ApprovalPurpose.CONTAINMENT


def test_integration_names_contract():
    assert len(INTEGRATION_NAMES) == 16 and "splunk" in INTEGRATION_NAMES


# ---------------------------------------------------------------- canonical --
def test_canonical_json_sorted_compact_utf8():
    out = canonical_json({"b": 1, "a": ["x", "é"], "c": None})
    assert out == '{"a":["x","é"],"b":1,"c":null}'.encode("utf-8")


def test_canonical_json_datetime_enum_tuple_set():
    dt = datetime(2026, 1, 15, 13, 0, tzinfo=timezone(timedelta(hours=1)))
    out = json.loads(canonical_json({"t": dt, "s": IncidentState.CLOSED, "tup": (1, 2), "set": {"b", "a"}}))
    assert out == {"t": "2026-01-15T12:00:00.000000Z", "s": "CLOSED", "tup": [1, 2], "set": ["a", "b"]}


def test_canonical_json_rejects_naive_datetime_and_floats():
    with pytest.raises(ValueError):
        canonical_json({"t": datetime(2026, 1, 1)})
    with pytest.raises(ValueError):
        canonical_json({"f": 1.5})
    assert canonical_json({"f": 1.5}, allow_floats=True) == b'{"f":1.5}'
    with pytest.raises(ValueError):
        canonical_json({"f": float("nan")}, allow_floats=True)


def test_canonical_json_key_order_independent():
    assert canonical_json({"a": 1, "b": {"y": 2, "x": 1}}) == canonical_json({"b": {"x": 1, "y": 2}, "a": 1})


def test_sha256_and_params_hash():
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex(b"abc") == sha256_hex("abc")
    h1 = params_hash({"integration": "umbrella", "list": 1})
    h2 = params_hash({"list": 1, "integration": "umbrella"})
    assert h1 == h2 and len(h1) == 64 and h1 == h1.lower()
    assert params_hash({"integration": "umbrella", "list": 2}) != h1


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (TargetKind.DOMAIN, " Bad.Example.TEST. ", "bad.example.test"),
        (TargetKind.EMAIL_ADDRESS, "J.Doe@Example.com", "j.doe@example.com"),
        (TargetKind.USER, "J.Doe@Example.com", "j.doe@example.com"),
        (TargetKind.HASH, "A" * 64, "a" * 64),
        (TargetKind.IP, "2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        (TargetKind.IP, " 203.0.113.10 ", "203.0.113.10"),
        (TargetKind.ENDPOINT, "th-lt-1047", "TH-LT-1047"),
        (TargetKind.URL, " https://Bad.Example.test/Path ", "https://Bad.Example.test/Path"),
        (TargetKind.EMAIL_MESSAGE, "<Msg-1@example.com>", "<Msg-1@example.com>"),
    ],
)
def test_normalize_target(kind, value, expected):
    assert normalize_target(kind, value) == expected


def test_normalize_target_rejects_empty_and_bad_ip():
    with pytest.raises(ValueError):
        normalize_target(TargetKind.DOMAIN, "  ")
    with pytest.raises(ValueError):
        normalize_target(TargetKind.IP, "999.1.1.1")


def test_idempotency_key_format():
    assert make_idempotency_key("XDR-83921", ActionType.ISOLATE_ENDPOINT, "TH-LT-1047") == \
        "XDR-83921:isolate_endpoint:TH-LT-1047"
    assert make_idempotency_key("XDR-1", "block_ip", "192.0.2.1") == "XDR-1:block_ip:192.0.2.1"
    with pytest.raises(ValueError):
        make_idempotency_key("", ActionType.BLOCK_IP, "192.0.2.1")
