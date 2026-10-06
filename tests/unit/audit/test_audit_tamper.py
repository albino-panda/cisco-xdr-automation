"""Tampering (edit, delete, insert, reorder, duplicate, truncate, rewrite) is detected."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from xdr_response.audit import AuditAnchor, verify_chain, verify_records
from xdr_response.audit.hashing import compute_record_hash
from xdr_response.errors import AuditIntegrityError
from xdr_response.models import GENESIS_HASH, AuditEventType, canonical_json


def _lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


def _write(path: Path, lines: list[bytes]) -> None:
    path.write_bytes(b"".join(lines))


def _rehash(line: bytes, **changes: object) -> bytes:
    """Edit fields of a line and recompute its own hash (a careful attacker)."""
    data = json.loads(line)
    data.update(changes)
    data["hash"] = compute_record_hash(data)
    return canonical_json(data, allow_floats=True) + b"\n"


@pytest.fixture
def chain(make_trail, fill, audit_path) -> Path:
    fill(make_trail(), 6)
    assert verify_chain(audit_path).ok
    return audit_path


# ------------------------------------------------------------------ files ---
def test_intact_chain_reports_count_and_head(chain):
    result = verify_chain(chain)
    assert result.ok and result.records == 6 and result.first_bad_seq is None
    assert result.head_hash == json.loads(_lines(chain)[-1])["hash"]


def test_modification_detected(chain):
    lines = _lines(chain)
    lines[2] = lines[2].replace(b'"index":2', b'"index":9')
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok
    assert result.first_bad_seq == 2 and result.records == 2
    assert "modified" in result.reason


def test_modification_of_actor_detected(chain):
    lines = _lines(chain)
    lines[1] = lines[1].replace(b'"actor":"automation:test"', b'"actor":"analyst.one@example.com"')
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 1


def test_modification_with_recomputed_hash_breaks_next_link(chain):
    lines = _lines(chain)
    payload = json.loads(lines[3])["payload"] | {"index": 99}
    lines[3] = _rehash(lines[3], payload=payload)
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 4
    assert "prev_hash" in result.reason


def test_deletion_in_the_middle_detected(chain):
    lines = _lines(chain)
    del lines[2]
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 2
    assert "deleted, duplicated or reordered" in result.reason


def test_deletion_of_first_record_detected(chain):
    _write(chain, _lines(chain)[1:])
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 0


def test_deletion_with_renumbering_detected(chain):
    lines = _lines(chain)
    del lines[2]
    # attacker renumbers the following records and recomputes their own hashes
    lines = lines[:2] + [_rehash(line, seq=i) for i, line in enumerate(lines[2:], start=2)]
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 2 and "prev_hash" in result.reason


def test_reordering_detected(chain):
    lines = _lines(chain)
    lines[1], lines[4] = lines[4], lines[1]
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 1


def test_duplicated_record_detected(chain):
    lines = _lines(chain)
    lines.insert(3, lines[2])
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 3


def test_inserted_forged_record_detected(chain):
    lines = _lines(chain)
    forged = _rehash(lines[2], seq=3, prev_hash=json.loads(lines[2])["hash"],
                     payload={"index": "forged"})
    lines.insert(3, forged)
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 4  # the forged record chains, the next does not


def test_truncated_partial_last_line_detected(chain):
    data = chain.read_bytes()
    chain.write_bytes(data[:-25])
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 5
    assert "truncated" in result.reason or "not a valid" in result.reason


def test_missing_trailing_newline_detected(chain):
    chain.write_bytes(chain.read_bytes()[:-1])
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 5 and "incomplete" in result.reason


def test_truncation_of_whole_records_detected_with_anchor(chain):
    anchor = AuditAnchor(seq=5, hash=json.loads(_lines(chain)[5])["hash"])
    _write(chain, _lines(chain)[:4])
    assert verify_chain(chain).ok  # a clean cut is invisible without an external anchor...
    result = verify_chain(chain, anchors=[anchor])
    assert not result.ok and result.first_bad_seq == 4  # ...and detected with one
    assert "truncated" in result.reason


def test_truncation_to_empty_detected_with_anchor(chain):
    anchor = AuditAnchor(seq=0, hash=json.loads(_lines(chain)[0])["hash"])
    chain.write_bytes(b"")
    result = verify_chain(chain, anchors=[anchor])
    assert not result.ok and result.first_bad_seq == 0


def test_full_rewrite_detected_with_anchor(chain, tmp_path, make_trail, fill, ids):
    anchor = AuditAnchor(seq=5, hash=json.loads(_lines(chain)[5])["hash"])
    forged_path = tmp_path / "forged.jsonl"
    forged = make_trail(forged_path, id_factory=ids("forged"))
    fill(forged, 6, incident_id="XDR-OTHER")
    chain.write_bytes(forged_path.read_bytes())
    assert verify_chain(chain).ok
    result = verify_chain(chain, anchors=[anchor])
    assert not result.ok and result.first_bad_seq == 5 and "anchor" in result.reason


def test_matching_anchor_passes(chain):
    hashes = [json.loads(line)["hash"] for line in _lines(chain)]
    anchors = [AuditAnchor(seq=i, hash=h) for i, h in enumerate(hashes)]
    assert verify_chain(chain, anchors=anchors).ok


@pytest.mark.parametrize("garbage", [b"\n", b"not json\n", b"[1,2]\n", b'{"seq": 6}\n',
                                     b'{"seq":6,"x":NaN}\n', b"\xff\xfe\n"])
def test_garbage_lines_detected(chain, garbage):
    _write(chain, _lines(chain) + [garbage])
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 6 and result.records == 6


def test_extra_field_detected(chain):
    lines = _lines(chain)
    data = json.loads(lines[1])
    data["injected"] = "x"
    lines[1] = json.dumps(data).encode() + b"\n"
    _write(chain, lines)
    result = verify_chain(chain)
    assert not result.ok and result.first_bad_seq == 1


def test_missing_file_reported_not_raised(tmp_path):
    result = verify_chain(tmp_path / "nope.jsonl")
    assert not result.ok and "not found" in result.reason


def test_empty_file_is_valid(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    result = verify_chain(path)
    assert result.ok and result.records == 0 and result.head_hash == GENESIS_HASH


# ------------------------------------------------------------- live trail ---
def test_live_trail_detects_truncation_before_append(make_trail, fill, audit_path):
    trail = make_trail()
    fill(trail, 4)
    _write(audit_path, _lines(audit_path)[:2])
    with pytest.raises(AuditIntegrityError, match="truncation"):
        trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})
    assert len(_lines(audit_path)) == 2  # nothing was written


def test_live_trail_detects_deleted_file(make_trail, fill, audit_path):
    trail = make_trail()
    fill(trail, 2)
    audit_path.unlink()
    with pytest.raises(AuditIntegrityError, match="deletion"):
        trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})


def test_live_trail_refuses_foreign_unchained_tail(make_trail, fill, audit_path):
    trail = make_trail()
    fill(trail, 2)
    with audit_path.open("ab") as fh:
        fh.write(_lines(audit_path)[0])  # replay of record 0 appended by someone else
    with pytest.raises(AuditIntegrityError, match="do not chain"):
        trail.append(AuditEventType.ERROR, incident_id=None, actor="automation:test", payload={})


def test_live_trail_records_raise_on_tampering(make_trail, fill, audit_path):
    trail = make_trail()
    fill(trail, 3)
    lines = _lines(audit_path)
    lines[0] = lines[0].replace(b'"index":0', b'"index":5')
    _write(audit_path, lines)  # same length: invisible to the size check, caught by full read
    with pytest.raises(AuditIntegrityError, match="seq 0"):
        list(trail.records())
    assert not trail.verify().ok


# ----------------------------------------------------------------- memory ---
def test_verify_records_detects_in_memory_tampering(memory_trail, fill):
    fill(memory_trail, 4)
    records = list(memory_trail.snapshot())
    assert verify_records(records).ok

    edited = records.copy()
    edited[1] = edited[1].model_copy(update={"payload": {"index": 42}})
    assert verify_records(edited).first_bad_seq == 1

    deleted = records[:1] + records[2:]
    assert verify_records(deleted).first_bad_seq == 1

    reordered = [records[0], records[2], records[1], records[3]]
    assert verify_records(reordered).first_bad_seq == 1

    truncated = records[:2]
    anchor = memory_trail.anchor()
    assert verify_records(truncated).ok
    assert verify_records(truncated, anchors=[anchor]).first_bad_seq == 2


def test_verify_records_accepts_dicts_and_reports_malformed(memory_trail, fill):
    fill(memory_trail, 2)
    dumps = [r.model_dump(mode="json") for r in memory_trail.snapshot()]
    assert verify_records(dumps).ok
    dumps[1]["seq"] = "x"
    result = verify_records(dumps)
    assert not result.ok and result.first_bad_seq == 1 and "malformed" in result.reason


def test_anchor_parse():
    anchor = AuditAnchor.parse("12:" + "A" * 64)
    assert anchor.seq == 12 and anchor.hash == "a" * 64
    for bad in ("12", "x:" + "a" * 64, "-1:" + "a" * 64, "3:abc"):
        with pytest.raises(ValueError):
            AuditAnchor.parse(bad)
