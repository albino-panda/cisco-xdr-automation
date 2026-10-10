"""Audit forwarding to an external collector (architecture 14.14.4): verified, ordered, resumable, read only."""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from tools.deployment import forward_audit as cli
from xdr_response.audit.forwarding import forward_audit_file, read_checkpoint, write_checkpoint
from xdr_response.audit.trail import AuditTrail
from xdr_response.models import AuditEventType


def _trail(tmp_path: Path, count: int = 4) -> Path:
    trail = AuditTrail(tmp_path / "audit.jsonl", fsync=False)
    for i in range(count):
        trail.append(AuditEventType.INCIDENT_RECEIVED, incident_id="XDR-83921", actor="system:test",
                     payload={"n": i, "host": "TH-LT-1047"})
    return trail.path


class Collector:
    def __init__(self, fail_at: int | None = None, accept: bool = True) -> None:
        self.events: list[dict[str, Any]] = []
        self.fail_at = fail_at
        self.accept = accept

    def __call__(self, event: Any) -> bool:
        if self.fail_at is not None and event["seq"] == self.fail_at:
            raise ConnectionError("collector down")
        if not self.accept:
            return False
        self.events.append(dict(event))
        return True


def test_forwards_every_record_in_chain_order_and_leaves_the_file_unchanged(tmp_path):
    path = _trail(tmp_path)
    before = path.read_bytes()
    collector = Collector()
    result = forward_audit_file(path, collector)
    assert result.chain_ok and result.sent == 4 and result.last_seq == 3 and not result.stopped
    assert [e["seq"] for e in collector.events] == [0, 1, 2, 3]
    assert path.read_bytes() == before


def test_resumes_after_the_checkpoint_and_stops_at_the_first_failure(tmp_path):
    path = _trail(tmp_path, 5)
    collector = Collector(fail_at=3)
    first = forward_audit_file(path, collector, after_seq=0)
    assert [e["seq"] for e in collector.events] == [1, 2]
    assert first.last_seq == 2 and "send failed at seq 3" in first.stopped
    collector.fail_at = None
    second = forward_audit_file(path, collector, after_seq=first.last_seq)
    assert [e["seq"] for e in collector.events] == [1, 2, 3, 4] and second.last_seq == 4


def test_a_disabled_collector_acknowledges_nothing(tmp_path):
    path = _trail(tmp_path)
    result = forward_audit_file(path, Collector(accept=False))
    assert result.sent == 0 and result.last_seq == -1 and "disabled" in result.stopped


def test_a_broken_chain_is_reported_and_nothing_is_forwarded(tmp_path):
    path = _trail(tmp_path)
    lines = path.read_bytes().splitlines(keepends=True)
    record = json.loads(lines[1])
    record["payload"]["n"] = 99
    lines[1] = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode()
    path.write_bytes(b"".join(lines))
    collector = Collector()
    result = forward_audit_file(path, collector)
    assert not result.chain_ok and result.sent == 0 and collector.events == []
    assert "chain broken" in result.stopped


def test_limit_caps_one_run(tmp_path):
    path = _trail(tmp_path, 5)
    result = forward_audit_file(path, Collector(), limit=2)
    assert result.sent == 2 and result.last_seq == 1 and "limit" in result.stopped


def test_checkpoint_round_trip_and_validation(tmp_path):
    cp = tmp_path / "cp" / "splunk.checkpoint"
    assert read_checkpoint(cp) == -1
    write_checkpoint(cp, 7)
    assert read_checkpoint(cp) == 7
    cp.write_text('{"last_seq": "7"}', encoding="utf-8")
    with pytest.raises(ValueError):
        read_checkpoint(cp)


def test_cli_forwards_and_moves_the_checkpoint(tmp_path):
    path = _trail(tmp_path, 3)
    cp = tmp_path / "splunk.checkpoint"
    collector = Collector()
    out = io.StringIO()
    assert cli.main([str(path), "--checkpoint", str(cp)], out=out, sender=collector) == cli.EXIT_OK
    assert read_checkpoint(cp) == 2 and "forwarded 3 record(s)" in out.getvalue()
    assert cli.main([str(path), "--checkpoint", str(cp)], out=io.StringIO(), sender=collector) == cli.EXIT_OK
    assert len(collector.events) == 3  # nothing sent twice


def test_cli_reports_a_failure_with_exit_code_one(tmp_path):
    path = _trail(tmp_path, 3)
    out = io.StringIO()
    code = cli.main([str(path), "--checkpoint", str(tmp_path / "cp")], out=out, sender=Collector(fail_at=0))
    assert code == cli.EXIT_STOPPED and "stopped" in out.getvalue()
    assert cli.main([str(tmp_path / "missing.jsonl"), "--checkpoint", "x"], out=io.StringIO()) == cli.EXIT_USAGE


def test_splunk_adapter_forward_audit_is_the_sender(tmp_path):
    """The configured sender is SplunkAdapter.forward_audit; a disabled Splunk sends nothing."""
    from xdr_response.config import IntegrationConfig
    from xdr_response.integrations.registry import load_adapter_class
    from xdr_response.secrets.provider import StaticSecretProvider

    adapter = load_adapter_class("splunk")(IntegrationConfig(enabled=False), StaticSecretProvider({}))
    result = forward_audit_file(_trail(tmp_path, 2), adapter.forward_audit)
    assert result.sent == 0 and "disabled" in result.stopped
