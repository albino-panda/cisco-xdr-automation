"""Forward a verified audit trail to an external collector (architecture 14.14.4).

The audit trail is the system of record: an append-only, hash-chained JSONL file. Forwarding is a
copy for the SOC's SIEM, never a second source of truth, and it runs **outside** the response path
(``tools/deployment/forward_audit.py``, for example from a scheduler), so a slow or unavailable
collector can never delay or block containment, and nothing here can write to the trail.

:func:`forward_audit_file` verifies the whole chain first and forwards nothing when it is broken (a
tampered trail is reported, not copied). It then sends each record after the checkpoint, in order,
through a ``send`` callable (``SplunkAdapter.forward_audit``: a VERIFIED HEC bookkeeping write that
redacts again before sending) and stops at the first failure, so the checkpoint (the last ``seq`` the
collector acknowledged) makes every later run resume exactly where the previous one stopped:
at-least-once delivery, in chain order. The checkpoint never moves backwards and never past a record
that was not sent.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from xdr_response.audit.hashing import parse_record_line
from xdr_response.audit.verify import iter_file_lines, verify_chain

__all__ = ["ForwardResult", "forward_audit_file", "read_checkpoint", "write_checkpoint"]


@dataclass(frozen=True)
class ForwardResult:
    """What one forwarding run did."""

    chain_ok: bool
    sent: int
    last_seq: int  # the checkpoint after the run (-1: nothing acknowledged yet)
    stopped: str = ""  # why the run stopped early ("" when every record after the checkpoint was sent)


def read_checkpoint(path: Path | str) -> int:
    """The last forwarded ``seq`` (-1 when the file is missing). ``ValueError`` on a malformed file."""
    file = Path(path)
    if not file.exists():
        return -1
    data = json.loads(file.read_text(encoding="utf-8"))
    seq = data.get("last_seq") if isinstance(data, Mapping) else None
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < -1:
        raise ValueError("checkpoint must be {\"last_seq\": <int >= -1>}")
    return seq


def write_checkpoint(path: Path | str, last_seq: int) -> None:
    """Persist the checkpoint atomically (write a temporary file, then replace)."""
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_suffix(file.suffix + ".tmp")
    tmp.write_text(json.dumps({"last_seq": int(last_seq)}), encoding="utf-8")
    tmp.replace(file)


def forward_audit_file(path: Path | str, send: Callable[[Mapping[str, Any]], bool], *,
                       after_seq: int = -1, limit: int | None = None) -> ForwardResult:
    """Send the records of the audit file at ``path`` with ``seq > after_seq``, in order.

    ``send`` returns True when the collector accepted the event, False when forwarding is disabled
    (the run stops and nothing is acknowledged); an exception also stops the run. ``limit`` caps the
    records sent in one run. The file is only read.
    """
    verification = verify_chain(path)
    if not verification.ok:
        return ForwardResult(chain_ok=False, sent=0, last_seq=after_seq,
                             stopped=f"audit chain broken at seq {verification.first_bad_seq}: "
                                     f"{verification.reason}; nothing forwarded")
    sent = 0
    last = after_seq
    for line in iter_file_lines(Path(path)):
        record = parse_record_line(line)
        if record.seq >= verification.records:
            break  # appended after the verification: forwarded by the next run, once verified
        if record.seq <= after_seq:
            continue
        if limit is not None and sent >= limit:
            return ForwardResult(chain_ok=True, sent=sent, last_seq=last, stopped=f"limit of {limit} reached")
        try:
            accepted = send(record.model_dump(mode="json"))
        except Exception as exc:  # noqa: BLE001 - a collector failure stops the run, never the caller
            return ForwardResult(chain_ok=True, sent=sent, last_seq=last,
                                 stopped=f"send failed at seq {record.seq}: {type(exc).__name__}")
        if not accepted:
            return ForwardResult(chain_ok=True, sent=sent, last_seq=last,
                                 stopped=f"forwarding disabled at seq {record.seq}")
        sent += 1
        last = record.seq
    return ForwardResult(chain_ok=True, sent=sent, last_seq=last)
