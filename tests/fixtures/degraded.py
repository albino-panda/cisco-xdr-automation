"""Degraded-source accounting check shared by the workflow safety tests (architecture 14.14.1).

Owner rule: a failed or degraded source must not block a recommendation backed by other evidence, and
nothing is dropped silently. :func:`degradation_findings` fails every read of one integration in a
workflow's ``tp-approve-all`` scenario and compares the degraded run with the full run:

* an action whose evidence never came from the failed integration must still be **proposed**;
* an action whose evidence came from the failed integration **and** from other integrations whose
  records are still collected and still name the action's target (the host of a file, process or
  persistence target; the account of a role assignment) must still be **accounted for**: proposed, or
  a rule outcome (below threshold, unrouted, allow-listed) whose detail names the failed integration,
  or a considered entry for the action and target (``"<action>:<host>"`` for a file, process or
  persistence target, whose path or pid only the failed source knew) whose reason names it;
* an action whose every record about its target came from the failed integration may be dropped, but
  never silently: when the degraded run still knows the target (the incident names it, or a read of
  the run was about it) it must be accounted for as above or as a **needs-investigation** entry
  (:class:`~xdr_response.workflows.runner.NeedsInvestigation`) for the action and target that names
  the failed integration; when the degraded run cannot know the target (only the failed source
  reported it, such as a hash or a pid), the run must report the failed integration as a degraded
  source with a ``degraded source:`` note (the unrouted / needs-investigation note for the analyst);
* no hook may fail in the degraded run (a crashed hook is a silent loss).

A URL whose domain the degraded run proposes to block is covered by that block.

Every case is checked; nothing is skipped because every action also cites the failed source.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from xdr_response import guard
from xdr_response.models import ActionType, TargetKind, same_endpoint

_HOST_PARTS = (TargetKind.FILE, TargetKind.PROCESS, TargetKind.PERSISTENCE_ITEM)
_UNACCEPTABLE = frozenset({"ERROR", "NO_EVIDENCE"})


def target_needles(kind: TargetKind, target: str) -> list[str]:
    """The strings a record must contain to be about the action's target."""
    if kind in _HOST_PARTS:
        return [target.partition("/")[0]]
    if kind is TargetKind.ROLE_ASSIGNMENT:
        return [target.partition("/")[0]]
    return [target]


def mentions(record: Any, needles: Iterable[str]) -> bool:
    text = json.dumps(record.rule_item(), default=str).lower()
    return any(n and n.lower() in text for n in needles)


def known_to_run(run: Any, kind: TargetKind, target: str) -> bool:
    """True when the run itself knows the target: the incident names it or a read was about it."""
    needle = target_needles(kind, target)[0].strip().lower()
    if not needle:
        return False
    values = [o.value for o in run.scenario.incident.observables] + list(run.scenario.incident.users)
    values += [r.subject.value for r in run.workflow_run.results]
    host = kind in (*_HOST_PARTS, TargetKind.ENDPOINT)
    return any(v.strip().lower() == needle or (host and same_endpoint(v, needle)) for v in values)


def with_failed_source(data: Mapping[str, Any], failed: str) -> dict[str, Any]:
    """A copy of scenario ``data`` where every read of ``failed`` is UNAVAILABLE."""
    out = copy.deepcopy(dict(data))
    environment = out.setdefault("environment", {})
    environment["faults"] = list(environment.get("faults") or []) + [
        {"kind": "UNAVAILABLE", "integration": failed, "times": None}]
    return out


def degradation_findings(raw: Mapping[str, Any], failed: str,
                         detect: Callable[[Mapping[str, Any]], Any]) -> list[str]:
    """Every way failing ``failed`` silently drops or blocks an action of the full run ([] when none)."""
    run = detect(raw)
    wf = run.workflow_run
    actions = []
    for action in run.detection.package.actions:
        cited = {e.data["record_id"]: wf.index.get(e.data["record_id"]).integration for e in action.evidence}
        actions.append((action.action_type, action.target, action.target_kind, cited))
    guard._reset_for_test_harness()
    degraded = detect(with_failed_source(raw, failed))
    dw = degraded.workflow_run
    package = degraded.detection.package
    guard._reset_for_test_harness()
    proposed = {(a.action_type, a.target) for a in package.actions} if package else set()
    outcomes = {(o.action_type, o.target): o for o in dw.outcomes}
    considered = {c.subject: c.reason for c in dw.considered if not c.manual}
    needs = {n.subject: n.failed for n in dw.needs_investigation}
    reported = failed in dw.degraded_sources() and any(n.startswith(f"degraded source: {failed} ") for n in dw.notes)
    problems = [f"hook failed in the degraded run: {n}" for n in dw.notes if n.startswith("hook ") and "failed" in n]
    domains = {t.rstrip(".").lower() for a, t in proposed if a is ActionType.BLOCK_DOMAIN}
    for action_type, target, kind, cited in actions:
        selector = f"{action_type.value}:{target}"
        if (action_type, target) in proposed:
            continue
        host = (urlsplit(target).hostname or "").lower() if kind is TargetKind.URL else ""
        if host and any(host == d or host.endswith("." + d) for d in domains):
            continue  # a proposed block of its domain covers the URL
        if failed not in cited.values():
            problems.append(f"{selector}: no evidence from {failed}, but no longer proposed")
            continue
        needles = target_needles(kind, target)
        surviving = [i for i, integration in cited.items()
                     if integration != failed and i in dw.index and mentions(dw.index.get(i), needles)]
        subjects = [selector]
        if kind in _HOST_PARTS:
            subjects.append(f"{action_type.value}:{target.partition('/')[0]}")
        if not surviving:
            # Every record about the target came from the failed source: nothing else backs it, so it
            # may be dropped, but never silently.
            if not known_to_run(degraded, kind, target):
                if not reported:
                    problems.append(f"{selector}: dropped and the run does not report {failed} as a degraded source")
                continue
            outcome = outcomes.get((action_type, target))
            if outcome is not None and outcome.status.value not in _UNACCEPTABLE and failed in outcome.detail:
                continue
            if any(s in considered and failed in considered[s] for s in subjects):
                continue
            if any(s in needs and failed in needs[s] for s in subjects):
                continue
            problems.append(f"{selector}: only {failed} backed it and the degraded run still knows the target, but "
                            f"it vanished (no outcome, considered or needs-investigation entry naming {failed})")
            continue
        outcome = outcomes.get((action_type, target))
        if outcome is not None and outcome.status.value not in _UNACCEPTABLE and failed in outcome.detail:
            continue
        if any(s in considered and failed in considered[s] for s in subjects):
            continue
        shown = (f"outcome {outcome.status.value}: {outcome.detail}" if outcome is not None else
                 next((f"considered: {considered[s]}" for s in subjects if s in considered), "nothing"))
        problems.append(f"{selector}: other sources still back it ({len(surviving)} record(s)), but the degraded "
                        f"run shows {shown[:300]} (the failed {failed} must be named)")
    return problems
