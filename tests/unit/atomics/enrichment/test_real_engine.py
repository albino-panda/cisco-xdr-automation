"""Enrichment atomics end to end with the scoring key's real engine (14.1.3 steps 3 and 4).

Only contract-level properties are asserted (14.1.3, 14.2.2): no single vendor decides the verdict,
a report with every source failed has risk 0, confidence 0 and verdict UNKNOWN, a not-queried source
costs no confidence, and dry run scores like a live run.
"""
from __future__ import annotations

import dataclasses

import pytest

pytest.importorskip("xdr_response.scoring.signals")
pytest.importorskip("xdr_response.scoring.engine")
pytest.importorskip("xdr_response.scoring.verdict")

from tests.unit.atomics.enrichment._support import lab  # noqa: E402
from xdr_response.atomics.enrichment import _scoring  # noqa: E402
from xdr_response.atomics.enrichment.atomics import enrich_domain  # noqa: E402
from xdr_response.config.schema import ExclusionsConfig  # noqa: E402
from xdr_response.integrations.simulated import (  # noqa: E402
    Fault,
    FaultKind,
    SimulatedEnvironment,
    register_simulated_adapters,
)
from xdr_response.models import ObservableType, Verdict  # noqa: E402

USE_REAL_ENGINE = True
DOMAIN = "bad.example.test"
SUITE = {"umbrella": ("network",), "virustotal": ("intel",), "alienvault_otx": ("intel",)}


def _run(*, malicious: tuple[str, ...] = ("umbrella",), fault: FaultKind | None = None,
         internal: bool = False, dry_run: bool = True):
    the_lab = lab(exclusions=ExclusionsConfig(internal_domains=["example.test"] if internal else []))
    env = SimulatedEnvironment(clock=the_lab.clock)
    register_simulated_adapters(the_lab.registry, env, suite=SUITE)
    if malicious:
        env.set_reputation(ObservableType.DOMAIN, DOMAIN, Verdict.MALICIOUS, risk_score=85, confidence=80,
                           summary="known malware host", integrations=malicious)
    if fault is not None:
        env.faults.append(Fault(fault, operation="enrich", remaining=None,
                                integration=None if not malicious else "virustotal"))
    ctx = dataclasses.replace(the_lab.context(), dry_run=dry_run)
    return enrich_domain(ctx, DOMAIN)


def test_production_uses_the_engine_backend():
    assert _scoring._backend is _scoring.engine_backend


def test_every_source_failed_gives_zero_scores_and_unknown():
    report = _run(malicious=(), fault=FaultKind.UNAVAILABLE)
    assert report.failed == ("umbrella", "virustotal", "alienvault_otx")
    assert (report.risk_score, report.confidence, report.verdict) == (0, 0, Verdict.UNKNOWN)
    assert len(report.breakdown.failed_sources) == 3


def test_one_vendor_malicious_alone_is_only_suspicious():
    report = _run(malicious=("virustotal",))
    assert report.source_verdicts() == {"virustotal": "MALICIOUS"}
    assert report.verdict is Verdict.SUSPICIOUS


def test_two_agreeing_reputation_sources_are_malicious():
    report = _run(malicious=("virustotal", "alienvault_otx"))
    assert report.verdict is Verdict.MALICIOUS
    assert report.risk_score > 0 and report.confidence > 0


def test_not_queried_costs_no_confidence_but_a_failure_does():
    withheld = _run(internal=True)
    empty = _run()
    failed = _run(fault=FaultKind.UNAVAILABLE)
    assert withheld.not_queried == ("virustotal", "alienvault_otx") and not withheld.degraded
    assert withheld.confidence == empty.confidence
    assert failed.degraded and failed.confidence < empty.confidence
    assert withheld.breakdown.not_queried and not withheld.breakdown.failed_sources


def test_dry_run_and_live_runs_score_identically():
    assert _run(dry_run=True) == _run(dry_run=False)
