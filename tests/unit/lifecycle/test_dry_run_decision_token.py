"""A decision taken while dry run is active never yields live authority (architecture 13.24)."""
from __future__ import annotations

import pytest

from tools.simulator.scenario import ScenarioRun, load_scenario
from xdr_response import guard
from xdr_response.errors import ApprovalRequiredError


def test_live_package_decided_during_dry_run_issues_a_dry_run_token_only():
    run = ScenarioRun(load_scenario("ransomware"), live=True)
    package = run.detect().package
    assert package is not None and package.dry_run is False  # proposed while live
    with guard.dry_run():  # the operator switched dry run on before the analyst decided
        decision = run.decide()
    token = decision.outcome.token
    assert decision.dry_run and token is not None and token.claims.dry_run is True
    with pytest.raises(ApprovalRequiredError):
        run.runtime.executor.execute(package, token)  # dry run is off again: still refused
    assert run.environment.state_changing_calls() == []
