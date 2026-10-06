"""Definition of done for every workflow: valid plan rules, templates and passing scenarios."""
from __future__ import annotations

import pytest

from xdr_plan import repo
from xdr_plan.validate import check_workflow


@pytest.mark.parametrize("workflow_id", repo.workflow_ids())
def test_workflow_is_complete(workflow_id):
    errors = check_workflow(workflow_id)
    assert not errors, "\n".join(errors)
