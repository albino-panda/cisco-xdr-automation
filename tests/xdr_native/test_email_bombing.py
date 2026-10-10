"""The XDR-native Email Bombing workflow: export shape, approval gate and embedded scripts."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tools.xdr_native import build as build_tool
from xdr_native import email_bombing, scripts, validate
from xdr_native.scripts import run

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def document() -> dict:
    return email_bombing.build().export()


def _find(document: dict, title: str) -> tuple[dict, tuple[dict, ...]]:
    for activity, ancestors in validate.walk(document["workflow"]["actions"]):
        if activity["title"] == title:
            return activity, ancestors
    raise AssertionError(title)


def _siblings(document: dict, title: str) -> list[dict]:
    _, ancestors = _find(document, title)
    return ancestors[-1]["actions"]


# -- export ------------------------------------------------------------------------------------------


def test_committed_export_is_current_and_valid(document):
    assert build_tool.main(["--check"]) == 0
    assert validate.check(document) == []


def test_export_keeps_the_tenant_template(document):
    workflow = document["workflow"]
    assert workflow["unique_name"] == email_bombing.WORKFLOW_ID
    assert workflow["template_type"] == "template_workflow.incident_response"
    assert workflow["properties"]["automation_rules"] == {"type": ["incident.rule_event"]}
    assert workflow["properties"]["wf_metadata"]["coa"]["observable_types"] == ["email"]
    ids = {activity["unique_name"] for activity, _ in validate.walk(workflow["actions"])}
    assert set(email_bombing.TEMPLATE_IDS.values()) <= ids
    selected, _ = _find(document, "For each selected observable")
    assert selected["properties"]["source_array"] == "$intent.intent incident_response.input.selected_observables$"
    incident, _ = _find(document, "For each incident observable")
    assert incident["properties"]["source_array"] == "$rule.incident rule_event.output.targets.data$"


def test_export_holds_no_credentials_and_defaults_to_dry_run(document):
    variables = {v["properties"]["name"]: v["properties"] for v in document["workflow"]["variables"]}
    assert variables["Dry Run"]["value"] is True
    assert variables["ETD API Key"]["type"] == "datatype.secure_string" and variables["ETD API Key"]["value"] == ""
    assert variables["ETD Access Token"]["type"] == "datatype.secure_string"
    for user in document["runtime_users"].values():
        assert user["properties"]["basic_username"] == "" and user["properties"]["basic_password"] == ""
    assert "example.com" not in json.dumps(document) and "assignees" not in json.dumps(document)  # roles only
    for script in (scripts.SELECT_MAILBOXES, scripts.BUILD_SEARCH, scripts.MERGE_PAGE, scripts.ASSESS,
                   scripts.RECORD_MOVE, scripts.RECORD_VERIFICATION, scripts.CONTAINMENT_RESULT):
        assert "import" in script and not any(word in script for word in ("requests", "urllib", "socket", "subprocess", "os."))


def test_build_tool_accepts_org_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    assert build_tool.main(["--approver-role", "user", "--elevated-role", "admin", "--elevated-approvals", "3",
                            "--etd-host", "api.de.etd.cisco.com"]) == 0
    written = json.loads(next((tmp_path / "xdr").rglob(f"{email_bombing.WORKFLOW_ID}.json")).read_text(encoding="utf-8"))
    standard, _ = _find(written, "Request standard approval")
    elevated, _ = _find(written, "Request elevated approval")
    assert standard["properties"]["assignee_roles"] == ["user"]
    assert elevated["properties"]["assignee_roles"] == ["admin"]
    assert elevated["properties"]["minimum_approvals"] == 3
    assert {t["properties"]["host"] for t in written["targets"].values()} == {"api.de.etd.cisco.com"}
    with pytest.raises(SystemExit):
        build_tool.main(["--approver-role", "everyone"])


def test_request_approval_matches_the_org_export(document):
    """Property names and values of the Request Approval activity exported from the target org."""
    request, _ = _find(document, "Request standard approval")
    properties = request["properties"]
    assert request["type"] == "task.request_approval" and request["name"] == "Request Approval"
    assert set(properties) == {
        "approval_choices_holder", "approval_title", "assignee_roles", "body_text", "continue_on_failure",
        "display_name", "due_date", "expiration_date", "expiration_status", "minimum_approvals", "priority",
        "skip_execution", "task_owner", "task_requestor", "wait_for_request_approval_response"}
    assert properties["assignee_roles"] == ["admin", "user"]
    assert properties["wait_for_request_approval_response"] is True
    assert properties["task_owner"] == properties["task_requestor"] == (
        f"$workflow.{email_bombing.WORKFLOW_ID}.output.started_by$")
    assert properties["expiration_date"] == {"is_relative_time": True, "relative_time": {"duration": 72, "time_units": "hours"}}
    assert properties["approval_choices_holder"] == {
        "approval_choices": ["Approve", "Reject", "More investigation"], "is_custom_approval_choices": True,
        "is_default_approval_choices": False}
    assessment, _ = _find(document, "Assess flood and write decision card")
    assert properties["body_text"] == f"$activity.{assessment['unique_name']}.output.script_queries.card$"


# -- approval gate -------------------------------------------------------------------------------------


def test_only_the_move_is_state_changing_and_it_is_gated(document):
    changing = [a["title"] for a, _ in validate.walk(document["workflow"]["actions"]) if validate.is_state_changing(a)]
    assert changing == ["Move approved messages"]
    assert validate.check_approval_gate(document) == []
    _, ancestors = _find(document, "Move approved messages")
    assert [a["title"] for a in ancestors if a["type"] == "logic.condition_block"][-2:] == [
        "Approved", "Live: execute the approved package"]


def test_elevated_approval_needs_two_people(document):
    elevated, _ = _find(document, "Request elevated approval")
    standard, _ = _find(document, "Request standard approval")
    assert elevated["properties"]["minimum_approvals"] == 2 and elevated["properties"]["assignee_roles"] == ["admin"]
    assert standard["properties"]["minimum_approvals"] == 1
    assert elevated["properties"]["approval_title"].startswith("ELEVATED APPROVAL REQUIRED")
    for request in (elevated, standard):
        assert request["properties"]["approval_choices_holder"]["approval_choices"] == [
            "Approve", "Reject", "More investigation"]


def _move_out_of_gate(document):
    move, ancestors = _find(document, "Move approved messages")
    ancestors[-1]["actions"].remove(move)
    document["workflow"]["actions"].append(move)


def _move_before_approval(document):
    siblings = _siblings(document, "Which approval level?")
    table, _ = _find(document, "Move requests table")
    loop, _ = _find(document, "For each chunk of up to 100 messages")
    siblings[0:0] = [copy.deepcopy(table), copy.deepcopy(loop)]


def _invert_gate(document):
    _find(document, "Approved")[0]["properties"]["condition"]["operator"] = "ne"


def _weaken_gate_to_or(document):
    branch, _ = _find(document, "Approved")
    branch["properties"]["condition"] = {"left_operand": branch["properties"]["condition"], "operator": "or",
                                         "right_operand": {"left_operand": "1", "operator": "eq", "right_operand": "1"}}


def _self_approve(document):
    record, _ = _find(document, "Record standard decision")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = "Approve"


def _approve_from_script(document):
    record, _ = _find(document, "Record standard decision")
    assess, _ = _find(document, "Assess flood and write decision card")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = (
        f"$activity.{assess['unique_name']}.output.script_queries.qualifies$")


def _do_not_wait(document):
    _find(document, "Request standard approval")[0]["properties"]["wait_for_request_approval_response"] = False


def _skip_the_request(document):
    _find(document, "Request elevated approval")[0]["properties"]["skip_execution"] = True


def _continue_when_the_request_fails(document):
    _find(document, "Request standard approval")[0]["properties"]["continue_on_failure"] = True


def _answer_of_another_task(document):
    record, _ = _find(document, "Record standard decision")
    other, _ = _find(document, "Request elevated approval")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = (
        f"$activity.{other['unique_name']}.output.response$")


def _answer_of_another_output(document):
    record, _ = _find(document, "Record standard decision")
    request, _ = _find(document, "Request standard approval")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = (
        f"$activity.{request['unique_name']}.output.succeeded$")


def _drop_the_request(document):
    siblings = _siblings(document, "Request standard approval")
    siblings[:] = [a for a in siblings if a["type"] != "task.request_approval"]


def _remove_dry_run_gate(document):
    live, _ = _find(document, "Live: execute the approved package")
    approved, _ = _find(document, "Approved")
    approved["actions"] = live["actions"]


def _dry_run_gate_on_true(document):
    _find(document, "Live: execute the approved package")[0]["properties"]["condition"]["right_operand"] = True


def _no_assignee(document):
    _find(document, "Request standard approval")[0]["properties"]["assignee_roles"] = []


def _unknown_role(document):
    _find(document, "Request standard approval")[0]["properties"]["assignee_roles"] = ["automation"]


def _zero_approvals(document):
    _find(document, "Request elevated approval")[0]["properties"]["minimum_approvals"] = 0


def _remove_approve_choice(document):
    _find(document, "Request standard approval")[0]["properties"]["approval_choices_holder"]["approval_choices"] = ["Reject"]


def _extra_write_elsewhere(document):
    move, _ = _find(document, "Move approved messages")
    extra = copy.deepcopy(move)
    extra["unique_name"] = extra["unique_name"][:-3] + "Zz9"
    extra["title"] = "Second move"
    _siblings(document, "Build ETD search").append(extra)


def _delete_request(document):
    search, _ = _find(document, "Search ETD messages")
    search["properties"]["method"] = "DELETE"


def _call_a_workflow(document):
    _siblings(document, "Build ETD search").append({
        "unique_name": "definition_activity_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa", "name": "Contain", "title": "Contain",
        "type": "workflow.atomic_workflow", "base_type": "subworkflow", "object_type": "definition_activity",
        "properties": {"workflow_id": "definition_workflow_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa"}})


def _swap_package_after_approval(document):
    move, _ = _find(document, "Move approved messages")
    move["properties"]["body"] = validate.variable_ref(document, "Search Body")


def _script_writes_decision(document):
    script, _ = _find(document, "Build ETD search")
    script["properties"]["script"] += "\n# " + validate.variable_ref(document, "Decision")


BYPASSES = [
    _move_out_of_gate, _move_before_approval, _invert_gate, _weaken_gate_to_or, _self_approve, _approve_from_script,
    _do_not_wait, _skip_the_request, _continue_when_the_request_fails, _answer_of_another_task,
    _answer_of_another_output, _drop_the_request, _remove_dry_run_gate, _dry_run_gate_on_true, _no_assignee,
    _unknown_role, _zero_approvals, _remove_approve_choice, _extra_write_elsewhere, _delete_request,
    _call_a_workflow, _swap_package_after_approval, _script_writes_decision,
]


@pytest.mark.parametrize("bypass", BYPASSES, ids=lambda f: f.__name__.lstrip("_"))
def test_gate_check_rejects_every_bypass(document, bypass):
    bypass(document)
    assert validate.check_approval_gate(document), f"{bypass.__name__} was not detected"


def test_structure_check_rejects_unknown_shapes(document):
    for mutate, expected in [
        (lambda d: d.update(rules={}), "envelope key"),
        (lambda d: _find(d, "Build ETD search")[0].update(type="core.sleep"), "activity type"),
        (lambda d: _find(d, "Approved")[0]["properties"]["condition"].update(operator="contains"), "operator"),
        (lambda d: d["workflow"]["variables"][0]["properties"].update(scope="static"), "unresolved variable"),
        (lambda d: next(iter(d["runtime_users"].values()))["properties"].update(basic_password="x"), "credentials"),
        (lambda d: _find(d, "Request standard approval")[0]["properties"].update(auto_approve=True), "forbidden"),
        (lambda d: _find(d, "Search ETD messages")[0]["properties"]["custom_headers"][0].update(value="Bearer abc"),
         "secure string"),
    ]:
        changed = copy.deepcopy(document)
        mutate(changed)
        assert any(expected in problem for problem in validate.check_structure(changed)), expected


# -- embedded scripts ----------------------------------------------------------------------------------


def _message(index: int, *, subject: str = "Welcome to our newsletter", verdict: str = "neutral",
             sender: str | None = None) -> dict:
    return {"id": f"msg-{index:04d}", "timestamp": "2026-01-01T10:00:00Z", "subject": subject,
            "fromAddress": sender or f"news@list{index % 40}.example", "verdict": {"latestVerdict": verdict}}


def _collect(messages: list[dict], *, page: int = 100, max_messages: int = 1000) -> dict:
    state, body = "{}", json.dumps({"recipient": "jsmith@example.com"})
    for start in range(0, max(len(messages), 1), page):
        chunk = messages[start:start + page]
        response = {"data": {"messages": chunk}}
        if start + page < len(messages):
            response["nextPageToken"] = f"token-{start + page}"
        result = run(scripts.MERGE_PAGE, state, 200, json.dumps(response), body, max_messages)
        state, body = result["state_json"], result["search_body"]
        if result["has_more"] != "true":
            break
    return json.loads(state)


def _assess(state: dict, *, protected: str = "false", dry_run: str = "True", folder: str = "quarantine",
            elevated_above: int = 500, trusted: str = "") -> dict:
    return run(scripts.ASSESS, json.dumps(state), "jsmith@example.com", protected, 30, 10, 50, dry_run, folder,
               "graymail", "2026-01-01T09:30:00Z", "2026-01-01T10:30:00Z", elevated_above, trusted)


def test_select_mailboxes_filters_dedupes_caps_and_flags_protected():
    result = run(scripts.SELECT_MAILBOXES,
                 "\nJSmith@Example.com\n198.51.100.7\nevil.example\njsmith@example.com\nceo@example.com\n"
                 + "\n".join(f"user{i}@example.com" for i in range(6)), "ceo@example.com, @finance.example", 5)
    rows = json.loads(result["mailboxes_json"])
    assert [r["mailbox"] for r in rows][:2] == ["jsmith@example.com", "ceo@example.com"]
    assert rows[0]["protected"] == "false" and rows[1]["protected"] == "true"
    assert result["mailbox_count"] == "5" and result["skipped_count"] == "3"
    assert json.loads(run(scripts.SELECT_MAILBOXES, "a@finance.example", "@finance.example", 5)["mailboxes_json"]) == [
        {"mailbox": "a@finance.example", "protected": "true"}]
    assert run(scripts.SELECT_MAILBOXES, "", "", 5)["mailbox_count"] == "0"


def test_build_search_bounds_the_window():
    result = run(scripts.BUILD_SEARCH, " JSmith@Example.com ", "999999")
    body = json.loads(result["search_body"])
    assert body["recipient"] == "jsmith@example.com" and body["directions"] == ["incoming"] and body["pageSize"] == 100
    assert body["timestamp"] == [result["window_start"], result["window_end"]]
    assert result["window_start"][:10] != "" and result["window_start"] < result["window_end"]


def test_merge_pages_follows_tokens_and_stops_at_the_limit():
    state = _collect([_message(i) for i in range(250)])
    assert len(state["messages"]) == 250 and state["pages"] == 3 and not state["truncated"] and not state["error"]
    capped = _collect([_message(i) for i in range(250)], max_messages=120)
    assert len(capped["messages"]) == 120 and capped["truncated"]


def test_merge_page_records_a_failed_source_and_stops():
    result = run(scripts.MERGE_PAGE, "{}", 502, "Bad Gateway", "{}", 1000)
    assert result["has_more"] == "false" and "HTTP 502" in json.loads(result["state_json"])["error"]
    result = run(scripts.MERGE_PAGE, "{}", 200, "not json", "{}", 1000)
    assert result["has_more"] == "false" and json.loads(result["state_json"])["error"]


def test_assess_proposes_the_flood_and_keeps_buried_messages():
    messages = [_message(i) for i in range(120)]
    messages.append(_message(900, subject="Your password was changed", sender="no-reply@bank.example"))
    messages.append(_message(901, subject="Reset your password now", verdict="phishing", sender="x@bad.example"))
    messages.append(_message(902, subject="Quarterly report", sender="partner@trusted.example"))
    result = _assess(_collect(messages), trusted="trusted.example")
    assert result["qualifies"] == "true" and result["elevated"] == "false"
    moved = [mid for chunk in json.loads(result["move_chunks"]) for mid in json.loads(chunk["body"])["ids"]]
    assert "msg-0900" not in moved and "msg-0902" not in moved and "msg-0901" in moved
    assert result["move_count"] == "121" and len(moved) == 121
    assert all(len(json.loads(chunk["body"])["ids"]) <= 100 for chunk in json.loads(result["move_chunks"]))
    assert "Your password was changed" in result["card"] and "DRY RUN" in result["card"]
    assert "Check the account" in result["card"] and result["package_digest"] in result["card"]
    assert len(json.loads(result["verify_sample"])) == 5
    assert _assess(_collect(messages), trusted="trusted.example")["package_digest"] == result["package_digest"]


def test_assess_does_not_propose_below_the_thresholds():
    few = _assess(_collect([_message(i) for i in range(12)]))
    assert few["qualifies"] == "false" and few["move_chunks"] == "[]" and few["move_count"] == "0" and few["card"] == ""
    one_sender = _assess(_collect([_message(i, sender="bulk@one.example") for i in range(200)]))
    assert one_sender["qualifies"] == "false"
    spam_storm = _assess(_collect([_message(i, verdict="spam") for i in range(200)]))
    assert spam_storm["qualifies"] == "false" and "No action proposed" in spam_storm["summary"]


def test_assess_surfaces_elevated_approval_instead_of_blocking():
    state = _collect([_message(i) for i in range(120)])
    protected = _assess(state, protected="true")
    assert protected["qualifies"] == "true" and protected["elevated"] == "true"
    assert "ELEVATED APPROVAL REQUIRED" in protected["card"] and "protected list" in protected["card"]
    large = _assess(state, elevated_above=100)
    assert large["elevated"] == "true" and "above the limit" in large["card"]
    truncated = _assess(_collect([_message(i) for i in range(250)], max_messages=120))
    assert truncated["elevated"] == "true" and "collection limit" in truncated["card"]


def test_assess_keeps_a_recommendation_when_the_source_degrades_midway():
    state = _collect([_message(i) for i in range(120)])
    state["error"] = "ETD message search failed on page 3: HTTP 502"
    result = _assess(state)
    assert result["qualifies"] == "true" and "Degraded source" in result["card"]
    empty = _assess({"messages": [], "error": "ETD message search failed on page 1: HTTP 403"})
    assert empty["qualifies"] == "false" and "HTTP 403" in empty["summary"]


def test_assess_treats_anything_but_false_as_dry_run_and_refuses_delete():
    state = _collect([_message(i) for i in range(120)])
    assert "LIVE" in _assess(state, dry_run="false")["card"]
    for value in ("True", "true", "", "0", "no"):
        assert "DRY RUN" in _assess(state, dry_run=value)["card"]
    with pytest.raises(SystemExit):
        _assess(state, folder="delete")


def test_move_tally_counts_queued_and_failed():
    ok = json.dumps({"data": [{"id": "a", "queueSuccess": True}, {"id": "b", "queueSuccess": False}]})
    tally = run(scripts.RECORD_MOVE, "{}", 200, ok, 2)["tally_json"]
    tally = run(scripts.RECORD_MOVE, tally, 200, "{}", 100)["tally_json"]
    tally = json.loads(run(scripts.RECORD_MOVE, tally, 403, "Forbidden", 50)["tally_json"])
    assert tally["queued"] == 101 and tally["failed"] == 51 and "403" in tally["errors"][0]


def test_verification_is_three_valued():
    def verify(tally, code, body):
        return run(scripts.RECORD_VERIFICATION, tally, code, body, "quarantine")["tally_json"]

    tally = verify("{}", 200, json.dumps({"data": {"statuses": [{"action": "Moved to Quarantine"}]}}))
    tally = verify(tally, 200, json.dumps({"data": {"statuses": [{"folder": "inbox"}]}}))
    tally = verify(tally, 200, json.dumps({"data": {}}))
    tally = verify(tally, 500, "error")
    assert json.loads(tally) == {"verified": 1, "not_verified": 1, "unable": 2}
    text = run(scripts.CONTAINMENT_RESULT, "jsmith@example.com", "quarantine", "abc", json.dumps(
        {"queued": 120, "failed": 0, **json.loads(tally)}))["result"]
    assert "120 messages queued" in text and "NOT VERIFIED" in text and "needs its own approval" in text
    verified = run(scripts.CONTAINMENT_RESULT, "jsmith@example.com", "quarantine", "abc",
                   json.dumps({"queued": 5, "failed": 0, "verified": 5}))["result"]
    assert "VERIFIED on a sample of 5" in verified
    unknown = run(scripts.CONTAINMENT_RESULT, "jsmith@example.com", "quarantine", "abc", json.dumps({"queued": 5}))["result"]
    assert "UNABLE TO VERIFY" in unknown
