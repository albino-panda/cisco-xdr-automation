"""The XDR-native Email Bombing workflow: export shape, approval gate and embedded scripts."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from tools.xdr_native import build as build_tool
from xdr_native import email_bombing, incident_scripts, scripts, validate
from xdr_native.builder import PLATFORM_APIS
from xdr_native.scripts import run

ROOT = Path(__file__).resolve().parents[2]
MAILBOX = "jsmith@example.com"
WINDOW = ("2026-01-01T09:30:00Z", "2026-01-01T10:30:00Z")


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


def test_identifier_needs_a_digit_0_to_7_in_14th_place(document):
    # XDR refused "variable_workflow_02XNISA5IB1H5SM7mfZ8lnhZypPaKoG0HZN": invalid unique_name format.
    variable = document["workflow"]["variables"][0]
    variable["unique_name"] = "variable_workflow_02XNISA5IB1H5SM7mfZ8lnhZypPaKoG0HZN"
    assert "malformed identifier variable_workflow_02XNISA5IB1H5SM7mfZ8lnhZypPaKoG0HZN" in validate.check(document)


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


def test_uses_the_etd_integration_through_xdr_and_asks_for_no_credential(document):
    """XDR asked for a username and password on import: the export now carries no target or account key."""
    assert set(document) == {"workflow", "module_targets"}
    assert document["module_targets"] == [{"module_type": PLATFORM_APIS[0], "external_id": PLATFORM_APIS[1],
                                           "proxy_endpoint_metadata_id": PLATFORM_APIS[2]}]
    variables = {v["properties"]["name"]: v["properties"] for v in document["workflow"]["variables"]}
    assert variables["Dry Run"]["value"] is True
    assert not [name for name, v in variables.items() if v["type"] == "datatype.secure_string"]
    for activity, _ in validate.walk(document["workflow"]["actions"]):
        if activity["type"] == "web-service.http_request":
            assert activity["properties"]["target"]["target_id"] == "$module_target;" + ";".join(PLATFORM_APIS) + "$"
            assert "custom_headers" not in activity["properties"]
    text = json.dumps(document)
    assert "etd.cisco.com" not in text and "example.com" not in text and "assignees" not in text
    for script in (scripts.SELECT_MAILBOXES, scripts.BUILD_OBSERVE, scripts.COLLECT_SIGHTINGS, scripts.ASSESS,
                   scripts.PLAN_MOVES):
        assert "import" in script and not any(word in script for word in ("requests", "urllib", "socket", "subprocess", "os."))


def test_build_tool_accepts_org_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    assert build_tool.main(["--approver-role", "user", "--elevated-role", "admin", "--elevated-approvals", "3"]) == 0
    written = json.loads(next((tmp_path / "xdr").rglob(f"{email_bombing.WORKFLOW_ID}.json")).read_text(encoding="utf-8"))
    standard, _ = _find(written, "Request standard approval")
    elevated, _ = _find(written, "Request elevated approval")
    assert standard["properties"]["assignee_roles"] == ["user"]
    assert elevated["properties"]["assignee_roles"] == ["admin"]
    assert elevated["properties"]["minimum_approvals"] == 3
    with pytest.raises(SystemExit):
        build_tool.main(["--approver-role", "everyone"])
    with pytest.raises(SystemExit):
        build_tool.main(["--etd-host", "api.de.etd.cisco.com"])


def test_request_approval_uses_the_default_choices(document):
    """A custom choice list showed an empty "Approval choices array" in XDR, so the default pair is used."""
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
        "approval_choices": ["Approve", "Reject"], "is_custom_approval_choices": False,
        "is_default_approval_choices": True}
    plan, _ = _find(document, "Plan moves and write decision card")
    assert properties["body_text"] == f"$activity.{plan['unique_name']}.output.script_queries.card$"


# -- approval gate -------------------------------------------------------------------------------------


def test_only_the_move_is_state_changing_and_it_is_gated(document):
    changing = [a["title"] for a, _ in validate.walk(document["workflow"]["actions"]) if validate.is_state_changing(a)]
    assert changing == ["Move approved message"]
    assert validate.check_approval_gate(document) == []
    _, ancestors = _find(document, "Move approved message")
    assert [a["title"] for a in ancestors if a["type"] == "logic.condition_block"][-2:] == [
        "Approved", "Live: execute the approved package"]


def test_elevated_approval_needs_two_people(document):
    elevated, _ = _find(document, "Request elevated approval")
    standard, _ = _find(document, "Request standard approval")
    assert elevated["properties"]["minimum_approvals"] == 2 and elevated["properties"]["assignee_roles"] == ["admin"]
    assert standard["properties"]["minimum_approvals"] == 1
    assert elevated["properties"]["approval_title"].startswith("ELEVATED APPROVAL REQUIRED")
    for request in (elevated, standard):
        assert request["properties"]["approval_choices_holder"]["approval_choices"] == ["Approve", "Reject"]


def _move_out_of_gate(document):
    move, ancestors = _find(document, "Move approved message")
    ancestors[-1]["actions"].remove(move)
    document["workflow"]["actions"].append(move)


def _move_before_approval(document):
    siblings = _siblings(document, "Which approval level?")
    table, _ = _find(document, "Approved moves table")
    loop, _ = _find(document, "For each approved move")
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
    plan, _ = _find(document, "Plan moves and write decision card")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = (
        f"$activity.{plan['unique_name']}.output.script_queries.has_proposal$")


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
    move, _ = _find(document, "Move approved message")
    extra = copy.deepcopy(move)
    extra["unique_name"] = extra["unique_name"][:-3] + "Zz9"
    extra["title"] = "Second move"
    _siblings(document, "Build sightings query").append(extra)


def _delete_request(document):
    sightings, _ = _find(document, "Get ETD sightings through XDR")
    sightings["properties"]["method"] = "DELETE"


def _call_a_workflow(document):
    _siblings(document, "Build sightings query").append({
        "unique_name": "definition_activity_02AAAAAAAAAAA0aaaaaaaaaaaaaaaaaaaaa", "name": "Contain", "title": "Contain",
        "type": "workflow.atomic_workflow", "base_type": "subworkflow", "object_type": "definition_activity",
        "properties": {"workflow_id": "definition_workflow_02AAAAAAAAAAA0aaaaaaaaaaaaaaaaaaaaa"}})


def _swap_package_after_approval(document):
    move, _ = _find(document, "Move approved message")
    move["properties"]["relative_url"] = validate.variable_ref(document, "Candidate Observables")


def _script_writes_decision(document):
    script, _ = _find(document, "Build sightings query")
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
    target = {"definition_target_02AAAAAAAAAAA0aaaaaaaaaaaaaaaaaaaaa": {"properties": {"host": "api.us.etd.cisco.com"}}}
    for mutate, expected in [
        (lambda d: d.update(rules={}), "envelope key"),
        (lambda d: d.update(targets=target), "envelope key 'targets'"),
        (lambda d: d.update(runtime_users={}), "envelope key 'runtime_users'"),
        (lambda d: _find(d, "Build sightings query")[0].update(type="core.sleep"), "activity type"),
        (lambda d: _find(d, "Approved")[0]["properties"]["condition"].update(operator="contains"), "operator"),
        (lambda d: d["workflow"]["variables"][0]["properties"].update(scope="static"), "unresolved variable"),
        (lambda d: _find(d, "Request standard approval")[0]["properties"].update(auto_approve=True), "forbidden"),
        (lambda d: _find(d, "Get ETD sightings through XDR")[0]["properties"].update(
            custom_headers=[{"name": "x-api-key", "value": "abc"}]), "custom header"),
        (lambda d: _find(d, "Get ETD sightings through XDR")[0]["properties"].update(relative_url="/messages/search"),
         "not a known request"),
    ]:
        changed = copy.deepcopy(document)
        mutate(changed)
        assert any(expected in problem for problem in validate.check_structure(changed)), expected


# -- embedded scripts ----------------------------------------------------------------------------------


def _sighting(index: int, *, subject: str = "Welcome to our newsletter", verdict: str = "Neutral",
              sender: str | None = None, when: str = "2026-01-01T10:00:00Z", message_id: bool = True) -> dict:
    observables = [{"type": "email", "value": MAILBOX}, {"type": "email_subject", "value": subject}]
    if message_id:
        observables.append({"type": "email_messageid", "value": f"<msg-{index:04d}@mail.example>"})
    return {"id": f"sighting-{index}", "title": f"Inbound message, verdict {verdict}", "observed_time": {"start_time": when},
            "observables": observables,
            "relations": [{"origin": "Secure Email Threat Defense", "relation": "Sent_From",
                           "source": {"type": "email", "value": sender or f"news@list{index % 40}.example"},
                           "related": {"type": "email", "value": MAILBOX}}]}


def _observe(docs: list[dict], *, count: int | None = None, module: str = "Secure Email Threat Defense",
             extra: list[dict] | None = None) -> str:
    rows = [{"module": module, "module_instance_id": "etd-1",
             "data": {"sightings": {"count": len(docs) if count is None else count, "docs": docs}}}]
    return json.dumps({"data": rows + (extra or [])})


def _collect(docs: list[dict], *, status: int = 200, max_messages: int = 200, **kwargs) -> dict:
    raw = docs if isinstance(docs, str) else _observe(docs, **kwargs)
    return json.loads(run(scripts.COLLECT_SIGHTINGS, status, raw, MAILBOX, *WINDOW, max_messages)["state_json"])


def _assess(state: dict, *, protected: str = "false", trusted: str = "") -> dict:
    return run(scripts.ASSESS, json.dumps(state), MAILBOX, protected, 30, 10, 50, *WINDOW, trusted)


def _offers(assessed: dict, *, title: str = "Move to Quarantine", **params) -> str:
    rows = []
    for obs in json.loads(assessed["respond_body"]):
        rows.append({"id": "etd-move-quarantine", "title": title, "module": "Secure Email Threat Defense",
                     "module_instance_id": "etd-instance-1",
                     "query-params": {"observable_type": obs["type"], "observable_value": obs["value"], **params}})
    return json.dumps({"data": rows})


def _plan(assessed: dict, respond: str, *, status: int = 200, dry_run: str = "True", folder: str = "quarantine",
          pattern: str = email_bombing.MOVE_PATTERN, elevated_above: int = 100) -> dict:
    return run(scripts.PLAN_MOVES, status, respond, assessed["respond_body"], MAILBOX, assessed["evidence"],
               assessed["elevated_reasons"], dry_run, folder, pattern, elevated_above)


def _flood(count: int = 120) -> list[dict]:
    return [_sighting(i) for i in range(count)]


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


def test_build_observe_asks_xdr_for_the_mailbox_and_bounds_the_window():
    result = run(scripts.BUILD_OBSERVE, " JSmith@Example.com ", "999999")
    assert json.loads(result["observe_body"]) == [{"type": "email", "value": "jsmith@example.com"}]
    assert result["window_start"] < result["window_end"]


def test_collect_reads_etd_sightings_and_ignores_other_modules():
    docs = _flood(50) + [_sighting(900, sender=MAILBOX), _sighting(901, when="2026-01-01T07:00:00Z"), _sighting(3)]
    other = [{"module": "Secure Endpoint", "data": {"sightings": {"count": 7, "docs": [_sighting(950)]}}}]
    state = _collect(docs, extra=other)
    assert len(state["messages"]) == 50  # outbound, outside the window and duplicate left out
    assert state["outside"] == 1 and state["other_modules"] == {"Secure Endpoint": 7}
    assert state["modules"] == {"Secure Email Threat Defense": 53} and not state["truncated"] and not state["error"]
    kind, value, domain, label, topic, when = state["messages"][0]
    assert (kind, value, domain, label, when) == ("email_messageid", "<msg-0000@mail.example>", "list0.example",
                                                  "neutral", "2026-01-01T10:00:00Z")


def test_collect_marks_a_partial_answer_and_the_collection_limit():
    assert _collect(_flood(20), count=500)["truncated"]
    capped = _collect(_flood(50), max_messages=30)
    assert len(capped["messages"]) == 30 and capped["truncated"]


def test_collect_records_a_failed_source():
    assert "HTTP 502" in _collect("Bad Gateway", status=502)["error"]
    assert _collect("not json")["error"]
    assert _collect(json.dumps({"data": "unexpected"})) ["messages"] == []


def test_collect_cleans_product_text():
    hostile = _sighting(1, subject="Reset your password **now** [click](https://evil.example)",
                        sender="x@evil`.example\n## injected")
    state = _collect([hostile])
    assert state["messages"][0][2] == "evil"  # cut at the first character a domain cannot hold
    assert not any(c in state["buried"][0]["subject"] + state["buried"][0]["from"] for c in "*[]`#\n")


def test_assess_measures_the_flood_and_keeps_buried_messages():
    docs = _flood(120)
    docs.append(_sighting(900, subject="Your password was changed", sender="no-reply@bank.example"))
    docs.append(_sighting(901, subject="Reset your password now", verdict="Phishing", sender="x@bad.example"))
    docs.append(_sighting(902, subject="Quarterly report", sender="partner@trusted.example"))
    result = _assess(_collect(docs), trusted="trusted.example")
    assert result["qualifies"] == "true" and json.loads(result["elevated_reasons"]) == []
    moved = [obs["value"] for obs in json.loads(result["respond_body"])]
    assert "<msg-0900@mail.example>" not in moved and "<msg-0902@mail.example>" not in moved
    assert "<msg-0901@mail.example>" in moved and result["move_count"] == "121" and len(moved) == 121
    assert "Your password was changed" in result["evidence"] and "Check the account" in result["evidence"]


def test_assess_does_not_propose_below_the_thresholds():
    few = _assess(_collect(_flood(12)))
    assert few["qualifies"] == "false" and few["respond_body"] == "[]" and few["move_count"] == "0"
    one_sender = _assess(_collect([_sighting(i, sender="bulk@one.example") for i in range(200)]))
    assert one_sender["qualifies"] == "false"
    spam_storm = _assess(_collect([_sighting(i, verdict="Spam") for i in range(200)]))
    assert spam_storm["qualifies"] == "false" and "No action proposed" in spam_storm["summary"]


def test_assess_without_verdicts_skips_that_threshold_and_says_so():
    docs = [_sighting(i, verdict="unrated") for i in range(60)]
    result = _assess(_collect(docs))
    assert result["qualifies"] == "true" and "threshold was not applied" in result["evidence"]


def test_assess_needs_message_ids_to_act():
    result = _assess(_collect([_sighting(i, message_id=False) for i in range(60)]))
    assert result["qualifies"] == "false" and "no message of the flood carries a message ID" in result["summary"]


def test_assess_surfaces_elevated_reasons_instead_of_blocking():
    assert "protected list" in _assess(_collect(_flood()), protected="true")["elevated_reasons"]
    assert "only part of the sightings" in _assess(_collect(_flood(), count=900))["elevated_reasons"]


def test_assess_reports_a_failed_source():
    empty = _assess(_collect("Forbidden", status=403))
    assert empty["qualifies"] == "false" and "HTTP 403" in empty["summary"]


def test_plan_lists_one_move_per_message_with_the_offered_action():
    assessed = _assess(_collect(_flood()))
    result = _plan(assessed, _offers(assessed, folder_id="7"))
    actions = json.loads(result["actions_json"])
    assert result["has_proposal"] == "true" and result["action_count"] == "120" == str(len(actions))
    url = urlsplit(actions[0]["url"])
    assert url.path == "/iroh-response/respond/trigger/etd-instance-1/etd-move-quarantine"
    query = parse_qs(url.query)
    assert query["observable_type"] == ["email_messageid"] and query["folder_id"] == ["7"]
    assert query["observable_value"][0] in [obs["value"] for obs in json.loads(assessed["respond_body"])]
    assert "DRY RUN" in result["card"] and result["package_digest"] in result["card"]
    assert "*Reject* changes nothing" in result["card"] and "More investigation" not in result["card"]
    assert result["elevated"] == "true"  # 120 is above the default limit of 100
    assert _plan(assessed, _offers(assessed, folder_id="7"))["package_digest"] == result["package_digest"]
    assert len(json.loads(result["verify_body"])) == 120


def test_plan_needs_the_folder_and_never_picks_an_undo_action():
    assessed = _assess(_collect(_flood(40)))
    for title in ("Release from Quarantine", "Move to Inbox", "Move to Junk", "Delete message"):
        assert _plan(assessed, _offers(assessed, title=title))["has_proposal"] == "false", title
    assert _plan(assessed, _offers(assessed, title="Move to Junk"), folder="junk")["has_proposal"] == "true"
    none = _plan(assessed, _offers(assessed, title="Release from Quarantine"))
    assert "Release from Quarantine" in none["summary"] and "Move Action Pattern" in none["summary"]
    with pytest.raises(SystemExit):
        _plan(assessed, _offers(assessed), folder="delete")
    with pytest.raises(SystemExit):
        _plan(assessed, _offers(assessed), pattern="(")


def test_plan_acts_only_on_listed_messages():
    assessed = _assess(_collect(_flood(40)))
    foreign = json.dumps({"data": [{"id": "move", "title": "Move to Quarantine", "module": "ETD",
                                    "module_instance_id": "i", "query-params": {
                                        "observable_type": "email_messageid", "observable_value": "<ceo@corp>"}}]})
    result = _plan(assessed, foreign)
    assert result["has_proposal"] == "false" and "<ceo@corp>" not in result["actions_json"]


def test_plan_reports_a_missing_integration_or_a_failed_source():
    assessed = _assess(_collect(_flood(40)))
    assert "Secure Email Threat Defense integration is enabled" in _plan(assessed, json.dumps({"data": []}))["summary"]
    assert "HTTP 500" in _plan(assessed, "error", status=500)["summary"]


def test_plan_treats_anything_but_false_as_dry_run():
    assessed = _assess(_collect(_flood(40)))
    assert "LIVE" in _plan(assessed, _offers(assessed), dry_run="false")["card"]
    for value in ("True", "true", "", "0", "no"):
        assert "DRY RUN" in _plan(assessed, _offers(assessed), dry_run=value)["card"]


def test_trigger_results_use_the_incident_steps():
    assessed = _assess(_collect(_flood(40)))
    action = json.loads(_plan(assessed, _offers(assessed))["actions_json"])[0]
    tally = run(incident_scripts.RECORD_TRIGGER, "{}", 200, json.dumps({"data": {"status": "success"}}),
                action["title"], action["target"], action["key"])["tally_json"]
    result = run(incident_scripts.RESULT, '{"name": "Email Bombing"}', "abc", tally, 200, json.dumps({"data": []}))
    assert result["result"].startswith("Email Bombing: APPROVED and executed") and "1 of 1" in result["result"]


# -- staying under XDR's 4 MB activity limit ----------------------------------------------------------


def _module_types(*rows: dict) -> str:
    return json.dumps(list(rows))


def test_find_email_modules_reads_the_etd_module_type():
    raw = _module_types({"title": "Secure Email Threat Defense", "product_categories": ["email-security", "Bad Value!"]},
                        {"title": "Secure Endpoint", "product_categories": ["edr"]})
    result = run(scripts.FIND_EMAIL_MODULES, 200, raw, "")
    assert result["found"] == "true" and result["module_filter"] == "product_categories=email-security"
    assert "Secure Email Threat Defense" in result["modules_text"] and "edr" not in result["module_filter"]


def test_find_email_modules_prefers_the_input_and_reports_nothing_found():
    assert run(scripts.FIND_EMAIL_MODULES, 200, "[]", "Email, other-cat")["module_filter"] == (
        "product_categories=email&product_categories=other-cat")
    missing = run(scripts.FIND_EMAIL_MODULES, 200, _module_types({"title": "Umbrella", "product_categories": ["dns"]}), "")
    assert missing["found"] == "false" and missing["module_filter"] == ""
    failed = run(scripts.FIND_EMAIL_MODULES, 401, "Unauthorized", "")
    assert failed["found"] == "false" and "HTTP 401" in failed["modules_text"]
    assert run(scripts.FIND_EMAIL_MODULES, 200, "[]", "x&mids=1")["module_filter"] == ""  # not a category


def test_sightings_ask_email_modules_only(document):
    sightings, ancestors = _find(document, "Get ETD sightings through XDR")
    modules, _ = _find(document, "Find email modules")
    assert sightings["properties"]["relative_url"] == (
        f"/iroh-enrich/observe/observables?$activity.{modules['unique_name']}.output.script_queries.module_filter$")
    assert "Email modules found" in [a["title"] for a in ancestors]
    lookup, _ = _find(document, "List ETD module types")
    assert lookup["properties"]["method"] == "GET" and "content_type" not in lookup["properties"]
    assert not validate.is_state_changing(sightings) and not validate.is_state_changing(lookup)


def test_validator_accepts_only_the_exact_filtered_query(document):
    for url in ("/iroh-enrich/observe/observables?mids=x",
                "/iroh-enrich/observe/observables?$activity.definition_activity_02AAAAAAAAAAA0aaaaaaaaaaaaaaaaaaaaa.output.script_queries.card$",
                "/iroh-int/module-instance"):
        changed = copy.deepcopy(document)
        _find(changed, "Get ETD sightings through XDR")[0]["properties"]["relative_url"] = url
        assert any("not a known request" in p for p in validate.check_structure(changed)), url
