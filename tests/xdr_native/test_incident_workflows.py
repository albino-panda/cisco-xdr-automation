"""The attack-type workflows built on the shared incident response workflow (``xdr_native.incident``)."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from tools.xdr_native import build as build_tool
from xdr_native import email_bombing, incident, specs, validate
from xdr_native import incident_scripts as scripts
from xdr_native.builder import PLATFORM_APIS, module_target_ref
from xdr_native.scripts import run

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = module_target_ref(PLATFORM_APIS)
TRIGGER = "Trigger response action"
SPEC_IDS = [spec.design for spec in specs.SPECS]


@pytest.fixture(params=specs.SPECS, ids=SPEC_IDS)
def spec(request) -> incident.Spec:
    return request.param


@pytest.fixture()
def document(spec) -> dict:
    return incident.build(spec).export()


@pytest.fixture()
def ransomware() -> dict:
    return incident.build(specs.BY_DESIGN["ransomware"]).export()


def _find(document: dict, title: str) -> tuple[dict, tuple[dict, ...]]:
    for activity, ancestors in validate.walk(document["workflow"]["actions"]):
        if activity["title"] == title:
            return activity, ancestors
    raise AssertionError(title)


def _siblings(document: dict, title: str) -> list[dict]:
    _, ancestors = _find(document, title)
    return ancestors[-1]["actions"]


# -- catalog -------------------------------------------------------------------------------------------


def test_every_design_has_a_workflow():
    designs = {path.name for path in (ROOT / "workflows").iterdir() if path.is_dir()}
    assert {spec.design for spec in specs.SPECS} | {"mail-bombing"} == designs
    assert len(specs.SPECS) == 21 and len({spec.name for spec in specs.SPECS}) == 21
    assert "Email Bombing" not in {spec.name for spec in specs.SPECS}


def test_identifiers_are_unique_across_all_workflows():
    built = build_tool.workflows(email_bombing.Settings())
    assert len(built) == 22 and len({w.id for w in built}) == 22 and len({w.folder for w in built}) == 22
    activity_ids = [a["unique_name"] for w in built for a, _ in validate.walk(w.export()["workflow"]["actions"])]
    variable_ids = [v["unique_name"] for w in built for v in w.export()["workflow"]["variables"]]
    assert len(set(activity_ids)) == len(activity_ids) and len(set(variable_ids)) == len(variable_ids)


def test_committed_exports_are_current():
    assert build_tool.main(["--check"]) == 0


def test_check_reports_a_folder_that_is_no_longer_generated(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    assert build_tool.main([]) == 0
    (tmp_path / "xdr" / "Old-Workflow__definition_workflow_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa").mkdir()
    assert build_tool.main(["--check"]) == 1
    assert "not generated any more" in capsys.readouterr().err


def test_spec_refuses_what_the_workflow_cannot_do():
    with pytest.raises(ValueError, match="unknown action kind"):
        incident.Rule("delete_mailbox", 60, "x")
    with pytest.raises(ValueError, match="cannot target"):
        incident.Rule("isolate_endpoint", 60, "x", ("domain",))
    with pytest.raises(ValueError, match="min_risk"):
        incident.Rule("block_hash", 101, "x")
    bad = incident.Spec(design="x", name="X", purpose="p", rules=(incident.Rule("block_hash", 60, "costs $5 $"),))
    with pytest.raises(ValueError, match="dollar sign"):
        incident.build(bad)


# -- export ----------------------------------------------------------------------------------------------


def test_export_is_valid_and_within_xdr_limits(document, spec):
    assert validate.check(document) == []
    workflow = document["workflow"]
    assert workflow["name"] == spec.name and workflow["template_type"] == "template_workflow.incident_response"
    assert workflow["properties"]["automation_rules"] == {"type": ["incident.rule_event"]}
    assert workflow["properties"]["wf_metadata"]["coa"] == {
        "action": ["response"], "intent": "incident_response", "observable_types": spec.types}
    assert len(list(validate.walk(workflow["actions"]))) <= 100 and len(workflow["variables"]) <= 100


def test_export_needs_no_target_account_key_or_secret(document):
    assert set(document) == {"workflow", "module_targets"}
    assert document["module_targets"] == [{"module_type": "Cisco XDR", "external_id": "securex:ao:iroh_api",
                                           "proxy_endpoint_metadata_id": "platform-apis"}]
    variables = {v["properties"]["name"]: v["properties"] for v in document["workflow"]["variables"]}
    assert not [name for name, p in variables.items() if p["type"] == "datatype.secure_string"]
    assert variables["Dry Run"]["value"] is True and variables["Block Unrated Indicators"]["value"] is False
    requests = [a for a, _ in validate.walk(document["workflow"]["actions"]) if a["type"] == "web-service.http_request"]
    assert len(requests) == 5
    for request in requests:
        properties = request["properties"]
        assert properties["target"] == {"override_workflow_target": True, "target_id": PLATFORM}
        assert properties["method"] == "POST" and "custom_headers" not in properties
        assert properties["runtime_user"] == {"target_default": True}


def test_reads_are_the_three_verified_platform_calls(document):
    reads = [a["properties"]["relative_url"] for a, _ in validate.walk(document["workflow"]["actions"])
             if a["type"] == "web-service.http_request" and not validate.is_state_changing(a)]
    assert reads == ["/iroh-enrich/deliberate/observables", "/iroh-enrich/observe/observables",
                     "/iroh-response/respond/observables", "/iroh-response/respond/observables"]
    assert set(reads) == set(incident.PLATFORM_READS)


def test_only_the_trigger_is_state_changing_and_it_is_gated(document):
    changing = [a["title"] for a, _ in validate.walk(document["workflow"]["actions"]) if validate.is_state_changing(a)]
    assert changing == [TRIGGER]
    trigger, ancestors = _find(document, TRIGGER)
    assert [a["title"] for a in ancestors if a["type"] == "logic.condition_block"][-2:] == [
        "Approved", "Live: execute the approved package"]
    loop, _ = _find(document, "For each approved action")
    assert trigger["properties"]["relative_url"] == f"$activity.{loop['unique_name']}.input.source_array[@].url$"
    assert "body" not in trigger["properties"]
    table, _ = _find(document, "Approved actions table")
    assess, _ = _find(document, "Assess and write decision card")
    assert table["properties"]["input_json"] == f"$activity.{assess['unique_name']}.output.script_queries.actions_json$"
    for level in ("standard", "elevated"):
        request, _ = _find(document, f"Request {level} approval")
        assert request["properties"]["body_text"] == f"$activity.{assess['unique_name']}.output.script_queries.card$"


def test_approval_requests_follow_the_org_export(document, spec):
    standard, _ = _find(document, "Request standard approval")
    elevated, _ = _find(document, "Request elevated approval")
    assert standard["properties"]["assignee_roles"] == ["admin", "user"] and standard["properties"]["minimum_approvals"] == 1
    assert elevated["properties"]["assignee_roles"] == ["admin"] and elevated["properties"]["minimum_approvals"] == 2
    assert elevated["properties"]["approval_title"].startswith(f"ELEVATED APPROVAL REQUIRED - {spec.name}")
    reference, _ = email_bombing.build().export(), None
    for activity, _ in validate.walk(reference["workflow"]["actions"]):
        if activity["title"] == "Request standard approval":
            assert set(activity["properties"]) == set(standard["properties"])
    for request in (standard, elevated):
        # XDR showed an empty "Approval choices array" for a custom list, so the default pair is used.
        assert request["properties"]["approval_choices_holder"] == {
            "approval_choices": ["Approve", "Reject"], "is_custom_approval_choices": False,
            "is_default_approval_choices": True}
        assert request["properties"]["wait_for_request_approval_response"] is True


def test_inputs_match_the_spec(document, spec):
    variables = {v["properties"]["name"]: v["properties"] for v in document["workflow"]["variables"]}
    assert variables["Excluded Actions"]["value"] == ", ".join(spec.excluded)
    for kind, (title, default) in incident.ACTION_PATTERNS.items():
        if kind in spec.kinds:
            assert variables[title]["value"] == default and re.compile(default)
        else:
            assert title not in variables
    rules = validate.variable_ref(document, "Workflow Rules")
    passed = json.loads(variables["Workflow Rules"]["value"])
    assert variables["Workflow Rules"]["scope"] == "local"
    assert passed["name"] == spec.name and passed["types"] == spec.types and len(passed["rules"]) == len(spec.rules)
    assert all(rule["basis"] in ("asset", "indicator") and rule["label"] for rule in passed["rules"])
    classify, _ = _find(document, "Classify observables")
    assess, _ = _find(document, "Assess and write decision card")
    result, _ = _find(document, "Build containment result")
    assert classify["properties"]["script_arguments"][1] == rules == assess["properties"]["script_arguments"][8]
    assert result["properties"]["script_arguments"][0] == rules
    arguments = assess["properties"]["script_arguments"]
    assert len(arguments) == 18 + len(spec.kinds)
    assert arguments[18:] == [validate.variable_ref(document, incident.ACTION_PATTERNS[kind][0]) for kind in spec.kinds]


def test_build_tool_applies_org_roles_to_every_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    assert build_tool.main(["--approver-role", "user", "--elevated-approvals", "3"]) == 0
    files = list((tmp_path / "xdr").rglob("*.json"))
    assert len(files) == 22
    for path in files:
        written = json.loads(path.read_text(encoding="utf-8"))
        assert _find(written, "Request standard approval")[0]["properties"]["assignee_roles"] == ["user"]
        assert _find(written, "Request elevated approval")[0]["properties"]["minimum_approvals"] == 3


# -- approval gate ---------------------------------------------------------------------------------------


def _move_out_of_gate(document):
    table, ancestors = _find(document, "Approved actions table")
    loop, _ = _find(document, "For each approved action")
    ancestors[-1]["actions"].remove(table)
    ancestors[-1]["actions"].remove(loop)
    document["workflow"]["actions"] += [table, loop]


def _trigger_before_approval(document):
    siblings = _siblings(document, "Which approval level?")
    table, _ = _find(document, "Approved actions table")
    loop, _ = _find(document, "For each approved action")
    siblings[0:0] = [copy.deepcopy(table), copy.deepcopy(loop)]


def _invert_gate(document):
    _find(document, "Approved")[0]["properties"]["condition"]["operator"] = "ne"


def _weaken_gate_to_or(document):
    branch, _ = _find(document, "Approved")
    branch["properties"]["condition"] = {"left_operand": branch["properties"]["condition"], "operator": "or",
                                         "right_operand": {"left_operand": "1", "operator": "eq", "right_operand": "1"}}


def _self_approve(document):
    _find(document, "Record standard decision")[0]["properties"]["variables_to_update"][0]["variable_value_new"] = "Approve"


def _approve_at_start(document):
    start, _ = _find(document, "Start with the Observables input")
    for update in start["properties"]["variables_to_update"]:
        if update["variable_to_update"] == validate.variable_ref(document, "Decision"):
            update["variable_value_new"] = "Approve"


def _approve_from_script(document):
    record, _ = _find(document, "Record standard decision")
    assess, _ = _find(document, "Assess and write decision card")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = (
        f"$activity.{assess['unique_name']}.output.script_queries.has_proposal$")


def _do_not_wait(document):
    _find(document, "Request standard approval")[0]["properties"]["wait_for_request_approval_response"] = False


def _skip_the_request(document):
    _find(document, "Request elevated approval")[0]["properties"]["skip_execution"] = True


def _answer_of_another_task(document):
    record, _ = _find(document, "Record standard decision")
    other, _ = _find(document, "Request elevated approval")
    record["properties"]["variables_to_update"][0]["variable_value_new"] = f"$activity.{other['unique_name']}.output.response$"


def _drop_the_request(document):
    siblings = _siblings(document, "Request standard approval")
    siblings[:] = [a for a in siblings if a["type"] != "task.request_approval"]


def _remove_dry_run_gate(document):
    live, _ = _find(document, "Live: execute the approved package")
    _find(document, "Approved")[0]["actions"] = live["actions"]


def _dry_run_gate_on_true(document):
    _find(document, "Live: execute the approved package")[0]["properties"]["condition"]["right_operand"] = True


def _no_assignee(document):
    _find(document, "Request standard approval")[0]["properties"]["assignee_roles"] = []


def _zero_approvals(document):
    _find(document, "Request elevated approval")[0]["properties"]["minimum_approvals"] = 0


def _remove_approve_choice(document):
    _find(document, "Request standard approval")[0]["properties"]["approval_choices_holder"]["approval_choices"] = ["Reject"]


def _second_trigger_during_investigation(document):
    extra = copy.deepcopy(_find(document, TRIGGER)[0])
    extra["unique_name"] = extra["unique_name"][:-3] + "Zz9"
    extra["title"] = "Second trigger"
    _siblings(document, "Get verdicts").append(extra)


def _read_becomes_a_write(document):
    _find(document, "Get verdicts")[0]["properties"]["relative_url"] = "/iroh-response/respond/trigger/module/action"


def _delete_request(document):
    _find(document, "List response actions")[0]["properties"]["method"] = "DELETE"


def _call_a_workflow(document):
    _siblings(document, "Get verdicts").append({
        "unique_name": "definition_activity_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa", "name": "Contain", "title": "Contain",
        "type": "workflow.atomic_workflow", "base_type": "subworkflow", "object_type": "definition_activity",
        "properties": {"workflow_id": "definition_workflow_023KVFX7H9O0Z1OfA9nqcQ3SLNoWyX8wtC9"}})


def _url_from_a_variable(document):
    _find(document, TRIGGER)[0]["properties"]["relative_url"] = validate.variable_ref(document, "Candidate Observables")


def _constant_url(document):
    _find(document, TRIGGER)[0]["properties"]["relative_url"] = "/iroh-response/respond/trigger/module/isolate?observable_value=dc01"


def _url_computed_after_approval(document):
    table, _ = _find(document, "Approved actions table")
    result, _ = _find(document, "Build containment result")
    table["properties"]["input_json"] = f"$activity.{result['unique_name']}.output.script_queries.result$"


def _url_with_an_appended_value(document):
    trigger, _ = _find(document, TRIGGER)
    trigger["properties"]["relative_url"] += validate.variable_ref(document, "Never Act On")


def _body_from_a_variable(document):
    _find(document, TRIGGER)[0]["properties"]["body"] = validate.variable_ref(document, "Candidate Observables")


def _script_writes_decision(document):
    script, _ = _find(document, "Classify observables")
    script["properties"]["script"] += "\n# " + validate.variable_ref(document, "Decision")


BYPASSES = [
    _move_out_of_gate, _trigger_before_approval, _invert_gate, _weaken_gate_to_or, _self_approve, _approve_at_start,
    _approve_from_script, _do_not_wait, _skip_the_request, _answer_of_another_task, _drop_the_request,
    _remove_dry_run_gate, _dry_run_gate_on_true, _no_assignee, _zero_approvals, _remove_approve_choice,
    _second_trigger_during_investigation, _read_becomes_a_write, _delete_request, _call_a_workflow,
    _url_from_a_variable, _constant_url, _url_computed_after_approval, _url_with_an_appended_value,
    _body_from_a_variable, _script_writes_decision,
]


@pytest.mark.parametrize("bypass", BYPASSES, ids=lambda f: f.__name__.lstrip("_"))
def test_gate_check_rejects_every_bypass(ransomware, bypass):
    assert validate.check_approval_gate(ransomware) == []
    bypass(ransomware)
    assert validate.check_approval_gate(ransomware), f"{bypass.__name__} was not detected"


@pytest.mark.parametrize("bypass", [_move_out_of_gate, _self_approve, _remove_dry_run_gate, _url_from_a_variable],
                         ids=lambda f: f.__name__.lstrip("_"))
def test_gate_check_holds_for_every_attack_type(document, bypass):
    bypass(document)
    assert validate.check_approval_gate(document)


def test_structure_check_rejects_other_module_targets(ransomware):
    for mutate, expected in [
        (lambda d: d["module_targets"].append({"module_type": "Cisco XDR", "external_id": "securex:ao:sxo",
                                               "proxy_endpoint_metadata_id": "automation-apis"}), "module target"),
        (lambda d: d["module_targets"][0].update(host="evil.example"), "module target"),
        (lambda d: d.update(module_targets=[]), "unknown target"),
        (lambda d: _find(d, "Get verdicts")[0]["properties"]["target"].update(
            target_id="$module_target;Cisco XDR;securex:ao:sxo;automation-apis$"), "unknown target"),
        (lambda d: d.update(atomic_workflows=[]), "envelope key"),
        (lambda d: _find(d, "Classify observables")[0].update(type="core.sleep"), "activity type"),
    ]:
        changed = copy.deepcopy(ransomware)
        mutate(changed)
        assert any(expected in problem for problem in validate.check_structure(changed)), expected


# -- embedded scripts: classification --------------------------------------------------------------------

ALL_TYPES = ["hostname", "domain", "url", "ip", "ipv6", "sha256", "sha1", "md5", "email", "user", "email_messageid"]
SHA = "a" * 64


def _classify(candidates: str, allowed=None, internal: str = "", limit: int = 20, sightings: str = "True") -> dict:
    return run(scripts.CLASSIFY, candidates, json.dumps({"types": allowed or ALL_TYPES}), internal, limit, sightings)


def _rows(result: dict) -> list[tuple[str, str]]:
    return [(row["type"], row["value"]) for row in json.loads(result["observables_json"])]


def test_classify_types_every_supported_value():
    result = _classify("\n".join([
        "LAPTOP-042", "Evil.Example.NET", "https://evil.example.net/a?b=c,d", "203.0.113.9", "2001:DB8::1",
        SHA.upper(), "b" * 40, "c" * 32, "JSmith@Example.com", "<abc@mail.example>"]))
    assert _rows(result) == [
        ("hostname", "LAPTOP-042"), ("user", "LAPTOP-042"), ("domain", "evil.example.net"),
        ("url", "https://evil.example.net/a?b=c,d"), ("ip", "203.0.113.9"), ("ipv6", "2001:db8::1"), ("sha256", SHA),
        ("sha1", "b" * 40), ("md5", "c" * 32), ("email", "jsmith@example.com"), ("user", "jsmith@example.com"),
        ("email_messageid", "<abc@mail.example>")]
    assert result["observable_count"] == "12" and result["ignored_count"] == "0"
    assert result["intake"].startswith("1 domain, 1 email, 1 email_messageid")


def test_classify_refangs_dedupes_splits_and_ignores_free_text():
    result = _classify("hxxp://evil[.]example[.]net/x\nevil[.]example[.]net, 203.0.113.9; 203.0.113.9\n"
                       "the user clicked a link\n999.1.1.1\n\n  \"LAPTOP-042\"  \nlaptop-042")
    assert _rows(result) == [("url", "http://evil.example.net/x"), ("domain", "evil.example.net"),
                             ("ip", "203.0.113.9"), ("domain", "999.1.1.1"), ("hostname", "LAPTOP-042"),
                             ("user", "LAPTOP-042")]
    assert result["ignored_count"] == "1"
    mixed = _classify("evil.example.net, https://evil.example/a?b=c,d; 203.0.113.9,\n<a@b.example>, <c@d.example>")
    assert _rows(mixed) == [("domain", "evil.example.net"), ("url", "https://evil.example/a?b=c,d"),
                            ("ip", "203.0.113.9"), ("email_messageid", "<a@b.example>"),
                            ("email_messageid", "<c@d.example>")]
    assert _classify("https://evil.example/`x`\n<a`b@c.example>\n" + "h" * 2001)["ignored_count"] == "3"


def test_classify_keeps_only_the_types_of_the_workflow():
    allowed = specs.BY_DESIGN["password-spray"].types
    result = _classify(f"203.0.113.9\nevil.example.net\n{SHA}\njsmith@example.com\nLAPTOP-042", allowed)
    assert _rows(result) == [("ip", "203.0.113.9"), ("email", "jsmith@example.com"), ("user", "jsmith@example.com"),
                             ("user", "LAPTOP-042")]
    assert result["ignored_count"] == "2"
    assert _rows(_classify("jsmith", ["hostname", "user"])) == [("hostname", "jsmith"), ("user", "jsmith")]
    assert _rows(_classify("jsmith", ["hostname", "sha256"])) == [("hostname", "jsmith")]


def test_classify_uses_internal_suffixes_to_tell_hosts_from_domains():
    result = _classify("fs01.corp.example.com\nevil.example.net", internal="*.corp.example.com, example.org")
    assert _rows(result) == [("hostname", "fs01.corp.example.com"), ("domain", "evil.example.net")]
    assert _rows(_classify("fs01.corp.example.com", internal="example.org  corp.example.com")) == [
        ("hostname", "fs01.corp.example.com")]
    hosts_only = ["hostname", "sha256"]
    assert _rows(_classify("fs01.corp.example.com\nevil.example.net", hosts_only)) == [
        ("hostname", "fs01.corp.example.com"), ("hostname", "evil.example.net")]
    assert _rows(_classify("fs01.corp.example.com\nevil.example.net", hosts_only, internal="corp.example.com")) == [
        ("hostname", "fs01.corp.example.com")]


def test_classify_caps_the_run_and_can_skip_sightings():
    result = _classify("\n".join(f"host-{i}" for i in range(30)), ["hostname"], limit=5)
    assert result["observable_count"] == "5" and result["over_limit_count"] == "25"
    assert result["observe_body"] == result["observables_json"]
    assert _classify("host-1", sightings="False")["observe_body"] == "[]"
    assert _classify("host-1", ["hostname"], limit=9999)["observable_count"] == "1" and _classify("", limit=0)["observable_count"] == "0"
    assert _classify("")["intake"] == "none"


# -- embedded scripts: assessment ------------------------------------------------------------------------

PATTERNS = [incident.ACTION_PATTERNS[kind][1] for kind in scripts.KINDS]


def _verdict(kind: str, value: str, disposition: int, module: str = "Umbrella") -> dict:
    return {"module": module, "data": {"verdicts": {"count": 1, "docs": [
        {"disposition": disposition, "observable": {"type": kind, "value": value}}]}}}


def _offer(action_id: str, title: str, module: str, kind: str, value: str, **extra) -> dict:
    return {"id": action_id, "title": title, "module": module, "module_instance_id": "inst-" + module.replace(" ", "-"),
            "query-params": {"observable_type": kind, "observable_value": value, **extra}}


OFFERS = [
    _offer("isolate", "Isolate Host", "Secure Endpoint", "hostname", "LAPTOP-042"),
    _offer("stop-isolate", "Stop Isolating Host", "Secure Endpoint", "hostname", "LAPTOP-042"),
    _offer("isolate", "Isolate Host", "Secure Endpoint", "hostname", "DC-01"),
    _offer("scd-add", 'Add SHA256 to custom detections "Quick SCD"', "Secure Endpoint", "sha256", SHA, list="abc 1"),
    _offer("scd-add-2", 'Add SHA256 to custom detections "Other"', "Secure Endpoint", "sha256", SHA),
    _offer("scd-remove", 'Remove SHA256 from custom detections "Quick SCD"', "Secure Endpoint", "sha256", SHA),
    _offer("mde-block", "Block file hash", "Microsoft Defender for Endpoint", "sha256", SHA),
    _offer("block", "Block this domain", "Umbrella", "domain", "evil.example.net"),
    _offer("unblock", "Unblock this domain", "Umbrella", "domain", "evil.example.net"),
    _offer("block", "Block this domain", "Umbrella", "domain", "new.example.net"),
    _offer("block", "Block this domain", "Umbrella", "domain", "clean.example.net"),
    _offer("block-ip", "Block IP", "Umbrella", "ip", "203.0.113.9"),
    _offer("block-ip", "Block IP", "Umbrella", "ip", "10.1.2.3"),
    _offer("revoke", "Revoke sessions", "Microsoft Entra ID", "email", "jsmith@example.com"),
    _offer("disable", "Disable user", "Microsoft Entra ID", "email", "jsmith@example.com"),
    _offer("enable", "Enable user", "Microsoft Entra ID", "email", "jsmith@example.com"),
    _offer("revoke", "Revoke sessions", "Microsoft Entra ID", "email", "attacker@bad.example"),
    _offer("quarantine", "Quarantine message", "Secure Email Threat Defense", "email_messageid", "<abc@mail.example>"),
]
VERDICTS = [
    _verdict("domain", "evil.example.net", 2), _verdict("domain", "evil.example.net", 3, "VirusTotal"),
    _verdict("domain", "clean.example.net", 1), _verdict("sha256", SHA, 2, "Secure Endpoint"),
    _verdict("ip", "203.0.113.9", 3, "VirusTotal"),
]
CANDIDATES = (f"LAPTOP-042\nevil.example.net\nnew.example.net\nclean.example.net\n203.0.113.9\n10.1.2.3\n{SHA}\n"
              "jsmith@example.com\nattacker@bad.example\n<abc@mail.example>")


def _assess(design: str = "ransomware", candidates: str = CANDIDATES, *, started: str = "incident_rule",
            verdicts=VERDICTS, offers=OFFERS, sightings=None, statuses=(200, 200, 200), dry_run: str = "True",
            protected: str = "", never: str = "", excluded: str | None = None, above: int = 5, trust: str = "True",
            unrated: str = "False", internal: str = "", patterns=None, raw=None, collect: str = "True") -> dict:
    spec = specs.BY_DESIGN[design]
    observables = _classify(candidates, spec.types, internal)["observables_json"]
    bodies = raw or (json.dumps({"data": verdicts}), json.dumps({"data": sightings or []}), json.dumps({"data": offers}))
    return run(scripts.ASSESS, observables, started, statuses[0], bodies[0], statuses[1], bodies[1], statuses[2],
               bodies[2], spec.script_spec(), dry_run, protected, never,
               ", ".join(spec.excluded) if excluded is None else excluded, above, trust, unrated, internal, collect,
               *[(patterns or PATTERNS)[scripts.KINDS.index(kind)] for kind in spec.kinds])


def _actions(result: dict) -> list[tuple[str, str, str]]:
    return [(row["kind"], row["target"], row["title"]) for row in json.loads(result["actions_json"])]


def test_assess_proposes_indicators_on_their_verdict_and_assets_on_the_incident():
    result = _assess()
    assert result["has_proposal"] == "true" and result["risk"] == "90" and result["elevated"] == "true"
    assert _actions(result) == [
        ("isolate_endpoint", "LAPTOP-042", "Isolate Host"),
        ("block_indicator", "203.0.113.9", "Block IP"),
        ("block_indicator", "evil.example.net", "Block this domain"),
        ("block_hash", SHA, "Block file hash"),
        ("block_hash", SHA, "Add SHA256 to custom detections 'Quick SCD'"),
        ("revoke_sessions", "attacker@bad.example", "Revoke sessions"),
        ("revoke_sessions", "jsmith@example.com", "Revoke sessions"),
        ("quarantine_email", "<abc@mail.example>", "Quarantine message"),
    ]
    card = result["card"]
    assert "ELEVATED APPROVAL REQUIRED: 8 actions is above the limit of 5" in card and "DRY RUN" in card
    assert "`new.example.net`: not proposed, rated no verdict (risk 0, needs 60)" in card
    assert "`clean.example.net`: not proposed, rated Umbrella: clean (risk 5, needs 60)" in card
    assert "`10.1.2.3`: not proposed, it is not a public address" in card
    assert "*disable_user* is on the Excluded Actions input" in card
    assert "Umbrella: malicious, VirusTotal: suspicious" in card and result["package_digest"] in card
    assert "Other matching actions of this module, not used: 1." in card
    assert "Do not power off affected hosts" in card and "Check before you approve" in card
    assert result["action_count"] == "8" and result["summary"].endswith("elevated approval.")
    assert _assess()["package_digest"] == result["package_digest"] and _assess(dry_run="false")["card"].count("LIVE") == 1


def test_assess_never_matches_an_action_that_undoes_containment():
    undo = {"Stop Isolating Host", "Unblock this domain", "Enable user", 'Remove SHA256 from custom detections "Quick SCD"'}
    any_text = {title for _, _, title in _actions(_assess(excluded="", patterns=["."] * 6))}
    assert any_text and not any_text & undo
    only_undo = _assess(excluded="", patterns=["stop|unblock|enable|remove"] * 6)
    assert only_undo["has_proposal"] == "false"
    titles = {title for _, _, title in _actions(_assess(excluded=""))}
    assert not titles & undo and {"Disable user", "Isolate Host", "Revoke sessions"} <= titles


def test_assess_builds_the_trigger_url_for_the_approved_observable_only():
    rows = {row["title"]: row for row in json.loads(_assess()["actions_json"])}
    assert rows["Isolate Host"]["url"] == (
        "/iroh-response/respond/trigger/inst-Secure-Endpoint/isolate?observable_type=hostname&observable_value=LAPTOP-042")
    assert rows["Revoke sessions"]["url"].endswith("observable_type=email&observable_value=jsmith%40example.com")
    assert rows["Add SHA256 to custom detections 'Quick SCD'"]["url"].endswith(f"observable_value={SHA}&list=abc%201")
    assert rows["Quarantine message"]["url"].endswith("observable_value=%3Cabc%40mail.example%3E")
    hostile = [_offer("isolate/../../x?y=1&z", "Isolate Host", "Secure Endpoint", "hostname", "LAPTOP-042")]
    url = json.loads(_assess("malware", "LAPTOP-042", started="playbook_task", offers=hostile)["actions_json"])[0]["url"]
    assert url == ("/iroh-response/respond/trigger/inst-Secure-Endpoint/isolate%2F..%2F..%2Fx%3Fy%3D1%26z"
                   "?observable_type=hostname&observable_value=LAPTOP-042")
    assert json.loads(_assess()["verify_body"])[0] == {"type": "hostname", "value": "LAPTOP-042"}


def test_assess_proposes_an_asset_only_on_evidence_or_a_persons_choice():
    by_rule = _assess("account-takeover", "LAPTOP-042\njsmith@example.com", verdicts=[])
    assert by_rule["has_proposal"] == "false" and by_rule["card"] == "" and by_rule["actions_json"] == "[]"
    assert "no indicator of this incident reaches risk 60" in by_rule["summary"]
    chosen = _assess("account-takeover", "LAPTOP-042\njsmith@example.com", verdicts=[], started="playbook_task")
    assert _actions(chosen) == [("isolate_endpoint", "LAPTOP-042", "Isolate Host"),
                                ("revoke_sessions", "jsmith@example.com", "Revoke sessions")]
    assert "chosen by the person who started the workflow" in chosen["card"]
    by_hand = _assess("account-takeover", "jsmith@example.com", verdicts=[], started="user")
    assert _actions(by_hand) == [("revoke_sessions", "jsmith@example.com", "Revoke sessions")]
    distrust = _assess("account-takeover", "jsmith@example.com", verdicts=[], started="playbook_task", trust="False")
    assert distrust["has_proposal"] == "false"
    suspicious = _assess("account-takeover", "LAPTOP-042\njsmith@example.com\n203.0.113.9")
    assert _actions(suspicious) == [("revoke_sessions", "jsmith@example.com", "Revoke sessions")]
    assert "`203.0.113.9`: not proposed, rated VirusTotal: suspicious (risk 60, needs 90)" in suspicious["card"]
    assert "`LAPTOP-042`: not proposed, no indicator of this incident reaches risk 90 (highest 60)" in suspicious["card"]


def test_assess_honours_exclusions_allow_list_and_own_accounts():
    result = _assess(never="*.example.net, LAPTOP-*, 203.0.113.*", internal="example.com")
    assert _actions(result) == [("block_hash", SHA, "Block file hash"),
                                ("block_hash", SHA, "Add SHA256 to custom detections 'Quick SCD'"),
                                ("revoke_sessions", "jsmith@example.com", "Revoke sessions"),
                                ("quarantine_email", "<abc@mail.example>", "Quarantine message")]
    card = result["card"]
    assert "matches the Never Act On entry `*.example.net`" in card and "matches the Never Act On entry `LAPTOP-*`" in card
    assert "`attacker@bad.example`: not proposed, the address is outside the Internal Domain Suffixes" in card
    parent = _assess("c2", "cdn.evil.example.net\nhttps://x.evil.example.net/a", never="evil.example.net",
                     verdicts=[_verdict("domain", "cdn.evil.example.net", 2), _verdict("url", "https://x.evil.example.net/a", 2)])
    assert parent["has_proposal"] == "false" and parent["summary"].count("Never Act On entry `evil.example.net`") == 2
    own_host = _assess("malware", "fs01.corp.example.com", started="playbook_task", never="example.com",
                       internal="corp.example.com",
                       offers=[_offer("isolate", "Isolate Host", "Secure Endpoint", "hostname", "fs01.corp.example.com")])
    assert _actions(own_host) == [("isolate_endpoint", "fs01.corp.example.com", "Isolate Host")]
    everything = _assess(excluded="")
    assert ("disable_user", "jsmith@example.com", "Disable user") in _actions(everything)
    nothing = _assess(excluded="isolate_endpoint, block indicator, block_hash, revoke_sessions, disable_user, quarantine_email")
    assert nothing["has_proposal"] == "false"


def test_assess_surfaces_elevated_approval_instead_of_blocking():
    protected = _assess("malware", "DC-01", started="playbook_task", protected="dc-*, ceo@example.com")
    assert protected["has_proposal"] == "true" and protected["elevated"] == "true"
    assert "ELEVATED APPROVAL REQUIRED: protected asset: `DC-01` (entry `dc-*`)" in protected["card"]
    standard = _assess("malware", "LAPTOP-042", started="playbook_task", protected="dc-*")
    assert standard["elevated"] == "false" and "ELEVATED" not in standard["card"]
    assert _assess(above=50)["elevated"] == "false" and _assess(above=7)["elevated"] == "true"
    vip = _assess("account-takeover", "jsmith@example.com", started="playbook_task", protected="@example.com")
    assert vip["elevated"] == "true"


def test_assess_blocks_an_unrated_indicator_only_on_request():
    assert ("block_indicator", "new.example.net", "Block this domain") not in _actions(_assess(started="playbook_task"))
    asked = _assess(started="playbook_task", unrated="True")
    assert ("block_indicator", "new.example.net", "Block this domain") in _actions(asked)
    assert ("block_indicator", "clean.example.net", "Block this domain") not in _actions(asked)
    assert "Block Unrated Indicators is true" in asked["card"]
    assert ("block_indicator", "new.example.net", "Block this domain") not in _actions(_assess(unrated="True"))


def test_assess_reports_what_xdr_cannot_do():
    result = _assess("malware", f"LAPTOP-099\n{SHA}", offers=[
        _offer("pivot", "Search in console", "Secure Endpoint", "hostname", "LAPTOP-099")])
    assert result["has_proposal"] == "false"
    assert "Isolate endpoint `LAPTOP-099`: XDR offers no matching response action" in result["summary"]
    assert "Offered for it: Search in console (Secure Endpoint)." in result["summary"]
    assert f"Block file hash `{SHA}`: XDR offers no matching response action" in result["summary"]
    mixed = _assess("malware", f"LAPTOP-042\nLAPTOP-099\n{SHA}")
    assert "Needed but not available as an XDR response action (1)" in mixed["card"]
    assert "Terminate the malicious process" in mixed["card"]
    both_forms = _assess("account-takeover", "jsmith@example.com", started="playbook_task")
    assert "Needed but not available" not in both_forms["card"]
    bare = _assess("account-takeover", "LAPTOP-042", started="playbook_task")
    assert _actions(bare) == [("isolate_endpoint", "LAPTOP-042", "Isolate Host")]
    assert "Needed but not available" not in bare["card"] and "`LAPTOP-042` (hostname, user)" in bare["card"]
    unknown = _assess("account-takeover", "LAPTOP-099", started="playbook_task")
    assert "Isolate endpoint `LAPTOP-099`: XDR offers no matching" in unknown["summary"]
    assert "Revoke sessions of `LAPTOP-099`: XDR offers no matching" in unknown["summary"]
    assert "`jsmith@example.com` (email, user): no verdict" in both_forms["card"]


def test_assess_lets_the_org_tune_the_action_text():
    patterns = list(PATTERNS)
    patterns[scripts.KINDS.index("block_hash")] = "custom detections .Other."
    assert [t for k, _, t in _actions(_assess(patterns=patterns)) if k == "block_hash"] == [
        "Add SHA256 to custom detections 'Other'"]
    patterns[scripts.KINDS.index("block_hash")] = "("
    with pytest.raises(SystemExit, match="not a valid regular expression"):
        _assess(patterns=patterns)


def test_assess_keeps_working_when_a_source_degrades():
    no_verdicts = _assess(statuses=(502, 200, 200), started="playbook_task")
    assert no_verdicts["has_proposal"] == "true" and "Degraded source:** verdicts (HTTP 502)" in no_verdicts["card"]
    assert not [a for a in _actions(no_verdicts) if a[0] in ("block_indicator", "block_hash")]
    no_actions = _assess(statuses=(200, 200, 403))
    assert no_actions["has_proposal"] == "false" and "response actions (HTTP 403)" in no_actions["summary"]
    for raw in [("not json", "[]", "{}"), ("null", "null", "null"), ('{"data": "x"}', '{"data": [1, "a"]}', '[{"id": 5}]'),
                ('[{"module": "m", "data": {"verdicts": {"docs": [1, {"disposition": "x"}]}}}]', "[]",
                 '[{"id": "a", "module_instance_id": "i", "query-params": "bad"}]')]:
        assert _assess(raw=raw)["has_proposal"] == "false"
    sightings = [{"module": "Secure Endpoint", "data": {"sightings": {"count": 4, "docs": [
        {"observables": [{"type": "sha256", "value": SHA}]}, {"observables": "bad"}, 7]}}}]
    card = _assess(sightings=sightings)["card"]
    assert f"`{SHA}` (sha256): Secure Endpoint: malicious; sightings Secure Endpoint 1" in card
    assert "Sightings for all observables by module: Secure Endpoint 4." in card
    skipped = _assess(sightings=sightings, statuses=(200, 400, 200), collect="False")["card"]
    assert "Sightings were not collected" in skipped and "Degraded" not in skipped and "sightings Secure" not in skipped


def test_assess_attributes_a_single_observable_without_an_echo():
    verdicts = [{"module": "Umbrella", "data": {"verdicts": {"docs": [{"disposition": 2}]}}}]
    offers = [{"id": "block", "title": "Block this domain", "module": "Umbrella", "module_instance_id": "inst-u"}]
    result = _assess("c2", "evil.example.net", verdicts=verdicts, offers=offers)
    assert _actions(result) == [("block_indicator", "evil.example.net", "Block this domain")]
    two = _assess("c2", "evil.example.net\nother.example.net", verdicts=verdicts, offers=offers)
    assert two["has_proposal"] == "false"


@pytest.mark.parametrize("design", SPEC_IDS)
def test_every_attack_type_assesses_the_sample_incident(design):
    spec = specs.BY_DESIGN[design]
    result = _assess(design, started="playbook_task", excluded="")
    actions = _actions(result)
    assert result["has_proposal"] == "true" and actions
    assert {kind for kind, _, _ in actions} <= set(spec.kinds)
    assert spec.name in result["card"] and result["package_digest"] in result["summary"]
    for line in spec.checks + spec.manual:
        assert line in result["card"]
    by_default = {kind for kind, _, _ in _actions(_assess(design, started="playbook_task"))}
    assert not by_default & set(spec.excluded)


# -- embedded scripts: execution and result ---------------------------------------------------------------


def _record(tally: str, status: int, body: str, key: str = "isolate|inst|hostname|laptop-042") -> str:
    return run(scripts.RECORD_TRIGGER, tally, status, body, "Isolate Host", "LAPTOP-042", key)["tally_json"]


def test_record_trigger_counts_only_an_explicit_success():
    tally = _record("{}", 200, '{"data": {"status": "success"}}')
    tally = _record(tally, 200, '{"data": {"status": "failure"}, "errors": [{"message": "host not found"}, "x"]}', "k2")
    tally = _record(tally, 403, "Forbidden", "k3")
    tally = _record(tally, 200, "not json", "k4")
    tally = _record(tally, 200, '{"data": []}', "k5")
    results = json.loads(tally)["results"]
    assert [r["ok"] for r in results] == [True, False, False, False, False]
    assert results[1]["detail"] == "XDR reported failure: host not found; x" and results[2]["detail"] == "HTTP 403"
    assert results[3]["detail"] == "XDR reported no status"


def test_result_reports_each_action_and_never_claims_verification():
    tally = _record("{}", 200, '{"data": {"status": "success"}}')
    tally = _record(tally, 200, '{"data": {"status": "success"}}', "block|inst-u|domain|evil.example.net")
    tally = _record(tally, 500, "", "revoke|inst-e|email|jsmith@example.com")
    still = json.dumps({"data": [
        _offer("block", "Block this domain", "u", "domain", "Evil.Example.NET") | {"module_instance_id": "inst-u"},
        _offer("stop-isolate", "Stop Isolating Host", "x", "hostname", "LAPTOP-042") | {"module_instance_id": "inst"},
        "junk"]})
    result = run(scripts.RESULT, '{"name": "Ransomware"}', "abc123", tally, 200, still)["result"]
    assert result.startswith("Ransomware: APPROVED and executed (package abc123). 2 of 3 actions reported success, 1 failed.")
    assert '"Isolate Host" on `LAPTOP-042`: XDR reported success and no longer offers the action' in result
    assert "still offered, so the change is NOT CONFIRMED" in result and "FAILED (HTTP 500)" in result
    assert "confirm each change in the product console" in result and "VERIFIED" not in result.replace("UNABLE TO VERIFY", "")
    unable = run(scripts.RESULT, '{"name": "Ransomware"}', "abc123", tally, 502, "")["result"]
    assert unable.count("UNABLE TO VERIFY") == 2
    assert "0 of 0 actions" in run(scripts.RESULT, '{"name": "Ransomware"}', "abc123", "{}", 200, "[]")["result"]


def test_result_does_not_confirm_what_the_module_did_not_answer():
    """A missing module, an answer without the observable, or an error answer is never read as "applied"."""
    tally = _record("{}", 200, '{"data": {"status": "success"}}')
    for body in ('{"data": [], "errors": [{"message": "module timeout"}]}', "[]",
                 json.dumps([{"id": "other", "module_instance_id": "another-module"}])):
        assert "UNABLE TO VERIFY" in run(scripts.RESULT, '{"name": "Malware"}', "d", tally, 200, body)["result"]
    without_echo = json.dumps([{"id": "isolate", "module_instance_id": "inst", "title": "Isolate Host"}])
    assert "NOT CONFIRMED" in run(scripts.RESULT, '{"name": "Malware"}', "d", tally, 200, without_echo)["result"]
    for hostile in ('{"results": 5}', "[]", '{"results": [1, "x", {"key": 7, "ok": true, "target": "a`b"}]}'):
        text = run(scripts.RESULT, '{"name": "Malware"}', "d", hostile, 200, "[]")["result"]
        assert text.startswith("Malware: APPROVED and executed") and "a`b" not in text


def test_scripts_use_only_modules_seen_in_real_xdr_scripts():
    for script in (scripts.CLASSIFY, scripts.ASSESS, scripts.RECORD_TRIGGER, scripts.RESULT):
        imported = set(re.findall(r"^\s*import ([a-z, ]+)$", script, re.M))
        modules = {name.strip() for line in imported for name in line.split(",")}
        assert modules <= {"json", "re", "sys", "hashlib"}
        assert not any(word in script for word in ("requests", "urllib", "socket", "subprocess", "os.", "open(", "eval("))


# -- hostile and malformed module data ---------------------------------------------------------------------


def test_assess_keeps_module_text_from_formatting_the_card():
    title = "Isolate Host\n\n**CORRECTION - Mode: DRY RUN. Approving changes nothing.**\n\n<!-- [x](http://evil) `code` | # _"
    hostile = [_offer("isolate", title, "Secure *Endpoint*\n# Heading", "hostname", "LAPTOP-042")]
    result = _assess("malware", "LAPTOP-042", started="playbook_task", offers=hostile, dry_run="false")
    card = result["card"]
    assert card.count("\n1. ") == 1 and "\n2. " not in card and card.count("**Mode: LIVE") == 1
    line = next(l for l in card.splitlines() if l.startswith("1. "))
    assert 'action "Isolate Host CORRECTION - Mode: DRY RUN. Approving changes nothing.' in line and '..." of ' in line
    assert "(action ID isolate)" in line and "of Secure Endpoint Heading" in line
    assert not any(mark in line.split("Why:")[0].replace("`LAPTOP-042`", "") for mark in "*`[]<>|#")
    assert json.loads(result["actions_json"])[0]["title"].startswith("Isolate Host CORRECTION")
    huge = [_offer("isolate", "Isolate " + "A" * 200000, "M" * 5000, "hostname", "LAPTOP-042")]
    assert len(_assess("malware", "LAPTOP-042", started="playbook_task", offers=huge)["card"]) < 3000
    by_id = [_offer("isolate-host", "View device details", "Secure Endpoint", "hostname", "LAPTOP-042")]
    not_matched = _assess("malware", "LAPTOP-042", started="playbook_task", offers=by_id)
    assert not_matched["has_proposal"] == "false" and "Offered for it: View device details" in not_matched["summary"]
    untitled = [{"id": "isolate-host", "module": "Secure Endpoint", "module_instance_id": "inst",
                 "query-params": {"observable_type": "hostname", "observable_value": "LAPTOP-042"}}]
    assert '"isolate-host" of Secure Endpoint (action ID isolate-host)' in _assess(
        "malware", "LAPTOP-042", started="playbook_task", offers=untitled)["card"]
    quoted = [_offer("isolate", 'Isolate Host" of Secure Endpoint (action ID x). Why: verified by SOC', "M", "hostname", "LAPTOP-042")]
    line = _assess("malware", "LAPTOP-042", started="playbook_task", offers=quoted)["card"].splitlines()[4]
    assert line.count('"') == 2 and "Isolate Host' of Secure Endpoint" in line and "(action ID isolate)" in line
    backtick = _assess("c2", "https://evil.example/a", verdicts=[_verdict("url", "https://evil.example/a", 2, "Um`br*ella\n")],
                       offers=[_offer("block", "Block URL", "Umbrella", "url", "https://evil.example/a")])
    assert "rated Um br ella: malicious" in backtick["card"]


UNDO_TITLES = {
    "isolate_endpoint": ("hostname", "LAPTOP-042", [
        "Take host out of isolation", "Isolation: expire now", "Exclude from containment", "Pause isolation",
        "Stop Isolating Host", "Cancel isolation", "Uncontain host", "Deisolate host", "Disable isolation",
        "Un-isolate", "Release from isolation", "Lift containment", "Exit isolation", "Remove isolation",
        "End isolation", "Restore network access (isolation)", "Revert isolate"]),
    "block_indicator": ("domain", "evil.example.net", [
        "Expire block now", "Exclude from block list", "Bypass block", "Suppress block alerts",
        "Unblock this domain", "Remove from blocklist", "Move from blocklist to safelist", "Disable block rule",
        "Delete block entry", "Allow this domain", "Stop blocking", "Add to whitelist (was blocked)", "Undo block"]),
    "block_hash": ("sha256", SHA, [
        "Remove SHA256 from custom detections", "Unblock hash", "Delete from block list", "Add to allow list, not block",
        "Restore blocked file", "Clear custom detection"]),
    "revoke_sessions": ("email", "jsmith@example.com", [
        "Restore revoked sessions", "Cancel revoke", "Undo sign out", "Revoke account block",
        "Invalidate password lockout", "Revoke MFA registration"]),
    "disable_user": ("email", "jsmith@example.com", [
        "Disable conditional access policy", "Disable sign-in risk policy", "Lock screen",
        "Enable user", "Re-enable disabled user", "Clear lockout", "Disable MFA for user", "Unlock account",
        "Unsuspend user", "Reactivate suspended user", "Remove lock", "Disable two-factor for user"]),
    "quarantine_email": ("email_messageid", "<abc@mail.example>", [
        "Release from quarantine", "Remove from quarantine", "Deliver quarantined message", "Unquarantine",
        "Move quarantined message to inbox", "Restore quarantined message", "Delete quarantined message"]),
}


@pytest.mark.parametrize("kind", sorted(UNDO_TITLES))
def test_assess_never_chooses_an_undo_action_with_the_default_patterns(kind):
    observable_type, value, titles = UNDO_TITLES[kind]
    offers = [_offer(f"action-{i}", title, "Module", observable_type, value) for i, title in enumerate(titles)]
    design = "ransomware" if kind != "disable_user" else "account-takeover"
    result = _assess(design, value, started="playbook_task", excluded="", verdicts=[
        _verdict(observable_type, value, 2)], offers=offers)
    assert not [a for a in _actions(result) if a[0] == kind], _actions(result)
    assert "XDR offers no matching response action" in result["summary"] + result["card"]


def test_assess_does_not_attribute_data_that_names_another_observable():
    other = _assess("c2", "good.example.net", verdicts=[_verdict("domain", "totally-other.bad", 2)],
                    offers=[_offer("block", "Block this domain", "Umbrella", "domain", "totally-other.bad")])
    assert other["has_proposal"] == "false" and "`good.example.net`: not proposed, rated no verdict" in other["summary"]
    half = [{"module": "Umbrella", "data": {"verdicts": {"docs": [{"disposition": 2, "observable": {"value": "x.bad"}}]}}}]
    assert _assess("c2", "good.example.net", verdicts=half)["risk"] == "0"


def test_assess_survives_values_of_the_wrong_type():
    for verdicts in ([{"module": "m", "data": {"verdicts": {"docs": [{"disposition": [2]}, {"disposition": True}]}}}],
                     [{"module": ["m"], "data": {"verdicts": {"docs": 5}}}], [{"module": "m", "data": {"verdicts": 7}}],
                     [{"module": None, "data": [1]}]):
        assert _assess("c2", "evil.example.net", verdicts=verdicts)["risk"] == "0"
    sightings = [{"module": "m", "data": {"sightings": {"count": True, "docs": [{"observables": 7}, 3]}}},
                 {"module": "m", "data": {"sightings": {"count": 10 ** 30, "docs": "x"}}}]
    assert "Sightings for all" not in _assess(sightings=sightings)["card"]
    odd = [{"id": "isolate\ud800", "title": ["Isolate"], "module": {"a": 1}, "module_instance_id": "inst",
            "query-params": {"observable_type": "hostname", "observable_value": "LAPTOP-042", "n": "\ud800"}},
           {"id": 5, "module_instance_id": "inst"}, {"id": "x", "module_instance_id": ["inst"]}]
    result = _assess("malware", "LAPTOP-042", started="playbook_task", offers=odd)
    assert json.loads(result["actions_json"])[0]["url"].startswith("/iroh-response/respond/trigger/inst/isolate%3F?")
    assert result["card"].isascii()


def test_assess_keeps_hostile_identifiers_and_parameters_out_of_the_url():
    def urls(offers):
        result = _assess("malware", "LAPTOP-042", started="playbook_task", offers=offers, patterns=["."] * 6)
        return [row["url"] for row in json.loads(result["actions_json"])]

    base = {"title": "Isolate Host", "module": "Secure Endpoint"}
    echo = {"observable_type": "hostname", "observable_value": "LAPTOP-042"}
    assert urls([{**base, "id": "observables", "module_instance_id": "..", "query-params": echo},
                 {**base, "id": ".", "module_instance_id": "inst", "query-params": echo},
                 {**base, "id": "", "module_instance_id": "inst", "query-params": echo},
                 {**base, "id": "i" * 201, "module_instance_id": "inst", "query-params": echo}]) == []
    extras = {**echo, "Observable_Value": "DC-01", "observable_value ": "DC-01", "observable_value[]": "DC-01",
              "observable-type": "domain", "a&b": "1", "list": "x y", "flag": True, "nested": {"a": 1}, "n": 7,
              "long": "v" * 301}
    assert urls([{**base, "id": "isolate", "module_instance_id": "inst", "query-params": extras}]) == [
        "/iroh-response/respond/trigger/inst/isolate?observable_type=hostname&observable_value=LAPTOP-042&list=x%20y&n=7"]


def test_assess_matches_protected_assets_and_never_act_entries_in_every_form():
    def elevated(value, protected, design="malware"):
        offers = [_offer("isolate", "Isolate Host", "Secure Endpoint", "hostname", value)]
        return _assess(design, value, started="playbook_task", protected=protected, offers=offers,
                       internal="corp.example.com")["elevated"]

    assert elevated("dc-01.corp.example.com", "DC-01") == "true"
    assert elevated("DC-01", "dc-01.corp.example.com") == "true"
    assert elevated("DC-02", "DC-01 DC-02") == "true" and elevated("DC-02", "DC-01\nDC-02;") == "true"
    assert elevated("LAPTOP-042", "DC-01, dc-*") == "false" and elevated("DC-011", "DC-01") == "false"

    def blocked(value, never, kind="url"):
        offers = [_offer("block", "Block", "Umbrella", kind, value)]
        result = _assess("c2", value, never=never, verdicts=[_verdict(kind, value, 2)], offers=offers)
        return result["has_proposal"] == "true"

    for url in ("https://www.example.com?x=1", "https://www.example.com#a", "https://www.example.com./x",
                "https://www.example.com\\x", "https://user:pw@www.example.com:8443/x", "https://EXAMPLE.com/"):
        assert not blocked(url, "example.com"), url
    assert blocked("https://www.example.com.evil.net/x", "example.com") and blocked("https://notexample.com/", "example.com")
    assert not blocked("2001:0db8:0:0:0:0:0:1", "2001:db8::1", "ipv6") and blocked("2001:db8::2", "2001:db8::1", "ipv6")
    assert not blocked("8.8.8.8", "8.8.8.0/24", "ip") and blocked("8.8.9.8", "8.8.8.0/24", "ip")
    assert not blocked("https://8.8.8.8/x", "8.8.8.0/24") and not blocked("2001:db8:1::5", "2001:db8:1::/48", "ipv6")
    assert not blocked("evil.example.net", "EVIL.example.net.", "domain")


def test_assess_never_blocks_a_private_address_in_any_notation():
    for kind, value in (("ipv6", "::ffff:10.0.0.1"), ("ipv6", "0:0:0:0:0:0:0:1"), ("ipv6", "fec0::1"), ("ipv6", "fe80::1"),
                        ("ipv6", "fd00::1"), ("ipv6", "ff02::1"), ("ipv6", "::"), ("ip", "100.64.0.1"),
                        ("ip", "169.254.1.1"), ("ip", "172.31.255.255"), ("url", "http://10.1.2.3/x"),
                        ("url", "http://[fd00::1]:8080/x"), ("url", "http://127.0.0.1"), ("ipv6", "1::2::3")):
        offers = [_offer("block", "Block", "Umbrella", kind, value)]
        result = _assess("c2", value, verdicts=[_verdict(kind, value, 2)], offers=offers, started="playbook_task",
                         unrated="True")
        assert result["has_proposal"] == "false" and "not a public address" in result["summary"], value
    for kind, value in (("ipv6", "2001:4860:4860::8888"), ("ipv6", "::ffff:8.8.8.8"), ("ip", "172.32.0.1"),
                        ("url", "http://8.8.8.8/x"), ("url", "http://[2001:4860:4860::8888]/x")):
        offers = [_offer("block", "Block", "Umbrella", kind, value)]
        assert _assess("c2", value, verdicts=[_verdict(kind, value, 2)], offers=offers)["has_proposal"] == "true", value


def test_assess_pattern_matching_stays_fast_on_long_input():
    import time
    value = "https://evil.example/" + "a-" * 900
    started = time.perf_counter()
    result = _assess("c2", value, never="*-*-*-*-*.corp, " + "*a" * 49 + "Z", protected="*-*-*-*.corp",
                     verdicts=[_verdict("url", value, 2)], offers=[_offer("block", "Block", "Umbrella", "url", value)])
    assert time.perf_counter() - started < 2 and result["has_proposal"] == "true"
    assert "..." in result["card"]


# -- approval gate: what the validator must prove from the document alone ----------------------------------
#
# Each mutation below produced a document the first version of the validator accepted (independent review
# of 2026-10-10). They are checked against both workflow bodies where they apply.


def _variable(document: dict, name: str) -> dict:
    return next(v["properties"] for v in document["workflow"]["variables"] if v["properties"]["name"] == name)


def _activity(kind: str, title: str, properties: dict, **children) -> dict:
    suffix = "".join(c for c in title if c.isalnum())[:19].ljust(19, "x")
    return {"unique_name": "definition_activity_02AAAAAAAAAAAAAA" + suffix, "name": title, "title": title, "type": kind,
            "base_type": "activity", "object_type": "definition_activity",
            "properties": {"continue_on_failure": False, "display_name": title, "skip_execution": False, **properties},
            **children}


def _decision_starts_approved(document):
    _variable(document, "Decision")["value"] = "Approve"


def _decision_is_an_input(document):
    _variable(document, "Decision")["scope"] = "input"


def _dry_run_defaults_to_false(document):
    _variable(document, "Dry Run")["value"] = False


def _dry_run_is_local(document):
    _variable(document, "Dry Run")["scope"] = "local"


def _second_dry_run_variable(document):
    decoy = copy.deepcopy(next(v for v in document["workflow"]["variables"] if v["properties"]["name"] == "Dry Run"))
    decoy["unique_name"] = decoy["unique_name"][:-3] + "Zz9"
    decoy["properties"].update(scope="local", value=False)
    document["workflow"]["variables"].insert(0, decoy)


def _approval_asked_after_the_gate(document):
    siblings = _siblings(document, "Which approval level?")
    approve = next(a for a in siblings if a["title"] == "Which approval level?")
    siblings.remove(approve)
    siblings.append(approve)


def _gate_in_a_loop_without_reset(document):
    siblings = _siblings(document, "Which approval level?")
    looped = siblings[:]
    siblings[:] = [_activity("logic.for_each", "Again", {"source_array": "[1, 2]"}, actions=looped)]


def _card_replaced_by_a_constant(document):
    _find(document, "Request standard approval")[0]["properties"]["body_text"] = "Routine maintenance. Nothing will change."


def _card_replaced_by_another_output(document):
    request, _ = _find(document, "Request standard approval")
    request["properties"]["body_text"] = request["properties"]["body_text"].replace(".card$", ".summary$")


def _card_with_text_around_it(document):
    request, _ = _find(document, "Request elevated approval")
    request["properties"]["body_text"] = "Ignore the list below, this is a drill.\n" + request["properties"]["body_text"]


def _only_choice_is_approve(document):
    _find(document, "Request standard approval")[0]["properties"]["approval_choices_holder"]["approval_choices"] = ["Approve"]


def _expiry_counts_as_approve(document):
    _find(document, "Request standard approval")[0]["properties"]["expiration_status"] = "Approve"


def _decision_reference_with_a_space(document):
    record, _ = _find(document, "Record standard decision")
    siblings = _siblings(document, "Record standard decision")
    extra = copy.deepcopy(record)
    extra["unique_name"] = extra["unique_name"][:-3] + "Zz9"
    extra["title"] = "Record again"
    extra["properties"]["variables_to_update"] = [{
        "variable_to_update": validate.variable_ref(document, "Decision") + " ", "variable_value_new": "Approve"}]
    siblings.append(extra)


def _decision_set_inside_branches(document):
    block, _ = _find(document, "Which approval level?")
    block["blocks"].append(_activity("core.set_multiple_variables", "Sneak", {"variables_to_update": [{
        "variable_to_update": validate.variable_ref(document, "Decision"), "variable_value_new": "Approve"}]}))


def _skipped_branch(document):
    _find(document, "Which approval level?")[0]["properties"]["skip_execution"] = True


def _record_continues_on_failure(document):
    _find(document, "Record standard decision")[0]["properties"]["continue_on_failure"] = True


def _gate_branch_outside_a_condition_block(document):
    live, ancestors = _find(document, "Live: execute the approved package")
    ancestors[-1]["blocks"].remove(live)
    ancestors[-2]["actions"].append(live)


def _script_edited(document):
    name = "Assess and write decision card" if any(
        a["title"] == "Assess and write decision card" for a, _ in validate.walk(document["workflow"]["actions"])) \
        else "Plan moves and write decision card"
    _find(document, name)[0]["properties"]["script"] += "card = 'Nothing will change.'\n"


UNIVERSAL = [
    _decision_starts_approved, _decision_is_an_input, _dry_run_defaults_to_false, _dry_run_is_local,
    _second_dry_run_variable, _approval_asked_after_the_gate, _gate_in_a_loop_without_reset,
    _card_replaced_by_a_constant, _card_replaced_by_another_output, _card_with_text_around_it,
    _only_choice_is_approve, _expiry_counts_as_approve, _decision_reference_with_a_space,
    _decision_set_inside_branches, _skipped_branch, _record_continues_on_failure,
    _gate_branch_outside_a_condition_block, _script_edited,
]


@pytest.mark.parametrize("body", ["incident", "email"])
@pytest.mark.parametrize("mutation", UNIVERSAL, ids=lambda f: f.__name__.lstrip("_"))
def test_validator_rejects_review_bypasses_in_both_workflow_bodies(body, mutation):
    document = incident.build(specs.BY_DESIGN["ransomware"]).export() if body == "incident" else email_bombing.build().export()
    assert validate.check(document) == []
    mutation(document)
    assert validate.check(document), f"{mutation.__name__} was not detected in the {body} workflow"


def _table_fed_by_another_script(document):
    table, _ = _find(document, "Approved actions table")
    classify, _ = _find(document, "Classify observables")
    table["properties"]["input_json"] = f"$activity.{classify['unique_name']}.output.script_queries.observables_json$"


def _url_with_a_constant_prefix(document):
    trigger, _ = _find(document, TRIGGER)
    loop, _ = _find(document, "For each approved action")
    trigger["properties"]["relative_url"] = (
        "/iroh-response/respond/trigger/any-module/un-isolate?observable_type=hostname&observable_value="
        f"$activity.{loop['unique_name']}.input.source_array[@].target$")


def _trigger_reads_another_column(document):
    trigger, _ = _find(document, TRIGGER)
    trigger["properties"]["relative_url"] = trigger["properties"]["relative_url"].replace("[@].url$", "[@].target$")


def _trigger_sent_to_another_host(document):
    document["targets"] = {"definition_target_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa": {
        "unique_name": "definition_target_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa", "name": "t", "title": "t",
        "type": "web-service.endpoint", "base_type": "target", "object_type": "definition_target",
        "properties": {"host": "evil.example", "protocol": "https", "path": "/v1", "no_runtime_user": True,
                       "disable_certificate_validation": False, "display_name": "t"}}}
    _find(document, TRIGGER)[0]["properties"]["target"]["target_id"] = "definition_target_02AAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa"


def _read_path_on_a_host_whose_base_path_is_a_trigger(document):
    _trigger_sent_to_another_host(document)
    target = next(iter(document["targets"].values()))
    target["properties"].update(host="api.us.etd.cisco.com", path="/iroh-response/respond/trigger/m/isolate?x=")
    _find(document, TRIGGER)[0]["properties"]["target"]["target_id"] = PLATFORM
    _siblings(document, "Get verdicts").append(_activity("web-service.http_request", "Quiet", {
        "method": "POST", "relative_url": "/messages/search", "runtime_user": {"target_default": True},
        "target": {"override_workflow_target": True, "target_id": target["unique_name"]}}))


def _get_request_during_investigation(document):
    _siblings(document, "Get verdicts").append(_activity("web-service.http_request", "Quiet", {
        "method": "GET", "relative_url": "/iroh-response/respond/trigger/m/isolate?observable_value=dc01",
        "runtime_user": {"target_default": True}, "target": {"override_workflow_target": True, "target_id": PLATFORM}}))


def _lower_case_method(document):
    _find(document, "Get verdicts")[0]["properties"].update(method="post", relative_url="/iroh-response/respond/trigger/m/a")


def _header_on_the_trigger(document):
    _find(document, TRIGGER)[0]["properties"]["custom_headers"] = [{"name": "X-Forwarded-For", "value": "10.0.0.1"}]


def _request_without_a_target(document):
    _find(document, "Get verdicts")[0]["properties"]["target"] = {"use_workflow_target": True}


INCIDENT_ONLY = [
    _table_fed_by_another_script, _url_with_a_constant_prefix, _trigger_reads_another_column,
    _trigger_sent_to_another_host, _read_path_on_a_host_whose_base_path_is_a_trigger, _get_request_during_investigation,
    _lower_case_method, _header_on_the_trigger, _request_without_a_target,
]


@pytest.mark.parametrize("mutation", INCIDENT_ONLY, ids=lambda f: f.__name__.lstrip("_"))
def test_validator_rejects_review_bypasses_of_the_request(ransomware, mutation):
    mutation(ransomware)
    assert validate.check(ransomware), f"{mutation.__name__} was not detected"


def test_gate_check_alone_catches_the_approval_chain(ransomware):
    """These do not rely on the structure check: the gate check proves the chain by itself."""
    for mutation in (_decision_starts_approved, _dry_run_defaults_to_false, _second_dry_run_variable,
                     _approval_asked_after_the_gate, _gate_in_a_loop_without_reset, _card_replaced_by_a_constant,
                     _card_replaced_by_another_output, _only_choice_is_approve, _expiry_counts_as_approve,
                     _decision_reference_with_a_space, _decision_set_inside_branches, _table_fed_by_another_script,
                     _url_with_a_constant_prefix):
        document = copy.deepcopy(ransomware)
        mutation(document)
        assert validate.check_approval_gate(document), mutation.__name__


def test_a_loop_that_clears_the_decision_each_pass_is_accepted(ransomware):
    """The rule is not "no loops": Email Bombing loops over mailboxes and clears the decision first."""
    siblings = _siblings(ransomware, "Which approval level?")
    reset = _activity("core.set_multiple_variables", "Clear", {"variables_to_update": [{
        "variable_to_update": validate.variable_ref(ransomware, "Decision"), "variable_value_new": ""}]})
    siblings[:] = [_activity("logic.for_each", "Again", {"source_array": "[1, 2]"}, actions=[reset, *siblings])]
    assert validate.check_approval_gate(ransomware) == []
    assert validate.check(email_bombing.build().export()) == []


def test_every_exported_script_is_one_of_the_repository_scripts():
    known = validate.known_scripts()
    assert len(known) == 12  # Email Bombing reuses the trigger record and result steps
    for workflow in build_tool.workflows(email_bombing.Settings()):
        for activity, _ in validate.walk(workflow.export()["workflow"]["actions"]):
            if activity["type"] == "python3.script":
                assert activity["properties"]["script"] in known


def test_default_action_patterns_accept_the_plain_titles():
    """The strict defaults still match the obvious title of each kind, in the usual vendor spellings."""
    plain = {
        "isolate_endpoint": ("hostname", "LAPTOP-042", ["Isolate Host", "Isolate machine", "Contain host", "Network contain"]),
        "block_indicator": ("domain", "evil.example.net", ["Block this domain", "Block domain", "Deny domain",
                                                           "Add to blocklist", "Add domain to block list"]),
        "block_hash": ("sha256", SHA, ["Block file hash", "Add SHA256 to custom detections 'Quick SCD'",
                                       "Add to Blocked Application List"]),
        "revoke_sessions": ("email", "jsmith@example.com", ["Revoke sessions", "Revoke sign-in sessions",
                                                            "Sign out user sessions", "Invalidate refresh tokens"]),
        "disable_user": ("email", "jsmith@example.com", ["Disable user", "Disable account", "Suspend user account"]),
        "quarantine_email": ("email_messageid", "<abc@mail.example>", ["Quarantine message", "Quarantine email",
                                                                      "Move message to quarantine"]),
    }
    for kind, (observable_type, value, titles) in plain.items():
        design = "ransomware" if kind != "disable_user" else "account-takeover"
        for title in titles:
            result = _assess(design, value, started="playbook_task", excluded="",
                             verdicts=[_verdict(observable_type, value, 2)],
                             offers=[_offer("a1", title, "Module", observable_type, value)])
            assert [a for a in _actions(result) if a[0] == kind], (kind, title)


# -- shapes seen in real exports -------------------------------------------------------------------------


def test_script_steps_follow_the_shapes_of_real_exports():
    """In 92 real exports (80 Cisco atomics from the org, the Cisco Live workflows, the Secure Endpoint sample)
    a script step declares only string, secure string or boolean outputs, and receives each argument as one
    variable or activity reference (two literal numbers aside). Both workflow bodies keep to that."""
    reference = re.compile(r"\$(workflow|activity)\.[^$]+\$")
    for workflow in build_tool.workflows(email_bombing.Settings()):
        document = workflow.export()
        assert validate.check_structure(document) == []
        for activity, _ in validate.walk(document["workflow"]["actions"]):
            if activity["type"] != "python3.script":
                continue
            properties = activity["properties"]
            assert {q["script_query_type"] for q in properties["script_queries"]} <= {"string", "secure_string", "boolean"}
            for argument in properties["script_arguments"]:
                assert reference.fullmatch(argument) or re.fullmatch(r"\d{1,6}", argument), (workflow.name, argument)


def test_structure_check_rejects_script_shapes_never_seen(ransomware):
    for mutate, expected in [
        (lambda d: _find(d, "Classify observables")[0]["properties"]["script_queries"][0].update(script_query_type="integer"),
         "output type"),
        (lambda d: _find(d, "Classify observables")[0]["properties"]["script_arguments"].__setitem__(1, '{"types": []}'),
         "argument"),
        (lambda d: _find(d, "Classify observables")[0]["properties"]["script_arguments"].__setitem__(
            2, "prefix " + validate.variable_ref(d, "Never Act On")), "argument"),
    ]:
        changed = copy.deepcopy(ransomware)
        mutate(changed)
        assert any(expected in problem for problem in validate.check_structure(changed)), expected


# -- audit only, org settings and the rule guide ---------------------------------------------------------------


@pytest.mark.parametrize("body", ["incident", "email"])
def test_audit_only_stops_before_the_approval_task(body):
    document = incident.build(specs.BY_DESIGN["malware"]).export() if body == "incident" else email_bombing.build().export()
    assert validate.check(document) == []
    assert _variable(document, "Audit Only") == {**_variable(document, "Audit Only"), "scope": "input", "value": False,
                                                 "type": "datatype.boolean"}
    audit = validate.variable_ref(document, "Audit Only")
    quiet, _ = _find(document, "Audit only: no approval task")
    asked, _ = _find(document, "Ask for approval")
    assert quiet["properties"]["condition"] == {"left_operand": audit, "operator": "eq", "right_operand": True}
    assert asked["properties"]["condition"] == {"left_operand": audit, "operator": "eq", "right_operand": False}
    assert [a["type"] for a, _ in validate.walk([quiet])] == ["logic.condition_block", "core.set_multiple_variables"]
    inside = {a["title"] for a, _ in validate.walk([asked])}
    assert {"Request standard approval", "Request elevated approval", "Approved"} <= inside
    changing = [a for a, ancestors in validate.walk(document["workflow"]["actions"]) if validate.is_state_changing(a)]
    assert changing and all(asked in ancestors for a, ancestors in validate.walk(document["workflow"]["actions"])
                            if validate.is_state_changing(a))


def _write_settings(root: Path, text: str) -> None:
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "xdr-native.yaml").write_text(text, encoding="utf-8")


def test_org_settings_become_the_input_defaults_of_every_workflow(tmp_path, monkeypatch):
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    _write_settings(tmp_path, """
approver_roles: [user]
elevated_approvals: 3
internal_domain_suffixes: [corp.example.com, example.com]
protected_assets: ["DC-*", "ceo@example.com"]
never_act_on: [example.com, 192.0.2.0/28]
protected_mailboxes: ["@finance.example.com"]
trusted_sender_domains: [partner.example]
""")
    assert build_tool.main([]) == 0 and build_tool.main(["--check"]) == 0
    files = sorted((tmp_path / "xdr").rglob("*.json"))
    assert len(files) == 22 and (tmp_path / "xdr" / "RULES.md").is_file()
    for path in files:
        written = json.loads(path.read_text(encoding="utf-8"))
        assert validate.check(written) == []
        assert _find(written, "Request standard approval")[0]["properties"]["assignee_roles"] == ["user"]
        assert _find(written, "Request elevated approval")[0]["properties"]["minimum_approvals"] == 3
        if written["workflow"]["name"] == "Email Bombing":
            assert _variable(written, "Protected Mailboxes")["value"] == "@finance.example.com"
            assert _variable(written, "Trusted Sender Domains")["value"] == "partner.example"
            assert set(written) == {"workflow", "module_targets"}  # no ETD target or account key
        else:
            assert _variable(written, "Internal Domain Suffixes")["value"] == "corp.example.com, example.com"
            assert _variable(written, "Protected Assets")["value"] == "DC-*, ceo@example.com"
            assert _variable(written, "Never Act On")["value"] == "example.com, 192.0.2.0/28"
            assert _variable(written, "Dry Run")["value"] is True
    assert build_tool.main(["--check", "--approver-role", "admin"]) == 1  # a flag overrides the file


def test_committed_settings_file_changes_nothing_until_it_is_filled_in():
    values = build_tool.load_settings(ROOT / build_tool.SETTINGS_FILE)
    assert values == {"approver_roles": ["admin", "user"], "elevated_roles": ["admin"], "elevated_approvals": 2}
    assert email_bombing.Settings(**values) == email_bombing.Settings()


@pytest.mark.parametrize("text, message", [
    ("protected_asset: [DC-01]", "unknown settings"),
    ("- a list", "mapping"),
    ("protected_assets: ['DC-01, DC-02']", "without commas"),
    ("protected_assets: [5]", "without commas"),
    ("approver_roles: [everyone]", "XDR roles"),
    ("elevated_approvals: 0", "at least 1"),
    ("never_act_on: ['$workflow.x.local.y$']", "dollar sign"),
    ("never_act_on: [\"a\\nb\"]", "one line"),
    ("etd_host: api.us.etd.cisco.com", "unknown settings"),
])
def test_settings_file_is_checked(tmp_path, monkeypatch, text, message):
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    _write_settings(tmp_path, text)
    with pytest.raises(SystemExit, match=message):
        build_tool.main([])


def test_no_workflow_exports_a_vendor_target_or_account_key():
    """XDR asks for a username and password on import when a workflow carries an account key."""
    for workflow in build_tool.workflows(email_bombing.Settings()):
        document = workflow.export()
        assert set(document) == {"workflow", "module_targets"}
        document["targets"] = {}
        assert any("envelope key 'targets'" in problem for problem in validate.check_structure(document))


def test_rule_guide_covers_every_workflow_once(tmp_path, monkeypatch, capsys):
    from xdr_native import rules

    names = [w.name for w in build_tool.workflows(email_bombing.Settings())]
    assert sorted(g.workflow for g in rules.GUIDES) == sorted(names)
    guide = rules.render()
    for number, entry in enumerate(rules.GUIDES, 1):
        assert f"| {number} | `{entry.workflow}` |" in guide
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", technique) for technique in entry.techniques)
        assert entry.techniques or entry.note
    assert "Audit Only" in guide and "Stop processing subsequent rules" in guide and "Administration > Playbooks" in guide
    assert (ROOT / "xdr" / "RULES.md").read_text(encoding="utf-8") == guide
    monkeypatch.setattr(build_tool, "ROOT", tmp_path)
    assert build_tool.main([]) == 0
    (tmp_path / "xdr" / "RULES.md").write_text("edited by hand", encoding="utf-8")
    assert build_tool.main(["--check"]) == 1 and "RULES.md" in capsys.readouterr().err
