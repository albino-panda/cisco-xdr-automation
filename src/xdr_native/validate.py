"""Checks on a generated XDR workflow export.

Two kinds of check, both run on the JSON that is imported into XDR, not on the builder:

- ``check_structure``: identifiers are unique and well formed, every reference resolves, only activity
  types, operators and envelope keys seen in real exports are used, every script is one of this
  repository's own, every HTTP request is one of the known requests on one of the known targets, and no
  credential is embedded;
- ``check_approval_gate``: no state-changing activity can run unless a human chose *Approve* in an XDR
  approval task that showed the decision card, and Dry Run is false. This is the deterministic approval
  control for workflows that run inside XDR, where no code-level guard exists.

The gate check does not trust the layout the generator happens to produce. It refuses a document when it
cannot prove, from the document alone, each link of this chain:

1. the decision variable is a local variable that starts empty, and it only ever receives an empty value
   or the answer of the approval request placed just before the assignment;
2. every approval request waits, cannot be skipped, offers a way to refuse, and shows the decision card:
   the ``card`` output of a script that ran before it;
3. every state-changing request sits in the branch *decision = Approve* and in the branch
   *Dry Run = false*, the approval was recorded earlier in the same sequence of steps, and inside a loop
   the decision is cleared at the start of every pass;
4. what the request sends is exactly one output of the script that wrote that card, carried through a
   table and a for-each only.

An XDR org cannot be run offline, so these checks do not prove that the import succeeds or that an
activity behaves as expected. They prove the shape and the approval structure.
"""
from __future__ import annotations

import re
import textwrap
from collections.abc import Iterator
from typing import Any

from . import incident_scripts, scripts
from .builder import APPROVAL_RESPONSE, PLATFORM_APIS, TEMPLATE_OUTPUTS, module_target_ref

Activity = dict[str, Any]

#: Activity types observed in real exports (see ``builder`` for the sources).
KNOWN_TYPES = frozenset({
    "core.set_multiple_variables", "corejava.jsonpathquery", "corejava.read_table_from_json",
    "logic.condition_block", "logic.for_each", "logic.group", "logic.if_else", "logic.while",
    "python3.script", "task.request_approval", "web-service.http_request",
})
#: XDR roles a Request Approval activity can be assigned to (as exported by the target org).
KNOWN_ROLES = frozenset({"admin", "user"})
KNOWN_OPERATORS = frozenset({"and", "or", "eq", "eqi", "ne", "gt", "gte", "lt", "lte", "mregex", "mw"})
KNOWN_ENVELOPE = frozenset({"workflow", "targets", "runtime_users", "module_targets"})
#: Module targets a workflow may use: XDR's own platform APIs (enrich, response, private intelligence).
KNOWN_MODULE_TARGETS = frozenset({PLATFORM_APIS})
#: Hosts an exported HTTP target may name: the regional Secure Email Threat Defense APIs, path ``/v1``.
KNOWN_TARGET_HOST = re.compile(r"api\.(us|de|au|in|ae)\.etd\.cisco\.com")
KNOWN_TARGET_PATH = "/v1"
MAX_ACTIVITIES = 200  # documented XDR limit per workflow

#: Requests a workflow may send, per kind of target. ``READ_REQUESTS`` only read; the others change state.
ETD_READS = frozenset({("POST", "/oauth/token"), ("POST", "/messages/search"), ("POST", "/messages/status")})
ETD_WRITES = frozenset({("POST", "/messages/move")})
PLATFORM_READS = frozenset({
    ("POST", "/iroh-enrich/deliberate/observables"), ("POST", "/iroh-enrich/observe/observables"),
    ("POST", "/iroh-response/respond/observables"),
})
#: The Cisco XDR enrich and response reads: verdicts, sightings and the list of response actions on
#: offer. Triggering a response action is state-changing.
READ_REQUESTS = ETD_READS | PLATFORM_READS
#: Activity types that call other workflows. None is allowed outside the gate; there is no allow-list.
CALL_TYPES = frozenset({"workflow.sub_workflow", "workflow.atomic_workflow"})
FORBIDDEN_KEYS = frozenset({"auto_approve", "skip_approval", "bypass_approval", "approval_required"})
LOOP_TYPES = frozenset({"logic.for_each", "logic.while"})
#: Output types a script step declares in real exports. An integer output was never seen, so counts are
#: strings and decisions use "true" / "false".
SCRIPT_OUTPUT_TYPES = frozenset({"string", "secure_string", "boolean"})

_ID = re.compile(r"^(definition_workflow|definition_activity|variable_workflow|definition_target|"
                 r"definition_runtime_user)_0[12][0-9A-Z]{11}[0-7][0-9A-Za-z]{21}$")
_WORKFLOW_REF = re.compile(r"\$workflow\.([A-Za-z0-9_]+)\.([a-z]+)\.([A-Za-z0-9_]+)\$")
_ACTIVITY_REF = re.compile(r"\$activity\.([A-Za-z0-9_]+)\.(?:output|input)\.[^$]*\$")
#: A value that is one activity reference and nothing else.
_ONE_REF = re.compile(r"\$activity\.([A-Za-z0-9_]+)\.(output|input)\.([^$]*)\$")
_ITEM_URL = re.compile(r"\$activity\.[A-Za-z0-9_]+\.input\.source_array\[@\]\.url\$")
#: A script argument as real exports write it: one workflow variable reference, or a plain number.
_ARGUMENT = re.compile(r"\$workflow\.[A-Za-z0-9_]+\.[a-z]+\.[A-Za-z0-9_]+\$|\d{1,6}")
_CARD = re.compile(r"\$activity\.([A-Za-z0-9_]+)\.output\.script_queries\.card\$")


def known_scripts() -> frozenset[str]:
    """The script steps of this repository, as the builder writes them into an export."""
    found = set()
    for module in (scripts, incident_scripts):
        for name in dir(module):
            value = getattr(module, name)
            if name.isupper() and isinstance(value, str) and "sys.argv" in value:
                found.add(textwrap.dedent(value).strip() + "\n")
    return frozenset(found)


def walk(actions: list[Activity] | None, ancestors: tuple[Activity, ...] = ()) -> Iterator[tuple[Activity, tuple[Activity, ...]]]:
    """Every activity with its chain of enclosing activities, outermost first."""
    for activity in actions or []:
        yield activity, ancestors
        inner = (*ancestors, activity)
        yield from walk(activity.get("blocks"), inner)
        yield from walk(activity.get("actions"), inner)


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def _keys(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _keys(value)
    elif isinstance(node, list):
        for value in node:
            yield from _keys(value)


def _leaves(condition: Any) -> list[dict[str, Any]]:
    """Leaf comparisons that must all hold for ``condition`` to hold (``and`` is flattened, ``or`` is not)."""
    if not isinstance(condition, dict):
        return []
    if condition.get("operator") == "and":
        return _leaves(condition.get("left_operand")) + _leaves(condition.get("right_operand"))
    return [condition]


def _operators(condition: Any) -> Iterator[str]:
    if isinstance(condition, dict) and "operator" in condition:
        yield condition["operator"]
        yield from _operators(condition.get("left_operand"))
        yield from _operators(condition.get("right_operand"))


def _variables(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {v["unique_name"]: v["properties"] for v in document["workflow"].get("variables") or []}


def variable_ref(document: dict[str, Any], name: str) -> str:
    """Reference string of the workflow variable called ``name``."""
    workflow = document["workflow"]
    for unique_name, properties in _variables(document).items():
        if properties["name"] == name:
            return f"$workflow.{workflow['unique_name']}.{properties['scope']}.{unique_name}$"
    raise KeyError(name)


def _request(activity: Activity) -> tuple[str, Any]:
    properties = activity.get("properties", {})
    return str(properties.get("method", "")), properties.get("relative_url")


def is_state_changing(activity: Activity) -> bool:
    """True for a call to another workflow and for every HTTP request that is not a known read."""
    if activity.get("type") in CALL_TYPES:
        return True
    if activity.get("type") != "web-service.http_request":
        return False
    return _request(activity) not in READ_REQUESTS


def _children(activity: Activity) -> list[tuple[str, list[Activity]]]:
    return [(key, activity[key]) for key in ("blocks", "actions") if isinstance(activity.get(key), list)]


def check_structure(document: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    workflow = document["workflow"]
    for key in document:
        if key not in KNOWN_ENVELOPE:
            problems.append(f"envelope key {key!r} is not one seen in a real export")
    activities = list(walk(workflow.get("actions")))
    if len(activities) > MAX_ACTIVITIES:
        problems.append(f"{len(activities)} activities, over the XDR limit of {MAX_ACTIVITIES}")

    names = [workflow["unique_name"], *(a["unique_name"] for a, _ in activities), *_variables(document),
             *(document.get("targets") or {}), *(document.get("runtime_users") or {})]
    for name in names:
        if not _ID.match(name):
            problems.append(f"malformed identifier {name}")
    for name in {n for n in names if names.count(n) > 1}:
        problems.append(f"duplicate identifier {name}")

    variables = _variables(document)
    labels = [properties["name"] for properties in variables.values()]
    for label in sorted({n for n in labels if labels.count(n) > 1}):
        problems.append(f"duplicate variable name {label!r}")
    activity_ids = {a["unique_name"] for a, _ in activities}
    targets = document.get("targets") or {}
    runtime_users = document.get("runtime_users") or {}
    module_refs = set()
    for module in document.get("module_targets") or []:
        key = (module.get("module_type"), module.get("external_id"), module.get("proxy_endpoint_metadata_id")) \
            if isinstance(module, dict) else None
        if key is None or set(module) != {"module_type", "external_id", "proxy_endpoint_metadata_id"} \
                or key not in KNOWN_MODULE_TARGETS:
            problems.append(f"module target {module!r} is not one seen in a real export")
        else:
            module_refs.add(module_target_ref(key))
    own_scripts = known_scripts()

    for activity, ancestors in activities:
        where = f"{activity['title']!r}"
        kind = activity.get("type")
        if kind not in KNOWN_TYPES:
            problems.append(f"{where}: activity type {kind} was not seen in a real export")
        properties = activity.get("properties", {})
        if properties.get("skip_execution") is not False or properties.get("continue_on_failure") is not False:
            problems.append(f"{where}: an activity must not be skipped or continue after a failure")
        parent = ancestors[-1] if ancestors else None
        in_blocks = parent is not None and any(activity is child for child in parent.get("blocks") or [])
        if kind == "logic.condition_block":
            if not in_blocks or parent.get("type") not in ("logic.if_else", "logic.while"):
                problems.append(f"{where}: a condition branch must be a branch of a condition block or a while loop")
        elif in_blocks:
            problems.append(f"{where}: only condition branches may sit in the branches of an activity")
        for operator in _operators(properties.get("condition")):
            if operator not in KNOWN_OPERATORS:
                problems.append(f"{where}: operator {operator} was not seen in a real export")
        for key in _keys(properties):
            if key in FORBIDDEN_KEYS:
                problems.append(f"{where}: forbidden property {key}")
        for text in _strings(properties):
            for workflow_id, scope, name in _WORKFLOW_REF.findall(text):
                if workflow_id != workflow["unique_name"]:
                    problems.append(f"{where}: reference to another workflow {workflow_id}")
                elif name in TEMPLATE_OUTPUTS and scope == "output":
                    continue
                elif name not in variables or variables[name]["scope"] != scope:
                    problems.append(f"{where}: unresolved variable reference {scope}.{name}")
            for activity_id in _ACTIVITY_REF.findall(text):
                if activity_id not in activity_ids:
                    problems.append(f"{where}: reference to unknown activity {activity_id}")
        target_id = (properties.get("target") or {}).get("target_id")
        if target_id and target_id not in targets and target_id not in module_refs:
            problems.append(f"{where}: unknown target {target_id}")
        if kind == "python3.script":
            if properties.get("script") not in own_scripts:
                problems.append(f"{where}: the script is not one of this repository's script steps")
            for query in properties.get("script_queries") or []:
                if query.get("script_query_type") not in SCRIPT_OUTPUT_TYPES:
                    problems.append(f"{where}: script output type {query.get('script_query_type')} was not seen in a real export")
            for argument in properties.get("script_arguments") or []:
                if not (isinstance(argument, str) and (_ARGUMENT.fullmatch(argument) or _ONE_REF.fullmatch(argument))):
                    problems.append(f"{where}: a script argument must be one variable or activity reference, or a number")
        if kind == "web-service.http_request":
            request = _request(activity)
            headers = properties.get("custom_headers") or []
            if target_id in module_refs:
                trigger = request[0] == "POST" and isinstance(request[1], str) and _ITEM_URL.fullmatch(request[1])
                if request not in PLATFORM_READS and not trigger:
                    problems.append(f"{where}: {request[0]} {request[1]} is not a known request to the XDR platform")
                if headers:
                    problems.append(f"{where}: a request to the XDR platform carries no custom header")
            elif target_id in targets:
                if request not in ETD_READS | ETD_WRITES:
                    problems.append(f"{where}: {request[0]} {request[1]} is not a known request to this target")
            else:
                problems.append(f"{where}: an HTTP request must name its target")
            for header in headers:
                refs = _WORKFLOW_REF.findall(header["value"])
                if header["name"].lower() in ("authorization", "x-api-key") and (
                        not refs or any(variables.get(n, {}).get("type") != "datatype.secure_string" for _, _, n in refs)):
                    problems.append(f"{where}: header {header['name']} must come from a secure string variable")

    for target in targets.values():
        properties = target["properties"]
        user = properties.get("default_runtime_user_id")
        if user and user not in runtime_users:
            problems.append(f"target {target['name']}: unknown account key {user}")
        if target.get("type") != "web-service.endpoint" or properties.get("protocol") != "https" \
                or not KNOWN_TARGET_HOST.fullmatch(str(properties.get("host"))) \
                or properties.get("path") != KNOWN_TARGET_PATH or properties.get("disable_certificate_validation") is not False:
            problems.append(f"target {target['name']}: not a known HTTPS host and path")
    for user in runtime_users.values():
        if user["properties"].get("basic_password") or user["properties"].get("basic_username"):
            problems.append(f"account key {user['name']}: credentials must not be exported")
    for properties in variables.values():
        if properties["type"] == "datatype.secure_string" and properties["value"]:
            problems.append(f"secure variable {properties['name']}: a value must not be exported")
    return problems


def check_approval_gate(document: dict[str, Any], *, decision: str = "Decision", dry_run: str = "Dry Run",
                        approve: str = "Approve") -> list[str]:
    """Problems that would let a state-changing activity run without a human approval."""
    problems: list[str] = []
    workflow = document["workflow"]
    activities = list(walk(workflow.get("actions")))
    by_id = {a["unique_name"]: a for a, _ in activities}
    position = {a["unique_name"]: index for index, (a, _) in enumerate(activities)}
    ancestors_of = {a["unique_name"]: ancestors for a, ancestors in activities}
    declared = [(unique_name, p) for unique_name, p in _variables(document).items() if p["name"] in (decision, dry_run)]
    if sorted(p["name"] for _, p in declared) != sorted((decision, dry_run)):
        return [f"the variables {decision!r} and {dry_run!r} must each be declared exactly once"]
    decision_id, decision_properties = next((u, p) for u, p in declared if p["name"] == decision)
    dry_run_properties = next(p for _, p in declared if p["name"] == dry_run)
    decision_ref, dry_run_ref = variable_ref(document, decision), variable_ref(document, dry_run)

    # 0. The decision starts empty and cannot be supplied by whoever starts the workflow. Dry Run is an
    #    input that is true unless someone turns it off.
    if (decision_properties.get("scope"), decision_properties.get("type"), decision_properties.get("value")) != (
            "local", "datatype.string", ""):
        problems.append(f"variable {decision!r} must be a local string that starts empty")
    if (dry_run_properties.get("scope"), dry_run_properties.get("type")) != ("input", "datatype.boolean") \
            or dry_run_properties.get("value") is not True:
        problems.append(f"variable {dry_run!r} must be a boolean input that defaults to true")

    # 1. Every approval task is a real question to people, the workflow waits for the answer, and the
    #    task shows the decision card a script wrote before it.
    requests = [a for a, _ in activities if a["type"] == "task.request_approval"]
    if not requests:
        problems.append("no approval request in the workflow")
    card_scripts: set[str] = set()
    for request in requests:
        properties = request["properties"]
        choices = properties.get("approval_choices_holder", {}).get("approval_choices", [])
        if approve not in choices:
            problems.append(f"{request['title']!r}: choice {approve!r} is missing")
        if not [choice for choice in choices if choice != approve]:
            problems.append(f"{request['title']!r}: the task offers no way to refuse")
        roles = properties.get("assignee_roles")
        if not roles or not set(roles) <= KNOWN_ROLES:
            problems.append(f"{request['title']!r}: assignees must be XDR roles ({', '.join(sorted(KNOWN_ROLES))})")
        if not isinstance(properties.get("minimum_approvals"), int) or properties["minimum_approvals"] < 1:
            problems.append(f"{request['title']!r}: minimum approvals must be at least 1")
        if properties.get("wait_for_request_approval_response") is not True:
            problems.append(f"{request['title']!r}: the workflow does not wait for the answer")
        if properties.get("skip_execution") or properties.get("continue_on_failure"):
            problems.append(f"{request['title']!r}: the approval request can be skipped")
        if properties.get("expiration_status") != "Expired":
            problems.append(f"{request['title']!r}: an expired task must not count as an answer")
        shown = _CARD.fullmatch(str(properties.get("body_text")))
        writer = by_id.get(shown.group(1)) if shown else None
        if not writer or writer["type"] != "python3.script" or position[writer["unique_name"]] > position[request["unique_name"]]:
            problems.append(f"{request['title']!r}: the task does not show the decision card of an earlier script")
        else:
            card_scripts.add(writer["unique_name"])

    # 2. The decision variable only ever receives the answer of the approval request just before it, or
    #    is cleared. Every assignment is looked at, wherever it sits and however its target is written.
    answer = re.compile(r"\$activity\.([A-Za-z0-9_]+)\.output\." + re.escape(APPROVAL_RESPONSE) + r"\$")
    records: set[str] = set()
    resets: set[str] = set()
    containers = [("actions", workflow.get("actions") or [])]
    containers += [pair for activity, _ in activities for pair in _children(activity)]
    for key, siblings in containers:
        for index, activity in enumerate(siblings):
            if activity["type"] != "core.set_multiple_variables":
                continue
            for update in activity["properties"]["variables_to_update"]:
                target, value = str(update.get("variable_to_update")), update.get("variable_value_new")
                if decision_id not in target:
                    continue
                if target != decision_ref:
                    problems.append(f"{activity['title']!r}: the decision variable is addressed in an unexpected way")
                elif value == "":
                    resets.add(activity["unique_name"])
                else:
                    match = answer.fullmatch(str(value))
                    request = by_id.get(match.group(1)) if match else None
                    if not request or request["type"] != "task.request_approval":
                        problems.append(f"{activity['title']!r}: the decision is set from something other than an approval answer")
                    elif key != "actions" or index == 0 or siblings[index - 1] is not request:
                        problems.append(f"{activity['title']!r}: the decision is not bound to the approval task just before it")
                    else:
                        records.add(activity["unique_name"])
    for activity, _ in activities:
        if activity["type"] == "python3.script" and decision_id in "".join(_strings(activity["properties"])):
            problems.append(f"{activity['title']!r}: a script must not handle the decision variable")

    def holds(activity: Activity, wanted: set[str]) -> bool:
        return activity["unique_name"] in wanted or any(a["unique_name"] in wanted for a, _ in walk(
            [child for _, children in _children(activity) for child in children]))

    def earlier(container: Activity | None, member: Activity, wanted: set[str], *, direct: bool) -> bool:
        """True when a step before ``member`` in the same sequence is, or (unless ``direct``) contains, one of ``wanted``."""
        siblings = (container.get("actions") if container else workflow.get("actions")) or []
        for sibling in siblings:
            if sibling is member:
                return False
            if sibling["unique_name"] in wanted or (not direct and holds(sibling, wanted)):
                return True
        return False

    # 3. Every state-changing activity sits inside "decision = Approve" and "Dry Run = false", after the
    #    approval was recorded in the same sequence of steps. Inside a loop the decision is cleared at
    #    the start of every pass, so an answer never carries over to another package.
    changing = [(a, ancestors) for a, ancestors in activities if is_state_changing(a)]
    if not changing:
        problems.append("no state-changing activity found: the gate check has nothing to prove")
    for activity, ancestors in changing:
        gates = [ancestor for ancestor in ancestors if ancestor["type"] == "logic.condition_block" and any(
            leaf.get("left_operand") == decision_ref and leaf.get("operator") == "eq"
            and leaf.get("right_operand") == approve for leaf in _leaves(ancestor["properties"].get("condition")))]
        leaves = [leaf for ancestor in ancestors if ancestor["type"] == "logic.condition_block"
                  for leaf in _leaves(ancestor["properties"].get("condition"))]
        if not gates:
            problems.append(f"{activity['title']!r}: state-changing activity outside the approval branch")
        if not any(leaf.get("left_operand") == dry_run_ref and leaf.get("operator") == "eq"
                   and leaf.get("right_operand") is False for leaf in leaves):
            problems.append(f"{activity['title']!r}: state-changing activity outside the Dry Run = false branch")
        if not gates:
            continue
        gate = gates[0]  # the outermost approval branch
        chain = ancestors_of[gate["unique_name"]]  # activities enclosing the gate, outermost first
        block = chain[-1] if chain else None  # the condition block the gate is a branch of
        holder = chain[-2] if len(chain) > 1 else None
        if block is None or block["type"] != "logic.if_else" or not earlier(holder, block, records, direct=False):
            problems.append(f"{activity['title']!r}: the approval is not recorded before the approval branch")
        for depth, enclosing in enumerate(chain):
            if enclosing["type"] not in LOOP_TYPES:
                continue
            # For a for-each the pass is its actions; for a while loop it is the actions of its branch.
            body, inner = enclosing, chain[depth + 1] if depth + 1 < len(chain) else gate
            if enclosing["type"] == "logic.while":
                body, inner = inner, chain[depth + 2] if depth + 2 < len(chain) else gate
            if not earlier(body, inner, resets, direct=True):
                problems.append(f"{activity['title']!r}: the decision is not cleared at the start of each pass of "
                                f"{enclosing['title']!r}")

    # 4. The approver sees the package before deciding and it cannot change afterwards: what a
    #    state-changing request sends (its body, and its URL when the URL is not a constant) is exactly
    #    one output of the script that wrote the decision card, carried through a table and a for-each.
    def origin(text: str) -> Activity | None:
        """The script a value comes from, following for-each items and tables back to it."""
        for _ in range(5):
            match = _ONE_REF.fullmatch(text)
            source = by_id.get(match.group(1)) if match else None
            if source is None or source["type"] == "python3.script":
                return source if source is None or match.group(3).startswith("script_queries.") else None
            if source["type"] not in ("logic.for_each", "corejava.read_table_from_json"):
                return None
            properties = source["properties"]
            text = str(properties.get("source_array") or properties.get("input_json") or "")
        return None

    for activity, _ in changing:
        properties = activity.get("properties", {})
        sent = [str(properties[key]) for key in ("body", "relative_url")
                if properties.get(key) and (key == "body" or "$" in str(properties[key]))]
        if not sent:
            problems.append(f"{activity['title']!r}: the request does not come from a recommendation step")
        for text in sent:
            source = origin(text)
            if source is None:
                problems.append(f"{activity['title']!r}: the request body does not come from a recommendation step")
            elif source["unique_name"] not in card_scripts:
                problems.append(f"{activity['title']!r}: the request body is computed after the approval request, "
                                "or by a step other than the one that wrote the decision card")
    return problems


def check(document: dict[str, Any]) -> list[str]:
    return check_structure(document) + check_approval_gate(document)
