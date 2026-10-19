"""Builder for Cisco XDR Automation workflow exports.

Cisco publishes no schema for the export format. Every shape produced here is copied from a real export
(sources and what each one proves are listed in ``xdr/README.md``):

- the ``Email Bombing`` workflow exported from the target XDR org (envelope, ``wf_metadata``,
  ``started_by_type``, ``workflow_results``, the observable loops, and ``task.request_approval`` with
  role assignees and its built-in wait);
- ``ciscomanagedservices/ciscolive25-xdr-automate`` (``python3.script``, ``web-service.http_request`` with custom headers, secure string variables,
  compound conditions, ``logic.while``, ``corejava.read_table_from_json`` with ``logic.for_each``, and an
  HTTP request to the XDR platform through the module target
  ``$module_target;Cisco XDR;securex:ao:iroh_api;platform-apis$`` with the ``module_targets`` envelope);
- ``ciscotee/CiscoSecureEndpoint-FindDuplicateGUID`` (``logic.completed``, ``corejava.jsonpathquery``).

Activity types, property names and operators outside those exports are not used.
"""
from __future__ import annotations

import hashlib
import textwrap
from typing import Any

_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_OCTAL = "01234567"
_MIXED = _UPPER + "abcdefghijklmnopqrstuvwxyz"

#: Variables the incident response template provides without declaring them (referenced by name).
TEMPLATE_OUTPUTS = ("started_by", "started_by_type", "workflow_results")

#: Choices of a Request Approval activity left on its defaults, and the output that holds the answer.
#: The output name is not documented and was not in the org's export: confirm it in the variable browser.
DEFAULT_CHOICES = ["Approve", "Reject"]
APPROVAL_RESPONSE = "response"

#: The XDR platform APIs (enrich, response, private intelligence) as a module target: module type,
#: external ID and endpoint. XDR provides it in every org, so it needs no host, no account key and no
#: org-specific identifier. Relative URLs start below ``/iroh``.
PLATFORM_APIS = ("Cisco XDR", "securex:ao:iroh_api", "platform-apis")
#: Lists the module types whose title matches Secure Email Threat Defense (read-only; module types carry no
#: org credential). Used to limit the sightings query to email modules.
MODULE_TYPE_LOOKUP = "/iroh-int/module-type?query=Email%20Threat%20Defense&limit=20"


def module_target_ref(module: tuple[str, str, str]) -> str:
    """Target reference of a module target, as real exports write it."""
    return "$module_target;" + ";".join(module) + "$"

Activity = dict[str, Any]


def make_id(kind: str, *parts: str) -> str:
    """Deterministic identifier in the format XDR accepts.

    ``<kind>_02``, 11 upper-case letters or digits, one digit 0 to 7, then 21 letters or digits. All 1781
    identifiers in the org's exports and the Cisco Live exports have this shape, and XDR refuses an import
    whose 14th character is not a digit 0 to 7 ("invalid unique_name format").
    """
    digest = hashlib.sha512("|".join((kind, *parts)).encode()).digest()
    head = "".join(_UPPER[b % len(_UPPER)] for b in digest[:11])
    tail = "".join(_MIXED[b % len(_MIXED)] for b in digest[12:33])
    return f"{kind}_02{head}{_OCTAL[digest[11] % len(_OCTAL)]}{tail}"


def cond(left: Any, operator: str, right: Any) -> dict[str, Any]:
    return {"left_operand": left, "operator": operator, "right_operand": right}


def out(activity: Activity, field: str) -> str:
    """Reference to an output of an earlier activity."""
    return f"$activity.{activity['unique_name']}.output.{field}$"


def item(for_each: Activity, column: str) -> str:
    """Reference to a field of the element a ``logic.for_each`` is currently processing."""
    return f"$activity.{for_each['unique_name']}.input.source_array[@].{column}$"


class Workflow:
    """Incremental builder that keeps identifiers and references consistent."""

    def __init__(self, slug: str, name: str, description: str, *, unique_name: str | None = None) -> None:
        self.slug = slug
        self.id = unique_name or make_id("definition_workflow", slug)
        self.name = name
        self.description = description
        self.variables: list[dict[str, Any]] = []
        self.actions: list[Activity] = []
        self.module_targets: list[tuple[str, str, str]] = []
        self.properties: dict[str, Any] = {}
        self.categories: list[str] = []
        self.template_type: str | None = None
        self._vars: dict[str, tuple[str, str]] = {}
        self._titles: dict[str, int] = {}

    # -- variables ---------------------------------------------------------------------------------

    def var(self, name: str, vtype: str, scope: str, value: Any = "", *, description: str = "",
            required: bool = False) -> str:
        """Declare a workflow variable and return its reference."""
        if name in self._vars:
            raise ValueError(f"variable {name!r} declared twice")
        unique_name = make_id("variable_workflow", self.slug, name)
        schema = f"datatype.{vtype}"
        properties: dict[str, Any] = {"value": value, "scope": scope, "name": name, "type": schema}
        if description:
            properties["description"] = description
        properties.update({"is_required": required, "display_on_wizard": False, "is_invisible": False,
                           "variable_string_format": ""})
        self.variables.append({"schema_id": schema, "properties": properties, "unique_name": unique_name,
                               "object_type": "variable_workflow"})
        self._vars[name] = (scope, unique_name)
        return self.ref(name)

    def ref(self, name: str) -> str:
        scope, unique_name = self._vars[name]
        return f"$workflow.{self.id}.{scope}.{unique_name}$"

    def template_output(self, name: str) -> str:
        """Reference to an output the incident response template provides (``workflow_results`` ...)."""
        if name not in TEMPLATE_OUTPUTS:
            raise ValueError(f"{name!r} is not a template output")
        return f"$workflow.{self.id}.output.{name}$"

    # -- targets ------------------------------------------------------------------------------------
    # Only module targets XDR provides. A vendor target needs an account key, which XDR asks for on import.

    def module_target(self, module: tuple[str, str, str] = PLATFORM_APIS) -> str:
        """Declare a module target XDR provides (default: the platform APIs) and return its reference."""
        if module not in self.module_targets:
            self.module_targets.append(module)
        return module_target_ref(module)

    # -- activities --------------------------------------------------------------------------------

    def _activity(self, type_: str, name: str, title: str, properties: dict[str, Any], *,
                  unique_name: str | None = None, base_type: str = "activity", description: str = "",
                  **children: Any) -> Activity:
        seen = self._titles.get(title, 0)
        self._titles[title] = seen + 1
        key = title if not seen else f"{title}#{seen + 1}"
        base: dict[str, Any] = {"continue_on_failure": False}
        if description:
            base["description"] = description
        base["display_name"] = title
        base["skip_execution"] = False
        base.update(properties)
        activity: Activity = {
            "unique_name": unique_name or make_id("definition_activity", self.slug, key),
            "name": name, "title": title, "type": type_, "base_type": base_type,
            "properties": dict(sorted(base.items())), "object_type": "definition_activity",
        }
        activity.update(children)
        return activity

    def http(self, title: str, *, method: str, target_id: str, relative_url: str, body: str | None = None,
             headers: list[tuple[str, str]] | None = None,
             content_type: str | None = "application/json") -> Activity:
        """HTTP request to a module target (no account key).

        An error status does not stop the workflow: the caller checks ``status_code``.
        """
        properties: dict[str, Any] = {
            "accept": "application/json", "action_timeout": 180, "allow_auto_redirect": True,
            "allow_headers_redirect": False, "continue_on_error_status_code": True, "method": method,
            "relative_url": relative_url,
            "runtime_user": {"target_default": True},
            "target": {"override_workflow_target": True, "target_id": target_id},
        }
        if headers:
            properties["custom_headers"] = [{"name": n, "value": v} for n, v in headers]
        if body is not None:
            properties["body"] = body
        if content_type:
            properties["content_type"] = content_type
        return self._activity("web-service.http_request", "HTTP Request", title, properties)

    def python(self, title: str, script: str, args: list[str], outputs: list[tuple[str, str]]) -> Activity:
        """Execute Python Script: ``args`` arrive as ``sys.argv[1:]`` strings, outputs are global names."""
        return self._activity("python3.script", "Execute Python Script", title, {
            "action_timeout": 180, "script": textwrap.dedent(script).strip() + "\n", "script_arguments": args,
            "script_queries": [{"script_query": name, "script_query_name": name, "script_query_type": kind}
                               for name, kind in outputs],
        })

    def set_vars(self, title: str, updates: list[tuple[str, Any]]) -> Activity:
        """Set variables. Each update is ``(reference to the variable, new value)``."""
        return self._activity("core.set_multiple_variables", "Set Variables", title, {
            "variables_to_update": [{"variable_to_update": target, "variable_value_new": value}
                                    for target, value in updates],
        })

    def branch(self, title: str, condition: dict[str, Any], actions: list[Activity], *,
               unique_name: str | None = None) -> Activity:
        return self._activity("logic.condition_block", "Condition Branch", title, {"condition": condition},
                              unique_name=unique_name, actions=actions)

    def if_else(self, title: str, branches: list[Activity], *, unique_name: str | None = None) -> Activity:
        return self._activity("logic.if_else", "Condition Block", title, {"conditions": None},
                              unique_name=unique_name, blocks=branches)

    def for_each(self, title: str, source_array: str, *, unique_name: str | None = None,
                 description: str = "") -> Activity:
        return self._activity("logic.for_each", "For Each", title, {"source_array": source_array},
                              unique_name=unique_name, description=description, actions=[])

    def group(self, title: str, actions: list[Activity], *, unique_name: str | None = None,
              description: str = "") -> Activity:
        return self._activity("logic.group", "Group", title, {"display_as_suggestion": False},
                              unique_name=unique_name, description=description, actions=actions)

    def read_table(self, title: str, input_json: str, columns: list[str]) -> Activity:
        return self._activity("corejava.read_table_from_json", "Read Table from JSON", title, {
            "action_timeout": 180, "input_json": input_json, "jsonpath_query": "$.*", "persist_output": False,
            "populate_columns": False,
            "table_columns": [{"column_name": column, "column_type": "string"} for column in columns],
        })

    def request_approval(self, title: str, *, approval_title: str, body: str, roles: list[str],
                         choices: list[str], minimum_approvals: int, expire_hours: int = 72) -> Activity:
        """Request Approval as the target org exports it: the activity itself waits for the answer.

        Assignees are XDR roles (``admin``, ``user``). The owner and requestor are whoever started the
        workflow. The workflow acts only on the answer the activity returns.
        """
        default = choices == DEFAULT_CHOICES
        relative = {"duration": expire_hours, "time_units": "hours"}
        return self._activity("task.request_approval", "Request Approval", title, {
            "approval_choices_holder": {"approval_choices": choices, "is_custom_approval_choices": not default,
                                        "is_default_approval_choices": default},
            "approval_title": approval_title, "assignee_roles": roles, "body_text": body,
            "due_date": {"is_relative_time": True, "relative_time": dict(relative), "set_due_date": True},
            "expiration_date": {"is_relative_time": True, "relative_time": dict(relative)},
            "expiration_status": "Expired", "minimum_approvals": minimum_approvals, "priority": "high",
            "task_owner": self.template_output("started_by"),
            "task_requestor": self.template_output("started_by"),
            "wait_for_request_approval_response": True,
        })

    # -- export ------------------------------------------------------------------------------------

    def export(self) -> dict[str, Any]:
        properties: dict[str, Any] = {"atomic": {"is_atomic": False}}
        properties.update(self.properties)
        properties.update({"delete_workflow_instance": False, "description": self.description,
                           "display_name": self.name, "runtime_user": {"target_default": True},
                           "target": {"no_target": True}})
        workflow: dict[str, Any] = {
            "unique_name": self.id, "name": self.name, "title": self.name, "type": "generic.workflow",
            "base_type": "workflow", "variables": self.variables, "properties": dict(sorted(properties.items())),
            "object_type": "definition_workflow", "actions": self.actions, "categories": self.categories,
        }
        if self.template_type:
            workflow["template_type"] = self.template_type
        document: dict[str, Any] = {"workflow": workflow}
        if self.module_targets:
            document["module_targets"] = [
                {"module_type": module_type, "external_id": external_id, "proxy_endpoint_metadata_id": endpoint}
                for module_type, external_id, endpoint in self.module_targets]
        return document

    @property
    def folder(self) -> str:
        return f"{self.slug}__{self.id}"

    @property
    def filename(self) -> str:
        return f"{self.id}.json"
