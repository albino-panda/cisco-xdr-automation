"""The Email Bombing workflow, built on the ``Email Bombing`` workflow exported from the target XDR org.

Lifecycle inside one XDR workflow, per mailbox:

1. investigate (reads only): search Secure Email Threat Defense for inbound mail to the mailbox;
2. recommend: a script measures the flood, sets aside the messages a flood is used to hide and writes
   the decision card;
3. approve: a person with the assigned XDR role answers a Request Approval task (an elevated task,
   needing two approvals, for protected mailboxes and large floods);
4. contain: only inside the ``Decision = Approve`` and ``Dry Run = false`` branches, move exactly the
   messages listed before the approval;
5. verify: read the status of a sample of the moved messages;
6. record: the outcome goes to the incident worklog through the template's ``workflow_results``.

``validate.check_approval_gate`` proves point 4 on the generated JSON.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import scripts
from .builder import APPROVAL_RESPONSE, Activity, Workflow, cond, item, out

#: Identifiers of the "Email Bombing" workflow and of the template activities kept from its export, so
#: that importing the generated file updates that workflow instead of creating a second one.
WORKFLOW_ID = "definition_workflow_02Z4AR352O6QR6IidwMvYIOOo7bQvF5hrUW"
TEMPLATE_IDS = {
    "group": "definition_activity_02Z4AR36WU6940FpiKeQ1fLB0xXkuLWq6ny",
    "started": "definition_activity_02Z4AR39HOAZ16BDRhnNtrDLDCR9uLL9DX1",
    "playbook": "definition_activity_02Z4AR3AYLEUB05IR0HzhnObxOY7DlWyK5b",
    "selected": "definition_activity_02Z4AR3CXKWF43FvsKaPJKwpNXTECID0TGM",
    "rule": "definition_activity_02Z4AR3QRADQN6XcXYWAGXN4b2DLrqAqYZw",
    "incident": "definition_activity_02Z4AR3SOW6J155zRav4O7F986OaOairqyL",
}
RESPONSE_CATEGORY = "category_1BMfMXSnJMyt5Ihqi7rWJr5N8cf"

APPROVE = "Approve"
CHOICES = [APPROVE, "Reject", "More investigation"]


@dataclass(frozen=True)
class Settings:
    """Values that differ per XDR org."""

    #: XDR roles asked for a standard approval: ``admin`` (administrators), ``user`` (incident responders).
    approver_roles: list[str] = field(default_factory=lambda: ["admin", "user"])
    #: Roles asked when a protected mailbox or a large flood is involved, and how many must approve.
    elevated_roles: list[str] = field(default_factory=lambda: ["admin"])
    elevated_approvals: int = 2
    etd_host: str = "api.us.etd.cisco.com"
    #: Defaults of the org lists, written into every workflow so they are set once and not per workflow.
    #: Comma-separated. They stay inputs: a rule or a playbook task can still override them.
    internal_domain_suffixes: str = ""
    protected_assets: str = ""
    never_act_on: str = ""
    protected_mailboxes: str = ""
    trusted_sender_domains: str = ""

    def __post_init__(self) -> None:
        for name in ("internal_domain_suffixes", "protected_assets", "never_act_on", "protected_mailboxes",
                     "trusted_sender_domains", "etd_host"):
            value = getattr(self, name)
            if not isinstance(value, str) or "$" in value or "\n" in value or len(value) > 4000:
                raise ValueError(f"{name}: one line of text without a dollar sign is expected")


def build(settings: Settings | None = None) -> Workflow:
    settings = settings or Settings()
    wf = Workflow(
        "Email-Bombing", "Email Bombing",
        "Responds to an email or subscription bombing incident. For each mailbox it searches Secure Email "
        "Threat Defense, measures the flood, lists the messages the flood may hide and asks an administrator or incident responder "
        "to approve moving the flood out of the inbox. Nothing is moved without that approval, and nothing "
        "is moved while Dry Run is true.",
        unique_name=WORKFLOW_ID,
    )
    wf.properties = {
        "automation_rules": {"type": ["incident.rule_event"]},
        "wf_metadata": {"coa": {"action": ["response"], "intent": "incident_response",
                                "observable_types": ["email"]}},
    }
    wf.categories = [RESPONSE_CATEGORY]
    wf.template_type = "template_workflow.incident_response"

    # -- variables ---------------------------------------------------------------------------------
    dry_run = wf.var("Dry Run", "boolean", "input", True,
                     description="True: investigate, ask for approval and report what would be moved, but move "
                                 "nothing. Set to false only after a dry run looked right.")
    audit_only = wf.var("Audit Only", "boolean", "input", False,
                        description="True: investigate and write the assessment to the incident worklog, but raise "
                                    "no approval task and move nothing. For tuning the rule that starts the workflow.")
    mailbox_in = wf.var("Mailbox", "string", "input",
                        description="Optional. A mailbox to assess when the workflow is started by hand.")
    lookback = wf.var("Lookback Minutes", "integer", "input", 60,
                      description="How far back to search for the flood (5 to 1440).")
    min_messages = wf.var("Minimum Messages", "integer", "input", 30,
                          description="Fewer inbound messages than this is not a flood.")
    min_domains = wf.var("Minimum Sender Domains", "integer", "input", 10,
                         description="Fewer different sender domains than this is not a flood.")
    min_clean = wf.var("Minimum Clean Percent", "integer", "input", 50,
                       description="Share of neutral or graymail messages a subscription flood must reach.")
    max_messages = wf.var("Maximum Messages", "integer", "input", 1000,
                          description="Collection limit per mailbox. A larger flood needs elevated approval "
                                      "and a second run.")
    elevated_above = wf.var("Elevated Approval Above", "integer", "input", 500,
                            description="Moving more messages than this needs elevated approval.")
    folder = wf.var("Containment Folder", "string", "input", "quarantine",
                    description="Where approved messages go: quarantine, junk or trash. Delete is refused.")
    verdict = wf.var("Reclassify Verdict", "string", "input", "graymail",
                     description="ETD verdict recorded with the move (the ETD API requires one).")
    protected = wf.var("Protected Mailboxes", "string", "input", settings.protected_mailboxes,
                       description="Comma-separated addresses or @domains that always need elevated approval "
                                   "(executives, finance, shared and service mailboxes).")
    trusted = wf.var("Trusted Sender Domains", "string", "input", settings.trusted_sender_domains,
                     description="Comma-separated sender domains whose messages are never moved.")
    api_key = wf.var("ETD API Key", "secure_string", "local",
                     description="Secure Email Threat Defense API key, sent as x-api-key. Set it in the editor.")
    token = wf.var("ETD Access Token", "secure_string", "local",
                   description="Short-lived ETD token obtained by the workflow.")
    candidates = wf.var("Candidate Observables", "string", "local")
    search_body = wf.var("Search Body", "string", "local")
    state = wf.var("Search State", "string", "local", "{}")
    has_more = wf.var("Has More Pages", "string", "local", "false")
    decision = wf.var("Decision", "string", "local",
                      description="Answer of the approval task for the mailbox being processed.")
    tally = wf.var("Containment Tally", "string", "local", "{}")
    results = wf.template_output("workflow_results")
    started_by = wf.template_output("started_by_type")

    def report(title: str, text: str) -> Activity:
        """Append one line to the note the template writes to the incident worklog."""
        return wf.set_vars(title, [(results, f"{results}\n- {text}")])

    # -- targets -----------------------------------------------------------------------------------
    client = wf.runtime_user("Email Bombing - ETD API Client",
                             "Secure Email Threat Defense API client. Username: client ID. Password: client secret.")
    regions = "Regional hosts: api.us, api.de, api.au, api.in or api.ae .etd.cisco.com."
    token_target = wf.target("Email Bombing - ETD Token", settings.etd_host, path="/v1", runtime_user_id=client,
                             description="ETD token endpoint, called with the API client. " + regions)
    api_target = wf.target("Email Bombing - ETD API", settings.etd_host, path="/v1",
                           description="ETD message search, move and status, called with the token. " + regions)
    etd_headers = [("Authorization", f"Bearer {token}"), ("x-api-key", api_key)]

    # -- 1. collect the observables the template hands over -----------------------------------------
    selected = wf.for_each(
        "For each selected observable", "$intent.intent incident_response.input.selected_observables$",
        unique_name=TEMPLATE_IDS["selected"],
        description="Collects the observables the analyst selected in the playbook task.")
    selected["actions"] = [wf.set_vars("Collect selected observable",
                                       [(candidates, f"{candidates}\n{item(selected, 'value')}")])]
    incident = wf.for_each(
        "For each incident observable", "$rule.incident rule_event.output.targets.data$",
        unique_name=TEMPLATE_IDS["incident"], description="Collects the observables of the incident.")
    incident["actions"] = [wf.set_vars("Collect incident observable",
                                       [(candidates, f"{candidates}\n{item(incident, 'value')}")])]
    started = wf.if_else("How was the workflow started?", [
        wf.branch("Playbook task", cond(started_by, "eq", "playbook_task"), [selected],
                  unique_name=TEMPLATE_IDS["playbook"]),
        wf.branch("Incident automation rule", cond(started_by, "eq", "incident_rule"), [incident],
                  unique_name=TEMPLATE_IDS["rule"]),
    ], unique_name=TEMPLATE_IDS["started"])
    select = wf.python("Select mailboxes", scripts.SELECT_MAILBOXES, [candidates, protected, "5"],
                       [("mailboxes_json", "string"), ("has_mailboxes", "string"), ("mailbox_count", "string"),
                        ("skipped_count", "string")])

    # -- 2. investigate one mailbox (reads only) -----------------------------------------------------
    table = wf.read_table("Mailboxes table", out(select, "script_queries.mailboxes_json"), ["mailbox", "protected"])
    each = wf.for_each("For each mailbox", out(table, "read_table_from_json"),
                       description="Investigates one mailbox, asks for approval and acts on the answer.")
    mailbox, is_protected = item(each, "mailbox"), item(each, "protected")

    reset = wf.set_vars("Reset state for this mailbox", [
        (decision, ""), (state, "{}"), (tally, "{}"), (has_more, "true")])
    build_search = wf.python("Build ETD search", scripts.BUILD_SEARCH, [mailbox, lookback],
                             [("search_body", "string"), ("window_start", "string"), ("window_end", "string")])
    window_start = out(build_search, "script_queries.window_start")
    window_end = out(build_search, "script_queries.window_end")
    store_search = wf.set_vars("Store search body", [(search_body, out(build_search, "script_queries.search_body"))])
    # Same request as Cisco's "Secure Email Threat Defense - Get Access Token" atomic: no body, JSON content type.
    get_token = wf.http("Get ETD access token", method="POST", target_id=token_target, relative_url="/oauth/token",
                        headers=[("x-api-key", api_key)])
    extract_token = wf.jsonpath("Extract ETD access token", out(get_token, "response_body"),
                                [("$.accessToken", "access_token", "secure_string")])
    store_token = wf.set_vars("Store ETD access token",
                              [(token, out(extract_token, "jsonpath_queries.access_token"))])
    search = wf.http("Search ETD messages", method="POST", target_id=api_target, relative_url="/messages/search",
                     body=search_body, headers=etd_headers)
    merge = wf.python("Merge page into search state", scripts.MERGE_PAGE,
                      [state, out(search, "status_code"), out(search, "response_body"), search_body, max_messages],
                      [("state_json", "string"), ("search_body", "string"), ("has_more", "string"),
                       ("message_count", "string")])
    pages = wf.while_loop("Page through ETD results", cond(has_more, "eq", "true"), [
        search, merge,
        wf.set_vars("Update paging state", [(state, out(merge, "script_queries.state_json")),
                                            (search_body, out(merge, "script_queries.search_body")),
                                            (has_more, out(merge, "script_queries.has_more"))]),
    ])

    # -- 3. recommend ------------------------------------------------------------------------------
    assess = wf.python(
        "Assess flood and write decision card", scripts.ASSESS,
        [state, mailbox, is_protected, min_messages, min_domains, min_clean, dry_run, folder, verdict,
         window_start, window_end, elevated_above, trusted],
        [("qualifies", "string"), ("elevated", "string"), ("card", "string"), ("summary", "string"),
         ("move_chunks", "string"), ("move_count", "string"), ("verify_sample", "string"),
         ("package_digest", "string")])
    card = out(assess, "script_queries.card")
    summary = out(assess, "script_queries.summary")
    digest = out(assess, "script_queries.package_digest")

    # -- 4. approve --------------------------------------------------------------------------------
    def approval(level: str, roles: list[str], minimum: int, title: str) -> list[Activity]:
        request = wf.request_approval(f"Request {level} approval", approval_title=title, body=card, roles=roles,
                                      choices=CHOICES, minimum_approvals=minimum)
        return [request, wf.set_vars(f"Record {level} decision", [(decision, out(request, APPROVAL_RESPONSE))])]

    approve = wf.if_else("Which approval level?", [
        wf.branch("Elevated", cond(out(assess, "script_queries.elevated"), "eq", "true"),
                  approval("elevated", settings.elevated_roles, settings.elevated_approvals,
                           f"ELEVATED APPROVAL REQUIRED - Email bombing: move flood for {mailbox}")),
        wf.branch("Standard", cond(out(assess, "script_queries.elevated"), "ne", "true"),
                  approval("standard", settings.approver_roles, 1, f"Email bombing: move flood for {mailbox}")),
    ])

    # -- 5. contain and verify: only after Approve, only when Dry Run is false -----------------------
    chunks = wf.read_table("Move requests table", out(assess, "script_queries.move_chunks"), ["body", "count"])
    each_chunk = wf.for_each("For each chunk of up to 100 messages", out(chunks, "read_table_from_json"))
    move = wf.http("Move approved messages", method="POST", target_id=api_target, relative_url="/messages/move",
                   body=item(each_chunk, "body"), headers=etd_headers)
    record_move = wf.python("Record move result", scripts.RECORD_MOVE,
                            [tally, out(move, "status_code"), out(move, "response_body"), item(each_chunk, "count")],
                            [("tally_json", "string")])
    each_chunk["actions"] = [move, record_move, wf.set_vars(
        "Store move tally", [(tally, out(record_move, "script_queries.tally_json"))])]
    sample = wf.read_table("Verification sample table", out(assess, "script_queries.verify_sample"), ["body"])
    each_sample = wf.for_each("For each sampled message", out(sample, "read_table_from_json"))
    status = wf.http("Read message status", method="POST", target_id=api_target, relative_url="/messages/status",
                     body=item(each_sample, "body"), headers=etd_headers)
    record_status = wf.python("Record verification", scripts.RECORD_VERIFICATION,
                              [tally, out(status, "status_code"), out(status, "response_body"), folder],
                              [("tally_json", "string")])
    each_sample["actions"] = [status, record_status, wf.set_vars(
        "Store verification tally", [(tally, out(record_status, "script_queries.tally_json"))])]
    contain_result = wf.python("Build containment result", scripts.CONTAINMENT_RESULT,
                               [mailbox, folder, digest, tally], [("result", "string")])

    act = wf.if_else("What did the approver decide?", [
        wf.branch("Approved", cond(decision, "eq", APPROVE), [
            wf.if_else("Dry run?", [
                wf.branch("Dry run: report only", cond(dry_run, "eq", True), [
                    report("Report dry run",
                           f"`{mailbox}`: APPROVED in DRY RUN. Would move {out(assess, 'script_queries.move_count')} "
                           f"messages to {folder} (package {digest}). Nothing was changed."),
                ]),
                wf.branch("Live: execute the approved package", cond(dry_run, "eq", False), [
                    chunks, each_chunk, sample, each_sample, contain_result,
                    report("Report containment", out(contain_result, "script_queries.result")),
                ]),
            ]),
        ]),
        wf.branch("Not approved", cond(decision, "ne", APPROVE), [
            report("Report decision without action",
                   f"`{mailbox}`: decision \"{decision}\". Nothing was changed (package {digest})."),
        ]),
    ])

    each["actions"] = [
        reset, build_search, store_search, get_token,
        wf.if_else("Did ETD issue a token?", [
            wf.branch("No token", cond(out(get_token, "status_code"), "ne", 200), [
                report("Report ETD token failure",
                       f"`{mailbox}`: Secure Email Threat Defense refused the token request (HTTP "
                       f"{out(get_token, 'status_code')}). Not assessed, nothing changed."),
            ]),
            wf.branch("Token issued", cond(out(get_token, "status_code"), "eq", 200), [
                extract_token, store_token, pages, assess,
                wf.if_else("Is it a flood?", [
                    wf.branch("No flood", cond(out(assess, "script_queries.qualifies"), "ne", "true"),
                              [report("Report assessment without proposal", summary)]),
                    wf.branch("Flood", cond(out(assess, "script_queries.qualifies"), "eq", "true"), [
                        report("Report proposal", summary),
                        wf.if_else("Audit only?", [
                            wf.branch("Audit only: no approval task", cond(audit_only, "eq", True), [
                                report("Report audit only",
                                       f"`{mailbox}`: AUDIT ONLY. No approval task was raised and nothing was changed "
                                       f"(package {digest})."),
                            ]),
                            wf.branch("Ask for approval", cond(audit_only, "eq", False), [approve, act]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ]

    # -- 6. report back to the playbook task ---------------------------------------------------------
    answered = wf.for_each("For each selected observable: report",
                           "$intent.intent incident_response.input.selected_observables$")
    answered["actions"] = [wf.set_vars("Set observable result", [
        (item(answered, "succeeded"), True),
        (item(answered, "result_message"),
         "Email Bombing workflow finished. The outcome for each mailbox is in the incident worklog."),
    ])]

    wf.actions = [wf.group("Incident response with observables", [
        wf.set_vars("Start with the Mailbox input", [(candidates, mailbox_in)]),
        started, select,
        wf.if_else("Any mailbox to assess?", [
            wf.branch("No mailbox", cond(out(select, "script_queries.has_mailboxes"), "ne", "true"), [
                report("Report nothing to assess",
                       "No email address observable to assess. Nothing was changed."),
            ]),
            wf.branch("Mailboxes found", cond(out(select, "script_queries.has_mailboxes"), "eq", "true"),
                      [table, each]),
        ]),
        wf.if_else("Started from a playbook task?", [
            wf.branch("Playbook task: report", cond(started_by, "eq", "playbook_task"), [answered]),
        ]),
    ], unique_name=TEMPLATE_IDS["group"],
        description="Investigates each mailbox of the incident, asks for approval and acts on the answer.")]
    return wf
