"""The Email Bombing workflow, built on the ``Email Bombing`` workflow exported from the target XDR org.

It reads Secure Email Threat Defense (ETD) through the Cisco XDR platform APIs, so it uses the ETD
integration already connected in XDR: no ETD target, account key or API key is exported or configured.

Lifecycle inside one XDR workflow, per mailbox:

1. investigate (reads only): find the product category of the ETD module type, then ask XDR for the
   sightings of the mailbox from email modules only (all modules answered over XDR's 4 MB limit);
2. recommend: a script measures the flood and sets aside the messages a flood is used to hide; the
   response actions XDR offers for the remaining messages are listed and the decision card is written;
3. approve: a person with the assigned XDR role answers a Request Approval task (an elevated task,
   needing two approvals, for protected mailboxes and large floods);
4. contain: only inside the ``Decision = Approve`` and ``Dry Run = false`` branches, trigger exactly the
   response actions listed before the approval;
5. verify: list the response actions again and report which ones XDR no longer offers;
6. record: the outcome goes to the incident worklog through the template's ``workflow_results``.

``validate.check_approval_gate`` proves point 4 on the generated JSON.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import incident_scripts, scripts
from .builder import APPROVAL_RESPONSE, DEFAULT_CHOICES, MODULE_TYPE_LOOKUP, Activity, Workflow, cond, item, out

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
#: XDR's default choices. A custom choice list imported with an empty "Approval choices array" in the
#: target org, and Cisco does not document its format. *Reject* already changes nothing.
CHOICES = list(DEFAULT_CHOICES)
#: Default text looked for in the title of the ETD response action that moves a message (case-insensitive
#: regular expression). The title must also name the Containment Folder. Titles are not documented.
MOVE_PATTERN = "^(move|quarantine|remediate)"


@dataclass(frozen=True)
class Settings:
    """Values that differ per XDR org."""

    #: XDR roles asked for a standard approval: ``admin`` (administrators), ``user`` (incident responders).
    approver_roles: list[str] = field(default_factory=lambda: ["admin", "user"])
    #: Roles asked when a protected mailbox or a large flood is involved, and how many must approve.
    elevated_roles: list[str] = field(default_factory=lambda: ["admin"])
    elevated_approvals: int = 2
    #: Defaults of the org lists, written into every workflow so they are set once and not per workflow.
    #: Comma-separated. They stay inputs: a rule or a playbook task can still override them.
    internal_domain_suffixes: str = ""
    protected_assets: str = ""
    never_act_on: str = ""
    protected_mailboxes: str = ""
    trusted_sender_domains: str = ""

    def __post_init__(self) -> None:
        for name in ("internal_domain_suffixes", "protected_assets", "never_act_on", "protected_mailboxes",
                     "trusted_sender_domains"):
            value = getattr(self, name)
            if not isinstance(value, str) or "$" in value or "\n" in value or len(value) > 4000:
                raise ValueError(f"{name}: one line of text without a dollar sign is expected")


def build(settings: Settings | None = None) -> Workflow:
    settings = settings or Settings()
    wf = Workflow(
        "Email-Bombing", "Email Bombing",
        "Responds to an email or subscription bombing incident. For each mailbox it reads the Secure Email "
        "Threat Defense sightings through Cisco XDR, measures the flood, lists the messages the flood may hide "
        "and asks an administrator or incident responder to approve moving the flood out of the inbox with "
        "the ETD response action XDR offers. Nothing is moved without that approval, and nothing is moved "
        "while Dry Run is true.",
        unique_name=WORKFLOW_ID,
    )
    wf.properties = {
        "automation_rules": {"type": ["incident.rule_event"]},
        "wf_metadata": {"coa": {"action": ["response"], "intent": "incident_response",
                                "observable_types": ["email"]}},
    }
    wf.categories = [RESPONSE_CATEGORY]
    wf.template_type = "template_workflow.incident_response"
    platform = wf.module_target()

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
                      description="How far back to count the flood (5 to 1440).")
    min_messages = wf.var("Minimum Messages", "integer", "input", 30,
                          description="Fewer inbound messages than this is not a flood.")
    min_domains = wf.var("Minimum Sender Domains", "integer", "input", 10,
                         description="Fewer different sender domains than this is not a flood.")
    min_clean = wf.var("Minimum Clean Percent", "integer", "input", 50,
                       description="Share of neutral or graymail messages a subscription flood must reach, among "
                                   "the messages whose sighting names an ETD verdict.")
    max_messages = wf.var("Maximum Messages", "integer", "input", 200,
                          description="Collection limit per mailbox. Each message is moved by its own XDR response "
                                      "action. A larger flood needs elevated approval and a second run.")
    elevated_above = wf.var("Elevated Approval Above", "integer", "input", 100,
                            description="Moving more messages than this needs elevated approval.")
    folder = wf.var("Containment Folder", "string", "input", "quarantine",
                    description="Where approved messages go: quarantine, junk or trash. Delete is refused. The "
                                "ETD response action used must name this folder.")
    pattern = wf.var("Move Action Pattern", "string", "input", MOVE_PATTERN,
                     description="Text of the ETD response action that moves a message (regular expression on its "
                                 "title, case-insensitive). The worklog lists the titles on offer when nothing "
                                 "matches.")
    protected = wf.var("Protected Mailboxes", "string", "input", settings.protected_mailboxes,
                       description="Comma-separated addresses or @domains that always need elevated approval "
                                   "(executives, finance, shared and service mailboxes).")
    trusted = wf.var("Trusted Sender Domains", "string", "input", settings.trusted_sender_domains,
                     description="Comma-separated sender domains whose messages are never moved.")
    category = wf.var("ETD Product Category", "string", "input",
                      description="Optional. XDR product category of the Secure Email Threat Defense module, used to ask "
                                  "email modules only for sightings. Empty: read from the XDR module types.")
    # Script steps in real exports receive variable references, not literal JSON, so the name is a variable.
    identity = wf.var("Workflow Rules", "string", "local", '{"name": "Email Bombing"}',
                      description="Name used in the result line. Generated: do not edit here.")
    candidates = wf.var("Candidate Observables", "string", "local")
    decision = wf.var("Decision", "string", "local",
                      description="Answer of the approval task for the mailbox being processed.")
    tally = wf.var("Action Tally", "string", "local", "{}")
    results = wf.template_output("workflow_results")
    started_by = wf.template_output("started_by_type")

    def report(title: str, text: str) -> Activity:
        """Append one line to the note the template writes to the incident worklog."""
        return wf.set_vars(title, [(results, f"{results}\n- {text}")])

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

    reset = wf.set_vars("Reset state for this mailbox", [(decision, ""), (tally, "{}")])
    build_observe = wf.python("Build sightings query", scripts.BUILD_OBSERVE, [mailbox, lookback],
                              [("observe_body", "string"), ("window_start", "string"), ("window_end", "string")])
    window_start = out(build_observe, "script_queries.window_start")
    window_end = out(build_observe, "script_queries.window_end")
    lookup = wf.http("List ETD module types", method="GET", target_id=platform, relative_url=MODULE_TYPE_LOOKUP,
                     content_type=None)
    modules = wf.python("Find email modules", scripts.FIND_EMAIL_MODULES,
                        [out(lookup, "status_code"), out(lookup, "response_body"), category],
                        [("module_filter", "string"), ("found", "string"), ("modules_text", "string")])
    sightings = wf.http("Get ETD sightings through XDR", method="POST", target_id=platform,
                        relative_url="/iroh-enrich/observe/observables?" + out(modules, "script_queries.module_filter"),
                        body=out(build_observe, "script_queries.observe_body"))
    collect = wf.python("Collect messages from sightings", scripts.COLLECT_SIGHTINGS,
                        [out(sightings, "status_code"), out(sightings, "response_body"), mailbox, window_start,
                         window_end, max_messages],
                        [("state_json", "string"), ("message_count", "string")])

    # -- 3. recommend ------------------------------------------------------------------------------
    assess = wf.python(
        "Assess flood", scripts.ASSESS,
        [out(collect, "script_queries.state_json"), mailbox, is_protected, min_messages, min_domains, min_clean,
         window_start, window_end, trusted],
        [("qualifies", "string"), ("summary", "string"), ("evidence", "string"), ("respond_body", "string"),
         ("move_count", "string"), ("elevated_reasons", "string")])
    offered = wf.http("List ETD response actions", method="POST", target_id=platform,
                      relative_url="/iroh-response/respond/observables",
                      body=out(assess, "script_queries.respond_body"))
    plan = wf.python(
        "Plan moves and write decision card", scripts.PLAN_MOVES,
        [out(offered, "status_code"), out(offered, "response_body"), out(assess, "script_queries.respond_body"),
         mailbox, out(assess, "script_queries.evidence"), out(assess, "script_queries.elevated_reasons"),
         dry_run, folder, pattern, elevated_above],
        [("has_proposal", "string"), ("elevated", "string"), ("card", "string"), ("summary", "string"),
         ("actions_json", "string"), ("action_count", "string"), ("verify_body", "string"),
         ("package_digest", "string")])
    card = out(plan, "script_queries.card")
    digest = out(plan, "script_queries.package_digest")
    count = out(plan, "script_queries.action_count")

    # -- 4. approve --------------------------------------------------------------------------------
    def approval(level: str, roles: list[str], minimum: int, title: str) -> list[Activity]:
        request = wf.request_approval(f"Request {level} approval", approval_title=title, body=card, roles=roles,
                                      choices=CHOICES, minimum_approvals=minimum)
        return [request, wf.set_vars(f"Record {level} decision", [(decision, out(request, APPROVAL_RESPONSE))])]

    approve = wf.if_else("Which approval level?", [
        wf.branch("Elevated", cond(out(plan, "script_queries.elevated"), "eq", "true"),
                  approval("elevated", settings.elevated_roles, settings.elevated_approvals,
                           f"ELEVATED APPROVAL REQUIRED - Email bombing: move flood for {mailbox}")),
        wf.branch("Standard", cond(out(plan, "script_queries.elevated"), "ne", "true"),
                  approval("standard", settings.approver_roles, 1, f"Email bombing: move flood for {mailbox}")),
    ])

    # -- 5. contain and verify: only after Approve, only when Dry Run is false -----------------------
    actions = wf.read_table("Approved moves table", out(plan, "script_queries.actions_json"),
                            ["url", "title", "target", "kind", "module", "key"])
    each_action = wf.for_each("For each approved move", out(actions, "read_table_from_json"),
                              description="Triggers one response action that was listed on the decision card.")
    trigger = wf.http("Move approved message", method="POST", target_id=platform,
                      relative_url=item(each_action, "url"))
    record = wf.python("Record move result", incident_scripts.RECORD_TRIGGER,
                       [tally, out(trigger, "status_code"), out(trigger, "response_body"), item(each_action, "title"),
                        item(each_action, "target"), item(each_action, "key")], [("tally_json", "string")])
    each_action["actions"] = [trigger, record,
                              wf.set_vars("Store move tally", [(tally, out(record, "script_queries.tally_json"))])]
    recheck = wf.http("List ETD response actions again", method="POST", target_id=platform,
                      relative_url="/iroh-response/respond/observables",
                      body=out(plan, "script_queries.verify_body"))
    outcome = wf.python("Build containment result", incident_scripts.RESULT,
                        [identity, digest, tally, out(recheck, "status_code"), out(recheck, "response_body")],
                        [("result", "string")])

    act = wf.if_else("What did the approver decide?", [
        wf.branch("Approved", cond(decision, "eq", APPROVE), [
            wf.if_else("Dry run?", [
                wf.branch("Dry run: report only", cond(dry_run, "eq", True), [
                    report("Report dry run",
                           f"`{mailbox}`: APPROVED in DRY RUN. Would move {count} messages to {folder} "
                           f"(package {digest}). Nothing was changed."),
                ]),
                wf.branch("Live: execute the approved package", cond(dry_run, "eq", False), [
                    actions, each_action, recheck, outcome,
                    report("Report containment", f"`{mailbox}`: {out(outcome, 'script_queries.result')}"),
                ]),
            ]),
        ]),
        wf.branch("Not approved", cond(decision, "ne", APPROVE), [
            report("Report decision without action",
                   f"`{mailbox}`: decision \"{decision}\". Nothing was changed (package {digest})."),
        ]),
    ])

    each["actions"] = [
        reset, build_observe, sightings, collect, assess,
        wf.if_else("Is it a flood?", [
            wf.branch("No flood", cond(out(assess, "script_queries.qualifies"), "ne", "true"),
                      [report("Report assessment without proposal", out(assess, "script_queries.summary"))]),
            wf.branch("Flood", cond(out(assess, "script_queries.qualifies"), "eq", "true"), [
                report("Report flood", out(assess, "script_queries.summary")),
                offered, plan,
                wf.if_else("Can XDR move the messages?", [
                    wf.branch("No matching action", cond(out(plan, "script_queries.has_proposal"), "ne", "true"),
                              [report("Report flood without action", out(plan, "script_queries.summary"))]),
                    wf.branch("Moves proposed", cond(out(plan, "script_queries.has_proposal"), "eq", "true"), [
                        report("Report proposal", out(plan, "script_queries.summary")),
                        wf.if_else("Audit only?", [
                            wf.branch("Audit only: no approval task", cond(audit_only, "eq", True), [
                                report("Report audit only",
                                       f"`{mailbox}`: AUDIT ONLY. No approval task was raised and nothing was "
                                       f"changed (package {digest})."),
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
            wf.branch("Mailboxes found", cond(out(select, "script_queries.has_mailboxes"), "eq", "true"), [
                lookup, modules,
                wf.if_else("Email modules found?", [
                    wf.branch("No email module", cond(out(modules, "script_queries.found"), "ne", "true"), [
                        report("Report no email module",
                               "Email Bombing: no Secure Email Threat Defense module found in XDR ("
                               f"{out(modules, 'script_queries.modules_text')}). Nothing was assessed or changed. "
                               "Check that the integration is enabled, or set the ETD Product Category input."),
                    ]),
                    wf.branch("Email modules found", cond(out(modules, "script_queries.found"), "eq", "true"), [
                        report("Report email modules",
                               f"Email Bombing: sightings from {out(modules, 'script_queries.modules_text')}."),
                        table, each,
                    ]),
                ]),
            ]),
        ]),
        wf.if_else("Started from a playbook task?", [
            wf.branch("Playbook task: report", cond(started_by, "eq", "playbook_task"), [answered]),
        ]),
    ], unique_name=TEMPLATE_IDS["group"],
        description="Investigates each mailbox of the incident, asks for approval and acts on the answer.")]
    return wf
