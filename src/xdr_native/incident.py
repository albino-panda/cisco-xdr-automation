"""The shared incident response workflow, generated once per attack type (``specs.py``).

It needs one target only: the Cisco XDR platform APIs, which every org has (``builder.PLATFORM_APIS``).
No vendor host, account key or org-specific identifier is exported or has to be configured.

Lifecycle inside one XDR workflow:

1. collect the observables the playbook task or the incident rule hands over (or the *Observables* input);
2. investigate (reads only): verdicts and sightings of every observable from all XDR modules, and the
   response actions those modules offer for each observable;
3. recommend: a script applies the rules of the attack type and writes the decision card. An indicator is
   proposed for blocking on its own verdict. An asset (endpoint, account, message) is proposed when an
   indicator of the incident is rated high enough or a person chose it;
4. approve: a person with the assigned XDR role answers a Request Approval task (an elevated task for
   protected assets and large packages);
5. contain: only inside the ``Decision = Approve`` and ``Dry Run = false`` branches, trigger exactly the
   response actions listed before the approval;
6. verify: list the response actions again and report which ones XDR no longer offers;
7. record: the outcome goes to the incident worklog through the template's ``workflow_results``.

``validate.check_approval_gate`` proves point 5 on the generated JSON.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import incident_scripts as scripts
from .builder import APPROVAL_RESPONSE, Activity, Workflow, cond, item, out
from .email_bombing import APPROVE, CHOICES, RESPONSE_CATEGORY, Settings

#: Observable types (Cisco XDR names) each action kind can target.
KIND_TYPES: dict[str, tuple[str, ...]] = {
    "isolate_endpoint": ("hostname",),
    "block_indicator": ("domain", "url", "ip", "ipv6"),
    "block_hash": ("sha256",),
    "revoke_sessions": ("user", "email"),
    "disable_user": ("user", "email"),
    "quarantine_email": ("email_messageid",),
}
#: Kinds whose target is an asset: proposed on the incident's indicators or a person's choice, since XDR
#: gives no verdict for an endpoint, an account or a message.
ASSET_KINDS = frozenset({"isolate_endpoint", "revoke_sessions", "disable_user", "quarantine_email"})

#: Default text looked for in the title of an XDR response action, per kind (case-insensitive regular
#: expression; the action ID is matched when an action has no title). Titles differ per product and are not
#: documented, so each pattern is an input of the workflow. The defaults are strict on purpose: the title
#: must start with the verb, and for an account also name its object. A title that does not match is
#: listed on the decision card as "offered", so the pattern can be widened knowingly. Actions that undo a
#: containment (stop isolation, unblock, enable) are never matched, whatever the pattern says.
ACTION_PATTERNS: dict[str, tuple[str, str]] = {
    "isolate_endpoint": ("Isolate Action Pattern", "^(isolate|contain|network contain)"),
    "block_indicator": ("Block Action Pattern", "^(block|deny|add .*(block|deny))"),
    "block_hash": ("Block Hash Action Pattern", "^(block|deny|add .*(block|deny|custom detection))"),
    "revoke_sessions": ("Revoke Sessions Action Pattern",
                        "^(revoke|sign.?out|log.?out|invalidate) .*(session|token|sign.?in)"),
    "disable_user": ("Disable User Action Pattern", "^(disable|suspend|lock) .*(user|account|identity)"),
    "quarantine_email": ("Quarantine Email Action Pattern", "^(quarantine|move .*quarantine)"),
}

PLATFORM_READS = ("/iroh-enrich/deliberate/observables", "/iroh-enrich/observe/observables",
                  "/iroh-response/respond/observables")


@dataclass(frozen=True)
class Rule:
    """One containment the attack type may propose. The approver decides, never the rule."""

    kind: str
    #: Lowest risk that proposes the action: of the indicator itself, or of the incident for an asset.
    #: Verdicts map to risk as in the reference framework: malicious 90, suspicious 60, clean 5.
    min_risk: int
    #: Shown on the decision card: when the reference design recommends this action.
    label: str
    types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in KIND_TYPES:
            raise ValueError(f"unknown action kind {self.kind!r}")
        if not self.types:
            object.__setattr__(self, "types", KIND_TYPES[self.kind])
        if not set(self.types) <= set(KIND_TYPES[self.kind]):
            raise ValueError(f"{self.kind} cannot target {sorted(set(self.types) - set(KIND_TYPES[self.kind]))}")
        if not 0 <= self.min_risk <= 100:
            raise ValueError("min_risk must be within 0-100")

    @property
    def basis(self) -> str:
        return "asset" if self.kind in ASSET_KINDS else "indicator"


@dataclass(frozen=True)
class Spec:
    """What differs between attack types."""

    #: Identifier of the design in ``workflows/<design>/`` and ``src/xdr_response/workflows``.
    design: str
    name: str
    purpose: str
    rules: tuple[Rule, ...]
    #: Containment the design recommends for which XDR has no response action: shown as manual steps.
    manual: tuple[str, ...] = ()
    #: What the approver should check, because this workflow cannot.
    checks: tuple[str, ...] = ()
    #: Kinds left out by default (the *Excluded Actions* input), because the design ties them to evidence
    #: this workflow cannot collect.
    excluded: tuple[str, ...] = ()
    #: Observable types assessed for context only (rated and shown, never acted on).
    context_types: tuple[str, ...] = ()

    @property
    def slug(self) -> str:
        return self.name.replace(" ", "-")

    @property
    def types(self) -> list[str]:
        found: list[str] = []
        for kind in [t for rule in self.rules for t in rule.types] + list(self.context_types):
            if kind not in found:
                found.append(kind)
        return found

    @property
    def kinds(self) -> list[str]:
        return [kind for kind in scripts.KINDS if any(rule.kind == kind for rule in self.rules)]

    def script_spec(self) -> str:
        """The rules as the argument of the assessment script."""
        text = json.dumps({
            "name": self.name, "types": self.types,
            "rules": [{"kind": r.kind, "types": list(r.types), "basis": r.basis, "min_risk": r.min_risk,
                       "label": r.label} for r in self.rules],
            "manual": list(self.manual), "checks": list(self.checks),
        })
        if "$" in text:
            raise ValueError(f"{self.name}: a dollar sign in the spec would be read as a variable reference")
        return text


def build(spec: Spec, settings: Settings | None = None) -> Workflow:
    settings = settings or Settings()
    wf = Workflow(
        spec.slug, spec.name,
        f"{spec.purpose} It rates every observable with the Cisco XDR modules, lists the response actions "
        "they offer and asks an administrator or incident responder to approve the proposed actions. "
        "Nothing is changed without that approval, and nothing is changed while Dry Run is true.",
    )
    wf.properties = {
        "automation_rules": {"type": ["incident.rule_event"]},
        "wf_metadata": {"coa": {"action": ["response"], "intent": "incident_response",
                                "observable_types": spec.types}},
    }
    wf.categories = [RESPONSE_CATEGORY]
    wf.template_type = "template_workflow.incident_response"
    platform = wf.module_target()

    # -- variables ---------------------------------------------------------------------------------
    dry_run = wf.var("Dry Run", "boolean", "input", True,
                     description="True: investigate, ask for approval and report what would be done, but change "
                                 "nothing. Set to false only after a dry run looked right.")
    audit_only = wf.var("Audit Only", "boolean", "input", False,
                        description="True: investigate and write the assessment to the incident worklog, but raise "
                                    "no approval task and change nothing. For tuning the rule that starts the workflow.")
    manual_in = wf.var("Observables", "string", "input",
                       description="Optional. Observables to assess when the workflow is started by hand, one per "
                                   "line or separated by commas.")
    max_observables = wf.var("Maximum Observables", "integer", "input", 20,
                             description="Observables assessed per run (1 to 50). The rest is reported, not assessed.")
    sightings = wf.var("Collect Sightings", "boolean", "input", True,
                       description="False skips the sightings query, for incidents whose sightings are too large.")
    internal = wf.var("Internal Domain Suffixes", "string", "input", settings.internal_domain_suffixes,
                      description="Comma-separated DNS suffixes of your own hosts and mail domains "
                                  "(corp.example.com, example.com). A dotted name under one of them is an endpoint; "
                                  "any other dotted name is a domain. When set, account actions are proposed only "
                                  "for addresses under them.")
    protected = wf.var("Protected Assets", "string", "input", settings.protected_assets,
                       description="Comma-separated names or patterns (DC-*, ceo@example.com, @finance.example) that "
                                   "always need elevated approval.")
    never_act = wf.var("Never Act On", "string", "input", settings.never_act_on,
                       description="Comma-separated values, patterns or networks that are never proposed (your own "
                                   "domains, resolvers, break-glass accounts, 203.0.113.0/24). A domain also covers its "
                                   "subdomains.")
    excluded = wf.var("Excluded Actions", "string", "input", ", ".join(spec.excluded),
                      description="Comma-separated action kinds this run must not propose: "
                                  + ", ".join(spec.kinds) + ".")
    trust = wf.var("Trust Analyst Selection", "boolean", "input", True,
                   description="True: an endpoint, account or message a person chose is proposed even when no "
                               "indicator of the incident is rated high enough. The approval is still required.")
    block_unrated = wf.var("Block Unrated Indicators", "boolean", "input", False,
                           description="True: a domain, URL, address or hash that no module rates is proposed for "
                                       "blocking when a person started the workflow with it. An indicator rated clean "
                                       "is never proposed.")
    elevated_above = wf.var("Elevated Approval Above", "integer", "input", 5,
                            description="More proposed actions than this need elevated approval.")
    # One pattern input per kind the attack type uses, in the order of scripts.KINDS.
    patterns = [wf.var(ACTION_PATTERNS[kind][0], "string", "input", ACTION_PATTERNS[kind][1],
                       description=f"Text of the XDR response action used for {kind} (regular expression on its "
                                   "title, case-insensitive). The decision card lists the titles on offer when "
                                   "nothing matches.")
                for kind in spec.kinds]
    # Script steps in real exports receive variable references, not literal JSON, so the rules are a variable.
    rules = wf.var("Workflow Rules", "string", "local", spec.script_spec(),
                   description="Rules of this attack type, read by the script steps. Generated: do not edit here.")
    candidates = wf.var("Candidate Observables", "string", "local")
    decision = wf.var("Decision", "string", "local", description="Answer of the approval task.")
    tally = wf.var("Action Tally", "string", "local", "{}")
    results = wf.template_output("workflow_results")
    started_by = wf.template_output("started_by_type")

    def report(title: str, text: str) -> Activity:
        """Append one line to the note the template writes to the incident worklog."""
        return wf.set_vars(title, [(results, f"{results}\n- {text}")])

    def platform_read(title: str, relative_url: str, body: str) -> Activity:
        return wf.http(title, method="POST", target_id=platform, relative_url=relative_url, body=body)

    # -- 1. collect the observables the template hands over -----------------------------------------
    selected = wf.for_each(
        "For each selected observable", "$intent.intent incident_response.input.selected_observables$",
        description="Collects the observables the analyst selected in the playbook task.")
    selected["actions"] = [wf.set_vars("Collect selected observable",
                                       [(candidates, f"{candidates}\n{item(selected, 'value')}")])]
    incident = wf.for_each(
        "For each incident observable", "$rule.incident rule_event.output.targets.data$",
        description="Collects the observables of the incident.")
    incident["actions"] = [wf.set_vars("Collect incident observable",
                                       [(candidates, f"{candidates}\n{item(incident, 'value')}")])]
    started = wf.if_else("How was the workflow started?", [
        wf.branch("Playbook task", cond(started_by, "eq", "playbook_task"), [selected]),
        wf.branch("Incident automation rule", cond(started_by, "eq", "incident_rule"), [incident]),
    ])
    classify = wf.python(
        "Classify observables", scripts.CLASSIFY,
        [candidates, rules, internal, max_observables, sightings],
        [("observables_json", "string"), ("observe_body", "string"), ("has_observables", "string"),
         ("observable_count", "string"), ("ignored_count", "string"), ("over_limit_count", "string"),
         ("intake", "string")])
    observables = out(classify, "script_queries.observables_json")

    # -- 2. investigate (reads only) ------------------------------------------------------------------
    verdicts = platform_read("Get verdicts", PLATFORM_READS[0], observables)
    seen = platform_read("Get sightings", PLATFORM_READS[1], out(classify, "script_queries.observe_body"))
    offered = platform_read("List response actions", PLATFORM_READS[2], observables)

    # -- 3. recommend ------------------------------------------------------------------------------
    assess = wf.python(
        "Assess and write decision card", scripts.ASSESS,
        [observables, started_by,
         out(verdicts, "status_code"), out(verdicts, "response_body"),
         out(seen, "status_code"), out(seen, "response_body"),
         out(offered, "status_code"), out(offered, "response_body"),
         rules, dry_run, protected, never_act, excluded, elevated_above, trust, block_unrated,
         internal, sightings, *patterns],
        [("has_proposal", "string"), ("elevated", "string"), ("card", "string"), ("summary", "string"),
         ("actions_json", "string"), ("action_count", "string"), ("verify_body", "string"),
         ("package_digest", "string"), ("risk", "string")])
    card = out(assess, "script_queries.card")
    summary = out(assess, "script_queries.summary")
    digest = out(assess, "script_queries.package_digest")
    count = out(assess, "script_queries.action_count")

    # -- 4. approve --------------------------------------------------------------------------------
    def approval(level: str, roles: list[str], minimum: int, title: str) -> list[Activity]:
        request = wf.request_approval(f"Request {level} approval", approval_title=title, body=card, roles=roles,
                                      choices=CHOICES, minimum_approvals=minimum)
        return [request, wf.set_vars(f"Record {level} decision", [(decision, out(request, APPROVAL_RESPONSE))])]

    approve = wf.if_else("Which approval level?", [
        wf.branch("Elevated", cond(out(assess, "script_queries.elevated"), "eq", "true"),
                  approval("elevated", settings.elevated_roles, settings.elevated_approvals,
                           f"ELEVATED APPROVAL REQUIRED - {spec.name}: {count} containment actions")),
        wf.branch("Standard", cond(out(assess, "script_queries.elevated"), "ne", "true"),
                  approval("standard", settings.approver_roles, 1, f"{spec.name}: {count} containment actions")),
    ])

    # -- 5. contain and verify: only after Approve, only when Dry Run is false -----------------------
    actions = wf.read_table("Approved actions table", out(assess, "script_queries.actions_json"),
                            ["url", "title", "target", "kind", "module", "key"])
    each = wf.for_each("For each approved action", out(actions, "read_table_from_json"),
                       description="Triggers one response action that was listed on the decision card.")
    trigger = wf.http("Trigger response action", method="POST", target_id=platform,
                      relative_url=item(each, "url"))
    record = wf.python("Record action result", scripts.RECORD_TRIGGER,
                       [tally, out(trigger, "status_code"), out(trigger, "response_body"), item(each, "title"),
                        item(each, "target"), item(each, "key")], [("tally_json", "string")])
    each["actions"] = [trigger, record,
                       wf.set_vars("Store action tally", [(tally, out(record, "script_queries.tally_json"))])]
    recheck = platform_read("List response actions again", PLATFORM_READS[2],
                            out(assess, "script_queries.verify_body"))
    outcome = wf.python("Build containment result", scripts.RESULT,
                        [rules, digest, tally, out(recheck, "status_code"), out(recheck, "response_body")],
                        [("result", "string")])

    act = wf.if_else("What did the approver decide?", [
        wf.branch("Approved", cond(decision, "eq", APPROVE), [
            wf.if_else("Dry run?", [
                wf.branch("Dry run: report only", cond(dry_run, "eq", True), [
                    report("Report dry run",
                           f"{spec.name}: APPROVED in DRY RUN. Would run {count} response actions "
                           f"(package {digest}). Nothing was changed."),
                ]),
                wf.branch("Live: execute the approved package", cond(dry_run, "eq", False), [
                    actions, each, recheck, outcome,
                    report("Report containment", out(outcome, "script_queries.result")),
                ]),
            ]),
        ]),
        wf.branch("Not approved", cond(decision, "ne", APPROVE), [
            report("Report decision without action",
                   f"{spec.name}: decision \"{decision}\". Nothing was changed (package {digest})."),
        ]),
    ])

    # -- 6. report back to the playbook task ---------------------------------------------------------
    answered = wf.for_each("For each selected observable: report",
                           "$intent.intent incident_response.input.selected_observables$")
    answered["actions"] = [wf.set_vars("Set observable result", [
        (item(answered, "succeeded"), True),
        (item(answered, "result_message"),
         f"{spec.name} workflow finished. The outcome is in the incident worklog."),
    ])]

    wf.actions = [wf.group("Incident response with observables", [
        wf.set_vars("Start with the Observables input", [(candidates, manual_in), (decision, ""), (tally, "{}")]),
        started, classify,
        wf.if_else("Any observable to assess?", [
            wf.branch("No observable", cond(out(classify, "script_queries.has_observables"), "ne", "true"), [
                report("Report nothing to assess",
                       f"{spec.name}: no observable of a type this workflow handles ({', '.join(spec.types)}). "
                       "Nothing was changed."),
            ]),
            wf.branch("Observables found", cond(out(classify, "script_queries.has_observables"), "eq", "true"), [
                report("Report intake",
                       f"{spec.name}: assessing {out(classify, 'script_queries.intake')} "
                       f"({out(classify, 'script_queries.ignored_count')} values of other types ignored, "
                       f"{out(classify, 'script_queries.over_limit_count')} over the limit)."),
                verdicts, seen, offered, assess,
                wf.if_else("Anything to propose?", [
                    wf.branch("No proposal", cond(out(assess, "script_queries.has_proposal"), "ne", "true"),
                              [report("Report assessment without proposal", summary)]),
                    wf.branch("Proposal", cond(out(assess, "script_queries.has_proposal"), "eq", "true"), [
                        report("Report proposal", summary),
                        wf.if_else("Audit only?", [
                            wf.branch("Audit only: no approval task", cond(audit_only, "eq", True), [
                                report("Report audit only",
                                       f"{spec.name}: AUDIT ONLY. No approval task was raised and nothing was "
                                       f"changed (package {digest})."),
                            ]),
                            wf.branch("Ask for approval", cond(audit_only, "eq", False), [approve, act]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
        wf.if_else("Started from a playbook task?", [
            wf.branch("Playbook task: report", cond(started_by, "eq", "playbook_task"), [answered]),
        ]),
    ], description="Rates the observables of the incident, asks for approval and acts on the answer.")]
    return wf
