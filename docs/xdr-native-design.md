# XDR-native design

Status: all 22 attack types built. Requirement from the owner: the solution must run strictly inside Cisco
XDR, with no additional tools, hosts or services. The workflows are generated in [`xdr/`](../xdr/README.md) and
checked offline; none has been imported into an XDR org yet. Sections 1 to 7 are the design as first written;
[section 8](#8-as-built) says what was built and where it differs.

The framework in `src/xdr_response/` does not meet that requirement. It is an external orchestrator: it needs a
host, a secret store, an approver identity provider, an intake service and a decision screen. This page
describes how the same lifecycle is delivered with Cisco XDR Automation only, what carries over, and what gets
weaker. Sources for every XDR capability named here are in [integrations.md](integrations.md) section 1, plus
the Cisco documentation for the
[Execute Python Script activity](https://docs.xdr.security.cisco.com/Content/Automate/activities-python-execute-python-script.html).

## 1. What "strictly in XDR" means

Everything that runs in production is an XDR Automation object:

| Need | XDR-native building block |
|---|---|
| Start on detection | Automation rule on **new incident** (incident rule) |
| Investigation and enrichment | Cisco-managed XDR atomics over the integrations already connected to the org |
| Correlation, scoring, recommendation rules | **Execute Python Script** activities inside the workflow |
| Analyst decision | **Request Approval** task (assignees by role or email, minimum approvals, expiry, custom choices) |
| Containment after approval | Cisco-managed response workflows and atomics; **HTTP Request** activities against XDR targets where no native action exists |
| Verification | Read-back atomics or HTTP GET in the same workflow |
| Restoration | A separate release workflow with its own Request Approval task |
| Record | Incident worklog and notes, plus the workflow run history |
| Credentials | XDR targets, account keys and secure strings |
| Dry run | A workflow input (default true) that gates every state-changing block |

Nothing else is deployed. A Git repository is optional and only used to version and import the workflows.

## 2. Workflow shape

XDR limits how long a workflow can run, and an analyst may take hours to decide. So each attack type is three
workflows connected by XDR rules, not one long workflow:

1. **Investigate and propose** (trigger: incident rule). Reads the incident, enriches observables, investigates
   users and hosts, runs the scoring and rule script, writes the decision card to the incident, creates the
   Request Approval task, and ends.
2. **Contain** (trigger: approval task rule, on approval). Re-reads the incident and the proposed package,
   executes only the approved actions, verifies each one, writes the containment result and the list of
   controls it created to the incident.
3. **Release** (trigger: response playbook or pivot menu). Lists the controls recorded by workflow 2, creates a
   release approval task, and on approval removes exactly those controls and verifies.

Shared steps are atomic actions, so the 22 attack types reuse one library:

- enrichment: `enrich observable` (IP, domain, URL, hash, email address), `enrich user`, `enrich endpoint`
- investigation: user, endpoint, email, authentication, process, network connection, enterprise search
- decision: `build decision card`, `request containment approval`, `request elevated approval`
- containment (each takes the approved package and a dry-run flag): isolate endpoint, block domain, block URL,
  block IP, block hash, revoke sessions, disable user, quarantine email, delete email, device action,
  remove privileged role
- verification and restoration counterparts of each containment atomic
- `write incident note`, `notify SOC`

## 3. Action mapping

From [integrations.md](integrations.md) sections 1.4 and 2.

| Action | Inside XDR by | Restore |
|---|---|---|
| Isolate endpoint | Native: XDR - Contain Incident: Assets (Secure Endpoint, Defender for Endpoint) | Native: XDR - Restore Systems |
| Disable user | Native: XDR - Contain Incident: Users (Entra ID) | Native: XDR - Restore Users |
| Block domain | Native: XDR - Contain Incident: Domains (Umbrella) | Native: XDR - Restore Domains |
| Block URL | Native: XDR - Contain Incident: URLs (Umbrella) | Native |
| Block IP | Native: XDR - Contain Incident: IP Addresses (Umbrella, IPv4) | Native |
| Block file hash | Native: XDR - Contain Incident: File Hashes (Secure Endpoint, Defender for Endpoint) | Native: XDR - Restore File Hashes |
| Quarantine email | Native: XDR - Contain Incident: Quarantine Email Messages (Email Threat Defense, Defender for Office 365) | Native for Defender for Office 365; HTTP Request for Email Threat Defense |
| Delete email | Native: XDR - Delete Email Messages (Defender for Office 365 only) | Not reversible |
| Revoke Entra sessions | HTTP Request to the Microsoft Graph target, or a Cisco Microsoft Graph atomic if the catalog has one | Not reversible |
| Remove privileged role | HTTP Request to the Microsoft Graph target | HTTP Request (re-create the assignment) |
| Intune device action (remote lock) | HTTP Request to the Microsoft Graph target | Manual |
| Meraki client or firewall block | HTTP Request to the Meraki target | HTTP Request |
| Terminate process, quarantine file, remove persistence | No confirmed write endpoint. Recommended as a manual step on the decision card | Manual |

Threat intelligence (VirusTotal, AlienVault OTX, Umbrella, Secure Malware Analytics, Have I Been Pwned) comes
through XDR's own enrichment of the connected integrations. Splunk stays optional and disconnected.

## 4. Approval inside XDR

- Every state-changing activity lives only in the Contain and Release workflows, and those can only start from
  an approved task. The Investigate workflow contains no state-changing activity at all.
- The approval task lists the proposed actions as choices: approve all, approve selected, reject, request more
  investigation. The Contain workflow executes only what the task returned as approved.
- Assignees are XDR roles (administrators, incident responders), as the org's export shows. Anyone holding
  the role can answer, including the person who started the workflow.
- Critical assets (from a table kept as an XDR global variable) switch the task to the elevated assignee group
  and a higher minimum number of approvals, and the decision card shows the warning.
- The dry-run input defaults to true. In dry run the Contain workflow writes "Would isolate ..." to the incident
  and executes nothing.

## 5. What gets weaker than the external framework

Stated plainly, because these were hard guarantees before:

| Guarantee in `src/xdr_response/` | Inside XDR only |
|---|---|
| Signed approval token bound to the incident, exact actions, parameters and evidence hash | Enforced by workflow structure and the approval task result. No cryptographic binding |
| Code-level guard that refuses any write without a valid token | No equivalent. Safety rests on which workflows contain write activities and what can trigger them |
| Approver must be a verified human; AI and service identities refused in code | Whoever is an assignee of the XDR task can approve. Controlled by XDR user and role administration |
| Hash-chained, tamper-evident audit trail | Incident worklog and workflow run history (retention is limited; 90 days by default for run logs) |
| About 11,800 automated tests, including bypass attempts | XDR workflows cannot be executed offline. Testing happens in XDR, in dry run first |
| Idempotency keys and a control registry in a database | Controls created are recorded on the incident; each containment atomic checks current state first |

## 6. What carries over from this repository

- The 22 workflow designs: triggers, investigation steps, correlation logic, containment rules, MITRE mapping,
  READMEs and 426 scenarios become the specification and test cases for the XDR workflows.
- Scoring, rule and decision-card logic is ported into Python script activities. Its unit tests still run from
  the repository during development; they are not needed in production.
- Critical-asset classes, allow-lists and thresholds become XDR global variables or tables.
- [integrations.md](integrations.md): which vendor operations are confirmed, used for every HTTP Request step.

The `src/xdr_response/` package would no longer be deployed. It can stay as the reference model and offline
test bed, or be removed.

## 7. Open items

1. **Export format.** Cisco does not publish a schema for workflow JSON, and
   `CiscoSecurity/sxo-05-security-workflows` no longer exists on GitHub (404; only SecureX-era forks remain,
   the newest pushed in March 2024). Current XDR exports are public in
   `ciscomanagedservices/ciscolive25-xdr-automate` (Cisco Sample Code License 1.1, pushed November 2025) and are
   the format reference. They show:
   - the document envelope (`workflow`, `categories`, `targets`, `target_groups`, `module_targets`, `variables`,
     `subworkflows`, `atomic_workflows`, `dependent_workflows`, `rules`);
   - an older approval pair, `task.approval_request` followed by `task.wait_for_event`, whose
     `output.response` holds the chosen answer. The target org exports the current activity instead:
     `task.request_approval` with `assignee_roles`, `approval_choices_holder` and
     `wait_for_request_approval_response`. `Email Bombing` uses the current one;
   - `python3.script` (`script`, `script_arguments`, `script_queries`);
   - `workflow.atomic_workflow` and `workflow.sub_workflow` calls, referenced by workflow ID and input variable
     ID, with the XDR module target `$module_target;Cisco XDR;securex:ao:iroh_api;platform-apis$`;
   - `incident.rule_event` rules with `workflows_config`.

   The incident response template exported from the target org adds the `template_type`, `wf_metadata`,
   `started_by_type`, `workflow_results` and the observable loops for playbook tasks and incident rules.
   `ciscotee/CiscoSecureEndpoint-FindDuplicateGUID` (MIT) adds the atomic action export (`is_atomic`,
   `atomic_group`, target chosen at start) and how a workflow picks an integration's target by name.

   Update: the workflow IDs of the Cisco-managed atomics and response workflows (`XDR - Contain Incident: ...`,
   `XDR - Restore ...`) are public in the Cisco XDR Connect catalog and recorded in
   [xdr-catalog/](xdr-catalog/README.md). Their input and output variable IDs are not published, and a call
   needs them. Section 8 says how the workflows avoid that dependency.
2. **Approval wait and answer.** The org's Request Approval activity waits for the decision inside the
   same workflow. `Email Bombing` is built that way: one workflow instead of the three in section 2. Two
   points need a check in the org ([`xdr/README.md`](../xdr/README.md)): the name of the output that holds
   the answer (assumed `response`), and that the wait is not cut by the documented 30-minute run-time limit.
3. **ETD has no automatic target.** XDR creates Automation targets for Entra ID, Defender for Endpoint,
   Defender for Office 365, Intune, Meraki, Umbrella, Secure Endpoint, Secure Malware Analytics and Secure
   Cloud Analytics, but not for Secure Email Threat Defense. A hand-made ETD target needs an account key,
   which XDR asks for on import, so `Email Bombing` reads ETD through the XDR platform APIs instead
   (section 8).
   **Approval choices.** A custom choice list (*Approve*, *Reject*, *More investigation*) imported with an
   empty "Approval choices array", and Cisco does not document its format. All 22 workflows use the default
   *Approve* / *Reject* pair; *Reject* changes nothing.
4. **Python module set.** The script activity has a fixed module list (`help("modules")` shows it). The ported
   logic must use only those modules.
5. **Limits to confirm in the org:** maximum workflow run time and activity count, 100 variables per workflow,
   500 active approval tasks, webhook rate limits.
6. **Unverified vendor writes** in [integrations.md](integrations.md) stay manual steps until confirmed.

## 8. As built

**One workflow per attack type, not three.** The org's Request Approval activity waits for the answer inside
the workflow (open item 2), so investigation, approval, containment and verification are one workflow. Release
is not generated: undoing an action uses the restore tasks of the Cisco incident playbook.

**Two workflow bodies.**

- `Email Bombing` measures the flood from the Secure Email Threat Defense sightings of the mailbox
  (`observe/observables`), lists the ETD response actions on offer for the messages to move
  (`respond/observables`) and, after approval, triggers them (`respond/trigger`). It uses the ETD integration
  connected in XDR. An earlier version called the ETD API through hand-made targets; XDR then asked for the
  ETD client ID and secret on import, which the owner did not want.
- The other 21 attack types share the *incident response workflow* (`src/xdr_native/incident.py`), which calls
  only the Cisco XDR platform APIs of [integrations.md](integrations.md) section 2.1: verdicts
  (`deliberate/observables`), sightings (`observe/observables`), the response actions on offer
  (`respond/observables`) and, after approval, `respond/trigger`. The target is the module target
  `Cisco XDR; securex:ao:iroh_api; platform-apis`, which every org has. No vendor host, account key, secret or
  org-specific identifier is exported or configured.

**Why the platform APIs and not Cisco's atomics or native workflows.**

| Option | Finding | Decision |
|---|---|---|
| Call the Cisco-managed atomics | Their workflow IDs are public ([xdr-catalog/README.md](xdr-catalog/README.md)), but a call is wired by input and output variable IDs, which Cisco does not publish. An exported copy of an atomic carries new IDs | Not used. The exported copies document the request shapes instead |
| Call `XDR - Contain Incident: ...` | The catalog says each one ends unless a playbook task started it | Not used |
| Vendor APIs through HTTP targets | Needs a target and credentials per product and per org; XDR asks for them on import | Not used |
| XDR enrich and response APIs | VERIFIED endpoints, one built-in target, and the response actions are whatever the org's modules offer | Used for all 22 workflows |

**What this changes against sections 2 to 4.**

- *Shared steps are atomic actions* (section 2): the shared steps are one generated workflow body and four
  script steps, not atomics. All 21 files are regenerated together.
- *Action mapping* (section 3): the workflow does not name a product. It lists the response actions the modules
  offer for each observable and matches them by title (isolate, block, revoke, disable, quarantine). The decision
  card shows the exact action and module. Titles are not documented, so each match text is a workflow input.
  Session revocation, role removal and device actions run only if a module offers them; otherwise they are
  listed as manual steps.
- *Approve selected* (section 4): the task approves or rejects the whole package. Fewer actions means a new
  run with fewer observables or with kinds on the *Excluded Actions* input.
- *Critical assets* (section 4): the *Protected Assets* input of each workflow, not a global table.

**What gets weaker than the designs in `workflows/`.** The designs decide on evidence from sign-in logs, MFA
prompts, mailbox rules, process trees and file prevalence. Inside XDR, without vendor API calls, the workflow
has verdicts, sightings and the choice of the person who started it. So:

- an indicator is proposed for blocking on its own verdict;
- an endpoint, an account or a message is proposed when an indicator of the incident is rated high enough or
  when a person chose it, and the card says which;
- the condition of the design is printed with every proposed action, with a list of what to check;
- disabling an account is off by default wherever the design asks for more than a compromise indicator;
- verification is an inference: the trigger reports success or failure, and the workflow reports whether XDR
  still offers the action afterwards. It never reports an action as verified.

**What the offline check proves.** Section 5 says the approval is enforced by workflow structure. For these
files `src/xdr_native/validate.py` proves that structure from the JSON alone, link by link (decision variable,
approval task and its card, order of approval and gated branch, origin of what the request sends, scripts and
requests pinned to known ones). It does not prove behaviour inside XDR. Response data from modules is treated
as untrusted by the script steps.

The 426 scenarios of the reference framework do not apply to these workflows. Their tests are in
`tests/xdr_native/`: the export shape, the approval gate of all 22 files, and the script steps run as XDR runs
them.
