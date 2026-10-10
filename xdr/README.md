# Workflows that run inside Cisco XDR

This folder holds workflows for **Cisco XDR Automation only**. Nothing else is deployed: no host, no
service, no external tool. Design and trade-offs: [docs/xdr-native-design.md](../docs/xdr-native-design.md).

The folder is laid out for XDR's Git import (Code Path `xdr`):
`<Name>__definition_workflow_<id>/definition_workflow_<id>.json`.

**Status: 22 workflows generated and checked offline. None has been imported into an XDR org yet.** Cisco
publishes no schema for workflow JSON, so every shape is copied from a real export (table at the end).
Import one workflow and run the test steps below before importing the rest.

There are two kinds of workflow here:

- **`Email Bombing`** reads Secure Email Threat Defense (ETD) directly, because measuring a mail flood needs
  the ETD message search. It needs an ETD target and account key.
- **The other 21** share one workflow body, the *incident response workflow*. They call only the Cisco XDR
  platform APIs, which every org has. They need no target, no account key and no secret.

## Before you start testing

1. **Fill in [config/xdr-native.yaml](../config/xdr-native.yaml).** Your own domain suffixes, your protected
   assets and the values never to act on. They are empty in this repository, so until you fill them in no
   asset is protected and nothing is excluded. Do not put a secret in that file.
2. **Regenerate:** `python tools/xdr_native/build.py`. The values become the input defaults of all 22
   workflows, so you set them once.
3. **Import one workflow** and follow *Test the incident response workflow* below.
4. **Create the rules and playbook tasks** from [RULES.md](RULES.md), with *Audit Only* on while you tune them.

What to write down while you test, because it corrects the generator for every workflow at once:

- the exact text of any import or validation error;
- whether a run that waits for an approval longer than 30 minutes is still alive when you answer;
- the titles of the response actions XDR offers (the worklog lists them when nothing matches);
- what the **Property** and **Comparison** lists of an incident rule condition offer.

## The workflows

Every workflow starts from an incident automation rule, an incident playbook task, or by hand.

| Workflow | Design | Containment it can propose |
|---|---|---|
| `Email Bombing` | [mail-bombing](../workflows/mail-bombing/README.md) | move the flood out of the inbox in ETD |
| `Account Takeover` | [account-takeover](../workflows/account-takeover/README.md) | isolate endpoint; block address; revoke sessions; disable user (off by default) |
| `Business Email Compromise` | [bec](../workflows/bec/README.md) | isolate endpoint; block domain; revoke sessions; disable user (off by default); quarantine message |
| `Command and Control` | [c2](../workflows/c2/README.md) | isolate endpoint; block domain, URL, address |
| `Cloud Compromise` | [cloud-compromise](../workflows/cloud-compromise/README.md) | block address; revoke sessions; disable user (off by default) |
| `Credential Dumping` | [credential-dumping](../workflows/credential-dumping/README.md) | isolate endpoint; block file hash; revoke sessions; disable user (off by default) |
| `DNS Tunneling` | [dns-tunneling](../workflows/dns-tunneling/README.md) | isolate endpoint; block domain |
| `Data Exfiltration` | [exfiltration](../workflows/exfiltration/README.md) | isolate endpoint; block domain, address; revoke sessions; disable user (off by default) |
| `Lateral Movement` | [lateral-movement](../workflows/lateral-movement/README.md) | isolate endpoint; block address; block file hash; revoke sessions; disable user (off by default) |
| `Suspicious PowerShell` | [malicious-powershell](../workflows/malicious-powershell/README.md) | isolate endpoint; block domain, URL, address; block file hash |
| `Malware` | [malware](../workflows/malware/README.md) | isolate endpoint; block domain, URL, address; block file hash |
| `MFA Fatigue` | [mfa-fatigue](../workflows/mfa-fatigue/README.md) | isolate endpoint; block address; revoke sessions; disable user (off by default) |
| `Password Spray` | [password-spray](../workflows/password-spray/README.md) | block address; revoke sessions; disable user (off by default) |
| `Persistence` | [persistence](../workflows/persistence/README.md) | isolate endpoint; block file hash |
| `Phishing` | [phishing](../workflows/phishing/README.md) | isolate endpoint; block domain, URL; block file hash; revoke sessions; disable user (off by default); quarantine message |
| `Privilege Escalation` | [privilege-escalation](../workflows/privilege-escalation/README.md) | isolate endpoint; revoke sessions; disable user (off by default) |
| `Ransomware` | [ransomware](../workflows/ransomware/README.md) | isolate endpoint; block domain, URL, address; block file hash; revoke sessions; disable user (off by default); quarantine message |
| `Suspicious Authentication` | [suspicious-authentication](../workflows/suspicious-authentication/README.md) | block address; revoke sessions; disable user (off by default) |
| `Threat Intelligence Sweep` | [threat-intel-sweep](../workflows/threat-intel-sweep/README.md) | isolate endpoint; block domain, URL, address; block file hash; revoke sessions; quarantine message |
| `Unauthorized Remote Access Tool` | [unauthorized-rmm](../workflows/unauthorized-rmm/README.md) | isolate endpoint; block domain, address; block file hash |
| `Vulnerability Exploitation` | [vulnerability-exploitation](../workflows/vulnerability-exploitation/README.md) | isolate endpoint; block address |
| `Web Application Attacks` | [web-attacks](../workflows/web-attacks/README.md) | isolate endpoint; block address |

What each attack type proposes, and when, is in [`src/xdr_native/specs.py`](../src/xdr_native/specs.py).

## What every workflow guarantees

- Investigation and the recommendation are automatic and only read.
- A state-changing step runs only inside the branch *Decision = Approve* **and** *Dry Run = false*. The
  decision can only come from the answer of an XDR approval task assigned to XDR roles.
- What is executed is what was listed before the approval (the task shows the count and a package
  digest). Nothing is searched or computed again after the approval.
- A protected asset or a large package is not skipped: it goes to the elevated approvers, needs two
  approvals, and the task says **ELEVATED APPROVAL REQUIRED**.
- *Reject*, *More investigation*, an expired task or any other answer changes nothing.
- *Dry Run* is true by default: an approval then only reports what would be done.
- The exports contain no credentials.

`src/xdr_native/validate.py` proves these points from the generated JSON alone, and
`tools/xdr_native/build.py --check` refuses a file that fails. It requires that the decision starts empty
and only receives an approval answer, that every approval task shows the decision card, that the approval
is recorded before the gated branch, that each script is one of this repository's own, and that every
HTTP request is a known request on a known target. `tests/xdr_native/` holds 76 edits of a workflow file
that would bypass the approval (moving the step out of the branch, inverting the condition, starting the
decision at *Approve*, asking for approval after acting, replacing the card or a script, adding a second
write, sending the request to another host, and so on). Each one must be rejected. An independent review
on 2026-10-10 found 27 such edits that the first version accepted; all are now rejected and kept as tests.

## The incident response workflow (21 attack types)

1. **Collect.** The observables the analyst selected in the playbook task, the observables of the incident
   when a rule started it, or the *Observables* input when started by hand.
2. **Classify.** A script types each value (hostname, domain, URL, address, file hash, account, message ID)
   and keeps the types the attack type handles. XDR passes only the value, so the type is derived from it.
   An email address is asked for as both an email and a user, and a bare name as both an endpoint and an
   account, because the value alone does not say which it is.
3. **Investigate (three reads of the Cisco XDR platform).** Verdicts of every observable from all your
   modules, their sightings, and the response actions your modules offer for each observable.
4. **Recommend.** A script applies the rules of the attack type and writes the decision card:
   - A domain, URL, address or file hash is proposed for blocking **on its own verdict**: malicious, or
     also suspicious where the rule says so. Rated clean is never proposed. A private address is never
     proposed.
   - An endpoint, an account or a message has no verdict. It is proposed when an indicator of the incident
     is rated high enough, **or when a person chose it** (playbook task or manual start). The card says
     which of the two applied.
   - The action that would run is the XDR response action your module offers, matched by its title. The
     card shows that title, the module and the action ID. The default match is strict: the title must start
     with the verb (isolate, block, revoke, disable, quarantine). When nothing matches, the card lists the
     titles on offer so you can set the *Action Pattern* input. Actions that undo a containment are never
     matched.
   - Text that comes from a product (action titles, module names, errors) is shown as plain text and cut
     short, so it cannot add lines or formatting to the card.
   - What the design recommends but XDR cannot do is listed as a manual step, never dropped.
5. **Approve.** One approval task for the whole package.
6. **Contain.** Each approved action is triggered through the XDR response API.
7. **Verify and record.** The workflow lists the response actions again and reports, per action, what XDR
   answered and whether XDR still offers the action. The result goes to the incident worklog.

### What it cannot see

The designs in `workflows/` tie several actions to evidence that only the product consoles hold: sign-in
logs, MFA prompts, mailbox rules, process trees, file prevalence. This workflow does not read them. Each
decision card therefore carries a **Check before you approve** list for the attack type, and disabling an
account is off by default wherever the design asks for more than a compromise indicator.

### Inputs

| Input | Default | Meaning |
|---|---|---|
| *Dry Run* | true | Report only. Set to false after a dry run looked right |
| *Audit Only* | false | True: write the assessment to the worklog and raise no approval task. For tuning rules |
| *Observables* | empty | Values to assess when started by hand |
| *Maximum Observables* | 20 | Assessed per run (1 to 50); the rest is reported |
| *Collect Sightings* | true | False skips the sightings query for very large incidents |
| *Internal Domain Suffixes* | empty | Your DNS and mail suffixes. A dotted name under one is an endpoint, any other is a domain. When set, account actions are proposed only for addresses under them |
| *Protected Assets* | empty | Names or patterns (`DC-*`, `ceo@example.com`, `@finance.example`) that need elevated approval |
| *Never Act On* | empty | Values, patterns or networks (`203.0.113.0/24`) never proposed. A domain also covers its subdomains |
| *Excluded Actions* | per attack type | Kinds this run must not propose, for example `disable_user` |
| *Trust Analyst Selection* | true | Propose an asset a person chose even without a rated indicator |
| *Block Unrated Indicators* | false | Propose blocking an indicator no module rates, when a person chose it |
| *Elevated Approval Above* | 5 | More actions than this need elevated approval |
| *... Action Pattern* | per kind | Text looked for in the title of the XDR response action (regular expression, strict by default) |

*Internal Domain Suffixes*, *Protected Assets* and *Never Act On* take their defaults from
[config/xdr-native.yaml](../config/xdr-native.yaml) when the files are generated. A rule or a playbook task
can still pass other values.

## Import

1. Generate the files with your org settings from [config/xdr-native.yaml](../config/xdr-native.yaml):

   ```bash
   python tools/xdr_native/build.py
   ```

   The file holds the approver roles, the ETD host and your lists. ETD hosts: `api.us`, `api.de`, `api.au`,
   `api.in` or `api.ae` followed by `.etd.cisco.com`. Any other host is refused.
2. In XDR: **Automate > Workflows > Import Workflow**, paste the JSON, **Import**. The `Email Bombing` file
   keeps the ID of the existing workflow, so it replaces that workflow unless you tick *Import as a new
   workflow*. The other 21 have new IDs.
3. **Validate** in the editor.
4. Only for `Email Bombing`, configure once:

   | Object | Where | Value |
   |---|---|---|
   | Account key `Email Bombing - ETD API Client` | Automate > Account Keys | ETD API client ID and client secret (ETD: Administration > API Clients) |
   | Targets `Email Bombing - ETD Token` and `Email Bombing - ETD API` | Automate > Targets | Your regional ETD host, path `/v1` |
   | Variable `ETD API Key` | Workflow editor > Variables | ETD API key (secure string) |
   | Inputs `Protected Mailboxes`, `Trusted Sender Domains` | Workflow editor, or the rule or playbook that starts it | Your lists |

   ETD is not one of the integrations for which XDR creates an Automation target, so this target is
   created by hand. Moving messages needs ETD in Microsoft 365 *Read/Write* mode.

## Test the incident response workflow in this order

Start with one workflow, for example `Malware`. Every step runs with *Dry Run* = true until the last one.

1. **Import and validate.** If the import or the validation reports an error, send the message: it names
   the shape to fix in the generator, and the fix applies to all 21.
2. **Run by hand** with *Observables* set to a well-known benign domain. Expected worklog result:
   "No action proposed".
3. **Run by hand with a test endpoint name.** Expected: an approval task with the decision card. Read which
   response action it picked for the endpoint. If the worklog says "XDR offers no matching response action"
   and lists what is offered, put the right text in the matching *Action Pattern* input and note the
   titles, so the defaults in the generator can be corrected for all workflows.
4. **Answer *Reject*, run again and answer *Approve*.** Expected: "APPROVED in DRY RUN. Would run N
   response actions".
5. **Protected asset:** put the test endpoint in *Protected Assets*. Expected: the elevated task, two
   approvals needed.
6. **Playbook task and incident rule:** start it from an incident.
7. **Live:** *Dry Run* = false on the test endpoint. Check the endpoint in the product console and the
   result line in the worklog. Release it from the incident playbook.
8. **Import the other 20** and repeat step 3 for each kind of action they use (block, revoke sessions,
   quarantine message).

## Test `Email Bombing` in this order

Every step runs with *Dry Run* = true until the last one.

1. **Import and validate.**
2. **Run by hand** with *Mailbox* set to a mailbox that received little mail. Expected worklog result:
   "No action proposed: below the flood thresholds".
3. **Run by hand on a flooded test mailbox** (lower *Minimum Messages* and *Minimum Sender Domains* if
   needed). Expected: an approval task with the decision card. Answer *Reject*, then run again and answer
   *Approve*. Expected: "APPROVED in DRY RUN. Would move N messages".
4. **Leave one approval task unanswered for more than 30 minutes, then approve.** This shows whether the
   wait outlives the workflow run-time limit. If the run has ended, the design switches to two workflows
   joined by an approval task rule. The answer applies to all 22 workflows.
5. **Protected mailbox:** put the test mailbox in *Protected Mailboxes*. Expected: the elevated task, two
   approvals needed.
6. **Playbook task and incident rule:** start it from an incident with an email observable.
7. **Live:** *Dry Run* = false on the test mailbox. Check the messages in ETD and the verification line
   in the result.

## Not built yet

- **Release workflows.** Undoing an action is done with the restore tasks of the Cisco incident playbook
  (un-isolate, unblock, enable user) or in the product console. A release with its own approval task is
  not generated.
- **Reading the product consoles.** Sign-ins, MFA prompts, mailbox rules, process trees and file
  prevalence are not collected (see *What it cannot see*).
- **Approving a part of a package.** The task approves or rejects the whole package. To run fewer
  actions, start the workflow again with fewer observables or with kinds on *Excluded Actions*.

## Known unknowns

| Point | Why it matters | Covered by |
|---|---|---|
| Import of generated identifiers, of the module target and of the ETD targets and account key | Not documented by Cisco | Test step 1 |
| Whether `wait for approval` survives the 30-minute run-time limit, and the unit of its timeout | The reference export waits in the same workflow | Email Bombing test step 4 |
| `output.response` of the approval activity, also when two approvals are needed | The output name is not documented | Test steps 4 and 5 |
| Titles of the response actions each product offers | Actions are matched by title, and titles are not documented | Test step 3; the *Action Pattern* inputs |
| Fields of `respond/observables` entries (`query-params`, `module_instance_id`) and of verdict documents (`observable`) | Taken from the reference adapter and the CTIM model, not from a response of this org. With one observable the workflow needs neither | Test step 3 with two observables |
| Whether an account must be given as `email` or `user` | The workflow asks for both forms of an address | Test step 3 with an account |
| Fields of the observables in `selected_observables` and `targets.data` beyond `value` | The template only shows `value`; the workflows use only `value` | Test step 6 |
| Value of `started_by_type` for a manual start | Anything other than `incident_rule` counts as started by a person | Test step 3 |
| Size limit of a script argument | Sightings of a busy host can be large | *Collect Sightings* = false |
| Field names of the ETD status response | Email Bombing looks for the folder name; otherwise it reports UNABLE TO VERIFY | Email Bombing test step 7 |
| The ETD token is visible in the run history of the token request | Inherent to an HTTP token request in XDR; the token lives 60 minutes | Restrict who can view runs |

## Where each shape comes from

| Shape | Source |
|---|---|
| Workflow envelope, `wf_metadata`, `started_by_type`, `workflow_results`, the two observable loops, `task.request_approval` | The `Email Bombing` incident response template exported from the target XDR org |
| `python3.script`, HTTP request with custom headers, secure string variables, targets and account keys, `logic.while`, read table and for-each, compound conditions, and the HTTP request to the XDR platform through the module target `Cisco XDR; securex:ao:iroh_api; platform-apis` with the `module_targets` envelope | `ciscomanagedservices/ciscolive25-xdr-automate` (Cisco Sample Code License 1.1) |
| `corejava.jsonpathquery`, the import procedure, the shared response category ID | `ciscotee/CiscoSecureEndpoint-FindDuplicateGUID` (MIT) |
| Enrich and response API paths, the verdict numbers and the trigger result | [docs/integrations.md](../docs/integrations.md) section 2.1 (VERIFIED against Cisco's API documentation) and the reference adapter `src/xdr_response/integrations/cisco_xdr/` |
| ETD token, message search, move and status requests | [docs/integrations.md](../docs/integrations.md) section 2.3, and Cisco's own ETD atomics exported from the org ([docs/xdr-catalog/atomic-interfaces.md](../docs/xdr-catalog/atomic-interfaces.md)) |
| Script steps: outputs are strings only, and every argument is one variable reference | In 92 real exports no script step declares an integer output or receives literal JSON. Counts are strings, decisions are `true` or `false`, and the rules of an attack type are a workflow variable |
| Python modules used by the script steps (`json`, `re`, `sys`; `hashlib` when present, for the package digest) | The script steps of 80 Cisco atomics exported from the org and of the Cisco Live exports import `json`, `re`, `sys`, `datetime` and `urllib.parse` |

No file from those repositories or exports is copied here; only property names and structure are reused.

## Regenerate

```bash
python tools/xdr_native/build.py
```

```bash
python tools/xdr_native/build.py --check
```

`RULES.md` in this folder is generated too, from `src/xdr_native/rules.py`.

The generator is `src/xdr_native/`: `builder.py` (export shapes), `email_bombing.py` and `scripts.py` (the
Email Bombing workflow and its Python steps), `incident.py` and `incident_scripts.py` (the incident
response workflow and its Python steps), `specs.py` (the 21 attack types) and `validate.py` (structure and
approval-gate checks). The tests run the Python steps exactly as XDR runs them.
