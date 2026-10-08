# Cisco XDR trigger workflow

This is the small Cisco XDR Automation workflow that tells the response orchestrator (`xdr_response`) that a new incident exists (architecture sections 4.1, 12 and 14.6; `docs/deployment.md`, "Trigger"). Its one job is to pass the **incident ID**. Nothing else in the trigger is trusted.

> **No workflow JSON is committed here yet.** An XDR workflow export is only accepted from a real tenant, after a review. This repository never contains a hand-written or invented export, because an export that looks real but was never run in XDR would be a fabricated artifact. When an export exists, commit it next to this file as `xdr-trigger-workflow.json`, and first remove tenant ids, account keys, secure-string values and target URLs.

## What the trigger does

1. An XDR **automation rule** starts the workflow. Use either:
   - an **incident** trigger (new XDR incident), or
   - a **webhook** trigger, if another system announces incidents.
   The trigger types are documented on the XDR "Triggers" page (`docs/integrations.md`, Automation section). The trigger history only covers 72 hours, and it is not an audit trail.
2. The workflow sends **one value**, the XDR incident ID, to the orchestrator's intake. It uses an HTTP request activity with a target and an account key that you configure in XDR. The orchestrator never receives the trigger's other fields.
3. The orchestrator **re-reads the incident** through the VERIFIED incident APIs (`CiscoXdrAdapter.get_incident_summary` / `get_incident`). From that re-read it builds the `Incident`, then calls `ResponseOrchestrator.handle_detection(incident)`.
4. Everything after that happens in the orchestrator: workflow routing (14.3.5), read-only investigation and recommendation, the package, and the **human approval**.

Polling the incident API instead of a trigger is equally valid. The orchestrator side does not change.

## Payload

```json
{"incident_id": "<XDR incident id>"}
```

- There are no observables, verdicts, targets, severities, approval flags or free text. Even if a trigger payload carries other fields, the intake ignores them (architecture threat T14, untrusted trigger payload).
- The incident ID is checked as an opaque identifier (non-empty, bounded length, no whitespace or control characters) before the re-read.
- Webhook limits (1 MB payload, 25 runs per minute per rule) come from search summaries. Re-read the vendor page before you rely on them in production.

## What the trigger must never do

- **Never run containment.** Do not attach automation rules that run the Cisco-managed "XDR - Contain Incident" workflows (or any native response action) on their own. That would bypass the approval gate. The orchestrator triggers native actions with `respond/trigger` itself, inside `guard.authorized(...)`, and only after a human approval.
- **Never approve.** An XDR **Request Approval** task can notify the analyst and link to the orchestrator's decision page. It never authorizes anything: the HMAC approval token issued by `ApprovalEngine` to an authenticated human is the only authorization (`docs/approval-model.md`).
- **Never carry secrets in the export.** Account keys and secure strings stay in XDR. An export without secure-string values is the only form that may be committed.
- **Never decide.** The workflow has no conditions on verdicts or severity. Routing and recommendation happen in the orchestrator.

## Orchestrator intake (deployment code)

This repository does not ship an HTTP listener. A deployment exposes one that:

1. authenticates the caller (mutual TLS or a shared secret held in the deployment's `SecretProvider`);
2. accepts only `{"incident_id": "..."}` and validates the id;
3. re-reads the incident through `CiscoXdrAdapter` (READ operations only) and maps it to an `Incident`;
4. calls `runtime.orchestrator.handle_detection(incident)` on the runtime returned by `xdr_response.lifecycle.bootstrap(...)`.

Steps 3 and 4 are automatic and read-only. Any state change still waits for `submit_decision` with a human credential.

## Checklist before enabling the rule

- [ ] The rule's workflow only sends the incident ID (inspect the exported JSON).
- [ ] No automation rule runs a native containment workflow without going through the orchestrator.
- [ ] The export committed here comes from the tenant and has no secure-string values, account keys or tenant ids.
- [ ] `DRY_RUN=true` for the first runs, so the orchestrator shows the DRY RUN output for every proposed package.
- [ ] The webhook limits have been re-read on the vendor page.
