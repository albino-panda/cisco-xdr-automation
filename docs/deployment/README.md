# Deployment

How to take a workflow from specification to production in Cisco XDR Automation.

## Prerequisites

- Cisco XDR with Automation enabled and an administrator who can create targets, rules and workflows.
- One XDR Automation **target** per integration in [`integrations/`](../../integrations/README.md), with least-privilege credentials.
- A ServiceNow assignment group and a SOC notification channel (Webex, Microsoft Teams, Slack or email).
- The guardrails file filled in for your environment: copy [`guardrails.example.yaml`](guardrails.example.yaml).

## Rollout order

1. **Integrations.** Create targets and verify each with a read-only call.
2. **Read-only atomics.** Enrichment and investigation atomics. Run them by hand against known observables.
3. **Ticketing and notification.** `create-ticket` and `notify-soc`.
4. **Containment atomics in dry-run.** Confirm the planned output and the guardrail skips.
5. **Workflows in dry-run.** Attach incident rules so every matching incident produces a plan without acting.
6. **Enable containment** one workflow at a time after reviewing at least two weeks of dry-run plans.

## Approvals

- Containment actions marked *approval required* go through an XDR **Approval Task**.
- Auto-approval is configured per workflow and per atomic in the guardrails file, and is off by default.
- A sensible first candidate for auto-approval is `isolate-endpoint` in the ransomware workflow for non-protected workstations.

## Change management

- Treat `workflow.yaml` and `atomic.yaml` as the reviewed source. Export XDR JSON after every change and commit it beside the spec.
- Tag releases and keep a changelog of behaviour changes, especially changes to containment conditions.

## Limits to remember

- Workflow run time and action counts are capped by XDR Automation. Split long loops into child workflows.
- Webhook and API rate limits are shared with other projects, including the mail-bomb detector.
