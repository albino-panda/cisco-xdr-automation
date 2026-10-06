# Deployment

> **Start here: [docs/deployment.md](../deployment.md).** It covers secrets (`APPROVAL_SIGNING_KEY` and the integration keys from a secret store), the config files, enabling integrations including optional Splunk, running in dry run first, and the Cisco XDR Automation side. This page keeps the rollout notes for the workflow specs in XDR Automation.

## Prerequisites

- Cisco XDR with Automation enabled and an administrator who can create targets, rules and workflows.
- One XDR Automation **target** per integration in [`integrations/`](../../integrations/README.md), with least-privilege credentials.
- A ServiceNow assignment group and a SOC notification channel (Webex, Microsoft Teams, Slack or email).
- The guardrails file filled in for your environment: copy [`guardrails.example.yaml`](guardrails.example.yaml). It feeds the plan engine (`engine/xdr_plan`). The `xdr_response` framework uses the files in [`config/`](../../config/) instead.

## Rollout order

1. **Integrations.** Create targets and API clients, and verify each with a read-only call (`runtime.health.check_all()`, see [docs/deployment.md](../deployment.md) section 5).
2. **Read-only atomics.** Enrichment and investigation atomics. Run them by hand against known observables.
3. **Ticketing and notification.** `create-ticket` and `notify-soc`.
4. **Containment in dry run.** Confirm the planned output, the guardrail skips and the `DRY RUN` block (`Would isolate: TH-LT-1047`).
5. **Workflows in dry run.** Attach incident rules so every matching incident produces a plan without acting.
6. **Enable containment** one workflow at a time after reviewing at least two weeks of dry-run plans. Set `DRY_RUN=false` only then.

## Approvals

- Every state-changing action (containment, remediation, release, restoration, removing blocks) needs a human approval. There is no auto-approval.
- The approval is enforced by `xdr_response`: an HMAC approval token issued only to an authenticated HUMAN principal, checked by the execution guard on every call.
- An XDR **Request Approval** task may notify the analyst, but it never authorizes an action by itself.
- The guardrails file still has an `auto_approve` section, read by the legacy plan engine. The example sets `account-takeover: revoke-session: true`. Set every entry to `false` in your copy. The `xdr_response` loader refuses the key, and Phase 1 removes it from the specs.

## Change management

- Treat `workflow.yaml` and `atomic.yaml` as the reviewed source. Export XDR JSON after every change and commit it beside the spec. Check every export for secret literals first.
- Treat `config/thresholds.yaml`, `critical-assets.yaml`, `allowlists.yaml` and `exclusions.yaml` like code: change them through reviewed pull requests.
- Tag releases and keep a changelog of behaviour changes, especially changes to containment conditions.

## Limits to remember

- Workflow run time and action counts are capped by XDR Automation. Split long loops into child workflows.
- Webhook and API rate limits are shared with other projects, including the mail-bomb detector.
