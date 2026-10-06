# Atomic actions

Small, reusable building blocks that workflows chain together. Each one does a single job against one or more integrations and has a fixed input/output contract in `atomic.yaml`.

| Atomic | Category | Approval | Integrations |
|---|---|---|---|
| [`enrich-ip`](./enrich-ip/README.md) | enrichment | no | cisco-xdr, umbrella, splunk |
| [`enrich-domain`](./enrich-domain/README.md) | enrichment | no | cisco-xdr, umbrella |
| [`enrich-hash`](./enrich-hash/README.md) | enrichment | no | cisco-xdr, secure-endpoint |
| [`investigate-user`](./investigate-user/README.md) | investigation | no | microsoft-entra, splunk, cisco-xdr |
| [`investigate-host`](./investigate-host/README.md) | investigation | no | secure-endpoint, cisco-xdr, meraki, splunk |
| [`isolate-endpoint`](./isolate-endpoint/README.md) | containment | yes | secure-endpoint, cisco-xdr |
| [`disable-user`](./disable-user/README.md) | containment | yes | microsoft-entra |
| [`block-domain`](./block-domain/README.md) | containment | yes | umbrella, cloudflare |
| [`block-ip`](./block-ip/README.md) | containment | yes | meraki, cloudflare |
| [`block-url`](./block-url/README.md) | containment | yes | umbrella, cloudflare |
| [`block-hash`](./block-hash/README.md) | containment | yes | secure-endpoint |
| [`quarantine-email`](./quarantine-email/README.md) | containment | yes | secure-email |
| [`revoke-session`](./revoke-session/README.md) | containment | no | microsoft-entra |
| [`create-ticket`](./create-ticket/README.md) | ticketing | no | servicenow, cisco-xdr |
| [`notify-soc`](./notify-soc/README.md) | notification | no | cisco-xdr |

## Contract rules

- Inputs `incident_id` and `dry_run` are accepted by every atomic.
- Containment atomics default to `dry_run = true`, check guardrails and log rollback steps.
- Enrichment and investigation atomics are read-only.
- All atomics are idempotent and return an `error` output instead of failing the whole workflow.
