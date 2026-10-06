# cisco-xdr-automation

Incident response automation for Cisco XDR: playbooks for common attack types, the atomic actions they are built from, and the integrations those actions call.

```
cisco-xdr-automation/
├── workflows/      incident-type playbooks (README + workflow.yaml)
├── atomic/         reusable single-purpose actions (README + atomic.yaml)
├── integrations/   auth, permissions and API surface per product
└── docs/
    ├── mitre-mapping/   technique-to-workflow coverage
    ├── deployment/      rollout order, approvals, guardrails
    └── testing/         test levels and go-live checklist
```

## How it fits together

```
XDR incident ──► workflow ──► enrich ──► investigate ──► plan ──► approval ──► contain ──► ticket + note ──► notify
                     │                                    ▲
                     └──────────── guardrails ────────────┘
```

- A **workflow** handles one incident type. It enriches observables, investigates the user and host, builds a containment plan and asks for approval.
- An **atomic** does one job, such as isolating an endpoint or blocking a domain, and has a fixed input/output contract.
- An **integration** describes how to reach one product with least privilege.
- **Guardrails** (protected assets, allow-lists, blast-radius caps) are checked before every containment action.

## Catalog

|  | Count | Index |
|---|---|---|
| Workflows | 19 | [workflows/README.md](workflows/README.md) |
| Atomic actions | 15 | [atomic/README.md](atomic/README.md) |
| Containment atomics | 8 | approval-gated, dry-run by default |
| Integrations | 9 | [integrations/README.md](integrations/README.md) |

## Status

Everything here is a **specification**. Workflows are built in XDR Automation from the `workflow.yaml` files and their exported JSON is committed back beside them. API endpoints listed under `integrations/` must be verified against vendor documentation for your region before use.

## Safety defaults

- `dry_run` is `true` for every containment action until you turn it off per workflow.
- Protected hosts and users are never actioned automatically.
- Every containment action records its rollback in the incident note.
- Secrets live only in `.env` (git-ignored) or the XDR secret store.

## Getting started

1. Read [docs/deployment](docs/deployment/README.md) and copy the guardrails example.
2. Copy `.env.example` to `.env` for any code that runs outside XDR.
3. Configure the integrations as XDR Automation targets.
4. Build read-only atomics first, then one workflow in dry-run.
5. Follow the go-live checklist in [docs/testing](docs/testing/README.md).

## Related project

[cisco-xdr-mailbomb-detector](<../Mail Bombing/cisco-xdr-mailbomb-detector/README.md>) raises the incidents handled by [`workflows/mail-bombing`](workflows/mail-bombing/README.md).

## Claude Code agents

Each workflow has a dedicated Claude Code subagent in [`.claude/agents/`](.claude/agents/), named `wf-<workflow>` (for example `wf-ransomware`).
An agent edits only its own `workflows/<workflow>/` directory and reports any change needed in shared atomics, integrations or docs.
All agents keep the safety defaults above: dry-run, guardrails, approval gates and documented rollback.

Ask Claude Code to use one by name, for example:

```
Use the wf-phishing agent to add a step that checks whether any recipient clicked the link.
```

There are 19 agents, one per directory in [`workflows/`](workflows/README.md).
