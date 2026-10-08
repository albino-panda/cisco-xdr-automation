# Plan engine

`xdr_plan` turns a workflow's containment rules plus enrichment and investigation results into the exact
containment plan an approver would see. It only recommends: nothing it plans runs without a human
approval through the `xdr_response` lifecycle. It applies the guardrails in
[`docs/deployment/guardrails.example.yaml`](../docs/deployment/guardrails.example.yaml) to every action.
Scenario files then pin the expected plan, so containment logic is tested before anything is built in XDR.

```bash
pip install -r requirements-dev.txt
python -m pytest                                   # everything
PYTHONPATH=engine python -m xdr_plan check phishing   # repository checks plus one workflow, readable output
PYTHONPATH=engine python -m xdr_plan plan phishing workflows/phishing/scenarios/01-malicious-link.yaml
```

On Windows PowerShell set the path with `$env:PYTHONPATH = "engine"` first.

## What a finished workflow contains

`python -m xdr_plan check <workflow>` passes when all of these hold:

1. Every entry in `steps` has `on_error`: `continue`, `stop` or `escalate`.
2. A non-empty `plan` list, with at least one rule for every contain-phase atomic in `steps`.
3. A `templates` block with non-empty `approval`, `incident_note`, `ticket_title`, `ticket_body` and `notification`.
4. At least four scenario files in `workflows/<id>/scenarios/`, all passing.
5. Coverage across those scenarios:
   - at least one produces a `planned` action;
   - at least one is benign and produces no actions;
   - at least one exercises a guardrail (a `skipped_*` status or `elevated: true`);
   - every plan rule produces an action in at least one scenario.

## Plan rules

```yaml
plan:
  - id: isolate_infected_hosts            # snake_case, unique
    description: Hosts where the payload executed and isolation is possible.
    atomic: isolate-endpoint              # must be a contain-phase atomic of this workflow
    for_each: "results['investigate-host']"   # optional; a list to iterate. Omit to run once with item = None
    when: "item.isolation_capable and any(d.disposition == 'malicious' for d in item.detections)"
    target: "item.connector_guid"         # the value the atomic acts on
    args:                                  # optional; extra atomic inputs, each an expression
      reason: "'Ransomware: ' + incident.title"
```

Names available in expressions:

| Name | Value |
|---|---|
| `incident` | The scenario's incident: `id`, `title`, `severity`, `source`, `observables`, `targets`, `context` |
| `results` | `results['<atomic-id>']` is the list of records from an enrich or investigate atomic of this workflow. Missing ones are empty lists |
| `item` | The current element of `for_each` |
| `guardrails` | The merged guardrails file |

Allowed syntax: `and or not`, comparisons including `in`, `+ - * / %`, `x if c else y`, lists, indexing,
field access with `.`, and one-clause comprehensions such as `any(s.result == 'success' for s in item.signins)`.

Helper functions: `any all len min max sum sorted lower get domain_of severity_at_least startswith endswith`.

- `get(obj, 'field', default)` reads an optional field. Plain `obj.field` fails loudly when the field is missing, which catches typos.
- `severity_at_least(incident.severity, 'high')` compares on `info < low < medium < high < critical`.
- `domain_of(url)` returns the lower-case host of a URL.

## Guardrails the engine applies

You do not repeat these in rules; they run on every action after `when` is true.

| Atomic | Check | Status when it trips |
|---|---|---|
| `isolate-endpoint` | `item.is_protected`, or host/GUID/IP matches `protected.hosts` (globs or CIDRs) | stays `planned` with `elevated: true` |
| `disable-user`, `revoke-session` | `item.is_protected`, user matches `protected.users`, or `item.profile.groups` hits `protected.groups` | stays `planned` with `elevated: true` |
| `block-domain` | domain or parent in `allowlist.domains` | `skipped_allowlisted` |
| `block-url` | URL host in `allowlist.domains` and not in `allowlist.url_block_allowed_domains` | `skipped_allowlisted` |
| `block-ip` | `item.is_internal`, `allowlist.ip_ranges`, or a private/reserved address | `skipped_internal` |
| `block-hash` | hash in `allowlist.hashes` | `skipped_allowlisted` |
| caps | more planned actions than `blast_radius` allows | every action in that group stays `planned` with `elevated: true` and the plan sets `escalate: true` |

Duplicate `(atomic, target)` pairs are planned once. `requires_approval` is always `true` for a
containment atomic. A protected target or a group over its cap is never dropped: the action stays
`planned`, `elevated` is `true` and `reasons` says why (`protected asset: ELEVATED approval required`,
or `<cap>: <n> planned > limit <limit>: ELEVATED approval required`). The runtime turns that into an
ELEVATED approval with a visible critical-asset warning.

Each `Action` has `rule`, `atomic`, `target`, `status` (`planned`, `skipped_allowlisted`,
`skipped_internal`), `requires_approval`, `args`, `elevated`, `reasons` and `source`
(`(results key, index)` when the `for_each` item is an element of `results[key]`, else `null`).

## Lifecycle checks

`python -m xdr_plan check` also fails on anything that asserts a weaker rule than the runtime
(architecture section 14.4.1):

| # | Check |
|---|---|
| C1 | a containment atomic, contain-phase step or scenario expectation with `requires_approval: false` |
| C2 | `auto_approve`, `skip_approval`, `bypass_approval` or `approval_required` (`LEGACY_FORBIDDEN_KEYS`) at any depth in the guardrails, a spec or a scenario; `repo.load_guardrails` raises `ValueError` |
| C3 | a scenario expecting `skipped_protected` |
| C4 | a template that copies an unlock code (only "the unlock code stays in the Secure Endpoint console" may appear) |
| C5 | a scenario expecting `skipped_limit` |

## Scenario files

```yaml
name: Malicious link clicked by one recipient
description: Why this case matters and what the plan should do.
incident:
  id: INC-TEST-0001
  title: Phishing link delivered to finance
  severity: medium
  source: Secure Email Threat Defense
  observables:
    - {type: domain, value: invoice-portal.example}
  context: {}            # free-form, source-specific facts
results:                 # only enrich/investigate atomics of this workflow; fields must exist in atomic.yaml
  enrich-domain:
    - {domain: invoice-portal.example, verdict: malicious, categories: [Phishing], first_seen: "2026-10-01", internal_queries: 3}
guardrails:              # optional override merged over guardrails.example.yaml
  blast_radius: {max_indicators_blocked: 1}
expect:
  escalate: false        # optional, default false
  actions:               # the exact set of actions; order does not matter. elevated defaults to false
                         # and is compared strictly; requires_approval may only be true
    - {atomic: block-domain, target: invoice-portal.example, status: planned, requires_approval: true}
    - {atomic: isolate-endpoint, target: dc-01, status: planned, elevated: true}   # a protected host (workflows with isolate-endpoint)
```

### Test data conventions

- The organisation's own domain is `example.com` and is allow-listed. Use it for users and internal sites.
- Attacker domains use reserved names that are not allow-listed, for example `invoice-portal.example` or `cdn-update.test`.
- External IPs come from documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
- Protected by default (ELEVATED approval): hosts `dc-*`, `hv-*` and `10.0.10.0/24`; users `breakglass-01@example.com`, `breakglass-02@example.com`; group `Domain Admins`.
- Hashes are 64 hex characters and must not be real malware hashes.
