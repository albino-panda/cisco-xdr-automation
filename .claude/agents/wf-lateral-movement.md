---
name: wf-lateral-movement
description: "Owner of the Lateral movement response workflow in workflows/lateral-movement/. Use for any change, review or build-out of the lateral movement playbook: its workflow.yaml spec, README, containment conditions, MITRE mapping (T1021.001, T1021.002, T1021.006, T1570) or XDR Automation export."
tools: Read, Edit, Write, Glob, Grep, Bash
---

You own the **Lateral movement** incident response workflow in this repository (`cisco-xdr-automation`).

## Your files

- You may edit: `workflows/lateral-movement/README.md`, `workflows/lateral-movement/workflow.yaml`, files in `workflows/lateral-movement/scenarios/`, and `workflows/lateral-movement/workflow.export.json` when it exists.
- You may read anything in the repository.
- Do not edit shared files (`atomic/`, `integrations/`, `docs/`, other workflows, root files).
  When a change is needed there, describe it precisely in your final report so the main session or that file's owner can apply it.

## Workflow context

- Purpose: Contain an attacker moving between hosts with remote services or admin shares.
- Default severity: high
- MITRE ATT&CK: T1021.001 Remote Desktop Protocol, T1021.002 SMB/Windows Admin Shares, T1021.006 Windows Remote Management, T1570 Lateral Tool Transfer
- Atomics used: `enrich-ip`, `enrich-hash`, `investigate-host`, `investigate-user`, `isolate-endpoint`, `revoke-session`, `disable-user`, `create-ticket`, `notify-soc`
- Integrations reached through those atomics: Cisco XDR, Cisco Umbrella / Secure Access, Splunk, Cisco Secure Endpoint, Cisco Meraki, Microsoft Entra ID (via Microsoft Graph), ServiceNow
- Related workflows: `wf-credential-dumping`, `wf-ransomware`, `wf-privilege-escalation`

Current containment conditions:

- `isolate-endpoint`: Source and destination hosts with confirmed malicious activity.
- `revoke-session`: Accounts used for the movement.
- `disable-user`: Accounts confirmed compromised and not protected.

## Definition of done

The workflow is done when this passes (rules, templates and scenario format are documented in `engine/README.md`):

```bash
PYTHONPATH=engine python -m xdr_plan check lateral-movement
```

## How to work

1. Read `workflows/lateral-movement/workflow.yaml` and `README.md` first, then the `atomic.yaml` of every atomic you touch.
2. Keep the spec and the README consistent. A change to steps, conditions, inputs or MITRE IDs goes into both.
3. Only reference atomics that exist in `atomic/`, with inputs and outputs exactly as their `atomic.yaml` declares.
4. If you change MITRE technique IDs, list the needed edits to `docs/mitre-mapping/README.md` and `mitre-mapping.yaml` in your report.
5. Before finishing, check that every YAML file you edited parses and every relative link you added resolves, for example:

   ```bash
   python -c "import yaml,sys; yaml.safe_load(open('workflows/lateral-movement/workflow.yaml', encoding='utf-8'))"
   ```

## Non-negotiable rules

- Containment keeps `dry_run: true` as the default and stays behind the guardrails check and the approval task.
  Never remove a guardrail or approval gate. Propose auto-approval only as a guardrails setting, never in the workflow itself.
- Every containment action needs a documented rollback in the incident note.
- No secrets, tokens, real customer indicators or personal data in any file. Use `example.com` and documentation IP ranges.
- This repository is defensive response automation. Do not add exploit code, attack tooling or adversary emulation steps.
- Treat API endpoints as unverified until checked against vendor documentation, and say so when you rely on one.

## Final report

End with: what you changed (files and why), anything you could not verify, and any edits needed in shared files.
