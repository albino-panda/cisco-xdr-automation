# Validation tools

Read-only command-line checks. None of them opens a network connection, reads a secret value or
changes a file (except `generate_workflow_docs.py --write`). Exit codes: 0 good, 1 problems found,
2 usage error.

| Tool | What it checks | Runs in CI |
|---|---|---|
| `verify_audit_chain.py <audit.jsonl>` | the SHA-256 hash chain of an audit trail (edits, deletions, reordering; truncation with an anchor) | via unit tests |
| `validate_config.py [--config-dir config] [--use-env]` | every `config/*.yaml` with the production loader: unknown keys, approval bypass keys such as `auto_approve`, secrets by NAME only; prints a summary | yes |
| `check_endpoints.py [--integration <name>] [--list]` | every adapter manifest against `docs/integrations.md`: VERIFIED operations cite a listed source and have a method, UNVERIFIED ones cite none, supported actions have a VERIFIED write | yes |
| `check_workflow_readmes.py [--workflow <id>]` | each discovered workflow's `workflows/<id>/README.md` (17 sections of 14.5.4, integrations, ATT&CK ids, approval wording, testing paths, limitations, no `auto_approve` / unlock codes / secrets / non-documentation IPs) and its scenario coverage (14.5.3) | yes |
| `generate_workflow_docs.py [--write \| --check]` | the generated MITRE mapping and workflow index (owner: legacy-alignment, 14.5.5) | yes (`--check`) |

```
python tools/validation/validate_config.py
python tools/validation/check_endpoints.py --list
python tools/validation/check_workflow_readmes.py --workflow ransomware
python tools/validation/verify_audit_chain.py var/audit/audit.jsonl
```
