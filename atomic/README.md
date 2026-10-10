# Atomic actions (legacy names)

The per-atomic spec directories (`atomic/<name>/atomic.yaml` and their READMEs) were retired at the end of Phase 5 (docs/architecture.md 14.4.3 and 14.13.1). Every workflow is a migrated `WorkflowDefinition` that uses the atomic library in [`src/xdr_response/atomics/`](../src/xdr_response/atomics/__init__.py) and the action catalog in [`src/xdr_response/models/catalog.py`](../src/xdr_response/models/catalog.py). The catalog's `spec_ref` values (`atomic/<name>`) resolve to the table below.

| Legacy name (`spec_ref`) | Catalog action type | Category | `xdr_response.atomics` name | Rollback (catalog) |
|---|---|---|---|---|
| `atomic/enrich-ip` | `enrich_ip` | enrichment | `enrich_ip` (`read_atomics()`) | none (read-only) |
| `atomic/enrich-domain` | `enrich_domain` | enrichment | `enrich_domain` (`read_atomics()`) | none (read-only) |
| `atomic/enrich-hash` | `enrich_hash` | enrichment | `enrich_hash` (`read_atomics()`) | none (read-only) |
| `atomic/investigate-user` | `investigate_user` | investigation | `investigate_user` (`read_atomics()`) | none (read-only) |
| `atomic/investigate-host` | `investigate_endpoint` | investigation | `investigate_endpoint` (`read_atomics()`) | none (read-only) |
| `atomic/isolate-endpoint` | `isolate_endpoint` | containment | `isolate_secure_endpoint`, `isolate_defender_endpoint` (`containment_builders()`) | `release_endpoint` |
| `atomic/block-domain` | `block_domain` | containment | `block_domain_umbrella` (`containment_builders()`) | `unblock_domain` |
| `atomic/block-url` | `block_url` | containment | `block_url` (`containment_builders()`) | `unblock_url` |
| `atomic/block-ip` | `block_ip` | containment | `block_ip` (`containment_builders()`) | `unblock_ip` |
| `atomic/block-hash` | `block_hash` | containment | `block_hash` (`containment_builders()`) | `unblock_hash` |
| `atomic/disable-user` | `disable_user` | containment | `disable_entra_user` (`containment_builders()`) | `enable_user` |
| `atomic/revoke-session` | `revoke_sessions` | containment | `revoke_entra_sessions` (`containment_builders()`) | none (not reversible) |
| `atomic/quarantine-email` | `quarantine_email` | containment | `quarantine_email` (`containment_builders()`) | `release_email` |
| `atomic/create-ticket` | `create_ticket` | bookkeeping | none: a catalog bookkeeping operation | none |
| `atomic/notify-soc` | `notify_soc` | bookkeeping | `notifications.NotificationService` (`render_soc_notification`) | none |

## Contract rules (unchanged)

- Read atomics (enrichment and investigation) are read-only and reach adapters only through the read-only facade. A failed or degraded source is recorded and never blocks a recommendation that other evidence supports.
- Containment builders only **recommend**: they return a `BuiltRecommendation` and never execute. Every state-changing action, including session revocation, needs a human approval; a critical asset needs ELEVATED approval with a visible warning and is never skipped silently. Only the lifecycle orchestrator executes approved actions, verification is automatic, and restoration needs a separate human release approval.
- Every action supports dry run (`dry_run_verb` in the catalog).
- Isolation unlock codes stay in the Secure Endpoint console and are never copied to notes, tickets or notifications.

The vendor integrations behind each action are documented in [`integrations/`](../integrations/README.md) and, with their VERIFIED and UNVERIFIED endpoints, in [`docs/integrations.md`](../docs/integrations.md).
