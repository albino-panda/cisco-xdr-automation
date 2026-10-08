# Deployment

How to deploy the `xdr_response` framework (`src/xdr_response/`) next to Cisco XDR. Audience: the SOC engineer who installs it, wires the secrets and integrations, and takes it from dry run to live containment.

Read [architecture.md](architecture.md) for the design and [integrations.md](integrations.md) for which vendor endpoints are VERIFIED. The older workflow-spec rollout (XDR targets, the guardrails file, the plan engine) is in [deployment/README.md](deployment/README.md).

## 1. What you are deploying

The lifecycle is fixed in code. Configuration cannot change it.

| Stage | Who acts | Where it is enforced |
|---|---|---|
| Investigation, enrichment, scoring | Automatic | Read-only adapter operations |
| Recommendation (containment package) | Automatic | `PackageBuilder`. Never executes anything |
| Approval of any state change | **A human only** | `ApprovalEngine`, HMAC approval token, `guard.py` |
| Execution of the approved actions | Automatic, right after approval | `ContainmentExecutor` inside `guard.authorized(...)` |
| Verification | Automatic | `VerificationEngine` (read-only) |
| Restoration | A **separate** human release approval, then automatic | Release token (`purpose="release"`), `RestorationEngine` |

Two pieces run in production:

- **Cisco XDR Automation.** Detects, creates incidents, and starts a small trigger workflow. It can show an approval task to the analyst, but that task never authorizes anything by itself (section 8).
- **The external orchestrator** (`xdr_response`). Investigates, recommends, records the analyst decision, executes, verifies, restores and writes the audit trail.

Phase 0 ships `xdr_response` as a library. The entry point is `xdr_response.lifecycle.runtime.bootstrap()`. There is no packaged HTTP service or analyst web UI yet: you host the process and plug in your own approver authentication (section 6).

## 2. Prerequisites

- Python 3.12 or later. Install with `pip install .` from the repository root (dependencies: PyYAML, pydantic 2, httpx). Add `pip install -r requirements-dev.txt` on the machine where you run the tests.
- A secret store that can inject values as environment variables or as mounted files. For example HashiCorp Vault Agent, Azure Key Vault with a CSI driver, AWS Secrets Manager, or Kubernetes secrets.
- One least-privilege API client per integration you enable. Permissions per call are listed in [integrations.md](integrations.md).
- An identity provider (OIDC or SAML SSO) that can authenticate analysts and expose their roles.
- Persistent, backed-up storage for the `var/` files (audit trail, control registry, token ledger).
- Outbound HTTPS from the orchestrator host to the vendor API hosts in [integrations.md](integrations.md).

## 3. Secrets

### 3.1 Rules

- Secret **values** never go into code, YAML, git or tickets. Config files hold only the **name** of a secret (pattern `^[A-Z][A-Z0-9_]*$`).
- The loader refuses a literal value under any secret-like key (`token`, `api_key`, `password`, `client_secret` and similar) with a `ConfigError`. The error names the key path, never the value.
- Every value a secret provider returns is registered with the central redactor. Logs and audit records show `[REDACTED]` instead.

### 3.2 Where secrets are read from

`bootstrap()` uses `default_secret_provider()` from `xdr_response.secrets`:

1. Environment variables of the process.
2. If `XDR_RESPONSE_SECRETS_DIR` is set: one file per secret in that directory, named exactly after the secret (for example `/run/secrets/xdr/APPROVAL_SIGNING_KEY`). A trailing newline is stripped.

The environment wins when both have a value. A `.env` file is **not** read by the code. If you use one in the lab, your process manager must export it. Copy [`.env.example`](../.env.example) for the list of names.

For production, prefer mounted files written by the secret store agent over plain environment variables: they do not show up in process listings or crash dumps.

### 3.3 Framework secrets

| Secret | Required | What it does |
|---|---|---|
| `APPROVAL_SIGNING_KEY` | Yes | HMAC-SHA256 key that signs and verifies approval tokens. At least 32 bytes. `bootstrap()` fails without it |
| `APPROVAL_SIGNING_KEY_PREVIOUS` | Only during a key rotation | Old key, still accepted for verification |
| `AUDIT_CHAIN_KEY` | Strongly recommended | HMAC key for the audit trail head anchor. At least 32 bytes. Without it the trail falls back to `XDR_RESPONSE_AUDIT_KEY_FILE` or `~/.xdr_response/audit-chain.key`, created on first use |

Generate each key once, inside the secret store or on a trusted workstation, and never print it into a shared terminal or ticket:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

`token_hex(32)` gives 64 characters, which meets the 32-byte minimum. Store the output directly in the secret store.

**Key rotation.**

1. Put the current key into `APPROVAL_SIGNING_KEY_PREVIOUS`.
2. Put the new key into `APPROVAL_SIGNING_KEY`.
3. If you also change the key id, set `approval.signing_key_id` to the new id and `approval.previous_signing_key_id` to the old id in `thresholds.yaml`.
4. Restart the process.
5. Remove `APPROVAL_SIGNING_KEY_PREVIOUS` once every outstanding token has expired. Tokens live at most `containment_token_ttl_minutes` / `release_token_ttl_minutes` (30 minutes by default).

Anyone who holds `APPROVAL_SIGNING_KEY` and can write the token ledger could forge approvals. Restrict read access to the orchestrator's service identity.

### 3.4 Integration secrets

These are the default names. Each integration maps logical names to secret names under `secrets:` in `integrations.yaml`, so you can rename them.

| Integration | Secret names |
|---|---|
| `cisco_xdr` | `XDR_CLIENT_ID`, `XDR_CLIENT_SECRET` |
| `secure_endpoint` | `SE_CLIENT_ID`, `SE_API_KEY` |
| `secure_email` | `ETD_CLIENT_ID`, `ETD_CLIENT_SECRET`, `ETD_API_KEY` |
| `secure_malware_analytics` | `SMA_API_KEY` |
| `secure_cloud_analytics` | `SCA_API_KEY` (unused until an endpoint is VERIFIED) |
| `umbrella` | `UMBRELLA_API_KEY`, `UMBRELLA_API_SECRET` |
| `meraki` | `MERAKI_API_KEY` |
| `entra`, `defender_o365`, `intune`, `microsoft_cloud` | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` |
| `defender_endpoint` | `ENTRA_TENANT_ID`, `MDE_CLIENT_ID`, `MDE_CLIENT_SECRET` |
| `virustotal` | `VT_API_KEY` |
| `alienvault_otx` | `OTX_API_KEY` |
| `hibp` | `HIBP_API_KEY` |
| `splunk` (optional) | `SPLUNK_TOKEN`, `SPLUNK_HEC_TOKEN` |

A missing secret raises `SecretNotFoundError` naming the secret. The integration's health check then reports `UNKNOWN`.

## 4. Configuration files

`load_settings(config_dir)` reads five YAML files. Examples live in [`config/`](../config/). Keep your production copies in a separate, access-controlled directory (for example `/etc/xdr-response/`) and pass it to `bootstrap(config_dir=...)`.

| File | What it holds | Notes |
|---|---|---|
| `integrations.yaml` | `runtime` (dry run, environment, file paths) and one block per integration | Falls back to [`integrations.example.yaml`](../config/integrations.example.yaml) when absent. `config/integrations.yaml` is git-ignored |
| [`thresholds.yaml`](../config/thresholds.yaml) | Scoring bands, blast-radius caps, approval rules (roles, quorum, token lifetimes), verification timing, temporary-control review reminders | Review reminders never release anything |
| [`critical-assets.yaml`](../config/critical-assets.yaml) | Critical asset classes with `display_name`, `role`, `potential_impact` and match rules | A match makes the action ELEVATED and shows a warning. It never silently blocks |
| [`allowlists.yaml`](../config/allowlists.yaml) | `never_block` targets, owned domains where URL blocks are allowed, approved RMM and DNS tools | Allow-listed targets appear on the decision card as excluded, with the reason |
| [`exclusions.yaml`](../config/exclusions.yaml) | Values never sent to VirusTotal, OTX or HIBP | Private IPs, hostnames, endpoint ids, file paths and message ids are never disclosed, whatever this file says |

A missing optional file gives the defaults from `xdr_response.config.schema`.

**The loader fails closed.** `ConfigError` is raised for:

- the keys `auto_approve`, `skip_approval`, `bypass_approval` or `approval_required` anywhere, whatever their value;
- a secret value instead of a secret name;
- an unknown key, an unknown top-level section, or an unknown integration name;
- `standard_min_approvers` or `elevated_min_approvers` below 1.

**Environment overrides.**

| Variable | Effect |
|---|---|
| `DRY_RUN` | `true` or `false` (case-insensitive). Any other value is a `ConfigError` |
| `XDR_RESPONSE_ENVIRONMENT` | `lab`, `staging` or `production`. A label only. It does not change behaviour |
| `XDR_RESPONSE_AUDIT_PATH`, `XDR_RESPONSE_REGISTRY_PATH`, `XDR_RESPONSE_TOKEN_LEDGER_PATH` | Override the `runtime.*_path` files |
| `XDR_RESPONSE_SECRETS_DIR` | Directory of mounted secret files (section 3.2) |
| `XDR_RESPONSE_AUDIT_KEY_FILE` | Fallback audit chain key file when `AUDIT_CHAIN_KEY` is not set |

Check a config directory before you deploy it. This loads and validates every file and makes no network call:

```bash
PYTHONPATH=src python -c "from xdr_response.config import load_settings; s = load_settings('/etc/xdr-response'); print('dry_run =', s.runtime.dry_run); print('enabled =', [n for n, c in s.integrations.items() if c.enabled])"
```

## 5. Enabling integrations

Each block in `integrations.yaml` has `enabled`, `base_url`, `region`, `timeout_seconds`, `max_retries`, `backoff_base_seconds`, `backoff_max_seconds`, `rate_limit_per_minute`, `secrets` and `options`. Disabled is the default for any integration you leave out.

Steps for each integration:

1. Create the API client in the vendor console with only the permissions listed in [integrations.md](integrations.md) section 2.
2. Store its credentials in the secret store under the names from section 3.4.
3. Set `enabled: true` and the regional `base_url`. Use only hosts listed in [integrations.md](integrations.md). For example the EU Secure Endpoint host is `https://api.eu.amp.cisco.com`.
4. Fill required `options`:
   - `entra`, `defender_o365`, `intune`, `microsoft_cloud`: `oauth_scope`. The Graph scope string is UNVERIFIED, so the adapter refuses to build auth without an explicit value. Confirm it for your tenant.
   - `meraki`: `organization_id`.
   - `hibp`: `user_agent` (HIBP rejects requests without one).
5. Set `rate_limit_per_minute` where the vendor documents a limit. The example sets Umbrella 1000, Defender for Endpoint 100 and VirusTotal 4 (public API).
6. Start in dry run (section 7) and run the health check:

```python
for name, h in runtime.health.check_all().items():
    print(name, h.status.value, h.detail)
```

Health statuses: `CONNECTED`, `DEGRADED`, `UNAVAILABLE`, `AUTH_FAILED`, `RATE_LIMITED`, `UNKNOWN`. A disabled integration reports `UNKNOWN` ("integration disabled"). Health checks use read operations only. A failed enrichment source does not block a recommendation that other evidence supports.

Things to know before you enable each one:

- **UNVERIFIED endpoints are not implemented.** Those adapter methods raise `UnverifiedEndpointError` (a `NotImplementedError`) with `unverified endpoint: <integration>.<operation> - see docs/integrations.md`. The action then fails or is reported as unroutable. It is never guessed. To add one, promote it in [integrations.md](integrations.md) with an official source first.
- **Native XDR actions come first.** Where Cisco XDR has a native response action (isolate, disable user, block domain, URL, IP or hash, quarantine email), the `cisco_xdr` adapter is preferred and the product adapter verifies the result ([architecture.md](architecture.md) section 4.2).
- **Secure Cloud Analytics** has no VERIFIED endpoint. Leave it disabled and read its alerts as XDR incidents.
- **VirusTotal public API** is for non-commercial use only and allows 4 requests per minute. Use a premium key in production.
- **Third-party lookups** (VirusTotal, OTX, HIBP) only receive observables that `DisclosurePolicy` allows. Add your internal domains and ranges to `exclusions.yaml`.
- **Vendor-side expiry** (for example `expirationTime` on Defender indicators) is not set. An automatic expiry would be a release without a human release approval.

### 5.1 Splunk (optional)

Splunk is never a hard dependency. It is disabled in the example config. While disabled, its health is `UNKNOWN` and every other part works unchanged.

To enable it:

```yaml
splunk:
  enabled: true
  base_url: https://splunk.example.test:8089
  secrets:
    token: SPLUNK_TOKEN          # REST session key
    hec_token: SPLUNK_HEC_TOKEN  # HTTP Event Collector token
  options:
    auth_mode: session_key       # or "basic" with secrets username / password
    hec_url: https://splunk.example.test:8088
```

- `auth_mode: session_key` (default) sends `Authorization: Splunk <key>`. `basic` uses HTTP Basic with the logical secrets `username` and `password`, which you map to secret names under `secrets:`. `bearer` is UNVERIFIED and raises.
- Searches are read-only (`POST /services/search/jobs`, then results).
- `SplunkAdapter.forward_audit(event)` sends one redacted event to HEC. It is bookkeeping, not containment, and needs no approval. The Phase 0 runtime does not forward the audit trail automatically. The JSONL file stays the authoritative record.

## 6. Approvers

Only principals of kind `HUMAN` can approve. `SERVICE`, `AUTOMATION` and `AI` are always refused, and so is a requester approving their own request (`allow_self_approval: false`).

`bootstrap()` requires an `authenticator` that implements `xdr_response.interfaces.ApproverAuthenticator`:

```python
class ApproverAuthenticator(Protocol):
    def authenticate(self, credential: ApproverCredential) -> AuthenticatedPrincipal: ...
```

- In production, implement it against your identity provider. Validate the OIDC token or SSO assertion, map the user to `PrincipalKind.HUMAN`, and copy their roles. Map service principals and bots to their real kind, so the engine refuses them.
- `InMemoryApproverAuthenticator` exists for tests, the lab and the simulator only. It keeps salted PBKDF2 hashes in memory and loses them on restart.

Roles come from `thresholds.yaml`:

| Setting | Default | Meaning |
|---|---|---|
| `standard_role` | `xdr-approver` | Can approve STANDARD actions |
| `elevated_role` | `xdr-elevated-approver` | Needed for ELEVATED actions (critical assets, always-elevated actions, over blast-radius caps) |
| `standard_min_approvers` | 1 | Distinct HUMAN approvers per STANDARD package |
| `elevated_min_approvers` | 1 | Distinct HUMAN approvers holding `elevated_role` for ELEVATED actions |

Create both groups in your identity provider. Keep the elevated group small.

## 7. Run in dry run first

Dry run is the default everywhere: the example config sets `dry_run: true`, and the guard starts in dry run until the runtime configures it. In dry run the framework investigates, enriches, scores and recommends with real read calls, records the analyst decision, and prints what it would do:

```
DRY RUN
Would isolate: TH-LT-1047
Would block: c2.ransom-ops.example
No containment actions executed.
```

The guard refuses every state-changing call in dry run, even with a valid approval token. A token issued for a dry-run package can never authorize a live run. Dry run creates no temporary controls, so there is nothing to release.

### 7.1 Try it without any vendor access

The simulator runs the full lifecycle against simulated adapters, with no network:

```bash
python tools/simulator/simulate.py ransomware
python tools/simulator/simulate.py ransomware --live --check
```

See [tools/simulator/README.md](../tools/simulator/README.md) and [testing.md](testing.md).

### 7.2 Dry run against your tenant

1. Configure the integrations you need (section 5) with real read credentials.
2. Set `DRY_RUN=true` (or leave `runtime.dry_run: true`).
3. Start the runtime:

```python
from xdr_response.lifecycle.runtime import bootstrap

runtime = bootstrap("/etc/xdr-response", authenticator=MyOidcAuthenticator(...))
assert runtime.dry_run
result = runtime.orchestrator.handle_detection(incident)   # investigate, recommend, propose
print(result.dry_run_report)                                 # the DRY RUN block
```

One process holds one runtime: the guard's verifier slot is sealed by the first `bootstrap()`, and a second one in the same process is refused.

4. Feed real XDR incidents for at least two weeks. Review every decision card: evidence, risk, confidence, ELEVATED warnings, excluded targets.
5. Fix `critical-assets.yaml`, `allowlists.yaml` and `exclusions.yaml` until no proposal is unsafe.
6. Verify the audit trail (section 9).

### 7.3 Go live

Set `DRY_RUN=false` in the process environment (or `runtime.dry_run: false`) and restart. Live means: once an authenticated human approves, the approved actions run automatically and are verified. Nothing runs without that approval.

You can still force dry run for a single run (`xdr_response.dryrun.dry_run_scope(force=True)`). A per-run request can only turn dry run on, never off.

## 8. Cisco XDR Automation side

Based on [integrations.md](integrations.md) section 1 and [architecture.md](architecture.md) section 4.1.

**Trigger.** Create a small XDR workflow started by an automation rule on **new incident** (or a **webhook** rule). It sends only the incident ID to the orchestrator. The orchestrator re-reads the incident through the VERIFIED incident APIs. It never trusts fields in the trigger payload. Polling the incident API instead is also fine.

- Webhook limits (1 MB payload, 25 workflow runs per minute per rule) come from search summaries. Re-read the vendor page before you rely on them.
- On-premises targets are reached through the **Automation Remote** appliance.

**Approval UI (optional).** A **Request Approval** task can notify the analyst and link to your decision page. An XDR task approval never authorizes a state change: XDR documents no binding to evidence, parameters, targets or a human identity, and no VERIFIED API to act on tasks. The decision must reach `ApprovalEngine` with an authenticated human credential. The HMAC token is the only authorization.

**Native response actions.** The orchestrator triggers them with `POST /iroh/iroh-response/respond/trigger/{module-instance-id}/{action-id}` (VERIFIED) inside `guard.authorized(...)`, so the `cisco_xdr` API client must be allowed to call the Response API. Do not attach automation rules that run the Cisco-managed "XDR - Contain Incident" workflows on their own: that would bypass the approval gate.

**Credentials inside XDR.** XDR-side workflows keep credentials in target account keys and Secure Strings. The orchestrator never reads those, and they never go into this repository.

**Version control.** Export XDR workflows as JSON (or commit from the Workflow Editor to Git). Secure String values are not carried in exports, but check every export for literals before committing it. An import without "duplicate" overwrites the existing workflow and cannot be undone.

**Legacy guardrails file.** [`deployment/guardrails.example.yaml`](deployment/guardrails.example.yaml) feeds the workflow-spec plan engine (`engine/xdr_plan`). `xdr_response` does not read it in production. Since Phase 1 it has no `auto_approve` section: both the plan engine and the `xdr_response` loader refuse `auto_approve`, `skip_approval`, `bypass_approval` and `approval_required` at any depth. Protected assets stay planned with ELEVATED approval, and over a blast-radius cap actions stay planned, become ELEVATED and the plan escalates. The legacy replay (`tools/simulator/legacy_replay.py`) maps this file onto critical assets, allow-lists and caps only for the dry-run regression replay. Its `expiry_hours` are release-review reminders and never release anything automatically: every release needs its own human approval.

## 9. Runtime files and audit

| File (default) | Content | Notes |
|---|---|---|
| `var/audit/audit.jsonl` | Append-only audit trail with a SHA-256 hash chain (`prev_hash`) and an HMAC-protected head anchor | Authoritative record of every decision, call and result |
| `var/registry/controls.jsonl` | TemporaryControlRegistry: every control automation created, with rollback parameters | Release packages are built only from ACTIVE entries. Closing an incident never removes controls |
| `var/approval/token-ledger.jsonl` | Single-use token ledger | Prevents replay of an approval token |

Put these on persistent storage and back them up together. Never edit them by hand: the audit verifier and the registry detect in-place changes.

Verify the audit chain at any time. The tool only reads:

```bash
python tools/validation/verify_audit_chain.py var/audit/audit.jsonl
python tools/validation/verify_audit_chain.py var/audit/audit.jsonl --anchor-file anchors.json --json
```

Exit codes: 0 intact, 1 broken (the first broken record is reported), 2 usage error. Export anchors (`AuditTrail.anchor()`) to write-once storage on a schedule. Only an external anchor detects a rollback of both the file and its head anchor to an older genuine state.

## 10. Go-live checklist

- [ ] `APPROVAL_SIGNING_KEY` and `AUDIT_CHAIN_KEY` are in the secret store, at least 32 bytes, readable only by the orchestrator identity.
- [ ] `load_settings` passes on the production config directory, and `dry_run` is `true`.
- [ ] Every enabled integration reports `CONNECTED` or `DEGRADED` in the health check.
- [ ] The production `ApproverAuthenticator` maps only real analysts to `HUMAN`, and both approver groups exist.
- [ ] `critical-assets.yaml`, `allowlists.yaml` and `exclusions.yaml` were reviewed by the SOC lead and the asset owners.
- [ ] At least two weeks of dry-run decision cards were reviewed with no unsafe proposal.
- [ ] The full test suite passes on the deployed version (`python -m pytest`; see [testing.md](testing.md)).
- [ ] Release (restoration) was exercised once per action type on test assets, with a separate release approval.
- [ ] Audit chain verification and anchor export are scheduled.
- [ ] No XDR automation rule runs a native containment workflow without going through the orchestrator.
