# Security policy

## Reporting a vulnerability

Do **not** open a public issue for a security problem. Use GitHub private vulnerability reporting ("Report a vulnerability" under the Security tab) or contact the maintainers privately. You get an acknowledgement within 5 business days.

Include the affected version or commit, reproduction steps, the impact, and whether real tenant data was involved. Never send real telemetry, credentials, tokens or approval keys.

Treat these as critical and report them at once:

- any path that changes vendor state without a valid human approval token;
- any way for a `SERVICE`, `AUTOMATION` or `AI` principal to approve;
- a token accepted for another incident, target, parameter set, purpose or package;
- a secret, token, password, key or unlock code in a log, audit record, report or exception;
- an audit change the verifier does not detect;
- a release or restoration of a control the automation did not create.

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest release | yes |
| older releases | security fixes on a best-effort basis |

## Approval invariants

The code enforces these rules. A change that breaks one is a vulnerability.

1. **No state change without a human approval.** Containment, remediation, release, restoration and removing blocks all need a valid token. Every state-changing adapter method carries `@state_changing`, and the HTTP client refuses state-changing requests outside `guard.authorized(...)`. A direct call raises `ApprovalRequiredError`.
2. **Only humans approve.** `ApprovalEngine` accepts only principals of kind `HUMAN` that the configured `ApproverAuthenticator` authenticated. `SERVICE`, `AUTOMATION` and `AI` are always refused. The package requester does not count toward the quorum unless self-approval is explicitly allowed.
3. **Tokens are bound.** The HMAC-SHA256 token covers purpose, package, incident, evidence snapshot hash, workflow version, approvers, issue and expiry times, and per action the idempotency key, action type, target, params hash and approval level. Changing any of them invalidates the token.
4. **Tokens are short-lived and single use.** Default TTL is 30 minutes ([`config/thresholds.yaml`](config/thresholds.yaml)). The token-use ledger allows one use per action. A rejected package is revoked and cannot be approved again.
5. **Purposes do not mix.** A `containment` token cannot release, and a `release` token cannot contain.
6. **Critical assets need elevated approval.** ELEVATED actions need approvers with the elevated role. They are never silently skipped and never silently executed.
7. **The guard fails closed.** No verifier, dry run active, expired token, bad signature or any mismatch: no write. Dry run is on by default and can only be switched on per run, never off.
8. **Restoration is separate.** Release packages come only from `ACTIVE` entries in the temporary control registry and need a `release` token. Closing an incident never removes a control.
9. **Audit is append-only and tamper-evident.** Each record carries the hash of the previous one. Check a trail with `python tools/validation/verify_audit_chain.py <path>`. The audit API has no update or delete.
10. **Evidence is not fabricated.** Evidence comes from a registered integration, an analyst or the control registry. AI text is stored separately and never becomes numbered evidence.

The tests in [`tests/safety/`](tests/safety/) check these invariants. They are never weakened (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Secret handling

- **No secrets in the repository.** Config files hold secret **names** (for example `XDR_CLIENT_SECRET`), never values. The config loader refuses literal secret values.
- **Where values come from.** Environment variables first, then one file per secret name in `XDR_RESPONSE_SECRETS_DIR` (for example a mounted vault or Kubernetes secret). `.env` and `config/integrations.yaml` are git-ignored. [`.env.example`](.env.example) lists the names.
- **Redaction.** Every secret value a provider returns is registered with the central redactor. Logs and audit both use it. Sensitive keys (`password`, `secret`, `token`, `api_key`, `authorization`, `cookie`, `approval_token`, `unlock_code` and similar), URL query parameters and registered values are replaced by `[REDACTED]`. A `SecretValue` never prints its value.
- **Least privilege.** Give each integration only the API permissions its adapter needs. Give the orchestrator's service identity no approver role.
- **Splunk is optional.** It is disabled by default. Enable it only if you need it.

## Approval signing key

- `APPROVAL_SIGNING_KEY` signs approval tokens. It must be random and at least 32 bytes. Keep it in a vault or secret store, never in code, config or a ticket.
- Only the orchestrator process should read it. Anyone who holds the key and the code can sign tokens, so separation of duties is an operational control: vault access is restricted and audited.
- **Rotation.** Put the new key in `APPROVAL_SIGNING_KEY` and the old one in `APPROVAL_SIGNING_KEY_PREVIOUS`. Tokens signed with the old key keep verifying until they expire (30 minutes by default). Then remove `APPROVAL_SIGNING_KEY_PREVIOUS`.

**If the key is compromised:**

1. Stop the orchestrator, or set `DRY_RUN=true`, so no write can run.
2. Generate a new key and replace `APPROVAL_SIGNING_KEY`. Do **not** keep the compromised key as `APPROVAL_SIGNING_KEY_PREVIOUS`.
3. Restart. Every token signed with the old key now fails verification.
4. Verify the audit chain with `tools/validation/verify_audit_chain.py`, checked against an externally recorded head hash if you keep one.
5. Review every approval and execution record since the suspected compromise. Compare the temporary control registry with the vendor consoles.
6. Re-approve any pending package with the new key.

## Before live use

- Replace `InMemoryApproverAuthenticator` (tests and lab only) with an `ApproverAuthenticator` backed by your identity provider.
- Keep the audit trail on storage the orchestrator cannot rewrite, and record the head hash outside the system regularly.
- Follow the go-live checklist in [docs/testing](docs/testing/README.md) and the rollout order in [docs/deployment](docs/deployment/README.md).
