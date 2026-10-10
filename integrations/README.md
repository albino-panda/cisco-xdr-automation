# Integrations

Connection details, permissions and API surface for each product. The runtime adapters live in
`src/xdr_response/integrations/<name>/` (16 adapters, each with a capability manifest);
[`docs/integrations.md`](../docs/integrations.md) is the source of truth for every vendor endpoint and
whether it is VERIFIED or UNVERIFIED. An UNVERIFIED endpoint is never called: the adapter raises
`UnverifiedEndpointError`.

How the framework uses them: workflows only **read** (investigation and enrichment through a
read-only facade) and **recommend**. Every state-changing call goes through the lifecycle orchestrator
after a human approval: `ContainmentExecutor` -> `ActionRunner` -> the adapter's `@state_changing`
method -> `GuardedHttpClient`, inside an authorization context bound to the approved action. There
are no "XDR Automation targets" called from atomics any more; the retired plan-rule model is described
in `docs/architecture.md` as design history.

| Spec page | Runtime adapter | Purpose |
|---|---|---|
| [Cisco XDR](./cisco-xdr/README.md) | `cisco_xdr` | Incident source of truth, enrichment, native response actions (respond/trigger; not verifiable) |
| [Cisco Secure Endpoint](./secure-endpoint/README.md) | `secure_endpoint` | Endpoint telemetry and trajectory, isolation and release (isolation read-back is UNVERIFIED) |
| [Cisco Secure Email Threat Defense](./secure-email/README.md) | `secure_email` | Message search, quarantine, release and delete (verifiable) |
| [Cisco Umbrella / Secure Access](./umbrella/README.md) | `umbrella` | Domain and URL reputation, DNS activity, destination-list blocks (verifiable) |
| [Microsoft Entra ID](./microsoft-entra/README.md) | `entra` | Users, sign-ins and roles; disable, session revocation, role removal (verifiable) |
| [Splunk](./splunk/README.md) | `splunk` | Optional SIEM search and audit forwarding to HEC (`tools/deployment/forward_audit.py`) |
| [Cisco Meraki](./meraki/README.md) | `meraki` | Network clients, MX IP blocks and client blocks (verifiable) |
| [Microsoft Defender for Endpoint](./defender-endpoint/README.md) | `defender_endpoint` | Machines and alerts, isolation (verifiable), indicator blocks (not verifiable) |
| [Microsoft Defender for Office 365](./defender-o365/README.md) | `defender_o365` | Graph email remediation (not verifiable) |
| [Microsoft Intune](./intune/README.md) | `intune` | Managed devices, remote lock (not verifiable) |
| [Microsoft Defender XDR / Graph security](./microsoft-cloud/README.md) | `microsoft_cloud` | Alerts (alerts_v2) and advanced hunting (read only) |
| [VirusTotal](./virustotal/README.md) | `virustotal` | Public reputation (disclosure policy applies) |
| [AlienVault OTX](./alienvault-otx/README.md) | `alienvault_otx` | Independent reputation (disclosure policy applies) |
| [Have I Been Pwned](./hibp/README.md) | `hibp` | Credential exposure of an address (disclosure policy applies) |
| [Cisco Secure Malware Analytics](./secure-malware-analytics/README.md) | `secure_malware_analytics` | Domain reputation from the sandbox (hash lookups are UNVERIFIED) |
| [Cisco Secure Cloud Analytics](./secure-cloud-analytics/README.md) | `secure_cloud_analytics` | Stub only (every endpoint UNVERIFIED); alerts arrive as Cisco XDR incidents (docs/architecture.md section 15.5) |
| [Cloudflare](./cloudflare/README.md) | none | Spec only: no adapter exists; nothing routes to it |
| [ServiceNow](./servicenow/README.md) | none | Spec only: no adapter exists; `create_ticket` has no executing adapter (docs/architecture.md section 15.4) |

Legacy atomic names map to runtime action types in the [atomic table](../atomic/README.md).

What the real adapters cannot execute or cannot verify, and what would close each gap, is in [docs/architecture.md section 15](../docs/architecture.md#15-known-gaps-and-owner-decisions). The simulated adapters used by the simulator and the tests do exactly what these adapters support and verify (architecture 14.14.3).

## Rules

- Use separate read-only and read/write credentials where the product supports it.
- Secrets are referenced by **name** in `config/integrations.yaml` (environment variables or mounted
  secret files under `XDR_RESPONSE_SECRETS_DIR`); the loader refuses literal values.
- Never commit secrets. `.env` is git-ignored; only `.env.example` is tracked.
- A new vendor endpoint is implemented only after it is VERIFIED in `docs/integrations.md`.
