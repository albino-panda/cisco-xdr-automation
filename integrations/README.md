# Integrations

Connection details, permissions and API surface for each product the atomics call. Secrets are read only from environment variables or the XDR Automation target and secret store.

| Integration | Purpose |
|---|---|
| [Cisco XDR](./cisco-xdr/README.md) | Incident source of truth, threat-intel enrichment, automation engine, incident notes and SOC notification targets. |
| [Cisco Secure Endpoint](./secure-endpoint/README.md) | Endpoint telemetry, device trajectory, host isolation and simple custom detection (hash block) lists. |
| [Cisco Secure Email (Threat Defense / Gateway)](./secure-email/README.md) | Message search, quarantine and remediation of delivered mail. |
| [Cisco Umbrella / Secure Access](./umbrella/README.md) | Domain and IP reputation, DNS activity lookups and destination-list blocking. |
| [Microsoft Entra ID (via Microsoft Graph)](./microsoft-entra/README.md) | User and sign-in investigation, session revocation and account disablement. |
| [Splunk](./splunk/README.md) | Historical log search for enrichment and investigation, and an optional event sink for automation audit records. |
| [Cisco Meraki](./meraki/README.md) | Network client lookup and perimeter IP blocking on MX appliances. |
| [Cloudflare](./cloudflare/README.md) | Edge blocking of IPs and URLs for internet-facing applications, and Zero Trust Gateway lists. |
| [ServiceNow](./servicenow/README.md) | Incident / security incident ticketing and status sync. |

## Rules

- Use separate read-only and read/write credentials where the product supports it.
- Configure each product once as an XDR Automation **target** and reference the target from atomics.
- Never commit secrets. `.env` is git-ignored; only `.env.example` is tracked.
