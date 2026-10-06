# Integrations: Cisco XDR compatibility and vendor API verification

Status: research baseline, brief section 47. Research date: 2026-10-06.

This file is the **source of truth for which vendor endpoints may be implemented** in
`src/xdr_response/integrations/<adapter>/`. The rule is strict:

- **VERIFIED**: the method and path were read on an official vendor documentation page. The exact URL that was read is listed next to the endpoint. An adapter may implement it.
- **UNVERIFIED**: no fetched official page confirmed it. Possible reasons: the page was JavaScript-rendered and returned no content, the path only appeared in a search snippet or a community or third-party page, or nobody looked it up yet. An adapter method for an UNVERIFIED endpoint **must** raise `NotImplementedError("unverified endpoint: <integration>.<operation> - see docs/integrations.md")`.
- **N/A**: the vendor has no such operation, or the brief does not need it.

Nothing in this file is a guess. Where a fact comes from an inference rather than a sentence on the page, the text says **inference**. To promote an endpoint from UNVERIFIED to VERIFIED, read the official page and add its URL here in the same change.

Test data in this repo uses only `example.com`, `*.test`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, fake 64-hex hashes and hosts like `TH-LT-1047`.

---

## 1. How Cisco XDR Automation works (what is documented, and what is not)

### 1.1 Building workflows

| Topic | What the documentation says | Source (read) |
|---|---|---|
| Building blocks | Workflows are built in the Workflow Editor from **activities** and reusable **atomic actions**, with workflow variables (up to 100 per workflow, at most 5 Large String variables). | https://docs.xdr.security.cisco.com/Content/Automate/workflows.htm |
| How response workflows start | Pivot menu, Incident Response playbooks, automation rules, API requests, manual execution. | https://docs.xdr.security.cisco.com/Content/Automate/workflows.htm |
| Targets | Targets are the systems a workflow talks to. Some targets have an **account key** (credentials) and some do not. At most 300 targets and 50 target groups per org. On-prem systems are reached through the **Automation Remote** virtual appliance. | https://docs.xdr.security.cisco.com/Content/Automate/targets.htm |
| Secrets | **Secure String** variables (global or local to the workflow) hold API keys, passwords and tokens. Best practice is to use the target's default account key. | Seen only in a search-result summary of https://docs.xdr.security.cisco.com/Content/Automate/workflow-best-practices.htm (page not fetched, so this detail is **UNVERIFIED**) |

### 1.2 Export, import and version control

| Topic | What the documentation says | Source (read) |
|---|---|---|
| Format | Workflows and atomics export as **JSON**, either as text or as a file. Import accepts pasted JSON, a JSON file, or a Git repository. | https://docs.xdr.security.cisco.com/Content/Automate/import-git-content.htm |
| Git | The Workflow Editor can **commit to a Git repository** (Properties > Git Repository, then Share > Commit To Git) and can import a chosen file and version. **GitHub** is the provider the docs name. Private repos authenticate with an account key (username plus password, or a personal access token when 2FA is on). Content categories: Atomics, Workflows, Workflows-Default. | https://docs.xdr.security.cisco.com/Content/Automate/import-git-content.htm, https://docs.xdr.security.cisco.com/Content/Automate/github-repos.htm |
| Secrets on import | "If the workflow contains Secure Strings, you'll be asked to provide their values during import". You can enter placeholders and set real values later. **Inference:** secure-string values are not carried in the export, so the exported JSON can go into version control. Check every export for literals before committing it anyway. | https://docs.xdr.security.cisco.com/Content/Automate/import-git-content.htm |
| Sub-workflows | Missing sub-workflows produce a warning. The workflow stays invalid until they are imported. | same |
| Overwrite hazard | An import without "duplicate" overwrites the existing object and "cannot be undone". | same |
| **Not documented** | A JSON schema for the workflow definition. Whether targets and account keys are included in an export. Whether Automation keeps a change history of who edited a workflow. | n/a |

**What this repo can version-control:** workflow JSON exports (`workflows/<name>/` already holds the YAML plan rules), atomic JSON exports, target definitions *without* credentials, and automation-rule settings documented as YAML. Secure-string values, account keys and API keys are **never** committed. They go through the `xdr_response.secrets` interface or the XDR secure store.

### 1.3 Native approval tasks

| Topic | What the documentation says | Source (read) |
|---|---|---|
| Activity | **Request Approval** (Activities > Task) replaced the older "Create Approval Request" activity, which was deprecated in 2.36 and removed in 2.40. | https://docs.xdr.security.cisco.com/Content/Automate/activities-task-request-approval.htm, https://docs.xdr.security.cisco.com/Content/Automate/tasks.htm |
| Fields | Requestor, owner, assignees (default: the workflow executor; or by role, administrators and/or incident responders; or by email), due date, **expiration date** (an expiration status is set when it expires), approval type (Approve/Reject, or a custom array), **minimum number of approvals** (quorum), and "Continue Workflow Execution On Failure". | https://docs.xdr.security.cisco.com/Content/Automate/activities-task-request-approval.htm |
| Flow | A workflow can create a task and wait for it, or create it for another workflow to act on later through an **Approval Task Rule**. Analysts Approve or Reject from the task's Actions. The incident Response tab shows "Action required" while a task is pending. | https://docs.xdr.security.cisco.com/Content/Automate/tasks.htm, https://docs.xdr.security.cisco.com/Content/Incidents/incident-response.htm |
| Limits | At most 500 active approval tasks and 500 active prompt tasks per org. | https://docs.xdr.security.cisco.com/Content/Automate/tasks.htm |
| **Not documented** | Any cryptographic binding of an approval to evidence, parameters or targets. Any rule that an approver must be a human and not a service identity. Any rule that the requester cannot approve their own request. Separate role requirements per action type or per critical asset. A tamper-evident record of the decision. The output variable names of the activity. A REST endpoint to approve or reject tasks. | n/a |

**Consequence for this repo:** XDR approval tasks may be used as a **UI surface** for the analyst decision. They are **not** the enforcement point. Enforcement is the HMAC approval token checked by `xdr_response.guard`. An approval only counts when it arrives with a token issued to a HUMAN principal authenticated by our `ApproverAuthenticator`. An XDR task approval by itself never authorizes a state change.

### 1.4 Response actions and the Response API (pivot menu)

- The incident **Response** tab runs Cisco-managed workflows for containment and recovery. "Click the Execute button to run a workflow". Results appear in Actions Taken and the Worklog. Source: https://docs.xdr.security.cisco.com/Content/Incidents/incident-response.htm
- The pivot menu and the Response API list the actions that enabled modules expose for an observable, then trigger one. VERIFIED endpoints are in section 2.1.

Native (Cisco-managed) incident response workflows and the products they support. All read on https://docs.xdr.security.cisco.com/Content/Incidents/incident-response.htm:

| Action | Native workflow | Supported products (as listed) |
|---|---|---|
| Isolate device | XDR - Contain Incident: Assets | Cisco Secure Endpoint, CrowdStrike, SentinelOne, Microsoft Defender for Endpoint (+GCC), Trend Vision One, Cybereason, Palo Alto Cortex, Darktrace /NETWORK |
| Disable user | XDR - Contain Incident: Users | Cisco Duo, Microsoft Entra ID |
| Block domain | XDR - Contain Incident: Domains | Cisco Secure Access, Cisco Umbrella |
| Block URL | XDR - Contain Incident: URLs | Cisco Secure Access, Cisco Umbrella, Cisco XDR intelligence feeds |
| Block IP | XDR - Contain Incident: IP Addresses | Cisco Secure Access (IPv4), Cisco Umbrella (IPv4 only), Cisco XDR intelligence feeds |
| Block file hash | XDR - Contain Incident: File Hashes | Cisco Secure Endpoint, CrowdStrike, Microsoft Defender for Endpoint (+GCC), Trend Vision One, Palo Alto Cortex |
| Quarantine email | XDR - Contain Incident: Quarantine Email Messages | Cisco Secure Email Threat Defense, Microsoft Defender for Office 365 (+GCC) |
| Un-isolate | XDR - Restore Systems | same as isolate |
| Restore user | XDR - Restore Users | Cisco Duo, Microsoft Entra ID |
| Unblock domain / IP / URL | XDR - Restore Domains / IP Addresses / Contained URLs | Cisco Secure Access, Cisco Umbrella, Cisco XDR intelligence feeds |
| Restore file hash | XDR - Restore File Hashes | Secure Endpoint, CrowdStrike, MDE (+GCC), Palo Alto Cortex, Trend Vision One |
| Release quarantined email | XDR - Release Email Messages from Quarantine | **Microsoft Defender for Office 365 (+GCC) only** (Secure Email Threat Defense is not listed) |
| Delete email | XDR - Delete Email Messages | Microsoft Defender for Office 365 (+GCC) |

The page says some of these workflows may stop on an Automation approval or prompt task. It does **not** say which ones include an approval step by default. Do not rely on native workflows to enforce approval.

### 1.5 Triggers, webhooks and API triggers

| Topic | What the documentation says | Source (read) |
|---|---|---|
| Trigger types (automation rules) | Email, schedule, **webhook**, incident (new XDR incident), **approval task** (for example, a task is approved). The trigger history covers 72 hours. | https://docs.xdr.security.cisco.com/Content/Automate/triggers.htm |
| Webhook rule | Pick or create a webhook. Conditions can match an HTTP header or a body value. The rule can target only **non-atomic** workflows. Payload limit **1 MB** (larger returns 413). Content types: `application/json`, `application/json;charset=utf-8`, `application/x-www-form-urlencoded`, `application/xml`. At most **25 workflow executions per minute** from a rule. | Search-result summary of https://docs.xdr.security.cisco.com/Content/Automate/rules-webhook.htm and the Webhooks page (re-read both before relying on these limits in production) |
| API trigger | The Automation API can list workflows and execute workflows via API. The exact run-workflow path could not be confirmed from the fetched content: **UNVERIFIED**. | https://developer.cisco.com/docs/cisco-xdr/automation-api-guide/ |

### 1.6 Authentication, regions and secrets storage (XDR APIs)

- OAuth2 client credentials: `POST https://visibility.amp.cisco.com/iroh/oauth2/token`, `grant_type=client_credentials`, HTTP Basic with the client ID and secret, `Content-Type: application/x-www-form-urlencoded`. The response carries `expires_in`, and tokens are short-lived. Calls then use `Authorization: Bearer <token>`. **VERIFIED**: https://developer.cisco.com/docs/cisco-xdr/authentication/
- Regional bases (**VERIFIED**, https://developer.cisco.com/docs/cisco-xdr/getting-started/):
  - Platform (IROH): `https://visibility.amp.cisco.com/iroh/`, `https://visibility.eu.amp.cisco.com/iroh/`, `https://visibility.apjc.amp.cisco.com/iroh/`
  - Private Intelligence (CTIA): `https://private.intel.amp.cisco.com/ctia/`, `https://private.intel.eu.amp.cisco.com/ctia/`, `https://private.intel.apjc.amp.cisco.com/ctia/`
  - Automation: `https://automate.us.security.cisco.com/api/`, `https://automate.eu.security.cisco.com/api/`, `https://automate.apjc.security.cisco.com/api/`
- The Automation API is versioned (`/api/v1/`) and needs API client scope `ao`. **VERIFIED**: https://developer.cisco.com/docs/cisco-xdr/automation-api-guide/
- Rate limits for the XDR platform APIs: **not documented** on the pages read. Treat them as unknown: honor `429` and `Retry-After` when present, and back off exponentially otherwise.
- In this repo every credential comes through `xdr_response.secrets` (environment variables or a vault backend), never from code or config files. Inside XDR Automation, credentials live in account keys and Secure Strings.

---

## 2. Per-integration verification

The columns in every table: **Op** is what the brief needs. **Kind** is R (read), SC (state-changing) or V (verify-state). **Status** is VERIFIED or UNVERIFIED. **Source** is the page that was read.

### 2.1 `cisco_xdr` (Cisco XDR platform)

Auth: OAuth2 client credentials (section 1.6). Rate limits: not documented. Native action: this *is* XDR. Response actions run through each module's response capability.

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| Get token | R | `POST https://visibility.amp.cisco.com/iroh/oauth2/token` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/authentication/ |
| Verdicts for observables | R | `POST /iroh/iroh-enrich/deliberate/observables` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/ |
| Sightings / context | R | `POST /iroh/iroh-enrich/observe/observables` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/ |
| Pivot references | R | `POST /iroh/iroh-enrich/refer/observables` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/enrich-api-guide/ |
| List response actions for observables | R | `POST /iroh/iroh-response/respond/observables` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/response-api-guide/ |
| Trigger a response action (native) | SC | `POST /iroh/iroh-response/respond/trigger/{module-instance-id}/{action-id}?observable_type=..&observable_value=..` returns `data.status` of `success` or `failure`, plus `errors[]` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/trigger-an-action/ |
| Incident summary | R | `GET https://visibility.amp.cisco.com/iroh/private-intel/incident/{incident_id}/summary` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/incident-management-api-guide/ |
| Full incident view | R | `GET https://conure.us.security.cisco.com/incidents/{incident-id}` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/get-a-full-summary-of-the-incident-everything-seen-in-xdr/ |
| Create incident (bundle) | SC (not needed) | `POST /iroh/private-intel/bundle/import` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/incident-management-api-guide/ |
| Update incident status | SC (bookkeeping) | `POST https://intel.amp.cisco.com/ctia/incident/{id}/status` with body `{"status": "..."}` (capability `create-incident`). The page documents this on the **Global Intelligence** host. | VERIFIED (global host only) | https://developer.cisco.com/docs/cisco-xdr/global-intelligence-api-incident-update-an-incident-status/ |
| Update incident status on Private Intelligence host | SC | `POST https://private.intel.amp.cisco.com/ctia/incident/{id}/status` | UNVERIFIED (host substitution is an inference) | n/a |
| Create worklog note | SC (bookkeeping) | path not shown on the page read | UNVERIFIED | n/a |
| Search incidents | R | path not shown | UNVERIFIED | n/a |
| Inspect free text for observables | R | path not read | UNVERIFIED | n/a |
| List automation workflows | R | `GET https://automate.us.security.cisco.com/api/v1/workflows` | VERIFIED | https://developer.cisco.com/docs/cisco-xdr/automation-api-guide/ |
| Run workflow via API | SC | not confirmed | UNVERIFIED | n/a |
| List/act on approval tasks via API | R/SC | not confirmed | UNVERIFIED | n/a |
| Verify a native response action | V | The trigger response gives only `success` or `failure`. Real verification must use the underlying product's verify call (sections below). | n/a | n/a |

Response-API actions run with the API client's identity. They must go through the guard like any other state-changing call. Classify the triggered action by `action-id` and module type, and record the module-instance ID in the TemporaryControlRegistry.

### 2.2 `secure_endpoint` (Cisco Secure Endpoint)

Auth: HTTP Basic `base64(client_id:api_key)`. **VERIFIED**: https://developer.cisco.com/docs/secure-endpoint/overview/
Hosts: `https://api.amp.cisco.com`, `https://api.eu.amp.cisco.com`, `https://api.apjc.amp.cisco.com`. **VERIFIED**: https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html
Rate limits: hourly quota, reported in `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`. Going over returns `429`. **VERIFIED** (overview page above). The numeric quota is not stated.
Native XDR action: **yes**, for isolate/un-isolate and block/restore file hash (section 1.4).

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| List computers (find connector GUID by hostname) | R | `GET /v1/computers` | VERIFIED | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html, https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| Get computer | R / V | `GET /v1/computers/{connector_guid}` | VERIFIED (endpoint). The name of the isolation-state field in the response is UNVERIFIED. | https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| Device trajectory | R | `GET /v1/computers/{connector_guid}/trajectory` | VERIFIED | https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| Audit logs | R | `GET /v1/audit_logs` | VERIFIED | https://developer.cisco.com/docs/secure-endpoint/whats-new/ |
| **Isolate host** | SC | `PUT /v1/computers/{connector_guid}/isolation` | VERIFIED | https://www.cisco.com/c/en/us/support/docs/security/secure-endpoint/222226-automate-start-stop-isolation-on-multipl.html |
| **Stop isolation** (release) | SC | `DELETE /v1/computers/{connector_guid}/isolation` | VERIFIED | same |
| Isolation status | V | `GET /v1/computers/{connector_guid}/isolation` | UNVERIFIED (the DevNet page is JavaScript-rendered and returned no content. What's New only records that `OPTIONS` on this path was removed on 2023-08-23) | n/a |
| Events | R | `GET /v1/events` | UNVERIFIED | n/a |
| Block hash (simple custom detection list) | SC | `POST /v1/file_lists/{guid}/files/{sha256}` | UNVERIFIED | n/a |
| Unblock hash | SC | `DELETE /v1/file_lists/{guid}/files/{sha256}` | UNVERIFIED | n/a |
| Verify hash in list | V | `GET /v1/file_lists/{guid}/files/{sha256}` | UNVERIFIED | n/a |

Until the isolation GET is verified, the verify step for isolation returns **UNABLE_TO_VERIFY**, unless it is done through Cisco XDR (sections 2.1 and 1.4). Hash blocking should be **routed through the XDR native "Block File Hashes" response action** (Response API trigger, VERIFIED) rather than direct file-list calls.

### 2.3 `secure_email` (Cisco Secure Email Threat Defense, ETD)

Auth: `POST https://api.{us|de|au|in|ae}.etd.cisco.com/v1/oauth/token` with HTTP Basic `client_id:client_secret`, plus an `x-api-key` header on **all** calls. The JWT is valid for **60 minutes**. **VERIFIED**: https://developer.cisco.com/docs/message-search-api/authentication/
Regional bases: `api.us.etd.cisco.com`, `api.de.etd.cisco.com`, `api.au.etd.cisco.com`, `api.in.etd.cisco.com`, `api.ae.etd.cisco.com`. **VERIFIED**: https://developer.cisco.com/docs/message-search-api/getting-started/
Rate limits: not documented. A search page holds at most 100 messages. The search window is at most 32 days and no further back than 90 days. Remediation takes at most 100 IDs per call.
Native XDR action: **quarantine yes**. **Release no**: XDR lists release only for Defender for Office 365.

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| Message search | R | `POST /v1/messages/search` (a timestamp range is mandatory) | VERIFIED | https://developer.cisco.com/docs/message-search-api/message-search-api/ |
| **Quarantine / move / reclassify** | SC | `POST /v1/messages/move` with body `{"ids": [...<=100], "folder": "quarantine" or "trash" or "inbox", "verdict": "..."}`. `folder` and `verdict` are both mandatory. Per-message `queueSuccess` is returned. 403 means the tenant lacks Microsoft 365 write permission. | VERIFIED | https://developer.cisco.com/docs/message-search-api/remediation-and-reclassification-api/ |
| **Release to inbox** | SC | the same endpoint with `folder: "inbox"` | VERIFIED (endpoint and folder value) | same |
| Verify move | V | `POST /v1/messages/status` returns up to 5 most recent action and verdict statuses for a message | VERIFIED | https://developer.cisco.com/docs/message-search-api/status-api/ |

The restoration rollback for an ETD quarantine is `move` to `inbox`, with the verdict recorded at containment time in the registry `rollback_params`.

### 2.4 `secure_malware_analytics` (formerly Threat Grid)

Auth: an `api_key` **query parameter**. **VERIFIED**: https://www.cisco.com/c/en/us/support/docs/security/umbrella/224873-guide-to-integrating-cisco-secure.html. Our HTTP client must redact query strings in logs and audit records, because the key is in the URL.
Hosts: `https://panacea.threatgrid.com`, `https://panacea.threatgrid.eu`. **VERIFIED** (same page).
Rate limits: not documented. Native XDR action: N/A (read-only enrichment).

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| Domain IOC feed | R | `GET /api/v2/iocs/feeds/domains?api_key=..&after=..&before=..` | VERIFIED | https://www.cisco.com/c/en/us/support/docs/security/umbrella/224873-guide-to-integrating-cisco-secure.html |
| Search submissions by hash/IP/domain | R | `GET /api/v2/search/submissions?q=..` | UNVERIFIED (seen only in a search snippet) | n/a |
| Sample report / threat score | R | not read | UNVERIFIED | n/a |
| State-changing ops | N/A | none needed | N/A | n/a |

### 2.5 `secure_cloud_analytics`

No official API reference page could be fetched. Community and Code Exchange sources mention `https://<tenant>.obsrvbl.com/api/v3/` and an `Authorization: ApiKey ...` header, but those are **not** official reference pages. Secure Cloud Analytics is documented by Cisco as "now part of Cisco XDR", so prefer reading its alerts as XDR incidents and sightings.

| Op | Kind | Method and path | Status |
|---|---|---|---|
| List alerts | R | not read | UNVERIFIED |
| List observations | R | not read | UNVERIFIED |
| Device / source info | R | not read | UNVERIFIED |
| State-changing ops | N/A | none needed | N/A |

### 2.6 `umbrella` (Cisco Umbrella / Secure Access)

Auth: `POST https://api.umbrella.com/auth/v2/token`, `grant_type=client_credentials`, HTTP Basic `key:secret`. The token lasts **3600 s**, and an expired token returns **400**. **VERIFIED**: https://developer.cisco.com/docs/cloud-security/umbrella-api-getting-started/
Rate limits (**VERIFIED**, https://developer.cisco.com/docs/cloud-security/umbrella-api-rate-limits/): token endpoint 20/min per key. Policies (destination lists) 2000/min and 6000/h per key. Investigate 3 req/s on Integration and Tier 1. On `429`, wait 1 s and retry.
Native XDR action: **yes**, block/unblock domain and URL, and IP (IPv4) according to the XDR page.

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| Domain status and categories | R | `GET https://api.umbrella.com/investigate/v2/domains/categorization/{domain}` (scope `investigate.investigate:read`; status -1 malicious, 0 undetermined, 1 safe) | VERIFIED | https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-investigate-investigate-api-domain-status-and-categorization-get-domain-status-and-categorization/ |
| Security scores | R | `GET /investigate/v2/security/name/{domain}` | UNVERIFIED (search snippet only) | n/a |
| Risk score | R | `GET /investigate/v2/domains/risk-score/{domain}` | UNVERIFIED (search snippet only) | n/a |
| List destination lists | R | `GET https://api.umbrella.com/policies/v2/destinationlists` | VERIFIED | https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-destination-lists-overview/ |
| List destinations in a list | V | `GET /policies/v2/destinationlists/{destinationListId}/destinations` | VERIFIED | same |
| **Block domain/URL** (add to block list) | SC | `POST /policies/v2/destinationlists/{destinationListId}/destinations` with body `[{"destination": "...", "comment": "..."}]`. At most 500 per call. Scope `policies.destinations:write`. | VERIFIED | https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-policies-destination-lists-api-destinations-add-destinations-to-destination-list/ |
| **Unblock** (remove from list) | SC | `DELETE /policies/v2/destinationlists/{destinationListId}/destinations/remove` with body `[<destination id>, ...]`. Integer **destination IDs**, not values, at most 500. | VERIFIED | https://developer.cisco.com/docs/cloud-security/umbrella-api-api-reference-policies-destination-lists-api-destinations-delete-destinations-from-destination-list/ |
| Block IPv4 via destination list | SC | same POST | **UNVERIFIED / CONFLICT**: the destination-lists overview read as "IPv4: allow list yes, block list no", while the XDR Response page lists Umbrella as supporting "Block IP Addresses (IPv4 only)". Do not implement direct Umbrella IP blocking until this is resolved. Use the XDR native action or Meraki. | https://developer.cisco.com/docs/cloud-security/umbrella-api-reference-destination-lists-overview/ |

Idempotency: before adding, `GET` the list destinations and return ALREADY_CONTAINED if the value is present. Record the returned destination ID in the registry, because unblock needs the ID.

### 2.7 `meraki` (Cisco Meraki Dashboard API v1)

Auth: `Authorization: Bearer <API_KEY>` (legacy header: `X-Cisco-Meraki-API-Key`). Base `https://api.meraki.com/api/v1`. **VERIFIED**: https://developer.cisco.com/meraki/api-v1/authorization/
Rate limits: **10 req/s per organization**, shared across all applications, with a burst of +10 in the first second (max 30 in 2 s). `429` comes with `Retry-After`. **VERIFIED**: https://developer.cisco.com/meraki/api-v1/rate-limit/
Native XDR action: **no** Meraki action is listed in the XDR Response catalog.

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| Find client by MAC across org | R | `GET /organizations/{organizationId}/clients/search?mac=..` | VERIFIED | https://developer.cisco.com/meraki/api-v1/get-organization-clients-search/ |
| Get client policy | V | `GET /networks/{networkId}/clients/{clientId}/policy` | VERIFIED | https://developer.cisco.com/meraki/api-v1/get-network-client-policy/ |
| **Block client** / restore | SC | `PUT /networks/{networkId}/clients/{clientId}/policy` with `devicePolicy` one of `Whitelisted`, `Blocked`, `Normal`, `Group policy` (the last needs `groupPolicyId`). Rollback restores the **previous** policy captured before the change. | VERIFIED | https://developer.cisco.com/meraki/api-v1/update-network-client-policy/ |
| Get MX L3 rules | V | `GET /networks/{networkId}/appliance/firewall/l3FirewallRules` | VERIFIED | https://developer.cisco.com/meraki/api-v1/get-network-appliance-firewall-l-3-firewall-rules/ |
| **Block IP at MX** / remove | SC | `PUT /networks/{networkId}/appliance/firewall/l3FirewallRules`. The body is the **complete ordered rule list** and **replaces** the existing set. | VERIFIED | https://developer.cisco.com/meraki/api-v1/update-network-appliance-firewall-l-3-firewall-rules/ |

Safety note: the L3 update replaces the whole rule set, so the adapter must read the rules, insert or remove exactly one tagged rule (the comment carries the idempotency key), write them back, and verify. Two concurrent writers can lose rules. Serialize per network.

### 2.8 `entra` (Microsoft Entra ID through Microsoft Graph)

Auth: OAuth2 client credentials at `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `grant_type=client_credentials`. **VERIFIED** (Microsoft identity platform usage shown on https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp). The Graph scope string `https://graph.microsoft.com/.default` was not read on a fetched page: **UNVERIFIED** detail.
Throttling: `429 Too Many Requests` with `Retry-After`. Wait that many seconds; if the header is missing, use exponential backoff. Limits differ by request type. **VERIFIED**: https://learn.microsoft.com/en-us/graph/throttling
Native XDR action: **disable/restore user, yes**. **Revoke sessions, confirm compromised, remove role: not in the XDR Response catalog.**

| Op | Kind | Method and path (base `https://graph.microsoft.com/v1.0`) | Permission | Status | Source |
|---|---|---|---|---|---|
| Get user (incl. `accountEnabled`, `signInSessionsValidFromDateTime` via `$select`) | R / V | `GET /users/{id or userPrincipalName}` | `User.Read.All`; reading `accountEnabled` needs `User.EnableDisableAccount.All` + `User.Read.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0 |
| Sign-in logs | R | `GET /auditLogs/signIns` (use a `$filter` on time; max page 1000) | `AuditLog.Read.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0 |
| **Disable / enable account** | SC | `PATCH /users/{id or userPrincipalName}` with `{"accountEnabled": false or true}` returns 204. App-only callers also need a sufficiently privileged admin role for sensitive targets. | `User.EnableDisableAccount.All` + `User.Read.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0 |
| **Revoke sign-in sessions** | SC (not reversible) | `POST /users/{id or userPrincipalName}/revokeSignInSessions` resets `signInSessionsValidFromDateTime`. There may be a delay of a few minutes, and it does not affect external users. | `User.RevokeSessions.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0 |
| Confirm user compromised | SC | `POST /identityProtection/riskyUsers/confirmCompromised` with `{"userIds": [...]}` returns 204. Needs an Entra ID P2 license. | `IdentityRiskyUser.ReadWrite.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0 |
| Dismiss risky user (rollback) / get riskyUser | SC / V | not read | n/a | UNVERIFIED | n/a |
| List role assignments | R / V | `GET /roleManagement/directory/roleAssignments?$filter=principalId eq '..'` | `RoleManagement.Read.Directory` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0 |
| **Remove role** | SC | `DELETE /roleManagement/directory/roleAssignments/{id}` returns 204 | `RoleManagement.ReadWrite.Directory` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/unifiedroleassignment-delete?view=graph-rest-1.0 |
| **Restore role** (rollback) | SC | `POST /roleManagement/directory/roleAssignments` with `{roleDefinitionId, principalId, directoryScopeId}` returns 201 | `RoleManagement.ReadWrite.Directory` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignments?view=graph-rest-1.0 |

Rollback for "remove role" must capture `roleDefinitionId`, `principalId` and `directoryScopeId` **before** the delete. Role removal and role restore should always be ELEVATED.

### 2.9 `defender_endpoint` (Microsoft Defender for Endpoint)

Auth: client credentials with scope **`https://api.securitycenter.microsoft.com/.default`**. Some APIs still require the legacy audience and return 403 otherwise, even when called on `api.security.microsoft.com`. The token lasts about 1 h. **VERIFIED**: https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp
Base: `https://api.security.microsoft.com/api`. Rate limits: **100 calls/min and 1,500 calls/h** per API (stated on each page below).
Native XDR action: **yes**, isolate/un-isolate and block/restore file hash.

| Op | Kind | Method and path | Permission | Status | Source |
|---|---|---|---|---|---|
| Get machine | R / V | `GET /api/machines/{id}` (device ID or computer name) | `Machine.ReadWrite.All` (app) | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-by-id |
| **Isolate** | SC | `POST /api/machines/{id}/isolate` with `{"Comment": "...", "IsolationType": "Full" or "Selective" or "UnManagedDevice"}` returns 201 and a MachineAction | `Machine.Isolate` | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine |
| **Release from isolation** | SC | `POST /api/machines/{id}/unisolate` with `{"Comment": "..."}` returns 201. A repeat call returns 400 "Action is already in progress", so map that to ALREADY_CONTAINED or in-progress. | `Machine.Isolate` | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/unisolate-machine |
| Get machine action | V | `GET /api/machineactions/{id}` (`status`, for example `Succeeded`) | `Machine.ReadWrite.All` | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineaction-object |
| List machine actions (idempotency pre-check) | V | `GET /api/machineactions?$filter=machineId eq '..'` (filterable: `id`, `status`, `machineId`, `type`, `requestor`, `creationDateTimeUtc`) | `Machine.ReadWrite.All` | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/get-machineactions-collection |
| **Block indicator** (hash/IP/domain/URL) | SC | `POST /api/indicators` with `indicatorValue`, `indicatorType` (FileSha1, FileMd5, CertificateThumbprint, FileSha256, IpAddress, DomainName, Url), `action` (Alert, Warn, Block, Audit, BlockAndRemediate, AlertAndBlock, Allowed), `title`, `description`, optional `expirationTime`. No CIDR. At most 15,000 active indicators. | `Ti.ReadWrite.All` | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/post-ti-indicator |
| **Remove indicator** | SC | `DELETE /api/indicators/{id}` returns 204 (404 if absent) | `Ti.ReadWrite.All` | VERIFIED | https://learn.microsoft.com/en-us/defender-endpoint/api/delete-ti-indicator-by-id |
| List/get indicators (verify) | V | `GET /api/indicators` | n/a | UNVERIFIED | n/a |
| Restrict app execution, stop and quarantine file, AV scan | SC | not read | n/a | UNVERIFIED | n/a |

Isolation verify: `GET /api/machineactions/{id}` until the status is terminal. Map `Succeeded` to VERIFIED and any other terminal status to NOT_VERIFIED. The full status enum was not read, so treat unknown values as UNABLE_TO_VERIFY. `POST /api/indicators` "submits or updates", so re-submission is idempotent by value. Indicator verify stays UNABLE_TO_VERIFY until the list/get call is verified. The POST response body returns the entity, which is evidence but not an independent read.

### 2.10 `defender_o365` (Microsoft Defender for Office 365)

Auth: Microsoft Graph application permission (section 2.8).
Native XDR action: **yes**, quarantine, release from quarantine, delete (section 1.4).

| Op | Kind | Method and path | Permission | Status | Source |
|---|---|---|---|---|---|
| **Remediate email** (move to junk/inbox/deleted items, soft/hard delete, move to quarantine) | SC | `POST https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate` with `displayName`, `description`, `severity`, `action` (`moveToJunk`, `moveToInbox`, `hardDelete`, `softDelete`, `moveToDeletedItems`, `moveToQuarantine`; the last needs the header `Prefer: include-unknown-enum-members`), `remediateSendersCopy`, and `analyzedEmails[{networkMessageId, recipientEmailAddress}]`. Returns 202 with a `Location` pointing to the Defender action center. **Application permission only. Global cloud only.** | `SecurityAnalyzedMessage.ReadWrite.All` | VERIFIED (beta page; the page also links a v1.0 version, not read) | https://learn.microsoft.com/en-us/graph/api/security-analyzedemail-remediate?view=graph-rest-beta |
| Rollback | SC | the same endpoint with `action: moveToInbox` (the docs name this as the false-positive path). `hardDelete` cannot be rolled back, so never propose it as containment. | same | VERIFIED | same |
| List/search analyzed emails | R | not read | n/a | UNVERIFIED | n/a |
| Release from quarantine (quarantine API) | SC | no Graph endpoint read | n/a | UNVERIFIED | n/a |
| Verify remediation | V | The 202 `Location` is a **portal** URL, not an API. Possible path: `runHuntingQuery` (section 2.12) against post-delivery email tables, but those table names were not read. | n/a | UNVERIFIED, so UNABLE_TO_VERIFY | n/a |

### 2.11 `intune` (Microsoft Intune through Graph)

Requires an active Intune license (stated on each page). Native XDR action: **none listed**.

| Op | Kind | Method and path | Permission | Status | Source |
|---|---|---|---|---|---|
| Get managed device (includes `deviceActionResults[].actionState`, `complianceState`, `lastSyncDateTime`) | R / V | `GET /deviceManagement/managedDevices/{managedDeviceId}` | `DeviceManagementManagedDevices.Read.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0 |
| **Remote lock** | SC (no API undo read) | `POST /deviceManagement/managedDevices/{managedDeviceId}/remoteLock` returns 204 | `DeviceManagementManagedDevices.PrivilegedOperations.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-remotelock?view=graph-rest-1.0 |
| Retire / wipe | SC (destructive) | not read | n/a | UNVERIFIED. These are out of scope for automated containment in any case. | n/a |
| Sync device / Defender scan | SC | not read | n/a | UNVERIFIED | n/a |

Remote-lock verify: read `deviceActionResults` for an entry whose `actionName` is the lock action and whose `actionState` is done. The exact `actionName` string was not read, so the result is UNABLE_TO_VERIFY until it is.

### 2.12 `microsoft_cloud` (Microsoft Defender XDR / Graph Security, cross-product read)

Scope in this repo: read-only, cross-product context from Microsoft 365 Defender (alerts, advanced hunting). No containment. Native XDR action: N/A.

| Op | Kind | Method and path | Permission | Status | Source |
|---|---|---|---|---|---|
| List alerts | R | `GET https://graph.microsoft.com/v1.0/security/alerts_v2` (`$filter` on assignedTo, classification, determination, createdDateTime, lastUpdateDateTime, severity, serviceSource, status) | `SecurityAlert.Read.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0 |
| Advanced hunting (KQL) | R / V | `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery` with `{"Query": "...", "Timespan": "P1D"}` (default lookback 30 days) | `ThreatHunting.Read.All` | VERIFIED | https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0 |
| List incidents | R | `GET /security/incidents` | n/a | UNVERIFIED | n/a |
| Defender for Cloud / Azure resource actions | SC | not read | n/a | UNVERIFIED | n/a |

### 2.13 `virustotal`

Auth: header `x-apikey`. Base `https://www.virustotal.com/api/v3`. **VERIFIED**: https://docs.virustotal.com/reference/overview, https://docs.virustotal.com/reference/file-info
Rate limits (public API): **4 requests/min, 500/day**. The public API **must not be used in commercial products or services**. Over the quota: `429` `QuotaExceededError`. **VERIFIED**: https://docs.virustotal.com/reference/public-vs-premium-api
Privacy: "Any IoC submitted or queried via the API will be scanned and added to the VirusTotal dataset". Never send internal hostnames, internal URLs or anything that could be personal data. The adapter must allow-list the observable types it sends (public hashes, external domains and IPs only). Source: https://docs.virustotal.com/reference/domain-info

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| File report | R | `GET /files/{sha256 or sha1 or md5}` | VERIFIED | https://docs.virustotal.com/reference/file-info |
| Domain report | R | `GET /domains/{domain}` | VERIFIED | https://docs.virustotal.com/reference/domain-info |
| IP report | R | `GET /ip_addresses/{ip}` | VERIFIED | https://docs.virustotal.com/reference/ip-info |
| URL report | R | `GET /urls/{id}` where id is the URL-safe base64 of the URL **without padding** | VERIFIED | https://docs.virustotal.com/reference/url-info |
| State-changing ops | N/A | none | N/A | n/a |

### 2.14 `alienvault_otx` (LevelBlue OTX)

Base `https://otx.alienvault.com`. Indicator details: `GET /api/v1/indicators/{type}/{value}/{section}`. **VERIFIED**: https://otx.alienvault.com/assets/static/external_api.html
The API key header is `X-OTX-API-KEY`. It is **VERIFIED from the vendor's official SDK source** (https://raw.githubusercontent.com/AlienVault-OTX/OTX-Python-SDK/master/OTXv2.py), not from the reference page, which did not name the header. Rate limits: **not documented**. Native XDR action: N/A (read-only).

| Op | Kind | Path | Sections | Status |
|---|---|---|---|---|
| IPv4 | R | `/api/v1/indicators/IPv4/{ip}/{section}` | general, reputation, geo, malware, url_list, passive_dns, http_scans | VERIFIED |
| IPv6 | R | `/api/v1/indicators/IPv6/{ip}/{section}` | general, reputation, geo, malware, url_list, passive_dns | VERIFIED |
| Domain | R | `/api/v1/indicators/domain/{domain}/{section}` | general, geo, malware, url_list, passive_dns, whois, http_scans | VERIFIED |
| Hostname | R | `/api/v1/indicators/hostname/{hostname}/{section}` | general, geo, malware, url_list, passive_dns, http_scans | VERIFIED |
| File | R | `/api/v1/indicators/file/{hash}/{section}` | general, analysis | VERIFIED |
| URL | R | `/api/v1/indicators/url/{url}/{section}` | general, url_list | VERIFIED |

### 2.15 `hibp` (Have I Been Pwned v3)

Base `https://haveibeenpwned.com/api/v3`. Header `hibp-api-key` (a 32-character hex key). A **user-agent is mandatory**: requests without one get 403. Rate limits depend on the subscription. `429` returns a `retry-after` header in seconds. **VERIFIED**: https://haveibeenpwned.com/API/v3. Attribution under the Creative Commons licence is required when breach data is shown. Native XDR action: N/A.

| Op | Kind | Path | Status |
|---|---|---|---|
| Breaches for account | R | `GET /breachedaccount/{account}` (add `?truncateResponse=false` for full detail) | VERIFIED |
| Pastes for account | R | `GET /pasteaccount/{account}` | VERIFIED |
| All breaches (no key) | R | `GET /breaches` | VERIFIED |
| Pwned Passwords range | R | `GET https://api.pwnedpasswords.com/range/{first5sha1}` | VERIFIED. **Not used**: this repo never handles passwords. |

Privacy: the email address is personal data. Send only the investigated account, never bulk lists, and redact it in logs per the redaction policy.

### 2.16 `splunk` (optional, disabled by default)

Splunk is never a hard dependency. With `enabled: false`, the adapter reports health `UNKNOWN` and enrichment proceeds without it. Native XDR action: N/A.

| Op | Kind | Method and path | Status | Source |
|---|---|---|---|---|
| Create search job | R | `POST https://{host}:8089/services/search/jobs` returns an `sid` (use `earliest_time` and `latest_time`) | VERIFIED | https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/9.4/rest-api-tutorials/creating-searches-using-the-rest-api |
| Get results | R | `GET /services/search/jobs/{sid}/results?output_mode=json` | VERIFIED | same |
| Auth (REST) | n/a | basic auth, or a session key from `/services/auth/login` sent as `Authorization: Splunk {sessionKey}` | VERIFIED | same |
| Auth with Splunk bearer authentication tokens | n/a | not read | UNVERIFIED | n/a |
| Streaming export | R | `/services/search/v2/jobs/export` | UNVERIFIED (search snippet only) | n/a |
| Send audit event (HEC) | write (not containment) | `POST https://{host}:8088/services/collector/event` with `Authorization: Splunk <hec_token>` | VERIFIED | https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.4/get-data-with-http-event-collector/http-event-collector-examples |

HEC writes are audit forwarding, not containment. They are not guarded by approval, but they **must** pass through the central redaction before sending. Rate limits: not documented on the pages read.

---

## 3. Verify-state call for every state-changing operation

| Integration | State change | Verify call | Verify status |
|---|---|---|---|
| secure_endpoint | isolate / stop isolation | `GET /v1/computers/{guid}/isolation` | UNVERIFIED, so UNABLE_TO_VERIFY |
| secure_endpoint | block / unblock hash | `GET /v1/file_lists/...` | UNVERIFIED |
| secure_email | quarantine / release (move) | `POST /v1/messages/status` | VERIFIED |
| umbrella | add / remove destination | `GET /policies/v2/destinationlists/{id}/destinations` | VERIFIED |
| meraki | client policy | `GET /networks/{networkId}/clients/{clientId}/policy` | VERIFIED |
| meraki | L3 firewall rule | `GET /networks/{networkId}/appliance/firewall/l3FirewallRules` | VERIFIED |
| entra | disable / enable | `GET /users/{id}?$select=accountEnabled` | VERIFIED |
| entra | revoke sessions | `GET /users/{id}?$select=signInSessionsValidFromDateTime` (must be at or after the action time) | VERIFIED (endpoint; the property is named on the revoke page) |
| entra | confirm compromised | GET riskyUser | UNVERIFIED |
| entra | remove / restore role | `GET /roleManagement/directory/roleAssignments?$filter=principalId eq '..'` | VERIFIED |
| defender_endpoint | isolate / unisolate | `GET /api/machineactions/{id}` | VERIFIED |
| defender_endpoint | add / remove indicator | `GET /api/indicators` | UNVERIFIED |
| defender_o365 | remediate | (portal action center only) | UNVERIFIED, so UNABLE_TO_VERIFY |
| intune | remote lock | `GET /deviceManagement/managedDevices/{id}` (`deviceActionResults`) | VERIFIED endpoint, but the action name is unverified, so UNABLE_TO_VERIFY |
| cisco_xdr | respond/trigger | the underlying product verify above | n/a |

---

## 4. What Cisco XDR cannot do natively (according to the documentation read)

These are the gaps this repo's deterministic code (`guard.py`, `approval/`, `audit/`, `restoration/`, `verification/`, `dryrun/`) has to fill. "Not documented" means it was not found on the pages read. It does not prove the feature is absent, but we must not rely on it.

1. **Cryptographically bound approvals.** Request Approval records Approve or Reject (with quorum and expiry). Nothing documented binds the decision to the evidence snapshot, the action parameters, the targets or the workflow version, or guarantees that the executed action equals the approved one. Our HMAC token covers all of these.
2. **Human-only approvers.** Assignees are chosen by email or role. No documented check rejects service, automation or AI identities, and none stops a workflow's own executor (the default assignee) from approving its own request.
3. **Per-asset approval levels.** Quorum is per task. Nothing documented raises the approval level (ELEVATED, elevated role, N distinct approvers) when a target matches a critical-asset class, or shows a structured impact warning.
4. **A separate release approval with purpose binding.** Restore workflows exist (section 1.4), but no documented control requires a second, release-purpose approval or ties it to the controls actually created.
5. **Registry of controls the automation created.** No documented inventory of active temporary controls with rollback parameters. Our TemporaryControlRegistry is the only source for release packages, and closing an incident never removes controls.
6. **Tamper-evident audit.** Run history, worklog and a 72-hour trigger history exist. No hash-chained or append-only audit, and no verifier, is documented.
7. **Dry run.** No documented simulation mode that guarantees no state-changing call is reached.
8. **Independent post-action verification.** Native response workflows report success or failure (`respond/trigger` returns only `success` or `failure`). No documented re-read of the target state that yields VERIFIED, NOT_VERIFIED or UNABLE_TO_VERIFY.
9. **Partial-containment semantics.** No documented per-action result model (SUCCESS, ALREADY_CONTAINED, FAILED, SKIPPED, DRY_RUN) or overall CONTAINED, PARTIALLY_CONTAINED or CONTAINMENT_FAILED.
10. **Integration actions missing from the native Response catalog:**
    - Entra: revoke sign-in sessions, confirm compromised, remove privileged role (only disable and restore user are native).
    - Meraki: client block and MX L3 block (no Meraki actions listed).
    - Intune: remote lock and other device actions.
    - Secure Email Threat Defense: **release** (native release lists only Defender for Office 365).
    - Splunk search and HEC audit forwarding. VirusTotal, OTX and HIBP enrichment: these integrations do not appear in the Response catalog, and native XDR enrichment modules for them were not verified.
11. **Rate-limit and health aggregation.** No documented health model across integrations (CONNECTED, DEGRADED, UNAVAILABLE, AUTH_FAILED, RATE_LIMITED, UNKNOWN), and no rule that a failed enrichment source must not block a recommendation backed by other evidence.
12. **A published workflow schema.** Export is JSON, but no schema is documented, so validation of exported workflows in CI has to be structural and best-effort.

Where XDR **does** have a native action (section 1.4), the brief prefers it. Use the VERIFIED Response API (`respond/observables`, then `respond/trigger`) as the execution path, **wrapped by our guard and token check**, and verify with the product's own read call.

---

## 5. Open items (to promote UNVERIFIED to VERIFIED)

- Secure Endpoint: isolation GET, file-list (simple custom detection) CRUD, events. The DevNet pages are JavaScript-rendered, so read them in a browser and record the URL.
- Cisco XDR: run-workflow path, approval-task endpoints, worklog note path, incident search, and the Private Intelligence incident status host. Read the downloadable OpenAPI specs (`automation-oas3.json`, Incident Management OAS) linked from the API guides.
- Umbrella: resolve the IPv4 block-list conflict (section 2.6). Read the security-score and risk-score pages.
- Defender for Endpoint: indicator list/get, and the machine-action status enum.
- Defender for Office 365: a verify path (hunting table names), quarantine release API.
- Intune: the remoteLock `actionName` value in `deviceActionResults`.
- Entra: riskyUser get/dismiss, and the Graph `.default` scope string.
- Secure Malware Analytics and Secure Cloud Analytics: official API references.
- Splunk: bearer-token auth, and v2 export.
