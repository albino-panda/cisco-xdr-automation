# Lateral movement

Phase 3 workflow `lateral-movement` (version 3.0.0, default severity HIGH). Definition:
[`src/xdr_response/workflows/lateral_movement/definition.py`](../../src/xdr_response/workflows/lateral_movement/definition.py),
hooks: [`hooks.py`](../../src/xdr_response/workflows/lateral_movement/hooks.py). It replaces the legacy
specification of this directory (`legacy_id: lateral-movement`); the five legacy scenarios now live as
`legacy-*` fixtures under `tests/fixtures/workflows/lateral-movement/`.

## Purpose

Contain an attacker moving between hosts with remote services: remote desktop, SMB and admin shares,
WinRM, WMI, remote service creation and PsExec-like behaviour, abnormal authentication and unexpected
east-west traffic. The workflow determines the **source host**, the **target hosts**, the
**credential** used, the **responsible process** and the **blast radius**, and recommends one package:
isolate the source, isolate the targets that show malicious activity of their own, revoke (and when
confirmed compromised, disable) the credential, and block the transferred tool and the attacker's
address.

Investigation and recommendation are automatic. The workflow only **recommends**: it never calls a
state-changing adapter method, never builds approval tokens and never enters a guard context. Every
recommended action waits for a human decision in the lifecycle orchestrator.

## Trigger

- **XDR incident rule** (priority 160): the incident reports ATT&CK technique T1021 (any remote
  services sub-technique, such as remote desktop, SMB admin shares or WinRM) or T1570 in
  `trigger.mitre_techniques`.
- **XDR incident rule** (priority 140): the incident title matches `*lateral movement*`,
  `*remote logon*`, `*remote service*`, `*admin share*`, `*winrm*`, `*remote desktop*`, `*psexec*`
  or `*east-west*` (case-insensitive). Secure Cloud Analytics east-west alerts arrive this way, as
  Cisco XDR incidents.
- **Manual**: an analyst starts the workflow for an incident or a host pivot
  (`incident.workflow_id: lateral-movement`).

Ransomware (priority 200) wins when an incident also reports encryption. Lateral-movement (160) wins
over credential-dumping and unauthorized-rmm (150) when their techniques are reported too, so
credential-dumping is reached by hand-off (architecture 14.11.2). The XDR trigger sends only the incident id; the incident is re-read through the VERIFIED
APIs (`tools/deployment/xdr-trigger-workflow.md`).

## Required integrations

These are the expected sources. When one is disabled or failing the run notes it and confidence
drops; it never blocks a recommendation that other evidence supports.

- `secure_endpoint`: endpoint context, detections, process and network events of the source and
  target hosts (`investigate_endpoint`), related endpoints (`search_related_endpoints`) and tool
  prevalence (`search_hash_enterprise`); preferred isolation route.
- `entra`: profile, risk state, risk detections and sign-ins of the accounts used for the movement
  (`investigate_user`, `investigate_authentication`); session revocation and account disable route.

## Optional integrations

- `defender_endpoint`: context of Defender-managed devices; Defender isolation route; indicator route
  for the tool hash and the attacker's address.
- `microsoft_cloud`: Microsoft Defender XDR alerts (typed detections with the vendor's ATT&CK
  techniques) and hunting searches for related endpoints, tool prevalence and authentication.
- `splunk`: enterprise searches for related endpoints, tool prevalence and authentication.
- `cisco_xdr`: hash and IP enrichment, endpoint context and native response actions (native routes
  need operator-configured action ids).
- `meraki`: IP block route at the network edge.
- `virustotal`: second opinion on tool hash and sign-in address reputation (the disclosure policy
  decides what may be sent; internal and documentation-range addresses are never sent).
- `alienvault_otx`: additional reputation for tool hashes and addresses (disclosure policy applies).

## Input data

Incident observables of these types: hostname, endpoint id, user, IPv4 address and SHA-256; plus
`incident.users`, the title, the source and the reported ATT&CK techniques. Everything else is learned
by the investigation: the peer addresses of remote service connections are resolved to hosts, the
hosts that hold a transferred tool are found by prevalence, and the accounts named by the movement
records are investigated.

## Investigation steps

All steps are read-only atomics; a failing step or source is noted and the run continues.

1. `incident_hosts`: `investigate_endpoint` for every incident hostname and endpoint id (endpoint
   record, detections, process events, network connections).
2. `peer_lookup`: `search_related_endpoints` for every host with a connection on a remote service
   port (135, 139, 445, 3389, 5985, 5986).
3. `peer_hosts`: `investigate_endpoint` for the related endpoints that own a peer address of those
   connections.
4. `tool_reputation`: `enrich_hash` for incident hashes and hashes the records name.
5. `tool_spread`: `search_hash_enterprise` (72 hour lookback) for hashes rated malicious or
   suspicious, incident hashes and hashes a malicious detection names.
6. `tool_hosts`: `investigate_endpoint` for the endpoints that hold a flagged tool seen on at most 50
   endpoints (or with unknown prevalence).
7. `accounts`: `investigate_user` for incident users and the accounts named by connections, detections
   and malicious process events (UPNs only).
8. `authentication`: `investigate_authentication` for those accounts (abnormal authentication).
9. `address_reputation`: `enrich_ip` for incident IPv4 addresses and the sign-in addresses of those
   accounts.

## Correlation logic

The framework link rules run over every record of the run within 60 minutes: the same user on several
endpoints, the same endpoint used by several users, the same tool hash or address on two or more
endpoints, process lineage on one endpoint, and a successful sign-in followed by account activity.

The workflow hooks (pure, no adapter access) build the **movement graph** and add one correlation link
per source -> destination edge, with the account that used it. An edge comes from a network connection
record (or a `network` process event) on a remote service port: remote desktop (3389), SMB (445, 139),
WinRM (5985, 5986) or RPC/WMI (135). The peer address is resolved to a host through the endpoint records
of the run; an inbound record makes the peer the source. An unresolved peer counts only on an
`internal` connection or a non-public address. The hooks then derive, each mapped to the record ids it
was computed from:

- **compromised hosts**: a malicious detection, a malicious process event, or a transferred tool rated
  malicious (lateral tool transfer) on the host;
- **confirmed edges**: one end compromised, or a connection the vendor rates malicious; an edge rated
  only suspicious is shown as considered;
- **movement sources**: quiet hosts (no malicious activity of their own) that originated a confirmed
  edge; sanctioned **admin jump hosts** (endpoint group or tag naming a jump host, bastion or
  privileged access workstation) are listed separately and not isolated;
- **clean targets**: destinations of a confirmed edge without activity of their own (blast radius,
  scoped for review);
- **remote execution** (the responsible process on the destination): a service started by the service
  control manager, or a child of the WMI or WinRM provider host; on the source, the process that opened
  the connection;
- **movement accounts** (the credential named by confirmed edges or by malicious records of compromised
  hosts) and **compromised accounts** (a movement account rated high risk, confirmed compromised or with
  a risk detection, or any investigated account with a successful sign-in from an address rated
  malicious);
- **blockable tools** (rated malicious, seen on 50 endpoints or fewer) and **blockable addresses**
  (rated malicious or suspicious and used by a sign-in, an edge or the incident; never an address an
  investigated host owns);
- **unresolved peers**: ends of confirmed edges no endpoint record owns (manual steps).

## Risk calculation

Each recommended target is scored from the records its rule cites (separate `risk_score` and
`confidence_score`, 0-100). Endpoint detections and vendor-flagged process events dominate, and a vendor
category naming lateral movement scores as lateral movement. The hooks add record-backed signals:
lateral movement source and credential used for lateral movement (lateral movement, SUSPICIOUS,
severity 80, citing the edge records and the records that confirm the movement), and an address rated
malicious used by a sign-in (authentication anomaly) or an edge (lateral movement, SUSPICIOUS, severity
70). Identity risk and risk detections score as authentication anomalies. The engine caps reputation,
caps a single source below CRITICAL unless it is a MALICIOUS behavioural detection, adds the
corroboration and critical-asset bonuses and lowers confidence for failed expected sources. Default
category weights. The package shows the highest risk and the mean confidence; every rationale names the
host's role (source or target, protocol, account, process, own activity) and ends with the score
explanation and settings hash.

## Containment recommendations

| Rule | Action (builder) | When | Min risk |
|---|---|---|---|
| `isolate_compromised_hosts` | `isolate_endpoint` (`isolate_secure_endpoint`) | source or target with malicious activity of its own, isolation not forbidden, known to Secure Endpoint (or not to Defender) | 60 |
| `isolate_movement_sources` | `isolate_endpoint` (`isolate_secure_endpoint`) | quiet source of confirmed movement (not a jump host), same route conditions | 60 |
| `isolate_defender_hosts` | `isolate_endpoint` (`isolate_defender_endpoint`) | compromised host or movement source managed by Defender for Endpoint | 60 |
| `revoke_movement_credentials` | `revoke_sessions` (`revoke_entra_sessions`) | movement account or compromised account | 50 |
| `disable_compromised_accounts` | `disable_user` (`disable_entra_user`) | compromised account | 60 |
| `block_transferred_tool` | `block_hash` (`block_hash`) | transferred tool rated malicious, not widespread | 60 |
| `block_attacker_address` | `block_ip` (`block_ip`) | blockable address | 50 |

The package therefore covers the brief: isolate the source, optionally isolate the confirmed targets
(only those with activity of their own), revoke the credential, block the indicators. A second rule for
the same action and target merges its evidence into the first. Below its minimum risk an action is
listed as "considered, not proposed", never hidden. Every action carries numbered evidence that cites
records of the run. Allow-listed and non-public targets are shown as excluded with the reason, never
silently dropped.

### Hand-offs and items not proposed

- Considered, not proposed: a target reached by confirmed movement without activity of its own, a quiet
  admin jump host, a source of east-west traffic rated only suspicious, a host whose endpoint policy does
  not allow isolation, a tool hash seen on more than 50 endpoints and a hash a malicious detection names
  that no source rates.
- Manual steps: an end of confirmed movement that no investigated endpoint owns (`lateral peer
  <address>`): identify the host behind the address and investigate it.
- Hand-offs: `account-takeover` for compromised accounts (review sign-ins, MFA and cloud activity beyond
  the endpoints) and `credential-dumping` for compromised hosts with a credential-access detection.

They appear in the run notes and in the analyst summary ("Considered, deliberately not proposed",
"Manual steps", "Suggested hand-offs"), each with the record ids that show it. A hand-off is a
suggestion only: it starts nothing and never changes the package (architecture 14.10.1).

## Approval requirements

Every action needs human approval before it runs, including session revocation; there is no automatic
approval and no score can skip it. AI and automation principals can never approve. ELEVATED approval (a
lead with the elevated approver role) applies when a target is a critical asset (for example a domain
controller, hypervisor or production server reached by the movement, or a Domain Admins or other
privileged account used for it, by host pattern, group, tag, role or address range), when an action type
is always elevated, or when a blast-radius cap is exceeded (for example more than five isolations in one
fan-out package). The decision card shows the ELEVATED warning with the asset, role and potential
impact; a critical asset is never skipped silently. The analyst may approve all, approve a selection (for
example the source and the credential first) or reject.

## Containment execution

After approval the lifecycle orchestrator executes the approved actions automatically through the
execution guard, on the routes chosen at recommendation time (native Cisco XDR response first when
configured, else the product adapter: Secure Endpoint or Defender isolation, Entra revocation and
disable, Defender or native hash block, Meraki or Defender address block). Rejected or unselected
actions are recorded as rejected by the analyst and never run. Dry run (the default) simulates the
package and changes nothing.

## Verification

Every executed action is verified automatically by reading the target state back. Defender isolation,
Entra account state and Meraki firewall rules are verifiable. Secure Endpoint isolation reports
`UNABLE_TO_VERIFY` until its isolation-state read is verified (docs/integrations.md); the result says so
and the analyst checks the console. A result that cannot be read back is reported as such, never as
verified.

## Rollback

Isolation, hash and address blocks and account disable are temporary controls in the restoration
registry. Removing them needs a separate human release approval (release endpoint, unblock hash, unblock
address, enable user); nothing expires on its own. Session revocation is not reversible: the user signs
in again. Before release, the analyst resets the credentials used for the movement (including
on-premises accounts) and removes remote services and tools left on the targets. Isolation release codes
are never copied into notes or notifications; they stay in the vendor console.

## Failure handling

- A failed or disabled source becomes a degraded source in the notes and lowers confidence; the
  recommendation stands on the remaining evidence (for example the credential is still revoked from the
  Secure Endpoint movement records when Entra is unavailable, but it is not disabled without identity
  evidence).
- A step whose expression or atomic fails is noted and skipped; partial results stay. An unresolved peer
  is a manual step, never a guessed isolation target.
- An action without an executable route is reported as unrouted for manual handling.
- A failed execution is reported as FAILED (partial containment), never retried silently; the other
  approved actions still run.

## MITRE mapping

| Tactic | Technique | Sub-technique | Rules | Why |
|---|---|---|---|---|
| TA0008 Lateral Movement | T1021 Remote Services | T1021.001 Remote Desktop Protocol | isolation | remote desktop connections between investigated hosts |
| TA0008 Lateral Movement | T1021 Remote Services | T1021.002 SMB/Windows Admin Shares | isolation | SMB connections to admin shares, tool copies |
| TA0008 Lateral Movement | T1021 Remote Services | T1021.006 Windows Remote Management | isolation | WinRM connections and WinRM provider children on the destination |
| TA0008 Lateral Movement | T1570 Lateral Tool Transfer | none | isolation of tool hosts, hash block | a tool rated malicious present on further hosts |
| TA0002 Execution | T1569 System Services | T1569.002 Service Execution | isolation | remote service creation (PsExec-like behaviour) on the destination |
| TA0002 Execution | T1047 Windows Management Instrumentation | none | isolation | children of the WMI provider host on a destination reached over RPC |
| TA0001 Initial Access | T1078 Valid Accounts | none | session revocation, account disable, address block | the credential used for the movement and its abnormal sign-ins |

No account sub-technique is mapped: the records do not show whether the credential is a domain, local
or cloud account, so none is forced.

## Testing instructions

- Scenarios (format of architecture 14.5.2): `tests/fixtures/workflows/lateral-movement/`, the minimum
  set of 14.5.3, four edge cases (admin jump host, clean target not isolated, unresolved peer,
  Defender-managed source) and the five migrated `legacy-*` scenarios. They run automatically in dry
  run and simulated live through the orchestrator:
  `python -m pytest -q -p no:cacheprovider tests/simulation/test_workflow_scenarios.py -k "lateral-movement or lateral_movement"`.
- Unit and lifecycle tests of the definition, rules and hooks: `tests/workflows/lateral_movement/`
  (`python -m pytest -q -p no:cacheprovider tests/workflows/lateral_movement`).
- One scenario by hand:
  `python tools/simulator/simulate.py --workflow lateral-movement --scenario tp-approve-all --check`
  (add `--live` for the simulated live run).
- README check: `python tools/validation/check_workflow_readmes.py --workflow lateral-movement`.

## Known limitations

- Real Secure Endpoint trajectory events and Defender or Splunk hunting rows stay generic records (no
  event field schema is verified), so the source -> destination graph is built only from typed network
  connection records (simulated sources today). On real tenants hosts are isolated on their own typed
  detections (Microsoft Defender XDR alerts) and tool prevalence; a quiet source with no detection of its
  own needs the analyst until the event schema is verified.
- A peer address is resolved to a host only through the endpoint records of the run; an address two
  hosts claim or no investigated host owns is listed as a manual step, not isolated.
- Remote WMI and DCOM share the RPC port, so a connection on port 135 is labelled RPC/WMI; WMI is named
  only when the destination records a child of the WMI provider host.
- Targets reached without malicious activity of their own, quiet admin jump hosts (recognised by endpoint
  group or tag names), hosts whose policy forbids isolation and tool hashes seen on more than 50
  endpoints are not recommended; they are listed as considered with their records, and the analyst
  contains them by hand if needed.
- Revocation ends cloud sessions only: on-premises Active Directory credentials, Kerberos tickets and
  local accounts used for the movement are not reset by any VERIFIED write; credential resets stay
  analyst follow-up.
- Remote services and scheduled tasks created on destinations are not removed (no VERIFIED write for
  persistence removal); the persistence workflow or the analyst handles them.
- Secure Cloud Analytics east-west alerts are read only as Cisco XDR incidents (its API is UNVERIFIED),
  so they trigger the workflow but add no records of their own.
- A tenant whose only executor is Cisco XDR native response needs product-pinned builders; such actions
  are reported as unrouted for manual handling.
