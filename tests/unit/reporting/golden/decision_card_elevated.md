## HIGH INCIDENT `XDR-83921`

**Domain controller beaconing to evil.example.com**

- **Endpoint:** `DC-01`
- **User:** `jsmith@example.com`
- **Risk:** 88/100 (CRITICAL)
- **Confidence:** 70%
- **Blast radius:** 1 endpoint, 1 user, 1 domain, 1 other indicator

### Primary evidence

- **[1]** `cisco_xdr`: DC-01 contacted evil.example.com over HTTPS (ref `xdr-sighting-0001`)
- **[2]** `entra`: jsmith@example.com signed in from 203.0.113.50 (unfamiliar location) (ref `signin-0001`)
- **[3]** `umbrella`: TH-LT-1047 resolved evil.example.com (category: malware) (ref `umb-0001`)

### Recommended containment

- [ ] `isolate_endpoint DC-01` **ELEVATED**, risk 88, confidence 70%, via `cisco_xdr`, evidence [1]
- [ ] `remove_privileged_role jsmith@example.com/62e90394-69f5-4237-9190-012177145e10` **ELEVATED**, risk 85, confidence 80%, via `entra`, evidence [2]
- [ ] `block_domain evil.example.com` **STANDARD**, risk 90, confidence 92%, via `umbrella`, evidence [3]

### Excluded (allow-listed, not proposed)

- `block_domain example.com`: allowlists.never\_block.domains: example.com

> **WARNING: ELEVATED APPROVAL REQUIRED**
>
> - **Action:** `isolate_endpoint` `DC-01`
> - **Asset:** DC-01 (domain\_controller)
> - **Role:** Active Directory domain controller
> - **Potential impact:** Isolating a domain controller can stop authentication, Group Policy and DNS for the whole domain.
> - **Detail:** isolate\_endpoint on DC-01 (domain controller)
>
> Requires an approver holding the elevated approval role. The action is not blocked.

> **WARNING: ELEVATED APPROVAL REQUIRED**
>
> - **Action:** `remove_privileged_role` `jsmith@example.com/62e90394-69f5-4237-9190-012177145e10`
> - **Reason:** remove\_privileged\_role always requires elevated approval
>
> Requires an approver holding the elevated approval role. The action is not blocked.

Package `0f1e2d3c4b5a69788796a5b4c3d2e1f0`, workflow `ransomware 1.0.0`, evidence sha256 `2eafc69c9756`, approve before `2026-01-15T16:00:00Z`

**[APPROVE ALL]** **[APPROVE SELECTED]** **[REQUEST MORE INVESTIGATION]** **[REJECT]**
