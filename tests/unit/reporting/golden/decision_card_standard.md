## CRITICAL INCIDENT `XDR-83921`

**Potential ransomware**

- **Endpoint:** `TH-LT-1047`
- **User:** `jsmith@example.com`
- **Risk:** 97/100 (CRITICAL)
- **Confidence:** 94%
- **Blast radius:** 1 endpoint, 1 user, 1 domain

### Primary evidence

- **[1]** `entra`: jsmith@example.com signed in from 203.0.113.50 (unfamiliar location) (ref `signin-0001`)
- **[2]** `secure_endpoint`: Ransomware detection Win.Ransomware.Example on TH-LT-1047 (sha256 aaaaaaaa...) (ref `se-evt-0001`)
- **[3]** `umbrella`: TH-LT-1047 resolved evil.example.com (category: malware) (ref `umb-0001`)

### Recommended containment

- [ ] `isolate_endpoint TH-LT-1047` **STANDARD**, risk 97, confidence 94%, via `secure_endpoint`, evidence [2, 3]
- [ ] `block_domain evil.example.com` **STANDARD**, risk 90, confidence 92%, via `umbrella`, evidence [3]
- [ ] `revoke_sessions jsmith@example.com` **STANDARD**, risk 80, confidence 75%, via `entra`, evidence [1]

Package `0f1e2d3c4b5a69788796a5b4c3d2e1f0`, workflow `ransomware 1.0.0`, evidence sha256 `65331dd11ad3`, approve before `2026-01-15T16:00:00Z`

**[APPROVE ALL]** **[APPROVE SELECTED]** **[REQUEST MORE INVESTIGATION]** **[REJECT]**
