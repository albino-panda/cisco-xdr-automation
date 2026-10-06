## CONTAINMENT RESULT `XDR-83921`

- **Overall:** PARTIALLY_CONTAINED
- **Package:** `0f1e2d3c4b5a69788796a5b4c3d2e1f0`
- **Approval token:** `9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3`
- **Started:** 2026-01-15T12:05:00Z
- **Finished:** 2026-01-15T12:06:00Z

| Status | Action | Integration | Verification | Notes |
|---|---|---|---|---|
| SUCCESS | `isolate_endpoint TH-LT-1047` | secure_endpoint | VERIFIED | control registered |
| FAILED | `block_domain evil.example.com` | umbrella | - | ATTENTION; error RATE\_LIMITED: rate limited after 3 attempts; escalation Block evil.example.com manually in Umbrella and record it |
| SKIPPED | `revoke_sessions jsmith@example.com` | entra | - | REJECTED\_BY\_ANALYST |

### Attention

- block\_domain evil.example.com failed: RATE\_LIMITED

Temporary controls registered: 1 (release needs a separate release approval)
