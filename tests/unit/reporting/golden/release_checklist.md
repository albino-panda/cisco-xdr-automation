## RELEASE APPROVAL REQUIRED `XDR-83921`

**Release temporary controls for XDR-83921**

- **Temporary controls to release:** 3

### Evidence

- **[1]** `temporary_control_registry`: 3 ACTIVE temporary controls for XDR-83921 (ref `registry`)

### Release checklist

- [ ] Restore endpoint connectivity: TH-LT-1047 **STANDARD**, via `secure_endpoint`, restores `XDR-83921:isolate_endpoint:TH-LT-1047`
- [ ] Remove temporary Umbrella domain block: evil.example.com **STANDARD**, via `umbrella`, restores `XDR-83921:block_domain:evil.example.com`
- [ ] Restore privileged role assignment: jsmith@example.com/62e90394-69f5-4237-9190-012177145e10 **ELEVATED**, via `entra`, restores `XDR-83921:remove_privileged_role:jsmith@example.com/62e90394-69f5-4237-9190-012177145e10`

> **WARNING: ELEVATED APPROVAL REQUIRED**
>
> - **Action:** `restore_privileged_role` `jsmith@example.com/62e90394-69f5-4237-9190-012177145e10`
> - **Reason:** restore\_privileged\_role always requires elevated approval
>
> Requires an approver holding the elevated approval role. The action is not blocked.

Controls not listed here stay ACTIVE. Closing the incident never removes controls.

Package `1a2b3c4d5e6f708192a3b4c5d6e7f809`, workflow `ransomware 1.0.0`, evidence sha256 `9fb35d578e07`, approve before `2026-01-15T20:00:00Z`

**[APPROVE RELEASE]** **[REJECT]**
