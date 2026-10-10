"""Which incidents start which workflow: the incident response rules to create in Cisco XDR.

Cisco XDR does not import these rules from this repository. They are created by hand under
**Automate > Rules**, one per workflow. This module holds what each rule matches and renders
``xdr/RULES.md``, so the guide cannot drift from the designs.

The techniques and title words restate the automatic triggers of the designs in
``src/xdr_response/workflows/<design>/definition.py``. The order is the priority of those triggers: a
specific attack type is tried before a broad one, and a rule stops the ones below it.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleGuide:
    """What the incident response rule of one workflow matches."""

    workflow: str
    #: MITRE ATT&CK techniques. A sub-technique reported by a product matches its parent listed here.
    techniques: tuple[str, ...]
    #: Words or phrases in the incident title (case-insensitive, anywhere in the title).
    titles: tuple[str, ...]
    #: Empty when a rule is enough. Otherwise why the workflow is mostly started by a person.
    note: str = ""


#: In rule order: the first rule that matches starts its workflow and stops the others.
GUIDES: tuple[RuleGuide, ...] = (
    RuleGuide("Ransomware", ("T1486", "T1490"),
              ("ransom", "mass file modification", "shadow cop", "files encrypted", "mass encryption", "file encryption")),
    RuleGuide("MFA Fatigue", ("T1621",),
              ("mfa fatigue", "mfa push", "push bombing", "push spam", "mfa bombing", "mfa spam"),
              "Needs identity alerts in XDR. The public catalog does not list Entra ID as a detection source."),
    RuleGuide("DNS Tunneling", ("T1071.004", "T1572"), ("dns tunnel", "dns-tunnel", "tunneling over dns")),
    RuleGuide("Lateral Movement", ("T1021", "T1570"),
              ("lateral movement", "remote logon", "remote service", "admin share", "winrm", "remote desktop", "psexec",
               "east-west")),
    RuleGuide("Credential Dumping", ("T1003",),
              ("credential dump", "credential theft", "lsass", "ntds", "security account manager")),
    RuleGuide("Data Exfiltration", ("T1041", "T1048", "T1567"),
              ("exfiltration", "data theft", "data loss", "large outbound transfer", "large upload", "unusual upload")),
    RuleGuide("Email Bombing", ("T1667",),
              ("email bomb", "mail bomb", "subscription bomb", "mail flood"),
              "No connected product detects a mail flood. Start it from a playbook task or by hand with the mailbox."),
    RuleGuide("Unauthorized Remote Access Tool", ("T1219",),
              ("remote access tool", "remote access software", "remote desktop tool", "rmm tool",
               "remote monitoring and management")),
    RuleGuide("Web Application Attacks", ("T1505.003", "T1595.002"),
              ("web shell", "webshell", "sql injection", "command injection", "cross-site scripting", "path traversal",
               "file inclusion", "web application attack", "waf"),
              "Needs a web application firewall or IPS as a source. None is connected."),
    RuleGuide("Vulnerability Exploitation", ("T1190", "T1203"),
              ("exploit attempt", "exploitation attempt", "exploit signature", "exploit prevention",
               "remote code execution"),
              "Network exploit signatures need an IPS or WAF source. Endpoint exploit prevention alerts do arrive."),
    RuleGuide("Cloud Compromise", ("T1098.001", "T1098.003", "T1528"),
              ("oauth", "consent grant", "illicit consent", "app registration", "service principal", "client secret",
               "directory role"),
              "Needs identity and cloud alerts in XDR."),
    RuleGuide("Privilege Escalation", ("T1068", "T1548", "T1098"),
              ("privilege escalation", "privileged role", "admin role assigned", "role assignment", "privileged group",
               "domain admins", "uac bypass", "elevation of privilege")),
    RuleGuide("Suspicious PowerShell", ("T1059.001", "T1027", "T1218"),
              ("powershell", "pwsh", "mshta", "rundll32", "regsvr32", "certutil", "wscript", "cscript", "bitsadmin",
               "living off the land")),
    RuleGuide("Persistence", ("T1547.001", "T1053.005", "T1543.003", "T1546.003", "T1176.001"),
              ("run key", "autorun", "scheduled task", "new service", "service install", "startup folder",
               "browser extension", "persistence")),
    RuleGuide("Command and Control", ("T1071.001", "T1573", "T1568.002"),
              ("beacon", "command and control", "command-and-control", "c2 traffic", "c2 communication", "c2 callback",
               "c2 server", "c2 domain")),
    RuleGuide("Business Email Compromise", ("T1534", "T1114.003", "T1656"),
              ("business email compromise", "bank detail", "wire transfer", "payment change", "payment request",
               "forwarding rule", "inbox rule")),
    RuleGuide("Password Spray", ("T1110.003",), ("password spray", "password-spray", "password spraying"),
              "Needs identity alerts in XDR."),
    RuleGuide("Phishing", ("T1566",), ("phish",)),
    RuleGuide("Suspicious Authentication", ("T1078",),
              ("suspicious sign-in", "suspicious login", "unusual sign-in", "anomalous sign-in", "anonymous ip",
               "tor exit", "unmanaged device", "leaked credential", "unusual location", "new country"),
              "Needs identity alerts in XDR."),
    RuleGuide("Account Takeover", ("T1078.004", "T1539"),
              ("risky sign-in", "high-risk sign-in", "impossible travel", "atypical travel", "unfamiliar sign-in",
               "account takeover", "token replay"),
              "Needs identity alerts in XDR."),
    RuleGuide("Malware", ("T1204.002", "T1105"), ("malware", "malicious file")),
    RuleGuide("Threat Intelligence Sweep", (), (),
              "No rule. Start it by hand or from a playbook task with the indicators to sweep."),
)


def render() -> str:
    """``xdr/RULES.md``."""
    lines = [
        "# Incident rules and playbook tasks",
        "",
        "Generated by `tools/xdr_native/build.py` from `src/xdr_native/rules.py`. Do not edit by hand.",
        "",
        "Your connected products raise the detections and Cisco XDR correlates them into incidents. Nothing is",
        "built per workflow for that. What you create in XDR is one **Incident Response Rule** per workflow, which",
        "matches an incident and starts the workflow, and one **playbook task** per workflow, which lets an analyst",
        "start it with the observables they select.",
        "",
        "Cisco XDR does not import rules from this repository: create them by hand.",
        "",
        "## Create a rule",
        "",
        "For each workflow below that has techniques or title words:",
        "",
        "1. **Automate > Rules**, add a rule of type **Incident Response Rule**.",
        "2. Choose **Priority Rule** and leave **Stop processing subsequent rules** on, so one incident starts one",
        "   workflow.",
        "3. Keep the default **Status** condition. Without it the rule fires again on every status change.",
        "4. **Add Condition** for the techniques and the title words of the row, joined by **ANY**. With the Status",
        "   condition that needs the **Advanced** mode: `Status AND (technique OR title word OR ...)`.",
        "5. Under **Apply to selected workflows**, pick the workflow. Leave its inputs on their defaults",
        "   (*Dry Run* true) until the workflow passed its tests in [README.md](README.md).",
        "6. Save, then drag the rule to its position in the **Priority Incident Rules** table.",
        "",
        "Not confirmed: Cisco's documentation does not list the properties a condition can use, nor the operators.",
        "If the title or the techniques cannot be selected, or there is no \"contains\" comparison, note what the",
        "**Property** and **Comparison** lists offer so this guide can be corrected.",
        "",
        "## Tune first, then act",
        "",
        "Set the workflow input *Audit Only* to true in the rule while you tune its conditions. The workflow then",
        "writes its assessment to the incident worklog and raises no approval task. When the rule starts the right",
        "incidents, set *Audit Only* back to false and keep *Dry Run* true: approvals are then asked for and only",
        "reported. Set *Dry Run* to false last.",
        "",
        "## Rules, in priority order",
        "",
        "| # | Workflow | MITRE techniques | Incident title contains | Note |",
        "|---|---|---|---|---|",
    ]
    for number, guide in enumerate(GUIDES, 1):
        lines.append(f"| {number} | `{guide.workflow}` | {', '.join(guide.techniques) or 'none'} | "
                     f"{', '.join(guide.titles) or 'none'} | {guide.note} |")
    lines += [
        "",
        "A rule-started run proposes an endpoint or an account only when an indicator of the incident is rated high",
        "enough. Indicators are proposed on their own verdict.",
        "",
        "## Add the workflows to a playbook",
        "",
        "An analyst who starts a workflow from a playbook task chooses the observables, and the workflow then",
        "proposes actions for exactly those. This is the main way to act on an endpoint or an account.",
        "",
        "1. **Administration > Playbooks**, **Tasks** tab: create a task per workflow. In the **New Task** drawer",
        "   turn on **Include Workflow**, choose the workflow in **Workflow name**, and click **Add task**.",
        "2. **Editor** tab: add the tasks to a custom playbook. Cisco managed playbooks and tasks are read-only, so",
        "   work on a duplicate.",
        "3. Assign the playbook to incidents with an assignment rule on the same page. It can take a few minutes",
        "   before an incident shows the playbook.",
        "",
        "Source: Cisco XDR help, *Playbooks* and *Playbook task*. The step that places a task in a phase of the",
        "playbook is not described on the pages read.",
        "",
    ]
    return "\n".join(lines)
