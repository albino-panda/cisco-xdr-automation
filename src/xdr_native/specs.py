"""The attack types built on the shared incident response workflow (``incident.py``).

Each spec restates, for a workflow that runs inside Cisco XDR, the design of the same name in
``workflows/<design>/`` and ``src/xdr_response/workflows/``: which containment it may propose and when.

What carries over and what does not:

- An indicator (domain, URL, address, file hash) is proposed for blocking on its own XDR verdict.
  ``MALICIOUS`` proposes it only when a module rates it malicious, ``SUSPICIOUS`` also when one rates
  it suspicious.
- The designs tie actions on an endpoint, an account or a message to evidence this workflow cannot
  collect inside XDR (sign-in logs, process trees, mailbox rules). Here such an action is proposed when
  an indicator of the incident reaches the rule's risk, or when a person chose the asset. The label of
  the rule tells the approver the condition of the design, and ``checks`` says what to look at.
- Disabling an account is left out by default (``excluded``) wherever the design asks for more than a
  compromise indicator. Clear the *Excluded Actions* input to propose it.
- Containment with no Cisco XDR response action (terminate a process, quarantine a file, remove a
  role or a persistence item) is listed as a manual step.

``Email Bombing`` (design ``mail-bombing``) is not here: it has its own workflow (``email_bombing.py``).
"""
from __future__ import annotations

from .incident import Rule, Spec

MALICIOUS, SUSPICIOUS = 90, 60

_ADDRESSES = ("ip", "ipv6")
_NETWORK = ("domain", "url", "ip", "ipv6")
_PASSWORD = "Reset the password and re-register MFA of a confirmed compromised account in Entra ID."
_PROCESS = "Terminate the malicious process from the endpoint product console when it is still running."
_SHARED_IP = "Whether an address is a VPN exit, a carrier NAT, a CDN or a cloud provider before it is blocked."
_SIGN_INS = "The account's sign-ins, MFA prompts and risk detections in Entra ID: this workflow does not read them."
_PREVALENCE = "How many endpoints hold the file: a hash that is common in the estate may be a legitimate tool."


def _disable(label: str) -> Rule:
    return Rule("disable_user", MALICIOUS, label)


SPECS: tuple[Spec, ...] = (
    Spec(
        design="account-takeover", name="Account Takeover",
        purpose="Responds to a sign-in by an attacker who uses valid credentials or a stolen session.",
        rules=(
            Rule("revoke_sessions", SUSPICIOUS, "revoke every sign-in session of an account that shows a compromise indicator"),
            _disable("disable a compromised account that is privileged or was used again after its sessions were revoked"),
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint of the compromised account that has an active malicious detection"),
            Rule("block_indicator", MALICIOUS, "block a sign-in source address rated malicious that is not shared infrastructure", _ADDRESSES),
        ),
        manual=(_PASSWORD,),
        checks=(_SIGN_INS, _SHARED_IP,
                "Inbox rules, mail forwarding and OAuth consents created after the suspicious sign-in."),
        excluded=("disable_user",),
    ),
    Spec(
        design="bec", name="Business Email Compromise",
        purpose="Responds to a mailbox used for payment fraud or impersonation.",
        rules=(
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of a tenant mailbox with compromise or abuse evidence"),
            _disable("disable a mailbox account with compromise evidence and ongoing abuse (malicious rule, risky consent, fraud sent)"),
            Rule("quarantine_email", SUSPICIOUS, "quarantine a delivered fraudulent message"),
            Rule("block_indicator", SUSPICIOUS, "block a sender domain that impersonates the organisation or was flagged, unless its reputation is clean", ("domain",)),
            Rule("isolate_endpoint", MALICIOUS, "isolate an investigated endpoint with an active malicious detection"),
        ),
        manual=("Remove malicious inbox and forwarding rules and revoke risky OAuth consents in Exchange Online and Entra ID.",
                _PASSWORD),
        checks=("Mailbox rules, forwarding and OAuth consents of the mailbox.",
                "Whether payment details changed or money moved: call finance by phone, not by email.",
                "A new look-alike domain has no verdict yet. Set Block Unrated Indicators to propose it."),
        excluded=("disable_user",),
        context_types=_ADDRESSES,
    ),
    Spec(
        design="c2", name="Command and Control",
        purpose="Responds to an endpoint that talks to attacker infrastructure.",
        rules=(
            Rule("block_indicator", SUSPICIOUS, "block a destination rated malicious, or suspicious with a command-and-control category"),
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint that reached a malicious destination and shows malicious activity itself"),
        ),
        manual=("Terminate the process that holds the connection, from the endpoint product console.",),
        checks=(_SHARED_IP, "Which process on the endpoint made the connection.",
                "Other endpoints that reached the same destination: see the sightings and pivot in XDR."),
        context_types=("sha256",),
    ),
    Spec(
        design="cloud-compromise", name="Cloud Compromise",
        purpose="Responds to abuse of Microsoft cloud identities, application credentials, OAuth consent and directory roles.",
        rules=(
            Rule("revoke_sessions", SUSPICIOUS, "revoke every session and refresh token of an account that shows a compromise indicator or consented to a risky application"),
            _disable("disable a compromised account that is privileged or was used to plant cloud persistence"),
            Rule("block_indicator", MALICIOUS, "block a sign-in source address rated malicious that is not shared infrastructure", _ADDRESSES),
        ),
        manual=("Remove unauthorized privileged role assignments, application credentials and OAuth consents in Entra ID.",
                _PASSWORD),
        checks=(_SIGN_INS, "Role assignments, new application credentials and consents made by or to the account.",
                _SHARED_IP),
        excluded=("disable_user",),
    ),
    Spec(
        design="credential-dumping", name="Credential Dumping",
        purpose="Responds to credential dumping on an endpoint (LSASS, SAM or NTDS access, or a dumping tool).",
        rules=(
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint where credential access is confirmed"),
            Rule("block_hash", MALICIOUS, "block a credential-dumping tool hash rated malicious and seen on 10 endpoints or fewer"),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of an account whose credentials were exposed on the endpoint"),
            _disable("disable an exposed account that is privileged or confirmed compromised"),
        ),
        manual=("Reset the passwords of the accounts signed in on the endpoint, privileged ones first.",
                "When a domain controller is involved, rotate the krbtgt key twice."),
        checks=(_PREVALENCE, "Which accounts were signed in on the endpoint: their credentials are exposed.",
                "Legitimate security and backup tools also read credential memory."),
        excluded=("disable_user",),
    ),
    Spec(
        design="dns-tunneling", name="DNS Tunneling",
        purpose="Responds to data or command traffic hidden in DNS queries.",
        rules=(
            Rule("block_indicator", SUSPICIOUS, "block the tunnel parent domain once, never each random subdomain", ("domain",)),
            Rule("isolate_endpoint", MALICIOUS, "isolate a client endpoint whose process queried a confirmed tunnel parent domain"),
        ),
        manual=("Terminate the process that issues the queries, from the endpoint product console.",),
        checks=("Give the parent domain, not the generated subdomains.",
                "A DNS server forwards the queries of its clients: find the client behind the resolver.",
                "Approved DNS tools: put their domains on Never Act On."),
        context_types=("ip", "ipv6", "sha256"),
    ),
    Spec(
        design="exfiltration", name="Data Exfiltration",
        purpose="Responds to a large or unusual outbound transfer.",
        rules=(
            Rule("block_indicator", SUSPICIOUS, "block a destination that receives the data and is rated malicious or suspicious", ("domain", "ip", "ipv6")),
            Rule("isolate_endpoint", MALICIOUS, "isolate a source endpoint while its transfer is still running and shows exfiltration evidence"),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of an account that drives the transfer and is compromised"),
            _disable("disable an account that drives the transfer and is compromised, or that an insider-risk detection names"),
        ),
        manual=("Preserve proxy, firewall and endpoint logs for the impact assessment before isolation ends.",),
        checks=("Whether the destination is a cloud storage service the company uses.",
                "Whether the transfer is still running.",
                "An insider case: involve legal and HR before the account is disabled."),
        excluded=("disable_user",),
    ),
    Spec(
        design="lateral-movement", name="Lateral Movement",
        purpose="Responds to suspected lateral movement between hosts (remote desktop, SMB, WinRM, WMI, remote services).",
        rules=(
            Rule("isolate_endpoint", MALICIOUS, "isolate a source or target host with malicious activity, or the source of confirmed movement"),
            Rule("block_hash", MALICIOUS, "block a transferred tool hash rated malicious and seen on 50 endpoints or fewer"),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of the account used for confirmed lateral movement"),
            _disable("disable a movement account the identity provider rates high risk or confirms compromised"),
            Rule("block_indicator", SUSPICIOUS, "block an external address rated malicious or suspicious that a movement account signed in from", _ADDRESSES),
        ),
        manual=("Reset the password of the account used to move, and of service accounts seen on the hosts.",),
        checks=("The movement path: source host, target hosts and the account used.",
                "Administrators and management servers connect to many hosts legitimately.", _PREVALENCE),
        excluded=("disable_user",),
    ),
    Spec(
        design="malicious-powershell", name="Suspicious PowerShell",
        purpose="Responds to an endpoint alert about PowerShell, another script host or a signed system binary used as a proxy.",
        rules=(
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint where a retrieved payload landed, or where a malicious detection follows contact with a malicious destination"),
            Rule("block_hash", MALICIOUS, "block a malicious payload hash seen on 10 endpoints or fewer"),
            Rule("block_indicator", MALICIOUS, "block a download or command-and-control destination rated malicious"),
        ),
        manual=("Terminate the script host or system binary process when its activity is malicious.",),
        checks=("Use of PowerShell or a system binary alone is not malicious: read the command line and the parent process.",
                _PREVALENCE),
        context_types=("user",),
    ),
    Spec(
        design="malware", name="Malware",
        purpose="Responds to a malware detection on an endpoint.",
        rules=(
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint where a malicious file executed and the agent did not remediate it"),
            Rule("block_hash", MALICIOUS, "block a malicious hash fleet-wide when it is seen on 10 endpoints or fewer"),
            Rule("block_indicator", MALICIOUS, "block a malicious download or callback destination an affected endpoint contacted"),
        ),
        manual=(_PROCESS, "Quarantine the file from the endpoint product console when the agent did not remediate it."),
        checks=("Whether the file executed or was only detected and quarantined: a remediated detection needs no isolation.",
                _PREVALENCE),
    ),
    Spec(
        design="mfa-fatigue", name="MFA Fatigue",
        purpose="Responds to MFA push bombing: many prompts for one user, then one approved.",
        rules=(
            Rule("revoke_sessions", SUSPICIOUS, "revoke every session of a user who approved a prompt after repeated rejected or unanswered prompts"),
            _disable("disable the account when the session went further (mailbox rules, role grants, consents, a privileged account)"),
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint tied to the compromise that shows a malicious or suspicious detection"),
            Rule("block_indicator", SUSPICIOUS, "block a public address that sent rejected prompts or that the user signed in from after the approval", _ADDRESSES),
        ),
        manual=(_PASSWORD, "Move the user to number matching or a phishing-resistant method."),
        checks=("How many prompts were sent and whether one was approved: read the Entra ID sign-in log.",
                "What the session did after the approval.", _SHARED_IP),
        excluded=("disable_user",),
    ),
    Spec(
        design="password-spray", name="Password Spray",
        purpose="Responds to a password spray: one source, many accounts, many failed sign-ins.",
        rules=(
            Rule("block_indicator", SUSPICIOUS, "block a spray source address that is neither shared infrastructure nor an internal endpoint", _ADDRESSES),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of an account with a successful sign-in from a spray source"),
            _disable("disable an account whose successful sign-in from a spray source was followed by suspicious activity"),
        ),
        manual=("Reset the password of every account the spray signed in to.",),
        checks=("Which accounts had a successful sign-in from the source: only those need their sessions revoked.",
                _SHARED_IP),
        excluded=("disable_user",),
    ),
    Spec(
        design="persistence", name="Persistence",
        purpose="Responds to an attacker foothold on an endpoint (Run key, scheduled task, service, WMI subscription).",
        rules=(
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint whose malicious persistence item is backed by active malicious execution"),
            Rule("block_hash", MALICIOUS, "block the hash of a malicious persisted binary seen on 10 endpoints or fewer"),
        ),
        manual=("Remove the persistence item (Run key, startup item, scheduled task, service, WMI subscription) on the endpoint.",
                _PROCESS),
        checks=("What the persistence item starts and who created it.", _PREVALENCE),
    ),
    Spec(
        design="phishing", name="Phishing",
        purpose="Responds to a reported or detected phishing message.",
        rules=(
            Rule("quarantine_email", SUSPICIOUS, "quarantine every delivered copy of a confirmed phishing message"),
            Rule("block_indicator", SUSPICIOUS, "block a URL or domain carried by the phishing messages that is rated malicious or suspicious", ("url", "domain")),
            Rule("block_hash", SUSPICIOUS, "block an attachment hash rated malicious or suspicious"),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of a recipient who clicked and then signed in or was flagged"),
            _disable("disable an account whose compromise after the click is confirmed or strongly indicated"),
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint with malicious activity after the click"),
        ),
        manual=("Search the mail product for other copies of the campaign (same sender, subject or URL) and add their message IDs.",),
        checks=("Who received the message and who clicked.",
                "Whether a recipient entered credentials: then treat it as an account takeover.",
                "A URL on a shared service (file sharing, forms): block the URL, not the domain."),
        excluded=("disable_user",),
        context_types=_ADDRESSES,
    ),
    Spec(
        design="privilege-escalation", name="Privilege Escalation",
        purpose="Responds to an account, a service principal or a process that gained more privilege than expected.",
        rules=(
            Rule("revoke_sessions", SUSPICIOUS, "revoke every session of an account that made or received an anomalous privilege change"),
            _disable("disable a compromised identity used for or elevated by an anomalous change"),
            Rule("isolate_endpoint", MALICIOUS, "isolate the originating endpoint where a malicious detection or file shows the escalation"),
        ),
        manual=("Remove the anomalous privileged role assignment or group membership in Entra ID or Active Directory.",),
        checks=("Who made the change, from which device, and whether a change request covers it.", _SIGN_INS),
        excluded=("disable_user",),
        context_types=("sha256",),
    ),
    Spec(
        design="ransomware", name="Ransomware",
        purpose="Responds to suspected ransomware (mass file modification, shadow-copy deletion, a known ransomware file).",
        rules=(
            Rule("isolate_endpoint", SUSPICIOUS, "isolate an endpoint with ransomware activity of its own or that holds the spreading payload"),
            Rule("block_hash", MALICIOUS, "block a payload hash confirmed by reputation and seen on 50 endpoints or fewer"),
            Rule("block_indicator", SUSPICIOUS, "block a destination rated malicious or suspicious that an affected host contacted"),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of an account on an affected host or confirmed compromised"),
            _disable("disable an account the identity provider confirms compromised or rates high risk"),
            Rule("quarantine_email", SUSPICIOUS, "quarantine delivered messages of the originating campaign rated malicious"),
        ),
        manual=("Do not power off affected hosts: isolation keeps the memory evidence.",
                "Check that backup servers and consoles are unaffected and that offline copies exist."),
        checks=("Which hosts show encryption and which only hold the payload.",
                "Domain controllers, hypervisors and backup servers: put them on Protected Assets so they need elevated approval.",
                _PREVALENCE),
        excluded=("disable_user",),
    ),
    Spec(
        design="suspicious-authentication", name="Suspicious Authentication",
        purpose="Responds to a sign-in that does not look like the account owner (unusual country, new device, anonymising proxy, impossible travel).",
        rules=(
            Rule("revoke_sessions", SUSPICIOUS, "revoke every session of an account whose recent successful sign-in carries enough indicators"),
            _disable("disable a likely compromised account that is privileged, reused after revocation or shows persistence"),
            Rule("block_indicator", MALICIOUS, "block a public sign-in source address a source rates malicious, unless it is shared infrastructure", _ADDRESSES),
        ),
        manual=(_PASSWORD,),
        checks=(_SIGN_INS, "Whether the user is travelling or uses a new device: ask them through a known channel.",
                _SHARED_IP),
        excluded=("disable_user",),
    ),
    Spec(
        design="threat-intel-sweep", name="Threat Intelligence Sweep",
        purpose="Sweeps the estate for given indicators of compromise (file hash, address, domain, URL).",
        rules=(
            Rule("block_hash", SUSPICIOUS, "block a rated file hash indicator fleet-wide"),
            Rule("block_indicator", SUSPICIOUS, "block a rated domain, URL or address indicator"),
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint where a rated file indicator ran or that reached a rated network indicator"),
            Rule("quarantine_email", SUSPICIOUS, "quarantine a delivered message that carries a rated indicator"),
            Rule("revoke_sessions", SUSPICIOUS, "revoke the sessions of an account that signed in from a rated address"),
        ),
        manual=("Quarantine the file on endpoints where it is still present, from the endpoint product console.",),
        checks=("The source and confidence of the indicators.",
                "Where each indicator was seen: read the sightings below and pivot in XDR.",
                "An indicator no module rates is not proposed unless Block Unrated Indicators is true."),
    ),
    Spec(
        design="unauthorized-rmm", name="Unauthorized Remote Access Tool",
        purpose="Responds to a remote monitoring and management or remote desktop tool on an endpoint.",
        rules=(
            Rule("block_hash", SUSPICIOUS, "block the binary of a flagged remote access tool when it is seen on 50 endpoints or fewer"),
            Rule("block_indicator", SUSPICIOUS, "block a relay or broker destination of the tool that is rated malicious or suspicious", ("domain", "ip", "ipv6")),
            Rule("isolate_endpoint", MALICIOUS, "isolate an endpoint with an active remote session whose operator is untrusted"),
        ),
        manual=("Terminate and uninstall the remote access tool on the endpoint.",),
        checks=("Approved remote access tools: put their hashes and relay domains on Never Act On.",
                "Vendor relay addresses are shared: block the domain, not the address.",
                "Who installed the tool and whether a help-desk call or an email flood came first."),
        context_types=("user", "email"),
    ),
    Spec(
        design="vulnerability-exploitation", name="Vulnerability Exploitation",
        purpose="Responds to an exploitation attempt against an exposed service or a workstation.",
        rules=(
            Rule("block_indicator", SUSPICIOUS, "block an external source of the exploitation rated malicious or suspicious", _ADDRESSES),
            Rule("isolate_endpoint", MALICIOUS, "isolate a targeted host where exploitation succeeded"),
        ),
        manual=("Apply the virtual patch for the exploited path on the WAF or IPS, then patch the asset.",),
        checks=("Whether exploitation succeeded or was only attempted: an attempt alone never isolates.",
                "Other servers the same source reached.", _SHARED_IP),
        context_types=("url", "sha256"),
    ),
    Spec(
        design="web-attacks", name="Web Application Attacks",
        purpose="Responds to injection, exploit, scanning or web shell activity against an internet-facing application.",
        rules=(
            Rule("block_indicator", SUSPICIOUS, "block an external source address that attacked the application and is rated malicious or suspicious", _ADDRESSES),
            Rule("isolate_endpoint", MALICIOUS, "isolate a web server with a confirmed web shell; scanning or exploit attempts alone never isolate"),
        ),
        manual=("Block the exploited application URL on the WAF (edge virtual patch).",
                "Remove the web shell and rotate the application's secrets after forensics."),
        checks=("Isolating a production web server causes an outage: put it on Protected Assets.",
                "Whether a web shell is confirmed on the server.", _SHARED_IP),
        context_types=("url", "sha256"),
    ),
)

BY_DESIGN = {spec.design: spec for spec in SPECS}
