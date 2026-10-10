"""Python steps that run inside XDR's Execute Python Script activity.

Contract of the activity: arguments arrive as strings in ``sys.argv[1:]`` and every output is a global
name listed in the activity's script queries. The scripts use the standard library only, never receive
a credential and never call the network. ``run`` executes one of them the same way for the unit tests.
"""
from __future__ import annotations

import sys
from typing import Any

#: Outputs (all strings): mailboxes_json, has_mailboxes, mailbox_count, skipped_count.
SELECT_MAILBOXES = r'''
import json, re, sys
candidates = sys.argv[1]
protected_raw = sys.argv[2]
max_mailboxes = int(float(sys.argv[3] or "5"))
address = re.compile(r"^[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}$")
protected = set(p.strip().lower() for p in re.split(r"[,;\s]+", protected_raw) if p.strip())
rows, seen, skipped = [], set(), 0
for line in candidates.splitlines():
    value = line.strip().lower()
    if not value or value in seen or not address.match(value):
        continue
    seen.add(value)
    if len(rows) >= max_mailboxes:
        skipped += 1
        continue
    domain = "@" + value.split("@", 1)[1]
    is_protected = value in protected or domain in protected
    rows.append({"mailbox": value, "protected": "true" if is_protected else "false"})
mailboxes_json = json.dumps(rows)
has_mailboxes = "true" if rows else "false"
mailbox_count = str(len(rows))
skipped_count = str(skipped)
'''

#: Outputs: search_body, window_start, window_end.
BUILD_SEARCH = r'''
import datetime, json, sys
mailbox = sys.argv[1].strip().lower()
lookback = max(5, min(int(float(sys.argv[2] or "60")), 1440))
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
start = now - datetime.timedelta(minutes=lookback)
fmt = "%Y-%m-%dT%H:%M:%SZ"
window_start = start.strftime(fmt)
window_end = now.strftime(fmt)
search_body = json.dumps({"timestamp": [window_start, window_end], "pageSize": 100,
                          "recipient": mailbox, "directions": ["incoming"]})
'''

#: Outputs: state_json, search_body, has_more, message_count.
MERGE_PAGE = r'''
import json, re, sys
state = json.loads(sys.argv[1] or "{}")
status_code = str(sys.argv[2]).strip()
raw_response = sys.argv[3]
body = json.loads(sys.argv[4])
max_messages = int(float(sys.argv[5] or "1000"))
state.setdefault("messages", [])
state.setdefault("buried", [])
state.setdefault("pages", 0)
state.setdefault("error", "")
state.setdefault("truncated", False)
topics = [
    ("credential", r"password|passcode|account recovery|recover your account|reset your"),
    ("security alert", r"security alert|new sign[- ]?in|new log[- ]?in|new device|unusual (activity|sign)|suspicious (activity|sign)"),
    ("mfa", r"verification code|one[- ]time|\bmfa\b|\b2fa\b|two[- ]factor|multi[- ]factor|authenticat"),
    ("payment", r"wire transfer|invoice|payment|bank|purchase|order confirm|receipt|refund"),
    ("lure", r"docusign|shared a (file|document)|voicemail|microsoft 365|office 365"),
]
has_more = "false"
try:
    if status_code != "200":
        raise ValueError("HTTP " + status_code)
    response = json.loads(raw_response or "{}")
    known = set(m[0] for m in state["messages"])
    for msg in ((response.get("data") or {}).get("messages") or []):
        mid = msg.get("id")
        if not mid or mid in known:
            continue
        if len(state["messages"]) >= max_messages:
            state["truncated"] = True
            break
        known.add(mid)
        sender = str(msg.get("fromAddress") or msg.get("envelopeFrom") or "")
        domain = sender.rsplit("@", 1)[1].lower().strip("> ") if "@" in sender else "unknown"
        verdict = msg.get("verdict") or {}
        label = str(verdict.get("latestVerdict") or verdict.get("originalVerdict") or "noVerdict").lower()
        subject = str(msg.get("subject") or "")
        topic = ""
        for name, pattern in topics:
            if re.search(pattern, subject, re.IGNORECASE):
                topic = name
                break
        state["messages"].append([mid, domain, label, topic, str(msg.get("timestamp") or "")])
        if topic and len(state["buried"]) < 15:
            state["buried"].append({"id": mid, "topic": topic, "subject": subject[:120], "from": sender[:120],
                                    "time": str(msg.get("timestamp") or ""), "verdict": label})
    state["pages"] += 1
    next_token = response.get("nextPageToken")
    if next_token and state["pages"] >= 50:
        state["truncated"] = True
    elif next_token and not state["truncated"] and len(state["messages"]) < max_messages:
        body["pageToken"] = next_token
        has_more = "true"
    elif next_token:
        state["truncated"] = True
except Exception as exc:
    state["error"] = "ETD message search failed on page " + str(state["pages"] + 1) + ": " + str(exc)[:200]
state_json = json.dumps(state)
search_body = json.dumps(body)
message_count = str(len(state["messages"]))
'''

#: Outputs: qualifies, elevated, card, summary, move_chunks, move_count, verify_sample, package_digest.
ASSESS = r'''
import hashlib, json, sys
state = json.loads(sys.argv[1] or "{}")
mailbox = sys.argv[2]
protected = str(sys.argv[3]).lower() == "true"
min_messages = int(float(sys.argv[4] or "30"))
min_domains = int(float(sys.argv[5] or "10"))
min_clean = int(float(sys.argv[6] or "50"))
dry_run = str(sys.argv[7]).lower() != "false"
folder = (sys.argv[8] or "quarantine").strip().lower()
verdict = (sys.argv[9] or "graymail").strip().lower()
window_start, window_end = sys.argv[10], sys.argv[11]
elevated_above = int(float(sys.argv[12] or "500"))
trusted = set(d.strip().lower().lstrip("@") for d in (sys.argv[13] or "").replace(";", ",").split(",") if d.strip())
if folder not in ("quarantine", "junk", "trash"):
    raise SystemExit("Containment Folder must be quarantine, junk or trash (delete is permanent and is refused)")
if verdict not in ("spam", "malicious", "phishing", "neutral", "graymail", "bec", "scam"):
    raise SystemExit("Reclassify Verdict is not an ETD verdict: " + verdict)
messages = state.get("messages") or []
error = state.get("error") or ""
truncated = bool(state.get("truncated"))
total = len(messages)
domains, verdicts = {}, {}
for mid, domain, label, topic, when in messages:
    domains[domain] = domains.get(domain, 0) + 1
    verdicts[label] = verdicts.get(label, 0) + 1
clean = verdicts.get("neutral", 0) + verdicts.get("graymail", 0)
clean_share = int(round(100.0 * clean / total)) if total else 0
bad = ("malicious", "phishing", "bec", "scam")
kept = [m for m in messages if (m[3] and m[2] not in bad) or m[1] in trusted]
kept_ids = set(m[0] for m in kept)
move_ids = [m[0] for m in messages if m[0] not in kept_ids]
qualifies = total >= min_messages and len(domains) >= min_domains and clean_share >= min_clean and bool(move_ids)
reasons = []
if protected:
    reasons.append("the mailbox is on the protected list")
if len(move_ids) > elevated_above:
    reasons.append(str(len(move_ids)) + " messages is above the limit of " + str(elevated_above) + " for standard approval")
if truncated:
    reasons.append("the search stopped at the collection limit, so the flood is larger than what is listed")
elevated = bool(reasons)
buried = state.get("buried") or []
hidden_topics = sorted(set(b["topic"] for b in buried if b["verdict"] not in bad))
bad_count = sum(verdicts.get(b, 0) for b in bad)
risk = 70 + (10 if set(hidden_topics) & {"credential", "security alert", "mfa"} else 0) + (10 if bad_count else 0) + (10 if total >= 3 * min_messages else 0)
risk = min(risk, 100)
confidence = 70 + (10 if clean_share >= 80 and len(domains) >= 2 * min_domains else 0) - (20 if error else 0) - (10 if truncated else 0)
package_digest = hashlib.sha256("\n".join(sorted(move_ids)).encode()).hexdigest()[:16]
top = sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
verdict_text = ", ".join(k + " " + str(v) for k, v in sorted(verdicts.items(), key=lambda kv: (-kv[1], kv[0]))) or "none"
facts = ("`" + mailbox + "`: " + str(total) + " inbound messages from " + str(len(domains)) + " sender domains between "
         + window_start + " and " + window_end + " UTC, " + str(clean_share) + "% neutral or graymail")
if qualifies:
    lines = ["## Email bombing: decision needed", ""]
    if elevated:
        lines += ["**ELEVATED APPROVAL REQUIRED** because " + "; ".join(reasons) + ".", ""]
    lines += ["**Mode: " + ("DRY RUN. Approving moves nothing; the workflow only reports what it would do." if dry_run else "LIVE. Approving moves the messages.") + "**", "",
              "**Proposed action:** move " + str(len(move_ids)) + " messages of the flood to *" + folder + "* in Secure Email Threat Defense and reclassify them as *" + verdict + "*. Package `" + package_digest + "`.", "",
              "Risk " + str(risk) + "/100. Confidence " + str(confidence) + "/100.", "",
              "**Evidence**", "",
              "1. " + str(total) + " inbound messages to `" + mailbox + "` between " + window_start + " and " + window_end + " UTC (threshold " + str(min_messages) + ").",
              "2. " + str(len(domains)) + " different sender domains (threshold " + str(min_domains) + "). Largest: " + ", ".join("`" + d + "` " + str(n) for d, n in top) + ".",
              "3. " + str(clean_share) + "% of the messages are neutral or graymail (threshold " + str(min_clean) + "%). Verdicts: " + verdict_text + "."]
    if error:
        lines.append("4. Degraded source: " + error + ". The figures above cover the pages read before the failure.")
    lines += ["", "**Not moved (" + str(len(kept)) + "):** messages from trusted sender domains and messages a flood is used to hide."]
    for b in buried:
        if b["id"] in kept_ids:
            lines.append("- [" + b["topic"] + "] " + b["subject"] + " (from " + b["from"] + ", " + b["time"] + ")")
    if hidden_topics:
        lines += ["", "**Check the account:** the flood contains " + ", ".join(hidden_topics) + " messages. Review this user's sign-ins, MFA prompts and mailbox rules. This workflow does not change the account."]
    lines += ["", "**Choices:** *Approve* runs the proposed action. *Reject* and *More investigation* change nothing."]
    card = "\n".join(lines)
    summary = facts + ". Proposed: move " + str(len(move_ids)) + " messages to " + folder + " (package " + package_digest + ")."
else:
    card = ""
    why = error if (error and not total) else "below the flood thresholds (" + str(min_messages) + " messages, " + str(min_domains) + " sender domains, " + str(min_clean) + "% neutral or graymail)"
    summary = facts + ". No action proposed: " + why + "."
chunks = []
for i in range(0, len(move_ids), 100):
    part = move_ids[i:i + 100]
    chunks.append({"body": json.dumps({"ids": part, "folder": folder, "verdict": verdict}), "count": str(len(part))})
move_chunks = json.dumps(chunks if qualifies else [])
move_count = str(len(move_ids) if qualifies else 0)
verify_sample = json.dumps([{"body": json.dumps({"id": mid})} for mid in move_ids[:5]] if qualifies else [])
qualifies = "true" if qualifies else "false"
elevated = "true" if elevated else "false"
'''

#: Outputs: tally_json.
RECORD_MOVE = r'''
import json, sys
tally = json.loads(sys.argv[1] or "{}")
status_code = str(sys.argv[2]).strip()
raw_response = sys.argv[3]
count = int(float(sys.argv[4] or "0"))
tally.setdefault("queued", 0)
tally.setdefault("failed", 0)
tally.setdefault("errors", [])
def flags(node, found):
    if isinstance(node, dict):
        if isinstance(node.get("queueSuccess"), bool):
            found.append(node["queueSuccess"])
        for value in node.values():
            flags(value, found)
    elif isinstance(node, list):
        for value in node:
            flags(value, found)
    return found
if status_code == "200":
    try:
        found = flags(json.loads(raw_response or "{}"), [])
    except Exception:
        found = []
    if found:
        tally["queued"] += sum(1 for f in found if f)
        tally["failed"] += sum(1 for f in found if not f)
    else:
        tally["queued"] += count
else:
    tally["failed"] += count
    if len(tally["errors"]) < 5:
        tally["errors"].append("HTTP " + status_code + (" (403 means ETD has no Microsoft 365 write permission)" if status_code == "403" else ""))
tally_json = json.dumps(tally)
'''

#: Outputs: tally_json.
RECORD_VERIFICATION = r'''
import json, sys
tally = json.loads(sys.argv[1] or "{}")
status_code = str(sys.argv[2]).strip()
raw_response = sys.argv[3]
expected = (sys.argv[4] or "").strip().lower()
for key in ("verified", "not_verified", "unable"):
    tally.setdefault(key, 0)
def folders(node, key, seen):
    if isinstance(node, dict):
        for k, v in node.items():
            folders(v, str(k).lower(), seen)
    elif isinstance(node, list):
        for v in node:
            folders(v, key, seen)
    elif isinstance(node, str) and ("folder" in key or "action" in key):
        for name in ("quarantine", "junk", "trash", "inbox", "delete"):
            if name in node.lower():
                seen.add(name)
    return seen
seen = set()
if status_code == "200":
    try:
        seen = folders(json.loads(raw_response or "{}"), "", set())
    except Exception:
        seen = set()
if seen == {expected}:
    tally["verified"] += 1
elif seen and expected not in seen:
    tally["not_verified"] += 1
else:
    tally["unable"] += 1
tally_json = json.dumps(tally)
'''

#: Outputs: result.
CONTAINMENT_RESULT = r'''
import json, sys
mailbox, folder, digest = sys.argv[1], sys.argv[2], sys.argv[3]
tally = json.loads(sys.argv[4] or "{}")
queued, failed = tally.get("queued", 0), tally.get("failed", 0)
verified, not_verified, unable = tally.get("verified", 0), tally.get("not_verified", 0), tally.get("unable", 0)
sampled = verified + not_verified + unable
if sampled and verified == sampled:
    check = "VERIFIED on a sample of " + str(sampled)
elif not_verified:
    check = "NOT VERIFIED: " + str(not_verified) + " of " + str(sampled) + " sampled messages are not in " + folder + " yet (ETD applies moves from a queue; check again in ETD)"
else:
    check = "UNABLE TO VERIFY from the ETD status response; check in ETD"
result = ("`" + mailbox + "`: APPROVED and executed. " + str(queued) + " messages queued for move to " + folder
          + ", " + str(failed) + " failed (package " + digest + "). Verification: " + check + ".")
if tally.get("errors"):
    result += " Errors: " + "; ".join(tally["errors"]) + "."
if folder != "trash":
    result += " To undo, move the messages back to the inbox in ETD; that needs its own approval."
'''


def run(script: str, *args: Any) -> dict[str, Any]:
    """Execute ``script`` the way XDR does: string arguments in ``sys.argv``, outputs as globals."""
    namespace: dict[str, Any] = {"__name__": "__xdr_script__"}
    saved = sys.argv
    sys.argv = ["script", *[str(a) for a in args]]
    try:
        exec(compile(script, "<xdr-script>", "exec"), namespace)  # noqa: S102 - our own constant source
    finally:
        sys.argv = saved
    return namespace
