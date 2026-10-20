"""Python steps that run inside XDR's Execute Python Script activity.

Contract of the activity: arguments arrive as strings in ``sys.argv[1:]`` and every output is a global
name listed in the activity's script queries. The scripts use the standard library only, never receive
a credential and never call the network. ``run`` executes one of them the same way for the unit tests.

These are the steps of ``Email Bombing``. It reads Secure Email Threat Defense (ETD) through the Cisco XDR
platform APIs, so it uses the ETD integration already connected in XDR and needs no ETD credential:

- ``POST /iroh/iroh-enrich/observe/observables`` for the mailbox: one entry per module with
  ``data.sightings`` (CTIM sightings, one per message);
- ``POST /iroh/iroh-response/respond/observables`` for the messages of the flood: the response actions
  the org's modules offer, each with ``id``, ``title``, ``module``, ``module_instance_id`` and
  ``query-params``.

Its trigger, trigger record and result steps are the incident response workflow's own
(``incident_scripts.RECORD_TRIGGER`` and ``RESULT``). The responses are untrusted: parsing is tolerant,
product text reaches the card as plain text, and only a message the assessment listed is ever acted on.
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

#: Outputs: types_json, types_text.
#: Reads ``GET /iroh/iroh-int/module-type`` and keeps the module types whose title names Secure Email Threat
#: Defense (the org showed two: "Secure Email Threat Defense" and its "(Beta)"). Their module instances are
#: looked up next, so the sightings query can ask ETD only (``mids``): asking every module returned more
#: than XDR's 4 MB limit for one activity, and the ETD module types name no product category to filter on.
FIND_ETD_TYPES = r'''
import json, re, sys
status_code = str(sys.argv[1]).strip()
raw_response = sys.argv[2]
valid = re.compile(r"^[A-Za-z0-9_-]{1,100}$")

def plain(text, limit=60):
    line = "".join(c if 32 <= ord(c) < 127 and c not in "*`[]<>|#\\~_{}" else " " for c in str(text)[:4 * limit])
    return " ".join(line.split())[:limit]

rows, types, titles = [], [], []
if status_code == "200":
    try:
        body = json.loads(raw_response or "null")
        if isinstance(body, dict):
            body = body.get("data")
        rows = [r for r in body if isinstance(r, dict)] if isinstance(body, list) else []
    except Exception:
        rows = []
for row in rows:
    title = str(row.get("title") or row.get("default_name") or "")
    type_id = str(row.get("id") or "")
    if re.search(r"email threat defense|\betd\b", title, re.IGNORECASE) and valid.match(type_id):
        if {"id": type_id} not in types:
            types.append({"id": type_id})
            titles.append(plain(title))
types_json = json.dumps(types)
if status_code != "200":
    types_text = "the XDR module type list did not answer (HTTP " + plain(status_code, 12) + ")"
else:
    types_text = ", ".join(titles) or "no module type named Secure Email Threat Defense"
'''

#: Outputs: instances_json.
#: Adds the IDs of the enabled module instances in one ``GET /iroh/iroh-int/module-instance?module_type_id=``
#: answer to the list collected so far. Only the IDs are kept.
COLLECT_INSTANCES = r'''
import json, re, sys
collected = json.loads(sys.argv[1] or "[]")
status_code = str(sys.argv[2]).strip()
raw_response = sys.argv[3]
valid = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
collected = [c for c in collected if isinstance(c, str) and valid.match(c)] if isinstance(collected, list) else []
if status_code == "200":
    try:
        body = json.loads(raw_response or "null")
        if isinstance(body, dict):
            body = body.get("data")
        for row in body if isinstance(body, list) else []:
            if isinstance(row, dict) and row.get("enabled") is not False:
                instance = str(row.get("id") or "")
                if valid.match(instance) and instance not in collected:
                    collected.append(instance)
    except Exception:
        pass
instances_json = json.dumps(collected[:10])
'''

#: Outputs: module_filter, found, modules_text.
#: The query string that limits the sightings query to ETD: ``mids=<id>`` per module instance. IDs in the
#: *ETD Module Instance ID* input are used instead of the looked-up ones when set.
MODULE_FILTER = r'''
import json, re, sys
override = sys.argv[1] or ""
collected = json.loads(sys.argv[2] or "[]")
types_text = sys.argv[3]
valid = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
ids = []
for value in re.split(r"[,;\s]+", override.strip()):
    if value and valid.match(value) and value not in ids:
        ids.append(value)
if ids:
    source = "set in the ETD Module Instance ID input"
else:
    ids = [c for c in collected if isinstance(c, str) and valid.match(c)] if isinstance(collected, list) else []
    source = "looked up in XDR"
module_filter = "&".join("mids=" + i for i in ids[:10])
found = "true" if ids else "false"
modules_text = types_text + ": " + (str(len(ids)) + " module instance" + ("s" if len(ids) != 1 else "") + " (" + source + ")"
                                    if ids else "no enabled module instance")
'''

#: Outputs: observe_body, window_start, window_end.
BUILD_OBSERVE = r'''
import datetime, json, sys
mailbox = sys.argv[1].strip().lower()
lookback = max(5, min(int(float(sys.argv[2] or "60")), 1440))
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
start = now - datetime.timedelta(minutes=lookback)
fmt = "%Y-%m-%dT%H:%M:%SZ"
window_start = start.strftime(fmt)
window_end = now.strftime(fmt)
observe_body = json.dumps([{"type": "email", "value": mailbox}])
'''

#: Outputs: state_json, message_count.
#: Only modules whose name says they are an email product (Secure Email Threat Defense) are measured;
#: sightings of other modules are reported, never counted or acted on. Each sighting is one message: its
#: message ID (``email_messageid`` or ``cisco_mid``), its sender (a ``Sent_From`` / ``Sent_By`` relation,
#: else an email observable other than the mailbox), its subject (``email_subject``, else the title), its
#: time (``observed_time.start_time``) and an ETD verdict named in its title, description, severity or
#: resolution. These follow the CTIM model; ETD's sightings were not read from this org, so a missing field
#: leaves that fact out instead of failing.
COLLECT_SIGHTINGS = r'''
import datetime, json, re, sys
status_code = str(sys.argv[1]).strip()
raw_response = sys.argv[2]
mailbox = sys.argv[3].strip().lower()
window_start, window_end = sys.argv[4], sys.argv[5]
max_messages = int(float(sys.argv[6] or "200"))
topics = [
    ("credential", r"password|passcode|account recovery|recover your account|reset your"),
    ("security alert", r"security alert|new sign[- ]?in|new log[- ]?in|new device|unusual (activity|sign)|suspicious (activity|sign)"),
    ("mfa", r"verification code|one[- ]time|\bmfa\b|\b2fa\b|two[- ]factor|multi[- ]factor|authenticat"),
    ("payment", r"wire transfer|invoice|payment|bank|purchase|order confirm|receipt|refund"),
    ("lure", r"docusign|shared a (file|document)|voicemail|microsoft 365|office 365"),
]
message_types = ("email_messageid", "cisco_mid")
verdict_words = ("malicious", "phishing", "bec", "scam", "spam", "graymail", "neutral")
mail_module = re.compile(r"e-?mail|\betd\b|threat defense", re.IGNORECASE)
state = {"messages": [], "buried": [], "error": "", "truncated": False, "modules": {}, "other_modules": {},
         "no_id": 0, "outside": 0}

def plain(text, limit=120):
    out = []
    for char in str(text)[:4 * limit]:
        out.append("'" if char == '"' else char if 32 <= ord(char) < 127 and char not in "*`[]<>|#\\~_{}" else " ")
    line = " ".join("".join(out).split())
    return (line[:limit] + "...") if len(line) > limit else line

def when(text):
    try:
        stamp = datetime.datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None

def node(value):
    return value if isinstance(value, dict) else {}

def pair(value):
    value = node(value)
    return (str(value.get("type") or "").strip().lower(), str(value.get("value") or "").strip())

start, end = when(window_start), when(window_end)
try:
    if status_code != "200":
        raise ValueError("HTTP " + plain(status_code, 12))
    body = json.loads(raw_response or "null")
    if isinstance(body, dict):
        body = body.get("data")
    rows = [r for r in body if isinstance(r, dict)] if isinstance(body, list) else []
    known = set()
    for row in rows:
        module = plain(row.get("module") or row.get("module-name") or row.get("module_name") or "module", 40)
        sightings = node(node(row.get("data")).get("sightings"))
        docs = [d for d in sightings.get("docs") if isinstance(d, dict)] if isinstance(sightings.get("docs"), list) else []
        count = sightings.get("count")
        count = count if isinstance(count, int) and not isinstance(count, bool) else len(docs)
        if not mail_module.search(module):
            if count:
                state["other_modules"][module] = state["other_modules"].get(module, 0) + count
            continue
        state["modules"][module] = state["modules"].get(module, 0) + count
        if count > len(docs):
            state["truncated"] = True
        for doc in docs:
            pairs = [pair(o) for o in (doc.get("observables") if isinstance(doc.get("observables"), list) else [])]
            senders = []
            for relation in doc.get("relations") if isinstance(doc.get("relations"), list) else []:
                relation = node(relation)
                source, related = pair(relation.get("source")), pair(relation.get("related"))
                pairs += [source, related]
                name = re.sub(r"[^a-z]", "", str(relation.get("relation") or "").lower())
                if name in ("sentfrom", "sentby", "sender", "from") and source[0] == "email" and source[1]:
                    senders.append(source[1])
            if not senders:
                senders = [v for t, v in pairs if t == "email" and v and v.lower() != mailbox]
            sender = senders[0] if senders else ""
            if sender.lower() == mailbox:
                continue  # sent by the mailbox itself: not part of an inbound flood
            stamp = when(node(doc.get("observed_time")).get("start_time"))
            if stamp and start and end and not (start <= stamp <= end):
                state["outside"] += 1
                continue
            found = [(t, v) for t, v in pairs if t in message_types and v and len(v) <= 500]
            mid = found[0] if found else ("", "")
            key = (mid[0] + "|" + mid[1].lower()) if mid[1] else "sighting|" + str(doc.get("id") or len(known))
            if key in known:
                continue
            if len(state["messages"]) >= max_messages:
                state["truncated"] = True
                break
            known.add(key)
            if not mid[1]:
                state["no_id"] += 1
            domain = sender.rsplit("@", 1)[1].lower() if "@" in sender else ""
            domain = re.split(r"[^a-z0-9.-]", domain)[0].strip(".")[:100] or "unknown"
            text = " ".join(str(doc.get(k) or "") for k in ("title", "description", "short_description", "severity", "resolution")).lower()
            label = next((w for w in verdict_words if re.search(r"\b" + w + r"\b", text)), "noverdict")
            subject = next((v for t, v in pairs if t == "email_subject" and v), "") or str(doc.get("title") or "")
            topic = ""
            for name, pattern in topics:
                if re.search(pattern, subject, re.IGNORECASE):
                    topic = name
                    break
            moment = stamp.strftime("%Y-%m-%dT%H:%M:%SZ") if stamp else ""
            state["messages"].append([mid[0], mid[1], domain, label, topic, moment])
            if topic and len(state["buried"]) < 15:
                state["buried"].append({"topic": topic, "subject": plain(subject), "from": plain(sender),
                                        "time": moment, "verdict": label})
except Exception as exc:
    state["error"] = "the XDR sightings query failed: " + plain(exc, 200)
state_json = json.dumps(state)
message_count = str(len(state["messages"]))
'''

#: Outputs: qualifies, summary, evidence, respond_body, move_count, elevated_reasons.
ASSESS = r'''
import json, sys
state = json.loads(sys.argv[1] or "{}")
mailbox = sys.argv[2]
protected = str(sys.argv[3]).lower() == "true"
min_messages = int(float(sys.argv[4] or "30"))
min_domains = int(float(sys.argv[5] or "10"))
min_clean = int(float(sys.argv[6] or "50"))
window_start, window_end = sys.argv[7], sys.argv[8]
trusted = set(d.strip().lower().lstrip("@") for d in (sys.argv[9] or "").replace(";", ",").split(",") if d.strip())

def show(value):
    line = "".join(c if 32 <= ord(c) < 127 and c != "`" else "?" for c in str(value))
    return "`" + line[:200] + "`"

messages = state.get("messages") or []
error = state.get("error") or ""
truncated = bool(state.get("truncated"))
total = len(messages)
domains, verdicts = {}, {}
for kind, value, domain, label, topic, when in messages:
    domains[domain] = domains.get(domain, 0) + 1
    verdicts[label] = verdicts.get(label, 0) + 1
senders = len([d for d in domains if d != "unknown"])
rated = total - verdicts.get("noverdict", 0)
clean = verdicts.get("neutral", 0) + verdicts.get("graymail", 0)
clean_share = int(round(100.0 * clean / rated)) if rated else None
bad = ("malicious", "phishing", "bec", "scam")
kept = set(i for i, m in enumerate(messages) if (m[4] and m[3] not in bad) or m[2] in trusted)
move = [{"type": m[0], "value": m[1]} for i, m in enumerate(messages) if i not in kept and m[1]]
unmovable = sum(1 for i, m in enumerate(messages) if i not in kept and not m[1])
qualifies = (total >= min_messages and senders >= min_domains
             and (clean_share is None or clean_share >= min_clean) and bool(move))
reasons = []
if protected:
    reasons.append("the mailbox is on the protected list")
if truncated:
    reasons.append("XDR returned only part of the sightings or the collection limit was reached, so the flood is larger than what is listed")
modules = state.get("modules") or {}
others = state.get("other_modules") or {}
top = sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
verdict_text = ", ".join(k + " " + str(v) for k, v in sorted(verdicts.items(), key=lambda kv: (-kv[1], kv[0]))) or "none"
if clean_share is None:
    share_text = "no ETD verdict in the sightings"
else:
    share_text = str(clean_share) + "% of the messages with a verdict are neutral or graymail"
facts = (show(mailbox) + ": " + str(total) + " inbound messages from " + str(senders) + " sender domains between "
         + window_start + " and " + window_end + " UTC in the Secure Email Threat Defense sightings, " + share_text)
lines = ["**Evidence from Secure Email Threat Defense, through Cisco XDR**", "",
         "1. " + str(total) + " inbound messages to " + show(mailbox) + " between " + window_start + " and " + window_end + " UTC (threshold " + str(min_messages) + ").",
         "2. " + str(senders) + " different sender domains (threshold " + str(min_domains) + "). Largest: " + (", ".join(show(d) + " " + str(n) for d, n in top) or "none") + "."]
if clean_share is None:
    lines.append("3. The sightings name no ETD verdict, so the " + str(min_clean) + "% neutral or graymail threshold was not applied. Check the verdicts in ETD before approving.")
else:
    lines.append("3. " + share_text + " (threshold " + str(min_clean) + "%). Verdicts: " + verdict_text + ".")
lines.append("4. Sightings by module: " + (", ".join(m + " " + str(n) for m, n in sorted(modules.items())) or "none") + ".")
if others:
    lines.append("5. Sightings of other modules, not counted: " + ", ".join(m + " " + str(n) for m, n in sorted(others.items())[:8]) + ".")
if error:
    lines.append("Degraded source: " + error + ".")
if domains.get("unknown"):
    lines.append(str(domains["unknown"]) + " messages name no sender.")
if unmovable:
    lines.append(str(unmovable) + " messages of the flood carry no message ID in their sighting, so they cannot be acted on through XDR.")
if state.get("outside"):
    lines.append(str(state["outside"]) + " sightings outside the time window were left out.")
buried = state.get("buried") or []
lines += ["", "**Not moved (" + str(len(kept)) + "):** messages from trusted sender domains and messages a flood is used to hide."]
for b in buried:
    lines.append("- [" + b["topic"] + "] " + b["subject"] + " (from " + b["from"] + ", " + b["time"] + ")")
hidden_topics = sorted(set(b["topic"] for b in buried if b["verdict"] not in bad))
if hidden_topics:
    lines += ["", "**Check the account:** the flood contains " + ", ".join(hidden_topics) + " messages. Review this user's sign-ins, MFA prompts and mailbox rules. This workflow does not change the account."]
evidence = "\n".join(lines)
if qualifies:
    summary = facts + ". Flood found: " + str(len(move)) + " messages can be moved."
elif error and not total:
    summary = facts + ". No action proposed: " + error + "."
elif total >= min_messages and senders >= min_domains and not move:
    summary = facts + ". No action proposed: no message of the flood carries a message ID XDR can act on."
else:
    summary = (facts + ". No action proposed: below the flood thresholds (" + str(min_messages) + " messages, "
               + str(min_domains) + " sender domains, " + str(min_clean) + "% neutral or graymail).")
respond_body = json.dumps(move if qualifies else [])
move_count = str(len(move) if qualifies else 0)
elevated_reasons = json.dumps(reasons)
qualifies = "true" if qualifies else "false"
'''

#: Outputs: has_proposal, elevated, card, summary, actions_json, action_count, verify_body, package_digest.
#: Keeps, per message of the flood, the one response action that moves it to the Containment Folder. As in
#: the incident response workflow, the trigger URL carries the message the assessment listed and never one
#: the response names, and an action that undoes a containment or delivers to the inbox is never chosen.
PLAN_MOVES = r'''
import json, re, sys
respond_status, respond_raw = str(sys.argv[1]).strip(), sys.argv[2]
requested = json.loads(sys.argv[3] or "[]")
mailbox, evidence = sys.argv[4], sys.argv[5]
elevated_reasons = json.loads(sys.argv[6] or "[]")
dry_run = str(sys.argv[7]).strip().lower() != "false"
folder = (sys.argv[8] or "quarantine").strip().lower()
include = sys.argv[9] or "."
elevated_above = int(float(sys.argv[10] or "100"))
if folder not in ("quarantine", "junk", "trash"):
    raise SystemExit("Containment Folder must be quarantine, junk or trash (delete is permanent and is refused)")
folder_word = {"quarantine": r"quarantin", "junk": r"junk|spam folder", "trash": r"trash"}[folder]
undo = (r"\b(un|de)-?(isolat|contain|block|quarantin|lock|suspend)|cancel|stop|undo|revert|restor|releas|remov"
        r"|lift|clear|exit|deliver|allow|safe.?list|white.?list|re-?activat|\b(re-?)?enabl|delet|inbox"
        r"|end (of )?(isolation|containment)|out of|expir|exclud|exempt|bypass|paus|suppress|ignor")

def plain(text, limit=80):
    out = []
    for char in str(text)[:4 * limit]:
        out.append("'" if char == '"' else char if 32 <= ord(char) < 127 and char not in "*`[]<>|#\\~_{}" else " ")
    line = " ".join("".join(out).split())
    return (line[:limit] + "...") if len(line) > limit else line

def show(value):
    line = "".join(c if 32 <= ord(c) < 127 and c != "`" else "?" for c in str(value))
    return "`" + ((line[:200] + "...") if len(line) > 200 else line) + "`"

def key_of(kind, value):
    return str(kind) + "|" + str(value).lower()

def encode(text):
    out = []
    for byte in str(text).encode("utf-8", "replace"):
        char = chr(byte)
        out.append(char if byte < 128 and (char.isalnum() or char in "-._~") else "%%%02X" % byte)
    return "".join(out)

index = {}
for obs in requested:
    if isinstance(obs, dict) and obs.get("type") and obs.get("value"):
        index.setdefault(key_of(obs["type"], obs["value"]), {"type": str(obs["type"]), "value": str(obs["value"])})
only = list(index)[0] if len(index) == 1 else None
rows = None
if respond_status == "200":
    try:
        body = json.loads(respond_raw or "null")
        if isinstance(body, dict):
            body = body.get("data")
        rows = [r for r in body if isinstance(r, dict)] if isinstance(body, list) else []
    except Exception:
        rows = None
degraded = "" if rows is not None else "the list of response actions (HTTP " + plain(respond_status, 12) + ")"
offers = {}
for entry in rows or []:
    action_id = entry.get("id")
    instance = entry.get("module_instance_id") or entry.get("module-instance-id")
    if not isinstance(action_id, str) or not isinstance(instance, str):
        continue
    if not action_id.strip(". ") or not instance.strip(". ") or len(action_id) > 200 or len(instance) > 200:
        continue  # an empty or dots-only path segment is not an action
    params = entry.get("query-params") if isinstance(entry.get("query-params"), dict) else {}
    if params.get("observable_type") is None and params.get("observable_value") is None:
        key = only
    else:
        key = key_of(params.get("observable_type"), params.get("observable_value"))
        key = key if key in index else None
    if not key:
        continue
    extra = {}
    for name, value in params.items():
        reserved = re.sub(r"[^a-z]", "", str(name).lower()) in ("observabletype", "observablevalue")
        if not reserved and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(name)) and isinstance(value, (str, int)) \
                and not isinstance(value, bool) and len(str(value)) <= 300:
            extra[str(name)] = str(value)
    raw_title = entry.get("title") if isinstance(entry.get("title"), str) else ""
    offers.setdefault(key, []).append({
        "id": action_id, "instance": instance, "match": raw_title.strip()[:400] or action_id,
        "title": plain(raw_title) or plain(action_id),
        "module": plain(entry.get("module") or entry.get("module-name") or entry.get("module_name") or "module", 40),
        "params": extra,
    })
proposals, unmatched, offered_titles = [], 0, set()
for key, obs in index.items():
    chosen = None
    for offer in sorted(offers.get(key, []), key=lambda o: (o["module"], o["title"], o["id"], o["instance"])):
        offered_titles.add(offer["title"] + " (" + offer["module"] + ")")
        try:
            wanted = re.search(include, offer["match"], re.I) and re.search(folder_word, offer["match"], re.I) \
                and not re.search(undo, offer["match"], re.I)
        except re.error:
            raise SystemExit("Move Action Pattern is not a valid regular expression: " + include)
        if wanted and chosen is None:
            chosen = offer
    if chosen is None:
        unmatched += 1
        continue
    url = ("/iroh-response/respond/trigger/" + encode(chosen["instance"]) + "/" + encode(chosen["id"])
           + "?observable_type=" + encode(obs["type"]) + "&observable_value=" + encode(obs["value"]))
    for name in sorted(chosen["params"]):
        url += "&" + encode(name) + "=" + encode(chosen["params"][name])
    proposals.append({"url": url, "title": chosen["title"], "target": obs["value"], "kind": "move_email",
                      "module": chosen["module"], "type": obs["type"],
                      "key": "|".join((chosen["id"], chosen["instance"], obs["type"], obs["value"].lower()))})
proposals.sort(key=lambda p: p["url"])
reasons = list(elevated_reasons)
if len(proposals) > elevated_above:
    reasons.append(str(len(proposals)) + " messages is above the limit of " + str(elevated_above) + " for standard approval")
elevated = bool(reasons) and bool(proposals)

def digest(text):
    """Short identifier of the package: SHA-256 when the module is present, FNV-1a otherwise."""
    try:
        import hashlib
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    except ImportError:
        value = 0xcbf29ce484222325
        for byte in text.encode("utf-8"):
            value = ((value ^ byte) * 0x100000001b3) % (1 << 64)
        return "%012x" % (value % (1 << 48))

package_digest = digest(json.dumps([p["url"] for p in proposals]))
used = {}
for p in proposals:
    label = "\"" + p["title"] + "\" of " + p["module"]
    used[label] = used.get(label, 0) + 1
if proposals:
    lines = ["## Email bombing: decision needed", ""]
    if elevated:
        lines += ["**ELEVATED APPROVAL REQUIRED** because " + "; ".join(reasons) + ".", ""]
    lines += ["**Mode: " + ("DRY RUN. Approving moves nothing; the workflow only reports what it would do." if dry_run else "LIVE. Approving moves the messages.") + "**", "",
              "**Proposed action:** move " + str(len(proposals)) + " messages of the flood to *" + folder
              + "* with the Secure Email Threat Defense response action offered through Cisco XDR: "
              + "; ".join(k + " (" + str(n) + " messages)" for k, n in sorted(used.items())) + ". Package `" + package_digest + "`.", "",
              "Approve triggers these " + str(len(proposals)) + " actions and nothing else. The action names in quotes come from the product and are shown as plain text."]
    if unmatched:
        lines += ["", "**Not offered:** XDR offers no matching action for " + str(unmatched) + " further messages of the flood."
                  + (" Offered: " + "; ".join(sorted(offered_titles)[:6]) + "." if offered_titles else "") + " Move them in ETD if needed."]
    if degraded:
        lines += ["", "**Degraded source:** " + degraded + " did not answer."]
    lines += ["", evidence, "", "**Choices:** *Approve* runs the proposed action. *Reject* changes nothing."]
    card = "\n".join(lines)
    summary = (show(mailbox) + ": flood found. Proposed: move " + str(len(proposals)) + " messages to " + folder
               + " (package " + package_digest + ")" + (", elevated approval" if elevated else "") + ".")
else:
    card = ""
    if degraded:
        why = degraded + " did not answer"
    elif offered_titles:
        why = ("XDR offers no response action that moves a message to " + folder + " (offered: "
               + "; ".join(sorted(offered_titles)[:6]) + "). Set the Move Action Pattern input or move the messages in ETD")
    else:
        why = ("no module offers a response action for these messages. Check that the Secure Email Threat Defense "
               "integration is enabled in XDR, or move the messages in ETD")
    summary = show(mailbox) + ": flood found, but no action proposed: " + why + "."
has_proposal = "true" if proposals else "false"
elevated = "true" if elevated else "false"
actions_json = json.dumps([dict((k, p[k]) for k in ("url", "title", "target", "kind", "module", "key")) for p in proposals])
action_count = str(len(proposals))
verify_body = json.dumps([{"type": p["type"], "value": p["target"]} for p in proposals])
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
