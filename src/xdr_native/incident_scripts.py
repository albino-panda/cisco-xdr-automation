"""Python steps of the shared incident response workflow (``incident.py``).

Same contract as ``scripts.py``: arguments arrive as strings in ``sys.argv[1:]``, every output is a
global name, only the standard library is used, no credential is received and no network call is made.
``scripts.run`` executes them the same way for the unit tests.

The scripts read three Cisco XDR platform responses (docs/integrations.md section 2.1, all VERIFIED):

- ``POST /iroh/iroh-enrich/deliberate/observables``: one entry per module with
  ``data.verdicts.docs[]``, each carrying a ``disposition`` (1 clean, 2 malicious, 3 suspicious,
  4 common, 5 unknown) and the ``observable`` it rates;
- ``POST /iroh/iroh-enrich/observe/observables``: one entry per module with ``data.sightings.count``;
- ``POST /iroh/iroh-response/respond/observables``: the response actions the org's modules offer, each
  with ``id``, ``title``, ``module``, ``module_instance_id`` and ``query-params``.

**These responses are untrusted.** They come from third-party modules, and the incident's observables
come from whatever raised the incident. So:

- parsing is tolerant: a missing or malformed field never raises, it only leaves that fact off the card;
- an action is only ever proposed for an observable the workflow was given, and the trigger URL carries
  that observable, never one a response names;
- text a module supplies (action title, module name, error text) is reduced to plain printable
  characters and cut short before it reaches the decision card, so it cannot add lines or formatting;
- an action that undoes a containment is never chosen, whatever its title matches;
- the result never says an action is verified.
"""
from __future__ import annotations

#: Action kinds the workflow can propose, in the order they appear on the decision card.
KINDS = ("isolate_endpoint", "block_indicator", "block_hash", "revoke_sessions", "disable_user", "quarantine_email")

#: Outputs (all strings): observables_json, observe_body, has_observables, observable_count, ignored_count,
#: over_limit_count, intake.
CLASSIFY = r'''
import json, re, sys
candidates = sys.argv[1]
allowed = json.loads(sys.argv[2])["types"]
internal = [s.strip().lower().lstrip("*").lstrip("@").lstrip(".") for s in re.split(r"[,;\s]+", sys.argv[3]) if s.strip()]
limit = max(1, min(int(float(sys.argv[4] or "20")), 50))
sightings = str(sys.argv[5]).strip().lower() != "false"
hexes = {64: "sha256", 40: "sha1", 32: "md5"}

def typed(value):
    if re.match(r"^<[^<>\s`]+@[^<>\s`]+>$", value):
        return [("email_messageid", value)]
    if re.match(r"^[0-9a-fA-F]+$", value) and len(value) in hexes:
        return [(hexes[len(value)], value.lower())]
    clean = re.sub(r"^hxxp", "http", value, flags=re.I).replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if re.match(r"^[a-z][a-z0-9+.-]*://[^\s`]+$", clean, re.I):
        return [("url", clean)]
    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts):
        return [("ip", ".".join(str(int(p)) for p in parts))]
    if clean.count(":") >= 2 and re.match(r"^[0-9a-fA-F:.]+$", clean) and len(clean) <= 45:
        return [("ipv6", clean.lower())]
    lowered = clean.lower()
    if re.match(r"^[a-z0-9._%+'-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$", lowered):
        return [("email", lowered), ("user", lowered)]
    if re.match(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$", lowered):
        if any(lowered == s or lowered.endswith("." + s) for s in internal):
            return [("hostname", clean)]
        if "domain" in allowed or internal:
            return [("domain", lowered)]
        return [("hostname", clean)]
    if re.match(r"^[A-Za-z0-9_-]{1,63}$", clean):
        return [("hostname", clean), ("user", clean)]  # a bare name is an endpoint or an account
    return []

values = []
for line in candidates.splitlines():
    line = line.strip()
    if "://" in line or re.search(r"hxxp", line, re.I):
        values.extend(re.split(r"[,;]\s+|[,;]$", line))  # a URL may contain a comma: split only before a space
    else:
        values.extend(re.split(r"[,;]+", line))
rows, seen, ignored, over = [], set(), 0, 0
for raw in values:
    value = raw.strip().strip("\"'")
    if not value:
        continue
    found = [] if re.search(r"\s", value) or len(value) > 2000 else [(t, v) for t, v in typed(value) if t in allowed]
    if not found:
        ignored += 1
        continue
    for kind, text in found:
        key = (kind, text.lower())
        if key in seen:
            continue
        seen.add(key)
        if len(rows) >= limit:
            over += 1
            continue
        rows.append({"type": kind, "value": text})
counts = {}
for row in rows:
    counts[row["type"]] = counts.get(row["type"], 0) + 1
observables_json = json.dumps(rows)
observe_body = observables_json if sightings else "[]"
has_observables = "true" if rows else "false"
observable_count = str(len(rows))
ignored_count = str(ignored)
over_limit_count = str(over)
intake = ", ".join(str(n) + " " + t for t, n in sorted(counts.items())) or "none"
'''

#: Outputs (all strings): has_proposal, elevated, card, summary, actions_json, action_count, verify_body,
#: package_digest, risk.
ASSESS = r'''
import json, re, sys
observables = json.loads(sys.argv[1] or "[]")
started_by = str(sys.argv[2]).strip()
deliberate_status, deliberate_raw = str(sys.argv[3]).strip(), sys.argv[4]
observe_status, observe_raw = str(sys.argv[5]).strip(), sys.argv[6]
respond_status, respond_raw = str(sys.argv[7]).strip(), sys.argv[8]
spec = json.loads(sys.argv[9])
dry_run = str(sys.argv[10]).strip().lower() != "false"
def listed(raw):
    return [p.strip() for p in re.split(r"[,;\s]+", raw or "") if p.strip()]
protected = listed(sys.argv[11])
never_act = listed(sys.argv[12])
excluded_kinds = set(k.lower() for k in re.split(r"[,;\n]+", sys.argv[13] or ""))
excluded_kinds = set(re.sub(r"\s+", "_", k.strip()) for k in excluded_kinds if k.strip())
elevated_above = int(float(sys.argv[14] or "5"))
trust_selection = str(sys.argv[15]).strip().lower() != "false"
block_unrated = str(sys.argv[16]).strip().lower() == "true"
internal = [s.lower().lstrip("*").lstrip("@").lstrip(".") for s in listed(sys.argv[17])]
collect_sightings = str(sys.argv[18]).strip().lower() != "false"
# One pattern per kind the attack type uses, in the fixed order of the kinds.
kinds_in_order = ("isolate_endpoint", "block_indicator", "block_hash", "revoke_sessions", "disable_user", "quarantine_email")
used_kinds = [k for k in kinds_in_order if any(r.get("kind") == k for r in spec.get("rules") or [])]
patterns = dict(zip(used_kinds, sys.argv[19:19 + len(used_kinds)]))
# An action whose title or ID says it undoes a containment is never chosen, whatever the pattern matches.
reversal = (r"\b(un|de)-?(isolat|contain|block|quarantin|lock|suspend)|cancel|stop|undo|revert|restor|releas|remov"
            r"|lift|clear|exit|deliver|allow|safe.?list|white.?list|re-?activat|\b(re-?)?enabl|delet"
            r"|end (of )?(isolation|containment)|out of|expir|exclud|exempt|bypass|paus|suppress|ignor")
undo = {
    "isolate_endpoint": reversal + r"|disabl",
    "block_indicator": reversal + r"|disabl",
    "block_hash": reversal + r"|disabl",
    "revoke_sessions": reversal,
    "disable_user": reversal + r"|mfa|multi.?factor|two.?factor|2fa|disabl\w* (isolation|contain|block|rule|polic)",
    "quarantine_email": reversal + r"|inbox|disabl",
}
labels = {"isolate_endpoint": "Isolate endpoint", "block_indicator": "Block", "block_hash": "Block file hash",
          "revoke_sessions": "Revoke sessions of", "disable_user": "Disable user", "quarantine_email": "Quarantine message"}
indicator_types = ("ip", "ipv6", "domain", "url", "sha256", "sha1", "md5")
risk_of = {2: 90, 3: 60, 1: 5, 4: 5, 5: 0}
name_of = {1: "clean", 2: "malicious", 3: "suspicious", 4: "common", 5: "unknown"}

def plain(text, limit=80):
    """Module-supplied text as one short line of printable characters, with no Markdown or HTML."""
    out = []
    for char in str(text)[:4 * limit]:
        out.append("'" if char == '"' else char if 32 <= ord(char) < 127 and char not in "*`[]<>|#\\~_{}" else " ")
    line = " ".join("".join(out).split())
    return (line[:limit] + "...") if len(line) > limit else line

def show(value):
    """An observable inside backticks on the card."""
    line = "".join(c if 32 <= ord(c) < 127 and c != "`" else "?" for c in str(value))
    return "`" + ((line[:200] + "...") if len(line) > 200 else line) + "`"

def rows_of(status, raw):
    """Top-level list of a platform response, or None when the source failed."""
    if status != "200":
        return None
    try:
        body = json.loads(raw or "null")
    except Exception:
        return None
    if isinstance(body, dict):
        body = body.get("data")
    return [r for r in body if isinstance(r, dict)] if isinstance(body, list) else []

def part(node, name, kind):
    """``node[name]`` when it has the expected type, else an empty value of that type."""
    value = node.get(name) if isinstance(node, dict) else None
    return value if isinstance(value, kind) else kind()

def key_of(kind, value):
    return str(kind) + "|" + str(value).lower()

index = {}
for obs in observables:
    index[key_of(obs["type"], obs["value"])] = obs
only = list(index)[0] if len(index) == 1 else None

def key_for(named):
    """Key of the observable a response entry names. Without a name, the only observable asked for."""
    if isinstance(named, dict) and (named.get("type") is not None or named.get("value") is not None):
        key = key_of(named.get("type"), named.get("value"))
        return key if key in index else None
    return only

def v4(text):
    """An IPv4 address as a number, or None."""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text):
        return None
    parts = [int(p) for p in text.split(".")]
    return None if max(parts) > 255 else (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def v6(text):
    """An IPv6 address as a number, or None."""
    text = text.split("%")[0].lower()
    if len(text) > 45 or text.count("::") > 1 or ":" not in text or not re.fullmatch(r"[0-9a-f:.]+", text):
        return None
    def groups(piece):
        out = []
        fields = piece.split(":") if piece else []
        for position, field in enumerate(fields):
            if "." in field:
                number = v4(field)
                if number is None or position != len(fields) - 1:
                    return None
                out += [number >> 16, number & 0xffff]
            elif re.fullmatch(r"[0-9a-f]{1,4}", field):
                out.append(int(field, 16))
            else:
                return None
        return out
    if "::" in text:
        head, tail = text.split("::")
        left, right = groups(head), groups(tail)
        if left is None or right is None or len(left) + len(right) > 7:
            return None
        fields = left + [0] * (8 - len(left) - len(right)) + right
    else:
        fields = groups(text)
        if fields is None or len(fields) != 8:
            return None
    number = 0
    for field in fields:
        number = (number << 16) | field
    return number

def host_of(obs):
    """Lower-case host of a URL (no user, port or trailing dot); the value itself for other types."""
    value = obs["value"].lower()
    if obs["type"] != "url":
        return value.rstrip(".")
    rest = re.split(r"[/?#\\]", re.sub(r"^[a-z][a-z0-9+.-]*://", "", value), maxsplit=1)[0].rsplit("@", 1)[-1]
    if rest.startswith("["):
        return rest[1:].split("]")[0]
    return rest.split(":")[0].rstrip(".")

def private_v4(number):
    a, b = number >> 24, (number >> 16) & 255
    return (a in (0, 10, 127) or a >= 224 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 169 and b == 254) or (a == 100 and 64 <= b <= 127))

def is_public(obs):
    """False for an address (or a URL on an address) that is private, loopback, link-local, shared or multicast."""
    host = host_of(obs)
    number = v4(host)
    if number is not None:
        return not private_v4(number)
    number = v6(host)
    if number is None:
        return obs["type"] not in ("ip", "ipv6")  # an address that does not parse is not blocked
    top = number >> 112
    if number >> 32 == 0xffff:  # IPv4-mapped
        return not private_v4(number & 0xffffffff)
    return not (number in (0, 1) or top & 0xfe00 == 0xfc00 or top & 0xffc0 in (0xfe80, 0xfec0) or top & 0xff00 == 0xff00)

def in_network(host, entry):
    """True when ``host`` is the address ``entry`` or lies in the network ``entry`` (a.b.c.d/n)."""
    base, _, bits = entry.partition("/")
    for parse, width in ((v4, 32), (v6, 128)):
        address, network = parse(host), parse(base)
        if address is not None and network is not None:
            size = int(bits) if bits.isdigit() and int(bits) <= width else width
            return address >> (width - size) == network >> (width - size)
    return False

def wildcard(text, pattern):
    """Match where * stands for any text and ? for one character. Linear in len(text) * len(pattern)."""
    text, pattern = text[:256], pattern[:100]
    t, p, star, mark = 0, 0, -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] in ("?", text[t]):
            t, p = t + 1, p + 1
        elif p < len(pattern) and pattern[p] == "*":
            star, mark, p = p, t, p + 1
        elif star >= 0:
            mark += 1
            t, p = mark, star + 1
        else:
            return False
    return pattern[p:].strip("*") == ""

def matches(obs, entries):
    """The entry of a Protected Assets or Never Act On list that covers ``obs``, or an empty string."""
    value, host = obs["value"].lower(), host_of(obs)
    for entry in entries:
        pattern = entry.lower().rstrip(".")
        if wildcard(value, pattern) or wildcard(host, pattern) or in_network(host, pattern):
            return entry
        if obs["type"] == "hostname" and (wildcard(value.split(".")[0], pattern) or value == pattern.split(".")[0]):
            return entry  # DC-01 covers dc-01.corp.example.com, and the other way round
        if obs["type"] in ("domain", "url") and host.endswith("." + pattern.lstrip("*.")):
            return entry
        if obs["type"] in ("email", "user") and pattern.startswith("@") and value.endswith(pattern):
            return entry
    return ""

def is_own_account(obs):
    """True when no internal suffix is configured, or the address belongs to one of them."""
    if "@" not in obs["value"] or not internal:
        return True
    domain = obs["value"].lower().rsplit("@", 1)[1]
    return any(domain == s or domain.endswith("." + s) for s in internal)

degraded = []
verdicts = {}
deliberate = rows_of(deliberate_status, deliberate_raw)
if deliberate is None:
    degraded.append("verdicts (HTTP " + plain(deliberate_status, 12) + ")")
for module in deliberate or []:
    name = plain(module.get("module") or module.get("module-name") or "unknown module", 40)
    for doc in part(part(part(module, "data", dict), "verdicts", dict), "docs", list):
        if not isinstance(doc, dict):
            continue
        key = key_for(doc.get("observable"))
        disposition = doc.get("disposition")
        if key and isinstance(disposition, int) and not isinstance(disposition, bool):
            verdicts.setdefault(key, []).append((name, disposition))

sightings, sighting_total = {}, {}
observe = rows_of(observe_status, observe_raw) if collect_sightings else []
if observe is None:
    degraded.append("sightings (HTTP " + plain(observe_status, 12) + ")")
for module in observe or []:
    name = plain(module.get("module") or module.get("module-name") or "unknown module", 40)
    seen = part(part(module, "data", dict), "sightings", dict)
    count = seen.get("count")
    if isinstance(count, int) and not isinstance(count, bool) and 0 < count < 10 ** 9:
        sighting_total[name] = sighting_total.get(name, 0) + count
    for doc in part(seen, "docs", list):
        for rated in part(doc, "observables", list):
            if isinstance(rated, dict) and key_of(rated.get("type"), rated.get("value")) in index:
                per = sightings.setdefault(key_of(rated.get("type"), rated.get("value")), {})
                per[name] = per.get(name, 0) + 1

offers = {}
respond = rows_of(respond_status, respond_raw)
if respond is None:
    degraded.append("response actions (HTTP " + plain(respond_status, 12) + ")")
for entry in respond or []:
    action_id = entry.get("id")
    instance = entry.get("module_instance_id") or entry.get("module-instance-id")
    if not isinstance(action_id, str) or not isinstance(instance, str):
        continue
    if not action_id.strip(". ") or not instance.strip(". ") or len(action_id) > 200 or len(instance) > 200:
        continue  # an empty or dots-only path segment is not an action
    params = part(entry, "query-params", dict)
    named = {"type": params.get("observable_type"), "value": params.get("observable_value")}
    key = key_for(named)
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
        "title": plain(raw_title) or plain(action_id), "shown_id": plain(action_id, 60),
        "module": plain(entry.get("module") or entry.get("module-name") or entry.get("module_name") or "module", 40),
        "params": extra,
    })

def risk_for(key):
    return max([risk_of.get(d, 0) for _, d in verdicts.get(key, [])] or [0])

def verdict_text(key):
    found = verdicts.get(key, [])
    if not found:
        return "no verdict"
    return ", ".join(sorted(set(m + ": " + name_of.get(d, "unknown") for m, d in found))[:8])

incident_risk = max([risk_for(k) for k, o in index.items() if o["type"] in indicator_types] or [0])
selected = started_by != "incident_rule"  # a person chose these observables

def encode(text):
    out = []
    for byte in str(text).encode("utf-8", "replace"):
        char = chr(byte)
        out.append(char if byte < 128 and (char.isalnum() or char in "-._~") else "%%%02X" % byte)
    return "".join(out)

proposals, considered, missing, used = [], [], [], set()
for rule in spec.get("rules") or []:
    kind = rule["kind"]
    for key, obs in index.items():
        if obs["type"] not in rule["types"]:
            continue
        what = labels[kind] + " " + show(obs["value"])
        if obs["type"] in ("ip", "ipv6", "url") and not is_public(obs):
            considered.append(what + ": not proposed, it is not a public address.")
            continue
        if rule["basis"] == "asset" and obs["type"] in ("email", "user") and not is_own_account(obs):
            considered.append(what + ": not proposed, the address is outside the Internal Domain Suffixes, so it is not one of your accounts.")
            continue
        if kind in excluded_kinds:
            considered.append(what + ": not proposed because *" + kind + "* is on the Excluded Actions input. Design rule: " + rule["label"] + ".")
            continue
        hit = matches(obs, never_act)
        if hit:
            considered.append(what + ": not proposed, it matches the Never Act On entry " + show(hit) + ".")
            continue
        if rule["basis"] == "indicator":
            score = risk_for(key)
            if score >= rule["min_risk"]:
                reason = "rated " + verdict_text(key) + " (risk " + str(score) + ")"
            elif block_unrated and selected and not verdicts.get(key):
                reason = "not rated by any module; chosen by the person who started the workflow, and Block Unrated Indicators is true"
            else:
                considered.append(what + ": not proposed, rated " + verdict_text(key) + " (risk " + str(score) + ", needs " + str(rule["min_risk"]) + ").")
                continue
        elif incident_risk >= rule["min_risk"]:
            reason = "an indicator of this incident is rated at risk " + str(incident_risk) + " (needs " + str(rule["min_risk"]) + ")"
        elif selected and trust_selection:
            reason = "chosen by the person who started the workflow; no indicator of this incident reaches risk " + str(rule["min_risk"])
        else:
            considered.append(what + ": not proposed, no indicator of this incident reaches risk " + str(rule["min_risk"]) + " (highest " + str(incident_risk) + "). Start the workflow from a playbook task with it selected to propose it.")
            continue
        include = patterns.get(kind) or "."
        chosen, extra = {}, 0
        for offer in offers.get(key, []):
            try:
                wanted = re.search(include, offer["match"], re.I) and not re.search(undo[kind], offer["match"], re.I)
            except re.error:
                raise SystemExit("The action pattern for " + kind + " is not a valid regular expression: " + include)
            if not wanted:
                continue
            if offer["instance"] in chosen:
                extra += 1
            else:
                chosen[offer["instance"]] = offer
        if not chosen:
            others = sorted(set(o["title"] + " (" + o["module"] + ")" for o in offers.get(key, [])))
            missing.append((kind, key, what + ": XDR offers no matching response action (" + reason + "). "
                            + ("Offered for it: " + "; ".join(others[:6]) + "." if others else "No module offers an action for it.")
                            + " Do it in the product console if it is needed."))
            continue
        for offer in chosen.values():
            url = ("/iroh-response/respond/trigger/" + encode(offer["instance"]) + "/" + encode(offer["id"])
                   + "?observable_type=" + encode(obs["type"]) + "&observable_value=" + encode(obs["value"]))
            for name in sorted(offer["params"]):
                url += "&" + encode(name) + "=" + encode(offer["params"][name])
            if url in used:
                continue
            used.add(url)
            proposals.append({
                "url": url, "title": offer["title"], "target": obs["value"], "kind": kind, "module": offer["module"],
                "key": "|".join((offer["id"], offer["instance"], obs["type"], obs["value"].lower())),
                "type": obs["type"], "reason": reason, "rule": rule["label"], "protected": matches(obs, protected),
                "extra": str(extra), "shown_id": offer["shown_id"],
            })

order = dict((k, i) for i, k in enumerate(labels))
proposals.sort(key=lambda p: (order[p["kind"]], p["target"], p["module"]))
covered = set((p["kind"], p["target"].lower()) for p in proposals)
forms = {}
for key, obs in index.items():
    forms.setdefault(obs["value"].lower(), []).append(key)
manual = []
for kind, key, text in missing:
    value = index[key]["value"].lower()
    # A value asked for in two forms (an address as email and user, a bare name as endpoint and account)
    # is one target: the form no module knows is not reported when another form of it is known.
    other_form_known = not offers.get(key) and any(offers.get(k) for k in forms[value] if k != key)
    if (kind, value) not in covered and not other_form_known and text not in manual:
        manual.append(text)
considered = [c for i, c in enumerate(considered) if c not in considered[:i]]
reasons = []
guarded = sorted(set(show(p["target"]) + " (entry " + show(p["protected"]) + ")" for p in proposals if p["protected"]))
if guarded:
    reasons.append("protected asset: " + ", ".join(guarded))
if len(proposals) > elevated_above:
    reasons.append(str(len(proposals)) + " actions is above the limit of " + str(elevated_above) + " for standard approval")
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

package_digest = digest(json.dumps(sorted(p["url"] for p in proposals)))
name = spec.get("name", "Incident")

def evidence_lines():
    lines, grouped = [], {}
    for key, obs in index.items():
        grouped.setdefault(obs["value"].lower(), []).append((key, obs))
    for members in grouped.values():
        rated = sorted(set(m + ": " + name_of.get(d, "unknown") for key, _ in members for m, d in verdicts.get(key, [])))
        line = "- " + show(members[0][1]["value"]) + " (" + ", ".join(o["type"] for _, o in members) + "): " + (", ".join(rated[:8]) or "no verdict")
        seen = {}
        for key, _ in members:
            for module, number in sightings.get(key, {}).items():
                seen[module] = seen.get(module, 0) + number
        if seen:
            line += "; sightings " + ", ".join(m + " " + str(n) for m, n in sorted(seen.items())[:8])
        lines.append(line)
    if sighting_total:
        lines.append("- Sightings for all observables by module: " + ", ".join(m + " " + str(n) for m, n in sorted(sighting_total.items())[:12]) + ".")
    return lines

facts = (name + ": " + str(len(index)) + " observables assessed, highest indicator risk " + str(incident_risk))
if proposals:
    lines = []
    if elevated:
        lines += ["**ELEVATED APPROVAL REQUIRED: " + "; ".join(reasons) + ".**", ""]
    lines += ["**Mode: " + ("DRY RUN. Approving changes nothing; the workflow only reports what it would do." if dry_run else "LIVE. Approving runs the actions below.") + "**", "",
              "**" + name + ": " + str(len(proposals)) + " proposed actions. Package `" + package_digest + "`.**", ""]
    for number, p in enumerate(proposals, 1):
        lines.append(str(number) + ". " + labels[p["kind"]] + " " + show(p["target"]) + " with the XDR response action \"" + p["title"] + "\" of " + p["module"] + " (action ID " + p["shown_id"] + "). Why: " + p["reason"] + ". Rule: " + p["rule"] + "."
                     + (" Other matching actions of this module, not used: " + p["extra"] + "." if p["extra"] != "0" else ""))
    lines += ["", "Approve runs the " + str(len(proposals)) + " numbered actions above and nothing else. The action names in quotes come from the products and are shown as plain text. To run fewer, answer *More investigation* and start the workflow again with fewer observables or with kinds on the Excluded Actions input."]
    if manual:
        lines += ["", "**Needed but not available as an XDR response action (" + str(len(manual)) + "):**"] + ["- " + m for m in manual[:20]]
    if spec.get("manual"):
        lines += ["", "**Manual steps this workflow never runs:**"] + ["- " + m for m in spec["manual"]]
    if considered:
        lines += ["", "**Considered, not proposed (" + str(len(considered)) + "):**"] + ["- " + c for c in considered[:20]]
    if spec.get("checks"):
        lines += ["", "**Check before you approve:**"] + ["- " + c for c in spec["checks"]]
    lines += ["", "**Evidence from Cisco XDR:**"] + evidence_lines()
    if not collect_sightings:
        lines += ["- Sightings were not collected (Collect Sightings is false)."]
    if degraded:
        lines += ["", "**Degraded source:** " + ", ".join(degraded) + " did not answer. The proposal uses what was collected."]
    card = "\n".join(lines)
    summary = facts + ". Proposed: " + str(len(proposals)) + " actions (package " + package_digest + ")" + (", elevated approval" if elevated else "") + "."
else:
    card = ""
    why = "; ".join(degraded) + " did not answer" if degraded and not index else "nothing met the rules"
    summary = facts + ". No action proposed: " + why + "."
    if manual:
        summary += " Needed but not offered by XDR: " + " ".join(manual[:5])
    if considered:
        summary += " Considered: " + " ".join(considered[:5])
    if degraded:
        summary += " Degraded source: " + ", ".join(degraded) + "."
has_proposal = "true" if proposals else "false"
elevated = "true" if elevated else "false"
actions_json = json.dumps([dict((k, p[k]) for k in ("url", "title", "target", "kind", "module", "key")) for p in proposals])
action_count = str(len(proposals))
acted, verify = set(), []
for p in proposals:
    if (p["type"], p["target"]) not in acted:
        acted.add((p["type"], p["target"]))
        verify.append({"type": p["type"], "value": p["target"]})
verify_body = json.dumps(verify)
risk = str(incident_risk)
'''

#: Outputs: tally_json.
RECORD_TRIGGER = r'''
import json, sys
tally = json.loads(sys.argv[1] or "{}")
status_code = str(sys.argv[2]).strip()
raw_response = sys.argv[3]
title, target, key = sys.argv[4], sys.argv[5], sys.argv[6]

def plain(text, limit=160):
    line = "".join(c if 32 <= ord(c) < 127 and c not in "*`[]<>|#\\~_{}" else " " for c in str(text)[:4 * limit])
    return " ".join(line.split())[:limit]

ok, detail = False, ""
if status_code == "200":
    try:
        body = json.loads(raw_response or "{}")
    except Exception:
        body = {}
    data = body.get("data") if isinstance(body, dict) and isinstance(body.get("data"), dict) else {}
    state = data.get("status")
    ok = state == "success"
    if not ok:
        errors = body.get("errors") if isinstance(body, dict) else None
        parts = []
        for error in (errors if isinstance(errors, list) else [])[:3]:
            parts.append(str(error.get("message") or error.get("error") or error) if isinstance(error, dict) else str(error))
        detail = "XDR reported " + plain(state or "no status", 30) + (": " + plain("; ".join(parts)) if parts else "")
else:
    detail = "HTTP " + plain(status_code, 12)
tally.setdefault("results", []).append({"key": key, "title": title, "target": target, "ok": ok, "detail": detail})
tally_json = json.dumps(tally)
'''

#: Outputs: result.
RESULT = r'''
import json, sys
name, digest = json.loads(sys.argv[1]).get("name", "Incident"), sys.argv[2]
tally = json.loads(sys.argv[3] or "{}")
verify_status, verify_raw = str(sys.argv[4]).strip(), sys.argv[5]
results = tally.get("results") if isinstance(tally, dict) and isinstance(tally.get("results"), list) else []
results = [r for r in results if isinstance(r, dict)]

def show(value):
    line = "".join(c if 32 <= ord(c) < 127 and c != "`" else "?" for c in str(value))
    return "`" + line[:200] + "`"

# What XDR offers now, per module: the exact action for the exact observable, or, when the answer does
# not say which observable an offer is for, the action of that module for any observable.
answered, exact, loose = None, set(), set()
if verify_status == "200":
    try:
        body = json.loads(verify_raw or "null")
        if isinstance(body, dict):
            body = body.get("data")
        if isinstance(body, list):
            answered = set()
            for entry in body:
                if not isinstance(entry, dict):
                    continue
                instance = str(entry.get("module_instance_id") or entry.get("module-instance-id"))
                answered.add(instance)
                params = entry.get("query-params") if isinstance(entry.get("query-params"), dict) else {}
                if params.get("observable_type") is None and params.get("observable_value") is None:
                    loose.add(str(entry.get("id")) + "|" + instance)
                else:
                    exact.add("|".join((str(entry.get("id")), instance, str(params.get("observable_type")),
                                        str(params.get("observable_value")).lower())))
    except Exception:
        answered = None
succeeded = [r for r in results if r.get("ok")]
failed = [r for r in results if not r.get("ok")]
lines = []
for r in results:
    line = "\"" + str(r.get("title")) + "\" on " + show(r.get("target")) + ": "
    fields = str(r.get("key")).split("|")
    if not r.get("ok"):
        line += "FAILED (" + str(r.get("detail") or "no detail") + ")"
    elif answered is None or len(fields) < 4 or fields[1] not in answered:
        line += "XDR reported success; UNABLE TO VERIFY (the module did not list its actions afterwards)"
    elif r.get("key") in exact or fields[0] + "|" + fields[1] in loose:
        line += "XDR reported success; the action is still offered, so the change is NOT CONFIRMED"
    else:
        line += "XDR reported success and no longer offers the action (consistent with the change being applied)"
    lines.append(line)
result = (name + ": APPROVED and executed (package " + digest + "). " + str(len(succeeded)) + " of " + str(len(results))
          + " actions reported success" + (", " + str(len(failed)) + " failed" if failed else "") + ". "
          + " | ".join(lines)
          + " | The XDR trigger reports only success or failure: confirm each change in the product console. "
          + "To undo an action, use the matching restore task of the incident playbook; that is a separate decision.")
'''
