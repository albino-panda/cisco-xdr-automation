"""Generate the importable XDR Automation workflows under ``xdr/`` (or check they are current).

    python tools/xdr_native/build.py            # write xdr/**.json and xdr/RULES.md
    python tools/xdr_native/build.py --check    # exit 1 when a committed file is stale or invalid

What differs per org is read from ``config/xdr-native.yaml``: the approver roles, the ETD region used by
Email Bombing, and the lists every workflow needs (your own domain suffixes, protected assets, values
never to act on). Fill that file in once and regenerate; the values become the defaults of the workflow
inputs. A flag overrides the file:

    python tools/xdr_native/build.py --out build/xdr --etd-host api.de.etd.cisco.com \\
        --approver-role admin --approver-role user --elevated-role admin --elevated-approvals 2
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from xdr_native import email_bombing, incident, rules, specs, validate  # noqa: E402
from xdr_native.builder import Workflow  # noqa: E402

SETTINGS_FILE = "config/xdr-native.yaml"
RULES_FILE = "RULES.md"
#: Keys of the settings file that are lists of text, joined into one comma-separated input default.
LIST_KEYS = ("internal_domain_suffixes", "protected_assets", "never_act_on", "protected_mailboxes",
             "trusted_sender_domains")
ROLE_KEYS = ("approver_roles", "elevated_roles")


def workflows(settings: email_bombing.Settings) -> list[Workflow]:
    """Every workflow of ``xdr/``: Email Bombing, then one per attack type of ``specs.SPECS``."""
    return [email_bombing.build(settings), *(incident.build(spec, settings) for spec in specs.SPECS)]


def render(workflow: Workflow) -> str:
    return json.dumps(workflow.export(), indent=2, ensure_ascii=False) + "\n"


def load_settings(path: Path) -> dict[str, Any]:
    """Org settings from a YAML file (an absent file means defaults). Unknown keys are refused."""
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: a mapping of settings is expected")
    known = {*LIST_KEYS, *ROLE_KEYS, "elevated_approvals", "etd_host"}
    unknown = sorted(set(data) - known)
    if unknown:
        raise SystemExit(f"{path}: unknown settings {unknown}; known: {sorted(known)}")
    settings: dict[str, Any] = {}
    for key, value in data.items():
        if value in (None, "", []):
            continue
        if key in LIST_KEYS or key in ROLE_KEYS:
            items = value if isinstance(value, list) else [value]
            if not all(isinstance(item, str) and item.strip() and "," not in item for item in items):
                raise SystemExit(f"{path}: {key} must be a list of text values without commas")
            cleaned = [item.strip() for item in items]
            if key in ROLE_KEYS:
                if not set(cleaned) <= validate.KNOWN_ROLES:
                    raise SystemExit(f"{path}: {key} must be XDR roles {sorted(validate.KNOWN_ROLES)}")
                settings[key] = cleaned
            else:
                settings[key] = ", ".join(cleaned)
        elif key == "elevated_approvals":
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise SystemExit(f"{path}: elevated_approvals must be a number of at least 1")
            settings[key] = value
        else:
            settings[key] = str(value)
    return settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the committed files instead of writing")
    parser.add_argument("--out", default="xdr", help="output folder, relative to the repository root")
    parser.add_argument("--settings", default=SETTINGS_FILE,
                        help=f"org settings file, relative to the repository root (default {SETTINGS_FILE})")
    parser.add_argument("--approver-role", action="append", choices=sorted(validate.KNOWN_ROLES),
                        help="XDR role asked for a standard approval (repeatable; default admin and user)")
    parser.add_argument("--elevated-role", action="append", choices=sorted(validate.KNOWN_ROLES),
                        help="XDR role asked for an elevated approval (repeatable; default admin)")
    parser.add_argument("--elevated-approvals", type=int, help="approvals an elevated request needs (default 2)")
    parser.add_argument("--etd-host", help="regional ETD API host, for example api.de.etd.cisco.com")
    args = parser.parse_args(argv)

    values = load_settings(ROOT / args.settings)
    for key, flag in (("approver_roles", args.approver_role), ("elevated_roles", args.elevated_role),
                      ("elevated_approvals", args.elevated_approvals), ("etd_host", args.etd_host)):
        if flag:
            values[key] = flag
    try:
        settings = email_bombing.Settings(**values)
    except ValueError as error:
        raise SystemExit(f"{args.settings}: {error}") from None

    out = ROOT / args.out
    failed = False
    built = workflows(settings)
    for name in sorted({w.name for w in built if [x.name for x in built].count(w.name) > 1}
                       | {w.id for w in built if [x.id for x in built].count(w.id) > 1}):
        print(f"duplicate workflow name or identifier: {name}", file=sys.stderr)
        failed = True
    missing = sorted({guide.workflow for guide in rules.GUIDES} ^ {w.name for w in built})
    if missing:
        print(f"the rule guide and the workflows differ: {missing}", file=sys.stderr)
        failed = True
    if args.check and out.is_dir():
        expected = {w.folder for w in built}
        for folder in sorted(p.name for p in out.iterdir() if p.is_dir() and p.name not in expected):
            print(f"stale: {(out / folder).relative_to(ROOT)} is not generated any more", file=sys.stderr)
            failed = True
    files = []
    for workflow in built:
        problems = validate.check(workflow.export())
        for problem in problems:
            print(f"{workflow.name}: {problem}", file=sys.stderr)
        failed = failed or bool(problems)
        if not problems or args.check:
            files.append((out / workflow.folder / workflow.filename, render(workflow)))
    files.append((out / RULES_FILE, rules.render()))
    for path, text in files:
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                print(f"stale: {path.relative_to(ROOT)} (run tools/xdr_native/build.py)", file=sys.stderr)
                failed = True
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
