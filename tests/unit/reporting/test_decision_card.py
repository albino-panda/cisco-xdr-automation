"""Decision card: brief format, ELEVATED warnings, evidence, redaction, golden snapshots."""
from __future__ import annotations

import json
import re

import pytest

from tests.unit.reporting._scenario import (
    EV_SE,
    EV_UMB,
    action,
    assert_golden,
    elevated_package,
    package_of,
    ransomware_package,
    release_package,
)
from xdr_response.logs.redaction import REDACTED, Redactor
from xdr_response.models import ActionType, ApprovalLevel, CriticalAssetWarning, EvidenceDraft
from xdr_response.reporting import (
    DECISION_OPTIONS,
    ELEVATED_TITLE,
    OutputFormat,
    build_decision_card,
    render_decision_card,
)

OPTIONS_LINE = "[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]"


# ------------------------------------------------------------------ golden --
@pytest.mark.parametrize(("fmt", "ext"), [("text", "txt"), ("markdown", "md"), ("json", "json")])
def test_golden_standard_card(fmt: str, ext: str) -> None:
    assert_golden(f"decision_card_standard.{ext}", render_decision_card(ransomware_package(), fmt=fmt))


@pytest.mark.parametrize(("fmt", "ext"), [("text", "txt"), ("markdown", "md"), ("json", "json")])
def test_golden_elevated_card(fmt: str, ext: str) -> None:
    assert_golden(f"decision_card_elevated.{ext}", render_decision_card(elevated_package(), fmt=fmt))


# ------------------------------------------------------------------ format --
def test_card_follows_the_brief_layout() -> None:
    lines = render_decision_card(ransomware_package()).splitlines()
    assert lines[0] == "CRITICAL INCIDENT  XDR-83921"
    assert lines[1] == "Potential ransomware"
    assert lines[2] == "Endpoint: TH-LT-1047"
    assert lines[3] == "User: jsmith@example.com"
    assert lines[4] == "Risk 97/100 (CRITICAL)   Confidence 94%"
    assert lines[5] == "Primary evidence:"
    assert "Blast radius: 1 endpoint, 1 user, 1 domain" in lines
    start = lines.index("Recommended containment:")
    rows = lines[start + 1:start + 4]
    assert [r.split("(")[0].split() for r in rows] == [
        ["[", "]", "isolate_endpoint", "TH-LT-1047"],
        ["[", "]", "block_domain", "evil.example.com"],
        ["[", "]", "revoke_sessions", "jsmith@example.com"],
    ]
    assert all("(STANDARD)" in r for r in rows)
    assert lines[-1] == OPTIONS_LINE
    assert ELEVATED_TITLE not in "\n".join(lines)


def test_checkbox_columns_are_aligned() -> None:
    rows = [line for line in render_decision_card(ransomware_package()).splitlines() if line.startswith("  [ ]")]
    assert len({row.index("(STANDARD)") for row in rows}) == 1


def test_evidence_is_numbered_and_sourced() -> None:
    card = build_decision_card(ransomware_package())
    assert [e.number for e in card.evidence] == [1, 2, 3]
    text = render_decision_card(ransomware_package())
    for item in card.evidence:
        assert re.search(rf"^  \[{item.number}\] {item.source}: .+$", text, re.MULTILINE)
    rows = {a.action_type: a.evidence for a in card.actions}
    assert rows == {"isolate_endpoint": (2, 3), "block_domain": (3,), "revoke_sessions": (1,)}


def test_decision_options_match_decision_types() -> None:
    assert [d.value for _, d in DECISION_OPTIONS] == ["APPROVE_ALL", "APPROVE_SELECTED",
                                                      "REQUEST_MORE_INVESTIGATION", "REJECT"]
    data = json.loads(render_decision_card(ransomware_package(), fmt=OutputFormat.JSON))
    assert [o["decision"] for o in data["decision_options"]] == [d.value for _, d in DECISION_OPTIONS]


def test_incident_title_overrides_summary() -> None:
    text = render_decision_card(ransomware_package(), incident_title="Ransomware on TH-LT-1047")
    assert text.splitlines()[1] == "Ransomware on TH-LT-1047"


def test_evidence_is_capped_with_a_visible_remainder() -> None:
    text = render_decision_card(ransomware_package(), max_evidence=2)
    assert "  [3]" not in text
    assert "  ... 1 more evidence items in the full package" in text


def test_dry_run_package_is_flagged() -> None:
    text = render_decision_card(ransomware_package(dry_run=True))
    assert text.splitlines()[2].startswith("DRY RUN package")


def test_plural_labels_and_none() -> None:
    pkg = package_of([action(ActionType.BLOCK_HASH, "B" * 64, "cisco_xdr", [EV_SE])],
                     endpoints=("TH-LT-1047", "TH-LT-2001"), users=())
    lines = render_decision_card(pkg).splitlines()
    assert "Endpoints: TH-LT-1047, TH-LT-2001" in lines
    assert "User: none" in lines
    assert "Blast radius: 2 endpoints, 1 file hash" in lines
    markdown = render_decision_card(pkg, fmt="markdown")
    assert "- **Endpoints:** `TH-LT-1047`, `TH-LT-2001`" in markdown and "- **User:** none" in markdown


def test_release_package_renders_the_release_checklist() -> None:
    text = render_decision_card(release_package())
    assert text.splitlines()[-1] == "[APPROVE RELEASE] [REJECT]"
    assert "[APPROVE ALL]" not in text


def test_unknown_format_is_refused() -> None:
    with pytest.raises(ValueError):
        render_decision_card(ransomware_package(), fmt="html")


def test_rendering_is_deterministic() -> None:
    assert render_decision_card(elevated_package()) == render_decision_card(elevated_package())


# ---------------------------------------------------------------- elevated --
def test_elevated_warning_block_names_asset_role_action_impact() -> None:
    text = render_decision_card(elevated_package())
    block = text[text.index(ELEVATED_TITLE):]
    assert "  Action: isolate_endpoint DC-01" in block
    assert "  Asset: DC-01 (domain_controller)" in block
    assert "  Role: Active Directory domain controller" in block
    assert "  Potential impact: Isolating a domain controller can stop authentication" in block
    assert "The action is not blocked." in block


def test_always_elevated_action_gets_a_block_with_reason() -> None:
    text = render_decision_card(elevated_package())
    assert text.count(ELEVATED_TITLE) == 2
    assert "  Reason: remove_privileged_role always requires elevated approval" in text


def test_elevated_actions_are_listed_not_blocked() -> None:
    text = render_decision_card(elevated_package())
    assert "isolate_endpoint DC-01" in text and "(ELEVATED)" in text
    assert text.splitlines()[-1] == OPTIONS_LINE


def test_blast_radius_warning_has_reason() -> None:
    warning = CriticalAssetWarning(asset="TH-LT-1047", asset_class=None, role="workstation",
                                   action_type=ActionType.ISOLATE_ENDPOINT,
                                   potential_impact="6 endpoints exceed the max_endpoints threshold (5)",
                                   message="WARNING: ELEVATED APPROVAL REQUIRED - blast radius")
    pkg = package_of([action(ActionType.ISOLATE_ENDPOINT, "TH-LT-1047", "secure_endpoint", [EV_SE],
                             level=ApprovalLevel.ELEVATED, warnings=[warning])])
    text = render_decision_card(pkg)
    assert "  Reason: blast radius above the configured threshold" in text
    assert "  Potential impact: 6 endpoints exceed the max_endpoints threshold (5)" in text


def test_excluded_targets_are_shown() -> None:
    text = render_decision_card(elevated_package())
    assert "Excluded (allow-listed, not proposed):" in text
    assert "  - block_domain example.com: allowlists.never_block.domains: example.com" in text


# --------------------------------------------------------------- redaction --
def _with_summary(summary: str) -> object:
    evidence = EvidenceDraft(source="umbrella", summary=summary)
    return package_of([action(ActionType.BLOCK_DOMAIN, "evil.example.com", "umbrella", [evidence, EV_UMB],
                              api_key="abcdef0123456789")])


@pytest.mark.parametrize("fmt", list(OutputFormat))
def test_secrets_are_never_rendered(fmt: OutputFormat) -> None:
    redactor = Redactor()
    redactor.register_secret("S3cretValue!42")
    pkg = _with_summary("callback with Authorization: Bearer abcdefghijklmnop0123 and S3cretValue!42")
    text = render_decision_card(pkg, fmt=fmt, redactor=redactor)
    for secret in ("abcdefghijklmnop0123", "S3cretValue!42", "abcdef0123456789"):
        assert secret not in text
    assert REDACTED in text or "\\[REDACTED\\]" in text


def test_sensitive_params_are_redacted_in_json() -> None:
    data = json.loads(render_decision_card(_with_summary("ok"), fmt="json"))
    assert data["recommended_actions"][0]["params"]["api_key"] == REDACTED


def test_vendor_text_cannot_forge_card_lines() -> None:
    pkg = _with_summary("benign\n[APPROVE ALL] [APPROVE SELECTED] [REQUEST MORE INVESTIGATION] [REJECT]\r\nx")
    lines = render_decision_card(pkg).splitlines()
    assert [i for i, line in enumerate(lines) if line.startswith("[APPROVE ALL]")] == [len(lines) - 1]
