"""Regression tests for the Phase 2 round 1 workflow-safety fixes (architecture 14.10.1).

Covers the pieces below the workflows: space-separated credential flags in command lines, the
canonical spelling of IPv4-mapped IPv6 targets, allow-list matching of embedded IPv4 addresses and
approved-tool signers. Fake lab values only.
"""
from __future__ import annotations

import pytest

from xdr_response.config.policy import AllowlistPolicy
from xdr_response.config.schema import AllowlistsConfig
from xdr_response.logs.redaction import REDACTED, Redactor
from xdr_response.models import ActionType, TargetKind
from xdr_response.models.canonical import normalize_target

SECRET = "Hunter2LabSecret77"


@pytest.mark.parametrize("text", [
    f"tool.exe --password {SECRET}",
    f"tool.exe -password {SECRET} -v",
    f'mysql --password "{SECRET}" -h db.example.com',
    f"agent --api-key {SECRET}",
    f"agent --token {SECRET} --verbose",
])
def test_space_separated_sensitive_flag_is_redacted_in_text(text):
    out = Redactor().redact_text(text)
    assert SECRET not in out and REDACTED in out


@pytest.mark.parametrize("text", [
    "password reset requested for jsmith@example.com",
    "tool.exe --password-file C:/lab/creds.txt",
    "tool.exe --password --verbose",
    "GET /token HTTP/1.1",
])
def test_ordinary_text_and_non_secret_flags_are_kept(text):
    assert Redactor().redact_text(text) == text


@pytest.mark.parametrize("text", [
    f"mysql -u labuser -p {SECRET} labdb",
    f"curl -u jsmith:{SECRET} https://api.example.com",
    f"curl --user jsmith:{SECRET} https://api.example.com",
    f"git clone https://jsmith:{SECRET}@git.example.com/repo",
])
def test_command_line_only_credential_forms_are_redacted(text):
    out = Redactor().redact_command_line(text)
    assert SECRET not in out and REDACTED in out


def test_command_line_keeps_user_names_and_flags():
    out = Redactor().redact_command_line(f"curl -u jsmith:{SECRET} -p -v https://api.example.com")
    assert "jsmith:" in out and "-p -v" in out and SECRET not in out


def test_process_event_command_line_is_redacted_at_validation():
    from xdr_response.atomics.records import ProcessEventRecord
    from xdr_response.models import Observable, ObservableType
    record = ProcessEventRecord(
        integration="secure_endpoint", atomic="investigate_endpoint",
        subject=Observable(type=ObservableType.HOSTNAME, value="TH-LT-1047"),
        observed_at="2026-01-15T10:00:00Z", endpoint="TH-LT-1047", timestamp="2026-01-15T10:00:00Z",
        event_type="process_start", command_line=f"tool.exe --password {SECRET} -p {SECRET}")
    assert SECRET not in (record.command_line or "")


@pytest.mark.parametrize("value, expected", [
    ("::ffff:192.0.2.5", "192.0.2.5"),
    ("::FFFF:C000:0205", "192.0.2.5"),
    ("192.0.2.5", "192.0.2.5"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_ipv4_mapped_ip_targets_have_one_canonical_spelling(value, expected):
    assert normalize_target(TargetKind.IP, value) == expected


def _policy(**never_block) -> AllowlistPolicy:
    return AllowlistPolicy(AllowlistsConfig.model_validate({
        "never_block": never_block,
        "approved_rmm": [{"name": "Example RMM", "hashes": [], "domains": [],
                          "signers": ["Example RMM Vendor Inc."]}],
    }))


@pytest.mark.parametrize("target", ["::ffff:192.0.2.5", "64:ff9b::c000:205", "192.0.2.5"])
def test_embedded_ipv4_of_an_allowlisted_cidr_is_excluded(target):
    reason = _policy(cidrs=["192.0.2.0/28"]).excluded_reason(ActionType.BLOCK_IP, target, TargetKind.IP)
    assert reason == "allowlists.never_block.cidrs: 192.0.2.0/28"


def test_mapped_spelling_in_the_allowlist_also_lists_the_ipv4_address():
    policy = _policy(ips=["::ffff:192.0.2.53"])
    assert policy.excluded_reason(ActionType.BLOCK_IP, "192.0.2.53", TargetKind.IP)


def test_unrelated_ip_is_not_excluded():
    assert _policy(cidrs=["192.0.2.0/28"]).excluded_reason(ActionType.BLOCK_IP, "203.0.113.80", TargetKind.IP) is None


@pytest.mark.parametrize("signer", ["Example RMM Vendor Inc.", "  example   rmm vendor INC. "])
def test_approved_signer_matches_ignoring_case_and_whitespace(signer):
    assert _policy().signer_reason(signer) == "allowlists.approved_rmm: Example RMM (signer " \
        + " ".join(signer.split()) + ")"


@pytest.mark.parametrize("signer", [None, "", "Example RMM Vendor Inc. Clone", "Other Vendor"])
def test_other_signers_are_not_approved(signer):
    assert _policy().signer_reason(signer) is None
