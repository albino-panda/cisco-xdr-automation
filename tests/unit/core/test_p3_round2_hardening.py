"""Regression tests for the Phase 3 round 2 workflow-safety fixes (architecture 14.11.7).

Covers the pieces below the workflows: the Windows, PowerShell and URL credential forms in any
text (not only command lines), URL destinations without userinfo, and the allow-listed
infrastructure address check of a host. Fake lab values only.
"""
from __future__ import annotations

import pytest

from xdr_response.config.policy import AllowlistPolicy
from xdr_response.config.schema import AllowlistsConfig
from xdr_response.logs.redaction import REDACTED, Redactor
from xdr_response.workflows.malicious_powershell.hooks import url_destination

SECRET = "Hunter2LabSecret77"


@pytest.mark.parametrize("text", [
    "C:\\lab\\agent.exe /user:svc /pass:" + SECRET,
    "schtasks.exe /create /tn LabTask /ru jsmith /rp " + SECRET,
    "ConvertTo-SecureString '" + SECRET + "' -AsPlainText -Force",
    "net.exe use \\\\TH-SRV-0310\\share " + SECRET + " /user:jsmith",
    "https://svc:" + SECRET + "@files.example.test/agent.exe",
    "Service ImagePath quoted by the vendor: \"C:\\lab\\agent.exe\" /pw:" + SECRET,
])
def test_command_credential_forms_are_redacted_in_any_text(text):
    redactor = Redactor()
    for out in (redactor.redact_text(text), redactor.redact({"ScriptBlockText": text})["ScriptBlockText"],
                redactor.redact_command_line(text)):
        assert SECRET not in out and REDACTED in out


@pytest.mark.parametrize("text", [
    "C:\\Program Files\\Lab\\agent.exe /install /quiet",
    "ConvertTo-SecureString $plain -AsPlainText -Force",
    "net use \\\\TH-SRV-0310\\share * /user:jsmith",
    "https://files.example.test/agent.exe",
    "powershell contacted cdn-update.test",
])
def test_ordinary_text_is_kept(text):
    assert Redactor().redact_text(text) == text


def test_command_line_only_forms_stay_command_line_only():
    # "-p 8080" in free text is usually a port; it is a password only by command-line convention.
    assert Redactor().redact_text("listener -p 8080") == "listener -p 8080"
    assert SECRET not in Redactor().redact_command_line(f"mysql -p {SECRET}")


@pytest.mark.parametrize("url, expected", [
    (f"https://svc:{SECRET}@cdn-update.test/a.ps1", "https://cdn-update.test/a.ps1"),
    ("https://cdn-update.test/a.ps1?x=1", "https://cdn-update.test/a.ps1?x=1"),
])
def test_url_destination_drops_userinfo(url, expected):
    assert url_destination(url) == expected


def _policy(**never_block) -> AllowlistPolicy:
    return AllowlistPolicy(AllowlistsConfig.model_validate({"never_block": never_block}))


@pytest.mark.parametrize("address, reason", [
    ("192.0.2.53", "allowlists.never_block.ips: 192.0.2.53"),
    ("192.0.2.5", "allowlists.never_block.cidrs: 192.0.2.0/28"),
    ("::ffff:192.0.2.5", "allowlists.never_block.cidrs: 192.0.2.0/28"),
])
def test_infrastructure_address_reason(address, reason):
    assert _policy(ips=["192.0.2.53"], cidrs=["192.0.2.0/28"]).address_reason(address) == reason


@pytest.mark.parametrize("address", ["10.20.30.40", "198.51.100.7", "not-an-ip"])
def test_private_or_unlisted_address_is_not_infrastructure(address):
    assert _policy(ips=["192.0.2.53"], cidrs=["192.0.2.0/28"]).address_reason(address) is None
