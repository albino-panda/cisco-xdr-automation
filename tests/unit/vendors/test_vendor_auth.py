"""Auth wiring of the vendor adapters (no network: providers are built, never used for token calls)."""
from __future__ import annotations

import httpx
import pytest

from tests.unit.vendors._helpers import FAKE_SECRETS, make_adapter
from xdr_response.errors import ConfigError, UnverifiedEndpointError
from xdr_response.integrations._graph import token_url

GRAPH = ("entra", "defender_o365", "intune", "microsoft_cloud")


@pytest.mark.parametrize("name", GRAPH)
def test_graph_adapters_need_an_explicit_scope(name):
    """The Graph scope string is UNVERIFIED (docs/integrations.md 2.8): no silent default."""
    with pytest.raises(ConfigError, match="oauth_scope"):
        make_adapter(name).build_auth()


def test_token_url_quotes_the_tenant():
    assert token_url("0000/../x") == "https://login.microsoftonline.com/0000%2F..%2Fx/oauth2/v2.0/token"


def test_splunk_bearer_tokens_are_unverified():
    with pytest.raises(UnverifiedEndpointError, match="splunk.auth_bearer_token"):
        make_adapter("splunk", options={"auth_mode": "bearer"}).build_auth()
    with pytest.raises(ConfigError):
        make_adapter("splunk", options={"auth_mode": "magic"}).build_auth()


# --------------------------------------------- with the integrations-core auth module --
OPTIONS = {name: {"oauth_scope": "https://graph.example.test/.default"} for name in GRAPH}
WITH_AUTH = sorted({"cisco_xdr", "secure_endpoint", "secure_email", "secure_malware_analytics", "umbrella", "meraki",
                    "defender_endpoint", "virustotal", "alienvault_otx", "hibp", "splunk", *GRAPH})


@pytest.fixture
def auth_module():
    """The auth providers are owned by integrations-core; skip until that module exists."""
    return pytest.importorskip("xdr_response.integrations.auth")


@pytest.mark.usefixtures("auth_module")
@pytest.mark.parametrize("name", WITH_AUTH)
def test_build_auth_returns_a_provider(name):
    provider = make_adapter(name, options=OPTIONS.get(name)).build_auth()
    assert callable(getattr(provider, "apply", None)) and callable(getattr(provider, "invalidate", None))


@pytest.mark.parametrize(("name", "header", "value"), [
    ("meraki", "authorization", f"Bearer {FAKE_SECRETS['MERAKI_API_KEY']}"),
    ("virustotal", "x-apikey", FAKE_SECRETS["VT_API_KEY"]),
    ("alienvault_otx", "x-otx-api-key", FAKE_SECRETS["OTX_API_KEY"]),
    ("hibp", "hibp-api-key", FAKE_SECRETS["HIBP_API_KEY"]),
    ("splunk", "authorization", f"Splunk {FAKE_SECRETS['SPLUNK_TOKEN']}"),
])
@pytest.mark.usefixtures("auth_module")
def test_static_key_headers(name, header, value):
    request = httpx.Request("GET", "https://api.example.test/x")
    make_adapter(name).build_auth().apply(request)
    assert request.headers[header] == value


@pytest.mark.usefixtures("auth_module")
def test_secure_malware_analytics_key_goes_in_the_query_string():
    request = httpx.Request("GET", "https://panacea.threatgrid.com/api/v2/iocs/feeds/domains")
    make_adapter("secure_malware_analytics").build_auth().apply(request)
    assert request.url.params["api_key"] == FAKE_SECRETS["SMA_API_KEY"]
