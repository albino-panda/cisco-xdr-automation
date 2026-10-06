"""Cisco Meraki adapter (client policy and MX L3 firewall)."""
from xdr_response.integrations.meraki.adapter import MerakiAdapter
from xdr_response.integrations.meraki.manifest import MANIFEST

__all__ = ["MerakiAdapter", "MANIFEST"]
