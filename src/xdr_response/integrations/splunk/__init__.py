"""Splunk adapter (optional, disabled by default)."""
from xdr_response.integrations.splunk.adapter import SplunkAdapter
from xdr_response.integrations.splunk.manifest import MANIFEST

__all__ = ["SplunkAdapter", "MANIFEST"]
