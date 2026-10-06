"""Have I Been Pwned adapter (read-only enrichment, disclosure-policy gated)."""
from xdr_response.integrations.hibp.adapter import HibpAdapter
from xdr_response.integrations.hibp.manifest import MANIFEST

__all__ = ["HibpAdapter", "MANIFEST"]
