"""VirusTotal adapter (read-only enrichment, disclosure-policy gated)."""
from xdr_response.integrations.virustotal.adapter import VirusTotalAdapter
from xdr_response.integrations.virustotal.manifest import MANIFEST

__all__ = ["VirusTotalAdapter", "MANIFEST"]
