"""LevelBlue (AlienVault) OTX adapter (read-only enrichment, disclosure-policy gated)."""
from xdr_response.integrations.alienvault_otx.adapter import AlienVaultOtxAdapter
from xdr_response.integrations.alienvault_otx.manifest import MANIFEST

__all__ = ["AlienVaultOtxAdapter", "MANIFEST"]
