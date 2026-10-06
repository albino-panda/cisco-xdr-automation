"""Microsoft Defender for Office 365 adapter."""
from xdr_response.integrations.defender_o365.adapter import DefenderO365Adapter
from xdr_response.integrations.defender_o365.manifest import MANIFEST

__all__ = ["DefenderO365Adapter", "MANIFEST"]
