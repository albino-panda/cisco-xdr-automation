"""Microsoft Defender XDR / Graph Security adapter (read-only)."""
from xdr_response.integrations.microsoft_cloud.adapter import MicrosoftCloudAdapter
from xdr_response.integrations.microsoft_cloud.manifest import MANIFEST

__all__ = ["MicrosoftCloudAdapter", "MANIFEST"]
