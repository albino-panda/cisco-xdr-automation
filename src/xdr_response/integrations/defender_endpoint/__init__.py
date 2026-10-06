"""Microsoft Defender for Endpoint adapter."""
from xdr_response.integrations.defender_endpoint.adapter import DefenderEndpointAdapter
from xdr_response.integrations.defender_endpoint.manifest import MANIFEST

__all__ = ["DefenderEndpointAdapter", "MANIFEST"]
