"""Enrichment atomics (architecture 14.1.3; owner: enrichment).

* :mod:`xdr_response.atomics.enrichment.models` - :class:`ObservableReport` (layer 0 model module,
  re-exported here);
* :mod:`xdr_response.atomics.enrichment.atomics` - ``enrich_ip``, ``enrich_domain``, ``enrich_url``,
  ``enrich_hash``, ``enrich_email_address``, ``enrich_user``, ``enrich_endpoint``, ``enrich`` and the
  ``ENRICHMENT_ATOMICS`` / ``ENRICHMENT_SUBJECT_TYPES`` tables.

The atomics module is not imported here so that importing the model module never pulls in the
adapter facade; import the atomics from their module (or through ``xdr_response.atomics.read_atomics``).

Privacy: VirusTotal, OTX and HIBP only ever receive what ``DisclosurePolicy`` allows (public IPs,
external domains and URLs, hashes; HIBP only external email addresses). Hostnames, endpoint ids,
users, private IPs and internal domains go to internal tools only.
"""
from __future__ import annotations

from xdr_response.atomics.enrichment.models import ObservableReport

__all__ = ["ObservableReport"]
