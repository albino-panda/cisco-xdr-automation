"""Pure request builders for VirusTotal API v3 (docs/integrations.md section 2.13).

Base ``https://www.virustotal.com/api/v3``; header ``x-apikey`` (added by the auth provider).
Source: https://docs.virustotal.com/reference/overview
"""
from __future__ import annotations

import base64

from xdr_response.integrations._adapter_support import ApiRequest, segment

__all__ = ["BASE_URL", "url_id", "file_report", "domain_report", "ip_report", "url_report"]

BASE_URL = "https://www.virustotal.com/api/v3"


def url_id(url: str) -> str:
    """URL identifier: URL-safe base64 of the URL **without padding** (url-info page)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def file_report(file_hash: str) -> ApiRequest:
    """``GET /files/{sha256 | sha1 | md5}``. Source: https://docs.virustotal.com/reference/file-info"""
    return ApiRequest(operation="file_report", method="GET", path=f"files/{segment(file_hash)}",
                      expected=(200, 404))


def domain_report(domain: str) -> ApiRequest:
    """``GET /domains/{domain}``. Source: https://docs.virustotal.com/reference/domain-info"""
    return ApiRequest(operation="domain_report", method="GET", path=f"domains/{segment(domain)}",
                      expected=(200, 404))


def ip_report(ip: str) -> ApiRequest:
    """``GET /ip_addresses/{ip}``. Source: https://docs.virustotal.com/reference/ip-info"""
    return ApiRequest(operation="ip_report", method="GET", path=f"ip_addresses/{segment(ip, safe=':')}",
                      expected=(200, 404))


def url_report(url: str) -> ApiRequest:
    """``GET /urls/{id}``. Source: https://docs.virustotal.com/reference/url-info"""
    return ApiRequest(operation="url_report", method="GET", path=f"urls/{url_id(url)}", expected=(200, 404))
