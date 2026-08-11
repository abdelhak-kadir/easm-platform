"""csprecon — domain discovery via Content-Security-Policy headers.

Fetches the homepage of a domain and extracts every hostname listed in
its Content-Security-Policy (and Content-Security-Policy-Report-Only)
header.  CSP directives like ``script-src``, ``connect-src``, ``img-src``
often reference CDN endpoints, analytics platforms, and sister domains
that reveal an organisation's wider web footprint.

No API key required — works on any publicly accessible website.
"""

import logging
import re
from typing import Any

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_TIMEOUT_S = 15


class CspReconScanError(ToolScanError):
    """Raised when CSP reconnaissance fails."""


class CspReconRateLimitError(CspReconScanError, ToolRateLimitError):
    """Raised when the target server rate-limits — safe to retry."""


class CspReconNoDataError(CspReconScanError, ToolNoDataError):
    """Raised when no CSP header is present."""


def run(asset_value: str) -> dict[str, Any]:
    """Fetch CSP headers from *asset_value* and extract referenced domains."""
    domain = asset_value.strip().lower().rstrip(".")

    if not domain:
        raise CspReconNoDataError("Empty domain")

    urls_to_check = [f"https://{domain}", f"http://{domain}"]
    all_domains: set[str] = set()
    csp_raw: list[str] = []

    for url in urls_to_check:
        try:
            resp = requests.get(
                url,
                timeout=_TIMEOUT_S,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; EASM/1.0)"},
            )
        except requests.Timeout:
            continue
        except requests.ConnectionError:
            continue
        except requests.RequestException:
            continue

        for header_name in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
            csp_value = resp.headers.get(header_name, "")
            if csp_value:
                csp_raw.append(csp_value)
                all_domains.update(_extract_domains(csp_value))

    if not csp_raw:
        raise CspReconNoDataError(f"No CSP header found for {domain}")

    # Filter to related hosts
    related = sorted(all_domains)

    _logger.info("csprecon found %d domain(s) in CSP for %s", len(related), domain)

    return {
        "domain": domain,
        "csp_headers": csp_raw,
        "hosts": related,
        "emails": [],
        "ips": [],
        "urls": [],
        "sources_used": ["csprecon"],
    }


def _extract_domains(csp: str) -> set[str]:
    """Parse a CSP policy string and extract all hostnames."""
    domains: set[str] = set()

    # CSP directives contain URIs: https://example.com, wss://ws.example.com,
    # *.example.com, 'self', data:, etc.
    # Extract scheme://host or *.host patterns
    uri_pattern = re.compile(
        r"(?:https?|wss?|ftp)://([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)"
        r"|\*\.([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)",
        re.IGNORECASE,
    )

    for match in uri_pattern.finditer(csp):
        for group in match.groups():
            if group and group not in ("0.0.0.0", "127.0.0.1", "localhost") and "." in group:
                domains.add(group.strip().lower())

    return domains
