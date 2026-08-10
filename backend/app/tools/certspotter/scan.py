"""Certificate Transparency search via SSLMate CertSpotter API.

API docs: https://sslmate.com/help/reference/ct_search_api_v1
Endpoint: GET https://api.certspotter.com/v1/issuances

Works without an API key for low-volume evaluation; set CERTSPOTTER_API_KEY
in the environment for authenticated access with higher rate limits.
"""

import logging
import os
from typing import Any

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
_CERTSPOTTER_TIMEOUT_S = 30

# CertSpotter's ID field is an opaque string, not an integer.
_MAX_PAGES = 20  # safety cap — most domains fit in 1-3 pages


class CertSpotterScanError(ToolScanError):
    """Raised when a CertSpotter search can't be completed."""


class CertSpotterRateLimitError(CertSpotterScanError, ToolRateLimitError):
    """Raised when CertSpotter rate-limits — safe to retry."""


class CertSpotterNoDataError(CertSpotterScanError, ToolNoDataError):
    """Raised when CertSpotter has no data for the target — not a failure."""


def _auth_headers() -> dict[str, str]:
    api_key = os.environ.get("CERTSPOTTER_API_KEY")
    if api_key:
        return {"Authorization": f"Bearer {api_key}"}
    return {}


def run(asset_value: str) -> dict[str, Any]:
    """Search Certificate Transparency logs for all certificates issued
    to *asset_value* and its subdomains via CertSpotter.

    Paginates through all results (up to *_MAX_PAGES* pages) and returns
    the deduplicated set of DNS names across every cert found.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if not domain:
        raise CertSpotterNoDataError("Empty domain — nothing to search")

    all_dns_names: set[str] = set()
    after: str | None = None
    page = 0

    while page < _MAX_PAGES:
        params: dict[str, str] = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        if after:
            params["after"] = after

        try:
            resp = requests.get(
                _CERTSPOTTER_URL,
                params=params,
                headers=_auth_headers(),
                timeout=_CERTSPOTTER_TIMEOUT_S,
            )
        except requests.Timeout:
            raise CertSpotterRateLimitError(
                f"CertSpotter timed out for {domain} on page {page + 1}"
            ) from None
        except requests.ConnectionError as exc:
            raise CertSpotterScanError(
                f"CertSpotter connection failed for {domain}: {exc}"
            ) from exc

        if resp.status_code == 429:
            raise CertSpotterRateLimitError(
                f"CertSpotter rate-limited for {domain} on page {page + 1}"
            )
        if resp.status_code == 400:
            # Bad request — likely an invalid domain, not retryable.
            raise CertSpotterNoDataError(f"CertSpotter rejected the query for {domain} (400)")
        if resp.status_code != 200:
            raise CertSpotterScanError(f"CertSpotter returned HTTP {resp.status_code} for {domain}")

        try:
            data = resp.json()
        except ValueError as exc:
            raise CertSpotterScanError(f"CertSpotter returned invalid JSON for {domain}") from exc

        # CertSpotter returns a JSON array directly.  An error response
        # comes back as an object with a `code` key.
        if isinstance(data, dict):
            code = data.get("code", "")
            message = data.get("message", "")
            if code == "rate_limited":
                raise CertSpotterRateLimitError(f"CertSpotter rate-limited for {domain}: {message}")
            if code == "bad_request":
                raise CertSpotterNoDataError(f"CertSpotter bad request for {domain}: {message}")
            raise CertSpotterScanError(f"CertSpotter API error for {domain}: {code} — {message}")

        if not isinstance(data, list):
            raise CertSpotterScanError(
                f"CertSpotter returned unexpected response type for {domain}"
            )

        # Collect dns_names from this page
        page_dns_count = 0
        for issuance in data:
            dns_names: list[str] = issuance.get("dns_names") or []
            for name in dns_names:
                name = name.strip().lower().rstrip(".")
                if name:
                    all_dns_names.add(name)
                    page_dns_count += 1

        _logger.info(
            "CertSpotter page %d for %s: %d issuances, %d dns_names",
            page + 1,
            domain,
            len(data),
            page_dns_count,
        )

        # Pagination: use the last issuance's id as the cursor
        if len(data) > 0:
            after = data[-1].get("id")
            page += 1
        else:
            break

    # Filter to subdomains of the target domain, dropping wildcards
    hosts = sorted(
        name
        for name in all_dns_names
        if name.endswith(f".{domain}") and name != domain and "*" not in name
    )

    if not hosts:
        raise CertSpotterNoDataError(f"No certificates found in CT logs for {domain}")

    _logger.info(
        "CertSpotter found %d subdomain(s) for %s across %d page(s)",
        len(hosts),
        domain,
        page,
    )

    return {
        "domain": domain,
        "hosts": hosts,
        "emails": [],
        "ips": [],
        "urls": [],
        "sources_used": ["certspotter"],
    }
