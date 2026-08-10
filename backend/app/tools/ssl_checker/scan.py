"""SSL certificate check via CrtMgr public API.

Rate limits: 3/min, 20/hour, 50/day per IP.  Exceeding them returns 429.
"""

import logging

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_CRTMGR_URL = "https://api.crtmgr.com/api/v1/ssl-checker"
_CRTMGR_TIMEOUT_S = 15

# CrtMgr is behind Cloudflare.  429 and 5xx have different meanings:
# - 429: genuine rate limit — retry later
# - 502/503: transient Cloudflare or origin hiccup — retry later
# - 504: origin is DOWN — retrying won't help, treat as hard failure
_RETRYABLE_STATUSES = frozenset({429, 502, 503})


def _clean_error_body(resp: requests.Response) -> str:
    """Extract a readable error from a Cloudflare-wrapped HTML response."""
    text = (resp.text or "").strip()
    if not text:
        return ""
    # If it looks like HTML, extract just the <title> or return a short summary
    if text.startswith("<!") or text.startswith("<html"):
        import re

        match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
        if match:
            return match.group(1)[:200]
        return f"HTML response ({len(text)} bytes)"
    return text[:200]


class SslCheckerScanError(ToolScanError):
    """Raised when an SSL certificate check can't be completed."""


class SslCheckerRateLimitError(SslCheckerScanError, ToolRateLimitError):
    """Raised when CrtMgr rate-limits or has a transient server error — safe to retry."""


class SslCheckerNoDataError(SslCheckerScanError, ToolNoDataError):
    """Raised when the target has no reachable HTTPS service — not a failure."""


def run(asset_value: str) -> dict:
    """Fetch the live TLS certificate for *asset_value* from CrtMgr.

    Returns the JSON response containing CN, issuer, validity window,
    SANs, key type / size, fingerprint, and expiry status.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if not domain:
        raise SslCheckerNoDataError("Empty domain — nothing to check")

    try:
        resp = requests.get(
            _CRTMGR_URL,
            params={"domain": domain},
            timeout=_CRTMGR_TIMEOUT_S,
        )

        if resp.status_code in _RETRYABLE_STATUSES:
            detail = _clean_error_body(resp) or f"HTTP {resp.status_code}"
            raise SslCheckerRateLimitError(
                f"CrtMgr returned {resp.status_code} for {domain}: {detail}"
            )

        if resp.status_code == 400:
            raise SslCheckerNoDataError(
                f"CrtMgr rejected the request for {domain} (400) — domain may not resolve"
            )

        if resp.status_code == 504:
            raise SslCheckerScanError(
                f"CrtMgr origin is unreachable (504) for {domain} — "
                "the upstream service is down, not a rate-limit issue"
            )

        if resp.status_code != 200:
            raise SslCheckerScanError(
                f"CrtMgr returned unexpected status {resp.status_code} for {domain}"
            )

        data = resp.json()

    except requests.Timeout:
        raise SslCheckerRateLimitError(
            f"CrtMgr timed out after {_CRTMGR_TIMEOUT_S}s for {domain}"
        ) from None
    except requests.ConnectionError as exc:
        raise SslCheckerScanError(f"CrtMgr connection failed for {domain}: {exc}") from exc
    except SslCheckerScanError:
        raise
    except Exception as exc:
        raise SslCheckerScanError(f"Unexpected error checking SSL for {domain}: {exc}") from exc

    # A 200 with no CN means the API accepted the request but couldn't connect
    # to the target — treat as clean no-data.
    if not data.get("cn"):
        raise SslCheckerNoDataError(
            f"No certificate found for {domain} — target may not serve HTTPS"
        )

    _logger.info(
        "SSL cert fetched for %s: issuer=%s, days_left=%s",
        domain,
        data.get("issuer"),
        data.get("days_left"),
    )

    return data
