import re
from datetime import datetime

import whois as whois_lib

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError
from app.tools.whois._util import to_aware

_REGISTRABLE_SUFFIX_RE = re.compile(r"([^.]+\.[^.]+)$")


class WhoisScanError(ToolScanError):
    """Raised when a WHOIS lookup can't be completed."""


class WhoisRateLimitError(WhoisScanError, ToolRateLimitError):
    """Raised when the WHOIS server throttles us — safe to retry."""


class WhoisNoDataError(WhoisScanError, ToolNoDataError):
    """Raised when there's no WHOIS record for the target — not a failure."""


def run(asset_value: str) -> dict:
    """
    Look up WHOIS registration data for a domain or subdomain.

    Returns a JSON-safe dict. python-whois hands back native `datetime`
    objects for date fields, which aren't valid JSON -- since this raw
    response is persisted straight into a JSONB column (`ScanResult.raw_data`),
    every date is converted to an ISO 8601 string before it's returned.
    """
    domain = _to_registrable_domain(asset_value)

    try:
        result = whois_lib.whois(domain)
    except Exception as e:
        message = str(e).lower()
        if "rate limit" in message or "quota" in message or "too many" in message:
            raise WhoisRateLimitError(f"WHOIS rate limit reached for {domain}: {e}") from e
        raise WhoisScanError(f"WHOIS lookup failed for {domain}: {e}") from e

    if not result or not result.get("domain_name"):
        raise WhoisNoDataError(f"No WHOIS data available for {domain}")

    return _to_json_safe(dict(result))


def _to_registrable_domain(asset_value: str) -> str:
    """Reduce e.g. `app.staging.example.com` to `example.com` -- WHOIS
    only has records for registered domains, not subdomains.

    This is a simple last-two-labels heuristic; it under-handles
    multi-part public suffixes (.co.uk, .com.au). Swap in `tldextract`
    if that becomes a real problem.
    """
    match = _REGISTRABLE_SUFFIX_RE.search(asset_value.strip().lower().rstrip("."))
    return match.group(1) if match else asset_value


def _to_json_safe(value):
    if isinstance(value, datetime):
        return to_aware(value).isoformat()
    if isinstance(value, dict):
        return {k: _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_json_safe(v) for v in value]
    return value
