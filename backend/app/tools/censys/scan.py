import ipaddress
import os

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"
_CENSYS_TIMEOUT_S = 30


class CensysScanError(ToolScanError):
    """Raised when a Censys host lookup can't be completed."""


class CensysRateLimitError(CensysScanError, ToolRateLimitError):
    """Raised when Censys rate-limits — safe to retry."""


class CensysNoDataError(CensysScanError, ToolNoDataError):
    """Raised when Censys has no data for the target — not a failure."""


def run(asset_value: str) -> dict:
    """Look up an IP in Censys Search v2 and return host information.

    Censys only accepts IPs. Subnets and CIDRs are not supported for host lookup.
    Domains/subdomains are not resolved — this tool is registered for IP assets only.
    """
    ip = asset_value.strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise CensysScanError(f"'{ip}' is not a valid IP address — Censys requires an IP") from None

    api_id = os.environ.get("CENSYS_API_ID")
    api_secret = os.environ.get("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        raise CensysNoDataError(
            "CENSYS_API_ID and CENSYS_API_SECRET not set — skipping Censys lookup"
        )

    try:
        resp = requests.get(
            _CENSYS_HOST_URL.format(ip=ip),
            auth=(api_id, api_secret),
            timeout=_CENSYS_TIMEOUT_S,
        )
        resp.raise_for_status()
    except requests.Timeout:
        raise CensysRateLimitError(
            f"Censys host lookup timed out after {_CENSYS_TIMEOUT_S}s for {ip}"
        ) from None
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else 0
        if status == 404:
            raise CensysNoDataError(f"No Censys data available for {ip}") from None
        if status in (401, 403):
            raise CensysNoDataError(
                f"Censys API access denied ({status}) for {ip} — check credentials"
            ) from None
        if status == 429:
            raise CensysRateLimitError(f"Censys rate-limited on {ip}") from None
        if 500 <= status < 600:
            raise CensysRateLimitError(f"Censys server error {status} for {ip}") from None
        raise CensysScanError(f"Censys host lookup failed ({status}) for {ip}") from e
    except requests.ConnectionError as e:
        raise CensysScanError(f"Censys host lookup connection failed for {ip}: {e}") from e

    data = resp.json()
    result = data.get("result") or {}

    if not result:
        raise CensysNoDataError(f"No Censys data available for {ip}")

    return result
