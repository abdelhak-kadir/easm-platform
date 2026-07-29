import ipaddress
import os
import socket

import requests
import shodan

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError


class ShodanScanError(ToolScanError):
    """Raised when a Shodan lookup can't be completed."""


class ShodanRateLimitError(ShodanScanError, ToolRateLimitError):
    """Raised when Shodan's API rate limit is hit — safe to retry."""


class ShodanNoDataError(ShodanScanError, ToolNoDataError):
    """Raised when Shodan has no indexed data for the target — not a failure."""


def run(asset_value: str) -> dict:
    """
    Look up an asset (IP, domain, or subdomain) in Shodan.

    Shodan's host lookup only accepts IPs, so a domain/subdomain is
    resolved to an IP first. Returns the raw Shodan host response.
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        raise ShodanScanError("SHODAN_API_KEY is not set")

    ip = asset_value if _is_ip(asset_value) else _resolve_to_ip(asset_value)

    api = shodan.Shodan(api_key)
    try:
        host_data = api.host(ip)
    except shodan.APIError as e:
        message = str(e).lower()
        if "no information available" in message:
            raise ShodanNoDataError(f"No Shodan data available for {ip}") from e
        if "rate limit" in message:
            raise ShodanRateLimitError(f"Shodan rate limit reached for {ip}: {e}") from e
        raise ShodanScanError(f"Shodan lookup failed for {ip}: {e}") from e

    if isinstance(host_data.get("vulns"), list):
        host_data["vulns"] = _enrich_vulns_with_cvss(host_data["vulns"])

    return host_data


def _resolve_to_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except OSError as e:
        raise ShodanScanError(f"Could not resolve '{hostname}' to an IP address") from e


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _enrich_vulns_with_cvss(vulns: list[str]) -> dict:
    """When Shodan's host() response gives vulns as bare CVE ID strings
    (lower API tier), fetch real CVSS scores from Shodan's free public
    CVEDB so severity isn't lost to a Low-severity default."""
    enriched = {}
    for cve_id in vulns:
        try:
            resp = requests.get(f"https://cvedb.shodan.io/cve/{cve_id}", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            enriched[cve_id] = {
                "cvss": data.get("cvss") or 0.0,
                "summary": data.get("summary", ""),
            }
        except requests.RequestException:
            enriched[cve_id] = {"cvss": 0.0, "summary": ""}
    return enriched
