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

    if isinstance(host_data.get("vulns"), list | dict):
        host_data["vulns"] = _enrich_vulns(host_data["vulns"])

    # Normalize `hostnames` into the `hosts` key the suggest-discovered
    # endpoint expects, so Shodan-discovered hostnames (e.g.
    # office.iis.u-tokyo.ac.jp) flow into the human-gated acceptance UI
    # like the other discovery tools.
    host_data["hosts"] = host_data.get("hostnames") or []

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


def _enrich_vulns(vulns: list | dict) -> dict:
    """Fetch the full public CVE record for every CVE ID from Shodan's free
    CVEDB, regardless of which Shodan tier the host response came from.

    Both shapes get the same treatment:
    - bare list of CVE ID strings (lower API tier) — CVSS/summary and
      everything else come only from CVEDB;
    - dict of {cve_id: {cvss, summary}} (upper tier) — the tier already
      ships cvss/summary, but the fix-verdict fields (`cpes` affected
      versions), exploit context (`kev`, `epss`) and references only exist
      in the CVEDB record, so it's still fetched.

    Failures are best-effort: keep whatever the tier provided; the verdict
    just won't be computed for that CVE.
    """
    if isinstance(vulns, list):
        vulns = {cve_id: {} for cve_id in vulns}

    enriched = {}
    for cve_id, info in vulns.items():
        record = {
            "cvss": info.get("cvss") or 0.0,
            "summary": info.get("summary", ""),
        }
        try:
            resp = requests.get(f"https://cvedb.shodan.io/cve/{cve_id}", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            record.update(
                {
                    "cves": data.get("cpes", []),
                    "kev": bool(data.get("kev")),
                    "epss": data.get("epss") or 0.0,
                    "epss_ranking": data.get("ranking_epss") or 0.0,
                    "published_time": data.get("published_time", ""),
                    "references": data.get("references", []),
                }
            )
            # Prefer CVEDB's cvss/summary when present — same record the
            # tier data mirrors, but guaranteed complete.
            if data.get("cvss") is not None:
                record["cvss"] = data["cvss"]
            if data.get("summary"):
                record["summary"] = data["summary"]
        except requests.RequestException:
            pass  # keep tier-provided cvss/summary; no verdict for this CVE
        enriched[cve_id] = record
    return enriched
