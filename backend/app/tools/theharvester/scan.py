import ipaddress
import re

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

# Certificate Transparency — the one source that actually works reliably.
# Every other "source" in theHarvester is either an HTML scraper (fragile,
# breaks when upstream changes), requires an API key, or rate-limits
# aggressively. CRT.sh is a public JSON API: no auth, no scraping, 1–5 s.
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_CRTSH_TIMEOUT_S = 30

# DNS-based extraction: A/AAAA records for each discovered hostname.
# Disabled by default (adds latency proportional to host count) but
# useful when you want IPs alongside subdomains.
_RESOLVE_IPS = False

# Bare-IP regex — crt.sh name_value fields sometimes contain raw IPs
# from cert SAN entries.
_IP_RE = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b" r"|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)


class TheHarvesterScanError(ToolScanError):
    """Raised when a theHarvester search can't be completed."""


class TheHarvesterRateLimitError(TheHarvesterScanError, ToolRateLimitError):
    """Raised when a source engine rate-limits — safe to retry."""


class TheHarvesterNoDataError(TheHarvesterScanError, ToolNoDataError):
    """Raised when no data is found — target may have no public footprint."""


def run(asset_value: str) -> dict:
    """Passive OSINT discovery against a domain.

    Queries CRT.sh (Certificate Transparency logs) directly via HTTP —
    no theHarvester framework, no scraping, no async event-loop overhead.
    Returns discovered hostnames, IPs, and emails extracted from cert
    subject-alt-name fields.
    """
    domain = asset_value.strip().lower().rstrip(".")

    all_hosts: set[str] = set()
    all_ips: set[str] = set()
    all_emails: set[str] = set()

    _query_crtsh(domain, all_hosts, all_ips, all_emails)

    hosts = sorted(all_hosts)
    ips = sorted(all_ips, key=_ip_sort_key)

    if _RESOLVE_IPS and hosts:
        ips = sorted({*ips, *_resolve_hostnames(hosts)}, key=_ip_sort_key)

    data: dict = {
        "domain": domain,
        "emails": sorted(all_emails),
        "hosts": hosts,
        "ips": ips,
        "urls": [],
        "sources_used": ["crtsh"],
    }

    if not any(data[k] for k in ("emails", "hosts", "ips", "urls")):
        raise TheHarvesterNoDataError(f"No public data found for {domain}")

    return data


# ── CRT.sh ────────────────────────────────────────────────────────────


def _query_crtsh(
    domain: str,
    hosts: set[str],
    ips: set[str],
    emails: set[str],
) -> None:
    """Fetch cert transparency entries from crt.sh and extract hostnames,
    IPs, and email addresses from the name_value / common_name fields."""
    url = _CRTSH_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=_CRTSH_TIMEOUT_S)
        resp.raise_for_status()
    except requests.Timeout:
        raise TheHarvesterScanError(
            f"CRT.sh request timed out after {_CRTSH_TIMEOUT_S}s for {domain}"
        ) from None
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else 0
        if status == 429:
            raise TheHarvesterRateLimitError(f"CRT.sh rate-limited for {domain}") from e
        if status >= 500:
            # 502/503/504 are transient server errors — safe to retry
            raise TheHarvesterRateLimitError(f"CRT.sh server error ({status}) for {domain}") from e
        raise TheHarvesterScanError(f"CRT.sh request failed for {domain}: {e}") from e
    except requests.RequestException as e:
        raise TheHarvesterScanError(f"CRT.sh request failed for {domain}: {e}") from e

    try:
        entries: list[dict] = resp.json()
    except ValueError:
        return  # empty or malformed response — not an error

    for entry in entries:
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if not value:
                continue
            for name in str(value).splitlines():
                name = name.strip().lower().rstrip(".")
                if not name or name == domain:
                    continue
                if name.endswith(f".{domain}") or name == domain:
                    hosts.add(name)
                elif _IP_RE.fullmatch(name):
                    ips.add(name)
                elif "@" in name and _email_matches_domain(name, domain):
                    emails.add(name)


# ── optional DNS resolution ───────────────────────────────────────────


def _resolve_hostnames(hostnames: list[str]) -> set[str]:
    """Best-effort A/AAAA resolution for discovered hostnames."""
    import socket

    resolved: set[str] = set()
    for host in hostnames:
        try:
            resolved.add(socket.gethostbyname(host))
        except OSError:
            pass
    return resolved


# ── helpers ───────────────────────────────────────────────────────────


def _email_matches_domain(email: str, domain: str) -> bool:
    """Check whether *email* belongs to *domain* (best-effort — only
    compares the last two labels, so it under-handles .co.uk & friends)."""
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    registrable = ".".join(parts[-2:])
    return email.endswith("@" + registrable) or email.endswith("." + registrable)


def _ip_sort_key(ip: str):
    """Sort IPs numerically rather than lexicographically."""
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return ipaddress.ip_address("0.0.0.0")
