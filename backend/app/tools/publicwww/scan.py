"""PublicWWW — source-code search engine for web pages.

PublicWWW indexes HTML, JS, and CSS of ~469 million web pages.  Searching
for a domain name returns pages whose source code references that domain,
revealing related sites, subdomains, CDN endpoints, and technology stacks.

Uses the CSV export endpoint (CSV is more reliable than the JSON API).
The CSV has columns: Rank ; URL ; Snippet (delimited by ;).

CSV endpoint: https://publicwww.com/websites/\"{domain}\"/?export=csvu&key=...
"""

import csv
import io
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_PUBLICWWW_TIMEOUT_S = 30
_CSV_COL_DELIM = ";"


class PublicWWWScanError(ToolScanError):
    """Raised when a PublicWWW search can't be completed."""


class PublicWWWRateLimitError(PublicWWWScanError, ToolRateLimitError):
    """Raised when PublicWWW rate-limits — safe to retry."""


class PublicWWWNoDataError(PublicWWWScanError, ToolNoDataError):
    """Raised when PublicWWW has no data for the target."""


def run(asset_value: str) -> dict[str, Any]:
    """Search PublicWWW for pages referencing *asset_value* in their source.

    Downloads CSV export and extracts hostnames from page URLs.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if not domain:
        raise PublicWWWNoDataError("Empty domain — nothing to search")

    api_key = os.environ.get("PUBLICWWW_API_KEY")
    if not api_key:
        raise PublicWWWNoDataError(
            "PUBLICWWW_API_KEY not set — get a free key at https://publicwww.com/profile/"
        )

    _logger.info("PublicWWW searching for %s", domain)

    # CSV export URL — query is the domain in double-quotes, URL-encoded
    query = f'"{domain}"'
    url = (
        f"https://publicwww.com/websites/{requests.utils.quote(query)}/"
        f"?export=csvu&key={api_key}"
    )

    try:
        resp = requests.get(url, timeout=_PUBLICWWW_TIMEOUT_S)
    except requests.Timeout:
        raise PublicWWWRateLimitError(f"PublicWWW timed out for {domain}") from None
    except requests.ConnectionError as e:
        raise PublicWWWScanError(f"PublicWWW connection failed for {domain}: {e}") from e

    if resp.status_code == 429:
        raise PublicWWWRateLimitError(f"PublicWWW rate-limited for {domain}")
    if resp.status_code in (401, 403):
        raise PublicWWWScanError("PublicWWW API key invalid — check PUBLICWWW_API_KEY")
    if resp.status_code != 200:
        raise PublicWWWScanError(f"PublicWWW returned HTTP {resp.status_code} for {domain}")

    # Parse CSV: Rank ; URL ; Snippet
    all_urls: set[str] = set()
    hosts_found: set[str] = set()
    ips_found: set[str] = set()
    _IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    text = resp.text.strip()
    if not text:
        raise PublicWWWNoDataError(f"No pages reference {domain} in source code")

    reader = csv.reader(io.StringIO(text), delimiter=_CSV_COL_DELIM)
    for row in reader:
        if len(row) < 2:
            continue
        page_url = row[1].strip() if len(row) > 1 else ""
        if not page_url:
            continue
        all_urls.add(page_url)

        # Extract hostname from URL
        try:
            parsed = urlparse(page_url)
            host = (parsed.hostname or "").strip().lower().rstrip(".")
            if host and _IP_RE.fullmatch(host):
                ips_found.add(host)
            elif host and host.endswith(f".{domain}") and host != domain:
                hosts_found.add(host)
        except Exception:
            pass

    # ── Build result ───────────────────────────────────────────────
    if not all_urls:
        raise PublicWWWNoDataError(f"No pages reference {domain} in source code")

    _logger.info(
        "PublicWWW found %d page(s), %d host(s) for %s",
        len(all_urls),
        len(hosts_found),
        domain,
    )

    return {
        "domain": domain,
        "total_hits": len(all_urls),
        "pages_found": len(all_urls),
        "hosts": sorted(hosts_found),
        "ips": sorted(ips_found),
        "emails": [],
        "urls": sorted(all_urls)[:200],
        "sources_used": ["publicwww"],
    }
