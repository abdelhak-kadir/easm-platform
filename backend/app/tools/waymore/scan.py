"""WayMore — multi-source URL/subdomain discovery.

Aggregates results from 4 free passive sources:

1. **Wayback Machine** — historical URL snapshots (archive.org)
2. **Common Crawl** — web crawl index (index.commoncrawl.org)
3. **URLScan.io** — URL submission/search engine (urlscan.io)
4. **AlienVault OTX** — Open Threat Exchange passive DNS

No API keys required for Wayback or Common Crawl. URLScan and OTX
need free API keys for higher limits.

Each source returns a distinct set of URLs; we extract hostnames from
the combined results.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)
_TIMEOUT = 20


class WayMoreScanError(ToolScanError):
    """Raised when WayMore collection fails."""


class WayMoreRateLimitError(WayMoreScanError, ToolRateLimitError):
    """Raised when a source rate-limits — safe to retry."""


class WayMoreNoDataError(WayMoreScanError, ToolNoDataError):
    """Raised when no sources return data."""


def run(asset_value: str) -> dict[str, Any]:
    """Aggregate URLs/hosts from multiple passive sources."""
    domain = asset_value.strip().lower().rstrip(".")

    if not domain:
        raise WayMoreNoDataError("Empty domain")

    _logger.info("WayMore collecting for %s", domain)

    all_hosts: set[str] = set()
    all_urls: set[str] = set()
    sources_hit: list[str] = []

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(_wayback, domain): "wayback",
            pool.submit(_commoncrawl, domain): "commoncrawl",
            pool.submit(_urlscan, domain): "urlscan",
            pool.submit(_otx, domain): "otx",
        }
        for future in as_completed(futures):
            src = futures[future]
            try:
                urls, hosts = future.result()
                if urls or hosts:
                    all_urls.update(urls)
                    all_hosts.update(hosts)
                    sources_hit.append(src)
            except Exception:
                pass

    if not sources_hit:
        raise WayMoreNoDataError(f"No passive sources returned data for {domain}")

    # Filter hosts to same domain
    filtered = {h for h in all_hosts if h.endswith(f".{domain}") and h != domain}

    _logger.info("WayMore found %d host(s) from %s for %s", len(filtered), sources_hit, domain)

    return {
        "domain": domain,
        "hosts": sorted(filtered),
        "urls": sorted(all_urls)[:200],
        "emails": [],
        "ips": [],
        "sources_used": ["waymore"] + sources_hit,
    }


# ── Source: Wayback Machine ──────────────────────────────────────────


def _wayback(domain: str) -> tuple[set[str], set[str]]:
    urls, hosts = set(), set()
    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "limit": 500,
                "fl": "original",
                "collapse": "urlkey",
            },
            timeout=_TIMEOUT,
        )
        data = resp.json()
        for row in data[1:]:  # skip header
            url = row[0]
            urls.add(url)
            m = re.match(r"https?://([^/]+)", url)
            if m:
                hosts.add(m.group(1).lower().rstrip("."))
    except Exception:
        pass
    return urls, hosts


# ── Source: Common Crawl ─────────────────────────────────────────────


def _commoncrawl(domain: str) -> tuple[set[str], set[str]]:
    urls, hosts = set(), set()
    try:
        # Get latest index list
        idx_resp = requests.get("https://index.commoncrawl.org/collinfo.json", timeout=_TIMEOUT)
        indices = idx_resp.json()
        if indices:
            latest = indices[0]["id"]
            resp = requests.get(
                f"https://index.commoncrawl.org/{latest}-index",
                params={"url": f"*.{domain}", "output": "json", "limit": 500},
                timeout=_TIMEOUT,
            )
            for line in resp.text.strip().split("\n"):
                try:
                    entry = __import__("json").loads(line)
                    url = entry.get("url", "")
                    if url:
                        urls.add(url)
                        m = re.match(r"https?://([^/]+)", url)
                        if m:
                            hosts.add(m.group(1).lower().rstrip("."))
                except Exception:
                    pass
    except Exception:
        pass
    return urls, hosts


# ── Source: URLScan.io ───────────────────────────────────────────────


def _urlscan(domain: str) -> tuple[set[str], set[str]]:
    urls, hosts = set(), set()
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}"},
            timeout=_TIMEOUT,
        )
        for r in (resp.json().get("results") or [])[:100]:
            url = r.get("task", {}).get("url", "")
            if url:
                urls.add(url)
                m = re.match(r"https?://([^/]+)", url)
                if m:
                    hosts.add(m.group(1).lower().rstrip("."))
    except Exception:
        pass
    return urls, hosts


# ── Source: AlienVault OTX ───────────────────────────────────────────


def _otx(domain: str) -> tuple[set[str], set[str]]:
    urls, hosts = set(), set()
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=_TIMEOUT,
        )
        for entry in (resp.json().get("passive_dns") or [])[:100]:
            hostname = entry.get("hostname", "")
            if hostname:
                hosts.add(hostname.lower().rstrip("."))
    except Exception:
        pass
    return urls, hosts
