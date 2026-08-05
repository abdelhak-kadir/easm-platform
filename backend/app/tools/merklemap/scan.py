import os

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_MERKLEMAP_URL = "https://api.merklemap.com/v1/search"
_MERKLEMAP_TIMEOUT_S = 30


class MerkleMapScanError(ToolScanError):
    """Raised when a MerkleMap search can't be completed."""


class MerkleMapRateLimitError(MerkleMapScanError, ToolRateLimitError):
    """Raised when MerkleMap rate-limits — safe to retry."""


class MerkleMapNoDataError(MerkleMapScanError, ToolNoDataError):
    """Raised when MerkleMap has no data for the target — not a failure."""


def run(asset_value: str) -> dict:
    """Passive subdomain discovery via MerkleMap's Certificate Transparency API.

    Queries ``GET /v1/search?query=<domain>&type=wildcard`` and paginates
    through all results. Hostnames are filtered to the target domain only.
    """
    domain = asset_value.strip().lower().rstrip(".")

    # Wildcard domains are not queryable — reject early.
    if "*" in domain:
        raise MerkleMapNoDataError(f"Wildcard domains are not queryable: {domain}")

    api_key = os.environ.get("MERKLEMAP_API_KEY")
    if not api_key:
        raise MerkleMapNoDataError("MERKLEMAP_API_KEY not set — skipping MerkleMap lookup")

    all_hosts: set[str] = set()
    page = 0

    while True:
        try:
            resp = requests.get(
                _MERKLEMAP_URL,
                params={"query": domain, "type": "wildcard", "page": page},
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=_MERKLEMAP_TIMEOUT_S,
            )
            resp.raise_for_status()
        except requests.Timeout:
            raise MerkleMapRateLimitError(
                f"MerkleMap request timed out after {_MERKLEMAP_TIMEOUT_S}s for {domain}"
            ) from None
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if status in (401, 403):
                raise MerkleMapNoDataError(
                    f"MerkleMap API access denied ({status}) for {domain} — check MERKLEMAP_API_KEY"
                ) from None
            if status == 429:
                raise MerkleMapRateLimitError(f"MerkleMap rate-limited on {domain}") from None
            if 500 <= status < 600:
                raise MerkleMapRateLimitError(
                    f"MerkleMap server error {status} for {domain}"
                ) from None
            raise MerkleMapScanError(f"MerkleMap request failed ({status}) for {domain}") from e
        except requests.ConnectionError as e:
            raise MerkleMapScanError(f"MerkleMap connection failed for {domain}: {e}") from e

        data = resp.json()
        results: list[dict] = data.get("results") or []

        if not results:
            break

        for entry in results:
            hostname = (entry.get("hostname") or "").strip().lower().rstrip(".")
            if hostname and hostname != domain and hostname.endswith(f".{domain}"):
                all_hosts.add(hostname)

        page += 1

    hosts = sorted(all_hosts)

    if not hosts:
        raise MerkleMapNoDataError(f"No subdomains found for {domain}")

    return {
        "domain": domain,
        "hosts": hosts,
        "emails": [],
        "ips": [],
        "urls": [],
        "sources_used": ["merklemap"],
    }
