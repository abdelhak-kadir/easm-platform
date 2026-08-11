"""CloudScraper — cloud storage enumeration (S3, Azure Blob, DigitalOcean).

Generates common bucket/storage naming permutations from a domain and
probes each against AWS S3, Azure Blob Storage, and DigitalOcean Spaces.
No credentials required — works by HTTP response analysis.

A 200 means the bucket is PUBLIC (high severity finding).
A 403 means the bucket EXISTS but is private.
No response / DNS NXDOMAIN means no bucket with that name.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)

_TIMEOUT = 10
_MAX_WORKERS = 20

# Naming permutations derived from the domain
_PERMUTATIONS = [
    "{name}",
    "{name}-prod",
    "{name}-dev",
    "{name}-staging",
    "{name}-test",
    "{name}-backup",
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-files",
    "{name}-data",
    "{name}-cdn",
    "{name}-logs",
    "{name}-tmp",
    "{name}-www",
    "{name}-app",
    "{name}-api",
    "prod-{name}",
    "dev-{name}",
    "staging-{name}",
]

# Storage endpoints
_ENDPOINTS: list[dict[str, str]] = [
    {"provider": "aws_s3", "url": "https://{bucket}.s3.amazonaws.com"},
    {"provider": "aws_s3", "url": "https://{bucket}.s3.amazonaws.com/"},
    {"provider": "aws_s3", "url": "https://s3.amazonaws.com/{bucket}/"},
    {"provider": "azure_blob", "url": "https://{bucket}.blob.core.windows.net/"},
    {"provider": "azure_blob", "url": "https://{bucket}.blob.core.windows.net"},
    {"provider": "digitalocean", "url": "https://{bucket}.nyc3.digitaloceanspaces.com"},
    {"provider": "digitalocean", "url": "https://{bucket}.digitaloceanspaces.com"},
    {"provider": "gcp_storage", "url": "https://storage.googleapis.com/{bucket}/"},
    {"provider": "gcp_storage", "url": "https://{bucket}.storage.googleapis.com/"},
]


class CloudScraperScanError(ToolScanError):
    """Raised when cloud enumeration fails."""


class CloudScraperNoDataError(CloudScraperScanError, ToolNoDataError):
    """Raised when no storage buckets are found."""


def run(asset_value: str) -> dict[str, Any]:
    """Enumerate cloud storage buckets for permutations of *asset_value*."""
    domain = asset_value.strip().lower().rstrip(".")
    name = domain.split(".")[0]  # short name for permutations

    if not name:
        raise CloudScraperNoDataError("Invalid domain")

    _logger.info("CloudScraper enumerating buckets for %s", domain)

    # Generate all (bucket_name, endpoint) pairs
    tasks: list[tuple[str, dict[str, str]]] = []
    for perm in _PERMUTATIONS:
        bucket = perm.format(name=name)
        for ep in _ENDPOINTS:
            tasks.append((bucket, ep))

    found: list[dict] = []

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_probe, bucket, ep): (bucket, ep) for bucket, ep in tasks}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    found.append(result)
            except Exception:
                pass

    # Deduplicate by bucket + provider
    seen: set[tuple[str, str]] = set()
    unique: list[dict] = []
    for f in found:
        key = (f["bucket"], f["provider"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    if not unique:
        raise CloudScraperNoDataError(f"No cloud storage buckets found for {domain}")

    _logger.info("CloudScraper found %d bucket(s) for %s", len(unique), domain)

    return {
        "domain": domain,
        "name": name,
        "buckets": unique,
        "total_probed": len(tasks),
        "sources_used": ["cloudscraper"],
    }


def _probe(bucket: str, ep: dict) -> dict | None:
    """Probe one bucket/endpoint combination. Returns bucket info or None."""
    url = ep["url"].format(bucket=bucket)
    provider = ep["provider"]

    try:
        resp = requests.get(url, timeout=_TIMEOUT, allow_redirects=False)
        status = resp.status_code
    except requests.Timeout:
        return None
    except requests.ConnectionError:
        return None

    if status in (200, 403):
        return {
            "bucket": bucket,
            "provider": provider,
            "url": url,
            "public": status == 200,
            "status_code": status,
        }

    return None
