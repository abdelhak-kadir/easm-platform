"""Shodan org/ASN search -- discovers *additional* IPs that share an
organization or netblock with an IP you already scanned.

Deliberately NOT wired into TOOL_REGISTRY's spawns/resolve_spawn_value
chain like WHOIS<->Shodan: org/net matches are much higher
false-positive risk (shared hosting, CDNs, cloud providers can all
share an org string), so this is surfaced as suggestions for a human
to accept, not auto-created assets.
"""

import os

import shodan

_MAX_RESULTS = 100

# Orgs where a match is expected to be near-meaningless for asset
# discovery -- these are shared-hosting/cloud providers, so "same org"
# just means "also uses AWS", not "belongs to the same target".
_CLOUD_ORG_MARKERS = (
    "amazon",
    "aws",
    "google cloud",
    "google llc",
    "microsoft",
    "azure",
    "cloudflare",
    "digitalocean",
    "ovh",
    "akamai",
    "fastly",
    "linode",
    "hetzner",
    "alibaba",
)


class ShodanSearchError(Exception):
    """Raised when a Shodan org/net search can't be completed."""


def is_likely_shared_hosting(org: str | None) -> bool:
    """Best-effort heuristic: does this org string belong to a cloud/
    CDN/hosting provider, where 'same org' is a weak discovery signal?
    """
    if not org:
        return False
    lowered = org.lower()
    return any(marker in lowered for marker in _CLOUD_ORG_MARKERS)


def search_by_org(org: str, limit: int = _MAX_RESULTS) -> list[dict]:
    """Find other IPs Shodan has indexed under the same org string."""
    return _search(f'org:"{org}"', limit)


def search_by_net(cidr: str, limit: int = _MAX_RESULTS) -> list[dict]:
    """Find other IPs Shodan has indexed within the same netblock."""
    return _search(f"net:{cidr}", limit)


def _search(query: str, limit: int) -> list[dict]:
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        raise ShodanSearchError("SHODAN_API_KEY is not set")

    api = shodan.Shodan(api_key)
    try:
        results = api.search(query, limit=limit)
    except shodan.APIError as e:
        raise ShodanSearchError(f"Shodan search failed for '{query}': {e}") from e

    return _dedupe_by_ip(results.get("matches", []))


def _dedupe_by_ip(matches: list[dict]) -> list[dict]:
    """Shodan's search returns one match per indexed service/port, so
    the same IP can appear multiple times -- collapse to one candidate
    per IP, merging ports/hostnames seen across its matches."""
    candidates: dict[str, dict] = {}

    for match in matches:
        ip = match.get("ip_str")
        if not ip:
            continue

        candidate = candidates.setdefault(
            ip,
            {
                "ip": ip,
                "org": match.get("org"),
                "hostnames": [],
                "ports": [],
                "products": [],
            },
        )

        for hostname in match.get("hostnames", []) or []:
            if hostname not in candidate["hostnames"]:
                candidate["hostnames"].append(hostname)

        port = match.get("port")
        if port is not None and port not in candidate["ports"]:
            candidate["ports"].append(port)

        product = match.get("product")
        if product and product not in candidate["products"]:
            candidate["products"].append(product)

    return list(candidates.values())
