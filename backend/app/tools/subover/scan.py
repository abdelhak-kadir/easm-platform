"""SubOver — subdomain takeover vulnerability detection.

Resolves CNAME records for subdomains and checks whether the target
service is vulnerable to takeover (dangling DNS → unclaimed cloud resource).

Checks for the most common takeover-able services:
- AWS S3 / CloudFront
- Azure (blob, cloudapp, trafficmanager)
- GitHub Pages
- Heroku
- Shopify
- Fastly
- And more...

No API key required — pure DNS.
"""

import logging
import socket
from typing import Any

import dns.resolver

from app.tools.base import ToolNoDataError, ToolScanError

_logger = logging.getLogger(__name__)
_DNS_TIMEOUT = 10

# Services with known takeover vectors and their CNAME patterns
_TAKEOVER_SERVICES: dict[str, str] = {
    "s3.amazonaws.com": "AWS S3 bucket",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "blob.core.windows.net": "Azure Blob Storage",
    "cloudapp.net": "Azure CloudApp",
    "azurewebsites.net": "Azure Web Apps",
    "trafficmanager.net": "Azure Traffic Manager",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku DNS",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "fastly.net": "Fastly CDN",
    "surge.sh": "Surge.sh",
    "firebaseapp.com": "Firebase Hosting",
    "web.app": "Firebase Hosting",
    "azure-api.net": "Azure API Management",
    "azurecontainer.io": "Azure Container Instances",
}


class SubOverScanError(ToolScanError):
    pass


class SubOverNoDataError(SubOverScanError, ToolNoDataError):
    pass


def run(asset_value: str) -> dict[str, Any]:
    """Check *asset_value* for subdomain takeover via CNAME analysis."""
    hostname = asset_value.strip().lower().rstrip(".")

    if not hostname or "*" in hostname:
        raise SubOverNoDataError(f"Invalid hostname: {hostname!r}")

    _logger.info("SubOver checking %s", hostname)

    vulnerable: list[dict] = []
    cnames: list[str] = []

    try:
        answers = dns.resolver.resolve(hostname, "CNAME")
        for answer in answers:
            target = str(answer).rstrip(".").lower()
            cnames.append(target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.Timeout as e:
        raise SubOverScanError(f"DNS timeout for {hostname}") from e
    except Exception as e:
        raise SubOverScanError(f"DNS query failed for {hostname}: {e}") from e

    if not cnames:
        raise SubOverNoDataError(f"No CNAME records for {hostname}")

    for cname in cnames:
        for pattern, service in _TAKEOVER_SERVICES.items():
            if cname.endswith(f".{pattern}") or cname == pattern:
                # Check if the CNAME target resolves (dangling = vulnerable)
                is_dangling = not _resolves(cname)
                vulnerable.append(
                    {
                        "cname": cname,
                        "service": service,
                        "dangling": is_dangling,
                        "severity": "high" if is_dangling else "low",
                    }
                )

    if not vulnerable:
        raise SubOverNoDataError(f"No takeover-able CNAME targets for {hostname}")

    takeovers = [v for v in vulnerable if v["dangling"]]

    _logger.info(
        "SubOver: %d vulnerable (out of %d CNAMEs) for %s",
        len(takeovers),
        len(vulnerable),
        hostname,
    )

    return {
        "hostname": hostname,
        "cnames": cnames,
        "vulnerable": vulnerable,
        "takeover_count": len(takeovers),
        "sources_used": ["subover"],
    }


def _resolves(hostname: str) -> bool:
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False
