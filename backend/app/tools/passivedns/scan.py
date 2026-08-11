"""PassiveDNS — multi-source passive DNS enumeration.

Aggregates subdomains from 4 free, no-auth passive DNS APIs:

1. **DNSBufferOver** — dns.bufferover.run (passive DNS database)
2. **HackerTarget** — api.hackertarget.com (host search)
3. **ThreatMiner** — api.threatminer.org (domain subdomains)
4. **RapidDNS** — rapiddns.io (passive DNS — HTML scrape)

Also performs:
- **Virtual host detection** — group subdomains sharing the same IP
- **Cloudflare detection** — flag IPs owned by Cloudflare (shared hosting)
"""

import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)
_TIMEOUT = 20

# Cloudflare IP ranges (public prefixes)
_CF_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


class PassiveDNSScanError(ToolScanError):
    pass


class PassiveDNSRateLimitError(PassiveDNSScanError, ToolRateLimitError):
    pass


class PassiveDNSNoDataError(PassiveDNSScanError, ToolNoDataError):
    pass


def run(asset_value: str) -> dict[str, Any]:
    domain = asset_value.strip().lower().rstrip(".")

    if not domain or "*" in domain:
        raise PassiveDNSNoDataError(f"Invalid domain: {domain!r}")

    _logger.info("PassiveDNS: 4 sources for %s", domain)

    all_hosts: dict[str, set[str]] = {}  # hostname → IPs
    sources_hit: list[str] = []

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(_bufferover, domain): "bufferover",
            pool.submit(_hackertarget, domain): "hackertarget",
            pool.submit(_threatminer, domain): "threatminer",
            pool.submit(_rapiddns, domain): "rapiddns",
        }
        for future in as_completed(futures):
            src = futures[future]
            try:
                hosts = future.result()
                if hosts:
                    sources_hit.append(src)
                    for h in hosts:
                        if h not in all_hosts:
                            all_hosts[h] = set()
            except Exception:
                pass

    if not all_hosts:
        raise PassiveDNSNoDataError(f"No passive DNS data found for {domain}")

    # ── Virtual host + Cloudflare detection ─────────────────────
    # Only resolve up to 30 hosts to avoid hanging on large sets
    host_to_ips: dict[str, list[str]] = {}
    ip_to_hosts: dict[str, list[str]] = {}
    cloudflare_hosts: list[str] = []
    cf_nets = [ipaddress.ip_network(c) for c in _CF_RANGES]

    import socket

    socket.setdefaulttimeout(5)
    sample = sorted(all_hosts)[:30]
    for host in sample:
        try:
            ip = socket.gethostbyname(host)
        except (TimeoutError, socket.gaierror):
            continue
        host_to_ips[host] = [ip]
        ip_to_hosts.setdefault(ip, []).append(host)
        try:
            a = ipaddress.ip_address(ip)
            if any(a in net for net in cf_nets):
                cloudflare_hosts.append(host)
        except ValueError:
            pass

    virtual_hosts = {ip: hosts for ip, hosts in ip_to_hosts.items() if len(hosts) > 1}

    _logger.info(
        "PassiveDNS: %d hosts from %s | %d virtual host groups | %d Cloudflare",
        len(all_hosts),
        sources_hit,
        len(virtual_hosts),
        len(cloudflare_hosts),
    )

    return {
        "domain": domain,
        "hosts": sorted(all_hosts),
        "host_to_ips": host_to_ips,
        "virtual_hosts": {ip: sorted(h) for ip, h in virtual_hosts.items()},
        "cloudflare_hosts": sorted(cloudflare_hosts),
        "sources_hit": sources_hit,
        "emails": [],
        "ips": [],
        "sources_used": ["passivedns"] + sources_hit,
    }


# ── Source: bufferover.run ───────────────────────────────────────


def _bufferover(domain: str) -> set[str]:
    hosts: set[str] = set()
    try:
        resp = requests.get(
            "https://dns.bufferover.run/dns",
            params={"q": f".{domain}"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return hosts
        data = resp.json()
        for key in ("FDNS_A", "RDNS"):
            entries = data.get(key) or []
            # Format: "1.2.3.4,host.example.com"
            for entry in entries:
                parts = str(entry).split(",")
                if len(parts) >= 2:
                    h = parts[1].strip().lower().rstrip(".")
                    if h.endswith(f".{domain}") and h != domain and "*" not in h:
                        hosts.add(h)
    except Exception:
        pass
    return hosts


# ── Source: hackertarget.com ─────────────────────────────────────


def _hackertarget(domain: str) -> set[str]:
    hosts: set[str] = set()
    try:
        resp = requests.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return hosts
        # CSV: "hostname,ip\n"
        for line in resp.text.strip().split("\n"):
            parts = line.strip().split(",")
            if len(parts) >= 1:
                h = parts[0].strip().lower().rstrip(".")
                if h.endswith(f".{domain}") and h != domain and "*" not in h:
                    hosts.add(h)
    except Exception:
        pass
    return hosts


# ── Source: threatminer.org ──────────────────────────────────────


def _threatminer(domain: str) -> set[str]:
    hosts: set[str] = set()
    try:
        resp = requests.get(
            "https://api.threatminer.org/v2/domain.php",
            params={"domain": domain, "rt": 5},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return hosts
        data = resp.json()
        for entry in data.get("results") or []:
            if isinstance(entry, str):
                h = entry.strip().lower().rstrip(".")
                if h.endswith(f".{domain}") and h != domain:
                    hosts.add(h)
    except Exception:
        pass
    return hosts


# ── Source: rapiddns.io ──────────────────────────────────────────


def _rapiddns(domain: str) -> set[str]:
    hosts: set[str] = set()
    try:
        resp = requests.get(
            f"https://rapiddns.io/subdomain/{domain}",
            params={"full": "1"},
            timeout=_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code != 200:
            return hosts
        # HTML table scrape — extract hostnames from <td> cells
        for match in re.finditer(
            r"<td[^>]*>([a-zA-Z0-9][-a-zA-Z0-9.]*)</td>",
            resp.text,
        ):
            h = match.group(1).strip().lower().rstrip(".")
            if h.endswith(f".{domain}") and h != domain and "*" not in h:
                hosts.add(h)
    except Exception:
        pass
    return hosts
