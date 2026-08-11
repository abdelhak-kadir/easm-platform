"""DNS enumeration — A, AAAA, MX, NS, TXT, SOA, CNAME records.

Equivalent to what DNSDumpster.com would return, but using direct DNS
queries via dnspython instead of scraping their website.  This is faster,
more reliable, and doesn't depend on a third-party web service.

No API key required — DNS is public infrastructure.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from app.tools.base import ToolNoDataError, ToolRateLimitError, ToolScanError

_logger = logging.getLogger(__name__)

_DNS_TIMEOUT = 10  # seconds per query
_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")


class DNSDumpsterScanError(ToolScanError):
    """Raised when DNS enumeration fails."""


class DNSDumpsterRateLimitError(DNSDumpsterScanError, ToolRateLimitError):
    """Raised when DNS servers rate-limit — safe to retry."""


class DNSDumpsterNoDataError(DNSDumpsterScanError, ToolNoDataError):
    """Raised when no DNS records are found."""


def run(asset_value: str) -> dict:
    """Enumerate DNS records for a domain.

    Queries A, AAAA, MX, NS, TXT, SOA, and CNAME records directly
    against the authoritative DNS infrastructure.  Zone transfer
    (AXFR) is also attempted but rarely succeeds on the public
    internet — when it does, it's a goldmine.

    Returns all DNS records plus discovered hostnames.
    """
    domain = asset_value.strip().lower().rstrip(".")

    if not domain or "*" in domain:
        raise DNSDumpsterNoDataError(f"Invalid domain: {domain!r}")

    _logger.info("DNSDumpster enumerating %s", domain)

    records: dict[str, list] = {r.lower(): [] for r in _RECORD_TYPES}
    errors: list[str] = []

    # Query each record type in parallel
    with ThreadPoolExecutor(max_workers=len(_RECORD_TYPES)) as pool:
        futures = {pool.submit(_query_dns, domain, rtype): rtype for rtype in _RECORD_TYPES}
        for future in as_completed(futures):
            rtype = futures[future]
            try:
                results = future.result()
                records[rtype.lower()] = results
            except Exception as e:
                errors.append(f"{rtype}: {e}")

    # Also try a zone transfer — rare but high value
    try:
        _try_axfr(domain, records)
    except Exception:
        pass  # expected to fail 99.9% of the time

    # Extract hostnames from all record types
    hosts = _extract_hostnames(domain, records)

    # Build IP list from A/AAAA records
    ips: list[str] = []
    for rec in records["a"] + records["aaaa"]:
        ip = rec.get("ip") or rec.get("value") or ""
        if ip:
            ips.append(ip)

    data: dict = {
        "domain": domain,
        "hosts": sorted(hosts),
        "ips": sorted(set(ips)),
        "emails": [],
        "urls": [],
        "records": records,
        "sources_used": ["dnsdumpster"],
    }

    # Warn if everything failed — surface as no-data, not a hard failure.
    # DNS resolvers inside containers often can't reach authoritative NS.
    if errors and len(errors) == len(_RECORD_TYPES):
        _logger.warning("All DNS queries failed for %s: %s", domain, errors)
        raise DNSDumpsterNoDataError(f"No DNS records resolvable for {domain}")

    if not hosts and not ips and not records.get("mx") and not records.get("ns"):
        raise DNSDumpsterNoDataError(f"No DNS records found for {domain}")

    _logger.info(
        "DNSDumpster found %d host(s), %d IP(s), %d MX for %s",
        len(hosts),
        len(ips),
        len(records.get("mx", [])),
        domain,
    )

    return data


# ── DNS queries ───────────────────────────────────────────────────────


def _query_dns(domain: str, rtype: str) -> list[dict]:
    """Query one record type and return a list of parsed dictionaries."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT
    resolver.lifetime = _DNS_TIMEOUT

    try:
        answers = resolver.resolve(domain, rtype)
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN as e:
        raise DNSDumpsterNoDataError(f"Domain {domain} does not exist (NXDOMAIN)") from e
    except dns.resolver.NoNameservers as e:
        raise DNSDumpsterScanError(f"No nameservers available for {domain}") from e
    except dns.resolver.Timeout as e:
        raise DNSDumpsterRateLimitError(f"DNS timeout for {domain} ({rtype})") from e
    except Exception as e:
        raise DNSDumpsterScanError(f"DNS query failed for {domain} ({rtype}): {e}") from e

    results: list[dict] = []
    for answer in answers:
        item = {"type": rtype, "ttl": answer.ttl}
        raw = str(answer)

        if rtype in ("A", "AAAA"):
            item["ip"] = raw
            # Try reverse lookup for A records
            try:
                item["hostname"] = socket.gethostbyaddr(raw)[0]
            except (socket.herror, socket.gaierror):
                pass
        elif rtype == "MX":
            parts = raw.split()
            if len(parts) >= 2:
                item["preference"] = int(parts[0])
                item["exchange"] = parts[1].rstrip(".")
        elif rtype == "NS":
            item["nameserver"] = raw.rstrip(".")
        elif rtype == "TXT":
            item["value"] = raw.strip('"')
        elif rtype == "SOA":
            parts = raw.split()
            item["mname"] = parts[0].rstrip(".") if len(parts) > 0 else ""
            item["rname"] = parts[1].rstrip(".") if len(parts) > 1 else ""
        elif rtype == "CNAME":
            item["target"] = raw.rstrip(".")

        results.append(item)

    return results


def _try_axfr(domain: str, records: dict) -> None:
    """Attempt a zone transfer.  Almost always refused, but when it
    succeeds it's a treasure trove of internal hostnames."""
    try:
        # Find NS servers
        ns_records = records.get("ns", [])
        if not ns_records:
            # Try to resolve NS directly
            try:
                answers = dns.resolver.resolve(domain, "NS")
                ns_hosts = [str(a).rstrip(".") for a in answers]
            except Exception:
                return
        else:
            ns_hosts = [r.get("nameserver", "") for r in ns_records if r.get("nameserver")]

        for ns in ns_hosts:
            try:
                ns_ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=_DNS_TIMEOUT))
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rd in rdataset:
                            rtype = dns.rdatatype.to_text(rdataset.rdtype)
                            key = rtype.lower()
                            if key not in records:
                                records[key] = []
                            records[key].append(
                                {
                                    "name": str(name),
                                    "type": rtype,
                                    "value": str(rd),
                                    "source": f"axfr@{ns}",
                                }
                            )
                _logger.warning("AXFR succeeded on %s via %s!", domain, ns)
                break  # one successful transfer is enough
            except Exception:
                continue
    except Exception:
        pass


def _extract_hostnames(domain: str, records: dict) -> set[str]:
    """Pull all subdomain hostnames from every record type."""
    hosts: set[str] = set()
    for _rtype, recs in records.items():
        for rec in recs:
            for field in ("exchange", "nameserver", "target", "hostname", "name"):
                val = rec.get(field, "")
                if val and val.endswith(f".{domain}") and val != domain:
                    hosts.add(val.rstrip("."))
            # MX records
            exchange = rec.get("exchange", "")
            if exchange and exchange.endswith(f".{domain}") and exchange != domain:
                hosts.add(exchange)
    return hosts
